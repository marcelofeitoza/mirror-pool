//! `prove`: turn a saved ZK-opt-in note into a ready-to-submit `SettleZk`.
//!
//! Pipeline:
//!
//! 1. Recompute this note's `actionHash`, `nullifierHash`, and commitment leaf
//!    from the secret + bound `(recipient, amount)`, and check the leaf matches
//!    the note's commitment.
//! 2. Rebuild the Merkle inclusion path off-chain (walk the frontier snapshot the
//!    note captured at commit time, or rebuild the whole tree from `--leaves`) and
//!    confirm the resulting root is a root the Pool currently accepts.
//! 3. Size the anonymity set this settle would land in ([`AnonymitySet`]) and
//!    refuse to prove into a window below the pool's `k_floor` unless the
//!    participant waives it explicitly. This is the ZK path's floor: the program
//!    cannot enforce one at settle without stranding escrow (that path has no
//!    refund and no roll-forward), and the participant is the only party who can
//!    produce the proof, so refusing here is both free and sufficient.
//! 4. Generate the Groth16 proof IN-PROCESS in pure Rust (the default) via
//!    [`crate::prove_rust`]: `ark-circom` runs the compiled `membership.wasm`
//!    witness calculator under the `wasmer` VM, reads the proving key from
//!    `--zkey` (or, with `--proving-key`, from a ceremony `.mpk`), and
//!    `ark-groth16` produces + verifies the proof - no Node/snarkjs process is
//!    spawned. A `--use-snarkjs` fallback still shells out to
//!    `snarkjs groth16 fullprove` + `verify` for parity checks.
//!
//!    NOTE: the DEPLOYED membership verifying key is a phase-2 ceremony output
//!    (`docs/CEREMONY.md` section 10), and `circuits/membership_final.zkey` is the
//!    old dev key, so a proof made under the `--zkey` default cannot land. Pass
//!    `--proving-key <ceremony>/key_NNNN.mpk` to produce one that does. The
//!    `--zkey` path stays for circuit work against a locally exported key.
//!    Then verify that finished proof against the COMMITTED verifying key, using
//!    the same `groth16-solana` verifier the program runs, and refuse to emit if
//!    it fails. Every earlier check passes under a mismatched proving key, because
//!    a proof is verified against the key it was made under; this is the only step
//!    that compares it to the key the program will actually use. Without it the
//!    mismatch surfaces as a rejected transaction the user already paid for.
//! 5. Serialize the proof + public inputs into the exact `SettleZk` instruction
//!    data (proof_a pre-negated) and emit it for the relay/coordinator to submit.
//!
//! The circuit artifacts (`membership.r1cs`, `membership_js/membership.wasm`,
//! `membership_final.zkey`) are gitignored build outputs; the user must run
//! `bash circuits/build.sh` once (after `npm install` in `circuits/`) to produce
//! them. `prove` never submits `SettleZk`: settlement is paid for and signed by
//! the rotating gasless coordinator (the pool authority), never the participant.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::FromStr;

use anyhow::{anyhow, bail, Context, Result};
use mirror_core::{commit_with_action_hash, nullifier, transfer_action_hash, wire, Epoch, Hash32};
use serde::Serialize;
use solana_pubkey::Pubkey;

use crate::chain::{self, Chain};
use crate::groth16::{self, SnarkjsProof};
use crate::note::{ActionRecord, Note};
use crate::tree::{self, MerklePath};
use crate::util::{be32_to_decimal, from_hex32, read_leaves, to_hex};

/// `prove` arguments.
pub struct ProveOpts {
    pub note_path: PathBuf,
    pub rpc_url: String,
    pub wasm: PathBuf,
    /// Compiled R1CS (gitignored build output), needed by the in-process Rust prover.
    pub r1cs: PathBuf,
    pub zkey: PathBuf,
    /// A ceremony-produced proving key (`key_NNNN.mpk` from `ceremony contribute`).
    /// When set it REPLACES `zkey` as the source of the proving key, so a proof can
    /// be produced under a multi-party trusted setup instead of the dev setup. The
    /// program must be running the matching verifying key
    /// (`ceremony export-vk --out-rust`) or the proof will not land.
    pub proving_key: Option<PathBuf>,
    pub vk: PathBuf,
    /// snarkjs invocation (default `snarkjs`; e.g. `node <dir>/cli.cjs` also works).
    /// Only used by the `--use-snarkjs` fallback path.
    pub snarkjs: String,
    /// Use the legacy snarkjs shell-out instead of the default in-process Rust
    /// prover. The default (false) spawns NO Node process.
    pub use_snarkjs: bool,
    /// Optional full leaf set (hex, one per line) to rebuild the whole tree and
    /// prove against the CURRENT root instead of the note's frontier snapshot.
    pub leaves: Option<PathBuf>,
    /// Where to write input.json / proof.json / public.json (snarkjs path only;
    /// default: a temp dir).
    pub work_dir: Option<PathBuf>,
    /// Optional path to also write the emitted `SettleZk` JSON to.
    pub out: Option<PathBuf>,
    /// Settle even though the window's commit count is below the pool's
    /// `k_floor` (see [`AnonymitySet`]). Off by default: a thin window is the
    /// one condition the participant, and only the participant, can still
    /// refuse. Turning it on is a deliberate, informed trade of anonymity for
    /// getting the escrow out.
    pub accept_thin_set: bool,
}

/// What the client can see, from on-chain state alone, about the anonymity set a
/// `SettleZk` would land in.
///
/// `SettleZk` publishes the proof's `epoch` and the settled `amount`. The proof
/// itself hides the member among every leaf under the proven root, but those two
/// public values narrow what an observer has to consider: the leaf binds the
/// epoch (`commitment = Poseidon(secret, actionHash, epoch)`), and the escrow
/// amounts are public at deposit. So the set that actually covers an output is
/// the window's ZK deposits of the SAME amount, and `nominal_k` is an upper
/// bound on it in three separate ways: it counts crowd `Commit`s as well as ZK
/// `CommitDeposit`s, it counts every amount rather than the matching one, and it
/// counts operator and Sybil commits that add no anonymity at all.
///
/// The floor is checked HERE, in the client, and not on-chain, because the ZK
/// escrow's only exit is `SettleZk`: an on-chain floor would strand the escrow
/// of any window that never reaches it, and there is no refund and no
/// roll-forward on this path. The participant is also the only party who can
/// produce the proof at all, so declining is both free and sufficient.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct AnonymitySet {
    /// The epoch the note's leaf binds, i.e. the window this settle publishes.
    pub epoch: u64,
    /// The window's raw commit count (0 when the window has no Epoch account).
    pub nominal_k: u32,
    /// The pool's declared floor, fixed at `InitPool`.
    pub k_floor: u32,
    /// True only when the floor was actually missed AND the participant waived
    /// it, so a run that met the floor never records a waiver it did not use.
    pub accepted_below_floor: bool,
}

impl AnonymitySet {
    /// Whether the window's nominal count reaches the pool's floor.
    pub fn meets_floor(&self) -> bool {
        self.nominal_k >= self.k_floor
    }
}

/// The `SettleZk` bundle `prove` emits: instruction data plus the accounts the
/// relay/coordinator must pass. Machine-readable so a soak driver can submit it.
#[derive(Serialize)]
pub struct SettleZkEmit {
    pub program_id: String,
    pub pool: String,
    /// The pool authority (relay) that MUST sign `SettleZk` (from the pool account).
    pub authority: String,
    pub nullifier_pda: String,
    pub recipient: String,
    pub system_program: String,
    pub clock_sysvar: String,
    /// The write-once, digest-pinned MEMBERSHIP verifying-key registry PDA. The
    /// program reads its verifying key from here rather than from its own code,
    /// so a submitter MUST pass this account; it must already be installed
    /// (`mirror-cli init-vk --circuit membership`).
    pub vk_registry: String,
    pub epoch: u64,
    pub amount: u64,
    pub root_hex: String,
    pub nullifier_hash_hex: String,
    pub action_hash_hex: String,
    /// The full `SettleZk` instruction data (tag + body), hex, `SETTLE_ZK_LEN` bytes.
    pub settle_zk_data_hex: String,
    /// The anonymity set this settle lands in, as the client measured it. The
    /// program does not check any of this (see [`AnonymitySet`]), so it is
    /// recorded here to keep the number that was accepted on the record.
    pub anonymity: AnonymitySet,
}

/// A ZK opt-in note, resolved into everything BOTH proving commands need, with
/// every consistency check the client owes the user already made.
///
/// `prove` and `prove-associated` prove different statements, but they bind the
/// same note the same way, so this binding (and its validation) has exactly one
/// definition: recompute `action_hash`, `nullifier_hash` and the leaf from the
/// note's own secret, refuse a leaf that disagrees with the note's commitment,
/// rebuild the pool inclusion path, self-check it against its own root, and
/// refuse a root the pool would not accept.
pub(crate) struct ZkWitness {
    pub program_id: Pubkey,
    pub pool: Pubkey,
    pub recipient: Pubkey,
    pub amount: u64,
    pub secret: mirror_core::Secret,
    pub action_hash: Hash32,
    pub nullifier_hash: Hash32,
    pub leaf: Hash32,
    pub path: MerklePath,
    /// The connected RPC, so the caller can keep reading without reconnecting.
    pub chain: Chain,
    /// The pool account this proof was checked against.
    pub pool_state: chain::PoolState,
}

pub(crate) fn resolve_zk_note(
    note: &Note,
    note_path: &Path,
    leaves: Option<&Path>,
    rpc_url: &str,
    command: &str,
) -> Result<ZkWitness> {
    // A ZK proof only exists for the transfer (opt-in) path.
    let (recipient_str, amount) = match &note.action {
        ActionRecord::Transfer { recipient, amount } => (recipient.clone(), *amount),
        ActionRecord::Crowd { .. } => bail!(
            "note {} is a crowd-path note; `{command}` is only for ZK opt-in \
             (deposit-commit) notes",
            note_path.display()
        ),
    };

    let program_id = Pubkey::from_str(&note.program_id)
        .map_err(|e| anyhow!("note program_id is not a valid pubkey: {e}"))?;
    let pool = Pubkey::from_str(&note.pool)
        .map_err(|e| anyhow!("note pool is not a valid pubkey: {e}"))?;
    let recipient = Pubkey::from_str(&recipient_str)
        .map_err(|e| anyhow!("note recipient is not a valid pubkey: {e}"))?;

    let secret = mirror_core::Secret::from_bytes(from_hex32(&note.secret_hex)?);
    let epoch = Epoch(note.epoch);

    // Recompute the bound values and confirm the leaf matches the note.
    let action_hash = transfer_action_hash(&recipient.to_bytes(), amount);
    let nullifier_hash = nullifier(&secret, epoch).0;
    let leaf = commit_with_action_hash(&secret, &action_hash, epoch).0;
    let note_commitment = from_hex32(&note.commitment_hex)?;
    if leaf != note_commitment {
        bail!(
            "recomputed leaf {} does not match the note commitment {}: the note is inconsistent",
            to_hex(&leaf),
            note.commitment_hex
        );
    }

    // Rebuild the pool inclusion path off-chain and self-check the rebuild.
    let path = build_path(note, &leaf, leaves)?;
    if path.elements.len() != tree::DEPTH {
        bail!(
            "rebuilt pool path has {} levels, expected {}",
            path.elements.len(),
            tree::DEPTH
        );
    }
    if tree::verify_path(&leaf, &path.elements, &path.indices) != path.root {
        bail!("client-side pool path does not verify to its root (rebuild bug)");
    }

    // Confirm the Pool currently accepts this root (current root or in the ring).
    let chain = Chain::new(rpc_url.to_string());
    let pool_state = chain
        .pool_state(&pool)
        .context("reading the pool account to check the proof root is known")?;
    if !pool_state.is_known_root(&path.root) {
        bail!(
            "proof root {} is not a known recent root on-chain (it may have aged out of the \
             {}-root history; settle sooner, or pass --leaves to prove against the current root)",
            to_hex(&path.root),
            pool_state.root_ring.len()
        );
    }

    Ok(ZkWitness {
        program_id,
        pool,
        recipient,
        amount,
        secret,
        action_hash,
        nullifier_hash,
        leaf,
        path,
        chain,
        pool_state,
    })
}

pub fn run(opts: ProveOpts) -> Result<SettleZkEmit> {
    let note = Note::load(&opts.note_path)?;
    // (1)+(2) Bind and validate the note, rebuild the pool path, check the root.
    let ZkWitness {
        program_id,
        pool,
        recipient,
        amount,
        secret,
        action_hash,
        nullifier_hash,
        path,
        chain,
        pool_state,
        ..
    } = resolve_zk_note(
        &note,
        &opts.note_path,
        opts.leaves.as_deref(),
        &opts.rpc_url,
        "prove",
    )?;

    // (3) The anonymity gate. `SettleZk` publishes the epoch and the amount, so
    // the set that covers this output is the window's same-amount ZK deposits;
    // `nominal_k` bounds it from above. The program cannot enforce a floor here
    // without stranding escrow (there is no refund and no roll-forward on this
    // path), and the participant is the only party who can produce this proof,
    // so the floor is enforced at proof time and can be waived only here.
    let epoch_pda = chain::epoch_pda(&program_id, &pool, note.epoch);
    let nominal_k = match chain
        .epoch_state(&epoch_pda)
        .context("reading the epoch account to size the anonymity set")?
    {
        // No Epoch account means nothing was ever committed in that window.
        None => 0,
        Some(state) => {
            // The PDA seeds already bind the id; disagreeing state means layout
            // drift, and sizing an anonymity set off drifted state is exactly
            // the number nobody should trust. Fail closed instead.
            if state.epoch_id != note.epoch {
                bail!(
                    "epoch account {} reports epoch {} but the note binds epoch {} (layout drift)",
                    epoch_pda,
                    state.epoch_id,
                    note.epoch
                );
            }
            state.nominal_k
        }
    };
    let mut anonymity = AnonymitySet {
        epoch: note.epoch,
        nominal_k,
        k_floor: pool_state.k_floor,
        accepted_below_floor: false,
    };
    // One predicate for the gate and for the unit test that pins it.
    let below_floor = !anonymity.meets_floor();
    anonymity.accepted_below_floor = below_floor && opts.accept_thin_set;
    if below_floor && !opts.accept_thin_set {
        bail!(
            "epoch {} holds {} commitment(s), below this pool's k_floor of {}: settling now would \
             publish an output into an anonymity set small enough to attribute by elimination.\n\
             The window is closed, so this count can no longer grow. Your options are to leave the \
             escrow where it is (it stays in the pool; there is no refund instruction) or to accept \
             the thin set explicitly with --accept-thin-set.\n\
             Note that {} is an UPPER bound on your real cover: it counts crowd commits as well as \
             ZK deposits, every amount rather than the {} lamports this settle publishes, and any \
             operator or Sybil commits in the window.",
            note.epoch,
            nominal_k,
            pool_state.k_floor,
            nominal_k,
            amount,
        );
    }

    // (4) Generate + verify the Groth16 proof. Default: in-process pure Rust
    // (no Node process). Fallback: shell out to snarkjs behind `--use-snarkjs`.
    let proof_bytes = if opts.use_snarkjs {
        prove_with_snarkjs(
            &opts,
            &path,
            &nullifier_hash,
            &action_hash,
            note.epoch,
            &secret,
        )?
    } else {
        prove_with_rust(
            &opts,
            &path,
            &nullifier_hash,
            &action_hash,
            note.epoch,
            &secret,
        )?
    };

    // (4b) Refuse to emit a proof the deployed program would reject.
    //
    // The proving key and the committed verifying key can disagree: the membership
    // key came from the phase-2 ceremony, while `--zkey` still defaults to the dev
    // key `circuits/build.sh` produces. Proving under the wrong one yields a proof
    // that is internally valid and verifies against ITS OWN key, so every check up
    // to here passes, and it is only rejected on chain after the user has paid to
    // submit it. Verifying here against the SAME key the program pins turns that
    // into a local error with a name.
    check_against_committed_vk(
        &proof_bytes,
        &path.root,
        &nullifier_hash,
        &action_hash,
        note.epoch,
    )?;

    // (5) Serialize into SettleZk instruction data.
    let data = groth16::settle_zk_data(
        note.epoch,
        amount,
        &proof_bytes,
        &path.root,
        &nullifier_hash,
        &action_hash,
    );
    if data.len() != wire::SETTLE_ZK_LEN {
        bail!(
            "assembled SettleZk data is {} bytes, expected {}",
            data.len(),
            wire::SETTLE_ZK_LEN
        );
    }

    let nf_pda = chain::nullifier_pda(&program_id, &pool, note.epoch, &nullifier_hash);
    let emit = SettleZkEmit {
        program_id: program_id.to_string(),
        pool: pool.to_string(),
        authority: pool_state.authority.to_string(),
        nullifier_pda: nf_pda.to_string(),
        recipient: recipient.to_string(),
        system_program: chain::SYSTEM_PROGRAM_ID.to_string(),
        clock_sysvar: chain::CLOCK_SYSVAR_ID.to_string(),
        vk_registry: chain::vk_registry_pda(&program_id, wire::CIRCUIT_MEMBERSHIP).to_string(),
        epoch: note.epoch,
        amount,
        root_hex: to_hex(&path.root),
        nullifier_hash_hex: to_hex(&nullifier_hash),
        action_hash_hex: to_hex(&action_hash),
        settle_zk_data_hex: to_hex(&data),
        anonymity,
    };

    if let Some(out) = &opts.out {
        let json = serde_json::to_string_pretty(&emit).context("serializing emit")?;
        std::fs::write(out, json).with_context(|| format!("writing {}", out.display()))?;
    }
    Ok(emit)
}

/// Rebuild the inclusion path: from `--leaves` (full rebuild vs current root) if
/// given, otherwise from the note's frontier snapshot (walk-the-frontier).
///
/// Shared with [`crate::association`], whose `prove-associated` builds the SAME
/// pool path and then adds a second one against the curated set.
pub(crate) fn build_path(note: &Note, leaf: &Hash32, leaves: Option<&Path>) -> Result<MerklePath> {
    if let Some(leaves_path) = leaves {
        let leaf_set = read_leaves(leaves_path)?;
        let index = match note.leaf_index {
            Some(i) => i as usize,
            None => leaf_set.iter().position(|l| l == leaf).ok_or_else(|| {
                anyhow!(
                    "this note's commitment is not present in {}",
                    leaves_path.display()
                )
            })?,
        };
        if leaf_set.get(index) != Some(leaf) {
            bail!(
                "leaf at index {} in {} does not match this note's commitment",
                index,
                leaves_path.display()
            );
        }
        let mtree = tree::SparseMerkle::from_leaves(tree::DEPTH, &leaf_set);
        return Ok(mtree.path(index));
    }

    // Frontier-snapshot path.
    let leaf_index = note.leaf_index.ok_or_else(|| {
        anyhow!("note has no leaf_index; re-commit with this CLI, or pass --leaves")
    })?;
    let frontier_hex = note.frontier_pre.as_ref().ok_or_else(|| {
        anyhow!("note has no frontier snapshot; re-commit with this CLI, or pass --leaves")
    })?;
    if frontier_hex.len() != tree::DEPTH {
        bail!(
            "note frontier snapshot has {} levels, expected {}",
            frontier_hex.len(),
            tree::DEPTH
        );
    }
    let mut frontier = Vec::with_capacity(tree::DEPTH);
    for h in frontier_hex {
        frontier.push(from_hex32(h)?);
    }
    Ok(tree::incremental_path(leaf, leaf_index, &frontier))
}

/// The circom `input.json` object for the membership circuit (decimal field
/// elements), shared by the in-process Rust prover and the snarkjs fallback.
pub(crate) fn membership_input_json(
    root: &Hash32,
    nullifier_hash: &Hash32,
    action_hash: &Hash32,
    epoch: u64,
    secret: &Hash32,
    merkle_path: &MerklePath,
) -> serde_json::Value {
    serde_json::json!({
        "root": be32_to_decimal(root),
        "nullifierHash": be32_to_decimal(nullifier_hash),
        "actionHash": be32_to_decimal(action_hash),
        "epoch": epoch.to_string(),
        "secret": be32_to_decimal(secret),
        "pathElements": merkle_path.elements.iter().map(be32_to_decimal).collect::<Vec<_>>(),
        "pathIndices": merkle_path.indices.iter().map(|b| b.to_string()).collect::<Vec<_>>(),
    })
}

/// The four membership public inputs, in circuit-declaration order
/// `[root, nullifierHash, actionHash, epoch]`, each 32-byte big-endian. `epoch` is
/// the big-endian encoding of the u64 (the value the proof commits to).
/// Verify a freshly made membership proof against the COMMITTED verifying key,
/// using the exact verifier the on-chain program runs.
///
/// Every earlier check passes even when the proving key is the wrong one: a proof
/// is verified against the key it was made under, so a dev-key proof looks
/// perfectly valid right up until the program rejects it. This is the only check
/// that compares the proof to the key the program will actually use.
fn check_against_committed_vk(
    bytes: &groth16::ProofBytes,
    root: &Hash32,
    nullifier_hash: &Hash32,
    action_hash: &Hash32,
    epoch: u64,
) -> Result<()> {
    let public_inputs = membership_public_inputs(root, nullifier_hash, action_hash, epoch);
    let vk = crate::vk::key_for(wire::CIRCUIT_MEMBERSHIP)?;
    let mut verifier = groth16_solana::groth16::Groth16Verifier::new(
        &bytes.proof_a,
        &bytes.proof_b,
        &bytes.proof_c,
        &public_inputs,
        vk,
    )
    .map_err(|e| anyhow!("constructing the on-chain verifier: {e:?}"))?;
    verifier.verify().map_err(|_| {
        anyhow!(
            "this proof does NOT verify against the committed membership verifying key, so the \
             program would reject it on chain.\n\nThe usual cause is a proving-key mismatch: the \
             deployed membership key came from the phase-2 ceremony, while `--zkey` still \
             defaults to the dev key that `bash circuits/build.sh` produces. Prove under the \
             ceremony key instead:\n\n    --proving-key ceremony/membership/key_NNNN.mpk\n\n\
             See docs/CEREMONY.md. Refusing to emit rather than let you pay to submit a proof \
             that cannot land."
        )
    })
}

pub(crate) fn membership_public_inputs(
    root: &Hash32,
    nullifier_hash: &Hash32,
    action_hash: &Hash32,
    epoch: u64,
) -> [Hash32; 4] {
    let mut epoch_be = [0u8; 32];
    epoch_be[24..].copy_from_slice(&epoch.to_be_bytes());
    [*root, *nullifier_hash, *action_hash, epoch_be]
}

fn write_input_json(
    path: &Path,
    root: &Hash32,
    nullifier_hash: &Hash32,
    action_hash: &Hash32,
    epoch: u64,
    secret: &Hash32,
    merkle_path: &MerklePath,
) -> Result<()> {
    let input = membership_input_json(
        root,
        nullifier_hash,
        action_hash,
        epoch,
        secret,
        merkle_path,
    );
    std::fs::write(path, serde_json::to_string_pretty(&input)?)
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

/// Default in-process proving path: build the proof with `ark-circom` +
/// `ark-groth16`, spawning NO Node process.
fn prove_with_rust(
    opts: &ProveOpts,
    path: &MerklePath,
    nullifier_hash: &Hash32,
    action_hash: &Hash32,
    epoch: u64,
    secret: &mirror_core::Secret,
) -> Result<groth16::ProofBytes> {
    let input = membership_input_json(
        &path.root,
        nullifier_hash,
        action_hash,
        epoch,
        &secret.0,
        path,
    );
    let expected = membership_public_inputs(&path.root, nullifier_hash, action_hash, epoch);
    if let Some(mpk) = &opts.proving_key {
        let key = mirror_ceremony::key::CeremonyKey::load(mpk)
            .with_context(|| format!("loading ceremony proving key {}", mpk.display()))?;
        return crate::prove_rust::prove_with_key(
            &opts.wasm, &opts.r1cs, &key.pk, &input, &expected,
        )
        .context("in-process Rust Groth16 proving under a ceremony key");
    }
    crate::prove_rust::prove(
        &crate::prove_rust::Artifacts {
            wasm: &opts.wasm,
            r1cs: &opts.r1cs,
            zkey: &opts.zkey,
        },
        &input,
        &expected,
    )
    .context("in-process Rust Groth16 proving")
}

/// Legacy fallback: shell out to snarkjs `groth16 fullprove` + `verify` (needs
/// Node). Behind `--use-snarkjs`; the default path is `prove_with_rust`.
fn prove_with_snarkjs(
    opts: &ProveOpts,
    path: &MerklePath,
    nullifier_hash: &Hash32,
    action_hash: &Hash32,
    epoch: u64,
    secret: &mirror_core::Secret,
) -> Result<groth16::ProofBytes> {
    let work_dir = match &opts.work_dir {
        Some(d) => d.clone(),
        None => std::env::temp_dir().join(format!("mirror-cli-prove-{}", to_hex(&path.root))),
    };
    std::fs::create_dir_all(&work_dir)
        .with_context(|| format!("creating work dir {}", work_dir.display()))?;

    let input_path = work_dir.join("input.json");
    write_input_json(
        &input_path,
        &path.root,
        nullifier_hash,
        action_hash,
        epoch,
        &secret.0,
        path,
    )?;

    let proof_path = work_dir.join("proof.json");
    let public_path = work_dir.join("public.json");
    run_fullprove(
        &opts.snarkjs,
        &input_path,
        &opts.wasm,
        &opts.zkey,
        &proof_path,
        &public_path,
    )?;
    verify_proof(&opts.snarkjs, &opts.vk, &public_path, &proof_path)?;

    // Cross-check snarkjs's public signals against our computed public inputs.
    cross_check_public(&public_path, &path.root, nullifier_hash, action_hash, epoch)?;

    let proof_json = std::fs::read_to_string(&proof_path)
        .with_context(|| format!("reading {}", proof_path.display()))?;
    SnarkjsProof::parse(&proof_json)?.to_bytes()
}

/// Split a snarkjs invocation string into `(program, prefix_args)`, so both
/// `snarkjs` and `node /path/to/cli.cjs` work.
pub(crate) fn snarkjs_command(snarkjs: &str) -> Result<(String, Vec<String>)> {
    let mut parts = snarkjs.split_whitespace().map(str::to_string);
    let program = parts
        .next()
        .ok_or_else(|| anyhow!("empty --snarkjs command"))?;
    Ok((program, parts.collect()))
}

pub(crate) fn run_fullprove(
    snarkjs: &str,
    input: &Path,
    wasm: &Path,
    zkey: &Path,
    proof: &Path,
    public: &Path,
) -> Result<()> {
    for (p, what) in [(wasm, "circuit wasm"), (zkey, "proving key (zkey)")] {
        if !p.exists() {
            bail!(
                "{} not found at {}: run `bash circuits/build.sh` once to produce the \
                 gitignored zkey/wasm",
                what,
                p.display()
            );
        }
    }
    let (program, prefix) = snarkjs_command(snarkjs)?;
    let output = Command::new(&program)
        .args(&prefix)
        .args([
            "groth16",
            "fullprove",
            &input.to_string_lossy(),
            &wasm.to_string_lossy(),
            &zkey.to_string_lossy(),
            &proof.to_string_lossy(),
            &public.to_string_lossy(),
        ])
        .output()
        .with_context(|| format!("spawning `{program}` (is snarkjs installed / on PATH?)"))?;
    if !output.status.success() {
        bail!(
            "snarkjs groth16 fullprove failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

pub(crate) fn verify_proof(snarkjs: &str, vk: &Path, public: &Path, proof: &Path) -> Result<()> {
    if !vk.exists() {
        bail!(
            "verification key not found at {}: run `bash circuits/build.sh` (or point --vk at it)",
            vk.display()
        );
    }
    let (program, prefix) = snarkjs_command(snarkjs)?;
    let output = Command::new(&program)
        .args(&prefix)
        .args([
            "groth16",
            "verify",
            &vk.to_string_lossy(),
            &public.to_string_lossy(),
            &proof.to_string_lossy(),
        ])
        .output()
        .with_context(|| format!("spawning `{program}` for verify"))?;
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    // Fail loudly unless snarkjs both exits cleanly AND reports OK.
    if !output.status.success() || combined.contains("INVALID") || !combined.contains("OK!") {
        bail!("snarkjs groth16 verify did NOT confirm the proof:\n{combined}");
    }
    Ok(())
}

/// Confirm snarkjs's `public.json` equals our computed public inputs, in order.
fn cross_check_public(
    public_path: &Path,
    root: &Hash32,
    nullifier_hash: &Hash32,
    action_hash: &Hash32,
    epoch: u64,
) -> Result<()> {
    let raw = std::fs::read_to_string(public_path)
        .with_context(|| format!("reading {}", public_path.display()))?;
    let signals: Vec<String> = serde_json::from_str(&raw).context("parsing snarkjs public.json")?;
    let expected = [
        be32_to_decimal(root),
        be32_to_decimal(nullifier_hash),
        be32_to_decimal(action_hash),
        epoch.to_string(),
    ];
    if signals.len() != expected.len() {
        bail!(
            "public.json has {} signals, expected {} [root, nullifierHash, actionHash, epoch]",
            signals.len(),
            expected.len()
        );
    }
    let names = ["root", "nullifierHash", "actionHash", "epoch"];
    for i in 0..expected.len() {
        if signals[i] != expected[i] {
            bail!(
                "public signal {} ({}) from snarkjs ({}) does not match the computed value ({})",
                i,
                names[i],
                signals[i],
                expected[i]
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ZK path's k-floor lives here, so the decision itself is a unit under
    /// test: at or above the floor settles, below it does not, and a window with
    /// no Epoch account at all (nominal_k = 0) is the thinnest case there is.
    #[test]
    fn anonymity_set_floor_decision() {
        let set = |nominal_k, k_floor| AnonymitySet {
            epoch: 7,
            nominal_k,
            k_floor,
            accepted_below_floor: false,
        };
        assert!(set(3, 3).meets_floor(), "exactly at the floor settles");
        assert!(set(9, 3).meets_floor());
        assert!(!set(2, 3).meets_floor(), "below the floor must not settle");
        assert!(
            !set(0, 3).meets_floor(),
            "a window with no commits at all is the thinnest case"
        );
        // A floor of 0 or 1 is no floor: a set of one is one member, itself.
        assert!(set(1, 1).meets_floor());
    }

    /// The committed proving fixture (`circuits/artifacts/proof_fixture.json`),
    /// rebuilt from mirror-core + our tree code: ONE leaf at index 21 in an
    /// otherwise-empty depth-20 tree, secret 1111..9999, epoch 7, recipient bytes
    /// 0x01..0x20, amount 0.25 SOL. Every sibling is therefore the empty-subtree
    /// hash for its level (a sparse membership vector, not a dense frontier).
    ///
    /// Every test that proves under this witness gets it from HERE, so the
    /// fixture the tests reproduce has exactly one definition.
    struct Fixture {
        secret: mirror_core::Secret,
        amount: u64,
        epoch: u64,
        action_hash: [u8; 32],
        nullifier_hash: [u8; 32],
        path: MerklePath,
    }

    fn fixture_witness() -> Fixture {
        const LEAF_INDEX: u64 = 21;
        let secret = mirror_core::Secret::from_bytes(
            groth16::to_be32("111122223333444455556666777788889999").unwrap(),
        );
        let mut recipient = [0u8; 32];
        for (i, b) in recipient.iter_mut().enumerate() {
            *b = (i + 1) as u8;
        }
        let amount: u64 = 250_000_000;
        let epoch: u64 = 7;
        let action_hash = transfer_action_hash(&recipient, amount);
        let nullifier_hash = nullifier(&secret, Epoch(epoch)).0;
        let leaf = commit_with_action_hash(&secret, &action_hash, Epoch(epoch)).0;
        let zeros = tree::zero_ladder(tree::DEPTH);
        let mut elements = Vec::with_capacity(tree::DEPTH);
        let mut indices = Vec::with_capacity(tree::DEPTH);
        for (level, zero) in zeros.iter().enumerate().take(tree::DEPTH) {
            elements.push(*zero);
            indices.push(((LEAF_INDEX >> level) & 1) as u8);
        }
        let root = tree::verify_path(&leaf, &elements, &indices);
        Fixture {
            secret,
            amount,
            epoch,
            action_hash,
            nullifier_hash,
            path: MerklePath {
                elements,
                indices,
                root,
            },
        }
    }

    /// The committed fixture's `publicSignals`, as decimal strings.
    fn fixture_public_signals() -> Vec<String> {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../circuits/artifacts/proof_fixture.json"
        )))
        .unwrap();
        fixture["publicSignals"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect()
    }

    /// The repo root: this crate lives at `crates/mirror-cli`.
    fn repo_root() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf()
    }

    /// DECISIVE offline check: `prove`'s client-side building blocks reproduce the
    /// committed circuit fixture's root, nullifierHash, and actionHash EXACTLY.
    ///
    /// gen_fixture.js places a single leaf at index 21 in an otherwise-empty
    /// depth-20 tree, so EVERY sibling on the path is the canonical empty-subtree
    /// hash `zeros[level]` (not a real dense-append frontier), for
    /// secret = 111122223333444455556666777788889999, epoch = 7, recipient bytes
    /// 0x01..0x20, amount 0.25 SOL. Rebuilding that path with our zero ladder +
    /// `verify_path` and reproducing the public signals proves our Poseidon /
    /// hashing matches the circuit: a proof generated for the circuit verifies
    /// against a root this CLI (and the on-chain accumulator) produce.
    #[test]
    fn client_rebuild_reproduces_fixture_public_signals() {
        let ps = fixture_public_signals();
        let f = fixture_witness();

        assert_eq!(
            be32_to_decimal(&f.path.root),
            ps[0],
            "root must match fixture"
        );
        assert_eq!(
            be32_to_decimal(&f.nullifier_hash),
            ps[1],
            "nullifierHash must match fixture"
        );
        assert_eq!(
            be32_to_decimal(&f.action_hash),
            ps[2],
            "actionHash must match fixture"
        );
        assert_eq!(f.epoch.to_string(), ps[3], "epoch must match fixture");
    }

    /// Resolve the build artifacts a live test needs, or FAIL.
    ///
    /// A live test runs only when the operator explicitly asks for it with
    /// `MIRROR_PROVE_LIVE=1`. Once they have, a missing artifact is a broken
    /// environment, not a reason to pass: silently returning early would let the
    /// test that is supposed to prove something report success while proving
    /// nothing. Skipping is only legitimate BEFORE the flag is honoured.
    fn require_live_artifacts(paths: &[&Path]) {
        let missing: Vec<String> = paths
            .iter()
            .filter(|p| !p.exists())
            .map(|p| p.display().to_string())
            .collect();
        assert!(
            missing.is_empty(),
            "MIRROR_PROVE_LIVE=1 was set, so this test must actually run, but these build \
             artifacts are missing: {}. Build them with `bash circuits/build.sh` (and download the \
             powers-of-tau) or unset MIRROR_PROVE_LIVE to skip.",
            missing.join(", ")
        );
    }

    /// The guard above is the whole point of BUG 3: with the live flag set, an
    /// absent artifact must fail loudly rather than green-test nothing.
    #[test]
    fn live_prove_test_fails_when_artifacts_are_absent() {
        let present = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
        require_live_artifacts(&[&present]);

        let absent = Path::new(env!("CARGO_MANIFEST_DIR")).join("no-such-artifact.r1cs");
        let panicked = std::panic::catch_unwind(|| require_live_artifacts(&[&present, &absent]));
        let payload = panicked.expect_err("a missing artifact must fail, not pass");
        let message = payload
            .downcast_ref::<String>()
            .cloned()
            .unwrap_or_else(|| "<non-string panic>".into());
        assert!(
            message.contains("no-such-artifact.r1cs") && message.contains("must actually run"),
            "the failure must name what is missing and why: {message}"
        );
    }

    /// End-to-end `prove` proof generation through snarkjs against the REAL
    /// zkey/wasm. Gated behind MIRROR_PROVE_LIVE=1 and #[ignore] so CI without
    /// node/snarkjs/zkey still passes; the Surfpool soak exercises it live.
    ///
    /// SCOPE: this exercises the snarkjs SHELL-OUT plumbing (fullprove, verify,
    /// public-signal cross-check, SettleZk assembly), not the deployed root of
    /// trust. It proves under the `circuits/build.sh` dev zkey and verifies
    /// against THAT zkey's own verifying key, exported into the work directory,
    /// because the committed `circuits/artifacts/verification_key.json` is now the
    /// phase-2 CEREMONY key and the dev zkey cannot produce proofs under it. The
    /// tests that pin the deployed key are the `rust_prove` pair below, which
    /// prove under the ceremony proving key.
    ///
    /// Run with:
    ///   MIRROR_PROVE_LIVE=1 cargo test -p mirror-cli -- --ignored prove_pipeline
    #[test]
    #[ignore = "requires node + snarkjs + built zkey/wasm; set MIRROR_PROVE_LIVE=1"]
    fn prove_pipeline_generates_and_verifies_real_proof() {
        if std::env::var("MIRROR_PROVE_LIVE").ok().as_deref() != Some("1") {
            eprintln!("MIRROR_PROVE_LIVE != 1; skipping live prove pipeline test");
            return;
        }
        // Resolve circuit artifacts relative to the repo root.
        let root = repo_root();
        let wasm = root.join("circuits/membership_js/membership.wasm");
        let zkey = root.join("circuits/membership_final.zkey");

        let Fixture {
            secret,
            amount,
            epoch,
            action_hash,
            nullifier_hash,
            path,
        } = fixture_witness();

        let work = std::env::temp_dir().join("mirror-cli-prove-live-test");
        std::fs::create_dir_all(&work).unwrap();

        // The dev zkey's OWN verifying key (see SCOPE above).
        let vk = work.join("dev_zkey_verification_key.json");
        let (program, prefix) = snarkjs_command("snarkjs").unwrap();
        let export = Command::new(&program)
            .args(&prefix)
            .args([
                "zkey",
                "export",
                "verificationkey",
                &zkey.to_string_lossy(),
                &vk.to_string_lossy(),
            ])
            .output()
            .expect("spawning snarkjs to export the dev zkey's verifying key");
        assert!(
            export.status.success() && vk.exists(),
            "snarkjs zkey export verificationkey failed: {}{}",
            String::from_utf8_lossy(&export.stdout),
            String::from_utf8_lossy(&export.stderr)
        );

        let input = work.join("input.json");
        write_input_json(
            &input,
            &path.root,
            &nullifier_hash,
            &action_hash,
            epoch,
            &secret.0,
            &path,
        )
        .unwrap();

        let proof = work.join("proof.json");
        let public = work.join("public.json");
        run_fullprove("snarkjs", &input, &wasm, &zkey, &proof, &public).expect("snarkjs fullprove");
        verify_proof("snarkjs", &vk, &public, &proof).expect("snarkjs verify must confirm OK");

        // Assemble and sanity-check the SettleZk data length.
        cross_check_public(&public, &path.root, &nullifier_hash, &action_hash, epoch).unwrap();
        let proof_json = std::fs::read_to_string(&proof).unwrap();
        let proof_bytes = SnarkjsProof::parse(&proof_json)
            .unwrap()
            .to_bytes()
            .unwrap();
        let data = groth16::settle_zk_data(
            epoch,
            amount,
            &proof_bytes,
            &path.root,
            &nullifier_hash,
            &action_hash,
        );
        assert_eq!(data.len(), wire::SETTLE_ZK_LEN);
    }

    /// The committed on-chain verifying key (byte-for-byte the one the program
    /// embeds in `programs/mirror-pool/src/vk.rs`), included so the test can run the
    /// EXACT on-chain Groth16 verifier over a Rust-generated proof.
    mod committed_vk {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../circuits/artifacts/vk.rs"
        ));
    }

    /// The final transcript hash of the phase-2 ceremony the COMMITTED membership
    /// verifying key was exported from. Published in `docs/CEREMONY.md` and
    /// re-derivable from `docs/ceremony-run/membership-deployed-transcript.json`.
    const DEPLOYED_MEMBERSHIP_TRANSCRIPT_HASH: &str =
        "884c88601173b1f08bd2e26626b0fe4c553dedffe707b2387db754417a9cdd05";

    /// The proving key that matches the COMMITTED membership verifying key.
    ///
    /// The deployed membership key is a phase-2 CEREMONY output, not a
    /// `circuits/build.sh` dev setup, so `circuits/membership_final.zkey` no longer
    /// corresponds to `circuits/artifacts/vk.rs` and cannot produce a proof the
    /// program accepts. The matching proving key is the ceremony's head key. Like
    /// the zkey it is a multi-megabyte gitignored local artifact, so these live
    /// tests need the ceremony directory on disk; the transcript-hash assertion
    /// below makes sure it is the RIGHT ceremony and not some other run.
    fn deployed_membership_proving_key(repo: &Path) -> ark_groth16::ProvingKey<ark_bn254::Bn254> {
        let dir = repo.join("ceremony/membership");
        assert!(
            dir.join("transcript.json").exists(),
            "MIRROR_PROVE_LIVE=1 was set, so this test must actually run, but the membership \
             ceremony directory {} is missing. It holds the proving key matching the committed \
             verifying key and is gitignored (multi-megabyte key files); obtain it from the \
             ceremony operator, or unset MIRROR_PROVE_LIVE to skip.",
            dir.display()
        );
        let session =
            mirror_ceremony::session::Session::open(&dir).expect("opening the membership ceremony");
        let report = session
            .verify()
            .expect("the membership ceremony transcript must verify");
        assert_eq!(
            report.final_transcript_hash, DEPLOYED_MEMBERSHIP_TRANSCRIPT_HASH,
            "this is not the ceremony the committed verifying key was exported from"
        );
        session
            .load_head_key()
            .expect("loading the ceremony head proving key")
            .pk
    }

    /// DECISIVE end-to-end check for the in-process (Node-free) prover: generate a
    /// membership proof entirely in Rust (`ark-circom` + `ark-groth16`, no snarkjs),
    /// then confirm the emitted `groth16-solana` proof bytes + public inputs are
    /// accepted by the SAME on-chain `Groth16Verifier` + committed verifying key the
    /// program runs. `prove_rust::prove` also runs an internal `ark-groth16` verify
    /// and bails on failure, so reaching the on-chain check means BOTH verifiers
    /// accepted the Rust proof.
    ///
    /// Gated behind MIRROR_PROVE_LIVE=1 + #[ignore] because it needs the gitignored
    /// r1cs/wasm/zkey (`bash circuits/build.sh`), NOT because it needs Node - this
    /// path spawns no Node process. Run with:
    ///   MIRROR_PROVE_LIVE=1 cargo test -p mirror-cli -- --ignored rust_prove
    #[test]
    #[ignore = "requires the built r1cs/wasm/zkey (bash circuits/build.sh); set MIRROR_PROVE_LIVE=1"]
    fn rust_prove_membership_verifies_and_on_chain_verifier_accepts() {
        use groth16_solana::groth16::Groth16Verifier;

        if std::env::var("MIRROR_PROVE_LIVE").ok().as_deref() != Some("1") {
            eprintln!("MIRROR_PROVE_LIVE != 1; skipping live Rust prove test");
            return;
        }
        let repo = repo_root();
        let Fixture {
            secret,
            amount,
            epoch,
            action_hash,
            nullifier_hash,
            path,
        } = fixture_witness();

        // Cross-check the reproduced public signals against the committed fixture.
        let ps = fixture_public_signals();
        assert_eq!(be32_to_decimal(&path.root), ps[0]);
        assert_eq!(be32_to_decimal(&nullifier_hash), ps[1]);
        assert_eq!(be32_to_decimal(&action_hash), ps[2]);

        // Prove entirely in Rust (no Node). `prove_rust::prove` verifies with
        // ark-groth16 internally and bails on failure.
        let input = membership_input_json(
            &path.root,
            &nullifier_hash,
            &action_hash,
            epoch,
            &secret.0,
            &path,
        );
        let expected = membership_public_inputs(&path.root, &nullifier_hash, &action_hash, epoch);
        let pk = deployed_membership_proving_key(&repo);
        let proof_bytes = crate::prove_rust::prove_with_key(
            &repo.join("circuits/membership_js/membership.wasm"),
            &repo.join("circuits/membership.r1cs"),
            &pk,
            &input,
            &expected,
        )
        .expect("in-process Rust proving must succeed and ark-verify");

        // The emitted SettleZk data is well-formed.
        let data = groth16::settle_zk_data(
            epoch,
            amount,
            &proof_bytes,
            &path.root,
            &nullifier_hash,
            &action_hash,
        );
        assert_eq!(data.len(), wire::SETTLE_ZK_LEN);

        // DECISIVE: the EXACT on-chain verifier + committed vk accepts the Rust proof.
        let public_inputs: [[u8; 32]; 4] = expected;
        let mut verifier = Groth16Verifier::new(
            &proof_bytes.proof_a,
            &proof_bytes.proof_b,
            &proof_bytes.proof_c,
            &public_inputs,
            &committed_vk::VERIFYINGKEY,
        )
        .expect("verifier construction");
        verifier
            .verify()
            .expect("on-chain groth16-solana verifier must ACCEPT the Rust-generated proof");
    }

    /// ARTIFACT PROVENANCE: a proof over inputs the committed fixture never saw
    /// still verifies under the COMMITTED verifying key, through the real
    /// on-chain `groth16-solana` verifier.
    ///
    /// The test above proves the fixture's own witness, so it would keep passing
    /// if the proof and the key had drifted together away from the circuit. This
    /// one shares nothing with the fixture: a different secret, epoch, recipient,
    /// amount and leaf index, and a DENSE inclusion path (non-zero siblings at
    /// every level) instead of the fixture's sparse zero ladder. A proving key
    /// that no longer matched `circuits/artifacts/vk.rs` would fail here.
    ///
    /// Same gating as the test above: needs the gitignored r1cs/wasm/zkey, no
    /// Node. Run with:
    ///   MIRROR_PROVE_LIVE=1 cargo test -p mirror-cli -- --ignored fresh_inputs
    #[test]
    #[ignore = "requires the built r1cs/wasm/zkey (bash circuits/build.sh); set MIRROR_PROVE_LIVE=1"]
    fn rust_prove_fresh_inputs_verifies_under_the_committed_vk() {
        use groth16_solana::groth16::Groth16Verifier;

        if std::env::var("MIRROR_PROVE_LIVE").ok().as_deref() != Some("1") {
            eprintln!("MIRROR_PROVE_LIVE != 1; skipping fresh-input prove test");
            return;
        }
        let repo = repo_root();

        // Nothing here comes from the fixture.
        const LEAF_INDEX: u64 = 0x0005_2a91;
        let secret = mirror_core::Secret::from_bytes(
            groth16::to_be32("880123456789012345678901234567890123456789").unwrap(),
        );
        let mut recipient = [0u8; 32];
        for (i, b) in recipient.iter_mut().enumerate() {
            *b = (0xa0 ^ i) as u8;
        }
        let amount: u64 = 1_337_000_001;
        let epoch: u64 = 4_242;
        let action_hash = transfer_action_hash(&recipient, amount);
        let nullifier_hash = nullifier(&secret, Epoch(epoch)).0;
        let leaf = commit_with_action_hash(&secret, &action_hash, Epoch(epoch)).0;

        // A DENSE path: every sibling is a real (non-empty) node, so no level of
        // the Merkle climb degenerates into the zero ladder the fixture uses.
        let mut elements = Vec::with_capacity(tree::DEPTH);
        let mut indices = Vec::with_capacity(tree::DEPTH);
        for level in 0..tree::DEPTH {
            let mut sibling = [0u8; 32];
            sibling[31] = (level as u8).wrapping_mul(7).wrapping_add(3);
            sibling[30] = 0x11;
            elements.push(sibling);
            indices.push(((LEAF_INDEX >> level) & 1) as u8);
        }
        let root = tree::verify_path(&leaf, &elements, &indices);
        let path = MerklePath {
            elements,
            indices,
            root,
        };

        // These really are new inputs.
        let ps = fixture_public_signals();
        assert_ne!(be32_to_decimal(&path.root), ps[0]);
        assert_ne!(be32_to_decimal(&nullifier_hash), ps[1]);
        assert_ne!(be32_to_decimal(&action_hash), ps[2]);

        let input = membership_input_json(
            &path.root,
            &nullifier_hash,
            &action_hash,
            epoch,
            &secret.0,
            &path,
        );
        let expected = membership_public_inputs(&path.root, &nullifier_hash, &action_hash, epoch);
        let pk = deployed_membership_proving_key(&repo);
        let proof_bytes = crate::prove_rust::prove_with_key(
            &repo.join("circuits/membership_js/membership.wasm"),
            &repo.join("circuits/membership.r1cs"),
            &pk,
            &input,
            &expected,
        )
        .expect("in-process Rust proving must succeed and ark-verify");

        let mut verifier = Groth16Verifier::new(
            &proof_bytes.proof_a,
            &proof_bytes.proof_b,
            &proof_bytes.proof_c,
            &expected,
            &committed_vk::VERIFYINGKEY,
        )
        .expect("verifier construction");
        verifier.verify().expect(
            "the committed verifying key must accept a fresh proof over new inputs; if this \
             fails the proving key and the committed vk have drifted apart",
        );
    }

    /// The guard's reason for existing: a proof made under the DEV zkey is
    /// internally valid and verifies against its OWN key, so every check in the
    /// prove pipeline passes. Only a comparison against the COMMITTED key, which
    /// is now a ceremony output, catches it. Without this the user finds out by
    /// paying to submit a transaction the program rejects.
    ///
    /// Asserts the failure is the specific mismatch, and that the message points
    /// at the fix rather than just saying "verification failed".
    #[test]
    #[ignore = "requires the built r1cs/wasm/dev zkey (bash circuits/build.sh); set MIRROR_PROVE_LIVE=1"]
    fn a_dev_key_proof_is_refused_before_it_can_be_emitted() {
        if std::env::var("MIRROR_PROVE_LIVE").ok().as_deref() != Some("1") {
            eprintln!("MIRROR_PROVE_LIVE != 1; skipping dev-key refusal test");
            return;
        }
        let repo = repo_root();
        let dev_zkey = repo.join("circuits/membership_final.zkey");
        assert!(
            dev_zkey.exists(),
            "this test needs the dev zkey at {} (bash circuits/build.sh)",
            dev_zkey.display()
        );

        // Prove the FIXTURE witness under the DEV key. The witness is fine; only
        // the proving key is wrong for the deployed program.
        let f = fixture_witness();
        let (root, nullifier_hash, action_hash, epoch) =
            (f.path.root, f.nullifier_hash, f.action_hash, f.epoch);
        let input = membership_input_json(
            &root,
            &nullifier_hash,
            &action_hash,
            epoch,
            &f.secret.0,
            &f.path,
        );
        let expected = membership_public_inputs(&root, &nullifier_hash, &action_hash, epoch);
        let wasm = repo.join("circuits/membership_js/membership.wasm");
        let r1cs = repo.join("circuits/membership.r1cs");
        let art = crate::prove_rust::Artifacts {
            wasm: &wasm,
            r1cs: &r1cs,
            zkey: &dev_zkey,
        };
        let proof_bytes = crate::prove_rust::prove(&art, &input, &expected).expect(
            "proving under the dev key must SUCCEED: the proof is valid, just for the wrong key",
        );

        // The guard is the only thing standing between that and a wasted fee.
        let err =
            check_against_committed_vk(&proof_bytes, &root, &nullifier_hash, &action_hash, epoch)
                .expect_err("a dev-key proof MUST be refused against the committed ceremony key");
        let msg = format!("{err}");
        assert!(
            msg.contains("does NOT verify against the committed membership verifying key"),
            "unexpected error text: {msg}"
        );
        assert!(
            msg.contains("--proving-key"),
            "the error must tell the user how to fix it, got: {msg}"
        );
    }

    /// THE decisive ceremony test: run a real multi-contribution phase-2 ceremony
    /// over the membership circuit's phase-1-derived initial key, then prove the
    /// membership circuit under the CEREMONY-produced proving key and confirm the
    /// EXACT on-chain `groth16-solana` verifier accepts that proof against the
    /// CEREMONY-exported verifying key.
    ///
    /// It also asserts the ceremony key is genuinely different from the committed
    /// dev key (only `delta` moves, which is exactly what phase 2 re-randomizes),
    /// so the check cannot pass by accidentally using the old key.
    ///
    /// Gated behind MIRROR_PROVE_LIVE=1 + #[ignore] because it needs the gitignored
    /// build artifacts: the r1cs, the wasm, the public powers-of-tau, and the
    /// initial zkey from `snarkjs groth16 setup`. Run with:
    ///   MIRROR_PROVE_LIVE=1 cargo test -p mirror-cli -- --ignored ceremony_key
    #[test]
    #[ignore = "requires the built r1cs/wasm/ptau/initial zkey (bash circuits/build.sh); set MIRROR_PROVE_LIVE=1"]
    fn ceremony_key_proves_and_on_chain_verifier_accepts() {
        use groth16_solana::groth16::{Groth16Verifier, Groth16Verifyingkey};
        use mirror_ceremony::contribute::Entropy;
        use mirror_ceremony::session::{Session, StartOptions};
        use mirror_ceremony::vk_export;

        if std::env::var("MIRROR_PROVE_LIVE").ok().as_deref() != Some("1") {
            eprintln!("MIRROR_PROVE_LIVE != 1; skipping live ceremony test");
            return;
        }
        let repo = repo_root();
        let r1cs = repo.join("circuits/membership.r1cs");
        let ptau = repo.join("circuits/pot16_final.ptau");
        let initial_zkey = repo.join("circuits/membership_0000.zkey");
        let wasm = repo.join("circuits/membership_js/membership.wasm");
        require_live_artifacts(&[&r1cs, &ptau, &initial_zkey, &wasm]);

        // A scratch ceremony directory, so this exercises the real on-disk flow a
        // contributor follows rather than an in-memory shortcut.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!("mirror-ceremony-e2e-{nanos}"));

        let mut session = Session::start(StartOptions {
            dir: &dir,
            circuit: "membership",
            r1cs: &r1cs,
            ptau: &ptau,
            initial_zkey: &initial_zkey,
        })
        .expect("opening the ceremony");

        // Two contributions plus a closing beacon. Deterministic seeds keep the test
        // reproducible; the ceremony records that and refuses to count them.
        session
            .contribute("test-contributor-a", &Entropy::Deterministic("a".into()))
            .expect("first contribution");
        session
            .contribute("test-contributor-b", &Entropy::Deterministic("b".into()))
            .expect("second contribution");
        session
            .beacon("test-coordinator", b"mirror-pool test beacon", 8)
            .expect("beacon");

        let report = session.verify().expect("the ceremony must verify");
        assert_eq!(report.steps, 3);
        assert_eq!(report.beacon_steps, 1);
        assert_eq!(
            report.independence.independent_contributors, 0,
            "deterministic test contributions must never be counted as independent"
        );

        let key = session.load_head_key().expect("loading the ceremony key");
        let initial = session.load_initial_key().expect("loading the initial key");
        assert_ne!(
            key.delta_g2(),
            initial.delta_g2(),
            "the ceremony must have moved delta"
        );

        let Fixture {
            secret,
            epoch,
            action_hash,
            nullifier_hash,
            path,
            ..
        } = fixture_witness();

        let input = membership_input_json(
            &path.root,
            &nullifier_hash,
            &action_hash,
            epoch,
            &secret.0,
            &path,
        );
        let expected = membership_public_inputs(&path.root, &nullifier_hash, &action_hash, epoch);
        let proof_bytes =
            crate::prove_rust::prove_with_key(&wasm, &r1cs, &key.pk, &input, &expected)
                .expect("proving under the ceremony key must succeed and ark-verify");

        // The ceremony key is NOT the committed dev key: a proof under it must be
        // rejected by the committed verifying key.
        let mut stale = Groth16Verifier::new(
            &proof_bytes.proof_a,
            &proof_bytes.proof_b,
            &proof_bytes.proof_c,
            &expected,
            &committed_vk::VERIFYINGKEY,
        )
        .expect("verifier construction");
        assert!(
            stale.verify().is_err(),
            "a ceremony-key proof must NOT verify under the old dev verifying key"
        );

        // DECISIVE: the EXACT on-chain verifier accepts it under the ceremony vk.
        let exported = vk_export::solana_bytes(&key.pk.vk);
        let ic: &'static [[u8; 64]] = Box::leak(exported.ic.clone().into_boxed_slice());
        let ceremony_vk = Groth16Verifyingkey {
            nr_pubinputs: exported.nr_pubinputs,
            vk_alpha_g1: exported.alpha_g1,
            vk_beta_g2: exported.beta_g2,
            vk_gamme_g2: exported.gamma_g2,
            vk_delta_g2: exported.delta_g2,
            vk_ic: ic,
        };
        // Only delta moved: everything else comes from phase 1 and the circuit.
        assert_eq!(
            ceremony_vk.vk_alpha_g1,
            committed_vk::VERIFYINGKEY.vk_alpha_g1
        );
        assert_eq!(
            ceremony_vk.vk_beta_g2,
            committed_vk::VERIFYINGKEY.vk_beta_g2
        );
        assert_eq!(
            ceremony_vk.vk_gamme_g2,
            committed_vk::VERIFYINGKEY.vk_gamme_g2
        );
        assert_eq!(ceremony_vk.vk_ic, committed_vk::VERIFYINGKEY.vk_ic);
        assert_ne!(
            ceremony_vk.vk_delta_g2,
            committed_vk::VERIFYINGKEY.vk_delta_g2
        );

        let mut verifier = Groth16Verifier::new(
            &proof_bytes.proof_a,
            &proof_bytes.proof_b,
            &proof_bytes.proof_c,
            &expected,
            &ceremony_vk,
        )
        .expect("verifier construction");
        verifier.verify().expect(
            "on-chain groth16-solana verifier must ACCEPT a proof made under the ceremony key",
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
