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
//! 3. Generate the Groth16 proof IN-PROCESS in pure Rust (the default) via
//!    [`crate::prove_rust`]: `ark-circom` runs the compiled `membership.wasm`
//!    witness calculator under the `wasmer` VM, reads the proving key from
//!    `membership_final.zkey`, and `ark-groth16` produces + verifies the proof - no
//!    Node/snarkjs process is spawned. A `--use-snarkjs` fallback still shells out
//!    to `snarkjs groth16 fullprove` + `verify` for parity checks.
//! 4. Serialize the proof + public inputs into the exact `SettleZk` instruction
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
use crate::util::{be32_to_decimal, from_hex32, to_hex};

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
    pub epoch: u64,
    pub amount: u64,
    pub root_hex: String,
    pub nullifier_hash_hex: String,
    pub action_hash_hex: String,
    /// The full `SettleZk` instruction data (tag + body), hex, `SETTLE_ZK_LEN` bytes.
    pub settle_zk_data_hex: String,
}

pub fn run(opts: ProveOpts) -> Result<SettleZkEmit> {
    let note = Note::load(&opts.note_path)?;

    // A ZK proof only exists for the transfer (opt-in) path.
    let (recipient_str, amount) = match &note.action {
        ActionRecord::Transfer { recipient, amount } => (recipient.clone(), *amount),
        ActionRecord::Crowd { .. } => bail!(
            "note {} is a crowd-path note; `prove` is only for ZK opt-in (deposit-commit) notes",
            opts.note_path.display()
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

    // (1) Recompute the bound values and confirm the leaf matches the note.
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

    // (2) Rebuild the inclusion path off-chain.
    let path = build_path(&note, &leaf, opts.leaves.as_deref())?;
    if path.elements.len() != tree::DEPTH {
        bail!(
            "rebuilt path has {} levels, expected {}",
            path.elements.len(),
            tree::DEPTH
        );
    }
    // The path must verify to its own root (self-check on the client-side rebuild).
    let recomputed = tree::verify_path(&leaf, &path.elements, &path.indices);
    if recomputed != path.root {
        bail!("client-side path does not verify to its root (rebuild bug)");
    }

    // Confirm the Pool currently accepts this root (current root or in the ring).
    let chain = Chain::new(opts.rpc_url.clone());
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

    // (3) Generate + verify the Groth16 proof. Default: in-process pure Rust
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

    // (4) Serialize into SettleZk instruction data.
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
        epoch: note.epoch,
        amount,
        root_hex: to_hex(&path.root),
        nullifier_hash_hex: to_hex(&nullifier_hash),
        action_hash_hex: to_hex(&action_hash),
        settle_zk_data_hex: to_hex(&data),
    };

    if let Some(out) = &opts.out {
        let json = serde_json::to_string_pretty(&emit).context("serializing emit")?;
        std::fs::write(out, json).with_context(|| format!("writing {}", out.display()))?;
    }
    Ok(emit)
}

/// Rebuild the inclusion path: from `--leaves` (full rebuild vs current root) if
/// given, otherwise from the note's frontier snapshot (walk-the-frontier).
fn build_path(note: &Note, leaf: &Hash32, leaves: Option<&Path>) -> Result<MerklePath> {
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

/// Read a leaf set: one 64-char hex commitment per non-empty line, in order.
fn read_leaves(path: &Path) -> Result<Vec<Hash32>> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading leaves file {}", path.display()))?;
    let mut leaves = Vec::new();
    for (i, line) in raw.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        leaves.push(
            from_hex32(line)
                .with_context(|| format!("leaf on line {} of {}", i + 1, path.display()))?,
        );
    }
    Ok(leaves)
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
        let fixture: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../circuits/artifacts/proof_fixture.json"
        )))
        .unwrap();
        let ps = fixture["publicSignals"].as_array().unwrap();
        let want_root = ps[0].as_str().unwrap();
        let want_nullifier = ps[1].as_str().unwrap();
        let want_action = ps[2].as_str().unwrap();
        let epoch: u64 = ps[3].as_str().unwrap().parse().unwrap();

        // Rebuild the fixture inputs with mirror-core + our tree code.
        let secret = mirror_core::Secret::from_bytes(
            groth16::to_be32("111122223333444455556666777788889999").unwrap(),
        );
        let mut recipient = [0u8; 32];
        for (i, b) in recipient.iter_mut().enumerate() {
            *b = (i + 1) as u8;
        }
        let amount: u64 = 250_000_000;
        let action_hash = transfer_action_hash(&recipient, amount);
        let nullifier_hash = nullifier(&secret, Epoch(epoch)).0;
        let leaf = commit_with_action_hash(&secret, &action_hash, Epoch(epoch)).0;

        // Single leaf at index 21: every sibling is the empty-subtree hash for
        // its level (the fixture's sparse membership vector).
        let zeros = tree::zero_ladder(tree::DEPTH);
        let leaf_index: u64 = 21;
        let mut elements = Vec::with_capacity(tree::DEPTH);
        let mut indices = Vec::with_capacity(tree::DEPTH);
        for (level, zero) in zeros.iter().enumerate().take(tree::DEPTH) {
            elements.push(*zero);
            indices.push(((leaf_index >> level) & 1) as u8);
        }
        let root = tree::verify_path(&leaf, &elements, &indices);

        assert_eq!(be32_to_decimal(&root), want_root, "root must match fixture");
        assert_eq!(
            be32_to_decimal(&nullifier_hash),
            want_nullifier,
            "nullifierHash must match fixture"
        );
        assert_eq!(
            be32_to_decimal(&action_hash),
            want_action,
            "actionHash must match fixture"
        );
    }

    /// End-to-end `prove` proof generation through snarkjs against the REAL
    /// zkey/wasm. Gated behind MIRROR_PROVE_LIVE=1 and #[ignore] so CI without
    /// node/snarkjs/zkey still passes; the Surfpool soak exercises it live.
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
        // Resolve circuit artifacts relative to the repo root (crate is crates/mirror-cli).
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        let wasm = root.join("circuits/membership_js/membership.wasm");
        let zkey = root.join("circuits/membership_final.zkey");
        let vk = root.join("circuits/artifacts/verification_key.json");

        // Reproduce the fixture witness (single leaf at index 21).
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
        // Single leaf at index 21: every sibling is the empty-subtree hash for its
        // level, reproducing the committed fixture's exact membership vector.
        let zeros = tree::zero_ladder(tree::DEPTH);
        let mut elements = Vec::with_capacity(tree::DEPTH);
        let mut indices = Vec::with_capacity(tree::DEPTH);
        for (level, zero) in zeros.iter().enumerate().take(tree::DEPTH) {
            elements.push(*zero);
            indices.push(((21u64 >> level) & 1) as u8);
        }
        let root = tree::verify_path(&leaf, &elements, &indices);
        let path = MerklePath {
            elements,
            indices,
            root,
        };

        let work = std::env::temp_dir().join("mirror-cli-prove-live-test");
        std::fs::create_dir_all(&work).unwrap();
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
        let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();

        // Reproduce the committed fixture witness (single leaf at index 21 in an
        // otherwise-empty depth-20 tree), so the public signals also match the
        // committed proof_fixture.json.
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
            indices.push(((21u64 >> level) & 1) as u8);
        }
        let root = tree::verify_path(&leaf, &elements, &indices);
        let path = MerklePath {
            elements,
            indices,
            root,
        };

        // Cross-check the reproduced public signals against the committed fixture.
        let fixture: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../circuits/artifacts/proof_fixture.json"
        )))
        .unwrap();
        let ps = fixture["publicSignals"].as_array().unwrap();
        assert_eq!(be32_to_decimal(&path.root), ps[0].as_str().unwrap());
        assert_eq!(be32_to_decimal(&nullifier_hash), ps[1].as_str().unwrap());
        assert_eq!(be32_to_decimal(&action_hash), ps[2].as_str().unwrap());

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
        let proof_bytes = crate::prove_rust::prove(
            &crate::prove_rust::Artifacts {
                wasm: &repo.join("circuits/membership_js/membership.wasm"),
                r1cs: &repo.join("circuits/membership.r1cs"),
                zkey: &repo.join("circuits/membership_final.zkey"),
            },
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
        let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        let r1cs = repo.join("circuits/membership.r1cs");
        let ptau = repo.join("circuits/pot16_final.ptau");
        let initial_zkey = repo.join("circuits/membership_0000.zkey");
        for p in [&r1cs, &ptau, &initial_zkey] {
            if !p.exists() {
                eprintln!("missing {}; skipping", p.display());
                return;
            }
        }

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

        // Reproduce the fixture witness (single leaf at index 21).
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
            indices.push(((21u64 >> level) & 1) as u8);
        }
        let root = tree::verify_path(&leaf, &elements, &indices);
        let path = MerklePath {
            elements,
            indices,
            root,
        };

        let input = membership_input_json(
            &path.root,
            &nullifier_hash,
            &action_hash,
            epoch,
            &secret.0,
            &path,
        );
        let expected = membership_public_inputs(&path.root, &nullifier_hash, &action_hash, epoch);
        let proof_bytes = crate::prove_rust::prove_with_key(
            &repo.join("circuits/membership_js/membership.wasm"),
            &r1cs,
            &key.pk,
            &input,
            &expected,
        )
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
