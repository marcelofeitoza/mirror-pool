//! Opt-in association-set (Privacy-Pools-style) tooling: the prover side and the
//! curator side.
//!
//! PROVER SIDE (`prove-associated`). Same pipeline as [`crate::prove`], with one
//! extra inclusion proof:
//!
//! 1. Recompute this note's `actionHash`, `nullifierHash`, and commitment leaf,
//!    and check the leaf matches the note's commitment.
//! 2. Rebuild the POOL inclusion path (frontier snapshot or full `--leaves`
//!    rebuild) and confirm the root is one the Pool currently accepts.
//! 3. Rebuild the ASSOCIATION inclusion path from the curator's published leaf
//!    list, and confirm the resulting root is one the curator's AssociationSet
//!    account currently accepts. If our commitment is not in the curator's list,
//!    stop here with a clear message: this curator does not vouch for this
//!    deposit, and no proof exists.
//! 4. Generate the Groth16 proof for `circuits/association.circom` IN-PROCESS in
//!    pure Rust via [`crate::prove_rust`] (no Node process), or through the
//!    `--use-snarkjs` fallback.
//! 5. Serialize into the exact `SettleZkAssociated` instruction data.
//!
//! CURATOR SIDE (`assoc build-root`). Reads a curated leaf list, rebuilds the
//! Merkle root the circuit will check against, and emits the root plus the
//! ready-to-submit `UpdateAssociationRoot` instruction data. The curator is
//! expected to PUBLISH the same leaf list, so that anyone can rebuild the root
//! themselves and confirm the curator is curating what it claims. The chain
//! cannot check that; only publication can. See `docs/COMPLIANCE.md`.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use mirror_core::{wire, Hash32};
use serde::Serialize;
use solana_pubkey::Pubkey;

use crate::chain;
use crate::groth16;
use crate::note::Note;
use crate::tree::{self, MerklePath};
use crate::util::{be32_to_decimal, read_leaves, to_hex};

/// `prove-associated` arguments. A superset of [`crate::prove::ProveOpts`]: the
/// association circuit's artifacts replace the membership ones, and the curator's
/// identity plus leaf list are new.
pub struct ProveAssociatedOpts {
    pub note_path: PathBuf,
    pub rpc_url: String,
    /// Compiled association-circuit witness calculator (gitignored build output).
    pub wasm: PathBuf,
    /// Compiled association R1CS (gitignored build output).
    pub r1cs: PathBuf,
    /// Association proving key (gitignored build output).
    pub zkey: PathBuf,
    /// Association verifying key JSON (only used by the `--use-snarkjs` fallback).
    pub vk: PathBuf,
    /// snarkjs invocation for the `--use-snarkjs` fallback.
    pub snarkjs: String,
    /// Use the legacy snarkjs shell-out instead of the in-process Rust prover.
    pub use_snarkjs: bool,
    /// The curator whose association set we prove against. Together with the pool
    /// this fixes the AssociationSet PDA.
    pub curator: Pubkey,
    /// The curator's published leaf list (hex commitments, one per line, in the
    /// curator's own ordering). The association root is rebuilt from this.
    pub association_leaves: PathBuf,
    /// Optional full pool leaf set to rebuild the whole pool tree and prove
    /// against the CURRENT pool root instead of the note's frontier snapshot.
    pub leaves: Option<PathBuf>,
    /// Where to write input.json / proof.json / public.json (snarkjs path only).
    pub work_dir: Option<PathBuf>,
    /// Optional path to also write the emitted `SettleZkAssociated` JSON to.
    pub out: Option<PathBuf>,
}

/// The `SettleZkAssociated` bundle `prove-associated` emits: instruction data
/// plus the accounts the relay/coordinator must pass.
#[derive(Serialize)]
pub struct SettleZkAssociatedEmit {
    pub program_id: String,
    pub pool: String,
    /// The pool authority (relay) that MUST sign `SettleZkAssociated`.
    pub authority: String,
    pub nullifier_pda: String,
    pub recipient: String,
    pub system_program: String,
    pub clock_sysvar: String,
    /// The curator whose set this settlement is attesting against.
    pub curator: String,
    /// The AssociationSet PDA, seeds `["assoc", pool, curator]`.
    pub association_pda: String,
    /// The write-once, digest-pinned ASSOCIATION verifying-key registry PDA. The
    /// program reads its verifying key from here rather than from its own code,
    /// so a submitter MUST pass this account; it must already be installed
    /// (`mirror-cli init-vk --circuit association`).
    pub vk_registry: String,
    pub epoch: u64,
    pub amount: u64,
    pub root_hex: String,
    pub nullifier_hash_hex: String,
    pub action_hash_hex: String,
    pub association_root_hex: String,
    /// Size of the curated set this proof hides inside. This is the honest
    /// anonymity bound for the ASSOCIATION half of the statement: a settlement
    /// against a one-leaf set is fully deanonymized regardless of how large the
    /// pool is.
    pub association_set_size: usize,
    /// The full `SettleZkAssociated` instruction data (tag + body), hex,
    /// `SETTLE_ZK_ASSOCIATED_LEN` bytes.
    pub settle_zk_associated_data_hex: String,
}

pub fn run(opts: ProveAssociatedOpts) -> Result<SettleZkAssociatedEmit> {
    let note = Note::load(&opts.note_path)?;
    // (1)+(2) Bind and validate the note, rebuild the POOL path, check the root.
    let crate::prove::ZkWitness {
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
        ..
    } = crate::prove::resolve_zk_note(
        &note,
        &opts.note_path,
        opts.leaves.as_deref(),
        &opts.rpc_url,
        "prove-associated",
    )?;

    // (3) Rebuild the ASSOCIATION inclusion path from the curator's leaf list.
    let assoc_path = build_association_path(&opts.association_leaves, &leaf)?;
    let assoc_pda = chain::association_pda(&program_id, &pool, &opts.curator);
    let assoc_state = chain.association_state(&assoc_pda).with_context(|| {
        format!(
            "reading the association set {assoc_pda} for curator {} (has the curator run \
             `InitAssociation` for this pool?)",
            opts.curator
        )
    })?;
    // Re-check on the client what the program will re-check on chain, so a
    // misconfiguration is a clear local error rather than a failed transaction.
    if assoc_state.pool != pool {
        bail!(
            "association set {assoc_pda} curates pool {} but this note is for pool {pool}",
            assoc_state.pool
        );
    }
    if assoc_state.curator != opts.curator {
        bail!(
            "association set {assoc_pda} names curator {} but {} was requested (PDA collision or \
             a stale account)",
            assoc_state.curator,
            opts.curator
        );
    }
    if assoc_state.update_count == 0 {
        bail!(
            "curator {} has registered an association set but never published a root, so it \
             vouches for nothing yet",
            opts.curator
        );
    }
    if !assoc_state.is_known_root(&assoc_path.path.root) {
        bail!(
            "association root {} rebuilt from {} is not a root curator {} has recently published \
             (the curated list may be stale, or the curator may have republished more than {} \
             times since; re-fetch the curator's list)",
            to_hex(&assoc_path.path.root),
            opts.association_leaves.display(),
            opts.curator,
            assoc_state.root_ring.len()
        );
    }

    // (4) Generate + verify the Groth16 association proof.
    let input = association_input_json(
        &path.root,
        &nullifier_hash,
        &action_hash,
        note.epoch,
        &assoc_path.path.root,
        &secret.0,
        &path,
        &assoc_path.path,
    );
    let expected = association_public_inputs(
        &path.root,
        &nullifier_hash,
        &action_hash,
        note.epoch,
        &assoc_path.path.root,
    );
    let proof_bytes = if opts.use_snarkjs {
        prove_with_snarkjs(&opts, &input, &expected, &path.root)?
    } else {
        crate::prove_rust::prove(
            &crate::prove_rust::Artifacts {
                wasm: &opts.wasm,
                r1cs: &opts.r1cs,
                zkey: &opts.zkey,
            },
            &input,
            &expected,
        )
        .context("in-process Rust Groth16 proving (association circuit)")?
    };

    // (5) Serialize into SettleZkAssociated instruction data.
    let data = groth16::settle_zk_associated_data(
        note.epoch,
        amount,
        &proof_bytes,
        &path.root,
        &nullifier_hash,
        &action_hash,
        &assoc_path.path.root,
    );
    if data.len() != wire::SETTLE_ZK_ASSOCIATED_LEN {
        bail!(
            "assembled SettleZkAssociated data is {} bytes, expected {}",
            data.len(),
            wire::SETTLE_ZK_ASSOCIATED_LEN
        );
    }

    let nf_pda = chain::nullifier_pda(&program_id, &pool, note.epoch, &nullifier_hash);
    let emit = SettleZkAssociatedEmit {
        program_id: program_id.to_string(),
        pool: pool.to_string(),
        authority: pool_state.authority.to_string(),
        nullifier_pda: nf_pda.to_string(),
        recipient: recipient.to_string(),
        system_program: chain::SYSTEM_PROGRAM_ID.to_string(),
        clock_sysvar: chain::CLOCK_SYSVAR_ID.to_string(),
        curator: opts.curator.to_string(),
        association_pda: assoc_pda.to_string(),
        vk_registry: chain::vk_registry_pda(&program_id, wire::CIRCUIT_ASSOCIATION).to_string(),
        epoch: note.epoch,
        amount,
        root_hex: to_hex(&path.root),
        nullifier_hash_hex: to_hex(&nullifier_hash),
        action_hash_hex: to_hex(&action_hash),
        association_root_hex: to_hex(&assoc_path.path.root),
        association_set_size: assoc_path.set_size,
        settle_zk_associated_data_hex: to_hex(&data),
    };

    if let Some(out) = &opts.out {
        let json = serde_json::to_string_pretty(&emit).context("serializing emit")?;
        std::fs::write(out, json).with_context(|| format!("writing {}", out.display()))?;
    }
    Ok(emit)
}

/// A rebuilt association inclusion path plus the size of the curated set it was
/// built from (the honest anonymity bound for the association half).
#[derive(Debug)]
pub struct AssociationPath {
    pub path: MerklePath,
    pub set_size: usize,
}

/// Rebuild the association inclusion path for `leaf` from a curator's published
/// leaf list.
///
/// Fails loudly, and specifically, when the leaf is absent: "the curator does not
/// vouch for this deposit" is the single most important error this tool can
/// produce, and it must never be confused with a build or path bug.
pub fn build_association_path(leaves_path: &Path, leaf: &Hash32) -> Result<AssociationPath> {
    let leaf_set = read_leaves(leaves_path)?;
    if leaf_set.is_empty() {
        bail!(
            "curated leaf list {} is empty: there is no association set to prove against",
            leaves_path.display()
        );
    }
    let index = leaf_set.iter().position(|l| l == leaf).ok_or_else(|| {
        anyhow!(
            "this note's commitment {} is NOT in the curated list {} ({} leaves). This curator \
             does not vouch for this deposit, so no association proof exists. The plain `prove` / \
             SettleZk path is unaffected and still settles this note.",
            to_hex(leaf),
            leaves_path.display(),
            leaf_set.len()
        )
    })?;
    let mtree = tree::SparseMerkle::from_leaves(tree::DEPTH, &leaf_set);
    let path = mtree.path(index);
    if tree::verify_path(leaf, &path.elements, &path.indices) != path.root {
        bail!("client-side association path does not verify to its root (rebuild bug)");
    }
    Ok(AssociationPath {
        path,
        set_size: leaf_set.len(),
    })
}

/// The circom `input.json` object for the association circuit (decimal field
/// elements), shared by the in-process Rust prover and the snarkjs fallback.
#[allow(clippy::too_many_arguments)]
pub fn association_input_json(
    root: &Hash32,
    nullifier_hash: &Hash32,
    action_hash: &Hash32,
    epoch: u64,
    association_root: &Hash32,
    secret: &Hash32,
    pool_path: &MerklePath,
    assoc_path: &MerklePath,
) -> serde_json::Value {
    serde_json::json!({
        "root": be32_to_decimal(root),
        "nullifierHash": be32_to_decimal(nullifier_hash),
        "actionHash": be32_to_decimal(action_hash),
        "epoch": epoch.to_string(),
        "associationRoot": be32_to_decimal(association_root),
        "secret": be32_to_decimal(secret),
        "pathElements": pool_path.elements.iter().map(be32_to_decimal).collect::<Vec<_>>(),
        "pathIndices": pool_path.indices.iter().map(|b| b.to_string()).collect::<Vec<_>>(),
        "assocPathElements": assoc_path.elements.iter().map(be32_to_decimal).collect::<Vec<_>>(),
        "assocPathIndices": assoc_path.indices.iter().map(|b| b.to_string()).collect::<Vec<_>>(),
    })
}

/// The five association public inputs, in circuit-declaration order
/// `[root, nullifierHash, actionHash, epoch, associationRoot]`, each 32-byte
/// big-endian. `epoch` is the big-endian encoding of the u64.
pub fn association_public_inputs(
    root: &Hash32,
    nullifier_hash: &Hash32,
    action_hash: &Hash32,
    epoch: u64,
    association_root: &Hash32,
) -> [Hash32; wire::ASSOCIATION_N_PUBLIC_INPUTS] {
    let mut epoch_be = [0u8; 32];
    epoch_be[24..].copy_from_slice(&epoch.to_be_bytes());
    [
        *root,
        *nullifier_hash,
        *action_hash,
        epoch_be,
        *association_root,
    ]
}

/// Legacy fallback: shell out to snarkjs `groth16 fullprove` + `verify` against
/// the association artifacts. Behind `--use-snarkjs`.
fn prove_with_snarkjs(
    opts: &ProveAssociatedOpts,
    input: &serde_json::Value,
    expected: &[Hash32],
    root: &Hash32,
) -> Result<groth16::ProofBytes> {
    let work_dir = match &opts.work_dir {
        Some(d) => d.clone(),
        None => std::env::temp_dir().join(format!("mirror-cli-prove-assoc-{}", to_hex(root))),
    };
    std::fs::create_dir_all(&work_dir)
        .with_context(|| format!("creating work dir {}", work_dir.display()))?;

    let input_path = work_dir.join("input.json");
    std::fs::write(&input_path, serde_json::to_string_pretty(input)?)
        .with_context(|| format!("writing {}", input_path.display()))?;

    let proof_path = work_dir.join("proof.json");
    let public_path = work_dir.join("public.json");
    crate::prove::run_fullprove(
        &opts.snarkjs,
        &input_path,
        &opts.wasm,
        &opts.zkey,
        &proof_path,
        &public_path,
    )?;
    crate::prove::verify_proof(&opts.snarkjs, &opts.vk, &public_path, &proof_path)?;

    // Cross-check snarkjs's public signals against our computed public inputs, in
    // the fixed circuit-declaration order.
    let raw = std::fs::read_to_string(&public_path)
        .with_context(|| format!("reading {}", public_path.display()))?;
    let signals: Vec<String> = serde_json::from_str(&raw).context("parsing snarkjs public.json")?;
    if signals.len() != expected.len() {
        bail!(
            "public.json has {} signals, expected {} [root, nullifierHash, actionHash, epoch, \
             associationRoot]",
            signals.len(),
            expected.len()
        );
    }
    let names = [
        "root",
        "nullifierHash",
        "actionHash",
        "epoch",
        "associationRoot",
    ];
    for (i, (signal, want)) in signals.iter().zip(expected.iter()).enumerate() {
        let want_dec = be32_to_decimal(want);
        if signal != &want_dec {
            bail!(
                "public signal {i} ({}) from snarkjs ({signal}) does not match the computed value \
                 ({want_dec})",
                names[i]
            );
        }
    }

    let proof_json = std::fs::read_to_string(&proof_path)
        .with_context(|| format!("reading {}", proof_path.display()))?;
    groth16::SnarkjsProof::parse(&proof_json)?.to_bytes()
}

// ---------------------------------------------------------------------------
// Curator side.
// ---------------------------------------------------------------------------

/// What `assoc build-root` produces for a curator.
#[derive(Serialize)]
pub struct AssociationRootEmit {
    /// The Merkle root of the curated list, as the circuit and the on-chain
    /// account see it.
    pub association_root_hex: String,
    /// Number of curated leaves. This is the anonymity set an attestation against
    /// this root hides inside: publish a small set and you have published a
    /// deanonymization.
    pub set_size: usize,
    /// The AssociationSet PDA this root is meant for, when the caller supplied
    /// enough context to derive it.
    pub association_pda: Option<String>,
    /// Ready-to-submit `UpdateAssociationRoot` instruction data (tag + root), hex.
    pub update_root_data_hex: String,
}

/// Rebuild the association root from a curated leaf list and emit the
/// `UpdateAssociationRoot` instruction data.
///
/// `program_id` / `pool` / `curator` are optional and only used to also report
/// the AssociationSet PDA the curator should pass.
pub fn build_root(
    leaves_path: &Path,
    context: Option<(&Pubkey, &Pubkey, &Pubkey)>,
) -> Result<AssociationRootEmit> {
    let leaves = read_leaves(leaves_path)?;
    if leaves.is_empty() {
        bail!(
            "curated leaf list {} is empty; refusing to publish a root over nothing",
            leaves_path.display()
        );
    }
    // Duplicate leaves would silently shrink the real anonymity set below the
    // reported size, so reject them rather than quietly publishing a misleading
    // set_size.
    let mut sorted = leaves.clone();
    sorted.sort_unstable();
    sorted.dedup();
    if sorted.len() != leaves.len() {
        bail!(
            "curated leaf list {} contains {} duplicate entries; every leaf must be distinct so \
             the reported set size is the real anonymity set",
            leaves_path.display(),
            leaves.len() - sorted.len()
        );
    }

    let mtree = tree::SparseMerkle::from_leaves(tree::DEPTH, &leaves);
    let root = mtree.root();
    if root == [0u8; 32] {
        // The on-chain account treats all-zero as "unwritten ring slot" and
        // refuses to publish it. Unreachable for a non-empty list (a root is a
        // Poseidon output), but fail closed rather than emit an instruction the
        // program will reject.
        bail!("computed association root is all-zero, which the program refuses to publish");
    }
    let association_pda = context.map(|(program_id, pool, curator)| {
        chain::association_pda(program_id, pool, curator).to_string()
    });
    Ok(AssociationRootEmit {
        association_root_hex: to_hex(&root),
        set_size: leaves.len(),
        association_pda,
        update_root_data_hex: to_hex(&groth16::update_association_root_data(&root)),
    })
}

#[cfg(test)]
mod tests;
