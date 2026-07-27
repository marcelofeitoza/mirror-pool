//! Verify a whole ceremony, from the phase-1-derived initial key to the final key.
//!
//! Everything here is reproducible by anyone holding three public things: the
//! transcript, the initial key (which is itself re-derivable from the public r1cs
//! and the public powers-of-tau), and the final key.
//!
//! # The checks, in order
//!
//! 1. **Header**: the transcript version and the phase-1 record parse, and the
//!    ceremony is not empty.
//! 2. **Initial key**: its digest and both delta points are the ones the transcript
//!    header commits to.
//! 3. For each contribution `i`:
//!    - **Chain link**: `entry.prev_hash` equals the running chain hash. A
//!      reordered, spliced or edited transcript fails here.
//!    - **Index**: `entry.index == i`.
//!    - **Entry hash**: recomputing `SHA-256` over the canonical serialization
//!      reproduces `entry.hash`.
//!    - **Non-null**: the delta actually moved and is not the point at infinity.
//!    - **Proof of knowledge**: the Schnorr proof verifies against a challenge
//!      bound to this position, this contributor id and these delta points. A
//!      forged proof, or one lifted from another entry or another operator, fails
//!      here.
//!    - **Same ratio**: `e(prev_g1, new_g2) == e(new_g1, prev_g2)`, which is what
//!      forces `delta_g2` to have moved by the *same* scalar as `delta_g1`.
//!    - **Beacon**: for a beacon step, the scalar is recomputed from the published
//!      source and the whole step is reproduced point-for-point.
//! 4. **Final key**: its digest and both delta points are the ones the last entry
//!    commits to. A truncated transcript fails here, because the final key's delta
//!    is one (or more) steps ahead of the last entry.
//! 5. **Untouched parts**: `alpha_g1`, `beta_g1`, `beta_g2`, `gamma_g2`,
//!    `gamma_abc_g1`, `a_query`, `b_g1_query`, `b_g2_query` are byte-identical
//!    between the initial and final keys.
//! 6. **Query scaling**: a batched pairing check that `h_query` and `l_query` were
//!    divided by exactly the accumulated delta ratio - the step that makes the
//!    final key a *valid* key for the same circuit rather than merely a
//!    consistently-relabelled one.
//!
//! # What is NOT checked here
//!
//! - That the initial key is a correct phase-2 initialization of your circuit.
//!   That is what re-deriving it from the r1cs and the public powers-of-tau is
//!   for; the digest comparison is the check, and `snarkjs groth16 setup` is
//!   deterministic, so it is a real one.
//! - The intermediate keys. Only their digests are in the transcript. A contributor
//!   who still holds an intermediate file can compare its digest against the entry
//!   that claims to have produced it; a verifier who only has the endpoints relies
//!   on the per-step algebraic checks plus the endpoint scaling check.
//! - Whether any contributor actually destroyed their scalar. No protocol can
//!   check that.

use ark_bn254::{Bn254, Fr, G1Affine, G1Projective, G2Affine};
use ark_ec::{pairing::Pairing, AffineRepr, VariableBaseMSM};
use ark_ff::PrimeField;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::error::{CeremonyError, Check};
use crate::hexfmt;
use crate::independence::{self, IndependenceReport};
use crate::key::CeremonyKey;
use crate::points;
use crate::pok;
use crate::transcript::{entry_hash, ContributionKind, Transcript, TRANSCRIPT_VERSION};
use crate::Result;

const BATCH_TAG: &[u8] = b"mirror-pool/ceremony/v1/batch";

/// What a successful verification establishes, in a form that can be printed or
/// serialized next to the transcript.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    /// Circuit label from the transcript.
    pub circuit: String,
    /// `SHA-256` of the circuit r1cs the transcript is pinned to, hex.
    pub circuit_r1cs_digest: String,
    /// Number of steps in the chain (entropy contributions plus beacons).
    pub steps: usize,
    /// How many of those steps were beacons.
    pub beacon_steps: usize,
    /// Digest of the initial (phase-1-derived) key, hex.
    pub initial_key_digest: String,
    /// Digest of the final key, hex.
    pub final_key_digest: String,
    /// The final chain hash, hex. This is the single value to publish and compare.
    pub final_transcript_hash: String,
    /// Phase-1 file digest, hex.
    pub phase1_digest: String,
    /// Phase-1 contribution count.
    pub phase1_contributions: u32,
    /// Whether phase 1 looks like a public multi-contributor file.
    pub phase1_looks_public: bool,
    /// The conservative independent-contributor count and its caveats.
    pub independence: IndependenceReport,
}

/// Verify a ceremony end to end.
pub fn verify(
    transcript: &Transcript,
    initial: &CeremonyKey,
    final_key: &CeremonyKey,
) -> Result<Report> {
    // 1. Header.
    if transcript.version != TRANSCRIPT_VERSION {
        return Err(CeremonyError::whole(
            Check::Header,
            format!(
                "unsupported transcript version {} (expected {TRANSCRIPT_VERSION})",
                transcript.version
            ),
        ));
    }
    if transcript.contributions.is_empty() {
        return Err(CeremonyError::whole(
            Check::Empty,
            "a transcript with no contributions is not a ceremony",
        ));
    }

    // 2. Initial key binding.
    let declared_initial = hexfmt::decode32("initial_key_digest", &transcript.initial_key_digest)?;
    if initial.digest() != declared_initial {
        return Err(CeremonyError::whole(
            Check::InitialKey,
            format!(
                "supplied initial key digest {} does not match the transcript's {}",
                hexfmt::encode(&initial.digest()),
                transcript.initial_key_digest
            ),
        ));
    }
    let header_g1 = points::g1_from_bytes(
        "initial delta_g1",
        &hexfmt::decode(
            "initial_delta_g1",
            &transcript.initial_delta_g1,
            Some(points::G1_LEN),
        )?,
    )?;
    let header_g2 = points::g2_from_bytes(
        "initial delta_g2",
        &hexfmt::decode(
            "initial_delta_g2",
            &transcript.initial_delta_g2,
            Some(points::G2_LEN),
        )?,
    )?;
    if header_g1 != initial.delta_g1() || header_g2 != initial.delta_g2() {
        return Err(CeremonyError::whole(
            Check::InitialKey,
            "the transcript header's delta points are not the initial key's",
        ));
    }

    // 3. Walk the chain.
    let mut running_hash = transcript.genesis_hash()?;
    let mut prev_g1 = initial.delta_g1();
    let mut prev_g2 = initial.delta_g2();
    let mut beacon_steps = 0usize;

    for (i, rec) in transcript.contributions.iter().enumerate() {
        let recorded_prev = hexfmt::decode32("prev_hash", &rec.prev_hash)?;
        if recorded_prev != running_hash {
            return Err(CeremonyError::at(
                i,
                Check::ChainLink,
                format!(
                    "prev_hash is {} but the chain is at {}",
                    rec.prev_hash,
                    hexfmt::encode(&running_hash)
                ),
            ));
        }
        if rec.index as usize != i {
            return Err(CeremonyError::at(
                i,
                Check::Index,
                format!("entry declares index {} at position {i}", rec.index),
            ));
        }

        let recomputed = entry_hash(&running_hash, rec)?;
        let recorded_hash = hexfmt::decode32("contribution hash", &rec.hash)?;
        if recomputed != recorded_hash {
            return Err(CeremonyError::at(
                i,
                Check::EntryHash,
                format!(
                    "recorded {} but recomputed {}",
                    rec.hash,
                    hexfmt::encode(&recomputed)
                ),
            ));
        }

        let (new_g1, new_g2) = rec.deltas()?;
        if new_g1.is_zero() || new_g2.is_zero() {
            return Err(CeremonyError::at(
                i,
                Check::NullContribution,
                "the new delta is the point at infinity",
            ));
        }
        if new_g1 == prev_g1 || new_g2 == prev_g2 {
            return Err(CeremonyError::at(
                i,
                Check::NullContribution,
                "the delta did not change, so this step contributed nothing",
            ));
        }

        let statement = pok::Statement {
            prev_hash: &running_hash,
            index: rec.index,
            contributor_id: &rec.contributor_id,
            prev_delta_g1: prev_g1,
            prev_delta_g2: prev_g2,
            new_delta_g1: new_g1,
            new_delta_g2: new_g2,
        };
        let proof = pok::Pok {
            r: points::g1_from_bytes(
                "pok.r",
                &hexfmt::decode("pok.r", &rec.pok.r, Some(points::G1_LEN))?,
            )?,
            z: points::fr_from_bytes(
                "pok.z",
                &hexfmt::decode("pok.z", &rec.pok.z, Some(points::FR_LEN))?,
            )?,
        };
        if !pok::verify(&statement, &proof) {
            return Err(CeremonyError::at(
                i,
                Check::ProofOfKnowledge,
                format!(
                    "the proof of knowledge for contributor {:?} does not verify at this position",
                    rec.contributor_id
                ),
            ));
        }

        if !same_ratio(prev_g1, new_g1, prev_g2, new_g2) {
            return Err(CeremonyError::at(
                i,
                Check::SameRatio,
                "delta_g2 did not move by the same scalar as delta_g1",
            ));
        }

        if let ContributionKind::Beacon {
            source,
            iterations_exp,
        } = &rec.kind
        {
            beacon_steps += 1;
            let bytes = hexfmt::decode("beacon source", source, None)?;
            let s = crate::beacon::scalar(&bytes, *iterations_exp)?;
            let expect_g1: G1Affine = (prev_g1 * s).into();
            let expect_g2: G2Affine = (prev_g2 * s).into();
            if expect_g1 != new_g1 || expect_g2 != new_g2 {
                return Err(CeremonyError::at(
                    i,
                    Check::Beacon,
                    "the delta does not match the published beacon source and iteration count",
                ));
            }
        }

        running_hash = recorded_hash;
        prev_g1 = new_g1;
        prev_g2 = new_g2;
    }

    // 4. Final key binding. A truncated chain is caught here.
    let last = transcript
        .contributions
        .last()
        .expect("non-empty checked above");
    let declared_final = hexfmt::decode32("new_key_digest", &last.new_key_digest)?;
    if final_key.digest() != declared_final {
        return Err(CeremonyError::whole(
            Check::FinalKey,
            format!(
                "supplied final key digest {} does not match the last entry's {}",
                hexfmt::encode(&final_key.digest()),
                last.new_key_digest
            ),
        ));
    }
    if final_key.delta_g1() != prev_g1 || final_key.delta_g2() != prev_g2 {
        return Err(CeremonyError::whole(
            Check::FinalKey,
            "the final key's delta points are not the ones the chain ends at",
        ));
    }

    // 5. Nothing else moved.
    if let Some(part) = initial.first_fixed_part_mismatch(final_key) {
        return Err(CeremonyError::whole(
            Check::FixedPart,
            format!("{part} differs between the initial and final keys"),
        ));
    }

    // 6. h_query / l_query were divided by exactly the accumulated ratio.
    let seed = batch_seed(&initial.digest(), &final_key.digest());
    check_query_scaling(
        "h_query",
        &initial.pk.h_query,
        &final_key.pk.h_query,
        initial.delta_g2(),
        final_key.delta_g2(),
        &seed,
    )?;
    check_query_scaling(
        "l_query",
        &initial.pk.l_query,
        &final_key.pk.l_query,
        initial.delta_g2(),
        final_key.delta_g2(),
        &seed,
    )?;

    Ok(Report {
        circuit: transcript.circuit.clone(),
        circuit_r1cs_digest: transcript.circuit_r1cs_digest.clone(),
        steps: transcript.contributions.len(),
        beacon_steps,
        initial_key_digest: transcript.initial_key_digest.clone(),
        final_key_digest: hexfmt::encode(&final_key.digest()),
        final_transcript_hash: hexfmt::encode(&running_hash),
        phase1_digest: transcript.phase1.digest.clone(),
        phase1_contributions: transcript.phase1.contributions,
        phase1_looks_public: transcript.phase1.looks_public(),
        independence: independence::assess(transcript),
    })
}

/// `e(a1, b2) == e(b1, a2)`, i.e. `a1/b1 == a2/b2` as exponents. This is the check
/// that couples the two groups: it holds exactly when `b1 = a1 * s` and
/// `b2 = a2 * s` for the same `s`.
fn same_ratio(a1: G1Affine, b1: G1Affine, a2: G2Affine, b2: G2Affine) -> bool {
    Bn254::pairing(a1, b2) == Bn254::pairing(b1, a2)
}

/// Deterministic seed for the batching scalars.
///
/// It commits to BOTH key digests, so the scalars cannot be predicted by someone
/// crafting one of the keys: changing the key changes its digest and therefore
/// every scalar in the batch.
fn batch_seed(initial_digest: &[u8; 32], final_digest: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update((BATCH_TAG.len() as u32).to_be_bytes());
    h.update(BATCH_TAG);
    h.update(initial_digest);
    h.update(final_digest);
    h.finalize().into()
}

/// Batched same-ratio check over a whole query vector.
///
/// Instead of one pairing per element, take a pseudorandom linear combination of
/// each vector and do a single same-ratio check on the two aggregates. If any
/// element was scaled by the wrong factor, the aggregates no longer stand in the
/// delta ratio and the pairing check fails except with probability `1/|Fr|`.
fn check_query_scaling(
    label: &'static str,
    initial: &[G1Affine],
    finalized: &[G1Affine],
    initial_delta_g2: G2Affine,
    final_delta_g2: G2Affine,
    seed: &[u8; 32],
) -> Result<()> {
    if initial.len() != finalized.len() {
        return Err(CeremonyError::whole(
            Check::QueryScaling,
            format!(
                "{label} length changed: {} -> {}",
                initial.len(),
                finalized.len()
            ),
        ));
    }
    let scalars = batch_scalars(seed, label, initial.len());
    let agg_initial = msm(label, initial, &scalars)?;
    let agg_final = msm(label, finalized, &scalars)?;

    if agg_initial.is_zero() {
        return Err(CeremonyError::whole(
            Check::QueryScaling,
            format!("{label} aggregates to the point at infinity, so the check would be vacuous"),
        ));
    }
    // `final[j] = initial[j] / D` and `delta_g2_final = delta_g2_initial * D`, so
    // the two pairings must agree: the `D` in the G2 argument cancels the `1/D` in
    // the G1 argument. Written out rather than routed through `same_ratio`, because
    // the argument order here is easy to get backwards.
    if Bn254::pairing(agg_final, final_delta_g2) != Bn254::pairing(agg_initial, initial_delta_g2) {
        return Err(CeremonyError::whole(
            Check::QueryScaling,
            format!("{label} was not divided by the accumulated delta ratio"),
        ));
    }
    Ok(())
}

fn msm(label: &'static str, bases: &[G1Affine], scalars: &[Fr]) -> Result<G1Affine> {
    G1Projective::msm(bases, scalars)
        .map(Into::into)
        .map_err(|len| {
            CeremonyError::whole(
                Check::QueryScaling,
                format!("{label}: multi-scalar multiplication length mismatch at {len}"),
            )
        })
}

/// `n` pseudorandom scalars from `seed` and a label.
fn batch_scalars(seed: &[u8; 32], label: &str, n: usize) -> Vec<Fr> {
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let mut h = Sha256::new();
        h.update(seed);
        h.update((label.len() as u32).to_be_bytes());
        h.update(label.as_bytes());
        h.update((i as u64).to_be_bytes());
        out.push(Fr::from_be_bytes_mod_order(&h.finalize()));
    }
    out
}
