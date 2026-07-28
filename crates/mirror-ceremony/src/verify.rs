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
//!    - **Beacon is final**: nothing may follow a beacon, and there is at most one.
//!    - **Chain link**: `entry.prev_hash` equals the running chain hash. A
//!      reordered, spliced or edited transcript fails here.
//!    - **Index**: `entry.index == i`.
//!    - **Entry hash**: recomputing `SHA-256` over the canonical serialization
//!      reproduces `entry.hash`.
//!    - **Kind/provenance agreement**: `kind` and `entropy_source` must tell the
//!      same story about whether the step is a beacon. A half-finished relabelling
//!      fails here.
//!    - **Non-null**: the delta actually moved and is not the point at infinity.
//!    - **Proof of knowledge**: the Schnorr proof verifies against a challenge
//!      bound to this position, this contributor id, this step's kind and
//!      provenance, and these delta points. A forged proof, one lifted from another
//!      entry or another operator, or one whose step was relabelled, fails here.
//!    - **Same ratio**: `e(prev_g1, new_g2) == e(new_g1, prev_g2)`, which is what
//!      forces `delta_g2` to have moved by the *same* scalar as `delta_g1`.
//!    - **Beacon**: for a beacon step, the scalar is recomputed from the published
//!      source and the whole step is reproduced point-for-point.
//!    - **No disguised beacon**: no step applies the scalar of a beacon this
//!      verification knows about (one recorded in the transcript, or the value the
//!      caller pre-committed to) unless it is recorded as exactly that beacon.
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
//! - **Whether a step recorded as an entropy contribution really came from secret
//!   randomness.** A scalar is a scalar; nothing about the group elements says
//!   where it came from. The metadata is bound into the proof of knowledge, so no
//!   third party can relabel a published step - but the party who knows a step's
//!   ratio can always re-prove it under a different label, and for a beacon that
//!   ratio is public. Supplying the pre-committed beacon value
//!   ([`VerifyOptions::beacon_precommitment`]) is what turns that from an
//!   assumption into a check; without it, this verification cannot rule out that a
//!   step labelled "entropy" was in fact derived from a public value.

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
    /// Whether the chain is closed: its last step, and only its last step, is a
    /// beacon. An open ceremony still verifies - contributors check the chain
    /// before adding to it - but only a closed one is finished.
    pub closed_by_beacon: bool,
    /// Whether the caller supplied the beacon value the ceremony pre-committed to.
    /// When false, this verification could not check that a step recorded as an
    /// entropy contribution was not in fact a relabelled beacon.
    pub beacon_precommitment_checked: bool,
    /// Whether the key-level checks ran: initial-key binding, final-key binding,
    /// untouched-part equality and query scaling. False for a transcript-only
    /// verification, which has no key files to check against.
    pub key_checks: bool,
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

/// What a verifier knows in addition to the transcript and the keys.
#[derive(Default)]
pub struct VerifyOptions<'a> {
    /// The beacon value the ceremony pre-committed to in public, and the iteration
    /// exponent announced with it.
    ///
    /// A beacon is only worth anything if its source was published *before* the
    /// ceremony ended, which means a verifier can hold it independently of the
    /// transcript. Supplying it here turns two assumptions into checks: that the
    /// ceremony was closed by the beacon you were promised, and that no other step
    /// is that same public scalar wearing an "entropy contribution" label.
    pub beacon_precommitment: Option<BeaconPrecommitment<'a>>,
}

/// A publicly pre-committed beacon value.
pub struct BeaconPrecommitment<'a> {
    /// The announced source bytes.
    pub source: &'a [u8],
    /// The announced base-2 log of the iteration count.
    pub iterations_exp: u32,
}

/// A beacon whose scalar this verification can recompute, and therefore recognize
/// wherever it appears in the chain.
struct KnownBeacon {
    source: Vec<u8>,
    iterations_exp: u32,
    scalar: Fr,
    /// True when it came from the caller rather than from the transcript itself.
    precommitted: bool,
}

impl KnownBeacon {
    /// Whether a step is recorded as exactly this beacon.
    fn is_recorded_as(&self, kind: &ContributionKind) -> Result<bool> {
        match kind {
            ContributionKind::Beacon { iterations_exp, .. } => Ok(*iterations_exp
                == self.iterations_exp
                && kind.beacon_source_bytes()? == self.source),
            ContributionKind::Entropy => Ok(false),
        }
    }

    fn describe(&self) -> &'static str {
        if self.precommitted {
            "the pre-committed beacon"
        } else {
            "a beacon recorded in this transcript"
        }
    }
}

/// Verify a ceremony end to end.
///
/// This is [`verify_with`] with no extra knowledge. If you hold the beacon value
/// the ceremony pre-committed to, use [`verify_with`] instead: it is the only way
/// to check mechanically that a step recorded as an entropy contribution is not a
/// relabelled beacon.
pub fn verify(
    transcript: &Transcript,
    initial: &CeremonyKey,
    final_key: &CeremonyKey,
) -> Result<Report> {
    verify_with(transcript, initial, final_key, &VerifyOptions::default())
}

/// Verify a ceremony end to end, using whatever the verifier independently knows.
pub fn verify_with(
    transcript: &Transcript,
    initial: &CeremonyKey,
    final_key: &CeremonyKey,
    opts: &VerifyOptions,
) -> Result<Report> {
    // 1. Header.
    check_header(transcript)?;

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
    let (header_g1, header_g2) = transcript.header_deltas()?;
    if header_g1 != initial.delta_g1() || header_g2 != initial.delta_g2() {
        return Err(CeremonyError::whole(
            Check::InitialKey,
            "the transcript header's delta points are not the initial key's",
        ));
    }

    // 3. Walk the chain.
    let known = known_beacons(transcript, opts)?;
    let walk = walk_chain(transcript, initial.delta_g1(), initial.delta_g2(), &known)?;
    let (prev_g1, prev_g2) = (walk.final_g1, walk.final_g2);

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

    Ok(build_report(
        transcript,
        &walk,
        hexfmt::encode(&final_key.digest()),
        opts,
        true,
    ))
}

/// Verify everything the transcript can prove on its own, with no key files.
///
/// This is what a third party can run against a published `transcript.json` alone.
/// It performs checks 1 and 3 of the list above in full - the chain, every proof of
/// knowledge, every same-ratio pairing, beacon reproduction, the beacon-is-final
/// rule - and produces the same independent-contributor count.
///
/// It does NOT perform the key-level checks, because it has no keys: it cannot tell
/// you that the initial key is the one the header names, that the final key is the
/// one the chain ends at, that the delta-independent parts of the key never moved,
/// or that `h_query`/`l_query` were divided by the accumulated ratio. The report
/// says so in [`Report::key_checks`]. Use [`verify`] when you have the key files.
pub fn verify_transcript(transcript: &Transcript, opts: &VerifyOptions) -> Result<Report> {
    check_header(transcript)?;
    let (header_g1, header_g2) = transcript.header_deltas()?;
    let known = known_beacons(transcript, opts)?;
    let walk = walk_chain(transcript, header_g1, header_g2, &known)?;
    let final_key_digest = transcript
        .contributions
        .last()
        .expect("non-empty checked above")
        .new_key_digest
        .clone();
    Ok(build_report(
        transcript,
        &walk,
        final_key_digest,
        opts,
        false,
    ))
}

/// Transcript version and non-emptiness.
fn check_header(transcript: &Transcript) -> Result<()> {
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
    Ok(())
}

/// What the chain walk establishes.
struct Walk {
    final_hash: [u8; 32],
    final_g1: G1Affine,
    final_g2: G2Affine,
    beacon_steps: usize,
}

/// Every beacon this verification can recognize: the ones the transcript records,
/// plus the one the caller pre-committed to.
fn known_beacons(transcript: &Transcript, opts: &VerifyOptions) -> Result<Vec<KnownBeacon>> {
    let mut out: Vec<KnownBeacon> = Vec::new();
    for rec in &transcript.contributions {
        if let ContributionKind::Beacon { iterations_exp, .. } = &rec.kind {
            let source = rec.kind.beacon_source_bytes()?;
            if out
                .iter()
                .any(|k| k.source == source && k.iterations_exp == *iterations_exp)
            {
                continue;
            }
            out.push(KnownBeacon {
                scalar: crate::beacon::scalar(&source, *iterations_exp)?,
                source,
                iterations_exp: *iterations_exp,
                precommitted: false,
            });
        }
    }
    if let Some(pre) = &opts.beacon_precommitment {
        let scalar = crate::beacon::scalar(pre.source, pre.iterations_exp)?;
        match out
            .iter_mut()
            .find(|k| k.source == pre.source && k.iterations_exp == pre.iterations_exp)
        {
            // The transcript's beacon IS the pre-committed one.
            Some(existing) => existing.precommitted = true,
            None => out.push(KnownBeacon {
                source: pre.source.to_vec(),
                iterations_exp: pre.iterations_exp,
                scalar,
                precommitted: true,
            }),
        }
        // A ceremony that closed on some OTHER beacon did not close on the value
        // you were promised, whatever its transcript says.
        if let Some(i) = transcript.first_beacon_index() {
            let rec = &transcript.contributions[i];
            if rec.kind.beacon_source_bytes()? != pre.source
                || rec.kind.beacon_iterations_exp() != pre.iterations_exp
            {
                return Err(CeremonyError::at(
                    i,
                    Check::Beacon,
                    "the ceremony was closed by a beacon that is not the pre-committed one",
                ));
            }
        }
    }
    Ok(out)
}

/// Walk the chain from the initial delta points to the last entry, running every
/// per-step check. Shared by [`verify_with`] and [`verify_transcript`].
fn walk_chain(
    transcript: &Transcript,
    initial_g1: G1Affine,
    initial_g2: G2Affine,
    known: &[KnownBeacon],
) -> Result<Walk> {
    let mut running_hash = transcript.genesis_hash()?;
    let mut prev_g1 = initial_g1;
    let mut prev_g2 = initial_g2;
    let mut beacon_steps = 0usize;
    let mut closed_at: Option<usize> = None;

    for (i, rec) in transcript.contributions.iter().enumerate() {
        // A beacon closes the ceremony. Whoever appended a step after it took back
        // exactly the last move the beacon was there to remove.
        if let Some(at) = closed_at {
            return Err(CeremonyError::at(
                i,
                Check::BeaconFinal,
                format!(
                    "step {at} is a beacon, which closes the ceremony, but step {i} was appended \
                     after it"
                ),
            ));
        }

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

        if !rec.kind_matches_provenance() {
            return Err(CeremonyError::at(
                i,
                Check::KindConsistency,
                format!(
                    "kind says beacon={} but entropy_source is {:?}",
                    rec.kind.is_beacon(),
                    rec.provenance.entropy_source
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

        let beacon_source = rec.kind.beacon_source_bytes()?;
        let statement = pok::Statement {
            prev_hash: &running_hash,
            index: rec.index,
            contributor_id: &rec.contributor_id,
            metadata: pok::Metadata::new(&rec.kind, &beacon_source, &rec.provenance),
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

        if rec.kind.is_beacon() {
            beacon_steps += 1;
            closed_at = Some(i);
            let s = crate::beacon::scalar(&beacon_source, rec.kind.beacon_iterations_exp())?;
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

        // A step whose ratio is a beacon scalar IS that beacon, whatever it is
        // labelled. This is the check that a relabelled beacon fails - and the only
        // one that can, because a scalar carries no evidence of where it came from.
        for beacon in known {
            let applied: G1Affine = (prev_g1 * beacon.scalar).into();
            if applied == new_g1 && !beacon.is_recorded_as(&rec.kind)? {
                return Err(CeremonyError::at(
                    i,
                    Check::Beacon,
                    format!(
                        "this step applies the scalar of {}, whose value is public, but it is not \
                         recorded as that beacon",
                        beacon.describe()
                    ),
                ));
            }
        }

        running_hash = recorded_hash;
        prev_g1 = new_g1;
        prev_g2 = new_g2;
    }

    Ok(Walk {
        final_hash: running_hash,
        final_g1: prev_g1,
        final_g2: prev_g2,
        beacon_steps,
    })
}

/// Assemble the report, including the caveats that belong with the numbers.
fn build_report(
    transcript: &Transcript,
    walk: &Walk,
    final_key_digest: String,
    opts: &VerifyOptions,
    key_checks: bool,
) -> Report {
    let mut independence = independence::assess(transcript);
    let precommitment_checked = opts.beacon_precommitment.is_some();
    if !precommitment_checked && independence.independent_contributors > 0 {
        independence.warnings.push(
            "no pre-committed beacon value was supplied to this verification, so it cannot rule \
             out that a step counted as a secret contribution was a relabelled public beacon; \
             re-run with the beacon value the ceremony announced in advance"
                .into(),
        );
    }
    if !transcript.closed_by_beacon() {
        independence.warnings.push(
            "this ceremony is not closed by a beacon, so the last contributor could have ground \
             the final key by retrying until they liked it"
                .into(),
        );
    }
    Report {
        circuit: transcript.circuit.clone(),
        circuit_r1cs_digest: transcript.circuit_r1cs_digest.clone(),
        steps: transcript.contributions.len(),
        beacon_steps: walk.beacon_steps,
        closed_by_beacon: transcript.closed_by_beacon(),
        beacon_precommitment_checked: precommitment_checked,
        key_checks,
        initial_key_digest: transcript.initial_key_digest.clone(),
        final_key_digest,
        final_transcript_hash: hexfmt::encode(&walk.final_hash),
        phase1_digest: transcript.phase1.digest.clone(),
        phase1_contributions: transcript.phase1.contributions,
        phase1_looks_public: transcript.phase1.looks_public(),
        independence,
    }
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
