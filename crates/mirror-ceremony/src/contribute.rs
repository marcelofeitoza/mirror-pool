//! Making a phase-2 contribution: re-randomize `delta`, prove you know the ratio,
//! and append an entry to the transcript.
//!
//! # The math
//!
//! A Groth16 proving key contains `delta` in exactly four places, two of them
//! multiplied and two divided:
//!
//! ```text
//! delta_g1  = delta * G1        h_query[i] = (x^i * t(x)) / delta * G1
//! delta_g2  = delta * G2        l_query[i] = (beta*A_i + alpha*B_i + C_i) / delta * G1
//! ```
//!
//! Replacing `delta` with `delta * s` therefore means multiplying the first two by
//! `s` and the last two by `s^-1`. Every other element of the key is independent of
//! `delta` and must not move. Because the pairing equation only ever sees the
//! products `delta_g1 * h_query` and `delta_g2 * l_query`, the `s` cancels and the
//! key still proves the same circuit - while the new `delta` is unknown to anyone
//! who does not know every `s` in the chain.
//!
//! # Destroying the secret
//!
//! [`Contribution::scalar`] is overwritten before it is dropped, but Rust makes no
//! guarantee that no copy of it remains in a register, in a spilled stack slot, or
//! in swap. Treat the machine, not the process, as the thing that has to be
//! trusted: contribute from a machine you control, and prefer one you are willing
//! to power off afterwards.

use std::time::{SystemTime, UNIX_EPOCH};

use ark_bn254::{Bn254, Fr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Field, PrimeField, Zero};
use ark_groth16::ProvingKey;
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::error::CeremonyError;
use crate::hexfmt;
use crate::key::CeremonyKey;
use crate::points;
use crate::pok;
use crate::transcript::{
    entry_hash, ContributionKind, ContributionRecord, EntropySource, PokRecord, Provenance,
    Transcript,
};
use crate::Result;

const FINGERPRINT_TAG: &[u8] = b"mirror-pool/ceremony/v1/fingerprint";
const SCALAR_TAG: &[u8] = b"mirror-pool/ceremony/v1/delta-scalar";

/// How a contributor's delta scalar is produced.
pub enum Entropy {
    /// Operating-system randomness only.
    Os,
    /// Operating-system randomness mixed with a string the contributor supplies
    /// (dice rolls, a photograph's hash, whatever they trust). Mixing can only
    /// help: the result is a hash of both.
    OsPlusUser(String),
    /// A fixed seed. Reproducible on purpose - for tests and for the documented
    /// demo ceremony. A contribution made this way is flagged in the transcript and
    /// is never counted as an independent contributor.
    Deterministic(String),
}

impl Entropy {
    fn source(&self) -> EntropySource {
        match self {
            Entropy::Os => EntropySource::Os,
            Entropy::OsPlusUser(_) => EntropySource::OsPlusUser,
            Entropy::Deterministic(_) => EntropySource::Deterministic,
        }
    }

    /// Derive the delta scalar. 64 bytes are hashed into the field, so the result
    /// is within `2^-125` of uniform.
    fn scalar(&self) -> Fr {
        let mut wide = [0u8; 64];
        match self {
            Entropy::Os => {
                fill_os(&mut wide);
                Fr::from_be_bytes_mod_order(&wide)
            }
            Entropy::OsPlusUser(user) => {
                let mut os = [0u8; 64];
                fill_os(&mut os);
                wide.copy_from_slice(&wide_hash(SCALAR_TAG, &[&os[..], user.as_bytes()]));
                Fr::from_be_bytes_mod_order(&wide)
            }
            Entropy::Deterministic(seed) => {
                wide.copy_from_slice(&wide_hash(SCALAR_TAG, &[b"deterministic", seed.as_bytes()]));
                Fr::from_be_bytes_mod_order(&wide)
            }
        }
    }
}

fn fill_os(buf: &mut [u8]) {
    rand::rngs::OsRng.fill_bytes(buf);
}

/// 64 bytes from two domain-separated SHA-256 invocations.
fn wide_hash(tag: &[u8], parts: &[&[u8]]) -> [u8; 64] {
    let mut out = [0u8; 64];
    for (half, counter) in out.chunks_mut(32).zip(0u8..) {
        let mut h = Sha256::new();
        h.update((tag.len() as u32).to_be_bytes());
        h.update(tag);
        h.update([counter]);
        for p in parts {
            h.update((p.len() as u32).to_be_bytes());
            h.update(p);
        }
        half.copy_from_slice(&h.finalize());
    }
    out
}

/// A 16-byte fingerprint of the machine and account a contribution was produced on.
///
/// It is built only from environment values, and it is a hash, so it does not put a
/// hostname or a username into a public transcript. Its only job is to let
/// [`crate::independence`] notice that several "different" contributors ran on the
/// same box. When the environment exposes nothing distinguishing, every
/// contribution on that platform collapses into the same fingerprint - which makes
/// the independent-contributor count too LOW, never too high. That is the safe
/// direction for this heuristic.
pub fn machine_fingerprint() -> String {
    let mut h = Sha256::new();
    h.update((FINGERPRINT_TAG.len() as u32).to_be_bytes());
    h.update(FINGERPRINT_TAG);
    for var in [
        "HOSTNAME",
        "HOST",
        "COMPUTERNAME",
        "USER",
        "LOGNAME",
        "USERNAME",
        "HOME",
        "USERPROFILE",
    ] {
        let value = std::env::var(var).unwrap_or_default();
        h.update((value.len() as u32).to_be_bytes());
        h.update(value.as_bytes());
    }
    for value in [std::env::consts::OS, std::env::consts::ARCH] {
        h.update((value.len() as u32).to_be_bytes());
        h.update(value.as_bytes());
    }
    let hostname = std::fs::read_to_string("/etc/hostname").unwrap_or_default();
    h.update((hostname.len() as u32).to_be_bytes());
    h.update(hostname.trim().as_bytes());
    hexfmt::encode(&h.finalize()[..16])
}

/// Seconds since the Unix epoch (0 if the clock is before it).
fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Apply a delta ratio to a proving key.
///
/// Multiplies `delta_g1` and `delta_g2` by `s`, divides `h_query` and `l_query` by
/// `s`, and leaves every other element untouched.
pub fn apply_delta(pk: &ProvingKey<Bn254>, s: &Fr) -> Result<ProvingKey<Bn254>> {
    if s.is_zero() {
        return Err(CeremonyError::Contribution(
            "delta ratio is zero (this would destroy the key)".into(),
        ));
    }
    let s_inv = s
        .inverse()
        .ok_or_else(|| CeremonyError::Contribution("delta ratio is not invertible".into()))?;

    let mut out = pk.clone();
    out.delta_g1 = (pk.delta_g1 * s).into_affine();
    out.vk.delta_g2 = (pk.vk.delta_g2 * s).into_affine();
    out.h_query = scale(&pk.h_query, &s_inv);
    out.l_query = scale(&pk.l_query, &s_inv);
    Ok(out)
}

/// Multiply a vector of G1 points by a scalar, normalizing back to affine with a
/// single batch inversion.
fn scale(input: &[G1Affine], f: &Fr) -> Vec<G1Affine> {
    let projective: Vec<G1Projective> = input.iter().map(|p| *p * f).collect();
    G1Projective::normalize_batch(&projective)
}

/// What a contributor hands on: the new key and the transcript entry that proves
/// how it was derived.
pub struct Contribution {
    /// The re-randomized proving key.
    pub key: CeremonyKey,
    /// The transcript entry, already appended by [`contribute`].
    pub record: ContributionRecord,
    /// The delta ratio. Kept only so the caller can inspect it in tests; it is
    /// overwritten on drop.
    pub scalar: Fr,
}

impl Drop for Contribution {
    fn drop(&mut self) {
        self.scalar = Fr::zero();
    }
}

/// Deliberately hand-written so the delta scalar is never printed, logged, or
/// captured in a test failure message.
impl std::fmt::Debug for Contribution {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Contribution")
            .field("index", &self.record.index)
            .field("contributor_id", &self.record.contributor_id)
            .field("new_key_digest", &self.record.new_key_digest)
            .field("scalar", &"<redacted>")
            .finish()
    }
}

/// Add an entropy contribution to `transcript`, on top of `key`.
///
/// `key` must be the key at the head of the transcript: its digest is checked
/// against what the transcript says the current key is, so a contributor cannot
/// accidentally build on the wrong file.
pub fn contribute(
    transcript: &mut Transcript,
    key: &CeremonyKey,
    contributor_id: &str,
    entropy: &Entropy,
) -> Result<Contribution> {
    let s = entropy.scalar();
    apply(
        transcript,
        key,
        contributor_id,
        ContributionKind::Entropy,
        entropy.source(),
        s,
    )
}

/// Add a beacon step: a delta ratio derived from a public, pre-committed value.
///
/// See [`crate::beacon`] for what a beacon is for. It is recorded with
/// [`EntropySource::Beacon`], so it never inflates the independent-contributor
/// count.
///
/// **A beacon is final.** Once one is in the transcript, this function and
/// [`contribute`] both refuse to append anything else, and [`crate::verify`]
/// rejects a transcript where something was appended anyway. Allowing a step after
/// the beacon would hand the last move straight back to whoever added it, which is
/// the exact thing a beacon exists to prevent.
pub fn contribute_beacon(
    transcript: &mut Transcript,
    key: &CeremonyKey,
    contributor_id: &str,
    source: &[u8],
    iterations_exp: u32,
) -> Result<Contribution> {
    let s = crate::beacon::scalar(source, iterations_exp)?;
    apply(
        transcript,
        key,
        contributor_id,
        ContributionKind::Beacon {
            source: hexfmt::encode(source),
            iterations_exp,
        },
        EntropySource::Beacon,
        s,
    )
}

fn apply(
    transcript: &mut Transcript,
    key: &CeremonyKey,
    contributor_id: &str,
    kind: ContributionKind,
    entropy_source: EntropySource,
    s: Fr,
) -> Result<Contribution> {
    if contributor_id.trim().is_empty() {
        return Err(CeremonyError::Contribution(
            "contributor id must not be empty - it is bound into the proof of knowledge".into(),
        ));
    }
    // A beacon closes the ceremony. Appending anything after it - another beacon or
    // an entropy contribution - would give the appender the last move the beacon
    // exists to take away, so it is refused here and rejected by `verify`.
    if let Some(at) = transcript.first_beacon_index() {
        return Err(CeremonyError::Contribution(format!(
            "this ceremony was closed by the beacon at step {at}; a beacon is final, so no further \
             step can be appended. Start a new ceremony if more contributions are needed."
        )));
    }
    let expected = expected_head_digest(transcript)?;
    if key.digest() != expected {
        return Err(CeremonyError::Contribution(format!(
            "the supplied key ({}) is not the key at the head of this transcript ({})",
            hexfmt::encode(&key.digest()),
            hexfmt::encode(&expected)
        )));
    }
    if s.is_zero() || s == Fr::from(1u64) {
        return Err(CeremonyError::Contribution(
            "delta ratio is 0 or 1, which contributes nothing".into(),
        ));
    }

    let prev_g1 = key.delta_g1();
    let prev_g2 = key.delta_g2();
    if prev_g1.is_zero() || prev_g2.is_zero() {
        return Err(CeremonyError::Contribution(
            "the current key's delta is the point at infinity".into(),
        ));
    }

    let new_pk = apply_delta(&key.pk, &s)?;
    let new_key = CeremonyKey::new(key.circuit.clone(), new_pk)?;

    let prev_hash = transcript.head_hash()?;
    let index = transcript.contributions.len() as u32;

    // The provenance is fixed BEFORE the proof is made, because the proof commits
    // to it: a step's kind and provenance cannot be rewritten afterwards without
    // invalidating it.
    let provenance = Provenance {
        machine_fingerprint: machine_fingerprint(),
        entropy_source,
        timestamp_unix: now_unix(),
    };
    let beacon_source = kind.beacon_source_bytes()?;
    let statement = pok::Statement {
        prev_hash: &prev_hash,
        index,
        contributor_id,
        metadata: pok::Metadata::new(&kind, &beacon_source, &provenance),
        prev_delta_g1: prev_g1,
        prev_delta_g2: prev_g2,
        new_delta_g1: new_key.delta_g1(),
        new_delta_g2: new_key.delta_g2(),
    };
    let proof = pok::prove(&statement, &s, &mut rand::rngs::OsRng);

    let mut record = ContributionRecord {
        index,
        contributor_id: contributor_id.to_string(),
        kind,
        provenance,
        prev_hash: hexfmt::encode(&prev_hash),
        new_delta_g1: hexfmt::encode(&points::g1_bytes(&new_key.delta_g1())),
        new_delta_g2: hexfmt::encode(&points::g2_bytes(&new_key.delta_g2())),
        new_key_digest: hexfmt::encode(&new_key.digest()),
        pok: PokRecord {
            r: hexfmt::encode(&points::g1_bytes(&proof.r)),
            z: hexfmt::encode(&points::fr_bytes(&proof.z)),
        },
        hash: String::new(),
    };
    record.hash = hexfmt::encode(&entry_hash(&prev_hash, &record)?);
    transcript.contributions.push(record.clone());

    Ok(Contribution {
        key: new_key,
        record,
        scalar: s,
    })
}

/// The digest the key at the head of the transcript must have.
fn expected_head_digest(transcript: &Transcript) -> Result<[u8; 32]> {
    match transcript.contributions.last() {
        Some(last) => hexfmt::decode32("new_key_digest", &last.new_key_digest),
        None => hexfmt::decode32("initial_key_digest", &transcript.initial_key_digest),
    }
}
