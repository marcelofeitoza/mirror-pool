//! The ceremony transcript: a JSON document that anyone can re-hash and re-check.
//!
//! # Canonical serialization
//!
//! The JSON is for humans. Every hash in the chain is taken over an explicit,
//! unambiguous byte string built by [`Canonical`]:
//!
//! - a fixed domain-separation tag opens every hash;
//! - fixed-width values are written raw (32-byte digests, 64-byte G1, 128-byte G2,
//!   32-byte scalars);
//! - variable-length values (text, beacon sources) are written as a big-endian
//!   `u32` length followed by the bytes, so no two different field sequences can
//!   produce the same byte string;
//! - integers are big-endian, matching the rest of the repo.
//!
//! # The chain
//!
//! ```text
//! h_0     = SHA-256( GENESIS_TAG || header fields )
//! h_{i+1} = SHA-256( ENTRY_TAG   || h_i || entry i fields )
//! ```
//!
//! `h_i` is stored on entry `i` as `prev_hash` and `h_{i+1}` as `hash`, so a
//! verifier that recomputes the chain detects a reordered, spliced, edited, or
//! truncated transcript.

use ark_bn254::{G1Affine, G2Affine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::CeremonyError;
use crate::hexfmt;
use crate::points;
use crate::ptau::Phase1Provenance;
use crate::Result;

/// Transcript format version.
///
/// Version 2 binds the contribution kind and provenance into the proof of
/// knowledge, and makes a beacon final. A version-1 transcript is rejected rather
/// than re-interpreted: it was produced under weaker rules, and silently accepting
/// it would let a v1 transcript claim v2 guarantees.
pub const TRANSCRIPT_VERSION: u32 = 2;

const GENESIS_TAG: &[u8] = b"mirror-pool/ceremony/v2/genesis";
const ENTRY_TAG: &[u8] = b"mirror-pool/ceremony/v2/entry";
pub(crate) const POK_TAG: &[u8] = b"mirror-pool/ceremony/v2/pok";

/// How the contributor's delta scalar was sampled. Recorded because it decides
/// whether a contribution can be counted as an *independent* one at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntropySource {
    /// Operating-system randomness only.
    Os,
    /// Operating-system randomness mixed with a contributor-supplied string.
    OsPlusUser,
    /// Derived from a fixed seed. Reproducible, therefore its toxic waste is
    /// reproducible: never counted as an independent contributor.
    Deterministic,
    /// Derived from a published beacon value. Public by construction: never
    /// counted as an independent contributor.
    Beacon,
}

impl EntropySource {
    /// Whether a contribution from this source can hide `delta` from anyone.
    pub fn can_be_independent(self) -> bool {
        matches!(self, EntropySource::Os | EntropySource::OsPlusUser)
    }

    /// The one-byte code this variant contributes to every hash that binds it: the
    /// entry hash and the proof-of-knowledge challenge.
    pub fn tag(self) -> u8 {
        match self {
            EntropySource::Os => 0,
            EntropySource::OsPlusUser => 1,
            EntropySource::Deterministic => 2,
            EntropySource::Beacon => 3,
        }
    }
}

/// Self-reported context for a contribution. None of it is trusted; it exists so
/// [`crate::independence`] can refuse to count contributions that obviously came
/// from the same place.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    /// 16-byte hex fingerprint of the machine and account that produced the
    /// contribution. Derived from environment values only (see
    /// [`crate::contribute::machine_fingerprint`]); it carries no hostname or
    /// username in the clear.
    pub machine_fingerprint: String,
    /// How the delta scalar was sampled.
    pub entropy_source: EntropySource,
    /// Seconds since the Unix epoch, as reported by the contributor's machine.
    pub timestamp_unix: u64,
}

/// What kind of step this is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ContributionKind {
    /// A contributor's secret scalar. Its security rests on them destroying it.
    Entropy,
    /// A public, pre-committed beacon: the scalar is `SHA-256` iterated
    /// `2^iterations_exp` times over `source`, so anyone can recompute the whole
    /// step. It adds no secrecy; it removes the previous contributor's ability to
    /// grind the final key.
    Beacon {
        /// Hex of the pre-committed source bytes.
        source: String,
        /// Base-2 log of the iteration count.
        iterations_exp: u32,
    },
}

impl ContributionKind {
    /// The one-byte code this variant contributes to every hash that binds it: the
    /// entry hash and the proof-of-knowledge challenge. Because the challenge
    /// commits to it, a step cannot be relabelled without invalidating its proof -
    /// unless the relabeller knows that step's delta ratio, which for a beacon is
    /// public. See [`crate::verify`] for what closes that residual gap.
    pub fn tag(&self) -> u8 {
        match self {
            ContributionKind::Entropy => 0,
            ContributionKind::Beacon { .. } => 1,
        }
    }

    /// Whether this step is recorded as a beacon.
    pub fn is_beacon(&self) -> bool {
        matches!(self, ContributionKind::Beacon { .. })
    }

    /// The beacon's iteration exponent, or 0 for an entropy step.
    pub fn beacon_iterations_exp(&self) -> u32 {
        match self {
            ContributionKind::Beacon { iterations_exp, .. } => *iterations_exp,
            ContributionKind::Entropy => 0,
        }
    }

    /// The beacon's decoded source bytes, or an empty vector for an entropy step.
    pub fn beacon_source_bytes(&self) -> Result<Vec<u8>> {
        match self {
            ContributionKind::Beacon { source, .. } => {
                hexfmt::decode("beacon source", source, None)
            }
            ContributionKind::Entropy => Ok(Vec::new()),
        }
    }
}

/// A Schnorr proof of knowledge, hex-encoded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PokRecord {
    /// The nonce commitment `R = prev_delta_g1 * k`, 64-byte G1 hex.
    pub r: String,
    /// The response `z = k + c * s`, 32-byte scalar hex.
    pub z: String,
}

/// One step of the chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContributionRecord {
    /// Position in the chain, starting at 0.
    pub index: u32,
    /// The operator identifier this contribution is attributed to. Free-form and
    /// self-asserted, but bound into the proof of knowledge, so it cannot be
    /// rewritten after the fact without invalidating the contribution.
    pub contributor_id: String,
    /// Entropy or beacon.
    pub kind: ContributionKind,
    /// Self-reported context, used only by the independence heuristic.
    pub provenance: Provenance,
    /// The chain hash before this entry, hex.
    pub prev_hash: String,
    /// The new `delta * G1`, 64-byte hex.
    pub new_delta_g1: String,
    /// The new `delta * G2`, 128-byte hex.
    pub new_delta_g2: String,
    /// `SHA-256` of the proving key this contribution produced, hex.
    pub new_key_digest: String,
    /// Proof of knowledge of the delta ratio.
    pub pok: PokRecord,
    /// The chain hash after this entry, hex.
    pub hash: String,
}

impl ContributionRecord {
    /// Decode the new delta points.
    pub fn deltas(&self) -> Result<(G1Affine, G2Affine)> {
        let g1 = points::g1_from_bytes(
            "contribution delta_g1",
            &hexfmt::decode("new_delta_g1", &self.new_delta_g1, Some(points::G1_LEN))?,
        )?;
        let g2 = points::g2_from_bytes(
            "contribution delta_g2",
            &hexfmt::decode("new_delta_g2", &self.new_delta_g2, Some(points::G2_LEN))?,
        )?;
        Ok((g1, g2))
    }

    /// The contributor identifier, normalized for comparison (trimmed, lowercased).
    pub fn normalized_id(&self) -> String {
        self.contributor_id.trim().to_lowercase()
    }

    /// Whether the step's `kind` and its self-reported `entropy_source` tell the
    /// same story about whether it is a beacon.
    ///
    /// The two fields are redundant on purpose, and a half-finished relabelling
    /// shows up here. [`crate::verify`] rejects a record where they disagree, and
    /// [`crate::independence`] never counts one.
    pub fn kind_matches_provenance(&self) -> bool {
        self.kind.is_beacon() == (self.provenance.entropy_source == EntropySource::Beacon)
    }

    /// Whether this step may be counted as an independent secret contributor.
    ///
    /// Both signals must agree that it is not a beacon, and the entropy source must
    /// be one whose scalar can actually be secret. A beacon is never countable: its
    /// scalar is a published value.
    pub fn countable_as_independent(&self) -> bool {
        !self.kind.is_beacon()
            && self.kind_matches_provenance()
            && self.provenance.entropy_source.can_be_independent()
    }
}

/// The whole ceremony record for one circuit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transcript {
    /// Format version.
    pub version: u32,
    /// Circuit label, e.g. `membership`.
    pub circuit: String,
    /// `SHA-256` of the compiled `.r1cs` this ceremony is for, hex. This is what
    /// actually pins the transcript to a circuit; the label is a convenience.
    pub circuit_r1cs_digest: String,
    /// Where phase 1 came from.
    pub phase1: Phase1Provenance,
    /// `SHA-256` of the phase-1-derived initial proving key, hex.
    pub initial_key_digest: String,
    /// The initial key's `delta * G1`, hex.
    pub initial_delta_g1: String,
    /// The initial key's `delta * G2`, hex.
    pub initial_delta_g2: String,
    /// The chain, in order.
    pub contributions: Vec<ContributionRecord>,
}

impl Transcript {
    /// Open a transcript over a phase-1-derived initial key.
    pub fn new(
        circuit: impl Into<String>,
        circuit_r1cs_digest: [u8; 32],
        phase1: Phase1Provenance,
        initial: &crate::key::CeremonyKey,
    ) -> Transcript {
        Transcript {
            version: TRANSCRIPT_VERSION,
            circuit: circuit.into(),
            circuit_r1cs_digest: hexfmt::encode(&circuit_r1cs_digest),
            phase1,
            initial_key_digest: hexfmt::encode(&initial.digest()),
            initial_delta_g1: hexfmt::encode(&points::g1_bytes(&initial.delta_g1())),
            initial_delta_g2: hexfmt::encode(&points::g2_bytes(&initial.delta_g2())),
            contributions: Vec::new(),
        }
    }

    /// The genesis hash: everything the ceremony started from.
    pub fn genesis_hash(&self) -> Result<[u8; 32]> {
        let mut h = Canonical::new(GENESIS_TAG);
        h.u32(self.version);
        h.text(&self.circuit);
        h.raw(&hexfmt::decode32(
            "circuit_r1cs_digest",
            &self.circuit_r1cs_digest,
        )?);
        h.raw(&hexfmt::decode32("phase1.digest", &self.phase1.digest)?);
        h.text(&self.phase1.curve);
        h.u32(self.phase1.power);
        h.u32(self.phase1.ceremony_power);
        h.u32(self.phase1.contributions);
        h.raw(&hexfmt::decode32(
            "initial_key_digest",
            &self.initial_key_digest,
        )?);
        h.raw(&hexfmt::decode(
            "initial_delta_g1",
            &self.initial_delta_g1,
            Some(points::G1_LEN),
        )?);
        h.raw(&hexfmt::decode(
            "initial_delta_g2",
            &self.initial_delta_g2,
            Some(points::G2_LEN),
        )?);
        Ok(h.finish())
    }

    /// The position of the first beacon in the chain, if there is one.
    ///
    /// A beacon closes a ceremony: nothing may be appended after it, and there is
    /// at most one. Both [`crate::contribute`] and [`crate::verify`] enforce that
    /// against this, so the two cannot drift apart.
    pub fn first_beacon_index(&self) -> Option<usize> {
        self.contributions.iter().position(|c| c.kind.is_beacon())
    }

    /// Whether the chain is closed: its last step, and only its last step, is a
    /// beacon.
    pub fn closed_by_beacon(&self) -> bool {
        match self.first_beacon_index() {
            Some(i) => i + 1 == self.contributions.len(),
            None => false,
        }
    }

    /// The current head of the chain: the last entry's hash, or the genesis hash
    /// when there are no contributions yet.
    pub fn head_hash(&self) -> Result<[u8; 32]> {
        match self.contributions.last() {
            Some(last) => hexfmt::decode32("contribution hash", &last.hash),
            None => self.genesis_hash(),
        }
    }

    /// The delta points the header declares for the phase-1-derived initial key.
    ///
    /// These are self-declared: [`crate::verify::verify`] checks them against a
    /// real key file, while [`crate::verify::verify_transcript`] can only take them
    /// as the chain's starting point and says so in its report.
    pub fn header_deltas(&self) -> Result<(G1Affine, G2Affine)> {
        Ok((
            points::g1_from_bytes(
                "initial delta_g1",
                &hexfmt::decode(
                    "initial_delta_g1",
                    &self.initial_delta_g1,
                    Some(points::G1_LEN),
                )?,
            )?,
            points::g2_from_bytes(
                "initial delta_g2",
                &hexfmt::decode(
                    "initial_delta_g2",
                    &self.initial_delta_g2,
                    Some(points::G2_LEN),
                )?,
            )?,
        ))
    }

    /// The delta points at the head of the chain.
    pub fn head_deltas(&self) -> Result<(G1Affine, G2Affine)> {
        match self.contributions.last() {
            Some(last) => last.deltas(),
            None => self.header_deltas(),
        }
    }

    /// Pretty JSON.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| CeremonyError::json("serializing transcript", e))
    }

    /// Parse from JSON.
    pub fn from_json(s: &str) -> Result<Self> {
        serde_json::from_str(s).map_err(|e| CeremonyError::json("parsing transcript", e))
    }
}

/// Recompute the hash of one entry given the chain hash that precedes it.
pub fn entry_hash(prev_hash: &[u8; 32], rec: &ContributionRecord) -> Result<[u8; 32]> {
    let mut h = Canonical::new(ENTRY_TAG);
    h.raw(prev_hash);
    h.u32(rec.index);
    h.text(&rec.contributor_id);
    h.byte(rec.kind.tag());
    h.bytes(&rec.kind.beacon_source_bytes()?);
    h.u32(rec.kind.beacon_iterations_exp());
    h.text(&rec.provenance.machine_fingerprint);
    h.byte(rec.provenance.entropy_source.tag());
    h.u64(rec.provenance.timestamp_unix);
    h.raw(&hexfmt::decode(
        "new_delta_g1",
        &rec.new_delta_g1,
        Some(points::G1_LEN),
    )?);
    h.raw(&hexfmt::decode(
        "new_delta_g2",
        &rec.new_delta_g2,
        Some(points::G2_LEN),
    )?);
    h.raw(&hexfmt::decode32("new_key_digest", &rec.new_key_digest)?);
    h.raw(&hexfmt::decode("pok.r", &rec.pok.r, Some(points::G1_LEN))?);
    h.raw(&hexfmt::decode("pok.z", &rec.pok.z, Some(points::FR_LEN))?);
    Ok(h.finish())
}

/// The unambiguous byte-string builder every ceremony hash runs through.
pub(crate) struct Canonical(Sha256);

impl Canonical {
    pub(crate) fn new(tag: &[u8]) -> Self {
        let mut h = Sha256::new();
        h.update((tag.len() as u32).to_be_bytes());
        h.update(tag);
        Canonical(h)
    }

    /// Fixed-width bytes, written raw.
    pub(crate) fn raw(&mut self, b: &[u8]) {
        self.0.update(b);
    }

    /// Variable-length bytes, length-prefixed.
    pub(crate) fn bytes(&mut self, b: &[u8]) {
        self.0.update((b.len() as u32).to_be_bytes());
        self.0.update(b);
    }

    /// Variable-length UTF-8, length-prefixed.
    pub(crate) fn text(&mut self, s: &str) {
        self.bytes(s.as_bytes());
    }

    pub(crate) fn byte(&mut self, b: u8) {
        self.0.update([b]);
    }

    pub(crate) fn u32(&mut self, v: u32) {
        self.0.update(v.to_be_bytes());
    }

    pub(crate) fn u64(&mut self, v: u64) {
        self.0.update(v.to_be_bytes());
    }

    pub(crate) fn finish(self) -> [u8; 32] {
        self.0.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_prefixing_removes_field_boundary_ambiguity() {
        let mut a = Canonical::new(b"t");
        a.text("ab");
        a.text("c");
        let mut b = Canonical::new(b"t");
        b.text("a");
        b.text("bc");
        assert_ne!(a.finish(), b.finish());
    }

    #[test]
    fn domain_tags_separate_hashes() {
        let mut a = Canonical::new(GENESIS_TAG);
        a.u32(1);
        let mut b = Canonical::new(ENTRY_TAG);
        b.u32(1);
        assert_ne!(a.finish(), b.finish());
    }
}
