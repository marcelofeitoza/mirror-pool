//! One error type for the whole ceremony, so a verification failure names exactly
//! which check rejected and at which contribution index.

use std::fmt;

/// Everything that can go wrong producing or verifying a ceremony.
#[derive(Debug, thiserror::Error)]
pub enum CeremonyError {
    /// I/O around a transcript, key file, or powers-of-tau file.
    #[error("{context}: {source}")]
    Io {
        context: String,
        #[source]
        source: std::io::Error,
    },

    /// A file did not have the shape this crate expects (bad magic, bad version,
    /// truncated section, and so on).
    #[error("malformed {what}: {detail}")]
    Malformed { what: &'static str, detail: String },

    /// A curve point (or field element) was not a canonical, on-curve, in-subgroup
    /// encoding.
    #[error("invalid {what}: {detail}")]
    InvalidPoint { what: &'static str, detail: String },

    /// A structural precondition of a contribution was violated (identity delta,
    /// empty contributor id, and so on).
    #[error("cannot contribute: {0}")]
    Contribution(String),

    /// A verification check failed. `index` is the contribution index the failure
    /// belongs to, or `None` for whole-transcript checks.
    #[error("{}: {check} failed{}", .index.map(|i| format!("contribution {i}")).unwrap_or_else(|| "ceremony".into()), .detail.as_ref().map(|d| format!(" - {d}")).unwrap_or_default())]
    Verification {
        index: Option<usize>,
        check: Check,
        detail: Option<String>,
    },

    /// JSON (de)serialization of a transcript.
    #[error("{context}: {source}")]
    Json {
        context: String,
        #[source]
        source: serde_json::Error,
    },
}

impl CeremonyError {
    pub(crate) fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        CeremonyError::Io {
            context: context.into(),
            source,
        }
    }

    pub(crate) fn malformed(what: &'static str, detail: impl Into<String>) -> Self {
        CeremonyError::Malformed {
            what,
            detail: detail.into(),
        }
    }

    pub(crate) fn point(what: &'static str, detail: impl Into<String>) -> Self {
        CeremonyError::InvalidPoint {
            what,
            detail: detail.into(),
        }
    }

    pub(crate) fn json(context: impl Into<String>, source: serde_json::Error) -> Self {
        CeremonyError::Json {
            context: context.into(),
            source,
        }
    }

    /// A verification failure attributed to a specific contribution.
    pub(crate) fn at(index: usize, check: Check, detail: impl Into<String>) -> Self {
        CeremonyError::Verification {
            index: Some(index),
            check,
            detail: Some(detail.into()),
        }
    }

    /// A verification failure about the ceremony as a whole.
    pub(crate) fn whole(check: Check, detail: impl Into<String>) -> Self {
        CeremonyError::Verification {
            index: None,
            check,
            detail: Some(detail.into()),
        }
    }

    /// Which check rejected, when this is a verification failure.
    pub fn check(&self) -> Option<Check> {
        match self {
            CeremonyError::Verification { check, .. } => Some(*check),
            _ => None,
        }
    }
}

/// The named verification checks. Every rejection reports one of these, so a test
/// can assert not merely "it failed" but "it failed for the right reason".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Check {
    /// Transcript header (version, circuit label, phase-1 record) is well formed.
    Header,
    /// The initial key matches the digest and delta points the transcript names.
    InitialKey,
    /// `entry.prev_hash` equals the running chain hash (catches reorder / splice).
    ChainLink,
    /// `entry.index` equals its position in the chain.
    Index,
    /// The recomputed entry hash equals the recorded one.
    EntryHash,
    /// The Schnorr proof of knowledge of the delta ratio verifies.
    ProofOfKnowledge,
    /// `e(delta_g1_prev, delta_g2_new) == e(delta_g1_new, delta_g2_prev)`.
    SameRatio,
    /// A contribution left delta unchanged (a null contribution) or set it to the
    /// identity.
    NullContribution,
    /// A beacon step's delta could not be reproduced from its published source, or
    /// a step that is not recorded as a beacon applies a known beacon's scalar.
    Beacon,
    /// Something was appended after the beacon that closed the ceremony, or the
    /// chain contains more than one beacon.
    BeaconFinal,
    /// A step's `kind` and its self-reported `entropy_source` disagree about whether
    /// it is a beacon.
    KindConsistency,
    /// The final key matches the digest and delta points of the last entry.
    FinalKey,
    /// A part of the key that a contribution must never touch was modified.
    FixedPart,
    /// `h_query` / `l_query` were not divided by the accumulated delta ratio.
    QueryScaling,
    /// The transcript has no contributions at all.
    Empty,
}

impl fmt::Display for Check {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Check::Header => "transcript header",
            Check::InitialKey => "initial-key binding",
            Check::ChainLink => "transcript chain link",
            Check::Index => "contribution index",
            Check::EntryHash => "entry hash",
            Check::ProofOfKnowledge => "Schnorr proof of knowledge",
            Check::SameRatio => "delta same-ratio pairing check",
            Check::NullContribution => "non-null contribution",
            Check::Beacon => "beacon reproducibility",
            Check::BeaconFinal => "beacon-is-final rule",
            Check::KindConsistency => "kind/provenance agreement",
            Check::FinalKey => "final-key binding",
            Check::FixedPart => "untouched-key-part equality",
            Check::QueryScaling => "h_query/l_query scaling pairing check",
            Check::Empty => "non-empty ceremony",
        };
        f.write_str(s)
    }
}
