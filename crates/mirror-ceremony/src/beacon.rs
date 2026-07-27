//! The closing beacon.
//!
//! # What it is for
//!
//! Every contributor before the last one has to trust that the last one did not
//! *grind*: try many candidate scalars and keep the one that makes the final key
//! most convenient for them. A beacon closes that gap. The ceremony pre-commits, in
//! public and before the ceremony ends, to a source of randomness nobody can
//! predict or steer - the canonical choice is a future block hash of a public
//! chain, at a height announced in advance. When that value appears, the beacon
//! step applies it as one more delta ratio.
//!
//! # What it is NOT
//!
//! The beacon adds **no secrecy**. Its scalar is a published value that anyone can
//! recompute, so `delta`'s secrecy still rests entirely on the entropy
//! contributions. That is why a beacon step is recorded with
//! [`crate::EntropySource::Beacon`] and is never counted as an independent
//! contributor.
//!
//! # The delay
//!
//! The scalar is `SHA-256` iterated `2^iterations_exp` times over the source. This
//! is the same construction snarkjs uses. It is a **delay function, not a
//! verifiable delay function**: verifying costs exactly as much as evaluating. A
//! large exponent therefore also makes verification slow. Its purpose is only to
//! put wall-clock distance between the beacon value becoming public and the final
//! key existing.

use ark_bn254::Fr;
use ark_ff::PrimeField;
use sha2::{Digest, Sha256};

use crate::error::CeremonyError;
use crate::Result;

/// Refuse an exponent that would take geological time (and would make verification
/// take just as long).
pub const MAX_ITERATIONS_EXP: u32 = 40;

const BEACON_TAG: &[u8] = b"mirror-pool/ceremony/v1/beacon";

/// Derive the beacon's delta ratio from a published source.
///
/// Anyone can recompute this, which is what lets [`crate::verify`] check a beacon
/// step by full recomputation rather than only by its proof of knowledge.
pub fn scalar(source: &[u8], iterations_exp: u32) -> Result<Fr> {
    if source.is_empty() {
        return Err(CeremonyError::Contribution(
            "beacon source must not be empty".into(),
        ));
    }
    if iterations_exp > MAX_ITERATIONS_EXP {
        return Err(CeremonyError::Contribution(format!(
            "beacon iterations_exp {iterations_exp} exceeds the cap of {MAX_ITERATIONS_EXP}"
        )));
    }

    let mut state: [u8; 32] = Sha256::digest(source).into();
    let iterations: u64 = 1u64 << iterations_exp;
    for _ in 0..iterations {
        state = Sha256::digest(state).into();
    }

    // Widen to 64 bytes before reducing, so the scalar is near-uniform.
    let mut wide = [0u8; 64];
    for (half, counter) in wide.chunks_mut(32).zip(0u8..) {
        let mut h = Sha256::new();
        h.update((BEACON_TAG.len() as u32).to_be_bytes());
        h.update(BEACON_TAG);
        h.update([counter]);
        h.update(state);
        h.update(iterations_exp.to_be_bytes());
        half.copy_from_slice(&h.finalize());
    }
    Ok(Fr::from_be_bytes_mod_order(&wide))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn beacon_is_reproducible_and_source_sensitive() {
        let a = scalar(b"block-hash-abc", 4).unwrap();
        let b = scalar(b"block-hash-abc", 4).unwrap();
        let c = scalar(b"block-hash-abd", 4).unwrap();
        let d = scalar(b"block-hash-abc", 5).unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
    }

    #[test]
    fn rejects_empty_source_and_absurd_exponents() {
        assert!(scalar(b"", 1).is_err());
        assert!(scalar(b"x", MAX_ITERATIONS_EXP + 1).is_err());
    }
}
