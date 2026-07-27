//! A Schnorr proof of knowledge of the delta ratio, bound to the contributor and
//! to the position in the chain.
//!
//! # The statement
//!
//! A contribution replaces `delta` with `delta * s`. In the group that means
//!
//! ```text
//! new_delta_g1 = prev_delta_g1 * s
//! ```
//!
//! so the contributor is claiming to know the discrete logarithm of
//! `new_delta_g1` with respect to the base `prev_delta_g1`. That is exactly a
//! Schnorr statement, with the *previous* delta point as the generator.
//!
//! # Why it is needed
//!
//! Without it, a contributor could publish a `new_delta_g1` they do not know the
//! exponent of - for instance a point copied from an earlier step - and thereby
//! cancel an honest contributor's randomness, so that the final `delta` is
//! something the adversary knows. Requiring an extractable proof of knowledge at
//! every step is what makes "the final delta is the product of all contributions,
//! so one honest contributor suffices" true.
//!
//! # What it is bound to
//!
//! The Fiat-Shamir challenge commits to the running transcript hash, the
//! contribution index, the contributor identifier, and both the previous and new
//! delta points in both groups:
//!
//! ```text
//! c = Fr( SHA-256( POK_TAG || prev_hash || index || contributor_id
//!                  || prev_delta_g1 || prev_delta_g2
//!                  || new_delta_g1  || new_delta_g2 || R ) )
//! z = k + c * s          R = prev_delta_g1 * k
//! ```
//!
//! Verification is `prev_delta_g1 * z == R + new_delta_g1 * c`. Moving a proof to
//! a different position changes `prev_hash` and `index`; re-attributing it to
//! another operator changes `contributor_id`; either changes `c` and the check
//! fails.
//!
//! `Fr(...)` is `from_be_bytes_mod_order` over the 32-byte digest. Reducing 256
//! bits into the ~254-bit scalar field is very slightly non-uniform; the residual
//! min-entropy of the challenge is above 254 bits, which is far more than Schnorr
//! soundness needs here.

use ark_bn254::{Fr, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::{PrimeField, Zero};
use rand::RngCore;

use crate::points;
use crate::transcript::{Canonical, POK_TAG};

/// Everything the challenge is bound to.
pub struct Statement<'a> {
    /// The chain hash immediately before this contribution.
    pub prev_hash: &'a [u8; 32],
    /// This contribution's position in the chain.
    pub index: u32,
    /// The operator identifier the contribution is attributed to.
    pub contributor_id: &'a str,
    /// The delta points before the contribution (the Schnorr base is
    /// `prev_delta_g1`).
    pub prev_delta_g1: G1Affine,
    pub prev_delta_g2: G2Affine,
    /// The delta points after the contribution.
    pub new_delta_g1: G1Affine,
    pub new_delta_g2: G2Affine,
}

/// A Schnorr proof: the nonce commitment and the response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pok {
    /// `R = prev_delta_g1 * k`.
    pub r: G1Affine,
    /// `z = k + c * s`.
    pub z: Fr,
}

/// Prove knowledge of `s` such that `new_delta_g1 = prev_delta_g1 * s`.
///
/// The nonce `k` is sampled from 64 bytes of the supplied randomness and reduced,
/// so its distribution is within `2^-125` of uniform over the scalar field.
pub fn prove(statement: &Statement, s: &Fr, rng: &mut dyn RngCore) -> Pok {
    let mut wide = [0u8; 64];
    let mut k;
    loop {
        rng.fill_bytes(&mut wide);
        k = Fr::from_be_bytes_mod_order(&wide);
        if !k.is_zero() {
            break;
        }
    }
    let r = (statement.prev_delta_g1 * k).into();
    let c = challenge(statement, &r);
    Pok { r, z: k + c * s }
}

/// Check a proof. Returns `false` for a malformed proof (identity nonce
/// commitment or zero response) as well as for one that simply does not verify.
pub fn verify(statement: &Statement, pok: &Pok) -> bool {
    if pok.r.is_zero() || pok.z.is_zero() || statement.prev_delta_g1.is_zero() {
        return false;
    }
    let c = challenge(statement, &pok.r);
    let lhs = statement.prev_delta_g1 * pok.z;
    let rhs = pok.r + statement.new_delta_g1 * c;
    lhs == rhs
}

/// The Fiat-Shamir challenge.
fn challenge(statement: &Statement, r: &G1Affine) -> Fr {
    let mut h = Canonical::new(POK_TAG);
    h.raw(statement.prev_hash);
    h.u32(statement.index);
    h.text(statement.contributor_id);
    h.raw(&points::g1_bytes(&statement.prev_delta_g1));
    h.raw(&points::g2_bytes(&statement.prev_delta_g2));
    h.raw(&points::g1_bytes(&statement.new_delta_g1));
    h.raw(&points::g2_bytes(&statement.new_delta_g2));
    h.raw(&points::g1_bytes(r));
    Fr::from_be_bytes_mod_order(&h.finish())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::CurveGroup;
    use rand::SeedableRng;

    struct Fixture {
        s: Fr,
        prev_hash: [u8; 32],
        id: String,
        index: u32,
        prev_g1: G1Affine,
        prev_g2: G2Affine,
        new_g1: G1Affine,
        new_g2: G2Affine,
    }

    fn fixture(id: &str, index: u32, prev_hash: [u8; 32], s: u64) -> Fixture {
        let id = id.to_string();
        let s = Fr::from(s);
        let base_scalar = Fr::from(11u64);
        let prev_g1 = (G1Affine::generator() * base_scalar).into_affine();
        let prev_g2 = (G2Affine::generator() * base_scalar).into_affine();
        Fixture {
            s,
            prev_hash,
            id,
            index,
            prev_g1,
            prev_g2,
            new_g1: (prev_g1 * s).into_affine(),
            new_g2: (prev_g2 * s).into_affine(),
        }
    }

    impl Fixture {
        fn statement(&self) -> Statement<'_> {
            Statement {
                prev_hash: &self.prev_hash,
                index: self.index,
                contributor_id: &self.id,
                prev_delta_g1: self.prev_g1,
                prev_delta_g2: self.prev_g2,
                new_delta_g1: self.new_g1,
                new_delta_g2: self.new_g2,
            }
        }
    }

    fn rng() -> rand::rngs::StdRng {
        rand::rngs::StdRng::seed_from_u64(1)
    }

    #[test]
    fn honest_proof_verifies() {
        let f = fixture("alice", 0, [1u8; 32], 5);
        let pok = prove(&f.statement(), &f.s, &mut rng());
        assert!(verify(&f.statement(), &pok));
    }

    #[test]
    fn proof_does_not_transfer_to_another_contributor_id() {
        let f = fixture("alice", 0, [1u8; 32], 5);
        let pok = prove(&f.statement(), &f.s, &mut rng());
        let mut forged = f.statement();
        forged.contributor_id = "mallory";
        assert!(!verify(&forged, &pok));
    }

    #[test]
    fn proof_does_not_transfer_to_another_position() {
        let f = fixture("alice", 0, [1u8; 32], 5);
        let pok = prove(&f.statement(), &f.s, &mut rng());
        let mut moved = f.statement();
        moved.index = 1;
        assert!(!verify(&moved, &pok));
        let other_hash = [2u8; 32];
        let mut replayed = f.statement();
        replayed.prev_hash = &other_hash;
        assert!(!verify(&replayed, &pok));
    }

    #[test]
    fn proof_fails_when_the_new_delta_is_tampered() {
        let f = fixture("alice", 0, [1u8; 32], 5);
        let pok = prove(&f.statement(), &f.s, &mut rng());
        let mut tampered = f.statement();
        tampered.new_delta_g1 = (f.new_g1 * Fr::from(2u64)).into_affine();
        assert!(!verify(&tampered, &pok));
    }

    #[test]
    fn malformed_proofs_are_rejected() {
        let f = fixture("alice", 0, [1u8; 32], 5);
        let mut pok = prove(&f.statement(), &f.s, &mut rng());
        pok.z = Fr::zero();
        assert!(!verify(&f.statement(), &pok));
        let mut pok = prove(&f.statement(), &f.s, &mut rng());
        pok.r = G1Affine::identity();
        assert!(!verify(&f.statement(), &pok));
    }

    #[test]
    fn a_prover_without_the_secret_cannot_forge() {
        // Mallory knows `new_delta_g1` but not `s`; the best she can do is guess a
        // response, which fails.
        let f = fixture("alice", 0, [1u8; 32], 5);
        let forged = Pok {
            r: (f.prev_g1 * Fr::from(9u64)).into_affine(),
            z: Fr::from(9u64),
        };
        assert!(!verify(&f.statement(), &forged));
    }
}
