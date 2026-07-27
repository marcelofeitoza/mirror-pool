//! Canonical big-endian, uncompressed encodings for the BN254 points and scalars
//! that appear in a transcript.
//!
//! This is deliberately the SAME layout the repo already uses on chain (see
//! `circuits/README.md` and `programs/mirror-pool/src/vk.rs`), so a delta point in
//! a transcript can be compared byte-for-byte against a verifying key without a
//! second convention to learn:
//!
//! ```text
//! G1     = x_be(32) || y_be(32)                                    (64 bytes)
//! G2     = x_c1_be(32) || x_c0_be(32) || y_c1_be(32) || y_c0_be(32) (128 bytes)
//!          i.e. each Fp2 coordinate is imaginary-part-first.
//! scalar = value_be(32)
//! ```
//!
//! The all-zero encoding is the point at infinity. Decoding is strict: a
//! coordinate that is not a canonical field element, a point off the curve, or a
//! point outside the prime-order subgroup is rejected rather than silently
//! reduced.

use ark_bn254::{Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField};

use crate::error::CeremonyError;

/// Bytes in the uncompressed big-endian G1 encoding.
pub const G1_LEN: usize = 64;
/// Bytes in the uncompressed big-endian G2 encoding.
pub const G2_LEN: usize = 128;
/// Bytes in the big-endian scalar encoding.
pub const FR_LEN: usize = 32;

/// Encode a base-field element as 32 big-endian bytes.
fn fq_bytes(x: &Fq) -> [u8; 32] {
    let be = x.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    // BN254's Fq is 254 bits, so `to_bytes_be` is always exactly 32 bytes; the
    // copy is written defensively anyway.
    out[32 - be.len()..].copy_from_slice(&be);
    out
}

/// Decode 32 big-endian bytes into a base-field element, rejecting any encoding
/// that is not already reduced (so one point never has two valid encodings).
fn fq_from_bytes(what: &'static str, b: &[u8]) -> Result<Fq, CeremonyError> {
    let x = Fq::from_be_bytes_mod_order(b);
    if fq_bytes(&x) != b {
        return Err(CeremonyError::point(
            what,
            "base-field coordinate is not a canonical (already reduced) encoding",
        ));
    }
    Ok(x)
}

/// Encode a scalar-field element as 32 big-endian bytes.
pub fn fr_bytes(x: &Fr) -> [u8; FR_LEN] {
    let be = x.into_bigint().to_bytes_be();
    let mut out = [0u8; FR_LEN];
    out[FR_LEN - be.len()..].copy_from_slice(&be);
    out
}

/// Decode 32 big-endian bytes into a scalar, rejecting non-reduced encodings.
pub fn fr_from_bytes(what: &'static str, b: &[u8]) -> Result<Fr, CeremonyError> {
    if b.len() != FR_LEN {
        return Err(CeremonyError::point(
            what,
            format!("expected {FR_LEN} scalar bytes, got {}", b.len()),
        ));
    }
    let x = Fr::from_be_bytes_mod_order(b);
    if fr_bytes(&x) != b {
        return Err(CeremonyError::point(
            what,
            "scalar is not a canonical (already reduced) encoding",
        ));
    }
    Ok(x)
}

/// Encode a G1 point (all-zero means the point at infinity).
pub fn g1_bytes(p: &G1Affine) -> [u8; G1_LEN] {
    let mut out = [0u8; G1_LEN];
    let Some((x, y)) = p.xy() else {
        return out;
    };
    out[..32].copy_from_slice(&fq_bytes(&x));
    out[32..].copy_from_slice(&fq_bytes(&y));
    out
}

/// Decode a G1 point, checking canonical coordinates, on-curve, and subgroup
/// membership.
pub fn g1_from_bytes(what: &'static str, b: &[u8]) -> Result<G1Affine, CeremonyError> {
    if b.len() != G1_LEN {
        return Err(CeremonyError::point(
            what,
            format!("expected {G1_LEN} bytes, got {}", b.len()),
        ));
    }
    if b.iter().all(|x| *x == 0) {
        return Ok(G1Affine::identity());
    }
    let x = fq_from_bytes(what, &b[..32])?;
    let y = fq_from_bytes(what, &b[32..])?;
    let p = G1Affine::new_unchecked(x, y);
    if !p.is_on_curve() {
        return Err(CeremonyError::point(what, "G1 point is not on the curve"));
    }
    if !p.is_in_correct_subgroup_assuming_on_curve() {
        return Err(CeremonyError::point(
            what,
            "G1 point is not in the prime-order subgroup",
        ));
    }
    Ok(p)
}

/// Encode a G2 point, each Fp2 coordinate imaginary-part-first.
pub fn g2_bytes(p: &G2Affine) -> [u8; G2_LEN] {
    let mut out = [0u8; G2_LEN];
    let Some((x, y)) = p.xy() else {
        return out;
    };
    out[0..32].copy_from_slice(&fq_bytes(&x.c1));
    out[32..64].copy_from_slice(&fq_bytes(&x.c0));
    out[64..96].copy_from_slice(&fq_bytes(&y.c1));
    out[96..128].copy_from_slice(&fq_bytes(&y.c0));
    out
}

/// Decode a G2 point, checking canonical coordinates, on-curve, and subgroup
/// membership.
pub fn g2_from_bytes(what: &'static str, b: &[u8]) -> Result<G2Affine, CeremonyError> {
    if b.len() != G2_LEN {
        return Err(CeremonyError::point(
            what,
            format!("expected {G2_LEN} bytes, got {}", b.len()),
        ));
    }
    if b.iter().all(|x| *x == 0) {
        return Ok(G2Affine::identity());
    }
    let x = Fq2::new(
        fq_from_bytes(what, &b[32..64])?,
        fq_from_bytes(what, &b[0..32])?,
    );
    let y = Fq2::new(
        fq_from_bytes(what, &b[96..128])?,
        fq_from_bytes(what, &b[64..96])?,
    );
    let p = G2Affine::new_unchecked(x, y);
    if !p.is_on_curve() {
        return Err(CeremonyError::point(what, "G2 point is not on the curve"));
    }
    if !p.is_in_correct_subgroup_assuming_on_curve() {
        return Err(CeremonyError::point(
            what,
            "G2 point is not in the prime-order subgroup",
        ));
    }
    Ok(p)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::CurveGroup;
    use ark_ff::UniformRand;

    #[test]
    fn g1_round_trips_and_rejects_off_curve() {
        let mut rng = ark_std_rng();
        for _ in 0..8 {
            let p = (G1Affine::generator() * Fr::rand(&mut rng)).into_affine();
            let bytes = g1_bytes(&p);
            assert_eq!(g1_from_bytes("t", &bytes).unwrap(), p);
        }
        // Flipping a coordinate byte takes the point off the curve with
        // overwhelming probability.
        let p = (G1Affine::generator() * Fr::from(7u64)).into_affine();
        let mut bytes = g1_bytes(&p);
        bytes[5] ^= 1;
        assert!(g1_from_bytes("t", &bytes).is_err());
    }

    #[test]
    fn g2_round_trips() {
        let mut rng = ark_std_rng();
        for _ in 0..4 {
            let p = (G2Affine::generator() * Fr::rand(&mut rng)).into_affine();
            let bytes = g2_bytes(&p);
            assert_eq!(g2_from_bytes("t", &bytes).unwrap(), p);
        }
        let mut bytes = g2_bytes(&G2Affine::generator());
        bytes[100] ^= 1;
        assert!(g2_from_bytes("t", &bytes).is_err());
    }

    #[test]
    fn identity_round_trips() {
        assert!(g1_from_bytes("t", &g1_bytes(&G1Affine::identity()))
            .unwrap()
            .is_zero());
        assert!(g2_from_bytes("t", &g2_bytes(&G2Affine::identity()))
            .unwrap()
            .is_zero());
    }

    #[test]
    fn scalar_round_trips_and_rejects_overflow() {
        let mut rng = ark_std_rng();
        let x = Fr::rand(&mut rng);
        assert_eq!(fr_from_bytes("t", &fr_bytes(&x)).unwrap(), x);
        // All-ones is far above the scalar modulus, so it is not canonical.
        assert!(fr_from_bytes("t", &[0xffu8; 32]).is_err());
    }

    fn ark_std_rng() -> impl rand::Rng {
        use rand::SeedableRng;
        rand::rngs::StdRng::seed_from_u64(7)
    }
}
