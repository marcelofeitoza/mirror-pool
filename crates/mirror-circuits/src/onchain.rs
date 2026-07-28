//! Turn an arkworks proof and verifying key into the bytes the on-chain
//! `groth16-solana` verifier consumes.
//!
//! There is deliberately NO new encoder here. The verifying key goes through
//! `mirror_ceremony::vk_export`, the same exporter the trusted-setup ceremony
//! uses, and the point encodings come from `mirror_ceremony::points`, so this
//! repo keeps ONE definition of "big-endian, uncompressed, G2 imaginary-part
//! first" rather than acquiring a third.
//!
//! The only conversion that lives here is the `proof_a` NEGATION:
//! `Groth16Verifier::new` expects A already negated (its pairing check computes
//! `e(-A, B) * .. == 1` and does not negate internally), which is the same
//! convention `circuits/convert_to_rust.js` and the circom-path serializer
//! follow.

use ark_bn254::{Bn254, G1Affine};
use ark_groth16::{Proof, VerifyingKey};

pub use mirror_ceremony::vk_export::{solana_bytes as verifying_key_bytes, SolanaVerifyingKey};

/// Bytes in the uncompressed big-endian G1 encoding.
pub const PROOF_A_LEN: usize = 64;
/// Bytes in the uncompressed big-endian G2 encoding.
pub const PROOF_B_LEN: usize = 128;
/// Bytes in the uncompressed big-endian G1 encoding.
pub const PROOF_C_LEN: usize = 64;

/// A Groth16 proof in the `groth16-solana` byte layout, with `proof_a` ALREADY
/// negated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OnChainProof {
    pub proof_a: [u8; PROOF_A_LEN],
    pub proof_b: [u8; PROOF_B_LEN],
    pub proof_c: [u8; PROOF_C_LEN],
}

/// Serialize a proof for the on-chain verifier.
pub fn proof_bytes(proof: &Proof<Bn254>) -> OnChainProof {
    let neg_a: G1Affine = -proof.a;
    OnChainProof {
        proof_a: mirror_ceremony::points::g1_bytes(&neg_a),
        proof_b: mirror_ceremony::points::g2_bytes(&proof.b),
        proof_c: mirror_ceremony::points::g1_bytes(&proof.c),
    }
}

/// The canonical registry encoding of a verifying key: exactly the bytes the
/// on-chain `INIT_VK` instruction hashes and stores, so a key produced by this
/// path can be digested and compared the same way the committed circom keys are.
///
/// Returns `None` if the key has a shape the encoding cannot represent (more
/// public inputs than the wire format allows).
pub fn canonical_registry_encoding(vk: &VerifyingKey<Bn254>) -> Option<Vec<u8>> {
    let b = verifying_key_bytes(vk);
    mirror_core::wire::encode_vk(
        b.nr_pubinputs,
        &b.alpha_g1,
        &b.beta_g2,
        &b.gamma_g2,
        &b.delta_g2,
        &b.ic,
    )
}
