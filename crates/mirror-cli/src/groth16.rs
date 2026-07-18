//! Serialize a snarkjs Groth16 proof into the byte layout `groth16-solana`
//! (v0.2.0) and the on-chain `SettleZk` handler consume.
//!
//! This is the Rust twin of `circuits/convert_to_rust.js`: same big-endian,
//! uncompressed encoding, same pre-negated `proof_a`. All elements are big-endian
//! and uncompressed:
//!
//! ```text
//! G1 point  = x_be(32) || y_be(32)                                   (64 bytes)
//! G2 point  = x_c1_be(32) || x_c0_be(32) || y_c1_be(32) || y_c0_be(32)  (128 bytes)
//!             i.e. each Fp2 coordinate is imaginary-part-first.
//! field elt = value_be(32)
//! ```
//!
//! `proof_a` is emitted ALREADY NEGATED, because `Groth16Verifier::new` expects
//! the negated A (its pairing check computes `e(-A, B) * ... == 1` and does not
//! negate A internally). Negation over the BN254 base field Fq is
//! `-(x, y) = (x, q - y)`.

use anyhow::{bail, Context, Result};
use num_bigint::BigUint;
use serde::Deserialize;

use mirror_core::{wire, Hash32};

/// Groth16 proof component sizes (groth16-solana v0.2.0 byte layout). These
/// mirror the on-chain program's `wire::PROOF_*_LEN`; `mirror_core::wire` does not
/// re-export them, and `SETTLE_ZK_LEN` pins their sum.
pub const PROOF_A_LEN: usize = 64;
pub const PROOF_B_LEN: usize = 128;
pub const PROOF_C_LEN: usize = 64;

// Keep the component sizes honest against the shared SettleZk wire length.
const _: () =
    assert!(wire::SETTLE_ZK_LEN == 1 + 8 + 8 + PROOF_A_LEN + PROOF_B_LEN + PROOF_C_LEN + 4 * 32);

/// BN254 base field (Fq) modulus, for the G1 point negation of `proof_a`.
fn fq() -> BigUint {
    BigUint::parse_bytes(
        b"21888242871839275222246405745257275088696311157297823662689037894645226208583",
        10,
    )
    .expect("valid Fq modulus literal")
}

/// A decimal (or `0x`-hex) field-element string -> canonical 32-byte big-endian.
///
/// Rejects values that do not fit in 32 bytes (a malformed proof), so a bad proof
/// can never be silently truncated into a valid-looking instruction.
pub fn to_be32(dec: &str) -> Result<Hash32> {
    let n = parse_field(dec)?;
    biguint_to_be32(&n)
}

fn parse_field(s: &str) -> Result<BigUint> {
    let s = s.trim();
    let n = if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        BigUint::parse_bytes(hex.as_bytes(), 16)
    } else {
        BigUint::parse_bytes(s.as_bytes(), 10)
    };
    n.with_context(|| format!("parsing field element {s:?}"))
}

fn biguint_to_be32(n: &BigUint) -> Result<Hash32> {
    let be = n.to_bytes_be();
    if be.len() > 32 {
        bail!(
            "field element does not fit in 32 bytes ({} bytes)",
            be.len()
        );
    }
    let mut out = [0u8; 32];
    out[32 - be.len()..].copy_from_slice(&be);
    Ok(out)
}

/// A snarkjs `proof.json`.
#[derive(Deserialize)]
pub struct SnarkjsProof {
    pub pi_a: Vec<String>,
    pub pi_b: Vec<Vec<String>>,
    pub pi_c: Vec<String>,
}

/// The serialized Groth16 proof triple in `groth16-solana` byte layout, with
/// `proof_a` already negated.
pub struct ProofBytes {
    pub proof_a: [u8; PROOF_A_LEN],
    pub proof_b: [u8; PROOF_B_LEN],
    pub proof_c: [u8; PROOF_C_LEN],
}

impl SnarkjsProof {
    /// Parse a `proof.json` string.
    pub fn parse(json: &str) -> Result<SnarkjsProof> {
        serde_json::from_str(json).context("parsing snarkjs proof.json")
    }

    /// Serialize into the on-chain byte layout (negating `proof_a`).
    pub fn to_bytes(&self) -> Result<ProofBytes> {
        if self.pi_a.len() < 2 || self.pi_c.len() < 2 || self.pi_b.len() < 2 {
            bail!("malformed proof.json: pi_a/pi_b/pi_c too short");
        }
        if self.pi_b[0].len() < 2 || self.pi_b[1].len() < 2 {
            bail!("malformed proof.json: pi_b coordinates too short");
        }

        // proof_a = x_be || (q - y)_be   (negated G1)
        let ax = to_be32(&self.pi_a[0])?;
        let ay = parse_field(&self.pi_a[1])?;
        let q = fq();
        let neg_ay = (&q - (&ay % &q)) % &q;
        let mut proof_a = [0u8; PROOF_A_LEN];
        proof_a[..32].copy_from_slice(&ax);
        proof_a[32..].copy_from_slice(&biguint_to_be32(&neg_ay)?);

        // proof_b = x_c1 || x_c0 || y_c1 || y_c0   (imaginary-part-first)
        let mut proof_b = [0u8; PROOF_B_LEN];
        proof_b[0..32].copy_from_slice(&to_be32(&self.pi_b[0][1])?);
        proof_b[32..64].copy_from_slice(&to_be32(&self.pi_b[0][0])?);
        proof_b[64..96].copy_from_slice(&to_be32(&self.pi_b[1][1])?);
        proof_b[96..128].copy_from_slice(&to_be32(&self.pi_b[1][0])?);

        // proof_c = x_be || y_be   (plain G1)
        let mut proof_c = [0u8; PROOF_C_LEN];
        proof_c[..32].copy_from_slice(&to_be32(&self.pi_c[0])?);
        proof_c[32..].copy_from_slice(&to_be32(&self.pi_c[1])?);

        Ok(ProofBytes {
            proof_a,
            proof_b,
            proof_c,
        })
    }
}

/// Assemble the full `SettleZk` instruction data (401 bytes).
///
/// ```text
/// [tag(1)][epoch(8 LE)][amount(8 LE)]
///   [proof_a(64)][proof_b(128)][proof_c(64)]
///   [root(32)][nullifierHash(32)][actionHash(32)][epoch(32 BE)]
/// ```
///
/// The four trailing 32-byte values are the Groth16 public inputs in the FIXED
/// order `[root, nullifierHash, actionHash, epoch]`; `epoch` appears twice (the
/// `u64` header drives the window gate and the nullifier PDA seed, the 32-byte
/// big-endian public input is what the proof commits to, and the program requires
/// the two to agree).
#[allow(clippy::too_many_arguments)]
pub fn settle_zk_data(
    epoch: u64,
    amount: u64,
    proof: &ProofBytes,
    root: &Hash32,
    nullifier_hash: &Hash32,
    action_hash: &Hash32,
) -> Vec<u8> {
    let mut data = Vec::with_capacity(wire::SETTLE_ZK_LEN);
    data.push(wire::tag::SETTLE_ZK);
    data.extend_from_slice(&epoch.to_le_bytes());
    data.extend_from_slice(&amount.to_le_bytes());
    data.extend_from_slice(&proof.proof_a);
    data.extend_from_slice(&proof.proof_b);
    data.extend_from_slice(&proof.proof_c);
    data.extend_from_slice(root);
    data.extend_from_slice(nullifier_hash);
    data.extend_from_slice(action_hash);
    // epoch public input: 32-byte big-endian encoding of the u64 header.
    let mut epoch_be = [0u8; 32];
    epoch_be[24..].copy_from_slice(&epoch.to_be_bytes());
    data.extend_from_slice(&epoch_be);
    debug_assert_eq!(data.len(), wire::SETTLE_ZK_LEN);
    data
}

/// Assemble the full `Transact` instruction data (tag + body) exactly as the
/// on-chain `instructions::transact` handler parses it, with `proof_a` already
/// negated (via [`ProofBytes`]).
///
/// ```text
/// [tag(1)]
///   [publicAmount(32)][extDataHash(32)][root(32)]
///   [inputNullifier[0](32)][inputNullifier[1](32)]
///   [outputCommitment[0](32)][outputCommitment[1](32)]
///   [proof_a(64)][proof_b(128)][proof_c(64)]
///   [fee(8 LE)]
///   [enc0_len(2 LE)][enc0 bytes][enc1_len(2 LE)][enc1 bytes]
/// ```
///
/// The seven 32-byte header values are the Groth16 public inputs, but the WIRE
/// header order is `[publicAmount, extDataHash, root, ...]` while the public-input
/// order fed to the verifier is `[root, publicAmount, extDataHash, ...]`; this
/// builder takes them individually so the caller places each correctly. Each blob
/// is length-prefixed (`u16` LE) and capped at [`wire::TRANSACT_MAX_ENC_LEN`].
/// MUST stay byte-identical to the program's `wire::TRANSACT_HEADER_LEN` layout
/// (the offset asserts below pin it).
#[allow(clippy::too_many_arguments)]
pub fn transact_data(
    public_amount: &Hash32,
    ext_data_hash: &Hash32,
    root: &Hash32,
    in_nullifier0: &Hash32,
    in_nullifier1: &Hash32,
    out_commitment0: &Hash32,
    out_commitment1: &Hash32,
    proof: &ProofBytes,
    fee: u64,
    enc0: &[u8],
    enc1: &[u8],
) -> Result<Vec<u8>> {
    if enc0.len() > wire::TRANSACT_MAX_ENC_LEN || enc1.len() > wire::TRANSACT_MAX_ENC_LEN {
        bail!(
            "encrypted-note blob too long (enc0={}, enc1={}, cap={})",
            enc0.len(),
            enc1.len(),
            wire::TRANSACT_MAX_ENC_LEN
        );
    }
    let mut data = Vec::with_capacity(1 + wire::TRANSACT_HEADER_LEN + 4 + enc0.len() + enc1.len());
    data.push(wire::tag::TRANSACT);
    data.extend_from_slice(public_amount);
    data.extend_from_slice(ext_data_hash);
    data.extend_from_slice(root);
    data.extend_from_slice(in_nullifier0);
    data.extend_from_slice(in_nullifier1);
    data.extend_from_slice(out_commitment0);
    data.extend_from_slice(out_commitment1);
    data.extend_from_slice(&proof.proof_a);
    data.extend_from_slice(&proof.proof_b);
    data.extend_from_slice(&proof.proof_c);
    data.extend_from_slice(&fee.to_le_bytes());
    data.extend_from_slice(&(enc0.len() as u16).to_le_bytes());
    data.extend_from_slice(enc0);
    data.extend_from_slice(&(enc1.len() as u16).to_le_bytes());
    data.extend_from_slice(enc1);
    // The fixed header (everything after the tag, before the blobs) must be
    // exactly TRANSACT_HEADER_LEN bytes: 7*32 + 64 + 128 + 64 + 8.
    debug_assert_eq!(
        1 + wire::TRANSACT_HEADER_LEN + 4 + enc0.len() + enc1.len(),
        data.len()
    );
    Ok(data)
}

// The header field placement above must match the program's TRANSACT offsets.
const _: () = assert!(wire::TRANSACT_PUBLIC_AMOUNT_OFF == 0);
const _: () = assert!(wire::TRANSACT_EXT_DATA_HASH_OFF == 32);
const _: () = assert!(wire::TRANSACT_ROOT_OFF == 64);
const _: () = assert!(wire::TRANSACT_IN_NULLIFIER0_OFF == 96);
const _: () = assert!(wire::TRANSACT_IN_NULLIFIER1_OFF == 128);
const _: () = assert!(wire::TRANSACT_OUT_COMMIT0_OFF == 160);
const _: () = assert!(wire::TRANSACT_OUT_COMMIT1_OFF == 192);
const _: () = assert!(wire::TRANSACT_PROOF_A_OFF == 224);
const _: () = assert!(wire::TRANSACT_FEE_OFF == 480);
const _: () = assert!(wire::TRANSACT_ENC_OFF == 488);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_be32_left_pads_and_round_trips() {
        assert_eq!(to_be32("0").unwrap(), [0u8; 32]);
        let one = to_be32("1").unwrap();
        assert_eq!(one[31], 1);
        assert_eq!(one[..31], [0u8; 31]);
        // 0x0102..0x20 (32 bytes) parsed from hex.
        let hex = format!(
            "0x{}",
            (1u8..=32).map(|b| format!("{b:02x}")).collect::<String>()
        );
        let be = to_be32(&hex).unwrap();
        for (i, b) in be.iter().enumerate() {
            assert_eq!(*b, (i + 1) as u8);
        }
    }

    #[test]
    fn to_be32_rejects_oversized() {
        // 33 bytes of 0xff does not fit in a field element slot.
        let big = "0x".to_string() + &"ff".repeat(33);
        assert!(to_be32(&big).is_err());
    }

    #[test]
    fn negation_is_additive_inverse_mod_fq() {
        // proof_a's y' must satisfy (y + y') % q == 0.
        let proof = SnarkjsProof {
            pi_a: vec!["123456789".into(), "987654321".into(), "1".into()],
            pi_b: vec![
                vec!["1".into(), "2".into()],
                vec!["3".into(), "4".into()],
                vec!["1".into(), "0".into()],
            ],
            pi_c: vec!["5".into(), "6".into(), "1".into()],
        };
        let bytes = proof.to_bytes().unwrap();
        let y = BigUint::parse_bytes(b"987654321", 10).unwrap();
        let neg_y = BigUint::from_bytes_be(&bytes.proof_a[32..]);
        let q = fq();
        assert_eq!((&y + &neg_y) % &q, BigUint::from(0u8));
        // x is copied through unchanged.
        assert_eq!(
            BigUint::from_bytes_be(&bytes.proof_a[..32]),
            BigUint::parse_bytes(b"123456789", 10).unwrap()
        );
    }

    #[test]
    fn settle_zk_data_layout() {
        let proof = ProofBytes {
            proof_a: [1u8; 64],
            proof_b: [2u8; 128],
            proof_c: [3u8; 64],
        };
        let root = [4u8; 32];
        let nf = [5u8; 32];
        let action = [6u8; 32];
        let data = settle_zk_data(7, 250_000_000, &proof, &root, &nf, &action);
        assert_eq!(data.len(), wire::SETTLE_ZK_LEN);
        assert_eq!(data[0], wire::tag::SETTLE_ZK);
        assert_eq!(data[1..9], 7u64.to_le_bytes());
        assert_eq!(data[9..17], 250_000_000u64.to_le_bytes());
        assert_eq!(data[17..81], [1u8; 64]);
        assert_eq!(data[81..209], [2u8; 128]);
        assert_eq!(data[209..273], [3u8; 64]);
        assert_eq!(data[273..305], root);
        assert_eq!(data[305..337], nf);
        assert_eq!(data[337..369], action);
        // epoch public input: 32-byte BE of 7.
        let mut epoch_be = [0u8; 32];
        epoch_be[24..].copy_from_slice(&7u64.to_be_bytes());
        assert_eq!(data[369..401], epoch_be);
    }

    #[test]
    fn transact_data_layout() {
        let proof = ProofBytes {
            proof_a: [1u8; 64],
            proof_b: [2u8; 128],
            proof_c: [3u8; 64],
        };
        let public_amount = [10u8; 32];
        let ext_data_hash = [11u8; 32];
        let root = [12u8; 32];
        let nf0 = [13u8; 32];
        let nf1 = [14u8; 32];
        let out0 = [15u8; 32];
        let out1 = [16u8; 32];
        let enc0 = vec![0xAAu8; 100];
        let enc1 = vec![0xBBu8; 50];
        let data = transact_data(
            &public_amount,
            &ext_data_hash,
            &root,
            &nf0,
            &nf1,
            &out0,
            &out1,
            &proof,
            777,
            &enc0,
            &enc1,
        )
        .unwrap();

        assert_eq!(data[0], wire::tag::TRANSACT);
        // Body offsets are relative to the byte AFTER the tag; add 1 here.
        let b = 1;
        assert_eq!(
            data[b + wire::TRANSACT_PUBLIC_AMOUNT_OFF..b + 32],
            public_amount
        );
        assert_eq!(
            data[b + wire::TRANSACT_EXT_DATA_HASH_OFF..b + wire::TRANSACT_EXT_DATA_HASH_OFF + 32],
            ext_data_hash
        );
        assert_eq!(
            data[b + wire::TRANSACT_ROOT_OFF..b + wire::TRANSACT_ROOT_OFF + 32],
            root
        );
        assert_eq!(
            data[b + wire::TRANSACT_IN_NULLIFIER0_OFF..b + wire::TRANSACT_IN_NULLIFIER0_OFF + 32],
            nf0
        );
        assert_eq!(
            data[b + wire::TRANSACT_IN_NULLIFIER1_OFF..b + wire::TRANSACT_IN_NULLIFIER1_OFF + 32],
            nf1
        );
        assert_eq!(
            data[b + wire::TRANSACT_OUT_COMMIT0_OFF..b + wire::TRANSACT_OUT_COMMIT0_OFF + 32],
            out0
        );
        assert_eq!(
            data[b + wire::TRANSACT_OUT_COMMIT1_OFF..b + wire::TRANSACT_OUT_COMMIT1_OFF + 32],
            out1
        );
        assert_eq!(
            data[b + wire::TRANSACT_PROOF_A_OFF..b + wire::TRANSACT_PROOF_B_OFF],
            [1u8; 64]
        );
        assert_eq!(
            data[b + wire::TRANSACT_PROOF_B_OFF..b + wire::TRANSACT_PROOF_C_OFF],
            [2u8; 128]
        );
        assert_eq!(
            data[b + wire::TRANSACT_PROOF_C_OFF..b + wire::TRANSACT_FEE_OFF],
            [3u8; 64]
        );
        assert_eq!(
            data[b + wire::TRANSACT_FEE_OFF..b + wire::TRANSACT_ENC_OFF],
            777u64.to_le_bytes()
        );
        // enc0: [len u16 LE][bytes], then enc1 the same. Nothing trailing.
        let enc_start = b + wire::TRANSACT_ENC_OFF;
        assert_eq!(&data[enc_start..enc_start + 2], &100u16.to_le_bytes());
        assert_eq!(&data[enc_start + 2..enc_start + 102], &enc0[..]);
        let enc1_start = enc_start + 2 + 100;
        assert_eq!(&data[enc1_start..enc1_start + 2], &50u16.to_le_bytes());
        assert_eq!(&data[enc1_start + 2..enc1_start + 52], &enc1[..]);
        assert_eq!(data.len(), enc1_start + 52, "no trailing bytes");
    }

    #[test]
    fn transact_data_rejects_oversized_blob() {
        let proof = ProofBytes {
            proof_a: [0u8; 64],
            proof_b: [0u8; 128],
            proof_c: [0u8; 64],
        };
        let z = [0u8; 32];
        let too_big = vec![0u8; wire::TRANSACT_MAX_ENC_LEN + 1];
        assert!(
            transact_data(&z, &z, &z, &z, &z, &z, &z, &proof, 0, &too_big, &[]).is_err(),
            "a blob over the cap must be rejected"
        );
    }

    #[test]
    fn to_bytes_matches_committed_fixture_proof_a_x() {
        // The committed proof fixture's pi_a[0] serialized big-endian must equal
        // the first 32 bytes of the fixture's PROOF_A (x is not negated).
        let fixture: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../circuits/artifacts/proof_fixture.json"
        )))
        .unwrap();
        let pi_a0 = fixture["proof"]["pi_a"][0].as_str().unwrap();
        let expected_x = to_be32(pi_a0).unwrap();
        let proof = SnarkjsProof::parse(&fixture["proof"].to_string()).unwrap();
        let bytes = proof.to_bytes().unwrap();
        assert_eq!(&bytes.proof_a[..32], &expected_x);
    }

    /// Extract the byte array body of a `pub const NAME: [u8; N] = [ ... ];`.
    fn parse_rust_byte_const(src: &str, name: &str) -> Vec<u8> {
        // Anchor on the declaration `NAME:` so header comments mentioning the name
        // (e.g. "&PROOF_B,") do not match first.
        let decl = format!("{name}:");
        let start = src.find(&decl).expect("const declaration present");
        // From the declaration, jump to the assignment's `= [`.
        let assign = src[start..].find("= [").expect("assignment") + start + 2;
        let close = src[assign..].find(']').expect("close bracket") + assign;
        src[assign + 1..close]
            .split(',')
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .map(|t| t.parse::<u8>().expect("byte literal"))
            .collect()
    }

    /// DECISIVE on-chain-compatibility check: our proof serializer produces
    /// byte-identical PROOF_A / PROOF_B / PROOF_C to the committed
    /// `proof_fixture.rs` (generated by `convert_to_rust.js`), which the program's
    /// own test verifies against `groth16-solana`. So the SettleZk data `prove`
    /// emits is in exactly the byte layout the on-chain verifier accepts.
    #[test]
    fn emitted_proof_bytes_match_committed_fixture_rs() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../circuits/artifacts/proof_fixture.json"
        )))
        .unwrap();
        let rs = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../circuits/artifacts/proof_fixture.rs"
        ));
        let bytes = SnarkjsProof::parse(&fixture["proof"].to_string())
            .unwrap()
            .to_bytes()
            .unwrap();
        assert_eq!(
            bytes.proof_a.to_vec(),
            parse_rust_byte_const(rs, "PROOF_A"),
            "proof_a (negated G1) must match convert_to_rust.js"
        );
        assert_eq!(
            bytes.proof_b.to_vec(),
            parse_rust_byte_const(rs, "PROOF_B"),
            "proof_b (G2) must match convert_to_rust.js"
        );
        assert_eq!(
            bytes.proof_c.to_vec(),
            parse_rust_byte_const(rs, "PROOF_C"),
            "proof_c (G1) must match convert_to_rust.js"
        );
    }
}
