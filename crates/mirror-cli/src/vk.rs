//! The committed verifying keys, in the CANONICAL encoding `INIT_VK` expects.
//!
//! The on-chain program no longer reads its verifying key from its own code: it
//! reads it from a write-once registry account, and accepts it only if the bytes
//! hash to a digest the program pins at compile time. Someone has to publish
//! those bytes once per deployment, and this module is where the client gets
//! them: the same `circuits/artifacts/*_vk.rs` files the program vendors, so a
//! client cannot accidentally offer a key the program will refuse.
//!
//! There is exactly one legal byte string per circuit, so nothing here is a
//! choice: `mirror-cli init-vk` is a publication step, not a configuration step.

use anyhow::{anyhow, Result};
use groth16_solana::groth16::Groth16Verifyingkey;
use mirror_core::wire;

/// The committed MEMBERSHIP verifying key (`circuits/artifacts/vk.rs`),
/// byte-for-byte the file `programs/mirror-pool/src/vk.rs` vendors.
mod membership {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../circuits/artifacts/vk.rs"
    ));
}

/// The committed JoinSplit verifying key (`circuits/artifacts/transaction_vk.rs`).
mod transaction {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../circuits/artifacts/transaction_vk.rs"
    ));
}

/// The committed ASSOCIATION verifying key (`circuits/artifacts/association_vk.rs`).
mod association {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../circuits/artifacts/association_vk.rs"
    ));
}

/// Map a human circuit name to its wire id.
pub fn circuit_id(name: &str) -> Result<u8> {
    match name {
        "membership" => Ok(wire::CIRCUIT_MEMBERSHIP),
        "transaction" => Ok(wire::CIRCUIT_TRANSACTION),
        "association" => Ok(wire::CIRCUIT_ASSOCIATION),
        other => Err(anyhow!(
            "unknown circuit {other:?} (expected membership, transaction or association)"
        )),
    }
}

/// The committed verifying key for a circuit: the same bytes the program pins by
/// digest and reads from its registry PDA. `prove` checks its own output against
/// this before emitting, so a proof made under a mismatched proving key fails
/// locally instead of on chain.
pub(crate) fn key_for(circuit_id: u8) -> Result<&'static Groth16Verifyingkey<'static>> {
    match circuit_id {
        wire::CIRCUIT_MEMBERSHIP => Ok(&membership::VERIFYINGKEY),
        wire::CIRCUIT_TRANSACTION => Ok(&transaction::VERIFYINGKEY),
        wire::CIRCUIT_ASSOCIATION => Ok(&association::VERIFYINGKEY),
        other => Err(anyhow!("no committed verifying key for circuit id {other}")),
    }
}

/// SHA-256 of a canonical encoding, hex. This is the number the program pins in
/// `programs/mirror-pool/src/vk_digest.rs`, printed so a deployment can be
/// checked against the source out of band.
pub fn digest(canonical: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let out: [u8; 32] = Sha256::digest(canonical).into();
    out.iter().map(|b| format!("{b:02x}")).collect()
}

/// The canonical encoding of a circuit's committed verifying key: exactly the
/// bytes `INIT_VK` hashes and stores.
pub fn canonical(circuit_id: u8) -> Result<Vec<u8>> {
    let vk = key_for(circuit_id)?;
    wire::encode_vk(
        vk.nr_pubinputs,
        &vk.vk_alpha_g1,
        &vk.vk_beta_g2,
        &vk.vk_gamme_g2,
        &vk.vk_delta_g2,
        vk.vk_ic,
    )
    .ok_or_else(|| anyhow!("committed verifying key for circuit {circuit_id} is malformed"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    /// The canonical encodings must have the documented, circuit-determined
    /// lengths. These are the lengths the on-chain shape check enforces before
    /// it hashes anything, so a client that produced any other length would be
    /// rejected on shape.
    #[test]
    fn canonical_encodings_have_the_documented_lengths() {
        for (name, expected) in [
            ("membership", 769usize),
            ("association", 833),
            ("transaction", 961),
        ] {
            let id = circuit_id(name).unwrap();
            let bytes = canonical(id).unwrap();
            assert_eq!(bytes.len(), expected, "{name}");
            // The encoded nr_pubinputs byte must agree with what the length
            // implies, which is exactly the pair of facts the on-chain shape
            // check cross-examines before it hashes anything.
            let implied = (bytes.len() - wire::VK_IC_OFF) / wire::VK_G1_LEN - 1;
            assert_eq!(bytes[wire::VK_NR_PUBINPUTS_OFF] as usize, implied, "{name}");
        }
    }

    /// The digests the client would publish must be the digests the program
    /// pins. These are copied from `programs/mirror-pool/src/vk_digest.rs`; if
    /// the circuits are rebuilt, BOTH sides move together or this fails.
    #[test]
    fn canonical_encodings_hash_to_the_pinned_digests() {
        let expected: [(&str, &str); 3] = [
            (
                "membership",
                "be5f776d2a4ba83655c50a9ecf47192cd3aa74075cd9e3d8a62bd99e043e4c76",
            ),
            (
                "transaction",
                "9c310a0068a7036b1bbfbaed59d58c65740154d6aff4529b738ecff8c7601212",
            ),
            (
                "association",
                "77031fc732e4be82fbd2c77cb2076bf92b4fdb1ce9a74bf8cfa085464e3d23bd",
            ),
        ];
        for (name, want) in expected {
            let bytes = canonical(circuit_id(name).unwrap()).unwrap();
            let got: [u8; 32] = Sha256::digest(&bytes).into();
            let got_hex: String = got.iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(got_hex, want, "{name} digest drifted from the on-chain pin");
        }
    }

    #[test]
    fn unknown_circuits_are_rejected() {
        assert!(circuit_id("nope").is_err());
        assert!(canonical(9).is_err());
    }
}
