//! The PIN: SHA-256 digests of the three verifying keys this program is willing
//! to verify against, fixed at compile time.
//!
//! # What a digest here means
//!
//! Each constant is `SHA-256` over the CANONICAL encoding
//! ([`crate::state::vk_registry`]) of the correspondingly named vendored key in
//! `src/vk.rs`, `src/transaction_vk.rs`, `src/association_vk.rs`. Those files are
//! copied verbatim from `circuits/artifacts/`, which the circuit build and the
//! trusted setup produce; the digest is therefore a 32-byte commitment to the
//! exact setup output, carried in the program's bytecode. The membership key is
//! the output of a real phase-2 ceremony (see below); the transaction and
//! association keys are still DEV-setup keys from
//! `circuits/build_transaction.sh` and `circuits/build_association.sh`.
//!
//! # What it is for
//!
//! The keys live in program-owned registry accounts rather than in the code
//! path, so anyone can read the key in force straight off the chain. That is
//! only safe because of these constants: `INIT_VK` refuses to install bytes that
//! do not hash to the pinned digest, and every verify re-checks the stored bytes
//! against it before handing them to the verifier. Without the pin, "the vk
//! lives in an account" would mean "whoever writes that account chooses the root
//! of trust", and a well-formed key whose trapdoor the submitter holds forges
//! proofs for false statements.
//!
//! # What it is NOT
//!
//! It is not a rotation mechanism. Changing which key this program accepts means
//! changing a constant here, which means a program upgrade. That is deliberate:
//! a pin a third party could move is not a pin. `docs/VK_REGISTRY.md` states
//! that tradeoff plainly rather than claiming rotation the design does not have.
//!
//! # How these stay honest
//!
//! `digests_match_the_vendored_keys` below recomputes all three from the
//! vendored key modules with a host SHA-256 and asserts equality, so a key edit
//! that forgets the digest (or a digest edit that forgets the key) fails the
//! test suite instead of silently locking out every proof. Nothing in this file
//! is hand-computed.

/// `src/vk.rs` - membership circuit, 4 public inputs, 769-byte encoding.
///
/// This one pins a CEREMONY key: the phase-2 output recorded in
/// `docs/ceremony-run/membership-deployed-transcript.json` (final transcript
/// hash `884c88601173b1f08bd2e26626b0fe4c553dedffe707b2387db754417a9cdd05`).
/// The other two below still pin DEV-setup keys.
pub const MEMBERSHIP_VK_SHA256: [u8; 32] = [
    0xbe, 0x5f, 0x77, 0x6d, 0x2a, 0x4b, 0xa8, 0x36, 0x55, 0xc5, 0x0a, 0x9e, 0xcf, 0x47, 0x19, 0x2c,
    0xd3, 0xaa, 0x74, 0x07, 0x5c, 0xd9, 0xe3, 0xd8, 0xa6, 0x2b, 0xd9, 0x9e, 0x04, 0x3e, 0x4c, 0x76,
];

/// `src/transaction_vk.rs` - JoinSplit circuit, 7 public inputs, 961-byte encoding.
pub const TRANSACTION_VK_SHA256: [u8; 32] = [
    0x9c, 0x31, 0x0a, 0x00, 0x68, 0xa7, 0x03, 0x6b, 0x1b, 0xbf, 0xba, 0xed, 0x59, 0xd5, 0x8c, 0x65,
    0x74, 0x01, 0x54, 0xd6, 0xaf, 0xf4, 0x52, 0x9b, 0x73, 0x8e, 0xcf, 0xf8, 0xc7, 0x60, 0x12, 0x12,
];

/// `src/association_vk.rs` - association circuit, 5 public inputs, 833-byte encoding.
pub const ASSOCIATION_VK_SHA256: [u8; 32] = [
    0x77, 0x03, 0x1f, 0xc7, 0x32, 0xe4, 0xbe, 0x82, 0xfb, 0xd2, 0xc7, 0x7c, 0xb2, 0x07, 0x6b, 0xf9,
    0x2b, 0x4f, 0xdb, 0x1c, 0xe9, 0xa7, 0x4b, 0xf8, 0xcf, 0xa0, 0x85, 0x46, 0x4e, 0x3d, 0x23, 0xbd,
];

#[cfg(test)]
mod tests {
    use groth16_solana::groth16::Groth16Verifyingkey;
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::{state::vk_registry, wire};

    fn digest_of(vk: &Groth16Verifyingkey) -> [u8; 32] {
        let mut buf = [0u8; wire::VK_MAX_ENCODED_LEN];
        let len = vk_registry::encode_into(vk, &mut buf).expect("canonical encoding");
        let mut hasher = Sha256::new();
        hasher.update(&buf[..len]);
        hasher.finalize().into()
    }

    fn hex(bytes: &[u8; 32]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The pinned digests MUST be the digests of the vendored keys. Edit either
    /// side alone and this fails; the printed hex is what a new pin should be.
    #[test]
    fn digests_match_the_vendored_keys() {
        let cases: [(&str, [u8; 32], [u8; 32]); 3] = [
            (
                "MEMBERSHIP_VK_SHA256",
                digest_of(&crate::vk::VERIFYINGKEY),
                MEMBERSHIP_VK_SHA256,
            ),
            (
                "TRANSACTION_VK_SHA256",
                digest_of(&crate::transaction_vk::VERIFYINGKEY),
                TRANSACTION_VK_SHA256,
            ),
            (
                "ASSOCIATION_VK_SHA256",
                digest_of(&crate::association_vk::VERIFYINGKEY),
                ASSOCIATION_VK_SHA256,
            ),
        ];
        for (name, computed, pinned) in cases {
            assert_eq!(
                computed,
                pinned,
                "{name} is stale: vendored key hashes to {}, pin says {}",
                hex(&computed),
                hex(&pinned)
            );
        }
    }

    /// The canonical encoding must have the documented, circuit-determined
    /// length, so a blob of any other size is rejected on shape alone.
    #[test]
    fn canonical_encoding_lengths_are_circuit_determined() {
        let cases: [(&Groth16Verifyingkey, usize); 3] = [
            (&crate::vk::VERIFYINGKEY, 769),
            (&crate::transaction_vk::VERIFYINGKEY, 961),
            (&crate::association_vk::VERIFYINGKEY, 833),
        ];
        for (vk, expected) in cases {
            let mut buf = [0u8; wire::VK_MAX_ENCODED_LEN];
            let len = vk_registry::encode_into(vk, &mut buf).expect("canonical encoding");
            assert_eq!(len, expected);
            assert_eq!(len, wire::vk_encoded_len(vk.nr_pubinputs));
            assert_eq!(buf[wire::VK_NR_PUBINPUTS_OFF] as usize, vk.nr_pubinputs);
        }
    }

    /// Every approved circuit's public-input count must equal the vendored key's,
    /// so the table cannot drift from the keys it pins.
    #[test]
    fn approved_table_matches_the_vendored_keys() {
        let expected: [(u8, usize); 3] = [
            (
                wire::CIRCUIT_MEMBERSHIP,
                crate::vk::VERIFYINGKEY.nr_pubinputs,
            ),
            (
                wire::CIRCUIT_TRANSACTION,
                crate::transaction_vk::VERIFYINGKEY.nr_pubinputs,
            ),
            (
                wire::CIRCUIT_ASSOCIATION,
                crate::association_vk::VERIFYINGKEY.nr_pubinputs,
            ),
        ];
        for (id, nr_pubinputs) in expected {
            let circuit = vk_registry::approved(id).expect("circuit is approved");
            assert_eq!(circuit.nr_pubinputs, nr_pubinputs, "circuit {id}");
        }
        // An id outside the table is pinned to nothing.
        assert!(vk_registry::approved(3).is_err());
        assert!(vk_registry::approved(255).is_err());
    }
}
