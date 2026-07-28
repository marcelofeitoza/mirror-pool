//! Opt-in selective disclosure to an auditor the user chose (host-side).
//!
//! This is the client half of the on-chain viewing-key layer. Nothing here is
//! new cryptography: a disclosure is exactly one
//! [`crate::encrypted_note`] blob - X25519 ECDH, HKDF-SHA256, ChaCha20-Poly1305 -
//! sealed to the auditor's registered viewing key instead of to a note
//! recipient's. What changes is the PLAINTEXT and what the reader does with it.
//!
//! ## What is disclosed, and why that is the useful payload
//!
//! The behavioral ZK path's leaf and tag are
//!
//! ```text
//! commitment    = Poseidon(secret, actionHash, epoch)
//! nullifierHash = Poseidon(secret, epoch)
//! ```
//!
//! so `(epoch, secret)` plus the `actionHash` - which the on-chain record stores
//! in the clear, because it is derived from the settlement's own public recipient
//! and amount - is enough for a reader to recompute BOTH. That is the whole
//! disclosure: with the commitment the auditor can find the `CommitDeposit`
//! transaction (hence the wallet that funded the deposit) and with the nullifier
//! hash they can find the `SettleZk` that spent it (hence the payout). It closes
//! the deposit-to-settlement link for ONE action, for ONE reader.
//!
//! The plaintext is therefore `(u64, [u8; 32])`, byte-for-byte the shape
//! [`crate::encrypted_note`] already seals for value notes - there the `u64` is an
//! amount and the 32 bytes are a blinding, here they are an epoch and a note
//! secret. The same 100-byte blob, the same AEAD, the same trial-decrypt scan.
//!
//! ## What disclosing the secret does NOT give away
//!
//! Handing an auditor the `secret` does not hand them the money. The escrow's
//! only exit is `SettleZk`, which pays the address bound in `actionHash` and
//! nothing else, so a reader who learns the secret can at most produce a proof
//! that pays the user's own recipient. It is still worth disclosing only AFTER
//! the settlement has landed: before it, a reader holding the secret can settle
//! the action at a moment of their choosing (into a thinner window than the user
//! would have picked), which is a real anonymity harm even though it is not a
//! theft. See `docs/COMPLIANCE.md`.

use crate::encrypted_note::{self, ViewingKeypair};
use crate::{commit_with_action_hash, nullifier, Commitment, Epoch, Hash32, Nullifier, Secret};

/// The on-chain blob length of one sealed disclosure (identical to an encrypted
/// note's, since it IS one).
pub const DISCLOSURE_BLOB_LEN: usize = encrypted_note::ENC_NOTE_BLOB_LEN;

/// The material a disclosure carries, once opened.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct OpenedDisclosure {
    /// The epoch the disclosed commitment and nullifier are bound to.
    pub epoch: Epoch,
    /// The note secret. Spend material for the ZK path's proof (though not for
    /// redirecting its payout - see the module header).
    pub secret: Secret,
}

impl core::fmt::Debug for OpenedDisclosure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The secret is disclosure material; never print it.
        f.debug_struct("OpenedDisclosure")
            .field("epoch", &self.epoch.0)
            .field("secret", &"***")
            .finish()
    }
}

/// What an opened disclosure lets the reader recompute and then look up on-chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DisclosedAction {
    /// `Poseidon(secret, actionHash, epoch)` - the deposit leaf. Appears in the
    /// `CommitDeposit` instruction data of the transaction that escrowed it.
    pub commitment: Commitment,
    /// `Poseidon(secret, epoch)` - the epoch-scoped spend tag. Its Nullifier PDA
    /// (`["nf", pool, epoch, nullifierHash]`) exists if and only if the action
    /// has settled.
    pub nullifier: Nullifier,
    /// The epoch, echoed for convenience when deriving the Nullifier PDA.
    pub epoch: Epoch,
}

/// Seal `(epoch, secret)` to an auditor's registered X25519 viewing key.
///
/// Fresh OS randomness per call (the ephemeral secret), so two disclosures of the
/// same action to the same auditor are different ciphertexts.
pub fn seal(auditor_view_pub: &[u8; 32], epoch: Epoch, secret: &Secret) -> Vec<u8> {
    encrypted_note::encrypt_note(auditor_view_pub, epoch.0, &secret.0)
}

/// Seal with a caller-supplied ephemeral secret (deterministic).
///
/// SECURITY: the ephemeral secret MUST be unique per sealing; see
/// [`encrypted_note::encrypt_note_with_ephemeral_secret`]. Production code uses
/// [`seal`]; this exists so tests and fixtures are reproducible.
pub fn seal_with_ephemeral_secret(
    ephemeral_secret: [u8; 32],
    auditor_view_pub: &[u8; 32],
    epoch: Epoch,
    secret: &Secret,
) -> Vec<u8> {
    encrypted_note::encrypt_note_with_ephemeral_secret(
        ephemeral_secret,
        auditor_view_pub,
        epoch.0,
        &secret.0,
    )
}

/// Trial-open one on-chain disclosure blob with a viewing secret.
///
/// Returns `Some` iff the blob was sealed to this viewing key. Every failure
/// (wrong reader, tampered or malformed bytes) returns `None` and never panics,
/// which is what makes scanning a whole directory of records safe.
pub fn open(viewing_secret: &[u8; 32], blob: &[u8]) -> Option<OpenedDisclosure> {
    let decrypted = encrypted_note::try_decrypt_note(viewing_secret, blob)?;
    Some(OpenedDisclosure {
        epoch: Epoch(decrypted.amount),
        secret: Secret(decrypted.blinding),
    })
}

/// Recompute what the disclosure claims: the deposit leaf and the spend tag.
///
/// `action_hash` comes from the on-chain record (the program recomputed it from
/// the settlement's own recipient and amount, so it is not the discloser's to
/// choose). The two outputs are what the reader looks up on-chain to decide
/// whether the disclosure is true - the program cannot check that for them.
pub fn derive_action(opened: &OpenedDisclosure, action_hash: &Hash32) -> DisclosedAction {
    DisclosedAction {
        commitment: commit_with_action_hash(&opened.secret, action_hash, opened.epoch),
        nullifier: nullifier(&opened.secret, opened.epoch),
        epoch: opened.epoch,
    }
}

/// One on-chain record as a scanner sees it: the public `action_hash` the program
/// stored, and the sealed blob.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedRecord {
    /// The record's `action_hash` field (public, recomputed on-chain).
    pub action_hash: Hash32,
    /// The record's sealed blob.
    pub blob: Vec<u8>,
}

/// A record this reader could open, together with what it discloses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScannedDisclosure {
    /// Index of the record in the input slice, so the caller can map back to the
    /// account it came from.
    pub index: usize,
    /// The recomputed deposit leaf and spend tag.
    pub action: DisclosedAction,
}

/// Trial-open every record with `viewing`, keeping the ones addressed to it.
///
/// Records for other auditors fail their AEAD check and are skipped silently,
/// exactly as note scanning does. The opened `secret` is deliberately NOT
/// returned here: what a caller almost always wants is the pair of on-chain
/// lookups, and keeping the secret out of the aggregate result keeps it from
/// being logged by accident. Use [`open`] directly when the secret itself is
/// needed.
pub fn scan(viewing: &ViewingKeypair, records: &[SealedRecord]) -> Vec<ScannedDisclosure> {
    let secret = viewing.to_secret_bytes();
    records
        .iter()
        .enumerate()
        .filter_map(|(index, record)| {
            let opened = open(&secret, &record.blob)?;
            Some(ScannedDisclosure {
                index,
                action: derive_action(&opened, &record.action_hash),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transfer_action_hash;

    fn bytes(seed: u8) -> [u8; 32] {
        let mut b = [0u8; 32];
        for (i, x) in b.iter_mut().enumerate() {
            *x = seed.wrapping_add(i as u8).wrapping_mul(17).wrapping_add(3);
        }
        b
    }

    /// The whole point of the layer: the auditor recomputes the SAME commitment
    /// the depositor posted and the SAME nullifier the settlement burned, from
    /// nothing but the sealed blob and the record's public `action_hash`.
    #[test]
    fn round_trip_reproduces_the_deposit_leaf_and_the_spend_tag() {
        let auditor = ViewingKeypair::from_secret(bytes(1));
        let secret = Secret(bytes(2));
        let epoch = Epoch(4_242);
        let recipient = bytes(3);
        let amount = 750_000_000u64;
        let action_hash = transfer_action_hash(&recipient, amount);

        // What the depositor posted on-chain.
        let expected_commitment = commit_with_action_hash(&secret, &action_hash, epoch);
        let expected_nullifier = nullifier(&secret, epoch);

        let blob = seal(&auditor.public(), epoch, &secret);
        assert_eq!(blob.len(), DISCLOSURE_BLOB_LEN);

        let opened = open(&auditor.to_secret_bytes(), &blob).expect("the auditor must open it");
        assert_eq!(opened.epoch, epoch);
        assert_eq!(opened.secret, secret);

        let action = derive_action(&opened, &action_hash);
        assert_eq!(action.commitment, expected_commitment);
        assert_eq!(action.nullifier, expected_nullifier);
        assert_eq!(action.epoch, epoch);
    }

    /// A record sealed to somebody else stays shut, and a tampered one is
    /// rejected rather than silently mis-opened.
    #[test]
    fn a_disclosure_opens_only_for_its_auditor() {
        let auditor = ViewingKeypair::from_secret(bytes(4));
        let stranger = ViewingKeypair::from_secret(bytes(5));
        let secret = Secret(bytes(6));
        let mut blob = seal(&auditor.public(), Epoch(9), &secret);

        assert!(open(&stranger.to_secret_bytes(), &blob).is_none());

        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        assert!(open(&auditor.to_secret_bytes(), &blob).is_none());
        assert!(open(&auditor.to_secret_bytes(), &[]).is_none());
    }

    /// Scanning a mixed directory returns exactly this reader's records, and each
    /// one is bound to the `action_hash` of the record it came from - not to some
    /// other record's.
    #[test]
    fn scan_returns_only_my_records_bound_to_their_own_action() {
        let me = ViewingKeypair::from_secret(bytes(7));
        let other = ViewingKeypair::from_secret(bytes(8));

        let mine_secret = Secret(bytes(9));
        let mine_epoch = Epoch(11);
        let mine_action = transfer_action_hash(&bytes(10), 750_000_000);
        let theirs_action = transfer_action_hash(&bytes(11), 750_000_000);

        let records = vec![
            SealedRecord {
                action_hash: theirs_action,
                blob: seal(&other.public(), Epoch(12), &Secret(bytes(12))),
            },
            SealedRecord {
                action_hash: mine_action,
                blob: seal(&me.public(), mine_epoch, &mine_secret),
            },
            SealedRecord {
                action_hash: theirs_action,
                blob: seal(&other.public(), Epoch(13), &Secret(bytes(13))),
            },
        ];

        let hits = scan(&me, &records);
        assert_eq!(hits.len(), 1, "scan must find exactly my one record");
        assert_eq!(hits[0].index, 1);
        assert_eq!(
            hits[0].action.commitment,
            commit_with_action_hash(&mine_secret, &mine_action, mine_epoch)
        );
        assert_eq!(
            hits[0].action.nullifier,
            nullifier(&mine_secret, mine_epoch)
        );
    }

    /// A lie is detectable. The reader recomputes the leaf from the disclosed
    /// secret; if the discloser sealed a secret that has nothing to do with the
    /// commitment they deposited, the recomputed leaf simply is not on-chain. The
    /// program cannot catch this (it cannot decrypt); the auditor catches it in
    /// one Poseidon hash.
    #[test]
    fn a_false_disclosure_recomputes_to_a_leaf_that_was_never_posted() {
        let auditor = ViewingKeypair::from_secret(bytes(14));
        let real_secret = Secret(bytes(15));
        let epoch = Epoch(21);
        let action_hash = transfer_action_hash(&bytes(16), 750_000_000);
        let posted = commit_with_action_hash(&real_secret, &action_hash, epoch);

        // The discloser seals a DIFFERENT secret.
        let blob = seal(&auditor.public(), epoch, &Secret(bytes(17)));
        let opened = open(&auditor.to_secret_bytes(), &blob).unwrap();
        let claimed = derive_action(&opened, &action_hash);
        assert_ne!(
            claimed.commitment, posted,
            "a lie must not reproduce the posted leaf"
        );
    }

    /// The plaintext really is the same shape the value layer already seals, so
    /// this layer adds no new ciphertext format to review.
    #[test]
    fn the_blob_is_an_ordinary_encrypted_note_blob() {
        let auditor = ViewingKeypair::from_secret(bytes(18));
        let blob =
            seal_with_ephemeral_secret(bytes(19), &auditor.public(), Epoch(7), &Secret(bytes(20)));
        let again =
            seal_with_ephemeral_secret(bytes(19), &auditor.public(), Epoch(7), &Secret(bytes(20)));
        assert_eq!(blob, again, "the deterministic path must be reproducible");
        assert_eq!(blob.len(), encrypted_note::ENC_NOTE_BLOB_LEN);
        // And it decodes through the note API as the (u64, 32-byte) pair it is.
        let as_note = encrypted_note::try_decrypt_note(&auditor.to_secret_bytes(), &blob).unwrap();
        assert_eq!(as_note.amount, 7);
        assert_eq!(as_note.blinding, bytes(20));
    }
}
