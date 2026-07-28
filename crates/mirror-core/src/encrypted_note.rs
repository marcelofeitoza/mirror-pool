//! Encrypted output-notes and client-side discovery (host-side only).
//!
//! When a confidential [`Transact`](crate::wire::tag::TRANSACT) creates an output
//! note for a recipient, the sender encrypts the note's minimal spend material to
//! the recipient's **viewing key** and posts the ciphertext on-chain as one of the
//! two `enc` blobs (bound into `extDataHash`, see [`crate::note::ext_data_hash`]).
//! The recipient scans the on-chain `enc` blobs, trial-decrypts each with their
//! viewing key, and recovers the notes addressed to them.
//!
//! ## Two separate keys per address
//!
//! A recipient's address is the pair `(value public_key, viewing public_key)`:
//!
//! - The **value** key ([`crate::note::ValueKeypair`], a BN254 Poseidon key) is
//!   the in-circuit spend key: `public_key = Poseidon(private_key)`. It authorizes
//!   spending a note and is what the note commitment binds.
//! - The **viewing** key ([`ViewingKeypair`], an X25519 key) is used only to
//!   encrypt/discover notes off-chain. It never enters the circuit.
//!
//! Keeping them separate means a recipient can hand a third party (an auditor, a
//! watch-only wallet) the viewing key to *discover* incoming notes without also
//! granting the ability to *spend* them.
//!
//! ## What is encrypted
//!
//! The plaintext is the minimal material the recipient does not already know:
//! the note `amount` (`u64`) and its `blinding` (32 bytes). The recipient already
//! knows their own value `public_key`, so with `(amount, public_key, blinding)`
//! they can rebuild the [`Note`](crate::note::Note), recompute its commitment, find
//! its `leaf_index` by matching that commitment against the on-chain tree, and
//! later spend it.
//!
//! ## Construction (ECIES: X25519 + HKDF-SHA256 + ChaCha20-Poly1305)
//!
//! ```text
//! ephemeral_secret  = random 32 bytes (OS RNG; per message, MUST be unique)
//! ephemeral_pub     = X25519(ephemeral_secret, basepoint)
//! shared            = X25519(ephemeral_secret, recipient_view_pub)   // ECDH, 32B
//! okm(44)           = HKDF-SHA256(ikm = shared,
//!                                 salt = ephemeral_pub || recipient_view_pub,
//!                                 info = DOMAIN)
//! key(32)           = okm[0..32]
//! nonce(12)         = okm[32..44]
//! ct = ChaCha20Poly1305(key, nonce).seal(aad = ephemeral_pub, plaintext)
//! ```
//!
//! Deriving both the AEAD key and nonce from the fresh-per-message ECDH output
//! makes the `(key, nonce)` pair unique for every encryption, so nonce reuse is
//! structurally impossible. The recipient re-derives the same shared secret with
//! their viewing secret and `ephemeral_pub`, so decryption needs no extra state.
//!
//! ## On-chain blob byte layout (fixed)
//!
//! ```text
//! ephemeral_pub(32) || nonce(12) || ciphertext_and_tag(56)   = 100 bytes
//! ```
//!
//! where `ciphertext_and_tag` is the 40-byte plaintext plus the 16-byte Poly1305
//! tag. The total, [`ENC_NOTE_BLOB_LEN`] = 100, is well under the on-chain
//! [`TRANSACT_MAX_ENC_LEN`](crate::wire::TRANSACT_MAX_ENC_LEN) per-blob cap of 256,
//! pinned by a compile-time assert below. The coordinator/CLI produce exactly this
//! blob and place it in the Transact `enc` field, and the same bytes are hashed
//! into `extDataHash`, so sender, program, and recipient agree byte-for-byte.

use crate::note::Note;
use crate::Hash32;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

/// X25519 public-key / shared-secret / ephemeral-public length (bytes).
pub const X25519_LEN: usize = 32;
/// ChaCha20-Poly1305 nonce length (bytes).
pub const NONCE_LEN: usize = 12;
/// Poly1305 authentication tag length (bytes).
pub const TAG_LEN: usize = 16;
/// The AEAD plaintext: `amount(8, big-endian) || blinding(32)`.
pub const PLAINTEXT_LEN: usize = 8 + 32;
/// Total on-chain blob length: `ephemeral_pub(32) || nonce(12) || ct+tag(56)`.
pub const ENC_NOTE_BLOB_LEN: usize = X25519_LEN + NONCE_LEN + PLAINTEXT_LEN + TAG_LEN;

/// Byte offset of the nonce inside a blob (right after `ephemeral_pub`).
const NONCE_OFF: usize = X25519_LEN;
/// Byte offset of the AEAD ciphertext (`ct || tag`) inside a blob.
const CT_OFF: usize = X25519_LEN + NONCE_LEN;

/// HKDF `info` domain separator: binds derived keys to this scheme + version.
const KDF_INFO: &[u8] = b"mirror-pool/encrypted-note/v1";

// The blob MUST fit the on-chain per-blob cap so a Transact stays within limits.
const _: () = assert!(ENC_NOTE_BLOB_LEN <= crate::wire::TRANSACT_MAX_ENC_LEN);
const _: () = assert!(ENC_NOTE_BLOB_LEN == 100);

/// Little-endian encoding of the curve25519 field prime `p = 2^255 - 19`. Used
/// only to reject non-canonical public keys byte-wise (see
/// [`is_acceptable_x25519_pubkey`]); no field arithmetic happens here.
const CURVE25519_P_LE: [u8; 32] = [
    0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
];

/// The CANONICAL small-order X25519 public keys, i.e. the ones that survive the
/// canonicality filter below. Points of order 1, 2, 4 and 8 produce an ECDH
/// output that does not depend on the peer's secret at all, so a "sealed" blob
/// built against one is readable by anybody.
///
/// The non-canonical members of the classic 12-entry blacklist (`p`, `p+1`, and
/// the high-bit-set variants) are already rejected by the canonicality test, so
/// they are deliberately NOT repeated here.
const SMALL_ORDER_X25519: [[u8; 32]; 5] = [
    // 0 (order 4)
    [0u8; 32],
    // 1 (order 1)
    [
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ],
    // order 8
    [
        0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4,
        0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49,
        0xb8, 0x00,
    ],
    // order 8
    [
        0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef,
        0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f,
        0x11, 0x57,
    ],
    // p - 1 (order 2)
    [
        0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
];

/// Structural acceptance test for a 32-byte X25519 public key.
///
/// This is a BYTE test, not a curve membership proof. It rejects exactly two
/// classes, and it is worth being precise about why each one matters here:
///
/// 1. **Non-canonical encodings**: the top bit is ignored by X25519 and values
///    `>= p` reduce, so several byte strings denote the same key. Anywhere a
///    public key is used as an identifier (this repo derives a PDA from one) that
///    turns into malleability: two different accounts for one key. Requiring the
///    canonical little-endian encoding `< p` with the top bit clear makes the
///    identifier unique.
/// 2. **Small-order points**: the ECDH output for these is a fixed value
///    independent of the peer's secret, so anything "sealed" to one is public. A
///    key like this is either a broken client or a deliberate trap, and either way
///    a user who publishes a disclosure against one has published it to everybody.
///
/// An honestly generated key (clamped scalar, OS randomness) never trips either
/// branch, so this is a guard against buggy or hostile input and never fires on
/// the happy path. It does NOT prove the bytes are a point on the curve: X25519
/// accepts any 32 bytes, and a full check would need field arithmetic this crate
/// deliberately does not carry. The on-chain program mirrors this function
/// byte-for-byte (`state::viewing_key::is_acceptable_viewing_pub`).
pub fn is_acceptable_x25519_pubkey(pubkey: &[u8; 32]) -> bool {
    // (1a) The high bit is ignored by X25519, so a set one is a second encoding
    // of the same key.
    if pubkey[31] & 0x80 != 0 {
        return false;
    }
    // (1b) Canonical means numerically less than p, little-endian.
    let mut canonical = false;
    for i in (0..32).rev() {
        if pubkey[i] < CURVE25519_P_LE[i] {
            canonical = true;
            break;
        }
        if pubkey[i] > CURVE25519_P_LE[i] {
            return false;
        }
    }
    if !canonical {
        // Equal to p: not canonical either.
        return false;
    }
    // (2) Small-order points.
    for bad in SMALL_ORDER_X25519.iter() {
        if pubkey == bad {
            return false;
        }
    }
    true
}

/// A recipient's X25519 **viewing** keypair. Distinct from the value spend key
/// ([`crate::note::ValueKeypair`]): this one only encrypts and discovers notes and
/// never enters the circuit. The public half is half of the recipient address.
#[derive(Clone)]
pub struct ViewingKeypair {
    secret: StaticSecret,
}

impl ViewingKeypair {
    /// Build a viewing keypair from a 32-byte secret. The bytes are X25519-clamped
    /// internally, so any 32 bytes are a valid secret.
    pub fn from_secret(secret: [u8; 32]) -> Self {
        Self {
            secret: StaticSecret::from(secret),
        }
    }

    /// The X25519 public key (`[u8; 32]`) senders encrypt to. This is the viewing
    /// half of the recipient's `(value_pub, viewing_pub)` address.
    pub fn public(&self) -> [u8; 32] {
        PublicKey::from(&self.secret).to_bytes()
    }

    /// The raw 32-byte viewing secret (clamped). Callers that persist a wallet may
    /// need to serialize it; treat it as sensitive.
    pub fn to_secret_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }
}

impl core::fmt::Debug for ViewingKeypair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never print the secret material; the public key is safe to show.
        f.debug_struct("ViewingKeypair")
            .field("public", &self.public())
            .field("secret", &"***")
            .finish()
    }
}

/// The spend material recovered from a successfully decrypted blob. Combined with
/// the recipient's own value `public_key` it rebuilds the full [`Note`].
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DecryptedNote {
    /// The note value.
    pub amount: u64,
    /// The note blinding factor, canonical big-endian (32 bytes).
    pub blinding: Hash32,
}

impl DecryptedNote {
    /// Rebuild the [`Note`] given the recipient's value `public_key` (which the
    /// recipient already holds). The result recomputes the on-chain commitment, so
    /// the recipient can locate the leaf and later spend it.
    pub fn to_note(&self, value_public_key: Hash32) -> Note {
        Note::new(self.amount, value_public_key, self.blinding)
    }
}

impl core::fmt::Debug for DecryptedNote {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The blinding is spend material; do not print it.
        f.debug_struct("DecryptedNote")
            .field("amount", &self.amount)
            .field("blinding", &"***")
            .finish()
    }
}

/// Derive the 32-byte AEAD key and 12-byte nonce from an ECDH shared secret.
///
/// `HKDF-SHA256(ikm = shared, salt = ephemeral_pub || recipient_pub, info = DOMAIN)`
/// expanded to `PLAINTEXT`-independent 44 bytes, split into `key || nonce`. Binding
/// both public keys into the salt ties the key material to this exact transcript.
fn derive_key_nonce(
    shared: &[u8; 32],
    ephemeral_pub: &[u8; 32],
    recipient_pub: &[u8; 32],
) -> ([u8; 32], [u8; NONCE_LEN]) {
    let mut salt = [0u8; 2 * X25519_LEN];
    salt[..X25519_LEN].copy_from_slice(ephemeral_pub);
    salt[X25519_LEN..].copy_from_slice(recipient_pub);

    let hk = Hkdf::<Sha256>::new(Some(&salt), shared);
    let mut okm = [0u8; 32 + NONCE_LEN];
    hk.expand(KDF_INFO, &mut okm)
        .expect("HKDF-SHA256 expand of 44 bytes is always in range");

    let mut key = [0u8; 32];
    key.copy_from_slice(&okm[..32]);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&okm[32..]);
    (key, nonce)
}

/// Serialize the note plaintext: `amount(8, big-endian) || blinding(32)`.
fn plaintext(amount: u64, blinding: &Hash32) -> [u8; PLAINTEXT_LEN] {
    let mut pt = [0u8; PLAINTEXT_LEN];
    pt[..8].copy_from_slice(&amount.to_be_bytes());
    pt[8..].copy_from_slice(blinding);
    pt
}

/// Encrypt a note's spend material `(amount, blinding)` to a recipient's viewing
/// public key, producing the [`ENC_NOTE_BLOB_LEN`]-byte on-chain blob.
///
/// A fresh ephemeral X25519 secret is drawn from the OS RNG for every call, so the
/// derived `(key, nonce)` is unique per message. This is the production entry
/// point; use [`encrypt_note_with_ephemeral_secret`] only for deterministic tests.
pub fn encrypt_note(recipient_view_pub: &[u8; 32], amount: u64, blinding: &Hash32) -> Vec<u8> {
    use rand::RngCore;
    let mut ephemeral_secret = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut ephemeral_secret);
    let blob =
        encrypt_note_with_ephemeral_secret(ephemeral_secret, recipient_view_pub, amount, blinding);
    // Do not leave the raw ephemeral secret lingering on the stack.
    ephemeral_secret.fill(0);
    blob
}

/// Encrypt with a caller-supplied ephemeral secret (deterministic).
///
/// SECURITY: `ephemeral_secret` MUST be unique per encryption. Reusing it for two
/// notes to the same recipient reuses the AEAD `(key, nonce)` and breaks
/// confidentiality. Production code MUST use [`encrypt_note`] (OS randomness); this
/// path exists to make fixtures reproducible.
pub fn encrypt_note_with_ephemeral_secret(
    ephemeral_secret: [u8; 32],
    recipient_view_pub: &[u8; 32],
    amount: u64,
    blinding: &Hash32,
) -> Vec<u8> {
    let eph = StaticSecret::from(ephemeral_secret);
    let ephemeral_pub = PublicKey::from(&eph).to_bytes();
    let recipient = PublicKey::from(*recipient_view_pub);
    let shared = eph.diffie_hellman(&recipient).to_bytes();

    let (key, nonce) = derive_key_nonce(&shared, &ephemeral_pub, recipient_view_pub);
    let pt = plaintext(amount, blinding);

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &pt,
                aad: &ephemeral_pub,
            },
        )
        .expect("ChaCha20-Poly1305 encryption of a fixed-length plaintext cannot fail");
    debug_assert_eq!(ct.len(), PLAINTEXT_LEN + TAG_LEN);

    let mut blob = Vec::with_capacity(ENC_NOTE_BLOB_LEN);
    blob.extend_from_slice(&ephemeral_pub);
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ct);
    debug_assert_eq!(blob.len(), ENC_NOTE_BLOB_LEN);
    blob
}

/// Trial-decrypt one on-chain blob with a viewing secret.
///
/// Returns `Some(DecryptedNote)` iff the blob was encrypted to this viewing key
/// (AEAD authentication succeeds and the plaintext is well-formed). Any failure
/// (wrong recipient, malformed or truncated blob, tampered bytes) returns `None`;
/// this function never panics on attacker-chosen input.
pub fn try_decrypt_note(viewing_secret: &[u8; 32], blob: &[u8]) -> Option<DecryptedNote> {
    if blob.len() != ENC_NOTE_BLOB_LEN {
        return None;
    }
    let mut ephemeral_pub = [0u8; X25519_LEN];
    ephemeral_pub.copy_from_slice(&blob[..X25519_LEN]);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&blob[NONCE_OFF..NONCE_OFF + NONCE_LEN]);
    let ct = &blob[CT_OFF..];

    let secret = StaticSecret::from(*viewing_secret);
    let recipient_pub = PublicKey::from(&secret).to_bytes();
    let shared = secret
        .diffie_hellman(&PublicKey::from(ephemeral_pub))
        .to_bytes();

    let (key, derived_nonce) = derive_key_nonce(&shared, &ephemeral_pub, &recipient_pub);
    // The stored nonce must match the one we derive, and the AEAD tag must verify.
    if derived_nonce != nonce {
        return None;
    }

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let pt = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: ct,
                aad: &ephemeral_pub,
            },
        )
        .ok()?;
    if pt.len() != PLAINTEXT_LEN {
        return None;
    }

    let mut amount_bytes = [0u8; 8];
    amount_bytes.copy_from_slice(&pt[..8]);
    let mut blinding = [0u8; 32];
    blinding.copy_from_slice(&pt[8..]);
    Some(DecryptedNote {
        amount: u64::from_be_bytes(amount_bytes),
        blinding,
    })
}

/// Scan a batch of on-chain blobs, returning the notes addressed to `viewing`.
///
/// Trial-decrypts each blob with the viewing secret and keeps the hits, in input
/// order. Decoys and notes for other recipients silently fail their AEAD check and
/// are skipped.
pub fn scan(viewing: &ViewingKeypair, blobs: &[Vec<u8>]) -> Vec<DecryptedNote> {
    let secret = viewing.to_secret_bytes();
    blobs
        .iter()
        .filter_map(|blob| try_decrypt_note(&secret, blob))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::note::ValueKeypair;

    // A deterministic 32-byte value from a single seed byte.
    fn bytes(seed: u8) -> [u8; 32] {
        let mut b = [0u8; 32];
        for (i, x) in b.iter_mut().enumerate() {
            *x = seed.wrapping_add(i as u8).wrapping_mul(31).wrapping_add(7);
        }
        b
    }

    #[test]
    fn round_trip_recovers_amount_and_blinding() {
        let recipient = ViewingKeypair::from_secret(bytes(1));
        let blinding = bytes(9);
        let amount = 250_000_000u64;

        let blob = encrypt_note(&recipient.public(), amount, &blinding);
        let got = try_decrypt_note(&recipient.to_secret_bytes(), &blob)
            .expect("recipient must decrypt their own note");
        assert_eq!(got.amount, amount);
        assert_eq!(got.blinding, blinding);
    }

    #[test]
    fn deterministic_ephemeral_is_reproducible() {
        let recipient = ViewingKeypair::from_secret(bytes(2));
        let blinding = bytes(3);
        let eph = bytes(42);
        let a = encrypt_note_with_ephemeral_secret(eph, &recipient.public(), 7, &blinding);
        let b = encrypt_note_with_ephemeral_secret(eph, &recipient.public(), 7, &blinding);
        assert_eq!(a, b, "same ephemeral secret must give an identical blob");
        let got = try_decrypt_note(&recipient.to_secret_bytes(), &a).unwrap();
        assert_eq!((got.amount, got.blinding), (7, blinding));
    }

    #[test]
    fn wrong_viewing_secret_returns_none() {
        let recipient = ViewingKeypair::from_secret(bytes(4));
        let attacker = ViewingKeypair::from_secret(bytes(5));
        let blob = encrypt_note(&recipient.public(), 42, &bytes(6));
        assert!(
            try_decrypt_note(&attacker.to_secret_bytes(), &blob).is_none(),
            "a non-recipient must not decrypt and must not panic"
        );
    }

    #[test]
    fn tampered_or_malformed_blob_returns_none() {
        let recipient = ViewingKeypair::from_secret(bytes(7));
        let mut blob = encrypt_note(&recipient.public(), 99, &bytes(8));
        // Flip a ciphertext byte: AEAD auth must fail.
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        assert!(try_decrypt_note(&recipient.to_secret_bytes(), &blob).is_none());
        // Truncated / oversized blobs are rejected without panicking.
        assert!(try_decrypt_note(&recipient.to_secret_bytes(), &[]).is_none());
        assert!(try_decrypt_note(&recipient.to_secret_bytes(), &blob[..blob.len() - 1]).is_none());
        let mut oversized = blob.clone();
        oversized.push(0);
        assert!(try_decrypt_note(&recipient.to_secret_bytes(), &oversized).is_none());
    }

    #[test]
    fn blob_is_within_the_on_chain_cap() {
        let recipient = ViewingKeypair::from_secret(bytes(10));
        let blob = encrypt_note(&recipient.public(), u64::MAX, &bytes(11));
        assert_eq!(blob.len(), ENC_NOTE_BLOB_LEN);
        assert_eq!(blob.len(), 100);
        assert!(blob.len() <= crate::wire::TRANSACT_MAX_ENC_LEN);
    }

    #[test]
    fn scan_returns_exactly_my_notes() {
        let me = ViewingKeypair::from_secret(bytes(20));
        let other = ViewingKeypair::from_secret(bytes(21));

        // A mix of two of my notes and two decoys for someone else.
        let mine0 = encrypt_note(&me.public(), 100, &bytes(30));
        let decoy0 = encrypt_note(&other.public(), 500, &bytes(31));
        let mine1 = encrypt_note(&me.public(), 200, &bytes(32));
        let decoy1 = encrypt_note(&other.public(), 600, &bytes(33));
        let blobs = vec![mine0, decoy0, mine1, decoy1];

        let hits = scan(&me, &blobs);
        assert_eq!(hits.len(), 2, "scan must find exactly my two notes");
        assert_eq!(hits[0].amount, 100);
        assert_eq!(hits[0].blinding, bytes(30));
        assert_eq!(hits[1].amount, 200);
        assert_eq!(hits[1].blinding, bytes(32));
    }

    #[test]
    fn acceptance_test_takes_real_keys_and_refuses_degenerate_ones() {
        // Every honestly generated key is accepted.
        for seed in 0..16u8 {
            let kp = ViewingKeypair::from_secret(bytes(seed));
            assert!(
                is_acceptable_x25519_pubkey(&kp.public()),
                "a clamped X25519 public key must be accepted"
            );
        }
        // The canonical small-order points are refused.
        for bad in SMALL_ORDER_X25519.iter() {
            assert!(
                !is_acceptable_x25519_pubkey(bad),
                "a small-order point must be refused"
            );
        }
        // Non-canonical encodings are refused: high bit set, p, p+1, and a value
        // above p.
        let real = ViewingKeypair::from_secret(bytes(3)).public();
        let mut high_bit = real;
        high_bit[31] |= 0x80;
        assert!(!is_acceptable_x25519_pubkey(&high_bit));
        assert!(!is_acceptable_x25519_pubkey(&CURVE25519_P_LE));
        let mut p_plus_1 = CURVE25519_P_LE;
        p_plus_1[0] = 0xee;
        assert!(!is_acceptable_x25519_pubkey(&p_plus_1));
        let mut above = [0xffu8; 32];
        above[31] = 0x7f;
        assert!(!is_acceptable_x25519_pubkey(&above));
        // p - 1 is canonical but small order, so it is caught by the second test.
        let mut p_minus_1 = CURVE25519_P_LE;
        p_minus_1[0] = 0xec;
        assert!(!is_acceptable_x25519_pubkey(&p_minus_1));
    }

    #[test]
    fn recovered_note_rebuilds_the_correct_commitment() {
        // Recipient holds BOTH keys: a value spend key and a viewing key.
        let value_kp = ValueKeypair::from_private_key(bytes(40));
        let value_pub = value_kp.public_key();
        let viewing = ViewingKeypair::from_secret(bytes(41));

        // Sender builds the real note and encrypts (amount, blinding) to the
        // viewing key. `expected` is the on-chain commitment the sender posts.
        let amount = 1_234_567u64;
        let blinding = bytes(42);
        let expected = Note::new(amount, value_pub, blinding).commitment();

        let blob = encrypt_note(&viewing.public(), amount, &blinding);

        // Recipient discovers the note and rebuilds it from their own value_pub.
        let decrypted = try_decrypt_note(&viewing.to_secret_bytes(), &blob).unwrap();
        let rebuilt = decrypted.to_note(value_pub);
        assert_eq!(
            rebuilt.commitment(),
            expected,
            "rebuilt note must reproduce the on-chain commitment"
        );
    }
}
