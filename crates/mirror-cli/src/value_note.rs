//! Confidential-value wallet material: the two-key address, the on-disk keyfile,
//! and the spendable value-note record.
//!
//! A confidential address is the pair `(value public_key, viewing public_key)`:
//!
//! - the **value** key ([`mirror_core::note::ValueKeypair`], a BN254 Poseidon key)
//!   is the in-circuit spend key: `public_key = Poseidon(private_key)`. Whoever
//!   knows the private key can spend notes addressed to it.
//! - the **viewing** key ([`mirror_core::encrypted_note::ViewingKeypair`], an
//!   X25519 key) only encrypts and discovers notes off-chain.
//!
//! Both are derivable deterministically from a seed (so a soak flow is
//! reproducible) or drawn from OS randomness. The keyfile persists BOTH secrets;
//! like the behavioral note it is secret material, so `notes/` is gitignored.
//!
//! A [`ValueNoteRecord`] is what a wallet keeps to later spend a note: the note's
//! `{amount, public_key, blinding}`, its accumulator leaf index, and the frontier
//! snapshot needed to rebuild the inclusion path offline. It carries the owner's
//! value private key ONLY when this wallet can spend it (recovered by `scan` from a
//! keyfile the wallet controls); the sender's informational copy omits it.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use mirror_core::encrypted_note::ViewingKeypair;
use mirror_core::note::{Note, ValueKeypair};
use mirror_core::Hash32;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::util::{from_hex32, to_hex};

/// Current keyfile schema version.
pub const VALUE_KEYFILE_VERSION: u32 = 1;
/// Current value-note record schema version.
pub const VALUE_NOTE_VERSION: u32 = 1;

/// Domain tags stretching a seed into the value spend key and the viewing key.
/// Length-prefixed and domain-separated so the two keys can never collide and a
/// seed reused elsewhere in the CLI yields unrelated material.
mod domain {
    pub const VALUE_SPEND: &[u8] = b"mirror-cli:v1:value-spend";
    pub const VIEWING: &[u8] = b"mirror-cli:v1:value-view";
}

/// A confidential wallet: a value spend keypair + an X25519 viewing keypair.
pub struct ValueWallet {
    pub value: ValueKeypair,
    pub viewing: ViewingKeypair,
}

impl ValueWallet {
    /// Derive a wallet deterministically from `seed` (reproducible flows). The
    /// value private key is `SHA-256(tag || seed)` reduced into the BN254 field;
    /// the viewing secret is `SHA-256(viewing-tag || seed)` (X25519-clamped
    /// internally). Distinct domain tags keep the two keys independent.
    pub fn from_seed(seed: &str) -> Self {
        let value_sk = tagged_hash(domain::VALUE_SPEND, seed.as_bytes());
        let viewing_sk = tagged_hash(domain::VIEWING, seed.as_bytes());
        Self {
            value: ValueKeypair::from_private_key(value_sk),
            viewing: ViewingKeypair::from_secret(viewing_sk),
        }
    }

    /// Draw a fresh wallet from OS randomness (no reproducibility).
    pub fn random() -> Self {
        use rand::RngCore;
        let mut value_sk = [0u8; 32];
        let mut viewing_sk = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut value_sk);
        rand::rngs::OsRng.fill_bytes(&mut viewing_sk);
        Self {
            value: ValueKeypair::from_private_key(value_sk),
            viewing: ViewingKeypair::from_secret(viewing_sk),
        }
    }

    /// The public address `(value_public_key, viewing_public_key)`.
    pub fn address(&self) -> ValueAddress {
        ValueAddress {
            value_public_key: self.value.public_key(),
            viewing_public_key: self.viewing.public(),
        }
    }

    /// Serialize to a keyfile (both secrets included).
    pub fn to_keyfile(&self) -> ValueKeyfile {
        ValueKeyfile {
            version: VALUE_KEYFILE_VERSION,
            value_private_key_hex: to_hex(&self.value.private_key),
            value_public_key_hex: to_hex(&self.value.public_key()),
            viewing_secret_hex: to_hex(&self.viewing.to_secret_bytes()),
            viewing_public_key_hex: to_hex(&self.viewing.public()),
        }
    }

    /// Reconstruct a wallet from a keyfile, checking the stored public keys match
    /// the ones derived from the secrets (catches a corrupted or tampered file).
    pub fn from_keyfile(kf: &ValueKeyfile) -> Result<Self> {
        let value = ValueKeypair::from_private_key(from_hex32(&kf.value_private_key_hex)?);
        let viewing = ViewingKeypair::from_secret(from_hex32(&kf.viewing_secret_hex)?);
        if to_hex(&value.public_key()) != kf.value_public_key_hex {
            bail!("keyfile value_public_key does not match its private key");
        }
        if to_hex(&viewing.public()) != kf.viewing_public_key_hex {
            bail!("keyfile viewing_public_key does not match its secret");
        }
        Ok(Self { value, viewing })
    }
}

/// SHA-256 of `tag || len(seed) || seed`, length-prefixed so no two (tag, seed)
/// pairs collide across a boundary.
fn tagged_hash(tag: &[u8], seed: &[u8]) -> Hash32 {
    let mut h = Sha256::new();
    h.update(tag);
    h.update((seed.len() as u64).to_le_bytes());
    h.update(seed);
    h.finalize().into()
}

/// A confidential address: the value + viewing public keys, printed and parsed as
/// `"<value_pub_hex>:<viewing_pub_hex>"` (each 64 hex chars).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ValueAddress {
    pub value_public_key: Hash32,
    pub viewing_public_key: [u8; 32],
}

impl ValueAddress {
    /// `"<value_pub_hex>:<viewing_pub_hex>"`.
    pub fn to_encoded(self) -> String {
        format!(
            "{}:{}",
            to_hex(&self.value_public_key),
            to_hex(&self.viewing_public_key)
        )
    }

    /// Parse `"<value_pub_hex>:<viewing_pub_hex>"`.
    pub fn parse(s: &str) -> Result<ValueAddress> {
        let (v, view) = s
            .split_once(':')
            .ok_or_else(|| anyhow!("address must be '<value_pub_hex>:<viewing_pub_hex>'"))?;
        Ok(ValueAddress {
            value_public_key: from_hex32(v).context("address value_public_key")?,
            viewing_public_key: from_hex32(view).context("address viewing_public_key")?,
        })
    }
}

/// The on-disk keyfile (both secrets). Treat as sensitive; `notes/` is gitignored.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValueKeyfile {
    pub version: u32,
    pub value_private_key_hex: String,
    pub value_public_key_hex: String,
    pub viewing_secret_hex: String,
    pub viewing_public_key_hex: String,
}

impl ValueKeyfile {
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).context("serializing value keyfile")
    }

    /// Write to `path`, creating parent dirs.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("creating keyfile directory {}", parent.display()))?;
        }
        fs::write(path, self.to_json()?)
            .with_context(|| format!("writing keyfile {}", path.display()))
    }

    pub fn load(path: &Path) -> Result<ValueKeyfile> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("reading keyfile {}", path.display()))?;
        serde_json::from_str(&raw).with_context(|| format!("parsing keyfile {}", path.display()))
    }
}

/// A saved value-note record: what a wallet keeps to spend a note later.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValueNoteRecord {
    pub version: u32,
    /// The mirror-pool program id (base58) this note lives under.
    pub program_id: String,
    /// The ValuePool PDA (base58) whose accumulator holds this note.
    pub value_pool: String,
    /// Note value.
    pub amount: u64,
    /// Owner value public key (`Poseidon(private_key)`), hex.
    pub public_key_hex: String,
    /// Per-note blinding factor, canonical big-endian, hex.
    pub blinding_hex: String,
    /// The note's Merkle-leaf commitment `Poseidon(amount, public_key, blinding)`, hex.
    pub commitment_hex: String,
    /// The owner's value private key (hex). Present ONLY when this wallet can spend
    /// the note (recovered by `scan` from a controlled keyfile); a sender's
    /// informational copy of a note it does not own omits it.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub private_key_hex: Option<String>,
    /// The owner's X25519 viewing public key (hex). `scan` records it so a later
    /// `transfer` / `unshield` can encrypt the change output back to this same
    /// wallet without a separate address argument.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub owner_viewing_public_key_hex: Option<String>,
    /// This note's leaf index in the value accumulator.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub leaf_index: Option<u64>,
    /// The value accumulator's `filled_subtrees` (one 32-byte hash per level, hex)
    /// read immediately BEFORE this leaf was appended; walking it rebuilds the
    /// inclusion path without any other leaf.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub frontier_pre: Option<Vec<String>>,
}

impl ValueNoteRecord {
    /// Rebuild the [`Note`] this record describes.
    pub fn note(&self) -> Result<Note> {
        Ok(Note::new(
            self.amount,
            from_hex32(&self.public_key_hex)?,
            from_hex32(&self.blinding_hex)?,
        ))
    }

    /// The owner value keypair, iff this record carries the private key.
    pub fn keypair(&self) -> Result<ValueKeypair> {
        let sk = self
            .private_key_hex
            .as_ref()
            .ok_or_else(|| anyhow!("this note record is not spendable (no private key)"))?;
        Ok(ValueKeypair::from_private_key(from_hex32(sk)?))
    }

    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).context("serializing value note")
    }

    /// Write to `<dir>/value-<commitment_hex>.json` (the commitment is a unique,
    /// collision-free file name). Returns the path written.
    pub fn save(&self, dir: &Path) -> Result<PathBuf> {
        fs::create_dir_all(dir)
            .with_context(|| format!("creating note directory {}", dir.display()))?;
        let path = dir.join(format!("value-{}.json", self.commitment_hex));
        fs::write(&path, self.to_json()?)
            .with_context(|| format!("writing value note {}", path.display()))?;
        Ok(path)
    }

    pub fn load(path: &Path) -> Result<ValueNoteRecord> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("reading value note {}", path.display()))?;
        serde_json::from_str(&raw).with_context(|| format!("parsing value note {}", path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wallet_from_seed_is_deterministic_and_keys_are_independent() {
        let a = ValueWallet::from_seed("alice");
        let b = ValueWallet::from_seed("alice");
        assert_eq!(a.address(), b.address(), "same seed reproduces the address");

        let c = ValueWallet::from_seed("bob");
        assert_ne!(
            a.address().value_public_key,
            c.address().value_public_key,
            "a different seed changes the value key"
        );
        assert_ne!(
            a.address().viewing_public_key,
            c.address().viewing_public_key,
            "a different seed changes the viewing key"
        );
        // The value private key and the viewing secret are derived independently.
        assert_ne!(
            a.value.private_key.to_vec(),
            a.viewing.to_secret_bytes().to_vec(),
            "value and viewing secrets must be independent"
        );
    }

    #[test]
    fn keyfile_round_trips_and_validates() {
        let wallet = ValueWallet::from_seed("carol");
        let kf = wallet.to_keyfile();
        let json = kf.to_json().unwrap();
        let back: ValueKeyfile = serde_json::from_str(&json).unwrap();
        assert_eq!(kf, back);
        // Reconstruct and confirm the derived keys match.
        let rebuilt = ValueWallet::from_keyfile(&back).unwrap();
        assert_eq!(rebuilt.address(), wallet.address());

        // A corrupted public key is rejected.
        let mut bad = kf.clone();
        bad.value_public_key_hex = "00".repeat(32);
        assert!(ValueWallet::from_keyfile(&bad).is_err());
    }

    #[test]
    fn address_encodes_and_parses() {
        let addr = ValueWallet::from_seed("dave").address();
        let enc = addr.to_encoded();
        let back = ValueAddress::parse(&enc).unwrap();
        assert_eq!(addr, back);
        assert!(ValueAddress::parse("not-an-address").is_err());
        assert!(ValueAddress::parse(&format!("{}:zz", "00".repeat(32))).is_err());
    }

    fn sample_record(spendable: bool) -> ValueNoteRecord {
        let wallet = ValueWallet::from_seed("erin");
        let note = Note::new(1_234_567, wallet.value.public_key(), [9u8; 32]);
        ValueNoteRecord {
            version: VALUE_NOTE_VERSION,
            program_id: "MirroRPoo1111111111111111111111111111111111".to_string(),
            value_pool: "VPoo1111111111111111111111111111111111111111".to_string(),
            amount: note.amount,
            public_key_hex: to_hex(&note.public_key),
            blinding_hex: to_hex(&note.blinding),
            commitment_hex: to_hex(&note.commitment()),
            private_key_hex: spendable.then(|| to_hex(&wallet.value.private_key)),
            owner_viewing_public_key_hex: spendable.then(|| to_hex(&wallet.viewing.public())),
            leaf_index: Some(7),
            frontier_pre: Some(vec!["00".repeat(32); crate::tree::DEPTH]),
        }
    }

    #[test]
    fn value_note_round_trips_and_rebuilds_note() {
        let rec = sample_record(true);
        let json = rec.to_json().unwrap();
        let back: ValueNoteRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(rec, back);
        // The rebuilt note reproduces the stored commitment, and the keypair works.
        assert_eq!(
            to_hex(&back.note().unwrap().commitment()),
            back.commitment_hex
        );
        let kp = back.keypair().unwrap();
        assert_eq!(to_hex(&kp.public_key()), back.public_key_hex);
    }

    #[test]
    fn informational_note_has_no_private_key() {
        let rec = sample_record(false);
        let json = rec.to_json().unwrap();
        assert!(
            !json.contains("private_key_hex"),
            "an informational (non-spendable) note must omit the private key"
        );
        let back: ValueNoteRecord = serde_json::from_str(&json).unwrap();
        assert!(back.private_key_hex.is_none());
        assert!(back.keypair().is_err(), "a non-spendable note cannot spend");
    }

    #[test]
    fn value_note_save_and_load_by_commitment_filename() {
        let dir =
            std::env::temp_dir().join(format!("mirror-cli-value-note-test-{}", std::process::id()));
        let rec = sample_record(true);
        let path = rec.save(&dir).unwrap();
        assert!(path.ends_with(format!("value-{}.json", rec.commitment_hex)));
        let back = ValueNoteRecord::load(&path).unwrap();
        assert_eq!(rec, back);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
