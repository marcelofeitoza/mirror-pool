//! The client-side note: the record a participant must keep to be counted at
//! settlement.
//!
//! A note is written to disk (never printed to a shared log in v1's hardening
//! goal) by `commit` / `deposit-commit` and read back by `prove`. It holds the
//! secret pre-image (proving the commitment is theirs), the epoch-scoped
//! nullifier, and - for the ZK opt-in path - the bound `(recipient, amount)` plus
//! the Merkle-frontier snapshot needed to rebuild the inclusion path offline.
//!
//! ANYONE holding a note can act as the participant at settlement, so notes are
//! secret material: the `notes/` directory is gitignored, and v2 encrypts them.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use mirror_core::ActionClass;
use serde::{Deserialize, Serialize};

/// The current note schema version.
pub const NOTE_VERSION: u32 = 1;

/// What the committed leaf's `actionHash` binds.
///
/// - `Crowd`: the pooled `ActionClass` (swap / stake). Settled by the coordinator
///   composing every participant's own behavior into one `SettleEpoch` tx.
/// - `Transfer`: the ZK opt-in action "transfer `amount` lamports to `recipient`"
///   (a fresh address). Settled by `SettleZk` after a Groth16 membership proof;
///   the leaf's `actionHash = transfer_action_hash(recipient, amount)`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "path", rename_all = "snake_case")]
pub enum ActionRecord {
    Crowd {
        action: ActionClass,
    },
    Transfer {
        /// Fresh recipient address (base58); receives the escrow at `SettleZk`.
        recipient: String,
        /// Escrowed lamports, bound into the commitment's `actionHash`.
        amount: u64,
    },
}

/// A saved participant note.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Note {
    pub version: u32,
    /// The mirror-pool program id (base58) this note was committed under.
    pub program_id: String,
    /// The Pool PDA (base58) this note was committed into.
    pub pool: String,
    /// The slot the CLI read when computing the epoch (for auditing).
    pub slot: u64,
    /// The epoch the commitment (and nullifier) are bound to.
    pub epoch: u64,
    pub secret_hex: String,
    pub commitment_hex: String,
    pub nullifier_hex: String,
    /// What the leaf's `actionHash` binds (crowd action vs ZK transfer).
    pub action: ActionRecord,
    /// ZK path only: this leaf's index in the accumulator (= the pool's
    /// `commitment_count` immediately before the commit landed).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub leaf_index: Option<u64>,
    /// ZK path only: the pool's `filled_subtrees` (one 32-byte hash per level,
    /// hex) read immediately BEFORE the commit landed. `prove` walks this frontier
    /// snapshot to rebuild the inclusion path without any other leaf.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub frontier_pre: Option<Vec<String>>,
}

impl Note {
    /// Serialize to pretty JSON.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).context("serializing note")
    }

    /// Write the note to `<dir>/<commitment_hex>.json`, creating `dir` if needed.
    /// Returns the path written. The commitment is unique per (secret, action,
    /// epoch), so it is a stable, collision-free file name.
    pub fn save(&self, dir: &Path) -> Result<PathBuf> {
        fs::create_dir_all(dir)
            .with_context(|| format!("creating note directory {}", dir.display()))?;
        let path = dir.join(format!("{}.json", self.commitment_hex));
        fs::write(&path, self.to_json()?)
            .with_context(|| format!("writing note {}", path.display()))?;
        Ok(path)
    }

    /// Read a note from a JSON file.
    pub fn load(path: &Path) -> Result<Note> {
        let raw =
            fs::read_to_string(path).with_context(|| format!("reading note {}", path.display()))?;
        serde_json::from_str(&raw).with_context(|| format!("parsing note {}", path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mirror_core::SizeBucket;

    fn crowd_note() -> Note {
        Note {
            version: NOTE_VERSION,
            program_id: "MirroRPoo1111111111111111111111111111111111".to_string(),
            pool: "Poo1111111111111111111111111111111111111111".to_string(),
            slot: 1_500_000,
            epoch: 10_000,
            secret_hex: "aa".repeat(32),
            commitment_hex: "bb".repeat(32),
            nullifier_hex: "cc".repeat(32),
            action: ActionRecord::Crowd {
                action: ActionClass::Swap {
                    mint_in: [1u8; 32],
                    mint_out: [2u8; 32],
                    size: SizeBucket::Small,
                },
            },
            leaf_index: None,
            frontier_pre: None,
        }
    }

    fn zk_note() -> Note {
        Note {
            version: NOTE_VERSION,
            program_id: "MirroRPoo1111111111111111111111111111111111".to_string(),
            pool: "Poo1111111111111111111111111111111111111111".to_string(),
            slot: 1_500_000,
            epoch: 10_000,
            secret_hex: "11".repeat(32),
            commitment_hex: "22".repeat(32),
            nullifier_hex: "33".repeat(32),
            action: ActionRecord::Transfer {
                recipient: "Recipient111111111111111111111111111111111".to_string(),
                amount: 250_000_000,
            },
            leaf_index: Some(21),
            frontier_pre: Some(vec!["00".repeat(32); crate::tree::DEPTH]),
        }
    }

    #[test]
    fn crowd_note_round_trips() {
        let n = crowd_note();
        let json = n.to_json().unwrap();
        let back: Note = serde_json::from_str(&json).unwrap();
        assert_eq!(n, back);
        // A crowd note carries no ZK-path fields.
        assert!(back.leaf_index.is_none());
        assert!(back.frontier_pre.is_none());
        // The tagged action serializes with a "path" discriminator.
        assert!(json.contains("\"path\": \"crowd\""));
    }

    #[test]
    fn zk_note_round_trips() {
        let n = zk_note();
        let json = n.to_json().unwrap();
        let back: Note = serde_json::from_str(&json).unwrap();
        assert_eq!(n, back);
        assert_eq!(back.leaf_index, Some(21));
        assert_eq!(
            back.frontier_pre.as_ref().unwrap().len(),
            crate::tree::DEPTH
        );
        assert!(json.contains("\"path\": \"transfer\""));
        match back.action {
            ActionRecord::Transfer { amount, .. } => assert_eq!(amount, 250_000_000),
            _ => panic!("expected a transfer note"),
        }
    }

    #[test]
    fn save_and_load_by_commitment_filename() {
        let dir = std::env::temp_dir().join(format!("mirror-cli-note-test-{}", std::process::id()));
        let n = zk_note();
        let path = n.save(&dir).unwrap();
        assert!(path.ends_with(format!("{}.json", n.commitment_hex)));
        let back = Note::load(&path).unwrap();
        assert_eq!(n, back);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
