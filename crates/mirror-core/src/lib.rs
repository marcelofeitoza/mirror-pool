//! Shared types for mirror-pool.
//!
//! mirror-pool is "Tornado Cash for behavior, not funds": a shared anonymity
//! network where the anonymity set is over the *initiators* of an action, not
//! over denominations. This crate holds the primitives every off-chain crate
//! (coordinator, cli, harness) and the on-chain program agree on:
//!
//! - [`Commitment`] / [`Nullifier`] - the commit/replay primitives.
//! - [`ActionClass`] - the "fixed action shape per pool" concept. Heterogeneous
//!   actions leak exactly like mixed denominations, so every action emitted from
//!   one pool must be indistinguishable in its observable shape.
//! - [`Epoch`] - shared-timestamp batching. All actions in an epoch settle
//!   together, which is what defeats FIFO temporal matching (the single
//!   strongest empirical attack on Tornado, up to 49% linkage).
//! - [`KAnon`] - honest k reporting: the real anonymity set is the count of
//!   distinct, economically-distinct, non-operator participants, never the
//!   nominal commit count.
//! - [`wire`] - the byte layout the coordinator/cli use to build instructions
//!   that the on-chain program parses. Kept here so both sides cannot drift.
//!
//! v1 uses SHA-256 for commitments/nullifiers (fast, no proving system). v2
//! swaps in Poseidon + a Groth16 membership proof for ZK-deniable initiation;
//! see `docs/ROADMAP.md`. The public API is designed so that swap is additive.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Domain-separation tags so a hash computed for one purpose can never be
/// reinterpreted as another (commitment vs nullifier vs epoch binding).
mod domain {
    pub const COMMITMENT: &[u8] = b"mirror-pool:v1:commitment";
    pub const NULLIFIER: &[u8] = b"mirror-pool:v1:nullifier";
}

/// A 32-byte hash output (commitment or nullifier).
pub type Hash32 = [u8; 32];

/// The secret a participant keeps to later prove membership and derive a
/// nullifier. In v1 this is the pre-image; in v2 it becomes a ZK witness.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Secret(pub [u8; 32]);

impl Secret {
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }
}

impl core::fmt::Debug for Secret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never print the secret material.
        write!(f, "Secret(***)")
    }
}

/// A leaf posted to the pool's accumulator during the commit phase. It binds
/// the participant's secret to the action they intend to take, so the executed
/// action cannot be re-targeted after the fact.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Commitment(pub Hash32);

/// A one-way tag revealed at execution to prevent one participant from acting
/// twice in the same epoch. Bound to (secret, epoch) so the same secret in a
/// later epoch yields a different nullifier.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct Nullifier(pub Hash32);

/// Compute the commitment for `(secret, action, epoch)`.
///
/// Binding the action and epoch into the commitment is what makes the design
/// fail-closed: a relayer settling the epoch cannot substitute a different
/// action for a committed one without invalidating the commitment.
pub fn commit(secret: &Secret, action: &ActionClass, epoch: Epoch) -> Commitment {
    let mut h = Sha256::new();
    h.update(domain::COMMITMENT);
    h.update(secret.0);
    h.update(action.canonical_bytes());
    h.update(epoch.0.to_le_bytes());
    Commitment(h.finalize().into())
}

/// Derive the nullifier for `(secret, epoch)`.
pub fn nullifier(secret: &Secret, epoch: Epoch) -> Nullifier {
    let mut h = Sha256::new();
    h.update(domain::NULLIFIER);
    h.update(secret.0);
    h.update(epoch.0.to_le_bytes());
    Nullifier(h.finalize().into())
}

/// A coarse size bucket. Fixed buckets are the behavioral analog of Tornado's
/// fixed denominations: two actions in the same bucket are indistinguishable by
/// amount, so amount-matching cannot single one out. Public measurements of
/// privacy pools (Wang et al. 2022; the Tornado deanonymization study) show
/// variable and round-number amounts leak a large fraction of anonymity to
/// amount-matching, which is why bucketing is mandatory, not optional.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[repr(u8)]
pub enum SizeBucket {
    Nano = 0,
    Small = 1,
    Medium = 2,
    Large = 3,
}

impl SizeBucket {
    pub const ALL: [SizeBucket; 4] = [
        SizeBucket::Nano,
        SizeBucket::Small,
        SizeBucket::Medium,
        SizeBucket::Large,
    ];
}

/// The fixed shape of the action a pool performs. One anonymity set exists per
/// `ActionClass`; mixing classes in one pool would let an observer cluster by
/// shape. Extend this enum (and the on-chain settlement) to add pooled actions;
/// see `mirror-behaviors`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum ActionClass {
    /// Every participant performs the same swap (same mint pair + size bucket).
    Swap {
        mint_in: Hash32,
        mint_out: Hash32,
        size: SizeBucket,
    },
    /// Every participant stakes the same size bucket to the same validator.
    Stake { validator: Hash32, size: SizeBucket },
}

impl ActionClass {
    /// A stable byte encoding used inside the commitment. Must be deterministic
    /// and identical on the off-chain and on-chain sides.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(1 + 64 + 1);
        match self {
            ActionClass::Swap {
                mint_in,
                mint_out,
                size,
            } => {
                v.push(0u8);
                v.extend_from_slice(mint_in);
                v.extend_from_slice(mint_out);
                v.push(*size as u8);
            }
            ActionClass::Stake { validator, size } => {
                v.push(1u8);
                v.extend_from_slice(validator);
                v.push(*size as u8);
            }
        }
        v
    }
}

/// A synchronized round. `id` is a monotonically increasing epoch number derived
/// from the slot clock so every participant computes the same current epoch
/// without coordination.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Serialize, Deserialize)]
pub struct Epoch(pub u64);

/// Epoch scheduling parameters, fixed per pool at init.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct EpochSchedule {
    /// Length of an epoch in slots. All commits landing in the same window
    /// settle together on one timestamp.
    pub epoch_slots: u64,
    /// Minimum distinct participants required before an epoch may settle. Below
    /// this floor the epoch rolls forward instead of executing - never execute
    /// into a set small enough to deanonymize by elimination.
    pub k_floor: u32,
}

impl EpochSchedule {
    pub fn epoch_of_slot(&self, slot: u64) -> Epoch {
        Epoch(slot / self.epoch_slots.max(1))
    }

    /// First slot at which `epoch` is allowed to settle (its window has closed).
    pub fn settle_slot(&self, epoch: Epoch) -> u64 {
        (epoch.0 + 1) * self.epoch_slots.max(1)
    }
}

/// Honest anonymity accounting. The nominal set (commit count) overstates
/// privacy; report [`KAnon::real_k`] to users - distinct, non-operator,
/// non-Sybil participants - never the nominal count.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct KAnon {
    pub nominal: u32,
    /// Participants excluded as operator-owned or Sybil (attacker-controlled
    /// decoys the attacker already knows, which add zero real anonymity).
    pub excluded: u32,
}

impl KAnon {
    pub fn real_k(&self) -> u32 {
        self.nominal.saturating_sub(self.excluded)
    }

    /// An epoch may execute only if the real set meets the floor.
    pub fn meets_floor(&self, schedule: &EpochSchedule) -> bool {
        self.real_k() >= schedule.k_floor
    }
}

/// Errors shared across crates.
#[derive(Debug, thiserror::Error)]
pub enum MirrorError {
    #[error("epoch not yet settleable: current slot {current} < settle slot {settle}")]
    EpochNotClosed { current: u64, settle: u64 },
    #[error("k-anonymity floor not met: real_k={real_k} < k_floor={k_floor}")]
    BelowKFloor { real_k: u32, k_floor: u32 },
    #[error("nullifier already spent this epoch")]
    NullifierSpent,
    #[error("malformed instruction data")]
    MalformedInstruction,
}

/// The on-chain wire format. The coordinator/cli build instruction data with
/// these tags and offsets; the Pinocchio program parses the same layout. Kept
/// in one place so the two sides cannot silently drift.
pub mod wire {
    /// Instruction discriminators (first byte of instruction data).
    pub mod tag {
        pub const INIT_POOL: u8 = 0;
        pub const COMMIT: u8 = 1;
        pub const SETTLE_EPOCH: u8 = 2;
    }

    /// INIT_POOL layout: [tag(1)][epoch_slots(8)][k_floor(4)][entry_fee(8)] -
    /// the operator fixes the epoch window, the k-anonymity floor, and the
    /// per-commit anti-Sybil entry fee (lamports; 0 disables it). MUST stay
    /// byte-identical to the program's `wire::INIT_POOL_LEN`.
    pub const INIT_POOL_LEN: usize = 1 + 8 + 4 + 8;

    /// COMMIT layout: [tag(1)][commitment(32)] - the participant posts only the
    /// commitment; the action + secret stay client-side until settlement.
    pub const COMMIT_LEN: usize = 1 + 32;

    /// SETTLE_EPOCH header: [tag(1)][epoch(8)][n_nullifiers(4)] followed by
    /// n_nullifiers * 32 bytes. The relayer submits the whole epoch atomically.
    pub const SETTLE_HEADER_LEN: usize = 1 + 8 + 4;

    // Layout sanity: keep the documented sizes honest at compile time and in
    // lockstep with the on-chain program's mirrored constants.
    const _: () = assert!(INIT_POOL_LEN == 21);
    const _: () = assert!(COMMIT_LEN == 33);
    const _: () = assert!(SETTLE_HEADER_LEN == 13);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn action() -> ActionClass {
        ActionClass::Swap {
            mint_in: [1u8; 32],
            mint_out: [2u8; 32],
            size: SizeBucket::Small,
        }
    }

    #[test]
    fn commitment_binds_action_and_epoch() {
        let s = Secret([7u8; 32]);
        let c0 = commit(&s, &action(), Epoch(0));
        let c1 = commit(&s, &action(), Epoch(1));
        let other = ActionClass::Stake {
            validator: [3u8; 32],
            size: SizeBucket::Small,
        };
        let c2 = commit(&s, &other, Epoch(0));
        assert_ne!(c0, c1, "epoch must change the commitment");
        assert_ne!(c0, c2, "action must change the commitment");
    }

    #[test]
    fn nullifier_is_epoch_scoped() {
        let s = Secret([9u8; 32]);
        assert_ne!(nullifier(&s, Epoch(0)), nullifier(&s, Epoch(1)));
        assert_eq!(nullifier(&s, Epoch(5)), nullifier(&s, Epoch(5)));
    }

    #[test]
    fn commitment_and_nullifier_are_domain_separated() {
        // Same secret/epoch must not collide across the two hash domains.
        let s = Secret([4u8; 32]);
        let c = commit(&s, &action(), Epoch(2)).0;
        let n = nullifier(&s, Epoch(2)).0;
        assert_ne!(c, n);
    }

    #[test]
    fn epoch_math() {
        let sched = EpochSchedule {
            epoch_slots: 150,
            k_floor: 10,
        };
        assert_eq!(sched.epoch_of_slot(0), Epoch(0));
        assert_eq!(sched.epoch_of_slot(149), Epoch(0));
        assert_eq!(sched.epoch_of_slot(150), Epoch(1));
        assert_eq!(sched.settle_slot(Epoch(0)), 150);
    }

    #[test]
    fn real_k_excludes_sybils() {
        let k = KAnon {
            nominal: 100,
            excluded: 91,
        };
        assert_eq!(k.real_k(), 9);
        let sched = EpochSchedule {
            epoch_slots: 150,
            k_floor: 10,
        };
        assert!(!k.meets_floor(&sched), "9 < 10 must not settle");
    }
}
