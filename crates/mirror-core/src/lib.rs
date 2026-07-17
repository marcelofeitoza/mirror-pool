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
//! Commitments and nullifiers use circomlib Poseidon over the BN254 scalar
//! field, the exact scheme the Groth16 membership circuit
//! (`circuits/membership.circom`) enforces and the on-chain accumulator hashes
//! with, so a proof made for the circuit verifies against a root produced by
//! this code:
//!
//! ```text
//! commitment    = Poseidon(secret, actionHash, epoch)   // the Merkle leaf
//! nullifierHash = Poseidon(secret, epoch)               // epoch-scoped tag
//! Merkle node   = Poseidon(left, right)
//! ```
//!
//! All values are canonical 32-byte BIG-ENDIAN encodings of BN254 scalars,
//! which is the byte order circom/snarkjs and `groth16-solana` use for public
//! inputs and the order `light_poseidon` and the `sol_poseidon` syscall use
//! with `Endianness::BigEndian`. Correctness is pinned by the fixture
//! cross-check test, which reproduces the committed circuit's nullifierHash,
//! commitment leaf, and Merkle root exactly.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// BN254 scalar-field arithmetic and circomlib-compatible Poseidon.
///
/// Every hash input and output is a canonical 32-byte BIG-ENDIAN encoding of a
/// BN254 scalar (`Fr`). This is the byte order the circuit, snarkjs, and
/// `groth16-solana` public inputs use; the order `light_poseidon`'s
/// `hash_bytes_be` uses; and the order the on-chain `sol_poseidon` syscall uses
/// with `Endianness::BigEndian` (== 0). Host (`light-poseidon`) and on-chain
/// (syscall) are the same Poseidon implementation with the same byte order, so
/// they produce byte-identical results and both match the circuit.
mod field {
    use ark_bn254::Fr;
    use ark_ff::{BigInteger, PrimeField};
    use light_poseidon::{Poseidon, PoseidonHasher};

    /// Interpret 32 big-endian bytes as an `Fr`, reducing modulo the field
    /// order r. Reduction (rather than rejection) makes any 32-byte secret a
    /// valid field element; for canonical inputs already < r (as
    /// `gen_fixture.js` picks them) it is the identity, so the fixture
    /// reproduces exactly. All values this module emits are canonical (< r).
    pub fn from_be(bytes: &[u8; 32]) -> Fr {
        Fr::from_be_bytes_mod_order(bytes)
    }

    /// Canonical 32-byte big-endian encoding of `f` (always < r, left-padded).
    pub fn to_be(f: &Fr) -> [u8; 32] {
        let be = f.into_bigint().to_bytes_be();
        let mut out = [0u8; 32];
        out[32 - be.len()..].copy_from_slice(&be);
        out
    }

    /// A field element from a `u64` (used for the epoch id).
    pub fn from_u64(x: u64) -> Fr {
        Fr::from(x)
    }

    /// circomlib Poseidon over `inputs` (width = `inputs.len()`), returned as a
    /// canonical big-endian 32-byte field element. `new_circom` supports widths
    /// 1..=12; the scheme only uses 2 (nullifier / Merkle node) and 3
    /// (commitment) and every input is a valid `Fr`, so neither call can fail.
    pub fn poseidon(inputs: &[Fr]) -> [u8; 32] {
        let mut hasher = Poseidon::<Fr>::new_circom(inputs.len()).expect("Poseidon width 1..=12");
        let out = hasher
            .hash(inputs)
            .expect("Poseidon over valid field elements cannot fail");
        to_be(&out)
    }

    /// Parse a decimal field-element string (test fixtures use decimal). Only
    /// the cross-check test needs this.
    #[cfg(test)]
    pub fn from_dec(s: &str) -> [u8; 32] {
        use core::str::FromStr;
        to_be(&Fr::from_str(s).expect("valid decimal field element"))
    }
}

/// A 32-byte hash output (commitment or nullifier).
pub type Hash32 = [u8; 32];

/// The secret a participant keeps to later prove membership and derive a
/// nullifier. It is the circuit's private `secret` witness: 32 bytes
/// interpreted as a big-endian BN254 scalar (reduced modulo the field order, so
/// any 32 bytes are valid).
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

/// The canonical `actionHash` the circuit consumes as a public input.
///
/// Defined as SHA-256 of the deterministic [`ActionClass`] encoding, reduced
/// into the BN254 scalar field and encoded big-endian. The circuit treats
/// `actionHash` as an opaque field element (it does not re-derive it inside the
/// constraints), so any deterministic, collision-resistant map into `Fr` is
/// sound; this one is defined once here so the value the CLI feeds the prover
/// and the value the on-chain program binds as a public input are identical.
/// Binding it as a public input is what stops a relay from re-targeting the
/// action after commitment.
pub fn action_hash(action: &ActionClass) -> Hash32 {
    let digest: Hash32 = Sha256::digest(action.canonical_bytes()).into();
    // Reduce the 256-bit digest into the field and re-encode canonically so the
    // result is always a valid, canonical big-endian field element (< r).
    field::to_be(&field::from_be(&digest))
}

/// The canonical `actionHash` for the ZK opt-in settlement action.
///
/// The v1 opt-in action is "transfer `amount` lamports to `recipient`" (a
/// fresh address). `actionHash` binds BOTH so the settling relay cannot
/// redirect the escrow:
///
/// ```text
/// actionHash = Poseidon(recipientHi128, recipientLo128, amount)
/// ```
///
/// The 32-byte `recipient` is split into two big-endian 128-bit halves (each
/// < 2^128 < r, so both are canonical BN254 scalars with no modular reduction
/// and no loss of collision resistance) and `amount` is the `u64` as a field
/// element. `actionHash` is a PUBLIC input of the membership circuit, so a proof
/// exists only for a member whose committed leaf bound this exact
/// `(recipient, amount)`. The on-chain program recomputes this identical hash
/// with the `sol_poseidon` syscall (circomlib Poseidon, big-endian) and requires
/// it to equal the proof's `actionHash`; the CLI prover feeds the same value to
/// the circuit. All three sides therefore agree byte-for-byte.
pub fn transfer_action_hash(recipient: &Hash32, amount: u64) -> Hash32 {
    let mut hi = [0u8; 32];
    hi[16..].copy_from_slice(&recipient[0..16]);
    let mut lo = [0u8; 32];
    lo[16..].copy_from_slice(&recipient[16..32]);
    let mut amt = [0u8; 32];
    amt[24..].copy_from_slice(&amount.to_be_bytes());
    field::poseidon(&[
        field::from_be(&hi),
        field::from_be(&lo),
        field::from_be(&amt),
    ])
}

/// Compute the commitment leaf for `(secret, action, epoch)`.
///
/// `commitment = Poseidon(secret, actionHash, epoch)`, exactly the leaf the
/// circuit recomputes. Binding the action and epoch into the leaf is what makes
/// the design fail-closed: a relayer settling the epoch cannot substitute a
/// different action for a committed one without invalidating the commitment.
pub fn commit(secret: &Secret, action: &ActionClass, epoch: Epoch) -> Commitment {
    commit_with_action_hash(secret, &action_hash(action), epoch)
}

/// Compute the commitment leaf from an explicit `actionHash` field element.
///
/// `commit(secret, action, epoch)` is exactly
/// `commit_with_action_hash(secret, &action_hash(action), epoch)`. This lower
/// level entry point is what the prover uses when it already holds the
/// `actionHash` public input (and is what the fixture cross-check exercises
/// against the circuit's own `actionHash`).
pub fn commit_with_action_hash(secret: &Secret, action_hash: &Hash32, epoch: Epoch) -> Commitment {
    let s = field::from_be(&secret.0);
    let a = field::from_be(action_hash);
    let e = field::from_u64(epoch.0);
    Commitment(field::poseidon(&[s, a, e]))
}

/// Derive the nullifier for `(secret, epoch)`: `Poseidon(secret, epoch)`.
pub fn nullifier(secret: &Secret, epoch: Epoch) -> Nullifier {
    let s = field::from_be(&secret.0);
    let e = field::from_u64(epoch.0);
    Nullifier(field::poseidon(&[s, e]))
}

/// One internal Merkle node: `Poseidon(left, right)`, matching the circuit's
/// `HashLeftRight` and the on-chain accumulator's `hash_pair`. Inputs and the
/// output are canonical big-endian field elements. Exposed so off-chain code
/// (and the cross-check test) can recompute roots and inclusion paths.
pub fn merkle_node(left: &Hash32, right: &Hash32) -> Hash32 {
    field::poseidon(&[field::from_be(left), field::from_be(right)])
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
        /// ZK opt-in path: escrow + commit (see [`super::COMMIT_DEPOSIT_LEN`]).
        pub const COMMIT_DEPOSIT: u8 = 3;
        /// ZK opt-in path: settle one membership (see [`super::SETTLE_ZK_LEN`]).
        pub const SETTLE_ZK: u8 = 4;
        /// Crowd-path participation incentive: claim a dwell-proportional share
        /// of the on-chain reward pool (see [`super::CLAIM_REWARD_LEN`]).
        pub const CLAIM_REWARD: u8 = 5;
    }

    /// INIT_POOL layout:
    /// `[tag(1)][epoch_slots(8)][k_floor(4)][entry_fee(8)][reward_bps(2 LE)]` -
    /// the operator fixes the epoch window, the k-anonymity floor, the per-commit
    /// anti-Sybil entry fee (lamports; 0 disables it), and `reward_bps`, the
    /// basis-point share of each entry fee that accrues to the on-chain reward
    /// pool (the remainder covers relay/settlement cost; `reward_bps` must be
    /// `<= 10_000`). MUST stay byte-identical to the program's
    /// `wire::INIT_POOL_LEN`.
    pub const INIT_POOL_LEN: usize = 1 + 8 + 4 + 8 + 2;

    /// CLAIM_REWARD layout: `[tag(1)]`. The claimant is the signer; their dwell
    /// PDA (seeds `["dwell", pool, participant]`) carries the accumulated dwell,
    /// so no body fields are needed. MUST stay byte-identical to the program's
    /// `wire::CLAIM_REWARD_LEN`.
    pub const CLAIM_REWARD_LEN: usize = 1;

    /// Basis-point denominator for the entry-fee reward split (`reward_bps` is
    /// out of this). 100% = 10_000 bps.
    pub const BPS_DENOMINATOR: u16 = 10_000;

    /// COMMIT layout: [tag(1)][commitment(32)] - the participant posts only the
    /// commitment; the action + secret stay client-side until settlement.
    pub const COMMIT_LEN: usize = 1 + 32;

    /// SETTLE_EPOCH header: [tag(1)][epoch(8)][n_nullifiers(4)] followed by
    /// n_nullifiers * 32 bytes. The relayer submits the whole epoch atomically.
    pub const SETTLE_HEADER_LEN: usize = 1 + 8 + 4;

    /// COMMIT_DEPOSIT layout: [tag(1)][commitment(32)][amount(8 LE)] - the ZK
    /// opt-in escrow. Escrows `amount` lamports and posts the commitment whose
    /// `actionHash` binds `(recipient, amount)` (see
    /// [`super::transfer_action_hash`]). MUST stay byte-identical to the
    /// program's `wire::COMMIT_DEPOSIT_LEN`.
    pub const COMMIT_DEPOSIT_LEN: usize = 1 + 32 + 8;

    /// SETTLE_ZK layout (ONE membership per call; the coordinator batches calls):
    ///
    /// ```text
    /// [tag(1)][epoch(8 LE)][amount(8 LE)]
    ///   [proof_a(64)][proof_b(128)][proof_c(64)]
    ///   [root(32)][nullifierHash(32)][actionHash(32)][epoch(32 BE)]
    /// ```
    ///
    /// The four trailing 32-byte values are the Groth16 public inputs in the
    /// FIXED order [root, nullifierHash, actionHash, epoch]. `epoch` appears
    /// twice: the `u64` header drives the window-closed gate and the nullifier
    /// PDA seed, and the 32-byte big-endian public input is what the proof
    /// commits to; the program requires the two encodings to agree. MUST stay
    /// byte-identical to the program's `wire::SETTLE_ZK_LEN`.
    pub const SETTLE_ZK_LEN: usize = 1 + 8 + 8 + 64 + 128 + 64 + 32 + 32 + 32 + 32;

    // Layout sanity: keep the documented sizes honest at compile time and in
    // lockstep with the on-chain program's mirrored constants.
    const _: () = assert!(INIT_POOL_LEN == 23);
    const _: () = assert!(COMMIT_LEN == 33);
    const _: () = assert!(SETTLE_HEADER_LEN == 13);
    const _: () = assert!(COMMIT_DEPOSIT_LEN == 41);
    const _: () = assert!(SETTLE_ZK_LEN == 401);
    const _: () = assert!(CLAIM_REWARD_LEN == 1);
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
    fn commitment_and_nullifier_differ() {
        // The 3-input commitment Poseidon(secret, actionHash, epoch) and the
        // 2-input nullifier Poseidon(secret, epoch) differ by width and inputs,
        // so they cannot collide for the same secret/epoch.
        let s = Secret([4u8; 32]);
        let c = commit(&s, &action(), Epoch(2)).0;
        let n = nullifier(&s, Epoch(2)).0;
        assert_ne!(c, n);
    }

    #[test]
    fn action_hash_is_deterministic_and_binds_shape() {
        // action_hash is a canonical field element and distinguishes classes.
        let a = action_hash(&action());
        assert_eq!(a, action_hash(&action()), "must be deterministic");
        let other = ActionClass::Stake {
            validator: [3u8; 32],
            size: SizeBucket::Small,
        };
        assert_ne!(a, action_hash(&other), "class must change actionHash");
    }

    /// DECISIVE circomlib-compatibility check: reproduce the committed circuit's
    /// public signals with mirror-core's Poseidon scheme. If this passes, a
    /// proof generated for `circuits/membership.circom` verifies against a root
    /// this code (and the on-chain accumulator, which uses the same Poseidon
    /// with the same big-endian byte order) produces.
    #[test]
    fn fixture_cross_check_reproduces_circuit() {
        const DEPTH: usize = 20;

        // Public-input order is part of the scheme; assert the committed meta.
        let meta: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../circuits/artifacts/fixture_meta.json"
        )))
        .unwrap();
        assert_eq!(
            meta["publicInputOrder"],
            serde_json::json!(["root", "nullifierHash", "actionHash", "epoch"]),
            "public-input order must match the canonical scheme"
        );

        // Public signals [root, nullifierHash, actionHash, epoch] from the
        // committed proof fixture (the circuit's own output).
        let fixture: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../circuits/artifacts/proof_fixture.json"
        )))
        .unwrap();
        let ps = fixture["publicSignals"].as_array().unwrap();
        let root = field::from_dec(ps[0].as_str().unwrap());
        let fixture_nullifier = field::from_dec(ps[1].as_str().unwrap());
        let action_hash = field::from_dec(ps[2].as_str().unwrap());
        let epoch = Epoch(ps[3].as_str().unwrap().parse::<u64>().unwrap());

        // Known private inputs from circuits/gen_fixture.js (committed generator):
        // secret and the leaf index of the single inserted commitment.
        let secret = Secret(field::from_dec("111122223333444455556666777788889999"));
        let leaf_index: u64 = 21;

        // 1. nullifier() reproduces the circuit's nullifierHash exactly.
        assert_eq!(
            nullifier(&secret, epoch).0,
            fixture_nullifier,
            "nullifierHash must match the circuit"
        );

        // 2. The real commitment leaf path reproduces the leaf; recomputing the
        //    Merkle path over the canonical zero ladder reproduces the root.
        let leaf = commit_with_action_hash(&secret, &action_hash, epoch).0;

        // zeros[level]: zeros[0] = 0, zeros[i] = Poseidon(zeros[i-1], zeros[i-1]).
        let mut zeros = [[0u8; 32]; DEPTH];
        let mut z = [0u8; 32];
        for level in zeros.iter_mut() {
            *level = z;
            z = merkle_node(&z, &z);
        }

        let mut cur = leaf;
        for (level, sibling) in zeros.iter().enumerate() {
            cur = if (leaf_index >> level) & 1 == 0 {
                merkle_node(&cur, sibling) // current is left child
            } else {
                merkle_node(sibling, &cur) // current is right child
            };
        }
        assert_eq!(cur, root, "recomputed Merkle root must match the circuit");
    }

    #[test]
    fn transfer_action_hash_matches_fixture() {
        // The committed proof fixture's actionHash (public signal [2]) is built
        // by gen_fixture.js as Poseidon(recipientHi, recipientLo, amount) for the
        // recipient bytes 0x01..0x20 and 0.25 SOL. transfer_action_hash must
        // reproduce it exactly, proving the host binding equals the circuit's.
        let fixture: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../circuits/artifacts/proof_fixture.json"
        )))
        .unwrap();
        let ps = fixture["publicSignals"].as_array().unwrap();
        let fixture_action_hash = field::from_dec(ps[2].as_str().unwrap());

        let mut recipient = [0u8; 32];
        for (i, b) in recipient.iter_mut().enumerate() {
            *b = (i + 1) as u8;
        }
        let amount: u64 = 250_000_000;

        assert_eq!(
            transfer_action_hash(&recipient, amount),
            fixture_action_hash,
            "transfer_action_hash must equal the circuit's actionHash"
        );
    }

    #[test]
    fn transfer_action_hash_binds_recipient_and_amount() {
        let r0 = [1u8; 32];
        let mut r1 = [1u8; 32];
        r1[31] = 2;
        assert_ne!(
            transfer_action_hash(&r0, 100),
            transfer_action_hash(&r1, 100),
            "recipient must change actionHash"
        );
        assert_ne!(
            transfer_action_hash(&r0, 100),
            transfer_action_hash(&r0, 101),
            "amount must change actionHash"
        );
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
