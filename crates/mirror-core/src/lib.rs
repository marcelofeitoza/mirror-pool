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
//! commitment    = Poseidon(secret, actionHash, epoch)   // the ZK deposit leaf
//! crowdLeaf     = Poseidon(CROWD_LEAF_DOMAIN, commitment) // the crowd leaf
//! nullifierHash = Poseidon(secret, epoch)               // epoch-scoped tag
//! Merkle node   = Poseidon(left, right)
//! ```
//!
//! The two accumulator leaves live in DISJOINT domains and that separation is a
//! fund-safety property, not a nicety: a crowd `Commit` costs only the entry fee
//! while a `CommitDeposit` escrows lamports, so if the two produced leaves of the
//! same shape a free crowd leaf could satisfy the ZK spend circuit and settle
//! against somebody else's escrow. The domain tag is absorbed by the PROGRAM (see
//! [`crowd_leaf`]), never by the caller, because the caller supplies the 32-byte
//! commitment verbatim and could otherwise pre-hash any tag it liked.
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

    /// Field negation: canonical big-endian encoding of `(r - x) mod r`.
    /// `negate(0)` is `0`. Used to encode a withdraw `publicAmount = r - v` with
    /// the FIELD_SIZE offset, matching `(FIELD_SIZE - v) % r` in the fixture
    /// generator.
    pub fn negate(bytes: &[u8; 32]) -> [u8; 32] {
        to_be(&(-from_be(bytes)))
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

/// Domain tag absorbed into every CROWD `Commit` leaf, and into nothing else.
///
/// `SHA-256("mirror-pool/leaf-domain/crowd/v1")` reduced into the BN254 scalar
/// field and encoded canonically big-endian - the same derivation
/// [`action_hash`] uses, so there is one convention for "a domain string as a
/// field element" in this repo. [`crowd_leaf_domain`] recomputes it and the unit
/// test below asserts the constant equals that derivation, so the literal is
/// never hand-maintained.
pub const CROWD_LEAF_DOMAIN: Hash32 = [
    0x2e, 0x2a, 0x23, 0x5e, 0xaf, 0xc3, 0x3e, 0xf6, 0x4e, 0xfb, 0x63, 0xe2, 0xb1, 0x81, 0xc5, 0xdb,
    0x9b, 0x5e, 0xbc, 0x4c, 0xbc, 0x2c, 0x26, 0xff, 0xa8, 0xe7, 0x21, 0xcb, 0x79, 0xf7, 0xec, 0x09,
];

/// The string [`CROWD_LEAF_DOMAIN`] is derived from, and that derivation.
pub fn crowd_leaf_domain() -> Hash32 {
    let digest: Hash32 = Sha256::digest(b"mirror-pool/leaf-domain/crowd/v1").into();
    field::to_be(&field::from_be(&digest))
}

/// The accumulator leaf a CROWD `Commit` appends:
/// `Poseidon(CROWD_LEAF_DOMAIN, commitment)`.
///
/// The crowd path takes an opaque 32-byte `commitment` from an unauthenticated
/// caller and pays nothing but the entry fee for it, while the ZK path escrows
/// lamports for a leaf of the shape `Poseidon(secret, actionHash, epoch)` that
/// the membership and association circuits recompute. Wrapping the crowd
/// commitment here puts the free leaves in a domain no ZK proof can reach:
///
///  - a crowd leaf is a WIDTH-2 Poseidon whose first input is a fixed tag, a ZK
///    deposit leaf is a WIDTH-3 Poseidon, so no crowd leaf is a deposit leaf
///    short of a Poseidon collision; and
///  - the wrap is applied ON-CHAIN, so a caller who submits an already-tagged
///    value gets it tagged AGAIN and still lands outside the ZK domain. This is
///    the part that matters: absorbing a tag into the deposit preimage instead
///    would be worthless, because the deposit leaf is caller-supplied bytes and
///    the caller could simply compute the tagged value itself and post it for
///    free through `Commit`.
///
/// The on-chain program computes the identical hash with the `sol_poseidon`
/// syscall (`state::merkle::crowd_leaf`); this is the host mirror, used by
/// anything that reconstructs the accumulator off-chain.
pub fn crowd_leaf(commitment: &Hash32) -> Hash32 {
    field::poseidon(&[
        field::from_be(&CROWD_LEAF_DOMAIN),
        field::from_be(commitment),
    ])
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

/// The Merkle tree depth the value-note circuit and the on-chain accumulator use
/// (`2^20` leaves), matching `transaction.circom`'s `MERKLE_DEPTH` and the
/// existing membership accumulator.
pub const MERKLE_DEPTH: usize = 20;

/// The canonical empty-subtree zero ladder for a depth-`depth` tree:
/// `zeros[0] = 0`, `zeros[i] = Poseidon(zeros[i-1], zeros[i-1])`. Returns
/// `depth + 1` entries; `zeros[level]` is the root of an empty subtree of that
/// height, so `zeros[depth]` is the root of a fully empty tree. Matches the
/// circuit and the fixture generator, and lets off-chain code build inclusion
/// paths and dummy-input siblings.
pub fn merkle_zeros(depth: usize) -> Vec<Hash32> {
    let mut zeros = Vec::with_capacity(depth + 1);
    let mut z = [0u8; 32];
    zeros.push(z);
    for _ in 0..depth {
        z = merkle_node(&z, &z);
        zeros.push(z);
    }
    zeros
}

/// Recompute a Merkle root from a `leaf`, its `leaf_index`, and the sibling
/// `path_elements` bottom-up (`path_elements[i]` is the sibling hash at level
/// `i`). `leaf_index` is decomposed little-endian: bit `i` selects whether the
/// running node is the left child (`0`, sibling on the right) or the right child
/// (`1`, sibling on the left) at level `i`. This is exactly the circuit's
/// `Num2Bits` path selector combined with [`merkle_node`]'s `Poseidon(left,
/// right)`, so a root computed here equals the one the circuit proves against and
/// the accumulator stores.
pub fn merkle_root_from_path(leaf: &Hash32, leaf_index: u64, path_elements: &[Hash32]) -> Hash32 {
    let mut cur = *leaf;
    for (level, sibling) in path_elements.iter().enumerate() {
        cur = if (leaf_index >> level) & 1 == 0 {
            merkle_node(&cur, sibling)
        } else {
            merkle_node(sibling, &cur)
        };
    }
    cur
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
        /// Confidential-value layer: create a ValuePool (its own value-note
        /// accumulator + vault). See [`super::INIT_VALUE_POOL_LEN`].
        pub const INIT_VALUE_POOL: u8 = 6;
        /// Confidential-value layer: a Tornado-Nova-style 2-in/2-out JoinSplit
        /// settlement (shield / transfer / unshield). See
        /// [`super::TRANSACT_HEADER_LEN`].
        pub const TRANSACT: u8 = 7;
        /// Opt-in compliance layer: register a curator's association set (seeds
        /// `["assoc", pool, curator]`). See [`super::INIT_ASSOCIATION_LEN`].
        pub const INIT_ASSOCIATION: u8 = 8;
        /// Opt-in compliance layer: publish a new curated-set Merkle root. See
        /// [`super::UPDATE_ASSOCIATION_ROOT_LEN`].
        pub const UPDATE_ASSOCIATION_ROOT: u8 = 9;
        /// Opt-in compliance layer: settle one membership that ALSO carries a
        /// curated-set inclusion proof. See [`super::SETTLE_ZK_ASSOCIATED_LEN`].
        pub const SETTLE_ZK_ASSOCIATED: u8 = 10;
        /// Write-once install of a digest-pinned verifying key into its
        /// program-owned registry PDA (seeds `["vk", circuit_id]`). See
        /// [`super::INIT_VK_HEADER_LEN`]. There is deliberately no update tag:
        /// the key a verify path reads is immutable for the deployment's life.
        pub const INIT_VK: u8 = 11;
        /// Opt-in disclosure layer: register (or rotate) an X25519 viewing key
        /// under the SIGNER'S OWN address (seeds `["view", authority]`). See
        /// [`super::REGISTER_VIEWING_KEY_LEN`].
        pub const REGISTER_VIEWING_KEY: u8 = 12;
        /// Opt-in disclosure layer: publish ONE sealed disclosure record about a
        /// settlement whose bound recipient is the signer (seeds
        /// `["disc", pool, action_hash, auditor_view_pub]`). See
        /// [`super::PUBLISH_DISCLOSURE_LEN`].
        pub const PUBLISH_DISCLOSURE: u8 = 13;
    }

    /// INIT_POOL layout:
    /// `[tag(1)][epoch_slots(8)][k_floor(4)][entry_fee(8)][reward_bps(2 LE)]
    /// [zk_denomination(8 LE)]` - the operator fixes the epoch window, the
    /// k-anonymity floor, the per-commit anti-Sybil entry fee (lamports; 0
    /// disables it), `reward_bps`, the basis-point share of each entry fee that
    /// accrues to the on-chain reward pool (the remainder covers
    /// relay/settlement cost; `reward_bps` must be `<= 10_000`), and
    /// `zk_denomination`, the ONE escrow size the ZK opt-in path accepts.
    ///
    /// `zk_denomination` must be non-zero: it is what makes a settle unable to
    /// draw more than the leaf it spends escrowed, since `CommitDeposit` refuses
    /// any other amount and both ZK settle paths refuse to pay any other amount.
    /// A pool serving several sizes is several pools, exactly as the fixed
    /// action shape already implies. MUST stay byte-identical to the program's
    /// `wire::INIT_POOL_LEN`.
    pub const INIT_POOL_LEN: usize = 1 + 8 + 4 + 8 + 2 + 8;

    /// CLAIM_REWARD layout: `[tag(1)]`. The claimant is the signer; their dwell
    /// PDA (seeds `["dwell", pool, participant]`) carries the accumulated dwell,
    /// so no body fields are needed. MUST stay byte-identical to the program's
    /// `wire::CLAIM_REWARD_LEN`.
    pub const CLAIM_REWARD_LEN: usize = 1;

    /// Basis-point denominator for the entry-fee reward split (`reward_bps` is
    /// out of this). 100% = 10_000 bps.
    pub const BPS_DENOMINATOR: u16 = 10_000;

    /// COMMIT layout: [tag(1)][commitment(32)] - the participant posts only the
    /// commitment; the action + secret stay client-side until settlement. The
    /// program appends [`super::crowd_leaf`] of this value, not the value
    /// itself, so a free crowd leaf can never be a ZK deposit leaf.
    pub const COMMIT_LEN: usize = 1 + 32;

    /// SETTLE_EPOCH header: [tag(1)][epoch(8)][n_nullifiers(4)] followed by
    /// n_nullifiers * 32 bytes. The relayer submits the whole epoch atomically.
    pub const SETTLE_HEADER_LEN: usize = 1 + 8 + 4;

    /// COMMIT_DEPOSIT layout: [tag(1)][commitment(32)][amount(8 LE)] - the ZK
    /// opt-in escrow. Escrows `amount` lamports and posts the commitment whose
    /// `actionHash` binds `(recipient, amount)` (see
    /// [`super::transfer_action_hash`]). `amount` MUST equal the pool's
    /// `zk_denomination`; any other size is rejected. The commitment is appended
    /// verbatim, which is what makes it a ZK-domain leaf. MUST stay
    /// byte-identical to the program's `wire::COMMIT_DEPOSIT_LEN`.
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

    /// One Groth16 public input (a canonical big-endian BN254 scalar), shared by
    /// the membership and association layouts.
    pub const PUBLIC_INPUT_LEN: usize = 32;

    // --- Opt-in compliance layer (ADDITIVE): AssociationSet + SettleZkAssociated.
    // Kept byte-identical to the on-chain program's mirrored `wire` module; the
    // compile-time asserts below (and the program's) pin the numbers. ---

    /// INIT_ASSOCIATION layout: `[tag(1)]`. The pool and the curator are both
    /// accounts (the curator signs for itself), so there is no body. MUST stay
    /// byte-identical to the program's `wire::INIT_ASSOCIATION_LEN`.
    pub const INIT_ASSOCIATION_LEN: usize = 1;

    /// UPDATE_ASSOCIATION_ROOT layout: `[tag(1)][root(32)]` - the curator posts
    /// the Merkle root of its curated commitment list. MUST stay byte-identical to
    /// the program's `wire::UPDATE_ASSOCIATION_ROOT_LEN`.
    pub const UPDATE_ASSOCIATION_ROOT_LEN: usize = 1 + 32;

    /// Number of association public inputs, in the fixed order
    /// [root, nullifierHash, actionHash, epoch, associationRoot]. The first four
    /// are byte-for-byte the membership circuit's four, in the same order.
    pub const ASSOCIATION_N_PUBLIC_INPUTS: usize = 5;

    /// SETTLE_ZK_ASSOCIATED layout (ONE membership per call):
    ///
    /// ```text
    /// [tag(1)][epoch(8 LE)][amount(8 LE)]
    ///   [proof_a(64)][proof_b(128)][proof_c(64)]
    ///   [root(32)][nullifierHash(32)][actionHash(32)][epoch(32 BE)][associationRoot(32)]
    /// ```
    ///
    /// A strict EXTENSION of [`SETTLE_ZK_LEN`]: identical bytes through the first
    /// four public inputs, with the curated-set root appended. MUST stay
    /// byte-identical to the program's `wire::SETTLE_ZK_ASSOCIATED_LEN`.
    pub const SETTLE_ZK_ASSOCIATED_LEN: usize = SETTLE_ZK_LEN + PUBLIC_INPUT_LEN;

    // --- Confidential-value layer (ADDITIVE): ValuePool + Transact. Kept
    // byte-identical to the on-chain program's mirrored `wire` module; the
    // compile-time asserts below (and the program's) pin the numbers so the two
    // sides cannot drift. ---

    /// INIT_VALUE_POOL layout: `[tag(1)][fee(8 LE)][denom_flag(1)][denomination(8 LE)]`.
    ///
    /// `fee` is the relay fee (lamports) bound into every Transact's ext-data.
    /// `denomination` is an `Option<u64>` reserved for the fixed-denomination mode
    /// landing next: `denom_flag == 0` means `None` (and `denomination` is
    /// ignored); it is stored but NOT enforced in this version. MUST stay
    /// byte-identical to the program's `wire::INIT_VALUE_POOL_LEN`.
    pub const INIT_VALUE_POOL_LEN: usize = 1 + 8 + 1 + 8;

    /// Groth16 proof component sizes for the transaction circuit (groth16-solana
    /// v0.2.0 byte layout), shared by the Transact wire layout.
    pub const TRANSACT_PROOF_A_LEN: usize = 64;
    pub const TRANSACT_PROOF_B_LEN: usize = 128;
    pub const TRANSACT_PROOF_C_LEN: usize = 64;
    /// One Groth16 public input (a canonical big-endian BN254 scalar).
    pub const TRANSACT_PUBLIC_INPUT_LEN: usize = 32;
    /// Number of transaction public inputs, in the fixed order
    /// [root, publicAmount, extDataHash, inNullifier0, inNullifier1,
    /// outCommitment0, outCommitment1].
    pub const TRANSACT_N_PUBLIC_INPUTS: usize = 7;
    /// Per-blob cap on an encrypted output-note payload (bytes). Bounds the
    /// length arithmetic and keeps a Transact inside transaction limits.
    pub const TRANSACT_MAX_ENC_LEN: usize = 256;

    // Field offsets inside the fixed Transact header (after the tag byte).
    pub const TRANSACT_PUBLIC_AMOUNT_OFF: usize = 0;
    pub const TRANSACT_EXT_DATA_HASH_OFF: usize = 32;
    pub const TRANSACT_ROOT_OFF: usize = 64;
    pub const TRANSACT_IN_NULLIFIER0_OFF: usize = 96;
    pub const TRANSACT_IN_NULLIFIER1_OFF: usize = 128;
    pub const TRANSACT_OUT_COMMIT0_OFF: usize = 160;
    pub const TRANSACT_OUT_COMMIT1_OFF: usize = 192;
    pub const TRANSACT_PROOF_A_OFF: usize = 224;
    pub const TRANSACT_PROOF_B_OFF: usize = TRANSACT_PROOF_A_OFF + TRANSACT_PROOF_A_LEN; // 288
    pub const TRANSACT_PROOF_C_OFF: usize = TRANSACT_PROOF_B_OFF + TRANSACT_PROOF_B_LEN; // 416
    pub const TRANSACT_FEE_OFF: usize = TRANSACT_PROOF_C_OFF + TRANSACT_PROOF_C_LEN; // 480
    /// First byte of the two length-prefixed encrypted-note blobs.
    pub const TRANSACT_ENC_OFF: usize = TRANSACT_FEE_OFF + 8; // 488

    /// TRANSACT layout (ONE JoinSplit per call):
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
    /// The fixed header (body after the tag byte, before the two blobs) is
    /// [`TRANSACT_HEADER_LEN`] bytes. Each blob is a `u16` little-endian length
    /// followed by that many bytes, capped at [`TRANSACT_MAX_ENC_LEN`]. The seven
    /// 32-byte values are the Groth16 public inputs in the fixed order
    /// [root, publicAmount, extDataHash, inNullifier0, inNullifier1,
    /// outCommitment0, outCommitment1]. MUST stay byte-identical to the program's
    /// `wire::TRANSACT_HEADER_LEN` and offsets.
    pub const TRANSACT_HEADER_LEN: usize = 7 * TRANSACT_PUBLIC_INPUT_LEN
        + TRANSACT_PROOF_A_LEN
        + TRANSACT_PROOF_B_LEN
        + TRANSACT_PROOF_C_LEN
        + 8;

    // Layout sanity: keep the documented sizes honest at compile time and in
    // lockstep with the on-chain program's mirrored constants.
    const _: () = assert!(INIT_POOL_LEN == 31);
    const _: () = assert!(COMMIT_LEN == 33);
    const _: () = assert!(SETTLE_HEADER_LEN == 13);
    const _: () = assert!(COMMIT_DEPOSIT_LEN == 41);
    const _: () = assert!(SETTLE_ZK_LEN == 401);
    const _: () = assert!(CLAIM_REWARD_LEN == 1);
    const _: () = assert!(INIT_VALUE_POOL_LEN == 18);
    const _: () = assert!(TRANSACT_HEADER_LEN == 488);
    const _: () = assert!(TRANSACT_ENC_OFF == TRANSACT_HEADER_LEN);
    const _: () = assert!(TRANSACT_PROOF_B_OFF == 288);
    const _: () = assert!(TRANSACT_PROOF_C_OFF == 416);
    const _: () = assert!(TRANSACT_FEE_OFF == 480);
    // Opt-in compliance layer: pin the association sizes in lockstep with the
    // program's mirrored `wire` module (which asserts the same numbers).
    const _: () = assert!(INIT_ASSOCIATION_LEN == 1);
    const _: () = assert!(UPDATE_ASSOCIATION_ROOT_LEN == 33);
    const _: () = assert!(ASSOCIATION_N_PUBLIC_INPUTS == 5);
    const _: () = assert!(SETTLE_ZK_ASSOCIATED_LEN == 433);
    const _: () = assert!(PUBLIC_INPUT_LEN == 32);
    // Digest-pinned verifying-key registry: pin the canonical encoding sizes in
    // lockstep with the program's mirrored `wire` module.
    const _: () = assert!(VK_IC_OFF == 449);
    const _: () = assert!(vk_encoded_len(4) == 769);
    const _: () = assert!(vk_encoded_len(5) == 833);
    const _: () = assert!(vk_encoded_len(7) == 961);
    const _: () = assert!(VK_MAX_ENCODED_LEN == 961);
    const _: () = assert!(INIT_VK_HEADER_LEN == 2);
    const _: () = assert!(VK_REGISTRY_HEADER_LEN == 4);
    // Opt-in disclosure layer: pin the sizes in lockstep with the program's
    // mirrored `wire` module (which asserts the same numbers).
    const _: () = assert!(REGISTER_VIEWING_KEY_LEN == 33);
    const _: () = assert!(PUBLISH_DISCLOSURE_LEN == 109);
    const _: () = assert!(DISCLOSURE_BLOB_LEN == 100);
    // The on-chain record stores exactly one sealed `encrypted_note` blob, so the
    // two lengths are the same number by construction, not by coincidence.
    const _: () = assert!(DISCLOSURE_BLOB_LEN == crate::encrypted_note::ENC_NOTE_BLOB_LEN);

    // --- Opt-in disclosure layer (ADDITIVE): on-chain viewing keys + sealed
    // disclosure records. Kept byte-identical to the on-chain program's mirrored
    // `wire` module and `pda` seeds. ---

    /// Seed prefix of a registered viewing key's PDA: `["view", authority]`.
    ///
    /// The authority is the ONLY variable seed, so a registration can only ever
    /// land under the address that signed for it. There is no slot anybody else
    /// can take, which is what makes the directory unsquattable. MUST match the
    /// program's `pda::VIEWING_KEY_SEED`.
    pub const VIEWING_KEY_SEED: &[u8] = b"view";

    /// Seed prefix of a disclosure record's PDA:
    /// `["disc", pool, action_hash, auditor_view_pub]`.
    ///
    /// `action_hash = Poseidon(recipientHi128, recipientLo128, amount)` is
    /// recomputed ON-CHAIN from the SIGNING recipient's address, so the slot a
    /// record can occupy is a function of the signer's own key: publishing
    /// against somebody else's settlement is not a check that can be skipped, it
    /// is an address that cannot be derived. MUST match the program's
    /// `pda::DISCLOSURE_SEED`.
    pub const DISCLOSURE_SEED: &[u8] = b"disc";

    /// REGISTER_VIEWING_KEY layout: `[tag(1)][viewing_pub(32)]`.
    ///
    /// The authority and the rent payer are both accounts, so the body is just
    /// the X25519 public key. MUST match the program's
    /// `wire::REGISTER_VIEWING_KEY_LEN`.
    pub const REGISTER_VIEWING_KEY_LEN: usize = 1 + 32;

    /// The one sealed blob a disclosure record carries: exactly one
    /// [`crate::encrypted_note`] ciphertext,
    /// `ephemeral_pub(32) || nonce(12) || ct+tag(56)`. Any other length is
    /// malformed. MUST match the program's `wire::DISCLOSURE_BLOB_LEN`.
    pub const DISCLOSURE_BLOB_LEN: usize = 100;

    /// PUBLISH_DISCLOSURE layout: `[tag(1)][amount(8 LE)][blob(100)]`.
    ///
    /// `amount` is the settled action's public amount (the pool's fixed
    /// `zk_denomination`); together with the SIGNING recipient it is what the
    /// on-chain Poseidon recomputation turns into the record's address. MUST
    /// match the program's `wire::PUBLISH_DISCLOSURE_LEN`.
    pub const PUBLISH_DISCLOSURE_LEN: usize = 1 + 8 + DISCLOSURE_BLOB_LEN;

    // --- Digest-pinned verifying-key registry (ADDITIVE). Kept byte-identical to
    // the on-chain program's mirrored `wire` module. ---

    /// Circuit ids. One write-once registry PDA per id (seeds
    /// `["vk", circuit_id]`), each holding exactly the key whose SHA-256 the
    /// program pins at compile time. MUST match the program's `wire::CIRCUIT_*`.
    pub const CIRCUIT_MEMBERSHIP: u8 = 0;
    pub const CIRCUIT_TRANSACTION: u8 = 1;
    pub const CIRCUIT_ASSOCIATION: u8 = 2;

    /// PDA seed prefix for a circuit's verifying-key registry.
    pub const VK_REGISTRY_SEED: &[u8] = b"vk";

    /// Bytes of registry-account header before the key: `[version][circuit_id]
    /// [bump][reserved]`.
    pub const VK_REGISTRY_HEADER_LEN: usize = 4;

    /// Byte offsets inside the CANONICAL verifying-key encoding, the one
    /// serialization the on-chain digest is taken over:
    ///
    /// ```text
    /// [nr_pubinputs(1)][alpha_g1(64)][beta_g2(128)][gamma_g2(128)][delta_g2(128)]
    ///   [ic(64 * (nr_pubinputs + 1))]
    /// ```
    ///
    /// Big-endian and uncompressed, i.e. byte-identical to the `groth16-solana`
    /// in-memory layout. MUST match the program's `wire::VK_*`.
    pub const VK_NR_PUBINPUTS_OFF: usize = 0;
    pub const VK_ALPHA_G1_OFF: usize = 1;
    pub const VK_BETA_G2_OFF: usize = VK_ALPHA_G1_OFF + VK_G1_LEN;
    pub const VK_GAMMA_G2_OFF: usize = VK_BETA_G2_OFF + VK_G2_LEN;
    pub const VK_DELTA_G2_OFF: usize = VK_GAMMA_G2_OFF + VK_G2_LEN;
    pub const VK_IC_OFF: usize = VK_DELTA_G2_OFF + VK_G2_LEN;

    /// One uncompressed G1 point (`x || y`).
    pub const VK_G1_LEN: usize = 64;
    /// One uncompressed G2 point (`x_c1 || x_c0 || y_c1 || y_c0`).
    pub const VK_G2_LEN: usize = 128;

    /// Largest public-input count any pinned circuit uses (the JoinSplit's 7).
    pub const VK_MAX_PUBLIC_INPUTS: usize = 7;

    /// Length of the canonical encoding for a key with `nr_pubinputs` inputs.
    /// MUST match the program's `wire::vk_encoded_len`.
    pub const fn vk_encoded_len(nr_pubinputs: usize) -> usize {
        VK_IC_OFF + VK_G1_LEN * (nr_pubinputs + 1)
    }

    /// Longest canonical encoding across the pinned circuits.
    pub const VK_MAX_ENCODED_LEN: usize = vk_encoded_len(VK_MAX_PUBLIC_INPUTS);

    /// INIT_VK layout: `[tag(1)][circuit_id(1)][vk(vk_encoded_len(n))]`, where
    /// `n` is the circuit's pinned public-input count, so the body length is
    /// fixed per circuit and any other length is malformed. The largest key
    /// (the JoinSplit's 961 bytes) still fits a single 1232-byte transaction.
    /// MUST match the program's `wire::INIT_VK_HEADER_LEN`.
    pub const INIT_VK_HEADER_LEN: usize = 1 + 1;

    /// Serialize a Groth16 verifying key into the canonical encoding above.
    ///
    /// Takes the parts rather than a verifier type so this crate stays free of
    /// an on-chain-verifier dependency. `ic` must have `nr_pubinputs + 1`
    /// entries; anything else is a caller bug and returns `None`.
    pub fn encode_vk(
        nr_pubinputs: usize,
        alpha_g1: &[u8; VK_G1_LEN],
        beta_g2: &[u8; VK_G2_LEN],
        gamma_g2: &[u8; VK_G2_LEN],
        delta_g2: &[u8; VK_G2_LEN],
        ic: &[[u8; VK_G1_LEN]],
    ) -> Option<Vec<u8>> {
        if nr_pubinputs > VK_MAX_PUBLIC_INPUTS || ic.len() != nr_pubinputs + 1 {
            return None;
        }
        let mut out = vec![0u8; vk_encoded_len(nr_pubinputs)];
        out[VK_NR_PUBINPUTS_OFF] = nr_pubinputs as u8;
        out[VK_ALPHA_G1_OFF..VK_ALPHA_G1_OFF + VK_G1_LEN].copy_from_slice(alpha_g1);
        out[VK_BETA_G2_OFF..VK_BETA_G2_OFF + VK_G2_LEN].copy_from_slice(beta_g2);
        out[VK_GAMMA_G2_OFF..VK_GAMMA_G2_OFF + VK_G2_LEN].copy_from_slice(gamma_g2);
        out[VK_DELTA_G2_OFF..VK_DELTA_G2_OFF + VK_G2_LEN].copy_from_slice(delta_g2);
        for (i, point) in ic.iter().enumerate() {
            let off = VK_IC_OFF + i * VK_G1_LEN;
            out[off..off + VK_G1_LEN].copy_from_slice(point);
        }
        Some(out)
    }

    /// Assemble `INIT_VK` instruction data for a circuit and a canonical key.
    pub fn init_vk_data(circuit_id: u8, vk: &[u8]) -> Vec<u8> {
        let mut data = Vec::with_capacity(INIT_VK_HEADER_LEN + vk.len());
        data.push(tag::INIT_VK);
        data.push(circuit_id);
        data.extend_from_slice(vk);
        data
    }
}

/// Encrypted output-notes and client-side discovery (host-side only). ADDITIVE:
/// the sender seals a note's spend material to the recipient's X25519 viewing key,
/// the ciphertext rides on-chain as a Transact `enc` blob, and the recipient scans
/// and trial-decrypts to recover spendable notes. See the module docs for the
/// exact on-chain blob byte layout.
pub mod encrypted_note;

/// Opt-in selective disclosure to an auditor the user chose (host-side).
/// ADDITIVE, and additive to [`encrypted_note`] in particular: a disclosure IS an
/// encrypted-note blob, sealed to an auditor's on-chain-registered viewing key,
/// whose plaintext is the `(epoch, secret)` pair that lets exactly that reader
/// recompute one action's deposit leaf and spend tag. Nothing here is required by
/// any settle path. See the module docs and `docs/COMPLIANCE.md`.
pub mod disclosure;

/// Confidential value-note (UTXO) primitives for the 2-in / 2-out JoinSplit
/// `circuits/transaction.circom` (see `circuits/TRANSACTION.md`).
///
/// This is the value-carrying counterpart to the behavioral membership scheme in
/// the crate root: instead of hiding *which initiator* acted, it proves a
/// balanced spend of shielded value notes while hiding amounts, owners, and which
/// notes were spent. A value note is `{ amount, public_key, blinding }`; its
/// owner holds a `private_key`. Every hash is circomlib Poseidon over BN254,
/// canonical 32-byte BIG-ENDIAN, exactly as the circuit enforces and the
/// `sol_poseidon` syscall computes, so this module (host), the circuit, and the
/// on-chain program agree byte-for-byte:
///
/// ```text
/// public_key = Poseidon(private_key)                         // 1-input (t=2)
/// commitment = Poseidon(amount, public_key, blinding)        // 3-input (t=4)  -- Merkle leaf
/// signature  = Poseidon(private_key, commitment, pathIndex)  // 3-input (t=4)
/// nullifier  = Poseidon(commitment, pathIndex, signature)    // 3-input (t=4)
/// ```
///
/// `pathIndex` (the circuit's `merklePathIndices`) is the note's leaf index as a
/// single field element (`Fr::from(leaf_index)`, passed here as a `u64`); the
/// circuit `Num2Bits`-decomposes it into [`MERKLE_DEPTH`] little-endian selector
/// bits. Binding the index makes a note's nullifier position-specific.
///
/// Correctness is pinned by the fixture cross-check test, which reproduces the
/// committed circuit's output commitments, input nullifiers, Merkle root,
/// `publicAmount`, and `extDataHash` for the SHIELD, TRANSFER, and UNSHIELD
/// fixtures exactly.
pub mod note {
    use crate::{field, Hash32};
    use serde::{Deserialize, Serialize};
    use sha3::{Digest, Keccak256};

    /// Bit width the circuit range-binds each output amount and the
    /// `publicAmount` magnitude to (`Num2Bits(248)`). A valid magnitude is in
    /// `[0, 2^248)`; a `u64` is always in range.
    pub const MAX_AMOUNT_BITS: u32 = 248;

    /// A value-note owner keypair. `public_key = Poseidon(private_key)`.
    #[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    pub struct ValueKeypair {
        /// The owner's secret scalar, canonical big-endian (< r). Whoever knows
        /// it can spend notes addressed to `public_key()`.
        pub private_key: Hash32,
    }

    impl ValueKeypair {
        /// Build a keypair from a secret scalar, canonicalizing it into the field
        /// (reducing mod r) so the stored `private_key` is always a canonical
        /// `Fr` (< r). For inputs already < r (as the fixtures use) this is the
        /// identity.
        pub fn from_private_key(private_key: Hash32) -> Self {
            Self {
                private_key: field::to_be(&field::from_be(&private_key)),
            }
        }

        /// `public_key = Poseidon(private_key)` (1-input Poseidon, t = 2).
        pub fn public_key(&self) -> Hash32 {
            field::poseidon(&[field::from_be(&self.private_key)])
        }
    }

    impl core::fmt::Debug for ValueKeypair {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            // Never print the secret scalar.
            write!(f, "ValueKeypair {{ private_key: *** }}")
        }
    }

    /// A confidential value note (UTXO): `{ amount, public_key, blinding }`. The
    /// [`Note::commitment`] `Poseidon(amount, public_key, blinding)` is its Merkle
    /// leaf.
    #[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
    pub struct Note {
        /// Note value. The circuit `Num2Bits(248)`-range-binds output amounts; a
        /// `u64` is always in range.
        pub amount: u64,
        /// Owner public key `Poseidon(private_key)`, canonical big-endian.
        pub public_key: Hash32,
        /// Per-note blinding factor, canonical big-endian (< r); hides the amount
        /// and makes commitments unlinkable.
        pub blinding: Hash32,
    }

    impl Note {
        pub fn new(amount: u64, public_key: Hash32, blinding: Hash32) -> Self {
            Self {
                amount,
                public_key,
                blinding,
            }
        }

        /// `commitment = Poseidon(amount, public_key, blinding)` (3-input Poseidon,
        /// t = 4): the note's Merkle leaf.
        pub fn commitment(&self) -> Hash32 {
            field::poseidon(&[
                field::from_u64(self.amount),
                field::from_be(&self.public_key),
                field::from_be(&self.blinding),
            ])
        }

        /// A dummy input has `amount == 0`; the circuit disables its Merkle
        /// membership check (`ForceEqualIfEnabled` with `enabled = amount`), so it
        /// may sit at the zero ladder with index 0. This is what lets a shield
        /// spend two dummy inputs.
        pub fn is_dummy(&self) -> bool {
            self.amount == 0
        }
    }

    /// `signature = Poseidon(private_key, commitment, pathIndex)` where
    /// `pathIndex` is `leaf_index` as a single field element (3-input Poseidon,
    /// t = 4).
    pub fn signature(private_key: &Hash32, commitment: &Hash32, leaf_index: u64) -> Hash32 {
        field::poseidon(&[
            field::from_be(private_key),
            field::from_be(commitment),
            field::from_u64(leaf_index),
        ])
    }

    /// `nullifier = Poseidon(commitment, pathIndex, signature)` (3-input Poseidon,
    /// t = 4). This is the tag the program marks spent; it is deterministic from
    /// the note plus its position, so double-spends collide.
    pub fn nullifier(commitment: &Hash32, leaf_index: u64, signature: &Hash32) -> Hash32 {
        field::poseidon(&[
            field::from_be(commitment),
            field::from_u64(leaf_index),
            field::from_be(signature),
        ])
    }

    /// Convenience: the nullifier of `note` spent by `keypair` at `leaf_index`.
    /// Recomputes the commitment and signature, then returns
    /// `nullifier(commitment, leaf_index, signature(private_key, commitment,
    /// leaf_index))`.
    pub fn note_nullifier(keypair: &ValueKeypair, note: &Note, leaf_index: u64) -> Hash32 {
        let commitment = note.commitment();
        let sig = signature(&keypair.private_key, &commitment, leaf_index);
        nullifier(&commitment, leaf_index, &sig)
    }

    /// Net public value crossing the shielded boundary (in Tornado-Nova terms
    /// `publicAmount = extAmount - fee`), before FIELD_SIZE-offset field encoding.
    #[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
    pub enum SignedAmount {
        /// transfer: no public value moves. `publicAmount = 0`.
        Transfer,
        /// shield / deposit of `v` into the pool. `publicAmount = v`.
        Deposit(u64),
        /// unshield / withdraw of `v` out of the pool. `publicAmount = r - v`.
        Withdraw(u64),
    }

    /// Errors decoding a `publicAmount` field element.
    #[derive(Debug, thiserror::Error)]
    pub enum ValueNoteError {
        /// The value is in neither the deposit range `[0, 2^248)` nor the withdraw
        /// range `(r - 2^248, r)`, so it is not a valid signed encoding.
        #[error(
            "publicAmount is in neither the deposit [0, 2^248) nor withdraw (r - 2^248, r) range"
        )]
        PublicAmountOutOfRange(Hash32),
        /// The value is a valid signed encoding but its magnitude exceeds `u64`,
        /// so it is not a representable token amount.
        #[error("decoded publicAmount magnitude exceeds u64 (not a representable token amount)")]
        MagnitudeExceedsU64,
    }

    /// Encode a [`SignedAmount`] to the canonical `publicAmount` field element
    /// (canonical big-endian) using the FIELD_SIZE offset: `Deposit(v) -> v`,
    /// `Withdraw(v) -> r - v` (field negation), `Transfer -> 0`. A `u64` magnitude
    /// is always `< 2^248`, so the encoding is always in range.
    pub fn public_amount(signed: SignedAmount) -> Hash32 {
        match signed {
            SignedAmount::Transfer => [0u8; 32],
            SignedAmount::Deposit(v) => field::to_be(&field::from_u64(v)),
            SignedAmount::Withdraw(v) => field::negate(&field::to_be(&field::from_u64(v))),
        }
    }

    /// Decode a `publicAmount` field element back to a [`SignedAmount`]. The
    /// deposit range `[0, 2^248)` and the withdraw range `(r - 2^248, r)` are
    /// disjoint (r is ~2^253.6), so the sign is unambiguous and no negative value
    /// can wrap into a large positive one. Rejects a value in neither range, and
    /// a valid encoding whose magnitude does not fit `u64`.
    pub fn decode_public_amount(public_amount: &Hash32) -> Result<SignedAmount, ValueNoteError> {
        if public_amount == &[0u8; 32] {
            return Ok(SignedAmount::Transfer);
        }
        // publicAmount < 2^248  <=>  its most-significant byte is zero (a value
        // with any of bits 248..255 set has a nonzero top byte).
        if is_valid_amount_magnitude(public_amount) {
            return Ok(SignedAmount::Deposit(magnitude_to_u64(public_amount)?));
        }
        // r - publicAmount < 2^248  <=>  the negation's top byte is zero.
        let neg = field::negate(public_amount);
        if is_valid_amount_magnitude(&neg) {
            return Ok(SignedAmount::Withdraw(magnitude_to_u64(&neg)?));
        }
        Err(ValueNoteError::PublicAmountOutOfRange(*public_amount))
    }

    /// True iff `magnitude` (canonical big-endian) is `< 2^248`, the in-circuit
    /// `Num2Bits(248)` bound. Equivalent to the most-significant byte being zero.
    pub fn is_valid_amount_magnitude(magnitude: &Hash32) -> bool {
        magnitude[0] == 0
    }

    /// Extract a `u64` from a canonical big-endian magnitude, erroring if it does
    /// not fit (bytes above the low 8 are nonzero).
    fn magnitude_to_u64(be: &Hash32) -> Result<u64, ValueNoteError> {
        if be[..24].iter().any(|&b| b != 0) {
            return Err(ValueNoteError::MagnitudeExceedsU64);
        }
        let mut low = [0u8; 8];
        low.copy_from_slice(&be[24..32]);
        Ok(u64::from_be_bytes(low))
    }

    /// Canonical `extDataHash` public input: `keccak256(preimage) mod r`, where
    ///
    /// ```text
    /// preimage = recipient(32) || relayer(32) || fee_u64_be(8) || enc_out0 || enc_out1
    /// ```
    ///
    /// `keccak256` is Ethereum-style Keccak-256, byte-identical to the on-chain
    /// `sol_keccak256` / `solana-keccak-hasher` syscall and to `ethers.keccak256`
    /// in the fixture generator, so host, program, and circuit fixtures agree. The
    /// circuit only binds `extDataHash` against malleation; the program recomputes
    /// it from the ext data it receives and requires equality, so any tamper with
    /// recipient / relayer / fee / payload changes the hash and fails
    /// verification. The `enc_out*` are the encrypted output-note payloads that let
    /// recipients discover their outputs; their lengths are part of the agreed
    /// serialization.
    pub fn ext_data_hash(
        recipient: &[u8; 32],
        relayer: &[u8; 32],
        fee: u64,
        enc_out0: &[u8],
        enc_out1: &[u8],
    ) -> Hash32 {
        let mut hasher = Keccak256::new();
        hasher.update(recipient);
        hasher.update(relayer);
        hasher.update(fee.to_be_bytes());
        hasher.update(enc_out0);
        hasher.update(enc_out1);
        let digest: [u8; 32] = hasher.finalize().into();
        // Reduce the 256-bit big-endian digest into the field and re-encode
        // canonically, matching `BigInt(keccak256(...)) % r` in the generator.
        field::to_be(&field::from_be(&digest))
    }
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

    /// The pinned domain constant must equal its own derivation, so the literal
    /// in the source (and the one mirrored into the on-chain program) is never
    /// hand-maintained.
    #[test]
    fn crowd_leaf_domain_matches_its_derivation() {
        assert_eq!(CROWD_LEAF_DOMAIN, crowd_leaf_domain());
        // A canonical BN254 scalar: its top byte is below the field order's.
        assert!(CROWD_LEAF_DOMAIN[0] < 0x30);
    }

    /// The fund-safety statement in one test: no commitment a free `Commit` can
    /// post produces the same leaf as the ZK deposit path, because the program
    /// wraps the crowd value and the wrap is a different Poseidon width with a
    /// fixed first input. In particular, pre-wrapping client-side does not help:
    /// the program wraps whatever it is given.
    #[test]
    fn crowd_leaves_are_disjoint_from_zk_deposit_leaves() {
        let s = Secret([0x21u8; 32]);
        let epoch = Epoch(7);
        let deposit_leaf = commit(&s, &action(), epoch).0;

        // The obvious attack: post the deposit leaf itself through the free path.
        assert_ne!(crowd_leaf(&deposit_leaf), deposit_leaf);
        // The next attack: pre-compute the wrap client-side and post that.
        assert_ne!(crowd_leaf(&crowd_leaf(&deposit_leaf)), deposit_leaf);
        // And the wrap is injective in practice, so crowd leaves stay distinct.
        assert_ne!(crowd_leaf(&[0u8; 32]), crowd_leaf(&[1u8; 32]));
        // A zero commitment does not stay the zero (empty) leaf either.
        assert_ne!(crowd_leaf(&[0u8; 32]), [0u8; 32]);
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

#[cfg(test)]
mod value_note_tests {
    use super::note::*;
    use super::{field, merkle_root_from_path, merkle_zeros, Hash32, MERKLE_DEPTH};
    use serde_json::Value;

    // The three committed transaction fixtures (the circuit's own snarkjs output)
    // and the scheme metadata, embedded so the cross-check is hermetic.
    const META: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../circuits/artifacts/transaction_fixture_meta.json"
    ));
    const SHIELD: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../circuits/artifacts/transaction_shield_fixture.json"
    ));
    const TRANSFER: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../circuits/artifacts/transaction_proof_fixture.json"
    ));
    const UNSHIELD: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../circuits/artifacts/transaction_unshield_fixture.json"
    ));

    // A small field element (blindings / amounts appear as small integers in the
    // generator), as a canonical big-endian Hash32.
    fn fe(x: u64) -> Hash32 {
        field::to_be(&field::from_u64(x))
    }

    // A field element parsed from the generator's decimal constants.
    fn dec(s: &str) -> Hash32 {
        field::from_dec(s)
    }

    // The public signals array of a fixture, as decimal strings, in the fixed
    // on-chain order [root, publicAmount, extDataHash, inNf0, inNf1, outC0, outC1].
    fn public_signals(fixture: &str) -> Vec<String> {
        let v: Value = serde_json::from_str(fixture).unwrap();
        v["publicSignals"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap().to_string())
            .collect()
    }

    // Fixed 32-byte-per-32 recipient / relayer and the deterministic encrypted
    // payloads, matching gen_transaction_fixture.js exactly.
    fn recipient() -> [u8; 32] {
        let mut r = [0u8; 32];
        for (i, b) in r.iter_mut().enumerate() {
            *b = (i + 1) as u8; // 0x01..0x20
        }
        r
    }
    fn relayer() -> [u8; 32] {
        let mut r = [0u8; 32];
        for (i, b) in r.iter_mut().enumerate() {
            *b = (0x20 - i) as u8; // 0x20..0x01
        }
        r
    }
    fn payload(seed: u64) -> Vec<u8> {
        (0..48u64)
            .map(|i| ((seed * 131 + i * 17) & 0xff) as u8)
            .collect()
    }

    // A dummy input (amount == 0) built exactly as the generator's dummyInput().
    fn dummy(sk: &str, blinding: &str) -> (ValueKeypair, Note) {
        let kp = ValueKeypair::from_private_key(dec(sk));
        let note = Note::new(0, kp.public_key(), dec(blinding));
        (kp, note)
    }

    /// DECISIVE circomlib-compatibility check: reproduce, for the committed
    /// SHIELD, TRANSFER, and UNSHIELD circuit fixtures, every public signal the
    /// value-note primitives are responsible for - output commitments, input
    /// nullifiers, the Merkle root, `publicAmount`, and `extDataHash` - using only
    /// mirror-core. If this passes, a proof generated for `transaction.circom`
    /// verifies against a root and public inputs this code (and the on-chain
    /// accumulator, which uses the same Poseidon with the same big-endian byte
    /// order) produces.
    #[test]
    fn transaction_fixtures_cross_check() {
        // Public-input order and shape are part of the scheme; pin the meta.
        let meta: Value = serde_json::from_str(META).unwrap();
        assert_eq!(
            meta["publicInputOrder"],
            serde_json::json!([
                "root",
                "publicAmount",
                "extDataHash",
                "inputNullifier[0]",
                "inputNullifier[1]",
                "outputCommitment[0]",
                "outputCommitment[1]"
            ]),
            "public-input order must match the canonical scheme"
        );
        assert_eq!(meta["nPublic"], serde_json::json!(7));
        assert_eq!(meta["merkleDepth"].as_u64().unwrap() as usize, MERKLE_DEPTH);

        // Fixed keypairs from the generator.
        let alice = ValueKeypair::from_private_key(dec("100000000000000000000000000000000001"));
        let bob = ValueKeypair::from_private_key(dec("200000000000000000000000000000000002"));
        let alice_pk = alice.public_key();
        let bob_pk = bob.public_key();

        let zeros = merkle_zeros(MERKLE_DEPTH);

        // Assert a whole fixture's public signals against reproduced values.
        let check = |case: &str,
                     ps: &[String],
                     root: Hash32,
                     pa: Hash32,
                     edh: Hash32,
                     nf0: Hash32,
                     nf1: Hash32,
                     out0: Hash32,
                     out1: Hash32| {
            assert_eq!(root, field::from_dec(&ps[0]), "{case} root");
            assert_eq!(pa, field::from_dec(&ps[1]), "{case} publicAmount");
            assert_eq!(edh, field::from_dec(&ps[2]), "{case} extDataHash");
            assert_eq!(nf0, field::from_dec(&ps[3]), "{case} inputNullifier[0]");
            assert_eq!(nf1, field::from_dec(&ps[4]), "{case} inputNullifier[1]");
            assert_eq!(out0, field::from_dec(&ps[5]), "{case} outputCommitment[0]");
            assert_eq!(out1, field::from_dec(&ps[6]), "{case} outputCommitment[1]");
        };

        // ---- SHIELD: 2 dummy inputs, +10, outputs [10, 0] on an empty tree ----
        {
            let ps = public_signals(SHIELD);
            let (d1_kp, d1) = dummy(
                "300000000000000000000000000000000004",
                "555000000000000000000000000000000001",
            );
            let (d2_kp, d2) = dummy(
                "300000000000000000000000000000000005",
                "555000000000000000000000000000000002",
            );
            check(
                "SHIELD",
                &ps,
                zeros[MERKLE_DEPTH], // empty-tree root; dummy inputs are unchecked
                public_amount(SignedAmount::Deposit(10)),
                ext_data_hash(&recipient(), &relayer(), 0, &payload(1), &payload(2)),
                note_nullifier(&d1_kp, &d1, 0),
                note_nullifier(&d2_kp, &d2, 0),
                Note::new(10, alice_pk, fe(11)).commitment(),
                Note::new(0, alice_pk, fe(12)).commitment(),
            );
        }

        // ---- TRANSFER: 2 real inputs (30, 20), 2 outputs (35, 15), pa 0 ----
        {
            let ps = public_signals(TRANSFER);
            let in0 = Note::new(30, alice_pk, fe(31));
            let in1 = Note::new(20, alice_pk, fe(32));
            // Leaves c0@0 and c1@1: recompute the root from c0's path (sibling c1
            // at level 0, then the zero ladder above).
            let mut path = vec![in1.commitment()];
            path.extend_from_slice(&zeros[1..MERKLE_DEPTH]);
            let root = merkle_root_from_path(&in0.commitment(), 0, &path);
            check(
                "TRANSFER",
                &ps,
                root,
                public_amount(SignedAmount::Transfer),
                ext_data_hash(&recipient(), &relayer(), 0, &payload(3), &payload(4)),
                note_nullifier(&alice, &in0, 0),
                note_nullifier(&alice, &in1, 1),
                Note::new(35, bob_pk, fe(41)).commitment(),
                Note::new(15, alice_pk, fe(42)).commitment(),
            );
        }

        // ---- UNSHIELD: 1 real input (20) + dummy, -7, outputs [13, 0] ----
        {
            let ps = public_signals(UNSHIELD);
            let real = Note::new(20, alice_pk, fe(51));
            // Single leaf at index 0: its siblings are the full zero ladder.
            let root = merkle_root_from_path(&real.commitment(), 0, &zeros[0..MERKLE_DEPTH]);
            let (d9_kp, d9) = dummy(
                "300000000000000000000000000000000012",
                "555000000000000000000000000000000009",
            );
            check(
                "UNSHIELD",
                &ps,
                root,
                public_amount(SignedAmount::Withdraw(7)),
                ext_data_hash(&recipient(), &relayer(), 0, &payload(5), &payload(6)),
                note_nullifier(&alice, &real, 0),
                note_nullifier(&d9_kp, &d9, 0),
                Note::new(13, alice_pk, fe(61)).commitment(),
                Note::new(0, alice_pk, fe(62)).commitment(),
            );
        }
    }

    #[test]
    fn public_amount_round_trips() {
        for v in [1u64, 7, 10, 250_000_000, u64::MAX] {
            assert_eq!(
                decode_public_amount(&public_amount(SignedAmount::Deposit(v))).unwrap(),
                SignedAmount::Deposit(v),
                "deposit {v} must round-trip"
            );
            assert_eq!(
                decode_public_amount(&public_amount(SignedAmount::Withdraw(v))).unwrap(),
                SignedAmount::Withdraw(v),
                "withdraw {v} must round-trip"
            );
        }
        assert_eq!(
            decode_public_amount(&public_amount(SignedAmount::Transfer)).unwrap(),
            SignedAmount::Transfer
        );
        // Deposit(0) encodes to the zero field element, which decodes as Transfer.
        assert_eq!(public_amount(SignedAmount::Deposit(0)), [0u8; 32]);
    }

    #[test]
    fn public_amount_rejects_out_of_range() {
        // 2^248 exactly (top byte 0x01): in neither disjoint range.
        let mut two_pow_248 = [0u8; 32];
        two_pow_248[0] = 0x01;
        assert!(matches!(
            decode_public_amount(&two_pow_248),
            Err(ValueNoteError::PublicAmountOutOfRange(_))
        ));

        // 2^250 (top byte 0x04): squarely in the forbidden middle band.
        let mut mid = [0u8; 32];
        mid[0] = 0x04;
        assert!(matches!(
            decode_public_amount(&mid),
            Err(ValueNoteError::PublicAmountOutOfRange(_))
        ));

        // 2^100: a valid deposit-range field element whose magnitude exceeds u64.
        let mut big = [0u8; 32];
        big[31 - 12] = 1 << 4; // bit 100 set (byte index 19 from the MSB)
        assert!(is_valid_amount_magnitude(&big), "2^100 < 2^248");
        assert!(matches!(
            decode_public_amount(&big),
            Err(ValueNoteError::MagnitudeExceedsU64)
        ));
    }

    #[test]
    fn note_primitives_compose_and_bind() {
        let kp = ValueKeypair::from_private_key(fe(12345));
        let note = Note::new(42, kp.public_key(), fe(999));
        // note_nullifier is exactly nullifier(commitment, i, signature(...)).
        let c = note.commitment();
        let sig = signature(&kp.private_key, &c, 3);
        assert_eq!(note_nullifier(&kp, &note, 3), nullifier(&c, 3, &sig));
        // Position-specific: a different leaf index yields a different nullifier.
        assert_ne!(note_nullifier(&kp, &note, 3), note_nullifier(&kp, &note, 4));
        // Dummy detection.
        assert!(Note::new(0, kp.public_key(), fe(1)).is_dummy());
        assert!(!note.is_dummy());
    }
}
