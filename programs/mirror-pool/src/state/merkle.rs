//! Append-only frontier Merkle accumulator (Tornado-Cash-style commitment
//! tree, the shape Zcash Sapling also uses).
//!
//! A frontier tree stores only the right-edge path (`filled_subtrees`, one
//! sibling hash per level) plus the running root, so an append is O(DEPTH) in
//! both compute and account bytes and the full tree is never materialized
//! on-chain.
//!
//! Leaves come from two instructions and live in two DISJOINT hash domains:
//! `COMMIT_DEPOSIT` appends its 32-byte commitment verbatim (the ZK domain, the
//! shape the membership and association circuits recompute), while `COMMIT`
//! appends [`crowd_leaf`] of the value it was handed. See that function for why
//! the separation is a fund-safety property and why it has to be applied to the
//! FREE path, by the program.
//!
//! Hashing uses circomlib Poseidon over BN254 via the Solana `sol_poseidon`
//! syscall (`hash_pair(l, r) = Poseidon(l, r)`), the exact node hash the
//! Groth16 membership circuit (`circuits/membership.circom`) and the off-chain
//! `mirror_core::merkle_node` use, so a proof made for the circuit verifies
//! against a root this accumulator produces. Nodes are 32-byte canonical
//! big-endian field elements; the frontier shape is independent of the hash.
//!
//! The frontier bytes live inline in the Pool account (see `state::pool`); this
//! module operates on that byte slice through the offsets pool exposes.

use pinocchio::error::ProgramError;

use crate::state::pool;
use crate::MirrorPoolError;

/// Tree height. 2^20 ≈ 1.05M leaves per pool, plenty for v1 anonymity sets.
pub const DEPTH: usize = 20;

/// The empty-leaf value. A subtree of all `ZERO_LEAF`s hashes up to
/// `empty_root()`.
pub const ZERO_LEAF: [u8; 32] = [0u8; 32];

/// circomlib Poseidon of the two 32-byte children: `Poseidon(left, right)`.
///
/// `left` and `right` must be canonical big-endian BN254 field elements (each
/// < r). Every value this module hashes satisfies that: `ZERO_LEAF` is 0, every
/// node is a canonical Poseidon output, and commitment leaves are produced by
/// `mirror_core::commit` (also canonical). Using the same syscall parameters
/// the `solana-poseidon` crate uses keeps this byte-identical to the circuit
/// and to `mirror_core::merkle_node` on the host.
#[cfg(any(target_os = "solana", target_arch = "bpf"))]
#[inline(always)]
fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    // `sol_poseidon(parameters, endianness, vals, val_len, out)` reads
    // `val_len` byte-slices starting at `vals` (each an { addr, len } pair) and
    // writes the 32-byte hash to `out`.
    //   parameters = 0 -> Parameters::Bn254X5 (circomlib BN254, width t=3)
    //   endianness = 0 -> Endianness::BigEndian (matches circom / groth16-solana
    //                     public-input byte order and mirror_core's encoding)
    const BN254X5: u64 = 0;
    const BIG_ENDIAN: u64 = 0;
    let chunks: [&[u8]; 2] = [left, right];
    let mut out = [0u8; 32];
    unsafe {
        pinocchio::syscalls::sol_poseidon(
            BN254X5,
            BIG_ENDIAN,
            chunks.as_ptr() as *const u8,
            chunks.len() as u64,
            out.as_mut_ptr(),
        );
    }
    out
}

#[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
#[inline(always)]
fn hash_pair(_left: &[u8; 32], _right: &[u8; 32]) -> [u8; 32] {
    unreachable!("Poseidon hashing uses an on-chain syscall and never runs on the host")
}

/// Domain tag absorbed into every CROWD `COMMIT` leaf, and into nothing else.
///
/// `SHA-256("mirror-pool/leaf-domain/crowd/v1")` reduced into the BN254 scalar
/// field, canonical big-endian. MIRRORED from `mirror_core::CROWD_LEAF_DOMAIN`
/// (a Solana program must not depend on that std host crate); the host side's
/// `crowd_leaf_domain_matches_its_derivation` test recomputes it from the domain
/// string, and `crowd_leaf_matches_the_host_mirror` in `tests/integration.rs`
/// asserts the two sides agree on real leaves through the compiled program.
pub const CROWD_LEAF_DOMAIN: [u8; 32] = [
    0x2e, 0x2a, 0x23, 0x5e, 0xaf, 0xc3, 0x3e, 0xf6, 0x4e, 0xfb, 0x63, 0xe2, 0xb1, 0x81, 0xc5, 0xdb,
    0x9b, 0x5e, 0xbc, 0x4c, 0xbc, 0x2c, 0x26, 0xff, 0xa8, 0xe7, 0x21, 0xcb, 0x79, 0xf7, 0xec, 0x09,
];

/// The leaf a crowd `COMMIT` appends: `Poseidon(CROWD_LEAF_DOMAIN, commitment)`.
///
/// The crowd path accepts an opaque 32-byte `commitment` from anybody for the
/// price of the entry fee, while the ZK opt-in path escrows lamports for a leaf
/// of the shape `Poseidon(secret, actionHash, epoch)` that the membership and
/// association circuits recompute. Appending the crowd value verbatim would
/// therefore let a fee-only commit put a spendable ZK leaf into the accumulator
/// and settle it against somebody else's escrow. Wrapping it here fixes that
/// with one syscall:
///
///  - the crowd leaf is a WIDTH-2 Poseidon with a fixed first input and a ZK
///    deposit leaf is a WIDTH-3 Poseidon, so no crowd leaf is a deposit leaf
///    short of a Poseidon collision; and
///  - the wrap happens ON-CHAIN over whatever the caller sent, so pre-hashing a
///    tag client-side does not get a caller into the ZK domain either. That is
///    the load-bearing half: a tag absorbed only into the DEPOSIT preimage would
///    be forgeable, since the deposit leaf is caller-supplied bytes and the
///    caller could post the tagged value for free through `COMMIT`.
pub fn crowd_leaf(commitment: &[u8; 32]) -> [u8; 32] {
    hash_pair(&CROWD_LEAF_DOMAIN, commitment)
}

/// Root of a completely empty tree: `zeros(DEPTH)` where `zeros(0) = ZERO_LEAF`
/// and `zeros(i) = hash_pair(zeros(i-1), zeros(i-1))`.
pub fn empty_root() -> [u8; 32] {
    let mut z = ZERO_LEAF;
    for _ in 0..DEPTH {
        z = hash_pair(&z, &z);
    }
    z
}

/// A frontier accumulator stored inline in an account: the six offset-based
/// operations [`append_with`] needs. Implemented once per account layout so the
/// Tornado frontier math is shared, not duplicated. The behavioral [`pool`]
/// implements it here; the confidential [`crate::state::value_pool`] implements
/// it for its own byte layout, so both accumulators reuse this exact insert.
pub trait FrontierStore {
    /// Total leaves ever appended (= next leaf index).
    fn commitment_count(data: &[u8]) -> Result<u64, ProgramError>;
    /// Record the new leaf count.
    fn set_commitment_count(data: &mut [u8], count: u64) -> Result<(), ProgramError>;
    /// The stored left-sibling hash at `level` (0 = leaf level).
    fn filled_subtree(data: &[u8], level: usize) -> Result<[u8; 32], ProgramError>;
    /// Store a left-sibling hash at `level`.
    fn set_filled_subtree(
        data: &mut [u8],
        level: usize,
        value: &[u8; 32],
    ) -> Result<(), ProgramError>;
    /// Record the latest root.
    fn set_current_root(data: &mut [u8], root: &[u8; 32]) -> Result<(), ProgramError>;
    /// Push the latest root into the recent-root ring buffer.
    fn record_root_history(data: &mut [u8], root: &[u8; 32]) -> Result<(), ProgramError>;
}

/// The behavioral [`pool`] frontier (delegates to the `pool` accessors).
pub struct PoolFrontier;

impl FrontierStore for PoolFrontier {
    fn commitment_count(data: &[u8]) -> Result<u64, ProgramError> {
        pool::commitment_count(data)
    }
    fn set_commitment_count(data: &mut [u8], count: u64) -> Result<(), ProgramError> {
        pool::set_commitment_count(data, count)
    }
    fn filled_subtree(data: &[u8], level: usize) -> Result<[u8; 32], ProgramError> {
        pool::filled_subtree(data, level)
    }
    fn set_filled_subtree(
        data: &mut [u8],
        level: usize,
        value: &[u8; 32],
    ) -> Result<(), ProgramError> {
        pool::set_filled_subtree(data, level, value)
    }
    fn set_current_root(data: &mut [u8], root: &[u8; 32]) -> Result<(), ProgramError> {
        pool::set_current_root(data, root)
    }
    fn record_root_history(data: &mut [u8], root: &[u8; 32]) -> Result<(), ProgramError> {
        pool::record_root_history(data, root)
    }
}

/// Append `leaf` to the frontier accumulator `S` stored inline in `data`.
///
/// Updates `filled_subtrees`, `current_root`, and `commitment_count` in place
/// and returns the new root. The standard Tornado insert: walk from the leaf to
/// the root, and at each level use the stored left sibling (odd index) or the
/// running zero hash (even index), recording the new left sibling on the way up.
/// `filled_subtrees[i]` is always written (even index at level `i`) before it is
/// ever read (odd index at level `i`), so the frontier needs no pre-seeding.
pub fn append_with<S: FrontierStore>(
    data: &mut [u8],
    leaf: &[u8; 32],
) -> Result<[u8; 32], ProgramError> {
    let index = S::commitment_count(data)?;
    if index >= (1u64 << DEPTH) {
        return Err(MirrorPoolError::TreeFull.into());
    }

    let mut current_index = index;
    let mut current_hash = *leaf;
    // zeros(level), advanced one level per iteration.
    let mut current_zero = ZERO_LEAF;

    for level in 0..DEPTH {
        let (left, right) = if current_index & 1 == 0 {
            // This node is a left child: right sibling is the empty subtree, and
            // this node becomes the recorded left sibling for its level.
            S::set_filled_subtree(data, level, &current_hash)?;
            (current_hash, current_zero)
        } else {
            // Right child: pair with the previously recorded left sibling.
            let left = S::filled_subtree(data, level)?;
            (left, current_hash)
        };
        current_hash = hash_pair(&left, &right);
        current_zero = hash_pair(&current_zero, &current_zero);
        current_index >>= 1;
    }

    S::set_current_root(data, &current_hash)?;
    // Record the new root in the recent-root ring so a settle can verify a proof
    // made against this snapshot even after later appends move the frontier.
    S::record_root_history(data, &current_hash)?;
    let next = index
        .checked_add(1)
        .ok_or(MirrorPoolError::ArithmeticOverflow)?;
    S::set_commitment_count(data, next)?;
    Ok(current_hash)
}

/// Append `leaf` to the behavioral [`pool`] accumulator stored inline in
/// `pool_data`. Thin wrapper over [`append_with`] pinned to [`PoolFrontier`], so
/// the crowd `COMMIT` / `COMMIT_DEPOSIT` callers are unchanged.
pub fn append(pool_data: &mut [u8], leaf: &[u8; 32]) -> Result<[u8; 32], ProgramError> {
    append_with::<PoolFrontier>(pool_data, leaf)
}
