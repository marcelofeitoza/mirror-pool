//! Append-only frontier Merkle accumulator (Tornado-Cash-style commitment
//! tree, the shape Zcash Sapling also uses).
//!
//! A frontier tree stores only the right-edge path (`filled_subtrees`, one
//! sibling hash per level) plus the running root, so an append is O(DEPTH) in
//! both compute and account bytes and the full tree is never materialized
//! on-chain. Leaves are the opaque 32-byte commitments posted by COMMIT.
//!
//! Hashing uses keccak-256 via the Solana syscall (`hash_pair(l, r) =
//! keccak256(l ‖ r)`), which is cheap on-chain. v2 swaps this for Poseidon so
//! the tree hashing matches the Groth16 membership circuit; the frontier shape
//! is unchanged by that swap.
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

/// keccak-256 of the concatenation of the two 32-byte children.
#[cfg(any(target_os = "solana", target_arch = "bpf"))]
#[inline(always)]
fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    // `sol_keccak256(vals, val_len, out)` reads `val_len` byte-slices starting
    // at `vals` (each an { addr, len } pair) and writes 32 bytes to `out`.
    let chunks: [&[u8]; 2] = [left, right];
    let mut out = [0u8; 32];
    unsafe {
        pinocchio::syscalls::sol_keccak256(
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
    unreachable!("keccak hashing uses an on-chain syscall and never runs on the host")
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

/// Append `leaf` to the accumulator stored inline in `pool_data`.
///
/// Updates `filled_subtrees`, `current_root`, and `commitment_count` in place
/// and returns the new root. The standard Tornado insert: walk from the leaf to
/// the root, and at each level use the stored left sibling (odd index) or the
/// running zero hash (even index), recording the new left sibling on the way up.
/// `filled_subtrees[i]` is always written (even index at level `i`) before it is
/// ever read (odd index at level `i`), so the frontier needs no pre-seeding.
pub fn append(pool_data: &mut [u8], leaf: &[u8; 32]) -> Result<[u8; 32], ProgramError> {
    let index = pool::commitment_count(pool_data)?;
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
            pool::set_filled_subtree(pool_data, level, &current_hash)?;
            (current_hash, current_zero)
        } else {
            // Right child: pair with the previously recorded left sibling.
            let left = pool::filled_subtree(pool_data, level)?;
            (left, current_hash)
        };
        current_hash = hash_pair(&left, &right);
        current_zero = hash_pair(&current_zero, &current_zero);
        current_index >>= 1;
    }

    pool::set_current_root(pool_data, &current_hash)?;
    let next = index
        .checked_add(1)
        .ok_or(MirrorPoolError::ArithmeticOverflow)?;
    pool::set_commitment_count(pool_data, next)?;
    Ok(current_hash)
}
