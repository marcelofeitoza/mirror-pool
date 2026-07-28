//! AssociationSet account: one curator's published, curated set of pool
//! commitments, tracked as a small history of recent Merkle roots.
//!
//! This is the on-chain half of the OPT-IN compliance primitive (Privacy Pools
//! association sets). A curator maintains, off-chain, a list of pool commitments
//! it is willing to vouch for; it publishes the Merkle root of that list here.
//! A user can then prove, in zero knowledge, that their deposit is in the pool
//! AND in that curated list, without revealing which deposit it is
//! (`circuits/association.circom`, settled by `SETTLE_ZK_ASSOCIATED`).
//!
//! WHAT THIS ACCOUNT IS NOT. It is not an allowlist the program consults before
//! letting anyone act. The plain `SETTLE_ZK` path never reads this account and is
//! completely unaffected by it, so a curator cannot stop anybody from using the
//! pool. All a curator controls is whether a given settlement can carry ITS
//! attestation. See `docs/COMPLIANCE.md` for the full trust and censorship
//! analysis, including what a user excluded by a curator can still do.
//!
//! Layout (all integers little-endian):
//!
//! ```text
//! offset  size            field
//! 0       1               version           0 = uninitialized, 1 = v1
//! 1       32              pool              the Pool this set curates
//! 33      32              curator           the only signer allowed to update the root
//! 65      1               bump              AssociationSet PDA bump
//! 66      8               update_count      total roots ever published (monotonic)
//! 74      4               root_head         ring index of the NEXT root write
//! 78      RING_SIZE*32    root_ring         recent published roots
//! ```
//!
//! WHY A ROOT HISTORY. A curator republishes its root whenever the curated set
//! changes. A user builds a proof against whatever root was current when they
//! fetched the set, and settlement lands some slots later. Without a history, an
//! unrelated curator update between those two moments would invalidate an honest,
//! already-generated proof - a pure liveness race with no security benefit. The
//! ring accepts any of the last [`ROOT_HISTORY_SIZE`] published roots, which is
//! the same reasoning (and the same shape) as the Pool's own recent-root ring.
//!
//! THE COST OF THE HISTORY, stated plainly. Accepting a recent root means a
//! commitment the curator has just REMOVED can still settle with an attestation
//! for up to `ROOT_HISTORY_SIZE` further updates. That window is deliberate: the
//! alternative is breaking honest users on every curator edit. A curator that
//! needs a removal to take effect immediately can force the old roots out by
//! publishing `ROOT_HISTORY_SIZE` updates, which is an explicit, publicly visible
//! act rather than a silent one.

use pinocchio::error::ProgramError;

use super::{
    read_bytes32, read_u32, read_u64, read_u8, write_bytes32, write_u32, write_u64, write_u8,
};
use crate::MirrorPoolError;

pub const VERSION_OFF: usize = 0;
pub const POOL_OFF: usize = 1;
pub const CURATOR_OFF: usize = 33;
pub const BUMP_OFF: usize = 65;
pub const UPDATE_COUNT_OFF: usize = 66;
pub const ROOT_HEAD_OFF: usize = 74;
pub const ROOT_RING_OFF: usize = ROOT_HEAD_OFF + 4;

/// Number of recent published roots kept for [`is_known_root`].
///
/// Smaller than the Pool's 32-slot ring on purpose: pool roots move on every
/// single commit, whereas a curated set is republished rarely (a curator batches
/// its edits). Eight updates of slack is generous for the proof-generation race
/// this exists to absorb, and every extra slot widens the window in which a
/// just-removed commitment can still settle with an attestation.
pub const ROOT_HISTORY_SIZE: usize = 8;

/// Bytes of ring-buffer state (one 32-byte root per slot).
pub const ROOT_RING_LEN: usize = ROOT_HISTORY_SIZE * 32;

/// Total account size. A layout constant, never inferred from the account.
pub const LEN: usize = ROOT_RING_OFF + ROOT_RING_LEN;

pub const VERSION_UNINITIALIZED: u8 = 0;
pub const VERSION_V1: u8 = 1;

/// The sentinel written into every ring slot at init: all-zero bytes.
///
/// Zero is not a reachable Merkle root here (it is the empty-LEAF value, and a
/// root is always a Poseidon output), so a slot still holding the sentinel can
/// never be matched by an honest proof. [`is_known_root`] rejects it explicitly
/// anyway rather than relying on that argument, so a freshly created set with no
/// published root accepts NOTHING - fail closed.
pub const EMPTY_SLOT: [u8; 32] = [0u8; 32];

pub fn version(data: &[u8]) -> Result<u8, ProgramError> {
    read_u8(data, VERSION_OFF)
}

pub fn is_initialized(data: &[u8]) -> Result<bool, ProgramError> {
    Ok(version(data)? != VERSION_UNINITIALIZED)
}

/// The Pool whose commitments this set curates.
pub fn pool(data: &[u8]) -> Result<[u8; 32], ProgramError> {
    read_bytes32(data, POOL_OFF)
}

/// The only signer allowed to publish a new root.
pub fn curator(data: &[u8]) -> Result<[u8; 32], ProgramError> {
    read_bytes32(data, CURATOR_OFF)
}

/// Stored AssociationSet PDA bump.
pub fn bump(data: &[u8]) -> Result<u8, ProgramError> {
    read_u8(data, BUMP_OFF)
}

/// Total roots ever published by this curator (monotonic; never reset).
pub fn update_count(data: &[u8]) -> Result<u64, ProgramError> {
    read_u64(data, UPDATE_COUNT_OFF)
}

/// Ring index of the next root write.
pub fn root_head(data: &[u8]) -> Result<u32, ProgramError> {
    read_u32(data, ROOT_HEAD_OFF)
}

/// One recent root at ring slot `i` (`i < ROOT_HISTORY_SIZE`).
pub fn root_history_entry(data: &[u8], i: usize) -> Result<[u8; 32], ProgramError> {
    if i >= ROOT_HISTORY_SIZE {
        return Err(ProgramError::InvalidAccountData);
    }
    read_bytes32(data, ROOT_RING_OFF + i * 32)
}

/// One-time initialization. The caller is responsible for having already
/// rejected an initialized account; this only writes the layout.
///
/// Every ring slot starts at [`EMPTY_SLOT`], so a set with no published root
/// accepts no proof at all.
pub fn init(
    data: &mut [u8],
    pool: &[u8; 32],
    curator: &[u8; 32],
    bump: u8,
) -> Result<(), ProgramError> {
    if data.len() != LEN {
        return Err(ProgramError::InvalidAccountData);
    }
    write_u8(data, VERSION_OFF, VERSION_V1)?;
    write_bytes32(data, POOL_OFF, pool)?;
    write_bytes32(data, CURATOR_OFF, curator)?;
    write_u8(data, BUMP_OFF, bump)?;
    write_u64(data, UPDATE_COUNT_OFF, 0)?;
    write_u32(data, ROOT_HEAD_OFF, 0)?;
    for slot in 0..ROOT_HISTORY_SIZE {
        write_bytes32(data, ROOT_RING_OFF + slot * 32, &EMPTY_SLOT)?;
    }
    Ok(())
}

/// Publish `root` as the newest curated-set root: write it at the head slot,
/// advance the head (wrapping), and bump the monotonic update counter.
///
/// Fails closed on counter overflow rather than wrapping, and refuses the
/// all-zero sentinel so a curator cannot publish a root that would collide with
/// an unwritten slot.
pub fn publish_root(data: &mut [u8], root: &[u8; 32]) -> Result<(), ProgramError> {
    if root == &EMPTY_SLOT {
        return Err(MirrorPoolError::MalformedInstruction.into());
    }
    let head = read_u32(data, ROOT_HEAD_OFF)? as usize;
    if head >= ROOT_HISTORY_SIZE {
        return Err(ProgramError::InvalidAccountData);
    }
    write_bytes32(data, ROOT_RING_OFF + head * 32, root)?;
    let next = ((head + 1) % ROOT_HISTORY_SIZE) as u32;
    write_u32(data, ROOT_HEAD_OFF, next)?;
    let count = update_count(data)?
        .checked_add(1)
        .ok_or(MirrorPoolError::ArithmeticOverflow)?;
    write_u64(data, UPDATE_COUNT_OFF, count)?;
    Ok(())
}

/// Whether `root` is one of the last [`ROOT_HISTORY_SIZE`] published roots.
///
/// The all-zero sentinel is rejected up front, so an association set that has
/// never published a root matches nothing.
pub fn is_known_root(data: &[u8], root: &[u8; 32]) -> Result<bool, ProgramError> {
    if root == &EMPTY_SLOT {
        return Ok(false);
    }
    for i in 0..ROOT_HISTORY_SIZE {
        if &root_history_entry(data, i)? == root {
            return Ok(true);
        }
    }
    Ok(false)
}
