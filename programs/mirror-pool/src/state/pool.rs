//! Pool account: one anonymity set, one fixed action shape.
//!
//! A pool's parameters are written once at INIT_POOL and never change:
//! mutable parameters would let an operator quietly weaken the anonymity set
//! (for example lowering `k_floor` right before settling a targeted epoch).
//!
//! Layout (all integers little-endian):
//!
//! ```text
//! offset  size       field
//! 0       1          version           0 = uninitialized, 1 = v1
//! 1       8          epoch_slots        slots per epoch window
//! 9       4          k_floor            minimum commits before an epoch settles
//! 13      8          commitment_count   total leaves ever appended (= next index)
//! 21      32         current_root       frontier accumulator root
//! 53      32         authority          relay pubkey allowed to SETTLE_EPOCH
//! 85      8          entry_fee          per-commit anti-Sybil deposit (lamports)
//! 93      1          bump               Pool PDA bump (seeds [b"pool", authority])
//! 94      DEPTH*32   filled_subtrees    frontier right-edge sibling hashes
//! ```
//!
//! `DEPTH` (and the hashing) live in [`crate::state::merkle`]. The frontier is
//! stored inline so an append never touches a second account.
//!
//! The pool binds a fixed `ActionClass` off-chain via each participant's
//! commitment (`mirror_core::commit` mixes the action into the leaf); v2 stores
//! the class hash here and verifies the executed action against it at settle.

use pinocchio::error::ProgramError;

use super::merkle::DEPTH;
use super::{
    read_bytes32, read_u32, read_u64, read_u8, write_bytes32, write_u32, write_u64, write_u8,
};

pub const VERSION_OFF: usize = 0;
pub const EPOCH_SLOTS_OFF: usize = 1;
pub const K_FLOOR_OFF: usize = 9;
pub const COMMITMENT_COUNT_OFF: usize = 13;
pub const CURRENT_ROOT_OFF: usize = 21;
pub const AUTHORITY_OFF: usize = 53;
pub const ENTRY_FEE_OFF: usize = 85;
pub const BUMP_OFF: usize = 93;
pub const FRONTIER_OFF: usize = 94;

/// Bytes of frontier state (one 32-byte sibling per level).
pub const FRONTIER_LEN: usize = DEPTH * 32;

/// Total account size. A layout constant, never inferred from the account.
pub const LEN: usize = FRONTIER_OFF + FRONTIER_LEN;

pub const VERSION_UNINITIALIZED: u8 = 0;
pub const VERSION_V1: u8 = 1;

pub fn version(data: &[u8]) -> Result<u8, ProgramError> {
    read_u8(data, VERSION_OFF)
}

pub fn is_initialized(data: &[u8]) -> Result<bool, ProgramError> {
    Ok(version(data)? != VERSION_UNINITIALIZED)
}

/// Slots per epoch window (`mirror_core::EpochSchedule::epoch_slots`).
pub fn epoch_slots(data: &[u8]) -> Result<u64, ProgramError> {
    read_u64(data, EPOCH_SLOTS_OFF)
}

/// Minimum commits before an epoch may settle
/// (`mirror_core::EpochSchedule::k_floor`).
pub fn k_floor(data: &[u8]) -> Result<u32, ProgramError> {
    read_u32(data, K_FLOOR_OFF)
}

/// Total commitments ever appended to this pool's accumulator (= next leaf
/// index into the frontier tree).
pub fn commitment_count(data: &[u8]) -> Result<u64, ProgramError> {
    read_u64(data, COMMITMENT_COUNT_OFF)
}

/// Current root of the frontier accumulator.
pub fn current_root(data: &[u8]) -> Result<[u8; 32], ProgramError> {
    read_bytes32(data, CURRENT_ROOT_OFF)
}

/// Settlement authority (the relay allowed to submit SETTLE_EPOCH).
pub fn authority(data: &[u8]) -> Result<[u8; 32], ProgramError> {
    read_bytes32(data, AUTHORITY_OFF)
}

/// Per-commit anti-Sybil entry fee in lamports (0 disables it).
pub fn entry_fee(data: &[u8]) -> Result<u64, ProgramError> {
    read_u64(data, ENTRY_FEE_OFF)
}

/// Stored Pool PDA bump.
pub fn bump(data: &[u8]) -> Result<u8, ProgramError> {
    read_u8(data, BUMP_OFF)
}

/// One frontier sibling hash at `level` (0 = leaf level).
pub fn filled_subtree(data: &[u8], level: usize) -> Result<[u8; 32], ProgramError> {
    if level >= DEPTH {
        return Err(ProgramError::InvalidAccountData);
    }
    read_bytes32(data, FRONTIER_OFF + level * 32)
}

pub fn set_filled_subtree(
    data: &mut [u8],
    level: usize,
    value: &[u8; 32],
) -> Result<(), ProgramError> {
    if level >= DEPTH {
        return Err(ProgramError::InvalidAccountData);
    }
    write_bytes32(data, FRONTIER_OFF + level * 32, value)
}

/// One-time initialization. The caller (init_pool) is responsible for having
/// already rejected an initialized account; this only writes the layout. The
/// frontier bytes are left zeroed (a freshly created account is zero-filled and
/// each sibling is written before it is read); only the empty-tree root is set.
#[allow(clippy::too_many_arguments)]
pub fn init(
    data: &mut [u8],
    epoch_slots: u64,
    k_floor: u32,
    entry_fee: u64,
    authority: &[u8; 32],
    bump: u8,
    empty_root: &[u8; 32],
) -> Result<(), ProgramError> {
    if data.len() != LEN {
        return Err(ProgramError::InvalidAccountData);
    }
    write_u8(data, VERSION_OFF, VERSION_V1)?;
    write_u64(data, EPOCH_SLOTS_OFF, epoch_slots)?;
    write_u32(data, K_FLOOR_OFF, k_floor)?;
    write_u64(data, COMMITMENT_COUNT_OFF, 0)?;
    write_bytes32(data, CURRENT_ROOT_OFF, empty_root)?;
    write_bytes32(data, AUTHORITY_OFF, authority)?;
    write_u64(data, ENTRY_FEE_OFF, entry_fee)?;
    write_u8(data, BUMP_OFF, bump)?;
    Ok(())
}

pub fn set_commitment_count(data: &mut [u8], count: u64) -> Result<(), ProgramError> {
    write_u64(data, COMMITMENT_COUNT_OFF, count)
}

pub fn set_current_root(data: &mut [u8], root: &[u8; 32]) -> Result<(), ProgramError> {
    write_bytes32(data, CURRENT_ROOT_OFF, root)
}
