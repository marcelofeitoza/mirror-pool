//! Pool account: one anonymity set, one fixed action shape.
//!
//! A pool's parameters are written once at INIT_POOL and never change:
//! mutable parameters would let an operator quietly weaken the anonymity set
//! (for example lowering `k_floor` right before settling a targeted epoch).
//!
//! Layout (all integers little-endian):
//!
//! ```text
//! offset  size  field
//! 0       1     version           0 = uninitialized, 1 = v1
//! 1       8     epoch_slots       slots per epoch window
//! 9       4     k_floor           minimum participants before settle
//! 13      8     commitment_count  total leaves ever appended
//! 21      32    current_root      frontier accumulator root
//! 53      64    reserved          see TODO(v1) below
//! ```
//!
//! TODO(v1): widen the layout before first deploy with the frontier Merkle
//! accumulator state (technique: an append-only Poseidon frontier Merkle
//! accumulator, standard Tornado-Cash-style): `frontier[DEPTH]` sibling hashes
//! plus a ring buffer of recent roots (a root-history ring) so commits landing
//! while a settle is in flight still verify against a recent root. The reserved
//! tail is a placeholder, not the final size.
//!
//! TODO(v1): bind the pool's `ActionClass` here (store the canonical-bytes
//! hash of `mirror_core::ActionClass`) so settlement can verify the executed
//! action matches the pool's fixed shape.

use pinocchio::error::ProgramError;

use super::{read_bytes32, read_u32, read_u64, read_u8, write_bytes32, write_u32, write_u64, write_u8};

pub const VERSION_OFF: usize = 0;
pub const EPOCH_SLOTS_OFF: usize = 1;
pub const K_FLOOR_OFF: usize = 9;
pub const COMMITMENT_COUNT_OFF: usize = 13;
pub const CURRENT_ROOT_OFF: usize = 21;
pub const RESERVED_OFF: usize = 53;
pub const RESERVED_LEN: usize = 64;

/// Total account size. Will grow when the frontier state lands (see module
/// docs); it is a layout constant, never inferred from the account.
pub const LEN: usize = RESERVED_OFF + RESERVED_LEN;

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

/// Minimum participants before an epoch may settle
/// (`mirror_core::EpochSchedule::k_floor`).
pub fn k_floor(data: &[u8]) -> Result<u32, ProgramError> {
    read_u32(data, K_FLOOR_OFF)
}

/// Total commitments ever appended to this pool's accumulator.
pub fn commitment_count(data: &[u8]) -> Result<u64, ProgramError> {
    read_u64(data, COMMITMENT_COUNT_OFF)
}

/// Current root of the frontier accumulator (all zeroes until TODO(v1)).
pub fn current_root(data: &[u8]) -> Result<[u8; 32], ProgramError> {
    read_bytes32(data, CURRENT_ROOT_OFF)
}

/// One-time initialization. The caller (init_pool) is responsible for having
/// already rejected an initialized account; this only writes the layout.
pub fn init(data: &mut [u8], epoch_slots: u64, k_floor: u32) -> Result<(), ProgramError> {
    if data.len() != LEN {
        return Err(ProgramError::InvalidAccountData);
    }
    write_u8(data, VERSION_OFF, VERSION_V1)?;
    write_u64(data, EPOCH_SLOTS_OFF, epoch_slots)?;
    write_u32(data, K_FLOOR_OFF, k_floor)?;
    write_u64(data, COMMITMENT_COUNT_OFF, 0)?;
    write_bytes32(data, CURRENT_ROOT_OFF, &[0u8; 32])?;
    Ok(())
}

pub fn set_commitment_count(data: &mut [u8], count: u64) -> Result<(), ProgramError> {
    write_u64(data, COMMITMENT_COUNT_OFF, count)
}

pub fn set_current_root(data: &mut [u8], root: &[u8; 32]) -> Result<(), ProgramError> {
    write_bytes32(data, CURRENT_ROOT_OFF, root)
}
