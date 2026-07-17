//! Epoch account: per-window batching state.
//!
//! One account per (pool, epoch id). It tracks how many commitments landed in
//! the window and whether the window has settled. Nullifiers are NOT stored
//! here: replay protection is one PDA per nullifier (existence == spent), the
//! standard Solana anti-replay pattern (PDA existence marks a spent nullifier),
//! because a per-epoch bitmap would cap participation and a Vec would need
//! realloc on the hot path.
//!
//! Privacy note: `nominal_k` (the raw commit count) is an UPPER bound on the
//! real anonymity set. The honest number excludes operator-owned and Sybil
//! commitments (`mirror_core::KAnon::real_k`), which cannot be computed
//! on-chain. On-chain we enforce the necessary condition
//! `nominal_k >= k_floor` (if even the nominal count is below the floor, the
//! real set certainly is); the coordinator enforces the honest bound before
//! ever submitting a settle. `nominal_k` is exactly the epoch's commit count.
//!
//! Layout (all integers little-endian):
//!
//! ```text
//! offset  size  field
//! 0       1     version    0 = uninitialized, 1 = v1
//! 1       8     epoch_id   mirror_core::Epoch
//! 9       4     nominal_k  commitments in this window (the commit count)
//! 13      1     settled    0 = open or rolled forward, 1 = settled
//! 14      1     bump       Epoch PDA bump (seeds [b"epoch", pool, epoch_id LE])
//! 15      17    reserved   TODO(v2): action batch binding, root snapshot
//! ```

use pinocchio::error::ProgramError;

use super::{read_u32, read_u64, read_u8, write_u32, write_u64, write_u8};
use crate::MirrorPoolError;

pub const VERSION_OFF: usize = 0;
pub const EPOCH_ID_OFF: usize = 1;
pub const NOMINAL_K_OFF: usize = 9;
pub const SETTLED_OFF: usize = 13;
pub const BUMP_OFF: usize = 14;
pub const RESERVED_OFF: usize = 15;
pub const RESERVED_LEN: usize = 17;

pub const LEN: usize = RESERVED_OFF + RESERVED_LEN;

pub const VERSION_UNINITIALIZED: u8 = 0;
pub const VERSION_V1: u8 = 1;

pub fn version(data: &[u8]) -> Result<u8, ProgramError> {
    read_u8(data, VERSION_OFF)
}

pub fn is_initialized(data: &[u8]) -> Result<bool, ProgramError> {
    Ok(version(data)? != VERSION_UNINITIALIZED)
}

pub fn epoch_id(data: &[u8]) -> Result<u64, ProgramError> {
    read_u64(data, EPOCH_ID_OFF)
}

/// Raw commit count for this window; an upper bound on real k (module docs).
pub fn nominal_k(data: &[u8]) -> Result<u32, ProgramError> {
    read_u32(data, NOMINAL_K_OFF)
}

/// Alias for [`nominal_k`]: the number of commitments accepted this epoch.
pub fn commit_count(data: &[u8]) -> Result<u32, ProgramError> {
    nominal_k(data)
}

pub fn is_settled(data: &[u8]) -> Result<bool, ProgramError> {
    Ok(read_u8(data, SETTLED_OFF)? != 0)
}

pub fn bump(data: &[u8]) -> Result<u8, ProgramError> {
    read_u8(data, BUMP_OFF)
}

/// One-time initialization for a freshly created epoch account.
pub fn init(data: &mut [u8], epoch_id: u64, bump: u8) -> Result<(), ProgramError> {
    if data.len() != LEN {
        return Err(ProgramError::InvalidAccountData);
    }
    write_u8(data, VERSION_OFF, VERSION_V1)?;
    write_u64(data, EPOCH_ID_OFF, epoch_id)?;
    write_u32(data, NOMINAL_K_OFF, 0)?;
    write_u8(data, SETTLED_OFF, 0)?;
    write_u8(data, BUMP_OFF, bump)?;
    Ok(())
}

/// Increment the commit count by one, failing closed on overflow.
pub fn increment_commit_count(data: &mut [u8]) -> Result<u32, ProgramError> {
    let next = nominal_k(data)?
        .checked_add(1)
        .ok_or(MirrorPoolError::ArithmeticOverflow)?;
    write_u32(data, NOMINAL_K_OFF, next)?;
    Ok(next)
}

pub fn set_nominal_k(data: &mut [u8], k: u32) -> Result<(), ProgramError> {
    write_u32(data, NOMINAL_K_OFF, k)
}

pub fn set_settled(data: &mut [u8]) -> Result<(), ProgramError> {
    write_u8(data, SETTLED_OFF, 1)
}
