//! Dwell account: per-participant crowd-path participation counter.
//!
//! One PDA per (pool, participant) at seeds `[b"dwell", pool, participant]`. It
//! records how many DISTINCT epochs the participant has committed into ("dwell"),
//! and how much of that dwell has already been converted to a reward. Only the
//! CROWD path uses it: the committing wallet is already an on-chain signer there,
//! so a per-identity counter leaks nothing new. The ZK opt-in path is anonymous
//! and never touches a Dwell PDA (an anonymity-preserving ZK dwell claim is
//! documented, not implemented; see `docs/INCENTIVES.md`).
//!
//! Dwell is what `CLAIM_REWARD` pays against, so it MUST advance only through a
//! real, fee-paying `COMMIT`: a standalone "bump my dwell" call would let an
//! attacker mint dwell for free and drain the reward pool. Coupling the increment
//! to `COMMIT` (and capping it at once per epoch) keeps the incentive aligned
//! with the anti-Sybil entry cost.
//!
//! Layout (all integers little-endian):
//!
//! ```text
//! offset  size  field
//! 0       1     version       0 = uninitialized, 1 = v1
//! 1       8     dwell         distinct epochs committed into
//! 9       8     claimed_dwell dwell already converted to a reward
//! 17      8     last_epoch    most recent epoch counted (NEVER = u64::MAX until first)
//! 25      1     bump          Dwell PDA bump (seeds [b"dwell", pool, participant])
//! ```

use pinocchio::error::ProgramError;

use super::{read_u64, read_u8, write_u64, write_u8};
use crate::MirrorPoolError;

pub const VERSION_OFF: usize = 0;
pub const DWELL_OFF: usize = 1;
pub const CLAIMED_DWELL_OFF: usize = 9;
pub const LAST_EPOCH_OFF: usize = 17;
pub const BUMP_OFF: usize = 25;

pub const LEN: usize = BUMP_OFF + 1;

pub const VERSION_UNINITIALIZED: u8 = 0;
pub const VERSION_V1: u8 = 1;

/// Sentinel for `last_epoch` meaning "no epoch counted yet". Epoch 0 is a real,
/// countable epoch, so a distinct sentinel is required rather than 0.
pub const LAST_EPOCH_NEVER: u64 = u64::MAX;

pub fn version(data: &[u8]) -> Result<u8, ProgramError> {
    read_u8(data, VERSION_OFF)
}

pub fn is_initialized(data: &[u8]) -> Result<bool, ProgramError> {
    Ok(version(data)? != VERSION_UNINITIALIZED)
}

/// Distinct epochs this participant has committed into.
pub fn dwell(data: &[u8]) -> Result<u64, ProgramError> {
    read_u64(data, DWELL_OFF)
}

/// Dwell already converted to a reward (claimed).
pub fn claimed_dwell(data: &[u8]) -> Result<u64, ProgramError> {
    read_u64(data, CLAIMED_DWELL_OFF)
}

/// Most recent epoch counted into `dwell` ([`LAST_EPOCH_NEVER`] before the first).
pub fn last_epoch(data: &[u8]) -> Result<u64, ProgramError> {
    read_u64(data, LAST_EPOCH_OFF)
}

pub fn bump(data: &[u8]) -> Result<u8, ProgramError> {
    read_u8(data, BUMP_OFF)
}

/// One-time initialization for a freshly created dwell account.
pub fn init(data: &mut [u8], bump: u8) -> Result<(), ProgramError> {
    if data.len() != LEN {
        return Err(ProgramError::InvalidAccountData);
    }
    write_u8(data, VERSION_OFF, VERSION_V1)?;
    write_u64(data, DWELL_OFF, 0)?;
    write_u64(data, CLAIMED_DWELL_OFF, 0)?;
    write_u64(data, LAST_EPOCH_OFF, LAST_EPOCH_NEVER)?;
    write_u8(data, BUMP_OFF, bump)?;
    Ok(())
}

/// Count `current_epoch` toward this participant's dwell, at most once per epoch.
///
/// Dwell advances only when `current_epoch` is strictly newer than the last
/// counted epoch (or none has been counted yet). This makes a second commit in
/// the same window a no-op, and a stale-clock replay of an already-counted epoch
/// a no-op too, so dwell is exactly "distinct epochs committed into". Returns
/// `true` when it advanced (the caller then bumps the pool-level unclaimed-dwell
/// denominator), `false` when it was already counted. Fails closed on overflow.
pub fn record_epoch(data: &mut [u8], current_epoch: u64) -> Result<bool, ProgramError> {
    let last = last_epoch(data)?;
    let advance = last == LAST_EPOCH_NEVER || current_epoch > last;
    if !advance {
        return Ok(false);
    }
    let next = dwell(data)?
        .checked_add(1)
        .ok_or(MirrorPoolError::ArithmeticOverflow)?;
    write_u64(data, DWELL_OFF, next)?;
    write_u64(data, LAST_EPOCH_OFF, current_epoch)?;
    Ok(true)
}

/// Dwell accrued but not yet claimed (`dwell - claimed_dwell`). Fails closed if
/// the invariant `claimed_dwell <= dwell` is ever violated.
pub fn unclaimed_dwell(data: &[u8]) -> Result<u64, ProgramError> {
    dwell(data)?
        .checked_sub(claimed_dwell(data)?)
        .ok_or_else(|| MirrorPoolError::ArithmeticOverflow.into())
}

/// Mark all currently-accrued dwell as claimed (`claimed_dwell = dwell`).
pub fn mark_claimed(data: &mut [u8]) -> Result<(), ProgramError> {
    let d = dwell(data)?;
    write_u64(data, CLAIMED_DWELL_OFF, d)
}
