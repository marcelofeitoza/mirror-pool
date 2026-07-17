//! INIT_POOL: one-time, immutable pool configuration.
//!
//! `epoch_slots` and `k_floor` are fixed at init and can never be changed:
//! a mutable `k_floor` would let an operator lower the floor right before a
//! targeted epoch settles, shrinking the anonymity set on demand. One pool
//! also serves exactly one fixed action shape; the shape binding lands with
//! TODO(v1) below.
//!
//! Body layout after the tag byte (see `wire::INIT_POOL_LEN`):
//!
//! ```text
//! [epoch_slots: u64 LE][k_floor: u32 LE]
//! ```
//!
//! Accounts:
//!
//! ```text
//! 0. authority   signer      pays for and authorizes pool creation
//! 1. pool        writable    pre-created, program-owned, pool::LEN bytes
//! ```

use pinocchio::{error::ProgramError, AccountView, ProgramResult};
use pinocchio_log::log;

use crate::{state::pool, wire, MirrorPoolError};

/// Instruction body length (wire length minus the tag byte).
const BODY_LEN: usize = wire::INIT_POOL_LEN - 1;

pub fn process(accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    // Fail closed on shape before touching any account.
    if data.len() != BODY_LEN {
        return Err(MirrorPoolError::MalformedInstruction.into());
    }
    let epoch_slots = u64::from_le_bytes(
        data.get(0..8)
            .ok_or(MirrorPoolError::MalformedInstruction)?
            .try_into()
            .map_err(|_| MirrorPoolError::MalformedInstruction)?,
    );
    let k_floor = u32::from_le_bytes(
        data.get(8..12)
            .ok_or(MirrorPoolError::MalformedInstruction)?
            .try_into()
            .map_err(|_| MirrorPoolError::MalformedInstruction)?,
    );

    // A zero-length window cannot batch, and a pool that may settle with
    // k < 2 is a deanonymization machine, not an anonymity set.
    if epoch_slots == 0 || k_floor < 2 {
        return Err(ProgramError::InvalidArgument);
    }

    let (authority, pool_account) = match accounts {
        [authority, pool_account, ..] => (authority, pool_account),
        _ => return Err(ProgramError::NotEnoughAccountKeys),
    };
    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !pool_account.is_writable() {
        return Err(ProgramError::InvalidAccountData);
    }

    // TODO(v1): create the pool account here as a PDA via a system-program
    // CPI (seeds = [b"pool", action_class_hash]) instead of requiring a
    // pre-created account, and verify the derivation (technique: standard
    // Solana PDA creation with a system-program CPI, plus program-owner and
    // rent-exemption checks).
    // TODO(v1): store the ActionClass canonical-bytes hash (see state::pool
    // module docs) so SETTLE_EPOCH can enforce the fixed action shape.
    let mut pool_data = pool_account.try_borrow_mut()?;
    if pool_data.len() != pool::LEN {
        return Err(ProgramError::InvalidAccountData);
    }
    if pool::is_initialized(&pool_data)? {
        return Err(MirrorPoolError::PoolAlreadyInitialized.into());
    }
    pool::init(&mut pool_data, epoch_slots, k_floor)?;

    log!(
        "mirror-pool: init_pool epoch_slots={} k_floor={}",
        epoch_slots,
        k_floor
    );
    Ok(())
}
