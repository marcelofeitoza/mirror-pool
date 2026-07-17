//! COMMIT: a participant posts a commitment into the current epoch.
//!
//! The commitment is `H(secret, action, epoch)` computed client-side
//! (`mirror_core::commit`); on-chain it is an opaque 32-byte leaf. Binding
//! the action and epoch into the hash is what makes the relay untrusted: at
//! settlement it cannot substitute a different action for a committed one
//! without invalidating the commitment. The only signal a commit leaks is
//! timing, and shared-epoch batching absorbs exactly that: everyone in the
//! window settles together on one timestamp.
//!
//! Body layout after the tag byte (see `wire::COMMIT_LEN`):
//!
//! ```text
//! [commitment: 32 bytes]
//! ```
//!
//! Accounts:
//!
//! ```text
//! 0. participant  signer      the committing wallet (public at commit time;
//!                             unlinkability is at the settle side, where the
//!                             gasless rotating relay is the fee payer)
//! 1. pool         writable    initialized pool account
//! 2. epoch        writable    epoch account for the current window
//! ```

use pinocchio::{error::ProgramError, AccountView, ProgramResult};
use pinocchio_log::log;

use crate::{state::pool, wire, MirrorPoolError};

/// Instruction body length (wire length minus the tag byte).
const BODY_LEN: usize = wire::COMMIT_LEN - 1;

pub fn process(accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    // Fail closed: exactly one 32-byte commitment, nothing more.
    if data.len() != BODY_LEN {
        return Err(MirrorPoolError::MalformedInstruction.into());
    }
    // Opaque leaf; consumed by the accumulator append in TODO(v1) below.
    let _commitment: &[u8] = data;

    let (participant, pool_account, epoch_account) = match accounts {
        [participant, pool_account, epoch_account, ..] => {
            (participant, pool_account, epoch_account)
        }
        _ => return Err(ProgramError::NotEnoughAccountKeys),
    };
    if !participant.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !pool_account.is_writable() || !epoch_account.is_writable() {
        return Err(ProgramError::InvalidAccountData);
    }
    {
        let pool_data = pool_account.try_borrow()?;
        if pool_data.len() != pool::LEN || !pool::is_initialized(&pool_data)? {
            return Err(MirrorPoolError::PoolNotInitialized.into());
        }
    }

    // TODO(v1): build and wire up here:
    //  - read the Clock sysvar, derive the current epoch from
    //    pool.epoch_slots (mirror_core::EpochSchedule::epoch_of_slot) and
    //    require the epoch account to be the current window (create it lazily
    //    as a PDA with seeds [b"epoch", pool, epoch_id LE]);
    //  - append the commitment to the frontier Merkle accumulator (technique:
    //    an append-only Poseidon frontier Merkle accumulator, standard
    //    Tornado-Cash-style commitment tree: update frontier siblings in-place,
    //    push the new root into the root-history ring buffer, bump
    //    commitment_count);
    //  - bump epoch.nominal_k, the on-chain upper bound for the k_floor gate.
    log!("mirror-pool: commit received (skeleton, accumulator not wired)");
    Err(MirrorPoolError::NotImplemented.into())
}
