//! COMMIT: a participant posts a commitment into the current epoch.
//!
//! The commitment is `H(secret, action, epoch)` computed client-side
//! (`mirror_core::commit`); on-chain it is an opaque 32-byte leaf appended to
//! the frontier accumulator. Binding the action and epoch into the hash is what
//! makes the relay untrusted: at settlement it cannot substitute a different
//! action for a committed one without invalidating the commitment. The only
//! signal a commit leaks is timing, and shared-epoch batching absorbs exactly
//! that: everyone in the window settles together on one timestamp.
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
//! 0. pool           writable   initialized Pool PDA
//! 1. epoch          writable   Epoch PDA for the current window (created lazily);
//!                              seeds [b"epoch", pool, epoch_id LE]
//! 2. participant    signer     writable; posts the commit and pays the fee + rent
//! 3. system_program            for the create-account / transfer CPIs
//! 4. clock          sysvar     current slot -> current epoch = slot / epoch_slots
//! ```

use pinocchio::{
    cpi::Seed, error::ProgramError, sysvars::clock::Clock, AccountView, Address, ProgramResult,
};
use pinocchio_log::log;
use pinocchio_system::instructions::Transfer;

use crate::{
    pda,
    state::{epoch, merkle, pool},
    wire, MirrorPoolError,
};

/// Instruction body length (wire length minus the tag byte).
const BODY_LEN: usize = wire::COMMIT_LEN - 1;

pub fn process(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    // Fail closed: exactly one 32-byte commitment, nothing more.
    if data.len() != BODY_LEN {
        return Err(MirrorPoolError::MalformedInstruction.into());
    }
    let commitment: [u8; 32] = data
        .try_into()
        .map_err(|_| MirrorPoolError::MalformedInstruction)?;

    let [pool_account, epoch_account, participant, _system_program, clock_account, ..] = accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !participant.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !pool_account.is_writable() || !epoch_account.is_writable() {
        return Err(ProgramError::InvalidAccountData);
    }

    // Pool must be an initialized, program-owned account.
    if !pool_account.owned_by(program_id) {
        return Err(MirrorPoolError::PoolNotInitialized.into());
    }
    let (epoch_slots, entry_fee) = {
        let pool_data = pool_account.try_borrow()?;
        if pool_data.len() != pool::LEN || !pool::is_initialized(&pool_data)? {
            return Err(MirrorPoolError::PoolNotInitialized.into());
        }
        (pool::epoch_slots(&pool_data)?, pool::entry_fee(&pool_data)?)
    };
    if epoch_slots == 0 {
        return Err(ProgramError::InvalidAccountData);
    }

    // Derive the current epoch from the Clock sysvar.
    let current_slot = {
        let clock = Clock::from_account_view(clock_account)?;
        clock.slot
    };
    let current_epoch = current_slot / epoch_slots;
    let epoch_le = current_epoch.to_le_bytes();

    // Derive and verify the Epoch PDA for the current window.
    let pool_key = pool_account.address();
    let epoch_bump = pda::verify_pda(
        epoch_account,
        &[pda::EPOCH_SEED, pool_key.as_ref(), &epoch_le],
        program_id,
    )?;

    // Create the Epoch PDA on first commit of the window, else validate it.
    if epoch_account.data_len() == 0 {
        let bump_seed = [epoch_bump];
        let signer_seeds = [
            Seed::from(pda::EPOCH_SEED),
            Seed::from(pool_key.as_ref()),
            Seed::from(&epoch_le[..]),
            Seed::from(&bump_seed[..]),
        ];
        pda::create_pda_account(
            participant,
            epoch_account,
            program_id,
            epoch::LEN,
            &signer_seeds,
        )?;
        let mut epoch_data = epoch_account.try_borrow_mut()?;
        epoch::init(&mut epoch_data, current_epoch, epoch_bump)?;
    } else {
        if !epoch_account.owned_by(program_id) {
            return Err(MirrorPoolError::InvalidPda.into());
        }
        let epoch_data = epoch_account.try_borrow()?;
        if epoch_data.len() != epoch::LEN || !epoch::is_initialized(&epoch_data)? {
            return Err(MirrorPoolError::InvalidPda.into());
        }
        if epoch::epoch_id(&epoch_data)? != current_epoch {
            return Err(MirrorPoolError::EpochMismatch.into());
        }
        // A settled epoch's window is in the past; the clock can never land us
        // back on it, but reject defensively rather than mutate settled state.
        if epoch::is_settled(&epoch_data)? {
            return Err(MirrorPoolError::EpochAlreadySettled.into());
        }
    }

    // Collect the anti-Sybil entry fee (payer -> pool). Skipped when disabled.
    if entry_fee > 0 {
        Transfer {
            from: participant,
            to: pool_account,
            lamports: entry_fee,
        }
        .invoke()?;
    }

    // Append the commitment leaf to the frontier accumulator.
    let new_root = {
        let mut pool_data = pool_account.try_borrow_mut()?;
        merkle::append(&mut pool_data, &commitment)?
    };

    // Bump the epoch's commit count (the on-chain k-floor input).
    let commit_count = {
        let mut epoch_data = epoch_account.try_borrow_mut()?;
        epoch::increment_commit_count(&mut epoch_data)?
    };

    log!(
        "mirror-pool: commit epoch={} commit_count={} root0={}",
        current_epoch,
        commit_count,
        new_root[0]
    );
    Ok(())
}
