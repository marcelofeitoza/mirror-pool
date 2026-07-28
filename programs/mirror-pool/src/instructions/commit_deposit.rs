//! COMMIT_DEPOSIT: the ZK opt-in escrow + commit.
//!
//! Like the crowd `COMMIT`, a participant posts a 32-byte commitment leaf into
//! the current epoch's frontier accumulator. UNLIKE the crowd path, the
//! participant also ESCROWS `amount` lamports into the pool: the ZK opt-in
//! action (settled later by `SETTLE_ZK`) transfers that escrow to the bound
//! recipient (clients bind a fresh address), and the commitment's `actionHash`
//! binds `(recipient, amount)` (see `mirror_core::transfer_action_hash`) so the
//! relay cannot redirect it.
//!
//! The commitment is `Poseidon(secret, actionHash, epoch)` computed client-side;
//! on-chain it is an opaque leaf appended to the SAME accumulator the crowd path
//! uses, so both paths share one accumulator and one recent-root history.
//!
//! Two consequences of that sharing, both stated in full in the `settle_zk`
//! module header because they bound what this path promises: the escrow is a
//! POOL-WIDE POT (the leaf is opaque, so nothing on-chain can tie the `amount`
//! escrowed here to the `amount` the leaf's `actionHash` binds, and a fee-only
//! crowd leaf satisfies the membership circuit too), and the set that actually
//! covers a settled output is this window's ZK deposits OF THE SAME AMOUNT,
//! since `SETTLE_ZK` publishes both the epoch and the amount.
//!
//! Like the crowd `COMMIT`, this path also collects the pool's anti-Sybil entry
//! fee (on top of the escrow) and splits its `reward_bps` share into the reward
//! pool, so ZK opt-in commits pay the same per-identity cost and help fund the
//! participation incentive. It never touches a Dwell PDA: the ZK path is
//! anonymous, so tying a reward claim to an on-chain identity here would defeat
//! the point. The anonymity-preserving ZK dwell claim is documented (not
//! implemented) in `docs/INCENTIVES.md`.
//!
//! Body layout after the tag byte (see `wire::COMMIT_DEPOSIT_LEN`):
//!
//! ```text
//! [commitment: 32 bytes][amount: u64 LE]
//! ```
//!
//! Accounts:
//!
//! ```text
//! 0. pool           writable   initialized Pool PDA (holds the escrow)
//! 1. epoch          writable   Epoch PDA for the current window (created lazily);
//!                              seeds [b"epoch", pool, epoch_id LE]
//! 2. depositor      signer     writable; posts the commit, pays escrow + rent
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
const BODY_LEN: usize = wire::COMMIT_DEPOSIT_LEN - 1;

pub fn process(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    // Fail closed: exactly [commitment(32)][amount(8)], nothing more.
    if data.len() != BODY_LEN {
        return Err(MirrorPoolError::MalformedInstruction.into());
    }
    let commitment: [u8; 32] = data
        .get(0..32)
        .ok_or(MirrorPoolError::MalformedInstruction)?
        .try_into()
        .map_err(|_| MirrorPoolError::MalformedInstruction)?;
    let amount = u64::from_le_bytes(
        data.get(32..40)
            .ok_or(MirrorPoolError::MalformedInstruction)?
            .try_into()
            .map_err(|_| MirrorPoolError::MalformedInstruction)?,
    );

    // A zero escrow has no action to settle; reject rather than commit a no-op.
    if amount == 0 {
        return Err(ProgramError::InvalidArgument);
    }

    let [pool_account, epoch_account, depositor, _system_program, clock_account, ..] = accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !depositor.is_signer() {
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
            depositor,
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
        if epoch::is_settled(&epoch_data)? {
            return Err(MirrorPoolError::EpochAlreadySettled.into());
        }
    }

    // Escrow the deposit (depositor -> pool). The pool holds it until SETTLE_ZK
    // transfers it to the fresh recipient bound by the commitment's actionHash.
    Transfer {
        from: depositor,
        to: pool_account,
        lamports: amount,
    }
    .invoke()?;

    // Collect the anti-Sybil entry fee on top of the escrow (payer -> pool).
    // Skipped when disabled. The escrow and the fee are separate lamports: the
    // escrow is preserved in full for SETTLE_ZK; only the fee funds the reward
    // pool below.
    if entry_fee > 0 {
        Transfer {
            from: depositor,
            to: pool_account,
            lamports: entry_fee,
        }
        .invoke()?;
    }

    // Append the commitment leaf to the frontier accumulator (also records the
    // new root in the recent-root ring for SETTLE_ZK).
    let new_root = {
        let mut pool_data = pool_account.try_borrow_mut()?;
        merkle::append(&mut pool_data, &commitment)?
    };

    // Split the entry fee: the pool's `reward_bps` share accrues to the reward
    // pool (the escrow `amount` is untouched by this accounting).
    let reward_share = {
        let mut pool_data = pool_account.try_borrow_mut()?;
        pool::accrue_reward_from_fee(&mut pool_data, entry_fee)?
    };

    // Bump the epoch's commit count.
    let commit_count = {
        let mut epoch_data = epoch_account.try_borrow_mut()?;
        epoch::increment_commit_count(&mut epoch_data)?
    };

    log!(
        "mirror-pool: commit_deposit epoch={} amount={} commit_count={} reward_share={} root0={}",
        current_epoch,
        amount,
        commit_count,
        reward_share,
        new_root[0]
    );
    Ok(())
}
