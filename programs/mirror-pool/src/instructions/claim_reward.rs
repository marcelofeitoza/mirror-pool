//! CLAIM_REWARD: pay a crowd-path participant their dwell-proportional share of
//! the reward pool.
//!
//! This is the payout half of the participation incentive (the accrual half is
//! the entry-fee split in `COMMIT` / `COMMIT_DEPOSIT`, and the dwell counting is
//! the optional Dwell PDA in `COMMIT`). It rewards STAYING in the pool without
//! weakening anonymity: on the crowd path the committing wallet is already an
//! on-chain signer, so paying it against a per-identity dwell counter reveals
//! nothing new. The ZK opt-in path is anonymous and has no `CLAIM_REWARD`; its
//! anonymity-preserving equivalent is documented (not implemented) in
//! `docs/INCENTIVES.md`.
//!
//! Reward formula (drain-safe, proportional, fail-closed). Let
//!
//! ```text
//! d = dwell.dwell - dwell.claimed_dwell   (this participant's UNCLAIMED dwell)
//! U = pool.total_unclaimed_dwell          (sum of everyone's unclaimed dwell)
//! R = pool.reward_pool_lamports           (lamports earmarked for rewards)
//! payout = floor(R * d / U)
//! ```
//!
//! Then `payout <= R` because `d <= U`, so a claim can NEVER pay more than the
//! reward pool holds (drain-safe by construction), and the payout is exactly the
//! participant's proportional share of the CURRENT reward pool by their share of
//! the CURRENT unclaimed dwell. After paying: `R -= payout`, `U -= d`, and
//! `claimed_dwell = dwell`, so:
//!
//! - Double-claim is rejected: a repeat call has `d == 0` -> `NothingToClaim`.
//! - Over-claim is impossible: `payout <= R` and a checked subtraction guard.
//! - Staying pays more: committing again accrues fresh dwell to claim later.
//! - An empty pool or a share that rounds to zero pays nothing and consumes no
//!   dwell (`NothingToClaim`), so the participant can claim later instead of
//!   burning dwell for zero.
//!
//! Body layout after the tag byte (see `wire::CLAIM_REWARD_LEN`): empty.
//!
//! Accounts:
//!
//! ```text
//! 0. pool         writable        initialized Pool PDA (holds + pays the reward)
//! 1. participant  signer, writable  receives the reward
//! 2. dwell        writable        Dwell PDA; seeds [b"dwell", pool, participant]
//! ```

use pinocchio::{
    error::ProgramError,
    sysvars::{rent::Rent, Sysvar},
    AccountView, Address, ProgramResult,
};
use pinocchio_log::log;

use crate::{
    pda,
    state::{participant, pool},
    wire, MirrorPoolError,
};

/// Instruction body length (wire length minus the tag byte): no body.
const BODY_LEN: usize = wire::CLAIM_REWARD_LEN - 1;

pub fn process(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    // Fail closed on shape: the tag is stripped, so the body must be empty.
    if data.len() != BODY_LEN {
        return Err(MirrorPoolError::MalformedInstruction.into());
    }

    let [pool_account, participant_account, dwell_account, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // The claimant must sign and be writable (it receives the reward).
    if !participant_account.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !pool_account.is_writable()
        || !participant_account.is_writable()
        || !dwell_account.is_writable()
    {
        return Err(ProgramError::InvalidAccountData);
    }

    // Pool must be an initialized, program-owned account.
    if !pool_account.owned_by(program_id) {
        return Err(MirrorPoolError::PoolNotInitialized.into());
    }
    {
        let pool_data = pool_account.try_borrow()?;
        if pool_data.len() != pool::LEN || !pool::is_initialized(&pool_data)? {
            return Err(MirrorPoolError::PoolNotInitialized.into());
        }
    }

    // The Dwell PDA must be exactly [b"dwell", pool, participant] and an
    // initialized, program-owned account. A participant who never accrued dwell
    // has no PDA, so there is nothing to claim.
    let pool_key = pool_account.address();
    let participant_key = participant_account.address();
    pda::verify_pda(
        dwell_account,
        &[pda::DWELL_SEED, pool_key.as_ref(), participant_key.as_ref()],
        program_id,
    )?;
    if !dwell_account.owned_by(program_id) {
        return Err(MirrorPoolError::NothingToClaim.into());
    }
    let unclaimed = {
        let dwell_data = dwell_account.try_borrow()?;
        if dwell_data.len() != participant::LEN || !participant::is_initialized(&dwell_data)? {
            return Err(MirrorPoolError::NothingToClaim.into());
        }
        participant::unclaimed_dwell(&dwell_data)?
    };
    // No unclaimed dwell -> nothing to pay (also the double-claim guard).
    if unclaimed == 0 {
        return Err(MirrorPoolError::NothingToClaim.into());
    }

    // Compute the proportional payout: floor(R * d / U). `d <= U` (the invariant
    // maintained by COMMIT's `add_unclaimed_dwell` and this handler's decrement),
    // so `payout <= R`: never more than the reward pool holds.
    let (reward_pool, total_unclaimed) = {
        let pool_data = pool_account.try_borrow()?;
        (
            pool::reward_pool_lamports(&pool_data)?,
            pool::total_unclaimed_dwell(&pool_data)?,
        )
    };
    if total_unclaimed == 0 {
        return Err(MirrorPoolError::NothingToClaim.into());
    }
    let payout = (reward_pool as u128 * unclaimed as u128 / total_unclaimed as u128) as u64;
    // An empty pool (or a share that floors to zero) pays nothing; fail closed
    // WITHOUT consuming the participant's dwell so they can claim later.
    if payout == 0 {
        return Err(MirrorPoolError::NothingToClaim.into());
    }

    // Drain-safety: never drop the pool below rent exemption. `payout <= R` and
    // `R` is only ever the reward share of collected fees (real lamports on top
    // of escrow + rent), but keep an explicit guard regardless.
    let rent_min = Rent::get()?.try_minimum_balance(pool::LEN)?;
    let pool_balance = pool_account.lamports();
    let remaining = pool_balance
        .checked_sub(payout)
        .ok_or(MirrorPoolError::RewardPoolInsufficient)?;
    if remaining < rent_min {
        return Err(MirrorPoolError::RewardPoolInsufficient.into());
    }

    // Update accounting before moving lamports (all borrows dropped before the
    // lamport moves): decrement the reward pool and the unclaimed-dwell
    // denominator, and mark this participant's dwell claimed.
    {
        let mut pool_data = pool_account.try_borrow_mut()?;
        pool::settle_reward_claim(&mut pool_data, payout, unclaimed)?;
    }
    {
        let mut dwell_data = dwell_account.try_borrow_mut()?;
        participant::mark_claimed(&mut dwell_data)?;
    }

    // Move the reward: the pool is program-owned, so debit it directly (a system
    // transfer only moves lamports out of system-owned accounts) and credit the
    // participant.
    let participant_balance = participant_account
        .lamports()
        .checked_add(payout)
        .ok_or(MirrorPoolError::ArithmeticOverflow)?;
    pool_account.set_lamports(remaining);
    participant_account.set_lamports(participant_balance);

    log!(
        "mirror-pool: claim_reward payout={} claimed_dwell={} participant0={}",
        payout,
        unclaimed,
        participant_key.as_array()[0]
    );
    Ok(())
}
