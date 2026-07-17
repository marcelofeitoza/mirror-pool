//! SETTLE_EPOCH: a rotating relay settles a whole epoch atomically.
//!
//! This is the privacy-critical half of the protocol:
//!
//! - Batch settlement puts every action of the window on ONE timestamp,
//!   defeating FIFO temporal matching (empirically the strongest attack on
//!   Tornado-style pools, up to 49% linkage).
//! - The relay pays the fees, so no participant wallet ever appears as the
//!   initiator of the executed action.
//! - The k-anonymity floor is enforced here: an epoch below `k_floor` rolls
//!   forward instead of executing. Never settle into a set small enough to
//!   deanonymize by elimination.
//!
//! Body layout after the tag byte (see `wire::SETTLE_HEADER_LEN`):
//!
//! ```text
//! [epoch: u64 LE][n_nullifiers: u32 LE][nullifier: 32 bytes] * n_nullifiers
//! ```
//!
//! Accounts:
//!
//! ```text
//! 0.        pool            initialized Pool PDA
//! 1.        epoch           Epoch PDA being settled
//! 2.        authority       signer; MUST equal pool.authority
//! 3..3+n    nullifier[i]    writable; Nullifier PDA to create (anti-replay)
//! 3+n       payer           signer, writable; funds the nullifier-PDA rent
//! 4+n       system_program  for the create-account CPIs
//! 5+n       clock           sysvar; current slot for the window-closed gate
//! ```
//!
//! Honesty note (v1): this does NOT prove each `nullifier[i]` corresponds to a
//! distinct prior commitment - that binding is the v2 Groth16 membership proof.
//! v1 enforces batching, the on-chain k-floor (from the Epoch commit count),
//! per-nullifier anti-replay, relay-authority, and fail-closed parsing.

use pinocchio::{
    cpi::Seed, error::ProgramError, sysvars::clock::Clock, AccountView, Address, ProgramResult,
};
use pinocchio_log::log;

use crate::{
    pda,
    state::{epoch, nullifier, pool},
    wire, MirrorPoolError,
};

/// Header body length (wire header minus the tag byte): epoch(8) + n(4).
const HEADER_BODY_LEN: usize = wire::SETTLE_HEADER_LEN - 1;

pub fn process(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    // Fail closed on shape: parse the header, bound the count, then require the
    // EXACT total length. Trailing bytes are malformed input, not padding.
    if data.len() < HEADER_BODY_LEN {
        return Err(MirrorPoolError::MalformedInstruction.into());
    }
    let epoch_id = u64::from_le_bytes(
        data.get(0..8)
            .ok_or(MirrorPoolError::MalformedInstruction)?
            .try_into()
            .map_err(|_| MirrorPoolError::MalformedInstruction)?,
    );
    let n_nullifiers = u32::from_le_bytes(
        data.get(8..12)
            .ok_or(MirrorPoolError::MalformedInstruction)?
            .try_into()
            .map_err(|_| MirrorPoolError::MalformedInstruction)?,
    ) as usize;

    if n_nullifiers == 0 || n_nullifiers > wire::MAX_SETTLE_NULLIFIERS {
        return Err(MirrorPoolError::MalformedInstruction.into());
    }
    // n is bounded above, so this arithmetic cannot overflow.
    let expected_len = HEADER_BODY_LEN + n_nullifiers * wire::HASH_LEN;
    if data.len() != expected_len {
        return Err(MirrorPoolError::MalformedInstruction.into());
    }

    // Account layout is [pool, epoch, authority, n*nullifier, payer, system, clock].
    if accounts.len() != n_nullifiers + 6 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let pool_account = &accounts[0];
    let epoch_account = &accounts[1];
    let authority = &accounts[2];
    let nullifier_accounts = &accounts[3..3 + n_nullifiers];
    let payer = &accounts[3 + n_nullifiers];
    let _system_program = &accounts[4 + n_nullifiers];
    let clock_account = &accounts[5 + n_nullifiers];

    // (1) Authority must be a signer AND equal the pool's stored authority.
    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !payer.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !pool_account.owned_by(program_id) {
        return Err(MirrorPoolError::PoolNotInitialized.into());
    }
    let (epoch_slots, k_floor) = {
        let pool_data = pool_account.try_borrow()?;
        if pool_data.len() != pool::LEN || !pool::is_initialized(&pool_data)? {
            return Err(MirrorPoolError::PoolNotInitialized.into());
        }
        if &pool::authority(&pool_data)? != authority.address().as_array() {
            return Err(MirrorPoolError::Unauthorized.into());
        }
        (pool::epoch_slots(&pool_data)?, pool::k_floor(&pool_data)?)
    };
    if epoch_slots == 0 {
        return Err(ProgramError::InvalidAccountData);
    }

    // Verify the Epoch PDA for the requested epoch id.
    let pool_key = pool_account.address();
    let epoch_le = epoch_id.to_le_bytes();
    pda::verify_pda(
        epoch_account,
        &[pda::EPOCH_SEED, pool_key.as_ref(), &epoch_le],
        program_id,
    )?;
    if !epoch_account.owned_by(program_id) {
        return Err(MirrorPoolError::InvalidPda.into());
    }

    // Read the epoch state for the ordered gates.
    let commit_count = {
        let epoch_data = epoch_account.try_borrow()?;
        if epoch_data.len() != epoch::LEN || !epoch::is_initialized(&epoch_data)? {
            return Err(MirrorPoolError::InvalidPda.into());
        }
        if epoch::epoch_id(&epoch_data)? != epoch_id {
            return Err(MirrorPoolError::EpochMismatch.into());
        }

        // (2) The epoch window must have closed: current_slot >= (epoch+1)*slots.
        let current_slot = {
            let clock = Clock::from_account_view(clock_account)?;
            clock.slot
        };
        let settle_slot = epoch_id
            .checked_add(1)
            .and_then(|e| e.checked_mul(epoch_slots))
            .ok_or(MirrorPoolError::EpochNotClosed)?;
        if current_slot < settle_slot {
            return Err(MirrorPoolError::EpochNotClosed.into());
        }

        // (3) The epoch must not already be settled (double-settle guard).
        if epoch::is_settled(&epoch_data)? {
            return Err(MirrorPoolError::EpochAlreadySettled.into());
        }

        epoch::commit_count(&epoch_data)?
    };

    // (4) k-anonymity floor: never execute into a set below the floor. Below it
    // the coordinator rolls the epoch forward off-chain instead of settling.
    if commit_count < k_floor {
        return Err(MirrorPoolError::BelowKFloor.into());
    }

    // (5) Anti-replay: create one Nullifier PDA per revealed nullifier. An
    // already-existing (program-owned) PDA means the nullifier was spent.
    for (i, nf_account) in nullifier_accounts.iter().enumerate() {
        let off = HEADER_BODY_LEN + i * wire::HASH_LEN;
        let nf = &data[off..off + wire::HASH_LEN];
        if !nf_account.is_writable() {
            return Err(ProgramError::InvalidAccountData);
        }
        let nf_bump = pda::verify_pda(
            nf_account,
            &[pda::NULLIFIER_SEED, pool_key.as_ref(), &epoch_le, nf],
            program_id,
        )?;
        if nf_account.owned_by(program_id) {
            return Err(MirrorPoolError::NullifierSpent.into());
        }
        let bump_seed = [nf_bump];
        let signer_seeds = [
            Seed::from(pda::NULLIFIER_SEED),
            Seed::from(pool_key.as_ref()),
            Seed::from(&epoch_le[..]),
            Seed::from(nf),
            Seed::from(&bump_seed[..]),
        ];
        pda::create_pda_account(payer, nf_account, program_id, nullifier::LEN, &signer_seeds)?;
        let mut nf_data = nf_account.try_borrow_mut()?;
        nf_data[0] = nullifier::SPENT;
    }

    // TODO(v2 behaviors hook): here the pool executes its fixed-shape action once
    // per settled participant via CPI (e.g. a Jupiter swap or an SPL stake-pool
    // deposit), byte-shape identical for every participant so the executed action
    // carries no per-initiator signal. v1 stops at the anonymity mechanics
    // (batching + k-floor + anti-replay + authority + fail-closed), which is the
    // testable, provable core; the behavior CPI is additive and does not change
    // any account layout above.

    // (6) Finally, mark the epoch settled so it can never settle again.
    {
        let mut epoch_data = epoch_account.try_borrow_mut()?;
        epoch::set_settled(&mut epoch_data)?;
    }

    log!(
        "mirror-pool: settle_epoch epoch={} n={} commit_count={}",
        epoch_id,
        n_nullifiers as u64,
        commit_count
    );
    Ok(())
}
