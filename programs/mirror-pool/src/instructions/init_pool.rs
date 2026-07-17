//! INIT_POOL: one-time, immutable pool configuration.
//!
//! `epoch_slots`, `k_floor`, `authority`, and `entry_fee` are fixed at init and
//! can never change: a mutable `k_floor` would let an operator lower the floor
//! right before a targeted epoch settles, shrinking the anonymity set on demand.
//! One pool also serves exactly one fixed action shape (bound off-chain via each
//! commitment; the on-chain class hash is a v2 field).
//!
//! Body layout after the tag byte (see `wire::INIT_POOL_LEN`):
//!
//! ```text
//! [epoch_slots: u64 LE][k_floor: u32 LE][entry_fee: u64 LE]
//! ```
//!
//! Accounts:
//!
//! ```text
//! 0. pool            writable   Pool PDA to create; seeds [b"pool", authority]
//! 1. authority       signer     becomes pool.authority (the settle relay)
//! 2. payer           signer     writable; funds the Pool PDA rent
//! 3. system_program            for the create-account CPI
//! ```

use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};
use pinocchio_log::log;

use crate::{
    pda,
    state::{merkle, pool},
    wire, MirrorPoolError,
};

/// Instruction body length (wire length minus the tag byte).
const BODY_LEN: usize = wire::INIT_POOL_LEN - 1;

pub fn process(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
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
    let entry_fee = u64::from_le_bytes(
        data.get(12..20)
            .ok_or(MirrorPoolError::MalformedInstruction)?
            .try_into()
            .map_err(|_| MirrorPoolError::MalformedInstruction)?,
    );

    // A zero-length window cannot batch, and a pool that may settle with
    // k < 2 is a deanonymization machine, not an anonymity set.
    if epoch_slots == 0 || k_floor < 2 {
        return Err(ProgramError::InvalidArgument);
    }

    let [pool_account, authority, payer, _system_program, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !authority.is_signer() || !payer.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !pool_account.is_writable() {
        return Err(ProgramError::InvalidAccountData);
    }

    // Derive and verify the Pool PDA: seeds = [b"pool", authority].
    let authority_key = authority.address();
    let bump = pda::verify_pda(
        pool_account,
        &[pda::POOL_SEED, authority_key.as_ref()],
        program_id,
    )?;

    // Reject re-initialization: a live (already created) account has data.
    if pool_account.data_len() != 0 {
        return Err(MirrorPoolError::PoolAlreadyInitialized.into());
    }

    // Create the program-owned Pool PDA, signing with its seeds.
    let bump_seed = [bump];
    let signer_seeds = [
        pinocchio::cpi::Seed::from(pda::POOL_SEED),
        pinocchio::cpi::Seed::from(authority_key.as_ref()),
        pinocchio::cpi::Seed::from(&bump_seed),
    ];
    pda::create_pda_account(payer, pool_account, program_id, pool::LEN, &signer_seeds)?;

    // Write the immutable config plus the empty-tree root.
    let empty_root = merkle::empty_root();
    let mut pool_data = pool_account.try_borrow_mut()?;
    if pool::is_initialized(&pool_data)? {
        return Err(MirrorPoolError::PoolAlreadyInitialized.into());
    }
    pool::init(
        &mut pool_data,
        epoch_slots,
        k_floor,
        entry_fee,
        authority_key.as_array(),
        bump,
        &empty_root,
    )?;

    log!(
        "mirror-pool: init_pool epoch_slots={} k_floor={} entry_fee={}",
        epoch_slots,
        k_floor,
        entry_fee
    );
    Ok(())
}
