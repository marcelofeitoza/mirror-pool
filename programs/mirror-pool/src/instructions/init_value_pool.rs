//! INIT_VALUE_POOL: one-time confidential-value pool configuration.
//!
//! Creates a ValuePool (its own value-note frontier accumulator + recent-root
//! ring + config) and a separate `["vvault", vpool]` vault PDA that holds the
//! commingled lamports. The ValuePool is a SEPARATE account from the behavioral
//! [`crate::state::pool`]; the confidential layer never grows the behavioral one.
//!
//! `authority`, `fee`, and `denomination` are fixed at init. `denomination` is
//! an `Option<u64>` reserved for the fixed-denomination mode landing next: it is
//! stored but NOT enforced in this version.
//!
//! Body layout after the tag byte (see `wire::INIT_VALUE_POOL_LEN`):
//!
//! ```text
//! [fee: u64 LE][denom_flag: u8 (0=None,1=Some)][denomination: u64 LE]
//! ```
//!
//! Accounts:
//!
//! ```text
//! 0. vpool           writable   ValuePool PDA to create; seeds [b"vpool", authority]
//! 1. vault           writable   vault PDA to create; seeds [b"vvault", vpool]
//! 2. authority       signer     becomes vpool.authority (the Transact relay)
//! 3. payer           signer     writable; funds both PDAs' rent
//! 4. system_program            for the create-account CPIs
//! ```

use pinocchio::{cpi::Seed, error::ProgramError, AccountView, Address, ProgramResult};
use pinocchio_log::log;

use crate::{
    pda,
    state::{merkle, value_pool},
    wire, MirrorPoolError,
};

/// Instruction body length (wire length minus the tag byte).
const BODY_LEN: usize = wire::INIT_VALUE_POOL_LEN - 1;

pub fn process(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    // Fail closed on shape before touching any account.
    if data.len() != BODY_LEN {
        return Err(MirrorPoolError::MalformedInstruction.into());
    }
    let fee = u64::from_le_bytes(
        data.get(0..8)
            .ok_or(MirrorPoolError::MalformedInstruction)?
            .try_into()
            .map_err(|_| MirrorPoolError::MalformedInstruction)?,
    );
    let denom_flag = *data.get(8).ok_or(MirrorPoolError::MalformedInstruction)?;
    let denom_value = u64::from_le_bytes(
        data.get(9..17)
            .ok_or(MirrorPoolError::MalformedInstruction)?
            .try_into()
            .map_err(|_| MirrorPoolError::MalformedInstruction)?,
    );
    let denomination = match denom_flag {
        0 => None,
        1 => Some(denom_value),
        _ => return Err(MirrorPoolError::MalformedInstruction.into()),
    };

    let [vpool_account, vault_account, authority, payer, _system_program, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !authority.is_signer() || !payer.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !vpool_account.is_writable() || !vault_account.is_writable() {
        return Err(ProgramError::InvalidAccountData);
    }

    // Derive and verify the ValuePool PDA: seeds = [b"vpool", authority].
    let authority_key = authority.address();
    let vpool_bump = pda::verify_pda(
        vpool_account,
        &[pda::VALUE_POOL_SEED, authority_key.as_ref()],
        program_id,
    )?;
    // Reject re-initialization: a live account already has data.
    if vpool_account.data_len() != 0 {
        return Err(MirrorPoolError::ValuePoolAlreadyInitialized.into());
    }

    // Derive and verify the vault PDA: seeds = [b"vvault", vpool].
    let vpool_key = vpool_account.address();
    let vault_bump = pda::verify_pda(
        vault_account,
        &[pda::VALUE_VAULT_SEED, vpool_key.as_ref()],
        program_id,
    )?;
    if vault_account.data_len() != 0 {
        return Err(MirrorPoolError::ValuePoolAlreadyInitialized.into());
    }

    // Create the program-owned ValuePool PDA, signing with its seeds.
    let vpool_bump_seed = [vpool_bump];
    let vpool_signer_seeds = [
        Seed::from(pda::VALUE_POOL_SEED),
        Seed::from(authority_key.as_ref()),
        Seed::from(&vpool_bump_seed),
    ];
    pda::create_pda_account(
        payer,
        vpool_account,
        program_id,
        value_pool::LEN,
        &vpool_signer_seeds,
    )?;

    // Create the program-owned vault PDA (0 data; holds the commingled lamports).
    // A program-owned vault is required so Transact can debit it directly on a
    // withdraw (a system transfer only moves lamports out of system-owned
    // accounts); deposits reach it via a system transfer INTO it.
    let vault_bump_seed = [vault_bump];
    let vault_signer_seeds = [
        Seed::from(pda::VALUE_VAULT_SEED),
        Seed::from(vpool_key.as_ref()),
        Seed::from(&vault_bump_seed),
    ];
    pda::create_pda_account(payer, vault_account, program_id, 0, &vault_signer_seeds)?;

    // Write the immutable config plus the empty-tree root.
    let empty_root = merkle::empty_root();
    let mut vpool_data = vpool_account.try_borrow_mut()?;
    if value_pool::is_initialized(&vpool_data)? {
        return Err(MirrorPoolError::ValuePoolAlreadyInitialized.into());
    }
    value_pool::init(
        &mut vpool_data,
        authority_key.as_array(),
        fee,
        denomination,
        vpool_bump,
        vault_bump,
        &empty_root,
    )?;

    log!(
        "mirror-pool: init_value_pool fee={} denom_flag={} vault_bump={}",
        fee,
        denom_flag as u64,
        vault_bump as u64
    );
    Ok(())
}
