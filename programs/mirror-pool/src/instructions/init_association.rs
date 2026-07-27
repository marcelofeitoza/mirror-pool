//! INIT_ASSOCIATION: register a curator's association set for a pool.
//!
//! Creates the AssociationSet PDA at seeds `[b"assoc", pool, curator]`. The
//! curator signs for itself: registration is PERMISSIONLESS, and that is a
//! deliberate design choice, not an oversight.
//!
//! Why permissionless. If the pool authority gated who may become a curator, the
//! pool authority would hold a veto over the compliance story, and a user's only
//! option would be the one curator the operator blessed. Because the seeds
//! include the curator, any number of curators can publish competing sets over
//! the same pool, and a user picks which one to prove against. Whether a given
//! curator's attestation is worth anything is decided OFF-CHAIN by whoever reads
//! it (an exchange, an auditor, a counterparty); the program's job is only to
//! prove that the settlement really did carry an inclusion proof against the root
//! that curator had published. See `docs/COMPLIANCE.md`.
//!
//! Creating a set publishes NO root: every ring slot starts as the all-zero
//! sentinel and [`crate::state::association::is_known_root`] rejects it, so a
//! freshly registered curator can attest to nothing until it calls
//! `UPDATE_ASSOCIATION_ROOT`.
//!
//! Body layout after the tag byte (see `wire::INIT_ASSOCIATION_LEN`): empty. The
//! pool and the curator are both accounts, so there is nothing to encode.
//!
//! Accounts:
//!
//! ```text
//! 0. assoc          writable   AssociationSet PDA to create;
//!                              seeds [b"assoc", pool, curator]
//! 1. pool           readonly   the initialized Pool this set curates
//! 2. curator        signer     becomes assoc.curator
//! 3. payer          signer     writable; funds the PDA rent
//! 4. system_program            for the create-account CPI
//! ```

use pinocchio::{cpi::Seed, error::ProgramError, AccountView, Address, ProgramResult};
use pinocchio_log::log;

use crate::{
    pda,
    state::{association, pool},
    wire, MirrorPoolError,
};

/// Instruction body length (wire length minus the tag byte).
const BODY_LEN: usize = wire::INIT_ASSOCIATION_LEN - 1;

pub fn process(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    // Fail closed on shape before touching any account: this instruction has no
    // body, so ANY trailing byte is a malformed instruction, not a no-op.
    if data.len() != BODY_LEN {
        return Err(MirrorPoolError::MalformedInstruction.into());
    }

    let [assoc_account, pool_account, curator, payer, _system_program, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !curator.is_signer() || !payer.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !assoc_account.is_writable() {
        return Err(ProgramError::InvalidAccountData);
    }

    // The pool must be a real, initialized pool owned by this program. Curating a
    // set over an account that is not a pool would produce attestations that look
    // on-chain-verified but reference nothing.
    if !pool_account.owned_by(program_id) {
        return Err(MirrorPoolError::PoolNotInitialized.into());
    }
    {
        let pool_data = pool_account.try_borrow()?;
        if pool_data.len() != pool::LEN || !pool::is_initialized(&pool_data)? {
            return Err(MirrorPoolError::PoolNotInitialized.into());
        }
    }

    // Derive and verify the AssociationSet PDA: seeds = [b"assoc", pool, curator].
    let pool_key = pool_account.address();
    let curator_key = curator.address();
    let bump = pda::verify_pda(
        assoc_account,
        &[
            pda::ASSOCIATION_SEED,
            pool_key.as_ref(),
            curator_key.as_ref(),
        ],
        program_id,
    )?;
    // Reject re-registration: a live account already has data.
    if assoc_account.data_len() != 0 {
        return Err(MirrorPoolError::AssociationAlreadyInitialized.into());
    }

    let bump_seed = [bump];
    let signer_seeds = [
        Seed::from(pda::ASSOCIATION_SEED),
        Seed::from(pool_key.as_ref()),
        Seed::from(curator_key.as_ref()),
        Seed::from(&bump_seed[..]),
    ];
    pda::create_pda_account(
        payer,
        assoc_account,
        program_id,
        association::LEN,
        &signer_seeds,
    )?;

    let mut assoc_data = assoc_account.try_borrow_mut()?;
    if association::is_initialized(&assoc_data)? {
        return Err(MirrorPoolError::AssociationAlreadyInitialized.into());
    }
    association::init(
        &mut assoc_data,
        pool_key.as_array(),
        curator_key.as_array(),
        bump,
    )?;

    log!(
        "mirror-pool: init_association pool0={} curator0={}",
        pool_key.as_array()[0],
        curator_key.as_array()[0]
    );
    Ok(())
}
