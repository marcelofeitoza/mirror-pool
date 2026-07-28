//! UPDATE_ASSOCIATION_ROOT: publish a new curated-set root.
//!
//! The curator recomputes the Merkle root of its curated commitment list
//! off-chain (`mirror-cli assoc build-root`) and posts it here. The new root goes
//! into the set's recent-root ring, so proofs already generated against the
//! previous few roots keep landing (see `crate::state::association` for why that
//! window exists and what it costs).
//!
//! The program does NOT and CANNOT check that the root corresponds to a subset of
//! the pool's commitments: the leaves live off-chain, and re-deriving a Merkle
//! root over an arbitrary-size list is not something a settlement instruction can
//! afford. That is a real limit, so state it plainly: an on-chain association
//! proof shows "this settlement's commitment is under the root curator X
//! published", NOT "curator X curated honestly". Curator honesty is checked by
//! anyone who wants to, off-chain, by rebuilding the root from the curator's
//! published leaf list and comparing it to this account. Publishing that list is
//! the curator's job, and a curator who does not publish it is one whose
//! attestations nobody should accept. See `docs/COMPLIANCE.md`.
//!
//! Body layout after the tag byte (see `wire::UPDATE_ASSOCIATION_ROOT_LEN`):
//!
//! ```text
//! [root(32)]
//! ```
//!
//! Accounts:
//!
//! ```text
//! 0. assoc          writable   initialized AssociationSet PDA
//! 1. curator        signer     MUST equal assoc.curator
//! ```

use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};
use pinocchio_log::log;

use crate::{pda, state::association, wire, MirrorPoolError};

/// Instruction body length (wire length minus the tag byte).
const BODY_LEN: usize = wire::UPDATE_ASSOCIATION_ROOT_LEN - 1;

pub fn process(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    // Fail closed on shape: exact length, nothing more.
    if data.len() != BODY_LEN {
        return Err(MirrorPoolError::MalformedInstruction.into());
    }
    let root: [u8; 32] = data[0..32]
        .try_into()
        .map_err(|_| MirrorPoolError::MalformedInstruction)?;

    let [assoc_account, curator, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !curator.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !assoc_account.is_writable() {
        return Err(ProgramError::InvalidAccountData);
    }
    if !assoc_account.owned_by(program_id) {
        return Err(MirrorPoolError::AssociationNotInitialized.into());
    }

    let mut assoc_data = assoc_account.try_borrow_mut()?;
    if assoc_data.len() != association::LEN || !association::is_initialized(&assoc_data)? {
        return Err(MirrorPoolError::AssociationNotInitialized.into());
    }
    // Only the registered curator may publish. Re-derive the PDA from the stored
    // pool + curator as well, so a caller cannot pass some other program-owned
    // account that happens to parse as an association set.
    let stored_curator = association::curator(&assoc_data)?;
    if &stored_curator != curator.address().as_array() {
        return Err(MirrorPoolError::Unauthorized.into());
    }
    let stored_pool = association::pool(&assoc_data)?;
    pda::verify_pda(
        assoc_account,
        &[pda::ASSOCIATION_SEED, &stored_pool, &stored_curator],
        program_id,
    )?;

    association::publish_root(&mut assoc_data, &root)?;

    log!(
        "mirror-pool: update_association_root curator0={} root0={} updates={}",
        stored_curator[0],
        root[0],
        association::update_count(&assoc_data)?
    );
    Ok(())
}
