//! REGISTER_VIEWING_KEY: publish (or rotate) an X25519 viewing key under the
//! signer's own address.
//!
//! Creates the ViewingKey PDA at seeds `[b"view", authority]` on first call and
//! replaces the stored key on later calls by the same authority. It is the
//! directory the disclosure layer addresses readers through, and it is also
//! useful on its own: a sender who knows only a recipient's Solana address can
//! look up the X25519 key to encrypt a confidential-value note to
//! (`mirror_core::encrypted_note`), instead of exchanging one out of band.
//!
//! WHY THE SEEDS ARE THE ACCESS CONTROL. The authority is the only variable seed
//! and it must sign, so the sole PDA any signer can satisfy is their own. There is
//! no slot to squat, no first-come race, and no "whoever registered first owns
//! this" failure mode - not because a check forbids it but because the address
//! cannot be derived. The stored `authority` is compared against the signer on the
//! rotation path as well, which is redundant with the derivation and kept anyway:
//! two independent reasons a wrong signer fails is the right number for an
//! account whose whole job is attribution.
//!
//! WHAT IS VALIDATED, AND WHAT THAT DOES NOT PROVE. The key must pass
//! [`crate::state::viewing_key::is_acceptable_viewing_pub`]: canonical encoding
//! (so the key-derived Disclosure PDA is not malleable) and not a small-order
//! point (so a "sealed" disclosure is not readable by everybody). That is a byte
//! test. It does NOT prove the registrant holds the matching secret, and this
//! instruction deliberately does not try to: a proof of possession would add a
//! signature scheme to the program for a property nobody relies on, since a
//! registration whose secret is not held simply produces disclosures nobody can
//! open.
//!
//! OPT-IN. No settle path reads this account. Not registering blocks nothing and
//! degrades nothing.
//!
//! THE PRIVACY COST OF REGISTERING, stated here because it is real: the account is
//! public and permanently links this Solana address to an X25519 key, and (once
//! any disclosure names it) to the fact that this address participates in the
//! disclosure layer at all. See `docs/COMPLIANCE.md`.
//!
//! Body layout after the tag byte (see `wire::REGISTER_VIEWING_KEY_LEN`):
//!
//! ```text
//! [viewing_pub(32)]
//! ```
//!
//! Accounts:
//!
//! ```text
//! 0. viewkey        writable   ViewingKey PDA to create or update;
//!                              seeds [b"view", authority]
//! 1. authority      signer     owns the registration
//! 2. payer          signer     writable; funds the PDA rent on first call
//! 3. system_program            for the create-account CPI
//! ```

use pinocchio::{cpi::Seed, error::ProgramError, AccountView, Address, ProgramResult};
use pinocchio_log::log;

use crate::{pda, state::viewing_key, wire, MirrorPoolError};

/// Instruction body length (wire length minus the tag byte).
const BODY_LEN: usize = wire::REGISTER_VIEWING_KEY_LEN - 1;

pub fn process(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    // Fail closed on shape before touching any account: exactly the key, nothing
    // more.
    if data.len() != BODY_LEN {
        return Err(MirrorPoolError::MalformedInstruction.into());
    }
    let viewing_pub: [u8; 32] = data[0..32]
        .try_into()
        .map_err(|_| MirrorPoolError::MalformedInstruction)?;

    let [viewkey_account, authority, payer, _system_program, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !authority.is_signer() || !payer.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !viewkey_account.is_writable() {
        return Err(ProgramError::InvalidAccountData);
    }

    // Structural validation of the key itself, before anything is written.
    if !viewing_key::is_acceptable_viewing_pub(&viewing_pub) {
        return Err(MirrorPoolError::InvalidViewingKey.into());
    }

    // Derive and verify the ViewingKey PDA: seeds = [b"view", authority]. This is
    // the anti-squat property: no signer can satisfy anybody else's derivation.
    let authority_key = authority.address();
    let bump = pda::verify_pda(
        viewkey_account,
        &[pda::VIEWING_KEY_SEED, authority_key.as_ref()],
        program_id,
    )?;

    if viewkey_account.data_len() == 0 {
        // First registration: create the account and write v1.
        let bump_seed = [bump];
        let signer_seeds = [
            Seed::from(pda::VIEWING_KEY_SEED),
            Seed::from(authority_key.as_ref()),
            Seed::from(&bump_seed[..]),
        ];
        pda::create_pda_account(
            payer,
            viewkey_account,
            program_id,
            viewing_key::LEN,
            &signer_seeds,
        )?;
        let mut key_data = viewkey_account.try_borrow_mut()?;
        if viewing_key::is_initialized(&key_data)? {
            return Err(ProgramError::AccountAlreadyInitialized);
        }
        viewing_key::init(
            &mut key_data,
            authority_key.as_array(),
            &viewing_pub,
            bump,
        )?;
        log!(
            "mirror-pool: register_viewing_key authority0={} key0={} rotations=0",
            authority_key.as_array()[0],
            viewing_pub[0]
        );
        return Ok(());
    }

    // Rotation: the account already exists. It must be ours, well-formed, and
    // owned by the signer.
    if !viewkey_account.owned_by(program_id) {
        return Err(MirrorPoolError::ViewingKeyNotInitialized.into());
    }
    let mut key_data = viewkey_account.try_borrow_mut()?;
    if key_data.len() != viewing_key::LEN || !viewing_key::is_initialized(&key_data)? {
        return Err(MirrorPoolError::ViewingKeyNotInitialized.into());
    }
    if &viewing_key::authority(&key_data)? != authority_key.as_array() {
        return Err(MirrorPoolError::Unauthorized.into());
    }
    let rotations = viewing_key::rotate(&mut key_data, &viewing_pub)?;

    log!(
        "mirror-pool: register_viewing_key authority0={} key0={} rotations={}",
        authority_key.as_array()[0],
        viewing_pub[0],
        rotations
    );
    Ok(())
}
