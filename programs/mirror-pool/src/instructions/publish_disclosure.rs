//! PUBLISH_DISCLOSURE: post one sealed disclosure about one's own settlement.
//!
//! The user seals `(epoch, secret)` for a single ZK opt-in action to an auditor's
//! registered viewing key (`mirror_core::disclosure`, which is
//! `mirror_core::encrypted_note`'s ECIES with a different plaintext) and posts the
//! ciphertext here. The reader recomputes `Poseidon(secret, actionHash, epoch)`
//! and `Poseidon(secret, epoch)` from it, which are the deposit leaf and the spend
//! tag, and can then find both ends of that one action on-chain. Nobody else
//! learns anything from the record beyond what the settlement already published.
//!
//! # The authentication is the address, not a check
//!
//! `action_hash` is NOT accepted from the caller. This handler recomputes
//! `Poseidon(recipientHi128, recipientLo128, amount)` from the SIGNING recipient's
//! address with the same `sol_poseidon` call `SETTLE_ZK` uses, and that value is
//! one of the record's PDA seeds. So:
//!
//! ```text
//! commitment = Poseidon(secret, actionHash, epoch)     <- the leaf binds actionHash
//! actionHash = Poseidon(recipient, amount)             <- which binds the recipient
//! record PDA = ["disc", pool, actionHash, viewPub]     <- derived from the signer
//! ```
//!
//! the only party who can write a record about a settlement is the address that
//! settlement was bound to pay - the address the depositor themselves chose inside
//! the commitment. Squatting another user's slot is not forbidden by a rule that
//! could be forgotten; it is an address that cannot be derived without their key.
//! An attacker registering garbage under an address THEY control occupies only
//! their own slot, which corresponds to a settlement to themselves.
//!
//! # What is validated
//!
//! In order, all fail-closed, all before anything is written:
//!
//! 1. Exact body length; a non-zero `amount`; recipient and payer signatures.
//! 2. The pool is a real, initialized, program-owned Pool.
//! 3. `amount` equals that pool's `zk_denomination`. A record about an amount the
//!    pool can never settle would be about nothing.
//! 4. The auditor's ViewingKey account is program-owned, v1, the right size, and
//!    sits at its own canonical `["view", authority]` PDA. The key and the
//!    auditor identity are READ FROM THAT ACCOUNT, never from instruction data,
//!    so a record cannot name a reader who never registered.
//! 5. The stored key and the blob's ephemeral public key both pass the structural
//!    X25519 test (canonical encoding, not small-order).
//! 6. The record's PDA is derived from the recomputed `action_hash`, and must not
//!    already exist (WRITE-ONCE).
//!
//! # What this instruction CANNOT check
//!
//! Stated plainly, because a disclosure primitive that overclaims is worse than
//! none:
//!
//! - **It cannot decrypt.** The program holds no secret, so it cannot verify that
//!   the blob opens at all, that it opens to a secret matching a real commitment,
//!   or that it was sealed to the key the record names. A false record is
//!   possible. What the design does instead is make one impossible to hide behind:
//!   it is signed by the settlement's own recipient, it occupies no one else's
//!   slot, and the reader detects the lie with one Poseidon hash (the recomputed
//!   leaf is simply not on-chain).
//! - **It cannot check that the disclosed commitment exists.** Nothing on-chain
//!   links a commitment to an address, which is the entire point of the pool.
//! - **It cannot enforce that a settlement happened**, and deliberately does not
//!   try: a user may want the record in place first. Whether the action settled is
//!   a lookup the reader does (the Nullifier PDA either exists or does not).
//!
//! # Body layout after the tag byte (see `wire::PUBLISH_DISCLOSURE_LEN`)
//!
//! ```text
//! [amount(8 LE)][blob(100)]
//! ```
//!
//! Accounts:
//!
//! ```text
//! 0. disclosure     writable   Disclosure PDA to create; seeds
//!                              [b"disc", pool, action_hash, auditor_view_pub]
//! 1. pool           readonly   the initialized Pool this settlement belongs to
//! 2. recipient      signer     the address bound by the settlement's actionHash
//! 3. auditor_view   readonly   the reader's ViewingKey PDA; seeds
//!                              [b"view", auditor]
//! 4. payer          signer     writable; funds the record's rent
//! 5. system_program            for the create-account CPI
//! ```
//!
//! A note on WHO SHOULD PAY. The rent payer is a separate account on purpose, but
//! paying from a wallet that the settlement did not already expose links that
//! wallet to this action. The CLI pays from the recipient by default and says so.

use pinocchio::{cpi::Seed, error::ProgramError, AccountView, Address, ProgramResult};
use pinocchio_log::log;

use crate::{
    action, pda,
    state::{disclosure, pool, viewing_key},
    wire, MirrorPoolError,
};

/// Instruction body length (wire length minus the tag byte).
const BODY_LEN: usize = wire::PUBLISH_DISCLOSURE_LEN - 1;

/// Body field offsets (after the tag byte is stripped).
const AMOUNT_OFF: usize = 0;
const BLOB_OFF: usize = 8;

pub fn process(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    // (1) Fail closed on shape: exact length, nothing more. The blob length is
    // part of the layout, so a truncated or padded ciphertext never reaches the
    // account.
    if data.len() != BODY_LEN {
        return Err(MirrorPoolError::MalformedInstruction.into());
    }
    let amount = u64::from_le_bytes(
        data[AMOUNT_OFF..AMOUNT_OFF + 8]
            .try_into()
            .map_err(|_| MirrorPoolError::MalformedInstruction)?,
    );
    let blob = data
        .get(BLOB_OFF..BLOB_OFF + wire::DISCLOSURE_BLOB_LEN)
        .ok_or(MirrorPoolError::MalformedInstruction)?;
    if amount == 0 {
        return Err(ProgramError::InvalidArgument);
    }

    let [disclosure_account, pool_account, recipient, auditor_view_key, payer, _system_program, ..] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !recipient.is_signer() || !payer.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !disclosure_account.is_writable() {
        return Err(ProgramError::InvalidAccountData);
    }

    // (2) The pool must be a real, initialized pool owned by this program.
    if !pool_account.owned_by(program_id) {
        return Err(MirrorPoolError::PoolNotInitialized.into());
    }
    let zk_denomination = {
        let pool_data = pool_account.try_borrow()?;
        if pool_data.len() != pool::LEN || !pool::is_initialized(&pool_data)? {
            return Err(MirrorPoolError::PoolNotInitialized.into());
        }
        pool::zk_denomination(&pool_data)?
    };

    // (3) The amount must be one this pool can actually settle. It is also half of
    // the recomputed action hash, so an off-denomination record would sit at an
    // address no settlement of this pool can ever correspond to.
    if amount != zk_denomination {
        return Err(MirrorPoolError::DenominationMismatch.into());
    }

    // (4) The reader must be a REGISTERED viewing key: program-owned, v1, the
    // right size, and at its own canonical PDA. Both the auditor identity and the
    // key are read from the account, never from instruction data.
    if !auditor_view_key.owned_by(program_id) {
        return Err(MirrorPoolError::ViewingKeyNotInitialized.into());
    }
    let (auditor, auditor_view_pub) = {
        let key_data = auditor_view_key.try_borrow()?;
        if key_data.len() != viewing_key::LEN || !viewing_key::is_initialized(&key_data)? {
            return Err(MirrorPoolError::ViewingKeyNotInitialized.into());
        }
        (
            viewing_key::authority(&key_data)?,
            viewing_key::viewing_pub(&key_data)?,
        )
    };
    // Re-derive the ViewingKey PDA from the authority it claims, so a caller
    // cannot pass some other program-owned account that happens to parse as a
    // registration.
    pda::verify_pda(
        auditor_view_key,
        &[pda::VIEWING_KEY_SEED, &auditor],
        program_id,
    )?;

    // (5) Structural validation. The registered key is re-checked (it was checked
    // at registration; a second check costs nothing and keeps this handler sound
    // on its own), and the blob's ephemeral key is checked because a small-order
    // or aliased ephemeral is exactly the case where a user believes they sealed
    // to one reader and in fact sealed to everybody.
    if !viewing_key::is_acceptable_viewing_pub(&auditor_view_pub) {
        return Err(MirrorPoolError::InvalidViewingKey.into());
    }
    let ephemeral_pub: [u8; 32] = blob
        .get(disclosure::BLOB_EPHEMERAL_PUB_OFF..disclosure::BLOB_EPHEMERAL_PUB_OFF + 32)
        .ok_or(MirrorPoolError::InvalidDisclosureBlob)?
        .try_into()
        .map_err(|_| MirrorPoolError::InvalidDisclosureBlob)?;
    if !viewing_key::is_acceptable_viewing_pub(&ephemeral_pub) {
        return Err(MirrorPoolError::InvalidDisclosureBlob.into());
    }

    // (6) Recompute the action hash from the SIGNING recipient - the same hash
    // SETTLE_ZK binds - and derive the record's address from it. This is the
    // authentication: the seed is a function of a key the publisher must hold.
    let action_hash = action::transfer_action_hash(recipient.address().as_array(), amount);
    let pool_key = pool_account.address();
    let bump = pda::verify_pda(
        disclosure_account,
        &[
            pda::DISCLOSURE_SEED,
            pool_key.as_ref(),
            &action_hash,
            &auditor_view_pub,
        ],
        program_id,
    )?;
    // WRITE-ONCE: a live account already has data.
    if disclosure_account.data_len() != 0 {
        return Err(MirrorPoolError::DisclosureAlreadyInitialized.into());
    }

    let bump_seed = [bump];
    let signer_seeds = [
        Seed::from(pda::DISCLOSURE_SEED),
        Seed::from(pool_key.as_ref()),
        Seed::from(&action_hash[..]),
        Seed::from(&auditor_view_pub[..]),
        Seed::from(&bump_seed[..]),
    ];
    pda::create_pda_account(
        payer,
        disclosure_account,
        program_id,
        disclosure::LEN,
        &signer_seeds,
    )?;

    let mut record = disclosure_account.try_borrow_mut()?;
    if disclosure::is_initialized(&record)? {
        return Err(MirrorPoolError::DisclosureAlreadyInitialized.into());
    }
    disclosure::init(
        &mut record,
        pool_key.as_array(),
        recipient.address().as_array(),
        &auditor,
        &auditor_view_pub,
        &action_hash,
        amount,
        bump,
        blob,
    )?;

    log!(
        "mirror-pool: publish_disclosure pool0={} recipient0={} auditor0={} action0={}",
        pool_key.as_array()[0],
        recipient.address().as_array()[0],
        auditor[0],
        action_hash[0]
    );
    Ok(())
}
