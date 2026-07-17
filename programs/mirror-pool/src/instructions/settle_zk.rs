//! SETTLE_ZK: settle ONE ZK opt-in membership.
//!
//! This is the ZK-deniable half of the protocol. A relay proves in zero
//! knowledge that an output corresponds to SOME member committed via
//! `COMMIT_DEPOSIT`, without revealing which one, and the action executes to a
//! FRESH address. The membership proof (Groth16 over the same Poseidon
//! accumulator the crowd path uses) is verified on-chain with `groth16-solana`.
//!
//! One membership settles per call so the transaction and compute stay well
//! inside limits (data is ~401 bytes, verification is < ~200k CU); the
//! coordinator batches independent memberships across calls.
//!
//! Body layout after the tag byte (see `wire::SETTLE_ZK_LEN`):
//!
//! ```text
//! [epoch(8 LE)][amount(8 LE)]
//!   [proof_a(64)][proof_b(128)][proof_c(64)]
//!   [root(32)][nullifierHash(32)][actionHash(32)][epoch(32 BE)]
//! ```
//!
//! The four trailing 32-byte values are the Groth16 public inputs in the FIXED
//! order [root, nullifierHash, actionHash, epoch].
//!
//! Accounts:
//!
//! ```text
//! 0. pool           writable   initialized Pool PDA (holds the escrow)
//! 1. authority      signer     writable; MUST equal pool.authority; pays nf rent
//! 2. nullifier      writable   Nullifier PDA to create (anti-replay);
//!                              seeds [b"nf", pool, epoch_id LE, nullifierHash]
//! 3. recipient      writable   fresh output address; receives the escrow
//! 4. system_program            for the create-account CPI
//! 5. clock          sysvar     current slot for the window-closed gate
//! ```
//!
//! Checks run IN ORDER and fail closed: (1) authority is a signer and equals
//! pool.authority; (2) the epoch's `u64` header agrees with the 32-byte public
//! input; (3) the epoch window has closed; (4) `root` is a known recent root;
//! (5) the recomputed `actionHash` from (recipient, amount) equals the proof's
//! `actionHash` so the relay cannot redirect the escrow; (6) the nullifier PDA
//! does not yet exist (created here; NullifierSpent on replay); (7) the Groth16
//! proof verifies; then (8) the action executes (transfer the escrow to the
//! recipient).
//!
//! Extension note: swap/stake-from-pool are the same pattern with a different
//! step (8) - execute a different action from the pool authority via CPI
//! (e.g. a Jupiter swap or an SPL stake-pool deposit) instead of a lamport
//! transfer. Those are documented follow-ups; the anonymity mechanics
//! (membership proof + nullifier + recipient binding) are identical.

use groth16_solana::groth16::Groth16Verifier;
use pinocchio::{
    cpi::Seed,
    error::ProgramError,
    sysvars::{clock::Clock, rent::Rent, Sysvar},
    AccountView, Address, ProgramResult,
};
use pinocchio_log::log;

use crate::{
    action, pda,
    state::{nullifier, pool},
    vk::VERIFYINGKEY,
    wire, MirrorPoolError,
};

/// Instruction body length (wire length minus the tag byte).
const BODY_LEN: usize = wire::SETTLE_ZK_LEN - 1;

// Body field offsets (after the tag byte is stripped).
const EPOCH_OFF: usize = 0;
const AMOUNT_OFF: usize = 8;
const PROOF_A_OFF: usize = 16;
const PROOF_B_OFF: usize = PROOF_A_OFF + wire::PROOF_A_LEN; // 80
const PROOF_C_OFF: usize = PROOF_B_OFF + wire::PROOF_B_LEN; // 208
const ROOT_OFF: usize = PROOF_C_OFF + wire::PROOF_C_LEN; // 272
const NULLIFIER_OFF: usize = ROOT_OFF + wire::PUBLIC_INPUT_LEN; // 304
const ACTION_HASH_OFF: usize = NULLIFIER_OFF + wire::PUBLIC_INPUT_LEN; // 336
const EPOCH_PUB_OFF: usize = ACTION_HASH_OFF + wire::PUBLIC_INPUT_LEN; // 368

pub fn process(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    // Fail closed on shape: exact length, nothing more.
    if data.len() != BODY_LEN {
        return Err(MirrorPoolError::MalformedInstruction.into());
    }
    let epoch_id = u64::from_le_bytes(
        data[EPOCH_OFF..EPOCH_OFF + 8]
            .try_into()
            .map_err(|_| MirrorPoolError::MalformedInstruction)?,
    );
    let amount = u64::from_le_bytes(
        data[AMOUNT_OFF..AMOUNT_OFF + 8]
            .try_into()
            .map_err(|_| MirrorPoolError::MalformedInstruction)?,
    );
    let proof_a: [u8; 64] = data[PROOF_A_OFF..PROOF_A_OFF + wire::PROOF_A_LEN]
        .try_into()
        .map_err(|_| MirrorPoolError::MalformedInstruction)?;
    let proof_b: [u8; 128] = data[PROOF_B_OFF..PROOF_B_OFF + wire::PROOF_B_LEN]
        .try_into()
        .map_err(|_| MirrorPoolError::MalformedInstruction)?;
    let proof_c: [u8; 64] = data[PROOF_C_OFF..PROOF_C_OFF + wire::PROOF_C_LEN]
        .try_into()
        .map_err(|_| MirrorPoolError::MalformedInstruction)?;
    let root: [u8; 32] = data[ROOT_OFF..ROOT_OFF + 32]
        .try_into()
        .map_err(|_| MirrorPoolError::MalformedInstruction)?;
    let nullifier_hash: [u8; 32] = data[NULLIFIER_OFF..NULLIFIER_OFF + 32]
        .try_into()
        .map_err(|_| MirrorPoolError::MalformedInstruction)?;
    let action_hash: [u8; 32] = data[ACTION_HASH_OFF..ACTION_HASH_OFF + 32]
        .try_into()
        .map_err(|_| MirrorPoolError::MalformedInstruction)?;
    let epoch_pub: [u8; 32] = data[EPOCH_PUB_OFF..EPOCH_PUB_OFF + 32]
        .try_into()
        .map_err(|_| MirrorPoolError::MalformedInstruction)?;

    let [pool_account, authority, nullifier_account, recipient, _system_program, clock_account, ..] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // (1) Authority must be a signer AND equal the pool's stored authority.
    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !pool_account.is_writable() {
        return Err(ProgramError::InvalidAccountData);
    }
    if !nullifier_account.is_writable() || !recipient.is_writable() {
        return Err(ProgramError::InvalidAccountData);
    }
    if !pool_account.owned_by(program_id) {
        return Err(MirrorPoolError::PoolNotInitialized.into());
    }
    let epoch_slots = {
        let pool_data = pool_account.try_borrow()?;
        if pool_data.len() != pool::LEN || !pool::is_initialized(&pool_data)? {
            return Err(MirrorPoolError::PoolNotInitialized.into());
        }
        if &pool::authority(&pool_data)? != authority.address().as_array() {
            return Err(MirrorPoolError::Unauthorized.into());
        }
        pool::epoch_slots(&pool_data)?
    };
    if epoch_slots == 0 {
        return Err(ProgramError::InvalidAccountData);
    }

    // (2) The two epoch encodings must agree: the 32-byte public input is the
    // big-endian encoding of the u64 header, so the proof and the seed/gate use
    // the same epoch.
    let mut expected_epoch_pub = [0u8; 32];
    expected_epoch_pub[24..].copy_from_slice(&epoch_id.to_be_bytes());
    if epoch_pub != expected_epoch_pub {
        return Err(MirrorPoolError::EpochMismatch.into());
    }

    // (3) The epoch window must have closed: current_slot >= (epoch+1)*slots.
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

    // (4) The proof's root must be a known recent root (proofs are made against a
    // root snapshot, so any of the last ROOT_HISTORY_SIZE roots is acceptable).
    {
        let pool_data = pool_account.try_borrow()?;
        if !pool::is_known_root(&pool_data, &root)? {
            return Err(MirrorPoolError::RootNotKnown.into());
        }
    }

    // (5) Recipient/amount binding: the actionHash the member committed to must
    // equal the hash of the (recipient, amount) we are about to execute, so a
    // relay cannot redirect the escrow to a different address or amount.
    let expected_action_hash = action::transfer_action_hash(recipient.address().as_array(), amount);
    if expected_action_hash != action_hash {
        return Err(MirrorPoolError::ActionHashMismatch.into());
    }

    // (6) Anti-replay: the Nullifier PDA must not already exist. Its existence
    // (program-owned) marks the nullifier spent; create it, else NullifierSpent.
    let pool_key = pool_account.address();
    let epoch_le = epoch_id.to_le_bytes();
    let nf_bump = pda::verify_pda(
        nullifier_account,
        &[
            pda::NULLIFIER_SEED,
            pool_key.as_ref(),
            &epoch_le,
            &nullifier_hash,
        ],
        program_id,
    )?;
    if nullifier_account.owned_by(program_id) {
        return Err(MirrorPoolError::NullifierSpent.into());
    }
    let bump_seed = [nf_bump];
    let signer_seeds = [
        Seed::from(pda::NULLIFIER_SEED),
        Seed::from(pool_key.as_ref()),
        Seed::from(&epoch_le[..]),
        Seed::from(&nullifier_hash[..]),
        Seed::from(&bump_seed[..]),
    ];
    pda::create_pda_account(
        authority,
        nullifier_account,
        program_id,
        nullifier::LEN,
        &signer_seeds,
    )?;
    {
        let mut nf_data = nullifier_account.try_borrow_mut()?;
        nf_data[0] = nullifier::SPENT;
    }

    // (7) Verify the Groth16 membership proof against the fixed public-input
    // order [root, nullifierHash, actionHash, epoch]. `verify()` also rejects any
    // public input that is not a canonical BN254 scalar.
    let public_inputs: [[u8; 32]; wire::N_PUBLIC_INPUTS] =
        [root, nullifier_hash, action_hash, epoch_pub];
    let mut verifier =
        Groth16Verifier::new(&proof_a, &proof_b, &proof_c, &public_inputs, &VERIFYINGKEY)
            .map_err(|_| MirrorPoolError::ProofVerificationFailed)?;
    verifier
        .verify()
        .map_err(|_| MirrorPoolError::ProofVerificationFailed)?;

    // (8) Execute the action: transfer the escrow from the pool to the fresh
    // recipient. The pool is program-owned, so move lamports directly (a system
    // transfer only moves lamports out of system-owned accounts), keeping the
    // pool rent-exempt.
    let rent_min = Rent::get()?.try_minimum_balance(pool::LEN)?;
    let pool_balance = pool_account.lamports();
    let remaining = pool_balance
        .checked_sub(amount)
        .ok_or(MirrorPoolError::InsufficientEscrow)?;
    if remaining < rent_min {
        return Err(MirrorPoolError::InsufficientEscrow.into());
    }
    let recipient_balance = recipient
        .lamports()
        .checked_add(amount)
        .ok_or(MirrorPoolError::ArithmeticOverflow)?;
    pool_account.set_lamports(remaining);
    recipient.set_lamports(recipient_balance);

    log!(
        "mirror-pool: settle_zk epoch={} amount={} nf0={} recipient0={}",
        epoch_id,
        amount,
        nullifier_hash[0],
        recipient.address().as_array()[0]
    );
    Ok(())
}
