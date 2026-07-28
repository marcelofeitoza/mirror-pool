//! SETTLE_ZK_ASSOCIATED: settle ONE ZK opt-in membership that ALSO carries a
//! curated-set (association) inclusion proof.
//!
//! This is the OPT-IN compliance path. It does everything `SETTLE_ZK` does, plus
//! it requires the Groth16 proof to additionally show that the settling
//! commitment is a leaf of a specific curator's published set - enforced HERE, in
//! the execute path, not merely checked off-chain by a wallet that could skip it.
//! A settlement that lands through this instruction is on-chain evidence that an
//! association proof verified; a settlement that lands through `SETTLE_ZK` is
//! not, and the two are distinguishable by anyone reading the chain because they
//! are different instructions.
//!
//! It is an ADDITIVE, PARALLEL path. `SETTLE_ZK` is untouched and still settles
//! without any curator involvement, so this instruction adds an attestation
//! users may opt into; it does not add a gate they must pass. There is
//! deliberately NO pool-level flag that makes association proofs mandatory: such
//! a flag would hand the curator a kill switch over the pool. See
//! `docs/COMPLIANCE.md`.
//!
//! Body layout after the tag byte (see `wire::SETTLE_ZK_ASSOCIATED_LEN`):
//!
//! ```text
//! [epoch(8 LE)][amount(8 LE)]
//!   [proof_a(64)][proof_b(128)][proof_c(64)]
//!   [root(32)][nullifierHash(32)][actionHash(32)][epoch(32 BE)][associationRoot(32)]
//! ```
//!
//! The five trailing 32-byte values are the Groth16 public inputs in the FIXED
//! order [root, nullifierHash, actionHash, epoch, associationRoot]. The first
//! four are byte-for-byte `SETTLE_ZK`'s, in the same order and at the same
//! offsets; this layout is a strict EXTENSION with `associationRoot` appended.
//!
//! Accounts (0..=5 are exactly `SETTLE_ZK`'s, in the same order; 6 is new):
//!
//! ```text
//! 0. pool           writable   initialized Pool PDA (holds the escrow)
//! 1. authority      signer     writable; MUST equal pool.authority; pays nf rent
//! 2. nullifier      writable   Nullifier PDA to create (anti-replay);
//!                              seeds [b"nf", pool, epoch_id LE, nullifierHash]
//! 3. recipient      writable   fresh output address; receives the escrow
//! 4. system_program            for the create-account CPI
//! 5. clock          sysvar     current slot for the window-closed gate
//! 6. assoc          readonly   AssociationSet PDA; seeds [b"assoc", pool, curator]
//! 7. vk_registry    readonly   write-once, digest-pinned ASSOCIATION verifying
//!                              key; seeds [b"vk", CIRCUIT_ASSOCIATION]
//! ```
//!
//! # Where the verifying key comes from
//!
//! Account 7, not this program's `.rodata`. It is a program-owned PDA that
//! `INIT_VK` filled ONCE and that no instruction can rewrite, and step (8)
//! re-checks its SHA-256 against [`crate::vk_digest::ASSOCIATION_VK_SHA256`]
//! before the bytes reach the verifier. Because the registry PDA is keyed by
//! circuit id, passing the MEMBERSHIP registry here fails on the PDA derivation:
//! this instruction can only ever verify under the association key, exactly as
//! it could when that key was a compile-time constant. See
//! `docs/VK_REGISTRY.md`.
//!
//! The nullifier PDA uses the SAME seeds as `SETTLE_ZK`, so the two paths share
//! one spent-set: a commitment cannot be settled once with an attestation and
//! again without one.
//!
//! Checks run IN ORDER and fail closed: (1) authority is a signer and equals
//! pool.authority; (2) the epoch's `u64` header agrees with the 32-byte public
//! input; (3) the epoch window has closed; (4) `root` is a known recent POOL
//! root; (5) `associationRoot` is a known recent root of the passed
//! AssociationSet, which must be program-owned, initialized, bound to THIS pool,
//! and sit at its own derived PDA; (6) the recomputed `actionHash` from
//! (recipient, amount) equals the proof's `actionHash`; (7) the nullifier PDA
//! does not yet exist (created here); (8) the Groth16 proof verifies against the
//! ASSOCIATION verifying key over all five public inputs; then (9) the action
//! executes.

use pinocchio::{
    cpi::Seed,
    error::ProgramError,
    sysvars::{clock::Clock, rent::Rent, Sysvar},
    AccountView, Address, ProgramResult,
};
use pinocchio_log::log;

use crate::{
    action, pda,
    state::{association, nullifier, pool, vk_registry},
    wire, MirrorPoolError,
};

/// Instruction body length (wire length minus the tag byte).
const BODY_LEN: usize = wire::SETTLE_ZK_ASSOCIATED_LEN - 1;

// Body field offsets (after the tag byte is stripped). The first eight fields sit
// at exactly the offsets `settle_zk` uses; only `ASSOC_ROOT_OFF` is new.
const EPOCH_OFF: usize = 0;
const AMOUNT_OFF: usize = 8;
const PROOF_A_OFF: usize = 16;
const PROOF_B_OFF: usize = PROOF_A_OFF + wire::PROOF_A_LEN; // 80
const PROOF_C_OFF: usize = PROOF_B_OFF + wire::PROOF_B_LEN; // 208
const ROOT_OFF: usize = PROOF_C_OFF + wire::PROOF_C_LEN; // 272
const NULLIFIER_OFF: usize = ROOT_OFF + wire::PUBLIC_INPUT_LEN; // 304
const ACTION_HASH_OFF: usize = NULLIFIER_OFF + wire::PUBLIC_INPUT_LEN; // 336
const EPOCH_PUB_OFF: usize = ACTION_HASH_OFF + wire::PUBLIC_INPUT_LEN; // 368
const ASSOC_ROOT_OFF: usize = EPOCH_PUB_OFF + wire::PUBLIC_INPUT_LEN; // 400

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
    let assoc_root: [u8; 32] = data[ASSOC_ROOT_OFF..ASSOC_ROOT_OFF + 32]
        .try_into()
        .map_err(|_| MirrorPoolError::MalformedInstruction)?;

    let [pool_account, authority, nullifier_account, recipient, _system_program, clock_account, assoc_account, vk_account, ..] =
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

    // (2) The two epoch encodings must agree.
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

    // (4) The proof's pool root must be a known recent root.
    {
        let pool_data = pool_account.try_borrow()?;
        if !pool::is_known_root(&pool_data, &root)? {
            return Err(MirrorPoolError::RootNotKnown.into());
        }
    }

    // (5) The association root must be a recently published root of a REAL
    // association set for THIS pool. Every part of that sentence is checked:
    // program ownership, exact length, initialized version, the stored pool
    // binding, the PDA derivation from (stored pool, stored curator), and finally
    // ring membership. Skipping any of them would let a caller pass a
    // self-authored account and self-attest.
    let pool_key = pool_account.address();
    {
        if !assoc_account.owned_by(program_id) {
            return Err(MirrorPoolError::AssociationNotInitialized.into());
        }
        let assoc_data = assoc_account.try_borrow()?;
        if assoc_data.len() != association::LEN || !association::is_initialized(&assoc_data)? {
            return Err(MirrorPoolError::AssociationNotInitialized.into());
        }
        let stored_pool = association::pool(&assoc_data)?;
        if &stored_pool != pool_key.as_array() {
            return Err(MirrorPoolError::AssociationPoolMismatch.into());
        }
        let stored_curator = association::curator(&assoc_data)?;
        pda::verify_pda(
            assoc_account,
            &[pda::ASSOCIATION_SEED, &stored_pool, &stored_curator],
            program_id,
        )?;
        if !association::is_known_root(&assoc_data, &assoc_root)? {
            return Err(MirrorPoolError::AssociationRootNotKnown.into());
        }
    }

    // (6) Recipient/amount binding.
    let expected_action_hash = action::transfer_action_hash(recipient.address().as_array(), amount);
    if expected_action_hash != action_hash {
        return Err(MirrorPoolError::ActionHashMismatch.into());
    }

    // (7) Anti-replay: the Nullifier PDA must not already exist. Same seeds as
    // SETTLE_ZK, so both settle paths share one spent-set.
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

    // (8) Verify the Groth16 association proof against the fixed public-input
    // order [root, nullifierHash, actionHash, epoch, associationRoot], using the
    // ASSOCIATION verifying key (a different key from the membership one: a
    // membership proof can never satisfy this instruction, and vice versa).
    // `verify()` also rejects any public input that is not a canonical BN254
    // scalar.
    //
    // The key is READ FROM THE CHAIN, from the write-once VkRegistry PDA for
    // CIRCUIT_ASSOCIATION, and re-pinned to the compile-time digest before it
    // touches the verifier.
    let public_inputs: [[u8; 32]; wire::ASSOCIATION_N_PUBLIC_INPUTS] =
        [root, nullifier_hash, action_hash, epoch_pub, assoc_root];
    vk_registry::verify_pinned(
        vk_account,
        program_id,
        wire::CIRCUIT_ASSOCIATION,
        &proof_a,
        &proof_b,
        &proof_c,
        &public_inputs,
    )?;

    // (9) Execute the action: transfer the escrow from the pool to the fresh
    // recipient, keeping the pool rent-exempt.
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
        "mirror-pool: settle_zk_associated epoch={} amount={} nf0={} assocRoot0={}",
        epoch_id,
        amount,
        nullifier_hash[0],
        assoc_root[0]
    );
    Ok(())
}
