//! SETTLE_ZK: settle ONE ZK opt-in membership.
//!
//! This is the ZK-deniable half of the protocol. A relay proves in zero
//! knowledge that an output corresponds to SOME member of the accumulator,
//! without revealing which one, and the escrow is released to the address the
//! member bound at commit time. The membership proof (Groth16 over the same
//! Poseidon accumulator the crowd path uses) is verified on-chain with
//! `groth16-solana`.
//!
//! One membership settles per call so the transaction and compute stay well
//! inside limits (data is ~401 bytes, verification is < ~200k CU); the
//! coordinator batches independent memberships across calls.
//!
//! # What this instruction does NOT check
//!
//! Stated here because the anonymity of this path depends on it, and because
//! the checks below are easy to mistake for guarantees they do not give. Each
//! item is pinned by a test in `tests/integration.rs`.
//!
//! - **No k-anonymity floor.** Unlike `SETTLE_EPOCH`, this handler never reads
//!   `pool.k_floor` and never touches an Epoch account: it will settle a window
//!   that holds a single commitment. That is deliberate. The crowd path can
//!   enforce a floor cheaply because an under-floor epoch simply ROLLS FORWARD
//!   and nobody loses anything. On this path the escrow's ONLY exit is a
//!   `SETTLE_ZK` bound by `actionHash` to one `(recipient, amount)` and by the
//!   leaf to one epoch: there is no refund instruction and no re-binding, so a
//!   settle-time floor would convert "thin anonymity" into "permanently stranded
//!   escrow" for every window that never reaches it. The floor is enforced
//!   client-side at proof time instead (`mirror-cli prove`), which is both
//!   sufficient and safe: only the secret holder can produce this proof, the
//!   window's size is public before they decide, and declining costs them
//!   nothing but time. See `settle_zk_ignores_k_floor_and_needs_no_epoch_account`.
//! - **No denomination, and no link between `amount` and any single deposit.**
//!   The escrow is a pool-wide pot. Nothing ties the settled `amount` to what
//!   the leaf's owner escrowed at `COMMIT_DEPOSIT`, and a crowd `COMMIT` leaf
//!   (which escrows nothing) satisfies the membership circuit just as well as a
//!   deposit leaf, since both paths append the same `Poseidon(secret,
//!   actionHash, epoch)` shape to the same tree. A v1 pool therefore must not
//!   hold value it cannot afford to lose. Closing this needs a fixed
//!   denomination plus domain-separated leaves, which is a layout and circuit
//!   change; a half fix would read like a full one. See
//!   `settle_zk_escrow_is_a_pool_wide_pot_any_leaf_can_spend`.
//! - **No recipient freshness.** `recipient` is only required to match the
//!   proof's `actionHash`. "Fresh address" is a CLIENT convention, not a
//!   property this program enforces, and it is not meaningfully enforceable
//!   here: emptiness (`lamports == 0`) is a proxy for "unused" that says nothing
//!   about linkability, an address is only unlinkable until its owner sweeps it,
//!   and, worst of all, anyone who learns the bound address could permanently
//!   strand the escrow by dusting it with one lamport. See
//!   `settle_zk_accepts_a_recipient_that_is_not_fresh`.
//!
//! # What the anonymity set actually is
//!
//! The proof hides the member among EVERY leaf under the proven root. The two
//! values this instruction publishes then narrow what an observer must consider:
//! the `epoch` public input (the leaf binds it, so only leaves committed to that
//! epoch can be the source) and `amount` (escrow amounts are public at
//! `COMMIT_DEPOSIT`). So the set that actually covers an output is the window's
//! ZK deposits OF THE SAME AMOUNT. That per-window narrowing is the price paid
//! for the timing defense - binding the epoch is what forces every settle of a
//! window to wait for the same close, which is what denies the FIFO matching
//! that is the strongest published attack on this class of pool.
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
//! 3. recipient      writable   the address bound by actionHash; receives the
//!                              escrow. Clients bind a fresh one; the program
//!                              only checks the binding (see above)
//! 4. system_program            for the create-account CPI
//! 5. clock          sysvar     current slot for the window-closed gate
//! 6. vk_registry    readonly   write-once, digest-pinned membership verifying
//!                              key; seeds [b"vk", CIRCUIT_MEMBERSHIP]
//! ```
//!
//! Checks run IN ORDER and fail closed: (1) authority is a signer and equals
//! pool.authority; (2) the epoch's `u64` header agrees with the 32-byte public
//! input; (3) the epoch window has closed; (4) `root` is a known recent root;
//! (5) the recomputed `actionHash` from (recipient, amount) equals the proof's
//! `actionHash` so the relay cannot redirect the escrow; (6) the nullifier PDA
//! does not yet exist (created here; NullifierSpent on replay); (7) the verifying
//! key is loaded from its registry account and re-pinned to the compile-time
//! digest, and the Groth16 proof verifies under it; then (8) the action executes
//! (transfer the escrow to the recipient).
//!
//! # Where the verifying key comes from
//!
//! Account 6, not this program's `.rodata`. It is a program-owned PDA that
//! `INIT_VK` filled ONCE and that no instruction can rewrite, and step (7)
//! re-checks its SHA-256 against [`crate::vk_digest::MEMBERSHIP_VK_SHA256`]
//! before the bytes reach the verifier. The point of the account is that the key
//! in force is readable on-chain by anybody; the point of the digest is that
//! reading it is all anybody can do with it. Without that second half, moving a
//! verifying key into account data hands the root of trust to whoever can write
//! the account. See `docs/VK_REGISTRY.md`.
//!
//! Extension note: swap/stake-from-pool are the same pattern with a different
//! step (8) - execute a different action from the pool authority via CPI
//! (e.g. a Jupiter swap or an SPL stake-pool deposit) instead of a lamport
//! transfer. Those are documented follow-ups; the anonymity mechanics
//! (membership proof + nullifier + recipient binding) are identical.

use pinocchio::{
    cpi::Seed,
    error::ProgramError,
    sysvars::{clock::Clock, rent::Rent, Sysvar},
    AccountView, Address, ProgramResult,
};
use pinocchio_log::log;

use crate::{
    action, pda,
    state::{nullifier, pool, vk_registry},
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

    let [pool_account, authority, nullifier_account, recipient, _system_program, clock_account, vk_account, ..] =
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
    //
    // The verifying key is READ FROM THE CHAIN, not from this program's code:
    // `vk_registry::verify_pinned` loads the write-once VkRegistry PDA and re-checks
    // its contents against the digest pinned in `crate::vk_digest` before the key
    // touches the verifier. So the key in force is publicly readable, and is
    // still exactly the key the bytecode committed to.
    let public_inputs: [[u8; 32]; wire::N_PUBLIC_INPUTS] =
        [root, nullifier_hash, action_hash, epoch_pub];
    vk_registry::verify_pinned(
        vk_account,
        program_id,
        wire::CIRCUIT_MEMBERSHIP,
        &proof_a,
        &proof_b,
        &proof_c,
        &public_inputs,
    )?;

    // (8) Execute the action: transfer the escrow from the pool to the bound
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
