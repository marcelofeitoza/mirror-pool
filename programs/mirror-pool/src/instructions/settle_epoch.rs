//! SETTLE_EPOCH: a rotating relay settles a whole epoch atomically.
//!
//! This is the privacy-critical half of the protocol:
//!
//! - Batch settlement puts every action of the window on ONE timestamp,
//!   defeating FIFO temporal matching (empirically the strongest attack on
//!   Tornado-style pools, up to 49% linkage).
//! - The relay pays the fees, so no participant wallet ever appears as the
//!   initiator of the executed action; the relay identity rotates per epoch
//!   so it does not itself become a stable linkage handle.
//! - The k-anonymity floor is enforced here: an epoch below `k_floor` rolls
//!   forward instead of executing. Never settle into a set small enough to
//!   deanonymize by elimination.
//! - Every executed action must be byte-shape identical (fixed ActionClass
//!   per pool): heterogeneous actions leak like mixed denominations.
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
//! 0. relay   signer      rotating fee payer submitting the batch
//! 1. pool    writable    initialized pool account
//! 2. epoch   writable    epoch account being settled
//! (v1 adds: instructions sysvar for Ed25519 introspection, one nullifier
//!  PDA per revealed nullifier, and the accounts of the pooled action)
//! ```

use pinocchio::{error::ProgramError, AccountView, ProgramResult};
use pinocchio_log::log;

use crate::{state::pool, wire, MirrorPoolError};

/// Header body length (wire header minus the tag byte): epoch(8) + n(4).
const HEADER_BODY_LEN: usize = wire::SETTLE_HEADER_LEN - 1;

pub fn process(accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    // Fail closed on shape before touching any account: parse the header,
    // bound the count, then require the EXACT total length. Trailing bytes
    // are malformed input, not padding.
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
    // Consumed one 32-byte chunk at a time by the nullifier-PDA loop in
    // TODO(v1) below.
    let _nullifiers = data[HEADER_BODY_LEN..].chunks_exact(wire::HASH_LEN);

    let (relay, pool_account, epoch_account) = match accounts {
        [relay, pool_account, epoch_account, ..] => (relay, pool_account, epoch_account),
        _ => return Err(ProgramError::NotEnoughAccountKeys),
    };
    if !relay.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !pool_account.is_writable() || !epoch_account.is_writable() {
        return Err(ProgramError::InvalidAccountData);
    }
    {
        let pool_data = pool_account.try_borrow()?;
        if pool_data.len() != pool::LEN || !pool::is_initialized(&pool_data)? {
            return Err(MirrorPoolError::PoolNotInitialized.into());
        }
    }

    // TODO(v1): the settlement core, in order:
    //  1. Window gate: read the Clock sysvar and require
    //     current_slot >= EpochSchedule::settle_slot(epoch_id), else
    //     MirrorPoolError::EpochNotClosed.
    //  2. k-floor gate: require epoch.nominal_k >= pool.k_floor, else
    //     MirrorPoolError::BelowKFloor and the epoch rolls forward. (nominal_k
    //     is the on-chain upper bound; the coordinator enforces the honest
    //     real_k that excludes operator and Sybil commitments before ever
    //     submitting.)
    //  3. Replay gate: for each nullifier, create its PDA (seeds =
    //     [b"nullifier", pool, nullifier]); an already-existing PDA means
    //     MirrorPoolError::NullifierSpent (technique: a per-nullifier PDA whose
    //     existence marks a spent nullifier, standard Solana anti-replay via
    //     PDA existence, including rent handling).
    //  4. Authorization: build the Ed25519 instruction-introspection hardening
    //     for the settlement authorization signature (technique: on-chain
    //     Ed25519 signature verification read from the instructions sysvar,
    //     standard Solana instruction introspection): read the instructions
    //     sysvar, pin the Ed25519 program id, reject the self-reference sentinel
    //     ix_index == 0xFFFF explicitly, require exactly one signature entry,
    //     validate every offset in the offsets table points inside that same
    //     instruction (no cross-instruction references), and bind the signed
    //     message to this exact settlement payload (pool, epoch_id, nullifier
    //     set hash).
    //  5. Execute the pool's fixed-shape action once per nullifier via CPI,
    //     byte-shape identical for every participant, then mark the epoch
    //     settled.
    log!(
        "mirror-pool: settle_epoch epoch={} n={} (skeleton, settlement not wired)",
        epoch_id,
        n_nullifiers as u64
    );
    Err(MirrorPoolError::NotImplemented.into())
}
