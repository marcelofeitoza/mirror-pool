//! Program-derived address helpers: seed prefixes, derivation, and the
//! system-program CPI that creates a program-owned PDA.
//!
//! All three account kinds are PDAs so their addresses are a pure function of
//! the pool and (for epoch/nullifier) the epoch and nullifier bytes. That is
//! what makes the on-chain checks sound: a caller cannot substitute a forged
//! account for a real one because the program re-derives the expected address
//! and rejects any mismatch ([`MirrorPoolError::InvalidPda`]).
//!
//! ```text
//! Pool PDA       seeds = [b"pool",  authority(32)]
//! Epoch PDA      seeds = [b"epoch", pool(32), epoch_id(8 LE)]
//! Nullifier PDA  seeds = [b"nf",    pool(32), epoch_id(8 LE), nullifier(32)]
//! Dwell PDA      seeds = [b"dwell", pool(32), participant(32)]
//! ```

use pinocchio::{
    cpi::{Seed, Signer},
    error::ProgramError,
    sysvars::{rent::Rent, Sysvar},
    AccountView, Address, ProgramResult,
};
use pinocchio_system::instructions::CreateAccount;

/// Seed prefix for the Pool PDA.
pub const POOL_SEED: &[u8] = b"pool";
/// Seed prefix for the Epoch PDA.
pub const EPOCH_SEED: &[u8] = b"epoch";
/// Seed prefix for the Nullifier PDA.
pub const NULLIFIER_SEED: &[u8] = b"nf";
/// Seed prefix for the per-participant Dwell PDA (crowd-path incentive).
pub const DWELL_SEED: &[u8] = b"dwell";

/// Find a program-derived address and its bump.
///
/// On-chain this is the `sol_try_find_program_address` syscall. The host build
/// (integration tests load the compiled SBF program into mollusk, so this path
/// never executes off-chain) links a stub instead of pulling in curve25519, so
/// the deployed `.so` stays free of that dependency.
#[cfg(any(target_os = "solana", target_arch = "bpf"))]
#[inline(always)]
pub fn find_pda(seeds: &[&[u8]], program_id: &Address) -> (Address, u8) {
    Address::find_program_address(seeds, program_id)
}

#[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
#[inline(always)]
pub fn find_pda(_seeds: &[&[u8]], _program_id: &Address) -> (Address, u8) {
    unreachable!("PDA derivation uses an on-chain syscall and never runs on the host")
}

/// Verify `account` is exactly the PDA derived from `seeds` under `program_id`,
/// returning the bump for later signed CPIs. Fails closed on any mismatch.
#[inline]
pub fn verify_pda(
    account: &AccountView,
    seeds: &[&[u8]],
    program_id: &Address,
) -> Result<u8, ProgramError> {
    let (expected, bump) = find_pda(seeds, program_id);
    if account.address() != &expected {
        return Err(crate::MirrorPoolError::InvalidPda.into());
    }
    Ok(bump)
}

/// Create a rent-exempt, program-owned account at a PDA, signing with its
/// seeds. `signer_seeds` must be the full seed set including the trailing bump.
#[inline]
pub fn create_pda_account(
    payer: &AccountView,
    new_account: &AccountView,
    owner: &Address,
    space: usize,
    signer_seeds: &[Seed],
) -> ProgramResult {
    let lamports = Rent::get()?.try_minimum_balance(space)?;
    let signer = Signer::from(signer_seeds);
    CreateAccount {
        from: payer,
        to: new_account,
        lamports,
        space: space as u64,
        owner,
    }
    .invoke_signed(&[signer])
}
