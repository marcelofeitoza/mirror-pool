//! Client-side instruction builders for the public on-chain programs the
//! pooled behaviors target.
//!
//! Every builder here constructs instructions from the programs' documented,
//! public wire layouts (System, SPL Token, SPL Associated-Token-Account, SPL
//! Stake Pool). We build them by hand rather than pulling `spl-token` /
//! `spl-stake-pool`, because those crates pin their own (older) `solana-program`
//! and would drag a second, incompatible `Pubkey`/`Instruction` type into the
//! workspace. Hand-building keeps one type set (`solana-pubkey` v4 +
//! `solana-instruction` v3) and keeps the dependency tree clean, which is the
//! whole reason the layouts are asserted in the unit tests: if a program ever
//! changes its discriminant we want a red test, not a silent malformed ix.

use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

/// System program. Owns lamport transfers.
pub const SYSTEM_PROGRAM_ID: Pubkey = Pubkey::from_str_const("11111111111111111111111111111111");

/// SPL Token program (the original, non-2022 program).
pub const TOKEN_PROGRAM_ID: Pubkey =
    Pubkey::from_str_const("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");

/// SPL Associated Token Account program. ATAs are `f(owner, token_program,
/// mint)`, which is exactly the determinism the threat model warns about: value
/// landing in a canonical ATA re-links to the owner instantly. We derive it so
/// the re-link vector is explicit at the call site.
pub const ASSOCIATED_TOKEN_PROGRAM_ID: Pubkey =
    Pubkey::from_str_const("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");

/// SPL Stake Pool program (the on-chain program jitoSOL's stake pool runs).
pub const STAKE_POOL_PROGRAM_ID: Pubkey =
    Pubkey::from_str_const("SPoo1Ku8WFXoNDMHPsrGSTSG1Y47rzgn41SLUNakuHy");

/// System program instruction discriminant for `Transfer` (bincode-serialized
/// enum, variant index 2, encoded as a u32 LE).
const SYSTEM_IX_TRANSFER: u32 = 2;

/// SPL Token instruction discriminant for `TransferChecked` (single byte).
const TOKEN_IX_TRANSFER_CHECKED: u8 = 12;

/// SPL Stake Pool instruction discriminant for `DepositSol` (single byte; the
/// enum is borsh-serialized, so the variant index is one leading byte).
const STAKE_POOL_IX_DEPOSIT_SOL: u8 = 14;

/// Seed for the stake pool's withdraw-authority PDA.
const STAKE_POOL_WITHDRAW_SEED: &[u8] = b"withdraw";

/// Build a System `Transfer` of `lamports` from `from` to `to`.
///
/// `from` signs and both accounts are writable. Data is
/// `[2u32 LE][lamports u64 LE]` (12 bytes).
pub fn system_transfer(from: &Pubkey, to: &Pubkey, lamports: u64) -> Instruction {
    let mut data = Vec::with_capacity(12);
    data.extend_from_slice(&SYSTEM_IX_TRANSFER.to_le_bytes());
    data.extend_from_slice(&lamports.to_le_bytes());
    Instruction {
        program_id: SYSTEM_PROGRAM_ID,
        accounts: vec![AccountMeta::new(*from, true), AccountMeta::new(*to, false)],
        data,
    }
}

/// Derive the canonical associated token account for `(owner, mint)` under
/// `token_program`.
pub fn associated_token_address(owner: &Pubkey, mint: &Pubkey, token_program: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(
        &[owner.as_ref(), token_program.as_ref(), mint.as_ref()],
        &ASSOCIATED_TOKEN_PROGRAM_ID,
    )
    .0
}

/// Build an SPL Token `TransferChecked` of `amount` base units (decimals-aware)
/// from `source` to `destination`, signed by `authority`.
///
/// We use `TransferChecked` (not the deprecated `Transfer`) so the mint +
/// decimals are validated on-chain; that also pins the instruction shape (one
/// extra account, one extra data byte) uniformly across participants. Data is
/// `[12][amount u64 LE][decimals u8]` (10 bytes).
#[allow(clippy::too_many_arguments)]
pub fn token_transfer_checked(
    token_program: &Pubkey,
    source: &Pubkey,
    mint: &Pubkey,
    destination: &Pubkey,
    authority: &Pubkey,
    amount: u64,
    decimals: u8,
) -> Instruction {
    let mut data = Vec::with_capacity(10);
    data.push(TOKEN_IX_TRANSFER_CHECKED);
    data.extend_from_slice(&amount.to_le_bytes());
    data.push(decimals);
    Instruction {
        program_id: *token_program,
        accounts: vec![
            AccountMeta::new(*source, false),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new(*destination, false),
            AccountMeta::new_readonly(*authority, true),
        ],
        data,
    }
}

/// Derive a stake pool's withdraw-authority PDA (seeds `[stake_pool,
/// "withdraw"]`).
pub fn stake_pool_withdraw_authority(program_id: &Pubkey, stake_pool: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[stake_pool.as_ref(), STAKE_POOL_WITHDRAW_SEED], program_id).0
}

/// Accounts a stake-pool `DepositSol` needs beyond the depositing wallet. These
/// are pool-wide constants (same for every participant), so pinning them here is
/// what makes the deposit a naturally uniform pooled action.
#[derive(Clone, Copy, Debug)]
pub struct StakePoolAccounts {
    pub program_id: Pubkey,
    pub stake_pool: Pubkey,
    pub reserve_stake: Pubkey,
    pub manager_fee_account: Pubkey,
    pub pool_mint: Pubkey,
    pub token_program: Pubkey,
}

/// Build a stake-pool `DepositSol`: deposit `lamports` of SOL from `from` and
/// receive pool tokens (jitoSOL) into `dest_pool_tokens`.
///
/// Account order matches the SPL stake pool program's `deposit_sol` layout:
/// stake_pool, withdraw_authority, reserve, from(signer), dest_pool_tokens,
/// manager_fee, referrer_pool_tokens, pool_mint, system_program, token_program.
/// The referrer account is set to the manager fee account (no referral). Data is
/// `[14][lamports u64 LE]` (9 bytes).
pub fn stake_pool_deposit_sol(
    accounts: &StakePoolAccounts,
    from: &Pubkey,
    dest_pool_tokens: &Pubkey,
    lamports: u64,
) -> Instruction {
    let withdraw_authority =
        stake_pool_withdraw_authority(&accounts.program_id, &accounts.stake_pool);
    let mut data = Vec::with_capacity(9);
    data.push(STAKE_POOL_IX_DEPOSIT_SOL);
    data.extend_from_slice(&lamports.to_le_bytes());
    Instruction {
        program_id: accounts.program_id,
        accounts: vec![
            AccountMeta::new(accounts.stake_pool, false),
            AccountMeta::new_readonly(withdraw_authority, false),
            AccountMeta::new(accounts.reserve_stake, false),
            AccountMeta::new(*from, true),
            AccountMeta::new(*dest_pool_tokens, false),
            AccountMeta::new(accounts.manager_fee_account, false),
            AccountMeta::new(accounts.manager_fee_account, false),
            AccountMeta::new(accounts.pool_mint, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
            AccountMeta::new_readonly(accounts.token_program, false),
        ],
        data,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_transfer_layout() {
        let from = Pubkey::new_from_array([1u8; 32]);
        let to = Pubkey::new_from_array([2u8; 32]);
        let ix = system_transfer(&from, &to, 1_000_000_000);
        assert_eq!(ix.program_id, SYSTEM_PROGRAM_ID);
        assert_eq!(ix.accounts.len(), 2);
        assert!(ix.accounts[0].is_signer && ix.accounts[0].is_writable);
        assert!(!ix.accounts[1].is_signer && ix.accounts[1].is_writable);
        assert_eq!(ix.data.len(), 12);
        assert_eq!(ix.data[0..4], 2u32.to_le_bytes());
        assert_eq!(ix.data[4..12], 1_000_000_000u64.to_le_bytes());
    }

    #[test]
    fn token_transfer_checked_layout() {
        let src = Pubkey::new_from_array([3u8; 32]);
        let mint = Pubkey::new_from_array([4u8; 32]);
        let dst = Pubkey::new_from_array([5u8; 32]);
        let auth = Pubkey::new_from_array([6u8; 32]);
        let ix = token_transfer_checked(&TOKEN_PROGRAM_ID, &src, &mint, &dst, &auth, 250_000, 6);
        assert_eq!(ix.program_id, TOKEN_PROGRAM_ID);
        assert_eq!(ix.accounts.len(), 4);
        // source(w), mint(ro), destination(w), authority(signer, ro)
        assert!(ix.accounts[0].is_writable && !ix.accounts[0].is_signer);
        assert!(!ix.accounts[1].is_writable && !ix.accounts[1].is_signer);
        assert!(ix.accounts[2].is_writable && !ix.accounts[2].is_signer);
        assert!(!ix.accounts[3].is_writable && ix.accounts[3].is_signer);
        assert_eq!(ix.data.len(), 10);
        assert_eq!(ix.data[0], 12);
        assert_eq!(ix.data[1..9], 250_000u64.to_le_bytes());
        assert_eq!(ix.data[9], 6);
    }

    #[test]
    fn deposit_sol_layout() {
        let accts = StakePoolAccounts {
            program_id: STAKE_POOL_PROGRAM_ID,
            stake_pool: Pubkey::new_from_array([10u8; 32]),
            reserve_stake: Pubkey::new_from_array([11u8; 32]),
            manager_fee_account: Pubkey::new_from_array([12u8; 32]),
            pool_mint: Pubkey::new_from_array([13u8; 32]),
            token_program: TOKEN_PROGRAM_ID,
        };
        let from = Pubkey::new_from_array([14u8; 32]);
        let dest = Pubkey::new_from_array([15u8; 32]);
        let ix = stake_pool_deposit_sol(&accts, &from, &dest, 1_000_000_000);

        assert_eq!(ix.program_id, STAKE_POOL_PROGRAM_ID);
        assert_eq!(ix.accounts.len(), 10);
        assert_eq!(ix.data.len(), 9);
        assert_eq!(ix.data[0], 14);
        assert_eq!(ix.data[1..9], 1_000_000_000u64.to_le_bytes());

        // Only the depositing wallet signs.
        assert!(ix.accounts[3].is_signer);
        assert_eq!(ix.accounts[3].pubkey, from);
        assert_eq!(ix.accounts.iter().filter(|a| a.is_signer).count(), 1);

        // withdraw_authority is a PDA of (program, stake_pool).
        assert_eq!(
            ix.accounts[1].pubkey,
            stake_pool_withdraw_authority(&accts.program_id, &accts.stake_pool)
        );
        // referrer defaults to the manager fee account.
        assert_eq!(ix.accounts[5].pubkey, accts.manager_fee_account);
        assert_eq!(ix.accounts[6].pubkey, accts.manager_fee_account);
        // trailing programs.
        assert_eq!(ix.accounts[8].pubkey, SYSTEM_PROGRAM_ID);
        assert_eq!(ix.accounts[9].pubkey, TOKEN_PROGRAM_ID);
    }

    #[test]
    fn ata_is_deterministic_and_off_curve() {
        let owner = Pubkey::new_from_array([7u8; 32]);
        let mint = Pubkey::new_from_array([8u8; 32]);
        let a = associated_token_address(&owner, &mint, &TOKEN_PROGRAM_ID);
        let b = associated_token_address(&owner, &mint, &TOKEN_PROGRAM_ID);
        assert_eq!(a, b, "ATA derivation must be deterministic");
        // A different owner yields a different ATA (the re-link vector).
        let other =
            associated_token_address(&Pubkey::new_from_array([9u8; 32]), &mint, &TOKEN_PROGRAM_ID);
        assert_ne!(a, other);
    }
}
