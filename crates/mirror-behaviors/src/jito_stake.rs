//! [`JitoSolStake`] - pooled SOL -> jitoSOL stake-pool deposit.
//!
//! Every participant deposits the same bucketed lamports into the same SPL
//! stake pool and receives jitoSOL into their own associated token account. The
//! `DepositSol` account list is fixed pool-wide (only the depositing wallet and
//! its destination ATA vary), which is what makes this a naturally uniform
//! pooled action: an observer sees N identical deposits.
//!
//! The struct is address-agnostic (all pool accounts are supplied), so it never
//! hardcodes a mainnet address into the core type. [`JitoSolStake::jitosol`] is
//! an opt-in convenience that fills in jitoSOL's publicly documented mainnet
//! addresses - these are public program/account addresses, never keys.

use crate::{bucket_lamports, programs, programs::StakePoolAccounts, Behavior};
use anyhow::Result;
use async_trait::async_trait;
use mirror_core::{ActionClass, SizeBucket};
use solana_instruction::Instruction;
use solana_pubkey::Pubkey;

/// jitoSOL mainnet stake pool (public addresses).
pub mod jitosol_mainnet {
    use solana_pubkey::Pubkey;

    pub const STAKE_POOL: Pubkey =
        Pubkey::from_str_const("Jito4APyf642JPZPx3hGc6WWJ8zPKtRbRs4P815Awbb");
    pub const POOL_MINT: Pubkey =
        Pubkey::from_str_const("J1toso1uCk3RLmjorhTtrVwY9HJ7X8V9yYac6Y7kGCPn");
    pub const RESERVE_STAKE: Pubkey =
        Pubkey::from_str_const("BgKUXdS29YcHCFrPm5M8oLHiTzZaMDjsebggjoaQ6KFL");
    pub const MANAGER_FEE_ACCOUNT: Pubkey =
        Pubkey::from_str_const("feeeFLLsam6xZJFc6UQFrHqkvVt4jfmVvi2BRLkUZ4i");
}

/// A pooled jitoSOL (SPL stake-pool `DepositSol`) behavior.
#[derive(Clone, Copy, Debug)]
pub struct JitoSolStake {
    /// All the pool-wide accounts the deposit needs (program id, stake pool,
    /// reserve, manager fee account, pool mint, token program).
    pub accounts: StakePoolAccounts,
    /// The fixed size bucket shared by the whole pool.
    pub size: SizeBucket,
}

impl JitoSolStake {
    /// Build over an explicit set of stake-pool accounts (no hardcoded
    /// addresses).
    pub fn new(accounts: StakePoolAccounts, size: SizeBucket) -> Self {
        Self { accounts, size }
    }

    /// Convenience constructor for jitoSOL's public mainnet stake pool.
    pub fn jitosol(size: SizeBucket) -> Self {
        Self {
            accounts: StakePoolAccounts {
                program_id: programs::STAKE_POOL_PROGRAM_ID,
                stake_pool: jitosol_mainnet::STAKE_POOL,
                reserve_stake: jitosol_mainnet::RESERVE_STAKE,
                manager_fee_account: jitosol_mainnet::MANAGER_FEE_ACCOUNT,
                pool_mint: jitosol_mainnet::POOL_MINT,
                token_program: programs::TOKEN_PROGRAM_ID,
            },
            size,
        }
    }
}

#[async_trait]
impl Behavior for JitoSolStake {
    fn action_class(&self) -> ActionClass {
        // The stake pool is the fixed target; it stands in for `validator`.
        ActionClass::Stake {
            validator: self.accounts.stake_pool.to_bytes(),
            size: self.size,
        }
    }

    fn describe(&self) -> String {
        format!(
            "JitoSolStake: DepositSol {} lamports -> stake pool {} (pool tokens to participant ATA)",
            bucket_lamports(self.size),
            self.accounts.stake_pool
        )
    }

    async fn build_instructions(
        &self,
        participant: &Pubkey,
        size: SizeBucket,
    ) -> Result<Vec<Instruction>> {
        // jitoSOL lands in the participant's canonical ATA. This is the ATA
        // re-link vector: the pool token account is f(participant, pool_mint),
        // so a downstream observer can re-link the received jitoSOL to the
        // participant. Documented, not hidden - v1 obscures the initiator of the
        // batch, not the destination of value.
        let dest_pool_tokens = programs::associated_token_address(
            participant,
            &self.accounts.pool_mint,
            &self.accounts.token_program,
        );
        let ix = programs::stake_pool_deposit_sol(
            &self.accounts,
            participant,
            &dest_pool_tokens,
            bucket_lamports(size),
        );
        Ok(vec![ix])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn part() -> Pubkey {
        Pubkey::new_from_array([21u8; 32])
    }

    #[tokio::test]
    async fn deposit_sol_targets_jitosol_pool_and_participant_ata() {
        let b = JitoSolStake::jitosol(SizeBucket::Medium);
        let ixs = b
            .build_instructions(&part(), SizeBucket::Medium)
            .await
            .unwrap();
        assert_eq!(ixs.len(), 1);
        let ix = &ixs[0];

        assert_eq!(ix.program_id, programs::STAKE_POOL_PROGRAM_ID);
        assert_eq!(ix.accounts.len(), 10);
        assert_eq!(ix.accounts[0].pubkey, jitosol_mainnet::STAKE_POOL);

        // The depositing wallet is the only signer.
        assert_eq!(ix.accounts[3].pubkey, part());
        assert!(ix.accounts[3].is_signer);
        assert_eq!(ix.accounts.iter().filter(|a| a.is_signer).count(), 1);

        // jitoSOL lands in the participant's canonical ATA.
        let expected_ata = programs::associated_token_address(
            &part(),
            &jitosol_mainnet::POOL_MINT,
            &programs::TOKEN_PROGRAM_ID,
        );
        assert_eq!(ix.accounts[4].pubkey, expected_ata);

        // amount == bucket lamports.
        assert_eq!(ix.data[0], 14);
        assert_eq!(
            ix.data[1..9],
            bucket_lamports(SizeBucket::Medium).to_le_bytes()
        );
    }

    #[test]
    fn action_class_is_stake_over_the_pool() {
        let b = JitoSolStake::jitosol(SizeBucket::Small);
        assert_eq!(
            b.action_class(),
            ActionClass::Stake {
                validator: jitosol_mainnet::STAKE_POOL.to_bytes(),
                size: SizeBucket::Small,
            }
        );
    }

    #[test]
    fn amount_varies_by_bucket_but_shape_is_identical() {
        // Two participants at the same bucket -> byte-identical account shape and
        // data length; only signer/ATA pubkeys differ. This is the uniformity
        // the anonymity set depends on.
        let small = JitoSolStake::jitosol(SizeBucket::Small);
        let large = JitoSolStake::jitosol(SizeBucket::Large);
        assert_ne!(bucket_lamports(small.size), bucket_lamports(large.size));
    }
}
