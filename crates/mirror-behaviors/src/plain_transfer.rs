//! [`PlainTransfer`] - the guaranteed-working baseline pooled action.
//!
//! A fixed-amount transfer to one per-pool sink: either native SOL (System
//! `Transfer`) or a fixed SPL amount (`TransferChecked`). It needs no network,
//! no price oracle, and no external program state, so it is the action the
//! end-to-end Surfpool soak actually executes to prove the batching /
//! k-anonymity machinery. Jupiter and jitoSOL are the "real" behaviors; this is
//! the one that is deterministic enough to assert on.
//!
//! ## ActionClass mapping
//! `mirror_core::ActionClass` (owned by `mirror-core`, another crate) exposes
//! only `Swap` and `Stake`. A fixed-amount transfer to a fixed destination has
//! exactly the observable shape of `Stake { validator, size }` - one uniform
//! amount to one fixed target account - so PlainTransfer reports that class with
//! the sink standing in for `validator`. We deliberately do not add a new
//! variant to `mirror-core`; we map onto its nearest existing shape.

use crate::{bucket_base_units, bucket_lamports, programs, Behavior};
use anyhow::Result;
use async_trait::async_trait;
use mirror_core::{ActionClass, SizeBucket};
use solana_instruction::Instruction;
use solana_pubkey::Pubkey;

/// The asset a [`PlainTransfer`] moves.
#[derive(Clone, Copy, Debug)]
pub enum TransferAsset {
    /// Native SOL: a System `Transfer` of `bucket_lamports(size)` to the sink.
    Sol,
    /// A fixed SPL amount: `TransferChecked` of `bucket_base_units(size,
    /// decimals)` from the participant's ATA to the sink's ATA.
    Spl {
        mint: Pubkey,
        decimals: u8,
        token_program: Pubkey,
    },
}

/// A fixed-amount transfer every participant performs identically into one
/// per-pool `sink`.
#[derive(Clone, Copy, Debug)]
pub struct PlainTransfer {
    /// The destination every participant sends to (its owner address; for the
    /// SPL variant the destination ATA is derived from this owner + mint).
    pub sink: Pubkey,
    /// The fixed size bucket that fixes the amount pool-wide.
    pub size: SizeBucket,
    /// SOL or a fixed SPL amount.
    pub asset: TransferAsset,
}

impl PlainTransfer {
    /// A native-SOL pooled transfer to `sink`.
    pub fn sol(sink: Pubkey, size: SizeBucket) -> Self {
        Self {
            sink,
            size,
            asset: TransferAsset::Sol,
        }
    }

    /// A fixed SPL-amount pooled transfer to `sink`'s associated token account.
    pub fn spl(
        sink: Pubkey,
        size: SizeBucket,
        mint: Pubkey,
        decimals: u8,
        token_program: Pubkey,
    ) -> Self {
        Self {
            sink,
            size,
            asset: TransferAsset::Spl {
                mint,
                decimals,
                token_program,
            },
        }
    }
}

#[async_trait]
impl Behavior for PlainTransfer {
    fn action_class(&self) -> ActionClass {
        // Fixed amount to a fixed target == the observable shape of Stake.
        ActionClass::Stake {
            validator: self.sink.to_bytes(),
            size: self.size,
        }
    }

    fn describe(&self) -> String {
        match self.asset {
            TransferAsset::Sol => format!(
                "PlainTransfer: {} lamports SOL -> per-pool sink (soak baseline)",
                bucket_lamports(self.size)
            ),
            TransferAsset::Spl { mint, decimals, .. } => format!(
                "PlainTransfer: {} base units of SPL mint {} -> per-pool sink ATA (soak baseline)",
                bucket_base_units(self.size, decimals),
                mint
            ),
        }
    }

    async fn build_instructions(
        &self,
        participant: &Pubkey,
        size: SizeBucket,
    ) -> Result<Vec<Instruction>> {
        let ix = match self.asset {
            TransferAsset::Sol => {
                programs::system_transfer(participant, &self.sink, bucket_lamports(size))
            }
            TransferAsset::Spl {
                mint,
                decimals,
                token_program,
            } => {
                let source = programs::associated_token_address(participant, &mint, &token_program);
                let destination =
                    programs::associated_token_address(&self.sink, &mint, &token_program);
                programs::token_transfer_checked(
                    &token_program,
                    &source,
                    &mint,
                    &destination,
                    participant,
                    bucket_base_units(size, decimals),
                    decimals,
                )
            }
        };
        Ok(vec![ix])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::programs::{SYSTEM_PROGRAM_ID, TOKEN_PROGRAM_ID};

    fn part() -> Pubkey {
        Pubkey::new_from_array([42u8; 32])
    }

    fn sink() -> Pubkey {
        Pubkey::new_from_array([99u8; 32])
    }

    #[tokio::test]
    async fn sol_transfer_uses_bucket_lamports_and_participant_signs() {
        let b = PlainTransfer::sol(sink(), SizeBucket::Medium);
        let ixs = b
            .build_instructions(&part(), SizeBucket::Medium)
            .await
            .unwrap();
        assert_eq!(ixs.len(), 1);
        let ix = &ixs[0];
        assert_eq!(ix.program_id, SYSTEM_PROGRAM_ID);
        // participant is the from/signer, sink is the to.
        assert_eq!(ix.accounts[0].pubkey, part());
        assert!(ix.accounts[0].is_signer);
        assert_eq!(ix.accounts[1].pubkey, sink());
        assert_eq!(
            ix.data[4..12],
            bucket_lamports(SizeBucket::Medium).to_le_bytes()
        );
    }

    #[tokio::test]
    async fn spl_transfer_derives_atas_and_carries_decimals() {
        let mint = Pubkey::new_from_array([7u8; 32]);
        let b = PlainTransfer::spl(sink(), SizeBucket::Small, mint, 6, TOKEN_PROGRAM_ID);
        let ixs = b
            .build_instructions(&part(), SizeBucket::Small)
            .await
            .unwrap();
        let ix = &ixs[0];
        assert_eq!(ix.program_id, TOKEN_PROGRAM_ID);
        assert_eq!(ix.accounts.len(), 4);
        // source == participant's ATA, destination == sink's ATA.
        assert_eq!(
            ix.accounts[0].pubkey,
            programs::associated_token_address(&part(), &mint, &TOKEN_PROGRAM_ID)
        );
        assert_eq!(ix.accounts[1].pubkey, mint);
        assert_eq!(
            ix.accounts[2].pubkey,
            programs::associated_token_address(&sink(), &mint, &TOKEN_PROGRAM_ID)
        );
        // authority == participant, signs.
        assert_eq!(ix.accounts[3].pubkey, part());
        assert!(ix.accounts[3].is_signer);
        assert_eq!(
            ix.data[1..9],
            bucket_base_units(SizeBucket::Small, 6).to_le_bytes()
        );
        assert_eq!(ix.data[9], 6);
    }

    #[test]
    fn action_class_is_stake_shaped_over_the_sink() {
        let b = PlainTransfer::sol(sink(), SizeBucket::Large);
        assert_eq!(
            b.action_class(),
            ActionClass::Stake {
                validator: sink().to_bytes(),
                size: SizeBucket::Large,
            }
        );
    }
}
