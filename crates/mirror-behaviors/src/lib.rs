//! Pooled-action adapters for mirror-pool (v1 deliverable 4 in
//! `docs/ROADMAP.md`).
//!
//! A [`Behavior`] is the single action every participant in an epoch performs
//! *identically*. This crate builds the CLIENT-SIDE Solana [`Instruction`]s for
//! that action, one participant at a time. The coordinator (v1 deliverable 3)
//! then composes each participant's behavior instruction(s) together with the
//! on-chain `SettleEpoch` instruction into one atomic transaction - off-chain
//! composition, not on-chain CPI into Jupiter/stake-pool, which is impractical.
//! An observer therefore sees N identical actions settle on one timestamp and
//! cannot attribute one to an initiator.
//!
//! Uniformity is the whole point (see `docs/THREAT_MODEL.md`):
//!
//! - **Fixed action shape.** One anonymity set exists per
//!   [`mirror_core::ActionClass`]. Two participants emitting observably
//!   different instructions (different mint pair, amount, or account shape) could
//!   be clustered by shape, exactly like mixed denominations in Tornado, so a
//!   behavior pins its class + size bucket and every participant's instruction
//!   is the same shape at the same amount.
//! - **Fixed size buckets.** Amount-matching alone recovers a large fraction of
//!   a claimed anonymity set (Wang et al., arXiv:2201.09035); a bucket maps to
//!   one fixed amount pool-wide via [`bucket_base_units`] / [`bucket_lamports`].
//! - **Coordinator-owned tx shape.** These builders emit action instructions
//!   only. Fee payer, CU limit, priority fee, tx version, account ordering, and
//!   ALT normalization belong to the coordinator, so no acting wallet funds or
//!   signs its own execution and there is one pool-wide tx fingerprint. The
//!   Jupiter adapter deliberately drops the per-participant compute-budget
//!   instructions the API returns for exactly this reason.
//!
//! ## Adapters
//! - [`PlainTransfer`] - fixed SOL / SPL transfer to a per-pool sink. The
//!   deterministic, no-network action the end-to-end soak actually executes.
//! - [`JupiterSwap`] - pooled swap on the public Jupiter v6 API (fixed mint pair
//!   + bucketed amount).
//! - [`JitoSolStake`] - pooled SOL -> jitoSOL SPL stake-pool `DepositSol`.

mod jito_stake;
mod jupiter;
mod plain_transfer;
pub mod programs;

pub use jito_stake::{jitosol_mainnet, JitoSolStake};
pub use jupiter::{JupiterSwap, SwapInstructionsResponse, DEFAULT_JUPITER_BASE_URL};
pub use plain_transfer::{PlainTransfer, TransferAsset};
pub use programs::StakePoolAccounts;

use anyhow::Result;
use async_trait::async_trait;
use mirror_core::{ActionClass, SizeBucket};
use solana_instruction::Instruction;
use solana_pubkey::Pubkey;
use std::collections::HashMap;

/// A pooled action every participant in an epoch performs identically.
///
/// Implementations are `Send + Sync` so the coordinator can hold a registry of
/// them across its scheduler threads. `build_instructions` is `async` because a
/// behavior may need to reach an external quote/route API (Jupiter); adapters
/// that need no network simply return immediately.
#[async_trait]
pub trait Behavior: Send + Sync {
    /// The fixed action shape this behavior settles. Every commitment in the
    /// pool binds to this exact class via [`mirror_core::commit`], so a relayer
    /// cannot substitute a different action at settlement without invalidating
    /// every commitment.
    fn action_class(&self) -> ActionClass;

    /// Human-readable one-liner for the CLI `status` output and harness reports.
    fn describe(&self) -> String;

    /// Build the client-side instruction(s) for `participant`'s action at the
    /// given size bucket. The coordinator composes these with `SettleEpoch` into
    /// one atomic transaction; the returned instructions must be byte-shape
    /// identical across participants (only participant-specific pubkeys differ)
    /// so settlement stays uniform.
    ///
    /// `size` is passed explicitly (rather than read from the behavior) so the
    /// coordinator drives the pool's fixed bucket; for a coherent pool it equals
    /// the bucket in [`Behavior::action_class`].
    async fn build_instructions(
        &self,
        participant: &Pubkey,
        size: SizeBucket,
    ) -> Result<Vec<Instruction>>;
}

/// Per-bucket amount in hundredths of one whole unit: Nano = 0.01, Small = 0.1,
/// Medium = 1, Large = 10. Bucketing is the behavioral analog of Tornado's fixed
/// denominations; these four coarse steps keep amount-matching at the 1/k floor.
const BUCKET_HUNDREDTHS: [u64; 4] = [1, 10, 100, 1000];

/// Amount, in base units, for `size` on a token with `decimals` decimals.
///
/// `amount = hundredths(size) * 10^decimals / 100`. Multiplication happens
/// before the divide, so no precision is lost for `decimals >= 2` (all SPL mints
/// of interest, and native SOL's 9). For `decimals < 2` the sub-unit buckets
/// round toward zero; such mints are out of scope for v1 pools.
pub fn bucket_base_units(size: SizeBucket, decimals: u8) -> u64 {
    let hundredths = BUCKET_HUNDREDTHS[size as usize] as u128;
    let scaled = hundredths * 10u128.pow(decimals as u32) / 100;
    u64::try_from(scaled).expect("bucket amount fits in u64 for realistic decimals")
}

/// Native-SOL amount, in lamports, for `size` (SOL has 9 decimals): Nano =
/// 0.01 SOL, Small = 0.1, Medium = 1, Large = 10.
pub fn bucket_lamports(size: SizeBucket) -> u64 {
    bucket_base_units(size, 9)
}

/// Name-keyed registry of pooled behaviors.
///
/// The coordinator resolves a pool's configured behavior by name at startup; the
/// CLI uses the same names in `commit --behavior <name>`. One registry keeps the
/// set of deployable action shapes explicit and auditable, so nobody quietly
/// adds a heterogeneous action to a live pool.
#[derive(Default)]
pub struct BehaviorRegistry {
    entries: HashMap<String, Box<dyn Behavior>>,
}

impl BehaviorRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `behavior` under `name`, replacing any previous entry.
    pub fn register(&mut self, name: impl Into<String>, behavior: Box<dyn Behavior>) {
        self.entries.insert(name.into(), behavior);
    }

    pub fn get(&self, name: &str) -> Option<&dyn Behavior> {
        self.entries.get(name).map(|b| b.as_ref())
    }

    /// Registered names, sorted for stable CLI/help output.
    pub fn names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.entries.keys().map(String::as_str).collect();
        names.sort_unstable();
        names
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sol_buckets_are_the_expected_lamport_steps() {
        assert_eq!(bucket_lamports(SizeBucket::Nano), 10_000_000); // 0.01 SOL
        assert_eq!(bucket_lamports(SizeBucket::Small), 100_000_000); // 0.1 SOL
        assert_eq!(bucket_lamports(SizeBucket::Medium), 1_000_000_000); // 1 SOL
        assert_eq!(bucket_lamports(SizeBucket::Large), 10_000_000_000); // 10 SOL
    }

    #[test]
    fn token_buckets_scale_with_decimals() {
        // 6-decimal token (e.g. USDC-shaped): 0.01 == 10_000 base units.
        assert_eq!(bucket_base_units(SizeBucket::Nano, 6), 10_000);
        assert_eq!(bucket_base_units(SizeBucket::Medium, 6), 1_000_000);
        // strictly increasing across the four buckets at any fixed decimals.
        let steps: Vec<u64> = SizeBucket::ALL
            .iter()
            .map(|s| bucket_base_units(*s, 6))
            .collect();
        assert!(steps.windows(2).all(|w| w[0] < w[1]));
    }

    #[tokio::test]
    async fn registry_resolves_by_name_and_builds() {
        let sink = Pubkey::new_from_array([1u8; 32]);
        let mut reg = BehaviorRegistry::new();
        reg.register(
            "plain-transfer",
            Box::new(PlainTransfer::sol(sink, SizeBucket::Medium)),
        );
        reg.register(
            "jitosol-stake",
            Box::new(JitoSolStake::jitosol(SizeBucket::Medium)),
        );
        reg.register(
            "jupiter-swap",
            Box::new(JupiterSwap::new(
                Pubkey::new_from_array([2u8; 32]),
                Pubkey::new_from_array([3u8; 32]),
                9,
                SizeBucket::Medium,
            )),
        );

        assert_eq!(reg.len(), 3);
        assert_eq!(
            reg.names(),
            vec!["jitosol-stake", "jupiter-swap", "plain-transfer"]
        );
        assert!(reg.get("missing").is_none());

        // The soak baseline builds without any network.
        let b = reg.get("plain-transfer").expect("registered");
        assert!(b.describe().contains("PlainTransfer"));
        let participant = Pubkey::new_from_array([9u8; 32]);
        let ixs = b
            .build_instructions(&participant, SizeBucket::Medium)
            .await
            .expect("plain transfer builds offline");
        assert_eq!(ixs.len(), 1);
    }

    #[test]
    fn distinct_behaviors_have_distinct_classes() {
        let sink = Pubkey::new_from_array([1u8; 32]);
        let transfer = PlainTransfer::sol(sink, SizeBucket::Medium).action_class();
        let swap = JupiterSwap::new(
            Pubkey::new_from_array([2u8; 32]),
            Pubkey::new_from_array([3u8; 32]),
            9,
            SizeBucket::Medium,
        )
        .action_class();
        assert_ne!(transfer.canonical_bytes(), swap.canonical_bytes());
    }
}
