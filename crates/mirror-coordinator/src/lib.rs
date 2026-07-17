//! mirror-coordinator: the gasless epoch coordinator for mirror-pool.
//!
//! The coordinator is the off-chain relay that turns individual commitments
//! into a shared anonymity set. Its four privacy jobs, each visible in this
//! crate's structure:
//!
//! - **Shared-epoch batching** ([`pool::CommitPool`], [`scheduler::Coordinator`]).
//!   Participants commit during an epoch window and the whole epoch settles on
//!   one timestamp. Per-participant timing never reaches the chain, which is
//!   what defeats FIFO temporal matching, the single strongest empirical attack
//!   on Tornado-style pools.
//!
//! - **k-anonymity floor** ([`mirror_core::KAnon`], enforced in
//!   [`scheduler::Coordinator::on_slot`]). An epoch below `k_floor` real
//!   participants rolls forward instead of executing. Executing into a tiny set
//!   would let an observer deanonymize by elimination, so the floor is a hard
//!   gate, not a report. Honest accounting: operator-owned decoys are excluded
//!   because the operator already knows them and they add zero real anonymity.
//!
//! - **Gasless, rotating relay** ([`config::FeePayerRing`]). Participants never
//!   pay fees from their own wallets; fee-payer identity is one of the cheapest
//!   linkage vectors. The coordinator pays from a rotating set so no single
//!   payer key becomes a stable cluster label across epochs.
//!
//! - **Fixed action shape** ([`config::TxProfile`]). Every SettleEpoch tx uses
//!   the same normalized compute-unit limit and priority fee. Variable compute
//!   budgets fingerprint transactions exactly like variable amounts do, so the
//!   shape is a pool constant, never per-settlement.
//!
//! This crate is a compiling skeleton: module structure, types, and the
//! scheduler loop are real; on-chain submission is stubbed behind
//! [`submit::SettleSubmitter`]. TODO(milestone) markers reference the build
//! plan where full logic lands. Modules live inline in this file for now and
//! split into files when they grow.

pub use config::{Config, FeePayer, TxProfile};
pub use pool::{CommitPool, PoolEntry};
pub use scheduler::{Coordinator, EpochOutcome};
pub use submit::{InMemorySubmitter, SettleBatch, SettleReceipt, SettleSubmitter};

/// Coordinator configuration: epoch schedule, fee-payer rotation, tx shape.
pub mod config {
    use mirror_core::EpochSchedule;
    use serde::{Deserialize, Serialize};

    /// A fee-payer identity (an ed25519 public key in production), kept as
    /// opaque bytes here. Never hardcode a real key: production loads the set
    /// from the operator keystore. Rotating payers is what makes the relay
    /// "gasless" without creating a single stable payer key that clusters
    /// every settlement the pool ever makes.
    #[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
    pub struct FeePayer(pub [u8; 32]);

    /// Normalized transaction shape applied to every settlement.
    ///
    /// Privacy rationale: a variable compute budget or priority fee is a
    /// fingerprint, exactly like a variable amount. Fixing both per pool means
    /// two settlements are indistinguishable by fee shape.
    #[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
    pub struct TxProfile {
        /// Compute-unit limit requested on every SettleEpoch tx.
        pub cu_limit: u32,
        /// Priority fee in micro-lamports per CU, constant per pool.
        pub priority_fee_micro_lamports: u64,
    }

    impl Default for TxProfile {
        fn default() -> Self {
            Self {
                cu_limit: 400_000,
                priority_fee_micro_lamports: 10_000,
            }
        }
    }

    /// Static coordinator configuration, fixed for the process lifetime.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct Config {
        /// Epoch windowing and k floor. Must match the values the pool was
        /// initialized with on-chain, otherwise the program rejects settles.
        pub schedule: EpochSchedule,
        /// Rotating fee-payer set. Must be non-empty.
        pub fee_payers: Vec<FeePayer>,
        /// Normalized CU limit / priority fee for every settlement tx.
        pub tx_profile: TxProfile,
    }

    /// Round-robin rotation over the configured fee payers.
    ///
    /// TODO(milestone-4): decorrelate rotation from epoch ids (an observer who
    /// knows "payer i settles epoch i mod n" learns the schedule), retire
    /// payers after N uses, and top them up from a treasury flow that is not
    /// itself linkable to the pool.
    #[derive(Debug)]
    pub struct FeePayerRing {
        payers: Vec<FeePayer>,
        cursor: usize,
    }

    impl FeePayerRing {
        pub fn new(payers: Vec<FeePayer>) -> anyhow::Result<Self> {
            anyhow::ensure!(!payers.is_empty(), "fee-payer set must be non-empty");
            Ok(Self { payers, cursor: 0 })
        }

        /// Next payer in rotation.
        pub fn next_payer(&mut self) -> FeePayer {
            let payer = self.payers[self.cursor];
            self.cursor = (self.cursor + 1) % self.payers.len();
            payer
        }
    }
}

/// In-memory commit pool: groups commitments by epoch and does the honest
/// k-anonymity accounting for each window.
pub mod pool {
    use mirror_core::{Commitment, Epoch, KAnon, Nullifier};
    use std::collections::BTreeMap;

    /// One accepted commit, held until its epoch settles.
    ///
    /// In v1 the participant reveals the nullifier to the coordinator during a
    /// pre-settlement reveal phase (the coordinator cannot derive it: that
    /// requires the secret). v2 replaces the reveal with a ZK membership
    /// proof. TODO(milestone-2): split commit and reveal intake paths.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub struct PoolEntry {
        pub commitment: Commitment,
        pub nullifier: Nullifier,
        /// Operator-owned decoy. Decoys thicken traffic but add zero real
        /// anonymity (the operator already knows which ones they are), so
        /// honest k reporting excludes them.
        pub operator_owned: bool,
    }

    /// Commitments grouped by the epoch they were committed into.
    ///
    /// Purely in-memory for the skeleton. TODO(milestone-3): persist to disk
    /// so a coordinator restart cannot orphan an open epoch's commitments.
    #[derive(Debug, Default)]
    pub struct CommitPool {
        epochs: BTreeMap<Epoch, Vec<PoolEntry>>,
    }

    impl CommitPool {
        pub fn new() -> Self {
            Self::default()
        }

        /// Accept a commit into its epoch's batch.
        pub fn insert(&mut self, epoch: Epoch, entry: PoolEntry) {
            self.epochs.entry(epoch).or_default().push(entry);
        }

        /// Epochs that still hold unsettled entries, oldest first.
        pub fn pending_epochs(&self) -> Vec<Epoch> {
            self.epochs.keys().copied().collect()
        }

        /// Number of entries currently batched for `epoch`.
        pub fn len(&self, epoch: Epoch) -> usize {
            self.epochs.get(&epoch).map_or(0, Vec::len)
        }

        pub fn is_empty(&self) -> bool {
            self.epochs.is_empty()
        }

        /// Honest anonymity accounting for an epoch: nominal commit count with
        /// operator decoys excluded. This is the number gated on `k_floor` and
        /// the only number ever reported to users as their anonymity set.
        ///
        /// TODO(milestone-3): also exclude economically linked commits (same
        /// funding source) as Sybils; nominal-minus-decoys still overstates k
        /// against a Sybil-capable attacker.
        pub fn kanon(&self, epoch: Epoch) -> KAnon {
            let entries = self.epochs.get(&epoch).map_or(&[][..], Vec::as_slice);
            KAnon {
                nominal: entries.len() as u32,
                excluded: entries.iter().filter(|e| e.operator_owned).count() as u32,
            }
        }

        /// Remove and return an epoch's entries for settlement.
        pub fn take_epoch(&mut self, epoch: Epoch) -> Vec<PoolEntry> {
            self.epochs.remove(&epoch).unwrap_or_default()
        }

        /// Move an under-floor epoch's entries into a later epoch instead of
        /// executing into a set small enough to deanonymize by elimination.
        ///
        /// Commitments bind their epoch (see [`mirror_core::commit`]), so in
        /// the full protocol participants must re-commit for the new window.
        /// TODO(milestone-2): notify clients to re-commit instead of carrying
        /// stale entries whose commitments no longer verify for the new epoch.
        pub fn roll_forward(&mut self, from: Epoch, to: Epoch) -> usize {
            let entries = self.take_epoch(from);
            let moved = entries.len();
            if moved > 0 {
                self.epochs.entry(to).or_default().extend(entries);
            }
            moved
        }
    }
}

/// On-chain submission boundary: everything below this trait is stubbed in
/// the skeleton so the scheduler is fully testable without a validator.
pub mod submit {
    use crate::config::{FeePayer, TxProfile};
    use mirror_core::{wire, Epoch, Nullifier};

    /// Everything needed to build one SettleEpoch transaction.
    #[derive(Clone, Debug)]
    pub struct SettleBatch {
        pub epoch: Epoch,
        /// Nullifiers revealed for this epoch; the program marks each spent so
        /// no participant can act twice in the same window.
        pub nullifiers: Vec<Nullifier>,
        /// The rotating payer funding this settlement (gasless for users).
        pub fee_payer: FeePayer,
        /// Normalized tx shape (fixed CU limit + priority fee per pool).
        pub tx_profile: TxProfile,
    }

    impl SettleBatch {
        /// Serialize the SETTLE_EPOCH instruction data exactly as the on-chain
        /// program parses it. Layout lives in [`mirror_core::wire`] so the two
        /// sides cannot drift.
        pub fn instruction_data(&self) -> Vec<u8> {
            let mut data = Vec::with_capacity(wire::SETTLE_HEADER_LEN + self.nullifiers.len() * 32);
            data.push(wire::tag::SETTLE_EPOCH);
            data.extend_from_slice(&self.epoch.0.to_le_bytes());
            data.extend_from_slice(&(self.nullifiers.len() as u32).to_le_bytes());
            for n in &self.nullifiers {
                data.extend_from_slice(&n.0);
            }
            data
        }
    }

    /// Receipt for a submitted settlement.
    #[derive(Clone, Debug)]
    pub struct SettleReceipt {
        pub epoch: Epoch,
        /// Transaction signature (or a synthetic id for in-memory submitters).
        pub signature: String,
    }

    /// The single seam between the scheduler and the chain. The scheduler only
    /// ever says "settle this batch"; how the transaction is built, signed,
    /// and confirmed is the submitter's problem. This keeps the k-floor gate
    /// and the batching logic testable without any validator.
    pub trait SettleSubmitter {
        fn submit_settle(&mut self, batch: &SettleBatch) -> anyhow::Result<SettleReceipt>;
    }

    /// Test/demo submitter: records batches instead of touching a chain.
    #[derive(Debug, Default)]
    pub struct InMemorySubmitter {
        pub submitted: Vec<SettleBatch>,
    }

    impl SettleSubmitter for InMemorySubmitter {
        fn submit_settle(&mut self, batch: &SettleBatch) -> anyhow::Result<SettleReceipt> {
            let receipt = SettleReceipt {
                epoch: batch.epoch,
                signature: format!("in-memory-settle-{}", batch.epoch.0),
            };
            self.submitted.push(batch.clone());
            Ok(receipt)
        }
    }

    /// Real JSON-RPC submitter.
    ///
    /// TODO(milestone-4): build the versioned transaction (compute-budget
    /// instructions from [`TxProfile`], then the SettleEpoch instruction from
    /// [`SettleBatch::instruction_data`]), sign with the rotating fee payer,
    /// send over RPC, and confirm. No program id is hardcoded here: it arrives
    /// via deploy-time configuration.
    #[derive(Debug)]
    pub struct RpcSubmitter {
        pub rpc_url: String,
    }

    impl SettleSubmitter for RpcSubmitter {
        fn submit_settle(&mut self, _batch: &SettleBatch) -> anyhow::Result<SettleReceipt> {
            unimplemented!("TODO(milestone-4): on-chain SettleEpoch submission over JSON-RPC")
        }
    }
}

/// The epoch scheduler loop: close windows, gate on the k floor, settle.
pub mod scheduler {
    use crate::config::{Config, FeePayerRing};
    use crate::pool::CommitPool;
    use crate::submit::{SettleBatch, SettleSubmitter};
    use mirror_core::Epoch;
    use std::time::Duration;

    /// What happened to one closable epoch during a scheduler pass.
    #[derive(Clone, Debug)]
    pub enum EpochOutcome {
        /// The epoch met the floor and was submitted for settlement.
        Settled {
            epoch: Epoch,
            real_k: u32,
            signature: String,
        },
        /// The epoch was below the floor; its entries rolled into `to`.
        RolledForward {
            epoch: Epoch,
            to: Epoch,
            real_k: u32,
            moved: usize,
        },
    }

    /// The coordinator state machine: commit pool + fee-payer rotation +
    /// submitter, driven by observed slots.
    ///
    /// Generic over [`SettleSubmitter`] so the identical scheduling logic runs
    /// against the in-memory submitter in tests and the RPC submitter in
    /// production; the privacy-critical decisions (when to settle, when to
    /// refuse) never depend on which backend is wired in.
    pub struct Coordinator<S: SettleSubmitter> {
        config: Config,
        fee_payers: FeePayerRing,
        pool: CommitPool,
        submitter: S,
    }

    impl<S: SettleSubmitter> Coordinator<S> {
        pub fn new(config: Config, submitter: S) -> anyhow::Result<Self> {
            let fee_payers = FeePayerRing::new(config.fee_payers.clone())?;
            Ok(Self {
                config,
                fee_payers,
                pool: CommitPool::new(),
                submitter,
            })
        }

        pub fn config(&self) -> &Config {
            &self.config
        }

        /// Commit intake surface. TODO(milestone-2): replace with a network
        /// intake (HTTP/gRPC) that validates commitment format before insert.
        pub fn pool_mut(&mut self) -> &mut CommitPool {
            &mut self.pool
        }

        pub fn submitter(&self) -> &S {
            &self.submitter
        }

        /// Process one observed slot:
        ///
        /// (a) close every epoch whose window has passed
        ///     ([`mirror_core::EpochSchedule::settle_slot`]),
        /// (b) compute [`mirror_core::KAnon`] and check `meets_floor`,
        /// (c) settle via the submitter, or roll the epoch forward if the real
        ///     anonymity set is below the floor. Never execute into a set small
        ///     enough to deanonymize by elimination.
        ///
        /// An epoch rolled forward at this slot is reconsidered when its new
        /// window closes on a later call.
        pub fn on_slot(&mut self, slot: u64) -> anyhow::Result<Vec<EpochOutcome>> {
            let closable: Vec<Epoch> = self
                .pool
                .pending_epochs()
                .into_iter()
                .filter(|epoch| self.config.schedule.settle_slot(*epoch) <= slot)
                .collect();

            let mut outcomes = Vec::with_capacity(closable.len());
            for epoch in closable {
                let k = self.pool.kanon(epoch);
                if !k.meets_floor(&self.config.schedule) {
                    let to = Epoch(epoch.0 + 1);
                    let moved = self.pool.roll_forward(epoch, to);
                    tracing::warn!(
                        epoch = epoch.0,
                        real_k = k.real_k(),
                        nominal = k.nominal,
                        k_floor = self.config.schedule.k_floor,
                        moved,
                        "epoch below k floor: rolling forward instead of settling"
                    );
                    outcomes.push(EpochOutcome::RolledForward {
                        epoch,
                        to,
                        real_k: k.real_k(),
                        moved,
                    });
                    continue;
                }

                // TODO(milestone-4): re-queue entries if submission fails so a
                // transient RPC error cannot drop an entire epoch's commits.
                let entries = self.pool.take_epoch(epoch);
                let batch = SettleBatch {
                    epoch,
                    nullifiers: entries.iter().map(|e| e.nullifier).collect(),
                    fee_payer: self.fee_payers.next_payer(),
                    tx_profile: self.config.tx_profile,
                };
                let receipt = self.submitter.submit_settle(&batch)?;
                tracing::info!(
                    epoch = epoch.0,
                    real_k = k.real_k(),
                    nullifiers = batch.nullifiers.len(),
                    signature = %receipt.signature,
                    "epoch settled"
                );
                outcomes.push(EpochOutcome::Settled {
                    epoch,
                    real_k: k.real_k(),
                    signature: receipt.signature,
                });
            }
            Ok(outcomes)
        }

        /// Drive the scheduler against a simulated slot clock: one slot per
        /// tick, from `start_slot` through `end_slot` inclusive. Lets the demo
        /// binary and integration tests run the full loop with no validator.
        ///
        /// TODO(milestone-4): production slot source (RPC `getSlot` polling or
        /// `slotSubscribe`) behind the same `on_slot` entry point.
        pub async fn run_simulated(
            &mut self,
            start_slot: u64,
            end_slot: u64,
            tick: Duration,
        ) -> anyhow::Result<()> {
            let mut interval = tokio::time::interval(tick);
            let mut slot = start_slot;
            while slot <= end_slot {
                interval.tick().await;
                self.on_slot(slot)?;
                slot += 1;
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mirror_core::{
        commit, nullifier, wire, ActionClass, Epoch, EpochSchedule, Secret, SizeBucket,
    };

    fn action() -> ActionClass {
        ActionClass::Swap {
            mint_in: [0xAA; 32],
            mint_out: [0xBB; 32],
            size: SizeBucket::Small,
        }
    }

    fn entry(seed: u8, epoch: Epoch, operator_owned: bool) -> PoolEntry {
        let secret = Secret::from_bytes([seed; 32]);
        PoolEntry {
            commitment: commit(&secret, &action(), epoch),
            nullifier: nullifier(&secret, epoch),
            operator_owned,
        }
    }

    fn test_config(k_floor: u32) -> Config {
        Config {
            schedule: EpochSchedule {
                epoch_slots: 10,
                k_floor,
            },
            fee_payers: vec![FeePayer([1; 32]), FeePayer([2; 32])],
            tx_profile: TxProfile::default(),
        }
    }

    #[test]
    fn under_floor_epoch_does_not_settle() {
        let mut c = Coordinator::new(test_config(3), InMemorySubmitter::default()).unwrap();
        c.pool_mut().insert(Epoch(0), entry(1, Epoch(0), false));
        c.pool_mut().insert(Epoch(0), entry(2, Epoch(0), false));

        // Window still open: nothing happens.
        let outcomes = c.on_slot(9).unwrap();
        assert!(outcomes.is_empty());

        // Window closed but real_k = 2 < k_floor = 3: roll forward, never settle.
        let outcomes = c.on_slot(10).unwrap();
        assert_eq!(outcomes.len(), 1);
        assert!(matches!(
            outcomes[0],
            EpochOutcome::RolledForward {
                real_k: 2,
                moved: 2,
                ..
            }
        ));
        assert!(
            c.submitter().submitted.is_empty(),
            "under-floor epoch must not settle"
        );
        assert_eq!(
            c.pool_mut().len(Epoch(1)),
            2,
            "entries roll into the next epoch"
        );
    }

    #[test]
    fn meets_floor_epoch_settles_exactly_once() {
        let mut c = Coordinator::new(test_config(3), InMemorySubmitter::default()).unwrap();
        for seed in 1..=3u8 {
            c.pool_mut().insert(Epoch(0), entry(seed, Epoch(0), false));
        }

        let outcomes = c.on_slot(10).unwrap();
        assert_eq!(outcomes.len(), 1);
        assert!(matches!(
            outcomes[0],
            EpochOutcome::Settled { real_k: 3, .. }
        ));
        assert_eq!(c.submitter().submitted.len(), 1);
        assert_eq!(c.submitter().submitted[0].nullifiers.len(), 3);

        // A later slot must not settle the same epoch again.
        let outcomes = c.on_slot(50).unwrap();
        assert!(outcomes.is_empty());
        assert_eq!(c.submitter().submitted.len(), 1);
    }

    #[test]
    fn operator_decoys_do_not_count_toward_floor() {
        let mut c = Coordinator::new(test_config(3), InMemorySubmitter::default()).unwrap();
        // Nominal 5, but 3 are operator decoys: real_k = 2 < 3.
        for seed in 1..=2u8 {
            c.pool_mut().insert(Epoch(0), entry(seed, Epoch(0), false));
        }
        for seed in 3..=5u8 {
            c.pool_mut().insert(Epoch(0), entry(seed, Epoch(0), true));
        }

        let k = c.pool_mut().kanon(Epoch(0));
        assert_eq!(k.nominal, 5);
        assert_eq!(k.real_k(), 2);

        c.on_slot(10).unwrap();
        assert!(
            c.submitter().submitted.is_empty(),
            "decoy-padded epoch must not settle"
        );
    }

    #[test]
    fn settle_batch_matches_wire_layout() {
        let batch = SettleBatch {
            epoch: Epoch(7),
            nullifiers: vec![
                entry(1, Epoch(7), false).nullifier,
                entry(2, Epoch(7), false).nullifier,
            ],
            fee_payer: FeePayer([9; 32]),
            tx_profile: TxProfile::default(),
        };
        let data = batch.instruction_data();
        assert_eq!(data[0], wire::tag::SETTLE_EPOCH);
        assert_eq!(data.len(), wire::SETTLE_HEADER_LEN + 2 * 32);
        assert_eq!(&data[1..9], &7u64.to_le_bytes());
        assert_eq!(&data[9..13], &2u32.to_le_bytes());
    }

    #[test]
    fn fee_payers_rotate_across_settlements() {
        let mut c = Coordinator::new(test_config(2), InMemorySubmitter::default()).unwrap();
        for seed in 1..=2u8 {
            c.pool_mut().insert(Epoch(0), entry(seed, Epoch(0), false));
        }
        for seed in 3..=4u8 {
            c.pool_mut().insert(Epoch(1), entry(seed, Epoch(1), false));
        }

        // Slot 20 closes both epoch 0 (settle slot 10) and epoch 1 (settle slot 20).
        c.on_slot(20).unwrap();
        let submitted = &c.submitter().submitted;
        assert_eq!(submitted.len(), 2);
        assert_ne!(
            submitted[0].fee_payer, submitted[1].fee_payer,
            "consecutive settlements must not reuse the same fee payer"
        );
    }
}
