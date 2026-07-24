//! Adversarial evaluation harness for mirror-pool. This is the differentiator:
//! we do not assert privacy, we attack it and publish the numbers.
//!
//! # What is measured
//!
//! A population of participants each initiates one pooled action. An attacker
//! observes the commit-side records (who committed, when, with what wallet
//! habits and funding history) and the settled execution-side [`Action`]
//! records, and tries to attribute each settled action back to its initiator.
//! Random guessing inside an anonymity set of size `k` is right `1/k` of the
//! time, so we report every attack as an *advantage over `1/k`* on a held-out
//! split (attacks may calibrate on the first half of epochs, they are scored
//! only on the second half).
//!
//! # The two scenarios
//!
//! - [`Scenario::Baseline`] models what naive privacy tooling does: each actor
//!   settles after a private per-actor random delay (distinct timestamps),
//!   pays their own gas from a wallet funded by their usual source (distinct
//!   funding roots), moves a variable and often round amount, and signs with
//!   their habitual compute-unit price and fee settings.
//! - [`Scenario::MirrorPool`] models this protocol: every action in an epoch
//!   settles in one shared-epoch batch on a single `settle_slot` (shared
//!   timestamp defeats FIFO temporal matching, the strongest empirical attack
//!   on Tornado-style pools), amounts are quantized to one fixed
//!   [`SizeBucket`] (fixed action shape defeats amount matching), gas is paid
//!   by a small rotating relay fee-payer set (gasless execution defeats
//!   gas-payer and funding-root reuse), and the coordinator normalizes
//!   cu_price/fee (uniform shape defeats wallet fingerprinting).
//!
//! The attacks are fresh Rust implementations of the Wang et al. heuristics
//! (arXiv:2201.09035; amount matching, temporal correlation, gas-payer reuse),
//! recast from "effective vs claimed anonymity set" into per-action
//! attribution advantage so the two scenarios are directly comparable at equal
//! nominal `k`.
//!
//! # Honesty rules
//!
//! - Fully deterministic: fixed seeds, ChaCha20 streams, no wall-clock.
//! - Ground truth lives in [`EpochBatch::truth`] and is never shown to
//!   [`Attack::attribute`]; `fit` sees it only for the training split.
//! - The suite reports [`KAnon`] real k, never just the nominal batch size.
//!   In synthetic mode nothing is excluded; the exclusion logic gets real once
//!   operator wallets and funding-cluster Sybils exist in a live trace.
//!
//! TODO(milestone: docs/ROADMAP.md v1 deliverable 6): add the remaining
//! attackers (TemporalCorrelation across epochs, CommonFunding clustering, and
//! the learned classifier) on top of the [`Attack`] trait below.
//! TODO(milestone: docs/ROADMAP.md v1 deliverable 7): add an on-chain trace
//! loader (technique: a Surfpool/devnet RPC settlement-trace loader, built
//! fresh) so the same attacks run against a real Surfpool/devnet settlement
//! trace instead of synthetic populations.

use std::collections::HashMap;

use mirror_core::{Epoch, EpochSchedule, KAnon, SizeBucket};
use rand::{seq::SliceRandom, Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

/// Information-theoretic effective anonymity-set size (Serjantov-Danezis 2002):
/// nominal `k` vs the effective `2^H(p)` and min-entropy sizes an adversary
/// leaves after partitioning by funding provenance and the behavioral channels.
/// This is the answer to "advertised k != effective k"; see the module docs.
pub mod effective_k;

/// Fixed default seed so every run of the harness reproduces byte-identical
/// numbers. Never replace this with wall-clock entropy: reviewers must be able
/// to re-derive the published table.
pub const DEFAULT_SEED: u64 = 0x4d49_5252_4f52; // "MIRROR" tag, arbitrary but fixed

/// Slots per epoch window. Matches the order of magnitude a real pool would
/// pick (a few minutes) and is shared by both scenarios so the comparison is
/// apples to apples.
pub const EPOCH_SLOTS: u64 = 600;

/// The single fixed bucket amount every MirrorPool action settles with. One
/// pool serves one bucket: heterogeneous amounts leak exactly like mixed
/// denominations, so the bucket is a protocol constant, not a user choice.
pub const BUCKET_AMOUNT: u64 = 100_000_000;

/// Size of the rotating relay fee-payer set. Small on purpose: relay keys are
/// operator infrastructure shared across ALL participants, so reusing them
/// links actions to the relay, never to an initiator.
pub const RELAY_SET_SIZE: u64 = 4;

/// Coordinator-normalized compute-unit price applied to every settled action.
/// A uniform value carries zero bits about the initiator.
pub const RELAY_CU_PRICE: u64 = 10_000;

/// Coordinator-normalized transaction fee (lamports) for every settled action.
pub const RELAY_TX_FEE: u64 = 5_000;

/// Baseline actors settle within this many slots of their commit. Small
/// delays are realistic (users act within seconds of deciding) and are what
/// makes FIFO matching so strong against per-actor timing.
const BASELINE_MAX_DELAY_SLOTS: u64 = 20;

/// Protocol variable fee in basis points over 1000, mirroring the 0.3% fee
/// model the Python simulator used. Applied to Baseline settled amounts so
/// AmountMatch has to reconstruct the deposit->settle arithmetic, exactly as
/// Wang et al. do against real pools.
const VARIABLE_FEE_NUM: u64 = 3;
const VARIABLE_FEE_DEN: u64 = 1_000;

// Disjoint id namespaces so a funding root can never collide with a wallet id
// across categories. Synthetic ids only, no real keys anywhere in this crate.
const ACTOR_ROOT_BASE: u64 = 1_000_000;
const FRESH_ROOT_BASE: u64 = 2_000_000_000;
const RELAY_ROOT_BASE: u64 = 3_000_000_000;
const FRESH_WALLET_BASE: u64 = 4_000_000_000;

/// One settled, publicly observable action. This is exactly what a chain
/// observer sees after settlement; nothing here names the initiator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Action {
    /// Execution wallet. Fresh in both scenarios (even naive tooling rotates
    /// wallets); the leaks live in the other fields.
    pub wallet_id: u64,
    /// Epoch the action belongs to.
    pub epoch: Epoch,
    /// Slot the action settled in. Under MirrorPool every action in the epoch
    /// shares this value (shared-epoch batching), which is the whole defense
    /// against temporal attacks.
    pub settle_slot: u64,
    /// Coarse size bucket of the settled amount.
    pub size: SizeBucket,
    /// Settled amount in native units, net of protocol fees.
    pub amount: u64,
    /// Transaction fee (lamports) paid by the fee payer.
    pub fee: u64,
    /// Compute-unit price the settling transaction used.
    pub cu_price: u64,
    /// True when the initiator paid their own gas. MirrorPool is gasless for
    /// participants, so this is always false there.
    pub self_paid_gas: bool,
    /// Cluster id of whoever funded the fee payer (the faucet/CEX/hot-wallet
    /// lineage an attacker recovers by walking SOL transfers). Under
    /// MirrorPool this is a rotating relay root shared across everyone.
    pub funding_root: u64,
}

/// The commit-side view of one participant: everything an attacker can know
/// about an initiator BEFORE settlement (commit timestamp, wallet history
/// habits, funding lineage, and economic intent).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActorProfile {
    pub actor_id: u64,
    /// Slot of the public commit transaction. Commits stay individually
    /// timestamped in both scenarios; MirrorPool's defense is that settlement
    /// carries no per-actor time, not that commits are hidden.
    pub commit_slot: u64,
    /// The amount the actor intends to move. Under MirrorPool the protocol
    /// quantizes intent to [`BUCKET_AMOUNT`] at commit time, so the attacker
    /// gains nothing from this field there by construction.
    pub intent_amount: u64,
    /// Habitual compute-unit price from the actor's prior public activity.
    pub cu_price_habit: u64,
    /// Habitual transaction fee from prior public activity.
    pub fee_habit: u64,
    /// Funding lineage of the actor's known wallets.
    pub funding_root: u64,
}

/// One epoch of ground-truth data: `k` commit-side profiles, `k` settled
/// actions in observed (block) order, and the hidden truth mapping.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochBatch {
    pub epoch: Epoch,
    pub profiles: Vec<ActorProfile>,
    pub actions: Vec<Action>,
    /// `truth[j]` is the index into `profiles` of the initiator of
    /// `actions[j]`. Scoring-only: never passed to [`Attack::attribute`].
    pub truth: Vec<usize>,
}

/// Which world the population was rendered under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scenario {
    /// Naive privacy tooling: per-actor random delay, self-paid gas, variable
    /// and round amounts, distinct funding roots, habitual fee settings.
    Baseline,
    /// mirror-pool: shared-epoch batch settlement, gasless rotating relay
    /// fee payers, one fixed size bucket, coordinator-normalized fee shape.
    MirrorPool,
}

/// Generator configuration. `k` is the anonymity-set size per epoch; the
/// generator always fills full batches because the on-chain `k_floor` rule
/// (see [`EpochSchedule`]) rolls under-filled epochs forward instead of
/// settling them, so a settled epoch is a full epoch by construction.
#[derive(Clone, Copy, Debug)]
pub struct PopulationConfig {
    pub n_participants: usize,
    pub k: usize,
    pub seed: u64,
    pub scenario: Scenario,
}

/// A generated synthetic population, grouped into per-epoch batches.
#[derive(Clone, Debug)]
pub struct Population {
    pub scenario: Scenario,
    pub k: usize,
    pub batches: Vec<EpochBatch>,
}

/// Intrinsic (scenario-independent) properties of one synthetic participant.
/// The same actor stream is used for both scenarios so the comparison shows
/// the same people under two protocols, not two different crowds.
#[derive(Clone, Copy, Debug)]
struct Actor {
    id: u64,
    commit_slot: u64,
    intent_amount: u64,
    habit_cu_price: u64,
    habit_fee: u64,
    funding_root: u64,
    /// A minority of Baseline actors practice funding hygiene (fresh funding
    /// root for the acting wallet). Most do not, which is what makes
    /// gas-payer/funding reuse so effective in the wild.
    careful_hygiene: bool,
}

fn derive_seed(seed: u64, k: usize, tag: u64) -> u64 {
    seed.wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .wrapping_add((k as u64) << 8)
        .wrapping_add(tag)
}

const SEED_TAG_ACTORS: u64 = 0xA0;
const SEED_TAG_BASELINE: u64 = 0xB1;
const SEED_TAG_MIRROR: u64 = 0xC2;

/// Multiplicative jitter of +/- `pct` percent, integer math only.
fn jitter(rng: &mut ChaCha20Rng, value: u64, pct: u64) -> u64 {
    value * rng.gen_range(100 - pct..=100 + pct) / 100
}

/// Coarse bucket classification for Baseline settled amounts (MirrorPool
/// actions are all [`SizeBucket::Small`] by protocol rule).
fn bucket_of(amount: u64) -> SizeBucket {
    match amount {
        0..=49_999_999 => SizeBucket::Nano,
        50_000_000..=499_999_999 => SizeBucket::Small,
        500_000_000..=4_999_999_999 => SizeBucket::Medium,
        _ => SizeBucket::Large,
    }
}

fn sample_actor(rng: &mut ChaCha20Rng, id: u64, window_start: u64) -> Actor {
    // 30% of intents are round numbers (people love round amounts), which
    // creates the amount-collision structure real pools show. The rest are
    // effectively unique, the worst case for variable-amount privacy.
    let intent_amount = if rng.gen_bool(0.30) {
        const ROUND: [u64; 6] = [
            100_000_000,
            250_000_000,
            500_000_000,
            1_000_000_000,
            2_000_000_000,
            5_000_000_000,
        ];
        ROUND[rng.gen_range(0..ROUND.len())]
    } else {
        rng.gen_range(5_000_000..=5_000_000_000)
    };
    Actor {
        id,
        commit_slot: window_start + rng.gen_range(0..EPOCH_SLOTS),
        intent_amount,
        // TODO(milestone: docs/ROADMAP.md v1 deliverable 7): calibrate habit
        // distributions from a real trace instead of uniform sampling.
        habit_cu_price: rng.gen_range(1_000..=200_000),
        habit_fee: 5_000 + rng.gen_range(0..=20_000),
        funding_root: ACTOR_ROOT_BASE + id,
        careful_hygiene: rng.gen_bool(0.15),
    }
}

impl Actor {
    fn profile(&self, scenario: Scenario) -> ActorProfile {
        ActorProfile {
            actor_id: self.id,
            commit_slot: self.commit_slot,
            intent_amount: match scenario {
                Scenario::Baseline => self.intent_amount,
                // The pool quantizes intent into the fixed bucket at commit
                // time, so even the commit side carries no amount signal.
                Scenario::MirrorPool => BUCKET_AMOUNT,
            },
            cu_price_habit: self.habit_cu_price,
            fee_habit: self.habit_fee,
            funding_root: self.funding_root,
        }
    }
}

impl Population {
    /// Deterministically generate a population for one scenario. Two RNG
    /// streams are used: an actor stream keyed by (seed, k) shared across
    /// scenarios, and an observation stream keyed additionally by scenario
    /// for delays, jitters, and block-order shuffles.
    pub fn generate(cfg: &PopulationConfig) -> Population {
        assert!(cfg.k >= 2, "anonymity set needs at least 2 members");
        assert!(cfg.n_participants >= cfg.k, "need at least one full batch");

        let schedule = EpochSchedule {
            epoch_slots: EPOCH_SLOTS,
            k_floor: cfg.k as u32,
        };
        let n_batches = cfg.n_participants / cfg.k;
        let mut rng_actors =
            ChaCha20Rng::seed_from_u64(derive_seed(cfg.seed, cfg.k, SEED_TAG_ACTORS));
        let scenario_tag = match cfg.scenario {
            Scenario::Baseline => SEED_TAG_BASELINE,
            Scenario::MirrorPool => SEED_TAG_MIRROR,
        };
        let mut rng_obs = ChaCha20Rng::seed_from_u64(derive_seed(cfg.seed, cfg.k, scenario_tag));

        let mut fresh_wallet_ctr: u64 = 0;
        let mut relay_ctr: u64 = 0;
        let mut batches = Vec::with_capacity(n_batches);

        for e in 0..n_batches {
            let epoch = Epoch(e as u64);
            let window_start = epoch.0 * EPOCH_SLOTS;

            let actors: Vec<Actor> = (0..cfg.k)
                .map(|i| sample_actor(&mut rng_actors, (e * cfg.k + i) as u64, window_start))
                .collect();
            let profiles: Vec<ActorProfile> =
                actors.iter().map(|a| a.profile(cfg.scenario)).collect();

            // Observed block order is a shuffle of actor order. Under
            // MirrorPool this shuffle is all the ordering information an
            // attacker gets, because every action shares one settle_slot.
            let mut order: Vec<usize> = (0..cfg.k).collect();
            order.shuffle(&mut rng_obs);

            let mut actions = Vec::with_capacity(cfg.k);
            let mut truth = Vec::with_capacity(cfg.k);
            for &i in &order {
                let a = &actors[i];
                fresh_wallet_ctr += 1;
                let action = match cfg.scenario {
                    Scenario::Baseline => {
                        // Distinct per-actor timestamp: commit + small private
                        // delay. This is the signal FIFO matching feeds on.
                        let settle_slot =
                            a.commit_slot + rng_obs.gen_range(1..=BASELINE_MAX_DELAY_SLOTS);
                        let protocol_fee = a.intent_amount * VARIABLE_FEE_NUM / VARIABLE_FEE_DEN;
                        let amount = a.intent_amount - protocol_fee;
                        Action {
                            wallet_id: FRESH_WALLET_BASE + fresh_wallet_ctr,
                            epoch,
                            settle_slot,
                            size: bucket_of(amount),
                            amount,
                            fee: jitter(&mut rng_obs, a.habit_fee, 10),
                            cu_price: jitter(&mut rng_obs, a.habit_cu_price, 10),
                            self_paid_gas: true,
                            funding_root: if a.careful_hygiene {
                                FRESH_ROOT_BASE + a.id
                            } else {
                                a.funding_root
                            },
                        }
                    }
                    Scenario::MirrorPool => {
                        relay_ctr += 1;
                        Action {
                            wallet_id: FRESH_WALLET_BASE + fresh_wallet_ctr,
                            epoch,
                            // Shared-epoch batching: the entire epoch settles
                            // on ONE slot, so "who settled first" does not
                            // exist as a question.
                            settle_slot: schedule.settle_slot(epoch),
                            size: SizeBucket::Small,
                            amount: BUCKET_AMOUNT,
                            fee: RELAY_TX_FEE,
                            cu_price: RELAY_CU_PRICE,
                            self_paid_gas: false,
                            // Gasless: fee payer drawn from a small rotating
                            // relay set. The root links to the operator, never
                            // to an initiator.
                            // TODO(milestone: docs/ROADMAP.md v1 deliverable 3,
                            // coordinator): mirror the coordinator's actual
                            // rotation policy once it lands.
                            funding_root: RELAY_ROOT_BASE + (relay_ctr % RELAY_SET_SIZE),
                        }
                    }
                };
                actions.push(action);
                truth.push(i);
            }

            batches.push(EpochBatch {
                epoch,
                profiles,
                actions,
                truth,
            });
        }

        Population {
            scenario: cfg.scenario,
            k: cfg.k,
            batches,
        }
    }

    /// Temporal holdout: attacks may calibrate on the first half of epochs
    /// and are scored on the second half, mimicking an attacker who learned
    /// from history and now attacks live traffic.
    pub fn split(&self) -> (&[EpochBatch], &[EpochBatch]) {
        let mid = self.batches.len() / 2;
        self.batches.split_at(mid)
    }
}

/// A heuristic (or learned) attacker. Implementations get the commit-side
/// profiles and the settled actions of one epoch and must guess, for every
/// action, which profile initiated it.
pub trait Attack {
    fn name(&self) -> &'static str;

    /// Calibrate on the training split (ground truth visible). Default is a
    /// no-op for non-parametric heuristics.
    fn fit(&mut self, _train: &[EpochBatch]) {}

    /// For each action `j`, return the guessed index into `profiles` of its
    /// initiator. Ground truth is never available here.
    fn attribute(&self, profiles: &[ActorProfile], actions: &[Action]) -> Vec<usize>;
}

/// FIFO temporal matching (Wang et al.): the earliest committer tends to be
/// the earliest to settle, so rank-align commits by `commit_slot` against
/// actions by `settle_slot`. Devastating against per-actor random delays;
/// structurally dead against shared-epoch batching, where every action in the
/// epoch carries the same `settle_slot` and the ordering signal is gone.
pub struct FifoTemporalMatch;

impl Attack for FifoTemporalMatch {
    fn name(&self) -> &'static str {
        "FifoTemporalMatch"
    }

    fn attribute(&self, profiles: &[ActorProfile], actions: &[Action]) -> Vec<usize> {
        let mut prof_order: Vec<usize> = (0..profiles.len()).collect();
        prof_order.sort_by_key(|&i| (profiles[i].commit_slot, i));
        let mut act_order: Vec<usize> = (0..actions.len()).collect();
        // Stable tie-break by observed block position: when all settle slots
        // are equal (MirrorPool) this degenerates to the block shuffle, i.e.
        // to a random guess.
        act_order.sort_by_key(|&j| (actions[j].settle_slot, j));

        let mut guess = vec![0usize; actions.len()];
        for (&pi, &aj) in prof_order.iter().zip(act_order.iter()) {
            guess[aj] = pi;
        }
        guess
    }
}

/// Amount matching: reconstruct the fee arithmetic and link each settled
/// amount to the nearest committed intent. Near-perfect against variable
/// amounts (unique values are self-identifying); returns exactly `1/k`
/// against a fixed bucket, where every intent and every settled amount is the
/// same number by protocol rule.
pub struct AmountMatch;

impl AmountMatch {
    /// The attacker's model of intent -> settled amount (0.3% variable fee,
    /// same integer math as the generator, as a real attacker would derive
    /// from the public fee schedule).
    fn predicted_settled(intent: u64) -> u64 {
        intent - intent * VARIABLE_FEE_NUM / VARIABLE_FEE_DEN
    }
}

impl Attack for AmountMatch {
    fn name(&self) -> &'static str {
        "AmountMatch"
    }

    fn attribute(&self, profiles: &[ActorProfile], actions: &[Action]) -> Vec<usize> {
        actions
            .iter()
            .map(|action| {
                let mut best = 0usize;
                let mut best_dist = i128::MAX;
                for (i, p) in profiles.iter().enumerate() {
                    let predicted = Self::predicted_settled(p.intent_amount) as i128;
                    let dist = (predicted - action.amount as i128).abs();
                    if dist < best_dist {
                        best_dist = dist;
                        best = i;
                    }
                }
                best
            })
            .collect()
    }
}

/// Wallet fingerprinting: users keep habitual cu_price / fee settings across
/// wallets because their tooling does. Nearest-neighbor in normalized
/// (cu_price, fee) space, with scales calibrated on the training split.
/// Collapses when the coordinator normalizes the transaction shape: every
/// settled action carries the same [`RELAY_CU_PRICE`] / [`RELAY_TX_FEE`], so
/// the feature space is a single point.
pub struct WalletFingerprint {
    cu_scale: f64,
    fee_scale: f64,
}

impl Default for WalletFingerprint {
    fn default() -> Self {
        Self {
            cu_scale: 1.0,
            fee_scale: 1.0,
        }
    }
}

impl WalletFingerprint {
    fn std(values: impl Iterator<Item = f64> + Clone) -> f64 {
        let n = values.clone().count().max(1) as f64;
        let mean = values.clone().sum::<f64>() / n;
        let var = values.map(|v| (v - mean) * (v - mean)).sum::<f64>() / n;
        var.sqrt().max(1.0)
    }
}

impl Attack for WalletFingerprint {
    fn name(&self) -> &'static str {
        "WalletFingerprint"
    }

    fn fit(&mut self, train: &[EpochBatch]) {
        let cu = train
            .iter()
            .flat_map(|b| b.actions.iter().map(|a| a.cu_price as f64));
        let fee = train
            .iter()
            .flat_map(|b| b.actions.iter().map(|a| a.fee as f64));
        self.cu_scale = Self::std(cu);
        self.fee_scale = Self::std(fee);
    }

    fn attribute(&self, profiles: &[ActorProfile], actions: &[Action]) -> Vec<usize> {
        actions
            .iter()
            .map(|action| {
                let mut best = 0usize;
                let mut best_dist = f64::INFINITY;
                for (i, p) in profiles.iter().enumerate() {
                    let dc = (action.cu_price as f64 - p.cu_price_habit as f64) / self.cu_scale;
                    let df = (action.fee as f64 - p.fee_habit as f64) / self.fee_scale;
                    let dist = dc * dc + df * df;
                    if dist < best_dist {
                        best_dist = dist;
                        best = i;
                    }
                }
                best
            })
            .collect()
    }
}

/// Gas-payer / funding reuse (Wang et al.'s most effective Tornado
/// heuristic): the fresh acting wallet was funded from the actor's usual
/// source, so walking the funding edge deanonymizes it. Under a gasless
/// rotating relay the fee payer's lineage belongs to the operator set and
/// matches no participant, so the attack falls back to guessing.
pub struct GasPayerReuse;

impl Attack for GasPayerReuse {
    fn name(&self) -> &'static str {
        "GasPayerReuse"
    }

    fn attribute(&self, profiles: &[ActorProfile], actions: &[Action]) -> Vec<usize> {
        let by_root: HashMap<u64, usize> = profiles
            .iter()
            .enumerate()
            .map(|(i, p)| (p.funding_root, i))
            .collect();
        actions
            .iter()
            .enumerate()
            .map(|(j, action)| {
                // Deterministic spread fallback when the root matches no
                // profile (hygienic actor or relay-paid action): expected
                // accuracy is exactly the 1/k random baseline.
                *by_root
                    .get(&action.funding_root)
                    .unwrap_or(&(j % profiles.len()))
            })
            .collect()
    }
}

/// The standard attack battery, in report order.
pub fn default_attacks() -> Vec<Box<dyn Attack>> {
    vec![
        Box::new(FifoTemporalMatch),
        Box::new(AmountMatch),
        Box::new(WalletFingerprint::default()),
        Box::new(GasPayerReuse),
    ]
}

/// One attack's score on the held-out split.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct AttackReport {
    pub attack: &'static str,
    /// Fraction of held-out actions attributed to the correct initiator.
    pub accuracy: f64,
    /// `accuracy - 1/k`. Zero means the attacker learned nothing beyond
    /// random guessing inside the anonymity set; that is the design target
    /// for every attack under MirrorPool.
    pub advantage: f64,
}

/// Fit on `train`, score on `test`.
pub fn evaluate_attack(
    attack: &mut dyn Attack,
    train: &[EpochBatch],
    test: &[EpochBatch],
) -> AttackReport {
    attack.fit(train);
    let mut correct = 0usize;
    let mut total = 0usize;
    for batch in test {
        let guess = attack.attribute(&batch.profiles, &batch.actions);
        assert_eq!(
            guess.len(),
            batch.actions.len(),
            "attack must attribute every action"
        );
        for (j, &g) in guess.iter().enumerate() {
            if g == batch.truth[j] {
                correct += 1;
            }
            total += 1;
        }
    }
    let k = test.first().map(|b| b.profiles.len()).unwrap_or(1).max(1);
    let accuracy = correct as f64 / total.max(1) as f64;
    AttackReport {
        attack: attack.name(),
        accuracy,
        advantage: accuracy - 1.0 / k as f64,
    }
}

/// Full result for one `k`: every attack under both scenarios, plus honest
/// k-anonymity accounting.
#[derive(Clone, Debug, PartialEq)]
pub struct SuiteResult {
    pub k: usize,
    pub n_participants: usize,
    /// Honest k reporting per mirror-core: real k excludes operator-owned and
    /// Sybil participants. Synthetic actors are all distinct and none are
    /// operator-owned, so nothing is excluded here yet.
    /// TODO(milestone: docs/ROADMAP.md v1 deliverable 7): derive `excluded`
    /// from operator wallets and funding-cluster Sybil detection when the
    /// harness ingests a real on-chain trace.
    pub kanon: KAnon,
    pub baseline: Vec<AttackReport>,
    pub mirror_pool: Vec<AttackReport>,
}

impl SuiteResult {
    pub fn report(reports: &[AttackReport], name: &str) -> Option<AttackReport> {
        reports.iter().copied().find(|r| r.attack == name)
    }
}

/// Run the whole battery for one `k`: generate both populations from the same
/// actor stream, evaluate every attack on the held-out half of each.
pub fn run_suite(k: usize, n_participants: usize, seed: u64) -> SuiteResult {
    let run_scenario = |scenario: Scenario| -> Vec<AttackReport> {
        let pop = Population::generate(&PopulationConfig {
            n_participants,
            k,
            seed,
            scenario,
        });
        let (train, test) = pop.split();
        let mut attacks = default_attacks();
        attacks
            .iter_mut()
            .map(|a| evaluate_attack(a.as_mut(), train, test))
            .collect()
    };

    SuiteResult {
        k,
        n_participants,
        kanon: KAnon {
            nominal: k as u32,
            excluded: 0,
        },
        baseline: run_scenario(Scenario::Baseline),
        mirror_pool: run_scenario(Scenario::MirrorPool),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_N: usize = 2048;

    fn suite(k: usize) -> SuiteResult {
        run_suite(k, TEST_N, DEFAULT_SEED)
    }

    fn adv(reports: &[AttackReport], name: &str) -> f64 {
        SuiteResult::report(reports, name)
            .unwrap_or_else(|| panic!("missing attack {name}"))
            .advantage
    }

    #[test]
    fn deterministic_across_runs() {
        // Fixed seed, no wall-clock: the published table must be re-derivable
        // bit-for-bit by any reviewer.
        assert_eq!(run_suite(8, 512, 7), run_suite(8, 512, 7));
    }

    #[test]
    fn mirrorpool_epochs_share_one_settle_slot_and_shape() {
        let pop = Population::generate(&PopulationConfig {
            n_participants: 256,
            k: 8,
            seed: DEFAULT_SEED,
            scenario: Scenario::MirrorPool,
        });
        for batch in &pop.batches {
            let slot = batch.actions[0].settle_slot;
            for a in &batch.actions {
                assert_eq!(a.settle_slot, slot, "shared-epoch batching violated");
                assert_eq!(a.amount, BUCKET_AMOUNT, "fixed bucket violated");
                assert_eq!(a.cu_price, RELAY_CU_PRICE);
                assert_eq!(a.fee, RELAY_TX_FEE);
                assert!(!a.self_paid_gas, "MirrorPool must be gasless");
                assert!(
                    a.funding_root >= RELAY_ROOT_BASE
                        && a.funding_root < RELAY_ROOT_BASE + RELAY_SET_SIZE,
                    "fee payer must come from the rotating relay set"
                );
            }
        }
    }

    /// The headline claim of the whole project: FIFO temporal matching is
    /// devastating against per-actor random delays and collapses to the 1/k
    /// random-guess baseline under shared-epoch batch settlement.
    #[test]
    fn fifo_advantage_high_under_baseline_and_collapses_under_mirrorpool() {
        for k in [4usize, 8, 16] {
            let s = suite(k);
            let baseline = adv(&s.baseline, "FifoTemporalMatch");
            let mirror = adv(&s.mirror_pool, "FifoTemporalMatch");
            assert!(
                baseline > 0.5,
                "k={k}: FIFO advantage should be HIGH under Baseline, got {baseline:.4}"
            );
            assert!(
                mirror.abs() < 0.05,
                "k={k}: FIFO advantage should be ~0 under MirrorPool, got {mirror:.4}"
            );
        }
    }

    #[test]
    fn amount_match_collapses_under_fixed_buckets() {
        for k in [4usize, 8, 16] {
            let s = suite(k);
            assert!(
                adv(&s.baseline, "AmountMatch") > 0.5,
                "k={k}: variable amounts should be near self-identifying"
            );
            assert!(
                adv(&s.mirror_pool, "AmountMatch").abs() < 0.05,
                "k={k}: one fixed bucket must carry zero amount signal"
            );
        }
    }

    #[test]
    fn gas_payer_reuse_collapses_under_rotating_relay() {
        for k in [4usize, 8, 16] {
            let s = suite(k);
            assert!(
                adv(&s.baseline, "GasPayerReuse") > 0.6,
                "k={k}: funding-root reuse should deanonymize most Baseline actors"
            );
            assert!(
                adv(&s.mirror_pool, "GasPayerReuse").abs() < 0.05,
                "k={k}: relay-paid gas must not link to initiators"
            );
        }
    }

    #[test]
    fn wallet_fingerprint_collapses_under_normalized_shape() {
        for k in [4usize, 8, 16] {
            let s = suite(k);
            assert!(
                adv(&s.baseline, "WalletFingerprint") > 0.3,
                "k={k}: habitual cu_price/fee should leak under Baseline"
            );
            assert!(
                adv(&s.mirror_pool, "WalletFingerprint").abs() < 0.05,
                "k={k}: coordinator-normalized shape must carry no fingerprint"
            );
        }
    }

    #[test]
    fn real_k_is_reported_not_nominal() {
        let s = suite(8);
        assert_eq!(s.kanon.real_k(), 8, "synthetic mode excludes nothing yet");
        // The type forces the subtraction, so once exclusion logic lands the
        // report cannot silently fall back to the nominal count.
        assert_eq!(s.kanon.real_k(), s.kanon.nominal - s.kanon.excluded);
    }
}
