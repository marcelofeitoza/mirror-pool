//! The FUNDING leg, modeled: where each committer's wallet got its lamports, and
//! what an observer can still recover from the public boundary crossings.
//!
//! # Why this module exists
//!
//! The effective-k metric ([`crate::effective_k`]) is dominated by one channel:
//! funding provenance. A committer whose fresh wallet was topped up by an
//! ordinary transfer from their main wallet is re-linked by walking that single
//! public edge, and the epoch's committers partition into funding classes.
//!
//! mirror-pool's answer is a MECHANISM, not an assumption: the participant funds
//! the fresh commit wallet by unshielding from the confidential-value pool
//! (`mirror-cli fund-commit`, released by
//! `mirror_coordinator::funding::FundingRounds`). The vault is the on-chain
//! sender and the relay is the only signer, so the main-wallet-to-commit-wallet
//! edge is never written.
//!
//! # The residual this module refuses to wish away
//!
//! `publicAmount` is on-chain-visible on both crossings. The observer sees
//!
//! - **deposits**: (funder identity, amount, slot) for every shield, and
//! - **withdrawals**: (fresh commit wallet, amount, slot) for every unshield,
//!
//! and only the pairing between them is hidden. So the funding edge is not
//! erased, it is downgraded to a MATCHING PROBLEM, and the adversary's residual
//! advantage is exactly how well it can solve that matching. A participant who
//! shields a distinctive amount and withdraws it minutes later has published the
//! matching in all but name.
//!
//! We model the adversary as knowing the protocol (Kerckhoffs) and therefore
//! using the correct generative model of the funding mechanism. Two channels
//! feed it:
//!
//! - **Amount channel.** A deposit is a plausible source for a withdrawal in
//!   proportion to how close their amounts are ([`AMOUNT_REL_BANDWIDTH`]). Under
//!   a denominated pool every amount is the same number and this channel is
//!   dead by protocol rule (the program rejects anything else as
//!   `DenominationMismatch`); under a free-amount pool it is close to an oracle.
//! - **Timing channel.** A deposit is a plausible source only if it could
//!   causally have produced the withdrawal under the policy in force: within
//!   [`IMMEDIATE_MAX_LAG_SLOTS`] before it when withdrawals are submitted as soon
//!   as they are proved, or within the last `dwell_rounds + 1` funding rounds
//!   when the coordinator batches them. Causality is a hard constraint and it
//!   leaks: a deposit made after a withdrawal cannot have funded it, so the
//!   corresponding committer is eliminated outright.
//!
//! On top of those, [`MatchingAdversary`] decides how hard the attacker works at
//! the resulting matching problem: score each withdrawal on its own, or solve
//! the whole assignment at once (each deposit funds exactly one withdrawal).
//! Every published number uses the second, stronger one; the harness prints both
//! so the difference is a measurement rather than a claim.
//!
//! # Honesty
//!
//! This is a model of the mechanism, not a measurement of a live pool. What it
//! is not is circular: the MirrorPool provenance classes are DERIVED from the
//! funding mechanism above, so if the mechanism leaks, the metric reports the
//! leak. The measured numbers, including the ones that come out below nominal,
//! are published in `docs/EFFECTIVE_K.md`.

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

use crate::{BUCKET_AMOUNT, EPOCH_SLOTS};

/// Slots in the funding window that precedes an epoch's commit window. One epoch
/// of lead time: participants fund shortly before they commit.
pub const FUNDING_WINDOW_SLOTS: u64 = EPOCH_SLOTS;

/// Maximum lag (slots) between a shield and the matching unshield when
/// withdrawals are NOT batched: a participant funding a wallet they are about to
/// use acts within seconds. This is the naive behavior, and it is what makes the
/// timing channel an oracle.
pub const IMMEDIATE_MAX_LAG_SLOTS: u64 = 20;

/// Relative RBF bandwidth for the funding amount channel: a deposit within this
/// fraction of a withdrawal's amount is a plausible source for it. Same constant
/// the settlement-side amount channel uses, so the two are calibrated alike.
pub const AMOUNT_REL_BANDWIDTH: f64 = 0.05;

/// Default funding-round length in slots. Matches
/// `mirror_coordinator::funding::DEFAULT_ROUND_SLOTS`, so the modeled policy is
/// the one the shipped coordinator actually runs.
pub const DEFAULT_ROUND_SLOTS: u64 = 150;

/// Default number of rounds a participant may dwell shielded before their
/// funding withdrawal is released. Dwell is what widens the causal window: with
/// `dwell_rounds = 0` a withdrawal must come from its own round's deposits.
pub const DEFAULT_DWELL_ROUNDS: u64 = 2;

/// How a committer's fresh wallet got funded, as a protocol configuration.
///
/// The four fields are orthogonal on purpose: the ablation in the harness turns
/// them on one at a time, so the reported before/after attributes the shrinkage
/// to the mechanism responsible for it rather than to the bundle.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct FundingPolicy {
    /// The value pool's fixed denomination. `Some(d)`: every shield and unshield
    /// moves exactly `d`, enforced on-chain. `None`: free amounts, and a
    /// participant who pass-through-funds publishes a matching pair.
    pub denomination: Option<u64>,
    /// Funding-round length in slots; `0` means withdrawals are submitted as soon
    /// as they are proved (no batching).
    pub round_slots: u64,
    /// Rounds a participant may dwell shielded before their withdrawal is
    /// released. Ignored when `round_slots == 0`. Unrelated to the incentive
    /// `dwell` in `docs/INCENTIVES.md`, which counts epochs committed.
    pub dwell_rounds: u64,
    /// Fraction of committers that fund through the shielded path at all. The
    /// rest top up directly from their main wallet and are fully re-linked, and
    /// they also shrink the crowd for everyone else, because an adversary that
    /// can place them elsewhere eliminates them as candidates.
    pub adoption: f64,
}

impl FundingPolicy {
    /// The naive shielded funding a participant does if the protocol does not
    /// stop them: shield the amount they need, withdraw it immediately. Amounts
    /// and timing both match, so the matching problem is nearly free to solve.
    pub const fn pass_through() -> Self {
        Self {
            denomination: None,
            round_slots: 0,
            dwell_rounds: 0,
            adoption: 1.0,
        }
    }

    /// Uniform denomination only: the amount channel is closed, the timing
    /// channel is untouched.
    pub const fn denominated_only() -> Self {
        Self {
            denomination: Some(BUCKET_AMOUNT),
            ..Self::pass_through()
        }
    }

    /// Batched funding rounds only: arrival timing is destroyed, but a free
    /// amount still identifies the deposit.
    pub const fn batched_only() -> Self {
        Self {
            round_slots: DEFAULT_ROUND_SLOTS,
            dwell_rounds: DEFAULT_DWELL_ROUNDS,
            ..Self::pass_through()
        }
    }

    /// The recommended configuration: a denominated pool plus batched funding rounds,
    /// with participants dwelling a couple of rounds before their withdrawal is
    /// released. Both channels are attacked at once. Denomination and batching are
    /// enforced by code (the program and the batcher type); dwell is participant
    /// behaviour the protocol can recommend and measure but NOT enforce, so this is
    /// the cooperative case, not the guaranteed one. For the guarantee use
    /// [`Self::uniform_rounds_with_dwell`] with `0`.
    pub const fn uniform_rounds() -> Self {
        Self {
            denomination: Some(BUCKET_AMOUNT),
            round_slots: DEFAULT_ROUND_SLOTS,
            dwell_rounds: DEFAULT_DWELL_ROUNDS,
            adoption: 1.0,
        }
    }

    /// Same as [`Self::uniform_rounds`] with a different dwell, for the dwell
    /// sweep.
    pub const fn uniform_rounds_with_dwell(dwell_rounds: u64) -> Self {
        Self {
            dwell_rounds,
            ..Self::uniform_rounds()
        }
    }

    /// Same as [`Self::uniform_rounds`] with partial adoption.
    pub const fn with_adoption(self, adoption: f64) -> Self {
        Self { adoption, ..self }
    }

    /// Whether withdrawals are batched into funding rounds.
    pub const fn batched(&self) -> bool {
        self.round_slots > 0
    }

    /// A short label for report tables.
    pub fn label(&self) -> String {
        let amount = if self.denomination.is_some() {
            "denominated"
        } else {
            "free-amount"
        };
        let timing = if self.batched() {
            format!("rounds({}s, dwell {})", self.round_slots, self.dwell_rounds)
        } else {
            "immediate".to_string()
        };
        if self.adoption >= 1.0 {
            format!("{amount} + {timing}")
        } else {
            format!(
                "{amount} + {timing} @ {:.0}% adoption",
                100.0 * self.adoption
            )
        }
    }
}

impl Default for FundingPolicy {
    /// The recommended (cooperative, dwell-2) configuration ([`Self::uniform_rounds`]).
    fn default() -> Self {
        Self::uniform_rounds()
    }
}

/// One public deposit into the value pool: how much, and when. WHO made it is
/// public too, but it is held in the caller's `funders` vector rather than
/// duplicated here, so the two can never disagree.
#[derive(Clone, Copy, Debug)]
struct Deposit {
    amount: u64,
    slot: u64,
}

/// One public withdrawal out of the value pool into a fresh commit wallet.
#[derive(Clone, Copy, Debug)]
struct Withdrawal {
    amount: u64,
    slot: u64,
    /// Funding round the withdrawal was released in, when batching is on.
    round: Option<u64>,
}

/// How hard the adversary works at the deposit-to-withdrawal matching.
///
/// This is a property of the ATTACKER, not of the protocol, which is why it is
/// separate from [`FundingPolicy`]. Reporting both is the point: a defender who
/// only ever evaluates the weak attacker is grading their own homework.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum MatchingAdversary {
    /// Score each withdrawal on its own: the belief for withdrawal `i` is the
    /// normalized plausibility of every deposit as its source. Simple, and
    /// strictly weaker, because it forgets that a deposit can fund only one
    /// withdrawal.
    Independent,
    /// Solve the whole assignment at once. The model is a perfect matching
    /// between the round's deposits and its withdrawals, and the adversary wants
    /// the marginal `P[deposit d funded withdrawal i]` under the distribution
    /// over matchings weighted by plausibility. Exact marginals are permanents
    /// (`#P`-hard), so this uses [`SINKHORN_ITERS`] iterations of Sinkhorn
    /// scaling: alternately normalize rows and columns until the matrix is
    /// doubly stochastic. That enforces the "each deposit is used once"
    /// constraint the [`Self::Independent`] adversary ignores, and it sharpens
    /// the beliefs.
    #[default]
    Joint,
}

impl MatchingAdversary {
    /// Every adversary, in report order (weakest first).
    pub const ALL: [MatchingAdversary; 2] =
        [MatchingAdversary::Independent, MatchingAdversary::Joint];

    /// A short label for report tables.
    pub const fn label(&self) -> &'static str {
        match self {
            MatchingAdversary::Independent => "independent per-withdrawal marginals",
            MatchingAdversary::Joint => "joint matching (Sinkhorn)",
        }
    }
}

/// A protocol configuration together with the attacker it is evaluated against.
/// Every published effective-k number names both, because a number without an
/// attacker attached is not a claim.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct FundingModel {
    pub policy: FundingPolicy,
    pub adversary: MatchingAdversary,
}

impl FundingModel {
    /// `policy` against the strongest attacker implemented
    /// ([`MatchingAdversary::Joint`]). This is what the published tables use.
    pub const fn joint(policy: FundingPolicy) -> Self {
        Self {
            policy,
            adversary: MatchingAdversary::Joint,
        }
    }

    /// `policy` against the weaker per-withdrawal attacker, for the
    /// adversary-strength ablation.
    pub const fn independent(policy: FundingPolicy) -> Self {
        Self {
            policy,
            adversary: MatchingAdversary::Independent,
        }
    }

    /// A label naming both halves.
    pub fn label(&self) -> String {
        format!("{} vs {}", self.policy.label(), self.adversary.label())
    }
}

impl Default for FundingModel {
    /// The recommended (cooperative, dwell-2) configuration against the strongest
    /// implemented attacker.
    fn default() -> Self {
        Self::joint(FundingPolicy::default())
    }
}

impl From<FundingPolicy> for FundingModel {
    fn from(policy: FundingPolicy) -> Self {
        Self::joint(policy)
    }
}

/// Sinkhorn iterations for [`MatchingAdversary::Joint`]. The matrices here are
/// tiny (`k <= 64`) and the scaling converges geometrically, so this is a large
/// over-estimate of what is needed; it is fixed rather than tolerance-based so
/// the result is bit-identical on every machine.
pub const SINKHORN_ITERS: usize = 256;

/// The modeled public record of one epoch's funding, plus the adversary's
/// resulting belief about who funded whom.
#[derive(Clone, Debug)]
pub struct FundingTrace {
    model: FundingModel,
    /// Ground-truth funder of each committer.
    funders: Vec<usize>,
    /// Whether each committer used the shielded funding path.
    adopters: Vec<bool>,
    /// `belief[i][f]` = P[committer `i` was funded by funder `f`] under the
    /// adversary's model. Each row sums to 1.
    belief: Vec<Vec<f64>>,
}

/// Round-number funding top-ups: people move round amounts, which is what
/// creates the amount collisions a free-amount pool depends on for any cover at
/// all. Same shape as the settlement-side intent distribution.
const ROUND_TOP_UPS: [u64; 6] = [
    100_000_000,
    250_000_000,
    500_000_000,
    1_000_000_000,
    2_000_000_000,
    5_000_000_000,
];

/// Deterministic mixing tag for the funding RNG stream, kept disjoint from the
/// provenance and population streams so adding this model cannot perturb any
/// previously published number.
const FUNDING_TAG: u64 = 0xF0_1D_1E_5A;

fn rbf(d: f64) -> f64 {
    (-(d * d)).exp()
}

impl FundingTrace {
    /// Generate the public funding record for one epoch and precompute the
    /// adversary's belief matrix.
    ///
    /// `funders[i]` is committer `i`'s true funder (drawn by the caller from the
    /// same common-funder distribution the Baseline partition uses, so both
    /// scenarios describe the same crowd). `n_funders` is the funder-id space.
    ///
    /// Deterministic in `(funders, n_funders, epoch, seed, model)`. Every random
    /// draw is taken unconditionally and in a fixed order, so two policies see
    /// the SAME underlying population and differ only by the mechanism, and the
    /// choice of adversary changes only the inference, never the world.
    pub fn generate(
        funders: &[usize],
        n_funders: usize,
        epoch: u64,
        seed: u64,
        model: impl Into<FundingModel>,
    ) -> FundingTrace {
        let model = model.into();
        let policy = model.policy;
        let k = funders.len();
        let mut rng = ChaCha20Rng::seed_from_u64(
            seed.wrapping_mul(0x9E37_79B9_7F4A_7C15)
                .wrapping_add(epoch.wrapping_mul(0x1000_0001))
                .wrapping_add((k as u64) << 8)
                .wrapping_add(FUNDING_TAG),
        );

        let mut adopters = Vec::with_capacity(k);
        let mut deposits: Vec<Option<Deposit>> = Vec::with_capacity(k);
        let mut withdrawals: Vec<Option<Withdrawal>> = Vec::with_capacity(k);

        for _ in funders {
            // Fixed draw order, independent of the policy.
            let adopt_u: f64 = rng.gen();
            let shield_slot = rng.gen_range(0..FUNDING_WINDOW_SLOTS);
            let round_top_up = rng.gen_bool(0.30);
            let round_pick = rng.gen_range(0..ROUND_TOP_UPS.len());
            let free_top_up = rng.gen_range(5_000_000..=5_000_000_000u64);
            let lag = rng.gen_range(1..=IMMEDIATE_MAX_LAG_SLOTS);
            let dwell_u: f64 = rng.gen();

            let adopter = adopt_u < policy.adoption;
            adopters.push(adopter);
            if !adopter {
                // Direct top-up from the main wallet: no boundary crossing at all,
                // and the funding edge is public.
                deposits.push(None);
                withdrawals.push(None);
                continue;
            }

            let amount = match policy.denomination {
                Some(d) => d,
                None => {
                    if round_top_up {
                        ROUND_TOP_UPS[round_pick]
                    } else {
                        free_top_up
                    }
                }
            };
            let (withdraw_slot, round) = if policy.batched() {
                let shield_round = shield_slot / policy.round_slots;
                let dwell = (dwell_u * (policy.dwell_rounds + 1) as f64) as u64;
                let dwell = dwell.min(policy.dwell_rounds);
                let round = shield_round + dwell;
                ((round + 1) * policy.round_slots, Some(round))
            } else {
                (shield_slot + lag, None)
            };
            deposits.push(Some(Deposit {
                amount,
                slot: shield_slot,
            }));
            withdrawals.push(Some(Withdrawal {
                amount,
                slot: withdraw_slot,
                round,
            }));
        }

        let belief = build_belief(
            funders,
            n_funders,
            &adopters,
            &deposits,
            &withdrawals,
            model,
        );
        FundingTrace {
            model,
            funders: funders.to_vec(),
            adopters,
            belief,
        }
    }

    /// The adversary's probability that committer `i` was funded by `funder`.
    ///
    /// This is the whole provenance channel: a targeted adversary knows the
    /// TARGET's funder (that is what "targeted" means), and asks of every
    /// committer how likely they are to be funded by it. A point mass reproduces
    /// the hard funding-class partition of a naive pool; a flat row means the
    /// committer is provenance-indistinguishable from the rest of the crowd.
    pub fn belief(&self, i: usize, funder: usize) -> f64 {
        self.belief[i].get(funder).copied().unwrap_or(0.0)
    }

    /// Ground-truth funder of committer `i`.
    pub fn funder(&self, i: usize) -> usize {
        self.funders[i]
    }

    /// Whether committer `i` funded through the shielded path.
    pub fn is_adopter(&self, i: usize) -> bool {
        self.adopters[i]
    }

    pub fn policy(&self) -> FundingPolicy {
        self.model.policy
    }

    pub fn model(&self) -> FundingModel {
        self.model
    }

    /// The adversary's single best guess at each committer's funder (the MAP
    /// assignment). Used only for reporting the largest apparent provenance
    /// class; the metric itself uses the full distribution.
    pub fn map_classes(&self) -> Vec<usize> {
        self.belief
            .iter()
            .map(|row| {
                let mut best = 0usize;
                let mut best_w = f64::NEG_INFINITY;
                for (f, &w) in row.iter().enumerate() {
                    if w > best_w {
                        best_w = w;
                        best = f;
                    }
                }
                best
            })
            .collect()
    }
}

/// Build the row-normalized belief matrix from the public funding record.
///
/// Committers who did NOT adopt the shielded path get a point-mass row: their
/// funding edge is a public transfer, so there is nothing to infer. The rest are
/// scored by the requested [`MatchingAdversary`] over the plausibility matrix
/// (withdrawals as rows, deposits as columns).
fn build_belief(
    funders: &[usize],
    n_funders: usize,
    adopters: &[bool],
    deposits: &[Option<Deposit>],
    withdrawals: &[Option<Withdrawal>],
    model: FundingModel,
) -> Vec<Vec<f64>> {
    let k = funders.len();
    let mut belief = vec![vec![0.0f64; n_funders]; k];

    // The adopters, and the plausibility matrix over them. Both the rows
    // (withdrawals) and the columns (deposits) are indexed by position in
    // `adopter_ids`, because a non-adopter has neither.
    let adopter_ids: Vec<usize> = (0..k).filter(|&i| adopters[i]).collect();
    let m = adopter_ids.len();
    let mut w: Vec<Vec<f64>> = vec![vec![0.0; m]; m];
    for (row, &i) in adopter_ids.iter().enumerate() {
        let withdrawal = withdrawals[i].expect("an adopter has a withdrawal");
        for (col, &j) in adopter_ids.iter().enumerate() {
            let deposit = deposits[j].expect("an adopter has a deposit");
            w[row][col] = plausibility(&deposit, &withdrawal, model.policy);
        }
        debug_assert!(
            w[row][row] > 0.0,
            "the true deposit is always a plausible source for its own withdrawal"
        );
    }

    if model.adversary == MatchingAdversary::Joint {
        // Enforce the assignment constraint the independent adversary ignores:
        // each deposit funds exactly one withdrawal.
        sinkhorn(&mut w, SINKHORN_ITERS);
    }
    normalize_rows(&mut w);

    for i in 0..k {
        if !adopters[i] {
            // Funded by a public transfer: the adversary reads the funder off the
            // chain, so the row is a point mass and this committer is exactly as
            // exposed as they would be with no pool at all.
            belief[i][funders[i]] = 1.0;
        }
    }
    for (row, &i) in adopter_ids.iter().enumerate() {
        let mut any = false;
        for (col, &j) in adopter_ids.iter().enumerate() {
            let weight = w[row][col];
            if weight > 0.0 {
                belief[i][funders[j]] += weight;
                any = true;
            }
        }
        if !any {
            // Unreachable given the debug assertion above, but a silently
            // all-zero row would poison the entropy, so fall back to the truth
            // (the pessimistic direction).
            belief[i][funders[i]] = 1.0;
        }
    }
    belief
}

/// Normalize every row to sum to 1, leaving all-zero rows alone.
fn normalize_rows(w: &mut [Vec<f64>]) {
    for row in w.iter_mut() {
        let total: f64 = row.iter().sum();
        if total > 0.0 {
            for cell in row.iter_mut() {
                *cell /= total;
            }
        }
    }
}

/// Sinkhorn scaling: alternately normalize rows and columns so the matrix
/// approaches doubly stochastic.
///
/// The fixed point is the standard approximation to the marginals of the
/// matching distribution `P(sigma) proportional to prod_i w[i][sigma(i)]`, whose
/// exact marginals are permanents and therefore `#P`-hard. It converges whenever
/// the matrix has support (some permutation with all-positive entries), which
/// holds here because the true funding assignment is exactly such a permutation.
///
/// Zero rows and zero columns are skipped rather than divided by, so a
/// degenerate input cannot produce NaN.
fn sinkhorn(w: &mut [Vec<f64>], iters: usize) {
    let m = w.len();
    if m == 0 {
        return;
    }
    for _ in 0..iters {
        normalize_rows(w);
        for col in 0..m {
            let total: f64 = (0..m).map(|row| w[row][col]).sum();
            if total > 0.0 {
                for row in w.iter_mut() {
                    row[col] /= total;
                }
            }
        }
    }
}

/// How plausible `deposit` is as the source of `withdrawal`, under an adversary
/// that knows the funding policy. Zero when the pairing is impossible.
fn plausibility(deposit: &Deposit, withdrawal: &Withdrawal, policy: FundingPolicy) -> f64 {
    // Timing: causality is hard, and the policy bounds how long value may sit.
    let timing = match (policy.batched(), withdrawal.round) {
        (true, Some(round)) => {
            let deposit_round = deposit.slot / policy.round_slots;
            // A deposit made after the withdrawal's round cannot have funded it,
            // and one older than the dwell bound has already been released.
            if deposit_round > round || round - deposit_round > policy.dwell_rounds {
                0.0
            } else {
                1.0
            }
        }
        _ => {
            if withdrawal.slot > deposit.slot
                && withdrawal.slot - deposit.slot <= IMMEDIATE_MAX_LAG_SLOTS
            {
                1.0
            } else {
                0.0
            }
        }
    };
    if timing == 0.0 {
        return 0.0;
    }
    // Amount: identical under a denominated pool, near-identifying otherwise.
    let scale = (withdrawal.amount as f64).max(1.0) * AMOUNT_REL_BANDWIDTH;
    let d = (deposit.amount as f64 - withdrawal.amount as f64) / scale;
    timing * rbf(d)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: u64 = 0x4d49_5252_4f52;

    /// A crowd of `k` committers with `n` distinct funders, round-robin assigned
    /// so class sizes are known exactly.
    fn crowd(k: usize, n: usize) -> Vec<usize> {
        (0..k).map(|i| i % n).collect()
    }

    /// Mean, over committers, of the belief mass the adversary puts on the
    /// committer's TRUE funder. 1.0 means provenance is fully recovered; 1/n
    /// means the adversary learned nothing beyond the funder prior.
    fn mean_truth_mass(trace: &FundingTrace, funders: &[usize]) -> f64 {
        let n = funders.len() as f64;
        funders
            .iter()
            .enumerate()
            .map(|(i, &f)| trace.belief(i, f))
            .sum::<f64>()
            / n
    }

    #[test]
    fn deterministic() {
        let funders = crowd(32, 8);
        let a = FundingTrace::generate(&funders, 8, 3, SEED, FundingPolicy::uniform_rounds());
        let b = FundingTrace::generate(&funders, 8, 3, SEED, FundingPolicy::uniform_rounds());
        assert_eq!(a.belief, b.belief, "the funding model must be re-derivable");
    }

    #[test]
    fn belief_rows_are_distributions() {
        let funders = crowd(32, 8);
        for policy in [
            FundingPolicy::pass_through(),
            FundingPolicy::denominated_only(),
            FundingPolicy::batched_only(),
            FundingPolicy::uniform_rounds(),
        ] {
            for adversary in MatchingAdversary::ALL {
                let model = FundingModel { policy, adversary };
                let trace = FundingTrace::generate(&funders, 8, 0, SEED, model);
                for (i, row) in trace.belief.iter().enumerate() {
                    let sum: f64 = row.iter().sum();
                    assert!(
                        (sum - 1.0).abs() < 1e-9,
                        "{}: row {i} sums to {sum}",
                        model.label()
                    );
                    assert!(
                        trace.belief(i, funders[i]) > 0.0,
                        "{}: the true funder must always keep positive mass",
                        model.label()
                    );
                }
            }
        }
    }

    #[test]
    fn sinkhorn_makes_the_matrix_doubly_stochastic() {
        // The joint adversary's only mathematical claim: after scaling, every
        // withdrawal's beliefs sum to 1 AND every deposit is spent exactly once.
        // The second half is the constraint the independent adversary ignores.
        let mut w = vec![
            vec![1.0, 1.0, 0.0, 0.0],
            vec![1.0, 1.0, 1.0, 0.0],
            vec![0.0, 1.0, 1.0, 1.0],
            vec![0.0, 0.0, 1.0, 1.0],
        ];
        sinkhorn(&mut w, SINKHORN_ITERS);
        normalize_rows(&mut w);
        for (i, row) in w.iter().enumerate() {
            let sum: f64 = row.iter().sum();
            assert!((sum - 1.0).abs() < 1e-9, "row {i} sums to {sum}");
        }
        for col in 0..w.len() {
            let sum: f64 = w.iter().map(|row| row[col]).sum();
            assert!(
                (sum - 1.0).abs() < 1e-6,
                "column {col} sums to {sum}; the deposit is not spent exactly once"
            );
        }
    }

    #[test]
    fn sinkhorn_leaves_impossible_pairings_at_zero() {
        // Causality eliminations must survive the scaling: a deposit that cannot
        // have funded a withdrawal must stay at probability 0, not be smoothed
        // back in.
        let mut w = vec![
            vec![1.0, 0.0, 2.0],
            vec![0.0, 1.0, 1.0],
            vec![1.0, 1.0, 0.0],
        ];
        sinkhorn(&mut w, SINKHORN_ITERS);
        normalize_rows(&mut w);
        assert_eq!(w[0][1], 0.0);
        assert_eq!(w[1][0], 0.0);
        assert_eq!(w[2][2], 0.0);
        assert!(w.iter().flatten().all(|x| x.is_finite()));
    }

    #[test]
    fn sinkhorn_survives_a_degenerate_matrix() {
        // An all-zero row/column must not produce NaN (it cannot arise from the
        // generator, but a metric that silently returns NaN is worse than one
        // that returns a wrong number, so this is pinned).
        let mut w = vec![vec![0.0, 0.0], vec![0.0, 1.0]];
        sinkhorn(&mut w, 8);
        assert!(w.iter().flatten().all(|x| x.is_finite()));
        let mut empty: Vec<Vec<f64>> = Vec::new();
        sinkhorn(&mut empty, 8);
    }

    #[test]
    fn sinkhorn_is_an_approximation_not_a_bound() {
        // An honest negative result about our own attacker, found by looking for
        // it. Sinkhorn scaling approximates the marginals of the matching
        // distribution; it is not guaranteed to put MORE mass on the truth in
        // every single instance. Here is a measured instance where it puts
        // slightly less: k=16 under denominated rounds at dwell 2.
        //
        // The aggregate claim the tables make is still the one that is tested,
        // in `effective_k::tests::joint_adversary_never_leaves_more_effective_k`:
        // over the whole reported grid the joint attacker leaves LESS effective
        // anonymity. This test exists so nobody upgrades that into "the joint
        // attacker is provably stronger", which the measurement does not say.
        let funders = crowd(16, 4);
        let policy = FundingPolicy::uniform_rounds();
        let independent = mean_truth_mass(
            &FundingTrace::generate(&funders, 4, 0, SEED, FundingModel::independent(policy)),
            &funders,
        );
        let joint = mean_truth_mass(
            &FundingTrace::generate(&funders, 4, 0, SEED, FundingModel::joint(policy)),
            &funders,
        );
        assert!(
            joint < independent,
            "this instance is the documented counterexample: joint {joint:.4} should be BELOW \
             independent {independent:.4}; if the model changed, the caveat in \
             docs/EFFECTIVE_K.md has to be re-derived rather than deleted"
        );
        // Both are nonetheless far above the 1/4 funder prior: the residual is
        // real under either attacker.
        assert!(joint > 0.25 && independent > 0.25);
    }

    #[test]
    fn joint_matching_strictly_sharpens_a_denominated_pool() {
        // Where the constraint bites hardest: a denominated pool with immediate
        // withdrawals leaves a narrow causal window, so knowing that each deposit
        // is spent once measurably re-links funders.
        let funders = crowd(32, 8);
        let policy = FundingPolicy::denominated_only();
        let independent = mean_truth_mass(
            &FundingTrace::generate(&funders, 8, 0, SEED, FundingModel::independent(policy)),
            &funders,
        );
        let joint = mean_truth_mass(
            &FundingTrace::generate(&funders, 8, 0, SEED, FundingModel::joint(policy)),
            &funders,
        );
        assert!(
            joint > independent + 1e-6,
            "the joint attacker must be strictly better here: {joint:.4} vs {independent:.4}"
        );
    }

    #[test]
    fn pass_through_funding_leaks_the_funder() {
        // Shield the amount you are about to withdraw, withdraw it immediately:
        // the adversary recovers the funding link almost perfectly. This is the
        // honest negative result about naive shielded funding.
        let funders = crowd(32, 8);
        let trace = FundingTrace::generate(&funders, 8, 0, SEED, FundingPolicy::pass_through());
        let mass = mean_truth_mass(&trace, &funders);
        assert!(
            mass > 0.8,
            "pass-through funding should leave the funder nearly recovered, got {mass:.3}"
        );
    }

    #[test]
    fn uniform_rounds_shrink_the_residual() {
        // Denomination plus batching plus dwell: the adversary's mass on the true
        // funder collapses toward the prior.
        let funders = crowd(32, 8);
        let naive = FundingTrace::generate(&funders, 8, 0, SEED, FundingPolicy::pass_through());
        let mitigated =
            FundingTrace::generate(&funders, 8, 0, SEED, FundingPolicy::uniform_rounds());
        let naive_mass = mean_truth_mass(&naive, &funders);
        let mitigated_mass = mean_truth_mass(&mitigated, &funders);
        assert!(
            mitigated_mass < 0.5 * naive_mass,
            "uniform rounds must at least halve the recovered mass: {naive_mass:.3} -> {mitigated_mass:.3}"
        );
    }

    #[test]
    fn each_mitigation_alone_is_weaker_than_both() {
        let funders = crowd(32, 8);
        let mass = |p: FundingPolicy| {
            mean_truth_mass(&FundingTrace::generate(&funders, 8, 0, SEED, p), &funders)
        };
        let both = mass(FundingPolicy::uniform_rounds());
        assert!(
            both < mass(FundingPolicy::denominated_only()),
            "denomination alone must leak more than denomination + rounds"
        );
        assert!(
            both < mass(FundingPolicy::batched_only()),
            "batching alone must leak more than denomination + rounds"
        );
    }

    #[test]
    fn more_dwell_never_leaks_more() {
        let funders = crowd(32, 8);
        let mass = |dwell: u64| {
            mean_truth_mass(
                &FundingTrace::generate(
                    &funders,
                    8,
                    0,
                    SEED,
                    FundingPolicy::uniform_rounds_with_dwell(dwell),
                ),
                &funders,
            )
        };
        let (m0, m1, m2, m4) = (mass(0), mass(1), mass(2), mass(4));
        assert!(m1 <= m0 + 1e-9, "dwell 1 must not leak more than dwell 0");
        assert!(m2 <= m1 + 1e-9, "dwell 2 must not leak more than dwell 1");
        assert!(m4 <= m2 + 1e-9, "dwell 4 must not leak more than dwell 2");
        assert!(m4 < m0, "more dwell must measurably help");
    }

    #[test]
    fn non_adopters_are_fully_exposed() {
        let funders = crowd(32, 8);
        let trace = FundingTrace::generate(
            &funders,
            8,
            0,
            SEED,
            FundingPolicy::uniform_rounds().with_adoption(0.5),
        );
        let mut adopters = 0usize;
        for (i, &funder) in funders.iter().enumerate() {
            if trace.is_adopter(i) {
                adopters += 1;
            } else {
                assert_eq!(
                    trace.belief(i, funder),
                    1.0,
                    "a committer who topped up directly is fully re-linked"
                );
            }
        }
        assert!(
            adopters > 0 && adopters < funders.len(),
            "the 50% adoption scenario must contain both kinds of committer, got {adopters}/32"
        );
    }

    #[test]
    fn causality_eliminates_impossible_sources() {
        // A deposit that lands after the withdrawal cannot have funded it. Under
        // batching this shows up as zero belief mass on funders whose deposits are
        // all in later rounds, which is a real residual (it removes candidates)
        // and must not be smoothed away.
        let funders = crowd(24, 24); // one funder each, so classes are singletons
        let trace = FundingTrace::generate(
            &funders,
            24,
            0,
            SEED,
            FundingPolicy::uniform_rounds_with_dwell(0),
        );
        let zeros = (0..24)
            .flat_map(|i| (0..24).map(move |f| (i, f)))
            .filter(|&(i, f)| trace.belief(i, f) == 0.0)
            .count();
        assert!(
            zeros > 24 * 24 / 2,
            "with dwell 0 most (committer, funder) pairs must be causally impossible, got {zeros}"
        );
    }
}
