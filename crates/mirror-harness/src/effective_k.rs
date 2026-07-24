//! Information-theoretic EFFECTIVE anonymity-set size.
//!
//! The attack table in [`crate`] answers "can an attacker attribute a settled
//! action to its initiator better than random?". This module answers a sharper,
//! independent question that the empirical mixer literature made the memorable
//! one: a pool that advertises `k` participants does NOT provide `k`-anonymity
//! once an adversary partitions those participants by information they already
//! hold. The advertised (nominal) set and the EFFECTIVE set are different
//! numbers, and the gap is the whole story.
//!
//! # The metric (Serjantov-Danezis 2002)
//!
//! Serjantov and Danezis, "Towards an Information Theoretic Metric for
//! Anonymity" (PET 2002), define the effective anonymity-set size of a target as
//! `2^H(p)`, where `p` is the probability distribution a concrete attacker
//! assigns over the candidate initiators after using every channel available to
//! it, and `H` is Shannon entropy in bits. A uniform `p` over `k` candidates
//! gives `2^H = k` (the advertised set is real); a distribution the attacker has
//! sharpened gives `2^H < k` (the advertised set was an overstatement).
//!
//! We report two effective sizes for every target, because they answer two
//! different adversary questions:
//!
//! - [`shannon_effective_size`] `= 2^H(p)`: the Serjantov-Danezis effective set
//!   size. The average uncertainty the attacker faces.
//! - [`min_entropy_size`] `= 1 / max_i p_i`: the min-entropy (worst-case)
//!   effective size, i.e. the reciprocal of the attacker's single best guess.
//!   This is the conservative measure a defender must quote; it is never larger
//!   than the Shannon size.
//!
//! # The dominant real leak: funding provenance
//!
//! The strongest real-world anchor (Section 3.5 of `docs/THREAT_MODEL.md`, and
//! the empirical references [1][2]) is the common-funding-source heuristic: a
//! handful of exchange hot-wallets / faucets fund most participants, so the `k`
//! committers collapse into a few funding-provenance equivalence classes. An
//! adversary that knows the partition assigns probability uniformly WITHIN the
//! true initiator's class and zero outside it, so the effective set shrinks
//! toward the class size, not `k`. Class sizes are heterogeneous (a dominant
//! exchange plus a long tail down to singletons), which is exactly why the
//! effective set has a small MEAN and a worst case of 1.
//!
//! On top of provenance we fold in the same behavioral channels the attack
//! battery models (timing, amount, wallet fingerprint), each of which further
//! sharpens `p`. Crucially, a channel only informs the attacker if SETTLEMENT
//! exposed it: mirror-pool's shared-epoch batch gives every action one settle
//! slot, one bucket amount, and one normalized fee shape, so the timing / amount
//! / fingerprint channels carry zero variance across the batch and contribute
//! nothing; and funding via the shielded path breaks the provenance partition
//! (one indistinguishable class). That is why a naive pool's effective set
//! collapses while mirror-pool's stays at nominal.
//!
//! # Honesty
//!
//! This is a MODEL, driven by the same deterministic synthetic populations the
//! attack table uses (fixed seed, ChaCha20, no wall-clock, re-derivable by any
//! reviewer). It is not a measurement of a live pool; the funding-provenance
//! partition is modeled from a realistic (Zipf) common-funder distribution
//! rather than read off-chain. It answers the "advertised k != effective k"
//! concern on the same axis the empirical literature raised it, and states its
//! assumptions rather than asserting a bare number. See `docs/EFFECTIVE_K.md`.

use std::collections::HashMap;

use mirror_core::KAnon;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

use crate::{EpochBatch, Population, Scenario};

/// RBF bandwidth (slots) for the timing channel: two committers whose public
/// commit slots are within a few tens of slots are plausible timing decoys for
/// each other, because the per-actor settlement delay (up to a few tens of
/// slots) blurs the commit-to-settle link by that much. Only used when
/// settlement actually exposed per-actor timing (Baseline); under shared-epoch
/// batching the timing channel is inactive regardless of this value.
const TIMING_BANDWIDTH_SLOTS: f64 = 30.0;

/// Relative RBF bandwidth for the amount channel: two committers whose intended
/// amounts are within this fraction of each other are amount-indistinguishable.
/// Small on purpose so unique amounts self-identify and only near-equal
/// (round-number) intents cluster, matching the amount-collision structure real
/// pools show.
const AMOUNT_REL_BANDWIDTH: f64 = 0.05;

/// A channel of side information the adversary can use to sharpen its
/// distribution over candidate initiators. Each maps to one attack in the
/// battery: [`Channel::FundingProvenance`] is the strengthened form of
/// `GasPayerReuse` (common-funder clustering, the dominant real leak),
/// [`Channel::Timing`] of `FifoTemporalMatch`, [`Channel::Amount`] of
/// `AmountMatch`, and [`Channel::Fingerprint`] of `WalletFingerprint`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Channel {
    /// Partition committers by their common funding source (exchange / faucet
    /// lineage). The dominant leak; a hard partition.
    FundingProvenance,
    /// Public commit timing linked to per-actor settlement timing.
    Timing,
    /// Intended amount linked to the settled amount.
    Amount,
    /// Habitual compute-unit price / fee settings.
    Fingerprint,
}

impl Channel {
    /// Every channel, in report order.
    pub const ALL: [Channel; 4] = [
        Channel::FundingProvenance,
        Channel::Timing,
        Channel::Amount,
        Channel::Fingerprint,
    ];
}

/// The effective anonymity accounting for one modeled population under one
/// choice of adversary channels. The headline is the GAP between `nominal_k`
/// and the effective sizes.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct EffectiveK {
    /// The advertised anonymity-set size (the per-epoch commit count).
    pub nominal_k: usize,
    /// Mean over targets of the Serjantov-Danezis effective size `2^H(p)`.
    pub shannon_effective_k: f64,
    /// Mean over targets of the min-entropy (worst-case) effective size
    /// `1 / max_i p_i`. Never larger than [`Self::shannon_effective_k`].
    pub min_entropy_k: f64,
    /// The single most-exposed target: the minimum over targets of the
    /// min-entropy size. This is the "worst-case 1" in a "30 -> 6.5
    /// (worst-case 1)" headline.
    pub worst_case_k: f64,
    /// Size of the largest funding-provenance class (mean over epochs, rounded).
    /// The best-hidden participants achieve at most this from provenance alone.
    pub dominant_class_size: usize,
}

/// Shannon entropy `H(p)` in bits over a weight vector `w` (need not be
/// normalized; zero and negative weights are ignored). `H = -sum p_i log2 p_i`
/// with `p_i = w_i / sum(w)`.
fn shannon_entropy_bits(weights: &[f64]) -> f64 {
    let total: f64 = weights.iter().filter(|&&w| w > 0.0).sum();
    if total <= 0.0 {
        return 0.0;
    }
    let mut h = 0.0;
    for &w in weights {
        if w > 0.0 {
            let p = w / total;
            h -= p * p.log2();
        }
    }
    h
}

/// The Serjantov-Danezis effective anonymity-set size `2^H(p)` of a distribution
/// given as a (possibly unnormalized) weight vector. A uniform vector of length
/// `k` returns `k`; a point mass returns `1`; an all-zero/empty vector returns
/// `0`.
pub fn shannon_effective_size(weights: &[f64]) -> f64 {
    let total: f64 = weights.iter().filter(|&&w| w > 0.0).sum();
    if total <= 0.0 {
        return 0.0;
    }
    2f64.powf(shannon_entropy_bits(weights))
}

/// The min-entropy (worst-case) effective size `1 / max_i p_i`: the reciprocal
/// of the attacker's single best guess. A uniform vector of length `k` returns
/// `k`; a point mass returns `1`; an all-zero/empty vector returns `0`. Always
/// `<= shannon_effective_size` of the same vector.
pub fn min_entropy_size(weights: &[f64]) -> f64 {
    let total: f64 = weights.iter().filter(|&&w| w > 0.0).sum();
    if total <= 0.0 {
        return 0.0;
    }
    let max_p = weights.iter().copied().fold(0.0f64, f64::max) / total;
    if max_p <= 0.0 {
        return 0.0;
    }
    1.0 / max_p
}

/// Deterministic mixing for the provenance RNG seed.
fn mix(seed: u64, epoch: u64, k: usize) -> u64 {
    seed.wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .wrapping_add(epoch.wrapping_mul(0x1000_0001))
        .wrapping_add((k as u64) << 8)
        .wrapping_add(0xE77C_77EE) // "eff-k" tag
}

/// Number of distinct common funders modeled for a `k`-set: roughly one funder
/// per four committers, floored at four. Combined with the Zipf popularity below
/// this yields a dominant exchange class, a mid tail, and singletons, so the
/// effective set has a small mean and a worst case of 1, matching the empirical
/// common-funding structure. Under the size-weighted mean, `k = 32` lands near
/// the empirical marquee (advertised set shrinks to roughly a fifth), with the
/// rarer funders producing singletons over the epoch stream.
fn funder_count(k: usize) -> usize {
    (k / 4).max(4)
}

/// Assign each committer in the batch a funding-provenance class id.
///
/// Under [`Scenario::Baseline`] committers draw a common funder from a Zipf
/// popularity (`weight(rank) = 1/(rank+1)`), so a few exchanges fund most
/// participants and the rest are rare or unique. Under [`Scenario::MirrorPool`]
/// funding flows through the shielded path, so the adversary cannot separate
/// funders: every committer is placed in ONE class (the partition is broken).
fn assign_provenance(batch: &EpochBatch, scenario: Scenario, seed: u64) -> Vec<usize> {
    let k = batch.profiles.len();
    if scenario == Scenario::MirrorPool {
        // Provenance broken: one indistinguishable class.
        return vec![0usize; k];
    }
    let n_funders = funder_count(k);
    let weights: Vec<f64> = (0..n_funders).map(|f| 1.0 / (f as f64 + 1.0)).collect();
    let cum: Vec<f64> = weights
        .iter()
        .scan(0.0, |acc, &w| {
            *acc += w;
            Some(*acc)
        })
        .collect();
    let total = *cum.last().expect("at least two funders");
    let mut rng = ChaCha20Rng::seed_from_u64(mix(seed, batch.epoch.0, k));
    (0..k)
        .map(|_| {
            let x = rng.gen::<f64>() * total;
            cum.iter().position(|&c| x < c).unwrap_or(n_funders - 1)
        })
        .collect()
}

/// Which behavioral channels SETTLEMENT actually exposed in this epoch, decided
/// by whether the observable varies across the settled actions. Under
/// shared-epoch batching every action shares one settle slot, one bucket amount,
/// and one normalized (cu_price, fee), so all three are constant and the
/// channels carry no information; under Baseline they vary and are live.
#[derive(Clone, Copy, Debug)]
struct ChannelActivity {
    timing: bool,
    amount: bool,
    fingerprint: bool,
}

fn varies<T: PartialEq + Copy>(first: T, rest: impl Iterator<Item = T>) -> bool {
    rest.into_iter().any(|x| x != first)
}

fn channel_activity(batch: &EpochBatch) -> ChannelActivity {
    let a = &batch.actions;
    match a.first() {
        None => ChannelActivity {
            timing: false,
            amount: false,
            fingerprint: false,
        },
        Some(f0) => ChannelActivity {
            timing: varies(f0.settle_slot, a.iter().map(|x| x.settle_slot)),
            amount: varies(f0.amount, a.iter().map(|x| x.amount)),
            fingerprint: varies((f0.cu_price, f0.fee), a.iter().map(|x| (x.cu_price, x.fee))),
        },
    }
}

/// Population-level scales for the fingerprint channel, so the (cu_price, fee)
/// distance is dimensionless. Standard deviation of the committers' habitual
/// settings, floored at 1 to avoid division by zero.
fn fingerprint_scales(pop: &Population) -> (f64, f64) {
    let cu: Vec<f64> = pop
        .batches
        .iter()
        .flat_map(|b| b.profiles.iter().map(|p| p.cu_price_habit as f64))
        .collect();
    let fee: Vec<f64> = pop
        .batches
        .iter()
        .flat_map(|b| b.profiles.iter().map(|p| p.fee_habit as f64))
        .collect();
    (std_dev(&cu), std_dev(&fee))
}

fn std_dev(values: &[f64]) -> f64 {
    let n = values.len().max(1) as f64;
    let mean = values.iter().sum::<f64>() / n;
    let var = values.iter().map(|v| (v - mean) * (v - mean)).sum::<f64>() / n;
    var.sqrt().max(1.0)
}

/// Squared-exponential (RBF) similarity `exp(-d^2)` for a normalized distance
/// `d`. `1` at zero distance, decaying smoothly; used by the soft channels.
fn rbf(d: f64) -> f64 {
    (-(d * d)).exp()
}

/// The adversary's posterior weight vector over the `k` committers for a known
/// target committer `t`: how indistinguishable each committer `i` is from `t`
/// under the enabled channels. `t` itself always has weight 1 (it matches
/// itself exactly), so the true initiator is always in support. The effective
/// set size of `t` is [`shannon_effective_size`] / [`min_entropy_size`] of this
/// vector.
fn posterior(
    batch: &EpochBatch,
    provenance: &[usize],
    t: usize,
    channels: &[Channel],
    activity: &ChannelActivity,
    cu_scale: f64,
    fee_scale: f64,
) -> Vec<f64> {
    let k = batch.profiles.len();
    let mut w = vec![1.0f64; k];
    let pt = &batch.profiles[t];
    for &ch in channels {
        match ch {
            Channel::FundingProvenance => {
                for (i, wi) in w.iter_mut().enumerate() {
                    if provenance[i] != provenance[t] {
                        *wi = 0.0;
                    }
                }
            }
            Channel::Timing => {
                if activity.timing {
                    for (i, wi) in w.iter_mut().enumerate() {
                        let d = (batch.profiles[i].commit_slot as f64 - pt.commit_slot as f64)
                            / TIMING_BANDWIDTH_SLOTS;
                        *wi *= rbf(d);
                    }
                }
            }
            Channel::Amount => {
                if activity.amount {
                    let scale = (pt.intent_amount as f64).max(1.0) * AMOUNT_REL_BANDWIDTH;
                    for (i, wi) in w.iter_mut().enumerate() {
                        let d = (batch.profiles[i].intent_amount as f64 - pt.intent_amount as f64)
                            / scale;
                        *wi *= rbf(d);
                    }
                }
            }
            Channel::Fingerprint => {
                if activity.fingerprint {
                    for (i, wi) in w.iter_mut().enumerate() {
                        let dc = (batch.profiles[i].cu_price_habit as f64
                            - pt.cu_price_habit as f64)
                            / cu_scale;
                        let df =
                            (batch.profiles[i].fee_habit as f64 - pt.fee_habit as f64) / fee_scale;
                        *wi *= rbf(dc) * rbf(df);
                    }
                }
            }
        }
    }
    w
}

/// The largest provenance class size in a batch.
fn dominant_class(provenance: &[usize]) -> usize {
    let mut counts: HashMap<usize, usize> = HashMap::new();
    for &c in provenance {
        *counts.entry(c).or_insert(0) += 1;
    }
    counts.values().copied().max().unwrap_or(1)
}

/// Compute the effective anonymity accounting for a modeled population under a
/// set of adversary channels. Iterates every committer of every settled epoch
/// as a target, builds the attacker's posterior, and aggregates the two
/// effective sizes plus the worst case and the dominant class size.
///
/// Deterministic in `(population, channels, seed)`.
pub fn effective_k(pop: &Population, channels: &[Channel], seed: u64) -> EffectiveK {
    let (cu_scale, fee_scale) = fingerprint_scales(pop);
    let mut sum_shannon = 0.0;
    let mut sum_min = 0.0;
    let mut worst = f64::INFINITY;
    let mut sum_dominant = 0.0;
    let mut n_targets = 0usize;
    let mut n_batches = 0usize;

    for batch in &pop.batches {
        if batch.profiles.is_empty() {
            continue;
        }
        let provenance = assign_provenance(batch, pop.scenario, seed);
        let activity = channel_activity(batch);
        sum_dominant += dominant_class(&provenance) as f64;
        n_batches += 1;
        for t in 0..batch.profiles.len() {
            let w = posterior(
                batch,
                &provenance,
                t,
                channels,
                &activity,
                cu_scale,
                fee_scale,
            );
            sum_shannon += shannon_effective_size(&w);
            let me = min_entropy_size(&w);
            sum_min += me;
            worst = worst.min(me);
            n_targets += 1;
        }
    }

    let n = n_targets.max(1) as f64;
    EffectiveK {
        nominal_k: pop.k,
        shannon_effective_k: sum_shannon / n,
        min_entropy_k: sum_min / n,
        worst_case_k: if worst.is_finite() {
            worst
        } else {
            pop.k as f64
        },
        dominant_class_size: (sum_dominant / n_batches.max(1) as f64).round() as usize,
    }
}

/// Generate the Baseline and MirrorPool populations for one `k` (from the same
/// shared actor stream, exactly as the attack table does) and return their
/// effective-k accounting under `channels`.
pub fn run_effective_k(
    k: usize,
    n_participants: usize,
    seed: u64,
    channels: &[Channel],
) -> (EffectiveK, EffectiveK) {
    use crate::PopulationConfig;
    let baseline = Population::generate(&PopulationConfig {
        n_participants,
        k,
        seed,
        scenario: Scenario::Baseline,
    });
    let mirror = Population::generate(&PopulationConfig {
        n_participants,
        k,
        seed,
        scenario: Scenario::MirrorPool,
    });
    (
        effective_k(&baseline, channels, seed),
        effective_k(&mirror, channels, seed),
    )
}

/// Effective-k when a fraction of each epoch's committers are attacker-owned
/// Sybils (the concrete form of an inflated nominal set: operator cover traffic
/// or funding-cluster decoys). An adversary that owns the decoys removes them
/// from every honest target's candidate set, so honest committers are anonymous
/// only among the remaining honest committers. This makes the [`KAnon`]
/// `excluded` subtraction an information-theoretic result rather than a bare
/// assertion: the effective set collapses from `nominal` toward
/// `real_k = nominal - excluded`.
///
/// Returns the effective-k over honest targets together with the [`KAnon`] the
/// scenario implies. `sybil_fraction` is clamped so at least one honest
/// committer remains.
pub fn effective_k_under_sybils(
    pop: &Population,
    sybil_fraction: f64,
    seed: u64,
) -> (EffectiveK, KAnon) {
    let k = pop.k;
    let raw = (sybil_fraction.clamp(0.0, 1.0) * k as f64).round() as usize;
    let sybils = raw.min(k.saturating_sub(1)); // keep >= 1 honest committer
    let mut sum_shannon = 0.0;
    let mut sum_min = 0.0;
    let mut worst = f64::INFINITY;
    let mut n_targets = 0usize;

    for batch in &pop.batches {
        let bk = batch.profiles.len();
        if bk == 0 {
            continue;
        }
        // Deterministic Sybil set: the first `sybils` committers in a
        // seed-derived rotation. Which specific committers are decoys does not
        // change the honest anonymity count, only which indices are excluded.
        let mut rng = ChaCha20Rng::seed_from_u64(mix(seed, batch.epoch.0, bk).wrapping_add(1));
        let offset = if bk > 0 { rng.gen_range(0..bk) } else { 0 };
        let is_sybil = |i: usize| -> bool {
            let rotated = (i + offset) % bk;
            rotated < sybils.min(bk)
        };
        for t in 0..bk {
            if is_sybil(t) {
                continue; // score honest targets only
            }
            // Honest target: uniform over the honest committers (the adversary
            // has removed every decoy it controls).
            let w: Vec<f64> = (0..bk)
                .map(|i| if is_sybil(i) { 0.0 } else { 1.0 })
                .collect();
            sum_shannon += shannon_effective_size(&w);
            let me = min_entropy_size(&w);
            sum_min += me;
            worst = worst.min(me);
            n_targets += 1;
        }
    }

    let n = n_targets.max(1) as f64;
    let eff = EffectiveK {
        nominal_k: k,
        shannon_effective_k: sum_shannon / n,
        min_entropy_k: sum_min / n,
        worst_case_k: if worst.is_finite() {
            worst
        } else {
            (k - sybils) as f64
        },
        dominant_class_size: sybils, // the decoy cluster
    };
    let kanon = KAnon {
        nominal: k as u32,
        excluded: sybils as u32,
    };
    (eff, kanon)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DEFAULT_SEED;

    const TEST_N: usize = 2048;

    // ---- entropy primitives ----

    #[test]
    fn uniform_distribution_gives_full_k() {
        for k in [2usize, 4, 8, 16, 32] {
            let p = vec![1.0f64; k];
            assert!(
                (shannon_effective_size(&p) - k as f64).abs() < 1e-9,
                "uniform over {k}: shannon should be {k}"
            );
            assert!(
                (min_entropy_size(&p) - k as f64).abs() < 1e-9,
                "uniform over {k}: min-entropy should be {k}"
            );
        }
    }

    #[test]
    fn point_mass_gives_one() {
        let p = vec![0.0, 0.0, 1.0, 0.0];
        assert!((shannon_effective_size(&p) - 1.0).abs() < 1e-9);
        assert!((min_entropy_size(&p) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn two_class_split_collapses_to_class_size() {
        // A distribution uniform within a class of size 3 and zero outside must
        // report an effective size of exactly the class size, by both measures.
        let p = vec![1.0, 1.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0];
        assert!((shannon_effective_size(&p) - 3.0).abs() < 1e-9);
        assert!((min_entropy_size(&p) - 3.0).abs() < 1e-9);
    }

    #[test]
    fn min_entropy_never_exceeds_shannon() {
        // A peaked (non-uniform) distribution: min-entropy is strictly the more
        // pessimistic (smaller) measure.
        let p = vec![4.0, 2.0, 1.0, 1.0];
        let sh = shannon_effective_size(&p);
        let me = min_entropy_size(&p);
        assert!(me <= sh + 1e-12, "min-entropy {me} must be <= shannon {sh}");
        assert!(me < sh, "for a peaked p the two measures must differ");
    }

    #[test]
    fn empty_and_zero_are_defined() {
        assert_eq!(shannon_effective_size(&[]), 0.0);
        assert_eq!(min_entropy_size(&[]), 0.0);
        assert_eq!(shannon_effective_size(&[0.0, 0.0]), 0.0);
        assert_eq!(min_entropy_size(&[0.0, 0.0]), 0.0);
    }

    // ---- modeled population effective-k ----

    #[test]
    fn deterministic() {
        let a = run_effective_k(16, 512, 7, &Channel::ALL);
        let b = run_effective_k(16, 512, 7, &Channel::ALL);
        assert_eq!(a, b, "effective-k must be re-derivable bit-for-bit");
    }

    #[test]
    fn provenance_collapses_baseline_but_not_mirrorpool() {
        // Provenance ALONE: the rival's marquee axis. Baseline effective-k must
        // be far below nominal (the funding partition shrinks the set), while
        // MirrorPool keeps it at nominal (the partition is broken).
        for k in [16usize, 32, 64] {
            let (base, mirror) =
                run_effective_k(k, TEST_N, DEFAULT_SEED, &[Channel::FundingProvenance]);
            assert_eq!(base.nominal_k, k);
            assert!(
                base.shannon_effective_k < 0.5 * k as f64,
                "k={k}: provenance must collapse Baseline effective-k well below nominal, got {:.2}",
                base.shannon_effective_k
            );
            assert!(
                base.worst_case_k <= 1.0 + 1e-9,
                "k={k}: some committer must have a unique funder (worst case 1), got {:.2}",
                base.worst_case_k
            );
            assert!(
                (mirror.shannon_effective_k - k as f64).abs() < 1e-6,
                "k={k}: broken provenance must keep MirrorPool at nominal, got {:.2}",
                mirror.shannon_effective_k
            );
        }
    }

    #[test]
    fn full_channel_gap_baseline_vs_mirrorpool() {
        // With every channel the naive pool is almost fully deanonymizable while
        // mirror-pool stays at nominal: the central claim of the metric.
        for k in [16usize, 32, 64] {
            let (base, mirror) = run_effective_k(k, TEST_N, DEFAULT_SEED, &Channel::ALL);
            assert!(
                base.shannon_effective_k < 0.25 * k as f64,
                "k={k}: full-channel Baseline effective-k should be a small fraction of nominal, got {:.2}",
                base.shannon_effective_k
            );
            assert!(
                (mirror.shannon_effective_k - k as f64).abs() < 1e-6,
                "k={k}: full-channel MirrorPool effective-k should equal nominal, got {:.2}",
                mirror.shannon_effective_k
            );
            assert!(
                mirror.min_entropy_k <= mirror.shannon_effective_k + 1e-9,
                "min-entropy never exceeds shannon"
            );
        }
    }

    #[test]
    fn adding_channels_never_increases_effective_k() {
        // Each additional channel can only sharpen the attacker's distribution,
        // so effective-k is monotonically non-increasing as channels are added.
        let (p, _) = run_effective_k(32, TEST_N, DEFAULT_SEED, &[Channel::FundingProvenance]);
        let (pt, _) = run_effective_k(
            32,
            TEST_N,
            DEFAULT_SEED,
            &[Channel::FundingProvenance, Channel::Timing],
        );
        let (all, _) = run_effective_k(32, TEST_N, DEFAULT_SEED, &Channel::ALL);
        assert!(pt.shannon_effective_k <= p.shannon_effective_k + 1e-9);
        assert!(all.shannon_effective_k <= pt.shannon_effective_k + 1e-9);
    }

    #[test]
    fn sybil_dominance_collapses_effective_k_to_real_k() {
        // The "excluded=0 never demonstrates shrinkage" gap, fixed: with a
        // Sybil-dominated set the effective-k drops from nominal to real_k, and
        // matches KAnon's honest subtraction exactly.
        let mirror = Population::generate(&crate::PopulationConfig {
            n_participants: TEST_N,
            k: 32,
            seed: DEFAULT_SEED,
            scenario: Scenario::MirrorPool,
        });
        let (eff, kanon) = effective_k_under_sybils(&mirror, 0.75, DEFAULT_SEED);
        let real_k = kanon.real_k() as f64;
        assert!(
            kanon.excluded > 0,
            "the scenario must actually exclude Sybils"
        );
        assert!(
            (eff.shannon_effective_k - real_k).abs() < 1e-9,
            "effective-k {:.2} must equal real_k {:.2}",
            eff.shannon_effective_k,
            real_k
        );
        assert!(
            real_k < eff.nominal_k as f64,
            "real_k must be below nominal (shrinkage demonstrated)"
        );
    }
}
