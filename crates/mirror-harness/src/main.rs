//! mirror-harness binary: runs the adversarial attack battery on synthetic
//! Baseline vs MirrorPool populations and prints the advantage table.
//!
//! Deterministic by construction (fixed seed, no wall-clock): running this
//! twice prints the same numbers, so the table in the README is reproducible
//! by any reviewer with `cargo run -p mirror-harness --release`.
//!
//! TODO(milestone: docs/ROADMAP.md v1 deliverable 7): add a `--source
//! surfpool-rpc` mode that feeds a real on-chain settlement trace through the
//! same attacks, mirroring the Python simulator's loader.

use anyhow::{ensure, Result};
use mirror_harness::effective_k::{
    effective_k_under_sybils, run_effective_k_with_funding, Channel, EffectiveK,
};
use mirror_harness::funding::{FundingModel, FundingPolicy};
use mirror_harness::{
    run_suite, AttackReport, Population, PopulationConfig, Scenario, SuiteResult, DEFAULT_SEED,
};

/// At least 2000 synthetic participants per (scenario, k); 2048 divides
/// evenly into batches for every k below.
const N_PARTICIPANTS: usize = 2048;
const KS: [usize; 3] = [4, 8, 16];
/// Nominal set sizes for the effective-k table. Larger than the attack-table
/// `KS` so the effective-vs-nominal gap is legible (a pool advertising k=16/32/64
/// is the interesting regime for the "advertised != effective" claim).
const KS_EFFECTIVE: [usize; 3] = [16, 32, 64];

fn pct(x: f64) -> String {
    format!("{:6.2}%", 100.0 * x)
}

fn pp(x: f64) -> String {
    format!("{:+7.2}pp", 100.0 * x)
}

fn print_suite(s: &SuiteResult) {
    println!(
        "k = {:<2}  | random guess = {}  | real_k = {} (nominal {}, excluded {})",
        s.k,
        pct(1.0 / s.k as f64),
        s.kanon.real_k(),
        s.kanon.nominal,
        s.kanon.excluded,
    );
    println!("{}", "-".repeat(86));
    println!(
        "{:<20} {:>10} {:>10}   {:>10} {:>10}",
        "attack", "base acc", "base adv", "mirror acc", "mirror adv"
    );
    for (b, m) in s.baseline.iter().zip(s.mirror_pool.iter()) {
        debug_assert_eq!(b.attack, m.attack);
        println!(
            "{:<20} {:>10} {:>10}   {:>10} {:>10}",
            b.attack,
            pct(b.accuracy),
            pp(b.advantage),
            pct(m.accuracy),
            pp(m.advantage),
        );
    }
    println!();
}

fn find(reports: &[AttackReport], name: &str) -> Option<AttackReport> {
    SuiteResult::report(reports, name)
}

/// Ratio of effective to nominal, as a percentage (100% = the advertised set is
/// fully real; a small value is a large overstatement).
fn retained(eff: &EffectiveK) -> String {
    format!(
        "{:5.1}%",
        100.0 * eff.shannon_effective_k / eff.nominal_k as f64
    )
}

/// Width of the label column: wide enough for the longest funding-policy label,
/// so no row breaks the table alignment.
const LABEL_WIDTH: usize = 44;
/// Width of the whole effective-k table (the label column plus every numeric
/// column and its separators), used for the rule above each header.
const TABLE_WIDTH: usize = LABEL_WIDTH + 62;

fn print_effective_row(label: &str, eff: &EffectiveK) {
    println!(
        "{:<LABEL_WIDTH$} {:>7} {:>11.2} {:>11.2} {:>7.2} {:>9}   {:>8}",
        label,
        eff.nominal_k,
        eff.shannon_effective_k,
        eff.min_entropy_k,
        eff.worst_case_k,
        eff.dominant_class_size,
        retained(eff),
    );
}

fn print_effective_header() {
    println!("{}", "-".repeat(TABLE_WIDTH));
    println!(
        "{:<LABEL_WIDTH$} {:>7} {:>11} {:>11} {:>7} {:>9}   {:>8}",
        "scenario / funding policy",
        "nominal",
        "shannon-eff",
        "min-entropy",
        "worst",
        "dom-class",
        "retained"
    );
}

/// The MirrorPool funding policies reported in every table, in ablation order:
/// the naive one first (so the leak is not buried), then each mitigation alone,
/// then the shipped default with both.
fn reported_policies() -> [(&'static str, FundingPolicy); 4] {
    [
        (
            "MirrorPool: pass-through funding",
            FundingPolicy::pass_through(),
        ),
        (
            "MirrorPool: denominated only",
            FundingPolicy::denominated_only(),
        ),
        (
            "MirrorPool: batched rounds only",
            FundingPolicy::batched_only(),
        ),
        (
            "MirrorPool: denominated + rounds (default)",
            FundingPolicy::uniform_rounds(),
        ),
    ]
}

/// One block of the effective-k table: Baseline plus every MirrorPool funding
/// policy, at every nominal k, under `channels`.
fn print_effective_block(channels: &[Channel]) {
    print_effective_header();
    for &k in &KS_EFFECTIVE {
        // The Baseline row is funding-policy independent (a Baseline committer is
        // topped up by a public transfer), so any policy yields the same numbers.
        let (base, _) = run_effective_k_with_funding(
            k,
            N_PARTICIPANTS,
            DEFAULT_SEED,
            channels,
            FundingPolicy::pass_through(),
        );
        print_effective_row("Baseline: public funding edge", &base);
        for (label, policy) in reported_policies() {
            let (_, mirror) =
                run_effective_k_with_funding(k, N_PARTICIPANTS, DEFAULT_SEED, channels, policy);
            print_effective_row(label, &mirror);
        }
        println!();
    }
}

/// The effective-k table: nominal vs Serjantov-Danezis Shannon-effective vs
/// min-entropy (worst-case), Baseline vs MirrorPool under each funding policy,
/// at several nominal k.
fn print_effective_k_section() {
    println!("=================================================================================");
    println!("EFFECTIVE anonymity-set size (information-theoretic; Serjantov-Danezis 2002)");
    println!("=================================================================================");
    println!(
        "Effective set = 2^H(p) over the candidate initiators an adversary is left with, where"
    );
    println!(
        "H is Shannon entropy; min-entropy set = 1/max_i p_i (the attacker's single best guess)."
    );
    println!(
        "Dominant leak modeled: funding-provenance partitioning (a few common funders cluster the"
    );
    println!(
        "committers), plus the timing / amount / fingerprint channels the attack battery models."
    );
    println!();
    println!(
        "Baseline tops up its commit wallet by a public transfer, so its funding partition is"
    );
    println!("exact. MirrorPool funds by UNSHIELDING from the confidential-value pool, so the");
    println!("adversary is left matching the pool's public deposits to its public withdrawals:");
    println!(
        "publicAmount and slot are visible on both crossings, and how much that leaks is what"
    );
    println!("these rows measure. It is DERIVED from the funding mechanism, not assumed.");
    println!("Every MirrorPool row is scored against the STRONGEST attacker implemented here: one");
    println!(
        "that solves the whole deposit-to-withdrawal assignment jointly (block (c) prices the"
    );
    println!("weaker per-withdrawal attacker, so the difference is visible rather than assumed).");
    println!("MODEL, not a live-pool measurement (see docs/EFFECTIVE_K.md).");
    println!();

    // (a) Provenance ALONE: directly comparable to the marquee "advertised k
    // shrinks to a small effective k (worst-case 1)" result.
    println!("(a) Funding-provenance channel ALONE (the dominant real leak):");
    print_effective_block(&[Channel::FundingProvenance]);

    // (b) Every channel: provenance + timing + amount + fingerprint composed.
    println!("(b) All channels (provenance + timing + amount + fingerprint):");
    print_effective_block(&Channel::ALL);

    // (c) Adversary strength: the same worlds, scored by a weaker attacker. A
    // defender who only ever evaluates the weak attacker is grading their own
    // homework, so both are published.
    println!("(c) Adversary strength (provenance channel; how hard does the attacker work?):");
    println!("{}", "-".repeat(TABLE_WIDTH));
    println!(
        "independent = score each withdrawal on its own. joint = solve the whole assignment, so a"
    );
    println!(
        "deposit spent on one withdrawal is unavailable to another (Sinkhorn-approximated). Joint"
    );
    println!(
        "delta = joint minus independent: negative means the harder-working attacker left the"
    );
    println!("defender less anonymity, which is why the joint one is what every other block uses.");
    println!(
        "{:<44} {:>7} {:>13} {:>11} {:>9}",
        "funding policy", "nominal", "independent", "joint", "delta"
    );
    for &k in &KS_EFFECTIVE {
        for (label, policy) in reported_policies() {
            let (_, independent) = run_effective_k_with_funding(
                k,
                N_PARTICIPANTS,
                DEFAULT_SEED,
                &[Channel::FundingProvenance],
                FundingModel::independent(policy),
            );
            let (_, joint) = run_effective_k_with_funding(
                k,
                N_PARTICIPANTS,
                DEFAULT_SEED,
                &[Channel::FundingProvenance],
                FundingModel::joint(policy),
            );
            println!(
                "{:<44} {:>7} {:>13.2} {:>11.2} {:>9.2}",
                label.trim_start_matches("MirrorPool: "),
                k,
                independent.shannon_effective_k,
                joint.shannon_effective_k,
                joint.shannon_effective_k - independent.shannon_effective_k,
            );
        }
        println!();
    }

    // (d) The mitigation, swept: how much dwell buys, holding everything else at
    // the shipped default.
    println!("(d) Dwell sweep at nominal k=32 (denominated pool, batched rounds):");
    println!("{}", "-".repeat(TABLE_WIDTH));
    println!(
        "longer dwell widens the causal window an observer must search, so fewer deposits are"
    );
    println!("eliminated as impossible sources for a given withdrawal.");
    for dwell in [0u64, 1, 2, 4, 8] {
        let (_, mirror) = run_effective_k_with_funding(
            32,
            N_PARTICIPANTS,
            DEFAULT_SEED,
            &[Channel::FundingProvenance],
            FundingPolicy::uniform_rounds_with_dwell(dwell),
        );
        println!(
            "  dwell {dwell:<2} rounds -> effective-k {:>6.2} (min-entropy {:>5.2}, worst {:>4.2}, retained {})",
            mirror.shannon_effective_k,
            mirror.min_entropy_k,
            mirror.worst_case_k,
            retained(&mirror),
        );
    }
    println!();

    // (e) Adoption sensitivity: the mechanism only protects the people who use
    // it, and non-users shrink the crowd for everyone else.
    println!("(e) Adoption sensitivity at nominal k=32 (shipped default policy):");
    println!("{}", "-".repeat(TABLE_WIDTH));
    println!(
        "committers who top up directly instead of unshielding are fully re-linked AND can be"
    );
    println!("eliminated as candidates, which costs the adopters too.");
    for adoption in [1.0f64, 0.9, 0.75, 0.5, 0.25] {
        let (_, mirror) = run_effective_k_with_funding(
            32,
            N_PARTICIPANTS,
            DEFAULT_SEED,
            &[Channel::FundingProvenance],
            FundingPolicy::uniform_rounds().with_adoption(adoption),
        );
        println!(
            "  adoption {:>3.0}% -> effective-k {:>6.2} (min-entropy {:>5.2}, worst {:>4.2}, retained {})",
            100.0 * adoption,
            mirror.shannon_effective_k,
            mirror.min_entropy_k,
            mirror.worst_case_k,
            retained(&mirror),
        );
    }
    println!();

    // (f) Sybil dominance: the concrete inflated-nominal case. Shows the metric
    // is live (effective-k drops to real_k), fixing the excluded=0 gap.
    println!("(f) Sybil dominance (75% of the nominal set is attacker-owned decoy traffic):");
    println!("{}", "-".repeat(TABLE_WIDTH));
    println!(
        "an adversary that owns the decoys removes them, so effective-k collapses to real_k ="
    );
    println!("nominal - excluded. This is KAnon's honest subtraction, measured information-theoretically.");
    for &k in &KS_EFFECTIVE {
        let mirror = Population::generate(&PopulationConfig {
            n_participants: N_PARTICIPANTS,
            k,
            seed: DEFAULT_SEED,
            scenario: Scenario::MirrorPool,
        });
        let (eff, kanon) = effective_k_under_sybils(&mirror, 0.75, DEFAULT_SEED);
        println!(
            "  nominal k={:<3} excluded={:<3} -> real_k={:<3} | effective-k (shannon) = {:.2}",
            kanon.nominal,
            kanon.excluded,
            kanon.real_k(),
            eff.shannon_effective_k,
        );
    }
    println!();

    println!("headline (funding provenance, the empirical marquee axis):");
    for &k in &KS_EFFECTIVE {
        let (base, naive) = run_effective_k_with_funding(
            k,
            N_PARTICIPANTS,
            DEFAULT_SEED,
            &[Channel::FundingProvenance],
            FundingPolicy::pass_through(),
        );
        let (_, default) = run_effective_k_with_funding(
            k,
            N_PARTICIPANTS,
            DEFAULT_SEED,
            &[Channel::FundingProvenance],
            FundingPolicy::uniform_rounds(),
        );
        println!(
            "  k={k:<3} advertised -> public funding edge {:.1} (worst-case {:.0}) | \
             pass-through shielded funding {:.1} | denominated + batched rounds {:.1}",
            base.shannon_effective_k,
            base.worst_case_k,
            naive.shannon_effective_k,
            default.shannon_effective_k,
        );
    }
}

fn main() -> Result<()> {
    println!("mirror-harness: adversarial evaluation, Baseline vs MirrorPool");
    println!(
        "synthetic population, n = {N_PARTICIPANTS} participants per (scenario, k), \
         seed = {DEFAULT_SEED:#x}, 50/50 train/test split"
    );
    println!("advantage = held-out attribution accuracy minus the 1/k random-guess baseline");
    println!("Baseline: per-actor delay, self-paid gas, variable amounts, distinct funding roots");
    println!(
        "MirrorPool: shared-epoch batch settlement, rotating gasless relay, fixed size bucket"
    );
    println!();

    let mut headline: Vec<(usize, f64, f64)> = Vec::new();
    for &k in &KS {
        let suite = run_suite(k, N_PARTICIPANTS, DEFAULT_SEED);
        print_suite(&suite);
        let base = find(&suite.baseline, "FifoTemporalMatch");
        let mirror = find(&suite.mirror_pool, "FifoTemporalMatch");
        ensure!(
            base.is_some() && mirror.is_some(),
            "FifoTemporalMatch missing from the attack battery"
        );
        headline.push((k, base.unwrap().advantage, mirror.unwrap().advantage));
    }

    println!(
        "headline (FIFO temporal match, the strongest empirical attack on mixer-style pools):"
    );
    for (k, base, mirror) in headline {
        println!(
            "  k={k:<2}  advantage {} under per-actor delays  ->  {} under shared-epoch batching",
            pp(base),
            pp(mirror),
        );
    }

    println!();
    print_effective_k_section();
    Ok(())
}
