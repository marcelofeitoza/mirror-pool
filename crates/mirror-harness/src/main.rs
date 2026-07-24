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
use mirror_harness::effective_k::{effective_k_under_sybils, run_effective_k, Channel, EffectiveK};
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

fn print_effective_row(label: &str, eff: &EffectiveK) {
    println!(
        "{:<11} {:>9} {:>13.2} {:>13.2} {:>11.2} {:>11}   {:>8}",
        label,
        eff.nominal_k,
        eff.shannon_effective_k,
        eff.min_entropy_k,
        eff.worst_case_k,
        eff.dominant_class_size,
        retained(eff),
    );
}

/// The effective-k table: nominal vs Serjantov-Danezis Shannon-effective vs
/// min-entropy (worst-case), Baseline vs MirrorPool, at several nominal k.
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
    println!(
        "Baseline funds from clustered sources and settles per-actor; MirrorPool funds via the"
    );
    println!(
        "shielded path (provenance broken) and settles one shared-epoch batch (timing/amount/fee"
    );
    println!("normalized), so its behavioral channels carry zero variance. MODEL, not a live-pool");
    println!("measurement (see docs/EFFECTIVE_K.md).");
    println!();

    // (a) Provenance ALONE: directly comparable to the marquee "advertised k
    // shrinks to a small effective k (worst-case 1)" result.
    println!("(a) Funding-provenance channel ALONE (the dominant real leak):");
    println!("{}", "-".repeat(81));
    println!(
        "{:<11} {:>9} {:>13} {:>13} {:>11} {:>11}   {:>8}",
        "scenario", "nominal", "shannon-eff", "min-entropy", "worst", "dom-class", "retained"
    );
    for &k in &KS_EFFECTIVE {
        let (base, mirror) = run_effective_k(
            k,
            N_PARTICIPANTS,
            DEFAULT_SEED,
            &[Channel::FundingProvenance],
        );
        print_effective_row("Baseline", &base);
        print_effective_row("MirrorPool", &mirror);
    }
    println!();

    // (b) Every channel: provenance + timing + amount + fingerprint composed.
    println!("(b) All channels (provenance + timing + amount + fingerprint):");
    println!("{}", "-".repeat(81));
    println!(
        "{:<11} {:>9} {:>13} {:>13} {:>11} {:>11}   {:>8}",
        "scenario", "nominal", "shannon-eff", "min-entropy", "worst", "dom-class", "retained"
    );
    for &k in &KS_EFFECTIVE {
        let (base, mirror) = run_effective_k(k, N_PARTICIPANTS, DEFAULT_SEED, &Channel::ALL);
        print_effective_row("Baseline", &base);
        print_effective_row("MirrorPool", &mirror);
    }
    println!();

    // (c) Sybil dominance: the concrete inflated-nominal case. Shows the metric
    // is live (effective-k drops to real_k), fixing the excluded=0 gap.
    println!("(c) Sybil dominance (75% of the nominal set is attacker-owned decoy traffic):");
    println!("{}", "-".repeat(81));
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

    println!("headline (funding-provenance shrinkage, the empirical marquee result):");
    for &k in &KS_EFFECTIVE {
        let (base, mirror) = run_effective_k(
            k,
            N_PARTICIPANTS,
            DEFAULT_SEED,
            &[Channel::FundingProvenance],
        );
        println!(
            "  k={k:<3} advertised  ->  Baseline effective {:.1} (worst-case {:.0})  vs  \
             MirrorPool effective {:.1}",
            base.shannon_effective_k, base.worst_case_k, mirror.shannon_effective_k,
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
