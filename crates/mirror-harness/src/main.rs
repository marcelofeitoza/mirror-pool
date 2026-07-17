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
use mirror_harness::{run_suite, AttackReport, SuiteResult, DEFAULT_SEED};

/// At least 2000 synthetic participants per (scenario, k); 2048 divides
/// evenly into batches for every k below.
const N_PARTICIPANTS: usize = 2048;
const KS: [usize; 3] = [4, 8, 16];

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
    Ok(())
}
