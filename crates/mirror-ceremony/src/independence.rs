//! An honest count of *independent* contributors.
//!
//! A phase-2 ceremony is safe if at least one contributor destroyed their scalar
//! (1-of-N honest). The number that matters is therefore not "how many
//! contributions are in the transcript" but "how many parties those contributions
//! actually represent". Running the contribute command five times on your own
//! laptop produces five entries and zero additional safety, and a headline number
//! that counted them would be a lie.
//!
//! This module refuses to count self-runs. It groups contributions that are
//! evidently not independent and counts groups, not entries.
//!
//! # What it merges
//!
//! - Contributions sharing a **contributor identifier** (trimmed, lowercased).
//! - Contributions sharing a **machine fingerprint** - a hash of the environment
//!   the contribution was produced in (see
//!   [`crate::contribute::machine_fingerprint`]).
//! - Contributions sharing a **proof-of-knowledge nonce commitment**, which
//!   indicates one scripted run rather than separate sessions.
//!
//! # What it refuses to count at all
//!
//! - **Deterministic** contributions: the scalar comes from a fixed seed, so its
//!   toxic waste is reproducible by anyone reading the seed.
//! - **Beacon** steps: the scalar is public by construction. A step counts only
//!   when BOTH signals - the structural `kind` and the self-reported
//!   `entropy_source` - say it is not a beacon. A step whose two signals disagree
//!   is never counted, and [`crate::verify`] rejects it outright.
//!
//! # Why the metadata can be trusted this far, and no further
//!
//! Every field this module reads is bound into the step's proof of knowledge
//! ([`crate::pok`]), so it cannot be rewritten in a published transcript by anyone
//! who does not know that step's delta ratio. That is what stops a third party from
//! taking a finished ceremony and relabelling its closing beacon into a fourth
//! "contributor".
//!
//! It does not stop the party who KNOWS a step's ratio from re-proving it under a
//! different label, and a beacon's ratio is public by design. The mechanical
//! defence against that is [`crate::verify::VerifyOptions::beacon_precommitment`]:
//! a verifier holding the announced beacon value recomputes its scalar and rejects
//! any step that applies it without being recorded as that beacon. Without the
//! pre-commitment, no verifier can tell the difference, and the report says so.
//!
//! # What it CANNOT detect
//!
//! This is a guard against *accidental self-inflation*, not a Sybil defence:
//!
//! - Contributor identifiers are self-asserted strings. Nothing binds them to a
//!   real person or key.
//! - The machine fingerprint is computed by the contributor's own binary from its
//!   own environment. Anyone who wants to fake `n` distinct machines can.
//! - Contributions from `n` different machines that one person controls look
//!   exactly like contributions from `n` different people.
//! - Timestamps are self-reported and are used only for advisory warnings.
//! - An operator who runs the whole ceremony chooses every scalar, so they can
//!   always manufacture whatever count they want. The number is an upper bound on
//!   distinct secret holders, never a proof of one.
//!
//! It also errs conservatively in the other direction: where the environment
//! exposes nothing distinguishing, fingerprints collide and genuinely independent
//! contributors get merged. The count can be too LOW. It is designed never to be
//! too high by accident.
//!
//! The only thing that makes a ceremony trustworthy is having an external reason to
//! believe in at least one participant. Publish who they were and let people check.

use serde::Serialize;

use crate::transcript::{ContributionRecord, EntropySource, Transcript};

/// The standing caveat, carried in every report so it travels with the number.
pub const CAVEAT: &str = "Upper bound on distinct secret holders, and a heuristic against \
accidental self-inflation - NOT a Sybil defence: contributor identifiers and machine fingerprints \
are self-asserted, and the operator of a ceremony picks every scalar, so a determined operator can \
fake any number of them. It can also under-count when environments look alike.";

/// Contributions judged to come from one party.
#[derive(Debug, Clone, Serialize)]
pub struct Group {
    /// A representative identifier for the group.
    pub contributor_id: String,
    /// Indices of the contributions in this group.
    pub members: Vec<u32>,
    /// Why these were merged (empty for a group of one).
    pub reasons: Vec<String>,
    /// Whether this group counts toward the independent-contributor number.
    pub counted: bool,
}

/// The conservative count plus everything needed to argue with it.
#[derive(Debug, Clone, Serialize)]
pub struct IndependenceReport {
    /// Every step in the chain.
    pub total_steps: usize,
    /// Steps whose scalar could actually be secret: not a beacon by either signal,
    /// and drawn from OS randomness rather than a fixed seed.
    pub secret_steps: usize,
    /// Steps derived from a fixed seed.
    pub deterministic_steps: usize,
    /// Steps that either are recorded as a beacon or report beacon provenance.
    pub beacon_steps: usize,
    /// The number this module exists to produce: distinct parties that could have
    /// destroyed a secret.
    pub independent_contributors: usize,
    /// The grouping, so the number can be audited rather than believed.
    pub groups: Vec<Group>,
    /// Advisory observations. None of these fail verification.
    pub warnings: Vec<String>,
    /// [`CAVEAT`].
    pub caveat: &'static str,
}

/// Assess a transcript.
///
/// **Only meaningful for a transcript [`crate::verify`] has accepted.** This
/// function reads labels; it does not check a single proof of knowledge, so on its
/// own it cannot tell an edited transcript from an honest one. What makes the labels
/// hard to edit is the proof of knowledge they are bound into, and that is verified
/// there, not here. `verify` runs the whole chain first and only then calls this.
pub fn assess(transcript: &Transcript) -> IndependenceReport {
    let steps = &transcript.contributions;
    let n = steps.len();

    // Merge every pair that shares provenance.
    let mut parent: Vec<usize> = (0..n).collect();
    for i in 0..n {
        for j in (i + 1)..n {
            if shared_provenance(&steps[i], &steps[j]).is_some() {
                union(&mut parent, i, j);
            }
        }
    }

    // Collect the resulting groups, keeping the positions so the reasons can be
    // re-derived per group.
    let mut groups: Vec<Group> = Vec::new();
    let mut group_positions: Vec<Vec<usize>> = Vec::new();
    let mut roots: Vec<usize> = Vec::new();
    for (i, step) in steps.iter().enumerate() {
        let root = find(&mut parent, i);
        let slot = match roots.iter().position(|r| *r == root) {
            Some(pos) => pos,
            None => {
                roots.push(root);
                group_positions.push(Vec::new());
                groups.push(Group {
                    contributor_id: step.contributor_id.clone(),
                    members: Vec::new(),
                    reasons: Vec::new(),
                    counted: false,
                });
                groups.len() - 1
            }
        };
        group_positions[slot].push(i);
        groups[slot].members.push(step.index);
        if step.countable_as_independent() {
            groups[slot].counted = true;
        }
    }
    for (group, positions) in groups.iter_mut().zip(group_positions.iter()) {
        for (a, i) in positions.iter().enumerate() {
            for j in positions.iter().skip(a + 1) {
                if let Some(reason) = shared_provenance(&steps[*i], &steps[*j]) {
                    group.reasons.push(format!(
                        "{} and {}: {reason}",
                        steps[*i].index, steps[*j].index
                    ));
                }
            }
        }
    }

    let secret_steps = steps
        .iter()
        .filter(|s| s.countable_as_independent())
        .count();
    let deterministic_steps = steps
        .iter()
        .filter(|s| s.provenance.entropy_source == EntropySource::Deterministic)
        .count();
    // A step counts as a beacon if EITHER signal says so, so a half-finished
    // relabelling cannot hide one.
    let beacon_steps = steps
        .iter()
        .filter(|s| s.kind.is_beacon() || s.provenance.entropy_source == EntropySource::Beacon)
        .count();
    let inconsistent_steps = steps
        .iter()
        .filter(|s| !s.kind_matches_provenance())
        .count();
    let independent_contributors = groups.iter().filter(|g| g.counted).count();

    let mut warnings = Vec::new();
    if inconsistent_steps > 0 {
        warnings.push(format!(
            "{inconsistent_steps} step(s) record a kind and an entropy source that disagree about \
             whether they are a beacon; they are NOT counted, and `verify` rejects such a transcript \
             outright"
        ));
    }
    if deterministic_steps > 0 {
        warnings.push(format!(
            "{deterministic_steps} step(s) used a fixed seed; their toxic waste is reproducible and \
             they are NOT counted as independent contributors"
        ));
    }
    if beacon_steps > 0 {
        warnings.push(format!(
            "{beacon_steps} beacon step(s) present; a beacon removes last-mover grinding but adds no \
             secrecy, so it is NOT counted as an independent contributor"
        ));
    }
    if independent_contributors == 0 {
        warnings.push(
            "0 independent contributors: this transcript demonstrates the mechanism but the toxic \
             waste must be assumed public"
                .into(),
        );
    } else if independent_contributors == 1 {
        warnings.push(
            "only 1 independent contributor: safety rests entirely on that one party having \
             destroyed their scalar"
                .into(),
        );
    }
    warnings.extend(timing_warnings(steps));

    IndependenceReport {
        total_steps: n,
        secret_steps,
        deterministic_steps,
        beacon_steps,
        independent_contributors,
        groups,
        warnings,
        caveat: CAVEAT,
    }
}

/// Why two contributions are evidently not independent, if they are not.
fn shared_provenance(a: &ContributionRecord, b: &ContributionRecord) -> Option<&'static str> {
    if a.normalized_id() == b.normalized_id() {
        return Some("same contributor identifier");
    }
    if a.provenance.machine_fingerprint == b.provenance.machine_fingerprint {
        return Some("same machine fingerprint");
    }
    if a.pok.r == b.pok.r {
        return Some("same proof-of-knowledge nonce commitment");
    }
    None
}

/// Advisory timing observations. Timestamps are self-reported, so these never fail
/// verification and never change the count.
fn timing_warnings(steps: &[ContributionRecord]) -> Vec<String> {
    /// A handoff between genuinely separate operators does not normally happen in
    /// under a minute.
    const IMPLAUSIBLE_GAP_SECS: u64 = 60;

    let mut out = Vec::new();
    for pair in steps.windows(2) {
        let (a, b) = (&pair[0], &pair[1]);
        if b.provenance.timestamp_unix < a.provenance.timestamp_unix {
            out.push(format!(
                "contribution {} reports an earlier timestamp than {} (self-reported clocks; advisory only)",
                b.index, a.index
            ));
            continue;
        }
        let gap = b.provenance.timestamp_unix - a.provenance.timestamp_unix;
        if gap < IMPLAUSIBLE_GAP_SECS
            && a.countable_as_independent()
            && b.countable_as_independent()
        {
            out.push(format!(
                "contributions {} and {} are {gap}s apart, which is fast for an out-of-band handoff \
                 (advisory only; timestamps are self-reported)",
                a.index, b.index
            ));
        }
    }
    out
}

fn find(parent: &mut [usize], mut x: usize) -> usize {
    while parent[x] != x {
        parent[x] = parent[parent[x]];
        x = parent[x];
    }
    x
}

/// Returns true when the two were in different sets.
fn union(parent: &mut [usize], a: usize, b: usize) -> bool {
    let (ra, rb) = (find(parent, a), find(parent, b));
    if ra == rb {
        return false;
    }
    let (lo, hi) = if ra < rb { (ra, rb) } else { (rb, ra) };
    parent[hi] = lo;
    true
}
