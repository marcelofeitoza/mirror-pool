# Effective anonymity-set size (advertised k is not effective k)

The attack table in `crates/mirror-harness` measures whether an adversary can
attribute a settled action to its initiator better than the `1/k` random guess.
This document covers a second, independent axis that the empirical mixer
literature made the memorable one: a pool that advertises an anonymity set of
`k` participants does not actually provide `k`-anonymity once an adversary
partitions those participants by information it already holds. The advertised
(nominal) set and the effective set are different numbers, and the gap is the
result.

This metric is additive and lives in `crates/mirror-harness/src/effective_k.rs`.
It prints as a table under the attack table when you run:

```sh
cargo run -p mirror-harness --release
```

## The metric

Given the probability distribution `p` a concrete adversary assigns over the `k`
candidate initiators of a target action (after every channel it can use has
narrowed things down), we report two effective sizes, following the standard
information-theoretic anonymity metrics:

- **Shannon effective size** `= 2^H(p)`, where `H(p) = - sum_i p_i log2 p_i` is
  Shannon entropy in bits. This is the Serjantov-Danezis "effective anonymity
  set size" [1]. A uniform `p` over `k` candidates gives `2^H = k` (the
  advertised set is fully real); any distribution the adversary has sharpened
  gives `2^H < k` (the advertised set was an overstatement).
- **Min-entropy (worst-case) size** `= 1 / max_i p_i`, the reciprocal of the
  adversary's single best guess [2]. This is the conservative measure a defender
  must quote; it is never larger than the Shannon size.

Both are implemented as pure functions of a distribution and unit-tested against
their defining cases: a uniform distribution over `k` returns `k`, a point mass
returns `1`, and a distribution uniform within a class returns the class size.

The population-level function
`effective_k(population, channels, seed) -> { nominal_k, shannon_effective_k,
min_entropy_k, worst_case_k, dominant_class_size }`
iterates every committer of every settled epoch as a target, builds the
adversary's posterior under the requested channels, and aggregates: the reported
`shannon_effective_k` and `min_entropy_k` are the mean over targets, and
`worst_case_k` is the single most-exposed target (the "worst-case 1" below).

## The dominant real leak: funding provenance

The strongest real-world identity anchor (Section 3.5 of
[`THREAT_MODEL.md`](THREAT_MODEL.md), and the empirical references [3][4]) is the
common-funding-source heuristic: a handful of exchange hot-wallets and faucets
fund most participants, so the `k` committers collapse into a few
funding-provenance equivalence classes. An adversary that knows the partition
assigns probability uniformly within the true initiator's class and zero outside
it, so the effective set shrinks toward the class size, not `k`.

We model the common-funder distribution as Zipf popularity (a dominant exchange,
a middle tail, and rare funders down to singletons) over roughly one funder per
four committers. Class sizes are therefore heterogeneous, which is exactly why
the effective set has a small mean and a worst case of 1 (someone whose funder is
unique is alone in their class).

On top of provenance we fold in the same behavioral channels the attack battery
models, each of which further sharpens `p`:

- **Timing** (the `FifoTemporalMatch` axis): committers whose public commit slots
  are close are timing decoys for each other.
- **Amount** (the `AmountMatch` axis): committers with near-equal intended
  amounts are amount-indistinguishable; unique amounts self-identify.
- **Fingerprint** (the `WalletFingerprint` axis): habitual compute-unit price and
  fee settings cluster committers.

A behavioral channel informs the adversary only if settlement actually exposed
it. mirror-pool settles one shared-epoch batch: every action carries one settle
slot, one bucket amount, and one normalized fee shape, so the timing, amount, and
fingerprint channels carry zero variance across the batch and contribute nothing.
Funding via the shielded path breaks the provenance partition (one
indistinguishable class). That is why a naive pool's effective set collapses while
mirror-pool's stays at nominal.

## Headline numbers

Deterministic (fixed seed `0x4d49_5252_4f52`, 2048 synthetic participants per
scenario and `k`, ChaCha20, no wall-clock), so any reviewer re-derives them
bit-for-bit.

### Funding-provenance channel alone (the marquee axis)

| nominal k | Baseline Shannon-effective | Baseline worst-case | MirrorPool Shannon-effective |
| --- | --- | --- | --- |
| 16 | 5.98 | 1 | 16.00 |
| 32 | 7.51 | 1 | 32.00 |
| 64 | 9.47 | 1 | 64.00 |

A naive pool advertising `k = 32` provides an effective anonymity set of about
7.5, with a worst case of 1. mirror-pool keeps the full 32 because the shielded
funding path denies the adversary the partition.

### All channels (provenance + timing + amount + fingerprint)

| nominal k | Baseline Shannon-effective | Baseline min-entropy | MirrorPool Shannon-effective |
| --- | --- | --- | --- |
| 16 | 1.01 | 1.00 | 16.00 |
| 32 | 1.02 | 1.01 | 32.00 |
| 64 | 1.01 | 1.00 | 64.00 |

With every channel composed, a naive pool is effectively deanonymizable (the
effective set is barely above 1 at any nominal size), while mirror-pool retains
the full nominal set because it neutralizes every one of these channels at
settlement.

### Sybil dominance (fixing the "excluded = 0" gap)

The attack table runs with `KAnon::excluded = 0`, so it never demonstrates the
set shrinkage it warns about. The effective-k metric closes this: when a fraction
of the nominal set is attacker-owned decoy traffic (operator cover or a
funding-cluster Sybil group), an adversary that owns the decoys removes them, so
the honest participants are anonymous only among the remaining honest committers.

| nominal k | excluded (Sybils) | real_k | effective-k (Shannon) |
| --- | --- | --- | --- |
| 16 | 12 | 4 | 4.00 |
| 32 | 24 | 8 | 8.00 |
| 64 | 48 | 16 | 16.00 |

The effective-k equals `real_k = nominal - excluded` exactly. This makes
`KAnon`'s honest subtraction an information-theoretic result rather than a bare
assertion: an inflated nominal set buys no anonymity against anyone who can
identify the decoys.

## This is a model

These numbers come from deterministic synthetic populations, the same ones the
attack table uses. The funding-provenance partition is modeled from a realistic
Zipf common-funder distribution, not read from a live pool, and the behavioral
channels use the same synthetic profiles as the attack battery. The value of the
metric is the structural claim it makes on the same axis the empirical literature
raised it: advertised `k` is not effective `k` for a naive pool, and mirror-pool
keeps effective `k` at nominal precisely by breaking the funding-provenance and
timing channels that collapse a naive pool's effective set. An on-chain
settlement-trace loader that computes effective-k over real funding provenance is
a named roadmap extension (see [`ROADMAP.md`](ROADMAP.md)); until it lands, this
document and the printed table are honestly labeled as a model.

## Why this matters

Mixer projects have historically reported the nominal set size and overstated
privacy; the empirical literature dismantled those claims after the fact [3][4].
This metric answers the "advertised k is not effective k" concern directly and
falsifiably, on the same information-theoretic axis, and shows both that a naive
pool's effective set collapses and that mirror-pool's design keeps it at nominal.
It complements the `KAnon` real-k accounting in
[`THREAT_MODEL.md`](THREAT_MODEL.md) Section 5 (which subtracts known
operator/Sybil decoys) with a distribution-level measure of how much anonymity a
partitioning adversary actually leaves.

## References

[1] A. Serjantov and G. Danezis, "Towards an Information Theoretic Metric for
Anonymity", Privacy Enhancing Technologies (PET) 2002. Defines the effective
anonymity-set size as `2^H(p)`.

[2] C. Diaz, S. Seys, J. Claessens, B. Preneel, "Towards measuring anonymity",
PET 2002 (companion entropy metric); and the min-entropy / worst-case reading of
anonymity as `1 / max_i p_i`, the reciprocal of the adversary's best single
guess.

[3] "Deanonymizing Tornado Cash: an empirical analysis of mixed flows"
(arXiv:2510.09433). Funding-source and gas-payer heuristics are dominant
deanonymization vectors.

[4] Wang et al., "On How Zero-Knowledge Proof Blockchain Mixers Improve, and
Worsen User Privacy" (arXiv:2201.09035). Composable heuristics reduce the
effective anonymity set well below the nominal deposit count.
