# Effective anonymity-set size (advertised k is not effective k)

The attack table in `crates/mirror-harness` measures whether an adversary can
attribute a settled action to its initiator better than the `1/k` random guess.
This document covers a second, independent axis that the empirical mixer
literature made the memorable one: a pool that advertises an anonymity set of
`k` participants does not actually provide `k`-anonymity once an adversary
partitions those participants by information it already holds. The advertised
(nominal) set and the effective set are different numbers, and the gap is the
result.

This metric lives in `crates/mirror-harness/src/effective_k.rs`, its funding
model in `crates/mirror-harness/src/funding.rs`. It prints as a table under the
attack table when you run:

```sh
cargo run -p mirror-harness --release
```

## The headline, up front

Every number below is measured by the harness at a fixed seed. Two of them
matter, and quoting only the larger one would be dishonest, so both are here:

| what | effective k at nominal 32 | retained |
| --- | --- | --- |
| naive pool: commit wallet topped up by a public transfer | 7.51 (worst case 1.00) | 23.5% |
| mirror-pool with **naive** shielded funding (pass-through) | 7.66 (worst case 1.00) | 23.9% |
| **what the enforced rules deliver**: denominated pool + batched rounds, **dwell 0** | **24.25** (worst case 3.00) | **75.8%** |
| what it reaches with cooperative participants: the same, **dwell 2** | 28.80 (worst case 3.00) | 90.0% |

**Both of the last two rows assume 100% adoption**, i.e. that every committer in
the round funded through the pool. They differ only in *dwell*: how many funding
rounds a participant leaves value shielded before asking for the withdrawal.

The distinction is not cosmetic, because the two rows have different
enforceability:

- **Denomination and batching are enforced by code.** The program rejects an
  off-denomination `Transact` (`DenominationMismatch`), the CLI refuses it
  client-side first, and `FundingRounds` holds withdrawals to the round boundary,
  rolls a thin round forward, and releases in an arrival-independent order.
- **Dwell is not enforced by anything.** There is no dwell field in
  `FundingRoundConfig` and no on-chain check. It is how long a *participant*
  chooses to wait, and a participant in a hurry sets it to zero.

So the honest reading is: **the rules the protocol enforces deliver 24.25 of 32
(75.8%)**, and **28.80 (90.0%) is what a fully-adopted pool of cooperative
participants who dwell two rounds reaches**. Anything that quotes 28.80 as "the
number" is quoting a best case as a default.

Three further readings, all honest and all important:

1. Routing the funding leg through a shielded pool and then behaving naively
   (deposit the amount you need, withdraw it immediately) buys almost nothing:
   `7.51 -> 7.66`, about 2%. The pool does not save a user from a pass-through
   pattern.
2. Even the enforced-only configuration is a large win over the naive shielded
   flow: `7.66 -> 24.25`, a **3.2x** improvement, rising to **3.8x** at dwell 2.
   The residual (24.2% at dwell 0, 10.0% at dwell 2) is a real leak that this
   document measures rather than hides, and in both configurations the
   worst-placed committer is anonymous among `3.00`, not among 32.
3. Adoption dominates everything. At 50% adoption the dwell-2 configuration
   drops to 13.56 (42.4%) and the worst case returns to 1.00. See the adoption
   sweep below before quoting any of these numbers about a real pool.

One more scoping caveat that applies to this whole document: this leg is
**not wired into a running service** (see the status table in the README). The
CLI emits a funding request and `FundingRounds` can batch one, but nothing
connects them and no funding round has ever run. Every number here is a
measurement of the design's rules under a modeled population, not an observation
of a deployment.

Every mirror-pool number here is scored against the strongest attacker this repo
implements: one that solves the whole deposit-to-withdrawal assignment at once.
The weaker per-withdrawal attacker is also measured and published (it leaves
`28.87` instead of `28.80` at nominal 32 and dwell 2, and exactly the same `24.25`
at dwell 0, where the two readings coincide), because a defender who only ever
evaluates the weak attacker is grading their own homework.

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
`effective_k_with_funding(population, channels, seed, model) -> { nominal_k,
shannon_effective_k, min_entropy_k, worst_case_k, dominant_class_size }`
iterates every committer of every settled epoch as a target, builds the
adversary's posterior under the requested channels, and aggregates: the reported
`shannon_effective_k` and `min_entropy_k` are the mean over targets, and
`worst_case_k` is the single most-exposed target. The `model` names both halves
of what is being measured: the protocol's funding policy and the attacker it is
scored against.

The posterior is a weight vector, not a calibrated probability of guilt: the
metric scores the SHAPE of the distribution an attacker is left with, which is
what Serjantov-Danezis measures. The true initiator always keeps positive weight
(its own deposit is always a plausible source for its own withdrawal), but under
shielded funding it is not always the attacker's top-ranked candidate, and an
attacker who confidently ranks the wrong committer first is exactly what a
working mechanism looks like.

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
unique is alone in their class). Both scenarios draw from the same funder
distribution: the two worlds describe the same crowd of people with the same
banking habits, and differ only in how those people move value into the wallet
they commit from.

- **Baseline (a naive pool).** The commit wallet is topped up by an ordinary
  transfer from the participant's main wallet. That is one public edge, so the
  partition is exact and the adversary reads it off the chain.
- **mirror-pool.** The participant funds a fresh commit wallet by **unshielding
  from the confidential-value pool** (`mirror-cli fund-commit`, released by
  `mirror_coordinator::funding::FundingRounds`). The on-chain sender is the pool
  vault and the relay is the only signature on the transaction, so the
  main-wallet-to-commit-wallet edge is never written.

### What the mechanism does NOT hide

`publicAmount` is on-chain-visible for both boundary crossings. An observer sees

- **deposits**: (funder identity, amount, slot) for every shield, and
- **withdrawals**: (fresh commit wallet, amount, slot) for every unshield,

and only the pairing between them is hidden. The funding edge is therefore not
erased, it is downgraded to a **matching problem**, and the residual leak is
exactly how well an adversary can solve that matching. The harness models an
adversary that knows the protocol (Kerckhoffs) and uses the correct generative
model of the funding mechanism:

- **Amount.** A deposit is a plausible source for a withdrawal in proportion to
  how close their amounts are (RBF kernel, 5% relative bandwidth, the same
  constant the settlement-side amount channel uses). Under a denominated pool
  every crossing moves the same number and this channel is dead by protocol rule;
  under a free-amount pool a distinctive amount is close to an oracle.
- **Timing.** A deposit is a plausible source only if it could causally have
  produced the withdrawal under the policy in force: within 20 slots before it
  when withdrawals go out as soon as they are proved, or within the last
  `dwell_rounds + 1` funding rounds when the coordinator batches them. Causality
  is a hard constraint and it leaks: a deposit made after a withdrawal cannot
  have funded it, so that candidate is eliminated outright.

The adversary's belief that committer `i` was funded by funder `f` is the
normalized sum of the plausibility of `f`'s deposits as sources for `i`'s
withdrawal. A targeted adversary knows the **target's** funder (that is what
makes the attack targeted) and asks of every committer how likely they share it.
A point-mass belief reproduces the naive pool's hard partition exactly; a flat
belief means the committer is provenance-indistinguishable from the crowd.

### How hard does the attacker work?

The plausibility matrix (withdrawals by deposits) can be read two ways, and both
are implemented and published:

- **Independent.** Score each withdrawal on its own: normalize its row. Simple,
  and weaker in principle, because it forgets that a deposit can only fund one
  withdrawal.
- **Joint (the default for every published number).** Solve the whole assignment.
  The model is a perfect matching between the round's deposits and its
  withdrawals, and the attacker wants the marginal `P[deposit d funded withdrawal
  i]` under the distribution over matchings weighted by plausibility. Exact
  marginals are permanents (`#P`-hard), so this uses Sinkhorn scaling: alternately
  normalize rows and columns until the matrix is doubly stochastic. That imposes
  the "each deposit is spent once" constraint the independent reading drops.

Two honesty notes on this, both pinned by tests:

- Aggregated over the reported grid, the joint attacker measures strictly less
  effective anonymity in every cell of the table below. The test that guards this
  (`joint_adversary_never_leaves_more_effective_k`) asserts the weaker "never
  more", because "always strictly less" is an observation about this population,
  not a theorem. Either way, the joint attacker is the one the tables quote.
- It is an approximation, not a bound. In a single measured epoch (`k = 16`,
  denominated + rounds at dwell 2) the Sinkhorn marginals put slightly LESS mass on the
  true funder than the independent reading does. That instance is pinned by
  `sinkhorn_is_an_approximation_not_a_bound` so nobody upgrades "measured
  stronger on our grid" into "provably stronger".

**This is the part that used to be assumed.** An earlier version of this document
reported mirror-pool's effective k as exactly nominal, because the harness placed
every mirror-pool committer in a single provenance class by fiat. That was
circular: it assumed the channel closed and then reported it closed. The classes
are now derived from the funding mechanism above, the residual is measured, and
the measured number is below nominal.

## Measured results

Deterministic (fixed seed `0x4d49_5252_4f52`, 2048 synthetic participants per
scenario and `k`, ChaCha20, no wall-clock), so any reviewer re-derives them
bit-for-bit with `cargo run -p mirror-harness --release`.

### Funding-provenance channel alone (the marquee axis)

Shannon effective size, with min-entropy and the single worst-placed committer:

Every row assumes **100% adoption**. The dwell-2 rows additionally assume every
participant voluntarily leaves value shielded for two funding rounds, which the
protocol recommends but cannot enforce; the dwell-0 row is what the enforced
rules alone deliver. Each `k` is
shown at both dwells; the full dwell sweep at `k = 32` is further down.

| nominal k | scenario / funding policy | Shannon | min-entropy | worst case | retained |
| --- | --- | --- | --- | --- | --- |
| 16 | Baseline: public funding edge | 5.98 | 5.98 | 1.00 | 37.4% |
| 16 | pass-through shielded funding | 6.05 | 5.98 | 1.00 | 37.8% |
| 16 | denominated only | 6.77 | 6.00 | 1.00 | 42.3% |
| 16 | batched rounds only | 6.96 | 6.01 | 1.00 | 43.5% |
| 16 | **denominated + rounds, dwell 0 (enforced only)** | **12.22** | 9.22 | 2.00 | **76.4%** |
| 16 | **denominated + rounds, dwell 2** | **14.30** | 10.77 | 2.00 | **89.4%** |
| 32 | Baseline: public funding edge | 7.51 | 7.51 | 1.00 | 23.5% |
| 32 | pass-through shielded funding | 7.66 | 7.51 | 1.00 | 23.9% |
| 32 | denominated only | 10.19 | 7.65 | 1.00 | 31.8% |
| 32 | batched rounds only | 10.93 | 7.66 | 1.00 | 34.2% |
| 32 | **denominated + rounds, dwell 0 (enforced only)** | **24.25** | 18.42 | 3.00 | **75.8%** |
| 32 | **denominated + rounds, dwell 2** | **28.80** | 21.00 | 3.00 | **90.0%** |
| 64 | Baseline: public funding edge | 9.47 | 9.47 | 1.00 | 14.8% |
| 64 | pass-through shielded funding | 9.92 | 9.47 | 1.00 | 15.5% |
| 64 | denominated only | 17.33 | 10.08 | 1.00 | 27.1% |
| 64 | batched rounds only | 18.35 | 9.94 | 1.00 | 28.7% |
| 64 | **denominated + rounds, dwell 0 (enforced only)** | **47.11** | 35.93 | 10.00 | **73.6%** |
| 64 | **denominated + rounds, dwell 2** | **56.85** | 41.17 | 10.00 | **88.8%** |

What the rows say:

- **Naive shielded funding is close to worthless** against this channel. At every
  `k` it lands within 5% of the naive pool's number. If a deployment lets users
  pass value straight through the pool, it should not claim funding privacy.
- **Either mitigation alone is not enough.** Denomination alone leaves the short
  causal window (only a handful of deposits can have funded a given withdrawal);
  batching alone leaves the amount, which identifies the deposit directly. Both
  land around 27 to 44% of nominal.
- **Together they work, and they do not close the channel.** On the enforced
  rules alone (dwell 0) they retain 73.6 to 76.4% of nominal on the Shannon
  measure; cooperative dwell-2 participants push that to 88.8 to 90.0%. The
  min-entropy measure is harsher still (at `k = 32`: 57.6% of nominal at dwell 0,
  65.6% at dwell 2), and the worst-placed committer is at 3.00 either way.

### All channels (provenance + timing + amount + fingerprint)

| nominal k | scenario / funding policy | Shannon | min-entropy | retained |
| --- | --- | --- | --- | --- |
| 16 | Baseline: public funding edge | 1.01 | 1.00 | 6.3% |
| 16 | pass-through shielded funding | 6.05 | 5.98 | 37.8% |
| 16 | denominated + rounds, dwell 0 (enforced only) | 12.22 | 9.22 | 76.4% |
| 16 | denominated + rounds, dwell 2 | 14.30 | 10.77 | 89.4% |
| 32 | Baseline: public funding edge | 1.02 | 1.01 | 3.2% |
| 32 | pass-through shielded funding | 7.66 | 7.51 | 23.9% |
| 32 | denominated + rounds, dwell 0 (enforced only) | 24.25 | 18.42 | 75.8% |
| 32 | denominated + rounds, dwell 2 | 28.80 | 21.00 | 90.0% |
| 64 | Baseline: public funding edge | 1.01 | 1.00 | 1.6% |
| 64 | pass-through shielded funding | 9.92 | 9.47 | 15.5% |
| 64 | denominated + rounds, dwell 0 (enforced only) | 47.11 | 35.93 | 73.6% |
| 64 | denominated + rounds, dwell 2 | 56.85 | 41.17 | 88.8% |

With every channel composed, the naive pool is effectively deanonymizable (the
effective set is barely above 1 at any nominal size). mirror-pool's numbers are
identical to the provenance-only rows, because settlement exposes no per-actor
timing, amount, or fee shape: every action in an epoch shares one settle slot,
one bucket amount, and one normalized fee, so those three channels have zero
variance and contribute nothing. Funding is the only channel left, which is why
it gets a mechanism and a measurement instead of a paragraph.

### Adversary strength: what the assignment constraint is worth

The same worlds, scored by the weaker per-withdrawal attacker and by the joint
one. `delta` is joint minus independent, so a negative number means the
harder-working attacker left the defender less anonymity.

| nominal k | funding policy | independent | joint | delta |
| --- | --- | --- | --- | --- |
| 16 | pass-through funding | 6.07 | 6.05 | -0.02 |
| 16 | denominated only | 7.10 | 6.77 | -0.33 |
| 16 | batched rounds only | 7.20 | 6.96 | -0.24 |
| 16 | denominated + rounds, dwell 0 | 12.22 | 12.22 | 0.00 |
| 16 | denominated + rounds, dwell 2 | 14.47 | 14.30 | -0.18 |
| 32 | pass-through funding | 7.74 | 7.66 | -0.08 |
| 32 | denominated only | 11.24 | 10.19 | -1.06 |
| 32 | batched rounds only | 11.40 | 10.93 | -0.47 |
| 32 | denominated + rounds, dwell 0 | 24.25 | 24.25 | 0.00 |
| 32 | denominated + rounds, dwell 2 | 28.87 | 28.80 | -0.07 |
| 64 | pass-through funding | 10.15 | 9.92 | -0.23 |
| 64 | denominated only | 19.57 | 17.33 | -2.24 |
| 64 | batched rounds only | 19.24 | 18.35 | -0.89 |
| 64 | denominated + rounds, dwell 0 | 47.11 | 47.11 | 0.00 |
| 64 | denominated + rounds, dwell 2 | 56.94 | 56.85 | -0.08 |

The constraint is worth most against the un-batched mitigations: a denominated
pool with immediate withdrawals loses up to `2.24` effective committers at
`k = 64` when the attacker stops double-spending its hypotheses. Once rounds are
batched the constraint buys the attacker very little (`0.07` at `k = 32`, dwell
2) and, at dwell 0, nothing measurable at all: the joint and independent readings
are identical to two decimals in all three `k`. We report that as measured, not
as a proof that the two are equal there.

### The mitigation, swept: dwell (nominal k = 32, denominated, batched)

Longer dwell widens the causal window an observer has to search, so fewer
deposits are eliminated as impossible sources for a given withdrawal. ("Dwell"
here means funding-round dwell: how many rounds a participant leaves value
shielded before their withdrawal is released. It is unrelated to the incentive
`dwell` in [`INCENTIVES.md`](INCENTIVES.md), which counts epochs committed.)

| dwell (rounds) | Shannon | min-entropy | worst case | retained |
| --- | --- | --- | --- | --- |
| 0 | 24.25 | 18.42 | 3.00 | 75.8% |
| 1 | 27.43 | 20.43 | 3.00 | 85.7% |
| 2 (harness default) | 28.80 | 21.00 | 3.00 | 90.0% |
| 4 | 30.01 | 21.55 | 3.00 | 93.8% |
| 8 | 30.88 | 22.66 | 3.00 | 96.5% |

Dwell has diminishing returns and costs the participant latency (a funding round
is 150 slots by default, so dwell 8 is over 20 minutes of waiting before the
commit wallet is usable). The harness default of 2 is the middle of the curve,
not the best number on it.

**Read the dwell-0 row as the guarantee.** Dwell is how long a participant chooses
to leave value shielded before asking for the withdrawal. There is no dwell field
in `FundingRoundConfig`, no on-chain check, and no way for the coordinator to make
a participant wait; it is a recommendation the protocol can publish and measure but
not enforce. So `24.25` (75.8%) is what the mechanism delivers on its own rules,
and everything above that row is what cooperative participants can add to it.
Anywhere this repository quotes 28.80, it should say "dwell 2, full adoption"
alongside it, and it does.

### Adoption sensitivity (nominal k = 32, denominated + rounds, dwell 2)

The mechanism only protects the people who use it. A committer who tops up
directly is fully re-linked, and an adversary that can place them elsewhere
eliminates them as a candidate, which costs the adopters their crowd too.

| adoption | Shannon | min-entropy | worst case | retained |
| --- | --- | --- | --- | --- |
| 100% | 28.80 | 21.00 | 3.00 | 90.0% |
| 90% | 24.65 | 13.40 | 1.00 | 77.0% |
| 75% | 20.07 | 9.87 | 1.00 | 62.7% |
| 50% | 13.56 | 8.03 | 1.00 | 42.4% |
| 25% | 9.33 | 7.57 | 1.00 | 29.1% |

Note the worst case: as soon as a single committer funds directly, someone in the
set is fully exposed. A pool that advertises funding privacy while most of its
traffic tops up from main wallets is advertising a number it does not have.

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

## What is MEASURED and what is MODELLED

This distinction is the point of the document, so it is spelled out rather than
implied.

**MEASURED** (computed by code in this repo, deterministic, re-derivable by any
reviewer with one command):

- every number in every table above, including the ones that are unflattering;
- the entropy functions themselves, unit-tested against their defining cases;
- the derivation of mirror-pool's provenance classes from the funding mechanism
  (`funding.rs` builds the public deposit/withdrawal record and the adversary's
  belief matrix; `effective_k.rs` consumes it);
- that the Baseline column is untouched by the funding model, pinned by a test
  (`baseline_numbers_are_independent_of_the_funding_policy`);
- that the dwell-2 policy lands strictly below nominal, pinned by a test
  (`uniform_rounds_shrink_the_residual_but_do_not_close_it`), so this repo cannot
  drift back into claiming a perfect score without a test failing;
- that the published column is the one scored against the STRONGER attacker,
  pinned by two tests (`joint_adversary_never_leaves_more_effective_k` and
  `published_default_is_scored_against_the_joint_adversary`), so a refactor cannot
  quietly swap in the flattering number.

**MODELLED** (assumptions the measurement runs on top of, chosen before the
numbers were seen and stated here so a reviewer can attack them):

- the population itself is synthetic: commit slots, intents, wallet habits, and
  funder assignments are drawn from a fixed distribution, not from a chain;
- the common-funder distribution is Zipf over about one funder per four
  committers; a different concentration moves the Baseline column;
- funding top-ups in the free-amount case are 30% round numbers and 70% uniform
  draws, mirroring the intent distribution;
- the un-batched lag is uniform over 1 to 20 slots and the funding window is 600
  slots, one epoch of lead time;
- the funding round is 150 slots, matching `mirror_coordinator::funding`'s
  default, and each participant dwells a uniform 0 to `dwell_rounds` rounds before
  their withdrawal is released. Dwell is a participant-side behaviour (when they
  ask for the withdrawal after shielding), not something the coordinator enforces,
  so the sweep below is a claim about user behaviour, not about code;
- every committer makes exactly one deposit and one withdrawal, so the attacker
  faces a perfect matching. A real round has a `min_round_size` floor and rolls
  thin rounds forward (merging them, which helps the defender); that is not
  modeled, so the model is the pessimistic one here;
- the joint attacker's marginals are Sinkhorn-approximated rather than exact.
  Exact matching marginals are permanents and `#P`-hard; the approximation is
  documented above with a measured instance where it is slightly loose;
- participants pass value through (the deposit and the withdrawal are the same
  amount) whenever the pool does not force a denomination. This is the
  conservative assumption: a participant who parks a balance and withdraws a
  fraction of it later leaks less than this model says.

**NOT measured, with the direction of each omission stated:**

- **Favours us:** the attacker sees only the funding leg. A real chain-analysis
  firm also has exchange KYC records, off-chain intelligence, and the
  participant's later behaviour; nothing here models those, and every one of them
  would lower the numbers.
- **Favours us:** the attacker knows every committer's funder prior but not the
  true assignment. A firm that already owns one funder's records starts from a
  sharper prior than the one modeled.
- **Favours the reader (uncredited defence):** only the epoch's own committers
  deposit into the modeled pool. A real pool carries unrelated traffic, which
  enlarges the candidate deposit set and helps the defender. That direction is
  not credited here.
- Cross-epoch behaviour (a participant funding several commit wallets, or
  reusing one across epochs) is out of scope for this metric and is listed as a
  residual in [`THREAT_MODEL.md`](THREAT_MODEL.md) Section 8.
- No on-chain trace is involved. A settlement-trace loader that computes
  effective-k over real funding provenance is a named roadmap extension (see
  [`ROADMAP.md`](ROADMAP.md)); until it lands, every number here is a model
  result on a modeled population.

## The mechanism as it exists in the tree

The funding path is code rather than a recommendation in a document, but it is
**library code plus a CLI, not a wired-up service**. Read this section as "what
exists", not "what runs":

- `mirror-cli fund-commit` generates a fresh commit-wallet keypair, reads the
  value pool's denomination from chain, refuses any other amount (the on-chain
  program enforces the same rule as `DenominationMismatch`), proves the unshield,
  and emits the `Transact` for the relay. It prints an explicit warning when the
  pool has no denomination, because in that configuration the amount channel is
  open and the measured numbers above are the free-amount rows.
- `mirror_coordinator::funding::FundingRounds` batches those withdrawals, holds
  them to the round boundary, refuses to release a round below its floor (a round
  of one withdrawal is a direct link, the same argument as the epoch `k_floor`),
  and submits them in an order derived from the round rather than from arrival.
  Each withdrawal is relay-signed only: the participant never signs the
  transaction that funds their commit wallet.

Both are unit-tested (a thin round never reaches the chain; a released withdrawal
carries exactly one signature, the relay's; an off-denomination request is refused
before it is proved).

- `mirror_coordinator::funding_service::FundingService` is the ingestion path that
  connects the two on a live cluster: `DirectoryIntake` parses each `fund-commit`
  emit (refusing anything that is not a relay-only-signed unshield for this
  program), the service polls the REAL chain slot, batches, and releases. It also
  stamps the pool-wide normalized `TxProfile`, so a participant cannot fingerprint
  their own withdrawal with a distinctive compute budget.

All three are unit-tested (a thin round never reaches the chain; a released
withdrawal carries exactly one signature, the relay's; an off-denomination request
is refused before it is proved) AND soak-proven end to end on a live local Surfpool:
see the funding-round section of [`PROOF.md`](PROOF.md), 25/25 on-chain assertions.
The soak asserts the property this section depends on directly against the chain:
each fresh commit wallet's ONLY inbound transfer over its entire on-chain history is
from the pool vault, no funding transaction mentions any participant main wallet,
and each funding transaction carries exactly one signature, the relay's. It also
shows a round below the floor rolling forward without reaching the chain at all, and
the release order being arrival-independent.

What the soak does NOT establish is the size of the residual: that is a modeled
number from the harness, over a modeled population, and no live run can measure it.
The soak proves the edge is absent from the graph; the table above is what an
adversary is left with, and it is a model.

## Why this matters

Mixer projects have historically reported the nominal set size and overstated
privacy; the empirical literature dismantled those claims after the fact [3][4].
This metric answers the "advertised k is not effective k" concern directly and
falsifiably, on the same information-theoretic axis, and it does so for our own
protocol as harshly as for the naive one: the funding channel is the one channel
mirror-pool cannot zero at settlement, and the measurement says how much of it is
left. It complements the `KAnon` real-k accounting in
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
