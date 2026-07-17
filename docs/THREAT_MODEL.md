# Mirror Pool Threat Model

Mirror Pool is an anonymity set over **initiators**, not funds. N participants commit to
performing the same action; the pool settles all of them in one shared-timestamp epoch; an
observer sees N identical actions but cannot tell which participant initiated which output.
This document defines who we defend against, what they can actually see on Solana, which
attacks we defeat (with the empirical numbers that justify each defense), the falsifiable
metric we hold ourselves to, and, just as importantly, what we do **not** claim.

Every defense in this document maps to a concrete mechanism in the codebase.
`crates/mirror-core/src/lib.rs` is the shared vocabulary: `Commitment`, `Nullifier`,
`Secret`, `commit()`, `nullifier()`, `ActionClass`, `SizeBucket`, `Epoch`,
`EpochSchedule`, `KAnon`, `MirrorError`, and the `wire` layout. Every claim in this
document is testable by `crates/mirror-harness`, which implements the attacks below and
measures attacker advantage directly. If the harness shows an attack working, this
document is wrong and must be updated, not the other way around. That inversion (the
evaluation harness is the source of truth, the prose is downstream of it) is the whole
point: a privacy claim that cannot be falsified is marketing, not engineering.

---

## 1. Adversaries

We model four adversaries, in increasing order of leverage. All of them are assumed to run
full archival indexing of the chain, so every adversary below sees everything enumerated in
Section 2. We do not assume any of them is weak.

### A1. Chain-analysis clustering services

Commercial heuristics engines (Chainalysis-class). On Solana their core moves are:

- **Account roll-up.** Token accounts and stake accounts are attributed to the parent
  system (private-key) account that owns them. All system accounts judged to be one
  entity are merged into a single cluster.
- **ATA reversal.** The Associated Token Account address is a pure function of
  `(owner, mint, token_program)`. Providers maintain ATA-to-owner tables, so any value
  that lands in a recipient's canonical ATA is instantly re-linked to the owner wallet.
  There is no such thing as an anonymous ATA.
- **Co-signer merging.** Two wallets signing one transaction is treated as a strong
  co-ownership signal and typically merges their clusters.
- **Funding-source anchoring.** The single strongest real-world identity anchor is the
  common-funding-source heuristic: exchange deposit addresses and consolidation wallets
  give KYC-grade ground truth, and a fresh wallet funded from a clustered source is
  re-linked immediately.

Goal: attribute each settled action to a named cluster.

### A2. Copy-traders and shadowers

Solana has no lingering public mempool, but that does not mean pre-confirmation privacy.
Well-connected observers subscribe to validator-side streams (Geyser plugins, Yellowstone
gRPC, shred streaming) and see transactions on a sub-100ms hot path, before most
confirmations propagate. Production copy-trading systems parse swap intent (mint pair and
amount) out of these streams and replay it through an aggregator within the same or the
next slot. Master/copy detectors classify wallet pairs by timing correlation plus token
overlap across many DEXs.

The key lesson: **timing obfuscation alone loses against A2.** They do not need to know
who you are, only to parse what you are about to do. The defense must remove the
per-wallet parseable signal, not merely delay it.

Goal: identify a profitable wallet's intent early enough to front-run or shadow it.

### A3. The pool operator

The coordinator (`crates/mirror-coordinator`) is infrastructure, not a trusted party. We
model it as honest-but-curious at minimum and adversarial at maximum:

- It sees every participant's intent before settlement (v1 is commit-reveal, not ZK; see
  Section 6, Non-Goal 4).
- It could pad epochs with its own wallets to inflate the apparent anonymity set.
- It could censor, reorder, or stall epochs.

What it **cannot** do, by construction: substitute or retarget a committed action. The
commitment binds `(secret, action, epoch)` via `commit()` in
`crates/mirror-core/src/lib.rs`, so a coordinator that settles anything other than the
committed `ActionClass` produces an invalid epoch. It also cannot make a participant act
twice: nullifiers are epoch-scoped (`nullifier(secret, epoch)`) and enforced as per-epoch
PDAs on-chain. The operator can choose *whether* to settle an epoch; it can never choose
*what* each action is or *who* gets to double-act.

Goal (adversarial operator): deanonymize participants, or sell the mapping.

### A4. Sybil attacker

An attacker who joins the pool with many wallets they control. If an epoch contains 1
honest participant and k-1 attacker wallets, the attacker deanonymizes the honest
participant by elimination: they know their own actions, so whatever remains is the
target. This is not hypothetical; it is the standard way small mixers die, and it is why
Section 5 refuses to count nominal participants. Note that A4 composes with A1: an operator
that also Sybils (A3 + A4) can both fill the epoch and cluster its own fill wallets, which
is precisely the operator-cover-traffic failure Tornado was criticized for.

Goal: fill epochs cheaply so that real anonymity collapses to 1 while the pool still
advertises k.

---

## 2. What an observer actually sees on Solana

Threat models written for EVM chains under-count Solana's observability. We enumerate it
explicitly because every defense must be judged against this list. The recurring theme:
Solana surfaces more per-transaction structured data than Ethereum, so several attacks that
are approximate on EVM are *exact* here.

| Observable | Detail | Why it matters |
|---|---|---|
| **Balance deltas, first-class** | Transaction metadata carries `preBalances`/`postBalances` and `preTokenBalances`/`postTokenBalances` for every account touched. No log parsing or tracing needed; exact per-account deltas are one RPC call away and fully indexed. | Amount-matching attacks are cheap and exact. A destination whose pre-balance is 0 is trivially flagged as freshly funded (this is exactly the unmodeled side channel that broke a competing SOL-only decoy design). |
| **Deterministic ATAs** | ATA = f(owner, mint, token_program). Given any token account, the owner is a table lookup. | Any output delivered to a canonical ATA is attributed to its owner instantly. |
| **Signers and fee payer** | All signers are listed in the message header; the fee payer is the first signer. Co-signing is a clustering signal (A1). | Whoever pays for or co-signs an action is linked to it. Self-paid execution is self-attribution. |
| **Compute-budget and fee fingerprints** | `SetComputeUnitLimit` and `SetComputeUnitPrice` are ordinary visible instructions. Wallet software and SDKs have characteristic defaults (CU limits, priority-fee curves, instruction ordering, tx version, ALT usage). | Matching these settings across two transactions is the wallet-fingerprinting attack that cut Tornado's effective anonymity set by 37% on its own [1]. |
| **Timing, despite Gulf Stream** | Transactions are forwarded directly to upcoming leaders rather than sitting in a lingering public mempool, but Geyser/Yellowstone/shred-level observers see them pre-block (<100ms). Post-block, every transaction has an exact slot (~400ms granularity) and an intra-slot position. | Deposit-then-withdraw style temporal ordering is fully reconstructable. FIFO matching (Section 3.1) works exactly as well on Solana as it did on Ethereum. |
| **Account lists and ALTs** | The full account list of every transaction, including lookup-table-resolved addresses, is public. Which ALT a transaction uses is itself a fingerprint. | Per-participant account layout differences leak. Normalization must cover account ordering and ALT choice, not just fees. |
| **On-chain risk oracles** | Programs can gate execution on a wallet's risk score inside the transaction (oracle-fed risk APIs exist on Solana today). | Attribution is no longer only forensic/post-hoc; it can be enforced at execution time. A design that leaks the initiator leaks it to counterparty programs too. |

The one thing Solana does **not** give an observer that Ethereum does is a durable public
mempool of unconfirmed transactions. This is why A2 (shadowers) had to move to validator
streams. It buys a naive design nothing: the parseable intent is still there, just observed
a few milliseconds later.

---

## 3. Attacks we defend, and how

Each subsection names the attack, the empirical evidence that it is the real killer (not a
theoretical one), and the specific mechanism that defeats it. The corresponding attack
implementation lives in `crates/mirror-harness` so the defense is measured, not asserted.

### 3.1 FIFO temporal matching -> shared-epoch batching

**Attack.** Link each deposit to the earliest plausible later withdrawal. In the
large-scale empirical study of Tornado Cash (~$2.3B of mixed flows), this single heuristic
linked up to **49%** of deposits on small pools and outperformed every other heuristic by
**15-22 percentage points** [1]. It is the single strongest known attack on mixer-style
systems, which is why it is the first defense we specify.

**Why naive fixes fail.** Per-actor random delay does not defeat it. Each user's delay
distribution is heavy-tailed and user-specific, so the ordering signal survives; the study
data shows temporal matching degrades gracefully under jitter rather than collapsing. A
random delay just spreads the same ordered signature over a wider window.

**Defense.** Remove the ordering signal entirely instead of blurring it. All actions in an
epoch settle **on the same block timestamp**, in one atomic settlement
(`SettleEpoch`, `wire::tag::SETTLE_EPOCH`). There is no per-participant settlement time to
sort. `EpochSchedule::epoch_of_slot` derives the epoch from the slot clock so every
participant computes the same window with zero coordination; `EpochSchedule::settle_slot`
defines the single instant the batch becomes valid. This is the same construction that
batch-clearing DEX designs (Penumbra-style, where every swap in a block clears at one price)
use to eliminate per-user ordering by construction rather than by noise.

**Acceptance criterion (harness).** FIFO attacker advantage over random guessing must be
statistically indistinguishable from 0 under shared-epoch settlement, while the same attack
against a per-actor-random-delay baseline shows large positive advantage. This is the
headline result the harness exists to produce: FIFO advantage collapses to ~0 under
shared-epoch batching where it is high under random delay.

### 3.2 Amount matching -> fixed size buckets

**Attack.** Match inputs to outputs by value. On Solana this is especially cheap because
balance deltas are first-class metadata (Section 2), so the attacker does not even need to
trace instructions.

**Evidence.** The public measurement literature shows that variable and round-number amounts
leak a large fraction of a claimed anonymity set to amount-matching alone. Wang et al.
measured **27.34% (Ethereum) and 46.02% (BSC)** anonymity-set reduction on Tornado-style
pools from composable heuristics, and identified round-number and variable amounts as a
primary amount-matching signal [2]; the Tornado deanonymization study reports amount and
timing heuristics recovering large fractions of links, with wallet fingerprinting alone
cutting the effective set by 37% [1]. Restricting to fixed, stratified denominations sharply
reduces amount-matching leakage. That public result is the empirical proof that
size-bucketing is mandatory, not a nice-to-have; `crates/mirror-harness` implements these
heuristics fresh so the claim is measured, not asserted.

**Defense.** Fixed size buckets are baked into the type system, not left to convention.
`SizeBucket` (`Nano`/`Small`/`Medium`/`Large`) is a field of `ActionClass`, and one
anonymity set exists **per action class**: same action type, same mint pair or validator,
same bucket. The bucket is bound into the commitment via `commit()`, so a participant cannot
commit to one bucket and settle another. Two actions in the same pool are indistinguishable
by amount by construction. Heterogeneous actions in one pool would leak exactly like mixed
denominations in one mixer, so the pool refuses them at the type level rather than trusting
participants to self-segregate.

### 3.3 Wallet fingerprinting -> relay-normalized transactions

**Attack.** Match wallet-software fingerprints (fee settings, CU limits, tx construction
quirks, instruction ordering, tx version, ALT choice) between a user's entry and exit
transactions. In the Tornado study this cut the effective anonymity set by **37% on its
own** [1]. Combined with the other heuristics, the full stack achieved **34.7%** overall
linkage, plus **10-13%** from plain address reuse.

**Defense.** Participants never build or submit the settlement transaction. The coordinator
submits every epoch with **one pool-wide transaction profile**: identical CU limit,
identical priority fee, identical transaction version, canonical account ordering, and one
shared ALT. There is no per-participant transaction to fingerprint, because there is no
per-participant transaction at all at settlement. The harness includes a fingerprint
classifier and must show its advantage collapse to 0 against coordinator-built settlements.

### 3.4 Self-paid gas -> gasless execution with a rotating fee-payer set

**Attack.** Not using a relayer was a dominant deanonymization vector in the Tornado data:
users who paid their own withdrawal gas from linkable funds self-attributed, because the
fee-paying wallet is the first signer and is trivially clustered [1].

**Defense.** Execution is gasless for participants. The coordinator's fee payer signs and
funds settlement, so the acting wallet never funds or signs its own execution. But a single
fee payer for everyone is itself a consolidation node that clusters all users to the pool
operator (A1's co-signer and funding heuristics apply to the relay too). Therefore the
fee-payer role **rotates** across a set of coordinator keys with independent funding
histories. Being identified as *a Mirror Pool settlement* is acceptable and expected
(participation is public, Section 4 and 8); being clustered *per user* through a shared,
static fee payer is not. Rotation is the difference between "this is a pool transaction" and
"this is Alice's pool transaction."

### 3.5 Common funding source -> bounded, documented, partially out of scope

**Attack.** Cluster the commit wallet by where its SOL came from (A1's strongest anchor).
A fresh wallet funded straight from a KYC'd exchange deposit is re-linked the moment it
touches the pool.

**Defense and limits.** The pool cannot rewrite a participant's funding history, and we do
not pretend otherwise. What we do: (a) the commit transaction is the only transaction a
participant ever submits, and it carries only a 32-byte commitment (`wire::COMMIT_LEN`), so
the surface tied to the participant's wallet is minimal; (b) documentation and CLI warnings
push participants to commit from wallets not funded by a KYC-clustered source; (c) outputs
are never delivered to the canonical ATA of the committing wallet. Residual exposure is
acknowledged in Section 8. A pool that claimed to *fix* funding-source clustering would be
lying, and the metric in Section 5 is specifically designed to make that lie detectable.

### 3.6 Copy-trading / intent shadowing -> nothing parseable per wallet

**Attack.** A2 parses swap intent (mint pair, amount) from pre-block validator streams and
shadows it, replaying the trade through an aggregator in the same or next slot. Timing
delay does not help: the intent is parseable the instant it hits the wire.

**Defense.** Before settlement, the only thing on the wire is a commitment hash; intent
(mint pair, bucket) is not parseable from any per-wallet transaction because there is no
per-wallet action transaction, only a `Commit` carrying an opaque 32-byte leaf. At
settlement, N identical actions execute at once with no attributable initiator, so there is
no single wallet to shadow. The signal A2 needs (this wallet is about to swap X for Y as an
individual) never exists as a per-wallet observable. What A2 can still see is that *the pool*
is about to swap N-buckets of X for Y; it cannot copy any individual because there is no
individual to copy.

---

## 4. What is hidden vs. what is public

Precision here prevents overclaiming:

- **Public:** that a wallet committed into epoch E of pool P (membership); the pool's
  action class, bucket, and epoch schedule; the number of settled actions; every amount;
  every settlement transaction and its (rotating) fee payer.
- **Hidden:** the bijection between the epoch's committers and the epoch's settled outputs.
  An observer knows the set; they cannot attribute any single output to any single committer
  with probability better than 1/k (k as defined in Section 5).

This is the same shape of guarantee Tornado gave for funds, transplanted to initiation:
membership was never secret, the *link inside the set* is.

---

## 5. The k-anonymity metric (falsifiable, or it does not count)

Mixer projects have historically reported the **nominal** set size (total deposits) and
overstated privacy; the empirical literature dismantled those claims after the fact [1][2].
Operator-generated cover traffic is the worst version of this: wallets the operator controls
inflate the count while adding **zero** anonymity against anyone who clusters the operator
(and A1 will). Reporting a measured, falsifiable anonymity number is our explicit
differentiator against tools that leave anon-set size undisclosed.

Mirror Pool's rule, enforced in code:

- **real k = distinct, economically distinct, non-operator participants in the epoch.**
  Never the nominal commit count.
- The type is `KAnon { nominal, excluded }` with `real_k() = nominal.saturating_sub(excluded)`
  in `crates/mirror-core/src/lib.rs`. Operator wallets and detected Sybils go into
  `excluded`.
- An epoch may not settle below the floor: `KAnon::meets_floor(&schedule)` checks
  `real_k() >= EpochSchedule::k_floor`, and the coordinator rolls the epoch forward
  (`MirrorError::BelowKFloor`) rather than executing into a set small enough to deanonymize
  by elimination. Settling k=3 late is strictly better than settling k=1 on time.

**Falsifiability.** The claim "this epoch provided k-anonymity of k" is falsifiable in two
concrete ways, and we ship the tools to falsify it:

1. `crates/mirror-harness` runs the full attack suite (FIFO temporal matching, amount
   matching, gas-payer reuse, wallet fingerprinting, temporal correlation, common funding,
   plus a learned classifier over all features) and reports **attacker advantage**:
   `Adv = P[correct attribution] - 1/real_k`. The pool's claim holds only if `Adv` is
   statistically indistinguishable from 0 for the Mirror Pool configuration while being large
   for the baseline (per-actor random delay, self-paid gas, variable amounts). A positive
   measured `Adv` is a broken claim, full stop, and the harness prints it as such.
2. Anyone can recompute `real_k` for a settled epoch from public data plus the operator's
   published fee-payer and cover-wallet disclosures. If the recomputed real k is below what
   the pool reported, the report was false.

We publish real k per epoch. We never publish nominal as if it were anonymity. The unit test
`real_k_excludes_sybils` in `crates/mirror-core/src/lib.rs` pins this: a nominal set of 100
with 91 excluded is real_k = 9, which does not meet a k_floor of 10 and therefore must not
settle.

---

## 6. Non-goals

Stated bluntly, because a privacy tool that is vague about its non-goals is a trap:

1. **We do not hide amounts.** Every balance delta is public and intended to be. (Solana
   already has an amounts-only privacy primitive: Token-2022 confidential transfers hide the
   amount while leaving sender, receiver, and mint public, so the entity graph stays intact
   [4]. Mirror Pool is the complement: amounts public, initiator unattributable.) Anyone
   expecting fund hiding is in the wrong tool.
2. **We do not defend the destination history of external payees.** If the pooled action
   pays a known merchant, the merchant's canonical ATA identifies the merchant; that is
   inherent to deterministic ATAs. We hide **which participant** initiated the payment, not
   **who got paid**.
3. **The guarantee is per-epoch, not cross-epoch.** An adversary with a prior over many
   epochs (intersection attacks: "the target participated in epochs 3, 7, and 12") can narrow
   the set across epochs. v1 makes no cross-epoch claim. Mitigations (participation padding,
   epoch-varying wallets) are roadmap items in `docs/ROADMAP.md`, not shipped guarantees.
4. **v1 is not ZK.** The coordinator learns the participant-to-intent mapping off-chain (it
   must, to build the settlement). It cannot forge, retarget, or double-execute actions
   (commitment binding via `commit()` plus epoch-scoped nullifier PDAs), but a compromised or
   subpoenaed coordinator can reveal the mapping for epochs it served. v2 replaces
   commit-reveal with Poseidon commitments and Groth16 membership proofs verified on-chain via
   the alt_bn128 syscalls, removing the coordinator from the trust base for attribution. Until
   then, this is a disclosed trust assumption, not a hidden one, and the public API in
   `mirror-core` is deliberately shaped so the v2 swap is additive.
5. **No network-layer anonymity.** IP-level correlation between a participant and the
   coordinator's API is out of scope; use your own transport protections.

---

## 7. Sybil and incentive assumptions

The k-anonymity claim in Section 5 is only as good as these assumptions, so they are listed
as assumptions, not buried as implementation details. If one of these fails, the metric
still reports honestly (it will simply report a smaller real k), but the design's economic
security fails. The economic layer that backs these assumptions (the entry-fee split, the
dwell reward, and the honest real-k reporting) is specified in full in `docs/INCENTIVES.md`,
which is explicit about what is implemented on-chain versus designed for the anonymous path.

- **Per-identity cost is real.** Each commit carries a fixed, non-refundable entry fee
  (fidelity-bond style), collected on BOTH the crowd `COMMIT` and the ZK opt-in
  `COMMIT_DEPOSIT`. Filling an epoch with k-1 Sybil wallets must cost the attacker (k-1) x fee
  per epoch, forever, because the honest floor rolls forward until it is met. Without a real
  per-identity cost, A4 wins for free and real k = 1 regardless of what the pool reports. A
  configurable `reward_bps` share of each fee accrues to an on-chain reward pool
  (`pool::reward_pool_lamports`); the remainder covers settlement cost. The reward pool funds
  the participation incentive below without weakening the cost, since the fee is still
  non-refundable to the payer at commit time.
- **No-shows forfeit and stall nothing.** Settlement is atomic per epoch: a participant who
  commits and disappears forfeits their slot and fee; the epoch settles with the remaining set
  (if still above `k_floor`) or rolls forward. One-transaction-per-party settlement designs
  die to dropout griefing; atomic program-side epoch settlement does not. (Jito bundles cap at
  5 transactions, so N-party atomicity beyond ~5 must be program-side, which is why
  `SettleEpoch` settles all intents in a single instruction.)
- **Operator traffic is excluded by policy and by accounting.** Any coordinator-owned wallet
  in an epoch is counted in `KAnon::excluded`, as is any commit the coordinator flags
  Sybil-suspected (`PoolEntry::sybil_suspected`). Cover traffic may smooth epoch cadence, but
  it never counts toward the advertised k. This is the direct lesson from Tornado's overstated
  sets: operator-generated cover inflates nominal and adds zero real anonymity to anyone who
  clusters the operator. Every settlement outcome and log line surfaces `real_k` (with
  `nominal` and `excluded` beside it so the gap is auditable); users are shown `real_k`, never
  the nominal count.
- **Incentives reward measured anonymity, not pool size.** Anonymity-mining style rewards
  demonstrably attract privacy-indifferent users whose behavior (instant in-out, address
  reuse) degrades the set for everyone [2], which is why pool size is not anonymity. The
  shipped incentive is therefore a **dwell** reward: on the crowd path, `CLAIM_REWARD` pays a
  participant a drain-safe share of the reward pool proportional to how many distinct epochs
  they have committed into, so staying (which thickens future epochs) is what pays, and
  committing once and leaving is not. Dwell can only advance through a real, fee-paying commit,
  so it cannot be minted for free. The anonymous ZK path deliberately ships no identity-linked
  claim; its anonymity-preserving equivalent (a dwell/age ZK proof, so claiming does not
  deanonymize) is DESIGNED but not implemented, and `docs/INCENTIVES.md` says so plainly. The
  harness metric, not pool size, remains the success criterion.
- **Sybil detection is best-effort.** `excluded` reflects *detected* Sybils only: operator
  ownership and off-chain heuristic flags. The strongest anchor, a common on-chain funding
  source (Section 3.5), is NOT computable from the commit stream (a commit carries only a
  32-byte commitment), so same-funding-source Sybils are out of on-chain scope and inflate
  `real_k`. The honest worst-case statement a participant should rely on is: my anonymity is at
  least the number of participants I personally believe are independent, and at most `real_k`.

---

## 8. Honest residual leaks

What still leaks after every defense above. These are known, accepted (for v1), and tracked;
several are measurable by the harness today. We list them rather than hide them because a
threat model that only enumerates its wins is untrustworthy.

1. **Membership is public.** The commit transaction links a wallet to the pool and epoch.
   Like Tornado deposits, participation itself was never hidden. Anyone gating on "has used a
   privacy tool" will flag participants.
2. **Coordinator knowledge (v1).** See Non-Goal 4. The participant-to-intent mapping exists
   off-chain until v2.
3. **Cross-epoch intersection.** See Non-Goal 3. A participant with a recognizable
   participation schedule (same time of day, same epochs as some external event) fingerprints
   themselves across epochs even though each epoch is individually sound.
4. **Upstream funding of the commit wallet.** If the committing wallet is funded from a
   KYC-clustered source, A1 knows *who the member is* (though still not *which output is
   theirs*, which is the property we actually sell). Section 3.5 bounds but does not eliminate
   this.
5. **Output delivery discipline.** The epoch hides the committer-to-output bijection, but a
   participant who sweeps their output into a wallet clusterable to their commit wallet
   re-links themselves retroactively. Deterministic ATAs make this a one-lookup mistake. The
   CLI refuses the obvious footgun (delivering to the commit wallet's canonical ATA), but
   post-settlement hygiene is ultimately the participant's.
6. **Low-participation timing leak.** A `k_floor` roll-forward is observable: outsiders learn
   the pool had fewer than `k_floor` real participants that window, and settlement latency
   correlates with demand. This is the deliberate price of never settling thin epochs.
7. **Fresh-account side channels at the edges.** A destination account with `preBalance == 0`
   is visibly fresh (this is exactly the unmodeled side channel that broke a competing
   decoy-bundle design). Within an epoch this matches every participant equally (identical
   buckets, identical shapes), so it does not discriminate *inside* the set, but it does mark
   outputs as pool outputs.
8. **Behavior-module side effects.** Pooled actions execute through real venues (an
   aggregator route for `ActionClass::Swap`, a stake program for `ActionClass::Stake`). Route
   and venue parameters are pool-normalized per epoch, but venue-side effects (e.g. a route
   touching an unusual intermediate market) are shaped by market conditions the pool does not
   control. Any parameter that could vary per participant is either fixed pool-wide or the
   action does not ship.
9. **The pool itself is identifiable.** Normalization makes every settlement look like a
   Mirror Pool settlement. That is intentional (uniformity is the defense), but it means the
   pool's aggregate activity (volume per bucket per epoch) is public analytics.

None of these residuals reintroduce the property we sell: within a settled epoch that met its
floor, the committer-to-output bijection stays hidden at the 1/k bound. They erode the
context around the set, not the indistinguishability inside it, and every one of them is
either measured by the harness or has a named roadmap mitigation.

---

## References

[1] "Deanonymizing Tornado Cash: an empirical analysis of $2.3B of mixed flows"
(arXiv:2510.09433). Key figures used here: FIFO temporal matching links up to 49% of deposits
on small pools (+15-22pp over other heuristics); wallet fingerprinting via gas/priority-fee
settings reduces the effective anonymity set by 37% alone; address reuse links 10-13%;
combined heuristics reach 34.7%; self-paid (non-relayer) gas is a dominant deanonymization
vector.

[2] Wang et al., "On How Zero-Knowledge Proof Blockchain Mixers Improve, and Worsen User
Privacy" (arXiv:2201.09035). Key figures: 27.34% (Ethereum) / 46.02% (BSC) anonymity-set
reduction from composable heuristics; anonymity mining attracts privacy-indifferent users
whose behavior degrades the set.

[3] Effective-vs-claimed anonymity-set gap methodology. `crates/mirror-harness` implements,
fresh in Rust, the composable amount / timing / fingerprint heuristics of [1] and [2]
against two configurations (naive baseline vs. Mirror Pool) and reports attacker advantage
over the 1/k baseline, so every privacy claim in this document is measured rather than
asserted.

[4] Token-2022 Confidential Transfers (Solana Program Library). Hide the transferred amount
while leaving sender, receiver, and mint public. Cited as the complement to Mirror Pool:
amounts hidden but the entity graph intact, versus amounts public but the initiator
unattributable. Confidential Transfers alone do not obscure behavior.

[5] Penumbra batch swaps. All swaps in a block execute at one clearing price, so per-user
ordering and attribution are eliminated by construction and only the batch aggregate is
revealed. This is the precedent for shared-epoch settlement (Section 3.1): who-initiated
indistinguishability achieved structurally rather than through added noise.
