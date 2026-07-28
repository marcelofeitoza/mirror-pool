# mirror-pool roadmap

mirror-pool is "Tornado Cash for behavior, not funds." N participants voluntarily
pool one identical action into a synchronized round, and the round is what an
automated chain-analysis pipeline has to read. The two paths target different
things, and the difference is load-bearing:

- the **crowd path** removes the per-actor *signal* (timing, ordering, size, gas
  payer, fingerprint, parseable intent) while each participant still signs their
  own action, so the action stays attributable to that wallet;
- the **ZK opt-in path** removes the attribution itself, settling to a fresh
  output with no participant signature behind an on-chain membership proof.

Neither is about hiding funds, amounts, or the fact that an action occurred. An
optional confidential-value layer (below) deliberately extends BEYOND that theme: a
Tornado-Nova-style shielded pool that also hides amounts, so a deployment running
it alongside the ZK path hides both who initiated an action and how much moved.

This document states what is **built** and what is **future**. The complete
two-path behavioral system is built: a crowd path that defeats copy-trading and
signal extraction via synchronized identical actions, and a ZK opt-in path that
provides cryptographic who-initiated unlinkability, sharing one accumulator, one
epoch clock, one k-floor, and one anti-Sybil economy. The optional confidential-
value layer is built too and soak-proven end to end. Everything under "Future work"
is called out as such so a reviewer never mistakes an aspiration for a claim.

---

## Threat model (what we defeat)

The design is calibrated against the empirically strongest deanonymization attacks
on real mixers and Solana clustering, not a strawman. Full detail is in
`docs/THREAT_MODEL.md`; the short version:

- **FIFO temporal matching** - the single strongest empirical break on Tornado
  (deposit to earliest later withdrawal links up to about 49% on small pools,
  +15 to 22pp over other heuristics; arXiv:2510.09433). This is the primary attack
  mirror-pool is built to collapse.
- **Amount matching** - variable and round-number amounts leak a large fraction of
  the claimed anonymity set to amount-matching alone (Wang et al.,
  arXiv:2201.09035; the Tornado study, arXiv:2510.09433). Fixed/stratified
  denominations sharply reduce that leakage.
- **Wallet fingerprinting** - matching wallet-software gas/priority-fee/tx-shape
  settings across two transactions cut the effective set about 37% alone.
- **Gas-payer reuse / common funding source** - self-paying gas is a dominant
  deanon vector, and a single fee-payer for everyone becomes a consolidation node.
- **Copy-trading pre-block shadowing** - bots replay parsed swap intent
  (mints + amount) via validator streams in under 75ms; timing obfuscation alone
  loses, so the parseable signal must be removed, not merely delayed.
- **Sybil / operator cover traffic** - operator-generated decoys inflate the
  *nominal* count but add zero real anonymity; we report real k, never nominal.

Design responses, one line each: shared-epoch batch settlement defeats FIFO; fixed
size buckets defeat amount matching; a normalized, rotating gasless coordinator
defeats fingerprinting and gas-payer reuse; denominated, batched funding rounds
that credit a fresh commit wallet out of the value pool would remove the
main-wallet-to-commit-wallet edge that common-funding clustering keys on (designed
and unit-tested but not wired into a running service, with the residual measured in
`EFFECTIVE_K.md` rather than assumed away); a fixed uniform action shape removes
the copy-trade signal; honest k-accounting keeps the reported number truthful; and
the ZK opt-in path adds a cryptographic membership proof so who-initiated is hidden
even from the relay - which the crowd path, where each participant signs their own
action, does not do.

---

## Built: the complete two-path system

Everything below is implemented, tested, and demonstrable end to end (unit tests
per crate, mollusk tests for the program, and a Surfpool run for the crowd path).

### The on-chain program (`programs/mirror-pool`)

A standalone Pinocchio program (its own `[workspace]`, built with
`cargo build-sbf`) exposing six instructions across both paths, all with
fail-closed parsing:

- `InitPool` - fix `epoch_slots`, `k_floor`, `entry_fee`, `reward_bps`, and the
  settle authority forever.
- `Commit` (crowd) - append a commitment leaf, lazily create the Epoch PDA, bump
  the commit count, collect the entry fee, optionally accrue dwell.
- `SettleEpoch` (crowd) - enforce authority + window-closed + on-chain k-floor,
  create one Nullifier PDA per spend (anti-replay), mark the epoch settled.
- `CommitDeposit` (ZK opt-in) - escrow the action input and append a commitment
  whose `actionHash` binds `(recipient, amount)`.
- `SettleZk` (ZK opt-in) - verify a Groth16 membership proof on-chain
  (alt_bn128), check the root-history ring, the actionHash binding, and the
  nullifier, then release the escrow to the bound recipient with no participant
  signature. It enforces no k-floor, no denomination and no recipient freshness;
  `docs/THREAT_MODEL.md` section 4 gives the reason for each and names what
  compensates, and "Denominated ZK deposits with per-leaf escrow" below is the
  change that would let the program enforce them.
- `ClaimReward` (crowd) - pay a dwell-proportional, drain-safe share of the reward
  pool.

State: a Pool PDA holding an inline Poseidon frontier Merkle accumulator (depth 20)
plus a 32-root history ring and the incentive counters; per-window Epoch PDAs;
per-spend Nullifier PDAs; per-participant Dwell PDAs. Details in
`docs/ARCHITECTURE.md`.

### The ZK layer (`circuits/` + on-chain verifier)

A depth-20 Poseidon membership circuit (circomlib Poseidon, Groth16) with 4 public
inputs `[root, nullifierHash, actionHash, epoch]`, a reproducible development/test
trusted setup, a committed proof fixture, and the verifying key vendored into the
program. The on-chain `SettleZk` verifies proofs with `groth16-solana` via the
alt_bn128 syscalls. A fixture cross-check test proves the host Poseidon, the
on-chain syscall Poseidon, and the circuit agree byte-for-byte.

### The trusted-setup ceremony (`crates/mirror-ceremony`)

A distributable multi-party Groth16 **phase-2** ceremony, in pure Rust, for both
circuits: import a PUBLIC phase-1 powers-of-tau (the file's own contributor list is
read back out of it), re-randomize `delta` per contribution with a Schnorr proof of
knowledge bound to the contributor identifier, the position in the chain, and the
step's kind and provenance, chain the whole thing with SHA-256 over a canonical
serialization, and verify it with pairing same-ratio checks anyone can reproduce.
Verification rejects a tampered delta, a forged or replayed proof of knowledge, a
reordered chain, a truncated chain, a step appended after the closing beacon and a
beacon relabelled as a contributor, each with its own test. The reported number is an
**independent-contributor** count that refuses to count self-runs, deterministic
contributions or beacons, and that documents precisely what it cannot detect - in
particular that without the pre-committed beacon value a public beacon scalar and a
secret one are indistinguishable.

Driven from `mirror-cli ceremony start | contribute | beacon | verify |
verify-transcript | export-vk | inspect-ptau | prove-check`. `prove-check` is the
decisive one: it proves the membership circuit under a ceremony-produced key and runs
the EXACT on-chain `groth16-solana` verifier over the result against the
ceremony-exported verifying key. Full guide in `docs/CEREMONY.md`; the demonstration
run's transcripts are committed under `docs/ceremony-run/`.

**What is not yet done:** no production ceremony has been *run*. The committed and
deployed verifying keys still come from the insecure dev setup.

### The coordinator (`crates/mirror-coordinator`)

The off-chain gasless coordinator: a slot-window batch scheduler, the real-k floor
gate (roll forward below the floor, never execute into a set small enough to
deanonymize by elimination), a rotating fee-payer set, and a normalized
transaction profile (fixed CU limit + priority fee). The crowd path composes one
atomic v0 transaction (normalized ComputeBudget + `SettleEpoch` + every
participant's own action) with `N + 1` signers over an Address Lookup Table, sized
to the 1232-byte packet limit and chunked by `plan_settlements`. The scheduler is
generic over a submitter seam so the privacy-critical logic is fully testable
without a validator.

### The behaviors (`crates/mirror-behaviors`)

A `Behavior` trait plus adapters: a fixed-shape `PlainTransfer` (the deterministic,
no-network action the end-to-end soak executes), a Jupiter v6 swap, and a jitoSOL
stake-pool deposit. Amounts are bucketed (`SizeBucket`), never free-form; the
Jupiter adapter drops per-participant compute-budget instructions so the
coordinator owns the one pool-wide tx shape.

### The CLI (`crates/mirror-cli`)

`init-pool`, `commit`, `deposit-commit`, `prove`, and `status`. `prove` rebuilds
the Merkle inclusion path off-chain, confirms the root is a known recent root,
generates and verifies a Groth16 proof in-process in pure Rust (`ark-circom` /
`ark-groth16`, no Node; `--use-snarkjs` is a legacy fallback), and emits the `SettleZk`
instruction for the relay (it never self-submits, keeping settlement gasless).

### The adversarial harness (`crates/mirror-harness`)

The measurement layer that turns anonymity claims into numbers. It runs four
chain-analysis attacks (FIFO temporal matching, amount matching, gas-payer reuse,
wallet fingerprinting) against a naive Baseline and the mirror-pool configuration
and reports attacker advantage over the 1/k baseline. It is deterministic (fixed
seed, ChaCha20) so the table is re-derivable. The headline result: FIFO advantage
is high under per-actor random delay and collapses to about 0 under shared-epoch
batching, with amount, gas-payer, and fingerprint advantage collapsing under fixed
buckets, gasless rotating relay, and normalized shape.

### The anti-Sybil economy (`docs/INCENTIVES.md`)

A per-commit, non-refundable entry fee on both commit paths, a `reward_bps` split
into an on-chain reward pool, crowd-path dwell accrual, and a drain-safe,
dwell-proportional `ClaimReward`. The coordinator reports real k (nominal minus
operator-owned and detected Sybils) and gates settlement on it. Implemented on the
crowd path; the ZK-path anonymity-mining equivalent is designed, not implemented
(see Future work).

### The confidential-value layer (`programs/mirror-pool` + `circuits/` + crates)

An optional, SEPARATE subsystem that hides amounts, complementing the behavioral
core's who-initiated privacy. A dedicated `ValuePool` account (its own Poseidon
value-note accumulator + 32-root history ring + a vault PDA for the commingled
lamports) is created by `InitValuePool` (tag 6). One `Transact` instruction (tag 7)
settles a Tornado-Nova-style 2-in/2-out JoinSplit: a single universal statement
covers shield (`publicAmount = +v`), transfer (`publicAmount = 0`), and unshield
(`publicAmount = r - v`), distinguished only by the signed public amount. The
program verifies the JoinSplit Groth16 proof on-chain (`groth16-solana`, alt_bn128,
7 public inputs), checks the root-history ring and the `extDataHash` binding, spends
two input nullifier PDAs, inserts two output commitments, and moves lamports per the
decoded amount. Value notes are `Poseidon(amount, pubkey, blinding)` UTXOs with
position-bound nullifiers; output notes are delivered as on-chain encrypted blobs
(ECIES: X25519 -> HKDF-SHA256 -> ChaCha20-Poly1305, 100-byte blob) that the
recipient discovers by trial-decryption with a viewing key. An optional fixed-
denomination mode (`ValuePool.denomination = Some(d)`) enforces that every public
shield/unshield moves exactly `d` (`DenominationMismatch`), giving amount
k-anonymity. The CLI (`value-keygen`/`init-value-pool`/`shield`/`transfer`/
`unshield`/`scan`) proves in pure Rust and emits the `Transact`; the coordinator's
`submit_transact` settles it gaslessly (relay-only signer for transfer/unshield, so
the user never signs; depositor co-sign for a shield). Because a confidential
transfer settles through the gasless relay with `publicAmount == 0`, that transfer
hides both who initiated it and how much it moved. That property belongs to the
value layer's own transfers; it does not extend to a crowd-path action, which the
participant still signs. The whole path is soak-proven end
to end (shield / transfer / unshield + fixed-denomination, 25/25 on-chain
assertions; `docs/PROOF.md`). The JoinSplit trusted setup is the same reproducible
development/test setup as the membership circuit and MUST NOT secure real value.

---

## Future work

Directional and explicitly not part of the current claim. Each item extends an
existing, shipped pattern rather than introducing new cryptography.

### Swap-from-pool and stake-from-pool via CPI

The ZK opt-in path today releases the escrow to the bound recipient (a lamport
transfer). The identical pattern (membership proof + root history + nullifier +
recipient/action binding) supports executing a *different* action from the pool
authority via CPI: a Jupiter swap or a jitoSOL stake-pool deposit from the pool,
landing in a fresh account. The behavior adapters already build these instructions
for the crowd path; the CPI step slots into `SettleZk` step (8) without changing
the anonymity mechanics. The `SettleEpoch` handler carries the matching hook for
program-side crowd execution.

### Denominated ZK deposits with per-leaf escrow

The v1 ZK escrow is a pool-wide pot: the leaf is opaque, so nothing on-chain ties
the `amount` a settle releases to the `amount` its owner escrowed, and because both
paths append the same leaf shape to one accumulator, a fee-only crowd `Commit` leaf
satisfies the membership circuit too (`docs/THREAT_MODEL.md` section 4 and residual
11, with the test that demonstrates it). The consequence is the disclosed limit that
a v1 pool must not hold value it cannot afford to lose.

The fix is the same one Tornado-style pools use, and it is deliberately a v2
because it is two coordinated breaking changes rather than a patch:

1. **A fixed denomination per pool.** `InitPool` pins it, `CommitDeposit` rejects
   anything else, and `SettleZk` requires the released amount to equal it. Each
   leaf is then worth exactly one denomination, so the pot balances by counting,
   and the amount channel stops singling out deposits. The confidential-value
   layer already ships this shape (`DenominationMismatch`, `ValuePool`), so the
   pattern is proven in-tree. This changes the Pool layout.
2. **Domain-separated leaves.** The crowd and ZK paths must not share a leaf
   space, so a crowd commit can never be a membership witness for an escrow.
   Separating them at append (a distinct hash domain per path) is enough and does
   not change the circuit; a separate accumulator per path is the heavier variant.

Only with both does an on-chain floor mean what a reader would assume, which is
why v1 does not ship a floor on this path instead of shipping half of this. Any
version that adds a settle-time condition to `SettleZk` must ALSO add a refund or
re-bind path, or it converts thin windows into stranded escrow (the reason the
floor is a client check today).

### Anonymity-mining reward on the ZK path

The crowd path pays dwell to reward staying. Tying a reward to an on-chain identity
on the ZK path would re-introduce the linkage that path exists to remove, so the
ZK path today only funds the shared reward pool through its entry fee. The
anonymity-preserving equivalent, designed in `docs/INCENTIVES.md`, mirrors the
membership proof: commit a dwell/age value at `CommitDeposit`, then prove in zero
knowledge "I am a member whose dwell is at least T, here is a fresh reward-epoch
nullifier" and pay out to a fresh address. Shipping it is gated on a second circuit
and its trusted setup.

### Running the ceremony for production and redeploying with its key

The ceremony itself is **built** (see "The trusted-setup ceremony" above and
`docs/CEREMONY.md`). What remains is operational: recruit contributors who are
independent of the project and of each other, run the chain for both circuits with a
publicly pre-committed beacon, publish the transcripts, the ceremony hashes AND the
beacon source (a verifier needs it to check that no counted step is the beacon under
another name), then export the verifying keys and redeploy the program with them.

Until that is done the committed and deployed verifying keys are still the dev-setup
keys, whose toxic waste is public by construction. The circuits and the on-chain
verifiers do not change; only the embedded verifying key does.

### Confidential deposits (hide even the shield amount)

Today the confidential layer's shield and unshield expose their magnitude at the
public boundary (only internal transfers carry `publicAmount == 0`); the fixed-
denomination mode narrows that to one uniform amount but does not remove it. A
confidential-deposit rail would let the shield amount itself be hidden (for example,
funding the pool from an already-shielded balance or a batched deposit clearing), so
that even entering and leaving the pool leaks no magnitude. This is additive to the
existing `Transact` statement and does not change the who-initiated mechanics.

### n-in / n-out JoinSplit beyond 2-in / 2-out

The `Transact` statement is fixed at two inputs and two outputs, which forces
multi-note consolidation or splits across several transactions. A parameterized
n-in / n-out circuit (the standard Tornado-Nova generalization) would settle larger
UTXO reshuffles in one proof. It is a circuit-shape change plus a wider instruction
layout; the account model, nullifier PDAs, and verifier integration are unchanged.

### Confidential swap and stake from the value pool

The behavioral ZK path already has swap-from-pool and stake-from-pool on its
roadmap (via CPI at settle). The confidential-value layer is the natural home for
the amount-hiding version: execute a pooled swap or stake whose input note is
spent inside a `Transact` and whose output lands as a fresh confidential note, so
neither the initiator nor the amount is exposed. This reuses the shipped JoinSplit
plus the behavior adapters and adds a CPI step at settle, mirroring the behavioral
plan below.

### Multi-transaction atomic settlement for large epochs

`SettleEpoch` settles up to `MAX_SETTLE_NULLIFIERS` (32) per call and marks the
epoch settled, so an epoch larger than one packet's worth of participants needs a
settle-in-parts capability: either grow the ALT to also carry the per-participant
Nullifier PDAs (raising the single-tx cap) or add an additive program capability
that settles an epoch across several transactions while preserving atomic k-floor
and anti-replay. `plan_settlements` already chunks the participant set correctly so
the split is ready when that capability lands.

### Scaling and hardening

Directional items with no current claim: a larger root-history ring for
higher-throughput ZK settlement; a production slot source (RPC polling or slot
subscription) behind the existing `on_slot` entry point; decorrelating fee-payer
rotation from epoch ids and retiring payers after N uses; persisting the commit
pool so a coordinator restart cannot orphan an open epoch; cross-epoch privacy
(defeating intersection attacks across rounds); a decentralized/threshold
coordinator set so no single operator sees every commit; additional pooled
`ActionClass` variants (LP add/remove, governance votes, NFT mints), each its own
anonymity set; and completing the harness's named extensions (temporal
correlation, common-funding clustering, and a learned classifier over the combined
feature set) plus an on-chain trace loader so the attacks also run against a real
settlement trace.

---

## Built-vs-future at a glance

| Capability | Status |
| --- | --- |
| Crowd path: k-anon slot epochs + shared-timestamp atomic settle | Built |
| ZK opt-in path: on-chain Groth16 membership proof + fresh-recipient settle | Built |
| Poseidon frontier accumulator + 32-root history ring | Built |
| Fixed `ActionClass` + `SizeBucket` (one anonymity set per class) | Built |
| Gasless rotating coordinator with normalized tx shape | Built |
| Behavior adapters (PlainTransfer, Jupiter swap, jitoSOL stake) | Built |
| CLI `prove` (path rebuild + in-process pure-Rust Groth16 + emit `SettleZk`) | Built |
| Adversarial harness (FIFO/amount/gas-payer/fingerprint, real k) | Built |
| Anti-Sybil entry fee + crowd-path dwell reward | Built |
| Membership circuit + dev/test trusted setup + vendored verifying key | Built |
| Multi-party phase-2 ceremony: delta re-randomization, Schnorr PoK bound to kind and provenance, SHA-256 transcript, enforced beacon-is-final rule, reproducible verify (with optional beacon pre-commitment check), transcript-only verify, self-run-refusing contributor count | Built |
| Confidential-value layer: ValuePool + 2-in/2-out JoinSplit `Transact` (shield/transfer/unshield) | Built |
| Confidential JoinSplit circuit + dev/test setup + vendored verifying key | Built |
| Value notes + encrypted-note discovery (ECIES, viewing key, `scan`) | Built |
| Fixed-denomination mode (amount k-anonymity, `DenominationMismatch`) | Built |
| Gasless confidential submit (`submit_transact`, relay-only signer) | Built |
| Confidential CLI (`value-keygen`/`shield`/`transfer`/`unshield`/`scan`) | Built |
| Funding-provenance path: `fund-commit` (fresh commit wallet funded by unshield, emits the request) + `FundingRounds` batcher (denomination, batching, minimum-round floor) | Library + CLI; NOT wired end to end, NOT soaked |
| Effective-k derived from the funding mechanism's rules, with its residual measured and published (a model, not a deployment measurement) | Built |
| Joint deposit-to-withdrawal matching inference in the harness adversary | Built |
| Swap/stake-from-pool via CPI on the ZK path | Future |
| ZK-path anonymity-mining reward (dwell/age proof) | Future |
| A production ceremony actually RUN with external contributors, and the program redeployed with its key | Future |
| Multi-transaction atomic settlement for large epochs | Future |
| Confidential deposits (hide even the shield/unshield magnitude) | Future |
| n-in / n-out JoinSplit beyond 2-in / 2-out | Future |
| Confidential swap/stake from the value pool | Future |
| Wiring `fund-commit` into a running `FundingRounds` service, and soaking a funding round live | Future |
| Cross-epoch privacy, decentralized coordinator, more behaviors | Future |

**One-line honest claim:** mirror-pool ships a complete two-path behavioral
anonymity pool plus an optional confidential-value layer. The crowd path collapses
the strongest empirical mixer attack (FIFO temporal matching) to the 1/real_k
baseline via shared-epoch batch settlement, proven by an adversarial harness, and
defeats fingerprint and amount-match attacks with a gasless rotating coordinator and
fixed size buckets - it does not hide the on-chain signer, because each participant
signs their own action; the ZK opt-in path is the one that adds cryptographic
who-initiated unlinkability, with an on-chain Groth16 membership proof and no
participant signature at settle; and the confidential-value layer adds a
Tornado-Nova 2-in/2-out JoinSplit that hides amounts (soak-proven end to end), so a
deployment running it with the ZK path can hide both who initiated and how much
moved. That same value pool is *designed* to carry the funding leg: a commit wallet
credited by an unshield in a denominated, batched funding round rather than by a
transfer from a main wallet, which would remove the common-funding edge and leave a
residual the harness measures (75.8% of nominal effective-k at k=32 from the
enforced rules alone, 90.0% if participants voluntarily dwell two rounds, both at
full adoption) instead of assuming. That leg is library code plus a CLI that emits
a request; nothing wires the two together yet, and it has never been soaked. The
remaining work is that wiring plus a funding-round soak, CPI-executed pooled
actions, an anonymous ZK-path reward, actually running the (already built)
trusted-setup ceremony with external contributors and redeploying with its key,
confidential deposits, an n-in/n-out JoinSplit, confidential swap/stake, and
scaling, all extensions of shipped patterns rather than new claims.
