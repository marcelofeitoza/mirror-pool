# mirror-pool roadmap

mirror-pool is "Tornado Cash for behavior, not funds." N participants voluntarily
pool an action so the action is publicly visible but its initiator is not. The
privacy target is behavioral obscurity: making an on-chain action un-attributable
to a specific wallet by an automated chain-analysis pipeline. It is not about
hiding funds, amounts, or the fact that an action occurred.

This document states what is **built** and what is **future**. The complete
two-path system is built: a crowd path that defeats copy-trading and signal
extraction via synchronized identical actions, and a ZK opt-in path that provides
cryptographic who-initiated unlinkability, sharing one accumulator, one epoch
clock, one k-floor, and one anti-Sybil economy. Everything under "Future work" is
called out as such so a reviewer never mistakes an aspiration for a claim.

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
defeats fingerprinting and gas-payer reuse; a fixed uniform action shape removes
the copy-trade signal; honest k-accounting keeps the reported number truthful; and
the ZK opt-in path adds a cryptographic membership proof so who-initiated is
hidden even from the relay.

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
  nullifier, then release the escrow to a fresh recipient with no participant
  signature.
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
generates and verifies a Groth16 proof through snarkjs, and emits the `SettleZk`
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

---

## Future work

Directional and explicitly not part of the current claim. Each item extends an
existing, shipped pattern rather than introducing new cryptography.

### Swap-from-pool and stake-from-pool via CPI

The ZK opt-in path today releases the escrow to a fresh recipient (a lamport
transfer). The identical pattern (membership proof + root history + nullifier +
recipient/action binding) supports executing a *different* action from the pool
authority via CPI: a Jupiter swap or a jitoSOL stake-pool deposit from the pool,
landing in a fresh account. The behavior adapters already build these instructions
for the crowd path; the CPI step slots into `SettleZk` step (8) without changing
the anonymity mechanics. The `SettleEpoch` handler carries the matching hook for
program-side crowd execution.

### Anonymity-mining reward on the ZK path

The crowd path pays dwell to reward staying. Tying a reward to an on-chain identity
on the ZK path would re-introduce the linkage that path exists to remove, so the
ZK path today only funds the shared reward pool through its entry fee. The
anonymity-preserving equivalent, designed in `docs/INCENTIVES.md`, mirrors the
membership proof: commit a dwell/age value at `CommitDeposit`, then prove in zero
knowledge "I am a member whose dwell is at least T, here is a fresh reward-epoch
nullifier" and pay out to a fresh address. Shipping it is gated on a second circuit
and its trusted setup.

### A real multi-party trusted-setup ceremony

The current Groth16 setup is a reproducible development/test setup: its phase-2
entropy is public by design, which makes the toxic waste public, so it must not
secure real value. A production deployment needs a real multi-party (phase-2)
ceremony with independent contributors and a pre-committed beacon. This is
setup/operational work; the circuit and on-chain verifier do not change.

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
| CLI `prove` (path rebuild + snarkjs + emit `SettleZk`) | Built |
| Adversarial harness (FIFO/amount/gas-payer/fingerprint, real k) | Built |
| Anti-Sybil entry fee + crowd-path dwell reward | Built |
| Membership circuit + dev/test trusted setup + vendored verifying key | Built |
| Swap/stake-from-pool via CPI on the ZK path | Future |
| ZK-path anonymity-mining reward (dwell/age proof) | Future |
| Multi-party production trusted-setup ceremony | Future |
| Multi-transaction atomic settlement for large epochs | Future |
| Cross-epoch privacy, decentralized coordinator, more behaviors | Future |

**One-line honest claim:** mirror-pool ships a complete two-path behavioral
anonymity pool. The crowd path collapses the strongest empirical mixer attack
(FIFO temporal matching) to the 1/real_k baseline via shared-epoch batch
settlement, proven by an adversarial harness, and defeats fingerprint and
amount-match attacks with a gasless rotating coordinator and fixed size buckets;
the ZK opt-in path adds cryptographic who-initiated unlinkability with an on-chain
Groth16 membership proof. The remaining work is CPI-executed pooled actions, an
anonymous ZK-path reward, a production trusted-setup ceremony, and scaling, all
extensions of shipped patterns rather than new claims.
