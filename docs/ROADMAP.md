# mirror-pool Roadmap

mirror-pool is "Tornado Cash for synchronized *behavior*, not funds." N users
voluntarily pool an action so the action is publicly visible but its initiator is
not. The privacy target is **behavioral obscurity**: making an on-chain action
un-attributable to a specific wallet by an automated chain-analysis pipeline. We
are not hiding funds, amounts, or the fact that an action occurred.

This document is the single source of truth for scope. It marks what ships for
the Superteam Brasil bounty deadline (**2026-07-29**) versus what is deliberately
deferred. Everything under "v1" is in-scope and must be demonstrable end-to-end;
everything under "v2" and "v3+" is stretch and is called out as such so a reviewer
never mistakes an aspiration for a claim.

---

## Threat model (what we are defeating)

The design is calibrated against the empirically strongest deanonymization
attacks on real mixers and Solana clustering, not a strawman:

- **FIFO temporal matching** - the single strongest empirical break on Tornado
  Cash (deposit to earliest later withdrawal links up to ~49% on small pools,
  +15-22pp over other heuristics; see arXiv 2510.09433). This is the primary
  attack mirror-pool is built to collapse.
- **Amount matching** - variable and round-number amounts leak a large fraction
  of the claimed anonymity set to amount-match alone (Wang et al.,
  arXiv:2201.09035, 27.34% ETH / 46.02% BSC anonymity reduction from composable
  heuristics; the Tornado deanonymization study, arXiv:2510.09433).
  Fixed/stratified denominations sharply reduce that leakage.
- **Wallet fingerprinting** - matching wallet-software gas/priority-fee/tx-shape
  settings across a deposit and a withdrawal cut the effective set ~37% alone.
- **Gas-payer reuse / common funding source** - self-paying gas is a dominant
  deanon vector; a single fee-payer for everyone becomes a consolidation node
  that re-clusters every participant. Deposit-address / funding-source reuse is
  the #1 real-world identity anchor.
- **Solana ATA determinism** - a recipient's canonical ATA is `f(owner, mint,
  token_program)`, so value landing in it re-links to the identity wallet
  instantly; providers keep ATA-to-owner tables.
- **Copy-trading pre-block shadowing** - bots replay parsed swap intent
  (mints + amount) via Geyser/ShredStream in <75ms; timing obfuscation alone
  loses. The parseable signal must be removed, not merely delayed.
- **Sybil / operator cover traffic** - operator-generated decoys inflate the
  *nominal* count but add zero real anonymity to anyone who clusters the
  operator. We report **real k**, never nominal (Tornado's documented failure).

Design responses, in one line each: shared-epoch batch settlement defeats FIFO;
fixed size buckets defeat amount matching; a normalized, rotating gasless
coordinator defeats fingerprinting and gas-payer reuse; a fixed uniform action
shape per pool removes the copy-trade signal; honest k-accounting keeps the
reported number truthful.

---

## v1 - in-scope for the bounty deadline (2026-07-29)

**Thesis:** a non-ZK, commit-reveal + k-anonymous slot-epoch design is enough to
collapse the strongest empirical attack (FIFO temporal matching) to a random
baseline, and we prove it with an adversarial harness rather than asserting it.
ZK-deniable initiation (v2) strengthens the *commit* side, but the batch-settlement
privacy win is independent of ZK and is what the bounty theme rewards.

### v1 deliverables

Every item below is targeted to compile, be tested, and be demonstrated on
Surfpool (localhost:8899, mirroring mainnet) and/or devnet.

1. **`crates/mirror-core`** - *DONE.* Shared primitives and wire format, with
   unit tests. This is the contract both the off-chain crates and the on-chain
   program bind to, so the two sides cannot silently drift. Public API in play
   for v1:
   - `Commitment`, `Nullifier`, `Secret`, `commit(secret, action, epoch)`,
     `nullifier(secret, epoch)` - SHA-256, domain-separated
     (`mirror-pool:v1:commitment` vs `mirror-pool:v1:nullifier`).
   - `ActionClass` (`Swap { mint_in, mint_out, size }`, `Stake { validator,
     size }`) with `canonical_bytes()` - the fixed action shape; one anonymity
     set per class.
   - `SizeBucket` (`Nano`/`Small`/`Medium`/`Large`) - the behavioral analog of
     fixed denominations.
   - `Epoch`, `EpochSchedule { epoch_slots, k_floor }` with `epoch_of_slot()` /
     `settle_slot()` - slot-derived shared batching so every participant computes
     the same current epoch without coordination.
   - `KAnon { nominal, excluded }` with `real_k()` / `meets_floor()` - honest
     anonymity accounting.
   - `MirrorError`, and `wire::{tag, COMMIT_LEN, SETTLE_HEADER_LEN}` - the byte
     layout for `INIT_POOL` / `COMMIT` / `SETTLE_EPOCH`.

2. **`programs/mirror-pool`** - standalone Pinocchio on-chain program (its own
   `[workspace]`, built with `cargo build-sbf`). Instructions:
   - `InitPool` - fix the `ActionClass`, `EpochSchedule` (`epoch_slots`,
     `k_floor`), and coordinator authority for the pool.
   - `Commit` - append the 32-byte commitment as a leaf to an append-only intent
     accumulator (an append-only Poseidon frontier Merkle accumulator built
     fresh in this crate: a standard Tornado-Cash-style commitment tree with
     O(depth) frontier storage and a ring buffer of recent roots; Zcash Sapling
     uses the same accumulator shape). Layout `[tag(1)][commitment(32)]` per
     `wire::COMMIT_LEN`.
   - `SettleEpoch` - verify the epoch's window has closed
     (`current_slot >= settle_slot(epoch)`), enforce the real-k floor, and write
     one nullifier PDA per participant at seeds `['nullifier', pool, epoch, nf]`
     for anti-replay. Header `[tag(1)][epoch(8)][n_nullifiers(4)]` +
     `n * 32` per `wire::SETTLE_HEADER_LEN`. The whole epoch settles atomically
     in one instruction so a no-show forfeits its slot without stalling the round
     (N-party atomicity beyond Jito's 5-tx bundle cap must live program-side).
   - **Fail-closed parsing** throughout; build fresh the Ed25519 instruction-
     introspection + validation-order hardening (on-chain Ed25519 signature
     verification read from the instructions sysvar, standard Solana instruction
     introspection), handling the self-reference sentinel `ix_index == 0xFFFF`
     explicitly to avoid an introspection-index confusion.

3. **`crates/mirror-coordinator`** - off-chain gasless coordinator built fresh:
   a slot-window batch scheduler (close an epoch when its slot window passes,
   gate on k_floor, then settle). Responsibilities:
   - Watch `Commit`s and bucket them into slot-window epochs.
   - **Enforce `k_floor` (real k) BEFORE settle.** Below floor, roll the epoch
     forward; never execute into a set small enough to deanonymize by elimination.
   - Submit `SettleEpoch` as the **sole fee-payer/signer** so no acting wallet
     funds or signs its own execution (the gasless-relayer requirement).
   - **Rotate the fee-payer** across a pool so the coordinator does not become a
     consolidation node; **normalize** CU limit, priority fee, tx version,
     account ordering, and ALT to one pool-wide standard to kill the ~37%
     fingerprint attack. (Build tx construction over Address Lookup Tables and
     v0 transactions fresh, standard Solana, to keep the settlement tx under
     1232 bytes.)

4. **`crates/mirror-behaviors`** - a `Behavior` trait plus **2 pooled-action
   adapters**, so all epoch participants perform an *identical* action:
   - **Jupiter swap** adapter (built fresh on the public Jupiter v6 quote + swap
     API: quote fetch, route selection, swap-instruction construction); same
     mint pair + size bucket for every participant.
   - **jitoSOL stake** adapter (built fresh on the public Jito stake-pool
     program: an SPL stake-pool deposit).
   - Output must land such that the ATA re-link vector is understood and
     documented; uniform shape is the point.

5. **`crates/mirror-cli`** - clap-based participant CLI: `commit` and `status`
   (the `prove` subcommand arrives in v2). Lets a reviewer drive the flow by hand.

6. **`crates/mirror-harness`** - **the differentiator.** An adversarial
   evaluation harness that measures attacker advantage over the `1/k` random
   baseline for two configurations:
   - **Baseline** (what naive privacy tooling does): per-actor random delay,
     self-paid gas, variable amounts.
   - **MirrorPool**: shared-epoch batch settlement, gasless rotating relay,
     fixed size bucket.

   Heuristic attackers implemented: FIFO temporal match, amount match, gas-payer
   reuse, wallet fingerprint, temporal correlation, common-funding, plus a
   learned classifier. Implement the Wang et al. heuristics and the
   effective-vs-claimed anonymity-gap methodology (arXiv:2201.09035) fresh in
   Rust, with a Surfpool-RPC settlement-trace loader.

   **Required headline result:** the FIFO temporal-match advantage, which is high
   under per-actor random delay, collapses to ~0 (i.e. to `1/k`) under shared-
   epoch batch settlement. Amount-match advantage similarly collapses under fixed
   size buckets. The harness reports **real k**, never nominal.

7. **Surfpool / devnet proof** - a reproducible end-to-end run: init a pool,
   have N participants commit across an epoch, settle atomically via the rotating
   gasless coordinator, and feed the resulting on-chain trace through the harness
   to produce the before/after attacker-advantage numbers. Surfpool has no
   historical tx data, so round-trip validation uses a fresh-seeded pool.

### v1 explicit non-goals

Stated so a reviewer does not read an absence as a bug:

- **No ZK in v1.** Commit-reveal uses SHA-256 pre-images; the coordinator learns
  each participant's `(secret, action)` at settlement. This is honest and
  documented. ZK-deniable initiation is v2.
- **Amounts, mints, and the fact of the action stay public.** We obscure the
  *initiator*, not the funds. Size is coarsened into buckets, not hidden.
- **k-anonymity, not cryptographic unlinkability.** v1 privacy is `1/real_k`
  within an epoch's settlement; it does not claim information-theoretic hiding.
- **No compliance/association-set lever in v1.**
- **Sybil resistance is measured and reported, not yet economically enforced.**
  v1 reports real k honestly; a fixed-entry-fee / fidelity-bond Sybil cost is a
  v2 hardening item.

---

## v2 - ZK-deniable initiation (stretch, post-deadline)

v2 removes the coordinator's ability to learn who initiated what, upgrading the
*commit* side from "the relayer trusts but cannot re-target" to "the relayer
cannot even learn the mapping." The v1 public API was designed so this is
**additive** (`Secret` becomes a ZK witness; a `prove` CLI subcommand appears).

- **Poseidon commitments + Groth16 membership proof, verified on-chain.**
  Swap SHA-256 for Poseidon in the accumulator; a participant proves knowledge of
  `(nullifier, secret)` for *some* leaf without revealing which, and publishes
  `nullifierHash` to prevent double-spend. Verify on-chain via the `alt_bn128`
  (BN254) syscalls (~170 to 500K CU, 128-byte compressed proof); see the public
  Lightprotocol/groth16-solana crate. Build the circom membership +
  value-conservation circuits fresh.
- **`extDataHash` action binding** - bind the executed action data into the proof
  so the coordinator cannot substitute an action even under ZK, matching the v1
  commit-binds-action guarantee cryptographically.
- **Larger anonymity sets via ALT** - use address lookup tables + v0 tx to fit
  the pool PDA, Merkle tree, per-participant nullifier PDAs, and participant
  accounts under the 1232-byte limit, raising the max participants per settled
  epoch. (Keep Jito tip accounts OUT of ALTs.)
- **Association-set compliance lever** - an optional ZK-native proof that a
  participant dissociates from a flagged subset (Privacy Pools style). Kept out
  of public-facing naming; an opt-in lever, never a gate on the base pool.
- **Sybil cost** - introduce a real per-identity entry cost (fixed fee /
  fidelity bond) so an attacker cannot cheaply fill a round and force real k=1.

---

## v3+ - ideas (not committed)

Directional, unscoped, and explicitly not part of any bounty claim:

- **Cross-epoch privacy** - an initiator's action indistinguishable not just
  within one epoch but across a rolling window of epochs, defeating an attacker
  who correlates a participant across consecutive rounds.
- **Decentralized coordinator set** - replace the single rotating coordinator
  with a permissionless set (threshold/committee) so no one operator sees all
  commits, removing the last trusted party from the batching layer.
- **More behaviors** - additional pooled `ActionClass` variants (LP add/remove,
  governance votes, NFT mints) each with their own uniform shape and size
  buckets; one anonymity set per class.
- **Incentives / dwell rewards** - a reason for participants to stay so the set
  does not decay, with the explicit caution that anonymity mining attracts
  privacy-indifferent users and pool size is not anonymity (report real k).

---

## Scope summary

| Capability | v1 (deadline) | v2 (stretch) | v3+ (idea) |
| --- | --- | --- | --- |
| Commit-reveal (SHA-256) | Yes | replaced by ZK | - |
| k-anon slot epochs + shared-timestamp settle | Yes | Yes | cross-epoch |
| Gasless rotating coordinator (normalized) | Yes | Yes | decentralized set |
| Fixed size buckets | Yes | Yes | Yes |
| 2 behavior modules (Jupiter swap, jitoSOL stake) | Yes | Yes | more |
| Adversarial harness (real-k, FIFO collapse) | Yes | extended | - |
| Surfpool / devnet E2E proof | Yes | Yes | Yes |
| Poseidon + Groth16 ZK membership on-chain | No | Yes | Yes |
| extDataHash action binding | No | Yes | Yes |
| Larger sets via ALT | partial (tx normalization) | Yes | Yes |
| Association-set compliance lever | No | Yes | Yes |
| Economic Sybil cost | reported only | Yes | Yes |

**One-line honest claim for the submission:** v1 collapses the strongest
empirical mixer attack (FIFO temporal matching) to the `1/real_k` random baseline
via shared-epoch batch settlement, proven by an adversarial harness on a real
Surfpool trace, with a gasless rotating coordinator and fixed size buckets that
also defeat the fingerprint and amount-match attacks; ZK-deniable initiation is
the next milestone, not a current claim.
