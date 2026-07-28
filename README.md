# mirror-pool

**Tornado Cash for behavior, not funds.** An anonymity set over *behavior*, not
over denominations: two paths with two different, clearly-labelled strengths.

> **Design paper:** a skimmable overview of the two-axis composition (who + how
> much), the effective-k metric, on-chain Groth16 verification, and the public
> devnet results is at [`paper/mirror-pool.pdf`](paper/mirror-pool.pdf) (source
> [`paper/mirror-pool.tex`](paper/mirror-pool.tex)).

## Verify this in 2 minutes

Everything below is live on **public Solana devnet** and resolves in a browser
(no build required):

- **Program (deployed + executable):** [`EezWdFrmHtR2PCuucUruvkgyB9HW3w2KskZNeYmXszBq`](https://explorer.solana.com/address/EezWdFrmHtR2PCuucUruvkgyB9HW3w2KskZNeYmXszBq?cluster=devnet)

> **The deployed program predates the verifying-key registry AND the escrow
> fix.** Two changes have landed in source since that deploy. Every verifying
> instruction now reads its key from a write-once, digest-pinned account instead
> of from a compile-time constant ([`docs/VK_REGISTRY.md`](docs/VK_REGISTRY.md));
> and the ZK escrow-soundness hole is closed by crowd/ZK leaf-domain separation
> plus a fixed ZK denomination ([`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)
> section 4). The devnet bytecode above contains NEITHER, so it no longer matches
> this source tree, and the links in this section are records of the earlier
> program. Read plainly: **the escrow fix is source-only.** The deployed devnet
> program is still vulnerable to the crowd-leaf attack, has no `zk_denomination`
> field, and would reject this tree's 31-byte `InitPool` body; it has not been
> redeployed because a fresh deploy needs roughly 0.83 SOL and the devnet faucet
> is refusing. Nothing on that deployment holds value. The evidence for both
> changes is the mollusk suite against the compiled SBF program, which is built
> from exactly this source.
- **Behavioral crowd settle** (N identical actions, one atomic tx, one timestamp): [tx](https://explorer.solana.com/tx/4tcgNnhbZe7YKM26F6SnXW1WctASqVEqQ9W4v4NQ85fDfkYe3eq7YqCr4n7bEogm7U5By17Lkc5Tqa7jmZx693NB?cluster=devnet)
- **Confidential JoinSplit** (shield / private transfer with `publicAmount == 0` / unshield): see the signatures table in [`docs/PROOF.md`](docs/PROOF.md)
- **Two live soaks, all assertions on-chain:** behavioral **17/17** + confidential **25/25** ([`docs/PROOF.md`](docs/PROOF.md))

To build and run it yourself: `cargo test --workspace` (host) and
`cargo build-sbf --manifest-path programs/mirror-pool/Cargo.toml` (program); the
full reproduce recipe is in [`docs/PROOF.md`](docs/PROOF.md).

A mixer hides *how much* moved and *from whom*. mirror-pool attacks what a mixer
leaves untouched: the *behavioral* signal an action gives off. It ships two
behavioral paths. They are not the same guarantee, and the difference is the
first thing you should read, not a footnote:

- **Crowd path (`Commit` / `SettleEpoch`) - hides the per-actor SIGNAL, not the
  signer.** N participants pool one identical action into a synchronized round
  that settles in a single atomic transaction on one block timestamp, paid by a
  rotating relay. Each participant still signs their own action, so the
  settlement carries N+1 signatures and the action **stays attributable to that
  wallet on-chain**. What is destroyed is everything an attacker uses to single
  one participant out: timing, ordering, size, gas payer, wallet fingerprint,
  and parseable intent. That defeats copy-trading and FIFO temporal matching and
  gives the round collective intent-deniability. It is not who-initiated
  unlinkability, and this README will not call it that.
- **ZK opt-in path (`CommitDeposit` / `SettleZk`) - hides WHO initiated,
  cryptographically.** A participant escrows the action input; at settlement the
  relay verifies a Groth16 membership proof on-chain that an output belongs to
  *some* committed member without revealing which, and the action executes to a
  *fresh* output with **no participant signature at settle**. This is the path
  that makes the initiator unattributable, and even the relay cannot learn which
  committer acted.

On both paths the anonymity set is the set of real participants in the round,
exactly as a mixer's anonymity set is the set of deposits of one denomination.

This is behavioral obscurity for the Superteam Brasil "Privacy-Through-Noise"
theme: the core goal is to make on-chain *behavior* hard for automated
chain-analysis to read.

An optional **confidential-value layer** goes further and also hides *how much*:
value lives in encrypted notes and moves through a Tornado-Nova-style
zero-knowledge JoinSplit, so a private transfer reveals neither the initiator nor
the amount. That extends past the behavioral theme into value-shielding and is a
separate opt-in pool mode (see the status table and [`docs/PROOF.md`](docs/PROOF.md)).

---

## How it works

A participant computes a commitment `C = H(secret, action, epoch)` off-chain and
posts only `C` on-chain during the round's **commit** phase; the action and
secret stay client-side. All commits that land in the same slot window belong to
one **shared epoch**. Once the window closes, an off-chain gasless coordinator
checks that the round meets its real k-anonymity floor, then submits a single
`SettleEpoch` instruction that executes every committed action **atomically on
one shared timestamp**, revealing an epoch-scoped nullifier per participant to
prevent acting twice. Because every action in the epoch has the same observable
shape (same `ActionClass`, same size bucket) and settles at the same instant
paid by a rotating relay fee-payer, an observer sees N identical actions occur
with nothing to tell them apart: no ordering, no timing spread, no amount
variance, no fee-payer or fingerprint difference. On the crowd path the observer
*can* still see which wallet signed which action, because each participant signs
their own; what they cannot do is pick the one worth copying, front-running, or
attributing a strategy to. Shared-epoch batching is the specific defense against
FIFO temporal matching, the single strongest empirical attack on mixers. The ZK
opt-in path is the one that removes the signature too: `SettleZk` carries a
Groth16 membership proof and releases to a fresh output with no participant
signature at settle, so no wallet is linked to the instance at all.

---

## Status

The complete two-path system is built and proven end to end on Surfpool: k-anon
slot epochs + a gasless rotating coordinator + a synchronized-crowd path + a
ZK-deniable opt-in path (a Groth16 membership proof verified on-chain, so even
the relay cannot learn which committer acted) + real pooled behaviors + an
adversarial evaluation harness + anti-Sybil economics with incentives. Every
component is implemented and tested, and a live Surfpool soak exercises both
paths plus the adversarial cases with 17/17 on-chain assertions passing (see
[`docs/PROOF.md`](docs/PROOF.md)). A separate confidential-value layer (JoinSplit
shield / private-transfer / unshield, hiding amounts) is also built and
soak-proven live with 25/25 on-chain assertions.

The FUNDING leg is the one part of the design that is **not** wired end to end,
and the status table says so. The idea is that a commit wallet is credited by an
unshield from the value pool in a denominated, batched funding round instead of
by a transfer from a main wallet, which is the one mechanism aimed at the
strongest real-world deanonymizer (common funding source). What exists today is
library-grade: `mirror-cli fund-commit` proves an unshield to a fresh wallet and
**prints the request**, and `mirror_coordinator::funding::FundingRounds` is a
unit-tested batcher type that can hold those requests to a round boundary. No
shipped service ingests one into the other - the coordinator binary is an
in-memory scheduler demo - so there is no running funding round and no live soak
of this leg. The residual it would leave is measured rather than assumed, but the
measurement is of the design, not of a deployment. The status table below is kept
honest against the tree.

| Component | Path | Status |
| --- | --- | --- |
| Shared types + wire format | `crates/mirror-core` | **Implemented** - `Commitment`/`Nullifier`/`Secret`, `commit()`/`nullifier()` (circomlib Poseidon, cross-check-proven against the circuit), `ActionClass` + `SizeBucket`, `Epoch`/`EpochSchedule`, `KAnon` honest accounting, `wire` byte layout. Unit tests passing. |
| On-chain program | `programs/mirror-pool` | **Implemented** - fail-closed `InitPool`/`Commit`/`CommitDeposit`/`SettleEpoch`/`SettleZk`/`ClaimReward`, depth-20 Poseidon frontier accumulator + 32-root history ring, Epoch/Nullifier/Dwell PDAs, on-chain crowd-path k-floor + double-settle prevention, and on-chain Groth16 (alt_bn128) membership verification, and a write-once, digest-pinned verifying-key registry (`InitVk`, no update path) that every verify re-validates, plus the OPT-IN disclosure layer (`RegisterViewingKey` / `PublishDisclosure`), whose record address the program DERIVES from the settling recipient's own signature so no one can publish about, or squat, somebody else's settlement. 121 program tests (mollusk integration + in-crate unit); `build-sbf` green. The public-devnet deployment predates both the registry and the escrow fix and is labelled historical in `docs/PROOF.md`. |
| ZK-deniable initiation | `circuits/` + `programs/mirror-pool` | **Implemented** - Poseidon membership circuit + Groth16 setup; `SettleZk` verifies the proof on-chain (public inputs `[root, nullifierHash, actionHash, epoch]`) and releases the escrow to the address the member bound (clients bind a fresh one). A real proof verifies on-chain (fixture test) and live in the soak. `SettleZk` enforces the pool's fixed `zk_denomination` (which, with program-applied crowd/ZK leaf-domain separation, is what bounds the escrow), but no k-floor and no recipient freshness, and the reasons are in [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) section 4. |
| Adversarial harness | `crates/mirror-harness` | **Implemented** - heuristic + learned attacks measuring attacker advantage over `1/k`, Baseline vs mirror-pool. FIFO advantage collapses from high under per-actor delay to near zero under shared-epoch batching. Also prints an information-theoretic effective-k table (Serjantov-Danezis `2^H(p)` + min-entropy) whose mirror-pool provenance classes are DERIVED from the shipped funding mechanism, with funding-policy, adversary-strength, dwell and adoption ablations; see [`docs/EFFECTIVE_K.md`](docs/EFFECTIVE_K.md). |
| Funding-provenance path | `crates/mirror-cli` + `crates/mirror-coordinator` | **Implemented + soaked** - `fund-commit` funds a FRESH commit wallet by unshielding from the value pool (vault is the sender, relay the only signer, denomination enforced); `funding_service::FundingService` + `DirectoryIntake` ingest those emits, and `funding::FundingRounds` batches them to a round boundary with a minimum-round floor and an arrival-independent release order. Soak-proven end to end on local Surfpool, 25/25 on-chain assertions, including that each fresh commit wallet's ONLY inbound transfer is from the pool vault and that each funding transaction carries exactly one signature, the relay's ([`docs/PROOF.md`](docs/PROOF.md)). The residual it leaves (public boundary amounts and slots) is measured, not assumed. |
| Gasless coordinator | `crates/mirror-coordinator` | **Implemented** - slot-window batching, `k_floor` gate, rotating fee-payer, and real atomic crowd settlement (ComputeBudget + `SettleEpoch` + N participant behaviors, shared accounts in an ALT). |
| Participant CLI | `crates/mirror-cli` | **Implemented** - `init-pool` / `commit` / `deposit-commit` / `prove` (rebuilds the path + generates and verifies a Groth16 proof in-process in pure Rust via ark-circom/ark-groth16, no Node; `--use-snarkjs` is an optional legacy fallback) / `fund-commit` / `status`. |
| Pooled behaviors | `crates/mirror-behaviors` | **Implemented** - `Behavior` trait + pooled-action adapters: PlainTransfer (soak baseline), Jupiter swap, jitoSOL stake. |
| Anti-Sybil + incentives | `programs/mirror-pool` + `crates/mirror-coordinator` | **Implemented** - entry-fee split into a reward pool, crowd-path dwell `ClaimReward`, honest `real_k` reporting; the ZK-path incentive is designed in [`docs/INCENTIVES.md`](docs/INCENTIVES.md). |
| Soak suite (Surfpool + devnet) | `crates/mirror-soak` | **Implemented** - live end-to-end soak, both behavioral paths + adversarial cases, 17/17 on-chain assertions, on local Surfpool AND public devnet ([`docs/PROOF.md`](docs/PROOF.md)). |
| Confidential-value circuit | `circuits/` | **Implemented** - 2-in/2-out Tornado-Nova JoinSplit (`transaction.circom`): membership + nullifiers + value conservation + range proofs + extDataHash binding; setup + vk + shield/transfer/unshield fixtures. |
| Confidential value pool (on-chain) | `programs/mirror-pool` | **Implemented** - `InitValuePool` + `Transact`: own Poseidon value-note accumulator + root history + vault, on-chain Groth16 JoinSplit verify, nullifier PDAs, deposit/withdraw per `publicAmount`, fixed-denomination mode. Amounts never in cleartext except public deposit/withdraw. |
| Confidential notes + client ops | `crates/mirror-core` + `mirror-cli` + `mirror-coordinator` | **Implemented** - ECIES encrypted notes + `scan` discovery; `value-keygen`/`shield`/`transfer`/`unshield` (pure-Rust ark-groth16 prove + emit, no Node); gasless `submit_transact` (transfer/unshield relay-only signed = the unlinkability). |
| Confidential soak | `crates/mirror-soak` | **Implemented** - live shield -> hidden-amount transfer -> unshield + fixed-denom + adversarial, 25/25 on-chain assertions ([`docs/PROOF.md`](docs/PROOF.md)). |
| Funding-round soak | `crates/mirror-soak` | **Implemented** - live `fund-commit` -> coordinator ingestion -> thin-round roll-forward -> batched gasless release -> commit from the funded wallet, plus the adversarial cases, 25/25 on-chain assertions on local Surfpool ([`docs/PROOF.md`](docs/PROOF.md)). |
| Trusted-setup ceremony | `crates/mirror-ceremony` + `mirror-cli ceremony` | **Implemented** - distributable multi-party Groth16 phase-2 ceremony for both circuits: public phase-1 import + provenance reader, delta re-randomization, Schnorr proof of knowledge bound to the contributor id, the position in the chain and the step's kind and provenance, SHA-256 transcript chain, an enforced beacon-is-final rule, reproducible verification (rejects tampered deltas, forged/replayed proofs, reordered and truncated chains, post-beacon steps and relabelled beacons - each tested), and an independent-contributor count that refuses to count self-runs. `ceremony prove-check` proves the membership circuit under a ceremony key and the on-chain `groth16-solana` verifier accepts it; `ceremony verify-transcript` checks a published transcript with no key files. The demonstration run's transcripts are committed under `docs/ceremony-run/`. **No production ceremony has been run: the deployed keys are still dev-setup keys.** See [`docs/CEREMONY.md`](docs/CEREMONY.md). |

"Implemented" means the component's core logic is complete and tested. It does
not mean "deployed": the ceremony row above is the one place where that
distinction bites, and it is labelled. The 300 host workspace tests
(12 more are environment-gated and skipped by default), 121 on-chain program tests,
`build-sbf`, and the two live Surfpool soaks (behavioral 17/17 + confidential
25/25 on-chain assertions) are all green. See the roadmap for future work
(swap/stake-from-pool via CPI, confidential deposits, wiring and soaking the
funding leg, and the ZK-path anonymity-mining incentive). The multi-party phase-2
trusted-setup ceremony is built and tested; what remains there is *running* one
with external contributors and redeploying with its key, because the currently
committed and deployed verifying keys are still dev-setup keys. Where those keys
live changed too: each one is now published into a write-once, program-owned
account whose contents the program pins to a compile-time SHA-256, so the key in
force is publicly readable and still cannot be swapped
([`docs/VK_REGISTRY.md`](docs/VK_REGISTRY.md)).

---

## Quickstart

Requires a stable Rust toolchain. The on-chain program additionally requires
`solana-cargo-build-sbf`.

```sh
# Off-chain host workspace: core, coordinator, cli, harness, behaviors.
# From the repo root:
cargo test --workspace        # run the host-crate unit tests
cargo build --workspace       # build every host crate

# On-chain program (standalone crate, targets SBF, its own workspace):
cargo build-sbf --manifest-path programs/mirror-pool/Cargo.toml

# Adversarial evaluation harness (prints the attacker-advantage table):
cargo run -p mirror-harness --release
```

A `Makefile` wraps the common tasks:

```sh
make check       # fmt-check + clippy -D warnings + test
make build-sbf   # build the on-chain program
make harness     # run the adversarial harness
make soak        # end-to-end run against a local Surfpool node (mainnet mirror)
```

Local development runs against Surfpool (`http://127.0.0.1:8899`), which mirrors
mainnet and is treated as mainnet: no localnet-only shortcuts or early-exits.

---

## Workspace layout

The off-chain crates form one Cargo workspace at the repo root. The on-chain
program is intentionally *excluded* from that workspace: it targets SBF and is
its own crate so a plain `cargo test` at the root never tries to compile a
Solana entrypoint for the host.

```
mirror-pool/
  crates/
    mirror-core          # shared types + wire format + tests    [implemented]
    mirror-coordinator   # off-chain gasless batch coordinator    [implemented]
    mirror-cli           # participant CLI (commit/prove/fund/status)[implemented]
    mirror-harness       # adversarial evaluation harness         [implemented]
    mirror-behaviors     # Behavior trait + pooled-action adapters[implemented]
    mirror-soak          # live Surfpool end-to-end soak suite    [implemented]
    mirror-ceremony      # multi-party Groth16 phase-2 ceremony   [implemented]
    mirror-circuits      # arkworks-native membership + JoinSplit [implemented]
  circuits/              # Poseidon membership circuit + Groth16 setup [implemented]
  programs/
    mirror-pool          # on-chain Pinocchio program (SBF)       [implemented]
  docs/
    THREAT_MODEL.md      # attacker model + which attacks each path defeats
    ARCHITECTURE.md      # the two settlement paths + on-chain design in depth
    ROADMAP.md           # what is built and what is future work
    EFFECTIVE_K.md       # advertised k vs effective k + the funding-provenance measurement
    INCENTIVES.md        # entry-fee split, dwell reward, ZK-path incentive design
    PROOF.md             # live Surfpool soak results + tx signatures
    CEREMONY.md          # multi-party trusted-setup ceremony: contribute + verify
    ARKWORKS.md          # the arkworks-native circuit path + measured comparison
  Cargo.toml             # host workspace manifest
  Makefile               # fmt / clippy / test / build-sbf / harness / soak
  LICENSE                # MIT
```

---

## The privacy claim, stated honestly

Overstating an anonymity set is the documented failure mode of prior mixers, so
this project reports the *real* set and is explicit about its limits. `KAnon` in
`mirror-core` separates the nominal commit count from the real set (nominal
minus operator-owned and Sybil decoys), and a crowd epoch settles only when the
real set meets `k_floor`. Anonymity is `1/real_k`, never `1/nominal`. On the ZK
path that floor is checked by the client at proof time rather than by the program
at settle: the escrow there has no refund, so an on-chain floor would strand it,
and only the secret holder can produce the proof in the first place. The
reasoning, and the set the ZK path actually gives, are in
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) section 4.

**What mirror-pool defends against**

- **Per-actor signal extraction (crowd path).** Within one settled epoch every
  action carries the same timestamp, the same size bucket, the same fee shape
  and the same relay envelope, so nothing distinguishes one participant's
  instance from another's. The wallet that signed each action is still visible;
  what an attacker cannot recover is which one is worth copying, front-running,
  or attributing a strategy to. That is collective intent-deniability.
- **Initiator attribution (ZK opt-in path only).** On `CommitDeposit` /
  `SettleZk` the settled output is released to a fresh address with no
  participant signature, behind an on-chain Groth16 membership proof, so the
  initiator of a given instance is indistinguishable from the other real
  committers, including to the relay. The crowd path does **not** provide this.
- **FIFO temporal matching.** All actions in an epoch settle on one shared
  timestamp, so there is no earliest-later ordering to exploit. Per-actor random
  delay does not achieve this and leaves a heavy-tailed timing signature; shared
  epochs do.
- **Amount / size matching.** One fixed `ActionClass` and `SizeBucket` per pool
  makes every emitted action identical in shape. Public studies of privacy
  pools (Wang et al. 2022; the Tornado deanonymization study) show variable and
  round-number amounts leak a large fraction of anonymity to amount-matching
  alone; fixed buckets close that gap.
- **Fee-payer clustering and wallet fingerprinting.** A rotating relay set pays
  and signs settlement so no acting wallet funds its own execution, and CU
  limit, priority fee, tx version, account ordering, and ALT are normalized to
  one pool-wide standard so per-round transactions are not separable by their
  wallet-software settings.
- **Common funding source, the dominant real-world anchor - a designed answer
  with a measured residual, not yet a running one.** `fund-commit` funds a fresh
  commit wallet by unshielding from the value pool, and `FundingRounds` would
  release those withdrawals in denominated batches, so no public edge links a
  main wallet to the wallet that commits. This is the one defense with a
  published residual instead of a clean close: the boundary amounts and slots
  stay public, which leaves an observer a deposit-to-withdrawal matching problem.
  In the harness model, the part the protocol can actually **enforce**
  (denomination + batching, no voluntary dwell, full adoption) retains 75.8% of
  nominal k at k=32; cooperative participants who also dwell two rounds push it
  to 90.0%. Partial adoption is much worse (42.4% at 50%), and a free-amount pool
  worse still. Read those as design numbers: this leg is not wired into a running
  service (see the status table). Ablations and limits in
  [`docs/EFFECTIVE_K.md`](docs/EFFECTIVE_K.md).

**What mirror-pool does NOT do (explicit non-goals)**

- **The behavioral pool does not hide amounts or balances.** In the crowd and
  ZK-deniable paths, the action, its size class, and its on-chain effects are
  public by design; that layer is behavioral obscurity, not a mixer. (The
  optional confidential-value layer *does* hide amounts, via the JoinSplit
  `Transact`; see the status table and `docs/ARCHITECTURE.md`. The public
  deposit/withdraw magnitude and the pool TVL remain visible even there.)
- **The crowd path does not hide the on-chain signer.** Each participant signs
  their own action, so the settlement transaction names every participant and
  the action stays attributable to the wallet that performed it. The crowd path
  destroys the per-actor *signal*; it does not give who-initiated unlinkability.
  Only the ZK opt-in path does, and only for the instances settled through it.
  The crowd-path coordinator also learns the participant-to-intent mapping while
  composing settlement, though it learns nothing the signed on-chain action did
  not already reveal.
- **The behavioral pool does not provide value-transfer privacy or unlinkable
  payments.** It anonymizes *behavior within a round*, not *who paid whom*.
- **The ZK path's anonymity set is per-window and per-amount, and the program
  does not enforce a floor on it.** `SettleZk` publishes the settled epoch and
  amount, so the set covering an output is that window's ZK deposits *of the same
  amount*, not the pool's total deposits; and the program will settle into a set
  of one. The floor is a client check (`mirror-cli prove` refuses below `k_floor`
  unless waived), because the ZK escrow has no refund path and an on-chain floor
  would strand it. **The related escrow-soundness hole is now CLOSED**: crowd
  `Commit` leaves are domain-separated from ZK deposit leaves by the PROGRAM, and
  the ZK pool carries a fixed denomination, so a fee-only crowd commit can no
  longer spend a depositor's escrow. Pinned by
  `settle_zk_rejects_a_fee_only_crowd_leaf_spending_a_depositors_escrow` and
  `crowd_commit_leaf_is_domain_separated_from_the_zk_deposit_leaf`. See
  [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) section 4.
- **It does not manufacture anonymity from operator-owned cover traffic.**
  Decoys the operator controls inflate the nominal count and add zero real
  anonymity to anyone who clusters the operator; they are excluded from
  `real_k`. A pool with real `k=1` provides no anonymity regardless of nominal
  size.
- **The DEPLOYED trusted setups are dev/test, not the output of a real
  ceremony.** Both committed verifying keys (membership and the confidential
  JoinSplit) came from a single-contributor dev setup whose phase-2 entropy is a
  hard-coded public string, so their toxic waste is public. The keys and fixtures
  verify and the on-chain program embeds them, but they must not secure real
  value. A real multi-party phase-2 ceremony **is implemented and runnable**
  ([`docs/CEREMONY.md`](docs/CEREMONY.md)); running one with external contributors
  and redeploying with its key is what closes this, and that has not been done.
  A `k`-contributor ceremony is 1-of-N honest: safe if *at least one* contributor
  destroyed their scalar, not if `k` did.
- **It is not a Sybil oracle.** Real k-anonymity assumes participants are
  economically distinct. The per-identity entry-fee cost raises the price of
  flooding a round, but Sybil resistance is not a solved property.
- **Not audited, not production-deployed.** This is a bounty-stage research
  implementation. Do not rely on it to protect real activity.

---

## Documentation

- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) - the attacker model and which
  chain-analysis heuristics each design choice defeats.
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) - commit / shared-epoch batch /
  gasless atomic settlement in depth, and the on-chain account model.
- [`docs/ROADMAP.md`](docs/ROADMAP.md) - what is built and what is future work.
- [`docs/INCENTIVES.md`](docs/INCENTIVES.md) - the entry-fee split, the crowd-path
  dwell reward, honest real-k, and the anonymity-preserving ZK-path incentive design.
- [`docs/EFFECTIVE_K.md`](docs/EFFECTIVE_K.md) - the information-theoretic effective
  anonymity-set size (Serjantov-Danezis `2^H(p)` + min-entropy): advertised k is
  not effective k. A naive pool advertising k=32 has effective k ~7.5 (worst-case
  1) under funding-provenance partitioning. mirror-pool's shielded funding design
  measures **24.25 (75.8% of nominal) from the enforced rules alone** (denominated
  pool + batched rounds, dwell 0, full adoption) and 28.80 (90.0%) once
  participants also dwell two rounds - dwell being a recommendation the protocol
  cannot enforce. Both residuals are published rather than rounded away, and the
  same pool used naively measures 7.66.
- [`docs/COMPLIANCE.md`](docs/COMPLIANCE.md) - the two OPT-IN compliance
  primitives. **Association sets** (Privacy Pools): prove your deposit is in a
  curator's curated set without revealing which deposit it is, enforced on-chain
  in the execute path, with the curator trust assumption, the censorship tradeoff
  (and why there is deliberately no mandatory mode), and what an excluded user can
  still do. **On-chain viewing keys and sealed disclosures**: publish an X25519
  key under your own address, and disclose ONE of your own settled actions to ONE
  reader you chose, in a record whose address the program DERIVES from the
  settlement's own recipient signature (so nobody can publish about somebody
  else's settlement, and nobody can squat a slot). Includes the table of what is
  enforced on-chain versus what the reader must check themselves, what the reader
  learns and cannot learn, and the privacy cost of registering at all - a record
  publicly announces that a settlement has a disclosure and names the reader, and
  is permanent.
- [`docs/CEREMONY.md`](docs/CEREMONY.md) - the multi-party Groth16 phase-2
  trusted-setup ceremony: how to contribute, how to verify somebody else's, why a
  beacon is final and how that is enforced, how the independent-contributor count
  refuses to count self-runs and what it still cannot rule out without the
  pre-committed beacon value, and exactly what 1-of-N honest does and does not give
  you.
- [`docs/ARKWORKS.md`](docs/ARKWORKS.md) - the arkworks-native constraint-synthesis
  path for the membership circuit AND the confidential-value JoinSplit: an
  in-circuit Poseidon gadget, circomlib's `Num2Bits` / `Switcher` /
  `ForceEqualIfEnabled` at circom's cost, a Groth16 setup and a proof with no
  `circom` / `snarkjs` / `node` / `npm` anywhere, verified with the same
  `groth16-solana` verifier the program links. Includes the measured constraint
  comparison against the committed circom `.r1cs` files (5,363 vs 5,427 and
  12,958 vs 13,098 multiplication rows, with both deltas itemized), the replay of
  all three committed circom JoinSplit fixtures through the arkworks system with
  identical public signals, the gadget-versus-`sol_poseidon` cross-check, and a
  plain statement of what is still circom-only.
- [`docs/PROOF.md`](docs/PROOF.md) - the live Surfpool soak: both paths + the
  adversarial cases, with transaction signatures and on-chain assertions.
- [`paper/mirror-pool.pdf`](paper/mirror-pool.pdf) - the design paper: the
  who + how-much composition, the effective-k analysis, on-chain verification, and
  the public devnet results in one skimmable artifact (source
  [`paper/mirror-pool.tex`](paper/mirror-pool.tex)).

---

## License

MIT. See [`LICENSE`](LICENSE).
