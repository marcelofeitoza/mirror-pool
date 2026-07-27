# mirror-pool

**Tornado Cash for behavior, not funds.** An anonymity set over the *initiators*
of an action, not over denominations.

> **Design paper:** a skimmable overview of the two-axis composition (who + how
> much), the effective-k metric, on-chain Groth16 verification, and the public
> devnet results is at [`paper/mirror-pool.pdf`](paper/mirror-pool.pdf) (source
> [`paper/mirror-pool.tex`](paper/mirror-pool.tex)).

## Verify this in 2 minutes

Everything below is live on **public Solana devnet** and resolves in a browser
(no build required):

- **Program (deployed + executable):** [`EezWdFrmHtR2PCuucUruvkgyB9HW3w2KskZNeYmXszBq`](https://explorer.solana.com/address/EezWdFrmHtR2PCuucUruvkgyB9HW3w2KskZNeYmXszBq?cluster=devnet)
- **Behavioral crowd settle** (N identical actions, one atomic tx, one timestamp): [tx](https://explorer.solana.com/tx/4tcgNnhbZe7YKM26F6SnXW1WctASqVEqQ9W4v4NQ85fDfkYe3eq7YqCr4n7bEogm7U5By17Lkc5Tqa7jmZx693NB?cluster=devnet)
- **Confidential JoinSplit** (shield / private transfer with `publicAmount == 0` / unshield): see the signatures table in [`docs/PROOF.md`](docs/PROOF.md)
- **Two live soaks, all assertions on-chain:** behavioral **17/17** + confidential **25/25** ([`docs/PROOF.md`](docs/PROOF.md))

To build and run it yourself: `cargo test --workspace` (host) and
`cargo build-sbf --manifest-path programs/mirror-pool/Cargo.toml` (program); the
full reproduce recipe is in [`docs/PROOF.md`](docs/PROOF.md).

A mixer hides *how much* moved and *from whom*. mirror-pool hides *who started
an action that everyone can see happened*. N participants voluntarily pool one
identical action into a synchronized round; the action executes on-chain in full
view, but which wallet initiated any given instance cannot be attributed. The
anonymity set is the set of participants in the round, exactly as a mixer's
anonymity set is the set of deposits of one denomination.

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
but cannot link any of them back to the wallet that committed it. Shared-epoch
batching is the specific defense against FIFO temporal matching, the single
strongest empirical attack on mixers.

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
soak-proven live with 25/25 on-chain assertions. The status table below is kept
honest against the tree.

| Component | Path | Status |
| --- | --- | --- |
| Shared types + wire format | `crates/mirror-core` | **Implemented** - `Commitment`/`Nullifier`/`Secret`, `commit()`/`nullifier()` (circomlib Poseidon, cross-check-proven against the circuit), `ActionClass` + `SizeBucket`, `Epoch`/`EpochSchedule`, `KAnon` honest accounting, `wire` byte layout. Unit tests passing. |
| On-chain program | `programs/mirror-pool` | **Implemented** - fail-closed `InitPool`/`Commit`/`CommitDeposit`/`SettleEpoch`/`SettleZk`/`ClaimReward`, depth-20 Poseidon frontier accumulator + 32-root history ring, Epoch/Nullifier/Dwell PDAs, on-chain k-floor + double-settle prevention, and on-chain Groth16 (alt_bn128) membership verification. 42 mollusk tests; `build-sbf` green; deployed + exercised on public devnet. |
| ZK-deniable initiation | `circuits/` + `programs/mirror-pool` | **Implemented** - Poseidon membership circuit + Groth16 setup; `SettleZk` verifies the proof on-chain (public inputs `[root, nullifierHash, actionHash, epoch]`) and executes to a fresh output. A real proof verifies on-chain (fixture test) and live in the soak. |
| Adversarial harness | `crates/mirror-harness` | **Implemented** - heuristic + learned attacks measuring attacker advantage over `1/k`, Baseline vs mirror-pool. FIFO advantage collapses from high under per-actor delay to near zero under shared-epoch batching. Also prints an information-theoretic effective-k table (Serjantov-Danezis `2^H(p)` + min-entropy) under funding-provenance partitioning; see [`docs/EFFECTIVE_K.md`](docs/EFFECTIVE_K.md). |
| Gasless coordinator | `crates/mirror-coordinator` | **Implemented** - slot-window batching, `k_floor` gate, rotating fee-payer, and real atomic crowd settlement (ComputeBudget + `SettleEpoch` + N participant behaviors, shared accounts in an ALT). |
| Participant CLI | `crates/mirror-cli` | **Implemented** - `init-pool` / `commit` / `deposit-commit` / `prove` (rebuilds the path + generates and verifies a Groth16 proof in-process in pure Rust via ark-circom/ark-groth16, no Node; `--use-snarkjs` is an optional legacy fallback) / `status`. |
| Pooled behaviors | `crates/mirror-behaviors` | **Implemented** - `Behavior` trait + pooled-action adapters: PlainTransfer (soak baseline), Jupiter swap, jitoSOL stake. |
| Anti-Sybil + incentives | `programs/mirror-pool` + `crates/mirror-coordinator` | **Implemented** - entry-fee split into a reward pool, crowd-path dwell `ClaimReward`, honest `real_k` reporting; the ZK-path incentive is designed in [`docs/INCENTIVES.md`](docs/INCENTIVES.md). |
| Soak suite (Surfpool + devnet) | `crates/mirror-soak` | **Implemented** - live end-to-end soak, both behavioral paths + adversarial cases, 17/17 on-chain assertions, on local Surfpool AND public devnet ([`docs/PROOF.md`](docs/PROOF.md)). |
| Confidential-value circuit | `circuits/` | **Implemented** - 2-in/2-out Tornado-Nova JoinSplit (`transaction.circom`): membership + nullifiers + value conservation + range proofs + extDataHash binding; setup + vk + shield/transfer/unshield fixtures. |
| Confidential value pool (on-chain) | `programs/mirror-pool` | **Implemented** - `InitValuePool` + `Transact`: own Poseidon value-note accumulator + root history + vault, on-chain Groth16 JoinSplit verify, nullifier PDAs, deposit/withdraw per `publicAmount`, fixed-denomination mode. Amounts never in cleartext except public deposit/withdraw. |
| Confidential notes + client ops | `crates/mirror-core` + `mirror-cli` + `mirror-coordinator` | **Implemented** - ECIES encrypted notes + `scan` discovery; `value-keygen`/`shield`/`transfer`/`unshield` (pure-Rust ark-groth16 prove + emit, no Node); gasless `submit_transact` (transfer/unshield relay-only signed = the unlinkability). |
| Confidential soak | `crates/mirror-soak` | **Implemented** - live shield -> hidden-amount transfer -> unshield + fixed-denom + adversarial, 25/25 on-chain assertions ([`docs/PROOF.md`](docs/PROOF.md)). |
| Trusted-setup ceremony | `crates/mirror-ceremony` + `mirror-cli ceremony` | **Implemented** - distributable multi-party Groth16 phase-2 ceremony for both circuits: public phase-1 import + provenance reader, delta re-randomization, Schnorr proof of knowledge bound to the contributor id and the running transcript hash, SHA-256 transcript chain, reproducible verification (rejects tampered deltas, forged/replayed proofs, reordered and truncated chains - each tested), and an independent-contributor count that refuses to count self-runs. `ceremony prove-check` proves the membership circuit under a ceremony key and the on-chain `groth16-solana` verifier accepts it. **No production ceremony has been run: the deployed keys are still dev-setup keys.** See [`docs/CEREMONY.md`](docs/CEREMONY.md). |

"Implemented" means the component's core logic is complete and tested. The host
workspace tests, 42 on-chain mollusk tests, `build-sbf`, and the two live Surfpool
soaks (behavioral 17/17 + confidential 25/25 on-chain assertions) are all green.
See the roadmap for future work (swap/stake-from-pool via CPI, confidential
deposits, and the ZK-path anonymity-mining incentive). The multi-party phase-2
trusted-setup ceremony is built and tested; what remains there is *running* one
with external contributors and redeploying with its key, because the currently
committed and deployed verifying keys are still dev-setup keys.

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
    mirror-cli           # participant CLI (commit/prove/status)  [implemented]
    mirror-harness       # adversarial evaluation harness         [implemented]
    mirror-behaviors     # Behavior trait + pooled-action adapters[implemented]
    mirror-soak          # live Surfpool end-to-end soak suite    [implemented]
    mirror-ceremony      # multi-party Groth16 phase-2 ceremony   [implemented]
  circuits/              # Poseidon membership circuit + Groth16 setup [implemented]
  programs/
    mirror-pool          # on-chain Pinocchio program (SBF)       [implemented]
  docs/
    THREAT_MODEL.md      # attacker model + which attacks each path defeats
    ARCHITECTURE.md      # the two settlement paths + on-chain design in depth
    ROADMAP.md           # what is built and what is future work
    INCENTIVES.md        # entry-fee split, dwell reward, ZK-path incentive design
    PROOF.md             # live Surfpool soak results + tx signatures
    CEREMONY.md          # multi-party trusted-setup ceremony: contribute + verify
  Cargo.toml             # host workspace manifest
  Makefile               # fmt / clippy / test / build-sbf / harness / soak
  LICENSE                # MIT
```

---

## The privacy claim, stated honestly

Overstating an anonymity set is the documented failure mode of prior mixers, so
this project reports the *real* set and is explicit about its limits. `KAnon` in
`mirror-core` separates the nominal commit count from the real set (nominal
minus operator-owned and Sybil decoys), and an epoch settles only when the real
set meets `k_floor`. Anonymity is `1/real_k`, never `1/nominal`.

**What mirror-pool defends against**

- **Initiator attribution of a pooled action.** Within one settled epoch, the
  initiator of any given action instance is indistinguishable from the other
  real participants. This is the whole point.
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

**What mirror-pool does NOT do (explicit non-goals)**

- **The behavioral pool does not hide amounts or balances.** In the crowd and
  ZK-deniable paths, the action, its size class, and its on-chain effects are
  public by design; that layer is behavioral obscurity, not a mixer. (The
  optional confidential-value layer *does* hide amounts, via the JoinSplit
  `Transact`; see the status table and `docs/ARCHITECTURE.md`. The public
  deposit/withdraw magnitude and the pool TVL remain visible even there.)
- **The behavioral pool does not provide value-transfer privacy or unlinkable
  payments.** It anonymizes *who initiated a shared action*, not *who paid whom*.
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
  1) under funding-provenance partitioning; mirror-pool keeps it at 32.
- [`docs/CEREMONY.md`](docs/CEREMONY.md) - the multi-party Groth16 phase-2
  trusted-setup ceremony: how to contribute, how to verify somebody else's, what the
  beacon is for, how the independent-contributor count refuses to count self-runs,
  and exactly what 1-of-N honest does and does not give you.
- [`docs/PROOF.md`](docs/PROOF.md) - the live Surfpool soak: both paths + the
  adversarial cases, with transaction signatures and on-chain assertions.
- [`paper/mirror-pool.pdf`](paper/mirror-pool.pdf) - the design paper: the
  who + how-much composition, the effective-k analysis, on-chain verification, and
  the public devnet results in one skimmable artifact (source
  [`paper/mirror-pool.tex`](paper/mirror-pool.tex)).

---

## License

MIT. See [`LICENSE`](LICENSE).
