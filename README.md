# mirror-pool

**Tornado Cash for behavior, not funds.** An anonymity set over the *initiators*
of an action, not over denominations.

A mixer hides *how much* moved and *from whom*. mirror-pool hides *who started
an action that everyone can see happened*. N participants voluntarily pool one
identical action into a synchronized round; the action executes on-chain in full
view, but which wallet initiated any given instance cannot be attributed. The
anonymity set is the set of participants in the round, exactly as a mixer's
anonymity set is the set of deposits of one denomination.

This is behavioral obscurity for the Superteam Brasil "Privacy-Through-Noise"
theme: the goal is to make on-chain *behavior* hard for automated chain-analysis
to read, explicitly **not** to hide balances or move value privately.

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

v1 is a non-ZK commit-reveal design: k-anon slot epochs + a gasless rotating
coordinator + pooled behavior modules + an adversarial evaluation harness. v2
swaps in a Groth16 membership proof for ZK-deniable initiation. The shared type
layer is the contract every other component builds against and is complete; the
components that consume it are scaffolded and under active development.

| Component | Path | Status |
| --- | --- | --- |
| Shared types + wire format | `crates/mirror-core` | **Implemented** - `Commitment`/`Nullifier`/`Secret`, `commit()`/`nullifier()` with domain separation, `ActionClass` + `SizeBucket`, `Epoch`/`EpochSchedule`, `KAnon` honest accounting, `wire` byte layout. 5 unit tests passing. |
| On-chain program | `programs/mirror-pool` | **Scaffolded** - module layout (`instructions/`, `state/`) in place. `InitPool` / `Commit` / `SettleEpoch`, the append-only intent accumulator (frontier Merkle tree), and nullifier PDAs are pending. |
| Gasless coordinator | `crates/mirror-coordinator` | **Scaffolded** - watches commits, batches into slot-window epochs, enforces `k_floor` before settle, submits `SettleEpoch` as the sole rotating fee-payer with normalized CU/fee/ALT. |
| Participant CLI | `crates/mirror-cli` | **Scaffolded** - `commit` / `status` (`prove` in v2). |
| Adversarial harness | `crates/mirror-harness` | **Scaffolded** - the differentiator. Runs heuristic + learned attacks and measures attacker advantage over `1/k` for a Baseline vs mirror-pool. |
| Behavior modules | `crates/mirror-behaviors` | **Scaffolded** - `Behavior` trait + pooled-action adapters (swap, stake). |

"Scaffolded" means the crate compiles as part of the workspace and its role is
fixed by the `mirror-core` API, but the logic is a placeholder. The status table
is kept honest against the tree; see the roadmap for the build order.

---

## Quickstart

Requires a stable Rust toolchain. The on-chain program additionally requires
`solana-cargo-build-sbf`.

```sh
# Off-chain host workspace: core, coordinator, cli, harness, behaviors.
# From the repo root:
cargo test --workspace        # run the unit tests (mirror-core: 5 passing)
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
    mirror-core          # shared types + wire format + tests   [implemented]
    mirror-coordinator   # off-chain gasless batch coordinator   [scaffolded]
    mirror-cli           # participant CLI (commit / status)      [scaffolded]
    mirror-harness       # adversarial evaluation harness         [scaffolded]
    mirror-behaviors     # Behavior trait + pooled-action adapters[scaffolded]
  programs/
    mirror-pool          # on-chain Pinocchio program (SBF)       [scaffolded]
  docs/
    THREAT_MODEL.md      # attacker model + which attacks are defeated
    ARCHITECTURE.md      # commit / batch / settle design in depth
    ROADMAP.md           # v1 build order and the v2 ZK path
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

- **It does not hide funds, amounts, or balances.** The action, its size class,
  and its on-chain effects are public by design. This is behavioral obscurity,
  not a mixer and not confidential transfers.
- **It does not provide value-transfer privacy or unlinkable payments.** It
  anonymizes *who initiated a shared action*, not *who paid whom*.
- **It does not manufacture anonymity from operator-owned cover traffic.**
  Decoys the operator controls inflate the nominal count and add zero real
  anonymity to anyone who clusters the operator; they are excluded from
  `real_k`. A pool with real `k=1` provides no anonymity regardless of nominal
  size.
- **v1 is not ZK.** The commit-reveal design hides the initiator within the
  epoch but is not a zero-knowledge proof of membership. ZK-deniable initiation
  (Groth16 membership proof) is v2; see `docs/ROADMAP.md`.
- **It is not a Sybil oracle.** Real k-anonymity assumes participants are
  economically distinct. Without a per-identity entry cost an attacker can fill a
  round and reduce the real set to one; Sybil resistance is a first-class
  roadmap item, not a solved property.
- **Not audited, not production-deployed.** This is a bounty-stage research
  implementation. Do not rely on it to protect real activity.

---

## Documentation

- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) - the attacker model and which
  chain-analysis heuristics each design choice defeats.
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) - commit / shared-epoch batch /
  gasless atomic settlement in depth, and the on-chain account model.
- [`docs/ROADMAP.md`](docs/ROADMAP.md) - the v1 build order and the v2 path to
  ZK-deniable initiation.

---

## License

MIT. See [`LICENSE`](LICENSE).
