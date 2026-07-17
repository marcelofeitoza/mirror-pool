# mirror-pool architecture

mirror-pool is "Tornado Cash for synchronized *behavior*, not funds." A classic
mixer breaks the link between a deposit and a withdrawal of *value*. mirror-pool
breaks the link between an on-chain *action* and the *identity that initiated it*.
N participants voluntarily pool the same action into one synchronized epoch. An
observer sees N identical actions land together and cannot attribute any one of
them to its initiator.

This is **behavioral obscurity**, not fund hiding. The funds are visible, the
action is visible, the aggregate is visible. What is destroyed is the
per-initiator signal that chain-analysis tools rely on: timing, amount, gas
payer, and wallet fingerprint.

The threat model and every design choice below is grounded in the empirical
attack literature. The single strongest documented attack on Tornado is FIFO
temporal matching (linking a deposit to the earliest later withdrawal), which
recovers up to 49% of links on small pools. mirror-pool's core defense -
shared-epoch batching - exists specifically to collapse that attack to the
theoretical floor of 1/k. The adversarial harness (`mirror-harness`) is the
component that *proves* it does.

---

## 1. Protocol flow

The v1 protocol is a non-ZK commit / reveal round with k-anonymity slot epochs
and a gasless coordinator. The lifecycle of a single pool:

```
                            ┌──────────────────────────────────────────────┐
                            │              on-chain program                  │
                            │            (programs/mirror-pool)              │
                            └──────────────────────────────────────────────┘

  ┌── InitPool ──────────────────────────────────────────────────────────────┐
  │ operator sets ActionClass (fixed shape) + EpochSchedule{epoch_slots,        │
  │ k_floor}. Creates the Pool PDA and the empty frontier Merkle accumulator.   │
  └────────────────────────────────────────────────────────────────────────────┘
                                       │
                                       ▼
  ┌── Commit phase (epoch window open, epoch = slot / epoch_slots) ─────────────┐
  │                                                                              │
  │  participant i (client-side):                                               │
  │    secret_i        <- random 32 bytes         (never leaves the client)      │
  │    C_i = commit(secret_i, action, epoch)      mirror-core::commit()          │
  │    -> submits Commit{C_i} to the coordinator (relay), NOT self-signed        │
  │                                                                              │
  │  coordinator appends C_i as a Merkle leaf via the Commit instruction.        │
  │  Observers see only opaque 32-byte leaves; action + secret stay client-side. │
  │                                                                              │
  └──────────────────────────────────────────────────────────────────────────────┘
                                       │
                                       ▼   window closes at settle_slot(epoch)
                                       │   = (epoch + 1) * epoch_slots
                                       ▼
  ┌── Coordinator enforces k_floor (OFF-CHAIN gate, BEFORE submitting) ─────────┐
  │                                                                              │
  │  KAnon{ nominal, excluded } for the epoch                                    │
  │  real_k = nominal - excluded    (mirror-core::KAnon::real_k)                 │
  │                                                                              │
  │  if !k.meets_floor(schedule):   real_k < k_floor                             │
  │        -> DO NOT settle. Roll commitments forward / refund slots.            │
  │        -> never execute into a set small enough to deanonymize by            │
  │           elimination.                                                       │
  │                                                                              │
  └──────────────────────────────────────────────────────────────────────────────┘
                                       │  real_k >= k_floor
                                       ▼
  ┌── Atomic SettleEpoch (ONE instruction, all initiators at once) ─────────────┐
  │                                                                              │
  │  coordinator (sole rotating fee-payer) submits:                             │
  │    SettleEpoch{ epoch, [nullifier_0 .. nullifier_{k-1}] }                    │
  │                                                                              │
  │  program, per nullifier, in one atomic transaction:                         │
  │    1. verify the epoch window has closed (fail-closed on slot)              │
  │    2. create nullifier PDA ['nullifier', pool, epoch, nf]  -> anti-replay    │
  │    3. execute the pool's fixed action for that slot                          │
  │  all k actions share ONE block timestamp -> FIFO temporal matching has       │
  │  nothing to order on.                                                        │
  │                                                                              │
  └──────────────────────────────────────────────────────────────────────────────┘
```

The three properties that make this work, and why each is load-bearing:

1. **Shared-epoch batching.** Every action in an epoch settles on the *same*
   block timestamp. FIFO temporal matching links a deposit to the earliest later
   withdrawal; when all k actions are simultaneous there is no "earliest," so the
   attack degenerates to guessing 1-in-k. Per-actor random delay does *not*
   achieve this - a random delay leaves a heavy-tailed per-user timing signature
   that correlation attacks recover. Batching is the empirically correct defense.

2. **Gasless rotating relay.** Self-paying gas is a dominant deanonymization
   vector (a wallet that funds and signs its own execution is trivially linked).
   The coordinator is the fee-payer and signer for `SettleEpoch`, so the acting
   wallet never funds or signs. But a *single* fee-payer for everyone becomes a
   consolidation node that clusters every participant, so the fee-payer set
   **rotates**, and CU limit, priority fee, tx version, account ordering, and ALT
   are normalized to one pool-wide standard. Wallet fingerprinting (matching gas
   and priority-fee settings across legs) cut Tornado's effective set by 37% on
   its own; normalization closes that channel.

3. **Fixed action shape.** One `ActionClass` per pool, one `SizeBucket` per
   action. Heterogeneous actions leak exactly like mixed denominations.
   Variable and round-number amounts leak a large fraction of an anonymity set
   to amount-matching *alone* (Wang et al., arXiv:2201.09035, measured 27.34%
   ETH / 46.02% BSC anonymity reduction from composable heuristics; the Tornado
   deanonymization study, arXiv:2510.09433), and fixed/stratified denominations
   sharply reduce that leakage. Size-bucketing is therefore mandatory, encoded
   directly in `ActionClass` and bound into the commitment.

These three combine multiplicatively: batching removes the timing signal, the
rotating gasless relay removes the payer/fingerprint signal, and the fixed action
shape removes the amount/shape signal. Removing any one re-opens a documented
attack, which is why the harness measures all three together.

---

## 2. Crate responsibilities

The workspace is split into off-chain host crates (one Cargo workspace) and the
on-chain program (its own workspace, built for SBF). This separation is
deliberate: `cargo build` / `cargo test` at the root never tries to compile a
Solana entrypoint for the host target.

### `crates/mirror-core` - shared primitives  [DONE, compiling, tested]

The single source of truth that every other crate and the on-chain program agree
on. If this crate and the program ever disagree on a byte layout or a hash
domain, the whole design fails silently, so it is kept minimal and heavily
tested.

Public API (see `crates/mirror-core/src/lib.rs`):

- `Secret([u8; 32])` - the client-held pre-image; `Debug` is redacted so secret
  material never prints. In v2 it becomes a ZK witness.
- `Commitment(Hash32)` / `Nullifier(Hash32)` - the commit/replay primitives.
- `commit(secret, action, epoch) -> Commitment` - SHA-256 over a
  domain-separated encoding of `(secret, action.canonical_bytes(), epoch)`.
  Binding the action *and* epoch into the leaf is what makes settlement
  fail-closed: a relayer cannot substitute a different action for a committed one
  without invalidating the commitment.
- `nullifier(secret, epoch) -> Nullifier` - SHA-256 over `(secret, epoch)`,
  domain-separated from `commit` so the two hashes can never collide or be
  reinterpreted. Epoch-scoped so the same secret yields a different nullifier in
  a later epoch.
- `ActionClass` - the fixed action shape: `Swap { mint_in, mint_out, size }` or
  `Stake { validator, size }`, with a deterministic `canonical_bytes()` encoding
  identical on both sides of the wire.
- `SizeBucket` (`Nano | Small | Medium | Large`) - the behavioral analog of
  fixed denominations.
- `Epoch(u64)` and `EpochSchedule { epoch_slots, k_floor }` with
  `epoch_of_slot`, `settle_slot` - the shared slot-clock math so every
  participant derives the same current epoch with zero coordination.
- `KAnon { nominal, excluded }` with `real_k()` and `meets_floor(schedule)` -
  honest anonymity accounting. `real_k = nominal - excluded`; users are shown
  `real_k`, never the nominal commit count.
- `MirrorError` - the shared error taxonomy (`EpochNotClosed`, `BelowKFloor`,
  `NullifierSpent`, `MalformedInstruction`).
- `wire` - the on-chain byte layout (`tag::{INIT_POOL, COMMIT, SETTLE_EPOCH}`,
  `COMMIT_LEN`, `SETTLE_HEADER_LEN`). Documented in section 4.

v1 uses SHA-256 (fast, no proving system). The API is shaped so v2 can swap in
Poseidon + Groth16 membership proofs additively, without breaking callers.

### `crates/mirror-coordinator` - gasless batch coordinator

The off-chain relay. Watches for `Commit` submissions, batches them into
slot-window epochs, enforces `k_floor` *before* settling, and submits
`SettleEpoch` as the sole, rotating fee-payer with normalized CU / priority-fee /
ALT. Built fresh here: a slot-window batch scheduler (close an epoch when its
slot window passes, gate on k_floor, then settle) plus atomic multi-instruction
transaction building over Address Lookup Tables and v0 transactions (standard
Solana). This is where the
"shared-epoch batching + gasless rotating relay" properties are physically
implemented. Critically, the coordinator is *not* trusted for correctness: it can
only choose *whether* to settle an epoch, never *what* each action is (the action
is bound in each participant's commitment), and it cannot forge a nullifier.

### `crates/mirror-cli` - participant CLI

The clap-based participant tool. v1 subcommands: `commit` (generate a secret,
compute the commitment for the current epoch, submit it) and `status` (report the
epoch, its live `KAnon`, and whether the floor is met). v2 adds `prove` (produce
the Groth16 membership proof for deniable initiation). The CLI holds the secret;
it never self-pays or self-signs execution.

### `crates/mirror-harness` - adversarial evaluation harness  [THE DIFFERENTIATOR]

The component that turns anonymity claims into measured numbers. It runs a suite
of heuristic chain-analysis attacks and a learned classifier against two
simulated worlds, and reports the **attacker advantage over the 1/k baseline**:

- **Baseline** - per-actor random delay, self-paid gas, variable amounts (the
  naive privacy setup real users default to).
- **MirrorPool** - shared-epoch batch, gasless rotating relay, fixed size bucket.

Attacks implemented: FIFO temporal matching, amount matching, gas-payer reuse,
wallet fingerprinting, temporal correlation, common-funding-source, plus a
learned classifier over the combined feature set. The headline result the
harness must demonstrate: **FIFO advantage is high under random delay and
collapses to ~0 under shared-epoch batching.** The harness implements, fresh in
Rust, the Wang et al. heuristics (effective-vs-claimed anonymity-set gap;
arXiv:2201.09035) plus a learned classifier. Reporting measured anonymity, not
an undisclosed set size, is the explicit differentiator against competitors who
leave anon-set size undisclosed.

### `crates/mirror-behaviors` - pooled-action adapters

A `Behavior` trait plus adapters for the concrete pooled actions every epoch
participant performs identically: a Jupiter swap adapter and a jitoSOL stake
adapter. These map an `ActionClass` to the actual on-chain instruction executed
at settlement, keeping the fixed-shape invariant (all participants emit the
identical action) enforceable in one place. Swap behavior is Jupiter-only; swap
input is wSOL-locked; output lands in a public ATA - mirror-pool hides the
*initiator*, not the action.

### `programs/mirror-pool` - on-chain program (standalone, SBF)

The Pinocchio program. Three instructions - `InitPool`, `Commit`, `SettleEpoch`
- an append-only intent accumulator (frontier Merkle tree), nullifier PDAs,
fail-closed parsing, and the Ed25519 introspection + validation-order hardening.
Detailed in section 3. It is intentionally excluded from the host workspace and
built with `cargo build-sbf --manifest-path programs/mirror-pool/Cargo.toml`.

---

## 3. On-chain program design

### Instructions

| tag | instruction | who submits | effect |
|-----|-------------|-------------|--------|
| `0` | `InitPool` | operator | create Pool PDA; fix `ActionClass` + `EpochSchedule`; init empty accumulator |
| `1` | `Commit` | coordinator (relayed) | append one 32-byte commitment leaf to the frontier Merkle tree |
| `2` | `SettleEpoch` | coordinator (rotating fee-payer) | after window close, atomically create k nullifier PDAs and execute the k fixed actions |

### Intent accumulator - frontier Merkle tree

Commitments are appended to an append-only Poseidon frontier Merkle accumulator
built fresh in this crate: a standard Tornado-Cash-style commitment tree (Zcash
Sapling uses the same accumulator shape). A frontier tree stores only the
right-edge path plus the running root, so appends are O(tree height) in compute
and O(height) in account bytes, and it never materializes the full tree
on-chain. In v1 the tree is the public record of which commitments
entered which epoch; in v2 it becomes the set a Groth16 membership proof proves
inclusion in without revealing the leaf.

### Nullifier PDAs - anti-replay

Each executed action consumes a nullifier, materialized as a PDA at
`['nullifier', pool, epoch, nf]`. Creation is the atomicity primitive: a PDA that
already exists cannot be created again, so the runtime itself rejects a
double-spend within an epoch (`MirrorError::NullifierSpent`). Scoping the seed by
`epoch` means the same secret is a fresh, unlinkable nullifier in a later epoch,
while remaining single-use within its own epoch. This is the standard Solana
anti-replay pattern, built fresh: a per-(pool, epoch, nullifier) PDA whose
existence marks a spent nullifier.

### Fail-closed parsing

All instruction parsing is fail-closed: any length mismatch, unknown
discriminator, or trailing/short data is rejected as
`MirrorError::MalformedInstruction` rather than being interpreted leniently. The
program never "best-effort" parses. `SETTLE_HEADER_LEN` and `COMMIT_LEN` from
`mirror-core::wire` are validated exactly, and the declared `n_nullifiers` count
must match the remaining byte length precisely before any state is touched. The
epoch-window check is likewise fail-closed: settlement before
`settle_slot(epoch)` is rejected (`MirrorError::EpochNotClosed`), never rounded
or waved through.

### Ed25519 introspection + validation-order hardening

For settlement authorization (e.g. verifying a coordinator/relayer signature or a
Range-style risk attestation carried in a sibling instruction), the program
verifies the Ed25519 signature by reading it from the instructions sysvar
(standard Solana instruction introspection), built fresh here. The hardening,
standard for this pattern:

- **The `ix_index == 0xFFFF` sentinel is rejected.** An unresolved / sentinel
  instruction index must never be treated as a valid introspection target;
  accepting it would let a caller point the check at a non-existent instruction
  and pass validation vacuously.
- **Validation-order hardening.** All structural and index checks on the
  introspected instruction happen *before* any signature or attestation content
  is trusted. Ordering matters: verifying content before confirming *which*
  instruction and *whose* pubkey produced it is the class of bug that lets a
  crafted sibling instruction spoof a valid gate. The introspected program id,
  account layout, and expected pubkey are all pinned before the signature payload
  is read.

This is the pattern the harness's "common-funding" and "gas-payer" attacks
implicitly assume is airtight: the on-chain gate cannot be tricked into settling
an epoch that fails the k-floor or authorization checks.

### Range risk gating (optional, execution-time)

Because attribution can be enforced *within* a transaction via the Range on-chain
Risk API (a Switchboard oracle), a pool may optionally gate settlement on a
risk-score attestation carried through the same Ed25519 introspection path. This
keeps compliance a program-side, execution-time property rather than a post-hoc
one, without weakening initiator-anonymity for honest participants.

---

## 4. Wire format

The wire layout lives in `mirror-core::wire` so the coordinator/CLI (builders)
and the Pinocchio program (parser) cannot silently drift. The first byte of every
instruction is the discriminator.

```
tag::INIT_POOL     = 0
tag::COMMIT        = 1
tag::SETTLE_EPOCH  = 2
```

**COMMIT** (`COMMIT_LEN = 1 + 32 = 33` bytes):

```
offset  size  field
0       1     tag = 1 (COMMIT)
1       32    commitment (Hash32)
```

The participant posts *only* the commitment. The action and secret stay
client-side until settlement - the chain sees an opaque 32-byte leaf.

**SETTLE_EPOCH** (`SETTLE_HEADER_LEN = 1 + 8 + 4 = 13` bytes header, then a
packed nullifier array):

```
offset  size          field
0       1             tag = 2 (SETTLE_EPOCH)
1       8             epoch (u64, little-endian)
9       4             n_nullifiers (u32, little-endian)
13      n * 32        nullifier[0..n]  (each Hash32)
```

The relayer submits the whole epoch atomically. The parser validates
`data.len() == SETTLE_HEADER_LEN + n_nullifiers * 32` exactly (fail-closed)
before touching any account. All multi-byte integers are little-endian, matching
`Epoch(u64).to_le_bytes()` used inside `commit`/`nullifier`.

---

## 5. Solana specifics

- **ALT + v0 transactions under 1232 bytes.** `SettleEpoch` references the Pool
  PDA, the accumulator, one nullifier PDA per participant, and each
  participant's action accounts. That account list exceeds a legacy transaction's
  capacity quickly, so settlement uses a versioned (v0) transaction with an
  Address Lookup Table (standard Solana) to keep the settlement tx under 1232
  bytes. Everything must still fit the 1232-byte packet limit, which caps how many
  participants one `SettleEpoch` transaction can carry and drives the batching
  math in the coordinator.
- **Jito 5-tx bundle cap → N-party atomicity is program-side.** A Jito bundle
  atomically lands at most 5 transactions. N-party settlement for N > ~5 cannot
  rely on bundle atomicity, so **all k intents settle inside one instruction /
  one epoch** program-side. This is why `SettleEpoch` takes the full nullifier
  array and executes every action in a single atomic instruction: a no-show
  simply forfeits its slot and fee without stalling the epoch, and there is no
  per-party transaction an attacker can isolate. **Jito tip accounts are kept out
  of the ALT** (a known footgun).
- **Groth16 / alt_bn128 costs (v2).** ZK-deniable initiation verifies a Groth16
  membership proof on-chain via the `alt_bn128` (BN254) syscalls; see the public
  Lightprotocol/groth16-solana crate. Cost is roughly 170K to 500K CU per proof
  with a 128-byte compressed G1/G2 proof, cheap enough for per-action
  verification and comfortably inside the per-transaction CU budget alongside the
  settlement work. v2 swaps SHA-256 for Poseidon in `mirror-core` so the tree
  hashing matches the circuit.

---

## 6. Component status

| component | path | status |
|-----------|------|--------|
| shared types + wire format + tests | `crates/mirror-core` | **Done** - written, compiling, unit-tested (commitment binding, epoch-scoped nullifiers, domain separation, epoch math, real-k accounting) |
| gasless batch coordinator | `crates/mirror-coordinator` | Scaffolded: window scheduler + rotating fee-payer + k-floor gate to build (technique: slot-window batch scheduler, built fresh) |
| participant CLI | `crates/mirror-cli` | Scaffolded - `commit` / `status` (v2: `prove`) |
| adversarial harness | `crates/mirror-harness` | Scaffolded: build fresh (Wang et al. heuristics, arXiv:2201.09035); attacker-advantage table (the differentiator) |
| pooled-action behaviors | `crates/mirror-behaviors` | Scaffolded - `Behavior` trait + Jupiter swap + jitoSOL stake adapters |
| on-chain program | `programs/mirror-pool` | Scaffolded - `InitPool` / `Commit` / `SettleEpoch`; frontier accumulator; nullifier PDAs; fail-closed parsing; Ed25519 introspection hardening |
| v2: ZK-deniable initiation | (Poseidon + Groth16) | Planned - see `docs/ROADMAP.md` |

Legend: **Done** = written and tested; Scaffolded = crate exists and compiles as
a stub, implementation pending.

---

## 7. Prior art

mirror-pool is an independent clean-room implementation. It reuses no private
code; every primitive is rebuilt fresh in this repo from public techniques. Each
mechanism traces to a documented attack or a public precedent:

- **Shared-epoch batching** defeats FIFO temporal matching (the strongest
  empirical Tornado attack, up to 49% on small pools; arXiv:2510.09433); the
  batch-clearing model follows Penumbra, where all swaps in a block clear at one
  price so per-user ordering and attribution are eliminated by construction.
- **Gasless rotating relay + normalized tx shape** closes the not-using-a-relayer
  deanonymization vector and the 37% wallet-fingerprint attack, while rotation
  prevents the relayer itself from becoming a clustering consolidation node.
- **Fixed `ActionClass` + `SizeBucket`** is the behavioral analog of fixed
  denominations, backed by the public finding that variable and round-number
  amounts leak a large fraction of anonymity to amount-matching (Wang et al.,
  arXiv:2201.09035; the Tornado study, arXiv:2510.09433) while fixed/stratified
  denominations sharply reduce it.
- **Honest `KAnon` (real k, not nominal)** answers the documented failure where
  operator-generated cover traffic and anonymity-mining inflate the nominal set
  while adding zero real anonymity. Sybil resistance requires real per-identity
  cost (Whirlpool-style fixed entry fee / fidelity bonds); the harness reports
  real k so that cost is measurable.
- **Frontier Merkle accumulator, nullifier PDAs, Ed25519 introspection
  hardening, on-chain Groth16** follow public systems and are built fresh here,
  not ported from any private codebase: Tornado Cash (commitment/nullifier/Merkle
  anonymity set), Zcash Sapling (Merkle accumulator), the
  Lightprotocol/groth16-solana crate (on-chain Groth16 via the alt_bn128
  syscalls), and standard Solana docs (Address Lookup Tables, versioned
  transactions, Jito bundles).
