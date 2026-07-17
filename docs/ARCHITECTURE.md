# mirror-pool architecture

mirror-pool is "Tornado Cash for behavior, not funds." A classic mixer breaks the
link between a deposit and a withdrawal of *value*. mirror-pool breaks the link
between an on-chain *action* and the *identity that initiated it*. N participants
voluntarily pool the same action into one synchronized epoch; an observer sees N
identical actions land together and cannot extract the per-initiator signal that
chain-analysis tools rely on: timing, amount, gas payer, and wallet fingerprint.

The funds are visible, the action is visible, the aggregate is visible. What is
destroyed is *which participant initiated which instance*. mirror-pool delivers
this with two settlement paths that share one accumulator, one epoch clock, and
one anti-Sybil economy, and offer two distinct strengths of the same guarantee:

1. **Crowd path** (`Commit` / `SettleEpoch`). Participants each sign their own
   identical action, and the coordinator composes them into one atomic
   transaction that settles the whole epoch on a single block timestamp. This
   defeats copy-trading and signal extraction (synchronized identical actions
   carry no per-actor intent, timing, or fingerprint) and gives collective
   intent-deniability. The action still executes from the participant's named
   wallet, so it stays attributable to that wallet; what is hidden is the
   per-actor *signal*, not the on-chain signer.

2. **ZK opt-in path** (`CommitDeposit` / `SettleZk`). A participant escrows the
   action input at commit time. At settlement a relay verifies a Groth16
   membership proof on-chain that an output corresponds to *some* committed
   member without revealing which, checks the action binding and nullifier, and
   executes the action to a *fresh* output address with no participant signature.
   This provides cryptographic who-initiated unlinkability: the deposit is
   visible, the output goes to a fresh address, and no participant signs at
   settle.

Both paths append to the same Poseidon frontier Merkle accumulator, derive their
epoch from the same slot clock, are gated by the same on-chain k-floor and
per-nullifier anti-replay, and pay the same anti-Sybil entry fee. The entire
design is grounded in the empirical attack literature: the single strongest
documented attack on Tornado is FIFO temporal matching (linking a deposit to the
earliest later withdrawal), which recovers up to 49% of links on small pools.
mirror-pool's core defense, shared-epoch batching, exists specifically to
collapse that attack to the 1/k floor, and the adversarial harness
(`mirror-harness`) is the component that *measures* the collapse instead of
asserting it.

---

## 1. System overview

```
                          participants                          participants
                       (crowd path, sign                    (ZK opt-in, escrow
                        their own action)                    at commit time)
                               |                                    |
                     Commit{C_i}                          CommitDeposit{C_i, amount}
                               |                                    |
                               v                                    v
        +-------------------------------------------------------------------------+
        |                     on-chain program (programs/mirror-pool)             |
        |                                                                         |
        |   Pool PDA: frontier Merkle accumulator (Poseidon, depth 20)           |
        |             + 32-root history ring + k_floor + entry-fee economy       |
        |   Epoch PDA (per window)   Nullifier PDA (per spend)   Dwell PDA        |
        +-------------------------------------------------------------------------+
                               |                                    |
             coordinator composes ONE                    relay proves membership
             atomic v0 tx: ComputeBudget +               in ZK and settles ONE
             SettleEpoch + N participant                 SettleZk per membership
             actions (N+1 signers, ALT)                  (no participant signs)
                               |                                    |
                               v                                    v
                 N identical actions land on              escrow released to a
                 one shared timestamp, paid by            FRESH recipient bound
                 a rotating relay fee-payer               by the proof's actionHash
```

The two paths are peers, not versions. A pool can run either or both. The crowd
path is what the end-to-end Surfpool soak exercises with a fixed-shape transfer
behavior; the ZK path is exercised by the `deposit-commit` / `prove` CLI flow and
the on-chain `SettleZk` verifier against a committed proof fixture.

---

## 2. Instruction set

The first byte of every instruction is the discriminator. All multi-byte integers
in instruction data are little-endian unless a field is explicitly a 32-byte
big-endian Groth16 public input. Parsing is fail-closed everywhere: a wrong
length, an unknown tag, an out-of-range count, or trailing bytes are rejected as
`MalformedInstruction` before any account is touched. The wire layout is defined
once in `mirror_core::wire` (host builders) and mirrored byte-for-byte in the
program's `wire` module (SBF parser) with compile-time size asserts on both sides.

| tag | instruction | who submits | effect |
|-----|-------------|-------------|--------|
| `0` | `InitPool` | operator | create the Pool PDA and fix `epoch_slots`, `k_floor`, `entry_fee`, `reward_bps`, and the settle authority forever |
| `1` | `Commit` | participant (crowd) | append one 32-byte commitment leaf, lazily create the Epoch PDA, bump its commit count, collect the entry fee, optionally accrue dwell |
| `2` | `SettleEpoch` | rotating relay | after the window closes, enforce authority + k-floor, create one Nullifier PDA per spend (anti-replay), mark the epoch settled |
| `3` | `CommitDeposit` | participant (ZK opt-in) | escrow `amount` into the pool, append one commitment leaf whose `actionHash` binds `(recipient, amount)`, collect the entry fee |
| `4` | `SettleZk` | rotating relay | verify a Groth16 membership proof on-chain, check the root/actionHash/nullifier, release the escrow to a fresh recipient |
| `5` | `ClaimReward` | participant (crowd) | pay a dwell-proportional, drain-safe share of the on-chain reward pool |

### 2.1 `InitPool` (tag 0, body 22 bytes)

```
offset  size  field
0       8     epoch_slots  (u64 LE)   slots per epoch window
8       4     k_floor      (u32 LE)   minimum commits before an epoch may settle (>= 2)
12      8     entry_fee    (u64 LE)   per-commit anti-Sybil deposit in lamports (0 disables)
20      2     reward_bps   (u16 LE)   entry-fee share (bps, <= 10000) sent to the reward pool
```

Accounts: `0` pool (writable, PDA to create), `1` authority (signer; becomes the
settle relay), `2` payer (signer, writable; funds Pool rent), `3` system program.
Every parameter is immutable after init: a mutable `k_floor` would let an operator
lower the floor right before a targeted epoch settles and shrink the anonymity set
on demand. The reward-split economy (`entry_fee`, `reward_bps`) is specified in
`docs/INCENTIVES.md`.

### 2.2 `Commit` (tag 1, body 32 bytes)

```
offset  size  field
0       32    commitment (Hash32)   Poseidon(secret, actionHash, epoch), computed client-side
```

Accounts: `0` pool (writable), `1` epoch (writable, created lazily; seeds
`[b"epoch", pool, epoch_id LE]`), `2` participant (signer, writable; pays fee +
rent), `3` system program, `4` clock sysvar, `5` dwell (OPTIONAL, writable; seeds
`[b"dwell", pool, participant]`). The current epoch is derived on-chain from the
clock (`slot / epoch_slots`). The handler appends the leaf to the frontier
accumulator, creates the Epoch PDA on the first commit of the window, bumps the
commit count (the on-chain k-floor input), collects the entry fee, and splits the
`reward_bps` share into the reward pool. When the optional Dwell PDA is passed,
the commit counts once toward the participant's dwell (distinct epochs committed
into); omitting it leaves the commit byte-for-byte backward compatible.

### 2.3 `SettleEpoch` (tag 2, header 12 bytes + n * 32)

```
offset  size          field
0       8             epoch        (u64 LE)
8       4             n_nullifiers (u32 LE)   1 .. MAX_SETTLE_NULLIFIERS (32)
12      n * 32        nullifier[i] (Hash32)   packed
```

Accounts: `0` pool, `1` epoch, `2` authority (signer; MUST equal `pool.authority`),
`3 .. 3+n` nullifier PDAs (writable; seeds `[b"nf", pool, epoch_id LE, nf]`),
`3+n` payer (signer, writable; funds nullifier rent), `4+n` system program,
`5+n` clock sysvar. The parser validates `data.len() == 12 + n * 32` exactly. The
checks run in a fixed, fail-closed order: authority match, window closed
(`current_slot >= (epoch + 1) * epoch_slots`), not already settled, on-chain
k-floor (`commit_count >= k_floor`), then per-nullifier anti-replay by PDA
creation (an already program-owned PDA means the nullifier was spent, so the whole
epoch is rejected), then mark the epoch settled so it can never settle twice. In
the crowd path the settled *actions* themselves are the participant behavior
instructions composed alongside this one in the same transaction (section 5), not
a CPI inside this handler; `SettleEpoch` performs the anonymity bookkeeping
(batching, k-floor, anti-replay, authority, fail-closed parsing).

Honesty note: `SettleEpoch` does not cryptographically bind each nullifier to a
distinct prior commitment. That binding is exactly what the ZK opt-in path adds.
The crowd path's guarantee is behavioral (synchronized identical actions), not a
membership proof.

### 2.4 `CommitDeposit` (tag 3, body 40 bytes)

```
offset  size  field
0       32    commitment (Hash32)   Poseidon(secret, actionHash, epoch); actionHash binds (recipient, amount)
32      8     amount     (u64 LE)   lamports to escrow into the pool (> 0)
```

Accounts: `0` pool (writable, holds the escrow), `1` epoch (writable), `2`
depositor (signer, writable; pays escrow + fee + rent), `3` system program, `4`
clock sysvar. This is the ZK opt-in escrow. It appends the commitment leaf to the
*same* accumulator the crowd path uses (so both paths share one anonymity set and
one root history), escrows `amount` into the pool, and collects the entry fee on
top of the escrow (the escrow is preserved in full for `SettleZk`; only the fee
funds the reward pool). It never touches a Dwell PDA: the ZK path is anonymous, so
tying a reward to an on-chain identity here would defeat its purpose.

### 2.5 `SettleZk` (tag 4, body 400 bytes)

```
offset  size   field
0       8      epoch          (u64 LE)   drives the window gate and the nullifier PDA seed
8       8      amount         (u64 LE)   escrow to release
16      64     proof_a                   Groth16 proof (A, already negated)
80      128    proof_b                   Groth16 proof (B)
208     64     proof_c                   Groth16 proof (C)
272     32     root                      public input 0
304     32     nullifierHash             public input 1
336     32     actionHash                public input 2
368     32     epoch (32-byte BE)        public input 3
```

The four trailing 32-byte values are the Groth16 public inputs in the fixed order
`[root, nullifierHash, actionHash, epoch]`. Accounts: `0` pool (writable, holds
the escrow), `1` authority (signer, writable; MUST equal `pool.authority`, pays
nullifier rent), `2` nullifier PDA (writable; seeds `[b"nf", pool, epoch_id LE,
nullifierHash]`), `3` recipient (writable; the fresh output), `4` system program,
`5` clock sysvar. The checks run in order and each fails closed: (1) authority is
a signer and equals `pool.authority`; (2) the `u64` epoch header equals the
32-byte big-endian epoch public input; (3) the epoch window has closed; (4) `root`
is one of the pool's recent roots (root-history ring); (5) the recomputed
`actionHash` from the on-chain `(recipient, amount)` equals the proof's
`actionHash`, so a relay cannot redirect the escrow; (6) the Nullifier PDA does
not yet exist (created here, else `NullifierSpent`); (7) the Groth16 proof verifies
against the vendored verifying key; (8) the escrow is released to the recipient by
a direct lamport move (the pool is program-owned), keeping the pool rent-exempt.
One membership settles per call; the coordinator batches independent memberships
across calls. Swap-from-pool and stake-from-pool are the identical pattern with a
different step (8): execute a different action from the pool authority via CPI
instead of a lamport transfer.

### 2.6 `ClaimReward` (tag 5, body 0 bytes)

Accounts: `0` pool (writable), `1` participant (signer, writable; receives the
reward), `2` dwell PDA (writable; seeds `[b"dwell", pool, participant]`). Pays a
dwell-proportional, drain-safe share of the reward pool. Only the crowd path has a
`ClaimReward`; the anonymity-preserving ZK-path equivalent is designed (not
implemented) in `docs/INCENTIVES.md`. The full reward formula and its drain-safety
invariant live there.

---

## 3. Account model

Every account is a PDA whose address is a pure function of the pool and the
epoch/nullifier/participant bytes, so a caller cannot substitute a forged account:
the program re-derives the expected address and rejects any mismatch
(`InvalidPda`). Every layout is explicit byte offsets with bounds-checked,
little-endian accessors: no `unsafe`, no transmutes, no `#[repr(C)]` casts on
untrusted account bytes.

```
Pool PDA       seeds = [b"pool",  authority(32)]
Epoch PDA      seeds = [b"epoch", pool(32), epoch_id(8 LE)]
Nullifier PDA  seeds = [b"nf",    pool(32), epoch_id(8 LE), nullifier(32)]
Dwell PDA      seeds = [b"dwell", pool(32), participant(32)]
```

### 3.1 Pool account (1780 bytes)

One anonymity set, one fixed action shape, one immutable config, plus the inline
frontier accumulator, the recent-root ring, and the incentive counters.

```
offset  size       field                 meaning
0       1          version               0 = uninitialized, 1 = v1
1       8          epoch_slots           slots per epoch window
9       4          k_floor               minimum commits before an epoch settles
13      8          commitment_count      total leaves appended (= next leaf index)
21      32         current_root          frontier accumulator root (latest)
53      32         authority             relay pubkey allowed to settle
85      8          entry_fee             per-commit anti-Sybil deposit (lamports)
93      1          bump                  Pool PDA bump
94      640        filled_subtrees       frontier right-edge siblings (DEPTH * 32)
734     4          root_head             ring index of the next root write
738     1024       root_ring             recent-root ring (ROOT_HISTORY_SIZE * 32)
1762    2          reward_bps            entry-fee share (bps) sent to the reward pool
1764    8          reward_pool_lamports  lamports earmarked for participation rewards
1772    8          total_unclaimed_dwell reward-formula denominator
```

The frontier accumulator (`DEPTH = 20`, up to about 1.05M leaves) is stored inline
so an append never touches a second account. The `root_ring` keeps the last
`ROOT_HISTORY_SIZE = 32` roots: a membership proof is made against a root
*snapshot*, so `SettleZk` must accept any recent root, not only the current one.
Every append (both `Commit` and `CommitDeposit`) records the new root here. The
last three fields are the incentive layer and are strictly additive: they sit
after the root ring, so offsets `0 .. 1762` are byte-identical to the
pre-incentive layout.

### 3.2 Epoch account (32 bytes)

```
offset  size  field       meaning
0       1     version     0 = uninitialized, 1 = v1
1       8     epoch_id    the window this account tracks
9       4     nominal_k   commitments accepted this window (the commit count)
13      1     settled     0 = open or rolled forward, 1 = settled
14      1     bump        Epoch PDA bump
15      17    reserved    future action-batch binding / root snapshot
```

`nominal_k` is the raw commit count and an upper bound on the real anonymity set.
On-chain the program enforces the necessary condition `nominal_k >= k_floor`; the
coordinator enforces the honest `real_k` before ever submitting a settle
(section 4.1). Nullifiers are not stored here: replay protection is one PDA per
nullifier, because a per-epoch bitmap would cap participation and a growable vector
would need realloc on the hot path.

### 3.3 Nullifier account (1 byte)

One PDA per `(pool, epoch, nullifier)`. It carries a single marker byte; its
*existence* (program-owned) is what marks the nullifier spent. Re-creating a live
account is impossible, so a double-spend within an epoch fails closed. Scoping the
seed by epoch means the same secret yields a fresh, unlinkable nullifier in a
later epoch while staying single-use within its own.

### 3.4 Dwell account (26 bytes)

```
offset  size  field         meaning
0       1     version       0 = uninitialized, 1 = v1
1       8     dwell         distinct epochs committed into
9       8     claimed_dwell dwell already converted to a reward
17      8     last_epoch    dedupe cursor (u64::MAX until the first commit)
25      1     bump          Dwell PDA bump
```

The crowd-path participation counter. Dwell advances only through a real,
fee-paying `Commit`, at most once per epoch, so it cannot be minted for free to
drain the reward pool. Only the crowd path uses it; see `docs/INCENTIVES.md`.

---

## 4. The two settlement flows, end to end

### 4.1 Crowd path (`Commit` / `SettleEpoch`)

```
InitPool ─► operator fixes epoch_slots, k_floor, entry_fee, reward_bps, authority

Commit phase (epoch = slot / epoch_slots)
  participant i (client-side):
    secret_i    <- random 32 bytes                      (never leaves the client)
    C_i = commit(secret_i, action, epoch)               mirror_core::commit
    -> signs and submits Commit{C_i}; pays the entry fee; the leaf is appended
  observers see only opaque 32-byte leaves; the action + secret stay client-side

Window closes at settle_slot(epoch) = (epoch + 1) * epoch_slots
  coordinator computes KAnon{ nominal, excluded } and real_k = nominal - excluded
    if real_k < k_floor:  DO NOT settle. Roll the epoch forward. Never execute
                          into a set small enough to deanonymize by elimination.

Atomic SettleEpoch (real_k >= k_floor)
  coordinator (rotating fee-payer) submits ONE v0 transaction:
    ComputeBudget(limit) + ComputeBudget(price)          normalized, pool-wide
    SettleEpoch{ epoch, [nf_0 .. nf_{k-1}] }             anonymity bookkeeping
    participant_0 action .. participant_{k-1} action      each signed by its owner
  every action lands on ONE block timestamp; FIFO temporal matching has nothing
  to order on; the rotating gasless relay removes the payer/fingerprint signal;
  the fixed ActionClass + SizeBucket removes the amount/shape signal
```

Two honest properties of the crowd path: the participant signs their own action
(so the action stays attributable to that wallet; what is defeated is the
per-actor timing/amount/fingerprint signal and copy-trade shadowing, not the
signer), and `SettleEpoch` proves batching and anti-replay, not membership.

### 4.2 ZK opt-in path (`CommitDeposit` / `SettleZk`)

```
CommitDeposit
  participant (client-side):
    secret       <- random 32 bytes
    actionHash   = transfer_action_hash(recipient, amount)     binds a FRESH output
    C = commit_with_action_hash(secret, actionHash, epoch)     Poseidon leaf
    -> signs and submits CommitDeposit{C, amount}; escrows `amount`; pays the fee
  the pool records the leaf index and pre-insert frontier snapshot for proving

prove (client-side, off-chain, gasless for the participant)
  rebuild the Merkle inclusion path (frontier snapshot, or full tree from leaves)
  confirm the path root is a known recent root on-chain
  snarkjs groth16 fullprove + verify against the built circuit
  emit the SettleZk instruction bytes for the relay to submit (never self-submit)

SettleZk (relay-submitted, after the window closes)
  verify: authority, epoch encodings agree, window closed, root is recent,
          recomputed actionHash == proof's actionHash, nullifier unspent,
          Groth16 proof verifies against [root, nullifierHash, actionHash, epoch]
  execute: release the escrow to the FRESH recipient (direct lamport move)
  no participant signs at settle; the deposit is visible but WHICH committer
  settled is cryptographically hidden inside the anonymity set
```

The result is who-initiated unlinkability: the output lands at a fresh address the
committer bound at deposit time, the relay cannot redirect it (actionHash
binding), and no participant signature appears at settle.

---

## 5. Coordinator: crowd-tx composition

`mirror-coordinator` turns individual commits into a shared anonymity set. Its
privacy jobs map directly onto its modules: shared-epoch batching and the k-floor
gate (`scheduler::Coordinator::on_slot`), the honest `KAnon` accounting
(`pool::CommitPool`), the rotating gasless relay (`config::FeePayerRing`), and the
normalized transaction shape (`config::TxProfile`, `cu_limit = 400_000`,
`priority_fee = 10_000`). The scheduler is generic over a `SettleSubmitter` seam,
so the identical batching and k-floor logic runs against an in-memory submitter in
tests and the real crowd-path submitter in production, with no validator needed to
test the privacy-critical decisions.

The crowd path (`crowd.rs`) composes one settlement as a single v0 transaction:

```
  ix[0]  ComputeBudget SetComputeUnitLimit   (TxProfile, pool-wide)
  ix[1]  ComputeBudget SetComputeUnitPrice   (TxProfile, pool-wide)
  ix[2]  SettleEpoch { epoch, [nullifier..] } (mirror-pool program)
  ix[3..]  participant_i behavior instruction(s)  (identical shape per participant)
```

The signer set is `N + 1`: the rotating coordinator fee-payer at index 0 (which
also fills the `SettleEpoch` authority and payer roles, collapsing both onto one
rotating key rather than pinning a fixed authority that would itself become a
stable cluster label) plus each participant, who signs only their own action.
Solana forbids loading a signer through an Address Lookup Table, so every signer is
a static key; the pool's shared, non-signer accounts (program ids, the Pool PDA,
the clock sysvar, the shared sink) live in the ALT, while per-settlement accounts
that change every epoch (the Epoch PDA and the per-participant Nullifier PDAs) stay
in the static key list. `build_crowd_message` fails closed if a built message
would exceed the 1232-byte packet limit; for the fixed-shape `PlainTransfer`
baseline that caps one settlement at `PLAIN_TRANSFER_MAX_PER_TX = 4` participants
(five serialize to 1234 bytes, two over). `plan_settlements` chunks a larger epoch
into transaction-sized groups with disjoint nullifier subsets whose union is the
whole epoch; the ALT is created once by `setup_pool_alt` and reused for every
settlement.

---

## 6. CLI: the `prove` flow

`mirror-cli` is the participant surface: `init-pool` (admin), `commit` (crowd),
`deposit-commit` (ZK opt-in escrow), `prove` (ZK opt-in proof), and `status`. The
`prove` subcommand is where the ZK path's client-side work happens, and it never
self-submits: settlement is paid for and signed by the rotating gasless relay, so
`prove` *emits* the `SettleZk` instruction for the relay instead of sending it.

The pipeline:

1. Recompute this note's `actionHash`, `nullifierHash`, and commitment leaf from
   the secret and the bound `(recipient, amount)`, and confirm the leaf matches
   the note's commitment.
2. Rebuild the Merkle inclusion path off-chain, either by walking the frontier
   snapshot the note captured at commit time, or by rebuilding the whole tree from
   a `--leaves` set to prove against the current root. Self-check that the path
   verifies to its own root, then confirm the pool currently accepts that root
   (current root or in the ring).
3. Generate the Groth16 proof by shelling out to `snarkjs groth16 fullprove`
   against the built `membership.wasm` + `membership_final.zkey`, then verify it
   with `snarkjs groth16 verify` and fail loudly unless it reports OK. Cross-check
   snarkjs's public signals against the computed `[root, nullifierHash,
   actionHash, epoch]`.
4. Serialize the proof (proof A pre-negated) plus public inputs into the exact
   `SettleZk` instruction bytes and emit the bundle (data + accounts) for the relay
   to submit.

---

## 7. Poseidon scheme and on-chain Groth16

Both paths hash with circomlib Poseidon over the BN254 scalar field, the exact
scheme the membership circuit enforces:

```
commitment    = Poseidon(secret, actionHash, epoch)   // the Merkle leaf
nullifierHash = Poseidon(secret, epoch)               // epoch-scoped tag
Merkle node   = Poseidon(left, right)
actionHash    = Poseidon(recipientHi128, recipientLo128, amount)   // ZK transfer binding
```

All values are canonical 32-byte big-endian encodings of BN254 scalars, which is
the byte order circom/snarkjs and `groth16-solana` use for public inputs and the
order the on-chain `sol_poseidon` syscall and the host `light-poseidon` crate use
with big-endian selected. On-chain the frontier accumulator and the `actionHash`
recomputation call `sol_poseidon`; on the host `mirror-core` calls `light-poseidon`.
The two are byte-identical, and both match the circuit: this is pinned by a fixture
cross-check test that reproduces the committed circuit's `nullifierHash`,
commitment leaf, and Merkle root exactly, plus a `transfer_action_hash` test
against the circuit's own `actionHash`.

`SettleZk` verifies the membership proof with `groth16-solana` (v0.2.0 byte
layout) via the `alt_bn128` (BN254) pairing syscalls. The verifying key is
vendored into the program from `circuits/artifacts/vk.rs`; proof A is pre-negated
in the emitted layout so the on-chain path needs no ark serialization at runtime.
Verification is 4 public inputs in the fixed order and runs in under about 200K
compute units, comfortably inside a transaction's CU budget alongside the
settlement work. The circuit (`circuits/membership.circom`, depth 20, 11522 R1CS
constraints) enforces leaf recomputation, Merkle inclusion, and the nullifier
relation. Its trusted setup is a reproducible development/test setup (the phase-2
entropy is public), not a secure ceremony; a real multi-party ceremony is roadmap
work (`docs/ROADMAP.md`).

---

## 8. Solana specifics

- **ALT + v0 transactions under 1232 bytes.** A settlement references the Pool
  PDA, the Epoch PDA, one Nullifier PDA per participant, the clock, the shared
  sink, and each participant's action accounts. That account list exceeds a legacy
  transaction quickly, so settlement uses a versioned (v0) transaction with an
  Address Lookup Table to keep shared accounts out of the static list. Everything
  must still fit the 1232-byte packet limit, which caps participants per crowd
  transaction and drives the coordinator's chunking math.
- **Jito 5-tx bundle cap, so N-party atomicity is program-side.** A Jito bundle
  atomically lands at most 5 transactions, so N-party settlement for N greater
  than about 5 cannot rely on bundle atomicity. `SettleEpoch` therefore takes the
  full nullifier array and settles all intents in one instruction: a no-show
  simply forfeits its slot and fee without stalling the epoch, and there is no
  per-party transaction an attacker can isolate.
- **On-chain Groth16 via alt_bn128.** The ZK opt-in path verifies a Groth16 proof
  on-chain through the `alt_bn128` syscalls (about 170K to 500K CU for a 128-byte
  compressed proof), cheap enough for per-membership verification.
- **Signers are never in the ALT.** Solana forbids loading a signer through a
  lookup table, so participant wallets and the rotating fee-payer are always static
  keys; only shared non-signer accounts are looked up.

---

## 9. Component status

| component | path | status |
|-----------|------|--------|
| shared types + wire format + Poseidon + tests | `crates/mirror-core` | **Implemented** - `commit`/`nullifier`/`transfer_action_hash`, `ActionClass`/`SizeBucket`, `Epoch`/`EpochSchedule`, `KAnon`, `wire`; circomlib-Poseidon; fixture cross-check against the circuit |
| on-chain program (both settle paths) | `programs/mirror-pool` | **Implemented** - `InitPool`/`Commit`/`SettleEpoch`/`CommitDeposit`/`SettleZk`/`ClaimReward`; frontier accumulator + 32-root ring; Epoch/Nullifier/Dwell PDAs; on-chain k-floor, double-settle prevention, per-nullifier anti-replay; on-chain Groth16 (alt_bn128) |
| membership circuit + setup + verifying key | `circuits/` | **Implemented** - depth-20 Poseidon membership circuit, dev/test Groth16 setup, committed proof fixture + vendored `vk.rs` |
| gasless batch coordinator | `crates/mirror-coordinator` | **Implemented** - slot-window scheduler, real-k floor gate, rotating fee-payer, normalized `TxProfile`, atomic crowd-tx composition (N+1 signer, ALT, `plan_settlements`), mockable RPC boundary |
| pooled-action behaviors | `crates/mirror-behaviors` | **Implemented** - `Behavior` trait + `PlainTransfer` (soak baseline), Jupiter swap, jitoSOL stake adapters; bucketed amounts |
| participant CLI | `crates/mirror-cli` | **Implemented** - `init-pool`/`commit`/`deposit-commit`/`prove`/`status`; prove rebuilds the path, runs snarkjs, emits `SettleZk` |
| adversarial harness | `crates/mirror-harness` | **Implemented** - FIFO, amount, gas-payer, and wallet-fingerprint attacks measuring attacker advantage over 1/k, Baseline vs mirror-pool; FIFO advantage collapses to about 0 under shared-epoch batching |
| anti-Sybil entry fee + dwell reward | `programs/mirror-pool` + `docs/INCENTIVES.md` | **Implemented** (crowd path) - entry-fee split, reward pool, dwell accrual, drain-safe `ClaimReward`; ZK-path reward is designed, not implemented |
| Surfpool soak | `tests/` | **In progress** - automated end-to-end multi-epoch run against a local mainnet mirror |

The harness implements four attacks today (FIFO temporal matching, amount
matching, gas-payer reuse, wallet fingerprinting); temporal-correlation,
common-funding, and a learned classifier are named extensions on the same `Attack`
trait, and the docs say so plainly rather than claiming they run.

---

## 10. Prior art

mirror-pool is an independent clean-room implementation built entirely from public
techniques and papers. Each mechanism traces to a documented attack or a public
precedent:

- **Shared-epoch batching** defeats FIFO temporal matching (the strongest
  empirical Tornado attack, up to 49% on small pools; arXiv:2510.09433). The
  batch-clearing model follows Penumbra, where all swaps in a block clear at one
  price so per-user ordering and attribution are eliminated by construction.
- **Fixed `ActionClass` + `SizeBucket`** is the behavioral analog of fixed
  denominations, backed by the public finding that variable and round-number
  amounts leak a large fraction of anonymity to amount-matching (Wang et al.,
  arXiv:2201.09035; the Tornado study, arXiv:2510.09433) while fixed/stratified
  denominations sharply reduce it.
- **Gasless rotating relay + normalized tx shape** closes the not-using-a-relayer
  deanonymization vector and the 37% wallet-fingerprint attack, while rotation
  prevents the relayer from becoming a clustering consolidation node.
- **Frontier Merkle accumulator, nullifier anti-replay, on-chain Groth16, and the
  membership proof** follow Tornado Cash (commitment / nullifier / Merkle
  anonymity set), Zcash Sapling (Merkle accumulator shape), the
  Lightprotocol/groth16-solana crate (on-chain Groth16 via the alt_bn128
  syscalls), circomlib and snarkjs (Poseidon and Groth16), and standard Solana
  docs (Address Lookup Tables, versioned transactions, Jito bundles).
