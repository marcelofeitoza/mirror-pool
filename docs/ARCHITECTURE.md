# mirror-pool architecture

mirror-pool is "Tornado Cash for behavior, not funds." A classic mixer breaks the
link between a deposit and a withdrawal of *value*. mirror-pool attacks the
*behavioral* legibility of an on-chain action instead. N participants voluntarily
pool the same action into one synchronized epoch; an observer sees N identical
actions land together and cannot extract the per-initiator signal that
chain-analysis tools rely on: timing, ordering, amount, gas payer, and wallet
fingerprint.

The funds are visible, the action is visible, the aggregate is visible. What is
destroyed depends on the path, and the two are not equivalent: the crowd path
destroys the per-actor *signal* while leaving each action attributable to the
wallet that signed it, and the ZK opt-in path destroys the attribution itself.
mirror-pool delivers this with two settlement paths that share one accumulator,
one epoch clock, and one anti-Sybil economy:

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
| `6` | `InitValuePool` | operator | create the confidential ValuePool (its own value-note accumulator + 32-root ring) and its vault PDA, and fix `authority`, `fee`, and `denomination` forever |
| `7` | `Transact` | rotating relay | verify one 2-in/2-out JoinSplit Groth16 proof on-chain, spend two input nullifiers, insert two output commitments, and move lamports per the signed `publicAmount` (shield / transfer / unshield) |

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
3. Generate the Groth16 proof in-process in pure Rust (`ark-circom` builds the
   witness from the built `membership.wasm` inside a `wasmer` VM and reads the
   proving key from `membership_final.zkey`; `ark-groth16` over `ark-bn254`
   proves with the snarkjs-compatible `CircomReduction` QAP), then verify it
   in-process against the same verifying key and fail loudly unless it passes.
   Cross-check the circuit's public signals against the computed `[root,
   nullifierHash, actionHash, epoch]`. No Node process is spawned. `--use-snarkjs`
   selects the legacy `snarkjs groth16 fullprove` shell-out instead.
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
relation. The verifying key that is committed and deployed comes from a reproducible
development/test setup (the phase-2 entropy is a hard-coded public string), not from
a secure ceremony. A real multi-party phase-2 ceremony is implemented and runnable
(Section 8.5, `docs/CEREMONY.md`); it has not been run for production, so this
caveat stands until a ceremony output is exported and the program is redeployed.

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

## 8.5 Trusted-setup ceremony (`crates/mirror-ceremony`)

Groth16 buys small, cheap on-chain verification at the cost of a per-circuit
structured reference string whose sampling secrets ("toxic waste") must be destroyed.
`crates/mirror-ceremony` implements a distributable multi-party **phase-2** ceremony
for that, in pure Rust, for both circuits. Full guide: `docs/CEREMONY.md`.

- **Phase 1 is imported, not generated.** `ceremony start` takes a public
  powers-of-tau file and records its SHA-256, curve, power and contribution count
  into the transcript; `ceremony inspect-ptau` reads the contributor names out of the
  file's own section 7 so they can be compared against the published list. A file
  with fewer than two contributions is refused unless explicitly overridden.
- **The initial phase-2 key is reproducible.** It is the output of
  `snarkjs groth16 setup <r1cs> <ptau>`, which is deterministic, so the start of the
  chain can be re-derived from public inputs rather than trusted. `ark_circom::read_zkey`
  imports it; that is the only snarkjs-produced input to the ceremony.
- **A contribution moves only `delta`.** `delta_g1` and `delta_g2` are multiplied by
  a fresh secret `s`; `h_query` and `l_query` are multiplied by `s^-1`. Everything
  else (`alpha_g1`, `beta_g1`, `beta_g2`, `gamma_g2`, `gamma_abc_g1`, `a_query`,
  `b_g1_query`, `b_g2_query`) is byte-identical from the initial key to the final
  key. In the exported verifying key, only `vk_delta_2` differs.
- **Each contribution proves knowledge of its ratio.** A Schnorr proof over the base
  `delta_g1` of the previous key, with a Fiat-Shamir challenge bound to the running
  transcript hash, the contribution index, the contributor identifier, and the step's
  kind and provenance - so a proof cannot be replayed at another position,
  re-attributed to another operator, or carried over to a step relabelled from
  "beacon" to "entropy contribution".
- **A beacon is final.** Once the closing beacon is in the transcript, `contribute`
  refuses to append anything and `verify` rejects a chain with a step after the
  beacon or with more than one beacon.
- **The chain is SHA-256 over a canonical serialization** (domain tag, fixed-width
  values raw, variable-length values length-prefixed). The final chain hash is the
  value a coordinator publishes.
- **Verification is reproducible by anyone** holding the transcript, the initial key
  and the final key: chain links, entry hashes, kind/provenance agreement, every proof
  of knowledge, a pairing same-ratio check per step, beacon recomputation, the
  beacon-is-final rule, endpoint digests, untouched-part equality, and a batched
  pairing check that the query vectors were divided by the accumulated ratio.
  Tampered deltas, forged or replayed proofs, reordered chains, truncated chains,
  post-beacon steps and relabelled beacons are each rejected, each with a test.
  `ceremony verify-transcript` runs everything that does not need the key files, for
  a third party who has only the published `transcript.json`.
- **The reported number is an independent-contributor count**, not a contribution
  count. Contributions sharing an identity, a machine fingerprint or a
  proof-of-knowledge nonce are merged; deterministic and beacon steps are never
  counted, and a step counts only when its kind and its self-reported entropy source
  agree that it is not a beacon. It is a heuristic against accidental self-inflation
  and an upper bound on distinct secret holders, explicitly not a Sybil defence. A
  verifier who supplies the pre-committed beacon value additionally gets a mechanical
  check that no counted step is the public beacon scalar under another name; without
  it, the two are indistinguishable and the report says so.
- **Keys travel in a `.mpk` container** around arkworks' canonical uncompressed
  `ProvingKey<Bn254>` serialization (arkworks has no zkey writer). Verifying keys are
  exported in both the snarkjs `verification_key.json` shape and the
  `groth16-solana` byte layout the program embeds. Proving under a ceremony key goes
  through `mirror-cli prove --proving-key` or `ceremony prove-check`.

`ceremony prove-check` closes the loop: it proves the membership circuit under a
ceremony-produced key and runs the exact on-chain `groth16-solana` verifier over the
result against the ceremony-exported verifying key.

**Status.** The machinery is built and tested; no production ceremony has been run,
so the committed and deployed verifying keys are still dev-setup keys. The
transcripts of the local demonstration run are committed under `docs/ceremony-run/`
and are checked by the test suite; the keys they refer to are not published, so the
four key-level checks are not third-party reproducible for that run
(`docs/PROOF.md`).

---

## 9. Confidential-value layer

Everything above works on the *behavioral* axis (the crowd path removing the
per-actor signal, the ZK opt-in path removing the attribution) while leaving every
amount public (Non-goal 1 of the threat model). The confidential-value layer is the
optional complement: a Tornado-Nova-style shielded pool that hides *how much*
moves. It is a
SEPARATE subsystem from the behavioral Pool (its own account, its own accumulator,
its own two instructions), so a deployment can run the behavioral pool, the
confidential pool, or both. A confidential transfer settles through the same
gasless relay with no user signature and carries `publicAmount == 0`, so an
observer learns neither which wallet initiated *that transfer* nor how much it
moved. Composing the two axes into one action means pairing this layer with the ZK
opt-in path; paired with the crowd path it hides the amounts, but the pooled action
itself still carries the participant's signature. The value lives only in the on-chain
commitments and the encrypted note payloads. The layer is a clean-room
implementation of the public, open-source Tornado-Nova transaction circuit (the
standard Poseidon JoinSplit), cited as prior art.

### 9.1 ValuePool and vault accounts

`InitValuePool` (tag 6, body 17 bytes: `[fee (u64 LE)][denom_flag (u8)][denomination
(u64 LE)]`) creates two PDAs. The **ValuePool** (`[b"vpool", authority]`) is a
value-note accumulator fully independent of the behavioral Pool; the behavioral Pool
never grows from confidential activity. A separate **vault** PDA (`[b"vvault",
vpool]`, zero data, program-owned) holds the commingled lamports so the data
account's balance stays pure rent. `authority` (the Transact relay), `fee`, and
`denomination` are fixed at init.

```
offset  size       field              meaning
0       1          version            0 = uninitialized, 1 = v1
1       32         authority          relay pubkey allowed to submit Transact
33      8          fee                relay fee (lamports) bound into ext-data
41      1          denom_flag         0 = None, 1 = Some(denomination)
42      8          denomination       fixed-denom magnitude (0 when None)
50      1          bump               ValuePool PDA bump
51      1          vault_bump         vault PDA bump
52      8          commitment_count   total value-note leaves ever appended
60      32         current_root       frontier accumulator root (latest)
92      640        filled_subtrees    frontier right-edge siblings (DEPTH * 32)
732     4          root_head          ring index of the next root write
736     1024       root_ring          recent-root ring (ROOT_HISTORY_SIZE * 32)
```

The value accumulator reuses the exact `state::merkle` frontier insert the
behavioral pool uses (`DEPTH = 20`, up to about 1.05M leaves) and keeps its own
32-root history ring, because a JoinSplit proof is made against a root snapshot and
must still verify after later appends.

### 9.2 The value-note (UTXO) scheme

A value note is `{ amount, public_key, blinding }`, a shielded UTXO. Its owner holds
a value keypair, distinct from any Solana wallet:

```
public_key = Poseidon(private_key)                        // 1-input, t=2
commitment = Poseidon(amount, public_key, blinding)       // 3-input, t=4  (Merkle leaf)
signature  = Poseidon(private_key, commitment, leafIndex) // 3-input, t=4
nullifier  = Poseidon(commitment, leafIndex, signature)   // 3-input, t=4
```

The nullifier is bound to both the owner (through `signature`, which needs the
private key) and the leaf position, so the same note at a different index yields a
different nullifier and a double-spend collides. A dummy input has `amount == 0`;
the circuit skips its Merkle-membership check, which is what lets a shield spend two
dummy inputs.

### 9.3 publicAmount and extDataHash

`publicAmount` is the net public value crossing the shielded boundary, encoded as a
signed BN254 field element with the standard FIELD_SIZE offset:

```
shield   (deposit v)  : publicAmount = v          (top byte 0, in [0, 2^248))
unshield (withdraw v) : publicAmount = r - v      (in (r - 2^248, r))
transfer              : publicAmount = 0
```

The two ranges are disjoint, so the on-chain decoder recovers the sign
unambiguously and rejects anything in neither range or exceeding a `u64`.
`extDataHash` is `keccak256(recipient || relayer || fee_be || enc0 || enc1) mod r`;
the program recomputes it from the accounts and payloads it receives and requires
equality, so the relay cannot retarget the recipient, change the fee, or swap the
encrypted payloads. The value path uses the same host and on-chain Poseidon and the
same big-endian scalar encoding as the behavioral membership path (section 7).

### 9.4 Transact (tag 7): one 2-in/2-out JoinSplit

A single universal statement, distinguished only by the signed `publicAmount`,
covers all three operations: **shield** (`+v`, two dummy inputs, lamports depositor
-> vault), **transfer** (`0`, real inputs and outputs, no lamports move), and
**unshield** (`r - v`, lamports vault -> recipient). The instruction body (after the
tag byte) is:

```
[publicAmount(32)][extDataHash(32)][root(32)]
  [inputNullifier[0](32)][inputNullifier[1](32)]
  [outputCommitment[0](32)][outputCommitment[1](32)]
  [proof_a(64)][proof_b(128)][proof_c(64)]
  [fee(8 LE)]
  [enc0_len(2 LE)][enc0][enc1_len(2 LE)][enc1]
```

Accounts: `0` vpool (writable), `1` authority (signer, writable; MUST equal
`vpool.authority`, pays nullifier rent), `2`/`3` the two value nullifier PDAs
(writable; seeds `[b"vnf", vpool, inputNullifier]`), `4` recipient (writable;
credited on unshield), `5` depositor (signer + writable for a shield only), `6`
system program, `7` clock, `8` vault (writable). The handler's checks run in a
fixed, fail-closed order: (1) authority is a signer and equals `vpool.authority`;
(2) `root` is a known recent root; (2b) if a denomination is pinned, the decoded
deposit/withdraw magnitude equals it (`DenominationMismatch`, checked before the
expensive work); (3) the recomputed `extDataHash` equals the proof's; (4) create
each input nullifier PDA (an all-zero dummy sentinel is skipped, `NullifierSpent`
on replay); (5) the Groth16 proof verifies against the seven public inputs; (6)
both output commitments are appended to the value accumulator; (7) lamports move
per the decoded `publicAmount`, keeping the vault rent-exempt; (8) enc0/enc1 are
emitted as return data for client discovery.

The JoinSplit circuit (`circuits/transaction.circom`, depth 20, 27278 R1CS
constraints, 7 public inputs, 56 private inputs) enforces, per input, the key,
commitment, signature, and nullifier relations plus Merkle inclusion when
`amount != 0`; per output, the commitment and a 248-bit range bind; and globally,
value conservation `sum(inAmount) + publicAmount == sum(outAmount)`, distinct input
nullifiers, and tamper-evidence of `extDataHash`. On-chain `Transact` verifies the
proof with `groth16-solana` via the alt_bn128 pairing syscalls against the vendored
`transaction_vk.rs`, in the fixed public-input order:

```
[root, publicAmount, extDataHash,
 inputNullifier[0], inputNullifier[1],
 outputCommitment[0], outputCommitment[1]]
```

`proof_a` is emitted pre-negated so the program needs no runtime ark
serialization. The deployed verifying key comes from the same reproducible
development/test setup as the membership circuit (its phase-2 entropy is a public
string), so it MUST NOT secure real value. The multi-party ceremony in Section 8.5
supports this circuit as an independent second transcript; running it and redeploying
is what closes the caveat.

### 9.5 Encrypted notes and discovery

Each output commitment is opaque on-chain, so the sender posts an encrypted note
blob (the two `enc` fields, bound into `extDataHash`) that lets the recipient
discover and rebuild the note. A recipient address is a pair of keys: the BN254
**value** key that authorizes spending (and that the commitment binds) and an
X25519 **viewing** key used only to encrypt and discover notes off-chain. Splitting
them lets a recipient hand the viewing key to an auditor or watch-only wallet
without granting spend authority. The blob is ECIES (X25519 ECDH -> HKDF-SHA256 ->
ChaCha20-Poly1305): a fresh ephemeral key per message makes the AEAD `(key, nonce)`
pair unique by construction, so nonce reuse is impossible. The plaintext is the 40
bytes the recipient does not already know, `amount(8, big-endian) || blinding(32)`,
and the on-chain blob is a fixed 100 bytes (`ephemeral_pub(32) || nonce(12) ||
ct+tag(56)`), well under the 256-byte per-blob cap. The recipient trial-decrypts
every blob with their viewing secret (`scan`), keeps the hits, and rebuilds each
note's commitment from their own value key to locate its leaf and later spend it.

### 9.6 Fixed-denomination mode (amount k-anonymity)

Setting `ValuePool.denomination = Some(d)` at init pins every *public* value
crossing: a shield or unshield must move exactly `d` lamports or the Transact is
rejected on-chain with `DenominationMismatch`. Internal transfers move no public
value (`publicAmount == 0`) and are always allowed. This is the value analog of the
behavioral pool's fixed size buckets: when every deposit and withdrawal is
byte-identical in magnitude, the amount cannot single a participant out. The check
runs before the ext-data recompute, before any nullifier PDA is created, and before
Groth16 verification, so a mismatch fails cheaply with no state change; the CLI
mirrors the same check client-side and refuses a doomed Transact before proving.

### 9.7 CLI and coordinator flow

`mirror-cli` carries the participant surface for the value layer: `value-keygen`,
`init-value-pool`, `shield`, `transfer`, `unshield`, and `scan`. As with the
behavioral `prove`, none of the proving commands self-submit: each rebuilds the
value Merkle path off-chain from the note's captured frontier snapshot, generates
and verifies a Groth16 proof in-process in pure Rust, cross-checks the public signals, and
*emits* the `Transact` instruction bytes plus account list for the relay.
`mirror-coordinator::submit_transact` is the gasless submitter: it wraps the emit in
the same normalized `TxProfile` (identical CU limit and priority fee) as the crowd
path, with the relay authority as fee payer at index 0. A transfer or unshield is
signed ONLY by the relay (there is no user signature, which is the who-initiated
unlinkability), while a shield additionally co-signs the depositor, who authorizes
and funds their own deposit. A Transact uses no Address Lookup Table because its
per-settlement nullifier PDAs change every time, so all its accounts stay static.

### 9.8 Funding rounds: the commit wallet's lamports

The value layer also carries the FUNDING leg of the behavioral protocol, which is
where the strongest real-world identity anchor lives. A participant who tops up
their fresh commit wallet from their main wallet writes that edge into the public
graph, and the common-funding-source heuristic walks it backwards; no amount of
shared-epoch batching at settlement repairs it.

`mirror-cli fund-commit` funds a fresh commit wallet by **unshielding** into it:
it generates the keypair (refusing to clobber an existing one), reads the value
pool's `denomination` from chain, refuses any other amount client-side (the program
would reject it as `DenominationMismatch` anyway), proves the unshield, and emits
the `Transact`. On-chain the sender is the vault PDA and the only signature is the
relay's, so the participant's main wallet appears on no transaction in the path.

`mirror_coordinator::funding::FundingRounds` releases those withdrawals in rounds:

- `accept(slot, request)` validates that the request really is a withdrawal (a
  deposit or an internal transfer is refused before it can burn a relay signature)
  and that it moves exactly the denomination, then batches it into the round
  `slot / round_slots`.
- `on_slot(slot, ...)` releases every round whose window has closed, submitting its
  withdrawals in `release_order` (a deterministic permutation derived from the round
  number and each commit wallet, never the arrival order).
- A round below `min_round_size` rolls FORWARD instead of releasing, exactly like an
  epoch below `k_floor`: a round of one withdrawal is a direct shield-to-unshield
  link no matter how good the cryptography is.

The residual is stated rather than hidden: `publicAmount` is public on both
crossings, so an observer sees the deposits and the withdrawals and is left with a
matching problem. `crates/mirror-harness` measures how much of that matching
survives (`docs/EFFECTIVE_K.md`); under denominated batched rounds the residual is
about 24% of nominal `k` on the rules the protocol enforces (dwell 0, full
adoption) and about 10% if participants also voluntarily dwell two rounds, and
under naive pass-through use of the same pool it is most of it.

**Wiring status.** The two halves above are library primitives, not a running
pipeline. `fund-commit` prints the emitted request and stops there; `FundingRounds`
is a type that a service would drive with a slot clock. No shipped component
connects them - the coordinator binary (`crates/mirror-coordinator/src/main.rs`) is
an in-memory scheduler demo - so no funding round has ever released a withdrawal,
and the live soaks in `docs/PROOF.md` do not exercise this leg. Dwell is not
implemented anywhere: `FundingRoundConfig` has no dwell field, and how long a
participant sits shielded before requesting the withdrawal is entirely their
choice.

---

## 10. Component status

| component | path | status |
|-----------|------|--------|
| shared types + wire format + Poseidon + tests | `crates/mirror-core` | **Implemented** - `commit`/`nullifier`/`transfer_action_hash`, `ActionClass`/`SizeBucket`, `Epoch`/`EpochSchedule`, `KAnon`, `wire`; circomlib-Poseidon; fixture cross-check against the circuit |
| on-chain program (both settle paths) | `programs/mirror-pool` | **Implemented** - `InitPool`/`Commit`/`SettleEpoch`/`CommitDeposit`/`SettleZk`/`ClaimReward`; frontier accumulator + 32-root ring; Epoch/Nullifier/Dwell PDAs; on-chain k-floor, double-settle prevention, per-nullifier anti-replay; on-chain Groth16 (alt_bn128) |
| membership circuit + setup + verifying key | `circuits/` | **Implemented** - depth-20 Poseidon membership circuit, dev/test Groth16 setup, committed proof fixture + vendored `vk.rs` |
| multi-party phase-2 trusted-setup ceremony | `crates/mirror-ceremony` | **Implemented** - public phase-1 import + provenance reader, delta re-randomization, Schnorr PoK bound to contributor, position, kind and provenance, SHA-256 transcript chain, enforced beacon-is-final rule, reproducible verification (PoK + pairing same-ratio + batched query-scaling + optional beacon pre-commitment check), self-run-refusing independent-contributor count, transcript-only verification, snarkjs/`groth16-solana` verifying-key export; driven by `mirror-cli ceremony ...`. NOT yet run for production: the deployed keys are still dev-setup keys |
| gasless batch coordinator | `crates/mirror-coordinator` | **Implemented** - slot-window scheduler, real-k floor gate, rotating fee-payer, normalized `TxProfile`, atomic crowd-tx composition (N+1 signer, ALT, `plan_settlements`), mockable RPC boundary |
| pooled-action behaviors | `crates/mirror-behaviors` | **Implemented** - `Behavior` trait + `PlainTransfer` (soak baseline), Jupiter swap, jitoSOL stake adapters; bucketed amounts |
| participant CLI | `crates/mirror-cli` | **Implemented** - `init-pool`/`commit`/`deposit-commit`/`prove`/`fund-commit`/`status`/`ceremony`; prove rebuilds the path, proves in-process in pure Rust (`ark-circom`/`ark-groth16`, no Node; `--use-snarkjs` is a legacy fallback, `--proving-key` proves under a ceremony key), emits `SettleZk` |
| adversarial harness | `crates/mirror-harness` | **Implemented** - FIFO, amount, gas-payer, and wallet-fingerprint attacks measuring attacker advantage over 1/k, Baseline vs mirror-pool; FIFO advantage collapses to about 0 under shared-epoch batching; plus the effective-k metric whose funding-provenance classes are derived from the funding mechanism's rules (`funding.rs`) with policy, adversary-strength, dwell and adoption ablations |
| funding rounds (funding-provenance path) | `crates/mirror-coordinator` + `crates/mirror-cli` | **Library + CLI only; NOT wired, NOT soaked** - `fund-commit` (fresh commit wallet, proves the unshield, denomination enforced client-side and on-chain, relay-only signature, prints the emitted request) + `FundingRounds` (round batching, minimum-round floor with roll-forward, arrival-independent release order); unit-tested against the mock RPC boundary. Nothing ingests a `fund-commit` request into a `FundingRounds` instance, so no funding round has run and the live soaks in `docs/PROOF.md` do not exercise it. Dwell is participant behaviour with no field and no enforcement. Residual modelled in `docs/EFFECTIVE_K.md` |
| anti-Sybil entry fee + dwell reward | `programs/mirror-pool` + `docs/INCENTIVES.md` | **Implemented** (crowd path) - entry-fee split, reward pool, dwell accrual, drain-safe `ClaimReward`; ZK-path reward is designed, not implemented |
| confidential-value program (ValuePool + Transact) | `programs/mirror-pool` | **Implemented** - `InitValuePool`/`Transact`; separate ValuePool value-note accumulator + 32-root ring + vault PDA; on-chain 2-in/2-out JoinSplit Groth16 (alt_bn128), value nullifier PDAs, `publicAmount` lamport moves, fixed-denomination enforcement (`DenominationMismatch`) |
| confidential JoinSplit circuit + setup + verifying key | `circuits/` | **Implemented** - depth-20 2-in/2-out Tornado-Nova transaction circuit (7 public inputs), dev/test Groth16 setup, committed shield/transfer/unshield fixtures + vendored `transaction_vk.rs` |
| value notes + encrypted notes | `crates/mirror-core` | **Implemented** - `note` (value-note commitment / nullifier / `publicAmount` / `extDataHash`) + `encrypted_note` (ECIES X25519 -> HKDF-SHA256 -> ChaCha20-Poly1305, 100-byte blob, `scan`) |
| confidential CLI | `crates/mirror-cli` | **Implemented** - `value-keygen`/`init-value-pool`/`shield`/`transfer`/`unshield`/`scan`; proves in-process in pure Rust (`ark-circom`/`ark-groth16`, no Node) and emits `Transact` |
| gasless confidential submitter | `crates/mirror-coordinator` | **Implemented** - `submit_transact` (relay-only signer for transfer/unshield, depositor co-sign for shield), normalized `TxProfile`, mockable RPC boundary |
| confidential-value soak | `tests/` | **Implemented** - shield / transfer / unshield + fixed-denomination end-to-end on a local mainnet mirror, 25/25 on-chain assertions (`docs/PROOF.md`) |
| Surfpool soak (behavioral crowd path) | `tests/` | **In progress** - automated end-to-end multi-epoch run against a local mainnet mirror |

The harness implements four attacks today (FIFO temporal matching, amount
matching, gas-payer reuse, wallet fingerprinting); temporal-correlation,
common-funding, and a learned classifier are named extensions on the same `Attack`
trait, and the docs say so plainly rather than claiming they run.

---

## 11. Prior art

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
