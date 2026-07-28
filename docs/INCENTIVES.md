# Mirror Pool Incentives

This document specifies the economic layer that sits on top of the anonymity mechanics in
`docs/THREAT_MODEL.md`: the anti-Sybil entry cost, the participation (dwell) reward, and the
honest real-k reporting that ties them together. It states plainly what is **implemented**
on-chain today and what is **designed** for the anonymous path but not yet shipped, so no
reader mistakes a plan for a guarantee.

The guiding rule from the threat model (Section 7) is inverted into a design constraint here:
an incentive must reward behavior that increases the **measured** anonymity set (staying,
paying the per-identity cost), and it must never pay in a way that itself deanonymizes the
recipient. Pool size is not anonymity, so no reward is paid for merely showing up.

Every field and instruction named below is additive: the incentive layer is appended after
the Pool account's root-history ring, so no pre-existing account offset shifts and callers
that ignore it keep working unchanged.

---

## 1. Anti-Sybil entry cost with a reward split (IMPLEMENTED)

### The cost

Each commit carries a fixed, non-refundable `entry_fee` (lamports), set once at `INIT_POOL`
and immutable thereafter. Filling an epoch with `k-1` Sybil wallets costs the attacker
`(k-1) * entry_fee` per epoch, forever, because the honest floor rolls the epoch forward
until it is met (`docs/THREAT_MODEL.md` Sections 5 and 7). A zero `entry_fee` disables the
cost (and, transitively, the reward pool).

Both commit paths collect the fee: the crowd `COMMIT` and the ZK opt-in `COMMIT_DEPOSIT`
(the latter on top of its escrow, so the escrow is preserved in full for `SETTLE_ZK`). Paying
the same per-identity cost on both paths keeps the anti-Sybil property uniform.

### The split

`INIT_POOL` also fixes `reward_bps`, the basis-point share of each entry fee that accrues to
an on-chain reward pool. The split is:

```text
reward_share    = entry_fee * reward_bps / 10_000   (floor)
settlement_part = entry_fee - reward_share
```

`reward_share` is added to the Pool's `reward_pool_lamports` counter; `settlement_part` stays
in the pool balance as the un-earmarked settlement reserve (it offsets relay and settlement
cost). `reward_bps` must be `<= 10_000`; `INIT_POOL` rejects anything larger. A zero
`reward_bps`, or a zero `entry_fee`, leaves `reward_pool_lamports` at zero cleanly.

The lamports themselves move into the pool as part of the ordinary fee transfer;
`reward_pool_lamports` is an accounting sub-total of the pool balance that is earmarked for
rewards, never a separate account.

### Pool account fields (additive)

Appended after the root-history ring, so offsets `0..1762` are byte-identical to the
pre-incentive layout:

| offset | size | field | meaning |
|---|---|---|---|
| 1762 | 2 | `reward_bps` | entry-fee share (bps) sent to the reward pool; fixed at init |
| 1764 | 8 | `reward_pool_lamports` | lamports earmarked for participation rewards |
| 1772 | 8 | `total_unclaimed_dwell` | sum of all participants' unclaimed dwell (reward denominator) |

The account grows from 1762 to 1780 bytes. Any off-chain mirror of the Pool layout that
does a strict-length decode must bump its length constant to 1780; the field offsets it
already reads are unchanged.

---

## 2. Participation reward: dwell (CROWD path IMPLEMENTED, ZK path DESIGNED)

The incentive rewards **dwell**: staying in the pool across epochs rather than committing
once and leaving. Dwell that persists thickens future epochs, which is exactly the behavior
that raises measured anonymity.

### 2.1 Crowd path (IMPLEMENTED)

On the crowd path the committing wallet is already an on-chain signer, so a per-identity
counter reveals nothing that the commit transaction did not already reveal (membership is
public; see `docs/THREAT_MODEL.md` Section 4). We therefore track dwell directly.

**Dwell PDA.** One account per `(pool, participant)` at seeds `["dwell", pool, participant]`.
It stores the participant's `dwell` (distinct epochs committed into), `claimed_dwell` (dwell
already converted to a reward), and `last_epoch` (dedupe cursor).

**Accrual.** `COMMIT` takes the Dwell PDA as an OPTIONAL trailing account. When present, the
commit counts once toward the participant's dwell, and only when the current epoch is
strictly newer than `last_epoch`: a second commit in the same window is a no-op, so dwell is
exactly "distinct epochs committed into". Dwell can advance **only** through a real,
fee-paying commit; there is no standalone "bump my dwell" instruction, so an attacker cannot
mint dwell for free to drain the reward pool. Omitting the account leaves the commit exactly
as before (backward compatible).

Each accrual also increments the Pool's `total_unclaimed_dwell`, the shared denominator.

**Claim.** `CLAIM_REWARD` pays a claimant a dwell-proportional, drain-safe share of the
reward pool. With

```text
d = dwell - claimed_dwell        this participant's UNCLAIMED dwell
U = total_unclaimed_dwell        sum of everyone's unclaimed dwell
R = reward_pool_lamports         lamports earmarked for rewards
payout = floor(R * d / U)
```

the handler then sets `R -= payout`, `U -= d`, and `claimed_dwell = dwell`.

Properties, each enforced in code and covered by a mollusk test:

- **Drain-safe by construction.** `d <= U` (the invariant maintained by accrual and this
  decrement), so `payout <= R`: a claim can never pay more than the reward pool holds. A
  checked subtraction and an explicit rent-exemption guard back this up, so the pool is never
  drained below rent and never goes negative.
- **Proportional.** The payout is the participant's share of the CURRENT reward pool by their
  share of the CURRENT unclaimed dwell. Two participants with dwell 2 and 1 split a pool
  2-to-1.
- **Double-claim rejected.** After a full claim `d == 0`, so a repeat call fails closed with
  `NothingToClaim`; no lamports move.
- **Over-claim impossible.** `payout <= R`, and an empty pool or a share that floors to zero
  pays nothing and consumes no dwell (the participant can claim later instead of burning
  dwell for zero).
- **Staying pays more.** Committing again in a later epoch accrues fresh unclaimed dwell to
  claim later, so the reward grows with continued participation, which is the point.

Anonymity note: `CLAIM_REWARD` links a wallet to a payout, but that wallet's crowd-path
commits were already public. It reveals no new bijection between committers and settled
outputs, which is the property the pool actually sells (`docs/THREAT_MODEL.md` Section 4).

### 2.2 ZK opt-in path (DESIGNED, NOT IMPLEMENTED)

The ZK opt-in path is anonymous by construction: `SETTLE_ZK` proves membership without
revealing which committer settled. Tying a reward to an on-chain identity there (a Dwell PDA
keyed by a pubkey) would re-introduce exactly the linkage the path exists to remove. So the
ZK path funds the reward pool through its entry fee (Section 1) but has **no** `CLAIM_REWARD`
and no Dwell PDA. It is deliberately left as a documented design, not shipped code.

The anonymity-preserving equivalent, for a future version, mirrors the membership proof:

- **Dwell/age commitment.** At `COMMIT_DEPOSIT` the participant commits not only to their
  action but to a dwell/age value (for example the epoch of first deposit), inside the same
  Poseidon commitment scheme the membership circuit already uses.
- **Reward-claim proof.** A separate Groth16 circuit proves, in zero knowledge, "I am a
  member whose committed dwell/age is at least T, and here is a fresh nullifier for this
  reward epoch," without revealing which member. The public inputs bind a recent root
  (reusing the Pool's root-history ring), a reward-claim nullifier (epoch-scoped, so each
  membership claims at most once, exactly like `SETTLE_ZK`), and the payout amount derived
  from the proven dwell against the on-chain reward-pool accounting.
- **Why it does not deanonymize.** The claim carries a proof and a fresh nullifier, never an
  identity, and pays out to a client-generated fresh address, so it has the same
  unlinkability as `SETTLE_ZK` - including the same limits, since it would hide the
  claimant only among the members its own public inputs leave standing (see
  `docs/THREAT_MODEL.md` section 4). The reward is a function of proven dwell, not of who
  is claiming.

This is a real extension of the existing pattern (proof + root-history + nullifier +
fresh-recipient binding), not new cryptography. It is described here so the ZK path's
incentive is honest about being designed rather than delivered. Shipping it is gated on a
second circuit and its trusted setup; until then the ZK path's only incentive is that its
fee subsidizes the shared reward pool.

---

## 3. Honest real-k reporting (IMPLEMENTED off-chain)

Rewards attract privacy-indifferent users if the pool advertises a number it cannot defend
(`docs/THREAT_MODEL.md` Section 7, reference [2]). The metric, not pool size, is the success
criterion, so the coordinator reports the honest number:

- **real_k, never nominal.** `mirror_core::KAnon { nominal, excluded }` with
  `real_k() = nominal - excluded`. The coordinator computes `excluded` as the operator-owned
  decoys plus any commit flagged Sybil-suspected by off-chain heuristics, and every
  settlement outcome and log line surfaces `real_k` (alongside `nominal` and `excluded` so
  the gap is auditable). Users are shown `real_k`; `nominal` is logged only as the upper bound
  it is.
- **The floor gates on real_k.** An epoch settles only if `real_k >= k_floor`; otherwise it
  rolls forward. Detected Sybils are excluded from the REPORTED anonymity even though their
  commits still settle on-chain as real nullifiers: the reported number is the honest one, not
  the transaction count.
- **Bounded scope (documented limitation).** `excluded` reflects only what off-chain
  heuristics DETECT. The strongest Sybil anchor, a common on-chain funding source, is out of
  scope here: a commit exposes only a 32-byte commitment, so same-funding-source clustering
  is not computable from the commit stream the coordinator sees (`docs/THREAT_MODEL.md`
  Sections 3.5 and 7). Undetected Sybils therefore inflate `real_k`. This accounting can only
  lower the reported number toward the truth, never prove the absence of Sybils. The honest
  worst-case statement a participant should rely on is: my anonymity is at least the number of
  participants I personally believe are independent, and at most `real_k`.

---

## 4. Implemented vs designed, at a glance

| Item | Status |
|---|---|
| `entry_fee` per commit (crowd + ZK) | Implemented (on-chain) |
| `reward_bps` split into `reward_pool_lamports` at `INIT_POOL` | Implemented (on-chain) |
| Dwell PDA + per-epoch accrual in `COMMIT` | Implemented (on-chain) |
| `CLAIM_REWARD` dwell-proportional, drain-safe payout (crowd) | Implemented (on-chain) |
| ZK-path anonymity-mining reward (dwell/age proof) | Designed only (this doc, Section 2.2) |
| real_k reporting + Sybil exclusion + floor gate | Implemented (coordinator) |
| Same-funding-source Sybil detection | Out of scope on-chain; documented limitation |
