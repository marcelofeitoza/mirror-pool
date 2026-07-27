# Association sets: the opt-in compliance layer

mirror-pool ships an OPTIONAL association-set primitive, in the sense of
Buterin, Illum, Nadler, Schaer and Soleimani's *Blockchain Privacy and Regulatory
Compliance: Towards a Practical Equilibrium* ("Privacy Pools"). A user can prove,
in zero knowledge, that their deposit belongs to a CURATED subset of the pool's
deposits, without revealing which deposit is theirs.

This document is about the politics as much as the cryptography, because a
compliance feature in a privacy tool is mostly a political object. It states what
the primitive does, who has to be trusted for it to mean anything, what a user
who is excluded can still do, and what it does NOT provide.

---

## 1. The problem it addresses

A privacy pool's anonymity set is everyone in it, including anyone whose funds
came from a theft. An honest user has no way to say "I am in this pool, but I am
not that person" without deanonymizing themselves. Counterparties respond to that
by treating the whole pool as one undifferentiated risk.

The association-set idea breaks the deadlock. The user proves membership in a
smaller, curated set instead of only in the pool. The proof still hides WHICH
member they are; what it adds is that the set they are hiding in has been vouched
for by somebody. An honest user dissociates from known-bad funds while keeping
anonymity inside the honest crowd.

---

## 2. What we built

Three additive pieces. Nothing in the pre-existing membership path changed.

**A separate circuit, `circuits/association.circom`.** It proves the membership
statement AND a second Poseidon Merkle inclusion of the SAME commitment under a
second, public `associationRoot`. Both trees are depth 20 and share the
`MerkleProof` template with `membership.circom` (extracted verbatim into
`circuits/merkle.circom`).

Public inputs, 5, in this exact order:

| # | name              | meaning                                                            |
|---|-------------------|--------------------------------------------------------------------|
| 0 | `root`            | pool accumulator root (a recent root from the Pool's ring)          |
| 1 | `nullifierHash`   | `Poseidon(secret, epoch)`, the epoch-scoped double-spend tag        |
| 2 | `actionHash`      | binds `(recipient, amount)` so a relay cannot redirect the escrow   |
| 3 | `epoch`           | 32-byte big-endian encoding of the `u64` epoch id                   |
| 4 | `associationRoot` | root of the curator's curated leaf set                              |

Inputs 0..3 are byte-for-byte the membership circuit's four, in the same order,
so the wire layout is a strict extension. The curator's IDENTITY is deliberately
NOT a public input: it is carried by the on-chain account the root was read from,
which keeps the public-input count (and the verification cost) minimal.

**An on-chain account and two curator instructions.** `INIT_ASSOCIATION` creates
an `AssociationSet` PDA at seeds `["assoc", pool, curator]`.
`UPDATE_ASSOCIATION_ROOT` lets that curator publish a new root, which lands in a
small ring of the last 8 published roots.

**An enforcing settle instruction.** `SETTLE_ZK_ASSOCIATED` verifies the
association proof against its own verifying key over all five public inputs,
after checking that the pool root is recent, that the passed `AssociationSet` is
program-owned, initialized, bound to THIS pool, sits at its correctly derived
PDA, and has recently published exactly the `associationRoot` the proof commits
to.

---

## 3. Enforced on-chain, in the execute path

This is the distinction worth being precise about. The association check is not a
wallet-side courtesy that a client could skip: it runs inside the instruction that
moves the money, and the escrow does not move unless the Groth16 proof verifies.
A settlement that lands via `SETTLE_ZK_ASSOCIATED` is on-chain evidence that an
association proof was verified, and it is distinguishable from a plain settlement
by anyone reading the chain, because it is a different instruction with a
different verifying key.

Two consequences worth stating:

- A 4-input membership proof cannot satisfy the 5-input association instruction.
  The verifying keys differ, so "association required" is not bypassable by
  swapping in a cheaper proof. There is a test for exactly this.
- Both settle paths derive the nullifier PDA from the SAME seeds, so they share
  one spent-set. A commitment cannot be settled once with an attestation and
  again without one. There is a test for this too.

The proof is also genuinely zero-knowledge on both halves: it reveals neither
which pool leaf nor which association leaf is yours. There is no separate
"exclusion proof" mode that leaks the excluded set.

---

## 4. The curator: what they can and cannot do

**Registration is permissionless.** Anybody can register as a curator for any
pool, because the PDA seeds include the curator. That is intentional. If the pool
authority chose who may curate, the operator would hold a veto over the entire
compliance story, and users would have exactly one curator to accept or reject.

**A curator CAN:**

- decide which commitments go into its published list, and therefore which
  settlements can carry ITS attestation;
- change that list at any time by publishing a new root;
- publish a root over an arbitrary list, including a list containing junk, or a
  list of one.

**A curator CANNOT:**

- stop anyone from using the pool. `SETTLE_ZK` never reads the association
  account and is completely unaffected by any curator's behaviour;
- learn which member settled against its root. The proof hides that;
- redirect a settlement, change an amount, or affect the pool's own accounting.

**Whether an attestation is WORTH anything is an off-chain judgement.** The
program proves only that an inclusion proof against curator X's published root
verified. It does not and cannot prove that curator X curated honestly. That
judgement belongs to whoever is reading the attestation - an exchange, an
auditor, a counterparty - and it is a judgement about a named, publicly
identifiable curator with a public update history.

**Curators must publish their leaf lists.** The chain stores only a root. Anyone
who wants to check what a curator actually vouched for must be able to rebuild
that root from a published list (`mirror-cli assoc build-root` does exactly this).
A curator that does not publish its list is one whose attestations nobody should
accept, and the CLI says so at every opportunity.

---

## 5. The censorship tradeoff, honestly

An association set IS a mechanism for exclusion. That is the point of it, and it
is also its danger. We made three choices to keep it from becoming a gate.

**It is opt-in per settlement, not per pool.** There is deliberately NO pool-level
flag that makes association proofs mandatory. Adding one would be a handful of
lines and we did not add them, because a mandatory-association pool hands its
curator a kill switch: the curator could stop any user by omitting them, and the
user's escrowed funds would have no path out. As built, the worst a curator can
do to a user is decline to vouch for them.

**Curators compete.** Multiple curators can register over one pool, and a user
picks which set to prove against. A user excluded by one curator can seek another
whose criteria they meet, and different verifiers can accept different curators.

**An excluded user is not stuck.** They settle through `SETTLE_ZK` exactly as
before, with full privacy and no curator involved. What they lose is the ability
to present that particular curator's attestation. The CLI's exclusion error says
this explicitly rather than reading like a failure.

None of that makes the mechanism politically neutral. If, in practice, one
curator's set became the only one counterparties accept, that curator would hold
real power over which users can transact with those counterparties, and the
permissionless-registration property would be a formality. We can build the
mechanism so it does not require a monopoly curator; we cannot prevent one from
emerging socially. Anyone deploying this should think about that before they
point users at a single curator.

---

## 6. Limits, stated plainly

**Your anonymity is the size of the intersection.** The association proof hides
you inside the set of commitments that are in BOTH the pool tree and the curated
tree. A curator that publishes a root over a one-leaf set learns exactly who
settled against it; a large pool does not rescue a tiny curated set. The CLI
prints the curated set size on every proof for this reason, and refuses lists with
duplicates so the reported size is the real one.

**The chain cannot check the curated set.** `UPDATE_ASSOCIATION_ROOT` accepts any
non-zero 32 bytes. The program does not verify that the root covers a subset of
this pool's commitments, because the leaves live off-chain and re-deriving a root
over an arbitrary-size list is not something a settlement instruction can afford.
Curator honesty is checked by publication and off-chain rebuilding, not by the
program.

**Recently-removed commitments have a settlement window.** The root ring holds the
last 8 published roots, so a commitment the curator has just removed can still
settle with an attestation until 8 further updates push the old root out. That is
a deliberate trade: without a history, every curator edit would invalidate
honest, already-generated proofs mid-flight. A curator needing an immediate
removal can force it by publishing 8 updates - an explicit, publicly visible act.

**One set per curator per pool.** Seeds are `["assoc", pool, curator]`, so a
curator wanting several policies needs several keys.

**This is not a sanctions oracle, a KYC system, or legal advice.** It is a
mechanism for making a specific, narrow, verifiable claim. What claim is useful,
and to whom, is not something the code decides.

**The trusted setup caveat applies here too.** The association circuit's committed
verifying key comes from the same DEV/TEST single-party setup as the other two
circuits (see `docs/CEREMONY.md`). It must not secure real value until a
multi-party phase-2 ceremony has been run over this circuit. The ceremony tooling
supports it; the ceremony has not been run for it.

---

## 7. How it composes with viewing keys

The two disclosure primitives are complementary and deliberately separate.

**Encrypted notes / viewing keys** (`crates/mirror-core/src/encrypted_note.rs`,
X25519 ECDH + HKDF-SHA256 + ChaCha20-Poly1305, with a viewing key kept distinct
from the spend key) let a user reveal the CONTENTS of specific activity to a
specific party: hand over the viewing key and the auditor reads those notes and
nothing else. It answers "here is exactly what I did", to one recipient, and it
is a disclosure of private data.

**Association proofs** answer a different question - "my funds are in the
acceptable set" - to EVERYONE, publicly, while disclosing nothing at all. There
is no recipient, no key handed over, no data revealed.

Used together: an association proof is the cheap, public, always-on signal that
gets a user through the front door, and a viewing key is the targeted, revocable-
in-practice disclosure for the rare case where somebody has standing to ask for
detail. Neither can substitute for the other, and neither requires the other.

---

## 8. Using it

Curator, once per pool:

```bash
mirror-cli assoc init \
  --program-id <PROGRAM> --pool <POOL> --curator curator.json
```

Curator, whenever the curated list changes (and publish `curated.txt` too):

```bash
mirror-cli assoc publish \
  --program-id <PROGRAM> --pool <POOL> --curator curator.json \
  --leaves curated.txt
```

Or build the root without submitting, to hand the bytes to a different signer:

```bash
mirror-cli assoc build-root --leaves curated.txt \
  --program-id <PROGRAM> --pool <POOL> --curator <CURATOR_PUBKEY>
```

Anyone, to inspect what a curator has published:

```bash
mirror-cli assoc show --program-id <PROGRAM> --pool <POOL> --curator <CURATOR_PUBKEY>
```

User, instead of `mirror-cli prove`:

```bash
mirror-cli prove-associated \
  --note notes/<note>.json \
  --curator <CURATOR_PUBKEY> \
  --association-leaves curated.txt
```

This emits `SettleZkAssociated` instruction data plus its seven accounts (the six
`SettleZk` accounts in the same order, with the `AssociationSet` appended). It
needs the association circuit's build artifacts, produced once by
`bash circuits/build_association.sh`.

If the curator does not vouch for this deposit, the command stops with a message
saying so and reminding you that plain `mirror-cli prove` still works.

---

## 9. Where the code is

| Piece | Path |
|---|---|
| Circuit | `circuits/association.circom` |
| Shared Merkle templates | `circuits/merkle.circom` |
| Build + fixture | `circuits/build_association.sh`, `circuits/gen_association_fixture.js` |
| Committed vk + fixture | `circuits/artifacts/association_*` |
| Vendored vk (on-chain) | `programs/mirror-pool/src/association_vk.rs` |
| Account | `programs/mirror-pool/src/state/association.rs` |
| Instructions | `programs/mirror-pool/src/instructions/{init_association,update_association_root,settle_zk_associated}.rs` |
| On-chain tests | `programs/mirror-pool/tests/association.rs` |
| Host prover + curator tooling | `crates/mirror-cli/src/association.rs` |
| Host tests | `crates/mirror-cli/src/association/tests.rs` |
