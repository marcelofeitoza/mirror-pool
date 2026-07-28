# The opt-in compliance layer: association sets and viewing keys

mirror-pool ships TWO optional compliance primitives, and they answer different
questions.

**Association sets** (sections 1 to 6), in the sense of Buterin, Illum, Nadler,
Schaer and Soleimani's *Blockchain Privacy and Regulatory Compliance: Towards a
Practical Equilibrium* ("Privacy Pools"). A user proves, in zero knowledge, that
their deposit belongs to a CURATED subset of the pool's deposits, without
revealing which deposit is theirs. It answers "my funds are in the acceptable
set", to EVERYONE, while revealing nothing.

**Viewing keys and sealed disclosures** (section 7). A user publishes an
X25519 key under their own address, and a user can post a sealed record that
reveals ONE of their own settled actions to ONE reader they chose. It answers
"here is exactly what I did", to one party, and it is a disclosure of private
data.

Neither is required by anything. A pool that required either would be a
surveillance pool.

This document is about the politics as much as the cryptography, because a
compliance feature in a privacy tool is mostly a political object. It states what
each primitive does, who has to be trusted for it to mean anything, what a user
who is excluded can still do, and what neither provides.

---

## 1. The problem association sets address

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

## 2. What we built (association sets)

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

## 6. Limits of association sets, stated plainly

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
verifying key comes from the DEV/TEST single-party setup in
`circuits/build_association.sh`, whose phase-2 entropy is a hard-coded public
string (see `docs/CEREMONY.md`). It must not secure real value until a multi-party
phase-2 ceremony has been run over this circuit. The ceremony tooling supports it
and it HAS been run for the membership circuit (`docs/CEREMONY.md` section 10), but
not for this one; the JoinSplit circuit is in the same position.

---

## 7. Viewing keys and sealed disclosures

The second primitive, and the one that reveals something. An association proof
says "I am in the acceptable set" to everybody while disclosing nothing. A
disclosure says "here is exactly what this one action was" to exactly one reader.
Neither substitutes for the other, and neither requires the other.

The cryptography already existed client-side
(`crates/mirror-core/src/encrypted_note.rs`: X25519 ECDH, HKDF-SHA256,
ChaCha20-Poly1305, with a viewing key deliberately separate from the spend key).
What section 7 is about is the ON-CHAIN half: where a reader's key is published,
how a record is bound to a settlement, and which parts of the claim the program
actually enforces.

### 7.1 What we built

**A viewing-key directory.** `REGISTER_VIEWING_KEY` writes a `ViewingKey` account
at seeds `["view", authority]`, holding `{ authority, viewing_pub,
rotation_count }`. The authority signs for itself. The same instruction rotates
the key later, and only that authority can, because the account is that
authority's PDA. An auditor publishes a key so users have something to seal to; a
user may publish one so a sender can encrypt a confidential-value note to them
knowing only their address.

**A disclosure record.** `PUBLISH_DISCLOSURE` writes a `Disclosure` account at
seeds `["disc", pool, action_hash, auditor_view_pub]`, holding
`{ pool, recipient, auditor, auditor_view_pub, action_hash, amount, blob }`. The
`blob` is exactly one 100-byte encrypted-note ciphertext. Its plaintext is the
`(epoch, secret)` pair for one ZK opt-in action, which is all a reader needs,
because

```text
commitment    = Poseidon(secret, actionHash, epoch)     the deposit leaf
nullifierHash = Poseidon(secret, epoch)                 the spend tag
```

and `action_hash` is on the record in the clear. The reader recomputes both,
finds the `CommitDeposit` that escrowed the deposit (hence the wallet that funded
it) and the `SettleZk` that spent it (hence the payout), and has the whole
provenance of that one action.

**What the record deliberately does NOT contain: the commitment.** Putting the
disclosed commitment on-chain, or in the record's address, would publicly link
that deposit to that settlement for everybody, which is precisely the link the
pool exists to break. Here the deposit side is inside the sealed blob and nowhere
else. What the record makes public is the settlement side, which the settlement
already made public itself.

### 7.2 Registration is authenticated, and by derivation rather than by a check

The obvious way to build this layer is a record keyed by the commitment being
disclosed, written by whoever pays for it. That has two holes: any payer can
claim any commitment first, and the handler accepts the sealed bytes without
knowing anything about them. We do not do either.

`action_hash` is not accepted from the caller. The handler recomputes

```text
action_hash = Poseidon(recipientHi128, recipientLo128, amount)
```

on-chain from the SIGNING recipient's address, with the same `sol_poseidon` call
`SETTLE_ZK` uses, and that value is a PDA seed. Chaining it up:

```text
record PDA  = ["disc", pool, actionHash, auditorViewPub]   derived from the signer
actionHash  = Poseidon(recipient, amount)                   binds the recipient
commitment  = Poseidon(secret, actionHash, epoch)           binds the actionHash
```

so the only party who can write a record about a settlement is the address that
settlement was bound to pay, which is the address the depositor themselves chose
INSIDE the commitment. Squatting somebody else's slot is not forbidden by a rule
that could be forgotten; it is an address that cannot be derived. An attacker who
publishes junk under an address they control occupies only their own slot, which
corresponds to a settlement to themselves.

The directory has the same shape: the authority is the only variable seed, so the
only registration any signer can write is their own. There is no first-come race
for anybody's entry.

### 7.3 What is enforced where

| Claim | Enforced by |
|---|---|
| The publisher holds the key the settlement pays | On-chain: PDA derived from the signing recipient's `action_hash` |
| Nobody else can occupy that record | On-chain: same derivation, plus write-once |
| Nobody else can occupy a directory entry | On-chain: `["view", authority]` with the authority signing |
| The reader is a real, registered party | On-chain: the ViewingKey account must be program-owned, v1, and at its own PDA; the key is READ from it |
| The amount is one this pool can settle | On-chain: equals `pool.zk_denomination` |
| The blob is the right shape | On-chain: exact length, and its ephemeral X25519 key must be canonical and not small-order |
| The blob opens at all | NOT enforced. The program holds no secret and cannot decrypt |
| The blob opens to the claimed action | NOT enforced on-chain. The READER checks it in one Poseidon hash |
| The disclosed action really settled | NOT enforced. The reader checks the Nullifier PDA exists |
| The publisher told the truth | NOT enforceable by any program. See below |

The last three are the honest limit of the design, and they are why the record is
signed. A false disclosure is possible. It costs the liar their own slot, it is
detected by the reader immediately (the recomputed commitment is simply not on
the chain, and the recomputed nullifier has no PDA), and it carries the signature
of the address that settlement paid. That is accountability, not prevention, and
calling it prevention would be a lie about what the code does.

### 7.4 What the reader learns, and what they do not

Learns, for each record they can open:

- the `(epoch, secret)` of that ONE action, hence its deposit leaf and spend tag;
- therefore the deposit transaction, hence the wallet that funded it;
- therefore the settlement transaction, hence what was paid and to whom;
- that the publisher signed the claim.

Does not learn:

- anything about any other participant of the pool;
- anything about the publisher's OTHER actions. Every action has its own secret
  and its own record, so disclosure is per-action, not per-account. Handing over
  a viewing key wholesale is a different, blunter act, and this layer does not
  require it;
- anything about the confidential-value layer. Those notes use a separate key and
  a separate accumulator;
- any ability to move the money. The escrow's only exit is `SETTLE_ZK`, which
  pays the address bound in `actionHash`. A reader who holds the secret can at
  most produce a proof that pays the publisher's own recipient.

One real harm remains: a reader who gets the secret BEFORE the action settles can
settle it at a moment of their choosing, which can put the settlement in a thinner
window than the user would have picked. That is an anonymity harm, not a theft.
The CLI refuses to publish a disclosure for an unsettled action unless you pass
`--allow-unsettled`, and says why.

### 7.5 The privacy cost of registering at all

Stated plainly, because a disclosure feature that hides its own cost is a trap.

**Registering a viewing key is a public, permanent act.** The account links your
Solana address to an X25519 key forever. Anyone can read it. If you later receive
confidential-value notes at that key, an observer still cannot tell which notes
are yours (that needs trial decryption with your secret), but they can tell that
this address is set up to participate.

**Publishing a disclosure is a public act about a specific settlement.** The
record says, to everybody: the settlement to address R on this pool, for this
amount, has a disclosure addressed to auditor A. So it publishes the FACT of a
disclosure and the IDENTITY of your reader. It does not publish the commitment,
the epoch, the nullifier, or the secret.

**The rent payer is a linkability leak if you let it be.** The settlement paid a
fresh address; paying the record's rent from your main wallet links that wallet
to the action, which is exactly what the fresh address was for. The CLI pays from
the recipient by default.

**Choosing an auditor is itself information.** Which reader you named is public
and permanent, and "this user discloses to that firm" may be more than you meant
to say.

**It is one-way.** Records are write-once and there is no close instruction, so
there is no revocation: the reader keeps whatever they decrypted, and the fact of
the disclosure stays on-chain. Rotating your reader's key does not un-disclose
anything; it only changes where future records land.

### 7.6 How the two primitives compose

An association proof is the cheap, public, always-on signal that gets a user
through the front door without revealing anything. A disclosure is the targeted,
one-reader, one-action detail for the rarer case where somebody has standing to
ask. They are independent: the association path (`SETTLE_ZK_ASSOCIATED`) never
reads a viewing key or a record, and the disclosure path never reads an
association set. A user can use either, both, or neither.

Used together the story is: prove publicly that you are in a curated set, and, if
a counterparty needs more than that, disclose the one action they are asking
about to them alone. What you never have to do is hand anybody a key that opens
everything you have ever done.

### 7.7 Limits, stated plainly

**No on-chain disclosure for the confidential-value layer.** The authentication
above works because a behavioral settlement binds a Solana address inside its
commitment. A confidential value note binds a Poseidon key, not an on-chain
address, so there is no signature the program could require. Disclosure there
stays client-side: hand the reader the note material or the viewing key out of
band. The fix would be to bind an auditor blob into a JoinSplit's `extDataHash`
so the spend proof itself authorizes the record. We have not built that, and we
are not going to imply the amount layer has an on-chain disclosure primitive when
it does not.

**The X25519 checks are byte checks.** Canonical encoding and the small-order
blacklist are what the program can afford, and they are what protects a user from
a client that seals to a degenerate key. They do NOT prove the bytes are a point
on the curve, and they do not prove the registrant holds the matching secret. A
registration whose secret nobody holds simply produces records nobody can open.

**Nothing stops a reader from republishing.** Disclosure is disclosure. Once a
reader can open a record, what they do with the contents is a matter of law and
contract, not of cryptography.

**One record per (action, reader key).** Disclosing the same action to a second
reader is a second record, at a different address, sealed to their key. Rotating
a reader's key changes where new records land and does not disturb old ones.

**The trusted-setup caveat is unchanged.** This layer verifies no proof and adds
no circuit, so it neither improves nor worsens the ceremony situation described
in `docs/CEREMONY.md`.

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

### Viewing keys and disclosures

Auditor (or anyone), once, to publish the key they can be addressed at. The key
comes from a `value-keygen` keyfile, or as raw hex when the secret lives
elsewhere:

```bash
mirror-cli viewing-key register \
  --program-id <PROGRAM> --authority auditor.json --wallet auditor-wallet.json
```

Anyone, to look up an address's published key (including to check it before
sealing anything to it):

```bash
mirror-cli viewing-key show --program-id <PROGRAM> --authority <AUDITOR_PUBKEY>
```

User, to disclose ONE settled action to ONE reader. The `--recipient` keypair is
the fresh address that settlement paid, and it must sign: that signature is what
the record's address is derived from:

```bash
mirror-cli disclose \
  --program-id <PROGRAM> --note notes/<note>.json \
  --auditor <AUDITOR_PUBKEY> --recipient recipient.json
```

The command refuses if the action has not settled yet and explains why (a reader
holding the secret early can choose when it settles), refuses if the reader has
not registered a key, and refuses if the keypair is not the note's bound
recipient. It prints, in plain words, what the reader can now read and what
everybody else can now read.

Auditor, to find and check what has been disclosed to them:

```bash
mirror-cli audit scan --program-id <PROGRAM> --wallet auditor-wallet.json
```

For each record it can open, this prints the recomputed commitment and nullifier
and then VERIFIES the claim against the chain by deriving the Nullifier PDA and
checking it exists. A record that does not open, or that opens to an action with
no on-chain nullifier, is reported as unverified rather than believed.

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

Viewing keys and disclosures (section 7):

| Piece | Path |
|---|---|
| Sealing, opening, recomputing (host) | `crates/mirror-core/src/disclosure.rs` |
| The ECIES it reuses unchanged | `crates/mirror-core/src/encrypted_note.rs` |
| Accounts | `programs/mirror-pool/src/state/{viewing_key,disclosure}.rs` |
| Instructions | `programs/mirror-pool/src/instructions/{register_viewing_key,publish_disclosure}.rs` |
| On-chain tests | `programs/mirror-pool/tests/viewing.rs` |
| CLI | `mirror-cli viewing-key register / viewing-key show / disclose / audit scan` |

There is deliberately no circuit and no verifying key in that table: this layer
proves nothing in zero knowledge. It publishes a key, and it publishes a sealed
record whose address is derived from a signature. Everything it claims beyond
that, the reader checks for themselves.
