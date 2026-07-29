# The verifying-key registry: write-once and digest-pinned

Every proof mirror-pool accepts is checked against a Groth16 **verifying key**.
That key is the root of trust of the whole system: whoever chooses it chooses
what counts as a valid proof, and a key whose trapdoor you hold lets you produce
a convincing proof of a statement that is false. On the settle paths a false
statement means "this nullifier belongs to a leaf in the tree" when it does not,
which drains the escrow. On the confidential path it means "these inputs and
outputs balance" when they do not, which mints value out of nothing.

So the only interesting question about where a verifying key lives is: **who can
change it, and to what?**

This document states what we built, why the obvious version of it is a downgrade
rather than an upgrade, exactly what our version buys, and exactly what it costs.
The costs section is not a formality; read it.

---

## 1. Two designs that both look reasonable

**Compile it in.** The key is a `const` in the program's code. Nobody can change
it without a program upgrade, which is a governance event with an on-chain
record. The downside is opacity: to know which key is in force you disassemble
the deployed bytecode, or you trust that the deployed bytes match the source.
And a program that wants to serve several circuits carries several constants,
each pinned to a build.

**Put it in a config account.** The key is written into a program-owned PDA at
initialization. Now anyone can read the key in force straight off the chain, and
the program can serve several circuits by keying the account per circuit.

The second design is the one the review item asked for, and taken naively it is
strictly worse than the first, because it converts a compile-time constant into
mutable data. If the account can be written by an operator, or by anyone, then
the root of trust is whatever that writer says it is. A verifying key is not
self-authenticating: a well-formed 769-byte blob with valid BN254 points and the
right `ic` length is a perfectly good verifying key. It just happens to be
somebody else's, and that somebody kept the toxic waste.

That is the specific failure mode of a registry that validates **format only**:
right length, right `ic_len`, done. Such a check rejects garbage and accepts the
one input that matters. It is worth being precise about why: format validation
answers "is this a verifying key?", and the question that protects the pool is
"is this *the* verifying key?".

---

## 2. What we built

A program-owned PDA per circuit, `seeds = ["vk", circuit_id]`, with two
properties that have to hold together:

**Write-once.** `INIT_VK` is the only instruction in the program that writes a
registry account, and there is deliberately no counterpart that rewrites one. A
second `INIT_VK` over a live registry fails with
`VkRegistryAlreadyInitialized` rather than overwriting - it is not even
idempotent, so nothing can be smuggled in behind a "harmless" retry. There is no
admin, no authority field, and no upgrade instruction to find.

**Digest-pinned.** The program carries, in its bytecode, the SHA-256 of the
canonical encoding of each key it is willing to verify against
(`programs/mirror-pool/src/vk_digest.rs`). `INIT_VK` accepts bytes only if they
hash to that digest, and **every verify recomputes the same digest over the
stored bytes** before they reach the verifier. The set of keys the program can
ever verify against is therefore fixed by its bytecode, exactly as it was when
the key was a `const`.

The pin is what makes the account model safe. Without it, "the key lives in an
account" means "whoever writes the account picks the root of trust". With it, the
account buys visibility and nothing else: the key in force is publicly readable,
and reading it is all anybody can do with it.

Because the caller cannot choose the key, installation is **permissionless** and
that is fine. All a caller can do is pay rent to publish the one key the bytecode
already committed to. That is a publication step, not a configuration step, which
is why `mirror-cli init-vk` takes no key argument.

### Where the digests come from

Each digest is SHA-256 over the canonical encoding of the correspondingly named
vendored key module (`src/vk.rs`, `src/transaction_vk.rs`,
`src/association_vk.rs`), which are copied verbatim from `circuits/artifacts/`,
which the circuit build and the trusted setup produce. The digest is a 32-byte
commitment to the exact setup output, carried in the program's bytecode.

Nothing about that is hand-maintained. The unit test
`vk_digest::tests::digests_match_the_vendored_keys` recomputes all three from the
vendored modules with a host SHA-256 and asserts equality, printing the correct
hex on failure, so editing a key without editing its digest (or the reverse)
fails the suite rather than silently locking out every proof. A second test
pins each circuit's public-input count against its vendored key, so the approved
table cannot drift from the keys it approves.

### Canonical encoding

The digest and the account both use one serialization, byte-identical to the
`groth16-solana` in-memory layout so decoding is a copy and never a re-encoding:

```text
offset  size                     field
0       1                        nr_pubinputs
1       64                       vk_alpha_g1        G1: x || y
65      128                      vk_beta_g2         G2: x_c1 || x_c0 || y_c1 || y_c0
193     128                      vk_gamma_g2
321     128                      vk_delta_g2
449     64 * (nr_pubinputs + 1)  vk_ic
```

All big-endian and uncompressed. Membership (4 inputs) is 769 bytes, association
(5) is 833, the JoinSplit (7) is 961. The account prepends a 4-byte header
(`version`, `circuit_id`, `bump`, a reserved zero).

### Account layout

```text
offset  size   field
0       1      version        0 = uninitialized, 1 = v1
1       1      circuit_id     which pinned circuit this registry serves
2       1      bump           VkRegistry PDA bump
3       1      reserved       always 0; a non-zero byte fails the load
4       N      vk             the canonical encoding above
```

The total size is a pure function of the circuit's pinned public-input count and
is never inferred from the account, so a resized or truncated account fails on
shape before anything is hashed.

### What runs on every verify

`state::vk_registry::verify_pinned` is the single function all three verifying
instructions call. It fails closed at the first failure, in this order:

1. the account is owned by this program;
2. it is the canonical registry PDA for the circuit the instruction wants;
3. its size, version, stored circuit id and reserved byte are exactly right;
4. **the stored key hashes to the digest pinned at compile time**;
5. it decodes into a `Groth16Verifyingkey` of the pinned shape (fixed-size
   scratch, no allocation, no casting of account bytes).

Steps 1 to 3 are ownership arguments and step 4 is a content argument. That
distinction is the point: the content argument holds even if an ownership
argument turns out to be wrong.

### Which instructions read it

All three, with no compile-time verifying key left on any verify path:

| instruction | circuit | account slot | pinned digest |
|---|---|---|---|
| `SettleZk` | membership (4 inputs) | 6 | `MEMBERSHIP_VK_SHA256` |
| `SettleZkAssociated` | association (5 inputs) | 7 | `ASSOCIATION_VK_SHA256` |
| `Transact` | JoinSplit (7 inputs) | 9 | `TRANSACTION_VK_SHA256` |

The registry PDA is keyed by circuit id, so passing another circuit's registry
fails on the PDA derivation. A membership proof still cannot satisfy the
association instruction and vice versa, exactly as when those keys were separate
constants.

---

## 3. What it buys

**The key in force is publicly readable.** Anyone can fetch three accounts and
see the exact bytes every proof is checked against, without disassembling a
program or trusting that a published build matches a deployed one. Combined with
the digests being in the bytecode, a reviewer now has two independent handles on
the same fact.

**Multi-circuit pools become uniform.** Adding a circuit is a new entry in one
approved table plus a new registry account, rather than a new constant threaded
into a new instruction. The three circuits this program already has now go
through one code path, which is also the answer to one of the costs below.

**Rotation after a real ceremony becomes a smaller operation.** This is the
honest version of the usual claim, and it is weaker than "rotate without a
program upgrade". See the next section.

---

## 4. What it costs

**An extra account read and a SHA-256 on every verify.** Measured with the
mollusk suite against the compiled SBF program, one instruction each, before and
after this change:

| instruction | before (CU) | after (CU) | delta |
|---|---|---|---|
| `SettleZk` (membership, 4 inputs) | 103,387 | 107,354 | +3,967 |
| `SettleZkAssociated` (5 inputs) | 113,733 | 120,742 | +7,009 |
| `Transact` (JoinSplit, 7 inputs) | 195,213 | 197,843 | +2,630 |
| `InitVk` (once per circuit, ever) | n/a | 3,972 | new |

The deltas are not uniform, and the spread is informative. The only structural
difference between the three paths is key length (769, 833, 961 bytes), which is
monotone, while the deltas are not: the shortest key costs 3,967 and the longest
2,630. So the hashing is not the dominant term. The dominant term is the PDA
derivation, `sol_try_find_program_address`, which costs roughly 1,500 CU per bump
it has to skip before it finds a valid one - and how many that is depends on the
program id and the seeds, so **a different deployment will see different numbers
in this range**. Take these as an order of magnitude (single-digit thousands of
CU), not as constants.

We deliberately did NOT optimize this by deriving with the stored bump instead of
searching. It would be sound - only `INIT_VK` can create a registry and it always
uses the canonical bump - and it would make the cost roughly flat, but it
replaces a trivial argument with a subtle one inside the security-critical path,
and the normalized transaction profile already requests 400,000 CU, so nothing
here is close to a ceiling. If a future circuit pushes a verify near that limit,
this is the first thing to spend.

**A second place a mistake can live.** This is the real cost, and it is not
measurable. Before, the key was in the instruction's own code and a reader could
see it there. Now correctness depends on the instruction passing the right
account, on the registry having been installed, and on the load-and-pin function
being called on every path. Three mitigations, all mechanical rather than
aspirational:

- There is exactly ONE function that hands a verifying key to a verifier
  (`vk_registry::verify_pinned`) and it always re-checks the pin. There is no way
  to reach `Groth16Verifier::new` in this program without going through it.
- A missing registry fails closed with `VkRegistryNotInitialized`, so "forgot to
  install" is a loud, immediate, first-transaction failure, never a silent
  weakening.
- `tests/vk_registry.rs` drives all 256 instruction tags with a live registry in
  the first writable account slot and asserts its bytes, lamports and owner never
  change. That is the mechanical form of "there is no update instruction": it
  asks the compiled program rather than trusting a reading of the dispatcher.

**One more account per transaction.** Readonly, never a signer, always appended
last so index-based checks elsewhere are unaffected. Costs 32 bytes of
transaction size.

**Rent, once per circuit per deployment.** A membership registry is 773 bytes and
its rent-exempt minimum is 6,270,960 lamports (about 0.0063 SOL), paid by
whoever publishes it; the figure is asserted in
`init_vk_installs_exactly_the_canonical_pinned_key` so it stays a measurement. A
rejected install costs nothing but a failed transaction: the digest is checked
before the account is created.

**Rotation still needs a program upgrade.** After a real multi-party ceremony
(`docs/CEREMONY.md`) the new key is installed by moving the pinned digest in
`vk_digest.rs` and upgrading, then publishing the new key into a fresh registry.
It would be more convenient if a ceremony transcript alone could rotate the key,
and we are not going to claim that, because a pin a third party could move is not
a pin. What the registry actually removes from a rotation is the need to touch
the verifying instructions or re-derive anything: the change is one constant and
one publication.

**The vendored key modules are still in the source tree.** They are the
provenance of the digests and the input to the test that keeps them honest, and
they are what `mirror-cli init-vk` publishes. They are no longer read by any
verify path. A reader who greps for `VERIFYINGKEY` and concludes the program
verifies against a constant would be wrong, which is itself a small cost.

---

## 5. What this does NOT do

- It does not make an unsound trusted setup sound. If the setup that produced a
  key was single-party, pinning that key just means the program is faithfully
  committed to a key somebody may hold the trapdoor for. The registry is
  orthogonal to `docs/CEREMONY.md`; both are needed.
- It does not add governance. There is no authority that can rotate a key, which
  also means there is no authority that can respond to a compromised key without
  a program upgrade.
- It does not protect against a malicious program upgrade. Whoever holds the
  upgrade authority can move the digest. That was equally true when the key was a
  constant, and it is the reason upgrade authority is the thing to scrutinize.
- It does not make the key bytes trustworthy on their own. An observer who reads
  a registry account learns what key is in force; to learn whether that key is
  the ceremony's output they still have to check the digest against the source
  and the source against the transcript.

---

## 6. Using it

Publish one key per circuit the deployment will use, once, after deploying:

```sh
mirror-cli init-vk --program-id <PROGRAM_ID> --circuit membership  --payer <KEYPAIR>
mirror-cli init-vk --program-id <PROGRAM_ID> --circuit transaction --payer <KEYPAIR>
mirror-cli init-vk --program-id <PROGRAM_ID> --circuit association --payer <KEYPAIR>
```

`--dry-run` prints the registry address and the SHA-256 the program will check,
without submitting anything, so a deployment can be reconciled against
`vk_digest.rs` out of band.

The registry address goes into every emitted settle bundle
(`vk_registry` in the `prove` / `prove-associated` emits, and a `vk_registry`
entry in the `shield`/`transfer`/`unshield` account list), so a submitter never
derives it itself.

---

## 7. Where the code is

| what | where |
|---|---|
| pinned digests + the test that keeps them honest | `programs/mirror-pool/src/vk_digest.rs` |
| account layout, approved table, encode/decode, load-and-pin, verify | `programs/mirror-pool/src/state/vk_registry.rs` |
| the write-once install instruction | `programs/mirror-pool/src/instructions/init_vk.rs` |
| adversarial tests (install, no-update sweep, per-verify revalidation) | `programs/mirror-pool/tests/vk_registry.rs` |
| per-path revalidation tests | `programs/mirror-pool/tests/transact.rs`, `tests/association.rs` |
| client-side canonical encoding + `init-vk` | `crates/mirror-cli/src/vk.rs`, `crates/mirror-cli/src/chain.rs` |
| shared wire constants | `crates/mirror-core/src/lib.rs` (`wire`), mirrored in the program's `wire` |

---

## 8. Live check on a local validator

The mollusk suite runs the real compiled SBF bytecode, so it already exercises
account ownership, PDA derivation, the `sol_sha256` syscall and the create-account
CPI. What it does not exercise is transaction assembly and the shipped CLI. That
part was checked against a running Surfpool (a local mainnet mirror, treated as
mainnet by this repo's convention), on a fresh deployment of the current
bytecode:

```text
program GQJPJ51FMYRw2VeQ2cSvGZzJfckjjEBEvFNxCDggcnYB   (local Surfpool, fresh deploy)

circuit       registry PDA                                    len  lamports  bump
membership    F8WXC9XNj8hABebMqXb72DbMwvSK8LAdiVJXbfikyWRT    773  6270960   252
transaction   CoZqWcnKaLZ94BAiqGJxtZkq3Ar3FKzUTUjXCRUXMYA9    965  7607280   255
association   4U72nGfbWGPeuNFJJobTPKPxmna4quTNLm71HDg4tdhp    837  6716400   255
```

Each account came back program-owned, `version = 1`, the right `circuit_id`,
`reserved = 0`, and its stored key hashing to exactly the constant in
`vk_digest.rs`:

```text
membership   108733d1671cd3ea8aae375f1f6d232877b33826fef9370c196f72457cf1a6da
transaction  9c310a0068a7036b1bbfbaed59d58c65740154d6aff4529b738ecff8c7601212
association  77031fc732e4be82fbd2c77cb2076bf92b4fdb1ce9a74bf8cfa085464e3d23bd
```

> **This run predates all three ceremonies.** Every digest above is one of the old
> dev-setup keys. All three verifying keys have since been replaced by phase-2
> ceremony outputs (`docs/CEREMONY.md`), so the constants in `vk_digest.rs` are now
>
> ```text
> membership   be5f776d2a4ba83655c50a9ecf47192cd3aa74075cd9e3d8a62bd99e043e4c76
> transaction  4b542099cea5bd4dfdfd6f9d5d649bc23acd9aab35d8f3ac1a984e13b38e28c1
> association  90d13582aba26708672b3f118dea345c9636534b1b9de3fd7fce4708062832ee
> ```
>
> The transcript above is left exactly as captured; nothing else about the
> mechanism changed, and the write-once behaviour it demonstrates is the same.
> Those three digests ARE what the deployed devnet program pins today, and the
> live registries hold exactly them (`docs/PROOF.md`).

Re-running `init-vk` for `membership` against the live registry failed on-chain
with `custom program error: 0x1c` (28, `VkRegistryAlreadyInitialized`), after
6,662 CU: the write-once property holds on a validator and not only in mollusk.

The three bumps above (252, 255, 255) are also the concrete reason the
per-verify CU deltas in section 4 are not constants: a bump of 252 costs three
extra `create_program_address` attempts that a bump of 255 does not.

### The whole behavioral flow, end to end

The behavioral soak (`mirror-soak`) was then run in full against the same
validator, on its own fresh deployment of the current bytecode
(`7vUgz7eMA2HD1DrTrKp3YWvUgpmyyrab8ogmnfdHhuve`), driving the shipped CLI and the
shipped coordinator:

```text
init_vk_membership  4RvZe2WFCXcEY568G11LQ8qt78v3KyN6UcY99unkrwSiooY9hvh4UePNu2UAN7HLCFnb1J4fTzDs6XhC12DvqzG8
zk_settle           2AZeCMii7PJALPnqHGgdqRuANMHq1fJWTwFqgykHFcSjKNHSMd3L4jkCyU9dLd6uv4BvhZ6rNGV5gG2rEEVVQpfs

SOAK RESULT: GREEN (18/18 assertions passed)
```

`zk_settle` is the one that matters here: a real Groth16 membership proof,
verified on a validator against a key the program loaded from account
`F8WXC9XNj8hABebMqXb72DbMwvSK8LAdiVJXbfikyWRT` and re-hashed against
`MEMBERSHIP_VK_SHA256` inside the same instruction, releasing the escrow to the
bound fresh recipient. The replay of the same settle was then rejected with
`NullifierSpent`, so nothing about the anti-replay path changed either.

That run is 18 assertions rather than the 17 recorded in `PROOF.md`: the extra
one is the new "membership verifying key published into its write-once registry
PDA" check. It is a different program on a different cluster, so it does not
supersede any number in `PROOF.md`; the two are not comparable and neither is
being restated as the other.

These are local-validator signatures, not public-cluster ones. They are recorded
here as a reproduction recipe, not as browser-verifiable proof. Reproduce with a
running Surfpool:

```sh
cargo build-sbf --manifest-path programs/mirror-pool/Cargo.toml
cargo run -p mirror-soak --release
```

---

## 9. Status of the published devnet deployment

The devnet program `EezWdFrmHtR2PCuucUruvkgyB9HW3w2KskZNeYmXszBq` has since been
**upgraded in place** to the current bytecode, so it now contains the registry,
the `INIT_VK` instruction, and the post-ceremony membership digest:

```text
upgrade signature  58gKGUdvKowyv4phxNUxKxiPbbnWNps9SKhxVkLWt7V8Q7DQLhrTuH2UWhUPtDzmeSPTEBExzXYeGVeYDuGFWHm
slot               479600717
on-chain bytes     127680, byte-for-byte equal to programs/mirror-pool/target/deploy/mirror_pool.so
sha256(.so)        6b026cf95e7f76d8a45c248004f98e2f647e7fc806203e1785bdeddcbea4f466
```

Reproduce the bytecode check with:

```sh
solana program dump EezWdFrmHtR2PCuucUruvkgyB9HW3w2KskZNeYmXszBq /tmp/onchain.so --url devnet
cmp /tmp/onchain.so programs/mirror-pool/target/deploy/mirror_pool.so
```

**No registry account exists on devnet yet.** The three registry PDAs for this
program id are

```text
membership   6fkK14YXovKkJQ7z2Df7sBeCGPEnRK2XGBrRkMJJbRYg
transaction  BD1cm4jqbDHxgWX7ZfLmFaWWc1wSJFr5h68YesrkuCfW
association  3EyfUQZFSEz1VcTkCK3EsUV5uE8XqyCBmCQHETqjhWVn
```

and all three came back `AccountNotFound` both before and after the upgrade.
That matters because the registry is write-once: had a membership registry
already been initialized with the OLD dev key, no instruction could update it and
the upgraded program would reject it forever, since the stored bytes no longer
hash to the pinned digest. Because none exists, the FIRST `mirror-cli init-vk
--circuit membership` run against this program installs the ceremony key, and it
is the only key that program will accept.

The behavioral and confidential runs recorded in `PROOF.md` were produced by the
earlier, pre-registry bytecode at this same address; they are left exactly as
captured and are labeled there. They are records of that earlier program, not
evidence about the code described here. The evidence for the design in this
document is the mollusk suite against the compiled SBF program, reproducible with
`cargo build-sbf` followed by `cargo test` in `programs/mirror-pool/`, plus the
Surfpool run in section 8. The soak drivers publish the keys and pass the
accounts, but the full soak has not been re-run against a public cluster since
the upgrade.
