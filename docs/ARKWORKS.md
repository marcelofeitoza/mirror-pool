# The arkworks path: shrinking the toolchain surface

Arkworks-native constraint systems for **all three** circuits in this repo -
**membership**, the **confidential-value JoinSplit**, and the opt-in
**association** statement - alongside the circom ones. Same statements, no
`circom`, no `snarkjs`, no `node`, no `npm` - and the resulting proofs are
checked with the same `groth16-solana` verifier the on-chain program links.

This document says exactly what was built, what was measured, and what is still
circom-shaped. Nothing below is an estimate.

| circuit | circom | arkworks | agrees with committed circom fixtures | arkworks proof verified by `groth16-solana` |
| --- | --- | --- | --- | --- |
| membership (4 public inputs) | shipped, deployed | yes | yes, 1 fixture | yes, host test |
| JoinSplit (7 public inputs) | shipped, deployed | yes | yes, 3 fixtures | yes, host test |
| association (5 public inputs) | shipped, deployed | yes | yes, 1 fixture | yes, host test |

"Host test" and not "landed transaction" is a real distinction and section 5
spells out why.

---

## 1. What was actually still on the toolchain

It is worth being precise, because "we removed the JavaScript" is a claim this
repo already half-earned and could easily overstate.

**Already gone: Node at proving time.** `crates/mirror-cli/src/prove_rust.rs` is
the default proving path. It loads the circom `.wasm` witness calculator and runs
it *in-process* under the pure-Rust `wasmer` VM, reads the `.zkey` with
`ark_circom::read_zkey`, and proves with `ark-groth16`. No `node` process is
spawned to make a proof.

**Still there: circom upstream of that.** The circuit is `.circom` source, so
producing the `.r1cs` / `.wasm` / `.zkey` artifacts requires the `circom`
compiler, `snarkjs`, `node`, and an `npm install` of `circomlib` + `snarkjs`
(`circuits/package.json`). The trusted setup - both the dev setup in
`circuits/build.sh` and the *initial* key the multi-party ceremony re-randomizes -
comes out of `snarkjs groth16 setup`. So four tools remain in the build and
supply chain even though none of them runs at proving time.

That upstream half is what this path removes, for every circuit in the repo.
Section 6 states precisely what still needs circom after this change, which is
not nothing: the DEPLOYED artifacts are still circom artifacts.

---

## 2. What is in the crate

`crates/mirror-circuits`:

| module | what it is |
| --- | --- |
| `poseidon` | the circomlib Poseidon permutation synthesized as R1CS constraints, plus the native reference it is tested against |
| `gadgets` | circomlib's `Num2Bits`, `Switcher` and `ForceEqualIfEnabled`, each at the cost circom pays for it |
| `membership` | the behavioral statement: `commitment = Poseidon(secret, actionHash, epoch)`, `nullifierHash = Poseidon(secret, epoch)`, depth-20 Merkle inclusion, 4 public inputs in the order `[root, nullifierHash, actionHash, epoch]` |
| `transaction` | the confidential-value statement: a 2-in / 2-out JoinSplit with note commitments, owner-and-leaf-bound nullifiers, value conservation, 248-bit range proofs and the `extDataHash` binding, 7 public inputs in the order `[root, publicAmount, extDataHash, inputNullifier[0..2], outputCommitment[0..2]]` |
| `association` | the opt-in compliance statement: everything `membership` proves, plus a second depth-20 inclusion of the SAME commitment under a curator's published root, 5 public inputs in the order `[root, nullifierHash, actionHash, epoch, associationRoot]` |
| `setup` | Groth16 setup / prove / verify and constraint accounting, for all three circuits |
| `onchain` | the `groth16-solana` byte encodings, reusing `mirror-ceremony`'s exporters rather than adding a third copy |

Run it:

```bash
cargo test -p mirror-circuits
```

That run does three Groth16 setups, produces proofs, and verifies them with
`groth16_solana::groth16::Groth16Verifier` - the crate the on-chain program
links - with no circom artifact on disk.

### The association circuit does not fork the membership one

`association.circom` shares `MerkleProof(20)` with `membership.circom` by
including `circuits/merkle.circom`; the Rust side keeps that property rather than
copying it. `membership::native_inclusion` (climb a path natively) and
`membership::enforce_inclusion` (allocate a path as witnesses and enforce the
climb in circuit) are the only definitions of "walk a depth-20 Merkle path" in
the crate. `MembershipCircuit` calls the latter once; `AssociationCircuit` calls
it twice, over two independent paths for one shared leaf. The commitment and
nullifier derivations are the same two `hash_var` calls in both.

Because the statement really is a superset, `AssociationWitness::membership()`
returns the membership witness hiding inside an association one, and two tests
use it: one asserts the four shared public inputs agree, and
`the_committed_fixtures_membership_half_satisfies_the_membership_circuit` takes
the witness rebuilt from the COMMITTED association fixture and requires its pool
half to satisfy the membership circuit with the same first four public signals.
"Strict extension" is therefore checked, not asserted in prose.

### Why the gadgets are hand-written rather than borrowed from `ark-r1cs-std`

Because the arkworks equivalents are more expensive for reasons unrelated to
these statements, and using them would have made the constraint comparison in
section 4 meaningless:

- `FpVar::to_bits_le` decomposes into all 254 bits and then proves the result is
  below the modulus. `Num2Bits(n)` allocates exactly `n` bits and binds their
  weighted sum, which for `n < 253` already forces the value into `[0, 2^n)`.
  That bound *is* the range check the JoinSplit needs, so the cheaper gadget is
  also the faithful one.
- Two `FpVar::conditionally_select` calls cost two rows per Merkle level.
  circomlib's `Switcher` gets both outputs from one multiplication,
  `aux = (R - L) * sel`, and so does `gadgets::switcher`.
- `ForceEqualIfEnabled` has no arkworks counterpart at all. It is what lets a
  shield spend dummy inputs whose Merkle path is meaningless, so it had to be
  written.

### One residual coupling, stated up front

`mirror-circuits` depends on `mirror-ceremony` so it can reuse that crate's
verifying-key exporter and its big-endian G1/G2 point encodings instead of
adding a third copy of the same byte format. `mirror-ceremony` in turn depends
on `ark-circom`, because importing the snarkjs `.zkey` is how the ceremony gets
its initial key. So `cargo build -p mirror-circuits` still *compiles*
`ark-circom` and its `wasmer` runtime, even though nothing on the arkworks path
calls either.

That is a Rust crate already in the lockfile, not a JavaScript toolchain
dependency: `circom`, `snarkjs`, `node` and `npm` are genuinely absent from this
path. Cutting the last Rust link would mean duplicating the encoder, which this
repo deliberately avoids elsewhere, so the coupling is documented rather than
traded for a copy.

---

## 3. The Poseidon gadget, and what the cross-checks actually prove

The gadget is a transcription of the permutation: state
`[domain_tag = 0, in_0, ..]`, four full rounds, `partial` partial rounds, four
full rounds, `x^5` S-box, MDS mix, output `state[0]`. Round constants and the MDS
matrix come from `light_poseidon::parameters::bn254_x5`.

Three checks, in increasing strength:

1. **Gadget == native hash.** `gadget_agrees_with_the_native_hash_at_every_supported_width`
   runs the gadget inside a real `ConstraintSystem` for widths 2..=5 over a
   spread of inputs (zero, one, `r - 1`, `u64::MAX`, fixed pseudo-random
   vectors) and asserts the in-circuit value equals `light-poseidon`'s.
2. **Gadget == the repo's commitment scheme.**
   `gadget_reproduces_the_repo_commitment_scheme` asserts the gadget reproduces
   `mirror_core::commit_with_action_hash`, `mirror_core::nullifier` and
   `mirror_core::merkle_node` - the same functions the CLI, the coordinator and
   the fixtures use.
3. **Gadget == the `sol_poseidon` syscall.**
   `crates/mirror-circuits/tests/end_to_end.rs::gadget_produces_the_syscall_cross_check_vector`
   synthesizes the full membership circuit for a fixed witness and pins the leaf
   and the depth-20 root it computes **in circuit**. The mollusk test
   `programs/mirror-pool/tests/integration.rs::on_chain_accumulator_matches_the_arkworks_gadget_vector`
   pushes that same leaf through the real `COMMIT` instruction, where the root is
   produced by twenty nested `sol_poseidon` syscall calls inside the SBF VM, and
   asserts the same root constant. Neither test trusts the other; both recompute
   and compare to the shared vector.

### The honest caveat on (3)

Agave's `sol_poseidon` syscall is **implemented on top of `light-poseidon`**, and
this gadget takes its round constants and MDS matrix from `light-poseidon` too.
So (3) is **not** agreement between two independently written Poseidons, and
nobody should read it as one. What it does pin is the thing that actually breaks
in practice and has broken in other projects: the parameter set, the state
layout, the domain tag, the round schedule, the input order, and the big-endian
byte encoding, all the way from in-circuit witness to on-chain syscall. A shared
bug inside the Poseidon permutation itself would survive all three checks. The
existing `tests/fixtures/host_frontier.rs` header makes the same disclosure for
the host-vs-syscall frontier check; this is the same caveat, restated rather than
quietly dropped.

---

## 4. Constraint comparison against the committed circom circuits

Every number below is produced by a test, not by hand.

| | circom `membership.r1cs` | arkworks `MembershipCircuit` | circom `transaction.r1cs` | arkworks `TransactionCircuit` | circom `association.r1cs` | arkworks `AssociationCircuit` |
| --- | --- | --- | --- | --- | --- | --- |
| public inputs | 4 | 4 | 7 | 7 | 5 | 5 |
| private inputs | 41 | 41 | 56 | 56 | 81 | 81 |
| **rows that are multiplications** | **5,427** | **5,363** | **13,098** | **12,958** | **10,347** | **10,224** |
| rows that are purely affine | 6,095 | 0 (carried as symbolic linear combinations) | 14,180 | 0 (same) | 11,575 | 0 (same) |
| **total R1CS rows** | **11,522** | **5,363** | **27,278** | **12,958** | **21,922** | **10,224** |
| wires / witness variables | 11,546 | 5,382 | 27,328 | 13,000 | 21,966 | 10,262 |

Reproduce:

```bash
# arkworks side (self-contained)
cargo test -p mirror-circuits -- --nocapture constraint_shape

# circom side: compile the three r1cs files (gitignored build outputs)
cd circuits && npm install
circom membership.circom  --r1cs -l node_modules
circom transaction.circom --r1cs -l node_modules
circom association.circom --r1cs -l node_modules
cd .. && cargo test -p mirror-circuits -- --ignored --nocapture circom
```

Compile the `.r1cs` and nothing else. The comparison needs only the r1cs shape,
whereas the full `build*.sh` scripts also run a trusted setup that OVERWRITES the
committed verifying keys and fixtures in `circuits/artifacts/` with fresh,
non-reproducible ones. Each script says so in its own header; this is the same
warning at the point where a reader is most likely to reach for the wrong
command.

### Membership: why the two "multiplication" columns are close but not equal

The 5,427 circom multiplication rows are fully accounted for, and the test
asserts the accounting:

```
21 x Poseidon(2)  = 21 x 3 x (8*3 + 57) = 5,103     nullifier + 20 Merkle levels
 1 x Poseidon(3)  =  1 x 3 x (8*4 + 56) =   264     the commitment
20 x PathSelector = 20 x 3              =    60     booleanity + two mux rows
                                          -----
                                          5,427
```

The arkworks system is **64 rows smaller**, and the difference is entirely
explained:

- **-66**: in each of the 22 hashes, `state[0]` in round 0 is the constant zero
  domain tag. `ark-r1cs-std` folds `0^5` at synthesis time, so that S-box costs
  nothing; circom keeps it as a signal and pays three rows for it.
- **+2**: the two `===` assertions (`nullifierHash` and `root`) are one row each
  in arkworks, whereas circom emits them as affine rows and they land in the
  6,095 column instead.

`-66 + 2 = -64`. That is the whole delta.

### JoinSplit: the same accounting, at four times the size

The 13,098 circom multiplication rows:

```
 2 x Poseidon(1)  =  2 x 3 x (8*2 + 56) =   432     the two input keypairs
 8 x Poseidon(3)  =  8 x 3 x (8*4 + 56) = 2,112     2 in-commitments, 2 signatures,
                                                    2 nullifiers, 2 out-commitments
40 x Poseidon(2)  = 40 x 3 x (8*3 + 57) = 9,720     20 Merkle levels x 2 inputs
 2 x Num2Bits(20)                       =    40     the two leaf indices
40 x Switcher                           =    40     one row per Merkle level
 2 x ForceEqualIfEnabled                =     6     IsZero (2) + the enable product
 3 x Num2Bits(248)                      =   744     2 output amounts + the magnitude
 1 x sign booleanity                    =     1
 1 x publicAmount === magnitude*sign    =     1
 1 x nullifier distinctness             =     1     see below
 1 x extDataHash * extDataHash          =     1
                                          ------
                                          13,098
```

The arkworks system is **140 rows smaller**, and again the difference is
entirely explained:

- **-150**: 50 hashes x 3, the folded round-0 domain-tag S-box.
- **+10**: rows arkworks spends on equalities circom emits as affine rows - five
  `Num2Bits` sum bindings, two nullifier `===`, two output-commitment `===`, and
  value conservation.

`-150 + 10 = -140`.

One line of that table is counter-intuitive and worth stating, because it is why
the arkworks translation is *cheaper* than a naive reading of the circom source
suggests. circomlib's `IsEqual` is two rows, and `transaction.circom` writes
`sameNullifier[p].out === 0`. That equality is linear, so circom's
linear-substitution pass eliminates `out`, at which point `IsZero`'s second row
`in * out === 0` becomes identically zero and is dropped. What survives is one
row, `diff * inv === 1` - exactly what `FpVar::enforce_not_equal` emits. Both
sides pay one row.

### Association: membership plus one more inclusion, on both sides

The 10,347 circom multiplication rows:

```
41 x Poseidon(2)  = 41 x 3 x (8*3 + 57) = 9,963     nullifier + 2 x 20 Merkle levels
 1 x Poseidon(3)  =  1 x 3 x (8*4 + 56) =   264     the commitment
40 x PathSelector = 40 x 3              =   120     booleanity + two mux rows
                                          ------
                                          10,347
```

The relationship to `membership.r1cs` is exact and the test asserts it:
`10,347 - 5,427 = 4,920 = 20 x 243 + 20 x 3`, which is precisely one more
`MerkleProof(20)`. Nothing else was added, because the statement adds nothing
else: `associationRoot === assoc.root` is affine and lands in the linear column.

The arkworks system is **123 rows smaller**, and the difference is entirely
explained:

- **-126**: 42 hashes x 3, the folded round-0 domain-tag S-box.
- **+3**: the three `===` assertions (`nullifierHash`, `root`,
  `associationRoot`) are one row each in arkworks; circom emits them as affine
  rows, so they land in the 11,575 column instead.

`-126 + 3 = -123`. The arkworks side keeps the same superset relationship:
`10,224 - 5,363 = 4,861 = 20 x 240 + 20 x 3 + 1`, one more inclusion plus the
one extra `===` row arkworks pays and circom does not.

Both sides pay for a FULL second inclusion, and there is no cheaper way to do it:
the curated tree's leaf index is unrelated to the pool's, so no path work is
shareable between the two walks. What the two halves share is the leaf, and the
leaf is one hash, already counted once.

### What this comparison is NOT

It is **not** a claim of constraint-for-constraint identity. Equal
multiplication-row counts (up to differences that are themselves itemized) plus
identical hash outputs is strong evidence the two systems express the same
statement at the same cost. It is not a proof that the two R1CS matrices are the
same up to permutation, and no such proof was attempted. Wire ordering, variable
indices, and the linear structure differ.

The total-rows columns are real but should not be waved around: circom's default
optimization level keeps affine rows in the emitted system, and arkworks
represents the same affine work as free symbolic linear combinations. Both prove
the same statement. The number that matters for proving cost is the
multiplication count, and there the two systems are within 1.18% (membership),
1.07% (JoinSplit) and 1.19% (association).

---

## 4b. The equivalence checks: replaying the committed circom fixtures

The constraint counts say the two systems cost the same. They do not, on their
own, say the two systems *accept the same witnesses*. Every committed snarkjs
proof in this repo has a witness reconstructible from published constants, so a
much sharper check is available for all three circuits, and it is run: five
fixtures in total, one per circuit for membership and association and three for
the JoinSplit.

### JoinSplit

`circuits/artifacts/` ships three snarkjs proofs produced by
`transaction.circom` - SHIELD, TRANSFER and UNSHIELD - and
`gen_transaction_fixture.js` built them from fixed, published constants. So the
private witness behind each committed proof is fully reconstructible.
`arkworks_agrees_with_every_committed_circom_fixture` rebuilds all three, feeds
them to the ARKWORKS constraint system, and requires:

1. the arkworks system is **satisfied** by the witness circom accepted, and
2. the seven public inputs arkworks derives are **equal, element by element, in
   order**, to the seven `publicSignals` snarkjs emitted.

That covers all three operations the one universal statement has to express: two
dummy inputs and a positive `publicAmount` (shield), two real inputs at leaves 0
and 1 with `publicAmount = 0` (transfer), and a real input plus a dummy with a
negative `publicAmount` (unshield). It exercises both `Switcher` directions, the
disabled and enabled branches of `ForceEqualIfEnabled`, and both signs of the
`publicAmount` decoding.

The public-input LAYOUT is not restated in the test either: it is read from the
committed `transaction_fixture_meta.json`, so a reordering on the circom side
fails the arkworks test.

### Association

`circuits/artifacts/association_proof_fixture.json` is one snarkjs proof from
`association.circom`, and `association_fixture_meta.json` publishes the entire
scenario `gen_association_fixture.js` used: the secret, the epoch, the recipient
bytes, the amount, both leaf lists and both leaf indices. That scenario is
deliberately non-degenerate - **five pool deposits, of which the curator vouches
for three**, ours at pool leaf 3 and association leaf 1 - so both trees have real
non-zero sibling paths and two pool deposits are genuinely excluded.

`arkworks_agrees_with_the_committed_circom_fixture` rebuilds that witness and
requires:

1. the arkworks system is **satisfied** by the witness circom accepted, and
2. the five public inputs arkworks derives are **equal, element by element, in
   order**, to the five `publicSignals` snarkjs emitted.

Nothing is copied out of the fixture into the witness. `actionHash` is recomputed
from the recipient and amount through `mirror_core::transfer_action_hash`, the
commitment is recomputed from the secret, and both roots are recomputed by
rebuilding both trees with the same dense-prefix/zero-ladder rule the generator
and the on-chain accumulator use. The committed leaf lists are used only to place
other participants' commitments, and the test asserts the *derived* commitment
really is the leaf sitting at each declared index - so a meta whose leaf lists
were edited without regenerating the proof fails here rather than passing
vacuously. The two roots are then cross-checked a second way: the value the
witness builder reaches by CLIMBING the path must equal the value the tree
builder reaches by hashing level by level.

The public-input LAYOUT is read from `association_fixture_meta.json`, and the
membership layout is read from `fixture_meta.json`; the test requires the former
to be the latter plus exactly one appended element. A circom-side reorder on
either circuit fails it.

### Membership

`arkworks_agrees_with_the_committed_circom_fixture` in `tests/end_to_end.rs` does
the same for `proof_fixture.json`, rebuilt from the constants `gen_fixture.js`
fixes: leaf index 21 (`0b10101`, so both path-index bits are exercised) in an
otherwise-empty depth-20 tree. Its scenario constants come from the generator
script rather than from `fixture_meta.json`, which records only the public-input
order - a weaker provenance than the association and JoinSplit metas, and worth
naming rather than glossing. The layout itself IS read from the committed meta.

### What these checks are, and are not

These are per-witness agreement checks on published fixtures, not a proof of
equivalence over all inputs. Five fixtures are not a quantifier. It is the
strongest evidence available without a formal argument, and the difference is
worth keeping straight.

---

## 5. End to end: a fresh proof through the real on-chain verifier

All three circuits do, in one test each
(`arkworks_proof_is_accepted_by_the_on_chain_verifier`,
`arkworks_joinsplit_proof_is_accepted_by_the_on_chain_verifier` and
`arkworks_association_proof_is_accepted_by_the_on_chain_verifier`):

1. `Groth16::circuit_specific_setup` over the arkworks circuit.
2. `Groth16::prove` for a witness whose public inputs were derived natively.
3. Serialize the proof into the `groth16-solana` layout (big-endian,
   uncompressed, G2 imaginary-part-first, `proof_a` pre-negated) through
   `mirror-ceremony`'s existing point encoders.
4. Export the verifying key with `mirror_ceremony::vk_export::solana_bytes`.
5. Run `groth16_solana::groth16::Groth16Verifier` over the result and require it
   to accept.

The JoinSplit run proves a **fresh witness that appears in no fixture**: two real
notes at leaves 2 and 3 of a four-leaf tree, partly withdrawn with a relayer fee,
so the path bits, the enabled root check and the negative `publicAmount` branch
are all live.

The association run does the same: a **fresh witness over new inputs**, with a
different secret, epoch, recipient and amount from the fixture's, in a
seven-deposit pool of which a curator vouches for four. Ours sits at pool leaf 6
and association leaf 2, so the two index bit patterns differ from each other and
from the fixture's, and both walks run over non-zero siblings.

Step 5 is not vacuous. `on_chain_verifier_rejects_a_tampered_public_input`
(membership) moves the epoch; on the JoinSplit side
`the_on_chain_verifier_rejects_a_moved_amount_or_nullifier` moves `publicAmount`
and `inputNullifier[0]`; and on the association side
`the_on_chain_verifier_rejects_a_moved_public_input` moves the pool root, the
nullifier and - the one that carries the compliance story -
`associationRoot`. All require the same verifier to reject.

That last one is the substitution `SETTLE_ZK_ASSOCIATED` has to defeat: the
instruction reads `associationRoot` off the curator's `AssociationSet` account
and feeds it to the verifier, so a proof made against one curator's root must not
verify against another's. It does not.

Each key also encodes to the **same canonical registry record** the program's
write-once `INIT_VK` expects - 769 bytes for 4 public inputs, 833 for 5, 961 for
7 - and the same tests assert the keys do **not** hash to the digests
`programs/mirror-pool/src/vk_digest.rs` pins for the deployed circom keys.

### This is a HOST test, not a landed transaction

Nothing here settles on chain, and it cannot. The deployed program pins each
verifying key by SHA-256 digest, and an arkworks-native constraint system is a
different constraint system, so it has a different key and a different digest.
Landing an arkworks proof would require pinning a second digest, which is a
program upgrade and a deliberate decision about which circuit is authoritative.
That decision was not taken here and no program logic was changed. What the test
does establish is that the proof, the key and the byte encodings are all correct
against the very verifier code the program runs.

### The one thing `extDataHash` does not do

`transaction.circom` binds `extDataHash` with
`extDataHashSquare <== extDataHash * extDataHash`, and the arkworks circuit
emits the same row. It is worth being precise about what that row achieves,
because it is easy to overstate: **it does not constrain `extDataHash` at all.**
The row is satisfiable for any value; it merely defines the square. Changing
`extDataHash` leaves the constraint system satisfied - in circom for the same
reason. In circom the row exists because an unused signal is pruned and snarkjs
then refuses to treat it as public.

What makes ext data tamper-evident is Groth16 itself: `extDataHash` is a public
input, so a proof made for one value does not verify against another. That is a
property of the proof, not of the R1CS, so it is tested where it lives -
`the_on_chain_verifier_rejects_a_moved_ext_data_hash` moves it and requires the
real `groth16-solana` verifier to reject. The unit test
`ext_data_hash_is_bound_by_groth16_not_by_a_constraint` asserts the other half
of that statement, that the constraint system alone does *not* catch it.

---

## 6. Limits, stated plainly

- **These are not the deployed circuits.** The deployed program verifies against
  digest-pinned circom keys. A different constraint system means a different
  verifying key, so an arkworks proof is rejected on chain today. Making it
  deployable means pinning a second digest, which means a program upgrade and a
  deliberate decision about which circuit is authoritative. That decision was not
  taken here and no program logic was changed.
- **The setup is single-party.** `setup::setup`, `setup::transaction_setup` and
  `setup::association_setup` are `circuit_specific_setup` with a caller-supplied
  RNG. Whoever runs one can forge proofs unless the toxic waste is destroyed. It
  is a development setup, exactly like `circuits/build.sh`, and it is not what
  `docs/CEREMONY.md` describes.
- **Equivalence is checked per witness, not proven.** Section 4b replays five
  published circom fixtures through the arkworks circuits and requires identical
  public signals. That is not a proof that the constraint systems accept exactly
  the same witness sets.
- **`association.r1cs` is not a committed artifact.** The other two `.r1cs`
  files are gitignored build outputs too, but at least the deployed association
  key was produced from one. The circom numbers in section 4 for association
  therefore come from recompiling `association.circom` with the same compiler
  version, not from an artifact shipped with the repo. Recompiling the r1cs is
  deterministic given the source and circomlib version; the *setup* is not, which
  is why section 4's reproduce block compiles the r1cs alone and never runs
  `build_association.sh`.
- **The circom path is untouched by this crate.** No artifact under
  `circuits/artifacts/` changes because of the arkworks work, the vendored
  program-side keys still match `circuits/artifacts/`, and no pinned digest moves
  for this reason. Adding the association circuit changed nothing here either:
  every file under `circuits/artifacts/` and all three vendored keys in
  `programs/mirror-pool/src/` are byte-identical before and after, and
  `digests_match_the_vendored_keys` still passes. (The membership key and its
  digest DID change earlier, when the phase-2 ceremony key was deployed -
  `docs/CEREMONY.md` section 10. That is unrelated to this crate, and the
  JoinSplit and association artifacts were byte-identical across it.)
- **There is deliberately no `mirror-cli prove --backend arkworks`.** A proof from
  this path cannot land on chain (first bullet), so a CLI switch that looked like
  a proving option would hand a reviewer a proof that silently fails to settle.
  The entry point is `cargo test -p mirror-circuits`, and the library API
  (`mirror_circuits::setup` / `::onchain`) is what a future deployment would call
  if a second digest were ever pinned.

---

## 7. Exactly what still needs circom after this change

For a reviewer weighing "Rust-only vs circom" as a supply-chain argument, this is
the state, split into what no longer needs the JavaScript toolchain and what
still does.

**No longer needs `circom` / `snarkjs` / `node` / `npm`** - every circuit in the
repo, for circuit definition, trusted setup, proving and verification:

| circuit | arkworks rows | circom rows | agreement evidence |
| --- | --- | --- | --- |
| membership | 5,363 | 5,427 | 1 committed fixture replayed, identical public signals |
| association | 10,224 | 10,347 | 1 committed fixture replayed, identical public signals |
| JoinSplit | 12,958 | 13,098 | 3 committed fixtures replayed, identical public signals |

All three within about 1% of the circom system they mirror, all three producing
proofs the real `groth16-solana` verifier accepts, all three with every row of
the delta itemized.

**Still needs `circom` / `snarkjs` / `node` / `npm`**, and this is the part that
would be dishonest to leave out:

1. **The deployed artifacts.** The keys the program pins by digest
   (`src/vk.rs`, `src/transaction_vk.rs`, `src/association_vk.rs`) were produced
   by `snarkjs` from `circom`-compiled r1cs. Rebuilding *what is deployed today*
   still requires the full chain: `npm install` in `circuits/`, `circom` to
   compile, `snarkjs` for the setup and the verifying-key export.
2. **The default proving path.** `crates/mirror-cli/src/prove_rust.rs` loads the
   circom `.wasm` witness calculator and the snarkjs `.zkey`. No `node` process
   runs, but those two files must exist, and only `circom` and `snarkjs` produce
   them.
3. **The ceremony's initial key.** `docs/CEREMONY.md`'s phase-2 re-randomizes a
   `snarkjs groth16 setup` output, so a ceremony run still starts from a snarkjs
   artifact.
4. **The committed proof fixtures**, which the on-chain tests and the arkworks
   equivalence checks both consume, are snarkjs output by construction. That is
   the point of them: they are the circom side of the comparison.
5. **`circuits/*.r1cs`**, needed only to re-derive the circom column of section
   4's table.

So the accurate claim is: **the circom dependency is now demonstrated to be
removable for every circuit in the repo, and removed for none of them.** Making
it actually removable means pinning arkworks-key digests in a program upgrade,
and choosing which constraint system is authoritative. That is a deployment
decision, not a code-availability one, and it has not been taken.
