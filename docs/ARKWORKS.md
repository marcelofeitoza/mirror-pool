# The arkworks path: shrinking the toolchain surface

Arkworks-native constraint systems for the **membership** circuit and the
**confidential-value JoinSplit**, alongside the circom ones. Same statements, no
`circom`, no `snarkjs`, no `node`, no `npm` - and the resulting proofs are
checked with the same `groth16-solana` verifier the on-chain program links.

This document says exactly what was built, what was measured, and what is still
circom-shaped. Nothing below is an estimate.

| circuit | circom | arkworks | arkworks proof verified by `groth16-solana` |
| --- | --- | --- | --- |
| membership (4 public inputs) | shipped, deployed | yes | yes, host test |
| JoinSplit (7 public inputs) | shipped, deployed | yes | yes, host test |
| association (5 public inputs) | shipped, deployed | **no** | n/a |

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

That upstream half is what this path removes, for two of the three circuits.

---

## 2. What is in the crate

`crates/mirror-circuits`:

| module | what it is |
| --- | --- |
| `poseidon` | the circomlib Poseidon permutation synthesized as R1CS constraints, plus the native reference it is tested against |
| `gadgets` | circomlib's `Num2Bits`, `Switcher` and `ForceEqualIfEnabled`, each at the cost circom pays for it |
| `membership` | the behavioral statement: `commitment = Poseidon(secret, actionHash, epoch)`, `nullifierHash = Poseidon(secret, epoch)`, depth-20 Merkle inclusion, 4 public inputs in the order `[root, nullifierHash, actionHash, epoch]` |
| `transaction` | the confidential-value statement: a 2-in / 2-out JoinSplit with note commitments, owner-and-leaf-bound nullifiers, value conservation, 248-bit range proofs and the `extDataHash` binding, 7 public inputs in the order `[root, publicAmount, extDataHash, inputNullifier[0..2], outputCommitment[0..2]]` |
| `setup` | Groth16 setup / prove / verify and constraint accounting, for both circuits |
| `onchain` | the `groth16-solana` byte encodings, reusing `mirror-ceremony`'s exporters rather than adding a third copy |

Run it:

```bash
cargo test -p mirror-circuits
```

That run does two Groth16 setups, produces proofs, and verifies them with
`groth16_solana::groth16::Groth16Verifier` - the crate the on-chain program
links - with no circom artifact on disk.

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

| | circom `membership.r1cs` | arkworks `MembershipCircuit` | circom `transaction.r1cs` | arkworks `TransactionCircuit` |
| --- | --- | --- | --- | --- |
| public inputs | 4 | 4 | 7 | 7 |
| private inputs | 41 | 41 | 56 | 56 |
| **rows that are multiplications** | **5,427** | **5,363** | **13,098** | **12,958** |
| rows that are purely affine | 6,095 | 0 (carried as symbolic linear combinations) | 14,180 | 0 (same) |
| **total R1CS rows** | **11,522** | **5,363** | **27,278** | **12,958** |

Reproduce:

```bash
# arkworks side (self-contained)
cargo test -p mirror-circuits -- --nocapture constraint_shape

# circom side (needs the gitignored build artifacts)
cargo test -p mirror-circuits -- --ignored --nocapture circom
```

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
multiplication count, and there the two systems are within 1.2% (membership) and
1.1% (JoinSplit).

---

## 4b. The JoinSplit equivalence check: replaying the committed circom fixtures

The constraint counts say the two systems cost the same. They do not, on their
own, say the two systems *accept the same witnesses*. For the JoinSplit there is
a much sharper check available, and it is run:

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

This is a per-witness agreement check on published fixtures, not a proof of
equivalence over all inputs. It is the strongest evidence available without a
formal argument, and the difference is worth keeping straight.

---

## 5. End to end: a fresh proof through the real on-chain verifier

Both circuits do, in one test each
(`arkworks_proof_is_accepted_by_the_on_chain_verifier` and
`arkworks_joinsplit_proof_is_accepted_by_the_on_chain_verifier`):

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

Step 5 is not vacuous. `on_chain_verifier_rejects_a_tampered_public_input`
(membership) moves the epoch, and on the JoinSplit side
`the_on_chain_verifier_rejects_a_moved_amount_or_nullifier` moves `publicAmount`
and `inputNullifier[0]`; all require the same verifier to reject.

Each key also encodes to the **same canonical registry record** the program's
write-once `INIT_VK` expects - 769 bytes for 4 public inputs, 961 for 7 - and the
same tests assert the keys do **not** hash to the digests
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
- **The setup is single-party.** `setup::setup` and `setup::transaction_setup`
  are `circuit_specific_setup` with a caller-supplied RNG. Whoever runs one can
  forge proofs unless the toxic waste is destroyed. It is a development setup,
  exactly like `circuits/build.sh`, and it is not what `docs/CEREMONY.md`
  describes.
- **The association circuit is still circom-only.** `association.circom` (5
  public inputs) has no arkworks version. The Poseidon gadget and the Merkle
  machinery here would carry over, but its statement has not been written and
  pretending otherwise would be the overclaim this document exists to avoid.
- **Equivalence is checked per witness, not proven.** Section 4b replays three
  published circom fixtures through the arkworks JoinSplit and requires identical
  public signals. That is not a proof that the two constraint systems accept
  exactly the same witness set.
- **The circom path is untouched.** Every pre-existing artifact under
  `circuits/` is byte-identical, the vendored program-side keys still match
  `circuits/artifacts/`, and the pinned digests are unchanged.
- **There is deliberately no `mirror-cli prove --backend arkworks`.** A proof from
  this path cannot land on chain (first bullet), so a CLI switch that looked like
  a proving option would hand a reviewer a proof that silently fails to settle.
  The entry point is `cargo test -p mirror-circuits`, and the library API
  (`mirror_circuits::setup` / `::onchain`) is what a future deployment would call
  if a second digest were ever pinned.

---

## 7. What this would buy if it were finished

For a reviewer weighing "Rust-only vs circom" as a supply-chain argument, the
honest summary of the state after this change is:

- Membership: circuit, setup, proving and verification can all be Rust.
- JoinSplit: circuit, setup, proving and verification can all be Rust, and the
  arkworks version is checked to agree with the committed circom fixtures on
  every public signal.
- Association: still circom-only.
- The circom circuits remain the deployed ones, so `circom`, `snarkjs`, `node`
  and `npm` are still required to build this repo's deployed artifacts. The
  dependency is now *demonstrated to be removable* for the two circuits that
  carry the privacy claims - behavioral membership and confidential value - and
  removed for none of them.

Two circuits down is the difference between "this could be done" and "this was
done, and here is what it costs": 5,363 and 12,958 constraints, both within
about 1% of the circom systems they replace, both producing proofs the on-chain
verifier accepts.
