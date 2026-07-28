# The arkworks path: shrinking the toolchain surface

An arkworks-native constraint system for the **membership** circuit, alongside
the circom one. Same statement, no `circom`, no `snarkjs`, no `node`, no
`npm` - and the resulting proof is checked with the same `groth16-solana`
verifier the on-chain program links.

This document says exactly what was built, what was measured, and what is still
circom-shaped. Nothing below is an estimate.

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

That upstream half is what this path removes, for one circuit.

---

## 2. What is in the crate

`crates/mirror-circuits`:

| module | what it is |
| --- | --- |
| `poseidon` | the circomlib Poseidon permutation synthesized as R1CS constraints, plus the native reference it is tested against |
| `membership` | the statement: `commitment = Poseidon(secret, actionHash, epoch)`, `nullifierHash = Poseidon(secret, epoch)`, depth-20 Merkle inclusion, 4 public inputs in the order `[root, nullifierHash, actionHash, epoch]` |
| `setup` | Groth16 setup / prove / verify and constraint accounting |
| `onchain` | the `groth16-solana` byte encodings, reusing `mirror-ceremony`'s exporters rather than adding a third copy |

Run it:

```bash
cargo test -p mirror-circuits
```

That run does a Groth16 setup, produces a proof, and verifies it with
`groth16_solana::groth16::Groth16Verifier` - the crate the on-chain program
links - with no circom artifact on disk.

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

## 4. Constraint comparison against the committed circom circuit

Both numbers below are produced by tests, not by hand.

| | circom `membership.r1cs` | arkworks `MembershipCircuit` |
| --- | --- | --- |
| public inputs | 4 | 4 |
| private inputs | 41 | 41 |
| **rows that are multiplications** | **5,427** | **5,363** |
| rows that are purely affine | 6,095 | 0 (carried as symbolic linear combinations) |
| **total R1CS rows** | **11,522** | **5,363** |

Reproduce:

```bash
# arkworks side (self-contained)
cargo test -p mirror-circuits -- --nocapture membership_constraint_shape

# circom side (needs the gitignored build artifact: bash circuits/build.sh)
cargo test -p mirror-circuits -- --ignored --nocapture circom
```

### Why the two "multiplication" columns are close but not equal

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
- **+2**: the two `===` assertions (`nullifierHash` and `root`) are one
  multiplication row each in arkworks, whereas circom emits them as affine rows
  and they land in the 6,095 column instead.

`-66 + 2 = -64`. That is the whole delta.

### What this comparison is NOT

It is **not** a claim of constraint-for-constraint identity. Equal
multiplication-row counts (up to a 64-row difference that is itself explained)
plus identical hash outputs is strong evidence the two systems express the same
statement at the same cost. It is not a proof that the two R1CS matrices are the
same up to permutation, and no such proof was attempted. Wire ordering, variable
indices, and the linear structure differ.

The 11,522-vs-5,363 "total rows" comparison is real but should not be waved
around: circom's default optimization level keeps affine rows in the emitted
system, and arkworks represents the same affine work as free symbolic linear
combinations. Both prove the same statement. The number that matters for proving
cost is the multiplication count, and there the two are within 1.2%.

---

## 5. End to end: a fresh proof through the real on-chain verifier

`arkworks_proof_is_accepted_by_the_on_chain_verifier` does, in one test:

1. `Groth16::circuit_specific_setup` over the arkworks membership circuit.
2. `Groth16::prove` for a witness whose public inputs were derived natively.
3. Serialize the proof into the `groth16-solana` layout (big-endian,
   uncompressed, G2 imaginary-part-first, `proof_a` pre-negated) through
   `mirror-ceremony`'s existing point encoders.
4. Export the verifying key with `mirror_ceremony::vk_export::solana_bytes`.
5. Run `groth16_solana::groth16::Groth16Verifier` over the result and require it
   to accept.

`on_chain_verifier_rejects_a_tampered_public_input` moves the epoch and requires
the same verifier to reject, so step 5 is not vacuous.

The key also encodes to the **same 769-byte canonical registry record** the
program's write-once `INIT_VK` expects for a 4-public-input circuit
(`arkworks_key_encodes_to_the_registry_shape_but_is_not_the_pinned_key`), and
that test also asserts it does **not** hash to the digest
`programs/mirror-pool/src/vk_digest.rs` pins for the deployed membership key.

---

## 6. Limits, stated plainly

- **This is not the deployed circuit.** The deployed program verifies against a
  digest-pinned circom key. A different constraint system means a different
  verifying key, so an arkworks proof is rejected on chain today. Making it
  deployable means pinning a second digest, which means a program upgrade and a
  deliberate decision about which circuit is authoritative. That decision was not
  taken here and no program logic was changed.
- **The setup is single-party.** `setup::setup` is `circuit_specific_setup` with
  a caller-supplied RNG. Whoever runs it can forge proofs unless the toxic waste
  is destroyed. It is a development setup, exactly like `circuits/build.sh`, and
  it is not what `docs/CEREMONY.md` describes.
- **Only the membership circuit.** The confidential-value JoinSplit circuit
  (27,278 circom rows, 13,098 of them multiplications) has no arkworks version.
  The gadget and the Merkle machinery here would carry over; the JoinSplit
  statement itself - two inputs, two outputs, the signature and nullifier
  derivation, the `publicAmount` field arithmetic - would not, and pretending
  otherwise would be the overclaim this document exists to avoid.
- **The circom path is untouched.** Every pre-existing artifact under
  `circuits/` is byte-identical, the vendored program-side keys still match
  `circuits/artifacts/`, and the pinned digests are unchanged.
- **There is deliberately no `mirror-cli prove --backend arkworks`.** A proof from
  this path cannot land on chain (previous bullet), so a CLI switch that looked
  like a proving option would hand a reviewer a proof that silently fails to
  settle. The entry point is `cargo test -p mirror-circuits`, and the library API
  (`mirror_circuits::setup` / `::onchain`) is what a future deployment would call
  if the second digest were ever pinned.

---

## 7. What this would buy if it were finished

For a reviewer weighing "Rust-only vs circom" as a supply-chain argument, the
honest summary of the state after this change is:

- Membership: circuit, setup, proving and verification can all be Rust. The
  circom membership circuit remains the deployed one.
- JoinSplit: still circom-only.
- Therefore `circom`, `snarkjs`, `node` and `npm` are still required to build
  this repo's deployed artifacts. The dependency is *demonstrated to be
  removable* for one circuit, not removed.
