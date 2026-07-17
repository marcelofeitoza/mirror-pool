# mirror-pool circuits

Zero-knowledge membership circuit for mirror-pool's ZK-deniable initiation.

mirror-pool is "Tornado Cash for behavior": participants commit an intent into a
Poseidon Merkle accumulator, and at settlement a relay proves in zero knowledge
that each settled action corresponds to some committed member without revealing
which one. This directory holds the Groth16 circuit that is the heart of that
guarantee, its dev/test trusted setup, and the artifacts the on-chain Rust
verifier consumes.

Clean-room and MIT licensed. It depends only on public libraries: circomlib
(Poseidon), snarkjs (Groth16), circomlibjs (JS Poseidon for the fixture), and
the `groth16-solana` crate (v0.2.0) for on-chain verification.

## Canonical commitment scheme

This is the canonical scheme that the on-chain accumulator and the off-chain
crates MUST match. All values are BN254 scalar-field elements. Poseidon is
circomlib Poseidon; the input order is significant and fixed:

```
commitment    = Poseidon(secret, actionHash, epoch)     // the Merkle leaf
nullifierHash = Poseidon(secret, epoch)                 // epoch-scoped tag
```

- `Poseidon(secret, actionHash, epoch)` is the 3-input Poseidon (t = 4), inputs
  supplied in exactly that order.
- `Poseidon(secret, epoch)` is the 2-input Poseidon (t = 3), inputs in exactly
  that order.
- Internal Merkle nodes use the 2-input Poseidon: `node = Poseidon(left, right)`.

Binding `actionHash` and `epoch` as public inputs is what stops the relay from
re-targeting the action or replaying a proof across epochs. A proof is valid only
for the exact `(actionHash, epoch)` pair the prover committed to.

## Merkle accumulator

- `MERKLE_DEPTH = 20`, fixed to match the on-chain accumulator (2^20 leaves).
- Empty-subtree hashes are the canonical zero ladder: `zeros[0] = 0`,
  `zeros[i] = Poseidon(zeros[i-1], zeros[i-1])`.
- A path index bit of `0` means the current node is the left child (sibling on
  the right); a bit of `1` means the current node is the right child (sibling on
  the left).

## Signals

Public inputs, in the exact order snarkjs emits them in `publicSignals` (and the
order the on-chain `PUBLIC_INPUTS` array must use):

| index | signal          | meaning                                   |
| ----- | --------------- | ----------------------------------------- |
| 0     | `root`          | Merkle root of the intent accumulator     |
| 1     | `nullifierHash` | `Poseidon(secret, epoch)`, prevents reuse |
| 2     | `actionHash`    | bound action digest (class + size bucket) |
| 3     | `epoch`         | settlement epoch id                       |

Private inputs:

| signal                    | meaning                                     |
| ------------------------- | ------------------------------------------- |
| `secret`                  | the participant's per-commitment secret     |
| `pathElements[20]`        | Merkle sibling hashes, leaf to root         |
| `pathIndices[20]`         | path bits (0 = left child, 1 = right child) |

The circuit enforces three things:

1. `commitment = Poseidon(secret, actionHash, epoch)` (recomputes the leaf).
2. Merkle inclusion of that leaf under `root` via `Poseidon(left, right)` nodes.
3. `nullifierHash == Poseidon(secret, epoch)`.

## Rebuild

```sh
npm install      # once: circomlib, circomlibjs, snarkjs
bash build.sh
```

`build.sh` compiles the circuit, runs the Groth16 phase-2 setup, generates a
known-good proof fixture, verifies it, and emits the Rust constants. It reuses
`pot16_final.ptau` (a universal, circuit-independent phase-1 powers-of-tau) if
present, and otherwise generates a reproducible 2^16 phase-1 from a fixed entropy
string.

Constraint count: 11522 total R1CS constraints (5427 non-linear, 6095 linear),
4 public inputs, 41 private inputs. This fits comfortably inside a 2^16 (65536)
powers-of-tau.

Verify the fixture directly at any time:

```sh
snarkjs groth16 verify artifacts/verification_key.json <(node -e \
  'console.log(JSON.stringify(require("./artifacts/proof_fixture.json").publicSignals))') \
  <(node -e 'console.log(JSON.stringify(require("./artifacts/proof_fixture.json").proof))')
# -> [INFO] snarkJS: OK!
```

## Dev-setup caveat

The trusted setup produced by `build.sh` is a DEVELOPMENT and TEST setup only.
The phase-2 contribution uses a hard-coded entropy string so the build is
reproducible, which by definition makes the toxic waste public. It is NOT a
secure ceremony and MUST NOT be used to secure real value. A real multi-party
trusted setup ceremony is a separate deliverable.

## Artifacts

Committed (small, in `artifacts/`):

| file                    | contents                                               |
| ----------------------- | ------------------------------------------------------ |
| `verification_key.json` | snarkjs Groth16 verifying key                          |
| `vk.json`               | copy of the verifying key (consumed by the converter)  |
| `vk.rs`                 | `VERIFYINGKEY: Groth16Verifyingkey` for groth16-solana |
| `proof_fixture.json`    | `{ proof, publicSignals }` from snarkjs                |
| `proof_fixture.rs`      | `PROOF_A` / `PROOF_B` / `PROOF_C` / `PUBLIC_INPUTS`     |
| `fixture_meta.json`     | public-input order metadata                            |

Not committed (gitignored build outputs): `node_modules/`, `*.ptau`, `*.zkey`,
`*.r1cs`, `*.sym`, `*.wasm`, `*_js/`.

## On-chain verifier integration (groth16-solana v0.2.0)

`vk.rs` and `proof_fixture.rs` are emitted in the exact byte layout the
`groth16-solana` crate expects for its `alt_bn128` syscall based verifier:

- All elements are big-endian and uncompressed.
- G1 point = `x_be(32) || y_be(32)` (64 bytes).
- G2 point = `x_c1_be(32) || x_c0_be(32) || y_c1_be(32) || y_c0_be(32)` (128
  bytes). Each Fp2 coordinate is serialized imaginary-part-first.
- Each field element (public input) = `value_be(32)`.
- `vk_ic` has `nPublic + 1 = 5` entries; `IC[0]` is the constant term.
- The `vk_gamme_g2` field name is spelled that way to match the (typo'd) field
  name in `groth16-solana` 0.2.0.

`PROOF_A` is emitted ALREADY NEGATED. `Groth16Verifier::new` expects the negated
A because the pairing check computes `e(-A, B) * e(alpha, beta) * e(L, gamma) *
e(C, delta) == 1` and does not negate A internally. Negation over the BN254 base
field Fq is `-(x, y) = (x, q - y)`. Because it is pre-negated, the on-chain
program does not need any `ark` serialization at runtime:

```rust
use groth16_solana::groth16::Groth16Verifier;
// include the generated constants (paths as vendored into the program):
// mod vk;            use vk::VERIFYINGKEY;
// mod proof_fixture; use proof_fixture::{PROOF_A, PROOF_B, PROOF_C, PUBLIC_INPUTS};

let mut verifier = Groth16Verifier::new(
    &PROOF_A, &PROOF_B, &PROOF_C, &PUBLIC_INPUTS, &VERIFYINGKEY,
)?;
verifier.verify()?; // Ok(()) for the shipped fixture
```

The layout was validated end to end against `groth16-solana` 0.2.0: the shipped
fixture verifies, and a fixture with any mutated public input is rejected. As a
cross-check, `vk_alpha_g1` in `vk.rs` is byte-identical to the crate's own
reference verifying key (both derive alpha from the same universal ptau), which
confirms the G1 serialization.

Integration notes for the on-chain program author:

- The program must supply `PUBLIC_INPUTS` in the fixed order above (`root`,
  `nullifierHash`, `actionHash`, `epoch`). A mismatch is a silent verification
  failure, not a compile error.
- `Groth16Verifier::new` returns `InvalidPublicInputsLength` unless
  `public_inputs.len() + 1 == vk_ic.len()`, i.e. exactly 4 public inputs here.
- `verify()` (as opposed to `verify_unchecked()`) also rejects any public input
  that is not less than the BN254 scalar field modulus.
- The whole verification runs in under ~200k compute units per the crate docs.
