# mirror-pool circuits

This directory holds three independent Groth16 circuits and their dev/test trusted
setups and on-chain artifacts:

- **`membership.circom`**: the ZK-deniable initiation (behavioral) circuit,
  documented in the rest of this file.
- **`transaction.circom`**: a 2-in / 2-out confidential-value JoinSplit
  (Tornado-Nova style) for shielded value notes (UTXOs): shield, private
  transfer, and unshield. Its canonical note/nullifier scheme, the FIELD_SIZE
  `publicAmount` encoding, the 7 public inputs, build steps, and groth16-solana
  layout are specified in **[`TRANSACTION.md`](./TRANSACTION.md)**. Build it with
  `bash build_transaction.sh` (or `npm run build:transaction`). It is additive:
  it shares `convert_to_rust.js` (via `--circuit=transaction`) but leaves the
  membership circuit and all its artifacts untouched.
- **`association.circom`**: the OPT-IN compliance circuit (Privacy-Pools-style
  association sets). It proves the membership statement AND that the same
  commitment is in a curator's curated set, under a 5th public input
  `associationRoot`. Build it with `bash build_association.sh`; it touches only
  the `association_*` artifacts. The trust model, the censorship tradeoff and the
  limits are in **[`../docs/COMPLIANCE.md`](../docs/COMPLIANCE.md)**.

`membership.circom` and `association.circom` share their Poseidon Merkle
templates through **`merkle.circom`** (`HashLeftRight`, `PathSelector`,
`MerkleProof(depth)`), extracted verbatim from `membership.circom` rather than
forked. See [Artifact consistency](#artifact-consistency) for why that extraction
is safe for the already-deployed membership key, and how to re-check it.

---

## Membership circuit

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

## Dev-setup caveat, and the real ceremony

The trusted setup produced by `build.sh` (and by `build_transaction.sh`) is a
DEVELOPMENT and TEST setup only. Its phase-2 contribution uses a hard-coded
entropy string so the build is reproducible, which by definition makes the toxic
waste public. It is NOT a secure ceremony and MUST NOT be used to secure real
value.

**The verifying keys committed in `artifacts/` and embedded in the deployed
program came from that dev setup. That remains true until a real ceremony output
is exported and the program is redeployed with it.**

A real multi-party **phase-2 ceremony is implemented** in
`crates/mirror-ceremony`, driven from `mirror-cli ceremony ...`, and documented in
[`../docs/CEREMONY.md`](../docs/CEREMONY.md). It imports a public phase-1
powers-of-tau, re-randomizes `delta` per contribution with a Schnorr proof of
knowledge bound to the contributor, chains the transcript with SHA-256, verifies
the whole chain with pairing same-ratio checks anyone can reproduce, and reports a
conservative independent-contributor count that refuses to count self-runs. The
short version, per circuit:

```sh
# phase 1: a PUBLIC powers-of-tau. Check what is in it first.
mirror-cli ceremony inspect-ptau --ptau <public>.ptau

# the initial phase-2 key is deterministic, so anyone can re-derive it
snarkjs groth16 setup membership.r1cs <public>.ptau membership_0000.zkey

mirror-cli ceremony start --circuit membership --dir ceremony/membership \
  --r1cs membership.r1cs --ptau <public>.ptau --initial-zkey membership_0000.zkey
mirror-cli ceremony contribute --dir ceremony/membership --id "alice@example.org"
# ... more contributors, each on their own machine ...
mirror-cli ceremony beacon --dir ceremony/membership --id coordinator \
  --source-hex <pre-committed public value> --iterations-exp 20
mirror-cli ceremony verify --dir ceremony/membership \
  --r1cs membership.r1cs --initial-zkey membership_0000.zkey
mirror-cli ceremony export-vk --dir ceremony/membership \
  --out-json artifacts/verification_key.json --out-rust ../programs/mirror-pool/src/vk.rs
```

A `k`-contributor ceremony is safe if **at least one** contributor destroyed their
scalar (1-of-N honest), not if `k` of them did. See the guide for what that does
and does not buy you.

`pot16_final.ptau`, the phase-1 file the committed dev artifacts were built from,
records **55 contributions from named contributors at ceremony power 2^28** - the
signature of a public perpetual-powers-of-tau file rather than a self-generated one.
Its SHA-256 is
`1c401abb57c9ce531370f3015c3e75c0892e0f32b8b1e94ace0f6682d9695922`, and
`mirror-cli ceremony inspect-ptau --ptau pot16_final.ptau` prints the digest and
every contributor name so you can compare them against the published record for the
file you believe you have. The dev-setup weakness is therefore entirely in phase 2,
not phase 1. (`build.sh` will fall back to generating its own single-contribution
phase 1 if the file is missing; that fallback is for offline development only and
is even weaker.)

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

The transaction circuit's artifacts are the `transaction_*`-prefixed equivalents,
and the association circuit's are the `association_*`-prefixed equivalents
(`association_verification_key.json`, `association_vk.rs`,
`association_proof_fixture.json`, `association_proof_fixture.rs`,
`association_fixture_meta.json`).

Not committed (gitignored build outputs): `node_modules/`, `*.ptau`, `*.zkey`,
`*.r1cs`, `*.sym`, `*.wasm`, `*_js/`.

## Artifact consistency

A committed verifying key is bound to the exact constraint system it was
generated from. If the circuit source changes and the key does not, the committed
FIXTURE keeps verifying (it was generated with the key) while every FRESHLY
generated proof fails on-chain. That failure mode is silent under a test suite
that only checks fixtures, so this repo checks more than fixtures.

Three properties are worth re-establishing after ANY circuit change.

**1. A fresh proof over new inputs verifies against the committed key.** This is
the check that actually rules out key drift, because it exercises the committed
key against a statement it has never seen:

```bash
# membership + transaction (pre-existing), and association
MIRROR_PROVE_LIVE=1 cargo test -p mirror-cli -- --ignored
```

`association_fresh_proof_over_new_inputs_verifies_under_committed_vk` builds a
witness that shares nothing with the committed fixture (different secret, epoch,
recipient, amount, and both tree shapes), proves it in-process with
`ark-groth16`, and then runs the EXACT on-chain `groth16-solana` verifier against
the COMMITTED `association_vk.rs`. `rust_prove_membership_verifies_and_on_chain_verifier_accepts`
does the equivalent for the membership circuit.

**2. Every pre-existing fixture still passes.**

```bash
cargo test --workspace
cd programs/mirror-pool && cargo build-sbf && cargo test
```

**3. The vendored program-side keys match the `artifacts/` copies.** The program
embeds its own copies so the deployed `.so` is self-contained; they must not
diverge:

```bash
diff programs/mirror-pool/src/transaction_vk.rs circuits/artifacts/transaction_vk.rs
diff programs/mirror-pool/src/association_vk.rs circuits/artifacts/association_vk.rs
# vk.rs is the same bytes with a 5-line vendoring header prepended:
diff <(tail -n +6 programs/mirror-pool/src/vk.rs) circuits/artifacts/vk.rs
```

### Why extracting `merkle.circom` did not disturb the membership key

circom inlines templates at their use site, so moving `HashLeftRight`,
`PathSelector` and `MerkleProof` into an included file cannot change the emitted
constraint system. That is an argument, not evidence, so it was measured:

```bash
# compile the circuit as committed and compare the constraint system
circom membership.circom --r1cs -l node_modules -o /tmp/check
shasum -a 256 /tmp/check/membership.r1cs membership.r1cs   # identical
```

The `.r1cs` is byte-identical before and after the extraction, so the committed
`membership_final.zkey` and `vk.rs` remain valid for it. The witness-calculator
`.wasm` DOES differ (it is regenerated from different source text), so that was
checked too, by proving with the newly compiled `.wasm` against the COMMITTED
zkey and verifying against the COMMITTED verifying key - which succeeds, with
public signals identical to the committed fixture. The membership, ceremony, and
transaction live tests all pass against the recompiled artifacts.

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
