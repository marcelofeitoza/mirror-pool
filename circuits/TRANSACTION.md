# mirror-pool transaction circuit (confidential-value JoinSplit)

`transaction.circom` is a 2-in / 2-out Groth16 JoinSplit over BN254. It is the
value-carrying counterpart to `membership.circom`: it proves a **balanced spend of
shielded value notes (UTXOs)** while hiding amounts, owners, and which notes were
spent. One universal statement covers three operations:

- **shield** (deposit): 2 dummy inputs, `publicAmount = +v`.
- **transfer**: 2 real inputs, 2 real outputs, `publicAmount = 0`.
- **unshield** (withdraw): real input(s), `publicAmount = -v`.

This is a clean-room implementation written from the **public, open-source
Tornado-Nova transaction circuit** (the standard reference for a Poseidon
JoinSplit). It depends only on circomlib, snarkjs, circomlibjs, and, for on-chain
verification, the `groth16-solana` crate (v0.2.0). MIT licensed.

This document is the **canonical specification** that the on-chain program and
`mirror-core` MUST match byte-for-byte. Both recompute these hashes with
`sol_poseidon` / a host Poseidon and enforce the same value math; a mismatch is a
silent verification failure, not a compile error.

## Field and hashing

- All values are elements of the **BN254 scalar field**; its modulus is

  ```
  FIELD_SIZE = r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
  ```

- Poseidon is **circomlib Poseidon**, `t = nInputs + 1`. Input order is
  significant and fixed below. circomlibjs (used by the fixture generator) shares
  the same constants, so JS-computed and circuit-computed hashes agree.
- Byte encoding across the whole pipeline is **big-endian, uncompressed**.

## Canonical value-note scheme

A value note (UTXO) is `{ amount, publicKey, blinding }`. The owner holds a
`privateKey`; the note is spendable by whoever knows it.

```
publicKey  = Poseidon(privateKey)                                 // 1-input  (t=2)
commitment = Poseidon(amount, publicKey, blinding)                // 3-input  (t=4)  -- the Merkle leaf
signature  = Poseidon(privateKey, commitment, merklePathIndices)  // 3-input  (t=4)
nullifier  = Poseidon(commitment, merklePathIndices, signature)   // 3-input  (t=4)
```

- `merklePathIndices` is the note's **leaf index as a single field element**. The
  circuit decomposes it into `MERKLE_DEPTH` little-endian bits with `Num2Bits`;
  bit `i` is the left/right selector at level `i` (`0` = the running node is the
  **left** child and the sibling is on the right, `1` = the running node is the
  **right** child).
- Binding the leaf index into the signature and nullifier makes a note's
  nullifier position-specific: the same secret at a different index yields a
  different nullifier, matching Tornado-Nova.
- The nullifier is what the program marks spent. It is deterministic from the
  note plus its position, so double-spends collide.

## Merkle accumulator

- `MERKLE_DEPTH = 20`, matching the existing on-chain accumulator (2^20 leaves).
- Internal nodes: `node = Poseidon(left, right)` (2-input, `t = 3`).
- Empty-subtree zero ladder: `zeros[0] = 0`, `zeros[i] = Poseidon(zeros[i-1], zeros[i-1])`.
- A **dummy input** has `amount == 0`; its Merkle membership check is **skipped**
  (see below), so its path may be the zero ladder with index `0`. This is what
  lets a shield spend two dummy inputs.

## publicAmount: signed value with the FIELD_SIZE offset

`publicAmount` is the net public value moving in/out of the shielded pool,
encoded as a signed field element using the standard offset:

```
deposit  of v  (0 <= v < 2^248):  publicAmount = v
withdraw of v  (0 <  v < 2^248):  publicAmount = FIELD_SIZE - v      (i.e. -v mod r)
transfer      :                   publicAmount = 0
```

In Tornado-Nova terms `publicAmount = extAmount - fee`, where `extAmount` is the
actual token amount deposited (`+`) or withdrawn (`-`) at the program boundary and
`fee` is paid to the relayer out of the transaction. The program is responsible
for enforcing that the on-chain token movement equals the decoded `extAmount`.

The circuit range-binds the **magnitude**: it takes private witnesses
`publicAmountMagnitude` and `publicAmountSign` (boolean) and enforces

```
publicAmountSign * (1 - publicAmountSign) === 0          // sign is 0/1
Num2Bits(248)(publicAmountMagnitude)                     // |value| < 2^248
publicAmount === publicAmountMagnitude * (1 - 2*publicAmountSign)
```

For `sign = 0` this yields `+magnitude`; for `sign = 1` it yields
`-magnitude = r - magnitude`. The ranges `[0, 2^248)` and `(r - 2^248, r)` are
disjoint, so the decoding is unambiguous and no negative value can wrap into a
large positive one.

## What the circuit enforces

For each of the 2 inputs:

1. `publicKey  = Poseidon(privateKey)`.
2. `commitment = Poseidon(amount, publicKey, blinding)`.
3. `signature  = Poseidon(privateKey, commitment, merklePathIndices)`.
4. `nullifier  = Poseidon(commitment, merklePathIndices, signature)` and this
   equals the public `inputNullifier[i]`.
5. Merkle inclusion of `commitment` under `root`, **only if `amount != 0`**
   (`ForceEqualIfEnabled` with `enabled = amount`). A dummy input (`amount == 0`)
   skips this check.

For each of the 2 outputs:

6. `commitment = Poseidon(amount, publicKey, blinding)` equals the public
   `outputCommitment[i]`.
7. `Num2Bits(248)(amount)`: the output amount fits in 248 bits (no overflow).

Global:

8. **Value conservation** (in the field): `sum(inAmount) + publicAmount === sum(outAmount)`.
9. **No in-transaction double spend**: `inputNullifier[0] != inputNullifier[1]`.
10. **extDataHash tamper-evidence**: `extDataHashSquare <== extDataHash * extDataHash`.
    The circuit does not recompute `extDataHash`; it only binds it into the proof
    so it cannot be malleated. (See below.)

**Overflow safety.** Outputs are each `< 2^248` and `|publicAmount| < 2^248`.
Inputs are not range-checked in-circuit, but every committed note was itself a
range-checked output when created, so `sum(inAmount) < 2 * 2^248`. The
value-conservation sum therefore stays far below `r ≈ 2^254`, so it cannot wrap.

## extDataHash

`extDataHash` is a **public input** that commits, off-chain, to the transaction's
external data: recipient, relayer, fee, and the encrypted-note payloads that let
recipients discover their outputs. The circuit binds it (`extDataHash *
extDataHash === extDataHashSquare`) but does not constrain how it is
computed; that is a program choice. The recommended, Solana-idiomatic
construction (used by the fixtures) is:

```
preimage     = recipient(32) || relayer(32) || fee_u64_be(8) || encOut0 || encOut1
extDataHash  = keccak256(preimage) mod r
```

keccak256 has a cheap `sol_keccak256` syscall on Solana. The program recomputes
`extDataHash` from the ext data it receives and checks it equals this public
input; any tampering with recipient/relayer/fee/payload changes the hash and
fails verification. Prover and verifier need only agree on the serialization.

## Public inputs (fixed order)

snarkjs emits public signals in declaration order; the on-chain `PUBLIC_INPUTS`
array MUST use exactly this order (**7 public inputs**):

| index | signal                | meaning                                            |
| ----- | --------------------- | -------------------------------------------------- |
| 0     | `root`                | Merkle root the inputs are proven against          |
| 1     | `publicAmount`        | signed net public value (FIELD_SIZE offset)        |
| 2     | `extDataHash`         | binds recipient / relayer / fee / encrypted payload |
| 3     | `inputNullifier[0]`   | nullifier of input 0                               |
| 4     | `inputNullifier[1]`   | nullifier of input 1                               |
| 5     | `outputCommitment[0]` | commitment of output 0                             |
| 6     | `outputCommitment[1]` | commitment of output 1                             |

Private inputs: `inAmount[2]`, `inPrivateKey[2]`, `inBlinding[2]`,
`inPathIndices[2]`, `inPathElements[2][20]`, `outAmount[2]`, `outPubkey[2]`,
`outBlinding[2]`, `publicAmountMagnitude`, `publicAmountSign`.

## Build, trusted setup, artifacts

```sh
npm install                  # once: circomlib, circomlibjs, snarkjs, ethers
bash build_transaction.sh
```

`build_transaction.sh` compiles the circuit, runs the Groth16 phase-2 setup and a
reproducible dev contribution, generates the three proof fixtures (verifying each
with snarkjs), and emits the Rust constants.

- **Constraint count: 27278 R1CS constraints** (13098 non-linear + 14180 linear),
  7 public inputs, 56 private inputs.
- **Powers of tau: the local universal `pot16_final.ptau` (2^16 = 65536)**, which
  comfortably covers the ~27.3k constraints (a 2^15 domain). No 2^17 ptau is
  needed. If a future change exceeds 2^16, drop the public 2^17 ptau in as
  `pot17_final.ptau` and set `DEPTH_POWER=17` in `build_transaction.sh`.

### Dev-setup caveat

The phase-2 contribution uses a hard-coded entropy string so the build is
reproducible, which by definition makes the toxic waste public. This is a
**DEVELOPMENT / TEST setup only**. It MUST NOT secure real value; a real
multi-party ceremony is a separate deliverable.

### Committed artifacts (`artifacts/`)

| file                                | contents                                             |
| ----------------------------------- | ---------------------------------------------------- |
| `transaction_verification_key.json` | snarkjs Groth16 verifying key                        |
| `transaction_vk.rs`                 | `VERIFYINGKEY: Groth16Verifyingkey` (groth16-solana) |
| `transaction_proof_fixture.json`    | canonical **TRANSFER** `{ proof, publicSignals }`    |
| `transaction_proof_fixture.rs`      | `PROOF_A/PROOF_B/PROOF_C/PUBLIC_INPUTS` (TRANSFER)   |
| `transaction_shield_fixture.json`   | SHIELD `{ proof, publicSignals }`                    |
| `transaction_unshield_fixture.json` | UNSHIELD `{ proof, publicSignals }`                  |
| `transaction_fixture_meta.json`     | public-input order, nPublic, scheme metadata         |

Gitignored build outputs: `*.r1cs`, `*.sym`, `*.wasm`, `*_js/`, `*.zkey`,
`*.ptau`.

## On-chain verifier integration (groth16-solana v0.2.0)

`transaction_vk.rs` and `transaction_proof_fixture.rs` use the exact byte layout
the `groth16-solana` crate expects (identical converter to the membership
artifacts, whose layout is validated end to end against the crate):

- All elements big-endian, uncompressed. `G1 = x||y` (64B).
  `G2 = x_c1||x_c0||y_c1||y_c0` (128B), each Fp2 coordinate imaginary-part-first.
- **`nPublic = 7`, so `vk_ic` has `nPublic + 1 = 8` entries** (`IC[0]` is the
  constant term). `Groth16Verifier::new` returns `InvalidPublicInputsLength`
  unless `public_inputs.len() + 1 == vk_ic.len()`, i.e. exactly 7 public inputs.
- `PROOF_A` is emitted **already negated** (`-(x, y) = (x, q - y)` over Fq), as
  `Groth16Verifier::new` expects; the program needs no runtime `ark` serialization.
- The `vk_gamme_g2` field name matches the (typo'd) field in groth16-solana 0.2.0.

As a cross-check, `vk_alpha_g1`, `vk_beta_g2`, and `vk_gamme_g2` in
`transaction_vk.rs` are byte-identical to those in the membership `vk.rs` (both
derive from the same `pot16_final.ptau`), which confirms the G1/G2 serialization;
only `vk_delta_g2` and `vk_ic` differ, as expected.

```rust
use groth16_solana::groth16::Groth16Verifier;
// mod transaction_vk;            use transaction_vk::VERIFYINGKEY;
// mod transaction_proof_fixture; use transaction_proof_fixture::{PROOF_A, PROOF_B, PROOF_C, PUBLIC_INPUTS};

let mut verifier = Groth16Verifier::new(
    &PROOF_A, &PROOF_B, &PROOF_C, &PUBLIC_INPUTS, &VERIFYINGKEY,
)?;
verifier.verify()?; // Ok(()) for the shipped TRANSFER fixture
```
