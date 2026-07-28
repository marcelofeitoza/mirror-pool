//! The confidential-value JoinSplit, synthesized natively in arkworks.
//!
//! This is the same statement `circuits/transaction.circom` proves - a 2-in /
//! 2-out Tornado-Nova JoinSplit over a depth-20 Poseidon accumulator - expressed
//! as Rust constraint synthesis instead of circom source. The canonical
//! specification both sides implement is `circuits/TRANSACTION.md`:
//!
//! ```text
//! public : root, publicAmount, extDataHash,
//!          inputNullifier[0..2], outputCommitment[0..2]          (7 inputs)
//! private: inAmount[2], inPrivateKey[2], inBlinding[2],
//!          inPathIndices[2], inPathElements[2][20],
//!          outAmount[2], outPubkey[2], outBlinding[2],
//!          publicAmountMagnitude, publicAmountSign
//!
//! publicKey  = Poseidon(privateKey)                                // t = 2
//! commitment = Poseidon(amount, publicKey, blinding)               // t = 4, the leaf
//! signature  = Poseidon(privateKey, commitment, pathIndex)         // t = 4
//! nullifier  = Poseidon(commitment, pathIndex, signature)          // t = 4
//! node       = Poseidon(left, right)                               // t = 3
//! ```
//!
//! and the six things it enforces, in the order the code below emits them:
//!
//! 1. every input's nullifier is the one published in `inputNullifier[t]`;
//! 2. every input with a NONZERO amount is a member of `root` (a zero-amount
//!    dummy skips the check, which is what lets a shield spend two dummies);
//! 3. every output's commitment is the one published in `outputCommitment[t]`;
//! 4. every output amount, and the magnitude of `publicAmount`, fits 248 bits;
//! 5. `sum(inAmount) + publicAmount === sum(outAmount)` in the field, with
//!    `publicAmount` decoded from a (magnitude, sign) witness so the FIELD_SIZE
//!    offset encoding cannot be abused;
//! 6. the two input nullifiers differ, and `extDataHash` is bound into the
//!    proof.
//!
//! The public-input ORDER is fixed and identical to the circom circuit's
//! declaration order, which is the order snarkjs emits public signals and the
//! order `mirror_core::wire` feeds `groth16-solana`. Allocation order in
//! [`ConstraintSynthesizer::generate_constraints`] IS that order.
//!
//! # Relationship to the deployed circuit
//!
//! Same statement, DIFFERENT constraint system, therefore a different verifying
//! key. A proof produced here does not verify under the committed circom key and
//! is not accepted by the deployed program, which pins that key by digest. See
//! `docs/ARKWORKS.md`.

use ark_bn254::Fr;
use ark_ff::{One, Zero};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use mirror_core::note::SignedAmount;

use crate::gadgets;
use crate::membership::{fr_from_be, fr_to_be, Be32};
use crate::poseidon::{hash_native, hash_var, PoseidonGadgetError};

/// Merkle depth, fixed to the on-chain accumulator and to `Transaction(20, ..)`
/// in the circom source.
pub const DEPTH: usize = 20;

/// Spent notes per transaction.
pub const N_INS: usize = 2;

/// Fresh notes per transaction.
pub const N_OUTS: usize = 2;

/// Bit width each output amount and the `publicAmount` magnitude are range-bound
/// to, matching `Num2Bits(248)` in the circom source and
/// `mirror_core::note::MAX_AMOUNT_BITS`.
pub const MAX_AMOUNT_BITS: usize = 248;

/// Public inputs, in the order
/// `[root, publicAmount, extDataHash, inputNullifier.., outputCommitment..]`.
pub const N_PUBLIC_INPUTS: usize = 3 + N_INS + N_OUTS;

/// The JoinSplit circuit.
///
/// Every field is an `Option` so the SAME type serves two roles: [`blank`] for
/// the Groth16 setup (shape only, no assignments) and a fully populated instance
/// for proving. A missing assignment during proving surfaces as
/// [`SynthesisError::AssignmentMissing`] rather than a silent zero.
///
/// [`blank`]: TransactionCircuit::blank
#[derive(Clone, Debug, Default)]
pub struct TransactionCircuit {
    // public
    pub root: Option<Fr>,
    pub public_amount: Option<Fr>,
    pub ext_data_hash: Option<Fr>,
    pub input_nullifier: [Option<Fr>; N_INS],
    pub output_commitment: [Option<Fr>; N_OUTS],
    // private, inputs
    pub in_amount: [Option<Fr>; N_INS],
    pub in_private_key: [Option<Fr>; N_INS],
    pub in_blinding: [Option<Fr>; N_INS],
    /// The spent note's leaf index as a SINGLE field element, exactly as the
    /// circom circuit takes it. The circuit decomposes it into [`DEPTH`]
    /// little-endian selector bits.
    pub in_path_indices: [Option<Fr>; N_INS],
    pub in_path_elements: [Option<Vec<Fr>>; N_INS],
    // private, outputs
    pub out_amount: [Option<Fr>; N_OUTS],
    pub out_pubkey: [Option<Fr>; N_OUTS],
    pub out_blinding: [Option<Fr>; N_OUTS],
    // private, signed-amount decoding
    pub public_amount_magnitude: Option<Fr>,
    /// `false` = value enters the pool (deposit), `true` = value leaves it
    /// (withdraw). The circuit reads `publicAmount = magnitude * (1 - 2*sign)`.
    pub public_amount_sign: Option<bool>,
}

impl TransactionCircuit {
    /// The shape-only instance the Groth16 setup needs.
    pub fn blank() -> Self {
        Self::default()
    }
}

/// A note being SPENT: the value note plus where it sits in the accumulator and
/// the key that authorizes it.
#[derive(Clone, Debug)]
pub struct InputNote {
    /// Note value. `0` marks a DUMMY input whose Merkle membership is skipped.
    pub amount: u64,
    pub private_key: Fr,
    pub blinding: Fr,
    /// Leaf index in the depth-[`DEPTH`] tree.
    pub leaf_index: u64,
    /// The [`DEPTH`] siblings on the inclusion path, bottom-up.
    pub path_elements: Vec<Fr>,
}

impl InputNote {
    /// A dummy input: zero value, so its Merkle check is disabled and its path
    /// need not be meaningful. `nonce` only has to make its nullifier distinct
    /// from every other input's, which the circuit requires.
    pub fn dummy(nonce: u64) -> Self {
        Self {
            amount: 0,
            private_key: Fr::from(nonce),
            blinding: Fr::from(nonce) + Fr::one(),
            leaf_index: 0,
            path_elements: vec![Fr::zero(); DEPTH],
        }
    }

    /// True when this input carries no value, and therefore skips the root
    /// check.
    pub fn is_dummy(&self) -> bool {
        self.amount == 0
    }
}

/// A note being CREATED. The sender knows only the recipient's public key, which
/// is why an output has no private key.
#[derive(Clone, Debug)]
pub struct OutputNote {
    pub amount: u64,
    pub public_key: Fr,
    pub blinding: Fr,
}

/// Everything that can be wrong with a JoinSplit witness, caught while BUILDING
/// it rather than as an unsatisfiable constraint system.
#[derive(Debug, thiserror::Error)]
pub enum TransactionWitnessError {
    #[error(transparent)]
    Poseidon(#[from] PoseidonGadgetError),
    #[error("input {index}: an inclusion path has exactly {expected} siblings, got {got}")]
    PathLength {
        index: usize,
        expected: usize,
        got: usize,
    },
    #[error("input {index}: leaf index {leaf_index} does not fit a depth-{expected} tree")]
    LeafIndexOutOfRange {
        index: usize,
        leaf_index: u64,
        expected: usize,
    },
    #[error("input {index} carries value but its inclusion path does not reproduce the root")]
    RootMismatch { index: usize },
    #[error(
        "value is not conserved: sum(in) {in_sum} + publicAmount {delta} != sum(out) {out_sum}"
    )]
    ValueNotConserved {
        in_sum: u128,
        delta: i128,
        out_sum: u128,
    },
    #[error("inputs {i} and {j} produce the same nullifier; the circuit forbids it")]
    DuplicateNullifier { i: usize, j: usize },
}

/// A fully specified JoinSplit witness plus the public inputs it implies.
///
/// Built by [`TransactionWitness::new`], which derives every commitment,
/// signature, nullifier and Merkle root NATIVELY (via `light-poseidon`, the same
/// hash the chain runs) so the public inputs a caller verifies against are never
/// hand-assembled.
#[derive(Clone, Debug)]
pub struct TransactionWitness {
    pub circuit: TransactionCircuit,
    /// `[root, publicAmount, extDataHash, inputNullifier.., outputCommitment..]`.
    pub public_inputs: [Fr; N_PUBLIC_INPUTS],
    /// The recomputed leaf of each spent note.
    pub input_commitment: [Fr; N_INS],
    /// The recomputed nullifier of each spent note.
    pub input_nullifier: [Fr; N_INS],
    /// The recomputed leaf of each fresh note.
    pub output_commitment: [Fr; N_OUTS],
}

impl TransactionWitness {
    /// Derive every public input from the private data, the way a prover would.
    ///
    /// `root` is supplied rather than inferred because a SHIELD spends only
    /// dummy inputs and therefore proves membership of nothing: the prover still
    /// has to name a root the program will accept. Every input that does carry
    /// value is checked here to reproduce that same root, so a witness that
    /// would fail in-circuit fails at build time with a named error instead.
    pub fn new(
        root: Fr,
        inputs: [InputNote; N_INS],
        outputs: [OutputNote; N_OUTS],
        signed: SignedAmount,
        ext_data_hash: Fr,
    ) -> Result<Self, TransactionWitnessError> {
        let mut in_amount = [None; N_INS];
        let mut in_private_key = [None; N_INS];
        let mut in_blinding = [None; N_INS];
        let mut in_path_indices = [None; N_INS];
        let mut in_path_elements: [Option<Vec<Fr>>; N_INS] = Default::default();
        let mut input_commitment = [Fr::zero(); N_INS];
        let mut input_nullifier = [Fr::zero(); N_INS];

        for (index, note) in inputs.iter().enumerate() {
            if note.path_elements.len() != DEPTH {
                return Err(TransactionWitnessError::PathLength {
                    index,
                    expected: DEPTH,
                    got: note.path_elements.len(),
                });
            }
            if note.leaf_index >= 1u64 << DEPTH {
                return Err(TransactionWitnessError::LeafIndexOutOfRange {
                    index,
                    leaf_index: note.leaf_index,
                    expected: DEPTH,
                });
            }

            let index_f = Fr::from(note.leaf_index);
            let public_key = hash_native(&[note.private_key])?;
            let commitment = hash_native(&[Fr::from(note.amount), public_key, note.blinding])?;
            let signature = hash_native(&[note.private_key, commitment, index_f])?;
            let nullifier = hash_native(&[commitment, index_f, signature])?;

            // Climb the path exactly as the circuit does, so a real input that
            // does not belong under `root` is rejected here.
            if !note.is_dummy() {
                let mut cur = commitment;
                for (level, sibling) in note.path_elements.iter().enumerate() {
                    let right = (note.leaf_index >> level) & 1 == 1;
                    cur = if right {
                        hash_native(&[*sibling, cur])?
                    } else {
                        hash_native(&[cur, *sibling])?
                    };
                }
                if cur != root {
                    return Err(TransactionWitnessError::RootMismatch { index });
                }
            }

            in_amount[index] = Some(Fr::from(note.amount));
            in_private_key[index] = Some(note.private_key);
            in_blinding[index] = Some(note.blinding);
            in_path_indices[index] = Some(index_f);
            in_path_elements[index] = Some(note.path_elements.clone());
            input_commitment[index] = commitment;
            input_nullifier[index] = nullifier;
        }

        for i in 0..N_INS {
            for j in (i + 1)..N_INS {
                if input_nullifier[i] == input_nullifier[j] {
                    return Err(TransactionWitnessError::DuplicateNullifier { i, j });
                }
            }
        }

        let mut out_amount = [None; N_OUTS];
        let mut out_pubkey = [None; N_OUTS];
        let mut out_blinding = [None; N_OUTS];
        let mut output_commitment = [Fr::zero(); N_OUTS];
        for (index, note) in outputs.iter().enumerate() {
            output_commitment[index] =
                hash_native(&[Fr::from(note.amount), note.public_key, note.blinding])?;
            out_amount[index] = Some(Fr::from(note.amount));
            out_pubkey[index] = Some(note.public_key);
            out_blinding[index] = Some(note.blinding);
        }

        // Value conservation, checked in the integers where it is unambiguous,
        // before the field encoding can hide a wraparound.
        let in_sum: u128 = inputs.iter().map(|n| u128::from(n.amount)).sum();
        let out_sum: u128 = outputs.iter().map(|n| u128::from(n.amount)).sum();
        let (magnitude, sign, delta) = match signed {
            SignedAmount::Transfer => (0u64, false, 0i128),
            SignedAmount::Deposit(v) => (v, false, i128::from(v)),
            SignedAmount::Withdraw(v) => (v, true, -i128::from(v)),
        };
        if in_sum as i128 + delta != out_sum as i128 {
            return Err(TransactionWitnessError::ValueNotConserved {
                in_sum,
                delta,
                out_sum,
            });
        }

        // The canonical FIELD_SIZE-offset encoding, taken from mirror-core so
        // this path cannot drift from the one the program and fixtures use.
        let public_amount = fr_from_be(&mirror_core::note::public_amount(signed));

        let circuit = TransactionCircuit {
            root: Some(root),
            public_amount: Some(public_amount),
            ext_data_hash: Some(ext_data_hash),
            input_nullifier: input_nullifier.map(Some),
            output_commitment: output_commitment.map(Some),
            in_amount,
            in_private_key,
            in_blinding,
            in_path_indices,
            in_path_elements,
            out_amount,
            out_pubkey,
            out_blinding,
            public_amount_magnitude: Some(Fr::from(magnitude)),
            public_amount_sign: Some(sign),
        };

        let public_inputs = [
            root,
            public_amount,
            ext_data_hash,
            input_nullifier[0],
            input_nullifier[1],
            output_commitment[0],
            output_commitment[1],
        ];

        Ok(Self {
            circuit,
            public_inputs,
            input_commitment,
            input_nullifier,
            output_commitment,
        })
    }

    /// The public inputs in the 32-byte big-endian encoding `groth16-solana`
    /// (and the on-chain instruction data) uses.
    pub fn public_inputs_be(&self) -> [Be32; N_PUBLIC_INPUTS] {
        self.public_inputs.map(|f| fr_to_be(&f))
    }
}

impl ConstraintSynthesizer<Fr> for TransactionCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // ---- PUBLIC, in the circom declaration order, which is the order the
        // ---- on-chain verifier consumes them.
        let root = FpVar::new_input(cs.clone(), || {
            self.root.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let public_amount = FpVar::new_input(cs.clone(), || {
            self.public_amount.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let ext_data_hash = FpVar::new_input(cs.clone(), || {
            self.ext_data_hash.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let mut input_nullifier = Vec::with_capacity(N_INS);
        for slot in self.input_nullifier.iter() {
            input_nullifier.push(FpVar::new_input(cs.clone(), || {
                slot.ok_or(SynthesisError::AssignmentMissing)
            })?);
        }
        let mut output_commitment = Vec::with_capacity(N_OUTS);
        for slot in self.output_commitment.iter() {
            output_commitment.push(FpVar::new_input(cs.clone(), || {
                slot.ok_or(SynthesisError::AssignmentMissing)
            })?);
        }

        // ---- inputs (spends) ----
        let mut in_sum = FpVar::<Fr>::zero();
        for (t, published_nullifier) in input_nullifier.iter().enumerate() {
            let in_amount = FpVar::new_witness(cs.clone(), || {
                self.in_amount[t].ok_or(SynthesisError::AssignmentMissing)
            })?;
            let in_private_key = FpVar::new_witness(cs.clone(), || {
                self.in_private_key[t].ok_or(SynthesisError::AssignmentMissing)
            })?;
            let in_blinding = FpVar::new_witness(cs.clone(), || {
                self.in_blinding[t].ok_or(SynthesisError::AssignmentMissing)
            })?;
            let in_path_index = FpVar::new_witness(cs.clone(), || {
                self.in_path_indices[t].ok_or(SynthesisError::AssignmentMissing)
            })?;
            let mut siblings = Vec::with_capacity(DEPTH);
            for level in 0..DEPTH {
                siblings.push(FpVar::new_witness(cs.clone(), || {
                    let p = self.in_path_elements[t]
                        .as_ref()
                        .ok_or(SynthesisError::AssignmentMissing)?;
                    p.get(level)
                        .copied()
                        .ok_or(SynthesisError::AssignmentMissing)
                })?);
            }

            // publicKey = Poseidon(privateKey); commitment = Poseidon(amount,
            // publicKey, blinding). Deriving the public key IN CIRCUIT is what
            // proves the spender holds the key the note was addressed to.
            let public_key = hash_var(std::slice::from_ref(&in_private_key))?;
            let commitment = hash_var(&[in_amount.clone(), public_key, in_blinding])?;

            // signature = Poseidon(privateKey, commitment, pathIndex) and
            // nullifier = Poseidon(commitment, pathIndex, signature). Binding
            // the leaf index makes the nullifier position-specific, so the same
            // note at a different index is a different tag.
            let signature = hash_var(&[in_private_key, commitment.clone(), in_path_index.clone()])?;
            let nullifier = hash_var(&[commitment.clone(), in_path_index.clone(), signature])?;
            nullifier.enforce_equal(published_nullifier)?;

            // Merkle inclusion under `root`, ENFORCED ONLY when the amount is
            // nonzero. A dummy input (amount == 0) may carry any path, which is
            // what lets a shield spend two dummies, and it contributes nothing
            // to the value sum below.
            let bits = gadgets::num_to_bits_le(cs.clone(), &in_path_index, DEPTH)?;
            let mut cur = commitment;
            for (level, sibling) in siblings.iter().enumerate() {
                let (left, right) = gadgets::switcher(&cur, sibling, &bits[level])?;
                cur = hash_var(&[left, right])?;
            }
            gadgets::force_equal_if_enabled(cs.clone(), &root, &cur, &in_amount)?;

            in_sum += &in_amount;
        }

        // ---- outputs (fresh notes) ----
        let mut out_sum = FpVar::<Fr>::zero();
        for (t, published_commitment) in output_commitment.iter().enumerate() {
            let out_amount = FpVar::new_witness(cs.clone(), || {
                self.out_amount[t].ok_or(SynthesisError::AssignmentMissing)
            })?;
            let out_pubkey = FpVar::new_witness(cs.clone(), || {
                self.out_pubkey[t].ok_or(SynthesisError::AssignmentMissing)
            })?;
            let out_blinding = FpVar::new_witness(cs.clone(), || {
                self.out_blinding[t].ok_or(SynthesisError::AssignmentMissing)
            })?;

            let commitment = hash_var(&[out_amount.clone(), out_pubkey, out_blinding])?;
            commitment.enforce_equal(published_commitment)?;

            // Range: a fresh note's amount must fit 248 bits, so no output can
            // be a huge field element that wraps the conservation sum.
            gadgets::num_to_bits_le(cs.clone(), &out_amount, MAX_AMOUNT_BITS)?;

            out_sum += &out_amount;
        }

        // ---- publicAmount: range plus signed decoding ----
        // `Boolean::new_witness` emits the booleanity constraint, which is
        // circom's `publicAmountSign * (1 - publicAmountSign) === 0`.
        let sign = Boolean::new_witness(cs.clone(), || {
            self.public_amount_sign
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let magnitude = FpVar::new_witness(cs.clone(), || {
            self.public_amount_magnitude
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        gadgets::num_to_bits_le(cs.clone(), &magnitude, MAX_AMOUNT_BITS)?;

        // publicAmount == magnitude * (1 - 2*sign): sign 0 gives +magnitude,
        // sign 1 gives r - magnitude. The ranges [0, 2^248) and (r - 2^248, r)
        // are disjoint, so the decoding is unambiguous.
        let sign_factor = FpVar::one() - FpVar::from(sign) * FpVar::Constant(Fr::from(2u64));
        magnitude.mul_equals(&sign_factor, &public_amount)?;

        // ---- value conservation ----
        (in_sum + &public_amount).enforce_equal(&out_sum)?;

        // ---- no in-transaction double spend ----
        // `enforce_not_equal` is one constraint (it exhibits an inverse of the
        // difference), which is exactly what circom's `IsEqual` plus `out === 0`
        // reduces to after its linear-substitution pass.
        for i in 0..N_INS {
            for j in (i + 1)..N_INS {
                input_nullifier[i].enforce_not_equal(&input_nullifier[j])?;
            }
        }

        // ---- extDataHash tamper-evidence ----
        // circom needs this because an unused signal is pruned and snarkjs then
        // refuses to treat it as public. arkworks keeps every `new_input` in the
        // verifier equation regardless, so this row is kept for parity with the
        // circom statement rather than out of necessity: it makes `extDataHash`
        // appear in the constraint matrices exactly as it does there.
        let _ext_data_hash_square = ext_data_hash.square()?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Field;
    use ark_relations::r1cs::ConstraintSystem;

    /// `zeros[i]` for i in 0..DEPTH: the sibling at every level for the first
    /// leaf of an empty tree, the same ladder the on-chain accumulator uses.
    pub(crate) fn zero_ladder() -> Vec<Fr> {
        let mut out = Vec::with_capacity(DEPTH);
        let mut z = Fr::zero();
        for _ in 0..DEPTH {
            out.push(z);
            z = hash_native(&[z, z]).expect("width 3");
        }
        out
    }

    fn keypair(seed: u64) -> (Fr, Fr) {
        let sk = Fr::from(seed) + Fr::from(1_000_003u64);
        (sk, hash_native(&[sk]).expect("width 2"))
    }

    /// A TRANSFER: one real input at leaf 0 of an otherwise empty tree, one
    /// dummy, split into two fresh notes. `publicAmount = 0`.
    fn transfer_witness() -> TransactionWitness {
        let (sk, pk) = keypair(1);
        let (_, pk_bob) = keypair(2);
        let amount = 1_000_000u64;
        let blinding = Fr::from(0xfeed_u64);

        // The real input's leaf is the tree's only leaf, so the root is the
        // zero-ladder root with that leaf at index 0.
        let siblings = zero_ladder();
        let public_key = hash_native(&[sk]).expect("width 2");
        let leaf = hash_native(&[Fr::from(amount), public_key, blinding]).expect("width 4");
        let mut root = leaf;
        for sibling in siblings.iter() {
            root = hash_native(&[root, *sibling]).expect("width 3");
        }

        TransactionWitness::new(
            root,
            [
                InputNote {
                    amount,
                    private_key: sk,
                    blinding,
                    leaf_index: 0,
                    path_elements: siblings,
                },
                InputNote::dummy(77),
            ],
            [
                OutputNote {
                    amount: 400_000,
                    public_key: pk_bob,
                    blinding: Fr::from(0xb0b_u64),
                },
                OutputNote {
                    amount: 600_000,
                    public_key: pk,
                    blinding: Fr::from(0xa11ce_u64),
                },
            ],
            SignedAmount::Transfer,
            Fr::from(0x1234_5678_u64),
        )
        .expect("witness")
    }

    /// A SHIELD: two dummy inputs, `publicAmount = +v`, one real output.
    fn shield_witness(v: u64) -> TransactionWitness {
        let (_, pk) = keypair(3);
        TransactionWitness::new(
            Fr::from(0u64),
            [InputNote::dummy(11), InputNote::dummy(12)],
            [
                OutputNote {
                    amount: v,
                    public_key: pk,
                    blinding: Fr::from(0xdeaf_u64),
                },
                OutputNote {
                    amount: 0,
                    public_key: pk,
                    blinding: Fr::from(0xdeb0_u64),
                },
            ],
            SignedAmount::Deposit(v),
            Fr::from(0x9999_u64),
        )
        .expect("witness")
    }

    fn satisfied(circuit: TransactionCircuit) -> bool {
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).expect("synthesis");
        cs.is_satisfied().expect("satisfiability")
    }

    /// A prover is refused if EITHER no witness can be generated or the
    /// generated one does not satisfy the system. Both are rejections; which one
    /// a given tamper produces is an arkworks implementation detail (an inverse
    /// hint that does not exist fails witness generation, where circom would
    /// emit an unsatisfiable row), and a test that insisted on one flavour would
    /// be testing the wrong thing.
    fn refused(circuit: TransactionCircuit) -> bool {
        let cs = ConstraintSystem::<Fr>::new_ref();
        match circuit.generate_constraints(cs.clone()) {
            Err(_) => true,
            Ok(()) => !cs.is_satisfied().expect("satisfiability"),
        }
    }

    /// The witness builder must agree with `mirror-core::note`, which is what
    /// the on-chain program and the circom fixtures both compute. If this
    /// passes, the arkworks statement is over the SAME note scheme, not a
    /// lookalike.
    #[test]
    fn witness_matches_the_repo_note_scheme() {
        use mirror_core::note::{self, Note, ValueKeypair};

        let w = transfer_witness();
        let (sk, _) = keypair(1);
        let core_kp = ValueKeypair::from_private_key(fr_to_be(&sk));
        let core_note = Note::new(
            1_000_000,
            core_kp.public_key(),
            fr_to_be(&Fr::from(0xfeed_u64)),
        );

        assert_eq!(
            fr_to_be(&w.input_commitment[0]),
            core_note.commitment(),
            "the spent note's leaf must be mirror-core's commitment"
        );
        assert_eq!(
            fr_to_be(&w.input_nullifier[0]),
            note::note_nullifier(&core_kp, &core_note, 0),
            "the nullifier must be mirror-core's nullifier"
        );

        // And publicAmount uses mirror-core's canonical signed encoding.
        assert_eq!(
            fr_to_be(&w.public_inputs[1]),
            note::public_amount(note::SignedAmount::Transfer)
        );
        let shield = shield_witness(250);
        assert_eq!(
            fr_to_be(&shield.public_inputs[1]),
            note::public_amount(note::SignedAmount::Deposit(250))
        );
    }

    /// All three operations the one universal statement has to cover.
    #[test]
    fn transfer_shield_and_unshield_all_satisfy_the_circuit() {
        assert!(satisfied(transfer_witness().circuit), "transfer");
        assert!(satisfied(shield_witness(5_000).circuit), "shield");

        // UNSHIELD: the same real input, but the value leaves the pool.
        let base = transfer_witness();
        let root = base.public_inputs[0];
        let (sk, pk) = keypair(1);
        let unshield = TransactionWitness::new(
            root,
            [
                InputNote {
                    amount: 1_000_000,
                    private_key: sk,
                    blinding: Fr::from(0xfeed_u64),
                    leaf_index: 0,
                    path_elements: zero_ladder(),
                },
                InputNote::dummy(78),
            ],
            [
                OutputNote {
                    amount: 250_000,
                    public_key: pk,
                    blinding: Fr::from(1u64),
                },
                OutputNote {
                    amount: 0,
                    public_key: pk,
                    blinding: Fr::from(2u64),
                },
            ],
            SignedAmount::Withdraw(750_000),
            Fr::from(7u64),
        )
        .expect("witness");
        assert!(satisfied(unshield.circuit), "unshield");
    }

    /// Six of the seven public inputs are load-bearing IN THE CONSTRAINT
    /// SYSTEM. This is the circuit-level statement of "a relayer cannot
    /// re-target the root, move the amount, replay a nullifier, or swap in a
    /// different output note".
    ///
    /// `extDataHash` (index 2) is deliberately excluded; see
    /// [`ext_data_hash_is_bound_by_groth16_not_by_a_constraint`].
    #[test]
    fn tampering_a_constrained_public_input_breaks_the_circuit() {
        for which in [0usize, 1, 3, 4, 5, 6] {
            let mut c = transfer_witness().circuit;
            let bump = |x: Option<Fr>| Some(x.expect("set") + Fr::one());
            match which {
                0 => c.root = bump(c.root),
                1 => c.public_amount = bump(c.public_amount),
                3 => c.input_nullifier[0] = bump(c.input_nullifier[0]),
                4 => c.input_nullifier[1] = bump(c.input_nullifier[1]),
                5 => c.output_commitment[0] = bump(c.output_commitment[0]),
                _ => c.output_commitment[1] = bump(c.output_commitment[1]),
            }
            assert!(refused(c), "public input {which} must be constrained");
        }
    }

    /// The honest statement about `extDataHash`, which is easy to overclaim.
    ///
    /// `extDataHashSquare <== extDataHash * extDataHash` is satisfiable for ANY
    /// value: it defines the square, it does not pin the input. So changing
    /// `extDataHash` leaves the CONSTRAINT SYSTEM satisfied - here and, for the
    /// same reason, in `transaction.circom`. What makes it tamper-evident is
    /// Groth16 itself: it is a PUBLIC input, so a proof made for one value does
    /// not verify against another.
    ///
    /// That is a property of the proof, not of the R1CS, so it is proven where
    /// it lives: `tests/transaction_end_to_end.rs` moves `extDataHash` and
    /// requires the real on-chain `groth16-solana` verifier to reject.
    #[test]
    fn ext_data_hash_is_bound_by_groth16_not_by_a_constraint() {
        let w = transfer_witness();
        assert!(satisfied(w.circuit.clone()));
        let mut moved = w.circuit;
        moved.ext_data_hash = Some(Fr::from(0xdead_beef_u64));
        assert!(
            satisfied(moved),
            "the square row does not constrain extDataHash; only the verifier does"
        );
    }

    /// Value cannot be created. The builder catches an unbalanced witness, and
    /// forcing an unbalanced one past the builder leaves the circuit
    /// unsatisfied.
    #[test]
    fn value_conservation_is_enforced() {
        let (_, pk) = keypair(3);
        let unbalanced = TransactionWitness::new(
            Fr::zero(),
            [InputNote::dummy(1), InputNote::dummy(2)],
            [
                OutputNote {
                    amount: 100,
                    public_key: pk,
                    blinding: Fr::from(1u64),
                },
                OutputNote {
                    amount: 0,
                    public_key: pk,
                    blinding: Fr::from(2u64),
                },
            ],
            // Deposit 99 but mint 100.
            SignedAmount::Deposit(99),
            Fr::zero(),
        );
        assert!(matches!(
            unbalanced,
            Err(TransactionWitnessError::ValueNotConserved { .. })
        ));

        // Past the builder: inflate one output amount without touching its
        // commitment, so only the sum breaks.
        let mut c = shield_witness(5_000).circuit;
        c.out_amount[0] = Some(Fr::from(5_001u64));
        assert!(!satisfied(c));
    }

    /// A withdraw cannot be laundered into a deposit by flipping the sign
    /// witness: `publicAmount` is a public input and the decoding pins it.
    #[test]
    fn the_public_amount_sign_cannot_be_flipped() {
        let mut c = shield_witness(5_000).circuit;
        c.public_amount_sign = Some(true);
        assert!(!satisfied(c));
    }

    /// An out-of-range magnitude must not decompose. `2^248` is the first value
    /// the range check rejects, and it is also the first value whose negation
    /// stops being distinguishable from a deposit.
    #[test]
    fn an_out_of_range_public_amount_magnitude_is_rejected() {
        let mut c = shield_witness(5_000).circuit;
        let two_248 = Fr::from(2u64).pow([MAX_AMOUNT_BITS as u64]);
        c.public_amount_magnitude = Some(two_248);
        c.public_amount = Some(two_248);
        assert!(!satisfied(c));
    }

    /// A REAL input must be in the tree. This is the check a dummy skips, so it
    /// is worth showing it is not skipped for value-carrying notes.
    #[test]
    fn a_real_input_must_be_a_member_of_the_root() {
        let w = transfer_witness();
        let mut c = w.circuit;
        let mut path = c.in_path_elements[0].clone().expect("path");
        path[7] += Fr::one();
        c.in_path_elements[0] = Some(path);
        assert!(!satisfied(c), "a wrong sibling must break membership");

        // The builder refuses the same thing up front.
        let (sk, pk) = keypair(1);
        let bad = TransactionWitness::new(
            Fr::from(12345u64),
            [
                InputNote {
                    amount: 10,
                    private_key: sk,
                    blinding: Fr::from(3u64),
                    leaf_index: 0,
                    path_elements: zero_ladder(),
                },
                InputNote::dummy(5),
            ],
            [
                OutputNote {
                    amount: 10,
                    public_key: pk,
                    blinding: Fr::from(4u64),
                },
                OutputNote {
                    amount: 0,
                    public_key: pk,
                    blinding: Fr::from(5u64),
                },
            ],
            SignedAmount::Transfer,
            Fr::zero(),
        );
        assert!(matches!(
            bad,
            Err(TransactionWitnessError::RootMismatch { index: 0 })
        ));
    }

    /// A DUMMY input skips the root check, which is exactly what makes a shield
    /// expressible: `shield_witness` names root 0, which no real tree has.
    #[test]
    fn a_dummy_input_skips_the_root_check() {
        let w = shield_witness(5_000);
        assert_eq!(w.public_inputs[0], Fr::zero());
        assert!(satisfied(w.circuit));
    }

    /// The same note cannot be spent twice in one transaction.
    #[test]
    fn duplicate_input_nullifiers_are_refused() {
        let (_, pk) = keypair(3);
        let twin = InputNote::dummy(11);
        let dup = TransactionWitness::new(
            Fr::zero(),
            [twin.clone(), twin],
            [
                OutputNote {
                    amount: 0,
                    public_key: pk,
                    blinding: Fr::from(1u64),
                },
                OutputNote {
                    amount: 0,
                    public_key: pk,
                    blinding: Fr::from(2u64),
                },
            ],
            SignedAmount::Transfer,
            Fr::zero(),
        );
        assert!(matches!(
            dup,
            Err(TransactionWitnessError::DuplicateNullifier { i: 0, j: 1 })
        ));

        // And in-circuit: hand it two identical nullifiers directly. The
        // distinctness row is `(nf0 - nf1) * inv === 1`, which has no witness
        // when the two are equal, so this is refused at witness generation.
        let mut c = shield_witness(1_000).circuit;
        c.in_private_key[1] = c.in_private_key[0];
        c.in_blinding[1] = c.in_blinding[0];
        c.input_nullifier[1] = c.input_nullifier[0];
        assert!(refused(c));
    }

    /// A spender must know the private key: the public key is DERIVED in
    /// circuit, so a wrong key yields a different commitment and the note is not
    /// in the tree.
    #[test]
    fn spending_needs_the_owners_private_key() {
        let mut c = transfer_witness().circuit;
        c.in_private_key[0] = Some(c.in_private_key[0].expect("set") + Fr::one());
        assert!(!satisfied(c));
    }

    /// The setup instance carries no assignments; synthesizing it for proving
    /// must fail loudly rather than proving a statement about zeros.
    #[test]
    fn a_blank_circuit_has_no_assignments() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        assert!(TransactionCircuit::blank()
            .generate_constraints(cs)
            .is_err());
    }

    /// Malformed witnesses are named errors, not panics.
    #[test]
    fn malformed_witnesses_are_rejected_by_name() {
        let (_, pk) = keypair(3);
        let outs = || {
            [
                OutputNote {
                    amount: 0,
                    public_key: pk,
                    blinding: Fr::from(1u64),
                },
                OutputNote {
                    amount: 0,
                    public_key: pk,
                    blinding: Fr::from(2u64),
                },
            ]
        };

        let mut short = InputNote::dummy(1);
        short.path_elements.pop();
        assert!(matches!(
            TransactionWitness::new(
                Fr::zero(),
                [short, InputNote::dummy(2)],
                outs(),
                SignedAmount::Transfer,
                Fr::zero()
            ),
            Err(TransactionWitnessError::PathLength { index: 0, .. })
        ));

        let mut far = InputNote::dummy(1);
        far.leaf_index = 1 << DEPTH;
        assert!(matches!(
            TransactionWitness::new(
                Fr::zero(),
                [far, InputNote::dummy(2)],
                outs(),
                SignedAmount::Transfer,
                Fr::zero()
            ),
            Err(TransactionWitnessError::LeafIndexOutOfRange { index: 0, .. })
        ));
    }
}
