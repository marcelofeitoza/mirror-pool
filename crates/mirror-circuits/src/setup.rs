//! Groth16 setup, proving, and constraint accounting for the arkworks circuit.
//!
//! Everything in this module is Rust: no `circom` compile step, no `snarkjs`
//! phase-2, no `node`, no `npm install`. The trade is the usual one - a
//! `circuit_specific_setup` is a SINGLE-PARTY setup, and whoever runs it can
//! forge proofs unless the toxic waste is destroyed. That is the same trust
//! statement `circuits/build.sh` already prints for the circom dev setup, and it
//! is why the multi-party phase-2 ceremony exists. Nothing here is a ceremony,
//! and nothing here should secure value.
//!
//! Reduction note: an arkworks-native circuit uses arkworks' own R1CS-to-QAP map
//! (`LibsnarkReduction`, the default for [`Groth16`]) for BOTH setup and proving.
//! The circom path uses `CircomReduction` because snarkjs does. Each path is
//! internally consistent; a key from one does not prove for the other.

use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisError};
use ark_snark::SNARK;
use ark_std::rand::{CryptoRng, RngCore};

use crate::membership::{MembershipCircuit, MembershipWitness, N_PUBLIC_INPUTS};
use crate::transaction::{
    TransactionCircuit, TransactionWitness, N_PUBLIC_INPUTS as TRANSACTION_N_PUBLIC_INPUTS,
};

/// The R1CS shape of a circuit, measured by synthesizing it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Shape {
    /// Constraints arkworks emits. Every one is a genuine multiplication
    /// constraint: affine work (round-constant addition, the MDS matrix, the
    /// mux arithmetic) is carried as symbolic linear combinations and costs
    /// nothing.
    pub constraints: usize,
    /// Witness variables (private).
    pub witness_variables: usize,
    /// Instance variables, EXCLUDING the constant `1`.
    pub instance_variables: usize,
}

/// Synthesize any circuit in this crate and report its shape, plus whether the
/// resulting system is satisfied.
pub fn shape_of<C: ConstraintSynthesizer<Fr>>(circuit: C) -> Result<(Shape, bool), SynthesisError> {
    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone())?;
    let satisfied = cs.is_satisfied()?;
    Ok((
        Shape {
            constraints: cs.num_constraints(),
            witness_variables: cs.num_witness_variables(),
            // `num_instance_variables` counts the constant 1 as instance 0.
            instance_variables: cs.num_instance_variables().saturating_sub(1),
        },
        satisfied,
    ))
}

/// Synthesize the membership circuit and report its shape. Takes a populated
/// witness so the result is a system that is actually satisfied, not just
/// allocated.
pub fn shape(witness: &MembershipWitness) -> Result<(Shape, bool), SynthesisError> {
    shape_of(witness.circuit.clone())
}

/// Synthesize the JoinSplit circuit and report its shape.
pub fn transaction_shape(witness: &TransactionWitness) -> Result<(Shape, bool), SynthesisError> {
    shape_of(witness.circuit.clone())
}

/// Run a single-party Groth16 setup over the membership circuit.
///
/// Returns the proving key; its `vk` field is the verifying key a deployment
/// would publish. NOT a ceremony - see the module docs.
pub fn setup<R: RngCore + CryptoRng>(rng: &mut R) -> Result<ProvingKey<Bn254>, SynthesisError> {
    let (pk, _vk) = Groth16::<Bn254>::circuit_specific_setup(MembershipCircuit::blank(), rng)?;
    Ok(pk)
}

/// Prove a membership witness under `pk`, and verify the proof in-process
/// against `pk.vk` before returning it.
///
/// The in-process verification is not decoration: a proof that does not satisfy
/// its own key can never satisfy the on-chain verifier either, and failing here
/// gives a caller the arkworks error instead of an opaque pairing rejection.
pub fn prove<R: RngCore + CryptoRng>(
    pk: &ProvingKey<Bn254>,
    witness: &MembershipWitness,
    rng: &mut R,
) -> Result<Proof<Bn254>, SynthesisError> {
    let proof = Groth16::<Bn254>::prove(pk, witness.circuit.clone(), rng)?;
    let ok = verify(&pk.vk, &witness.public_inputs, &proof)?;
    if !ok {
        return Err(SynthesisError::Unsatisfiable);
    }
    Ok(proof)
}

/// Verify with arkworks' own verifier (the in-process cross-check; the on-chain
/// verifier is exercised separately in `tests/`).
pub fn verify(
    vk: &VerifyingKey<Bn254>,
    public_inputs: &[Fr; N_PUBLIC_INPUTS],
    proof: &Proof<Bn254>,
) -> Result<bool, SynthesisError> {
    let pvk = Groth16::<Bn254>::process_vk(vk)?;
    Groth16::<Bn254>::verify_with_processed_vk(&pvk, public_inputs, proof)
}

/// Run a single-party Groth16 setup over the JoinSplit circuit.
///
/// The same trust statement as [`setup`]: NOT a ceremony, and nothing here
/// should secure value. See the module docs.
pub fn transaction_setup<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> Result<ProvingKey<Bn254>, SynthesisError> {
    let (pk, _vk) = Groth16::<Bn254>::circuit_specific_setup(TransactionCircuit::blank(), rng)?;
    Ok(pk)
}

/// Prove a JoinSplit witness under `pk`, and verify the proof in-process against
/// `pk.vk` before returning it, for the same reason [`prove`] does.
pub fn transaction_prove<R: RngCore + CryptoRng>(
    pk: &ProvingKey<Bn254>,
    witness: &TransactionWitness,
    rng: &mut R,
) -> Result<Proof<Bn254>, SynthesisError> {
    let proof = Groth16::<Bn254>::prove(pk, witness.circuit.clone(), rng)?;
    if !transaction_verify(&pk.vk, &witness.public_inputs, &proof)? {
        return Err(SynthesisError::Unsatisfiable);
    }
    Ok(proof)
}

/// Verify a JoinSplit proof with arkworks' own verifier (the in-process
/// cross-check; the on-chain verifier is exercised separately in `tests/`).
pub fn transaction_verify(
    vk: &VerifyingKey<Bn254>,
    public_inputs: &[Fr; TRANSACTION_N_PUBLIC_INPUTS],
    proof: &Proof<Bn254>,
) -> Result<bool, SynthesisError> {
    let pvk = Groth16::<Bn254>::process_vk(vk)?;
    Groth16::<Bn254>::verify_with_processed_vk(&pvk, public_inputs, proof)
}
