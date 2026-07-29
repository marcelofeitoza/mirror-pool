//! The opt-in compliance statement, synthesized natively in arkworks.
//!
//! This is the same statement `circuits/association.circom` proves, expressed as
//! Rust constraint synthesis instead of circom source:
//!
//! ```text
//! public : root, nullifierHash, actionHash, epoch, associationRoot
//! private: secret,
//!          pathElements[20],      pathIndices[20],       (pool tree)
//!          assocPathElements[20], assocPathIndices[20]   (curated tree)
//!
//! commitment      = Poseidon(secret, actionHash, epoch)    // leaf of BOTH trees
//! nullifierHash   = Poseidon(secret, epoch)                // epoch-scoped tag
//! root            = MerkleInclusion(commitment, path)      // depth 20
//! associationRoot = MerkleInclusion(commitment, assocPath) // depth 20
//! ```
//!
//! ONE commitment feeds BOTH inclusions, which is the whole point: it is what
//! ties "a deposit of mine" to "a deposit the curator vouches for". Two
//! independent inclusions over two unrelated leaves would prove nothing.
//!
//! # Sharing with [`crate::membership`]
//!
//! The first four public inputs, the commitment, the nullifier binding and the
//! pool inclusion are the membership statement, and they are not re-derived
//! here: the native path walk is [`crate::membership::native_inclusion`] and the
//! in-circuit walk is [`crate::membership::enforce_inclusion`], called twice.
//! [`AssociationWitness::membership`] hands back the corresponding
//! [`MembershipWitness`], and a test asserts the two agree on all four shared
//! public inputs - so "strict extension of the membership statement" is checked
//! rather than asserted in prose.
//!
//! The public-input ORDER is fixed and is the order the on-chain
//! `SETTLE_ZK_ASSOCIATED` handler feeds `groth16-solana`:
//! `[root, nullifierHash, actionHash, epoch, associationRoot]`, i.e. the
//! membership layout with one element appended. Allocation order in
//! [`ConstraintSynthesizer::generate_constraints`] IS that order.
//!
//! # Relationship to the deployed circuit
//!
//! Same statement, DIFFERENT constraint system, therefore a different verifying
//! key. A proof produced here does not verify under the committed circom key and
//! is not accepted by the deployed program, which pins that key by digest. See
//! `docs/ARKWORKS.md`.

use ark_bn254::Fr;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use crate::membership::{
    enforce_inclusion, native_inclusion, Be32, MembershipCircuit, MembershipWitness, DEPTH,
};
use crate::poseidon::{hash_native, hash_var, PoseidonGadgetError};

/// Number of public inputs, in the order
/// `[root, nullifierHash, actionHash, epoch, associationRoot]`.
pub const N_PUBLIC_INPUTS: usize = 5;

/// The association circuit.
///
/// Every field is an `Option` so the SAME type serves two roles: `blank()` for
/// the Groth16 setup (shape only, no assignments) and a fully populated instance
/// for proving. A missing assignment during proving surfaces as
/// [`SynthesisError::AssignmentMissing`] rather than a silent zero.
#[derive(Clone, Debug, Default)]
pub struct AssociationCircuit {
    // public
    pub root: Option<Fr>,
    pub nullifier_hash: Option<Fr>,
    pub action_hash: Option<Fr>,
    pub epoch: Option<Fr>,
    pub association_root: Option<Fr>,
    // private
    pub secret: Option<Fr>,
    /// Siblings of the commitment in the POOL tree, bottom-up.
    pub path_elements: Option<Vec<Fr>>,
    /// `false` = the running node is the LEFT child at this level. Bit `i` of
    /// the POOL leaf index, little-endian.
    pub path_indices: Option<Vec<bool>>,
    /// Siblings of the SAME commitment in the curator's tree, bottom-up.
    ///
    /// The leaf index in the curated tree is unrelated to the pool leaf index -
    /// the curator lists a subset in its own order - so this is an independent
    /// path and only the leaf value is shared.
    pub assoc_path_elements: Option<Vec<Fr>>,
    /// Bit `i` of the ASSOCIATION leaf index, little-endian.
    pub assoc_path_indices: Option<Vec<bool>>,
}

impl AssociationCircuit {
    /// The shape-only instance the Groth16 setup needs.
    pub fn blank() -> Self {
        Self::default()
    }
}

/// A fully specified association witness, plus the public inputs it implies.
///
/// Built by [`AssociationWitness::new`], which derives the leaf, the nullifier
/// and BOTH roots NATIVELY (via `light-poseidon`, the same hash the chain runs)
/// so the public inputs a caller verifies against are never hand-assembled.
#[derive(Clone, Debug)]
pub struct AssociationWitness {
    pub circuit: AssociationCircuit,
    /// `[root, nullifierHash, actionHash, epoch, associationRoot]`.
    pub public_inputs: [Fr; N_PUBLIC_INPUTS],
    /// The recomputed Merkle leaf, `Poseidon(secret, actionHash, epoch)`, which
    /// is a leaf of BOTH trees.
    pub commitment: Fr,
}

impl AssociationWitness {
    /// Derive every public input from the private data, the way a prover would.
    ///
    /// `pool_path_elements[i]` / `assoc_path_elements[i]` are the siblings at
    /// level `i` (bottom-up) in the respective tree, and the two leaf indices
    /// select the side at each level, little-endian. The indices are
    /// deliberately independent: a curator publishes a SUBSET in its own order,
    /// so a commitment at pool leaf 3 can sit at association leaf 1.
    pub fn new(
        secret: Fr,
        action_hash: Fr,
        epoch: u64,
        pool_leaf_index: u64,
        pool_path_elements: &[Fr],
        assoc_leaf_index: u64,
        assoc_path_elements: &[Fr],
    ) -> Result<Self, PoseidonGadgetError> {
        assert_eq!(
            pool_path_elements.len(),
            DEPTH,
            "a depth-{DEPTH} pool inclusion path has exactly {DEPTH} siblings"
        );
        assert_eq!(
            assoc_path_elements.len(),
            DEPTH,
            "a depth-{DEPTH} association inclusion path has exactly {DEPTH} siblings"
        );
        let epoch_f = Fr::from(epoch);
        let commitment = hash_native(&[secret, action_hash, epoch_f])?;
        let nullifier_hash = hash_native(&[secret, epoch_f])?;

        let (root, indices) = native_inclusion(commitment, pool_leaf_index, pool_path_elements)?;
        let (association_root, assoc_indices) =
            native_inclusion(commitment, assoc_leaf_index, assoc_path_elements)?;

        Ok(Self {
            circuit: AssociationCircuit {
                root: Some(root),
                nullifier_hash: Some(nullifier_hash),
                action_hash: Some(action_hash),
                epoch: Some(epoch_f),
                association_root: Some(association_root),
                secret: Some(secret),
                path_elements: Some(pool_path_elements.to_vec()),
                path_indices: Some(indices),
                assoc_path_elements: Some(assoc_path_elements.to_vec()),
                assoc_path_indices: Some(assoc_indices),
            },
            public_inputs: [root, nullifier_hash, action_hash, epoch_f, association_root],
            commitment,
        })
    }

    /// The MEMBERSHIP witness hiding inside this one: the same secret, action,
    /// epoch and pool path, with the curated half dropped.
    ///
    /// This is what makes "the association statement is a strict extension"
    /// checkable: the returned witness's four public inputs must equal this
    /// witness's first four, and its circuit must be satisfiable by the same
    /// private data.
    pub fn membership(&self) -> MembershipWitness {
        let c = &self.circuit;
        MembershipWitness {
            circuit: MembershipCircuit {
                root: c.root,
                nullifier_hash: c.nullifier_hash,
                action_hash: c.action_hash,
                epoch: c.epoch,
                secret: c.secret,
                path_elements: c.path_elements.clone(),
                path_indices: c.path_indices.clone(),
            },
            public_inputs: [
                self.public_inputs[0],
                self.public_inputs[1],
                self.public_inputs[2],
                self.public_inputs[3],
            ],
            commitment: self.commitment,
        }
    }

    /// The public inputs in the 32-byte big-endian encoding `groth16-solana`
    /// (and the on-chain instruction data) uses.
    pub fn public_inputs_be(&self) -> [Be32; N_PUBLIC_INPUTS] {
        let mut out = [[0u8; 32]; N_PUBLIC_INPUTS];
        for (slot, f) in out.iter_mut().zip(self.public_inputs.iter()) {
            *slot = crate::membership::fr_to_be(f);
        }
        out
    }
}

impl ConstraintSynthesizer<Fr> for AssociationCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // PUBLIC, in the order the on-chain verifier consumes them. The first
        // four are the membership layout, unchanged; `associationRoot` is
        // APPENDED, which is what makes the wire format a strict extension.
        let root = FpVar::new_input(cs.clone(), || {
            self.root.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let nullifier_hash = FpVar::new_input(cs.clone(), || {
            self.nullifier_hash.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let action_hash = FpVar::new_input(cs.clone(), || {
            self.action_hash.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let epoch = FpVar::new_input(cs.clone(), || {
            self.epoch.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let association_root = FpVar::new_input(cs.clone(), || {
            self.association_root
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        // PRIVATE.
        let secret = FpVar::new_witness(cs.clone(), || {
            self.secret.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // 1. Recompute the committed leaf. ONE commitment, TWO inclusions.
        let commitment = hash_var(&[secret.clone(), action_hash, epoch.clone()])?;

        // 2. Bind the epoch-scoped nullifier. Identical to the membership
        //    circuit, so a commitment settled through the association path burns
        //    the SAME nullifier it would have burned through the plain path.
        let recomputed_nullifier = hash_var(&[secret, epoch])?;
        nullifier_hash.enforce_equal(&recomputed_nullifier)?;

        // 3. Inclusion under the POOL root.
        enforce_inclusion(
            cs.clone(),
            &commitment,
            &root,
            self.path_elements.as_ref(),
            self.path_indices.as_ref(),
        )?;

        // 4. Inclusion of the SAME leaf under the ASSOCIATION root, over an
        //    independent path.
        enforce_inclusion(
            cs,
            &commitment,
            &association_root,
            self.assoc_path_elements.as_ref(),
            self.assoc_path_indices.as_ref(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::membership::{fr_from_be, fr_to_be};
    use ark_relations::r1cs::ConstraintSystem;

    /// A deterministic witness whose commitment sits at pool leaf 5 and
    /// association leaf 2, with distinct non-trivial siblings in each tree, so
    /// both `PathSelector` branches are exercised on BOTH trees and a bug that
    /// swapped the two paths would be caught.
    fn witness() -> AssociationWitness {
        let secret = fr_from_be(&[0x5bu8; 32]);
        let action_hash = fr_from_be(&mirror_core::transfer_action_hash(&[0x11u8; 32], 4_242));
        let pool: Vec<Fr> = (0..DEPTH as u64).map(|i| Fr::from(i * 7 + 1)).collect();
        let assoc: Vec<Fr> = (0..DEPTH as u64).map(|i| Fr::from(i * 13 + 5)).collect();
        AssociationWitness::new(secret, action_hash, 11, 5, &pool, 2, &assoc).expect("witness")
    }

    fn satisfied(circuit: AssociationCircuit) -> bool {
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).expect("synthesis");
        cs.is_satisfied().expect("satisfiability")
    }

    /// The witness builder must agree with `mirror-core`, which is what the
    /// on-chain accumulator and the circom circuit both compute. If this passes,
    /// the arkworks statement is the SAME statement, not a lookalike.
    #[test]
    fn witness_matches_the_repo_scheme() {
        let w = witness();
        let secret = mirror_core::Secret([0x5bu8; 32]);
        let action_bytes = mirror_core::transfer_action_hash(&[0x11u8; 32], 4_242);

        let commitment =
            mirror_core::commit_with_action_hash(&secret, &action_bytes, mirror_core::Epoch(11));
        assert_eq!(fr_to_be(&w.commitment), commitment.0);
        assert_eq!(
            fr_to_be(&w.public_inputs[1]),
            mirror_core::nullifier(&secret, mirror_core::Epoch(11)).0
        );

        let pool: Vec<[u8; 32]> = (0..DEPTH as u64)
            .map(|i| fr_to_be(&Fr::from(i * 7 + 1)))
            .collect();
        let assoc: Vec<[u8; 32]> = (0..DEPTH as u64)
            .map(|i| fr_to_be(&Fr::from(i * 13 + 5)))
            .collect();
        assert_eq!(
            fr_to_be(&w.public_inputs[0]),
            mirror_core::merkle_root_from_path(&commitment.0, 5, &pool)
        );
        assert_eq!(
            fr_to_be(&w.public_inputs[4]),
            mirror_core::merkle_root_from_path(&commitment.0, 2, &assoc)
        );
    }

    #[test]
    fn a_correct_witness_satisfies_the_circuit() {
        assert!(satisfied(witness().circuit));
    }

    /// The membership statement really is embedded: the same private data
    /// satisfies the membership circuit, and the two witnesses agree on all four
    /// shared public inputs, in order.
    #[test]
    fn the_membership_half_is_the_membership_statement() {
        let w = witness();
        let m = w.membership();
        for i in 0..4 {
            assert_eq!(m.public_inputs[i], w.public_inputs[i], "public input {i}");
        }
        let cs = ConstraintSystem::<Fr>::new_ref();
        m.circuit.generate_constraints(cs.clone()).expect("synth");
        assert!(cs.is_satisfied().expect("satisfiability"));
    }

    /// Every public input is load-bearing, including the appended one: moving
    /// any of the five, or the secret, breaks the system.
    #[test]
    fn tampering_any_public_input_breaks_the_circuit() {
        for which in 0..N_PUBLIC_INPUTS {
            let mut c = witness().circuit;
            match which {
                0 => c.root = Some(c.root.unwrap() + Fr::from(1u64)),
                1 => c.nullifier_hash = Some(c.nullifier_hash.unwrap() + Fr::from(1u64)),
                2 => c.action_hash = Some(c.action_hash.unwrap() + Fr::from(1u64)),
                3 => c.epoch = Some(c.epoch.unwrap() + Fr::from(1u64)),
                _ => c.association_root = Some(c.association_root.unwrap() + Fr::from(1u64)),
            }
            assert!(!satisfied(c), "public input {which} must be constrained");
        }

        let mut c = witness().circuit;
        c.secret = Some(c.secret.unwrap() + Fr::from(1u64));
        assert!(!satisfied(c), "the secret must be constrained");
    }

    /// Either inclusion path alone must be enough to break the proof: a curated
    /// path that does not reach the published association root is exactly the
    /// case the compliance statement exists to reject.
    #[test]
    fn tampering_either_inclusion_path_breaks_the_circuit() {
        let mut c = witness().circuit;
        let mut path = c.path_elements.clone().unwrap();
        path[3] += Fr::from(1u64);
        c.path_elements = Some(path);
        assert!(!satisfied(c), "the pool path must be constrained");

        let mut c = witness().circuit;
        let mut path = c.assoc_path_elements.clone().unwrap();
        path[3] += Fr::from(1u64);
        c.assoc_path_elements = Some(path);
        assert!(!satisfied(c), "the association path must be constrained");

        let mut c = witness().circuit;
        let mut bits = c.assoc_path_indices.clone().unwrap();
        bits[0] = !bits[0];
        c.assoc_path_indices = Some(bits);
        assert!(
            !satisfied(c),
            "the association index bits must be constrained"
        );
    }

    /// The two inclusions must be over the SAME leaf. Presenting a curated path
    /// for some OTHER commitment - the "I am in the pool, and separately
    /// something else is in the curated set" attack - must not satisfy the
    /// circuit. Here that is forced by swapping in an association path built for
    /// a different leaf, which is what such a prover would hold.
    #[test]
    fn the_two_inclusions_must_share_one_leaf() {
        let w = witness();
        let other_leaf = w.commitment + Fr::from(1u64);
        let assoc: Vec<Fr> = (0..DEPTH as u64).map(|i| Fr::from(i * 13 + 5)).collect();
        let (other_root, other_bits) =
            native_inclusion(other_leaf, 2, &assoc).expect("native inclusion");

        // The prover keeps their real pool half and swaps in a curated half that
        // reaches a root over a leaf that is not theirs.
        let mut c = w.circuit;
        c.association_root = Some(other_root);
        c.assoc_path_indices = Some(other_bits);
        assert!(
            !satisfied(c),
            "an association path over a different leaf must not satisfy the circuit"
        );
    }

    /// The setup instance carries no assignments; synthesizing it for proving
    /// must fail loudly rather than proving a statement about zeros.
    #[test]
    fn a_blank_circuit_has_no_assignments() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        assert!(AssociationCircuit::blank()
            .generate_constraints(cs)
            .is_err());
    }
}
