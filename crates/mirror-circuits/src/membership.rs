//! The membership statement, synthesized natively in arkworks.
//!
//! This is the same statement `circuits/membership.circom` proves, expressed as
//! Rust constraint synthesis instead of circom source:
//!
//! ```text
//! public : root, nullifierHash, actionHash, epoch
//! private: secret, pathElements[20], pathIndices[20]
//!
//! commitment    = Poseidon(secret, actionHash, epoch)     // the Merkle leaf
//! nullifierHash = Poseidon(secret, epoch)                 // epoch-scoped tag
//! root          = MerkleInclusion(commitment, path)       // depth 20
//! ```
//!
//! The public-input ORDER is fixed and is the order the on-chain `SETTLE_ZK`
//! handler feeds `groth16-solana`: `[root, nullifierHash, actionHash, epoch]`.
//! Allocation order in [`ConstraintSynthesizer::generate_constraints`] IS that
//! order, so a verifier built from this circuit's key consumes public inputs in
//! the layout the program already uses.
//!
//! # Relationship to the deployed circuit
//!
//! Same statement, DIFFERENT constraint system, therefore a different verifying
//! key. A proof produced here does not verify under the committed circom key and
//! is not accepted by the deployed program, which pins that key by digest. This
//! module exists to show the statement can be expressed and proven with no
//! circom / snarkjs / node in the loop, and to measure what that costs. See
//! `docs/ARKWORKS.md`.

use ark_bn254::Fr;
use ark_ff::PrimeField;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::select::CondSelectGadget;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use crate::poseidon::{hash_native, hash_var, PoseidonGadgetError};

/// Merkle depth, fixed to the on-chain accumulator and to `Membership(20)` in
/// the circom source.
pub const DEPTH: usize = 20;

/// Number of public inputs, in the order `[root, nullifierHash, actionHash,
/// epoch]`.
pub const N_PUBLIC_INPUTS: usize = 4;

/// A canonical 32-byte big-endian field element - the encoding every hash input
/// and output uses across this repo, the `sol_poseidon` syscall, and the
/// `groth16-solana` public inputs.
pub type Be32 = [u8; 32];

/// Interpret 32 big-endian bytes as a BN254 scalar, reducing modulo the field
/// order (the identity for canonical values, which is everything this repo
/// produces).
pub fn fr_from_be(bytes: &Be32) -> Fr {
    Fr::from_be_bytes_mod_order(bytes)
}

/// Canonical 32-byte big-endian encoding of a BN254 scalar.
pub fn fr_to_be(f: &Fr) -> Be32 {
    use ark_ff::BigInteger;
    let be = f.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - be.len()..].copy_from_slice(&be);
    out
}

/// The membership circuit.
///
/// Every field is an `Option` so the SAME type serves two roles: `blank()` for
/// the Groth16 setup (shape only, no assignments) and a fully populated instance
/// for proving. A missing assignment during proving surfaces as
/// [`SynthesisError::AssignmentMissing`] rather than a silent zero.
#[derive(Clone, Debug, Default)]
pub struct MembershipCircuit {
    // public
    pub root: Option<Fr>,
    pub nullifier_hash: Option<Fr>,
    pub action_hash: Option<Fr>,
    pub epoch: Option<Fr>,
    // private
    pub secret: Option<Fr>,
    pub path_elements: Option<Vec<Fr>>,
    /// `false` = the running node is the LEFT child at this level, `true` = the
    /// RIGHT child. Bit `i` is bit `i` of the leaf index, little-endian, exactly
    /// the decomposition `mirror_core::merkle_root_from_path` uses.
    pub path_indices: Option<Vec<bool>>,
}

impl MembershipCircuit {
    /// The shape-only instance the Groth16 setup needs.
    pub fn blank() -> Self {
        Self::default()
    }
}

/// A fully specified membership witness, plus the public inputs it implies.
///
/// Built by [`MembershipWitness::new`], which derives the leaf, the nullifier
/// and the root NATIVELY (via `light-poseidon`, the same hash the chain runs) so
/// the public inputs a caller verifies against are never hand-assembled.
#[derive(Clone, Debug)]
pub struct MembershipWitness {
    pub circuit: MembershipCircuit,
    /// `[root, nullifierHash, actionHash, epoch]`.
    pub public_inputs: [Fr; N_PUBLIC_INPUTS],
    /// The recomputed Merkle leaf, `Poseidon(secret, actionHash, epoch)`.
    pub commitment: Fr,
}

impl MembershipWitness {
    /// Derive every public input from the private data, the way a prover would.
    ///
    /// `path_elements[i]` is the sibling at level `i` (bottom-up) and
    /// `leaf_index` selects the side at each level, little-endian.
    pub fn new(
        secret: Fr,
        action_hash: Fr,
        epoch: u64,
        leaf_index: u64,
        path_elements: &[Fr],
    ) -> Result<Self, PoseidonGadgetError> {
        assert_eq!(
            path_elements.len(),
            DEPTH,
            "a depth-{DEPTH} inclusion path has exactly {DEPTH} siblings"
        );
        let epoch_f = Fr::from(epoch);
        let commitment = hash_native(&[secret, action_hash, epoch_f])?;
        let nullifier_hash = hash_native(&[secret, epoch_f])?;

        let mut indices = Vec::with_capacity(DEPTH);
        let mut cur = commitment;
        for (level, sibling) in path_elements.iter().enumerate() {
            let right = (leaf_index >> level) & 1 == 1;
            indices.push(right);
            cur = if right {
                hash_native(&[*sibling, cur])?
            } else {
                hash_native(&[cur, *sibling])?
            };
        }
        let root = cur;

        Ok(Self {
            circuit: MembershipCircuit {
                root: Some(root),
                nullifier_hash: Some(nullifier_hash),
                action_hash: Some(action_hash),
                epoch: Some(epoch_f),
                secret: Some(secret),
                path_elements: Some(path_elements.to_vec()),
                path_indices: Some(indices),
            },
            public_inputs: [root, nullifier_hash, action_hash, epoch_f],
            commitment,
        })
    }

    /// The public inputs in the 32-byte big-endian encoding `groth16-solana`
    /// (and the on-chain instruction data) uses.
    pub fn public_inputs_be(&self) -> [Be32; N_PUBLIC_INPUTS] {
        [
            fr_to_be(&self.public_inputs[0]),
            fr_to_be(&self.public_inputs[1]),
            fr_to_be(&self.public_inputs[2]),
            fr_to_be(&self.public_inputs[3]),
        ]
    }
}

impl ConstraintSynthesizer<Fr> for MembershipCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // PUBLIC, in the order the on-chain verifier consumes them.
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

        // PRIVATE.
        let secret = FpVar::new_witness(cs.clone(), || {
            self.secret.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let mut siblings = Vec::with_capacity(DEPTH);
        for level in 0..DEPTH {
            siblings.push(FpVar::new_witness(cs.clone(), || {
                let p = self
                    .path_elements
                    .as_ref()
                    .ok_or(SynthesisError::AssignmentMissing)?;
                p.get(level)
                    .copied()
                    .ok_or(SynthesisError::AssignmentMissing)
            })?);
        }
        // `Boolean::new_witness` emits the booleanity constraint, which is
        // circom's `s * (1 - s) === 0`.
        let mut bits = Vec::with_capacity(DEPTH);
        for level in 0..DEPTH {
            bits.push(Boolean::new_witness(cs.clone(), || {
                let p = self
                    .path_indices
                    .as_ref()
                    .ok_or(SynthesisError::AssignmentMissing)?;
                p.get(level)
                    .copied()
                    .ok_or(SynthesisError::AssignmentMissing)
            })?);
        }

        // 1. Recompute the committed leaf.
        let commitment = hash_var(&[secret.clone(), action_hash, epoch.clone()])?;

        // 2. Bind the epoch-scoped nullifier.
        let recomputed_nullifier = hash_var(&[secret, epoch])?;
        nullifier_hash.enforce_equal(&recomputed_nullifier)?;

        // 3. Climb the inclusion path. `bit == true` means the running node is
        //    the RIGHT child, so the sibling goes on the left - the same
        //    convention as circom's `PathSelector` and as the on-chain
        //    accumulator.
        let mut cur = commitment;
        for level in 0..DEPTH {
            let sibling = &siblings[level];
            let left = FpVar::conditionally_select(&bits[level], sibling, &cur)?;
            let right = FpVar::conditionally_select(&bits[level], &cur, sibling)?;
            cur = hash_var(&[left, right])?;
        }
        root.enforce_equal(&cur)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;

    /// A deterministic witness: leaf index 5 in a depth-20 tree with fixed,
    /// non-trivial siblings (so both `pathIndices` values are exercised).
    fn witness() -> MembershipWitness {
        let secret = fr_from_be(&[0x3cu8; 32]);
        let action_hash = fr_from_be(&mirror_core::transfer_action_hash(&[0x07u8; 32], 42));
        let siblings: Vec<Fr> = (0..DEPTH as u64).map(|i| Fr::from(i * 7 + 1)).collect();
        MembershipWitness::new(secret, action_hash, 9, 5, &siblings).expect("witness")
    }

    fn satisfied(circuit: MembershipCircuit) -> bool {
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
        let secret_bytes = [0x3cu8; 32];
        let action_bytes = mirror_core::transfer_action_hash(&[0x07u8; 32], 42);
        let secret = mirror_core::Secret(secret_bytes);

        let commitment =
            mirror_core::commit_with_action_hash(&secret, &action_bytes, mirror_core::Epoch(9));
        assert_eq!(fr_to_be(&w.commitment), commitment.0);
        assert_eq!(
            fr_to_be(&w.public_inputs[1]),
            mirror_core::nullifier(&secret, mirror_core::Epoch(9)).0
        );

        let siblings: Vec<[u8; 32]> = (0..DEPTH as u64)
            .map(|i| fr_to_be(&Fr::from(i * 7 + 1)))
            .collect();
        assert_eq!(
            fr_to_be(&w.public_inputs[0]),
            mirror_core::merkle_root_from_path(&commitment.0, 5, &siblings)
        );
    }

    #[test]
    fn a_correct_witness_satisfies_the_circuit() {
        assert!(satisfied(witness().circuit));
    }

    /// Every public input is load-bearing: moving any one of them, or the
    /// secret, breaks the system. This is the circuit-level statement of "a
    /// relay cannot re-target the action or replay across epochs".
    #[test]
    fn tampering_any_public_input_breaks_the_circuit() {
        for which in 0..N_PUBLIC_INPUTS {
            let mut c = witness().circuit;
            match which {
                0 => c.root = Some(c.root.unwrap() + Fr::from(1u64)),
                1 => c.nullifier_hash = Some(c.nullifier_hash.unwrap() + Fr::from(1u64)),
                2 => c.action_hash = Some(c.action_hash.unwrap() + Fr::from(1u64)),
                _ => c.epoch = Some(c.epoch.unwrap() + Fr::from(1u64)),
            }
            assert!(!satisfied(c), "public input {which} must be constrained");
        }

        let mut c = witness().circuit;
        c.secret = Some(c.secret.unwrap() + Fr::from(1u64));
        assert!(!satisfied(c), "the secret must be constrained");
    }

    /// A wrong sibling, or the right siblings in the wrong order, must not
    /// reproduce the root.
    #[test]
    fn tampering_the_inclusion_path_breaks_the_circuit() {
        let mut c = witness().circuit;
        let mut path = c.path_elements.clone().unwrap();
        path[3] += Fr::from(1u64);
        c.path_elements = Some(path);
        assert!(!satisfied(c));

        let mut c = witness().circuit;
        let mut bits = c.path_indices.clone().unwrap();
        bits[0] = !bits[0];
        c.path_indices = Some(bits);
        assert!(!satisfied(c));
    }

    /// The setup instance carries no assignments; synthesizing it for proving
    /// must fail loudly rather than proving a statement about zeros.
    #[test]
    fn a_blank_circuit_has_no_assignments() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        assert!(MembershipCircuit::blank().generate_constraints(cs).is_err());
    }
}
