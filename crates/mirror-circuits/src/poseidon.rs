//! An in-circuit Poseidon gadget wired to the SAME parameter table the chain
//! uses, plus the native hash it is tested against.
//!
//! # What this is
//!
//! [`hash_var`] synthesizes the circomlib Poseidon permutation as R1CS
//! constraints over BN254. It is a transcription of the permutation
//! `light-poseidon` performs natively - identical state layout, identical round
//! schedule, identical constants - with every field operation replaced by its
//! constraint-system counterpart:
//!
//! ```text
//! state      = [domain_tag = 0, in_0, .., in_{t-2}]     (width t = inputs + 1)
//! full  half : add round constants, x^5 on ALL elements, multiply by MDS
//! partial    : add round constants, x^5 on element 0,    multiply by MDS
//! full  half : add round constants, x^5 on ALL elements, multiply by MDS
//! output     = state[0]
//! ```
//!
//! # Where the constants come from, and what that does and does not prove
//!
//! The round constants and the MDS matrix are read from
//! `light_poseidon::parameters::bn254_x5`, which is the parameter table the
//! Solana `sol_poseidon` syscall is built on: agave's syscall implementation
//! calls `light-poseidon`. So agreement between this gadget and the syscall is
//! NOT agreement between two independently written Poseidons. It pins the thing
//! that actually breaks in practice - the parameter set, the state layout, the
//! round schedule, the byte order - between the circuit and the chain. The
//! permutation *code* here is independent (it is written against the algorithm,
//! not derived from light-poseidon's hasher), but the *constants* are shared by
//! construction, and that is the honest description.
//!
//! # Cost
//!
//! Each `x^5` is three multiplication constraints (`x2 = x*x`, `x4 = x2*x2`,
//! `x5 = x4*x`), exactly what circomlib's `Sigma` costs. Adding round constants
//! and multiplying by the MDS matrix are affine and cost nothing: `ark-r1cs-std`
//! carries them as symbolic linear combinations. See `docs/ARKWORKS.md` for the
//! measured comparison against the committed circom `.r1cs`.

use std::sync::OnceLock;

use ark_bn254::Fr;
use ark_ff::Zero;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_relations::r1cs::SynthesisError;
use light_poseidon::{parameters::bn254_x5, PoseidonHasher, PoseidonParameters};

/// The smallest supported state width (one input).
pub const MIN_WIDTH: usize = 2;
/// The largest state width this crate caches parameters for. The membership
/// scheme uses widths 3 (`Poseidon(2)`) and 4 (`Poseidon(3)`); 5 is included so
/// tests can exercise a width the scheme does not use.
pub const MAX_WIDTH: usize = 5;

/// The S-box exponent the BN254 x^5 parameter set uses. Asserted rather than
/// assumed: a parameter table with a different alpha would need a different
/// gadget, and silently proving the wrong permutation is the failure this
/// prevents.
const ALPHA: u64 = 5;

/// Errors this gadget can return before any constraint is generated.
#[derive(Debug, thiserror::Error)]
pub enum PoseidonGadgetError {
    /// The requested number of inputs has no cached parameter set.
    #[error("Poseidon width {width} is outside the supported range {MIN_WIDTH}..={MAX_WIDTH}")]
    UnsupportedWidth { width: usize },
}

/// The cached `bn254_x5` parameter sets for widths [`MIN_WIDTH`]..=[`MAX_WIDTH`],
/// indexed by `width - MIN_WIDTH`. Built once; the tables are large and the
/// membership circuit hashes 22 times per proof.
fn table() -> &'static [PoseidonParameters<Fr>] {
    static TABLE: OnceLock<Vec<PoseidonParameters<Fr>>> = OnceLock::new();
    TABLE.get_or_init(|| {
        (MIN_WIDTH..=MAX_WIDTH)
            .map(|w| {
                let p = bn254_x5::get_poseidon_parameters::<Fr>(w as u8)
                    .expect("bn254_x5 has parameters for widths 2..=13");
                assert_eq!(p.alpha, ALPHA, "bn254_x5 is an x^5 parameter set");
                assert_eq!(p.width, w, "parameter width matches the request");
                assert_eq!(
                    p.ark.len(),
                    (p.full_rounds + p.partial_rounds) * p.width,
                    "one round constant per state element per round"
                );
                p
            })
            .collect()
    })
}

/// The parameter set for a state of `width` elements (`width - 1` hash inputs).
pub fn parameters(width: usize) -> Result<&'static PoseidonParameters<Fr>, PoseidonGadgetError> {
    if !(MIN_WIDTH..=MAX_WIDTH).contains(&width) {
        return Err(PoseidonGadgetError::UnsupportedWidth { width });
    }
    Ok(&table()[width - MIN_WIDTH])
}

/// The NATIVE circomlib Poseidon over `inputs`, as the rest of the repo (and the
/// `sol_poseidon` syscall) computes it. This is the reference [`hash_var`] is
/// tested against; it is `light-poseidon`'s own hasher, not a re-implementation,
/// so the test compares the gadget against the shipping native path rather than
/// against a second copy of the same bug.
pub fn hash_native(inputs: &[Fr]) -> Result<Fr, PoseidonGadgetError> {
    let width = inputs.len() + 1;
    // Validate the width against the same bound the gadget uses, so native and
    // in-circuit reject exactly the same calls.
    parameters(width)?;
    let mut hasher =
        light_poseidon::Poseidon::<Fr>::new_circom(inputs.len()).expect("width already validated");
    Ok(hasher.hash(inputs).expect("inputs are field elements"))
}

/// `x^5` as three multiplication constraints, matching circomlib's `Sigma`.
///
/// On a constant input this folds to a constant and costs nothing, which is the
/// one place the arkworks constraint count differs from circom's: circom keeps
/// the zero domain tag as a signal and pays for its round-0 S-box.
fn sbox(x: &FpVar<Fr>) -> Result<FpVar<Fr>, SynthesisError> {
    let x2 = x.square()?;
    let x4 = x2.square()?;
    Ok(x4 * x)
}

/// Add this round's constants to every state element (affine, no constraints).
fn add_round_constants(state: &mut [FpVar<Fr>], p: &PoseidonParameters<Fr>, round: usize) {
    for (i, s) in state.iter_mut().enumerate() {
        *s += FpVar::Constant(p.ark[round * p.width + i]);
    }
}

/// Multiply the state by the MDS matrix (affine, no constraints).
fn apply_mds(state: &mut [FpVar<Fr>], p: &PoseidonParameters<Fr>) {
    let mixed: Vec<FpVar<Fr>> = (0..p.width)
        .map(|i| {
            state
                .iter()
                .enumerate()
                .fold(FpVar::<Fr>::zero(), |acc, (j, s)| {
                    acc + s * FpVar::Constant(p.mds[i][j])
                })
        })
        .collect();
    state.clone_from_slice(&mixed);
}

/// The circomlib Poseidon of `inputs`, synthesized as constraints.
///
/// The number of inputs selects the width exactly as `new_circom` does
/// (`width = inputs + 1`), so `hash_var(&[a, b])` is the in-circuit twin of
/// `hash_native(&[a, b])` and of `Poseidon(2)` in the circom sources.
pub fn hash_var(inputs: &[FpVar<Fr>]) -> Result<FpVar<Fr>, SynthesisError> {
    let width = inputs.len() + 1;
    let p = parameters(width).map_err(|_| SynthesisError::Unsatisfiable)?;

    // state[0] is the domain tag, zero for the circom-compatible parameterization.
    let mut state: Vec<FpVar<Fr>> = Vec::with_capacity(width);
    state.push(FpVar::Constant(Fr::zero()));
    state.extend_from_slice(inputs);

    let half = p.full_rounds / 2;
    let partial_end = half + p.partial_rounds;
    let all = p.full_rounds + p.partial_rounds;

    for round in 0..half {
        add_round_constants(&mut state, p, round);
        for s in state.iter_mut() {
            *s = sbox(s)?;
        }
        apply_mds(&mut state, p);
    }
    for round in half..partial_end {
        add_round_constants(&mut state, p, round);
        state[0] = sbox(&state[0])?;
        apply_mds(&mut state, p);
    }
    for round in partial_end..all {
        add_round_constants(&mut state, p, round);
        for s in state.iter_mut() {
            *s = sbox(s)?;
        }
        apply_mds(&mut state, p);
    }

    Ok(state[0].clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::PrimeField;
    use ark_r1cs_std::alloc::AllocVar;
    use ark_r1cs_std::R1CSVar;
    use ark_relations::r1cs::ConstraintSystem;

    /// A spread of inputs: small, zero, the field maximum, and fixed
    /// pseudo-random 32-byte vectors reduced into the field.
    fn vectors() -> Vec<Fr> {
        let mut v = vec![
            Fr::from(0u64),
            Fr::from(1u64),
            Fr::from(2u64),
            -Fr::from(1u64),
            Fr::from(u64::MAX),
        ];
        // Deterministic, non-trivial field elements (a fixed byte pattern per
        // index, reduced), so the vectors are stable across runs.
        for seed in 0u8..6 {
            let mut b = [0u8; 32];
            for (i, x) in b.iter_mut().enumerate() {
                *x = seed
                    .wrapping_mul(37)
                    .wrapping_add((i as u8).wrapping_mul(11));
            }
            v.push(Fr::from_be_bytes_mod_order(&b));
        }
        v
    }

    /// Run the gadget over `inputs` inside a real constraint system and return
    /// (in-circuit output, constraints emitted, satisfied).
    fn run_gadget(inputs: &[Fr]) -> (Fr, usize, bool) {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let vars: Vec<FpVar<Fr>> = inputs
            .iter()
            .map(|x| FpVar::new_witness(cs.clone(), || Ok(*x)).unwrap())
            .collect();
        let out = hash_var(&vars).unwrap();
        let value = out.value().unwrap();
        (value, cs.num_constraints(), cs.is_satisfied().unwrap())
    }

    /// THE gadget/native agreement check. For every supported width and a spread
    /// of inputs, the in-circuit Poseidon must produce exactly the value
    /// `light-poseidon` produces natively - the same hash the on-chain
    /// `sol_poseidon` syscall computes, since the syscall is built on
    /// `light-poseidon`.
    #[test]
    fn gadget_agrees_with_the_native_hash_at_every_supported_width() {
        let v = vectors();
        for n_inputs in 1..MAX_WIDTH {
            for window in v.windows(n_inputs) {
                let (in_circuit, _constraints, satisfied) = run_gadget(window);
                assert!(satisfied, "constraint system must be satisfied");
                let native = hash_native(window).unwrap();
                assert_eq!(
                    in_circuit, native,
                    "gadget and native Poseidon disagree for {n_inputs} inputs on {window:?}"
                );
            }
        }
    }

    /// The gadget must agree with the SCHEME the rest of the repo computes, not
    /// just with a raw hash call: the commitment, the nullifier and a Merkle node
    /// as `mirror-core` defines them (and as the on-chain accumulator recomputes
    /// them).
    #[test]
    fn gadget_reproduces_the_repo_commitment_scheme() {
        use crate::membership::{fr_from_be, fr_to_be};

        let secret_bytes = [0x2au8; 32];
        let mut recipient = [0u8; 32];
        for (i, b) in recipient.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(3);
        }
        let action_hash = mirror_core::transfer_action_hash(&recipient, 1_234_567);
        let epoch = 11u64;

        let secret = mirror_core::Secret(secret_bytes);
        let expected_commitment =
            mirror_core::commit_with_action_hash(&secret, &action_hash, mirror_core::Epoch(epoch));
        let expected_nullifier = mirror_core::nullifier(&secret, mirror_core::Epoch(epoch));

        let (commitment, _, ok1) = run_gadget(&[
            fr_from_be(&secret_bytes),
            fr_from_be(&action_hash),
            Fr::from(epoch),
        ]);
        let (nullifier, _, ok2) = run_gadget(&[fr_from_be(&secret_bytes), Fr::from(epoch)]);
        assert!(ok1 && ok2);
        assert_eq!(fr_to_be(&commitment), expected_commitment.0);
        assert_eq!(fr_to_be(&nullifier), expected_nullifier.0);

        // One internal Merkle node, the hash the on-chain accumulator makes with
        // `sol_poseidon` at every level.
        let left = [0x11u8; 32];
        let right = [0x22u8; 32];
        let (node, _, ok3) = run_gadget(&[fr_from_be(&left), fr_from_be(&right)]);
        assert!(ok3);
        assert_eq!(fr_to_be(&node), mirror_core::merkle_node(&left, &right));
    }

    /// Each `x^5` is three multiplication constraints and nothing else costs
    /// anything, so a width-`t` hash is `3 * (8t + partial)` constraints minus
    /// the three the round-0 domain-tag S-box folds away as a constant.
    #[test]
    fn constraint_cost_per_hash_is_exactly_the_sbox_count() {
        for n_inputs in 1..MAX_WIDTH {
            let width = n_inputs + 1;
            let p = parameters(width).unwrap();
            let sboxes = p.full_rounds * width + p.partial_rounds;
            // Round 0 element 0 is the constant domain tag; its S-box folds.
            let expected = 3 * (sboxes - 1);
            let inputs: Vec<Fr> = (0..n_inputs).map(|i| Fr::from(i as u64 + 3)).collect();
            let (_, constraints, satisfied) = run_gadget(&inputs);
            assert!(satisfied);
            assert_eq!(
                constraints, expected,
                "width {width}: {sboxes} S-boxes, one of them constant-folded"
            );
        }
    }

    /// Widths the parameter table does not cover are refused up front rather
    /// than silently hashing with the wrong constants.
    #[test]
    fn unsupported_widths_are_rejected() {
        assert!(parameters(1).is_err());
        assert!(parameters(MAX_WIDTH + 1).is_err());
        assert!(hash_native(&[]).is_err());
        let too_many: Vec<Fr> = (0..MAX_WIDTH as u64).map(Fr::from).collect();
        assert!(hash_native(&too_many).is_err());
    }
}
