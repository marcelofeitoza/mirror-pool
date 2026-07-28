//! The three non-hash circomlib gadgets the JoinSplit needs, transcribed to
//! arkworks constraint synthesis at the SAME cost circom pays for them.
//!
//! `transaction.circom` builds its statement out of `Num2Bits`, `Switcher` and
//! `ForceEqualIfEnabled`. Each one below is written against the circomlib source
//! rather than against an arkworks equivalent, because the arkworks equivalents
//! are more expensive for reasons that have nothing to do with this statement:
//!
//! - [`num_to_bits_le`] vs `FpVar::to_bits_le`. The arkworks method decomposes
//!   into the FULL 254 bits and then proves the result is below the modulus.
//!   `Num2Bits(n)` does neither: it allocates exactly `n` bits and binds their
//!   weighted sum to the value, which for `n < 253` already forces the value
//!   into `[0, 2^n)` with no wraparound. That bound is the whole point of the
//!   range checks here, so the cheaper gadget is also the faithful one.
//! - [`switcher`] vs two `FpVar::conditionally_select` calls. One multiplication
//!   (`aux = (R - L) * sel`) yields BOTH outputs affinely, which is what
//!   circomlib's `Switcher` does and half what a pair of selects costs.
//! - [`force_equal_if_enabled`] has no arkworks counterpart at all: it is
//!   circomlib's `IsZero` plus one product, and it is what lets a shield spend
//!   dummy inputs whose Merkle path is meaningless.
//!
//! Every gadget states its constraint cost, and
//! `crates/mirror-circuits/tests/transaction_end_to_end.rs` pins the total those
//! costs add up to.

use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, BigInteger, Field, One, PrimeField, Zero};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::R1CSVar;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

/// circomlib `Num2Bits(n)`: decompose `value` into `n` little-endian bits.
///
/// Emits `n` booleanity constraints (one per allocated [`Boolean`]) plus one row
/// binding the weighted sum, so `n + 1` in total. circom emits the same `n`
/// booleanity rows and carries the sum as an affine row instead; that one row is
/// the entire per-call difference between the two systems.
///
/// The binding is what makes this a RANGE CHECK: `value` equals a sum of `n`
/// bits, which is at most `2^n - 1`. For every `n` used here (20 and 248) that
/// is far below the BN254 modulus, so no larger field element can be
/// represented and no wraparound can forge value.
pub(crate) fn num_to_bits_le(
    cs: ConstraintSystemRef<Fr>,
    value: &FpVar<Fr>,
    n: usize,
) -> Result<Vec<Boolean<Fr>>, SynthesisError> {
    let mut bits = Vec::with_capacity(n);
    let mut acc = FpVar::<Fr>::zero();
    let mut weight = Fr::one();
    for i in 0..n {
        // In setup mode this closure is never called, so a shape-only instance
        // never needs a value here.
        let bit = Boolean::new_witness(cs.clone(), || Ok(value.value()?.into_bigint().get_bit(i)))?;
        // Boolean -> field and scaling by a constant are both affine.
        acc += FpVar::from(bit.clone()) * FpVar::Constant(weight);
        weight.double_in_place();
        bits.push(bit);
    }
    value.enforce_equal(&acc)?;
    Ok(bits)
}

/// circomlib `Switcher`: return `(L, R)` when `sel` is false and `(R, L)` when
/// it is true.
///
/// One constraint. `aux = (R - L) * sel` is the only multiplication; both
/// outputs, `L + aux` and `R - aux`, are affine in it.
pub(crate) fn switcher(
    l: &FpVar<Fr>,
    r: &FpVar<Fr>,
    sel: &Boolean<Fr>,
) -> Result<(FpVar<Fr>, FpVar<Fr>), SynthesisError> {
    let aux = (r - l) * FpVar::from(sel.clone());
    Ok((l + &aux, r - &aux))
}

/// circomlib `ForceEqualIfEnabled`: require `a == b`, but only when `enabled`
/// is nonzero.
///
/// Three constraints, the same three circomlib emits:
///
/// ```text
/// is_nonzero = diff * inv          // inv is a hint witness
/// diff * (1 - is_nonzero) === 0    // pins inv when diff != 0
/// is_nonzero * enabled     === 0   // so diff != 0 forces enabled == 0
/// ```
///
/// The soundness argument, spelled out because this gadget is what a shield
/// leans on:
///
/// - `diff == 0`: rows two and three hold for any `inv`, and `a == b` anyway.
/// - `diff != 0`: row two forces `is_nonzero == 1`, so row three forces
///   `enabled == 0`. A prover can therefore only present a non-matching root
///   for an input whose amount is zero, and a zero-amount input contributes
///   nothing to the value sum.
pub(crate) fn force_equal_if_enabled(
    cs: ConstraintSystemRef<Fr>,
    a: &FpVar<Fr>,
    b: &FpVar<Fr>,
    enabled: &FpVar<Fr>,
) -> Result<(), SynthesisError> {
    let diff = b - a;
    let inv = FpVar::new_witness(cs, || Ok(diff.value()?.inverse().unwrap_or_else(Fr::zero)))?;

    let is_nonzero = &diff * &inv;
    let is_zero = FpVar::one() - &is_nonzero;
    diff.mul_equals(&is_zero, &FpVar::zero())?;
    is_nonzero.mul_equals(enabled, &FpVar::zero())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;

    /// Run `body` in a fresh constraint system and report (constraints,
    /// satisfied).
    fn run<F>(body: F) -> (usize, bool)
    where
        F: FnOnce(ConstraintSystemRef<Fr>) -> Result<(), SynthesisError>,
    {
        let cs = ConstraintSystem::<Fr>::new_ref();
        body(cs.clone()).expect("synthesis");
        (
            cs.num_constraints(),
            cs.is_satisfied().expect("satisfiable"),
        )
    }

    fn witness(cs: &ConstraintSystemRef<Fr>, v: Fr) -> FpVar<Fr> {
        FpVar::new_witness(cs.clone(), || Ok(v)).expect("witness")
    }

    /// A correct decomposition costs exactly `n + 1` rows and is satisfied.
    #[test]
    fn num_to_bits_costs_one_row_per_bit_plus_the_binding() {
        for n in [1usize, 8, 20, 248] {
            let (constraints, ok) = run(|cs| {
                let v = witness(&cs, Fr::from(12_345u64 % (1u64 << n.min(20))));
                num_to_bits_le(cs, &v, n).map(|_| ())
            });
            assert!(ok, "n = {n}");
            assert_eq!(constraints, n + 1, "n = {n}");
        }
    }

    /// The bits really are the value's bits, little-endian.
    #[test]
    fn num_to_bits_returns_the_little_endian_bits() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let v = witness(&cs, Fr::from(0b1011u64));
        let bits = num_to_bits_le(cs.clone(), &v, 8).expect("synthesis");
        let got: Vec<bool> = bits.iter().map(|b| b.value().expect("value")).collect();
        assert_eq!(
            got,
            vec![true, true, false, true, false, false, false, false]
        );
        assert!(cs.is_satisfied().expect("satisfiable"));
    }

    /// THE range property: a value that does not fit `n` bits cannot be
    /// decomposed, so the system is unsatisfiable. Without this, an "amount"
    /// could be a huge field element and value conservation could wrap.
    #[test]
    fn num_to_bits_rejects_a_value_that_does_not_fit() {
        for n in [4usize, 20] {
            let (_, ok) = run(|cs| {
                let v = witness(&cs, Fr::from(1u64 << n));
                num_to_bits_le(cs, &v, n).map(|_| ())
            });
            assert!(!ok, "2^{n} must not decompose into {n} bits");
        }
        // The interesting adversarial case: -1 is a 254-bit field element.
        let (_, ok) = run(|cs| {
            let v = witness(&cs, -Fr::one());
            num_to_bits_le(cs, &v, 248).map(|_| ())
        });
        assert!(!ok, "r - 1 must not decompose into 248 bits");
    }

    /// One constraint, and the swap goes the direction the Merkle convention
    /// needs: `sel = true` means the running node is the RIGHT child, so the
    /// sibling comes out on the left.
    #[test]
    fn switcher_swaps_on_a_true_selector_for_one_constraint() {
        for (sel, expect_l, expect_r) in [(false, 7u64, 9u64), (true, 9u64, 7u64)] {
            let cs = ConstraintSystem::<Fr>::new_ref();
            let l = witness(&cs, Fr::from(7u64));
            let r = witness(&cs, Fr::from(9u64));
            let s = Boolean::new_witness(cs.clone(), || Ok(sel)).expect("bit");
            let before = cs.num_constraints();
            let (out_l, out_r) = switcher(&l, &r, &s).expect("synthesis");
            assert_eq!(cs.num_constraints() - before, 1, "sel = {sel}");
            assert_eq!(out_l.value().expect("value"), Fr::from(expect_l));
            assert_eq!(out_r.value().expect("value"), Fr::from(expect_r));
            assert!(cs.is_satisfied().expect("satisfiable"));
        }
    }

    /// Three constraints, and the full truth table: equal values always pass;
    /// unequal values pass only when disabled.
    #[test]
    fn force_equal_if_enabled_has_the_circomlib_truth_table() {
        let cases = [
            // (a, b, enabled, must be satisfied)
            (3u64, 3u64, 0u64, true),
            (3, 3, 1, true),
            (3, 3, 500, true),
            (3, 4, 0, true),
            (3, 4, 1, false),
            (3, 4, 500, false),
        ];
        for (a, b, enabled, expected) in cases {
            let (constraints, ok) = run(|cs| {
                let av = witness(&cs, Fr::from(a));
                let bv = witness(&cs, Fr::from(b));
                let ev = witness(&cs, Fr::from(enabled));
                force_equal_if_enabled(cs, &av, &bv, &ev)
            });
            assert_eq!(constraints, 3, "({a}, {b}, {enabled})");
            assert_eq!(ok, expected, "({a}, {b}, {enabled})");
        }
    }

    /// A malicious prover cannot claim "disabled" by lying about `inv`: the
    /// gadget is checked with the value the witness generator produces, and the
    /// two product rows leave no free choice. This drives it directly by
    /// forcing an inconsistent `inv` and requiring the system to reject.
    #[test]
    fn force_equal_if_enabled_pins_the_inverse_hint() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let a = witness(&cs, Fr::from(3u64));
        let b = witness(&cs, Fr::from(4u64));
        let enabled = witness(&cs, Fr::from(1u64));

        // The same three rows, but with a WRONG inverse hint (zero, the value a
        // prover would want so that `is_nonzero` reads as 0 and the enable check
        // passes vacuously).
        let diff = &b - &a;
        let inv = witness(&cs, Fr::from(0u64));
        let is_nonzero = &diff * &inv;
        let is_zero = FpVar::one() - &is_nonzero;
        diff.mul_equals(&is_zero, &FpVar::zero()).expect("row");
        is_nonzero
            .mul_equals(&enabled, &FpVar::zero())
            .expect("row");

        assert!(
            !cs.is_satisfied().expect("satisfiable"),
            "a zero inverse hint for a nonzero difference must not satisfy the system"
        );
    }
}
