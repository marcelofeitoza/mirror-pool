//! Compare the arkworks constraint system against the COMMITTED circom one.
//!
//! The circom `.r1cs` is a gitignored build output (`bash circuits/build.sh`), so
//! this comparison cannot run in a clean checkout and is `#[ignore]`d. Run it
//! deliberately:
//!
//! ```text
//! cargo test -p mirror-circuits -- --ignored --nocapture circom
//! ```
//!
//! It is not decoration: the headline numbers in `docs/ARKWORKS.md` are produced
//! by this test, so they can be re-derived rather than believed.
//!
//! # What the numbers mean
//!
//! circom's default optimization level keeps purely LINEAR constraints (an R1CS
//! row whose `A` or `B` side is empty) in the emitted system: adding Poseidon
//! round constants, multiplying by the MDS matrix, and the two `===` equality
//! assertions all become rows. `ark-r1cs-std` carries the same affine work as
//! symbolic linear combinations and only emits a row for an actual
//! multiplication. So the honest comparison is arkworks' constraint count against
//! circom's QUADRATIC row count, and the linear rows are reported separately
//! rather than folded into a flattering single number.

use std::path::PathBuf;

/// The r1cs binary format's header numbers plus a quadratic/linear split of the
/// constraint section.
#[derive(Debug, PartialEq, Eq)]
struct R1csShape {
    n_wires: u32,
    n_pub_in: u32,
    n_prv_in: u32,
    n_constraints: u32,
    quadratic: usize,
    linear: usize,
}

fn u32_at(d: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(d[off..off + 4].try_into().expect("4 bytes"))
}

fn u64_at(d: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(d[off..off + 8].try_into().expect("8 bytes"))
}

/// Parse the `.r1cs` container: magic, version, section table, then the header
/// (type 1) and constraint (type 2) sections.
fn parse_r1cs(d: &[u8]) -> R1csShape {
    assert_eq!(&d[..4], b"r1cs", "not an r1cs file");
    let n_sections = u32_at(d, 8);
    let mut header = None;
    let mut constraints = None;
    let mut off = 12usize;
    for _ in 0..n_sections {
        let kind = u32_at(d, off);
        let size = u64_at(d, off + 4) as usize;
        off += 12;
        match kind {
            1 => header = Some(off),
            2 => constraints = Some(off),
            _ => {}
        }
        off += size;
    }
    let h = header.expect("header section");
    let field_size = u32_at(d, h) as usize;
    let mut p = h + 4 + field_size;
    let n_wires = u32_at(d, p);
    let n_pub_out = u32_at(d, p + 4);
    let n_pub_in = u32_at(d, p + 8);
    let n_prv_in = u32_at(d, p + 12);
    assert_eq!(n_pub_out, 0, "membership declares no public outputs");
    p += 16 + 8; // skip nLabels
    let n_constraints = u32_at(d, p);

    // Each constraint is three linear combinations; a row with a non-empty A AND
    // a non-empty B is a multiplication, anything else is affine.
    let mut p = constraints.expect("constraint section");
    let mut quadratic = 0usize;
    let mut linear = 0usize;
    for _ in 0..n_constraints {
        let mut nonzero = [0u32; 3];
        for slot in nonzero.iter_mut() {
            let n = u32_at(d, p);
            p += 4 + (n as usize) * (4 + field_size);
            *slot = n;
        }
        if nonzero[0] > 0 && nonzero[1] > 0 {
            quadratic += 1;
        } else {
            linear += 1;
        }
    }

    R1csShape {
        n_wires,
        n_pub_in,
        n_prv_in,
        n_constraints,
        quadratic,
        linear,
    }
}

fn r1cs_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("../../circuits/{name}.r1cs"))
}

fn read_shape(name: &str) -> R1csShape {
    let path = r1cs_path(name);
    let bytes = std::fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "cannot read {}: {e}. Run the circuit build script once to produce the \
             gitignored circom build artifacts.",
            path.display()
        )
    });
    parse_r1cs(&bytes)
}

/// A circomlib Poseidon of `t - 1` inputs costs three rows per S-box, and there
/// are `8*t + partial` S-boxes. `partial` comes from circomlib's own table.
fn circom_poseidon_rows(t: usize) -> usize {
    let partial = match t {
        2 => 56,
        3 => 57,
        4 => 56,
        _ => panic!("width {t} is not used by these circuits"),
    };
    3 * (8 * t + partial)
}

#[test]
#[ignore = "needs the gitignored circom build artifact circuits/membership.r1cs"]
fn circom_membership_r1cs_shape_is_what_the_docs_claim() {
    let shape = read_shape("membership");
    println!("circom membership.r1cs: {shape:?}");

    assert_eq!(
        shape,
        R1csShape {
            n_wires: 11_546,
            n_pub_in: 4,
            // secret + 20 pathElements + 20 pathIndices
            n_prv_in: 41,
            n_constraints: 11_522,
            quadratic: 5_427,
            linear: 6_095,
        },
        "the committed circom circuit changed shape; docs/ARKWORKS.md is now stale"
    );

    // 21 Poseidon(2) (nullifier + 20 Merkle levels) at 3 constraints per S-box,
    // 1 Poseidon(3), and 3 constraints per path selector, accounts for every
    // quadratic row exactly.
    let selectors = 3 * 20;
    assert_eq!(
        21 * circom_poseidon_rows(3) + circom_poseidon_rows(4) + selectors,
        shape.quadratic as usize,
        "the S-box accounting must explain every quadratic constraint"
    );
}

/// The same, for the confidential-value JoinSplit. This is the number
/// `docs/ARKWORKS.md` compares the arkworks JoinSplit against, so it is measured
/// rather than quoted.
///
/// The accounting below is worth reading once, because one line of it is
/// counter-intuitive. circomlib's `IsEqual` is two quadratic rows, and the
/// circuit writes `sameNullifier[p].out === 0`. That equality is LINEAR, so
/// circom's linear-substitution pass eliminates the `out` signal, at which point
/// `IsZero`'s second row `in * out === 0` becomes identically zero and is
/// dropped. What survives is a single row, `diff * inv === 1` - which is exactly
/// what `FpVar::enforce_not_equal` emits on the arkworks side, so the two
/// systems pay the same one row for nullifier distinctness.
#[test]
#[ignore = "needs the gitignored circom build artifact circuits/transaction.r1cs"]
fn circom_transaction_r1cs_shape_is_what_the_docs_claim() {
    let shape = read_shape("transaction");
    println!("circom transaction.r1cs: {shape:?}");

    assert_eq!(
        shape,
        R1csShape {
            n_wires: 27_328,
            n_pub_in: 7,
            // inAmount[2] + inPrivateKey[2] + inBlinding[2] + inPathIndices[2]
            // + inPathElements[2][20] + outAmount[2] + outPubkey[2]
            // + outBlinding[2] + magnitude + sign
            n_prv_in: 56,
            n_constraints: 27_278,
            quadratic: 13_098,
            linear: 14_180,
        },
        "the committed circom JoinSplit changed shape; docs/ARKWORKS.md is now stale"
    );

    // 50 Poseidon calls: 2 keypairs (t=2); 8 three-input hashes (t=4) for the
    // two input commitments, two signatures, two nullifiers and two output
    // commitments; and 40 Merkle nodes (t=3), 20 per input.
    let hashes =
        2 * circom_poseidon_rows(2) + 8 * circom_poseidon_rows(4) + 40 * circom_poseidon_rows(3);
    assert_eq!(hashes, 12_264);

    let num2bits_20 = 2 * 20; // one per input's path index
    let switchers = 2 * 20; // one row each
    let force_equal_if_enabled = 2 * 3; // IsZero (2) + the enable product (1)
    let num2bits_248 = 3 * 248; // two output amounts + the publicAmount magnitude
    let sign_booleanity = 1;
    let signed_decoding = 1; // publicAmount === magnitude * signFactor
    let nullifier_distinctness = 1; // IsEqual, reduced as described above
    let ext_data_hash_square = 1;

    assert_eq!(
        hashes
            + num2bits_20
            + switchers
            + force_equal_if_enabled
            + num2bits_248
            + sign_booleanity
            + signed_decoding
            + nullifier_distinctness
            + ext_data_hash_square,
        shape.quadratic as usize,
        "the gadget accounting must explain every quadratic constraint"
    );
}
