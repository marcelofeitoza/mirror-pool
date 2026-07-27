//! In-process, pure-Rust Groth16 proving: the default `prove` / `shield` /
//! `transfer` / `unshield` proving path, with NO Node/snarkjs process spawned.
//!
//! This replaces the `snarkjs groth16 fullprove` shell-out. The proof is produced
//! end-to-end in Rust at runtime:
//!
//! 1. Load the circom build artifacts - the compiled `.wasm` witness calculator and
//!    the `.r1cs` - with [`ark_circom`]. The `.wasm` is run IN-PROCESS by the
//!    pure-Rust `wasmer` WebAssembly runtime to compute the witness; nothing shells
//!    out to `node`.
//! 2. Read the Groth16 proving key from the committed `.zkey` with
//!    [`ark_circom::read_zkey`] (the SAME key the on-chain verifying key in
//!    `programs/mirror-pool/src/vk.rs` was exported from).
//! 3. Prove with [`ark_groth16`] over `ark-bn254`, using [`CircomReduction`] - the
//!    snarkjs-compatible R1CS-to-QAP witness map - so the proof verifies under a
//!    snarkjs-exported verifying key.
//! 4. Verify the proof in-process against the zkey's verifying key, cross-check the
//!    circuit's public signals against the values the caller will place in the
//!    instruction data, and serialize into the `groth16-solana` byte layout by
//!    reusing the audited [`crate::groth16::SnarkjsProof::to_bytes`] conversion
//!    (big-endian, `proof_a` pre-negated, G2 imaginary-part-first).
//!
//! The `.wasm` / `.r1cs` / `.zkey` are circom BUILD outputs (`bash circuits/build.sh`
//! and `build_transaction.sh`), exactly like the snarkjs path consumed; the
//! difference is that at RUNTIME no JavaScript/Node interpreter is involved. The
//! same function serves both the membership circuit (4 public inputs) and the
//! transaction circuit (7 public inputs); the caller supplies the circom-shaped
//! `input.json` object and the expected public inputs in circuit-declaration order.

use std::fs::File;
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use ark_bn254::{Bn254, Fr};
use ark_circom::{read_zkey, CircomBuilder, CircomConfig, CircomReduction};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{Groth16, Proof, ProvingKey};
use ark_snark::SNARK;
use num_bigint::{BigInt, BigUint};
use serde_json::Value;

use mirror_core::Hash32;

use crate::groth16::{ProofBytes, SnarkjsProof};

/// The circuit build artifacts an in-process proof needs. All three are circom
/// BUILD outputs (gitignored; produced once by `bash circuits/build.sh` for the
/// membership circuit or `build_transaction.sh` for the transaction circuit):
///
/// - `wasm`: the compiled witness calculator, run in-process under `wasmer`.
/// - `r1cs`: the compiled constraint system (used for the witness map + a debug
///   satisfiability sanity check).
/// - `zkey`: the Groth16 proving key the committed on-chain verifying key was
///   exported from.
pub struct Artifacts<'a> {
    pub wasm: &'a Path,
    pub r1cs: &'a Path,
    pub zkey: &'a Path,
}

/// Generate a Groth16 proof for a circom circuit fully in-process (no Node), verify
/// it against the verifying key embedded in the `.zkey` (the same key the on-chain
/// program embeds), cross-check the circuit's public signals against
/// `expected_public` (in circuit-declaration order), and return the proof in the
/// `groth16-solana` byte layout the on-chain verifier consumes.
///
/// `input` is the circom `input.json` object (decimal field-element strings, the
/// exact shape the snarkjs path writes). `expected_public` is what the caller will
/// embed in the instruction data; if the circuit's own public signals differ, the
/// emitted proof would commit to different inputs than the program checks, so this
/// fails loudly rather than emitting a proof that cannot land.
pub fn prove(art: &Artifacts, input: &Value, expected_public: &[Hash32]) -> Result<ProofBytes> {
    if !art.zkey.exists() {
        bail!(
            "proving key (zkey) not found at {}: run `bash circuits/build.sh` once to produce the \
             gitignored r1cs/wasm/zkey build artifacts",
            art.zkey.display()
        );
    }
    // Proving key from the committed zkey (the on-chain vk was exported from it).
    let mut file = File::open(art.zkey)
        .with_context(|| format!("opening proving key {}", art.zkey.display()))?;
    let (pk, _matrices) = read_zkey(&mut file)
        .map_err(|e| anyhow!("reading proving key from {}: {e}", art.zkey.display()))?;
    prove_with_key(art.wasm, art.r1cs, &pk, input, expected_public)
}

/// The same proof, but with the proving key supplied directly instead of read from
/// a `.zkey`.
///
/// This is what lets a CEREMONY-produced key be used to prove: `mirror-ceremony`
/// hands back an [`ark_groth16::ProvingKey`], and the resulting proof is verified
/// here against that key's own verifying key - which is the key a deployment would
/// embed on chain.
pub fn prove_with_key(
    wasm: &Path,
    r1cs: &Path,
    pk: &ProvingKey<Bn254>,
    input: &Value,
    expected_public: &[Hash32],
) -> Result<ProofBytes> {
    Ok(prove_with_key_full(wasm, r1cs, pk, input, expected_public)?.bytes)
}

/// A generated proof in both shapes a caller might need: the `groth16-solana` byte
/// layout the on-chain verifier consumes, and the snarkjs `proof.json` shape, so
/// the same proof can be handed to `snarkjs groth16 verify` as an independent
/// cross-check.
pub struct RustProof {
    pub bytes: ProofBytes,
    pub snarkjs: SnarkjsProof,
}

/// As [`prove_with_key`], returning both encodings of the proof.
pub fn prove_with_key_full(
    wasm: &Path,
    r1cs: &Path,
    pk: &ProvingKey<Bn254>,
    input: &Value,
    expected_public: &[Hash32],
) -> Result<RustProof> {
    for (p, what) in [(wasm, "circuit wasm"), (r1cs, "circuit r1cs")] {
        if !p.exists() {
            bail!(
                "{what} not found at {}: run `bash circuits/build.sh` once to produce the \
                 gitignored r1cs/wasm/zkey build artifacts",
                p.display()
            );
        }
    }

    // The `wasmer-wasix` witness runtime constructs a WASI stdin handle that calls
    // `tokio::runtime::Handle::current()`, so the witness calculation must run inside
    // a Tokio runtime context. A current-thread runtime whose context we merely enter
    // is enough: nothing reads stdin, so the reactor never has to be driven.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("building the Tokio runtime for the wasm witness calculator")?;
    let _rt_guard = rt.enter();

    // Load the circuit (wasm witness calculator + r1cs) and feed the typed inputs.
    let cfg = CircomConfig::<Fr>::new(wasm, r1cs)
        .map_err(|e| anyhow!("loading circuit artifacts (wasm + r1cs): {e}"))?;
    let mut builder = CircomBuilder::new(cfg);
    push_inputs(&mut builder, input)?;

    // Compute the witness in-process (runs the compiled circuit under wasmer; the
    // debug build additionally asserts the R1CS is satisfied). No Node process.
    let circom = builder
        .build()
        .map_err(|e| anyhow!("in-process witness generation failed: {e}"))?;
    let public_inputs = circom
        .get_public_inputs()
        .ok_or_else(|| anyhow!("circuit produced no public inputs"))?;

    // The circuit's public signals MUST equal the values the caller will place in
    // the instruction data.
    cross_check_public(&public_inputs, expected_public)?;

    // Prove with the snarkjs-compatible QAP reduction.
    let mut rng = rand::rngs::OsRng;
    let proof = Groth16::<Bn254, CircomReduction>::prove(pk, circom, &mut rng)
        .map_err(|e| anyhow!("groth16 prove failed: {e}"))?;

    // Verify in-process against this key's own verifying key (for the committed
    // zkey that is the on-chain vk; for a ceremony key it is the vk a deployment
    // would embed). Fail loudly if it does not verify.
    let pvk = Groth16::<Bn254>::process_vk(&pk.vk).map_err(|e| anyhow!("process_vk: {e}"))?;
    let verified = Groth16::<Bn254>::verify_with_processed_vk(&pvk, &public_inputs, &proof)
        .map_err(|e| anyhow!("groth16 verify: {e}"))?;
    if !verified {
        bail!("Rust-generated Groth16 proof did NOT verify against the committed verifying key");
    }

    let snarkjs = ark_proof_to_snarkjs(&proof);
    let bytes = snarkjs.to_bytes()?;
    Ok(RustProof { bytes, snarkjs })
}

/// Push every field of a circom `input.json` object into the builder. Values are
/// decimal field-element strings; arrays (and nested arrays such as the transaction
/// circuit's `inPathElements[2][depth]`) are flattened row-major under one name,
/// which is the order circom's witness calculator expects.
fn push_inputs(builder: &mut CircomBuilder<Fr>, input: &Value) -> Result<()> {
    let obj = input
        .as_object()
        .ok_or_else(|| anyhow!("circuit input must be a JSON object"))?;
    for (name, val) in obj {
        push_value(builder, name, val)?;
    }
    Ok(())
}

fn push_value(builder: &mut CircomBuilder<Fr>, name: &str, val: &Value) -> Result<()> {
    match val {
        Value::String(s) => builder.push_input(name, parse_bigint(s)?),
        Value::Number(n) => builder.push_input(name, parse_bigint(&n.to_string())?),
        Value::Array(items) => {
            for item in items {
                push_value(builder, name, item)?;
            }
        }
        other => bail!("unsupported circuit input value for {name:?}: {other}"),
    }
    Ok(())
}

/// Parse a non-negative decimal field-element string into a [`BigInt`].
fn parse_bigint(s: &str) -> Result<BigInt> {
    BigInt::parse_bytes(s.trim().as_bytes(), 10)
        .ok_or_else(|| anyhow!("invalid decimal field element {s:?}"))
}

/// Confirm the circuit's public signals equal the caller's expected inputs, in the
/// fixed circuit-declaration order.
fn cross_check_public(actual: &[Fr], expected: &[Hash32]) -> Result<()> {
    if actual.len() != expected.len() {
        bail!(
            "circuit produced {} public inputs, expected {}",
            actual.len(),
            expected.len()
        );
    }
    for (i, (a, e)) in actual.iter().zip(expected.iter()).enumerate() {
        let want = Fr::from_be_bytes_mod_order(e);
        if *a != want {
            bail!(
                "public input {i} mismatch: circuit={}, expected={}",
                field_dec(a),
                field_dec(&want)
            );
        }
    }
    Ok(())
}

/// Convert an `ark-groth16` proof into the `SnarkjsProof` shape snarkjs emits, which
/// is also what [`SnarkjsProof::to_bytes`] (the audited conversion that negates
/// `proof_a` and orders G2 imaginary-part-first) consumes - so there is ONE
/// serializer for both proving paths.
fn ark_proof_to_snarkjs(proof: &Proof<Bn254>) -> SnarkjsProof {
    let (a, b, c) = (&proof.a, &proof.b, &proof.c);
    SnarkjsProof {
        // pi_a / pi_c: affine G1 = [x, y, 1].
        pi_a: vec![field_dec(&a.x), field_dec(&a.y), "1".to_string()],
        pi_c: vec![field_dec(&c.x), field_dec(&c.y), "1".to_string()],
        // pi_b: affine G2 = [[x.c0, x.c1], [y.c0, y.c1], [1, 0]] (real part first,
        // matching snarkjs proof.json; to_bytes reorders to imaginary-first).
        pi_b: vec![
            vec![field_dec(&b.x.c0), field_dec(&b.x.c1)],
            vec![field_dec(&b.y.c0), field_dec(&b.y.c1)],
            vec!["1".to_string(), "0".to_string()],
        ],
    }
}

/// A canonical BN254 field element as a decimal string (the form `SnarkjsProof`
/// parses), via its big-endian integer encoding.
fn field_dec<F: PrimeField>(f: &F) -> String {
    BigUint::from_bytes_be(&f.into_bigint().to_bytes_be()).to_str_radix(10)
}
