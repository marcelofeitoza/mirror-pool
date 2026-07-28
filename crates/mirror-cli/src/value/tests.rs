//! Unit tests for the confidential-value witness builder + Transact assembly.
//!
//! The decisive check reproduces, for the committed SHIELD / TRANSFER / UNSHIELD
//! fixtures (the circuit's own snarkjs output), every public signal the witness
//! builder is responsible for - the Merkle root, publicAmount, extDataHash, both
//! input nullifiers, and both output commitments - and asserts the `input.json`
//! the CLI feeds snarkjs has exactly the shape `gen_transaction_fixture.js`
//! produces. If this passes, a proof generated from the CLI's witness verifies
//! against the same public inputs the on-chain program checks.

use super::*;
use crate::groth16;
use crate::tree;
use mirror_core::note::{Note, ValueKeypair};
use serde_json::Value;

// The three committed transaction fixtures, embedded so the test is hermetic.
const SHIELD: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../circuits/artifacts/transaction_shield_fixture.json"
));
const TRANSFER: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../circuits/artifacts/transaction_proof_fixture.json"
));
const UNSHIELD: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../circuits/artifacts/transaction_unshield_fixture.json"
));

/// A field element from the generator's decimal constants.
fn dec(s: &str) -> Hash32 {
    groth16::to_be32(s).unwrap()
}

/// A small field element (blindings / amounts appear as small integers).
fn fe(x: u64) -> Hash32 {
    groth16::to_be32(&x.to_string()).unwrap()
}

/// The fixed recipient / relayer, byte-identical to gen_transaction_fixture.js.
fn recipient() -> [u8; 32] {
    let mut r = [0u8; 32];
    for (i, b) in r.iter_mut().enumerate() {
        *b = (i + 1) as u8; // 0x01..0x20
    }
    r
}
fn relayer() -> [u8; 32] {
    let mut r = [0u8; 32];
    for (i, b) in r.iter_mut().enumerate() {
        *b = (0x20 - i) as u8; // 0x20..0x01
    }
    r
}
fn payload(seed: u64) -> Vec<u8> {
    (0..48u64)
        .map(|i| ((seed * 131 + i * 17) & 0xff) as u8)
        .collect()
}

/// The `publicSignals` array of a fixture, as decimal strings, in the fixed order
/// [root, publicAmount, extDataHash, inNf0, inNf1, outC0, outC1].
fn public_signals(fixture: &str) -> Vec<String> {
    let v: Value = serde_json::from_str(fixture).unwrap();
    v["publicSignals"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap().to_string())
        .collect()
}

/// A deterministic dummy input (amount == 0) matching the generator's dummyInput().
fn dummy(sk: &str, blinding: &str) -> ValueInput {
    ValueInput::dummy_from(dec(sk), dec(blinding))
}

/// Assert a witness's public inputs equal a fixture's public signals, in order.
fn assert_public_inputs_match(case: &str, witness: &TransactWitness, ps: &[String]) {
    let pi = witness.public_inputs();
    let names = [
        "root",
        "publicAmount",
        "extDataHash",
        "inputNullifier[0]",
        "inputNullifier[1]",
        "outputCommitment[0]",
        "outputCommitment[1]",
    ];
    for (i, name) in names.iter().enumerate() {
        assert_eq!(
            crate::util::be32_to_decimal(&pi[i]),
            ps[i],
            "{case} public input {i} ({name}) must match the fixture"
        );
    }
}

#[test]
fn shield_witness_reproduces_fixture() {
    let alice = ValueKeypair::from_private_key(dec("100000000000000000000000000000000001"));
    let alice_pk = alice.public_key();
    let zeros = tree::zero_ladder(tree::DEPTH);

    let witness = TransactWitness {
        inputs: [
            dummy(
                "300000000000000000000000000000000004",
                "555000000000000000000000000000000001",
            ),
            dummy(
                "300000000000000000000000000000000005",
                "555000000000000000000000000000000002",
            ),
        ],
        outputs: [
            Note::new(10, alice_pk, fe(11)),
            Note::new(0, alice_pk, fe(12)),
        ],
        signed_amount: SignedAmount::Deposit(10),
        root: zeros[tree::DEPTH], // empty-tree root (dummy inputs are unchecked)
        ext: ExtData {
            recipient: recipient(),
            relayer: relayer(),
            fee: 0,
            enc0: payload(1),
            enc1: payload(2),
        },
    };
    witness.check_balanced().unwrap();
    assert_public_inputs_match("SHIELD", &witness, &public_signals(SHIELD));
}

#[test]
fn transfer_witness_reproduces_fixture() {
    let alice = ValueKeypair::from_private_key(dec("100000000000000000000000000000000001"));
    let bob = ValueKeypair::from_private_key(dec("200000000000000000000000000000000002"));
    let alice_pk = alice.public_key();
    let bob_pk = bob.public_key();

    // Two real inputs (30@0, 20@1): rebuild both paths from the two-leaf tree.
    let in0 = Note::new(30, alice_pk, fe(31));
    let in1 = Note::new(20, alice_pk, fe(32));
    let mtree = tree::SparseMerkle::from_leaves(tree::DEPTH, &[in0.commitment(), in1.commitment()]);
    let p0 = mtree.path(0);
    let p1 = mtree.path(1);

    let witness = TransactWitness {
        inputs: [
            ValueInput {
                note: in0,
                keypair: alice,
                leaf_index: 0,
                path_elements: p0.elements,
            },
            ValueInput {
                note: in1,
                keypair: alice,
                leaf_index: 1,
                path_elements: p1.elements,
            },
        ],
        outputs: [
            Note::new(35, bob_pk, fe(41)),
            Note::new(15, alice_pk, fe(42)),
        ],
        signed_amount: SignedAmount::Transfer,
        root: p0.root,
        ext: ExtData {
            recipient: recipient(),
            relayer: relayer(),
            fee: 0,
            enc0: payload(3),
            enc1: payload(4),
        },
    };
    assert_eq!(p0.root, p1.root, "both inputs prove against one root");
    witness.check_balanced().unwrap();
    assert_public_inputs_match("TRANSFER", &witness, &public_signals(TRANSFER));

    // The input.json must have exactly the shape gen_transaction_fixture produces.
    let input = witness.to_input_json();
    assert_eq!(
        input["inPathElements"][0].as_array().unwrap().len(),
        tree::DEPTH
    );
    assert_eq!(
        input["inPathElements"][1].as_array().unwrap().len(),
        tree::DEPTH
    );
    assert_eq!(input["publicAmount"], "0");
    assert_eq!(input["publicAmountMagnitude"], "0");
    assert_eq!(input["publicAmountSign"], "0");
    assert_eq!(input["inAmount"][0], "30");
    assert_eq!(input["outAmount"][0], "35");
}

#[test]
fn unshield_witness_reproduces_fixture() {
    let alice = ValueKeypair::from_private_key(dec("100000000000000000000000000000000001"));
    let alice_pk = alice.public_key();

    let real = Note::new(20, alice_pk, fe(51));
    let mtree = tree::SparseMerkle::from_leaves(tree::DEPTH, &[real.commitment()]);
    let p = mtree.path(0);

    let witness = TransactWitness {
        inputs: [
            ValueInput {
                note: real,
                keypair: alice,
                leaf_index: 0,
                path_elements: p.elements,
            },
            dummy(
                "300000000000000000000000000000000012",
                "555000000000000000000000000000000009",
            ),
        ],
        outputs: [
            Note::new(13, alice_pk, fe(61)),
            Note::new(0, alice_pk, fe(62)),
        ],
        signed_amount: SignedAmount::Withdraw(7),
        root: p.root,
        ext: ExtData {
            recipient: recipient(),
            relayer: relayer(),
            fee: 0,
            enc0: payload(5),
            enc1: payload(6),
        },
    };
    witness.check_balanced().unwrap();
    assert_public_inputs_match("UNSHIELD", &witness, &public_signals(UNSHIELD));

    // Withdraw magnitude/sign witness pair.
    let input = witness.to_input_json();
    assert_eq!(input["publicAmountMagnitude"], "7");
    assert_eq!(input["publicAmountSign"], "1");
}

#[test]
fn check_balanced_rejects_unbalanced_and_double_spend() {
    let alice = ValueKeypair::from_private_key(fe(12345));
    let alice_pk = alice.public_key();
    // Deposit 10 but only 5 flows out: unbalanced.
    let bad = TransactWitness {
        inputs: [
            ValueInput::dummy_from(fe(1), fe(2)),
            ValueInput::dummy_from(fe(3), fe(4)),
        ],
        outputs: [Note::new(5, alice_pk, fe(9)), Note::new(0, alice_pk, fe(8))],
        signed_amount: SignedAmount::Deposit(10),
        root: [0u8; 32],
        ext: ExtData {
            recipient: [0u8; 32],
            relayer: [0u8; 32],
            fee: 0,
            enc0: vec![],
            enc1: vec![],
        },
    };
    assert!(
        bad.check_balanced().is_err(),
        "10 in != 5 out must be rejected"
    );

    // Identical dummy inputs collide on their nullifiers (in-tx double spend).
    let d = ValueInput::dummy_from(fe(7), fe(8));
    let d2 = ValueInput::dummy_from(fe(7), fe(8));
    let dbl = TransactWitness {
        inputs: [d, d2],
        outputs: [Note::new(0, alice_pk, fe(1)), Note::new(0, alice_pk, fe(2))],
        signed_amount: SignedAmount::Deposit(0),
        root: [0u8; 32],
        ext: ExtData {
            recipient: [0u8; 32],
            relayer: [0u8; 32],
            fee: 0,
            enc0: vec![],
            enc1: vec![],
        },
    };
    assert!(
        dbl.check_balanced().is_err(),
        "two equal input nullifiers must be rejected"
    );
}

#[test]
fn random_dummy_has_nonzero_distinct_nullifier() {
    let a = ValueInput::random_dummy();
    let b = ValueInput::random_dummy();
    assert!(a.note.is_dummy() && b.note.is_dummy());
    assert_ne!(
        a.nullifier(),
        [0u8; 32],
        "a dummy nullifier must be non-zero"
    );
    assert_ne!(
        a.nullifier(),
        b.nullifier(),
        "two fresh dummies must carry distinct nullifiers"
    );
    // A fresh dummy's blinding + private key are canonical (< 2^248 < r).
    assert_eq!(a.note.blinding[0], 0);
}

/// The repo root: this crate lives at `crates/mirror-cli`.
fn repo_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

/// The committed TRANSFER witness the live provers reproduce: 2 real inputs
/// (30 @ leaf 0, 20 @ leaf 1) owned by Alice, 2 outputs (35 to Bob, 15 back to
/// Alice), `publicAmount == 0`, zero fee. Both live tests prove THIS witness, so
/// it has exactly one definition.
fn committed_transfer_witness() -> TransactWitness {
    let alice = ValueKeypair::from_private_key(dec("100000000000000000000000000000000001"));
    let bob = ValueKeypair::from_private_key(dec("200000000000000000000000000000000002"));
    let in0 = Note::new(30, alice.public_key(), fe(31));
    let in1 = Note::new(20, alice.public_key(), fe(32));
    let mtree = tree::SparseMerkle::from_leaves(tree::DEPTH, &[in0.commitment(), in1.commitment()]);
    let p0 = mtree.path(0);
    let p1 = mtree.path(1);
    TransactWitness {
        inputs: [
            ValueInput {
                note: in0,
                keypair: alice,
                leaf_index: 0,
                path_elements: p0.elements,
            },
            ValueInput {
                note: in1,
                keypair: alice,
                leaf_index: 1,
                path_elements: p1.elements,
            },
        ],
        outputs: [
            Note::new(35, bob.public_key(), fe(41)),
            Note::new(15, alice.public_key(), fe(42)),
        ],
        signed_amount: SignedAmount::Transfer,
        root: p0.root,
        ext: ExtData {
            recipient: recipient(),
            relayer: relayer(),
            fee: 0,
            enc0: payload(3),
            enc1: payload(4),
        },
    }
}

/// End-to-end Transact proof generation through snarkjs against the REAL
/// transaction zkey/wasm, for the TRANSFER witness. Gated behind
/// MIRROR_PROVE_LIVE=1 and #[ignore] so CI without node/snarkjs/zkey still passes.
///
/// Run with:
///   MIRROR_PROVE_LIVE=1 cargo test -p mirror-cli -- --ignored transact_pipeline
#[test]
#[ignore = "requires node + snarkjs + built transaction zkey/wasm; set MIRROR_PROVE_LIVE=1"]
fn transact_pipeline_generates_and_verifies_real_proof() {
    if std::env::var("MIRROR_PROVE_LIVE").ok().as_deref() != Some("1") {
        eprintln!("MIRROR_PROVE_LIVE != 1; skipping live transact pipeline test");
        return;
    }
    let root = repo_root();

    // The committed TRANSFER witness (2 real inputs, publicAmount 0).
    let witness = committed_transfer_witness();

    let opts = TransactProveOpts {
        snarkjs: "snarkjs".to_string(),
        use_snarkjs: true,
        wasm: root.join("circuits/transaction_js/transaction.wasm"),
        r1cs: root.join("circuits/transaction.r1cs"),
        zkey: root.join("circuits/transaction_final.zkey"),
        vk: root.join("circuits/artifacts/transaction_verification_key.json"),
        work_dir: Some(std::env::temp_dir().join("mirror-cli-transact-live-test")),
    };
    let proof = prove_transact(&witness, &opts).expect("snarkjs must prove + verify the transfer");

    // The proof serializes into a full Transact instruction (tag + body + blobs).
    let pi = witness.public_inputs();
    let data = groth16::transact_data(
        &pi[1],
        &pi[2],
        &pi[0],
        &pi[3],
        &pi[4],
        &pi[5],
        &pi[6],
        &proof,
        0,
        &witness.ext.enc0,
        &witness.ext.enc1,
    )
    .unwrap();
    assert_eq!(data[0], mirror_core::wire::tag::TRANSACT);
    // tag + header + two length-prefixed 48-byte payloads.
    assert_eq!(
        data.len(),
        1 + mirror_core::wire::TRANSACT_HEADER_LEN + 4 + 48 + 48
    );
}

/// The committed on-chain TRANSACTION verifying key (byte-for-byte the one
/// `programs/mirror-pool/src/transaction_vk.rs` embeds), so the test can run the
/// EXACT on-chain Groth16 verifier over a Rust-generated transaction proof.
mod committed_tx_vk {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../circuits/artifacts/transaction_vk.rs"
    ));
}

/// DECISIVE end-to-end check for the in-process (Node-free) transaction prover:
/// prove the committed TRANSFER witness entirely in Rust (`ark-circom` +
/// `ark-groth16`, no snarkjs), then confirm the emitted `groth16-solana` proof
/// bytes + 7 public inputs are accepted by the SAME on-chain `Groth16Verifier` +
/// committed transaction verifying key the program runs.
///
/// Gated behind MIRROR_PROVE_LIVE=1 + #[ignore] because it needs the gitignored
/// transaction r1cs/wasm/zkey (`bash circuits/build_transaction.sh`), NOT because it
/// needs Node - this path spawns none. Run with:
///   MIRROR_PROVE_LIVE=1 cargo test -p mirror-cli -- --ignored rust_transact
#[test]
#[ignore = "requires the built transaction r1cs/wasm/zkey; set MIRROR_PROVE_LIVE=1"]
fn rust_transact_pipeline_verifies_and_on_chain_verifier_accepts() {
    use groth16_solana::groth16::Groth16Verifier;

    if std::env::var("MIRROR_PROVE_LIVE").ok().as_deref() != Some("1") {
        eprintln!("MIRROR_PROVE_LIVE != 1; skipping live Rust transact test");
        return;
    }
    let root = repo_root();

    // The committed TRANSFER witness (2 real inputs, publicAmount 0).
    let witness = committed_transfer_witness();

    // Prove entirely in Rust (default path; use_snarkjs = false).
    let opts = TransactProveOpts {
        snarkjs: "snarkjs".to_string(),
        use_snarkjs: false,
        wasm: root.join("circuits/transaction_js/transaction.wasm"),
        r1cs: root.join("circuits/transaction.r1cs"),
        zkey: root.join("circuits/transaction_final.zkey"),
        vk: root.join("circuits/artifacts/transaction_verification_key.json"),
        work_dir: None,
    };
    let proof = prove_transact(&witness, &opts)
        .expect("in-process Rust proving must succeed and ark-verify the transfer");

    // DECISIVE: the EXACT on-chain verifier + committed transaction vk accepts it.
    // groth16-solana public inputs are in the circuit-declaration order the
    // witness's public_inputs() already produces.
    let public_inputs: [[u8; 32]; 7] = witness.public_inputs();
    let mut verifier = Groth16Verifier::new(
        &proof.proof_a,
        &proof.proof_b,
        &proof.proof_c,
        &public_inputs,
        &committed_tx_vk::VERIFYINGKEY,
    )
    .expect("verifier construction");
    verifier.verify().expect(
        "on-chain groth16-solana verifier must ACCEPT the Rust-generated transaction proof",
    );
}

#[test]
fn transact_data_from_witness_matches_public_inputs() {
    // The instruction data the emit builds must place the witness's public inputs
    // at the program's TRANSACT offsets (wire order != public-input order).
    let alice = ValueKeypair::from_private_key(fe(999));
    let witness = TransactWitness {
        inputs: [
            ValueInput::dummy_from(fe(1), fe(2)),
            ValueInput::dummy_from(fe(3), fe(4)),
        ],
        outputs: [
            Note::new(7, alice.public_key(), fe(5)),
            Note::new(0, alice.public_key(), fe(6)),
        ],
        signed_amount: SignedAmount::Deposit(7),
        root: [0x22u8; 32],
        ext: ExtData {
            recipient: [0x33u8; 32],
            relayer: [0x44u8; 32],
            fee: 3,
            enc0: vec![1, 2, 3],
            enc1: vec![4, 5],
        },
    };
    let pi = witness.public_inputs();
    let proof = groth16::ProofBytes {
        proof_a: [1u8; 64],
        proof_b: [2u8; 128],
        proof_c: [3u8; 64],
    };
    let data = groth16::transact_data(
        &pi[1],
        &pi[2],
        &pi[0],
        &pi[3],
        &pi[4],
        &pi[5],
        &pi[6],
        &proof,
        3,
        &witness.ext.enc0,
        &witness.ext.enc1,
    )
    .unwrap();
    // Body offsets (relative to the byte after the tag): publicAmount, extDataHash,
    // root, nf0, nf1, out0, out1.
    let b = 1;
    assert_eq!(data[0], mirror_core::wire::tag::TRANSACT);
    assert_eq!(data[b..b + 32], pi[1]); // publicAmount
    assert_eq!(data[b + 32..b + 64], pi[2]); // extDataHash
    assert_eq!(data[b + 64..b + 96], pi[0]); // root
    assert_eq!(data[b + 96..b + 128], pi[3]); // inNf0
    assert_eq!(data[b + 128..b + 160], pi[4]); // inNf1
    assert_eq!(data[b + 160..b + 192], pi[5]); // outC0
    assert_eq!(data[b + 192..b + 224], pi[6]); // outC1
}
