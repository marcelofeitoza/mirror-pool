//! Tests for the opt-in association-set layer.
//!
//! The offline tests here run in plain CI: they reproduce the committed circuit
//! fixture's public signals from the host-side building blocks, and they pin the
//! curator-side root builder's refusals. The live tests (behind
//! `MIRROR_PROVE_LIVE=1` + `#[ignore]`, because they need the gitignored
//! r1cs/wasm/zkey) are the ones that prove the artifacts are CONSISTENT: a FRESH
//! proof over NEW inputs, verified by the EXACT on-chain verifier against the
//! COMMITTED verifying key.

use std::path::Path;

use super::*;
use crate::groth16;
use crate::util::from_hex32;
use mirror_core::{commit_with_action_hash, nullifier, transfer_action_hash, Epoch};

/// The committed on-chain ASSOCIATION verifying key (byte-for-byte the one the
/// program embeds in `programs/mirror-pool/src/association_vk.rs`), included so
/// the tests can run the EXACT on-chain Groth16 verifier.
mod committed_assoc_vk {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../circuits/artifacts/association_vk.rs"
    ));
}

/// The committed membership verifying key, used only to prove the two keys are
/// genuinely DIFFERENT (so the association path cannot be satisfied by a
/// membership proof and vice versa).
mod committed_membership_vk {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../circuits/artifacts/vk.rs"
    ));
}

/// The committed association fixture's raw JSON (proof + public signals).
fn fixture() -> serde_json::Value {
    serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../circuits/artifacts/association_proof_fixture.json"
    )))
    .expect("committed association fixture must parse")
}

/// The committed association fixture's metadata (public-input order + the exact
/// scenario `gen_association_fixture.js` built).
fn fixture_meta() -> serde_json::Value {
    serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../circuits/artifacts/association_fixture_meta.json"
    )))
    .expect("committed association fixture meta must parse")
}

/// The repo root (this crate lives at crates/mirror-cli).
fn repo_root() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

/// The public-input ORDER is a load-bearing constant: the on-chain handler feeds
/// the verifier `[root, nullifierHash, actionHash, epoch, associationRoot]` in
/// that exact sequence, and a silent reordering in the circuit would make every
/// proof fail (or, worse, make a wrong statement verify). Pin it against the
/// committed fixture metadata.
#[test]
fn association_public_input_order_is_pinned() {
    let meta = fixture_meta();
    let order: Vec<&str> = meta["publicInputOrder"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(
        order,
        vec![
            "root",
            "nullifierHash",
            "actionHash",
            "epoch",
            "associationRoot"
        ],
        "association public-input order must match the on-chain handler's array"
    );
    assert_eq!(
        meta["nPublic"].as_u64().unwrap() as usize,
        mirror_core::wire::ASSOCIATION_N_PUBLIC_INPUTS
    );
    // The first four are byte-for-byte the membership circuit's, in the same
    // order, which is what makes the wire layout a strict extension.
    let membership_meta: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../circuits/artifacts/fixture_meta.json"
    )))
    .unwrap();
    let membership_order: Vec<&str> = membership_meta["publicInputOrder"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(&order[..4], &membership_order[..]);
}

/// The association verifying key is a DIFFERENT key from the membership one, and
/// declares 5 public inputs. If these ever collided, "association proof required"
/// would be satisfiable by a plain membership proof.
#[test]
fn association_vk_is_distinct_from_membership_vk() {
    assert_eq!(committed_assoc_vk::VERIFYINGKEY.nr_pubinputs, 5);
    assert_eq!(committed_membership_vk::VERIFYINGKEY.nr_pubinputs, 4);
    assert_eq!(
        committed_assoc_vk::VERIFYINGKEY.vk_ic.len(),
        6,
        "vk_ic must have nPublic + 1 entries"
    );
    assert_ne!(
        committed_assoc_vk::VERIFYINGKEY.vk_delta_g2,
        committed_membership_vk::VERIFYINGKEY.vk_delta_g2,
        "the two circuits must not share a verifying key"
    );
}

/// DECISIVE offline check: the HOST building blocks reproduce the committed
/// association fixture's public signals exactly - pool root, association root,
/// nullifierHash and actionHash.
///
/// `gen_association_fixture.js` builds a 5-leaf pool tree (ours at index 3) and a
/// 3-leaf curated tree (ours at index 1). Rebuilding both here with
/// `mirror_core` + `tree::SparseMerkle` and landing on the same roots proves our
/// Poseidon, our leaf ordering and our tree math match the circuit's - i.e. a
/// proof generated for the circuit verifies against roots this CLI (and the
/// on-chain accumulator) produce.
#[test]
fn host_rebuild_reproduces_association_fixture_public_signals() {
    let fx = fixture();
    let ps = fx["publicSignals"].as_array().unwrap();
    let want_root = ps[0].as_str().unwrap();
    let want_nullifier = ps[1].as_str().unwrap();
    let want_action = ps[2].as_str().unwrap();
    let epoch: u64 = ps[3].as_str().unwrap().parse().unwrap();
    let want_assoc_root = ps[4].as_str().unwrap();

    let meta = fixture_meta();
    let scenario = &meta["scenario"];
    let secret = mirror_core::Secret::from_bytes(
        groth16::to_be32(scenario["secret"].as_str().unwrap()).unwrap(),
    );
    let amount = scenario["amountLamports"].as_u64().unwrap();
    let recipient = from_hex32(scenario["recipientHex"].as_str().unwrap()).unwrap();

    let action_hash = transfer_action_hash(&recipient, amount);
    let nullifier_hash = nullifier(&secret, Epoch(epoch)).0;
    let leaf = commit_with_action_hash(&secret, &action_hash, Epoch(epoch)).0;

    // Rebuild both trees from the leaf lists the fixture recorded.
    let to_leaves = |key: &str| -> Vec<Hash32> {
        scenario[key]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| groth16::to_be32(v.as_str().unwrap()).unwrap())
            .collect()
    };
    let pool_leaves = to_leaves("poolLeaves");
    let assoc_leaves = to_leaves("assocLeaves");
    let pool_leaf_index = scenario["poolLeafIndex"].as_u64().unwrap() as usize;
    let assoc_leaf_index = scenario["assocLeafIndex"].as_u64().unwrap() as usize;
    assert_eq!(pool_leaves[pool_leaf_index], leaf);
    assert_eq!(assoc_leaves[assoc_leaf_index], leaf);
    // The curator really did exclude someone: the curated set is smaller.
    assert!(
        assoc_leaves.len() < pool_leaves.len(),
        "the fixture must model an actual exclusion, not a pass-through set"
    );

    let pool_tree = tree::SparseMerkle::from_leaves(tree::DEPTH, &pool_leaves);
    let assoc_tree = tree::SparseMerkle::from_leaves(tree::DEPTH, &assoc_leaves);
    let pool_path = pool_tree.path(pool_leaf_index);
    let assoc_path = assoc_tree.path(assoc_leaf_index);

    assert_eq!(
        be32_to_decimal(&pool_path.root),
        want_root,
        "pool root must match fixture"
    );
    assert_eq!(
        be32_to_decimal(&assoc_path.root),
        want_assoc_root,
        "association root must match fixture"
    );
    assert_eq!(be32_to_decimal(&nullifier_hash), want_nullifier);
    assert_eq!(be32_to_decimal(&action_hash), want_action);
}

/// The committed fixture proof is accepted by the EXACT on-chain verifier and
/// the COMMITTED association verifying key. This is the same check the mollusk
/// integration test performs in-program, run here without a compiled `.so` so a
/// key/fixture mismatch is caught in plain `cargo test`.
#[test]
fn committed_association_fixture_verifies_under_the_on_chain_verifier() {
    use groth16_solana::groth16::Groth16Verifier;

    let fx = fixture();
    let ps: Vec<Hash32> = fx["publicSignals"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| groth16::to_be32(v.as_str().unwrap()).unwrap())
        .collect();
    let public: [Hash32; 5] = ps.try_into().expect("5 public signals");

    let proof = groth16::SnarkjsProof::parse(&serde_json::to_string(&fx["proof"]).unwrap())
        .expect("fixture proof must parse")
        .to_bytes()
        .expect("fixture proof must serialize");

    let mut verifier = Groth16Verifier::new(
        &proof.proof_a,
        &proof.proof_b,
        &proof.proof_c,
        &public,
        &committed_assoc_vk::VERIFYINGKEY,
    )
    .expect("verifier construction");
    verifier
        .verify()
        .expect("the committed association fixture must verify under the committed vk");
}

/// Flipping any single public input must break verification. Catches an accident
/// where the verifier ignores an input (the classic "the 5th input is not
/// actually constrained" bug), which would make the association root decorative.
#[test]
fn mutating_any_association_public_input_breaks_verification() {
    use groth16_solana::groth16::Groth16Verifier;

    let fx = fixture();
    let base: Vec<Hash32> = fx["publicSignals"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| groth16::to_be32(v.as_str().unwrap()).unwrap())
        .collect();
    let proof = groth16::SnarkjsProof::parse(&serde_json::to_string(&fx["proof"]).unwrap())
        .unwrap()
        .to_bytes()
        .unwrap();

    for i in 0..5 {
        let mut public: [Hash32; 5] = base.clone().try_into().unwrap();
        public[i][31] ^= 0x01;
        let rejected = match Groth16Verifier::new(
            &proof.proof_a,
            &proof.proof_b,
            &proof.proof_c,
            &public,
            &committed_assoc_vk::VERIFYINGKEY,
        ) {
            // A non-canonical scalar is rejected at construction; anything else
            // must fail the pairing check.
            Err(_) => true,
            Ok(mut v) => v.verify().is_err(),
        };
        assert!(
            rejected,
            "mutating public input {i} must break verification (input {i} is unconstrained?)"
        );
    }
}

/// The curator-side root builder refuses the inputs that would publish a
/// misleading set: an empty list, and a list with duplicates (which would report
/// a set size larger than the real anonymity set).
#[test]
fn build_root_refuses_empty_and_duplicate_leaf_lists() {
    let dir = std::env::temp_dir().join(format!(
        "mirror-assoc-build-root-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).unwrap();

    let empty = dir.join("empty.txt");
    std::fs::write(&empty, "# only a comment\n\n").unwrap();
    assert!(
        build_root(&empty, None).is_err(),
        "an empty curated list must be refused"
    );

    let dup = dir.join("dup.txt");
    let a = to_hex(&[1u8; 32]);
    let b = to_hex(&[2u8; 32]);
    std::fs::write(&dup, format!("{a}\n{b}\n{a}\n")).unwrap();
    assert!(
        build_root(&dup, None).is_err(),
        "a curated list with duplicates must be refused"
    );

    let good = dir.join("good.txt");
    std::fs::write(&good, format!("{a}\n{b}\n")).unwrap();
    let emit = build_root(&good, None).expect("a clean list must build");
    assert_eq!(emit.set_size, 2);
    assert_eq!(
        emit.update_root_data_hex.len(),
        2 * mirror_core::wire::UPDATE_ASSOCIATION_ROOT_LEN
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A leaf that is not in the curated list yields the specific "this curator does
/// not vouch for this deposit" error, not a generic failure. That message is the
/// whole user-facing meaning of exclusion, so it is worth pinning.
#[test]
fn association_path_absent_leaf_reports_exclusion() {
    let dir = std::env::temp_dir().join(format!(
        "mirror-assoc-absent-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let list = dir.join("curated.txt");
    std::fs::write(
        &list,
        format!("{}\n{}\n", to_hex(&[1u8; 32]), to_hex(&[2u8; 32])),
    )
    .unwrap();

    let err = build_association_path(&list, &[9u8; 32]).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("NOT in the curated list"),
        "exclusion must be reported explicitly, got: {msg}"
    );
    assert!(
        msg.contains("SettleZk"),
        "the exclusion message must tell the user the plain path still works, got: {msg}"
    );

    // A leaf that IS in the list builds a path that walks to the list's root.
    let path = build_association_path(&list, &[2u8; 32]).expect("present leaf must build");
    assert_eq!(path.set_size, 2);
    assert_eq!(
        tree::verify_path(&[2u8; 32], &path.path.elements, &path.path.indices),
        path.path.root
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// THE decisive artifact-consistency check for this layer: generate a FRESH
/// association proof over NEW inputs (a witness that is NOT the committed
/// fixture's - different secret, epoch, recipient, amount and BOTH trees) fully
/// in Rust, then confirm the EXACT on-chain `groth16-solana` verifier accepts it
/// against the COMMITTED verifying key.
///
/// This is what catches proving-key / verifying-key drift. A stale committed vk
/// can still pass a committed fixture (they were generated together) while every
/// freshly generated proof fails on-chain; only proving a NEW statement against
/// the COMMITTED key rules that out.
///
/// Gated behind MIRROR_PROVE_LIVE=1 + `#[ignore]` because it needs the gitignored
/// association r1cs/wasm/zkey (`bash circuits/build_association.sh`), NOT because
/// it needs Node - this path spawns no Node process. Run with:
///   MIRROR_PROVE_LIVE=1 cargo test -p mirror-cli -- --ignored association_fresh
#[test]
#[ignore = "requires the built association r1cs/wasm/zkey (bash circuits/build_association.sh); set MIRROR_PROVE_LIVE=1"]
fn association_fresh_proof_over_new_inputs_verifies_under_committed_vk() {
    use groth16_solana::groth16::Groth16Verifier;

    if std::env::var("MIRROR_PROVE_LIVE").ok().as_deref() != Some("1") {
        eprintln!("MIRROR_PROVE_LIVE != 1; skipping live association prove test");
        return;
    }
    let repo = repo_root();
    let wasm = repo.join("circuits/association_js/association.wasm");
    let r1cs = repo.join("circuits/association.r1cs");
    let zkey = repo.join("circuits/association_final.zkey");
    for p in [&wasm, &r1cs, &zkey] {
        if !p.exists() {
            eprintln!("missing {}; skipping", p.display());
            return;
        }
    }

    // A witness that shares NOTHING with the committed fixture.
    let secret = mirror_core::Secret::from_bytes(
        groth16::to_be32("987654321098765432109876543210987654321").unwrap(),
    );
    let epoch: u64 = 29;
    let mut recipient = [0u8; 32];
    for (i, b) in recipient.iter_mut().enumerate() {
        *b = (200 - i) as u8;
    }
    let amount: u64 = 1_337_000_000;

    let action_hash = transfer_action_hash(&recipient, amount);
    let nullifier_hash = nullifier(&secret, Epoch(epoch)).0;
    let leaf = commit_with_action_hash(&secret, &action_hash, Epoch(epoch)).0;

    // A different pool shape (7 leaves, ours at index 5) and a different curated
    // shape (4 leaves, ours at index 2) from the fixture's 5/3 and 3/1.
    let filler = |n: u8| -> Hash32 {
        let mut h = [0u8; 32];
        h[31] = n;
        h[30] = 0xAB;
        h
    };
    let pool_leaves: Vec<Hash32> = (0..7u8)
        .map(|i| if i == 5 { leaf } else { filler(i) })
        .collect();
    let assoc_leaves: Vec<Hash32> = vec![filler(0), filler(3), leaf, filler(6)];
    assert_eq!(assoc_leaves[2], leaf);

    let pool_tree = tree::SparseMerkle::from_leaves(tree::DEPTH, &pool_leaves);
    let assoc_tree = tree::SparseMerkle::from_leaves(tree::DEPTH, &assoc_leaves);
    let pool_path = pool_tree.path(5);
    let assoc_path = assoc_tree.path(2);

    // These roots must be new: if they matched the fixture's, the test would be
    // re-proving the committed statement and would prove nothing about drift.
    let fx = fixture();
    let fx_ps = fx["publicSignals"].as_array().unwrap();
    assert_ne!(be32_to_decimal(&pool_path.root), fx_ps[0].as_str().unwrap());
    assert_ne!(
        be32_to_decimal(&assoc_path.root),
        fx_ps[4].as_str().unwrap()
    );

    let input = association_input_json(
        &pool_path.root,
        &nullifier_hash,
        &action_hash,
        epoch,
        &assoc_path.root,
        &secret.0,
        &pool_path,
        &assoc_path,
    );
    let expected = association_public_inputs(
        &pool_path.root,
        &nullifier_hash,
        &action_hash,
        epoch,
        &assoc_path.root,
    );

    // `prove` verifies with ark-groth16 against the zkey's own vk and bails on
    // failure, so reaching the on-chain check means BOTH verifiers accepted.
    let proof_bytes = crate::prove_rust::prove(
        &crate::prove_rust::Artifacts {
            wasm: &wasm,
            r1cs: &r1cs,
            zkey: &zkey,
        },
        &input,
        &expected,
    )
    .expect("in-process Rust proving of the association circuit must succeed and ark-verify");

    // The emitted SettleZkAssociated data is well-formed.
    let data = groth16::settle_zk_associated_data(
        epoch,
        amount,
        &proof_bytes,
        &pool_path.root,
        &nullifier_hash,
        &action_hash,
        &assoc_path.root,
    );
    assert_eq!(data.len(), mirror_core::wire::SETTLE_ZK_ASSOCIATED_LEN);
    assert_eq!(data[0], mirror_core::wire::tag::SETTLE_ZK_ASSOCIATED);

    // DECISIVE: the EXACT on-chain verifier + COMMITTED vk accepts a FRESH proof.
    let mut verifier = Groth16Verifier::new(
        &proof_bytes.proof_a,
        &proof_bytes.proof_b,
        &proof_bytes.proof_c,
        &expected,
        &committed_assoc_vk::VERIFYINGKEY,
    )
    .expect("verifier construction");
    verifier.verify().expect(
        "on-chain groth16-solana verifier must ACCEPT a FRESH association proof over NEW inputs \
         against the COMMITTED verifying key",
    );
}

/// Exclusion is enforced by the CIRCUIT, not just by tooling: a witness whose
/// commitment is in the pool but NOT in the curated set cannot produce a proof at
/// all, because the association Merkle constraint is unsatisfiable. Witness
/// generation must FAIL rather than emit a proof of a false statement.
///
/// Same gating as above (needs the gitignored build artifacts).
#[test]
#[ignore = "requires the built association r1cs/wasm/zkey (bash circuits/build_association.sh); set MIRROR_PROVE_LIVE=1"]
fn association_excluded_commitment_cannot_produce_a_proof() {
    if std::env::var("MIRROR_PROVE_LIVE").ok().as_deref() != Some("1") {
        eprintln!("MIRROR_PROVE_LIVE != 1; skipping live association exclusion test");
        return;
    }
    let repo = repo_root();
    let wasm = repo.join("circuits/association_js/association.wasm");
    let r1cs = repo.join("circuits/association.r1cs");
    let zkey = repo.join("circuits/association_final.zkey");
    for p in [&wasm, &r1cs, &zkey] {
        if !p.exists() {
            eprintln!("missing {}; skipping", p.display());
            return;
        }
    }

    let secret = mirror_core::Secret::from_bytes(
        groth16::to_be32("55555555555555555555555555555555555").unwrap(),
    );
    let epoch: u64 = 4;
    let recipient = [0x5Au8; 32];
    let amount: u64 = 100_000_000;
    let action_hash = transfer_action_hash(&recipient, amount);
    let nullifier_hash = nullifier(&secret, Epoch(epoch)).0;
    let leaf = commit_with_action_hash(&secret, &action_hash, Epoch(epoch)).0;

    let filler = |n: u8| -> Hash32 {
        let mut h = [0u8; 32];
        h[31] = n;
        h[30] = 0xCD;
        h
    };
    // Ours IS in the pool ...
    let pool_leaves: Vec<Hash32> = vec![filler(1), leaf, filler(2)];
    // ... and is NOT in the curated set. The curator excluded us.
    let assoc_leaves: Vec<Hash32> = vec![filler(1), filler(2)];

    let pool_tree = tree::SparseMerkle::from_leaves(tree::DEPTH, &pool_leaves);
    let assoc_tree = tree::SparseMerkle::from_leaves(tree::DEPTH, &assoc_leaves);
    let pool_path = pool_tree.path(1);
    // Best try available to an excluded prover: claim someone else's slot in the
    // curated tree. The leaf hashed there is OUR commitment, so the recomputed
    // association root will not equal the real one and the constraint fails.
    let stolen_path = assoc_tree.path(0);

    let input = association_input_json(
        &pool_path.root,
        &nullifier_hash,
        &action_hash,
        epoch,
        &assoc_tree.root(),
        &secret.0,
        &pool_path,
        &stolen_path,
    );
    let expected = association_public_inputs(
        &pool_path.root,
        &nullifier_hash,
        &action_hash,
        epoch,
        &assoc_tree.root(),
    );

    // `ark-circom`'s debug build asserts R1CS satisfiability inside `build()`, so
    // an unsatisfiable witness surfaces as a PANIC rather than an `Err`. Either
    // outcome is a refusal to prove; what must never happen is a returned proof.
    // Catch the panic (silencing its default report, which would otherwise look
    // like a test failure) and assert on the outcome.
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        crate::prove_rust::prove(
            &crate::prove_rust::Artifacts {
                wasm: &wasm,
                r1cs: &r1cs,
                zkey: &zkey,
            },
            &input,
            &expected,
        )
    }));
    std::panic::set_hook(prev_hook);

    match outcome {
        Err(_) => { /* witness generation refused the unsatisfiable statement */ }
        Ok(Err(_)) => { /* proving returned an error, equally a refusal */ }
        Ok(Ok(_)) => panic!(
            "a commitment excluded from the curated set must NOT be provable against that set, \
             but proving SUCCEEDED"
        ),
    }
}
