//! The JoinSplit half of the arkworks path: the constraint shape, the
//! equivalence check against the COMMITTED circom fixtures, and a fresh proof
//! verified with the SAME `groth16-solana` verifier the on-chain program links -
//! with no circom artifact, no snarkjs, and no Node anywhere in the run.
//!
//! The equivalence check is the load-bearing one. `circuits/artifacts/` ships
//! three snarkjs proofs (SHIELD, TRANSFER, UNSHIELD) produced by
//! `transaction.circom`, and `gen_transaction_fixture.js` built them from fixed,
//! published constants. This file rebuilds those exact private witnesses, runs
//! them through the ARKWORKS constraint system, and requires two things:
//!
//! 1. the arkworks system is SATISFIED by the witness circom accepted, and
//! 2. the seven public inputs arkworks derives equal the seven `publicSignals`
//!    snarkjs emitted, element by element, in order.
//!
//! Together those say the two circuits accept the same witnesses and expose the
//! same public-input map. They do NOT say the two R1CS matrices are the same;
//! see `docs/ARKWORKS.md` for what is and is not claimed.

use std::str::FromStr;
use std::sync::OnceLock;

use ark_bn254::Fr;
use groth16_solana::groth16::{Groth16Verifier, Groth16Verifyingkey};
use mirror_circuits::membership::{fr_from_be, fr_to_be};
use mirror_circuits::onchain;
use mirror_circuits::setup;
use mirror_circuits::transaction::{
    InputNote, OutputNote, TransactionWitness, DEPTH, MAX_AMOUNT_BITS, N_INS, N_OUTS,
    N_PUBLIC_INPUTS,
};
use mirror_core::note::{ext_data_hash, SignedAmount, ValueKeypair};
use rand::SeedableRng;
use serde_json::Value;

// The committed circom artifacts, embedded so the cross-check is hermetic: it
// runs in a clean checkout, with no gitignored build output on disk.
const META: &str = include_str!("../../../circuits/artifacts/transaction_fixture_meta.json");
const SHIELD: &str = include_str!("../../../circuits/artifacts/transaction_shield_fixture.json");
const TRANSFER: &str = include_str!("../../../circuits/artifacts/transaction_proof_fixture.json");
const UNSHIELD: &str =
    include_str!("../../../circuits/artifacts/transaction_unshield_fixture.json");

/// A deterministic RNG so a failing run is reproducible. Setup randomness is the
/// Groth16 toxic waste; a fixed seed is correct for a test and catastrophic for
/// a deployment, which is exactly why this path is not a ceremony.
fn rng() -> rand::rngs::StdRng {
    rand::rngs::StdRng::seed_from_u64(20260728)
}

/// A field element from the decimal strings the fixtures and the generator use.
fn dec(s: &str) -> Fr {
    Fr::from_str(s).expect("valid decimal field element")
}

/// The `publicSignals` array of a fixture, as field elements, in the fixed order
/// `[root, publicAmount, extDataHash, inNf0, inNf1, outC0, outC1]`.
fn public_signals(fixture: &str) -> Vec<Fr> {
    let v: Value = serde_json::from_str(fixture).expect("fixture json");
    v["publicSignals"]
        .as_array()
        .expect("publicSignals array")
        .iter()
        .map(|s| dec(s.as_str().expect("decimal string")))
        .collect()
}

/// The zero ladder as field elements. `zeros[i]` is the root of an empty subtree
/// of height `i`, so `zeros[DEPTH]` is the empty-tree root.
fn zeros() -> Vec<Fr> {
    mirror_core::merkle_zeros(DEPTH)
        .iter()
        .map(fr_from_be)
        .collect()
}

/// The fixed recipient / relayer / payloads `gen_transaction_fixture.js` uses.
fn recipient() -> [u8; 32] {
    let mut r = [0u8; 32];
    for (i, b) in r.iter_mut().enumerate() {
        *b = (i + 1) as u8;
    }
    r
}

fn relayer() -> [u8; 32] {
    let mut r = [0u8; 32];
    for (i, b) in r.iter_mut().enumerate() {
        *b = (0x20 - i) as u8;
    }
    r
}

fn payload(seed: u64) -> Vec<u8> {
    (0..48u64)
        .map(|i| ((seed * 131 + i * 17) & 0xff) as u8)
        .collect()
}

fn fixture_ext_data_hash(a: u64, b: u64) -> Fr {
    fr_from_be(&ext_data_hash(
        &recipient(),
        &relayer(),
        0,
        &payload(a),
        &payload(b),
    ))
}

/// `Poseidon(private_key)`, through mirror-core so the keys are the ones the
/// generator derived.
fn public_key(private_key: Fr) -> Fr {
    fr_from_be(&ValueKeypair::from_private_key(fr_to_be(&private_key)).public_key())
}

/// A dummy input built exactly as the generator's `dummyInput()`.
fn dummy(sk: &str, blinding: &str) -> InputNote {
    InputNote {
        amount: 0,
        private_key: dec(sk),
        blinding: dec(blinding),
        leaf_index: 0,
        path_elements: zeros()[..DEPTH].to_vec(),
    }
}

const ALICE_SK: &str = "100000000000000000000000000000000001";
const BOB_SK: &str = "200000000000000000000000000000000002";

/// The three committed circom fixtures, rebuilt as arkworks witnesses from the
/// same published constants.
fn fixture_witnesses() -> Vec<(&'static str, TransactionWitness, Vec<Fr>)> {
    let alice_sk = dec(ALICE_SK);
    let alice_pk = public_key(alice_sk);
    let bob_pk = public_key(dec(BOB_SK));
    let z = zeros();

    // ---- SHIELD: 2 dummy inputs, +10, outputs [10, 0] on an empty tree ----
    let shield = TransactionWitness::new(
        z[DEPTH],
        [
            dummy(
                "300000000000000000000000000000000004",
                "555000000000000000000000000000000001",
            ),
            dummy(
                "300000000000000000000000000000000005",
                "555000000000000000000000000000000002",
            ),
        ],
        [
            OutputNote {
                amount: 10,
                public_key: alice_pk,
                blinding: Fr::from(11u64),
            },
            OutputNote {
                amount: 0,
                public_key: alice_pk,
                blinding: Fr::from(12u64),
            },
        ],
        SignedAmount::Deposit(10),
        fixture_ext_data_hash(1, 2),
    )
    .expect("shield witness");

    // ---- TRANSFER: 2 real inputs (30, 20) at leaves 0 and 1, outputs (35, 15) ----
    // Leaf 0's sibling at level 0 is leaf 1 and vice versa; above that both climb
    // the zero ladder.
    let in0_commitment =
        mirror_circuits::hash_native(&[Fr::from(30u64), alice_pk, Fr::from(31u64)])
            .expect("commitment");
    let in1_commitment =
        mirror_circuits::hash_native(&[Fr::from(20u64), alice_pk, Fr::from(32u64)])
            .expect("commitment");
    let mut path0 = vec![in1_commitment];
    path0.extend_from_slice(&z[1..DEPTH]);
    let mut path1 = vec![in0_commitment];
    path1.extend_from_slice(&z[1..DEPTH]);
    let transfer_root = {
        let mut cur = in0_commitment;
        for (level, sibling) in path0.iter().enumerate() {
            cur = if (0u64 >> level) & 1 == 1 {
                mirror_circuits::hash_native(&[*sibling, cur]).expect("node")
            } else {
                mirror_circuits::hash_native(&[cur, *sibling]).expect("node")
            };
        }
        cur
    };
    let transfer = TransactionWitness::new(
        transfer_root,
        [
            InputNote {
                amount: 30,
                private_key: alice_sk,
                blinding: Fr::from(31u64),
                leaf_index: 0,
                path_elements: path0,
            },
            InputNote {
                amount: 20,
                private_key: alice_sk,
                blinding: Fr::from(32u64),
                leaf_index: 1,
                path_elements: path1,
            },
        ],
        [
            OutputNote {
                amount: 35,
                public_key: bob_pk,
                blinding: Fr::from(41u64),
            },
            OutputNote {
                amount: 15,
                public_key: alice_pk,
                blinding: Fr::from(42u64),
            },
        ],
        SignedAmount::Transfer,
        fixture_ext_data_hash(3, 4),
    )
    .expect("transfer witness");

    // ---- UNSHIELD: 1 real input (20) + a dummy, -7, outputs [13, 0] ----
    let real_commitment =
        mirror_circuits::hash_native(&[Fr::from(20u64), alice_pk, Fr::from(51u64)])
            .expect("commitment");
    let unshield_root = {
        let mut cur = real_commitment;
        for sibling in z[..DEPTH].iter() {
            cur = mirror_circuits::hash_native(&[cur, *sibling]).expect("node");
        }
        cur
    };
    let unshield = TransactionWitness::new(
        unshield_root,
        [
            InputNote {
                amount: 20,
                private_key: alice_sk,
                blinding: Fr::from(51u64),
                leaf_index: 0,
                path_elements: z[..DEPTH].to_vec(),
            },
            dummy(
                "300000000000000000000000000000000012",
                "555000000000000000000000000000000009",
            ),
        ],
        [
            OutputNote {
                amount: 13,
                public_key: alice_pk,
                blinding: Fr::from(61u64),
            },
            OutputNote {
                amount: 0,
                public_key: alice_pk,
                blinding: Fr::from(62u64),
            },
        ],
        SignedAmount::Withdraw(7),
        fixture_ext_data_hash(5, 6),
    )
    .expect("unshield witness");

    vec![
        ("SHIELD", shield, public_signals(SHIELD)),
        ("TRANSFER", transfer, public_signals(TRANSFER)),
        ("UNSHIELD", unshield, public_signals(UNSHIELD)),
    ]
}

/// A FRESH witness over inputs that appear in no fixture: two real notes at
/// leaves 2 and 3 of a four-leaf tree, partly withdrawn. Used for the
/// setup/prove/verify run so "a fresh proof over new inputs" means what it says.
fn fresh_witness() -> TransactionWitness {
    let z = zeros();
    let alice_sk = dec("777000000000000000000000000000000123");
    let carol_sk = dec("888000000000000000000000000000000456");
    let alice_pk = public_key(alice_sk);
    let carol_pk = public_key(carol_sk);

    let amounts = [4_100_000_000u64, 900_000_000u64];
    let blindings = [Fr::from(0x5eed_u64), Fr::from(0x5eee_u64)];
    let leaves: Vec<Fr> = (0..2)
        .map(|i| {
            mirror_circuits::hash_native(&[Fr::from(amounts[i]), alice_pk, blindings[i]])
                .expect("commitment")
        })
        .collect();

    // A four-leaf tree whose first two leaves are unrelated fillers, so the two
    // spent notes sit at indices 2 and 3 and their path bits are not all zero.
    let filler0 = Fr::from(0xaaaa_u64);
    let filler1 = Fr::from(0xbbbb_u64);
    let left_pair = mirror_circuits::hash_native(&[filler0, filler1]).expect("node");
    let right_pair = mirror_circuits::hash_native(&[leaves[0], leaves[1]]).expect("node");
    let level1 = mirror_circuits::hash_native(&[left_pair, right_pair]).expect("node");
    let mut root = level1;
    for sibling in z[2..DEPTH].iter() {
        root = mirror_circuits::hash_native(&[root, *sibling]).expect("node");
    }

    let mut path2 = vec![leaves[1], left_pair];
    path2.extend_from_slice(&z[2..DEPTH]);
    let mut path3 = vec![leaves[0], left_pair];
    path3.extend_from_slice(&z[2..DEPTH]);

    TransactionWitness::new(
        root,
        [
            InputNote {
                amount: amounts[0],
                private_key: alice_sk,
                blinding: blindings[0],
                leaf_index: 2,
                path_elements: path2,
            },
            InputNote {
                amount: amounts[1],
                private_key: alice_sk,
                blinding: blindings[1],
                leaf_index: 3,
                path_elements: path3,
            },
        ],
        [
            OutputNote {
                amount: 3_000_000_000,
                public_key: carol_pk,
                blinding: Fr::from(0xc0c0_u64),
            },
            OutputNote {
                amount: 1_000_000_000,
                public_key: alice_pk,
                blinding: Fr::from(0xc0c1_u64),
            },
        ],
        // 5,000,000,000 in, 4,000,000,000 out, so 1,000,000,000 leaves the pool.
        SignedAmount::Withdraw(1_000_000_000),
        fr_from_be(&ext_data_hash(
            &recipient(),
            &relayer(),
            25_000,
            &payload(19),
            &payload(23),
        )),
    )
    .expect("fresh witness")
}

/// One setup and one proof, shared by every test that needs them.
///
/// A Groth16 setup over ~13k constraints is the expensive part of this file, and
/// four tests want the same key over the same witness. Doing it once is not a
/// shortcut: each test still checks a different property of the SAME proof,
/// which is closer to what a verifier actually faces than four unrelated proofs
/// would be.
fn shared() -> &'static (
    ark_groth16::ProvingKey<ark_bn254::Bn254>,
    ark_groth16::Proof<ark_bn254::Bn254>,
    TransactionWitness,
) {
    static SHARED: OnceLock<(
        ark_groth16::ProvingKey<ark_bn254::Bn254>,
        ark_groth16::Proof<ark_bn254::Bn254>,
        TransactionWitness,
    )> = OnceLock::new();
    SHARED.get_or_init(|| {
        let mut rng = rng();
        let witness = fresh_witness();
        let pk = setup::transaction_setup(&mut rng).expect("groth16 setup");
        // `transaction_prove` verifies in-process against `pk.vk` before
        // returning, so a proof that reaches here already satisfies arkworks'
        // own verifier.
        let proof = setup::transaction_prove(&pk, &witness, &mut rng).expect("groth16 prove");
        (pk, proof, witness)
    })
}

/// Build the `groth16-solana` verifying key from an arkworks key.
fn onchain_vk(vk: &ark_groth16::VerifyingKey<ark_bn254::Bn254>) -> Groth16Verifyingkey<'static> {
    let b = onchain::verifying_key_bytes(vk);
    let ic: &'static [[u8; 64]] = Box::leak(b.ic.clone().into_boxed_slice());
    Groth16Verifyingkey {
        nr_pubinputs: b.nr_pubinputs,
        vk_alpha_g1: b.alpha_g1,
        vk_beta_g2: b.beta_g2,
        vk_gamme_g2: b.gamma_g2,
        vk_delta_g2: b.delta_g2,
        vk_ic: ic,
    }
}

/// The public-input LAYOUT, taken from the committed circom metadata rather than
/// from this crate's own opinion of it. If the circom side ever reorders a
/// signal, this fails.
#[test]
fn public_input_layout_matches_the_committed_circom_metadata() {
    let meta: Value = serde_json::from_str(META).expect("meta json");
    assert_eq!(
        meta["publicInputOrder"],
        serde_json::json!([
            "root",
            "publicAmount",
            "extDataHash",
            "inputNullifier[0]",
            "inputNullifier[1]",
            "outputCommitment[0]",
            "outputCommitment[1]"
        ])
    );
    assert_eq!(meta["nPublic"].as_u64().expect("nPublic"), 7);
    assert_eq!(
        meta["nPublic"].as_u64().expect("nPublic") as usize,
        N_PUBLIC_INPUTS,
        "the arkworks circuit must allocate exactly the circom public inputs"
    );
    assert_eq!(meta["merkleDepth"].as_u64().expect("depth") as usize, DEPTH);
    assert_eq!(
        meta["maxAmountBits"].as_u64().expect("bits") as usize,
        MAX_AMOUNT_BITS
    );
    assert_eq!((N_INS, N_OUTS), (2, 2), "the scheme is 2-in / 2-out");
}

/// THE equivalence check. For each committed circom fixture, the arkworks
/// circuit must be satisfied by the same private witness AND derive the same
/// seven public signals snarkjs emitted.
#[test]
fn arkworks_agrees_with_every_committed_circom_fixture() {
    for (case, witness, expected) in fixture_witnesses() {
        let (shape, satisfied) = setup::transaction_shape(&witness).expect("synthesis");
        assert!(
            satisfied,
            "{case}: the arkworks system must accept the witness circom accepted"
        );
        assert_eq!(
            shape.instance_variables, N_PUBLIC_INPUTS,
            "{case}: public-input count"
        );
        assert_eq!(expected.len(), N_PUBLIC_INPUTS, "{case}: fixture shape");
        for (i, want) in expected.iter().enumerate() {
            assert_eq!(
                &witness.public_inputs[i], want,
                "{case}: public signal {i} disagrees with the committed circom fixture"
            );
        }
    }
}

/// The measured shape of the arkworks JoinSplit, pinned so a change in the
/// gadgets or the statement cannot silently move the number `docs/ARKWORKS.md`
/// reports.
///
/// Every row is accounted for. The committed circom circuit has 13,098
/// multiplication rows; this system has 12,958, and the 140-row difference is
/// exactly:
///
/// ```text
/// -150  50 hashes x 3, the round-0 S-box on the constant zero domain tag,
///       which ark-r1cs-std folds at synthesis time and circom pays for
/// + 10  rows arkworks spends on equalities that circom emits as affine rows
///       (5 Num2Bits bindings, 2 nullifier ===, 2 output-commitment ===,
///        1 value conservation)
/// ```
#[test]
fn transaction_constraint_shape_is_pinned() {
    let w = fresh_witness();
    let (shape, satisfied) = setup::transaction_shape(&w).expect("synthesis");
    println!("arkworks joinsplit shape: {shape:?}");
    assert!(satisfied);

    // 50 Poseidon calls: 2 keypairs (t=2), 8 three-input hashes (t=4: two input
    // commitments, two signatures, two nullifiers, two output commitments), and
    // 40 Merkle nodes (t=3). The `- 1` is the folded domain-tag S-box.
    let poseidon_t2 = 3 * (8 * 2 + 56 - 1);
    let poseidon_t3 = 3 * (8 * 3 + 57 - 1);
    let poseidon_t4 = 3 * (8 * 4 + 56 - 1);
    let hashes = 2 * poseidon_t2 + 8 * poseidon_t4 + 40 * poseidon_t3;

    // Per input: Num2Bits(20) = 21, 20 switchers, 1 nullifier ===, 3 for
    // ForceEqualIfEnabled.
    let per_input = 21 + 20 + 1 + 3;
    // Per output: 1 commitment ===, Num2Bits(248) = 249.
    let per_output = 1 + 249;
    // Sign booleanity, the magnitude range check, the signed decoding, value
    // conservation, nullifier distinctness, and the extDataHash square.
    let global = 1 + 249 + 1 + 1 + 1 + 1;

    assert_eq!(
        hashes + N_INS * per_input + N_OUTS * per_output + global,
        12_958,
        "the gadget accounting must explain every constraint"
    );
    assert_eq!(
        shape,
        setup::Shape {
            constraints: 12_958,
            witness_variables: 13_000,
            instance_variables: 7,
        }
    );
}

/// The whole point: a proof produced entirely in Rust from an arkworks-native
/// JoinSplit constraint system, over inputs that appear in no fixture, is
/// accepted by the same `groth16-solana` verifier the on-chain program links.
#[test]
fn arkworks_joinsplit_proof_is_accepted_by_the_on_chain_verifier() {
    let (pk, proof, witness) = shared();

    let (shape, satisfied) = setup::transaction_shape(witness).expect("synthesis");
    assert!(satisfied, "the fresh witness must satisfy the circuit");
    assert_eq!(shape.instance_variables, N_PUBLIC_INPUTS);

    let bytes = onchain::proof_bytes(proof);
    let public = witness.public_inputs_be();
    let vk = onchain_vk(&pk.vk);
    assert_eq!(vk.nr_pubinputs, 7);
    assert_eq!(vk.vk_ic.len(), 8, "IC has nPublic + 1 entries");

    let mut verifier =
        Groth16Verifier::new(&bytes.proof_a, &bytes.proof_b, &bytes.proof_c, &public, &vk)
            .expect("constructing the on-chain verifier");
    verifier
        .verify()
        .expect("the on-chain groth16-solana verifier must accept the arkworks JoinSplit proof");
}

/// `extDataHash` is not pinned by any constraint - the square row is satisfiable
/// for any value - so THIS is where its tamper-evidence is proven: it is a
/// public input, and moving it makes the on-chain verifier reject.
///
/// That matters because `extDataHash` is the only thing binding the recipient,
/// the relayer and the fee to the proof.
#[test]
fn the_on_chain_verifier_rejects_a_moved_ext_data_hash() {
    let (pk, proof, witness) = shared();
    let bytes = onchain::proof_bytes(proof);
    let vk = onchain_vk(&pk.vk);

    // Index 2 is extDataHash: a relayer rewriting the payout recipient.
    let mut public = witness.public_inputs_be();
    public[2] = fr_to_be(&(witness.public_inputs[2] + Fr::from(1u64)));

    let rejected =
        match Groth16Verifier::new(&bytes.proof_a, &bytes.proof_b, &bytes.proof_c, &public, &vk) {
            Err(_) => true,
            Ok(mut v) => v.verify().is_err(),
        };
    assert!(
        rejected,
        "a proof must not verify against ext data it does not commit to"
    );
}

/// Soundness sanity for the value-carrying public inputs: moving the amount or a
/// nullifier must be rejected by the on-chain verifier, not merely by arkworks.
#[test]
fn the_on_chain_verifier_rejects_a_moved_amount_or_nullifier() {
    let (pk, proof, witness) = shared();
    let bytes = onchain::proof_bytes(proof);
    let vk = onchain_vk(&pk.vk);

    // 1 = publicAmount (how much leaves the pool), 3 = inputNullifier[0] (which
    // note is being spent).
    for index in [1usize, 3] {
        let mut public = witness.public_inputs_be();
        public[index] = fr_to_be(&(witness.public_inputs[index] + Fr::from(1u64)));
        let rejected = match Groth16Verifier::new(
            &bytes.proof_a,
            &bytes.proof_b,
            &bytes.proof_c,
            &public,
            &vk,
        ) {
            Err(_) => true,
            Ok(mut v) => v.verify().is_err(),
        };
        assert!(rejected, "public input {index} must be verifier-bound");
    }
}

/// The arkworks JoinSplit key is a DIFFERENT key for the same statement. It
/// encodes to the same canonical registry shape the program's `INIT_VK` expects
/// (961 bytes for 7 public inputs), and it does NOT hash to the digest the
/// program pins for the deployed circom JoinSplit key - so nothing here could be
/// mistaken for, or installed as, the deployed key.
#[test]
fn arkworks_joinsplit_key_encodes_to_the_registry_shape_but_is_not_the_pinned_key() {
    use sha2::{Digest, Sha256};

    let (pk, _, _) = shared();
    let canonical = onchain::canonical_registry_encoding(&pk.vk).expect("canonical encoding");
    assert_eq!(
        canonical.len(),
        961,
        "7 public inputs encode to the same 961-byte registry record as the circom key"
    );

    // The digest `programs/mirror-pool/src/vk_digest.rs` pins for TRANSACTION.
    const PINNED_TRANSACTION_DIGEST: &str =
        "9c310a0068a7036b1bbfbaed59d58c65740154d6aff4529b738ecff8c7601212";
    let got: [u8; 32] = Sha256::digest(&canonical).into();
    let got_hex: String = got.iter().map(|b| format!("{b:02x}")).collect();
    assert_ne!(
        got_hex, PINNED_TRANSACTION_DIGEST,
        "the arkworks key must not collide with the pinned deployed key"
    );
}
