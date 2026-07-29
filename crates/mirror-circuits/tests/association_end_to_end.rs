//! The association half of the arkworks path: the constraint shape, the
//! equivalence check against the COMMITTED circom fixture, and a fresh proof
//! verified with the SAME `groth16-solana` verifier the on-chain program links -
//! with no circom artifact, no snarkjs, and no Node anywhere in the run.
//!
//! The equivalence check is the load-bearing one. `circuits/artifacts/` ships one
//! snarkjs proof produced by `association.circom`, and
//! `gen_association_fixture.js` built it from constants that are all published in
//! `association_fixture_meta.json`: the secret, the epoch, the recipient, the
//! amount, both leaf lists and both leaf indices. So the private witness behind
//! the committed proof is fully reconstructible. This file rebuilds it, runs it
//! through the ARKWORKS constraint system, and requires two things:
//!
//! 1. the arkworks system is SATISFIED by the witness circom accepted, and
//! 2. the five public inputs arkworks derives equal the five `publicSignals`
//!    snarkjs emitted, element by element, in order.
//!
//! Nothing is copied from the fixture into the witness: the commitment is
//! recomputed from the secret and the action, and both roots are recomputed by
//! rebuilding both trees. The committed leaf lists are used only to place that
//! recomputed commitment, and the test asserts it lands where the meta says.
//!
//! Together those say the two circuits accept the same witness and expose the
//! same public-input map. They do NOT say the two R1CS matrices are the same;
//! see `docs/ARKWORKS.md` for what is and is not claimed.

use std::str::FromStr;
use std::sync::OnceLock;

use ark_bn254::Fr;
use groth16_solana::groth16::{Groth16Verifier, Groth16Verifyingkey};
use mirror_circuits::association::{AssociationWitness, N_PUBLIC_INPUTS};
use mirror_circuits::membership::{fr_from_be, fr_to_be, DEPTH};
use mirror_circuits::onchain;
use mirror_circuits::setup;
use rand::SeedableRng;
use serde_json::Value;

// The committed circom artifacts, embedded so the cross-check is hermetic: it
// runs in a clean checkout, with no gitignored build output on disk.
const META: &str = include_str!("../../../circuits/artifacts/association_fixture_meta.json");
const FIXTURE: &str = include_str!("../../../circuits/artifacts/association_proof_fixture.json");

/// A deterministic RNG so a failing run is reproducible. Setup randomness is the
/// Groth16 toxic waste; a fixed seed is correct for a test and catastrophic for
/// a deployment, which is exactly why this path is not a ceremony.
fn rng() -> rand::rngs::StdRng {
    rand::rngs::StdRng::seed_from_u64(20260728)
}

/// A field element from the decimal strings the fixture and the generator use.
fn dec(s: &str) -> Fr {
    Fr::from_str(s).expect("valid decimal field element")
}

fn meta() -> Value {
    serde_json::from_str(META).expect("meta json")
}

/// The `publicSignals` array of the committed fixture, as field elements.
fn public_signals() -> Vec<Fr> {
    let v: Value = serde_json::from_str(FIXTURE).expect("fixture json");
    v["publicSignals"]
        .as_array()
        .expect("publicSignals array")
        .iter()
        .map(|s| dec(s.as_str().expect("decimal string")))
        .collect()
}

/// The zero ladder as field elements. `zeros[i]` is the root of an empty subtree
/// of height `i`, which is exactly the `zeros` array `gen_association_fixture.js`
/// builds inside `buildTree`.
fn zeros() -> Vec<Fr> {
    mirror_core::merkle_zeros(DEPTH)
        .iter()
        .map(fr_from_be)
        .collect()
}

/// A depth-`DEPTH` sparse Merkle tree over a DENSE PREFIX of leaves, built the
/// way `gen_association_fixture.js::buildTree` builds it and the way the
/// on-chain frontier accumulator produces roots for the same leaf list: a
/// missing right sibling at level `i` is `zeros[i]`.
struct Tree {
    levels: Vec<Vec<Fr>>,
    zeros: Vec<Fr>,
}

impl Tree {
    fn new(leaves: &[Fr]) -> Self {
        let zeros = zeros();
        let mut levels = vec![leaves.to_vec()];
        for level in 0..DEPTH {
            let cur = &levels[level];
            let mut next = Vec::with_capacity(cur.len().div_ceil(2));
            let mut i = 0;
            while i < cur.len() {
                let left = cur[i];
                let right = if i + 1 < cur.len() {
                    cur[i + 1]
                } else {
                    zeros[level]
                };
                next.push(mirror_circuits::hash_native(&[left, right]).expect("node"));
                i += 2;
            }
            levels.push(next);
        }
        Self { levels, zeros }
    }

    fn root(&self) -> Fr {
        self.levels[DEPTH]
            .first()
            .copied()
            .unwrap_or(self.zeros[DEPTH])
    }

    /// The sibling at each level for `index`, bottom-up.
    fn path(&self, index: u64) -> Vec<Fr> {
        let mut out = Vec::with_capacity(DEPTH);
        let mut idx = index as usize;
        for level in 0..DEPTH {
            let sibling_idx = if idx & 1 == 0 { idx + 1 } else { idx - 1 };
            let row = &self.levels[level];
            out.push(row.get(sibling_idx).copied().unwrap_or(self.zeros[level]));
            idx >>= 1;
        }
        out
    }
}

/// The committed circom fixture, rebuilt as an arkworks witness from the
/// scenario constants the meta publishes.
///
/// Everything is DERIVED. The commitment comes out of the secret, the recipient
/// and the amount; both roots come out of rebuilding both trees. The committed
/// leaf lists only say where other participants' commitments sit, and the
/// returned assertions check that our derived commitment really is at the leaf
/// indices the meta claims - so a fixture whose leaf lists were edited without
/// regenerating the proof fails here.
fn fixture_witness() -> AssociationWitness {
    let m = meta();
    let s = &m["scenario"];

    let secret = dec(s["secret"].as_str().expect("secret"));
    let epoch = s["epoch"].as_u64().expect("epoch");
    let amount = s["amountLamports"].as_u64().expect("amount");
    let recipient: [u8; 32] = {
        let hex = s["recipientHex"].as_str().expect("recipientHex");
        let mut out = [0u8; 32];
        for (i, slot) in out.iter_mut().enumerate() {
            *slot = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).expect("hex byte");
        }
        out
    };
    // actionHash = Poseidon(recipientHi128, recipientLo128, amount), the repo's
    // canonical form, so this is a real settlement statement.
    let action_hash = fr_from_be(&mirror_core::transfer_action_hash(&recipient, amount));
    let commitment =
        mirror_circuits::hash_native(&[secret, action_hash, Fr::from(epoch)]).expect("commitment");

    let leaves = |key: &str| -> Vec<Fr> {
        s[key]
            .as_array()
            .expect("leaf array")
            .iter()
            .map(|x| dec(x.as_str().expect("decimal leaf")))
            .collect()
    };
    let pool_leaves = leaves("poolLeaves");
    let assoc_leaves = leaves("assocLeaves");
    let pool_index = s["poolLeafIndex"].as_u64().expect("poolLeafIndex");
    let assoc_index = s["assocLeafIndex"].as_u64().expect("assocLeafIndex");

    // The derived commitment must be exactly the leaf the meta places in each
    // tree. If it is not, the fixture and the scenario have drifted apart.
    assert_eq!(
        pool_leaves[pool_index as usize], commitment,
        "the recomputed commitment must be the committed pool leaf"
    );
    assert_eq!(
        assoc_leaves[assoc_index as usize], commitment,
        "the recomputed commitment must be the committed association leaf"
    );
    // The curator vouches for a strict SUBSET: some pool deposits are excluded.
    assert!(
        assoc_leaves.len() < pool_leaves.len(),
        "the fixture must exercise a curator that excludes something"
    );

    let pool = Tree::new(&pool_leaves);
    let assoc = Tree::new(&assoc_leaves);

    let witness = AssociationWitness::new(
        secret,
        action_hash,
        epoch,
        pool_index,
        &pool.path(pool_index),
        assoc_index,
        &assoc.path(assoc_index),
    )
    .expect("fixture witness");

    // The generator self-checks its paths by walking them and comparing to the
    // tree root before it costs a proof; do the same here, because the witness
    // builder climbs the path while `Tree` hashes level by level, and a
    // disagreement would mean one of the two is wrong.
    assert_eq!(
        witness.public_inputs[0],
        pool.root(),
        "the climbed pool root must equal the built pool root"
    );
    assert_eq!(
        witness.public_inputs[4],
        assoc.root(),
        "the climbed association root must equal the built association root"
    );
    witness
}

/// A FRESH witness over inputs that appear in no fixture: a different secret,
/// epoch, recipient and amount, in a 7-deposit pool of which a curator vouches
/// for 4. Ours sits at pool leaf 6 and association leaf 2, so the two index bit
/// patterns differ from each other and from the fixture's.
fn fresh_witness() -> AssociationWitness {
    let secret = dec("31337000000000000000000000000000004242");
    let epoch = 23u64;
    let mut recipient = [0u8; 32];
    for (i, b) in recipient.iter_mut().enumerate() {
        *b = (0xa0 + i) as u8;
    }
    let action_hash = fr_from_be(&mirror_core::transfer_action_hash(
        &recipient,
        1_250_000_000,
    ));
    let commitment =
        mirror_circuits::hash_native(&[secret, action_hash, Fr::from(epoch)]).expect("commitment");

    // Six other participants' commitments, stood in for by distinct field
    // elements (their preimages are irrelevant to this proof), plus ours at 6.
    let mut pool: Vec<Fr> = (0..7u64).map(|i| Fr::from(0xdead_0000 + i)).collect();
    pool[6] = commitment;
    // The curator vouches for pool leaves 0, 3, 6 (ours) and 5, in its own
    // order, and excludes the rest.
    let assoc = vec![pool[0], pool[3], commitment, pool[5]];

    let pool_tree = Tree::new(&pool);
    let assoc_tree = Tree::new(&assoc);

    AssociationWitness::new(
        secret,
        action_hash,
        epoch,
        6,
        &pool_tree.path(6),
        2,
        &assoc_tree.path(2),
    )
    .expect("fresh witness")
}

/// One setup and one proof, shared by every test that needs them.
///
/// A Groth16 setup over ~10k constraints is the expensive part of this file, and
/// three tests want the same key over the same witness. Doing it once is not a
/// shortcut: each test still checks a different property of the SAME proof,
/// which is closer to what a verifier actually faces than three unrelated proofs
/// would be.
fn shared() -> &'static (
    ark_groth16::ProvingKey<ark_bn254::Bn254>,
    ark_groth16::Proof<ark_bn254::Bn254>,
    AssociationWitness,
) {
    static SHARED: OnceLock<(
        ark_groth16::ProvingKey<ark_bn254::Bn254>,
        ark_groth16::Proof<ark_bn254::Bn254>,
        AssociationWitness,
    )> = OnceLock::new();
    SHARED.get_or_init(|| {
        let mut rng = rng();
        let witness = fresh_witness();
        let pk = setup::association_setup(&mut rng).expect("groth16 setup");
        // `association_prove` verifies in-process against `pk.vk` before
        // returning, so a proof that reaches here already satisfies arkworks'
        // own verifier.
        let proof = setup::association_prove(&pk, &witness, &mut rng).expect("groth16 prove");
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
///
/// It also pins the STRICT-EXTENSION property the wire format depends on: the
/// first four names are the membership circuit's four, in the same order, and
/// `associationRoot` is appended.
#[test]
fn public_input_layout_matches_the_committed_circom_metadata() {
    let m = meta();
    assert_eq!(
        m["publicInputOrder"],
        serde_json::json!([
            "root",
            "nullifierHash",
            "actionHash",
            "epoch",
            "associationRoot"
        ])
    );
    assert_eq!(m["nPublic"].as_u64().expect("nPublic"), 5);
    assert_eq!(
        m["nPublic"].as_u64().expect("nPublic") as usize,
        N_PUBLIC_INPUTS,
        "the arkworks circuit must allocate exactly the circom public inputs"
    );

    // The membership layout, read from ITS committed metadata, must be a prefix
    // of this one.
    let membership: Value = serde_json::from_str(include_str!(
        "../../../circuits/artifacts/fixture_meta.json"
    ))
    .expect("membership meta json");
    let membership_order = membership["publicInputOrder"]
        .as_array()
        .expect("membership order");
    let association_order = m["publicInputOrder"].as_array().expect("order");
    assert_eq!(
        &association_order[..membership_order.len()],
        &membership_order[..],
        "the association layout must EXTEND the membership layout, not reorder it"
    );
    assert_eq!(
        association_order.len(),
        membership_order.len() + 1,
        "exactly one public input is appended"
    );
}

/// THE equivalence check. The arkworks circuit must be satisfied by the same
/// private witness circom accepted AND derive the same five public signals
/// snarkjs emitted.
#[test]
fn arkworks_agrees_with_the_committed_circom_fixture() {
    let witness = fixture_witness();
    let expected = public_signals();

    let (shape, satisfied) = setup::association_shape(&witness).expect("synthesis");
    assert!(
        satisfied,
        "the arkworks system must accept the witness circom accepted"
    );
    assert_eq!(shape.instance_variables, N_PUBLIC_INPUTS);
    assert_eq!(expected.len(), N_PUBLIC_INPUTS, "fixture shape");
    for (i, want) in expected.iter().enumerate() {
        assert_eq!(
            &witness.public_inputs[i], want,
            "public signal {i} disagrees with the committed circom fixture"
        );
    }
}

/// The association statement is a strict EXTENSION of the membership one, and
/// this is where that is checked on real committed data rather than on a
/// hand-made witness: the membership witness hiding inside the committed
/// association fixture satisfies the MEMBERSHIP circuit, and its four public
/// inputs are the fixture's first four.
#[test]
fn the_committed_fixtures_membership_half_satisfies_the_membership_circuit() {
    let witness = fixture_witness();
    let membership = witness.membership();
    let (shape, satisfied) = setup::shape(&membership).expect("synthesis");
    assert!(
        satisfied,
        "the pool half of a valid association witness must be a valid membership witness"
    );
    assert_eq!(shape.instance_variables, 4);

    let expected = public_signals();
    for (i, (got, want)) in membership
        .public_inputs
        .iter()
        .zip(expected.iter())
        .enumerate()
    {
        assert_eq!(got, want, "shared public signal {i}");
    }
}

/// The measured shape of the arkworks association circuit, pinned so a change in
/// the gadgets or the statement cannot silently move the number
/// `docs/ARKWORKS.md` reports.
///
/// Every row is accounted for. The committed circom circuit has 10,347
/// multiplication rows; this system has 10,224, and the 123-row difference is
/// exactly:
///
/// ```text
/// -126  42 hashes x 3, the round-0 S-box on the constant zero domain tag,
///       which ark-r1cs-std folds at synthesis time and circom pays for
/// +  3  rows arkworks spends on the three `===` assertions (nullifierHash,
///       root, associationRoot) that circom emits as affine rows
/// ```
#[test]
fn association_constraint_shape_is_pinned() {
    let w = fresh_witness();
    let (shape, satisfied) = setup::association_shape(&w).expect("synthesis");
    println!("arkworks association shape: {shape:?}");
    assert!(satisfied);

    // 42 Poseidon calls: 1 commitment (t=4), 1 nullifier (t=3), and 40 Merkle
    // nodes (t=3) - 20 per tree. The `- 1` is the folded domain-tag S-box.
    let poseidon_t3 = 3 * (8 * 3 + 57 - 1);
    let poseidon_t4 = 3 * (8 * 4 + 56 - 1);
    // One booleanity plus two `conditionally_select` rows per level, per tree.
    let selectors = 2 * 20 * 3;
    // nullifierHash, root, associationRoot.
    let equalities = 3;
    assert_eq!(
        41 * poseidon_t3 + poseidon_t4 + selectors + equalities,
        10_224,
        "the S-box accounting must explain every constraint"
    );
    assert_eq!(
        shape,
        setup::Shape {
            constraints: 10_224,
            witness_variables: 10_262,
            instance_variables: 5,
        }
    );
}

/// The whole point: a proof produced entirely in Rust from an arkworks-native
/// association constraint system, over inputs that appear in no fixture, is
/// accepted by the same `groth16-solana` verifier the on-chain program links.
#[test]
fn arkworks_association_proof_is_accepted_by_the_on_chain_verifier() {
    let (pk, proof, witness) = shared();

    let (shape, satisfied) = setup::association_shape(witness).expect("synthesis");
    assert!(satisfied, "the fresh witness must satisfy the circuit");
    assert_eq!(shape.instance_variables, N_PUBLIC_INPUTS);

    let bytes = onchain::proof_bytes(proof);
    let public = witness.public_inputs_be();
    let vk = onchain_vk(&pk.vk);
    assert_eq!(vk.nr_pubinputs, 5);
    assert_eq!(vk.vk_ic.len(), 6, "IC has nPublic + 1 entries");

    let mut verifier =
        Groth16Verifier::new(&bytes.proof_a, &bytes.proof_b, &bytes.proof_c, &public, &vk)
            .expect("constructing the on-chain verifier");
    verifier
        .verify()
        .expect("the on-chain groth16-solana verifier must accept the arkworks association proof");
}

/// Soundness sanity for the appended public input, which is the one the whole
/// compliance story rests on: a proof made against one curator's root must not
/// verify against another's. `SETTLE_ZK_ASSOCIATED` reads `associationRoot` off
/// the curator's account and feeds it to the verifier, so this is exactly the
/// substitution the on-chain check has to defeat.
///
/// The pool root and the epoch-scoped nullifier are moved too, so the shared
/// membership inputs are shown to be verifier-bound in the 5-input layout as
/// well as the 4-input one.
#[test]
fn the_on_chain_verifier_rejects_a_moved_public_input() {
    let (pk, proof, witness) = shared();
    let bytes = onchain::proof_bytes(proof);
    let vk = onchain_vk(&pk.vk);

    // 0 = pool root, 1 = nullifierHash, 4 = associationRoot.
    for index in [0usize, 1, 4] {
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

/// The arkworks association key is a DIFFERENT key for the same statement. It
/// encodes to the same canonical registry shape the program's `INIT_VK` expects
/// (833 bytes for 5 public inputs), and it does NOT hash to the digest the
/// program pins for the deployed circom association key - so nothing here could
/// be mistaken for, or installed as, the deployed key.
#[test]
fn arkworks_association_key_encodes_to_the_registry_shape_but_is_not_the_pinned_key() {
    use sha2::{Digest, Sha256};

    let (pk, _, _) = shared();
    let canonical = onchain::canonical_registry_encoding(&pk.vk).expect("canonical encoding");
    assert_eq!(
        canonical.len(),
        833,
        "5 public inputs encode to the same 833-byte registry record as the circom key"
    );

    // The digest `programs/mirror-pool/src/vk_digest.rs` pins for ASSOCIATION.
    const PINNED_ASSOCIATION_DIGEST: &str =
        "77031fc732e4be82fbd2c77cb2076bf92b4fdb1ce9a74bf8cfa085464e3d23bd";
    let got: [u8; 32] = Sha256::digest(&canonical).into();
    let got_hex: String = got.iter().map(|b| format!("{b:02x}")).collect();
    assert_ne!(
        got_hex, PINNED_ASSOCIATION_DIGEST,
        "the arkworks key must not collide with the pinned deployed key"
    );
}
