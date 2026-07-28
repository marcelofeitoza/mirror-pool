//! The end-to-end check for the arkworks path: setup, prove, and verify with the
//! SAME `groth16-solana` verifier the on-chain program links - with no circom
//! artifact, no snarkjs, and no Node anywhere in the run.
//!
//! Also pins the shape of the constraint system and the cross-check vector the
//! on-chain accumulator test reproduces with the `sol_poseidon` syscall.

use ark_bn254::{Bn254, Fr};
use ark_groth16::VerifyingKey;
use groth16_solana::groth16::{Groth16Verifier, Groth16Verifyingkey};
use mirror_circuits::membership::{fr_from_be, fr_to_be, MembershipWitness, DEPTH};
use mirror_circuits::onchain;
use mirror_circuits::poseidon::hash_native;
use mirror_circuits::setup;
use rand::SeedableRng;

/// A deterministic RNG so a failing run is reproducible. Setup randomness is the
/// Groth16 toxic waste; a fixed seed is correct for a test and catastrophic for
/// a deployment, which is exactly why this path is not a ceremony.
fn rng() -> rand::rngs::StdRng {
    rand::rngs::StdRng::seed_from_u64(20260728)
}

/// The fixed witness every test in this file proves: a member whose commitment
/// is the FIRST leaf of an empty depth-20 tree.
fn fixture_witness() -> MembershipWitness {
    let secret = fr_from_be(&[
        0x0a, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
        0xee, 0xff,
    ]);
    // A recipient/amount action hash in the repo's canonical form, so the
    // witness is a real settlement statement rather than arbitrary numbers.
    let mut recipient = [0u8; 32];
    for (i, b) in recipient.iter_mut().enumerate() {
        *b = (i + 1) as u8;
    }
    let action_hash = fr_from_be(&mirror_core::transfer_action_hash(&recipient, 250_000_000));
    let zeros = zero_ladder();
    MembershipWitness::new(secret, action_hash, 7, 0, &zeros).expect("witness")
}

/// `zeros[i]` for i in 0..DEPTH: the sibling at every level for the first leaf of
/// an empty tree.
fn zero_ladder() -> Vec<Fr> {
    let mut out = Vec::with_capacity(DEPTH);
    let mut z = Fr::from(0u64);
    for _ in 0..DEPTH {
        out.push(z);
        z = hash_native(&[z, z]).expect("width 3");
    }
    out
}

fn hex(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The cross-check vector shared with the on-chain accumulator test. Both sides
/// recompute it independently and compare to these constants:
///
/// - here, `MembershipCircuit` recomputes the leaf and climbs the depth-20 path
///   IN CIRCUIT, and the constraint system is satisfied only if both equal these
///   values;
/// - in `programs/mirror-pool/tests/integration.rs`, the same leaf goes through
///   the real `COMMIT` instruction and the root is produced by twenty nested
///   `sol_poseidon` syscall calls inside the SBF VM.
///
/// See `docs/ARKWORKS.md` section 3 for what that agreement does and does not
/// prove (the syscall is built on `light-poseidon`, whose parameter table this
/// gadget also uses).
pub const CROSS_CHECK_LEAF_HEX: &str =
    "17f05ec0329a0f4379a258bdb21ea7bcf77d18f8b29e938de4107000cbe29e47";
pub const CROSS_CHECK_ROOT_HEX: &str =
    "17eb8b099a02413857616f6707ae037e92f08aa788d501f49da9a78a67b6a7c2";

/// The measured shape of the arkworks constraint system, pinned so a change in
/// the gadget or the statement cannot silently move the number
/// `docs/ARKWORKS.md` reports.
///
/// Every one of the 5,363 rows is accounted for:
///
/// ```text
/// 21 x Poseidon(2)  21 * 3 * (8*3 + 57 - 1) = 5,040   nullifier + 20 Merkle levels
///  1 x Poseidon(3)   1 * 3 * (8*4 + 56 - 1) =   261   the commitment
/// 20 x path selector 20 * (1 booleanity + 2 mux) =  60
///  2 x `===`                                    =   2   nullifierHash, root
///                                                 -----
///                                                 5,363
/// ```
///
/// The `- 1` in each hash is the round-0 S-box on the constant zero domain tag,
/// which folds at synthesis time.
#[test]
fn membership_constraint_shape_is_pinned() {
    let w = fixture_witness();
    let (shape, satisfied) = setup::shape(&w).expect("synthesis");
    println!("arkworks membership shape: {shape:?}");
    assert!(satisfied);

    let poseidon_t3 = 3 * (8 * 3 + 57 - 1);
    let poseidon_t4 = 3 * (8 * 4 + 56 - 1);
    let selectors = 20 * 3;
    let equalities = 2;
    assert_eq!(
        21 * poseidon_t3 + poseidon_t4 + selectors + equalities,
        5_363,
        "the S-box accounting must explain every constraint"
    );
    assert_eq!(
        shape,
        setup::Shape {
            constraints: 5_363,
            witness_variables: 5_382,
            instance_variables: 4,
        }
    );
}

/// The in-circuit half of the gadget/syscall cross-check: satisfying this
/// constraint system means the leaf and the depth-20 root were computed by the
/// Poseidon GADGET and equal the shared vector.
#[test]
fn gadget_produces_the_syscall_cross_check_vector() {
    let w = fixture_witness();
    let (_, satisfied) = setup::shape(&w).expect("synthesis");
    assert!(
        satisfied,
        "the circuit must recompute this leaf and root in circuit"
    );
    assert_eq!(hex(&fr_to_be(&w.commitment)), CROSS_CHECK_LEAF_HEX);
    assert_eq!(hex(&fr_to_be(&w.public_inputs[0])), CROSS_CHECK_ROOT_HEX);
}

/// The whole point: a proof produced entirely in Rust from an arkworks-native
/// constraint system is accepted by the on-chain verifier.
#[test]
fn arkworks_proof_is_accepted_by_the_on_chain_verifier() {
    let mut rng = rng();
    let witness = fixture_witness();

    let (shape, satisfied) = setup::shape(&witness).expect("synthesis");
    assert!(satisfied, "the fixture witness must satisfy the circuit");
    assert_eq!(
        shape.instance_variables, 4,
        "root, nullifier, action, epoch"
    );

    let pk = setup::setup(&mut rng).expect("groth16 setup");
    let proof = setup::prove(&pk, &witness, &mut rng).expect("groth16 prove");

    let bytes = onchain::proof_bytes(&proof);
    let public = witness.public_inputs_be();

    let vk_bytes = onchain::verifying_key_bytes(&pk.vk);
    assert_eq!(vk_bytes.nr_pubinputs, 4);
    assert_eq!(vk_bytes.ic.len(), 5, "IC has nPublic + 1 entries");
    let ic: &'static [[u8; 64]] = Box::leak(vk_bytes.ic.clone().into_boxed_slice());
    let vk = Groth16Verifyingkey {
        nr_pubinputs: vk_bytes.nr_pubinputs,
        vk_alpha_g1: vk_bytes.alpha_g1,
        vk_beta_g2: vk_bytes.beta_g2,
        vk_gamme_g2: vk_bytes.gamma_g2,
        vk_delta_g2: vk_bytes.delta_g2,
        vk_ic: ic,
    };

    let mut verifier =
        Groth16Verifier::new(&bytes.proof_a, &bytes.proof_b, &bytes.proof_c, &public, &vk)
            .expect("constructing the on-chain verifier");
    verifier
        .verify()
        .expect("the on-chain groth16-solana verifier must accept the arkworks proof");
}

/// Soundness sanity: the same proof against a tampered public input must be
/// rejected by the on-chain verifier, not merely by arkworks.
#[test]
fn on_chain_verifier_rejects_a_tampered_public_input() {
    let mut rng = rng();
    let witness = fixture_witness();
    let pk = setup::setup(&mut rng).expect("groth16 setup");
    let proof = setup::prove(&pk, &witness, &mut rng).expect("groth16 prove");

    let bytes = onchain::proof_bytes(&proof);
    let mut public = witness.public_inputs_be();
    // Flip the epoch, the public input a replaying relay would want to move.
    public[3] = fr_to_be(&Fr::from(8u64));

    let vk_bytes = onchain::verifying_key_bytes(&pk.vk);
    let ic: &'static [[u8; 64]] = Box::leak(vk_bytes.ic.clone().into_boxed_slice());
    let vk = Groth16Verifyingkey {
        nr_pubinputs: vk_bytes.nr_pubinputs,
        vk_alpha_g1: vk_bytes.alpha_g1,
        vk_beta_g2: vk_bytes.beta_g2,
        vk_gamme_g2: vk_bytes.gamma_g2,
        vk_delta_g2: vk_bytes.delta_g2,
        vk_ic: ic,
    };
    let rejected =
        match Groth16Verifier::new(&bytes.proof_a, &bytes.proof_b, &bytes.proof_c, &public, &vk) {
            Err(_) => true,
            Ok(mut v) => v.verify().is_err(),
        };
    assert!(
        rejected,
        "a proof must not verify against public inputs it does not commit to"
    );
}

/// The arkworks key is a DIFFERENT key for the same statement. It encodes to the
/// same canonical registry shape the program's `INIT_VK` expects (769 bytes for
/// 4 public inputs), and it does NOT hash to the digest the program pins for the
/// deployed circom membership key - so nothing here could be mistaken for, or
/// installed as, the deployed key.
#[test]
fn arkworks_key_encodes_to_the_registry_shape_but_is_not_the_pinned_key() {
    use sha2::{Digest, Sha256};

    let mut rng = rng();
    let pk = setup::setup(&mut rng).expect("groth16 setup");
    let canonical = onchain::canonical_registry_encoding(&pk.vk).expect("canonical encoding");
    assert_eq!(
        canonical.len(),
        769,
        "4 public inputs encode to the same 769-byte registry record as the circom key"
    );

    // The digest `programs/mirror-pool/src/vk_digest.rs` pins for MEMBERSHIP.
    const PINNED_MEMBERSHIP_DIGEST: &str =
        "108733d1671cd3ea8aae375f1f6d232877b33826fef9370c196f72457cf1a6da";
    let got: [u8; 32] = Sha256::digest(&canonical).into();
    let got_hex: String = got.iter().map(|b| format!("{b:02x}")).collect();
    assert_ne!(
        got_hex, PINNED_MEMBERSHIP_DIGEST,
        "the arkworks key must not collide with the pinned deployed key"
    );
}

/// A verifying key round-trips through the byte layout unchanged, so the bytes
/// handed to the on-chain verifier really are this key.
#[test]
fn verifying_key_bytes_round_trip() {
    let mut rng = rng();
    let pk = setup::setup(&mut rng).expect("groth16 setup");
    let vk: &VerifyingKey<Bn254> = &pk.vk;
    let b = onchain::verifying_key_bytes(vk);
    assert_eq!(
        mirror_ceremony::points::g1_from_bytes("alpha", &b.alpha_g1).unwrap(),
        vk.alpha_g1
    );
    assert_eq!(
        mirror_ceremony::points::g2_from_bytes("delta", &b.delta_g2).unwrap(),
        vk.delta_g2
    );
    for (i, ic) in b.ic.iter().enumerate() {
        assert_eq!(
            mirror_ceremony::points::g1_from_bytes("ic", ic).unwrap(),
            vk.gamma_abc_g1[i]
        );
    }
}
