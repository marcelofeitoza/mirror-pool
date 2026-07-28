//! End-to-end tests for the phase-2 ceremony: the honest path, and every
//! rejection the verifier is supposed to make.
//!
//! These run over a small SYNTHETIC proving key so they need no build artifacts
//! and finish in milliseconds. The ceremony math does not care what circuit a key
//! belongs to - it only moves `delta` - so a synthetic key exercises exactly the
//! same code paths a real one does. The test that a ceremony-produced key still
//! PROVES lives in `mirror-cli` (`ceremony_key_proves_and_on_chain_verifier_accepts`),
//! because it needs the compiled circuit.

use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::UniformRand;
use ark_groth16::{ProvingKey, VerifyingKey};
use rand::rngs::StdRng;
use rand::SeedableRng;

use mirror_ceremony::contribute::{self, Entropy};
use mirror_ceremony::error::Check;
use mirror_ceremony::key::CeremonyKey;
use mirror_ceremony::ptau::Phase1Provenance;
use mirror_ceremony::session::Session;
use mirror_ceremony::transcript::{
    entry_hash, ContributionKind, ContributionRecord, EntropySource, PokRecord, Provenance,
    Transcript,
};
use mirror_ceremony::{hexfmt, points, pok, verify, CeremonyError};

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

/// A structurally valid (but circuit-less) proving key.
fn synthetic_key(seed: u64) -> CeremonyKey {
    const N: usize = 6;
    let mut rng = StdRng::seed_from_u64(seed);
    let g1 = |rng: &mut StdRng| (G1Affine::generator() * Fr::rand(rng)).into_affine();
    let a_query: Vec<G1Affine> = (0..N).map(|_| g1(&mut rng)).collect();
    let b_g1_query: Vec<G1Affine> = (0..N).map(|_| g1(&mut rng)).collect();
    let h_query: Vec<G1Affine> = (0..N).map(|_| g1(&mut rng)).collect();
    let l_query: Vec<G1Affine> = (0..N).map(|_| g1(&mut rng)).collect();
    let b_g2_query: Vec<G2Affine> = (0..N)
        .map(|_| (G2Affine::generator() * Fr::rand(&mut rng)).into_affine())
        .collect();

    // One delta scalar for both groups, as a real initial key has.
    let delta = Fr::rand(&mut rng);
    let pk = ProvingKey::<Bn254> {
        vk: VerifyingKey {
            alpha_g1: g1(&mut rng),
            beta_g2: (G2Affine::generator() * Fr::rand(&mut rng)).into_affine(),
            gamma_g2: (G2Affine::generator() * Fr::rand(&mut rng)).into_affine(),
            delta_g2: (G2Affine::generator() * delta).into_affine(),
            gamma_abc_g1: (0..3).map(|_| g1(&mut rng)).collect(),
        },
        beta_g1: g1(&mut rng),
        delta_g1: (G1Affine::generator() * delta).into_affine(),
        a_query,
        b_g1_query,
        b_g2_query,
        h_query,
        l_query,
    };
    CeremonyKey::new("synthetic", pk).expect("synthetic key serializes")
}

fn fake_phase1() -> Phase1Provenance {
    Phase1Provenance {
        digest: hexfmt::encode(&[7u8; 32]),
        curve: "bn254".into(),
        power: 16,
        ceremony_power: 28,
        contributions: 54,
        contributor_names: vec!["a".into(), "b".into()],
    }
}

fn open_transcript(initial: &CeremonyKey) -> Transcript {
    Transcript::new("synthetic", [3u8; 32], fake_phase1(), initial)
}

/// Run `n` deterministic contributions with distinct ids, returning the final key.
fn run_ceremony(n: usize) -> (Transcript, CeremonyKey, CeremonyKey) {
    let initial = synthetic_key(1);
    let mut transcript = open_transcript(&initial);
    let mut head = initial.clone();
    for i in 0..n {
        let out = contribute::contribute(
            &mut transcript,
            &head,
            &format!("contributor-{i}"),
            &Entropy::Deterministic(format!("seed-{i}")),
        )
        .expect("contribution");
        head = out.key.clone();
    }
    (transcript, initial, head)
}

/// Recompute every chain hash, as a sophisticated forger would after editing an
/// entry. This makes the hash-chain checks pass so the ALGEBRAIC checks are what
/// the test is actually exercising.
fn rehash(transcript: &mut Transcript) {
    let mut prev = transcript.genesis_hash().expect("genesis");
    for rec in transcript.contributions.iter_mut() {
        rec.prev_hash = hexfmt::encode(&prev);
        let h = entry_hash(&prev, rec).expect("entry hash");
        rec.hash = hexfmt::encode(&h);
        prev = h;
    }
}

fn check_of(err: &CeremonyError) -> Check {
    err.check()
        .unwrap_or_else(|| panic!("expected a verification failure, got: {err}"))
}

// ---------------------------------------------------------------------------
// the honest path
// ---------------------------------------------------------------------------

#[test]
fn a_multi_contribution_ceremony_verifies() {
    let (transcript, initial, final_key) = run_ceremony(3);
    let report = verify::verify(&transcript, &initial, &final_key).expect("must verify");
    assert_eq!(report.steps, 3);
    assert_eq!(report.beacon_steps, 0);
    assert_eq!(report.final_key_digest, hexfmt::encode(&final_key.digest()));
    // Every contribution moved delta.
    assert_ne!(initial.delta_g1(), final_key.delta_g1());
    assert_ne!(initial.delta_g2(), final_key.delta_g2());
}

#[test]
fn a_beacon_step_verifies_and_is_reproducible() {
    let initial = synthetic_key(2);
    let mut transcript = open_transcript(&initial);
    let first = contribute::contribute(
        &mut transcript,
        &initial,
        "alice",
        &Entropy::Deterministic("alice-seed".into()),
    )
    .expect("contribution");
    let head = first.key.clone();
    let beacon = contribute::contribute_beacon(&mut transcript, &head, "beacon", b"block-hash", 6)
        .expect("beacon");
    let final_key = beacon.key.clone();

    let report = verify::verify(&transcript, &initial, &final_key).expect("must verify");
    assert_eq!(report.steps, 2);
    assert_eq!(report.beacon_steps, 1);
    // A beacon is never counted as an independent contributor.
    assert_eq!(report.independence.independent_contributors, 0);
}

#[test]
fn the_final_key_differs_from_the_initial_only_in_the_delta_dependent_parts() {
    let (_, initial, final_key) = run_ceremony(2);
    assert!(initial.first_fixed_part_mismatch(&final_key).is_none());
    assert_ne!(initial.pk.h_query, final_key.pk.h_query);
    assert_ne!(initial.pk.l_query, final_key.pk.l_query);
    assert_eq!(initial.pk.a_query, final_key.pk.a_query);
    assert_eq!(initial.pk.vk.gamma_abc_g1, final_key.pk.vk.gamma_abc_g1);
}

#[test]
fn keys_round_trip_through_the_container_with_a_stable_digest() {
    let dir = tempdir("roundtrip");
    let key = synthetic_key(9);
    let path = dir.join("key_0000.mpk");
    key.save(&path).expect("save");
    let loaded = CeremonyKey::load(&path).expect("load");
    assert_eq!(loaded.digest(), key.digest());
    assert_eq!(loaded.circuit, key.circuit);

    // A single flipped byte in the payload is rejected.
    let mut bytes = std::fs::read(&path).expect("read");
    let last = bytes.len() - 40;
    bytes[last] ^= 1;
    std::fs::write(&path, &bytes).expect("write");
    assert!(CeremonyKey::load(&path).is_err());
}

// ---------------------------------------------------------------------------
// required rejections
// ---------------------------------------------------------------------------

#[test]
fn rejects_a_tampered_delta_in_the_transcript() {
    // Naive tamper: edit the delta, leave the hashes alone.
    let (mut transcript, initial, final_key) = run_ceremony(3);
    let other = (G1Affine::generator() * Fr::from(12345u64)).into_affine();
    transcript.contributions[1].new_delta_g1 = hexfmt::encode(&points::g1_bytes(&other));
    let err = verify::verify(&transcript, &initial, &final_key).expect_err("must reject");
    assert_eq!(check_of(&err), Check::EntryHash);
}

#[test]
fn rejects_a_tampered_delta_even_when_the_chain_is_rehashed() {
    // Sophisticated tamper: edit the delta AND recompute every hash, so only the
    // algebra can catch it.
    let (mut transcript, initial, final_key) = run_ceremony(3);
    let (g1, g2) = transcript.contributions[1].deltas().expect("deltas");
    let _ = g2;
    let scaled = (g1 * Fr::from(7u64)).into_affine();
    transcript.contributions[1].new_delta_g1 = hexfmt::encode(&points::g1_bytes(&scaled));
    rehash(&mut transcript);
    let err = verify::verify(&transcript, &initial, &final_key).expect_err("must reject");
    // The proof of knowledge is bound to the new delta, so it is the first to fail.
    assert_eq!(check_of(&err), Check::ProofOfKnowledge);
}

#[test]
fn rejects_a_tampered_delta_in_the_final_key() {
    let (transcript, initial, final_key) = run_ceremony(2);
    let mut bad = final_key.pk.clone();
    bad.vk.delta_g2 = (bad.vk.delta_g2 * Fr::from(3u64)).into_affine();
    let bad = CeremonyKey::new("synthetic", bad).expect("key");
    let err = verify::verify(&transcript, &initial, &bad).expect_err("must reject");
    assert_eq!(check_of(&err), Check::FinalKey);
}

#[test]
fn rejects_a_delta_g2_that_moved_by_a_different_scalar() {
    // Forge an entry whose G1 and G2 deltas use different scalars, with a PoK that
    // is valid for the G1 part. Only the pairing same-ratio check can catch this.
    let initial = synthetic_key(3);
    let mut transcript = open_transcript(&initial);

    let s_g1 = Fr::from(31u64);
    let s_g2 = Fr::from(32u64);
    let new_g1: G1Affine = (initial.delta_g1() * s_g1).into();
    let new_g2: G2Affine = (initial.delta_g2() * s_g2).into();

    // A key that matches the forged entry, so the digest check passes.
    let mut forged_pk = initial.pk.clone();
    forged_pk.delta_g1 = new_g1;
    forged_pk.vk.delta_g2 = new_g2;
    let forged_key = CeremonyKey::new("synthetic", forged_pk).expect("key");

    let prev_hash = transcript.genesis_hash().expect("genesis");
    let provenance = forged_provenance();
    let statement = pok::Statement {
        prev_hash: &prev_hash,
        index: 0,
        contributor_id: "mallory",
        metadata: forged_metadata(&provenance),
        prev_delta_g1: initial.delta_g1(),
        prev_delta_g2: initial.delta_g2(),
        new_delta_g1: new_g1,
        new_delta_g2: new_g2,
    };
    let proof = pok::prove(&statement, &s_g1, &mut rand::rngs::OsRng);
    transcript
        .contributions
        .push(record(0, "mallory", new_g1, new_g2, &forged_key, &proof));
    rehash(&mut transcript);

    let err = verify::verify(&transcript, &initial, &forged_key).expect_err("must reject");
    assert_eq!(check_of(&err), Check::SameRatio);
}

#[test]
fn rejects_a_replayed_proof_of_knowledge() {
    let (mut transcript, initial, final_key) = run_ceremony(3);
    let stolen = transcript.contributions[0].pok.clone();
    transcript.contributions[2].pok = stolen;
    rehash(&mut transcript);
    let err = verify::verify(&transcript, &initial, &final_key).expect_err("must reject");
    assert_eq!(check_of(&err), Check::ProofOfKnowledge);
}

#[test]
fn rejects_a_proof_of_knowledge_re_attributed_to_another_operator() {
    let (mut transcript, initial, final_key) = run_ceremony(2);
    transcript.contributions[1].contributor_id = "someone-else".into();
    rehash(&mut transcript);
    let err = verify::verify(&transcript, &initial, &final_key).expect_err("must reject");
    assert_eq!(check_of(&err), Check::ProofOfKnowledge);
}

#[test]
fn rejects_a_forged_proof_of_knowledge() {
    let (mut transcript, initial, final_key) = run_ceremony(2);
    let bogus = (G1Affine::generator() * Fr::from(4242u64)).into_affine();
    transcript.contributions[0].pok = PokRecord {
        r: hexfmt::encode(&points::g1_bytes(&bogus)),
        z: hexfmt::encode(&points::fr_bytes(&Fr::from(4242u64))),
    };
    rehash(&mut transcript);
    let err = verify::verify(&transcript, &initial, &final_key).expect_err("must reject");
    assert_eq!(check_of(&err), Check::ProofOfKnowledge);
}

#[test]
fn rejects_a_reordered_chain() {
    let (mut transcript, initial, final_key) = run_ceremony(3);
    transcript.contributions.swap(0, 1);
    let err = verify::verify(&transcript, &initial, &final_key).expect_err("must reject");
    // The swapped entries carry each other's prev_hash, so the link breaks first.
    assert_eq!(check_of(&err), Check::ChainLink);
}

#[test]
fn rejects_a_reordered_chain_even_when_indices_and_hashes_are_repaired() {
    let (mut transcript, initial, final_key) = run_ceremony(3);
    transcript.contributions.swap(0, 1);
    for (i, rec) in transcript.contributions.iter_mut().enumerate() {
        rec.index = i as u32;
    }
    rehash(&mut transcript);
    let err = verify::verify(&transcript, &initial, &final_key).expect_err("must reject");
    // The deltas no longer chain, so the proof of knowledge for the new first
    // entry is not a proof about the initial key's delta.
    assert_eq!(check_of(&err), Check::ProofOfKnowledge);
}

#[test]
fn rejects_a_truncated_chain() {
    let (mut transcript, initial, final_key) = run_ceremony(3);
    transcript.contributions.pop();
    let err = verify::verify(&transcript, &initial, &final_key).expect_err("must reject");
    assert_eq!(check_of(&err), Check::FinalKey);
}

#[test]
fn rejects_a_renumbered_index() {
    let (mut transcript, initial, final_key) = run_ceremony(2);
    transcript.contributions[1].index = 7;
    rehash(&mut transcript);
    let err = verify::verify(&transcript, &initial, &final_key).expect_err("must reject");
    assert_eq!(check_of(&err), Check::Index);
}

#[test]
fn rejects_an_unsupported_transcript_version() {
    let (mut transcript, initial, final_key) = run_ceremony(1);
    transcript.version = 99;
    let err = verify::verify(&transcript, &initial, &final_key).expect_err("must reject");
    assert_eq!(check_of(&err), Check::Header);
}

#[test]
fn rejects_a_null_contribution() {
    // A "contribution" with ratio 1: the delta does not move, so it adds nothing.
    // `contribute` refuses to make one, so it has to be forged by hand - and the
    // forged proof of knowledge is perfectly valid, which is why there is a separate
    // check for this.
    let initial = synthetic_key(21);
    let mut transcript = open_transcript(&initial);
    let prev_hash = transcript.genesis_hash().expect("genesis");
    let provenance = forged_provenance();
    let statement = pok::Statement {
        prev_hash: &prev_hash,
        index: 0,
        contributor_id: "lazy",
        metadata: forged_metadata(&provenance),
        prev_delta_g1: initial.delta_g1(),
        prev_delta_g2: initial.delta_g2(),
        new_delta_g1: initial.delta_g1(),
        new_delta_g2: initial.delta_g2(),
    };
    let proof = pok::prove(&statement, &Fr::from(1u64), &mut rand::rngs::OsRng);
    assert!(pok::verify(&statement, &proof), "the forged PoK is valid");
    transcript.contributions.push(record(
        0,
        "lazy",
        initial.delta_g1(),
        initial.delta_g2(),
        &initial,
        &proof,
    ));
    rehash(&mut transcript);
    let err = verify::verify(&transcript, &initial, &initial).expect_err("must reject");
    assert_eq!(check_of(&err), Check::NullContribution);
}

#[test]
fn rejects_an_empty_chain() {
    let initial = synthetic_key(5);
    let transcript = open_transcript(&initial);
    let err = verify::verify(&transcript, &initial, &initial).expect_err("must reject");
    assert_eq!(check_of(&err), Check::Empty);
}

#[test]
fn truncating_both_transcript_and_key_changes_the_published_ceremony_hash() {
    // Dropping the last contribution AND handing over the previous key is a
    // legitimately shorter ceremony - the algebra cannot object. What catches it is
    // the final transcript hash, which is why it is the value to publish.
    let initial = synthetic_key(6);
    let mut transcript = open_transcript(&initial);
    let mut keys = vec![initial.clone()];
    for i in 0..3 {
        let head = keys.last().expect("head").clone();
        let out = contribute::contribute(
            &mut transcript,
            &head,
            &format!("c{i}"),
            &Entropy::Deterministic(format!("s{i}")),
        )
        .expect("contribution");
        keys.push(out.key.clone());
    }
    let full = verify::verify(&transcript, &initial, keys.last().expect("last")).expect("verify");

    let mut short = transcript.clone();
    short.contributions.pop();
    let shortened = verify::verify(&short, &initial, &keys[2]).expect("shorter ceremony verifies");
    assert_eq!(shortened.steps, 2);
    assert_ne!(full.final_transcript_hash, shortened.final_transcript_hash);
}

#[test]
fn rejects_a_modified_fixed_part_of_the_key() {
    let (transcript, initial, final_key) = run_ceremony(2);
    let mut bad = final_key.pk.clone();
    bad.vk.alpha_g1 = (bad.vk.alpha_g1 * Fr::from(2u64)).into_affine();
    let bad = CeremonyKey::new("synthetic", bad).expect("key");
    // The digest moved too, so the final-key binding rejects it first. Point the
    // transcript at the modified key to isolate the fixed-part check.
    let mut transcript = transcript;
    let last = transcript.contributions.len() - 1;
    transcript.contributions[last].new_key_digest = hexfmt::encode(&bad.digest());
    rehash(&mut transcript);
    let err = verify::verify(&transcript, &initial, &bad).expect_err("must reject");
    assert_eq!(check_of(&err), Check::FixedPart);
}

#[test]
fn rejects_a_key_whose_h_query_was_not_divided_by_the_delta_ratio() {
    // The delta points move honestly and the proof of knowledge is real, but
    // h_query is left as it was. Only the batched pairing check catches this, and
    // it is the check that makes the output a VALID key rather than merely a
    // consistently-relabelled one.
    let initial = synthetic_key(4);
    let mut transcript = open_transcript(&initial);

    let s = Fr::from(97u64);
    let mut bad_pk = contribute::apply_delta(&initial.pk, &s).expect("apply");
    bad_pk.h_query = initial.pk.h_query.clone();
    let bad_key = CeremonyKey::new("synthetic", bad_pk).expect("key");

    let prev_hash = transcript.genesis_hash().expect("genesis");
    let provenance = forged_provenance();
    let statement = pok::Statement {
        prev_hash: &prev_hash,
        index: 0,
        contributor_id: "mallory",
        metadata: forged_metadata(&provenance),
        prev_delta_g1: initial.delta_g1(),
        prev_delta_g2: initial.delta_g2(),
        new_delta_g1: bad_key.delta_g1(),
        new_delta_g2: bad_key.delta_g2(),
    };
    let proof = pok::prove(&statement, &s, &mut rand::rngs::OsRng);
    transcript.contributions.push(record(
        0,
        "mallory",
        bad_key.delta_g1(),
        bad_key.delta_g2(),
        &bad_key,
        &proof,
    ));
    rehash(&mut transcript);

    let err = verify::verify(&transcript, &initial, &bad_key).expect_err("must reject");
    assert_eq!(check_of(&err), Check::QueryScaling);
}

#[test]
fn rejects_a_tampered_beacon_source() {
    let initial = synthetic_key(7);
    let mut transcript = open_transcript(&initial);
    let out = contribute::contribute_beacon(&mut transcript, &initial, "beacon", b"real-source", 4)
        .expect("beacon");
    let final_key = out.key.clone();

    // Claim a different iteration count. The iteration count is bound into the
    // proof of knowledge, so the first check to object is that one.
    if let ContributionKind::Beacon { iterations_exp, .. } = &mut transcript.contributions[0].kind {
        *iterations_exp = 5;
    }
    rehash(&mut transcript);
    let err = verify::verify(&transcript, &initial, &final_key).expect_err("must reject");
    assert_eq!(check_of(&err), Check::ProofOfKnowledge);

    // A beacon scalar is public, so the forger can re-prove the edited step. Now
    // only recomputing the beacon from its declared source and count can object,
    // and it does: 2^5 iterations do not produce the delta that is recorded.
    let real = mirror_ceremony::beacon::scalar(b"real-source", 4).expect("beacon scalar");
    reprove_step(&mut transcript, 0, real);
    rehash(&mut transcript);
    let err = verify::verify(&transcript, &initial, &final_key).expect_err("must reject");
    assert_eq!(check_of(&err), Check::Beacon);
}

#[test]
fn rejects_a_transcript_from_a_different_initial_key() {
    let (transcript, _, final_key) = run_ceremony(2);
    let other_initial = synthetic_key(11);
    let err = verify::verify(&transcript, &other_initial, &final_key).expect_err("must reject");
    assert_eq!(check_of(&err), Check::InitialKey);
}

// ---------------------------------------------------------------------------
// contribution-time guards
// ---------------------------------------------------------------------------

#[test]
fn refuses_to_contribute_on_a_key_that_is_not_the_head() {
    let initial = synthetic_key(12);
    let mut transcript = open_transcript(&initial);
    contribute::contribute(
        &mut transcript,
        &initial,
        "alice",
        &Entropy::Deterministic("a".into()),
    )
    .expect("first contribution");
    // Second contribution built on the INITIAL key instead of the new head.
    let err = contribute::contribute(
        &mut transcript,
        &initial,
        "bob",
        &Entropy::Deterministic("b".into()),
    )
    .expect_err("must refuse");
    assert!(err.to_string().contains("head of this transcript"));
}

#[test]
fn refuses_an_empty_contributor_id() {
    let initial = synthetic_key(13);
    let mut transcript = open_transcript(&initial);
    let err = contribute::contribute(
        &mut transcript,
        &initial,
        "   ",
        &Entropy::Deterministic("a".into()),
    )
    .expect_err("must refuse");
    assert!(err.to_string().contains("contributor id"));
}

// ---------------------------------------------------------------------------
// independent-contributor counting
// ---------------------------------------------------------------------------

#[test]
fn deterministic_self_runs_are_never_counted() {
    let (transcript, initial, final_key) = run_ceremony(4);
    let report = verify::verify(&transcript, &initial, &final_key).expect("verify");
    assert_eq!(report.steps, 4);
    assert_eq!(report.independence.deterministic_steps, 4);
    assert_eq!(report.independence.independent_contributors, 0);
    assert!(report
        .independence
        .warnings
        .iter()
        .any(|w| w.contains("fixed seed")));
}

#[test]
fn contributions_from_one_machine_collapse_to_one_contributor() {
    // Real OS entropy, four different self-asserted identities, one machine: the
    // machine fingerprint merges them.
    let initial = synthetic_key(14);
    let mut transcript = open_transcript(&initial);
    let mut head = initial.clone();
    for i in 0..4 {
        let out = contribute::contribute(
            &mut transcript,
            &head,
            &format!("persona-{i}"),
            &Entropy::Os,
        )
        .expect("contribution");
        head = out.key.clone();
    }
    let report = verify::verify(&transcript, &initial, &head).expect("verify");
    assert_eq!(report.steps, 4);
    assert_eq!(report.independence.secret_steps, 4);
    assert_eq!(
        report.independence.independent_contributors, 1,
        "four runs on one machine are one contributor, not four"
    );
    assert_eq!(report.independence.groups.len(), 1);
    assert!(report.independence.groups[0]
        .reasons
        .iter()
        .any(|r| r.contains("same machine fingerprint")));
}

#[test]
fn contributions_sharing_an_identity_collapse_even_across_machines() {
    let mut transcript = independence_fixture(&[
        ("alice", "fp-1", EntropySource::Os),
        ("Alice ", "fp-2", EntropySource::Os),
        ("bob", "fp-3", EntropySource::Os),
    ]);
    let report = mirror_ceremony::independence::assess(&transcript);
    assert_eq!(report.independent_contributors, 2);
    // Normalization is case- and whitespace-insensitive.
    transcript.contributions[1].contributor_id = "ALICE".into();
    let report = mirror_ceremony::independence::assess(&transcript);
    assert_eq!(report.independent_contributors, 2);
}

#[test]
fn genuinely_separate_contributions_are_counted_separately() {
    let transcript = independence_fixture(&[
        ("alice", "fp-1", EntropySource::Os),
        ("bob", "fp-2", EntropySource::OsPlusUser),
        ("carol", "fp-3", EntropySource::Os),
    ]);
    let report = mirror_ceremony::independence::assess(&transcript);
    assert_eq!(report.independent_contributors, 3);
    assert!(report.caveat.contains("NOT a Sybil defence"));
}

#[test]
fn a_beacon_never_raises_the_count() {
    let transcript = independence_fixture(&[
        ("alice", "fp-1", EntropySource::Os),
        ("beacon-operator", "fp-2", EntropySource::Beacon),
    ]);
    let report = mirror_ceremony::independence::assess(&transcript);
    assert_eq!(report.independent_contributors, 1);
    assert_eq!(report.beacon_steps, 1);
}

#[test]
fn a_shared_pok_nonce_commitment_merges_contributions() {
    let mut transcript = independence_fixture(&[
        ("alice", "fp-1", EntropySource::Os),
        ("bob", "fp-2", EntropySource::Os),
    ]);
    let shared = transcript.contributions[0].pok.r.clone();
    transcript.contributions[1].pok.r = shared;
    let report = mirror_ceremony::independence::assess(&transcript);
    assert_eq!(report.independent_contributors, 1);
    assert!(report.groups[0]
        .reasons
        .iter()
        .any(|r| r.contains("nonce commitment")));
}

// ---------------------------------------------------------------------------
// a beacon closes the ceremony
// ---------------------------------------------------------------------------

/// The value a ceremony announces in public before it ends. A verifier can hold it
/// independently of the transcript, which is what makes it useful.
const PRE_COMMITTED: &[u8] = b"block hash announced in advance";
const PRE_COMMITTED_EXP: u32 = 4;

/// Three contributions closed by the pre-committed beacon. Returns the transcript,
/// the initial key and the final (closed) key.
fn closed_ceremony(seed: u64) -> (Transcript, CeremonyKey, CeremonyKey) {
    let initial = synthetic_key(seed);
    let mut transcript = open_transcript(&initial);
    let mut head = initial.clone();
    for i in 0..3 {
        head = contribute::contribute(
            &mut transcript,
            &head,
            &format!("contributor-{i}"),
            &Entropy::Deterministic(format!("seed-{i}")),
        )
        .expect("contribution")
        .key
        .clone();
    }
    let closed = contribute::contribute_beacon(
        &mut transcript,
        &head,
        "coordinator",
        PRE_COMMITTED,
        PRE_COMMITTED_EXP,
    )
    .expect("beacon")
    .key
    .clone();
    (transcript, initial, closed)
}

#[test]
fn rejects_a_contribution_appended_after_the_closing_beacon() {
    // Five steps: three contributions, the closing beacon, and one more
    // contribution spliced on after it by an appender that ignores the rule. The
    // spliced step is impeccable in isolation - real delta ratio, real proof of
    // knowledge - so only the beacon-is-final rule can object.
    let (mut transcript, initial, closed) = closed_ceremony(41);
    let four_step =
        verify::verify(&transcript, &initial, &closed).expect("closed ceremony verifies");
    assert_eq!(four_step.steps, 4);
    assert!(four_step.closed_by_beacon);

    let after = append_forged_step(
        &mut transcript,
        &closed,
        "late-comer",
        ContributionKind::Entropy,
        EntropySource::Os,
        Fr::from(77u64),
    );
    let err = verify::verify(&transcript, &initial, &after).expect_err("must reject");
    assert_eq!(check_of(&err), Check::BeaconFinal);
    assert!(
        err.to_string().contains("step 4 was appended after it"),
        "the error must name the offending step: {err}"
    );
}

#[test]
fn rejects_a_second_beacon() {
    // A second beacon is still a step after the closing one, and it hands the last
    // move to whoever chose it.
    let (mut transcript, initial, closed) = closed_ceremony(42);
    let s = mirror_ceremony::beacon::scalar(b"a second beacon value", 4).expect("beacon scalar");
    let after = append_forged_step(
        &mut transcript,
        &closed,
        "coordinator",
        ContributionKind::Beacon {
            source: hexfmt::encode(b"a second beacon value"),
            iterations_exp: 4,
        },
        EntropySource::Beacon,
        s,
    );
    let err = verify::verify(&transcript, &initial, &after).expect_err("must reject");
    assert_eq!(check_of(&err), Check::BeaconFinal);
}

#[test]
fn refuses_to_contribute_after_a_beacon() {
    // The honest tooling refuses at the source, so the transcript above can only be
    // produced by someone who wrote their own appender.
    let (mut transcript, _, closed) = closed_ceremony(43);
    let err = contribute::contribute(&mut transcript, &closed, "late-comer", &Entropy::Os)
        .expect_err("must refuse");
    assert!(
        err.to_string().contains("a beacon is final"),
        "unexpected error: {err}"
    );
    let err = contribute::contribute_beacon(&mut transcript, &closed, "coordinator", b"again", 4)
        .expect_err("must refuse");
    assert!(
        err.to_string().contains("a beacon is final"),
        "unexpected error: {err}"
    );
    assert_eq!(transcript.contributions.len(), 4, "nothing was appended");
}

#[test]
fn a_session_refuses_to_contribute_after_its_closing_beacon() {
    // The same rule through the on-disk session surface the CLI drives.
    let dir = tempdir("session-closed");
    let initial = synthetic_key(44);
    let mut session = Session {
        dir: dir.clone(),
        transcript: open_transcript(&initial),
    };
    initial
        .save(&session.key_path(0))
        .expect("save initial key");
    session
        .contribute("alice", &Entropy::Deterministic("a".into()))
        .expect("contribution");
    session
        .beacon("coordinator", PRE_COMMITTED, PRE_COMMITTED_EXP)
        .expect("beacon");
    assert!(session.closed_by_beacon());

    let err = session
        .contribute("late-comer", &Entropy::Os)
        .expect_err("must refuse");
    assert!(
        err.to_string().contains("a beacon is final"),
        "unexpected error: {err}"
    );
    assert_eq!(session.transcript.contributions.len(), 2);
}

// ---------------------------------------------------------------------------
// a beacon cannot be relabelled into a secret contributor
// ---------------------------------------------------------------------------

#[test]
fn a_relabelled_beacon_does_not_verify() {
    // Rewrite the closing beacon as an ordinary OS-entropy contribution and
    // recompute every chain hash. That used to be enough, because the proof of
    // knowledge said nothing about the kind. It now commits to it.
    let (mut transcript, initial, closed) = closed_ceremony(45);
    let honest = verify::verify(&transcript, &initial, &closed).expect("verifies");
    assert_eq!(honest.beacon_steps, 1);

    let last = transcript.contributions.len() - 1;
    transcript.contributions[last].kind = ContributionKind::Entropy;
    transcript.contributions[last].provenance.entropy_source = EntropySource::Os;
    transcript.contributions[last]
        .provenance
        .machine_fingerprint = "a-different-machine".into();
    rehash(&mut transcript);

    let err = verify::verify(&transcript, &initial, &closed).expect_err("must reject");
    assert_eq!(check_of(&err), Check::ProofOfKnowledge);
}

#[test]
fn a_half_relabelled_beacon_is_rejected_on_kind_provenance_disagreement() {
    // Rewriting only one of the two redundant fields is caught before the algebra
    // is even reached.
    for relabel_kind in [false, true] {
        let (mut transcript, initial, closed) = closed_ceremony(46);
        let last = transcript.contributions.len() - 1;
        if relabel_kind {
            transcript.contributions[last].kind = ContributionKind::Entropy;
        } else {
            transcript.contributions[last].provenance.entropy_source = EntropySource::Os;
        }
        rehash(&mut transcript);
        let err = verify::verify(&transcript, &initial, &closed).expect_err("must reject");
        assert_eq!(check_of(&err), Check::KindConsistency);
    }
}

#[test]
fn a_relabelled_beacon_is_rejected_when_the_pre_committed_value_is_supplied() {
    // The party who applied the beacon knows its scalar - it is a published value,
    // so everybody does - and can therefore re-prove the relabelled step. Binding
    // the kind into the proof does not stop them. What stops them is the beacon
    // pre-commitment: any verifier holding the announced value recomputes the
    // scalar and sees it applied by a step that is not recorded as that beacon.
    let (mut transcript, initial, closed) = closed_ceremony(47);
    let last = transcript.contributions.len() - 1;
    transcript.contributions[last].kind = ContributionKind::Entropy;
    transcript.contributions[last].provenance.entropy_source = EntropySource::Os;
    transcript.contributions[last]
        .provenance
        .machine_fingerprint = "a-different-machine".into();
    transcript.contributions[last].contributor_id = "dave@example.org".into();
    rehash(&mut transcript);
    let beacon_scalar =
        mirror_ceremony::beacon::scalar(PRE_COMMITTED, PRE_COMMITTED_EXP).expect("beacon scalar");
    reprove_step(&mut transcript, last, beacon_scalar);
    rehash(&mut transcript);

    let opts = verify::VerifyOptions {
        beacon_precommitment: Some(verify::BeaconPrecommitment {
            source: PRE_COMMITTED,
            iterations_exp: PRE_COMMITTED_EXP,
        }),
    };
    let err = verify::verify_with(&transcript, &initial, &closed, &opts).expect_err("must reject");
    assert_eq!(check_of(&err), Check::Beacon);
    assert!(
        err.to_string().contains("not recorded as that beacon"),
        "unexpected error: {err}"
    );

    // The honest half of the story: WITHOUT the pre-commitment the relabelled step
    // is a scalar like any other, and no verifier can tell. The tool does not
    // pretend otherwise - it accepts the transcript, counts the relabelled step,
    // and says in the report that it could not rule this out.
    let blind = verify::verify(&transcript, &initial, &closed).expect("indistinguishable");
    assert_eq!(blind.independence.independent_contributors, 1);
    assert!(!blind.beacon_precommitment_checked);
    assert!(
        blind
            .independence
            .warnings
            .iter()
            .any(|w| w.contains("relabelled public beacon")),
        "the report must say the check was not performed: {:?}",
        blind.independence.warnings
    );
}

#[test]
fn a_step_that_replays_a_recorded_beacon_scalar_is_rejected() {
    // The same defence without any external input: a step earlier in the chain that
    // applies the very scalar the transcript's own beacon publishes is that beacon,
    // whatever it calls itself.
    let initial = synthetic_key(48);
    let mut transcript = open_transcript(&initial);
    let s = mirror_ceremony::beacon::scalar(PRE_COMMITTED, PRE_COMMITTED_EXP).expect("scalar");
    let head = append_forged_step(
        &mut transcript,
        &initial,
        "mallory",
        ContributionKind::Entropy,
        EntropySource::Os,
        s,
    );
    let closed = contribute::contribute_beacon(
        &mut transcript,
        &head,
        "coordinator",
        PRE_COMMITTED,
        PRE_COMMITTED_EXP,
    )
    .expect("beacon")
    .key
    .clone();
    let err = verify::verify(&transcript, &initial, &closed).expect_err("must reject");
    assert_eq!(check_of(&err), Check::Beacon);
}

#[test]
fn a_ceremony_closed_by_the_wrong_beacon_is_rejected() {
    // "We closed on the value we announced" is a claim; with the announced value in
    // hand it becomes a check.
    let (transcript, initial, closed) = closed_ceremony(49);
    let opts = verify::VerifyOptions {
        beacon_precommitment: Some(verify::BeaconPrecommitment {
            source: b"a value nobody announced",
            iterations_exp: PRE_COMMITTED_EXP,
        }),
    };
    let err = verify::verify_with(&transcript, &initial, &closed, &opts).expect_err("must reject");
    assert_eq!(check_of(&err), Check::Beacon);
    assert!(
        err.to_string().contains("not the pre-committed one"),
        "unexpected error: {err}"
    );

    // The right value verifies, and the report records that the check ran.
    let opts = verify::VerifyOptions {
        beacon_precommitment: Some(verify::BeaconPrecommitment {
            source: PRE_COMMITTED,
            iterations_exp: PRE_COMMITTED_EXP,
        }),
    };
    let report = verify::verify_with(&transcript, &initial, &closed, &opts).expect("verifies");
    assert!(report.beacon_precommitment_checked);
    assert!(report.closed_by_beacon);
}

#[test]
fn a_beacon_is_never_counted_even_when_its_provenance_claims_os_entropy() {
    // Both signals have to agree that a step is not a beacon before it can count.
    let transcript = independence_fixture(&[
        ("alice", "fp-1", EntropySource::Os),
        ("coordinator", "fp-2", EntropySource::Os),
    ]);
    let mut relabelled = transcript.clone();
    relabelled.contributions[1].kind = ContributionKind::Beacon {
        source: hexfmt::encode(PRE_COMMITTED),
        iterations_exp: PRE_COMMITTED_EXP,
    };
    let honest = mirror_ceremony::independence::assess(&transcript);
    let report = mirror_ceremony::independence::assess(&relabelled);
    assert_eq!(honest.independent_contributors, 2);
    assert_eq!(
        report.independent_contributors, 1,
        "a beacon-kind step must not be counted whatever its provenance claims"
    );
    assert_eq!(report.beacon_steps, 1);
}

// ---------------------------------------------------------------------------
// transcript-only verification (what a third party can check from a published
// transcript.json alone)
// ---------------------------------------------------------------------------

#[test]
fn a_published_transcript_verifies_on_its_own_without_the_key_files() {
    let (transcript, _, _) = closed_ceremony(50);
    let opts = verify::VerifyOptions {
        beacon_precommitment: Some(verify::BeaconPrecommitment {
            source: PRE_COMMITTED,
            iterations_exp: PRE_COMMITTED_EXP,
        }),
    };
    let report = verify::verify_transcript(&transcript, &opts).expect("transcript verifies");
    assert_eq!(report.steps, 4);
    assert!(report.closed_by_beacon);
    assert!(
        !report.key_checks,
        "a transcript-only run must not claim the key-level checks ran"
    );

    // It is a real check, not a rubber stamp: the same tampering the full verifier
    // catches is caught here too.
    let mut tampered = transcript.clone();
    tampered.contributions[1].contributor_id = "someone-else".into();
    rehash(&mut tampered);
    let err = verify::verify_transcript(&tampered, &opts).expect_err("must reject");
    assert_eq!(check_of(&err), Check::ProofOfKnowledge);
}

#[test]
fn the_committed_demo_transcripts_verify() {
    // The transcripts published under docs/ceremony-run/ are the specific recorded
    // run docs/PROOF.md describes. Checking them here means the published evidence
    // cannot silently stop matching the code that produced it - and it exercises
    // exactly the path a third party runs.
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/")
        .parent()
        .expect("repo root")
        .to_path_buf();
    let opts = verify::VerifyOptions {
        beacon_precommitment: Some(verify::BeaconPrecommitment {
            source: b"mirror-pool demo beacon 2026-07-27",
            iterations_exp: 16,
        }),
    };
    for (file, steps, final_hash) in [
        (
            "membership-transcript.json",
            4usize,
            "4704bc3af3dbd387fe24f831a3a951882373e05222278b3f4337dd50c7681049",
        ),
        (
            "transaction-transcript.json",
            3,
            "ea5608fdab7820d9c17c4271fb1d93bae35e7da732c90acd75b4051d3d8a4cf7",
        ),
    ] {
        let path = repo.join("docs/ceremony-run").join(file);
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
        let transcript = Transcript::from_json(&text).expect("parsing the published transcript");
        let report = verify::verify_transcript(&transcript, &opts)
            .unwrap_or_else(|e| panic!("{file} must verify: {e}"));
        assert_eq!(report.steps, steps);
        assert!(report.closed_by_beacon);
        assert!(report.beacon_precommitment_checked);
        assert_eq!(
            report.final_transcript_hash, final_hash,
            "{file} no longer hashes to the value docs/PROOF.md publishes"
        );
        assert_eq!(
            report.independence.independent_contributors, 1,
            "{file} was run on one machine, so the honest count is 1"
        );
    }
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// Append a step the honest tooling refuses to make, the way an attacker with
/// their own appender would: apply a delta ratio to the head key, prove knowledge
/// of it, and splice a well-formed entry onto the chain. Returns the new head key.
fn append_forged_step(
    transcript: &mut Transcript,
    head: &CeremonyKey,
    id: &str,
    kind: ContributionKind,
    entropy_source: EntropySource,
    s: Fr,
) -> CeremonyKey {
    let new_pk = contribute::apply_delta(&head.pk, &s).expect("apply delta");
    let new_key = CeremonyKey::new(head.circuit.clone(), new_pk).expect("key");
    let prev_hash = transcript.head_hash().expect("head hash");
    let index = transcript.contributions.len() as u32;
    let provenance = Provenance {
        machine_fingerprint: "attacker".into(),
        entropy_source,
        timestamp_unix: 1_700_100_000 + u64::from(index) * 600,
    };
    let beacon_source = kind.beacon_source_bytes().expect("beacon source");
    let statement = pok::Statement {
        prev_hash: &prev_hash,
        index,
        contributor_id: id,
        metadata: pok::Metadata::new(&kind, &beacon_source, &provenance),
        prev_delta_g1: head.delta_g1(),
        prev_delta_g2: head.delta_g2(),
        new_delta_g1: new_key.delta_g1(),
        new_delta_g2: new_key.delta_g2(),
    };
    let proof = pok::prove(&statement, &s, &mut rand::rngs::OsRng);
    let mut rec = ContributionRecord {
        index,
        contributor_id: id.to_string(),
        kind,
        provenance,
        prev_hash: hexfmt::encode(&prev_hash),
        new_delta_g1: hexfmt::encode(&points::g1_bytes(&new_key.delta_g1())),
        new_delta_g2: hexfmt::encode(&points::g2_bytes(&new_key.delta_g2())),
        new_key_digest: hexfmt::encode(&new_key.digest()),
        pok: PokRecord {
            r: hexfmt::encode(&points::g1_bytes(&proof.r)),
            z: hexfmt::encode(&points::fr_bytes(&proof.z)),
        },
        hash: String::new(),
    };
    rec.hash = hexfmt::encode(&entry_hash(&prev_hash, &rec).expect("entry hash"));
    transcript.contributions.push(rec);
    new_key
}

/// Re-prove a step after editing it, which the party who knows its delta ratio can
/// always do. Call [`rehash`] afterwards.
fn reprove_step(transcript: &mut Transcript, at: usize, s: Fr) {
    let (prev_g1, prev_g2) = if at == 0 {
        transcript.header_deltas().expect("header deltas")
    } else {
        transcript.contributions[at - 1].deltas().expect("deltas")
    };
    let rec = &transcript.contributions[at];
    let prev_hash = hexfmt::decode32("prev_hash", &rec.prev_hash).expect("prev hash");
    let (new_g1, new_g2) = rec.deltas().expect("deltas");
    let beacon_source = rec.kind.beacon_source_bytes().expect("beacon source");
    let statement = pok::Statement {
        prev_hash: &prev_hash,
        index: rec.index,
        contributor_id: &rec.contributor_id,
        metadata: pok::Metadata::new(&rec.kind, &beacon_source, &rec.provenance),
        prev_delta_g1: prev_g1,
        prev_delta_g2: prev_g2,
        new_delta_g1: new_g1,
        new_delta_g2: new_g2,
    };
    let proof = pok::prove(&statement, &s, &mut rand::rngs::OsRng);
    transcript.contributions[at].pok = PokRecord {
        r: hexfmt::encode(&points::g1_bytes(&proof.r)),
        z: hexfmt::encode(&points::fr_bytes(&proof.z)),
    };
}

/// The provenance every hand-forged record carries. It is bound into the proof of
/// knowledge, so a forged proof has to commit to exactly this.
fn forged_provenance() -> Provenance {
    Provenance {
        machine_fingerprint: "forged".into(),
        entropy_source: EntropySource::Os,
        timestamp_unix: 1_700_000_000,
    }
}

/// The PoK metadata binding for a hand-forged entropy record.
fn forged_metadata(provenance: &Provenance) -> pok::Metadata<'_> {
    pok::Metadata::new(&ContributionKind::Entropy, &[], provenance)
}

/// Build a transcript entry around already-computed values (used by the forgery
/// tests, which cannot go through the honest contribution path).
fn record(
    index: u32,
    id: &str,
    new_g1: G1Affine,
    new_g2: G2Affine,
    key: &CeremonyKey,
    proof: &pok::Pok,
) -> ContributionRecord {
    ContributionRecord {
        index,
        contributor_id: id.to_string(),
        kind: ContributionKind::Entropy,
        provenance: forged_provenance(),
        prev_hash: String::new(),
        new_delta_g1: hexfmt::encode(&points::g1_bytes(&new_g1)),
        new_delta_g2: hexfmt::encode(&points::g2_bytes(&new_g2)),
        new_key_digest: hexfmt::encode(&key.digest()),
        pok: PokRecord {
            r: hexfmt::encode(&points::g1_bytes(&proof.r)),
            z: hexfmt::encode(&points::fr_bytes(&proof.z)),
        },
        hash: String::new(),
    }
}

/// A transcript whose entries carry chosen identities, fingerprints and entropy
/// sources. Only the independence heuristic reads these fields, so the points do
/// not have to be consistent.
fn independence_fixture(rows: &[(&str, &str, EntropySource)]) -> Transcript {
    let initial = synthetic_key(20);
    let mut transcript = open_transcript(&initial);
    for (i, (id, fingerprint, source)) in rows.iter().enumerate() {
        let g1 = (G1Affine::generator() * Fr::from(i as u64 + 2)).into_affine();
        let g2 = (G2Affine::generator() * Fr::from(i as u64 + 2)).into_affine();
        let kind = if *source == EntropySource::Beacon {
            ContributionKind::Beacon {
                source: hexfmt::encode(b"fixture beacon"),
                iterations_exp: 4,
            }
        } else {
            ContributionKind::Entropy
        };
        transcript.contributions.push(ContributionRecord {
            index: i as u32,
            contributor_id: (*id).to_string(),
            kind,
            provenance: Provenance {
                machine_fingerprint: (*fingerprint).to_string(),
                entropy_source: *source,
                timestamp_unix: 1_700_000_000 + (i as u64) * 3600,
            },
            prev_hash: String::new(),
            new_delta_g1: hexfmt::encode(&points::g1_bytes(&g1)),
            new_delta_g2: hexfmt::encode(&points::g2_bytes(&g2)),
            new_key_digest: hexfmt::encode(&[0u8; 32]),
            pok: PokRecord {
                r: hexfmt::encode(&points::g1_bytes(&g1)),
                z: hexfmt::encode(&points::fr_bytes(&Fr::from(i as u64 + 2))),
            },
            hash: String::new(),
        });
    }
    transcript
}

/// A unique scratch directory under the target dir (no external tempdir crate).
fn tempdir(name: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!("mirror-ceremony-{name}-{nanos}"));
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}
