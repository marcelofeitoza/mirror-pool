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
    let statement = pok::Statement {
        prev_hash: &prev_hash,
        index: 0,
        contributor_id: "mallory",
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
    let statement = pok::Statement {
        prev_hash: &prev_hash,
        index: 0,
        contributor_id: "lazy",
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
    let statement = pok::Statement {
        prev_hash: &prev_hash,
        index: 0,
        contributor_id: "mallory",
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

    // Claim a different iteration count. The delta points and the proof of
    // knowledge are untouched, so only the beacon recomputation can object.
    if let ContributionKind::Beacon { iterations_exp, .. } = &mut transcript.contributions[0].kind {
        *iterations_exp = 5;
    }
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
// helpers
// ---------------------------------------------------------------------------

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
        provenance: Provenance {
            machine_fingerprint: "forged".into(),
            entropy_source: EntropySource::Os,
            timestamp_unix: 1_700_000_000,
        },
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
        transcript.contributions.push(ContributionRecord {
            index: i as u32,
            contributor_id: (*id).to_string(),
            kind: ContributionKind::Entropy,
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
