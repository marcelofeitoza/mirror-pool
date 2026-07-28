//! `mirror-cli ceremony ...`: the participant-facing surface of the multi-party
//! Groth16 phase-2 trusted-setup ceremony.
//!
//! The flow a ceremony coordinator and an outside contributor follow:
//!
//! ```text
//! # coordinator, once per circuit
//! snarkjs groth16 setup circuits/membership.r1cs <public>.ptau membership_0000.zkey
//! mirror-cli ceremony start --circuit membership --dir ceremony/membership \
//!     --r1cs circuits/membership.r1cs --ptau <public>.ptau \
//!     --initial-zkey membership_0000.zkey
//!
//! # each contributor, on their own machine, in turn
//! mirror-cli ceremony contribute --dir ceremony/membership --id "alice@example.org"
//!
//! # closing step, from a value pre-committed in public. FINAL: nothing can be
//! # appended afterwards, and `contribute` refuses from here on.
//! mirror-cli ceremony beacon --dir ceremony/membership --id coordinator \
//!     --source-hex <block hash> --iterations-exp 20
//!
//! # anyone, at any time. Pass the pre-committed beacon value if you have it.
//! mirror-cli ceremony verify --dir ceremony/membership \
//!     --beacon-source-hex <block hash> --beacon-iterations-exp 20
//!
//! # anyone holding only the published transcript.json
//! mirror-cli ceremony verify-transcript --file transcript.json
//! ```
//!
//! `verify` is the point of the whole thing: it recomputes the chain from the
//! phase-1-derived initial key to the final key, checks every proof of knowledge
//! and every pairing relation, and reports a conservative independent-contributor
//! count that refuses to count self-runs.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Subcommand};

use mirror_ceremony::contribute::Entropy;
use mirror_ceremony::key::CeremonyKey;
use mirror_ceremony::session::{Session, StartOptions};
use mirror_ceremony::{hexfmt, ptau, verify, vk_export};

/// `mirror-cli ceremony <subcommand>`.
#[derive(Args)]
pub struct CeremonyArgs {
    #[command(subcommand)]
    pub command: CeremonyCommand,
}

#[derive(Subcommand)]
pub enum CeremonyCommand {
    /// Open a ceremony over a phase-1-derived initial proving key.
    Start(StartArgs),
    /// Add your own entropy and hand the ceremony on.
    Contribute(ContributeArgs),
    /// Close the ceremony with a public, pre-committed beacon value. Final: no
    /// step can be added afterwards.
    Beacon(BeaconArgs),
    /// Recompute and check the whole chain. Anyone can run this.
    Verify(VerifyArgs),
    /// Check a published `transcript.json` on its own, with no key files.
    VerifyTranscript(VerifyTranscriptArgs),
    /// Show what a ceremony directory currently contains.
    Status(StatusArgs),
    /// Export the ceremony's verifying key (snarkjs JSON + on-chain Rust).
    ExportVk(ExportVkArgs),
    /// Read the provenance recorded inside a phase-1 powers-of-tau file.
    InspectPtau(InspectPtauArgs),
    /// Prove the membership circuit under the ceremony key and verify the proof
    /// with the on-chain verifier. The decisive end-to-end check.
    ProveCheck(ProveCheckArgs),
}

#[derive(Args)]
pub struct StartArgs {
    /// Directory to create the ceremony in.
    #[arg(long)]
    dir: PathBuf,
    /// Circuit label (`membership` or `transaction`).
    #[arg(long)]
    circuit: String,
    /// The compiled circuit. Only its SHA-256 is recorded, to pin the transcript.
    #[arg(long)]
    r1cs: PathBuf,
    /// The PUBLIC phase-1 powers-of-tau the initial key was derived from.
    #[arg(long)]
    ptau: PathBuf,
    /// Output of `snarkjs groth16 setup <r1cs> <ptau> <out>.zkey`, which is
    /// deterministic and therefore re-derivable by anyone.
    #[arg(long)]
    initial_zkey: PathBuf,
    /// Proceed even when the powers-of-tau file records fewer than two
    /// contributions (i.e. it is not a public multi-party phase 1).
    #[arg(long)]
    allow_untrusted_phase1: bool,
}

#[derive(Args)]
pub struct ContributeArgs {
    /// The ceremony directory.
    #[arg(long)]
    dir: PathBuf,
    /// Your operator identifier. Free-form, but it is bound into your proof of
    /// knowledge, so it cannot be rewritten afterwards.
    #[arg(long)]
    id: String,
    /// Extra entropy to mix with OS randomness (dice, a photo's hash, anything).
    #[arg(long)]
    entropy: Option<String>,
    /// Derive the scalar from this fixed seed instead of OS randomness.
    /// REPRODUCIBLE ON PURPOSE, for demos and tests: the resulting contribution is
    /// flagged in the transcript and never counted as an independent contributor.
    #[arg(long, conflicts_with = "entropy")]
    deterministic_seed: Option<String>,
}

#[derive(Args)]
pub struct BeaconArgs {
    /// The ceremony directory.
    #[arg(long)]
    dir: PathBuf,
    /// Who is applying the beacon (recorded, but never counted).
    #[arg(long)]
    id: String,
    /// The pre-committed public value, as hex.
    #[arg(long, conflicts_with = "source_text")]
    source_hex: Option<String>,
    /// The pre-committed public value, as text.
    #[arg(long)]
    source_text: Option<String>,
    /// Base-2 log of the SHA-256 iteration count.
    #[arg(long, default_value_t = 20)]
    iterations_exp: u32,
}

#[derive(Args)]
pub struct VerifyArgs {
    /// The ceremony directory.
    #[arg(long)]
    dir: PathBuf,
    /// Also confirm this `.r1cs` is the one the transcript is pinned to.
    #[arg(long)]
    r1cs: Option<PathBuf>,
    /// Also confirm the initial key equals a fresh `snarkjs groth16 setup` output,
    /// which is what makes the start of the chain reproducible from public inputs.
    #[arg(long)]
    initial_zkey: Option<PathBuf>,
    #[command(flatten)]
    precommitment: PrecommitmentArgs,
    /// Emit the report as JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
pub struct VerifyTranscriptArgs {
    /// The published `transcript.json`.
    #[arg(long)]
    file: PathBuf,
    #[command(flatten)]
    precommitment: PrecommitmentArgs,
    /// Emit the report as JSON.
    #[arg(long)]
    json: bool,
}

/// The beacon value the ceremony announced in public before it closed.
///
/// Supplying it is what turns "the coordinator says step 3 was the beacon" into a
/// check, and it is the only way a verifier can tell a public beacon scalar from a
/// secret contributor's scalar.
#[derive(Args)]
pub struct PrecommitmentArgs {
    /// The pre-committed public value, as hex.
    #[arg(long, conflicts_with = "beacon_source_text")]
    beacon_source_hex: Option<String>,
    /// The pre-committed public value, as text.
    #[arg(long)]
    beacon_source_text: Option<String>,
    /// The iteration exponent announced with it.
    #[arg(long, default_value_t = 20)]
    beacon_iterations_exp: u32,
}

impl PrecommitmentArgs {
    /// The announced source bytes, if any were given.
    fn source(&self) -> Result<Option<Vec<u8>>> {
        match (&self.beacon_source_hex, &self.beacon_source_text) {
            (Some(hex), _) => Ok(Some(
                hexfmt::decode("beacon source", hex, None)
                    .map_err(|e| anyhow!("--beacon-source-hex must be hex: {e}"))?,
            )),
            (None, Some(text)) => Ok(Some(text.as_bytes().to_vec())),
            (None, None) => Ok(None),
        }
    }
}

#[derive(Args)]
pub struct StatusArgs {
    /// The ceremony directory.
    #[arg(long)]
    dir: PathBuf,
}

#[derive(Args)]
pub struct ExportVkArgs {
    /// The ceremony directory.
    #[arg(long)]
    dir: PathBuf,
    /// Where to write the snarkjs-shaped `verification_key.json`.
    #[arg(long)]
    out_json: Option<PathBuf>,
    /// Where to write the `groth16-solana` Rust constant.
    #[arg(long)]
    out_rust: Option<PathBuf>,
    /// Comma-separated public-input names for the generated header comment.
    /// Defaults to the known order for `membership` and `transaction`.
    #[arg(long)]
    public_inputs: Option<String>,
}

#[derive(Args)]
pub struct InspectPtauArgs {
    /// The `.ptau` file.
    #[arg(long)]
    ptau: PathBuf,
}

#[derive(Args)]
pub struct ProveCheckArgs {
    /// The ceremony directory (must be a `membership` ceremony).
    #[arg(long)]
    dir: PathBuf,
    /// Circuit witness generator (gitignored; `bash circuits/build.sh`).
    #[arg(long, default_value = "circuits/membership_js/membership.wasm")]
    wasm: PathBuf,
    /// Compiled R1CS (gitignored; `bash circuits/build.sh`).
    #[arg(long, default_value = "circuits/membership.r1cs")]
    r1cs: PathBuf,
    /// Also write `proof.json` / `public.json` / `verification_key.json` here, so
    /// the same proof can be re-checked with `snarkjs groth16 verify`.
    #[arg(long)]
    out_dir: Option<PathBuf>,
}

/// Dispatch.
pub fn run(args: CeremonyArgs) -> Result<()> {
    match args.command {
        CeremonyCommand::Start(a) => start(a),
        CeremonyCommand::Contribute(a) => contribute(a),
        CeremonyCommand::Beacon(a) => beacon(a),
        CeremonyCommand::Verify(a) => run_verify(a),
        CeremonyCommand::VerifyTranscript(a) => run_verify_transcript(a),
        CeremonyCommand::Status(a) => status(a),
        CeremonyCommand::ExportVk(a) => export_vk(a),
        CeremonyCommand::InspectPtau(a) => inspect_ptau(a),
        CeremonyCommand::ProveCheck(a) => prove_check(a),
    }
}

fn start(args: StartArgs) -> Result<()> {
    let phase1 = ptau::read_provenance(&args.ptau)
        .with_context(|| format!("reading phase-1 file {}", args.ptau.display()))?;
    print_phase1(&phase1);
    if !phase1.looks_public() && !args.allow_untrusted_phase1 {
        bail!(
            "this powers-of-tau file records {} contribution(s), so it is not a public multi-party \
             phase 1. Download one of the public perpetual powers-of-tau files, or pass \
             --allow-untrusted-phase1 if you understand that phase 1 is then as weak as whoever \
             generated it.",
            phase1.contributions
        );
    }

    let session = Session::start(StartOptions {
        dir: &args.dir,
        circuit: &args.circuit,
        r1cs: &args.r1cs,
        ptau: &args.ptau,
        initial_zkey: &args.initial_zkey,
    })?;

    println!();
    println!("ceremony opened in {}", session.dir.display());
    println!("  circuit:            {}", session.transcript.circuit);
    println!(
        "  r1cs sha256:        {}",
        session.transcript.circuit_r1cs_digest
    );
    println!(
        "  initial key digest: {}",
        session.transcript.initial_key_digest
    );
    println!("  initial key file:   {}", session.key_path(0).display());
    println!();
    println!("Anyone can re-derive the initial key: `snarkjs groth16 setup` is deterministic, so");
    println!(
        "re-running it on the same r1cs and the same powers-of-tau reproduces it byte for byte."
    );
    println!();
    println!("Next: hand the directory to the first contributor, who runs");
    println!(
        "  mirror-cli ceremony contribute --dir {} --id \"<their identifier>\"",
        args.dir.display()
    );
    Ok(())
}

fn contribute(args: ContributeArgs) -> Result<()> {
    let mut session = Session::open(&args.dir)?;
    let entropy = match (&args.deterministic_seed, &args.entropy) {
        (Some(seed), _) => Entropy::Deterministic(seed.clone()),
        (None, Some(user)) => Entropy::OsPlusUser(user.clone()),
        (None, None) => Entropy::Os,
    };
    if args.deterministic_seed.is_some() {
        println!(
            "WARNING: --deterministic-seed makes this contribution REPRODUCIBLE. Its toxic waste is"
        );
        println!("public, and it will not be counted as an independent contributor.");
        println!();
    }

    let record = session.contribute(&args.id, &entropy)?;
    println!("contribution {} recorded", record.index);
    println!("  contributor:      {}", record.contributor_id);
    println!("  entropy source:   {:?}", record.provenance.entropy_source);
    println!(
        "  machine print:    {}",
        record.provenance.machine_fingerprint
    );
    println!("  new key digest:   {}", record.new_key_digest);
    println!("  transcript hash:  {}", record.hash);
    println!("  new key file:     {}", session.head_key_path().display());
    println!();
    println!("Your delta scalar was never written to disk. Nothing else can undo a contribution:");
    println!("if you keep it, you keep the ability to forge proofs, so destroy it - ideally by");
    println!("powering off the machine you ran this on.");
    println!();
    println!("Hand on the whole directory (transcript.json + the newest key_*.mpk).");
    Ok(())
}

fn beacon(args: BeaconArgs) -> Result<()> {
    let source = match (&args.source_hex, &args.source_text) {
        (Some(hex), None) => hexfmt::decode("beacon source", hex, None)
            .map_err(|e| anyhow!("--source-hex must be hex: {e}"))?,
        (None, Some(text)) => text.as_bytes().to_vec(),
        _ => bail!("pass exactly one of --source-hex or --source-text"),
    };
    let mut session = Session::open(&args.dir)?;
    println!(
        "applying the beacon: SHA-256 iterated 2^{} times over {} bytes of published source",
        args.iterations_exp,
        source.len()
    );
    let record = session.beacon(&args.id, &source, args.iterations_exp)?;
    println!("beacon recorded as step {}", record.index);
    println!("  new key digest:  {}", record.new_key_digest);
    println!("  transcript hash: {}", record.hash);
    println!();
    println!("A beacon removes the last contributor's ability to grind the final key. It adds NO");
    println!(
        "secrecy: its scalar is public, so it is never counted as an independent contributor."
    );
    println!();
    println!("This ceremony is now CLOSED. No further step can be added to it, and `verify`");
    println!("rejects a transcript that has one. Publish the beacon source alongside the final");
    println!("transcript hash: a verifier who has it can check mechanically that no step in the");
    println!("chain is this public scalar wearing a contributor's name.");
    Ok(())
}

fn run_verify(args: VerifyArgs) -> Result<()> {
    let session = Session::open(&args.dir)?;
    if let Some(r1cs) = &args.r1cs {
        session.check_r1cs(r1cs)?;
        println!("r1cs {} matches the transcript.", r1cs.display());
    }
    if let Some(zkey) = &args.initial_zkey {
        let derived = CeremonyKey::from_zkey(&session.transcript.circuit, zkey)?;
        let declared = &session.transcript.initial_key_digest;
        let got = hexfmt::encode(&derived.digest());
        if &got != declared {
            bail!(
                "{} produces initial-key digest {got}, but the transcript declares {declared}",
                zkey.display()
            );
        }
        println!(
            "initial key re-derived from {} matches the transcript.",
            zkey.display()
        );
    }

    let source = args.precommitment.source()?;
    let opts = verify_options(source.as_deref(), args.precommitment.beacon_iterations_exp);
    let initial = session.load_initial_key()?;
    let final_key = session.load_head_key()?;
    let report = verify::verify_with(&session.transcript, &initial, &final_key, &opts)?;
    emit_report(&report, args.json)
}

fn run_verify_transcript(args: VerifyTranscriptArgs) -> Result<()> {
    let text = std::fs::read_to_string(&args.file)
        .with_context(|| format!("reading {}", args.file.display()))?;
    let transcript = mirror_ceremony::Transcript::from_json(&text)?;
    let source = args.precommitment.source()?;
    let opts = verify_options(source.as_deref(), args.precommitment.beacon_iterations_exp);
    let report = verify::verify_transcript(&transcript, &opts)?;
    emit_report(&report, args.json)
}

fn verify_options(source: Option<&[u8]>, iterations_exp: u32) -> verify::VerifyOptions<'_> {
    verify::VerifyOptions {
        beacon_precommitment: source.map(|source| verify::BeaconPrecommitment {
            source,
            iterations_exp,
        }),
    }
}

fn emit_report(report: &verify::Report, json: bool) -> Result<()> {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(report).context("serializing report")?
        );
        return Ok(());
    }
    print_report(report);
    Ok(())
}

fn status(args: StatusArgs) -> Result<()> {
    let session = Session::open(&args.dir)?;
    let t = &session.transcript;
    println!("ceremony:            {}", args.dir.display());
    println!("circuit:             {}", t.circuit);
    println!("r1cs sha256:         {}", t.circuit_r1cs_digest);
    print_phase1(&t.phase1);
    println!("initial key digest:  {}", t.initial_key_digest);
    println!("steps:               {}", t.contributions.len());
    for rec in &t.contributions {
        println!(
            "  {:>3}  {:<28} {:?}  {}",
            rec.index,
            truncate(&rec.contributor_id, 28),
            rec.provenance.entropy_source,
            &rec.hash[..16]
        );
    }
    println!("head key file:       {}", session.head_key_path().display());
    println!(
        "closed by beacon:    {}",
        if session.closed_by_beacon() {
            "yes - no further step can be added"
        } else {
            "no - still open for contributions"
        }
    );
    println!();
    println!(
        "Run `mirror-cli ceremony verify --dir {}` to check it.",
        args.dir.display()
    );
    Ok(())
}

fn export_vk(args: ExportVkArgs) -> Result<()> {
    let session = Session::open(&args.dir)?;
    let report = session.verify()?;
    let key = session.load_head_key()?;

    let order: Vec<String> = match &args.public_inputs {
        Some(list) => list.split(',').map(|s| s.trim().to_string()).collect(),
        None => default_public_inputs(&session.transcript.circuit),
    };
    let order_refs: Vec<&str> = order.iter().map(String::as_str).collect();

    let provenance = format!(
        "From the {} ceremony: {} step(s), {} independent contributor(s), {}, final transcript hash {}.",
        session.transcript.circuit,
        report.steps,
        report.independence.independent_contributors,
        if report.closed_by_beacon {
            "closed by beacon"
        } else {
            "NOT closed by a beacon"
        },
        report.final_transcript_hash
    );

    if let Some(path) = &args.out_json {
        write_out(path, &vk_export::snarkjs_json(&key.pk.vk))?;
        println!("wrote {}", path.display());
    }
    if let Some(path) = &args.out_rust {
        let src = vk_export::rust_source(
            &key.pk.vk,
            &format!("mirror-pool {}", session.transcript.circuit),
            &order_refs,
            &provenance,
        );
        write_out(path, &src)?;
        println!("wrote {}", path.display());
    }
    if args.out_json.is_none() && args.out_rust.is_none() {
        println!("{}", vk_export::snarkjs_json(&key.pk.vk));
    }
    println!();
    println!("{provenance}");
    if !report.closed_by_beacon {
        println!();
        println!("WARNING: this ceremony has no closing beacon, so whoever made the last");
        println!("contribution could have retried until the final key suited them. Close it with");
        println!(
            "`ceremony beacon` from a publicly pre-committed value before deploying this key."
        );
    }
    println!();
    println!("Deploying this key means replacing the program's embedded verifying key and");
    println!("redeploying. Until that happens, the deployed program still verifies against");
    println!("whatever key it was built with.");
    Ok(())
}

fn inspect_ptau(args: InspectPtauArgs) -> Result<()> {
    let phase1 = ptau::read_provenance(&args.ptau)?;
    println!("file:            {}", args.ptau.display());
    print_phase1(&phase1);
    println!();
    if phase1.contributor_names.is_empty() {
        println!("No contributor names recorded.");
    } else {
        println!("contributors ({}):", phase1.contributor_names.len());
        for (i, name) in phase1.contributor_names.iter().enumerate() {
            let shown = if name.is_empty() { "<unnamed>" } else { name };
            println!("  {i:>3}  {shown}");
        }
        println!();
        println!("These names are recorded inside the file itself. Compare them, and the SHA-256");
        println!("above, against the published list for the powers-of-tau you believe you have.");
    }
    Ok(())
}

fn prove_check(args: ProveCheckArgs) -> Result<()> {
    use groth16_solana::groth16::{Groth16Verifier, Groth16Verifyingkey};
    use mirror_core::{commit_with_action_hash, nullifier, transfer_action_hash, Epoch, Secret};

    let session = Session::open(&args.dir)?;
    if session.transcript.circuit != "membership" {
        bail!(
            "prove-check builds a MEMBERSHIP witness, but this is a {:?} ceremony. The transaction \
             circuit needs a full JoinSplit witness, which this command does not construct; verify \
             that ceremony with `ceremony verify` and export its key with `ceremony export-vk`.",
            session.transcript.circuit
        );
    }
    let report = session.verify()?;
    println!(
        "ceremony verified: {} step(s), final transcript hash {}",
        report.steps, report.final_transcript_hash
    );

    let key = session.load_head_key()?;
    println!(
        "proving under the ceremony key {}",
        hexfmt::encode(&key.digest())
    );

    // A self-contained witness: one leaf at index 21 of an otherwise-empty
    // depth-20 tree. Nothing about it depends on a live cluster.
    let secret = Secret::from_bytes(crate::groth16::to_be32(
        "111122223333444455556666777788889999",
    )?);
    let mut recipient = [0u8; 32];
    for (i, b) in recipient.iter_mut().enumerate() {
        *b = (i + 1) as u8;
    }
    let amount: u64 = 250_000_000;
    let epoch: u64 = 7;
    let action_hash = transfer_action_hash(&recipient, amount);
    let nullifier_hash = nullifier(&secret, Epoch(epoch)).0;
    let leaf = commit_with_action_hash(&secret, &action_hash, Epoch(epoch)).0;

    let zeros = crate::tree::zero_ladder(crate::tree::DEPTH);
    let mut elements = Vec::with_capacity(crate::tree::DEPTH);
    let mut indices = Vec::with_capacity(crate::tree::DEPTH);
    for (level, zero) in zeros.iter().enumerate().take(crate::tree::DEPTH) {
        elements.push(*zero);
        indices.push(((21u64 >> level) & 1) as u8);
    }
    let root = crate::tree::verify_path(&leaf, &elements, &indices);
    let path = crate::tree::MerklePath {
        elements,
        indices,
        root,
    };

    let input = crate::prove::membership_input_json(
        &path.root,
        &nullifier_hash,
        &action_hash,
        epoch,
        &secret.0,
        &path,
    );
    let expected =
        crate::prove::membership_public_inputs(&path.root, &nullifier_hash, &action_hash, epoch);
    let generated =
        crate::prove_rust::prove_with_key_full(&args.wasm, &args.r1cs, &key.pk, &input, &expected)
            .context("proving under the ceremony key")?;
    let proof = &generated.bytes;
    println!("proof generated and verified in-process against the ceremony verifying key.");

    if let Some(dir) = &args.out_dir {
        let signals: Vec<String> = expected.iter().map(crate::util::be32_to_decimal).collect();
        write_out(
            &dir.join("proof.json"),
            &serde_json::to_string_pretty(&generated.snarkjs).context("serializing proof")?,
        )?;
        write_out(
            &dir.join("public.json"),
            &serde_json::to_string_pretty(&signals).context("serializing public signals")?,
        )?;
        write_out(
            &dir.join("verification_key.json"),
            &vk_export::snarkjs_json(&key.pk.vk),
        )?;
        println!(
            "wrote proof.json / public.json / verification_key.json to {}",
            dir.display()
        );
        println!(
            "cross-check with: snarkjs groth16 verify {0}/verification_key.json {0}/public.json {0}/proof.json",
            dir.display()
        );
    }

    // Now run the EXACT on-chain verifier over the ceremony-exported verifying key.
    let vk_bytes = vk_export::solana_bytes(&key.pk.vk);
    let ic: &'static [[u8; 64]] = Box::leak(vk_bytes.ic.clone().into_boxed_slice());
    let vk = Groth16Verifyingkey {
        nr_pubinputs: vk_bytes.nr_pubinputs,
        vk_alpha_g1: vk_bytes.alpha_g1,
        vk_beta_g2: vk_bytes.beta_g2,
        vk_gamme_g2: vk_bytes.gamma_g2,
        vk_delta_g2: vk_bytes.delta_g2,
        vk_ic: ic,
    };
    let mut verifier = Groth16Verifier::new(
        &proof.proof_a,
        &proof.proof_b,
        &proof.proof_c,
        &expected,
        &vk,
    )
    .map_err(|e| anyhow!("constructing the on-chain verifier: {e:?}"))?;
    verifier
        .verify()
        .map_err(|e| anyhow!("the on-chain groth16-solana verifier REJECTED the proof: {e:?}"))?;

    println!();
    println!("PASS: the on-chain groth16-solana verifier accepts a proof made under the");
    println!("      ceremony-produced proving key, checked against the ceremony-exported");
    println!("      verifying key. The ceremony output is a working Groth16 key.");
    Ok(())
}

// ---------------------------------------------------------------------------
// printing
// ---------------------------------------------------------------------------

fn print_phase1(p: &ptau::Phase1Provenance) {
    println!("phase 1 (powers of tau)");
    println!("  sha256:          {}", p.digest);
    println!("  curve:           {}", p.curve);
    println!("  power:           2^{}", p.power);
    println!("  ceremony power:  2^{}", p.ceremony_power);
    println!(
        "  contributions:   {}{}",
        p.contributions,
        if p.looks_public() {
            ""
        } else {
            "  (NOT a public multi-party phase 1)"
        }
    );
    let named: Vec<&str> = p
        .contributor_names
        .iter()
        .filter(|n| !n.is_empty())
        .map(String::as_str)
        .take(6)
        .collect();
    if !named.is_empty() {
        println!(
            "  first names:     {}{}",
            named.join(", "),
            if p.contributor_names.len() > named.len() {
                ", ..."
            } else {
                ""
            }
        );
    }
}

fn print_report(r: &verify::Report) {
    if r.key_checks {
        println!("CEREMONY VERIFIED");
    } else {
        println!("TRANSCRIPT VERIFIED (no key files: the key-level checks did NOT run)");
    }
    println!("  circuit:                 {}", r.circuit);
    println!("  r1cs sha256:             {}", r.circuit_r1cs_digest);
    println!("  steps:                   {}", r.steps);
    println!("  of which beacons:        {}", r.beacon_steps);
    println!(
        "  closed by beacon:        {}",
        if r.closed_by_beacon {
            "yes"
        } else {
            "NO - the last contributor could still grind the final key"
        }
    );
    println!(
        "  beacon pre-commitment:   {}",
        if r.beacon_precommitment_checked {
            "checked against the value you supplied"
        } else {
            "NOT supplied - a relabelled beacon cannot be ruled out"
        }
    );
    println!("  initial key digest:      {}", r.initial_key_digest);
    println!("  final key digest:        {}", r.final_key_digest);
    println!("  final transcript hash:   {}", r.final_transcript_hash);
    println!("  phase-1 sha256:          {}", r.phase1_digest);
    println!(
        "  phase-1 contributions:   {}{}",
        r.phase1_contributions,
        if r.phase1_looks_public {
            ""
        } else {
            "  (NOT a public multi-party phase 1)"
        }
    );
    println!();
    println!(
        "INDEPENDENT CONTRIBUTORS: {}",
        r.independence.independent_contributors
    );
    println!(
        "  from {} step(s): {} with secret entropy, {} deterministic, {} beacon",
        r.independence.total_steps,
        r.independence.secret_steps,
        r.independence.deterministic_steps,
        r.independence.beacon_steps
    );
    for group in &r.independence.groups {
        let members: Vec<String> = group.members.iter().map(u32::to_string).collect();
        println!(
            "  [{}] {} (steps {})",
            if group.counted { "counted" } else { "  not  " },
            truncate(&group.contributor_id, 40),
            members.join(", ")
        );
        for reason in &group.reasons {
            println!("        merged: {reason}");
        }
    }
    if !r.independence.warnings.is_empty() {
        println!();
        println!("WARNINGS");
        for w in &r.independence.warnings {
            println!("  - {w}");
        }
    }
    println!();
    println!("SECURITY PROPERTY");
    println!("  A phase-2 ceremony with k independent contributors is safe if AT LEAST ONE of");
    println!("  them destroyed their secret scalar (1-of-N honest). It is NOT k-of-N: one honest");
    println!("  contributor suffices, and all k colluding is enough to break it.");
    println!();
    println!("  {}", r.independence.caveat);
    if !r.key_checks {
        println!();
        println!("WHAT THIS RUN DID NOT CHECK");
        println!("  Without the key files this cannot check that the initial key is the one the");
        println!("  header names, that the final key is the one the chain ends at, that the");
        println!("  delta-independent parts of the key never moved, or that h_query/l_query were");
        println!("  divided by the accumulated ratio. Run `ceremony verify --dir ...` for those.");
    }
}

fn default_public_inputs(circuit: &str) -> Vec<String> {
    let names: &[&str] = match circuit {
        "membership" => &["root", "nullifierHash", "actionHash", "epoch"],
        "transaction" => &[
            "root",
            "publicAmount",
            "extDataHash",
            "inputNullifier[0]",
            "inputNullifier[1]",
            "outputCommitment[0]",
            "outputCommitment[1]",
        ],
        _ => &[],
    };
    names.iter().map(|s| s.to_string()).collect()
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        return s.to_string();
    }
    let head: String = s.chars().take(n.saturating_sub(3)).collect();
    format!("{head}...")
}

fn write_out(path: &Path, contents: &str) -> Result<()> {
    if let Some(dir) = path.parent() {
        if !dir.as_os_str().is_empty() {
            std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        }
    }
    std::fs::write(path, contents).with_context(|| format!("writing {}", path.display()))
}
