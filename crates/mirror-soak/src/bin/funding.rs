//! mirror-soak-funding: the FUNDING-ROUND end-to-end soak.
//!
//! The behavioral soak (`mirror-soak`) proves the crowd path and the
//! confidential soak (`mirror-soak-value`) proves the JoinSplit value layer.
//! This one proves the leg between them: **funding provenance**. A participant
//! who tops up their fresh commit wallet from their main wallet writes that edge
//! straight into the public transaction graph, and the common-funding-source
//! heuristic walks it backwards. The mechanism under test replaces that edge with
//! a batched, relay-signed unshield out of a denominated value pool.
//!
//! It runs against a LIVE local Surfpool validator (treated as a mainnet mirror)
//! using the REAL shipped components, end to end and in the shipped order:
//!
//! - `mirror-cli shield | scan | fund-commit` for the participant side (a fresh
//!   commit-wallet keypair plus a proved, relay-only-signed unshield emitted as
//!   JSON), and
//! - `mirror_coordinator::FundingService` + `DirectoryIntake` for the
//!   coordinator side, which is the ingestion path itself: it polls the real
//!   chain slot, reads the emits out of an inbox directory, batches them into
//!   slot rounds, holds a thin round back, and releases a full one through the
//!   gasless relay.
//!
//! # What it asserts on-chain
//!
//! 1. **Setup** - a denominated funding `ValuePool` and a behavioral `Pool`.
//! 2. **Shield** - every participant shields exactly the denomination from their
//!    OWN main wallet, then scans to recover a spendable note.
//! 3. **Request** - `fund-commit` mints a FRESH commit wallet (unfunded, and
//!    distinct from every main wallet) and emits its unshield into the inbox.
//! 4. **Thin round** - a round below `min_round_size` rolls forward, and NOTHING
//!    reaches the chain while it is thin.
//! 5. **Release** - the merged round releases at its boundary; every fresh
//!    commit wallet is credited exactly the denomination and the vault is
//!    debited by exactly the sum.
//! 6. **The property** - each funding transaction carries EXACTLY ONE signature
//!    (the relay's), mentions no participant main wallet, and the fresh commit
//!    wallet's ONLY inbound transfer over its whole on-chain history is from the
//!    pool vault.
//! 7. **Participation** - a funded commit wallet then commits to the behavioral
//!    pool, paying its own fee, so the funding actually enables participation.
//! 8. **Adversarial** - a wrong-amount request is refused client-side by the CLI
//!    and coordinator-side at the intake (zero transactions), and a mid-round
//!    submit failure re-queues the remainder instead of dropping it.
//!
//! # What it does NOT claim
//!
//! The shield leg is still the participant's own transaction from their own
//! wallet, and both boundary crossings expose an amount and a slot. The funding
//! edge is not erased; it is turned into a matching problem whose residual
//! `crates/mirror-harness` measures and `docs/EFFECTIVE_K.md` publishes. This
//! soak proves the edge is gone from the graph, not that the pool is unbreakable.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;

use mirror_coordinator::client::{RpcSolanaClient, SolanaClient};
use mirror_coordinator::crowd::epoch_pda;
use mirror_coordinator::{
    setup_pool_alt, submit_transact_with_luts, DirectoryIntake, FundingIntake, FundingRequest,
    FundingRoundConfig, FundingRounds, FundingService, FundingServiceConfig, RelaySet,
    RoundOutcome, TxProfile, ValueTransactRequest,
};
use mirror_core::{commit as core_commit, ActionClass, Epoch, Secret, SizeBucket};
use mirror_soak::{
    airdrop, begin_proof_section, ceremony_head_key, checks_table, cli_bin, clone_keypair,
    commit_ix, first_line, hex_decode, init_pool_ix, install_vk, lamports, load_keypair,
    new_keypair, note_is_spendable, parse_kv, pool_pda, read_vpool, repo_root, run_cli,
    run_cli_expect_fail, send, sigs_table, value_pool_pda, value_vault_pda, wait_until_slot,
    write_lines, Report, DEFAULT_RPC_URL, SYSTEM_PROGRAM_ID,
};

use solana_instruction::AccountMeta;
use solana_keypair::Keypair;
use solana_message::AddressLookupTableAccount;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;

// ---------------------------------------------------------------------------
// CLI args
// ---------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(
    name = "mirror-soak-funding",
    about = "Funding-round end-to-end Surfpool soak: fund-commit -> coordinator ingestion -> batched gasless release, with on-chain funding-provenance verification"
)]
struct Args {
    /// RPC endpoint (default: the running local Surfpool).
    #[arg(long, default_value = DEFAULT_RPC_URL)]
    rpc_url: String,
    /// mirror-pool program id (base58). REQUIRED: use the freshly-deployed id.
    #[arg(long)]
    program_id: String,
    /// The funding pool's fixed denomination (lamports). Every shield and every
    /// funding withdrawal moves exactly this, so the amount channel is closed.
    #[arg(long, default_value_t = 100_000_000)]
    denomination: u64,
    /// Relay fee (lamports) bound into every Transact's ext-data.
    #[arg(long, default_value_t = 5_000)]
    fee: u64,
    /// Participants in the funding round.
    #[arg(long, default_value_t = 4)]
    participants: usize,
    /// Funding-round length in slots. Kept short so the soak crosses several
    /// real round boundaries in reasonable wall-clock; production defaults to
    /// `DEFAULT_ROUND_SLOTS`.
    #[arg(long, default_value_t = 12)]
    round_slots: u64,
    /// Minimum withdrawals before a round may release.
    #[arg(long, default_value_t = 4)]
    min_round_size: usize,
    /// Behavioral pool epoch length in slots.
    #[arg(long, default_value_t = 60)]
    epoch_slots: u64,
    /// Behavioral pool k floor.
    #[arg(long, default_value_t = 2)]
    k_floor: u32,
    /// Skip the live mid-round-failure case (it costs one extra proof per
    /// participant).
    #[arg(long)]
    skip_failure_case: bool,
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Environment helpers
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// On-chain reads
// ---------------------------------------------------------------------------

/// Epoch account: version 0, epoch_id 1, nominal_k 9, settled 13.
async fn epoch_commit_count(client: &dyn SolanaClient, epoch_account: &Pubkey) -> Result<u32> {
    match client.get_account(epoch_account).await? {
        Some(acc) if acc.data.len() >= 14 => {
            Ok(u32::from_le_bytes(acc.data[9..13].try_into().unwrap()))
        }
        _ => Ok(0),
    }
}

// ---------------------------------------------------------------------------
// Transaction forensics
// ---------------------------------------------------------------------------

/// The decoded shape of one confirmed transaction, reduced to what a
/// funding-provenance argument actually needs.
struct TxFacts {
    signature: String,
    /// Number of signatures on the transaction. The whole point of the funding
    /// path is that this is 1.
    signature_count: usize,
    /// Static account keys, in order. Key 0 is the fee payer.
    account_keys: Vec<String>,
    /// Per-account lamport delta (post - pre), aligned with `account_keys`.
    deltas: Vec<i128>,
    compute_units: Option<u64>,
}

impl TxFacts {
    fn delta_of(&self, key: &Pubkey) -> Option<i128> {
        let key = key.to_string();
        self.account_keys
            .iter()
            .position(|k| *k == key)
            .map(|i| self.deltas[i])
    }
    fn mentions(&self, key: &Pubkey) -> bool {
        let key = key.to_string();
        self.account_keys.contains(&key)
    }
}

/// Fetch one confirmed transaction and reduce it to [`TxFacts`].
async fn tx_facts(rpc: &RpcSolanaClient, signature: &str) -> Result<TxFacts> {
    use solana_rpc_client_api::config::RpcTransactionConfig;
    use solana_transaction_status_client_types::{
        EncodedTransaction, UiMessage, UiTransactionEncoding,
    };

    let sig = Signature::from_str(signature)
        .map_err(|e| anyhow!("invalid signature {signature}: {e}"))?;
    let confirmed = rpc
        .inner()
        .get_transaction_with_config(
            &sig,
            RpcTransactionConfig {
                encoding: Some(UiTransactionEncoding::Json),
                commitment: Some(solana_commitment_config::CommitmentConfig::confirmed()),
                max_supported_transaction_version: Some(0),
            },
        )
        .await
        .with_context(|| format!("getTransaction {signature}"))?;

    let meta = confirmed
        .transaction
        .meta
        .ok_or_else(|| anyhow!("transaction {signature} has no metadata"))?;
    let EncodedTransaction::Json(ui) = confirmed.transaction.transaction else {
        bail!("expected a JSON-encoded transaction for {signature}");
    };
    let mut account_keys = match ui.message {
        UiMessage::Raw(raw) => raw.account_keys,
        UiMessage::Parsed(parsed) => parsed
            .account_keys
            .into_iter()
            .map(|k| k.pubkey)
            .collect::<Vec<_>>(),
    };
    // Addresses resolved through an Address Lookup Table are NOT in the message's
    // static key list; they arrive separately in `meta.loadedAddresses`, and the
    // balance arrays are indexed over static-then-writable-then-readonly. The
    // funding release compiles against a lookup table (the pool's static accounts
    // do not otherwise fit in one packet), so the pool vault itself is a loaded
    // address. Appending them in that exact order is what keeps this forensics
    // honest: without it `delta_of(vault)` silently returns None and the
    // provenance claim would be evaluated against a truncated account list.
    let loaded: Option<solana_transaction_status_client_types::UiLoadedAddresses> =
        meta.loaded_addresses.clone().into();
    if let Some(loaded) = loaded {
        account_keys.extend(loaded.writable);
        account_keys.extend(loaded.readonly);
    }
    let deltas: Vec<i128> = meta
        .post_balances
        .iter()
        .zip(meta.pre_balances.iter())
        .map(|(post, pre)| *post as i128 - *pre as i128)
        .collect();
    let compute_units: Option<u64> = meta.compute_units_consumed.into();

    Ok(TxFacts {
        signature: signature.to_string(),
        signature_count: ui.signatures.len(),
        account_keys,
        deltas,
        compute_units,
    })
}

/// Every transaction that ever touched `address`, oldest first.
async fn history(rpc: &RpcSolanaClient, address: &Pubkey) -> Result<Vec<String>> {
    use solana_rpc_client::rpc_client::GetConfirmedSignaturesForAddress2Config;
    let sigs = rpc
        .inner()
        .get_signatures_for_address_with_config(
            address,
            GetConfirmedSignaturesForAddress2Config {
                commitment: Some(solana_commitment_config::CommitmentConfig::confirmed()),
                ..Default::default()
            },
        )
        .await
        .with_context(|| format!("getSignaturesForAddress {address}"))?;
    // The RPC returns newest first; a provenance argument reads better oldest
    // first, and it makes "the FIRST thing that ever funded this wallet"
    // literal rather than implied.
    let mut out: Vec<String> = sigs.into_iter().map(|s| s.signature).collect();
    out.reverse();
    Ok(out)
}

// ---------------------------------------------------------------------------
// Participant helpers
// ---------------------------------------------------------------------------

/// One soak participant: a public main wallet, a confidential value wallet, and
/// (after `fund-commit`) a fresh commit wallet.
struct Participant {
    index: usize,
    /// The PUBLIC wallet that funds the shield. This is the identity the funding
    /// path must never be linkable to.
    main: Keypair,
    main_path: PathBuf,
    /// The confidential value-wallet address (from `value-keygen`).
    value_address: String,
    value_key_path: PathBuf,
    /// The FRESH commit wallet `fund-commit` generated.
    commit_wallet: Option<Pubkey>,
    commit_wallet_path: Option<PathBuf>,
}

/// The subset of a `mirror-cli` emit the soak reads directly.
fn emit_field(path: &Path, key: &str) -> Result<String> {
    let json = emit_json(path)?;
    json[key]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow!("emit {} missing string field `{key}`", path.display()))
}

/// [`emit_field`] for an emit already in memory.
fn json_field(emit: &serde_json::Value, key: &str) -> Result<String> {
    emit[key]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow!("emit missing string field `{key}`"))
}

fn emit_json(path: &Path) -> Result<serde_json::Value> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading emit {}", path.display()))?;
    serde_json::from_str(&raw).context("parsing emit json")
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let args = Args::parse();
    let program_id =
        Pubkey::from_str(&args.program_id).map_err(|e| anyhow!("invalid --program-id: {e}"))?;

    if args.participants < args.min_round_size {
        bail!(
            "--participants {} is below --min-round-size {}; the round could never release",
            args.participants,
            args.min_round_size
        );
    }

    let root = repo_root()?;
    let keys_dir = root.join(".soak/keys");
    let notes_dir = root.join(".soak/notes-funding");
    let work_dir = root.join(".soak/funding");
    let intake_dir = work_dir.join("intake");
    for d in [&keys_dir, &notes_dir, &work_dir, &intake_dir] {
        std::fs::create_dir_all(d)?;
    }

    let cli = cli_bin()?;
    let wasm = root.join("circuits/transaction_js/transaction.wasm");
    let r1cs = root.join("circuits/transaction.r1cs");
    // The DEPLOYED JoinSplit verifying key is a phase-2 ceremony output, so the
    // soak proves under the ceremony proving key. A proof made under the
    // `circuits/transaction_final.zkey` dev key is well-formed and would be
    // rejected on chain.
    let proving_key = ceremony_head_key(&root, "transaction")?;
    for (label, p) in [("wasm", &wasm), ("r1cs", &r1cs)] {
        if !p.exists() {
            bail!(
                "confidential circuit artifact missing: {label} at {} (build with `bash circuits/build_transaction.sh`)",
                p.display()
            );
        }
    }
    let wasm_s = wasm.to_string_lossy().to_string();
    let r1cs_s = r1cs.to_string_lossy().to_string();
    let pk_s = proving_key.to_string_lossy().to_string();

    println!("mirror-soak-funding: funding-round end-to-end soak against Surfpool");
    println!("  rpc:          {}", args.rpc_url);
    println!("  program:      {program_id}");
    println!(
        "  denomination: {} lamports   fee: {}",
        args.denomination, args.fee
    );
    println!(
        "  round:        {} slots   min_round_size: {}   participants: {}",
        args.round_slots, args.min_round_size, args.participants
    );
    println!();

    let rpc = Arc::new(RpcSolanaClient::new(args.rpc_url.clone()));
    let client: Arc<dyn SolanaClient> = rpc.clone();
    let mut report = Report::default();

    // -- 1. SETUP -----------------------------------------------------------
    println!("== 1. setup ==");
    let prog_acc = client
        .get_account(&program_id)
        .await?
        .ok_or_else(|| anyhow!("program {program_id} not found; deploy it first"))?;
    if !prog_acc.executable {
        bail!("program {program_id} is not executable; deploy it first");
    }
    report.check(
        "program deployed + executable",
        true,
        format!("{program_id}"),
    );

    // The relay is BOTH the funding pool's authority and the gasless submitter,
    // because the on-chain Transact requires the authority signature and makes it
    // the fee payer. See `mirror_coordinator::funding::RelaySet`.
    let relay = new_keypair(&keys_dir, "funding-relay")?;
    let payer = new_keypair(&keys_dir, "funding-payer")?;
    let pool_authority = new_keypair(&keys_dir, "funding-pool-authority")?;
    airdrop(&args.rpc_url, &relay.pubkey(), 100)?;
    airdrop(&args.rpc_url, &payer.pubkey(), 100)?;
    airdrop(&args.rpc_url, &pool_authority.pubkey(), 100)?;

    let relay_path = keys_dir.join("funding-relay.json");
    let payer_path = keys_dir.join("funding-payer.json");

    // Publish the JoinSplit verifying key into its write-once registry PDA.
    // TRANSACT reads its key from that account rather than from the program's
    // code, and re-checks it against a compile-time digest on every verify, so a
    // fresh deployment must publish it once before any funding release can land.
    // See docs/VK_REGISTRY.md.
    let vk_sig = install_vk(
        &cli,
        &root,
        &args.rpc_url,
        &program_id,
        &payer_path,
        "transaction",
    )?;
    report.check(
        "JoinSplit verifying key published into its write-once registry PDA",
        !vk_sig.is_empty(),
        format!("init_vk: {vk_sig}"),
    );
    // Only a real publication has a signature to record; an idempotent
    // "already published" run has nothing to link to.
    if !vk_sig.starts_with("already published") {
        report.sig("init_vk_transaction", &vk_sig);
    }

    let vpool = value_pool_pda(&program_id, &relay.pubkey());
    let vault = value_vault_pda(&program_id, &vpool);

    let out = run_cli(
        &cli,
        &root,
        &[
            "init-value-pool",
            "--rpc-url",
            &args.rpc_url,
            "--program-id",
            &program_id.to_string(),
            "--authority",
            &relay_path.to_string_lossy(),
            "--payer",
            &payer_path.to_string_lossy(),
            "--fee",
            &args.fee.to_string(),
            "--denomination",
            &args.denomination.to_string(),
        ],
    )?;
    report.sig(
        "init_value_pool_funding",
        parse_kv(&out, "signature:").unwrap_or_default(),
    );
    let vp = read_vpool(client.as_ref(), &vpool).await?;
    report.check(
        "denominated funding ValuePool initialized (uniform amount enforced on-chain)",
        vp.denomination == Some(args.denomination) && vp.commitment_count == 0,
        format!(
            "vpool={vpool} vault={vault} denomination={:?}",
            vp.denomination
        ),
    );

    // One Address Lookup Table for the accounts every funding Transact shares.
    // Without it the release does not fit in a 1232-byte packet: the instruction
    // carries a 256-byte proof, seven 32-byte public inputs and two
    // encrypted-note blobs, and since the verifying key moved into a registry
    // account it takes one more account than it used to. The nullifier PDAs and
    // the fresh commit wallet change every release, so those stay inline.
    let vk_registry = Pubkey::find_program_address(
        &[b"vk", &[mirror_core::wire::CIRCUIT_TRANSACTION]],
        &program_id,
    )
    .0;
    let alt = setup_pool_alt(
        client.as_ref(),
        &relay,
        &payer,
        vec![program_id, SYSTEM_PROGRAM_ID, vk_registry, vpool, vault],
    )
    .await
    .context("setup_pool_alt for the funding value pool")?;
    report.check(
        "funding-pool ALT created + extended (keeps a release inside one packet)",
        alt.addresses.len() == 5,
        format!("alt={} ({} shared accounts)", alt.key, alt.addresses.len()),
    );
    // A freshly extended table is only usable from the NEXT slot onward.
    tokio::time::sleep(Duration::from_secs(2)).await;
    let luts = vec![alt];

    // The behavioral pool the funded commit wallets will commit into.
    let pool = pool_pda(&program_id, &pool_authority.pubkey());
    let sig = send(
        client.as_ref(),
        &[init_pool_ix(
            &program_id,
            &pool,
            &pool_authority.pubkey(),
            &payer.pubkey(),
            args.epoch_slots,
            args.k_floor,
            0, // entry_fee: the funding soak measures provenance, not fees
            0, // reward_bps
            // zk_denomination: this soak only drives crowd commits into the
            // behavioral pool, but the parameter is mandatory and non-zero.
            250_000_000,
        )],
        &[&payer, &pool_authority],
        &[],
    )
    .await
    .map_err(|e| anyhow!("init_pool failed: {e}"))?;
    report.sig("init_pool_behavioral", &sig);
    report.check(
        "behavioral Pool initialized (the pool a funded commit wallet participates in)",
        client.get_account(&pool).await?.is_some(),
        format!(
            "pool={pool} epoch_slots={} k_floor={}",
            args.epoch_slots, args.k_floor
        ),
    );

    let vault_baseline = lamports(client.as_ref(), &vault).await?;
    println!();

    // -- 2. SHIELD ----------------------------------------------------------
    println!("== 2. participants shield the denomination from their OWN main wallets ==");
    let mut participants: Vec<Participant> = Vec::new();
    for i in 0..args.participants {
        let main = new_keypair(&keys_dir, &format!("funding-main-{i}"))?;
        airdrop(&args.rpc_url, &main.pubkey(), 10)?;
        let value_key_path = notes_dir.join(format!("participant-{i}-key.json"));
        let out = run_cli(
            &cli,
            &root,
            &[
                "value-keygen",
                "--seed",
                &format!("mirror-funding-soak-participant-{i}"),
                "--out",
                &value_key_path.to_string_lossy(),
            ],
        )?;
        let value_address =
            parse_kv(&out, "address:").ok_or_else(|| anyhow!("no value address for {i}"))?;
        participants.push(Participant {
            index: i,
            main_path: keys_dir.join(format!("funding-main-{i}.json")),
            main,
            value_address,
            value_key_path,
            commit_wallet: None,
            commit_wallet_path: None,
        });
    }

    let mut leaves: Vec<String> = Vec::new();
    let mut blobs: Vec<String> = Vec::new();
    let leaves_path = work_dir.join("leaves.txt");
    let blobs_path = work_dir.join("blobs.txt");
    let mut shield_commitments: Vec<String> = Vec::new();

    for p in &participants {
        let emit_path = work_dir.join(format!("shield-{}.json", p.index));
        run_cli(
            &cli,
            &root,
            &[
                "shield",
                "--rpc-url",
                &args.rpc_url,
                "--program-id",
                &program_id.to_string(),
                "--pool",
                &vpool.to_string(),
                "--depositor",
                &p.main_path.to_string_lossy(),
                "--to",
                &p.value_address,
                "--amount",
                &args.denomination.to_string(),
                "--note-dir",
                &notes_dir.to_string_lossy(),
                "--wasm",
                &wasm_s,
                "--r1cs",
                &r1cs_s,
                "--proving-key",
                &pk_s,
                "--out",
                &emit_path.to_string_lossy(),
            ],
        )?;
        let req = emit_to_request(&emit_path, &program_id)?;
        let sig = submit_transact_with_luts(client.as_ref(), &relay, &req, &[&p.main], &luts)
            .await
            .with_context(|| format!("submitting shield {}", p.index))?;
        report.sig(&format!("shield_{}", p.index), sig.to_string());
        let c0 = emit_field(&emit_path, "out_commitment0_hex")?;
        leaves.push(c0.clone());
        leaves.push(emit_field(&emit_path, "out_commitment1_hex")?);
        blobs.push(emit_field(&emit_path, "enc0_hex")?);
        blobs.push(emit_field(&emit_path, "enc1_hex")?);
        shield_commitments.push(c0);
    }

    let vault_after_shields = lamports(client.as_ref(), &vault).await?;
    let expected_shielded = args.denomination * args.participants as u64;
    report.check(
        "every participant shielded EXACTLY the denomination (uniform deposits)",
        vault_after_shields - vault_baseline == expected_shielded,
        format!(
            "vault credited {} lamports = {} x {}",
            vault_after_shields - vault_baseline,
            args.participants,
            args.denomination
        ),
    );
    println!();

    // -- 3. SCAN + FUND-COMMIT ---------------------------------------------
    println!("== 3. scan, then fund-commit into FRESH commit wallets ==");
    write_lines(&leaves_path, &leaves)?;
    write_lines(&blobs_path, &blobs)?;

    let mut all_spendable = true;
    let mut notes: Vec<PathBuf> = Vec::new();
    for p in &participants {
        run_cli(
            &cli,
            &root,
            &[
                "scan",
                "--viewing-key",
                &p.value_key_path.to_string_lossy(),
                "--blobs",
                &blobs_path.to_string_lossy(),
                "--leaves",
                &leaves_path.to_string_lossy(),
                "--rpc-url",
                &args.rpc_url,
                "--pool",
                &vpool.to_string(),
                "--program-id",
                &program_id.to_string(),
                "--note-dir",
                &notes_dir.to_string_lossy(),
            ],
        )?;
        let note = notes_dir.join(format!("value-{}.json", shield_commitments[p.index]));
        all_spendable &= note_is_spendable(&note)?;
        notes.push(note);
    }
    report.check(
        "every participant recovered a SPENDABLE note by scanning",
        all_spendable,
        format!(
            "{} notes recovered from the on-chain enc blobs",
            notes.len()
        ),
    );

    // `fund-commit` mints a fresh commit wallet and emits its unshield straight
    // into the coordinator's inbox. That handoff IS the ingestion path.
    let inbox = intake_dir.join("inbox");
    std::fs::create_dir_all(&inbox)?;
    let mut fresh_ok = true;
    let mut unfunded_ok = true;
    let main_wallet_set: BTreeSet<Pubkey> = participants.iter().map(|p| p.main.pubkey()).collect();
    // Every released unshield inserts its own two output commitments into the
    // value accumulator, so a later `scan` needs them in ON-CHAIN insertion
    // order (which is the release order, not the arrival order). Remember which
    // participant each commit wallet belongs to so those leaves can be appended
    // once the round has actually released and the order is known. The emit FILE
    // moves as the intake claims it, so resolve it by index at read time rather
    // than holding a path that will be stale.
    let mut participant_of_wallet: std::collections::BTreeMap<Pubkey, usize> =
        std::collections::BTreeMap::new();
    for p in participants.iter_mut() {
        let wallet_path = work_dir.join(format!("commit-wallet-{}.json", p.index));
        let _ = std::fs::remove_file(&wallet_path);
        let emit_path = inbox.join(format!("request-{}.json", p.index));
        let out = run_cli(
            &cli,
            &root,
            &[
                "fund-commit",
                "--rpc-url",
                &args.rpc_url,
                "--program-id",
                &program_id.to_string(),
                "--pool",
                &vpool.to_string(),
                "--note",
                &notes[p.index].to_string_lossy(),
                "--out-keypair",
                &wallet_path.to_string_lossy(),
                "--note-dir",
                &notes_dir.to_string_lossy(),
                "--wasm",
                &wasm_s,
                "--r1cs",
                &r1cs_s,
                "--proving-key",
                &pk_s,
                "--out",
                &emit_path.to_string_lossy(),
            ],
        )?;
        let wallet = Pubkey::from_str(
            &parse_kv(&out, "commit wallet:").ok_or_else(|| anyhow!("no commit wallet printed"))?,
        )?;
        // Freshness: distinct from every main wallet AND from every other commit
        // wallet, and with no on-chain existence at all before the round runs.
        fresh_ok &= !main_wallet_set.contains(&wallet);
        unfunded_ok &= lamports(client.as_ref(), &wallet).await? == 0;
        participant_of_wallet.insert(wallet, p.index);
        p.commit_wallet = Some(wallet);
        p.commit_wallet_path = Some(wallet_path);
    }
    let wallets: Vec<Pubkey> = participants
        .iter()
        .filter_map(|p| p.commit_wallet)
        .collect();
    let distinct: BTreeSet<Pubkey> = wallets.iter().copied().collect();
    report.check(
        "fund-commit minted a FRESH commit wallet per participant (all distinct, none a main wallet)",
        fresh_ok && distinct.len() == wallets.len(),
        format!("{} distinct commit wallets", distinct.len()),
    );
    report.check(
        "every fresh commit wallet is UNFUNDED before the round releases",
        unfunded_ok,
        "no commit wallet had any lamports at request time",
    );
    println!();

    // -- 4. COORDINATOR INGESTION + THIN ROUND -----------------------------
    println!("== 4. coordinator ingestion: a thin round rolls forward ==");
    // Hold back all but (min_round_size - 1) requests, so the first round that
    // closes is provably below the floor.
    let thin_count = args.min_round_size - 1;
    let mut held: Vec<PathBuf> = Vec::new();
    for p in participants.iter().skip(thin_count) {
        let from = inbox.join(format!("request-{}.json", p.index));
        let to = work_dir.join(format!("held-request-{}.json", p.index));
        std::fs::rename(&from, &to)?;
        held.push(to);
    }

    let tx_profile = TxProfile::default();
    let intake = DirectoryIntake::new(&intake_dir, program_id, tx_profile)?;
    let intake: Arc<dyn FundingIntake> = Arc::new(intake);
    let mut service = FundingService::new(
        FundingServiceConfig {
            rounds: FundingRoundConfig {
                round_slots: args.round_slots,
                min_round_size: args.min_round_size,
                denomination: Some(args.denomination),
                lookup_tables: luts.clone(),
            },
            poll_interval: Duration::from_millis(250),
        },
        RelaySet::single(clone_keypair(&relay)),
        intake,
        client.clone(),
    )?;

    let tick = service.tick().await?;
    let thin_round = tick.ingested.first().map(|(_, r)| *r).unwrap_or_default();
    report.check(
        "the coordinator INGESTED the fund-commit emits (the shipped intake path)",
        tick.ingested.len() == thin_count && tick.rejected.is_empty(),
        format!(
            "{} request(s) batched into round {thin_round} at slot {}",
            tick.ingested.len(),
            tick.slot
        ),
    );

    // Drive real slots past the thin round's boundary.
    let mut rolled: Option<RoundOutcome> = None;
    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    while rolled.is_none() {
        if std::time::Instant::now() > deadline {
            bail!("timed out waiting for the thin round to close");
        }
        let tick = service.tick().await?;
        rolled = tick
            .outcomes
            .into_iter()
            .find(|o| matches!(o, RoundOutcome::RolledForward { .. }));
        if rolled.is_none() {
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }
    match &rolled {
        Some(RoundOutcome::RolledForward { round, to, size }) => report.check(
            "a round below min_round_size ROLLS FORWARD instead of releasing",
            *size == thin_count && *size < args.min_round_size,
            format!(
                "round {round} held {size} < min_round_size {} and moved to round {to}",
                args.min_round_size
            ),
        ),
        other => bail!("expected a RolledForward outcome, got {other:?}"),
    }

    // The decisive negative: nothing reached the chain while the round was thin.
    let mut nothing_landed = true;
    for w in &wallets {
        nothing_landed &= lamports(client.as_ref(), w).await? == 0;
    }
    report.check(
        "a thin round reaches the chain NOT AT ALL (every commit wallet still unfunded)",
        nothing_landed,
        format!("all {} commit wallets still at 0 lamports", wallets.len()),
    );
    println!();

    // -- 5. RELEASE --------------------------------------------------------
    println!("== 5. the merged round releases at its boundary ==");
    // Release the held requests into the inbox; they join the rolled-forward
    // ones, and the merged round now meets the floor.
    for (i, path) in held.iter().enumerate() {
        let to = inbox.join(format!("request-{}.json", thin_count + i));
        std::fs::rename(path, &to)?;
    }

    let mut released: Option<RoundOutcome> = None;
    let mut arrival_wallets: Vec<Pubkey> = Vec::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(180);
    while released.is_none() {
        if std::time::Instant::now() > deadline {
            bail!("timed out waiting for the merged round to release");
        }
        let tick = service.tick().await?;
        arrival_wallets.extend(tick.ingested.iter().map(|(w, _)| *w));
        if let Some(err) = tick.release_error {
            bail!("the merged round failed to release: {err}");
        }
        released = tick
            .outcomes
            .into_iter()
            .find(|o| matches!(o, RoundOutcome::Released { .. }));
        if released.is_none() {
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }
    let (round_id, release_slot, release_sigs) = match released {
        Some(RoundOutcome::Released {
            round,
            release_slot,
            size,
            signatures,
        }) => {
            report.check(
                "the merged round RELEASED every batched withdrawal at its boundary",
                size == args.participants && signatures.len() == args.participants,
                format!("round {round} released {size} withdrawals at slot {release_slot}"),
            );
            (round, release_slot, signatures)
        }
        other => bail!("expected a Released outcome, got {other:?}"),
    };
    for (i, sig) in release_sigs.iter().enumerate() {
        report.sig(&format!("funding_release_{i}"), sig.to_string());
    }

    // Every fresh commit wallet is now funded by exactly the denomination.
    let mut credited_ok = true;
    for w in &wallets {
        credited_ok &= lamports(client.as_ref(), w).await? == args.denomination;
    }
    report.check(
        "every fresh commit wallet is credited EXACTLY the denomination",
        credited_ok,
        format!(
            "{} wallets each credited {} lamports",
            wallets.len(),
            args.denomination
        ),
    );
    let vault_after_release = lamports(client.as_ref(), &vault).await?;
    report.check(
        "the pool vault was debited by exactly the sum released",
        vault_after_shields - vault_after_release == expected_shielded,
        format!(
            "vault debited {} lamports (= {} x {})",
            vault_after_shields - vault_after_release,
            args.participants,
            args.denomination
        ),
    );
    println!();

    // -- 6. THE FUNDING-PROVENANCE PROPERTY --------------------------------
    println!("== 6. funding provenance: what the chain says about the fresh wallets ==");
    let main_wallets: Vec<Pubkey> = participants.iter().map(|p| p.main.pubkey()).collect();

    let mut facts: Vec<TxFacts> = Vec::new();
    for sig in &release_sigs {
        facts.push(tx_facts(rpc.as_ref(), &sig.to_string()).await?);
    }

    // Record the leaves each released unshield inserted, in the order the chain
    // saw them (the release order), so a later scan rebuilds the real root. The
    // credited wallet identifies which emit each transaction was.
    for f in &facts {
        let credited = wallets
            .iter()
            .find(|w| f.delta_of(w) == Some(args.denomination as i128))
            .ok_or_else(|| {
                anyhow!(
                    "funding transaction {} credited none of the commit wallets",
                    f.signature
                )
            })?;
        let index = *participant_of_wallet
            .get(credited)
            .ok_or_else(|| anyhow!("no emit recorded for commit wallet {credited}"))?;
        let emit = inbox_or_accepted(&intake_dir, index)?;
        leaves.push(json_field(&emit, "out_commitment0_hex")?);
        leaves.push(json_field(&emit, "out_commitment1_hex")?);
        blobs.push(json_field(&emit, "enc0_hex")?);
        blobs.push(json_field(&emit, "enc1_hex")?);
    }
    write_lines(&leaves_path, &leaves)?;
    write_lines(&blobs_path, &blobs)?;

    let one_signature = facts.iter().all(|f| f.signature_count == 1);
    report.check(
        "every funding transaction carries EXACTLY ONE signature",
        one_signature,
        format!(
            "signature counts: {:?}",
            facts.iter().map(|f| f.signature_count).collect::<Vec<_>>()
        ),
    );
    let relay_is_signer = facts
        .iter()
        .all(|f| f.account_keys.first().map(|k| k.as_str()) == Some(&relay.pubkey().to_string()));
    report.check(
        "that one signature is the RELAY's (fee payer at account key 0)",
        relay_is_signer,
        format!("relay {}", relay.pubkey()),
    );
    let no_main_wallet = facts
        .iter()
        .all(|f| !main_wallets.iter().any(|m| f.mentions(m)));
    report.check(
        "no funding transaction mentions ANY participant main wallet",
        no_main_wallet,
        format!(
            "{} main wallets checked against {} funding transactions",
            main_wallets.len(),
            facts.len()
        ),
    );

    // The headline: the ONLY inbound edge of each fresh wallet is the vault.
    let mut provenance_ok = true;
    let mut provenance_detail = String::new();
    for (i, w) in wallets.iter().enumerate() {
        let sigs = history(rpc.as_ref(), w).await?;
        let mut inbound: Vec<(String, i128)> = Vec::new();
        for s in &sigs {
            let f = tx_facts(rpc.as_ref(), s).await?;
            if let Some(delta) = f.delta_of(w) {
                if delta > 0 {
                    // The counterparty must be the vault, and it must have lost
                    // exactly what the wallet gained.
                    let vault_delta = f.delta_of(&vault).unwrap_or(0);
                    if vault_delta != -delta {
                        provenance_ok = false;
                    }
                    inbound.push((f.signature.clone(), delta));
                }
            }
        }
        if inbound.len() != 1 || inbound[0].1 != args.denomination as i128 {
            provenance_ok = false;
        }
        if i == 0 {
            provenance_detail = format!(
                "wallet {w}: {} transaction(s) in its entire history, {} inbound, the only \
                 credit is {} lamports debited from the vault {vault}",
                sigs.len(),
                inbound.len(),
                inbound.first().map(|(_, d)| *d).unwrap_or(0)
            );
        }
    }
    report.check(
        "each fresh commit wallet's ONLY inbound transfer is from the pool vault",
        provenance_ok,
        provenance_detail,
    );

    // Arrival-independence, proved rather than asserted: feed the SAME round to
    // the batcher twice, once in arrival order and once reversed, and the
    // sequence of wallets it releases must be identical. A batcher that leaked
    // arrival order at all would produce two different sequences.
    let order_forward = probe_release_order(
        &intake_dir,
        &participants,
        &program_id,
        tx_profile,
        &args,
        round_id,
        false,
    )?;
    let order_reversed = probe_release_order(
        &intake_dir,
        &participants,
        &program_id,
        tx_profile,
        &args,
        round_id,
        true,
    )?;
    report.check(
        "the release order within a round is ARRIVAL-INDEPENDENT (same round, reversed arrival, identical release sequence)",
        order_forward == order_reversed && order_forward.len() == args.participants,
        format!(
            "arrival-order run {:?} == reversed-arrival run {:?}",
            short(&order_forward),
            short(&order_reversed)
        ),
    );

    // And the chain saw exactly that order: the i-th released signature credits
    // the i-th wallet of the release order, not the i-th to arrive.
    let mut credited_in_release_order = true;
    for (i, f) in facts.iter().enumerate() {
        let credited = order_forward.get(i).copied();
        credited_in_release_order &= credited
            .map(|w| f.delta_of(&w) == Some(args.denomination as i128))
            .unwrap_or(false);
    }
    report.check(
        "the on-chain submission sequence IS the release order, not the arrival order",
        credited_in_release_order,
        format!(
            "released {:?} while participants arrived {:?}",
            short(&order_forward),
            short(&wallets)
        ),
    );
    if order_forward == wallets {
        report.note(
            "in this run the deterministic release order happened to coincide with the arrival \
             order (with a small round that is a normal coincidence, not a leak); the \
             arrival-independence assertion above is the one that carries the property.",
        );
    }
    println!();

    // -- 7. PARTICIPATION --------------------------------------------------
    println!("== 7. a funded commit wallet participates in the behavioral pool ==");
    let commit_wallet_path = participants[0]
        .commit_wallet_path
        .clone()
        .ok_or_else(|| anyhow!("participant 0 has no commit wallet"))?;
    let commit_keypair = load_keypair(&commit_wallet_path)?;
    let before = lamports(client.as_ref(), &commit_keypair.pubkey()).await?;

    let slot = client.get_slot().await?;
    let epoch_id = slot / args.epoch_slots;
    let epoch_account = epoch_pda(&program_id, &pool, Epoch(epoch_id));
    let action = ActionClass::Swap {
        mint_in: [0xAA; 32],
        mint_out: [0xBB; 32],
        size: SizeBucket::Small,
    };
    let secret = Secret::from_bytes([0x5A; 32]);
    let commitment = core_commit(&secret, &action, Epoch(epoch_id));
    let sig = send(
        client.as_ref(),
        &[commit_ix(
            &program_id,
            &pool,
            &epoch_account,
            &commit_keypair.pubkey(),
            &commitment.0,
        )],
        &[&commit_keypair],
        &[],
    )
    .await
    .map_err(|e| anyhow!("commit from the funded commit wallet failed: {e}"))?;
    report.sig("commit_from_funded_wallet", &sig);
    let after = lamports(client.as_ref(), &commit_keypair.pubkey()).await?;
    report.check(
        "the funded commit wallet COMMITS to the behavioral pool, paying its own fee",
        epoch_commit_count(client.as_ref(), &epoch_account).await? >= 1 && after < before,
        format!(
            "epoch {epoch_id} commit_count={} and the wallet paid {} lamports out of its \
             pool-funded balance",
            epoch_commit_count(client.as_ref(), &epoch_account).await?,
            before - after
        ),
    );
    println!();

    // -- 8. ADVERSARIAL ----------------------------------------------------
    println!("== 8. adversarial cases ==");
    // (a) The CLI refuses a wrong amount against a denominated pool, before it
    //     spends any time proving.
    let wrong = args.denomination + 1;
    let cli_fail = run_cli_expect_fail(
        &cli,
        &root,
        &[
            "fund-commit",
            "--rpc-url",
            &args.rpc_url,
            "--program-id",
            &program_id.to_string(),
            "--pool",
            &vpool.to_string(),
            "--note",
            &notes[0].to_string_lossy(),
            "--out-keypair",
            &work_dir.join("wrong-amount-wallet.json").to_string_lossy(),
            "--amount",
            &wrong.to_string(),
            "--note-dir",
            &notes_dir.to_string_lossy(),
            "--wasm",
            &wasm_s,
            "--r1cs",
            &r1cs_s,
            "--proving-key",
            &pk_s,
        ],
    );
    report.check(
        "CLI fail-fast: a wrong-amount funding request is refused client-side",
        cli_fail
            .as_ref()
            .map(|e| e.to_lowercase().contains("denominat"))
            .unwrap_or(false),
        match &cli_fail {
            Ok(e) => first_line(e),
            Err(e) => format!("UNEXPECTED: {}", first_line(&e.to_string())),
        },
    );

    // (b) A hostile participant edits their emit to withdraw an off-denomination
    //     amount. The coordinator must refuse it at the intake, so it never
    //     costs a relay signature or a distinguishable failed transaction.
    let doctored = doctor_public_amount(&inbox_or_accepted(&intake_dir, 0)?, wrong)?;
    std::fs::write(
        inbox.join("doctored-request.json"),
        serde_json::to_string_pretty(&doctored)?,
    )?;
    let before_sends = release_sigs.len();
    let tick = service.tick().await?;
    report.check(
        "coordinator refuses an off-denomination request at the intake (no relay signature burned)",
        tick.rejected.len() == 1
            && tick.rejected[0].1.contains("denomination")
            && tick.ingested.is_empty(),
        match tick.rejected.first() {
            Some((id, reason)) => format!("{id}: {}", first_line(reason)),
            None => format!("UNEXPECTED: nothing rejected ({before_sends} prior sends)"),
        },
    );
    report.check(
        "the refused request was quarantined, not batched",
        intake_dir.join("rejected/doctored-request.json").exists() && service.rounds().is_empty(),
        "the doctored emit is in rejected/ and no round holds it",
    );

    // (c) A mid-round submit failure must re-queue the remainder rather than
    //     drop it. Proved live by spending one request's nullifier out of band
    //     BEFORE the round releases, so its submit fails inside the batch.
    if args.skip_failure_case {
        report.note(
            "the live mid-round-failure case was skipped (--skip-failure-case); it remains \
             covered by the unit test `a_failed_submit_requeues_the_rest_of_the_round`",
        );
    } else {
        run_failure_case(
            &cli,
            &root,
            &args,
            &program_id,
            &vpool,
            &relay,
            client.as_ref(),
            &mut participants,
            &notes_dir,
            &work_dir,
            &leaves_path,
            &blobs_path,
            &mut leaves,
            &mut blobs,
            &wasm_s,
            &r1cs_s,
            &pk_s,
            &luts,
            tx_profile,
            &mut report,
        )
        .await?;
    }
    println!();

    // -- SUMMARY -----------------------------------------------------------
    println!("== summary ==");
    let passed = report.checks.iter().filter(|(_, p, _)| *p).count();
    let total = report.checks.len();
    println!("  {passed}/{total} on-chain assertions passed");
    println!("  {} captured transaction signatures", report.sigs.len());

    let cu: Vec<(String, Option<u64>)> = facts
        .iter()
        .map(|f| (f.signature.clone(), f.compute_units))
        .collect();
    append_proof_md(
        &root,
        &args,
        &program_id,
        &relay.pubkey(),
        &vpool,
        &vault,
        &pool,
        round_id,
        release_slot,
        &cu,
        &report,
    )?;
    println!("  updated {}", root.join("docs/PROOF.md").display());

    if report.all_passed() {
        println!("\nFUNDING SOAK RESULT: GREEN ({passed}/{total} assertions passed)");
        Ok(())
    } else {
        bail!("FUNDING SOAK RESULT: RED ({passed}/{total} assertions passed)");
    }
}

// ---------------------------------------------------------------------------
// The live mid-round-failure case
// ---------------------------------------------------------------------------

/// Prove, on a live cluster, that a submit failure part-way through a round
/// re-queues the remainder instead of dropping it.
///
/// Method: every participant shields and requests a SECOND funding withdrawal.
/// Before the round boundary, the request that the batcher's deterministic
/// release order puts SECOND is submitted out of band, spending its nullifiers.
/// When the round releases, the first request succeeds and the second fails with
/// `NullifierSpent` part-way through the batch, which is exactly the failure the
/// unit test simulates with a mock RPC.
#[allow(clippy::too_many_arguments)]
async fn run_failure_case(
    cli: &Path,
    root: &Path,
    args: &Args,
    program_id: &Pubkey,
    vpool: &Pubkey,
    relay: &Keypair,
    client: &dyn SolanaClient,
    participants: &mut [Participant],
    notes_dir: &Path,
    work_dir: &Path,
    leaves_path: &Path,
    blobs_path: &Path,
    leaves: &mut Vec<String>,
    blobs: &mut Vec<String>,
    wasm_s: &str,
    r1cs_s: &str,
    pk_s: &str,
    luts: &[AddressLookupTableAccount],
    tx_profile: TxProfile,
    report: &mut Report,
) -> Result<()> {
    println!("  (c) live mid-round submit failure");
    let fail_dir = work_dir.join("failure-case");
    std::fs::create_dir_all(&fail_dir)?;

    // Second shield per participant, so each has a fresh spendable note.
    let mut second_commitments: Vec<String> = Vec::new();
    for p in participants.iter() {
        let emit_path = fail_dir.join(format!("shield2-{}.json", p.index));
        run_cli(
            cli,
            root,
            &[
                "shield",
                "--rpc-url",
                &args.rpc_url,
                "--program-id",
                &program_id.to_string(),
                "--pool",
                &vpool.to_string(),
                "--depositor",
                &p.main_path.to_string_lossy(),
                "--to",
                &p.value_address,
                "--amount",
                &args.denomination.to_string(),
                "--note-dir",
                &notes_dir.to_string_lossy(),
                "--wasm",
                wasm_s,
                "--r1cs",
                r1cs_s,
                "--proving-key",
                pk_s,
                "--out",
                &emit_path.to_string_lossy(),
            ],
        )?;
        let req = emit_to_request(&emit_path, program_id)?;
        submit_transact_with_luts(client, relay, &req, &[&p.main], luts)
            .await
            .with_context(|| format!("submitting second shield {}", p.index))?;
        let c0 = emit_field(&emit_path, "out_commitment0_hex")?;
        leaves.push(c0.clone());
        leaves.push(emit_field(&emit_path, "out_commitment1_hex")?);
        blobs.push(emit_field(&emit_path, "enc0_hex")?);
        blobs.push(emit_field(&emit_path, "enc1_hex")?);
        second_commitments.push(c0);
    }
    write_lines(leaves_path, leaves)?;
    write_lines(blobs_path, blobs)?;

    // Scan + request, this time into a staging directory so the soak controls
    // exactly when each emit becomes visible to the coordinator.
    let staging = fail_dir.join("staging");
    std::fs::create_dir_all(&staging)?;
    let mut requests: Vec<(usize, PathBuf, Pubkey)> = Vec::new();
    for p in participants.iter() {
        run_cli(
            cli,
            root,
            &[
                "scan",
                "--viewing-key",
                &p.value_key_path.to_string_lossy(),
                "--blobs",
                &blobs_path.to_string_lossy(),
                "--leaves",
                &leaves_path.to_string_lossy(),
                "--rpc-url",
                &args.rpc_url,
                "--pool",
                &vpool.to_string(),
                "--program-id",
                &program_id.to_string(),
                "--note-dir",
                &notes_dir.to_string_lossy(),
            ],
        )?;
        let note = notes_dir.join(format!("value-{}.json", second_commitments[p.index]));
        let wallet_path = fail_dir.join(format!("commit-wallet2-{}.json", p.index));
        let _ = std::fs::remove_file(&wallet_path);
        let emit_path = staging.join(format!("request2-{}.json", p.index));
        let out = run_cli(
            cli,
            root,
            &[
                "fund-commit",
                "--rpc-url",
                &args.rpc_url,
                "--program-id",
                &program_id.to_string(),
                "--pool",
                &vpool.to_string(),
                "--note",
                &note.to_string_lossy(),
                "--out-keypair",
                &wallet_path.to_string_lossy(),
                "--note-dir",
                &notes_dir.to_string_lossy(),
                "--wasm",
                wasm_s,
                "--r1cs",
                r1cs_s,
                "--proving-key",
                pk_s,
                "--out",
                &emit_path.to_string_lossy(),
            ],
        )?;
        let wallet = Pubkey::from_str(
            &parse_kv(&out, "commit wallet:").ok_or_else(|| anyhow!("no commit wallet printed"))?,
        )?;
        requests.push((p.index, emit_path, wallet));
    }

    // A fresh service so the round arithmetic is independent of the first run.
    let intake2_dir = fail_dir.join("intake");
    let inbox2 = intake2_dir.join("inbox");
    let intake = DirectoryIntake::new(&intake2_dir, *program_id, tx_profile)?;
    let intake: Arc<dyn FundingIntake> = Arc::new(intake);
    let client_arc: Arc<dyn SolanaClient> = Arc::new(RpcSolanaClient::new(args.rpc_url.clone()));
    let mut service = FundingService::new(
        FundingServiceConfig {
            rounds: FundingRoundConfig {
                round_slots: args.round_slots,
                min_round_size: args.min_round_size,
                denomination: Some(args.denomination),
                lookup_tables: luts.to_vec(),
            },
            poll_interval: Duration::from_millis(250),
        },
        RelaySet::single(clone_keypair(relay)),
        intake,
        client_arc,
    )?;

    // Land every request inside one round window, and only then work out which
    // one the release order puts second.
    let slot = client.get_slot().await?;
    let round = slot / args.round_slots;
    // Start at the beginning of the NEXT window so the whole batch is certain to
    // share a round.
    let window_start = (round + 1) * args.round_slots;
    wait_until_slot(client, window_start).await?;
    for (i, path, _) in &requests {
        std::fs::copy(path, inbox2.join(format!("request2-{i}.json")))?;
    }
    let tick = service.tick().await?;
    if tick.ingested.len() != requests.len() {
        bail!(
            "expected {} ingested requests, got {}",
            requests.len(),
            tick.ingested.len()
        );
    }
    let round = tick.ingested[0].1;
    let order = service.rounds().release_order(round);
    if order.len() < 2 {
        bail!("the failure case needs a round of at least 2");
    }
    // `release_order` indexes the round's requests in ARRIVAL order, and the
    // intake hands them over sorted by file name, which is request2-0..N.
    let poisoned_arrival_index = order[1];
    let (poisoned_participant, poisoned_emit, poisoned_wallet) = &requests[poisoned_arrival_index];
    let survivor_arrival_index = order[0];
    let survivor_wallet = requests[survivor_arrival_index].2;

    // Spend the poisoned request's nullifiers out of band. This funds its wallet
    // early (harmless) and guarantees its in-round submit fails.
    let poisoned_request = emit_to_request(poisoned_emit, program_id)?;
    let out_of_band = submit_transact_with_luts(client, relay, &poisoned_request, &[], luts)
        .await
        .context("submitting the poisoned request out of band")?;
    report.sig("out_of_band_spend", out_of_band.to_string());

    // Drive slots to the boundary and catch the failure.
    let mut failure: Option<String> = None;
    let deadline = std::time::Instant::now() + Duration::from_secs(180);
    while failure.is_none() {
        if std::time::Instant::now() > deadline {
            bail!("timed out waiting for the poisoned round to release");
        }
        let tick = service.tick().await?;
        if let Some(err) = tick.release_error {
            failure = Some(err);
            break;
        }
        if tick
            .outcomes
            .iter()
            .any(|o| matches!(o, RoundOutcome::Released { .. }))
        {
            bail!("the poisoned round released cleanly; the out-of-band spend did not take");
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let failure = failure.expect("checked above");

    let requeued = service.rounds().len(round + 1);
    report.check(
        "a mid-round submit failure RE-QUEUES the remainder instead of dropping it",
        requeued == requests.len() - 1 && failure.contains("funding withdrawal in round"),
        format!(
            "the submit at release position 1 failed ({}), and {requeued} of {} withdrawals \
             moved into round {}",
            first_line(&failure),
            requests.len(),
            round + 1
        ),
    );
    report.check(
        "the withdrawal released BEFORE the failure still landed (partial release, honestly reported)",
        lamports(client, &survivor_wallet).await? == args.denomination,
        format!(
            "release position 0 ({survivor_wallet}) is funded; the poisoned request at \
             position 1 belonged to participant {poisoned_participant} (wallet \
             {poisoned_wallet})"
        ),
    );
    report.note(
        "the re-queued remainder keeps the FAILING request with it, so the same request \
         fails again in the next round it lands in, releasing only the withdrawals ordered \
         before it. The good requests still drain (the failing one drifts through the \
         deterministic order), but a permanently-invalid request degrades round throughput \
         until an operator removes it. FundingRounds has no quarantine policy for that today.",
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

/// Replay one round through a fresh [`FundingRounds`] and report the wallet
/// sequence it would release, optionally feeding the requests in REVERSED
/// arrival order. Two runs that differ only in arrival order must produce the
/// same sequence; that is what "arrival-independent" means operationally.
fn probe_release_order(
    intake_dir: &Path,
    participants: &[Participant],
    program_id: &Pubkey,
    tx_profile: TxProfile,
    args: &Args,
    round: u64,
    reversed: bool,
) -> Result<Vec<Pubkey>> {
    // Release-ORDER simulation only: it never submits, so it needs no lookup
    // tables.
    let mut probe = FundingRounds::new(FundingRoundConfig {
        round_slots: args.round_slots,
        min_round_size: args.min_round_size,
        denomination: Some(args.denomination),
        lookup_tables: Vec::new(),
    })?;
    let mut order: Vec<&Participant> = participants.iter().collect();
    if reversed {
        order.reverse();
    }
    let mut wallets = Vec::with_capacity(order.len());
    for p in order {
        let emit = inbox_or_accepted(intake_dir, p.index)?;
        let request = FundingRequest::from_emit_json(&emit, program_id, tx_profile)?;
        wallets.push(request.commit_wallet);
        probe.accept(round * args.round_slots, request)?;
    }
    Ok(probe
        .release_order(round)
        .into_iter()
        .map(|i| wallets[i])
        .collect())
}

fn short(keys: &[Pubkey]) -> Vec<String> {
    keys.iter()
        .map(|k| k.to_string().chars().take(6).collect())
        .collect()
}

/// An emit may be in the inbox (not yet ingested) or in accepted/ (already
/// batched); read it from wherever it is.
fn inbox_or_accepted(intake_dir: &Path, index: usize) -> Result<serde_json::Value> {
    let name = format!("request-{index}.json");
    for sub in ["accepted", "inbox"] {
        let path = intake_dir.join(sub).join(&name);
        if path.exists() {
            return emit_json(&path);
        }
    }
    bail!("no emit named {name} under {}", intake_dir.display())
}

/// Build a coordinator submit request straight from a `mirror-cli` emit.
fn emit_to_request(path: &Path, program_id: &Pubkey) -> Result<ValueTransactRequest> {
    let json = emit_json(path)?;
    let transact_data = hex_decode(
        json["transact_data_hex"]
            .as_str()
            .ok_or_else(|| anyhow!("emit missing transact_data_hex"))?,
    )?;
    let accounts = json["accounts"]
        .as_array()
        .ok_or_else(|| anyhow!("emit missing accounts"))?
        .iter()
        .map(|a| {
            Ok(AccountMeta {
                pubkey: Pubkey::from_str(
                    a["pubkey"].as_str().ok_or_else(|| anyhow!("no pubkey"))?,
                )?,
                is_signer: a["is_signer"].as_bool().unwrap_or(false),
                is_writable: a["is_writable"].as_bool().unwrap_or(false),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(ValueTransactRequest {
        program_id: *program_id,
        transact_data,
        accounts,
        tx_profile: TxProfile::default(),
    })
}

/// Rewrite an emit's `publicAmount` to withdraw `amount` instead. This is the
/// hostile-participant case: the proof no longer matches, so the transaction
/// would fail on-chain anyway. The point of the assertion is that the
/// coordinator refuses it BEFORE it costs a relay signature.
fn doctor_public_amount(emit: &serde_json::Value, amount: u64) -> Result<serde_json::Value> {
    use mirror_core::note::{public_amount, SignedAmount};
    let mut emit = emit.clone();
    let mut data = hex_decode(
        emit["transact_data_hex"]
            .as_str()
            .ok_or_else(|| anyhow!("emit missing transact_data_hex"))?,
    )?;
    let start = 1 + mirror_core::wire::TRANSACT_PUBLIC_AMOUNT_OFF;
    let pa = public_amount(SignedAmount::Withdraw(amount));
    data.get_mut(start..start + 32)
        .ok_or_else(|| anyhow!("emit transact_data is too short to doctor"))?
        .copy_from_slice(&pa);
    emit["transact_data_hex"] =
        serde_json::json!(data.iter().map(|b| format!("{b:02x}")).collect::<String>());
    Ok(emit)
}

// ---------------------------------------------------------------------------
// docs/PROOF.md
// ---------------------------------------------------------------------------

/// Append (idempotently) a "Funding-round soak" section to docs/PROOF.md,
/// preserving every section above it.
#[allow(clippy::too_many_arguments)]
fn append_proof_md(
    root: &Path,
    args: &Args,
    program_id: &Pubkey,
    relay: &Pubkey,
    vpool: &Pubkey,
    vault: &Pubkey,
    pool: &Pubkey,
    round: u64,
    release_slot: u64,
    cu: &[(String, Option<u64>)],
    report: &Report,
) -> Result<()> {
    use std::fmt::Write;
    const MARKER: &str = "<!-- funding-round-soak:begin -->";

    let (mut s, now) = begin_proof_section(root, MARKER)?;
    s.push_str(
        r##"## Funding-round soak

This section documents an automated end-to-end run of `mirror-soak-funding` against a
"##,
    );
    writeln!(
        s,
        "LIVE local Surfpool validator (a local mainnet mirror at `{}`), treated as mainnet and",
        args.rpc_url
    )?;
    s.push_str(
        r##"run honestly. It exercises the FUNDING-PROVENANCE path through the shipped components:
`mirror-cli shield | scan | fund-commit` on the participant side, and
`mirror_coordinator::FundingService` + `DirectoryIntake` on the coordinator side, which
polls the real chain slot, ingests the emitted requests, batches them into slot rounds,
and releases each round through the gasless relay. The signatures below are
local-validator signatures, reproducible by re-running the soak against a fresh Surfpool,
not lookups on a public explorer.

"##,
    );
    writeln!(s, "- generated: unix {now}")?;
    writeln!(s, "- program id (fresh deploy): `{program_id}`")?;
    writeln!(
        s,
        "- funding ValuePool: `{vpool}` (authority / relay `{relay}`), vault `{vault}`"
    )?;
    writeln!(s, "- behavioral Pool: `{pool}`")?;
    writeln!(
        s,
        "- denomination: {} lamports (every shield and every funding withdrawal moves exactly this)",
        args.denomination
    )?;
    writeln!(
        s,
        "- round: {} slots, `min_round_size` {}, {} participants; the released round was {round} at slot {release_slot}",
        args.round_slots, args.min_round_size, args.participants
    )?;
    writeln!(s)?;

    s.push_str(
        r##"### What was exercised

1. **Setup** - a denominated funding `ValuePool` plus the behavioral `Pool` a funded
   commit wallet participates in.
2. **Shield** - every participant shields exactly the denomination from their OWN main
   wallet, then `scan`s the on-chain `enc` blobs to recover a spendable note.
3. **Request** - `fund-commit` mints a FRESH commit-wallet keypair and emits its
   relay-only-signed unshield into the coordinator's inbox directory.
4. **Thin round** - a round below `min_round_size` rolls forward, and nothing reaches
   the chain while it is thin.
5. **Release** - the merged round releases at its boundary; each fresh commit wallet is
   credited exactly the denomination and the vault is debited by exactly the sum.
6. **Provenance** - every funding transaction carries exactly one signature (the
   relay's), mentions no participant main wallet, and each fresh commit wallet's ONLY
   inbound transfer across its entire on-chain history is from the pool vault.
7. **Participation** - a funded commit wallet then commits to the behavioral pool,
   paying its own fee out of the pool-funded balance.
8. **Adversarial** - a wrong-amount request is refused client-side by the CLI and
   coordinator-side at the intake, and a live mid-round submit failure re-queues the
   remainder instead of dropping it.

What this does NOT claim: the shield leg is still the participant's own transaction from
their own wallet, and both boundary crossings expose an amount and a slot. The funding
edge is not erased, it is turned into a matching problem; the residual is measured in
`docs/EFFECTIVE_K.md`, not assumed away.

"##,
    );

    checks_table(&mut s, report, "###");

    if !report.notes.is_empty() {
        writeln!(s, "### Honest notes from this run")?;
        writeln!(s)?;
        for note in &report.notes {
            writeln!(s, "- {note}")?;
        }
        writeln!(s)?;
    }

    sigs_table(&mut s, report, "###");

    s.push_str(
        r##"### Compute units (the released funding withdrawals)

| signature | compute units |
| --- | --- |
"##,
    );
    for (sig, units) in cu {
        writeln!(
            s,
            "| `{sig}` | {} |",
            units
                .map(|u| u.to_string())
                .unwrap_or_else(|| "not reported".to_string())
        )?;
    }
    writeln!(s)?;

    writeln!(s, "### Reproduce")?;
    writeln!(s)?;
    writeln!(
        s,
        "With a local Surfpool running at `{}` (treated as mainnet). That endpoint is whatever",
        args.rpc_url
    )?;
    s.push_str(
        r##"`--rpc-url` was given for this run; `surfpool start --no-tui` listens on port 8899 by
default, and any other port here simply means the run was pointed at one.

```sh
# 1. build the on-chain program + host workspace
cargo build-sbf --manifest-path programs/mirror-pool/Cargo.toml
cargo build --workspace

# 2. deploy the program under a FRESH program id
solana-keygen new -o .soak/keys/funding-program.json
solana program deploy \
"##,
    );
    writeln!(s, "  --url {} \\", args.rpc_url)?;
    s.push_str(
        r##"  --program-id .soak/keys/funding-program.json \
  programs/mirror-pool/target/deploy/mirror_pool.so

# 3. build the transaction-circuit artifacts (bash circuits/build_transaction.sh)

# 4. run the funding-round soak
cargo run -p mirror-soak --bin mirror-soak-funding -- \
"##,
    );
    writeln!(s, "  --rpc-url {} \\", args.rpc_url)?;
    writeln!(s, "  --program-id {program_id}")?;
    s.push_str(
        r##"```

Every run creates a fresh pool, fresh main wallets, and fresh commit wallets, so the run
is self-contained and repeatable; the signatures above are from this run.
"##,
    );

    std::fs::write(root.join("docs/PROOF.md"), s)?;
    Ok(())
}
