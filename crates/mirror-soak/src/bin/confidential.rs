//! mirror-soak-value: the confidential-VALUE end-to-end soak.
//!
//! This is the value-carrying counterpart to `mirror-soak` (the behavioral soak).
//! It drives the 2-in/2-out JoinSplit `Transact` layer (shield / transfer /
//! unshield) against a LIVE local Surfpool validator (treated as a mainnet
//! mirror), using the REAL shipped components:
//!
//! - the participant CLI (`mirror-cli value-keygen | init-value-pool | shield |
//!   transfer | unshield | scan`) for keygen, pool creation, and off-chain
//!   Groth16 proving (in-process, pure Rust via ark-circom/ark-groth16; the
//!   `--snarkjs` path below is only used when `--use-snarkjs` is passed), which
//!   EMITS each `Transact` bundle; and
//! - the gasless coordinator (`mirror_coordinator::submit_transact`) for the
//!   gasless relay submit (transfer/unshield are relay-only signed; a shield is
//!   co-signed by the depositor who funds the deposit).
//!
//! It verifies every effect on-chain and proves the headline claim: mirror-pool
//! hides both WHO initiated an action (the gasless relay is the only signer for a
//! transfer/unshield) AND HOW MUCH moved (a transfer carries `publicAmount == 0`;
//! amounts live only in commitments + ciphertext). What it exercises:
//!
//! 1. **Setup** - airdrop a relay/authority + payer + depositor; `InitValuePool`
//!    a main pool (nonzero fee) and a second pool with a fixed `denomination`.
//! 2. **Shield** - Alice `value-keygen`; shield Alice->Alice for `v`; submit
//!    co-signed by the depositor. Verify: vault credited by `v`, value root
//!    advanced, both output commitments inserted, both input nullifier PDAs
//!    created. A replay is rejected (`NullifierSpent`).
//! 3. **Scan + private transfer** - Alice `scan`s the emitted `enc` blobs against
//!    the on-chain leaves to recover a spendable note; `transfer` Alice->Bob for a
//!    HIDDEN amount (`publicAmount == 0`), submitted relay-only. Verify: root
//!    advanced, new nullifier PDAs created, and the on-chain Transact carries NO
//!    cleartext amount. A mutated public input is rejected
//!    (`ProofVerificationFailed`).
//! 4. **Unshield** - Bob `scan`s -> recovers his note; `unshield` Bob->a FRESH
//!    recipient for `w`, submitted relay-only. Verify: the fresh recipient is
//!    credited by `w`, the vault is debited by `w`, and the nullifier PDA exists.
//! 5. **Fixed-denom** - a shield of exactly the denomination succeeds; a Transact
//!    whose public deposit magnitude differs is rejected (`DenominationMismatch`),
//!    both on-chain and (fail-fast) client-side in the CLI.
//! 6. **Conservation** - the vault balance equals the net public deposit minus the
//!    net public withdrawal (a transfer moves no public lamports).

use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;

use mirror_coordinator::client::{RpcSolanaClient, SolanaClient};
use mirror_coordinator::{submit_transact, TxProfile, ValueTransactRequest};
use mirror_soak::{
    begin_proof_section, ceremony_head_key, checks_table, cli_bin, first_line, fund, hex_decode,
    install_vk, is_custom, lamports, new_keypair, note_is_spendable, parse_kv, read_vpool,
    repo_root, run_cli, run_cli_expect_fail, sigs_table, value_nullifier_pda, value_pool_pda,
    value_vault_pda, which, write_lines, write_report_json, Report, DEFAULT_RPC_URL,
    SYSTEM_PROGRAM_ID,
};

use solana_instruction::AccountMeta;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;

// ---------------------------------------------------------------------------
// Instruction discriminators + error codes this soak asserts on.
// ---------------------------------------------------------------------------

/// A circuit's write-once, digest-pinned verifying-key registry seed prefix.
const VK_REGISTRY_SEED: &[u8] = b"vk";
/// The Transact instruction discriminator (see `wire::tag::TRANSACT`).
const TAG_TRANSACT: u8 = 7;

// Program error codes (see `MirrorPoolError`), surfaced as `custom program error`.
const ERR_NULLIFIER_SPENT: u32 = 3;
const ERR_PROOF_FAILED: u32 = 12;
const ERR_DENOMINATION_MISMATCH: u32 = 23;

// ---------------------------------------------------------------------------
// CLI args
// ---------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(
    name = "mirror-soak-value",
    about = "Confidential-value (JoinSplit) end-to-end Surfpool soak: shield/transfer/unshield, fixed-denom, adversarial, on-chain verification"
)]
struct Args {
    /// RPC endpoint (default: the running local Surfpool).
    #[arg(long, default_value = DEFAULT_RPC_URL)]
    rpc_url: String,
    /// mirror-pool program id (base58). REQUIRED: use the freshly-deployed id.
    #[arg(long)]
    program_id: String,
    /// Relay fee (lamports) bound into every Transact's ext-data (nonzero).
    #[arg(long, default_value_t = 5_000)]
    fee: u64,
    /// Shield amount into the main pool (lamports).
    #[arg(long, default_value_t = 500_000_000)]
    shield_amount: u64,
    /// Hidden transfer amount Alice -> Bob (lamports).
    #[arg(long, default_value_t = 200_000_000)]
    transfer_amount: u64,
    /// Fixed denomination for the second pool (lamports).
    #[arg(long, default_value_t = 100_000_000)]
    denomination: u64,
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Environment helpers
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// ValuePool decoder (byte-identical to `state::value_pool`)
// ---------------------------------------------------------------------------

async fn nullifier_pda_created(
    client: &dyn SolanaClient,
    program_id: &Pubkey,
    pda: &Pubkey,
) -> Result<bool> {
    Ok(client
        .get_account(pda)
        .await?
        .map(|a| a.owner == *program_id && a.data.first() == Some(&1u8))
        .unwrap_or(false))
}

// ---------------------------------------------------------------------------
// Emit -> ValueTransactRequest
// ---------------------------------------------------------------------------

/// The subset of a `mirror-cli` Transact emit the soak consumes.
struct Emit {
    json: serde_json::Value,
}

impl Emit {
    fn load(path: &Path) -> Result<Emit> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading emit {}", path.display()))?;
        Ok(Emit {
            json: serde_json::from_str(&raw).context("parsing emit json")?,
        })
    }
    fn s(&self, key: &str) -> Result<String> {
        self.json[key]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow!("emit missing string field `{key}`"))
    }
    /// Build the coordinator submit request from the emit's data + account list.
    fn request(&self, program_id: &Pubkey) -> Result<ValueTransactRequest> {
        let transact_data = hex_decode(&self.s("transact_data_hex")?)?;
        let accounts = self
            .json
            .get("accounts")
            .and_then(|a| a.as_array())
            .ok_or_else(|| anyhow!("emit missing `accounts` array"))?
            .iter()
            .map(|a| {
                let pubkey = Pubkey::from_str(
                    a["pubkey"]
                        .as_str()
                        .ok_or_else(|| anyhow!("account missing pubkey"))?,
                )?;
                let is_signer = a["is_signer"].as_bool().unwrap_or(false);
                let is_writable = a["is_writable"].as_bool().unwrap_or(false);
                Ok(AccountMeta {
                    pubkey,
                    is_signer,
                    is_writable,
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
}

/// Submit a request through the gasless coordinator, returning the signature
/// string on success or the rendered error string on failure.
async fn submit(
    client: &dyn SolanaClient,
    relay: &Keypair,
    req: &ValueTransactRequest,
    extra: &[&Keypair],
) -> std::result::Result<String, String> {
    submit_transact(client, relay, req, extra)
        .await
        .map(|s| s.to_string())
        .map_err(|e| format!("{e:#}"))
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let args = Args::parse();
    let program_id =
        Pubkey::from_str(&args.program_id).map_err(|e| anyhow!("invalid --program-id: {e}"))?;

    let root = repo_root()?;
    let keys_dir = root.join(".soak/keys");
    let notes_dir = root.join(".soak/notes-value");
    let work_dir = root.join(".soak/value");
    std::fs::create_dir_all(&keys_dir)?;
    std::fs::create_dir_all(&notes_dir)?;
    std::fs::create_dir_all(&work_dir)?;

    let cli = cli_bin()?;
    let snarkjs = which("snarkjs").unwrap_or_else(|| "snarkjs".to_string());
    let wasm = root.join("circuits/transaction_js/transaction.wasm");
    let r1cs = root.join("circuits/transaction.r1cs");
    let vk = root.join("circuits/artifacts/transaction_verification_key.json");
    // The DEPLOYED JoinSplit verifying key is a phase-2 ceremony output, so the
    // soak proves under the ceremony proving key. A proof made under the
    // `circuits/transaction_final.zkey` dev key is well-formed and would be
    // rejected on chain.
    let proving_key = ceremony_head_key(&root, "transaction")?;
    let wasm_s = wasm.to_string_lossy().to_string();
    let pk_s = proving_key.to_string_lossy().to_string();
    let vk_s = vk.to_string_lossy().to_string();
    for (label, p) in [("wasm", &wasm), ("r1cs", &r1cs), ("vk", &vk)] {
        if !p.exists() {
            bail!(
                "confidential circuit artifact missing: {label} at {} (build with `bash circuits/build_transaction.sh`)",
                p.display()
            );
        }
    }

    println!("mirror-soak-value: confidential-value end-to-end soak against Surfpool");
    println!("  rpc:      {}", args.rpc_url);
    println!("  program:  {program_id}");
    // Passed through to the CLI but only consulted if `--use-snarkjs` is set;
    // proving is in-process pure Rust by default.
    println!("  snarkjs:  {snarkjs} (legacy fallback only; proving is in-process)");
    println!(
        "  amounts:  shield={} transfer={} denomination={} fee={}",
        args.shield_amount, args.transfer_amount, args.denomination, args.fee
    );
    println!();

    let client: Arc<dyn SolanaClient> = Arc::new(RpcSolanaClient::new(args.rpc_url.clone()));
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

    let relay = new_keypair(&keys_dir, "value-relay")?; // main pool authority + relay
    let relay2 = new_keypair(&keys_dir, "value-relay2")?; // fixed-denom pool authority
    let payer = new_keypair(&keys_dir, "value-payer")?; // funds init rent
    let depositor = new_keypair(&keys_dir, "value-depositor")?; // funds + co-signs shields
    fund(&args.rpc_url, &relay.pubkey(), 100, 60_000_000)?;
    fund(&args.rpc_url, &relay2.pubkey(), 100, 40_000_000)?;
    fund(&args.rpc_url, &payer.pubkey(), 100, 40_000_000)?;
    fund(&args.rpc_url, &depositor.pubkey(), 10, 200_000_000)?;

    let payer_path = keys_dir.join("value-payer.json");
    let relay_path = keys_dir.join("value-relay.json");
    let relay2_path = keys_dir.join("value-relay2.json");
    let depositor_path = keys_dir.join("value-depositor.json");

    // Publish the JoinSplit verifying key into its write-once registry PDA.
    // TRANSACT reads its key from that account rather than from the program's
    // code, and re-checks it against a compile-time digest on every verify, so a
    // fresh deployment must publish it once before any shield/transfer/unshield
    // can land. See docs/VK_REGISTRY.md.
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
        format!("init_vk signature={vk_sig}"),
    );
    report.sig("init_vk_transaction", &vk_sig);

    let vpool = value_pool_pda(&program_id, &relay.pubkey());
    let vault = value_vault_pda(&program_id, &vpool);
    let vpool2 = value_pool_pda(&program_id, &relay2.pubkey());
    let vault2 = value_vault_pda(&program_id, &vpool2);

    // Main pool (no denomination, nonzero fee).
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
        ],
    )?;
    report.sig(
        "init_value_pool_main",
        parse_kv(&out, "signature:").unwrap_or_default(),
    );
    let mv = read_vpool(client.as_ref(), &vpool).await?;
    report.check(
        "main ValuePool initialized (authority=relay, fee set, no denom)",
        mv.authority == relay.pubkey().to_bytes()
            && mv.fee == args.fee
            && mv.denomination.is_none()
            && mv.commitment_count == 0,
        format!(
            "vpool={vpool} vault={vault} fee={} denom={:?} cc={}",
            mv.fee, mv.denomination, mv.commitment_count
        ),
    );

    // Fixed-denomination pool (nonzero fee + a pinned denomination).
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
            &relay2_path.to_string_lossy(),
            "--payer",
            &payer_path.to_string_lossy(),
            "--fee",
            &args.fee.to_string(),
            "--denomination",
            &args.denomination.to_string(),
        ],
    )?;
    report.sig(
        "init_value_pool_denom",
        parse_kv(&out, "signature:").unwrap_or_default(),
    );
    let dv = read_vpool(client.as_ref(), &vpool2).await?;
    report.check(
        "fixed-denom ValuePool initialized (denomination pinned)",
        dv.authority == relay2.pubkey().to_bytes() && dv.denomination == Some(args.denomination),
        format!("vpool={vpool2} vault={vault2} denom={:?}", dv.denomination),
    );

    let vault_baseline = lamports(client.as_ref(), &vault).await?;
    println!("  main vpool: {vpool}");
    println!("  main vault: {vault} (baseline rent {vault_baseline} lamports)");
    println!("  denom vpool: {vpool2}");
    println!();

    // Alice + Bob confidential wallets (value spend key + X25519 viewing key).
    let alice_key = notes_dir.join("alice-key.json");
    let bob_key = notes_dir.join("bob-key.json");
    let out = run_cli(
        &cli,
        &root,
        &[
            "value-keygen",
            "--seed",
            "mirror-value-soak-alice",
            "--out",
            &alice_key.to_string_lossy(),
        ],
    )?;
    let alice_addr = parse_kv(&out, "address:").ok_or_else(|| anyhow!("no Alice address"))?;
    let out = run_cli(
        &cli,
        &root,
        &[
            "value-keygen",
            "--seed",
            "mirror-value-soak-bob",
            "--out",
            &bob_key.to_string_lossy(),
        ],
    )?;
    let bob_addr = parse_kv(&out, "address:").ok_or_else(|| anyhow!("no Bob address"))?;

    // Ordered on-chain leaves + enc blobs the wallets scan (Surfpool has no
    // history and the relay does not index, so the soak accumulates them from the
    // emits, in on-chain insertion order).
    let mut leaves: Vec<String> = Vec::new();
    let mut blobs: Vec<String> = Vec::new();
    let leaves_path = work_dir.join("leaves.txt");
    let blobs_path = work_dir.join("blobs.txt");

    // -- 2. SHIELD ----------------------------------------------------------
    println!("== 2. shield (Alice -> Alice, deposit) ==");
    let shield_emit_path = work_dir.join("shield-emit.json");
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
            &depositor_path.to_string_lossy(),
            "--to",
            &alice_addr,
            "--amount",
            &args.shield_amount.to_string(),
            "--note-dir",
            &notes_dir.to_string_lossy(),
            "--wasm",
            &wasm_s,
            "--proving-key",
            &pk_s,
            "--vk",
            &vk_s,
            "--snarkjs",
            &snarkjs,
            "--out",
            &shield_emit_path.to_string_lossy(),
        ],
    )?;
    let shield = Emit::load(&shield_emit_path)?;
    report.check(
        "shield proof generated + verified (in-process ark-groth16) and emitted",
        true,
        "mirror-cli shield produced a Transact whose proof it generated and verified in-process",
    );

    let before = read_vpool(client.as_ref(), &vpool).await?;
    let shield_req = shield.request(&program_id)?;
    let shield_sig = submit(client.as_ref(), &relay, &shield_req, &[&depositor])
        .await
        .map_err(|e| anyhow!("shield submit failed: {e}"))?;
    report.sig("shield", &shield_sig);

    let after = read_vpool(client.as_ref(), &vpool).await?;
    let vault_after_shield = lamports(client.as_ref(), &vault).await?;
    report.check(
        "vault credited by the shielded deposit amount",
        vault_after_shield - vault_baseline == args.shield_amount,
        format!(
            "vault delta {} lamports (= shield {})",
            vault_after_shield - vault_baseline,
            args.shield_amount
        ),
    );
    report.check(
        "value root advanced + both output commitments inserted",
        after.commitment_count == before.commitment_count + 2
            && after.current_root != before.current_root,
        format!(
            "commitment_count {}->{}, root changed",
            before.commitment_count, after.commitment_count
        ),
    );
    let sh_nf0 = Pubkey::from_str(&shield.s("nullifier0_pda")?)?;
    let sh_nf1 = Pubkey::from_str(&shield.s("nullifier1_pda")?)?;
    let sh_nf0_ok = nullifier_pda_created(client.as_ref(), &program_id, &sh_nf0).await?;
    let sh_nf1_ok = nullifier_pda_created(client.as_ref(), &program_id, &sh_nf1).await?;
    report.check(
        "both input nullifier PDAs created (anti-replay)",
        sh_nf0_ok && sh_nf1_ok,
        format!("nf0={sh_nf0} nf1={sh_nf1} both program-owned + spent"),
    );
    // A shield is a public deposit: its magnitude is intentionally in cleartext.
    report.check(
        "shield publicAmount encodes the deposit magnitude (public deposit)",
        shield.s("public_amount_hex")? != "0".repeat(64),
        format!("publicAmount={}", shield.s("public_amount_hex")?),
    );

    // Adversarial: replay the shield -> its dummy nullifiers are already spent.
    let replay = submit(client.as_ref(), &relay, &shield_req, &[&depositor]).await;
    report.check(
        "shield replay rejected (NullifierSpent)",
        replay
            .as_ref()
            .err()
            .map(|e| is_custom(e, ERR_NULLIFIER_SPENT))
            .unwrap_or(false),
        match &replay {
            Ok(s) => format!("UNEXPECTED success: {s}"),
            Err(e) => first_line(e),
        },
    );

    // Record the two on-chain leaves + enc blobs (insertion order: out0, out1).
    leaves.push(shield.s("out_commitment0_hex")?);
    leaves.push(shield.s("out_commitment1_hex")?);
    blobs.push(shield.s("enc0_hex")?);
    blobs.push(shield.s("enc1_hex")?);
    println!();

    // -- 3. SCAN + PRIVATE TRANSFER ----------------------------------------
    println!("== 3. scan + private transfer (Alice -> Bob, HIDDEN amount) ==");
    write_lines(&leaves_path, &leaves)?;
    write_lines(&blobs_path, &blobs)?;
    let scan_out = run_cli(
        &cli,
        &root,
        &[
            "scan",
            "--viewing-key",
            &alice_key.to_string_lossy(),
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
    // Alice's spendable note is the real (amount>0) output at leaf 0: its file is
    // named by its commitment (shield out_commitment0).
    let alice_note = notes_dir.join(format!("value-{}.json", shield.s("out_commitment0_hex")?));
    let alice_spendable = note_is_spendable(&alice_note)?;
    report.check(
        "Alice scan recovered a SPENDABLE note from the enc blobs",
        alice_spendable && scan_out.contains(&format!("amount={}", args.shield_amount)),
        format!(
            "recovered note {} (spendable={alice_spendable})",
            alice_note
                .strip_prefix(&root)
                .unwrap_or(&alice_note)
                .display()
        ),
    );

    let transfer_emit_path = work_dir.join("transfer-emit.json");
    run_cli(
        &cli,
        &root,
        &[
            "transfer",
            "--rpc-url",
            &args.rpc_url,
            "--program-id",
            &program_id.to_string(),
            "--pool",
            &vpool.to_string(),
            "--note",
            &alice_note.to_string_lossy(),
            "--to",
            &bob_addr,
            "--amount",
            &args.transfer_amount.to_string(),
            "--note-dir",
            &notes_dir.to_string_lossy(),
            "--wasm",
            &wasm_s,
            "--proving-key",
            &pk_s,
            "--vk",
            &vk_s,
            "--snarkjs",
            &snarkjs,
            "--out",
            &transfer_emit_path.to_string_lossy(),
        ],
    )?;
    let transfer = Emit::load(&transfer_emit_path)?;
    report.check(
        "transfer carries NO cleartext amount (publicAmount == 0)",
        transfer.s("public_amount_hex")? == "0".repeat(64),
        format!("publicAmount={}", transfer.s("public_amount_hex")?),
    );
    // The exact on-chain instruction bytes: publicAmount field (data[1..33]) must
    // be all-zero for a transfer; amounts live only in commitments + ciphertext.
    let transfer_req = transfer.request(&program_id)?;
    let pa_zero = transfer_req
        .transact_data
        .get(1..33)
        .map(|b| b.iter().all(|&x| x == 0))
        .unwrap_or(false);
    report.check(
        "on-chain Transact bytes carry a zeroed publicAmount for the transfer",
        pa_zero,
        "transact_data[1..33] (publicAmount) is 32 zero bytes",
    );

    // Adversarial: a mutated public input (flip a byte of outputCommitment[1])
    // must fail the Groth16 verification. Submit the mutated copy BEFORE the clean
    // one; the failed tx reverts atomically, so no nullifier is actually spent.
    let mut mutated_req = transfer.request(&program_id)?;
    // outputCommitment[1] lives at data offset 1 + 192 .. 1 + 224; flip its last
    // byte (keeps the field element canonical, well below r).
    let idx = 1 + 224 - 1;
    if let Some(b) = mutated_req.transact_data.get_mut(idx) {
        *b ^= 0x01;
    } else {
        bail!("transfer transact_data too short to mutate");
    }
    let mutated = submit(client.as_ref(), &relay, &mutated_req, &[]).await;
    report.check(
        "mutated public input rejected (ProofVerificationFailed)",
        mutated
            .as_ref()
            .err()
            .map(|e| is_custom(e, ERR_PROOF_FAILED))
            .unwrap_or(false),
        match &mutated {
            Ok(s) => format!("UNEXPECTED success: {s}"),
            Err(e) => first_line(e),
        },
    );

    // The clean transfer, submitted gasless (relay-only signer: unlinkability).
    let before = read_vpool(client.as_ref(), &vpool).await?;
    let vault_before_transfer = lamports(client.as_ref(), &vault).await?;
    let transfer_sig = submit(client.as_ref(), &relay, &transfer_req, &[])
        .await
        .map_err(|e| anyhow!("transfer submit failed: {e}"))?;
    report.sig("transfer", &transfer_sig);
    let after = read_vpool(client.as_ref(), &vpool).await?;
    let vault_after_transfer = lamports(client.as_ref(), &vault).await?;
    report.check(
        "transfer advanced the value root (2 new output commitments)",
        after.commitment_count == before.commitment_count + 2
            && after.current_root != before.current_root,
        format!(
            "commitment_count {}->{}, root changed",
            before.commitment_count, after.commitment_count
        ),
    );
    report.check(
        "transfer moved NO public lamports (vault unchanged)",
        vault_after_transfer == vault_before_transfer,
        format!("vault {vault_before_transfer} -> {vault_after_transfer}"),
    );
    let tr_nf0 = Pubkey::from_str(&transfer.s("nullifier0_pda")?)?;
    let tr_nf1 = Pubkey::from_str(&transfer.s("nullifier1_pda")?)?;
    let tr_nf0_ok = nullifier_pda_created(client.as_ref(), &program_id, &tr_nf0).await?;
    let tr_nf1_ok = nullifier_pda_created(client.as_ref(), &program_id, &tr_nf1).await?;
    report.check(
        "transfer created new nullifier PDAs (input note spent)",
        tr_nf0_ok && tr_nf1_ok,
        format!("nf0={tr_nf0} nf1={tr_nf1} both program-owned + spent"),
    );

    // Record the transfer's two leaves + enc blobs (out0 = change to Alice,
    // out1 = payment to Bob).
    leaves.push(transfer.s("out_commitment0_hex")?);
    leaves.push(transfer.s("out_commitment1_hex")?);
    blobs.push(transfer.s("enc0_hex")?);
    blobs.push(transfer.s("enc1_hex")?);
    println!();

    // -- 4. UNSHIELD --------------------------------------------------------
    println!("== 4. unshield (Bob -> fresh recipient, withdraw) ==");
    write_lines(&leaves_path, &leaves)?;
    write_lines(&blobs_path, &blobs)?;
    let scan_out = run_cli(
        &cli,
        &root,
        &[
            "scan",
            "--viewing-key",
            &bob_key.to_string_lossy(),
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
    let bob_note = notes_dir.join(format!("value-{}.json", transfer.s("out_commitment1_hex")?));
    let bob_spendable = note_is_spendable(&bob_note)?;
    report.check(
        "Bob scan auto-discovered his payment note (recipient-directed)",
        bob_spendable && scan_out.contains(&format!("amount={}", args.transfer_amount)),
        format!(
            "recovered note {} (spendable={bob_spendable})",
            bob_note.strip_prefix(&root).unwrap_or(&bob_note).display()
        ),
    );

    let fresh_recipient = new_keypair(&keys_dir, "value-fresh-recipient")?;
    let recip_before = lamports(client.as_ref(), &fresh_recipient.pubkey()).await?;
    let withdraw_amount = args.transfer_amount; // Bob withdraws his whole note.
    let unshield_emit_path = work_dir.join("unshield-emit.json");
    run_cli(
        &cli,
        &root,
        &[
            "unshield",
            "--rpc-url",
            &args.rpc_url,
            "--program-id",
            &program_id.to_string(),
            "--pool",
            &vpool.to_string(),
            "--note",
            &bob_note.to_string_lossy(),
            "--recipient",
            &fresh_recipient.pubkey().to_string(),
            "--amount",
            &withdraw_amount.to_string(),
            "--note-dir",
            &notes_dir.to_string_lossy(),
            "--wasm",
            &wasm_s,
            "--proving-key",
            &pk_s,
            "--vk",
            &vk_s,
            "--snarkjs",
            &snarkjs,
            "--out",
            &unshield_emit_path.to_string_lossy(),
        ],
    )?;
    let unshield = Emit::load(&unshield_emit_path)?;
    let before = read_vpool(client.as_ref(), &vpool).await?;
    let vault_before_unshield = lamports(client.as_ref(), &vault).await?;
    let unshield_req = unshield.request(&program_id)?;
    let unshield_sig = submit(client.as_ref(), &relay, &unshield_req, &[])
        .await
        .map_err(|e| anyhow!("unshield submit failed: {e}"))?;
    report.sig("unshield", &unshield_sig);

    let recip_after = lamports(client.as_ref(), &fresh_recipient.pubkey()).await?;
    let vault_after_unshield = lamports(client.as_ref(), &vault).await?;
    let after = read_vpool(client.as_ref(), &vpool).await?;
    report.check(
        "fresh recipient credited by the withdrawn amount",
        recip_after - recip_before == withdraw_amount,
        format!(
            "recipient {} credited {} lamports (= withdraw {})",
            fresh_recipient.pubkey(),
            recip_after - recip_before,
            withdraw_amount
        ),
    );
    report.check(
        "vault debited by exactly the withdrawn amount",
        vault_before_unshield - vault_after_unshield == withdraw_amount,
        format!(
            "vault debited {} lamports",
            vault_before_unshield - vault_after_unshield
        ),
    );
    report.check(
        "unshield advanced the value root",
        after.commitment_count == before.commitment_count + 2
            && after.current_root != before.current_root,
        format!(
            "commitment_count {}->{}, root changed",
            before.commitment_count, after.commitment_count
        ),
    );
    let un_nf0 = Pubkey::from_str(&unshield.s("nullifier0_pda")?)?;
    let un_nf0_ok = nullifier_pda_created(client.as_ref(), &program_id, &un_nf0).await?;
    report.check(
        "unshield created the input nullifier PDA (anti-replay)",
        un_nf0_ok,
        format!("nf0={un_nf0} program-owned + spent"),
    );
    println!();

    // -- 5. FIXED-DENOMINATION ---------------------------------------------
    println!("== 5. fixed-denomination pool ==");
    // Happy path: a shield of EXACTLY the denomination succeeds.
    let denom_shield_emit_path = work_dir.join("denom-shield-emit.json");
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
            &vpool2.to_string(),
            "--depositor",
            &depositor_path.to_string_lossy(),
            "--to",
            &alice_addr,
            "--amount",
            &args.denomination.to_string(),
            "--note-dir",
            &notes_dir.to_string_lossy(),
            "--wasm",
            &wasm_s,
            "--proving-key",
            &pk_s,
            "--vk",
            &vk_s,
            "--snarkjs",
            &snarkjs,
            "--out",
            &denom_shield_emit_path.to_string_lossy(),
        ],
    )?;
    let denom_shield = Emit::load(&denom_shield_emit_path)?;
    let before = read_vpool(client.as_ref(), &vpool2).await?;
    let vault2_before = lamports(client.as_ref(), &vault2).await?;
    let denom_req = denom_shield.request(&program_id)?;
    let denom_sig = submit(client.as_ref(), &relay2, &denom_req, &[&depositor])
        .await
        .map_err(|e| anyhow!("denom shield submit failed: {e}"))?;
    report.sig("denom_shield_exact", &denom_sig);
    let after = read_vpool(client.as_ref(), &vpool2).await?;
    let vault2_after = lamports(client.as_ref(), &vault2).await?;
    report.check(
        "fixed-denom shield of EXACTLY the denomination succeeds",
        vault2_after - vault2_before == args.denomination
            && after.commitment_count == before.commitment_count + 2,
        format!(
            "vault2 credited {} lamports (= denomination {})",
            vault2_after - vault2_before,
            args.denomination
        ),
    );

    // On-chain rejection: a Transact whose public deposit magnitude differs from
    // the pinned denomination. The on-chain denomination check runs BEFORE the
    // ext-data and Groth16 checks, so a placeholder proof still reaches (and is
    // rejected by) the denomination guard - the honest way to exercise it.
    let wrong_amount = args.denomination + 1;
    let dpool = read_vpool(client.as_ref(), &vpool2).await?;
    let mismatch_req = build_denom_mismatch_transact(
        &program_id,
        &vpool2,
        &vault2,
        &relay2.pubkey(),
        dpool.fee,
        &dpool.current_root,
        wrong_amount,
    );
    let mismatch = submit(client.as_ref(), &relay2, &mismatch_req, &[]).await;
    report.check(
        "on-chain: wrong-denomination deposit rejected (DenominationMismatch)",
        mismatch
            .as_ref()
            .err()
            .map(|e| is_custom(e, ERR_DENOMINATION_MISMATCH))
            .unwrap_or(false),
        match &mismatch {
            Ok(s) => format!("UNEXPECTED success: {s}"),
            Err(e) => first_line(e),
        },
    );

    // Fail-fast: the shipped CLI also refuses a wrong-denomination shield client
    // side (before spending any time proving).
    let cli_fail = run_cli_expect_fail(
        &cli,
        &root,
        &[
            "shield",
            "--rpc-url",
            &args.rpc_url,
            "--program-id",
            &program_id.to_string(),
            "--pool",
            &vpool2.to_string(),
            "--depositor",
            &depositor_path.to_string_lossy(),
            "--to",
            &alice_addr,
            "--amount",
            &wrong_amount.to_string(),
            "--note-dir",
            &notes_dir.to_string_lossy(),
            "--wasm",
            &wasm_s,
            "--proving-key",
            &pk_s,
            "--vk",
            &vk_s,
            "--snarkjs",
            &snarkjs,
        ],
    );
    report.check(
        "CLI fail-fast: wrong-denomination shield refused client-side",
        cli_fail
            .as_ref()
            .map(|e| e.to_lowercase().contains("denomination"))
            .unwrap_or(false),
        match &cli_fail {
            Ok(e) => first_line(e),
            Err(e) => format!("UNEXPECTED: {}", first_line(&e.to_string())),
        },
    );
    println!();

    // -- 6. VALUE CONSERVATION ---------------------------------------------
    println!("== 6. value conservation ==");
    let vault_final = lamports(client.as_ref(), &vault).await?;
    let net = args.shield_amount - withdraw_amount; // transfer moves no public value
    report.check(
        "main vault balance == net public deposit - net public withdrawal",
        vault_final == vault_baseline + net,
        format!(
            "vault {vault_final} == baseline {vault_baseline} + (shield {} - withdraw {}) = {}",
            args.shield_amount,
            withdraw_amount,
            vault_baseline + net
        ),
    );
    println!();

    // -- SUMMARY + PROOF.md -------------------------------------------------
    println!("== summary ==");
    let passed = report.checks.iter().filter(|(_, p, _)| *p).count();
    let total = report.checks.len();
    println!("  {passed}/{total} on-chain assertions passed");
    println!("  {} captured transaction signatures", report.sigs.len());

    // The public-devnet path emits JSON and leaves docs/PROOF.md alone (the
    // caller stitches the run in, preserving the committed Surfpool proof);
    // otherwise append the confidential section to PROOF.md as before.
    if let Ok(json_path) = std::env::var("MIRROR_PROOF_JSON") {
        let meta = serde_json::json!({
            "suite": "confidential",
            "rpc_url": args.rpc_url,
            "program_id": program_id.to_string(),
            "relay": relay.pubkey().to_string(),
            "vpool_main": vpool.to_string(),
            "vault_main": vault.to_string(),
            "vpool_denom": vpool2.to_string(),
            "fee": args.fee,
            "shield_amount": args.shield_amount,
            "transfer_amount": args.transfer_amount,
            "denomination": args.denomination,
        });
        write_report_json(&json_path, meta, &report)?;
        println!("  wrote report json {json_path}");
    } else {
        append_proof_md(
            &root,
            &args,
            &program_id,
            &relay.pubkey(),
            &vpool,
            &vault,
            &vpool2,
            &report,
        )?;
        println!("  updated {}", root.join("docs/PROOF.md").display());
    }

    if report.all_passed() {
        println!("\nCONFIDENTIAL SOAK RESULT: GREEN ({passed}/{total} assertions passed)");
        Ok(())
    } else {
        bail!("CONFIDENTIAL SOAK RESULT: RED ({passed}/{total} assertions passed)");
    }
}

/// Build a raw `Transact` whose public deposit magnitude differs from a
/// fixed-denomination pool's pinned amount, to exercise the on-chain
/// `DenominationMismatch` guard. The denomination check runs BEFORE the ext-data
/// and Groth16 checks, so a placeholder proof + zeroed ext-data still reach it and
/// the guard fails closed with no state change.
#[allow(clippy::too_many_arguments)]
fn build_denom_mismatch_transact(
    program_id: &Pubkey,
    vpool: &Pubkey,
    vault: &Pubkey,
    relay: &Pubkey,
    fee: u64,
    root: &[u8; 32],
    wrong_amount: u64,
) -> ValueTransactRequest {
    // publicAmount encodes Deposit(wrong_amount): big-endian u64 in the low 8
    // bytes (top byte zero => the deposit range [0, 2^248)).
    let mut public_amount = [0u8; 32];
    public_amount[24..].copy_from_slice(&wrong_amount.to_be_bytes());
    let nf0 = [1u8; 32];
    let nf1 = [2u8; 32];

    let mut data = Vec::with_capacity(1 + 488 + 4);
    data.push(TAG_TRANSACT);
    data.extend_from_slice(&public_amount); // publicAmount (32)
    data.extend_from_slice(&[0u8; 32]); // extDataHash (32) - unchecked (denom check is first)
    data.extend_from_slice(root); // root (32) - must be a known recent root
    data.extend_from_slice(&nf0); // inputNullifier[0] (32)
    data.extend_from_slice(&nf1); // inputNullifier[1] (32)
    data.extend_from_slice(&[0u8; 32]); // outputCommitment[0] (32)
    data.extend_from_slice(&[0u8; 32]); // outputCommitment[1] (32)
    data.extend_from_slice(&[0u8; 64]); // proof_a - placeholder
    data.extend_from_slice(&[0u8; 128]); // proof_b - placeholder
    data.extend_from_slice(&[0u8; 64]); // proof_c - placeholder
    data.extend_from_slice(&fee.to_le_bytes()); // fee (8)
    data.extend_from_slice(&0u16.to_le_bytes()); // enc0_len = 0
    data.extend_from_slice(&0u16.to_le_bytes()); // enc1_len = 0

    let nf0_pda = value_nullifier_pda(program_id, vpool, &nf0);
    let nf1_pda = value_nullifier_pda(program_id, vpool, &nf1);
    let accounts = vec![
        AccountMeta::new(*vpool, false),
        AccountMeta::new(*relay, true), // authority/relay (signer, fee payer)
        AccountMeta::new(nf0_pda, false),
        AccountMeta::new(nf1_pda, false),
        AccountMeta::new(*relay, false), // recipient placeholder
        AccountMeta::new(*relay, false), // depositor slot (unreached)
        AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
        AccountMeta::new_readonly(
            Pubkey::from_str_const("SysvarC1ock11111111111111111111111111111111"),
            false,
        ),
        AccountMeta::new(*vault, false),
        // The write-once, digest-pinned JoinSplit verifying key. Passed even
        // though this request is expected to fail earlier: the account list must
        // be the one a real client would send, or the rejection would prove
        // nothing about the check under test.
        AccountMeta::new_readonly(
            Pubkey::find_program_address(
                &[VK_REGISTRY_SEED, &[mirror_core::wire::CIRCUIT_TRANSACTION]],
                program_id,
            )
            .0,
            false,
        ),
    ];
    ValueTransactRequest {
        program_id: *program_id,
        transact_data: data,
        accounts,
        tx_profile: TxProfile::default(),
    }
}

/// Append (idempotently) a "Confidential-value soak" section to docs/PROOF.md,
/// preserving the existing behavioral proof section above it.
#[allow(clippy::too_many_arguments)]
fn append_proof_md(
    root: &Path,
    args: &Args,
    program_id: &Pubkey,
    relay: &Pubkey,
    vpool: &Pubkey,
    vault: &Pubkey,
    vpool2: &Pubkey,
    report: &Report,
) -> Result<()> {
    use std::fmt::Write;
    // Keep everything the earlier soaks wrote; a re-run replaces only this section.
    const MARKER: &str = "<!-- confidential-value-soak:begin -->";

    let (mut s, now) = begin_proof_section(root, MARKER)?;
    s.push_str(
        r##"## Confidential-value soak

This section documents an automated end-to-end run of `mirror-soak-value` (the
confidential-VALUE soak) against a LIVE local Surfpool validator (a local mainnet
"##,
    );
    writeln!(
        s,
        "mirror at `{}`), treated as mainnet and run honestly. It exercises the 2-in/2-out",
        args.rpc_url
    )?;
    s.push_str(
        r##"JoinSplit `Transact` layer (shield / transfer / unshield) through the SHIPPED
participant CLI (`mirror-cli`, which proves in-process in pure Rust and emits each Transact) and
the gasless coordinator (`mirror_coordinator::submit_transact`). The signatures below
are local-validator signatures, reproducible by re-running the soak against a fresh
Surfpool, not lookups on a public explorer.

"##,
    );
    writeln!(s, "- generated: unix {now}")?;
    writeln!(s, "- program id (fresh deploy): `{program_id}`")?;
    writeln!(
        s,
        "- main ValuePool: `{vpool}` (authority / relay `{relay}`), vault `{vault}`"
    )?;
    writeln!(
        s,
        "- fixed-denomination ValuePool: `{vpool2}` (denomination {} lamports)",
        args.denomination
    )?;
    writeln!(
        s,
        "- relay fee bound into ext-data: {} lamports (nonzero)",
        args.fee
    )?;
    writeln!(
        s,
        "- amounts: shield {} lamports, hidden transfer {} lamports, withdraw {} lamports",
        args.shield_amount, args.transfer_amount, args.transfer_amount
    )?;
    writeln!(s)?;

    s.push_str(
        r##"### What was exercised

1. **Setup** - airdrop a relay/authority + payer + depositor; `InitValuePool` a main
   pool (nonzero fee) and a second pool with a fixed `denomination`.
2. **Shield** - Alice `value-keygen`; shield Alice->Alice for `v`, submitted co-signed
   by the depositor. The vault is credited by `v`, the value root advances, both output
   commitments are inserted, and both input nullifier PDAs are created. A replay is
   rejected (`NullifierSpent`).
3. **Scan + private transfer** - Alice `scan`s the emitted `enc` blobs against the
   on-chain leaves to recover a spendable note, then `transfer`s a HIDDEN amount to Bob
   (`publicAmount == 0`), submitted gasless (relay-only signer). The root advances, new
   nullifier PDAs are created, and the on-chain Transact carries NO cleartext amount. A
   mutated public input is rejected (`ProofVerificationFailed`).
4. **Unshield** - Bob `scan`s -> recovers his note; `unshield` Bob->a FRESH recipient
   for `w`, submitted gasless. The fresh recipient is credited by `w`, the vault is
   debited by `w`, and the nullifier PDA exists.
5. **Fixed-denomination** - a shield of exactly the denomination succeeds; a Transact
   whose public deposit magnitude differs is rejected on-chain
   (`DenominationMismatch`), and the CLI fail-fasts the same case client-side.
6. **Conservation** - the vault balance equals the net public deposit minus the net
   public withdrawal (a transfer moves no public lamports).

This proves the headline claim: mirror-pool hides both WHO initiated (a transfer /
unshield is signed ONLY by the gasless relay, never the acting wallet) AND HOW MUCH
(a transfer's on-chain `publicAmount` is zero; amounts live only inside commitments and
encrypted note blobs).

"##,
    );

    checks_table(&mut s, report, "###");

    sigs_table(&mut s, report, "###");

    writeln!(s, "### Reproduce")?;
    writeln!(s)?;
    writeln!(
        s,
        "With a local Surfpool running at `{}` (treated as mainnet):",
        args.rpc_url
    )?;
    s.push_str(
        r##"
```sh
# 1. build the on-chain program + host workspace
cargo build-sbf --manifest-path programs/mirror-pool/Cargo.toml
cargo build --workspace

# 2. deploy the program under a FRESH program id
solana-keygen new -o .soak/keys/confidential-program.json
solana program deploy \
"##,
    );
    writeln!(s, "  --url {} \\", args.rpc_url)?;
    s.push_str(
        r##"  --program-id .soak/keys/confidential-program.json \
  programs/mirror-pool/target/deploy/mirror_pool.so

# 3. ensure the transaction-circuit artifacts are present (proving is in-process
#    pure Rust; circom/snarkjs are only needed to BUILD these artifacts)
#    circuits/transaction_final.zkey, circuits/transaction_js/transaction.wasm,
#    circuits/artifacts/transaction_verification_key.json

# 4. run the confidential-value soak against the fresh program id
cargo run -p mirror-soak --bin mirror-soak-value -- \
"##,
    );
    writeln!(s, "  --rpc-url {} \\", args.rpc_url)?;
    writeln!(s, "  --program-id {program_id}")?;
    s.push_str(
        r##"```

Every run creates fresh pools (fresh relay authorities) and fresh wallets, so the run
is self-contained and repeatable; the signatures above are from this run.
"##,
    );

    std::fs::write(root.join("docs/PROOF.md"), s)?;
    Ok(())
}
