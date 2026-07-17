//! mirror-soak: the automated end-to-end soak-test suite for mirror-pool.
//!
//! Drives BOTH settlement paths and the adversarial cases against a LIVE local
//! Surfpool validator (treated as a mainnet mirror), verifying every effect
//! on-chain and writing `docs/PROOF.md`:
//!
//! 1. **Setup** - point at Surfpool; create + airdrop a relay/authority and a
//!    payer; ensure the program is deployed; init a fresh pool (small epoch
//!    window, k_floor 3, nonzero entry_fee + reward_bps); set up the pool ALT.
//! 2. **Crowd path** - 4 participants commit the SAME PlainTransfer action into
//!    one shared epoch; after the window closes the coordinator settles ONE
//!    atomic tx (ComputeBudget + SettleEpoch + 4 identical transfers) as the
//!    rotating gasless relay. Verified: settle confirmed, 4 nullifier PDAs
//!    exist, the epoch is settled, and the 4 transfers landed (sink credited).
//! 3. **ZK opt-in path** - a depositor escrows to a FRESH recipient via the
//!    shipped `mirror-cli deposit-commit`; after the window closes `mirror-cli
//!    prove` produces a verified Groth16 SettleZk, submitted by the relay.
//!    Verified: the escrow landed at the fresh recipient, the nullifier PDA
//!    exists, and a replay is rejected (nullifier spent).
//! 4. **Adversarial** - an under-floor epoch does not settle (on-chain
//!    BelowKFloor + off-chain coordinator roll-forward); a duplicate crowd
//!    nullifier is rejected (NullifierSpent); a re-settle is rejected
//!    (EpochAlreadySettled); a ZK settle to a mismatched recipient is rejected
//!    (ActionHashMismatch).
//!
//! The soak uses the real shipped components: the participant CLI (`mirror-cli`)
//! for the ZK deposit-commit + prove, and the gasless coordinator library
//! (`mirror_coordinator::RpcSettleSubmitter`) for the atomic crowd settlement.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;

use mirror_behaviors::{Behavior, PlainTransfer};
use mirror_coordinator::client::{RpcSolanaClient, SolanaClient};
use mirror_coordinator::crowd::{
    epoch_pda, nullifier_pda, plain_transfer_shared_accounts, settle_epoch_instruction,
    setup_pool_alt, RpcSettleSubmitter, SettleContext, SettleParticipant,
};
use mirror_coordinator::{
    Config, Coordinator, EpochOutcome, FeePayer, InMemorySubmitter, PoolEntry, SettleBatch,
    TxProfile,
};
use mirror_core::{
    commit as core_commit, nullifier as core_nullifier, wire, ActionClass, Epoch, EpochSchedule,
    Nullifier, Secret, SizeBucket,
};

use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_message::{v0, AddressLookupTableAccount, VersionedMessage};
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;

// ---------------------------------------------------------------------------
// CLI args
// ---------------------------------------------------------------------------

/// The default local RPC: the Surfpool mainnet mirror.
const DEFAULT_RPC_URL: &str = "http://127.0.0.1:8899";
/// The built program id (programs/mirror-pool/target/deploy/mirror_pool-keypair.json).
const DEFAULT_PROGRAM_ID: &str = "7vUgz7eMA2HD1DrTrKp3YWvUgpmyyrab8ogmnfdHhuve";

#[derive(Parser, Debug)]
#[command(
    name = "mirror-soak",
    about = "End-to-end Surfpool soak: crowd + ZK settlement paths, adversarial cases, on-chain verification"
)]
struct Args {
    /// RPC endpoint (default: the running local Surfpool).
    #[arg(long, default_value = DEFAULT_RPC_URL)]
    rpc_url: String,
    /// mirror-pool program id (base58).
    #[arg(long, default_value = DEFAULT_PROGRAM_ID)]
    program_id: String,
    /// Slots per epoch window. Small enough that "wait for close" is quick, big
    /// enough that a 4-commit burst reliably lands in one window on Surfpool.
    #[arg(long, default_value_t = 64)]
    epoch_slots: u64,
    /// Minimum commits before an epoch may settle (must be >= 2).
    #[arg(long, default_value_t = 3)]
    k_floor: u32,
    /// Per-commit anti-Sybil entry fee, in lamports (nonzero exercises the fee).
    #[arg(long, default_value_t = 1_000_000)]
    entry_fee: u64,
    /// Basis-point share of each entry fee that accrues to the reward pool.
    #[arg(long, default_value_t = 2_500)]
    reward_bps: u16,
    /// ZK opt-in escrow amount, in lamports (default 0.25 SOL).
    #[arg(long, default_value_t = 250_000_000)]
    zk_amount: u64,
}

// ---------------------------------------------------------------------------
// Report accumulation
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Report {
    checks: Vec<(String, bool, String)>,
    sigs: Vec<(String, String)>,
}

impl Report {
    fn check(&mut self, label: &str, pass: bool, detail: impl Into<String>) {
        self.checks.push((label.to_string(), pass, detail.into()));
        let mark = if pass { "PASS" } else { "FAIL" };
        println!("  [{mark}] {label} - {}", self.checks.last().unwrap().2);
    }
    fn sig(&mut self, label: &str, sig: impl Into<String>) {
        let sig = sig.into();
        println!("  tx  {label}: {sig}");
        self.sigs.push((label.to_string(), sig));
    }
    fn all_passed(&self) -> bool {
        self.checks.iter().all(|(_, p, _)| *p)
    }
}

// ---------------------------------------------------------------------------
// Environment / external-binary helpers
// ---------------------------------------------------------------------------

/// The workspace root: `<root>/target/<profile>/mirror-soak` -> `<root>`.
fn repo_root() -> Result<PathBuf> {
    if let Ok(r) = std::env::var("MIRROR_REPO_ROOT") {
        return Ok(PathBuf::from(r));
    }
    let exe = std::env::current_exe().context("current_exe")?;
    // target/<profile>/mirror-soak -> repo root is three parents up.
    let root = exe
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
        .ok_or_else(|| anyhow!("cannot derive repo root from {}", exe.display()))?;
    Ok(root.to_path_buf())
}

/// The `mirror-cli` binary that ships alongside this soak binary.
fn cli_bin() -> Result<PathBuf> {
    if let Ok(p) = std::env::var("MIRROR_CLI_BIN") {
        return Ok(PathBuf::from(p));
    }
    let exe = std::env::current_exe().context("current_exe")?;
    let sibling = exe
        .parent()
        .ok_or_else(|| anyhow!("no parent for {}", exe.display()))?
        .join("mirror-cli");
    if sibling.exists() {
        return Ok(sibling);
    }
    bail!(
        "mirror-cli binary not found at {} (build it with `cargo build -p mirror-cli`, or set MIRROR_CLI_BIN)",
        sibling.display()
    )
}

fn which(bin: &str) -> Result<String> {
    let out = Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {bin}"))
        .output()
        .with_context(|| format!("locating {bin}"))?;
    if !out.status.success() {
        bail!("`{bin}` not found on PATH");
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Airdrop `sol` SOL to `pubkey` via the local validator faucet.
fn airdrop(rpc_url: &str, pubkey: &Pubkey, sol: u64) -> Result<()> {
    let out = Command::new("solana")
        .args([
            "airdrop",
            &sol.to_string(),
            &pubkey.to_string(),
            "--url",
            rpc_url,
        ])
        .output()
        .context("spawning `solana airdrop`")?;
    if !out.status.success() {
        bail!(
            "solana airdrop {sol} {pubkey} failed:\n{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(())
}

/// Generate a fresh keypair and persist it (gitignored) so a run is auditable.
fn new_keypair(dir: &Path, name: &str) -> Result<Keypair> {
    let kp = Keypair::new();
    let path = dir.join(format!("{name}.json"));
    std::fs::write(&path, serde_json::to_string(&kp.to_bytes().to_vec())?)
        .with_context(|| format!("writing keypair {}", path.display()))?;
    Ok(kp)
}

/// Ensure the program is deployed; deploy it from the built artifacts if not.
async fn ensure_deployed(
    client: &dyn SolanaClient,
    rpc_url: &str,
    program_id: &Pubkey,
) -> Result<()> {
    if let Some(acc) = client.get_account(program_id).await? {
        if acc.executable {
            return Ok(());
        }
    }
    println!("  program not deployed; deploying from built artifacts...");
    let root = repo_root()?;
    let so = root.join("programs/mirror-pool/target/deploy/mirror_pool.so");
    let prog_kp = root.join("programs/mirror-pool/target/deploy/mirror_pool-keypair.json");
    let payer = root.join(".soak/deploy-payer.json");
    if !payer.exists() {
        let kp = Keypair::new();
        std::fs::write(&payer, serde_json::to_string(&kp.to_bytes().to_vec())?)?;
        airdrop(rpc_url, &kp.pubkey(), 100)?;
    }
    let out = Command::new("solana")
        .args([
            "program",
            "deploy",
            "--url",
            rpc_url,
            "--keypair",
            &payer.to_string_lossy(),
            "--upgrade-authority",
            &payer.to_string_lossy(),
            "--program-id",
            &prog_kp.to_string_lossy(),
            &so.to_string_lossy(),
        ])
        .output()
        .context("spawning `solana program deploy`")?;
    if !out.status.success() {
        bail!(
            "solana program deploy failed:\n{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Instruction builders (wire layout from mirror_core::wire) + PDA
// ---------------------------------------------------------------------------

const SYSTEM_PROGRAM_ID: Pubkey = Pubkey::from_str_const("11111111111111111111111111111111");
const CLOCK_SYSVAR_ID: Pubkey =
    Pubkey::from_str_const("SysvarC1ock11111111111111111111111111111111");

/// Derive the Pool PDA: seeds `[b"pool", authority]`.
fn pool_pda(program_id: &Pubkey, authority: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[b"pool", authority.as_ref()], program_id).0
}

/// Build the `InitPool` instruction (see instructions::init_pool).
#[allow(clippy::too_many_arguments)]
fn init_pool_ix(
    program_id: &Pubkey,
    pool: &Pubkey,
    authority: &Pubkey,
    payer: &Pubkey,
    epoch_slots: u64,
    k_floor: u32,
    entry_fee: u64,
    reward_bps: u16,
) -> Instruction {
    let mut data = Vec::with_capacity(wire::INIT_POOL_LEN);
    data.push(wire::tag::INIT_POOL);
    data.extend_from_slice(&epoch_slots.to_le_bytes());
    data.extend_from_slice(&k_floor.to_le_bytes());
    data.extend_from_slice(&entry_fee.to_le_bytes());
    data.extend_from_slice(&reward_bps.to_le_bytes());
    Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(*pool, false),
            AccountMeta::new_readonly(*authority, true),
            AccountMeta::new(*payer, true),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
        ],
        data,
    }
}

/// Build the crowd-path `Commit` instruction (see instructions::commit).
fn commit_ix(
    program_id: &Pubkey,
    pool: &Pubkey,
    epoch_account: &Pubkey,
    participant: &Pubkey,
    commitment: &[u8; 32],
) -> Instruction {
    let mut data = Vec::with_capacity(wire::COMMIT_LEN);
    data.push(wire::tag::COMMIT);
    data.extend_from_slice(commitment);
    Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(*pool, false),
            AccountMeta::new(*epoch_account, false),
            AccountMeta::new(*participant, true),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
            AccountMeta::new_readonly(CLOCK_SYSVAR_ID, false),
        ],
        data,
    }
}

// ---------------------------------------------------------------------------
// On-chain account decoders (offsets mirror programs/mirror-pool/src/state)
// ---------------------------------------------------------------------------

fn le_u32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
}
fn le_u64(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(b[off..off + 8].try_into().unwrap())
}

struct PoolView {
    version: u8,
    epoch_slots: u64,
    k_floor: u32,
    commitment_count: u64,
    authority: [u8; 32],
    entry_fee: u64,
    reward_pool: u64,
}

impl PoolView {
    // state::pool offsets: version 0, epoch_slots 1, k_floor 9, commitment_count
    // 13, current_root 21, authority 53, entry_fee 85, ... reward_pool 1764.
    const REWARD_POOL_OFF: usize = 1764;
    fn decode(data: &[u8]) -> Result<PoolView> {
        if data.len() < Self::REWARD_POOL_OFF + 8 {
            bail!("pool account too short: {} bytes", data.len());
        }
        let mut authority = [0u8; 32];
        authority.copy_from_slice(&data[53..85]);
        Ok(PoolView {
            version: data[0],
            epoch_slots: le_u64(data, 1),
            k_floor: le_u32(data, 9),
            commitment_count: le_u64(data, 13),
            authority,
            entry_fee: le_u64(data, 85),
            reward_pool: le_u64(data, Self::REWARD_POOL_OFF),
        })
    }
}

struct EpochView {
    version: u8,
    epoch_id: u64,
    commit_count: u32,
    settled: bool,
}

impl EpochView {
    // state::epoch offsets: version 0, epoch_id 1, nominal_k 9, settled 13.
    fn decode(data: &[u8]) -> Result<EpochView> {
        if data.len() < 14 {
            bail!("epoch account too short: {} bytes", data.len());
        }
        Ok(EpochView {
            version: data[0],
            epoch_id: le_u64(data, 1),
            commit_count: le_u32(data, 9),
            settled: data[13] != 0,
        })
    }
}

// ---------------------------------------------------------------------------
// Submission helpers
// ---------------------------------------------------------------------------

/// Build, sign, and send a v0 transaction. `signers[0]` is the fee payer.
/// Returns `Ok(signature)` on success or `Err(error string)` on any failure.
async fn send(
    client: &dyn SolanaClient,
    ixs: &[Instruction],
    signers: &[&Keypair],
    alts: &[AddressLookupTableAccount],
) -> std::result::Result<String, String> {
    // Render the FULL anyhow chain (`{:#}`) so a rejected tx surfaces its
    // `custom program error: 0x..` code, not just the top-level context.
    let payer = signers.first().ok_or_else(|| "no signers".to_string())?;
    let blockhash = client
        .get_latest_blockhash()
        .await
        .map_err(|e| format!("{e:#}"))?;
    let msg = v0::Message::try_compile(&payer.pubkey(), ixs, alts, blockhash)
        .map_err(|e| format!("{e:#}"))?;
    let tx = VersionedTransaction::try_new(VersionedMessage::V0(msg), signers)
        .map_err(|e| format!("{e:#}"))?;
    client
        .send_and_confirm_transaction(&tx)
        .await
        .map(|s| s.to_string())
        .map_err(|e| format!("{e:#}"))
}

/// Whether an error string reports a specific mirror-pool custom program error.
fn is_custom(err: &str, code: u32) -> bool {
    err.contains(&format!("custom program error: 0x{code:x}"))
        || err.contains(&format!("Custom({code})"))
}

/// Poll `get_slot` until it reaches `target`.
async fn wait_until_slot(client: &dyn SolanaClient, target: u64) -> Result<u64> {
    loop {
        let s = client.get_slot().await?;
        if s >= target {
            return Ok(s);
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}

/// Return the id of a window with at least `need` slots of headroom, waiting for
/// the next window boundary if the current window is too far along. This is how
/// the soak guarantees a whole commit burst lands in one shared epoch.
async fn fresh_window(client: &dyn SolanaClient, epoch_slots: u64, need: u64) -> Result<u64> {
    let s = client.get_slot().await?;
    let remaining = epoch_slots - (s % epoch_slots);
    if remaining >= need {
        return Ok(s / epoch_slots);
    }
    let next = (s / epoch_slots + 1) * epoch_slots;
    let s2 = wait_until_slot(client, next).await?;
    Ok(s2 / epoch_slots)
}

fn hex_decode(s: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        bail!("odd-length hex");
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| anyhow!("bad hex: {e}")))
        .collect()
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let args = Args::parse();
    let program_id =
        Pubkey::from_str(&args.program_id).map_err(|e| anyhow!("invalid --program-id: {e}"))?;
    let w = args.epoch_slots;

    let root = repo_root()?;
    let keys_dir = root.join(".soak/keys");
    let notes_dir = root.join(".soak/notes");
    std::fs::create_dir_all(&keys_dir)?;
    std::fs::create_dir_all(&notes_dir)?;

    println!("mirror-soak: live end-to-end soak against Surfpool");
    println!("  rpc:         {}", args.rpc_url);
    println!("  program:     {program_id}");
    println!(
        "  epoch_slots: {w}   k_floor: {}   entry_fee: {}   reward_bps: {}",
        args.k_floor, args.entry_fee, args.reward_bps
    );
    println!();

    let client: Arc<dyn SolanaClient> = Arc::new(RpcSolanaClient::new(args.rpc_url.clone()));
    let mut report = Report::default();

    // -- 1. SETUP -----------------------------------------------------------
    println!("== 1. setup ==");
    ensure_deployed(client.as_ref(), &args.rpc_url, &program_id).await?;
    report.check(
        "program deployed + executable",
        true,
        format!("{program_id}"),
    );

    let relay = new_keypair(&keys_dir, "relay")?; // pool authority + settle relay
    let payer = new_keypair(&keys_dir, "payer")?; // funds the pool rent at init
    airdrop(&args.rpc_url, &relay.pubkey(), 100)?;
    airdrop(&args.rpc_url, &payer.pubkey(), 100)?;
    let pool = pool_pda(&program_id, &relay.pubkey());
    println!("  relay/authority: {}", relay.pubkey());
    println!("  payer:           {}", payer.pubkey());
    println!("  pool PDA:        {pool}");

    let sig = send(
        client.as_ref(),
        &[init_pool_ix(
            &program_id,
            &pool,
            &relay.pubkey(),
            &payer.pubkey(),
            w,
            args.k_floor,
            args.entry_fee,
            args.reward_bps,
        )],
        &[&payer, &relay],
        &[],
    )
    .await
    .map_err(|e| anyhow!("init_pool failed: {e}"))?;
    report.sig("init_pool", &sig);

    let pool_acc = client
        .get_account(&pool)
        .await?
        .ok_or_else(|| anyhow!("pool account not found after init"))?;
    let pv = PoolView::decode(&pool_acc.data)?;
    report.check(
        "pool initialized with fixed config",
        pv.version == 1
            && pv.epoch_slots == w
            && pv.k_floor == args.k_floor
            && pv.entry_fee == args.entry_fee
            && pv.authority == relay.pubkey().to_bytes(),
        format!(
            "version={} epoch_slots={} k_floor={} entry_fee={} authority=relay",
            pv.version, pv.epoch_slots, pv.k_floor, pv.entry_fee
        ),
    );

    // Pool ALT for the crowd path (shared, non-signer accounts).
    let sink = new_keypair(&keys_dir, "sink")?; // per-pool transfer sink
    let ctx0 = SettleContext {
        program_id,
        pool,
        alt: AddressLookupTableAccount {
            key: Pubkey::new_from_array([0u8; 32]),
            addresses: Vec::new(),
        },
    };
    let shared = plain_transfer_shared_accounts(&ctx0, &sink.pubkey());
    // Distinct authority + payer: the coordinator signs the ALT setup tx with
    // both, so passing one key twice would over-count the signer set.
    let alt = setup_pool_alt(client.as_ref(), &relay, &payer, shared)
        .await
        .context("setup_pool_alt")?;
    let ctx = SettleContext {
        program_id,
        pool,
        alt: alt.clone(),
    };
    report.check(
        "pool ALT created + extended",
        alt.addresses.len() == 6,
        format!("alt={} ({} shared accounts)", alt.key, alt.addresses.len()),
    );
    println!();

    // -- 2. CROWD PATH ------------------------------------------------------
    println!("== 2. crowd path (PlainTransfer, 4 participants, one atomic settle) ==");
    let crowd_action: ActionClass =
        PlainTransfer::sol(sink.pubkey(), SizeBucket::Nano).action_class();
    let bucket = mirror_behaviors::bucket_lamports(SizeBucket::Nano);

    // Align to a fresh window so all four commits land in one shared epoch.
    let epoch_a = fresh_window(client.as_ref(), w, 28).await?;
    println!("  shared epoch: {epoch_a} (window {w} slots)");

    let mut crowd_kps: Vec<Arc<Keypair>> = Vec::new();
    let mut crowd_nfs: Vec<Nullifier> = Vec::new();
    for i in 0..4u8 {
        let kp = Arc::new(new_keypair(&keys_dir, &format!("crowd-{i}"))?);
        airdrop(&args.rpc_url, &kp.pubkey(), 5)?;
        let secret = Secret::from_bytes([0xC0 + i; 32]);
        let commitment = core_commit(&secret, &crowd_action, Epoch(epoch_a));
        let nf = core_nullifier(&secret, Epoch(epoch_a));
        let ep = epoch_pda(&program_id, &pool, Epoch(epoch_a));
        let sig = send(
            client.as_ref(),
            &[commit_ix(
                &program_id,
                &pool,
                &ep,
                &kp.pubkey(),
                &commitment.0,
            )],
            &[kp.as_ref()],
            &[],
        )
        .await
        .map_err(|e| anyhow!("crowd commit {i} failed: {e}"))?;
        report.sig(&format!("crowd_commit_{i}"), &sig);
        crowd_kps.push(kp);
        crowd_nfs.push(nf);
    }

    // Confirm all four landed in the shared epoch (batching worked).
    let ep_a = epoch_pda(&program_id, &pool, Epoch(epoch_a));
    let ev = EpochView::decode(
        &client
            .get_account(&ep_a)
            .await?
            .ok_or_else(|| anyhow!("epoch {epoch_a} account missing"))?
            .data,
    )?;
    report.check(
        "4 commits batched into one shared epoch",
        ev.version == 1 && ev.epoch_id == epoch_a && ev.commit_count == 4 && !ev.settled,
        format!(
            "epoch_id={} commit_count={} settled={}",
            ev.epoch_id, ev.commit_count, ev.settled
        ),
    );

    // Wait for the window to close, which also lands us at the start of the next
    // window (used as the under-floor epoch below).
    let settle_slot_a = (epoch_a + 1) * w;
    println!("  waiting for epoch {epoch_a} window to close at slot {settle_slot_a}...");
    wait_until_slot(client.as_ref(), settle_slot_a).await?;

    // Under-floor epoch: commit only 2 (< k_floor) into the fresh next window.
    let epoch_b = client.as_ref().get_slot().await? / w;
    println!(
        "  under-floor epoch: {epoch_b} (2 commits < k_floor {})",
        args.k_floor
    );
    let mut uf_kps: Vec<Arc<Keypair>> = Vec::new();
    let mut uf_nfs: Vec<Nullifier> = Vec::new();
    for i in 0..2u8 {
        let kp = Arc::new(new_keypair(&keys_dir, &format!("underfloor-{i}"))?);
        airdrop(&args.rpc_url, &kp.pubkey(), 5)?;
        let secret = Secret::from_bytes([0xB0 + i; 32]);
        let commitment = core_commit(&secret, &crowd_action, Epoch(epoch_b));
        let nf = core_nullifier(&secret, Epoch(epoch_b));
        let ep = epoch_pda(&program_id, &pool, Epoch(epoch_b));
        let sig = send(
            client.as_ref(),
            &[commit_ix(
                &program_id,
                &pool,
                &ep,
                &kp.pubkey(),
                &commitment.0,
            )],
            &[kp.as_ref()],
            &[],
        )
        .await
        .map_err(|e| anyhow!("under-floor commit {i} failed: {e}"))?;
        report.sig(&format!("underfloor_commit_{i}"), &sig);
        uf_kps.push(kp);
        uf_nfs.push(nf);
    }

    // -- Adversarial (b): duplicate crowd nullifier is rejected (bare settle on
    //    the unsettled epoch A with a nullifier listed twice -> NullifierSpent).
    let dup = vec![crowd_nfs[0], crowd_nfs[0]];
    let dup_ix = settle_epoch_instruction(&ctx, Epoch(epoch_a), &relay.pubkey(), &dup);
    let dup_res = send(client.as_ref(), &[dup_ix], &[&relay], &[]).await;
    report.check(
        "duplicate crowd nullifier rejected (NullifierSpent)",
        dup_res
            .as_ref()
            .err()
            .map(|e| is_custom(e, 3))
            .unwrap_or(false),
        match &dup_res {
            Ok(s) => format!("UNEXPECTED success: {s}"),
            Err(e) => first_line(e),
        },
    );

    // -- Crowd happy-path settle via the gasless coordinator: ONE atomic tx =
    //    ComputeBudget + SettleEpoch + 4 identical transfers.
    let sink_before = client
        .get_account(&sink.pubkey())
        .await?
        .map(|a| a.lamports)
        .unwrap_or(0);
    let behavior: Arc<dyn Behavior> = Arc::new(PlainTransfer::sol(sink.pubkey(), SizeBucket::Nano));
    let mut submitter = RpcSettleSubmitter::new(client.clone(), ctx.clone());
    submitter.register_signer(Arc::new(clone_keypair(&relay)));
    let roster: Vec<SettleParticipant> = crowd_kps
        .iter()
        .zip(crowd_nfs.iter())
        .map(|(kp, nf)| {
            submitter.register_signer(kp.clone());
            SettleParticipant {
                signer: kp.pubkey(),
                behavior: behavior.clone(),
                size: SizeBucket::Nano,
                nullifier: *nf,
            }
        })
        .collect();
    submitter.register_epoch(Epoch(epoch_a), roster);
    let batch = SettleBatch {
        epoch: Epoch(epoch_a),
        nullifiers: crowd_nfs.clone(),
        fee_payer: FeePayer(relay.pubkey().to_bytes()),
        tx_profile: TxProfile::default(),
    };
    let receipt = submitter
        .submit_crowd(&batch)
        .await
        .context("crowd settle via coordinator")?;
    report.sig("crowd_settle", &receipt.signature);

    // Verify: epoch settled, 4 nullifier PDAs exist, 4 transfers landed.
    let ev = EpochView::decode(&client.get_account(&ep_a).await?.unwrap().data)?;
    report.check(
        "crowd epoch marked settled on-chain",
        ev.settled,
        format!("epoch_id={} settled={}", ev.epoch_id, ev.settled),
    );
    let mut nf_ok = 0;
    for nf in &crowd_nfs {
        let pda = nullifier_pda(&program_id, &pool, Epoch(epoch_a), nf);
        if let Some(acc) = client.get_account(&pda).await? {
            if acc.owner == program_id && acc.data.first() == Some(&1u8) {
                nf_ok += 1;
            }
        }
    }
    report.check(
        "4 nullifier PDAs created (anti-replay)",
        nf_ok == 4,
        format!("{nf_ok}/4 nullifier PDAs exist and are program-owned"),
    );
    let sink_after = client
        .get_account(&sink.pubkey())
        .await?
        .map(|a| a.lamports)
        .unwrap_or(0);
    report.check(
        "4 identical transfers executed atomically",
        sink_after - sink_before == 4 * bucket,
        format!(
            "sink credited {} lamports (= 4 x {} bucket)",
            sink_after - sink_before,
            bucket
        ),
    );

    // -- Adversarial (b2): re-settling a settled epoch is rejected.
    let resettle_ix = settle_epoch_instruction(&ctx, Epoch(epoch_a), &relay.pubkey(), &crowd_nfs);
    let resettle_res = send(client.as_ref(), &[resettle_ix], &[&relay], &[]).await;
    report.check(
        "re-settle of a settled epoch rejected (EpochAlreadySettled)",
        resettle_res
            .as_ref()
            .err()
            .map(|e| is_custom(e, 6))
            .unwrap_or(false),
        match &resettle_res {
            Ok(s) => format!("UNEXPECTED success: {s}"),
            Err(e) => first_line(e),
        },
    );
    println!();

    // -- 3. ADVERSARIAL: under-floor epoch does not settle -----------------
    println!("== 3. adversarial: under-floor epoch does not settle ==");
    let settle_slot_b = (epoch_b + 1) * w;
    println!("  waiting for under-floor epoch {epoch_b} to close at slot {settle_slot_b}...");
    wait_until_slot(client.as_ref(), settle_slot_b).await?;
    let uf_ix = settle_epoch_instruction(&ctx, Epoch(epoch_b), &relay.pubkey(), &uf_nfs);
    let uf_res = send(client.as_ref(), &[uf_ix], &[&relay], &[]).await;
    report.check(
        "under-floor epoch rejected on-chain (BelowKFloor)",
        uf_res
            .as_ref()
            .err()
            .map(|e| is_custom(e, 2))
            .unwrap_or(false),
        match &uf_res {
            Ok(s) => format!("UNEXPECTED success: {s}"),
            Err(e) => first_line(e),
        },
    );
    // Same decision off-chain: the coordinator rolls the epoch forward.
    let rolled = coordinator_rolls_forward_under_floor(w, args.k_floor)?;
    report.check(
        "under-floor epoch rolled forward off-chain (coordinator)",
        rolled,
        "coordinator.on_slot returned RolledForward (real_k < k_floor)",
    );
    println!();

    // -- 4. ZK OPT-IN PATH --------------------------------------------------
    println!("== 4. ZK opt-in path (deposit-commit -> prove -> SettleZk) ==");
    let cli = cli_bin()?;
    let snarkjs = which("snarkjs").unwrap_or_else(|_| "snarkjs".to_string());

    let depositor = new_keypair(&keys_dir, "zk-depositor")?;
    airdrop(&args.rpc_url, &depositor.pubkey(), 5)?;
    let depositor_path = keys_dir.join("zk-depositor.json");
    let recipient = new_keypair(&keys_dir, "zk-recipient")?; // FRESH, zero prior balance
    let recip_before = client
        .get_account(&recipient.pubkey())
        .await?
        .map(|a| a.lamports)
        .unwrap_or(0);

    // Deposit into a fresh window so we can then wait for it to close.
    let epoch_c = fresh_window(client.as_ref(), w, 16).await?;
    println!(
        "  ZK escrow epoch: {epoch_c}, recipient {} (balance {recip_before})",
        recipient.pubkey()
    );
    let dc_out = run_cli(
        &cli,
        &root,
        &[
            "deposit-commit",
            "--rpc-url",
            &args.rpc_url,
            "--program-id",
            &program_id.to_string(),
            "--pool",
            &pool.to_string(),
            "--keypair",
            &depositor_path.to_string_lossy(),
            "--seed",
            "zk-seed-soak",
            "--recipient",
            &recipient.pubkey().to_string(),
            "--amount",
            &args.zk_amount.to_string(),
            "--note-dir",
            &notes_dir.to_string_lossy(),
        ],
    )?;
    let note_path = parse_kv(&dc_out, "note saved:")
        .ok_or_else(|| anyhow!("could not find note path in deposit-commit output"))?;
    let dc_sig = parse_kv(&dc_out, "signature:").unwrap_or_default();
    report.sig("zk_deposit_commit", dc_sig);
    let note_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&note_path)?).context("read note")?;
    let zk_epoch = note_json["epoch"].as_u64().unwrap_or(epoch_c);

    // Wait for the escrow's window to close before proving + settling.
    let settle_slot_c = (zk_epoch + 1) * w;
    println!("  waiting for ZK epoch {zk_epoch} to close at slot {settle_slot_c}...");
    wait_until_slot(client.as_ref(), settle_slot_c).await?;

    // Generate + verify the Groth16 proof and emit the SettleZk instruction.
    let emit_path = root.join(".soak/zk-emit.json");
    run_cli(
        &cli,
        &root,
        &[
            "prove",
            "--note",
            &note_path,
            "--rpc-url",
            &args.rpc_url,
            "--snarkjs",
            &snarkjs,
            "--out",
            &emit_path.to_string_lossy(),
        ],
    )?;
    report.check(
        "Groth16 membership proof generated + verified (snarkjs)",
        true,
        "mirror-cli prove produced a snarkjs-verified SettleZk",
    );
    let emit: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&emit_path)?).context("read emit")?;
    let settle_data = hex_decode(emit["settle_zk_data_hex"].as_str().unwrap())?;
    let zk_nf_pda = Pubkey::from_str(emit["nullifier_pda"].as_str().unwrap())?;
    let emit_authority = Pubkey::from_str(emit["authority"].as_str().unwrap())?;
    report.check(
        "SettleZk authority == pool relay",
        emit_authority == relay.pubkey(),
        format!("authority={emit_authority}"),
    );

    let build_settle_zk = |recipient_key: Pubkey| -> Instruction {
        Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new(pool, false),
                AccountMeta::new(relay.pubkey(), true),
                AccountMeta::new(zk_nf_pda, false),
                AccountMeta::new(recipient_key, false),
                AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
                AccountMeta::new_readonly(CLOCK_SYSVAR_ID, false),
            ],
            data: settle_data.clone(),
        }
    };

    // -- Adversarial (c): SettleZk to a mismatched recipient is rejected. The
    //    actionHash binds (recipient, amount), so a redirect fails closed BEFORE
    //    the nullifier is created.
    let wrong_recipient = new_keypair(&keys_dir, "zk-wrong-recipient")?;
    let mismatch_res = send(
        client.as_ref(),
        &[build_settle_zk(wrong_recipient.pubkey())],
        &[&relay],
        &[],
    )
    .await;
    report.check(
        "ZK settle to mismatched recipient rejected (ActionHashMismatch)",
        mismatch_res
            .as_ref()
            .err()
            .map(|e| is_custom(e, 14))
            .unwrap_or(false),
        match &mismatch_res {
            Ok(s) => format!("UNEXPECTED success: {s}"),
            Err(e) => first_line(e),
        },
    );

    // -- ZK happy path: settle to the bound fresh recipient.
    let zk_sig = send(
        client.as_ref(),
        &[build_settle_zk(recipient.pubkey())],
        &[&relay],
        &[],
    )
    .await
    .map_err(|e| anyhow!("SettleZk failed: {e}"))?;
    report.sig("zk_settle", &zk_sig);

    let recip_after = client
        .get_account(&recipient.pubkey())
        .await?
        .map(|a| a.lamports)
        .unwrap_or(0);
    report.check(
        "escrow landed at the FRESH recipient",
        recip_after - recip_before == args.zk_amount,
        format!(
            "recipient credited {} lamports (= escrow {})",
            recip_after - recip_before,
            args.zk_amount
        ),
    );
    let zk_nf_ok = client
        .get_account(&zk_nf_pda)
        .await?
        .map(|a| a.owner == program_id && a.data.first() == Some(&1u8))
        .unwrap_or(false);
    report.check(
        "ZK nullifier PDA created (anti-replay)",
        zk_nf_ok,
        format!("nullifier PDA {zk_nf_pda} exists + program-owned"),
    );

    // -- Adversarial: replaying the same SettleZk is rejected (nullifier spent).
    let replay_res = send(
        client.as_ref(),
        &[build_settle_zk(recipient.pubkey())],
        &[&relay],
        &[],
    )
    .await;
    report.check(
        "ZK replay rejected (NullifierSpent)",
        replay_res
            .as_ref()
            .err()
            .map(|e| is_custom(e, 3))
            .unwrap_or(false),
        match &replay_res {
            Ok(s) => format!("UNEXPECTED success: {s}"),
            Err(e) => first_line(e),
        },
    );
    println!();

    // -- SUMMARY + PROOF.md -------------------------------------------------
    println!("== summary ==");
    let passed = report.checks.iter().filter(|(_, p, _)| *p).count();
    let total = report.checks.len();
    println!("  {passed}/{total} on-chain assertions passed");
    println!("  {} captured transaction signatures", report.sigs.len());

    let final_pool = PoolView::decode(&client.get_account(&pool).await?.unwrap().data)?;
    write_proof_md(
        &root,
        &args,
        &program_id,
        &pool,
        &relay.pubkey(),
        &report,
        &final_pool,
    )?;
    println!("  wrote {}", root.join("docs/PROOF.md").display());

    if report.all_passed() {
        println!("\nSOAK RESULT: GREEN ({passed}/{total} assertions passed)");
        Ok(())
    } else {
        bail!("SOAK RESULT: RED ({passed}/{total} assertions passed)");
    }
}

/// The coordinator's off-chain k-floor decision for an under-floor epoch.
fn coordinator_rolls_forward_under_floor(epoch_slots: u64, k_floor: u32) -> Result<bool> {
    let config = Config {
        schedule: EpochSchedule {
            epoch_slots,
            k_floor,
        },
        fee_payers: vec![FeePayer([1; 32]), FeePayer([2; 32])],
        tx_profile: TxProfile::default(),
    };
    let mut c = Coordinator::new(config, InMemorySubmitter::default())?;
    let action = ActionClass::Stake {
        validator: [7u8; 32],
        size: SizeBucket::Nano,
    };
    for seed in 0..(k_floor.saturating_sub(1)) as u8 {
        let secret = Secret::from_bytes([0xE0 + seed; 32]);
        c.pool_mut().insert(
            Epoch(0),
            PoolEntry {
                commitment: core_commit(&secret, &action, Epoch(0)),
                nullifier: core_nullifier(&secret, Epoch(0)),
                operator_owned: false,
                sybil_suspected: false,
            },
        );
    }
    let outcomes = c.on_slot(epoch_slots)?;
    let rolled = matches!(outcomes.first(), Some(EpochOutcome::RolledForward { .. }));
    Ok(rolled && c.submitter().submitted.is_empty())
}

/// Shell out to the shipped `mirror-cli`, returning stdout (fails on nonzero).
fn run_cli(cli: &Path, cwd: &Path, args: &[&str]) -> Result<String> {
    let out = Command::new(cli)
        .current_dir(cwd)
        .args(args)
        .output()
        .with_context(|| format!("spawning {}", cli.display()))?;
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    if !out.status.success() {
        bail!(
            "mirror-cli {:?} failed:\n{stdout}\n{}",
            args,
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(stdout)
}

/// Parse the value after a `key` prefix from CLI output (e.g. "note saved:").
fn parse_kv(text: &str, key: &str) -> Option<String> {
    text.lines()
        .find_map(|l| l.trim().strip_prefix(key).map(|v| v.trim().to_string()))
}

/// First line of a (possibly multi-line) error, for compact reporting.
fn first_line(s: &str) -> String {
    s.replace('\n', " ").chars().take(240).collect()
}

/// Deep-copy a keypair (Keypair is not Clone; go via its 64 bytes).
fn clone_keypair(kp: &Keypair) -> Keypair {
    Keypair::try_from(kp.to_bytes().as_slice()).expect("valid keypair bytes")
}

/// Write docs/PROOF.md documenting the live run.
fn write_proof_md(
    root: &Path,
    args: &Args,
    program_id: &Pubkey,
    pool: &Pubkey,
    relay: &Pubkey,
    report: &Report,
    final_pool: &PoolView,
) -> Result<()> {
    use std::fmt::Write;
    let mut s = String::new();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    writeln!(s, "# mirror-pool - live Surfpool soak proof")?;
    writeln!(s)?;
    writeln!(
        s,
        "This documents an automated end-to-end run of `mirror-soak` against a LIVE local"
    )?;
    writeln!(
        s,
        "Surfpool validator (a local mainnet mirror at `{}`), treated as mainnet. It is NOT",
        args.rpc_url
    )?;
    writeln!(
        s,
        "a public deploy: the transaction signatures below are local-validator signatures, so"
    )?;
    writeln!(
        s,
        "they are reproducible by re-running the soak against a fresh Surfpool, not lookups on a"
    )?;
    writeln!(s, "public explorer.")?;
    writeln!(s)?;
    writeln!(s, "- generated: unix {now}")?;
    writeln!(s, "- program id: `{program_id}`")?;
    writeln!(s, "- pool PDA: `{pool}` (authority / relay `{relay}`)")?;
    writeln!(
        s,
        "- pool config: epoch_slots={}, k_floor={}, entry_fee={} lamports, reward_bps={}",
        args.epoch_slots, args.k_floor, args.entry_fee, args.reward_bps
    )?;
    writeln!(
        s,
        "- reward pool accrued from entry fees at end of run: {} lamports",
        final_pool.reward_pool
    )?;
    writeln!(
        s,
        "- total leaves appended: {}",
        final_pool.commitment_count
    )?;
    writeln!(s)?;

    writeln!(s, "## What was exercised")?;
    writeln!(s)?;
    writeln!(
        s,
        "1. **Setup** - airdrop relay + payer, ensure the program is deployed, `InitPool`"
    )?;
    writeln!(
        s,
        "   a fresh pool with a nonzero entry fee + reward split, and create the pool ALT."
    )?;
    writeln!(
        s,
        "2. **Crowd path (PlainTransfer)** - 4 participants commit the SAME action into one"
    )?;
    writeln!(
        s,
        "   shared epoch; after the window closes the gasless coordinator"
    )?;
    writeln!(
        s,
        "   (`RpcSettleSubmitter`) settles ONE atomic transaction: ComputeBudget +"
    )?;
    writeln!(s, "   `SettleEpoch` + 4 identical System transfers.")?;
    writeln!(
        s,
        "3. **ZK opt-in path** - `mirror-cli deposit-commit` escrows to a FRESH recipient;"
    )?;
    writeln!(
        s,
        "   after the window closes `mirror-cli prove` generates a snarkjs-verified Groth16"
    )?;
    writeln!(
        s,
        "   membership proof and the relay submits `SettleZk`, moving the escrow to the"
    )?;
    writeln!(s, "   fresh recipient.")?;
    writeln!(
        s,
        "4. **Adversarial** - under-floor epoch does not settle (on-chain `BelowKFloor` +"
    )?;
    writeln!(
        s,
        "   off-chain coordinator roll-forward); duplicate crowd nullifier rejected"
    )?;
    writeln!(
        s,
        "   (`NullifierSpent`); re-settle rejected (`EpochAlreadySettled`); ZK settle to a"
    )?;
    writeln!(
        s,
        "   mismatched recipient rejected (`ActionHashMismatch`); ZK replay rejected"
    )?;
    writeln!(s, "   (`NullifierSpent`).")?;
    writeln!(s)?;

    writeln!(s, "## On-chain assertions")?;
    writeln!(s)?;
    let passed = report.checks.iter().filter(|(_, p, _)| *p).count();
    writeln!(s, "{passed}/{} assertions passed.", report.checks.len())?;
    writeln!(s)?;
    writeln!(s, "| result | assertion | detail |")?;
    writeln!(s, "| --- | --- | --- |")?;
    for (label, pass, detail) in &report.checks {
        writeln!(
            s,
            "| {} | {} | {} |",
            if *pass { "PASS" } else { "FAIL" },
            label,
            detail.replace('|', "\\|")
        )?;
    }
    writeln!(s)?;

    writeln!(s, "## Captured transaction signatures")?;
    writeln!(s)?;
    writeln!(s, "| step | signature |")?;
    writeln!(s, "| --- | --- |")?;
    for (label, sig) in &report.sigs {
        writeln!(s, "| {label} | `{sig}` |")?;
    }
    writeln!(s)?;

    writeln!(s, "## Reproduce")?;
    writeln!(s)?;
    writeln!(
        s,
        "With a local Surfpool running at `{}` (treated as mainnet):",
        args.rpc_url
    )?;
    writeln!(s)?;
    writeln!(s, "```sh")?;
    writeln!(s, "# 1. build the on-chain program and the host workspace")?;
    writeln!(
        s,
        "cargo build-sbf --manifest-path programs/mirror-pool/Cargo.toml"
    )?;
    writeln!(s, "cargo build --workspace")?;
    writeln!(s)?;
    writeln!(
        s,
        "# 2. deploy the program (the soak also does this if it is missing)"
    )?;
    writeln!(s, "solana program deploy \\")?;
    writeln!(s, "  --url {} \\", args.rpc_url)?;
    writeln!(
        s,
        "  --program-id programs/mirror-pool/target/deploy/mirror_pool-keypair.json \\"
    )?;
    writeln!(s, "  programs/mirror-pool/target/deploy/mirror_pool.so")?;
    writeln!(s)?;
    writeln!(
        s,
        "# 3. (ZK path) ensure snarkjs + the circuit artifacts are present"
    )?;
    writeln!(
        s,
        "#    circuits/membership_final.zkey, circuits/membership_js/membership.wasm,"
    )?;
    writeln!(
        s,
        "#    circuits/artifacts/verification_key.json  (build with `bash circuits/build.sh`)"
    )?;
    writeln!(s)?;
    writeln!(
        s,
        "# 4. run the soak (defaults target the running Surfpool + the built program id)"
    )?;
    writeln!(s, "cargo run -p mirror-soak -- \\")?;
    writeln!(s, "  --rpc-url {} \\", args.rpc_url)?;
    writeln!(s, "  --program-id {program_id} \\")?;
    writeln!(
        s,
        "  --epoch-slots {} --k-floor {}",
        args.epoch_slots, args.k_floor
    )?;
    writeln!(s, "```")?;
    writeln!(s)?;
    writeln!(
        s,
        "Every run creates a fresh pool (a fresh relay authority), so the run is"
    )?;
    writeln!(
        s,
        "self-contained and repeatable; the signatures above are from this run."
    )?;

    let docs = root.join("docs");
    std::fs::create_dir_all(&docs)?;
    std::fs::write(docs.join("PROOF.md"), s)?;
    Ok(())
}
