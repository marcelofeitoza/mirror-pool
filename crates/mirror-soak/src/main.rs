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
//!    exists, and a replay is rejected (nullifier spent). The soak makes ONE ZK
//!    deposit, so this window's nominal set is 1 and `prove`'s anonymity floor
//!    is waived on purpose (`--accept-thin-set`): the step proves the mechanism,
//!    not anonymity.
//! 4. **Adversarial** - an under-floor epoch does not settle (on-chain
//!    BelowKFloor + off-chain coordinator roll-forward); a duplicate crowd
//!    nullifier is rejected (NullifierSpent); a re-settle is rejected
//!    (EpochAlreadySettled); a ZK settle to a mismatched recipient is rejected
//!    (ActionHashMismatch).
//!
//! The soak uses the real shipped components: the participant CLI (`mirror-cli`)
//! for the ZK deposit-commit + prove, and the gasless coordinator library
//! (`mirror_coordinator::RpcSettleSubmitter`) for the atomic crowd settlement.

use std::path::Path;
use std::process::Command;
use std::str::FromStr;
use std::sync::Arc;

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
    commit as core_commit, nullifier as core_nullifier, ActionClass, Epoch, EpochSchedule,
    Nullifier, Secret, SizeBucket,
};
use mirror_soak::{
    airdrop, checks_table, cli_bin, clone_keypair, commit_ix, first_line, fund, hex_decode,
    init_pool_ix, install_vk, is_custom, new_keypair, parse_kv, pool_pda, repo_root, run_cli, send,
    sigs_table, wait_until_slot, which, write_report_json, Report, CLOCK_SYSVAR_ID,
    DEFAULT_RPC_URL, SYSTEM_PROGRAM_ID,
};

use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_message::AddressLookupTableAccount;
use solana_pubkey::Pubkey;
use solana_signer::Signer;

// ---------------------------------------------------------------------------
// CLI args
// ---------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(
    name = "mirror-soak",
    about = "End-to-end Surfpool soak: crowd + ZK settlement paths, adversarial cases, on-chain verification"
)]
struct Args {
    /// RPC endpoint (default: the running local Surfpool).
    #[arg(long, default_value = DEFAULT_RPC_URL)]
    rpc_url: String,
    /// mirror-pool program id (base58). Defaults to the deployed keypair's pubkey
    /// (programs/mirror-pool/target/deploy/mirror_pool-keypair.json), so a fresh
    /// clone that builds + deploys locally works without passing this.
    #[arg(long)]
    program_id: Option<String>,
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
// Deployment (the only environment step this soak does not share)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let args = Args::parse();
    let program_id = match &args.program_id {
        Some(s) => Pubkey::from_str(s).map_err(|e| anyhow!("invalid --program-id: {e}"))?,
        None => {
            // Derive from the built deploy keypair so a fresh clone is self-consistent.
            let kp =
                repo_root()?.join("programs/mirror-pool/target/deploy/mirror_pool-keypair.json");
            let out = Command::new("solana")
                .args(["address", "-k", &kp.to_string_lossy()])
                .output()
                .context(
                    "deriving the program id via `solana address -k` (or pass --program-id)",
                )?;
            if !out.status.success() {
                bail!(
                    "could not derive program id from {} (run `cargo build-sbf` first, or pass --program-id): {}",
                    kp.display(),
                    String::from_utf8_lossy(&out.stderr)
                );
            }
            let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
            Pubkey::from_str(&s).map_err(|e| anyhow!("derived program id is invalid: {e}"))?
        }
    };
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
    fund(&args.rpc_url, &relay.pubkey(), 100, 150_000_000)?;
    fund(&args.rpc_url, &payer.pubkey(), 100, 40_000_000)?;
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

    // Publish the MEMBERSHIP verifying key into its write-once registry PDA.
    // SETTLE_ZK reads its key from that account rather than from the program's
    // code, and re-checks it against a compile-time digest on every verify, so a
    // fresh deployment must publish it once before any ZK settle can land.
    let sig = install_vk(
        &cli_bin()?,
        &root,
        &args.rpc_url,
        &program_id,
        &keys_dir.join("payer.json"),
        "membership",
    )?;
    report.check(
        "membership verifying key published into its write-once registry PDA",
        !sig.is_empty(),
        format!("init_vk signature={sig}"),
    );
    report.sig("init_vk_membership", &sig);

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

    // Align to a fresh window so all four commits land in one shared epoch. On a
    // public cluster each commit takes real wall-clock to confirm (a confirmed
    // send can be several seconds), so require most of the window to remain
    // before opening the burst; otherwise a later commit can cross the epoch
    // boundary and be rejected (the program derives the epoch from the clock).
    let crowd_headroom = ((w * 3) / 4).max(1);
    let epoch_a = fresh_window(client.as_ref(), w, crowd_headroom).await?;
    println!("  shared epoch: {epoch_a} (window {w} slots)");

    let mut crowd_kps: Vec<Arc<Keypair>> = Vec::new();
    let mut crowd_nfs: Vec<Nullifier> = Vec::new();
    for i in 0..4u8 {
        let kp = Arc::new(new_keypair(&keys_dir, &format!("crowd-{i}"))?);
        fund(&args.rpc_url, &kp.pubkey(), 5, 20_000_000)?;
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
        fund(&args.rpc_url, &kp.pubkey(), 5, 20_000_000)?;
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
    let snarkjs = which("snarkjs").unwrap_or_else(|| "snarkjs".to_string());

    let depositor = new_keypair(&keys_dir, "zk-depositor")?;
    fund(&args.rpc_url, &depositor.pubkey(), 5, 100_000_000)?;
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
    //
    // `--accept-thin-set` is passed DELIBERATELY and is worth reading twice: this
    // soak makes exactly ONE ZK deposit, so the window it settles into has a
    // nominal set of 1 and `prove` would otherwise refuse (correctly). What this
    // step demonstrates is that the proof, the binding, and the settlement work
    // end to end; it demonstrates NOTHING about anonymity, because a set of one
    // is not an anonymity set. A real deployment must not pass this flag. The
    // emitted bundle records the waived count in its `anonymity` block.
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
            "--accept-thin-set",
        ],
    )?;
    report.check(
        "Groth16 membership proof generated + verified (in-process ark-groth16)",
        true,
        "mirror-cli prove produced a SettleZk whose proof it generated and verified in-process",
    );
    let emit: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&emit_path)?).context("read emit")?;
    let settle_data = hex_decode(emit["settle_zk_data_hex"].as_str().unwrap())?;
    let zk_nf_pda = Pubkey::from_str(emit["nullifier_pda"].as_str().unwrap())?;
    let emit_authority = Pubkey::from_str(emit["authority"].as_str().unwrap())?;
    let zk_vk_registry = Pubkey::from_str(
        emit["vk_registry"]
            .as_str()
            .ok_or_else(|| anyhow!("prove emit is missing vk_registry"))?,
    )?;
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
                // The write-once, digest-pinned MEMBERSHIP verifying key. The
                // CLI emits its address so the driver never derives it itself.
                AccountMeta::new_readonly(zk_vk_registry, false),
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
    // When MIRROR_PROOF_JSON is set (the public-devnet path), emit a machine
    // readable report and DO NOT touch docs/PROOF.md; the caller stitches the
    // devnet run into PROOF.md itself so the committed Surfpool proof is
    // preserved. Otherwise write the Surfpool PROOF.md as before.
    if let Ok(json_path) = std::env::var("MIRROR_PROOF_JSON") {
        let meta = serde_json::json!({
            "suite": "behavioral",
            "rpc_url": args.rpc_url,
            "program_id": program_id.to_string(),
            "pool": pool.to_string(),
            "relay": relay.pubkey().to_string(),
            "epoch_slots": args.epoch_slots,
            "k_floor": args.k_floor,
            "entry_fee": args.entry_fee,
            "reward_bps": args.reward_bps,
            "zk_amount": args.zk_amount,
            "reward_pool_final": final_pool.reward_pool,
            "leaves_appended": final_pool.commitment_count,
        });
        write_report_json(&json_path, meta, &report)?;
        println!("  wrote report json {json_path}");
    } else {
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
    }

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

    s.push_str(
        r##"# mirror-pool - live Surfpool soak proof

This documents an automated end-to-end run of `mirror-soak` against a LIVE local
"##,
    );
    writeln!(
        s,
        "Surfpool validator (a local mainnet mirror at `{}`), treated as mainnet. It is NOT",
        args.rpc_url
    )?;
    s.push_str(
        r##"a public deploy: the transaction signatures below are local-validator signatures, so
they are reproducible by re-running the soak against a fresh Surfpool, not lookups on a
public explorer.

"##,
    );
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

    s.push_str(
        r##"## What was exercised

1. **Setup** - airdrop relay + payer, ensure the program is deployed, `InitPool`
   a fresh pool with a nonzero entry fee + reward split, and create the pool ALT.
2. **Crowd path (PlainTransfer)** - 4 participants commit the SAME action into one
   shared epoch; after the window closes the gasless coordinator
   (`RpcSettleSubmitter`) settles ONE atomic transaction: ComputeBudget +
   `SettleEpoch` + 4 identical System transfers.
3. **ZK opt-in path** - `mirror-cli deposit-commit` escrows to a FRESH recipient;
   after the window closes `mirror-cli prove` generates an in-process-verified Groth16
   membership proof and the relay submits `SettleZk`, moving the escrow to the
   fresh recipient.
   This soak makes ONE ZK deposit, so its ZK window has a nominal set of 1 and the
   `prove` floor is waived with `--accept-thin-set`. It proves the proof, the
   binding, and the settlement, and proves NOTHING about anonymity: a set of one
   is not an anonymity set. `SettleZk` has no on-chain floor, by design and for
   the reason given in `docs/THREAT_MODEL.md` section 4.
4. **Adversarial** - under-floor epoch does not settle (on-chain `BelowKFloor` +
   off-chain coordinator roll-forward); duplicate crowd nullifier rejected
   (`NullifierSpent`); re-settle rejected (`EpochAlreadySettled`); ZK settle to a
   mismatched recipient rejected (`ActionHashMismatch`); ZK replay rejected
   (`NullifierSpent`).

"##,
    );

    checks_table(&mut s, report, "##");

    sigs_table(&mut s, report, "##");

    writeln!(s, "## Reproduce")?;
    writeln!(s)?;
    writeln!(
        s,
        "With a local Surfpool running at `{}` (treated as mainnet):",
        args.rpc_url
    )?;
    s.push_str(
        r##"
```sh
# 1. build the on-chain program and the host workspace
cargo build-sbf --manifest-path programs/mirror-pool/Cargo.toml
cargo build --workspace

# 2. deploy the program (the soak also does this if it is missing)
solana program deploy \
"##,
    );
    writeln!(s, "  --url {} \\", args.rpc_url)?;
    s.push_str(
        r##"  --program-id programs/mirror-pool/target/deploy/mirror_pool-keypair.json \
  programs/mirror-pool/target/deploy/mirror_pool.so

# 3. (ZK path) ensure the circuit artifacts are present (proving is in-process
#    pure Rust; circom/snarkjs are only needed to BUILD these artifacts)
#    circuits/membership_final.zkey, circuits/membership_js/membership.wasm,
#    circuits/artifacts/verification_key.json  (build with `bash circuits/build.sh`)

# 4. run the soak (defaults target the running Surfpool + the built program id)
cargo run -p mirror-soak -- \
"##,
    );
    writeln!(s, "  --rpc-url {} \\", args.rpc_url)?;
    writeln!(s, "  --program-id {program_id} \\")?;
    writeln!(
        s,
        "  --epoch-slots {} --k-floor {}",
        args.epoch_slots, args.k_floor
    )?;
    s.push_str(
        r##"```

Every run creates a fresh pool (a fresh relay authority), so the run is
self-contained and repeatable; the signatures above are from this run.
"##,
    );

    let docs = root.join("docs");
    std::fs::create_dir_all(&docs)?;
    std::fs::write(docs.join("PROOF.md"), s)?;
    Ok(())
}
