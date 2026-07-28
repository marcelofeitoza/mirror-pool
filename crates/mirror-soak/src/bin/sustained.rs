//! `mirror-soak-sustained`: a long-duration run against a live public cluster.
//!
//! The other three soaks answer "does every flow work?" in a few minutes. This
//! one answers a different question, and it is the only one duration can answer:
//! **does the same pool keep behaving identically after hours of real cluster
//! time?** Ten minutes of transactions all land inside one leader schedule, one
//! RPC connection, one slice of cluster load. Hours do not.
//!
//! So the run is deliberately paced rather than fast. It repeats ONE fixed
//! shape - `k` participants commit into a shared epoch window, the window
//! closes, one atomic gasless settlement lands - once per round, for as long as
//! it is told, and records what changed between the first round and the last:
//!
//! * **latency**, per transaction, bucketed by hour, so degradation is visible
//!   rather than asserted;
//! * **the leader set**, sampled continuously, so the run can state how many
//!   distinct block producers actually included its transactions;
//! * **state growth**, on-chain (accounts created, rent locked, accumulator
//!   leaves) and in-process (resident set size), so a leak shows up as a slope;
//! * **drift**, by recomputing the accumulator root off-chain from the same
//!   leaves and comparing it to the root the program wrote, every round.
//!
//! Two properties matter more than the numbers themselves.
//!
//! **It is budget-bounded, not faucet-bounded.** A public cluster rate-limits
//! its faucet hard, so the run airdrops NOTHING. One pre-funded master payer
//! fans out to every key by ordinary system transfer, the per-round cost is
//! measured rather than assumed, and the loop stops itself the moment the
//! master's balance would fall below the configured floor. A run that runs out
//! of money reports the rounds it completed; it does not fail.
//!
//! **Its evidence is re-derivable without a chain.** Every sample and every
//! round is appended to a JSONL file as it happens, so an interrupted run keeps
//! everything it measured, and `--summarize <rounds.jsonl>` recomputes the whole
//! aggregate report from the committed evidence with no RPC access at all.
//! Nothing in the report is a number this binary remembers; it is a number the
//! evidence file still contains.
//!
//! Run (public cluster, one pre-funded master payer):
//!
//! ```text
//! MIRROR_FUNDING_KEYPAIR=<master.json> mirror-soak-sustained \
//!   --rpc-url https://api.devnet.solana.com --program-id <id> \
//!   --duration-secs 14400 --round-interval-secs 165
//! ```

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;

use mirror_behaviors::{Behavior, PlainTransfer};
use mirror_coordinator::client::{RpcSolanaClient, SolanaClient};
use mirror_coordinator::crowd::{
    epoch_pda, nullifier_pda, plain_transfer_shared_accounts, setup_pool_alt, RpcSettleSubmitter,
    SettleContext, SettleParticipant,
};
use mirror_coordinator::{FeePayer, SettleBatch, TxProfile};
use mirror_core::{
    commit as core_commit, merkle_node, merkle_zeros, nullifier as core_nullifier, ActionClass,
    Epoch, Hash32, Nullifier, Secret, SizeBucket, MERKLE_DEPTH,
};
use mirror_soak::{
    clone_keypair, commit_ix, fund, init_pool_ix, new_keypair, pool_pda, repo_root, send,
    transfer_from_master, wait_until_slot, Report, DEFAULT_RPC_URL, SYSTEM_PROGRAM_ID,
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
    name = "mirror-soak-sustained",
    about = "Long-duration crowd-path run against a live cluster: latency, leader spread, state growth, drift"
)]
struct Args {
    /// RPC endpoint. Defaults to the local mirror; point it at a public cluster
    /// for a real sustained run.
    #[arg(long, default_value = DEFAULT_RPC_URL)]
    rpc_url: String,

    /// Deployed mirror-pool program id.
    #[arg(long)]
    program_id: Option<String>,

    /// Total wall-clock target, in seconds. The loop stops at the first round
    /// boundary past this, or earlier if the budget floor is hit.
    #[arg(long, default_value_t = 14_400)]
    duration_secs: u64,

    /// Seconds between the START of consecutive rounds.
    #[arg(long, default_value_t = 165)]
    round_interval_secs: u64,

    /// Seconds between passive chain samples (no transactions, no cost).
    #[arg(long, default_value_t = 20)]
    sample_interval_secs: u64,

    /// Participants per round. Fixed for the whole run on purpose: the pool's
    /// design point is that every settlement has the SAME shape, so varying `k`
    /// would change the thing being measured for degradation.
    #[arg(long, default_value_t = 3)]
    participants: usize,

    /// Slots per epoch window.
    #[arg(long, default_value_t = 64)]
    epoch_slots: u64,

    /// Minimum commits before an epoch may settle.
    #[arg(long, default_value_t = 2)]
    k_floor: u32,

    /// Per-commit anti-Sybil entry fee (lamports).
    #[arg(long, default_value_t = 10_000)]
    entry_fee: u64,

    /// Entry-fee share (bps) that accrues to the on-chain reward pool.
    #[arg(long, default_value_t = 2_500)]
    reward_bps: u16,

    /// Stop when the master payer would drop below this many lamports.
    #[arg(long, default_value_t = 30_000_000)]
    budget_floor_lamports: u64,

    /// Consecutive fully-failed rounds tolerated before giving up.
    #[arg(long, default_value_t = 5)]
    max_consecutive_failures: u32,

    /// Directory for the committed evidence files.
    #[arg(long, default_value = "docs/devnet-run")]
    out_dir: String,

    /// Evidence-file prefix.
    #[arg(long, default_value = "sustained")]
    tag: String,

    /// Re-derive the aggregate report from an existing rounds JSONL and exit.
    /// No RPC, no keys, no chain: it reads only the committed evidence.
    #[arg(long)]
    summarize: Option<String>,
}

// ---------------------------------------------------------------------------
// Evidence records
// ---------------------------------------------------------------------------

/// One passive observation of the cluster and of this process. Costs nothing.
#[derive(serde::Serialize, serde::Deserialize)]
struct Sample {
    /// Unix seconds.
    t: u64,
    /// Seconds since the run started.
    el: u64,
    /// Absolute slot.
    slot: u64,
    /// Cluster block height.
    bh: u64,
    /// Cluster epoch (the validator's, not the pool's).
    cep: u64,
    /// Leader of the current slot, base58.
    leader: String,
    /// Round-trip milliseconds for the epoch-info read.
    lat_ms: u64,
    /// Pool leaves appended so far.
    cc: u64,
    /// First 16 hex chars of the pool's current accumulator root.
    root: String,
    /// This process's resident set size, KiB.
    rss_kb: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    err: Option<String>,
}

/// One settlement round: the fixed shape, timed and verified.
#[derive(serde::Serialize, serde::Deserialize)]
struct Round {
    /// Round index, from 0.
    i: u64,
    /// Unix seconds at round start.
    t: u64,
    /// Seconds since the run started.
    el: u64,
    /// Pool epoch id this round settled.
    epoch: u64,
    /// Participants in this round.
    k: usize,
    /// Absolute slot when the round opened.
    slot: u64,
    /// Commit signatures, in order.
    commit_sigs: Vec<String>,
    /// Per-commit submit-to-confirmed milliseconds.
    commit_ms: Vec<u64>,
    /// The atomic settlement signature.
    settle_sig: String,
    /// Settlement submit-to-confirmed milliseconds.
    settle_ms: u64,
    /// Compute units the settlement consumed, as reported by the cluster.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    settle_cu: Option<u64>,
    /// Compute units the first commit consumed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    commit_cu: Option<u64>,
    /// Epoch account reports `settled` after the settlement.
    settled: bool,
    /// Nullifier PDAs found on-chain (anti-replay), out of `k`.
    nf_ok: usize,
    /// Lamports the sink was credited by the atomic settlement.
    sink_delta: u64,
    /// Accumulator root the program wrote, hex.
    root_onchain: String,
    /// Accumulator root recomputed off-chain from the same leaves, hex.
    root_host: String,
    /// True when the two roots disagree. Only meaningful when `drift_checked`.
    drift: bool,
    /// False when the off-chain reference could not be trusted this round (a
    /// commit whose outcome was ambiguous), so `drift` is not a verdict.
    #[serde(default = "yes")]
    drift_checked: bool,
    /// Master payer balance after the round.
    master_lamports: u64,
    /// Lamports the whole run has spent from the master so far.
    spent_lamports: u64,
    /// Everything that went wrong this round, in order.
    #[serde(default)]
    errors: Vec<String>,
}

fn yes() -> bool {
    true
}

/// Lamports the sink keeps back on every recycle. Above the rent-exempt minimum
/// for an empty system account, with room for its own fees.
const SINK_FLOAT: u64 = 1_500_000;

/// The balance every participant is topped back up to after each round: one
/// full transfer bucket plus enough headroom to pay an Epoch PDA's rent, an
/// entry fee and a signature, and still stay rent-exempt afterwards.
fn participant_target(bucket: u64) -> u64 {
    bucket + 6_000_000
}

// ---------------------------------------------------------------------------
// Host-side reference accumulator (the drift check)
// ---------------------------------------------------------------------------

/// The same append-only frontier the program keeps, restated off-chain.
///
/// It is deliberately a second statement of the algorithm rather than a copy of
/// the program's code: it keeps the full precomputed zeros ladder instead of
/// advancing a running zero hash. Both sides hash with the same Poseidon
/// parameterization, so this does not prove the hash independent; what it pins
/// is the wiring - sibling order, level order, and the leaf index - over
/// hundreds of appends spread across hours, which is exactly where a drift bug
/// would hide.
struct HostFrontier {
    zeros: Vec<Hash32>,
    filled: Vec<Hash32>,
    count: u64,
}

impl HostFrontier {
    fn new() -> Self {
        Self {
            zeros: merkle_zeros(MERKLE_DEPTH),
            filled: vec![[0u8; 32]; MERKLE_DEPTH],
            count: 0,
        }
    }

    /// Append one leaf; return the new root.
    fn append(&mut self, leaf: &Hash32) -> Hash32 {
        let mut index = self.count;
        let mut node = *leaf;
        for level in 0..MERKLE_DEPTH {
            if index.is_multiple_of(2) {
                self.filled[level] = node;
                node = merkle_node(&node, &self.zeros[level]);
            } else {
                node = merkle_node(&self.filled[level], &node);
            }
            index /= 2;
        }
        self.count += 1;
        node
    }
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn hex32(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Resident set size of THIS process, in KiB, via `ps`. Returns 0 when `ps` is
/// unavailable rather than failing a run over a metric.
fn rss_kb() -> u64 {
    Command::new("ps")
        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
        .output()
        .ok()
        .and_then(|o| {
            String::from_utf8_lossy(&o.stdout)
                .trim()
                .parse::<u64>()
                .ok()
        })
        .unwrap_or(0)
}

/// Pool fields this run reads, at the on-chain offsets documented in
/// `state::pool`: version 0, epoch_slots 1, k_floor 9, commitment_count 13,
/// current_root 21, entry_fee 85, reward_pool 1764.
struct PoolView {
    version: u8,
    epoch_slots: u64,
    k_floor: u32,
    commitment_count: u64,
    current_root: [u8; 32],
    reward_pool: u64,
}

impl PoolView {
    fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 1772 {
            bail!("pool account too short: {} bytes", data.len());
        }
        let mut root = [0u8; 32];
        root.copy_from_slice(&data[21..53]);
        Ok(Self {
            version: data[0],
            epoch_slots: u64::from_le_bytes(data[1..9].try_into()?),
            k_floor: u32::from_le_bytes(data[9..13].try_into()?),
            commitment_count: u64::from_le_bytes(data[13..21].try_into()?),
            current_root: root,
            reward_pool: u64::from_le_bytes(data[1764..1772].try_into()?),
        })
    }
}

/// Epoch fields: version 0, epoch_id 1, nominal_k 9, settled 13.
struct EpochView {
    epoch_id: u64,
    commit_count: u32,
    settled: bool,
}

impl EpochView {
    fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 14 {
            bail!("epoch account too short: {} bytes", data.len());
        }
        Ok(Self {
            epoch_id: u64::from_le_bytes(data[1..9].try_into()?),
            commit_count: u32::from_le_bytes(data[9..13].try_into()?),
            settled: data[13] != 0,
        })
    }
}

/// Read and decode the pool account, or `None` on any read/decode failure.
async fn read_pool(client: &dyn SolanaClient, pool: &Pubkey) -> Option<PoolView> {
    client
        .get_account(pool)
        .await
        .ok()
        .flatten()
        .and_then(|a| PoolView::decode(&a.data).ok())
}

/// A bare System-program transfer instruction (enum index 2 + lamports LE).
fn system_transfer_ix(from: &Pubkey, to: &Pubkey, lamports: u64) -> Instruction {
    let mut data = Vec::with_capacity(12);
    data.extend_from_slice(&2u32.to_le_bytes());
    data.extend_from_slice(&lamports.to_le_bytes());
    Instruction {
        program_id: SYSTEM_PROGRAM_ID,
        accounts: vec![AccountMeta::new(*from, true), AccountMeta::new(*to, false)],
        data,
    }
}

/// The Dwell PDA: seeds `[b"dwell", pool, participant]`.
fn dwell_pda(program_id: &Pubkey, pool: &Pubkey, participant: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[b"dwell", pool.as_ref(), participant.as_ref()], program_id).0
}

/// Wait until the current epoch window still has `headroom` slots left, so a
/// whole commit burst lands inside ONE window even on a public cluster where
/// each confirmation costs real seconds.
async fn fresh_window(
    client: &dyn SolanaClient,
    epoch_slots: u64,
    headroom: u64,
) -> Result<(u64, u64)> {
    let slot = client.get_slot().await?;
    let remaining = epoch_slots - (slot % epoch_slots);
    if remaining >= headroom {
        return Ok((slot / epoch_slots, slot));
    }
    let next = (slot / epoch_slots + 1) * epoch_slots;
    let slot2 = wait_until_slot(client, next).await?;
    Ok((slot2 / epoch_slots, slot2))
}

/// Compute units a landed transaction consumed, or `None` when the cluster does
/// not report them. Never fails the round.
async fn tx_compute_units(rpc: &RpcSolanaClient, signature: &str) -> Option<u64> {
    use solana_rpc_client_api::config::RpcTransactionConfig;
    use solana_transaction_status_client_types::UiTransactionEncoding;

    let sig = solana_signature::Signature::from_str(signature).ok()?;
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
        .ok()?;
    confirmed.transaction.meta?.compute_units_consumed.into()
}

// ---------------------------------------------------------------------------
// Aggregation (shared by the live run and `--summarize`)
// ---------------------------------------------------------------------------

fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

/// Everything the aggregate report says, derived ONLY from the round records.
fn aggregate(rounds: &[Round]) -> serde_json::Value {
    let completed: Vec<&Round> = rounds.iter().filter(|r| r.errors.is_empty()).collect();
    let mut all_ms: Vec<u64> = Vec::new();
    for r in rounds {
        all_ms.extend(r.commit_ms.iter().copied());
        if r.settle_ms > 0 {
            all_ms.push(r.settle_ms);
        }
    }
    all_ms.sort_unstable();

    // Hour buckets, so "did it get slower?" is answered by the evidence rather
    // than by a claim. Each bucket carries its own confirmation latencies.
    let mut buckets: Vec<serde_json::Value> = Vec::new();
    let last_el = rounds.last().map(|r| r.el).unwrap_or(0);
    let hours = (last_el / 3_600) + 1;
    for h in 0..hours {
        let mut ms: Vec<u64> = Vec::new();
        let mut n_rounds = 0;
        let mut n_fail = 0;
        let mut cu: Vec<u64> = Vec::new();
        for r in rounds.iter().filter(|r| r.el / 3_600 == h) {
            n_rounds += 1;
            if !r.errors.is_empty() {
                n_fail += 1;
            }
            ms.extend(r.commit_ms.iter().copied());
            if r.settle_ms > 0 {
                ms.push(r.settle_ms);
            }
            if let Some(c) = r.settle_cu {
                cu.push(c);
            }
        }
        ms.sort_unstable();
        buckets.push(serde_json::json!({
            "hour": h,
            "rounds": n_rounds,
            "rounds_with_errors": n_fail,
            "tx_confirmations": ms.len(),
            "confirm_ms_p50": percentile(&ms, 0.50),
            "confirm_ms_p95": percentile(&ms, 0.95),
            "confirm_ms_max": ms.last().copied().unwrap_or(0),
            "settle_cu_min": cu.iter().min().copied().unwrap_or(0),
            "settle_cu_max": cu.iter().max().copied().unwrap_or(0),
        }));
    }

    let txs: usize = rounds
        .iter()
        .map(|r| r.commit_sigs.len() + usize::from(!r.settle_sig.is_empty()))
        .sum();
    let errors: Vec<&String> = rounds.iter().flat_map(|r| r.errors.iter()).collect();
    let settle_cus: Vec<u64> = rounds.iter().filter_map(|r| r.settle_cu).collect();
    let epochs: BTreeSet<u64> = rounds.iter().map(|r| r.epoch).collect();

    serde_json::json!({
        "rounds_attempted": rounds.len(),
        "rounds_clean": completed.len(),
        "rounds_with_errors": rounds.len() - completed.len(),
        "distinct_pool_epochs": epochs.len(),
        "transactions_landed": txs,
        "errors_total": errors.len(),
        "errors": errors,
        "drift_rounds": rounds.iter().filter(|r| r.drift).count(),
        "rounds_root_checked": rounds.iter().filter(|r| r.drift_checked).count(),
        "rounds_settled": rounds.iter().filter(|r| r.settled).count(),
        "elapsed_secs_last_round": last_el,
        "confirm_ms_p50": percentile(&all_ms, 0.50),
        "confirm_ms_p95": percentile(&all_ms, 0.95),
        "confirm_ms_p99": percentile(&all_ms, 0.99),
        "confirm_ms_max": all_ms.last().copied().unwrap_or(0),
        "settle_cu_min": settle_cus.iter().min().copied().unwrap_or(0),
        "settle_cu_max": settle_cus.iter().max().copied().unwrap_or(0),
        "spent_lamports": rounds.last().map(|r| r.spent_lamports).unwrap_or(0),
        "hourly": buckets,
    })
}

/// Aggregate the passive samples: leader spread, growth slopes, read latency.
fn aggregate_samples(samples: &[Sample]) -> serde_json::Value {
    let leaders: BTreeSet<&str> = samples
        .iter()
        .filter(|s| !s.leader.is_empty())
        .map(|s| s.leader.as_str())
        .collect();
    let mut lat: Vec<u64> = samples
        .iter()
        .map(|s| s.lat_ms)
        .filter(|m| *m > 0)
        .collect();
    lat.sort_unstable();
    let rss: Vec<u64> = samples
        .iter()
        .map(|s| s.rss_kb)
        .filter(|r| *r > 0)
        .collect();
    let cluster_epochs: BTreeSet<u64> = samples.iter().map(|s| s.cep).collect();
    let first = samples.first();
    let last = samples.last();
    serde_json::json!({
        "samples": samples.len(),
        "distinct_slot_leaders": leaders.len(),
        "cluster_epochs_spanned": cluster_epochs.len(),
        "first_slot": first.map(|s| s.slot).unwrap_or(0),
        "last_slot": last.map(|s| s.slot).unwrap_or(0),
        "slots_spanned": last.map(|s| s.slot).unwrap_or(0)
            .saturating_sub(first.map(|s| s.slot).unwrap_or(0)),
        "blocks_spanned": last.map(|s| s.bh).unwrap_or(0)
            .saturating_sub(first.map(|s| s.bh).unwrap_or(0)),
        "read_lat_ms_p50": percentile(&lat, 0.50),
        "read_lat_ms_p95": percentile(&lat, 0.95),
        "read_lat_ms_max": lat.last().copied().unwrap_or(0),
        "rss_kb_first": rss.first().copied().unwrap_or(0),
        "rss_kb_last": rss.last().copied().unwrap_or(0),
        "rss_kb_max": rss.iter().max().copied().unwrap_or(0),
        "sample_errors": samples.iter().filter(|s| s.err.is_some()).count(),
    })
}

fn read_jsonl<T: serde::de::DeserializeOwned>(path: &Path) -> Result<Vec<T>> {
    let raw =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    raw.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str::<T>(l).map_err(|e| anyhow!("bad JSONL line: {e}")))
        .collect()
}

fn append_jsonl<T: serde::Serialize>(path: &Path, record: &T) -> Result<()> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    writeln!(f, "{}", serde_json::to_string(record)?)?;
    f.flush()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Offline mode: re-derive the report from committed evidence, no chain.
    if let Some(path) = &args.summarize {
        let rounds_path = PathBuf::from(path);
        let rounds: Vec<Round> = read_jsonl(&rounds_path)?;
        let mut out = aggregate(&rounds);
        let samples_path = PathBuf::from(path.replace("rounds", "samples"));
        if samples_path.exists() {
            let samples: Vec<Sample> = read_jsonl(&samples_path)?;
            out["passive"] = aggregate_samples(&samples);
        }
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(());
    }

    let program_id = Pubkey::from_str(
        args.program_id
            .as_deref()
            .ok_or_else(|| anyhow!("--program-id is required for a live run"))?,
    )
    .map_err(|e| anyhow!("invalid --program-id: {e}"))?;

    let root = repo_root()?;
    let keys_dir = root.join(".soak/keys-sustained");
    std::fs::create_dir_all(&keys_dir)?;
    let out_dir = root.join(&args.out_dir);
    std::fs::create_dir_all(&out_dir)?;
    let samples_path = out_dir.join(format!("{}-samples.jsonl", args.tag));
    let rounds_path = out_dir.join(format!("{}-rounds.jsonl", args.tag));
    let report_path = out_dir.join(format!("{}-report.json", args.tag));

    let master = std::env::var("MIRROR_FUNDING_KEYPAIR").map_err(|_| {
        anyhow!(
            "MIRROR_FUNDING_KEYPAIR must name the pre-funded master payer: this run never airdrops"
        )
    })?;
    let master_pubkey = {
        let out = Command::new("solana")
            .args(["address", "-k", &master])
            .output()
            .context("resolving the master payer address")?;
        Pubkey::from_str(String::from_utf8_lossy(&out.stdout).trim())
            .map_err(|e| anyhow!("master payer address: {e}"))?
    };

    let rpc = Arc::new(RpcSolanaClient::new(args.rpc_url.clone()));
    let client: Arc<dyn SolanaClient> = rpc.clone();

    let w = args.epoch_slots;
    let k = args.participants;
    let bucket = mirror_behaviors::bucket_lamports(SizeBucket::Nano);

    println!("mirror-soak-sustained");
    println!("  rpc:        {}", args.rpc_url);
    println!("  program:    {program_id}");
    println!("  master:     {master_pubkey}");
    println!(
        "  duration:   {} s   round every {} s   sample every {} s",
        args.duration_secs, args.round_interval_secs, args.sample_interval_secs
    );
    println!(
        "  pool:       k={k}  epoch_slots={w}  k_floor={}  entry_fee={}  reward_bps={}",
        args.k_floor, args.entry_fee, args.reward_bps
    );

    let master_start = mirror_soak::lamports(client.as_ref(), &master_pubkey).await?;
    println!("  master balance at start: {master_start} lamports");
    if master_start <= args.budget_floor_lamports {
        bail!("master payer is already at or below the budget floor: nothing to spend");
    }

    // -- setup --------------------------------------------------------------
    let acc = client
        .get_account(&program_id)
        .await?
        .ok_or_else(|| anyhow!("program {program_id} not found on this cluster"))?;
    if !acc.executable {
        bail!("program {program_id} is not executable");
    }

    let relay = new_keypair(&keys_dir, "sustained-relay")?;
    let payer = new_keypair(&keys_dir, "sustained-payer")?;
    let sink = new_keypair(&keys_dir, "sustained-sink")?;
    // One master airdrop already happened out of band; every key below is funded
    // by ordinary system transfer from it, never by the faucet.
    fund(&args.rpc_url, &relay.pubkey(), 100, 60_000_000)?;
    fund(&args.rpc_url, &payer.pubkey(), 100, 25_000_000)?;
    fund(&args.rpc_url, &sink.pubkey(), 100, 2_000_000)?;

    let pool = pool_pda(&program_id, &relay.pubkey());
    println!("  relay:      {}", relay.pubkey());
    println!("  pool:       {pool}");

    let init_sig = send(
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
    println!("  init_pool:  {init_sig}");

    let ctx0 = SettleContext {
        program_id,
        pool,
        alt: AddressLookupTableAccount {
            key: Pubkey::new_from_array([0u8; 32]),
            addresses: Vec::new(),
        },
    };
    let shared = plain_transfer_shared_accounts(&ctx0, &sink.pubkey());
    let alt = setup_pool_alt(client.as_ref(), &relay, &payer, shared)
        .await
        .context("setup_pool_alt")?;
    let ctx = SettleContext {
        program_id,
        pool,
        alt: alt.clone(),
    };
    println!("  pool ALT:   {}", alt.key);

    // Participants are created ONCE and reused for the whole run, which is what
    // makes the dwell counter and the per-participant float meaningful: the same
    // wallets keep acting for hours.
    let mut participants: Vec<Arc<Keypair>> = Vec::new();
    for i in 0..k {
        let kp = Arc::new(new_keypair(&keys_dir, &format!("sustained-p{i}"))?);
        fund(&args.rpc_url, &kp.pubkey(), 100, participant_target(bucket))?;
        participants.push(kp);
    }

    let action: ActionClass = PlainTransfer::sol(sink.pubkey(), SizeBucket::Nano).action_class();
    let behavior: Arc<dyn Behavior> = Arc::new(PlainTransfer::sol(sink.pubkey(), SizeBucket::Nano));
    let mut frontier = HostFrontier::new();

    // -- passive sampler ----------------------------------------------------
    // Reads only. It runs for the whole window, including the long idle stretch
    // between rounds, which is where leader changes and cluster drift show up.
    let started = Instant::now();
    let start_unix = now_unix();
    let sampler = {
        let rpc = rpc.clone();
        let client = client.clone();
        let samples_path = samples_path.clone();
        let interval = args.sample_interval_secs;
        let duration = args.duration_secs;
        tokio::spawn(async move {
            loop {
                let el = started.elapsed().as_secs();
                if el > duration + 120 {
                    return;
                }
                let t0 = Instant::now();
                let mut err = None;
                let (slot, bh, cep) = match rpc.inner().get_epoch_info().await {
                    Ok(info) => (info.absolute_slot, info.block_height, info.epoch),
                    Err(e) => {
                        err = Some(format!("epoch_info: {e}"));
                        (0, 0, 0)
                    }
                };
                let lat_ms = t0.elapsed().as_millis() as u64;
                // Who is producing THIS slot. Sampled every interval, the set of
                // distinct answers is the run's real leader spread.
                let leader = match rpc.inner().get_slot_leaders(slot, 1).await {
                    Ok(ls) => ls.first().map(|p| p.to_string()).unwrap_or_default(),
                    Err(e) => {
                        err.get_or_insert(format!("slot_leaders: {e}"));
                        String::new()
                    }
                };
                let (cc, rootv) = match client.get_account(&pool).await {
                    Ok(Some(a)) => match PoolView::decode(&a.data) {
                        Ok(pv) => (
                            pv.commitment_count,
                            hex32(&pv.current_root)[..16].to_string(),
                        ),
                        Err(e) => {
                            err.get_or_insert(format!("pool decode: {e}"));
                            (0, String::new())
                        }
                    },
                    Ok(None) => (0, String::new()),
                    Err(e) => {
                        err.get_or_insert(format!("pool read: {e}"));
                        (0, String::new())
                    }
                };
                let s = Sample {
                    t: now_unix(),
                    el,
                    slot,
                    bh,
                    cep,
                    leader,
                    lat_ms,
                    cc,
                    root: rootv,
                    rss_kb: rss_kb(),
                    err,
                };
                let _ = append_jsonl(&samples_path, &s);
                tokio::time::sleep(Duration::from_secs(interval)).await;
            }
        })
    };

    // -- round loop ---------------------------------------------------------
    let mut rounds: Vec<Round> = Vec::new();
    let mut consecutive_failures = 0u32;
    let mut round_index = 0u64;
    // Cleared for good the first time the off-chain reference cannot be lined
    // up with the chain's leaf count. From then on the run reports "not
    // checked" rather than a mismatch it can no longer attribute.
    let mut drift_reference_ok = true;
    let stop_reason;

    loop {
        let elapsed = started.elapsed().as_secs();
        if elapsed >= args.duration_secs {
            stop_reason = "duration reached".to_string();
            break;
        }
        let master_now = mirror_soak::lamports(client.as_ref(), &master_pubkey)
            .await
            .unwrap_or(0);
        if master_now <= args.budget_floor_lamports {
            stop_reason = format!("budget floor reached ({master_now} lamports left)");
            break;
        }
        if consecutive_failures >= args.max_consecutive_failures {
            stop_reason = format!("{consecutive_failures} consecutive failed rounds");
            break;
        }

        let round_started = Instant::now();
        let mut errors: Vec<String> = Vec::new();
        let mut commit_sigs: Vec<String> = Vec::new();
        let mut commit_ms: Vec<u64> = Vec::new();
        let mut nullifiers: Vec<Nullifier> = Vec::new();
        let mut leaves: Vec<Hash32> = Vec::new();

        // Open in a window with most of its slots still ahead, so the whole
        // burst shares one epoch even when a confirmation takes seconds.
        let headroom = ((w * 3) / 4).max(1);
        let (epoch_id, slot) = match fresh_window(client.as_ref(), w, headroom).await {
            Ok(v) => v,
            Err(e) => {
                errors.push(format!("fresh_window: {e}"));
                (0, 0)
            }
        };

        // Leaves the chain had accepted before this round. The reference
        // accumulator is only a verdict when it still agrees with this count.
        let count_before = read_pool(client.as_ref(), &pool)
            .await
            .map(|p| p.commitment_count);

        if errors.is_empty() {
            for (i, kp) in participants.iter().enumerate() {
                // A fresh secret per (round, participant): the nullifier is
                // epoch-scoped anyway, but reusing secrets across hours would
                // make the run weaker than the real thing.
                let mut seed = [0u8; 32];
                seed[..8].copy_from_slice(&round_index.to_le_bytes());
                seed[8] = i as u8;
                seed[9..17].copy_from_slice(&epoch_id.to_le_bytes());
                let secret = Secret::from_bytes(seed);
                let commitment = core_commit(&secret, &action, Epoch(epoch_id));
                let nf = core_nullifier(&secret, Epoch(epoch_id));
                let ep = epoch_pda(&program_id, &pool, Epoch(epoch_id));
                let dwell = dwell_pda(&program_id, &pool, &kp.pubkey());
                let mut ix = commit_ix(&program_id, &pool, &ep, &kp.pubkey(), &commitment.0);
                // Optional 6th account: the participant's dwell counter. Passing
                // it is what makes the incentive layer part of the sustained
                // measurement instead of a one-shot demo.
                ix.accounts.push(AccountMeta::new(dwell, false));

                let t0 = Instant::now();
                match send(client.as_ref(), &[ix], &[kp.as_ref()], &[]).await {
                    Ok(sig) => {
                        commit_ms.push(t0.elapsed().as_millis() as u64);
                        commit_sigs.push(sig);
                        nullifiers.push(nf);
                        leaves.push(commitment.0);
                    }
                    Err(e) => errors.push(format!("commit {i}: {e}")),
                }
            }
        }

        // -- drift, measured on the COMMITS, not on the settlement ----------
        // Commits are what append leaves, so the accumulator can be checked
        // even in a round whose settlement later fails. The reference is only
        // trusted while its leaf count still matches the chain's; if a commit's
        // outcome was ambiguous the round says "not checked" instead of
        // reporting a mismatch it caused itself.
        let mut root_onchain = String::new();
        let mut root_host = String::new();
        let mut drift = false;
        let mut drift_checked = false;
        if let (Some(before), Some(pv)) = (count_before, read_pool(client.as_ref(), &pool).await) {
            let landed = pv.commitment_count.saturating_sub(before) as usize;
            root_onchain = hex32(&pv.current_root);
            if landed == leaves.len() && drift_reference_ok {
                for leaf in &leaves {
                    root_host = hex32(&frontier.append(leaf));
                }
                if frontier.count == pv.commitment_count {
                    drift_checked = true;
                    drift = root_onchain != root_host;
                    if drift {
                        errors.push("accumulator root drift".to_string());
                    }
                } else {
                    drift_reference_ok = false;
                    errors.push(format!(
                        "reference accumulator desynchronized (host {} vs chain {})",
                        frontier.count, pv.commitment_count
                    ));
                }
            } else if drift_reference_ok {
                drift_reference_ok = false;
                errors.push(format!(
                    "commit outcome ambiguous: chain took {landed} leaves, {} sends succeeded",
                    leaves.len()
                ));
            }
        }

        // Settle only if the whole burst landed: a partial burst would settle a
        // different k than the one the round set out to measure.
        let mut settle_sig = String::new();
        let mut settle_ms = 0u64;
        let mut settled = false;
        let mut nf_ok = 0usize;
        let mut sink_delta = 0u64;

        if commit_sigs.len() == k {
            let ep_pda = epoch_pda(&program_id, &pool, Epoch(epoch_id));
            match client.get_account(&ep_pda).await {
                Ok(Some(a)) => match EpochView::decode(&a.data) {
                    Ok(ev) => {
                        if ev.commit_count as usize != k || ev.epoch_id != epoch_id {
                            errors.push(format!(
                                "epoch {epoch_id} holds {} commits (expected {k})",
                                ev.commit_count
                            ));
                        }
                    }
                    Err(e) => errors.push(format!("epoch decode: {e}")),
                },
                Ok(None) => errors.push(format!("epoch {epoch_id} account missing")),
                Err(e) => errors.push(format!("epoch read: {e}")),
            }

            // Wait for the window to close: the program refuses an early settle.
            if let Err(e) = wait_until_slot(client.as_ref(), (epoch_id + 1) * w).await {
                errors.push(format!("wait_until_slot: {e}"));
            }

            let sink_before = mirror_soak::lamports(client.as_ref(), &sink.pubkey())
                .await
                .unwrap_or(0);

            let mut submitter = RpcSettleSubmitter::new(client.clone(), ctx.clone());
            submitter.register_signer(Arc::new(clone_keypair(&relay)));
            let roster: Vec<SettleParticipant> = participants
                .iter()
                .zip(nullifiers.iter())
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
            submitter.register_epoch(Epoch(epoch_id), roster);
            let batch = SettleBatch {
                epoch: Epoch(epoch_id),
                nullifiers: nullifiers.clone(),
                fee_payer: FeePayer(relay.pubkey().to_bytes()),
                tx_profile: TxProfile::default(),
            };
            let t0 = Instant::now();
            match submitter.submit_crowd(&batch).await {
                Ok(receipt) => {
                    settle_ms = t0.elapsed().as_millis() as u64;
                    settle_sig = receipt.signature;
                }
                Err(e) => errors.push(format!("settle: {e:#}")),
            }

            if !settle_sig.is_empty() {
                if let Ok(Some(a)) = client.get_account(&ep_pda).await {
                    settled = EpochView::decode(&a.data)
                        .map(|e| e.settled)
                        .unwrap_or(false);
                }
                for nf in &nullifiers {
                    let pda = nullifier_pda(&program_id, &pool, Epoch(epoch_id), nf);
                    if let Ok(Some(acc)) = client.get_account(&pda).await {
                        if acc.owner == program_id && acc.data.first() == Some(&1u8) {
                            nf_ok += 1;
                        }
                    }
                }
                let sink_after = mirror_soak::lamports(client.as_ref(), &sink.pubkey())
                    .await
                    .unwrap_or(0);
                sink_delta = sink_after.saturating_sub(sink_before);
                if sink_delta != (k as u64) * bucket {
                    errors.push(format!(
                        "sink credited {sink_delta} lamports (expected {})",
                        (k as u64) * bucket
                    ));
                }
                if !settled {
                    errors.push("epoch not marked settled".to_string());
                }
                if nf_ok != k {
                    errors.push(format!("{nf_ok}/{k} nullifier PDAs present"));
                }
            }
        }

        // Recycle the settled lamports from the sink back to the participants,
        // so the run's cost is rent plus fees rather than transfer volume, and
        // top each wallet back up to the SAME target. Equal shares would not do:
        // whoever commits first in a window also pays that window's Epoch PDA
        // rent, so the wallets drift apart and the shortest one eventually
        // cannot make its transfer while staying rent-exempt.
        let sink_now = mirror_soak::lamports(client.as_ref(), &sink.pubkey())
            .await
            .unwrap_or(0);
        let mut budget = sink_now.saturating_sub(SINK_FLOAT);
        let mut refills: Vec<Instruction> = Vec::new();
        for p in &participants {
            let bal = mirror_soak::lamports(client.as_ref(), &p.pubkey())
                .await
                .unwrap_or(0);
            let need = participant_target(bucket).saturating_sub(bal);
            let give = need.min(budget);
            if give > 0 {
                refills.push(system_transfer_ix(&sink.pubkey(), &p.pubkey(), give));
                budget -= give;
            }
        }
        if !refills.is_empty() {
            if let Err(e) = send(client.as_ref(), &refills, &[&sink], &[]).await {
                errors.push(format!("recycle: {e}"));
            }
        }

        // Compute units, best effort: they are evidence, not a gate.
        let settle_cu = if settle_sig.is_empty() {
            None
        } else {
            tx_compute_units(&rpc, &settle_sig).await
        };
        let commit_cu = match commit_sigs.first() {
            Some(s) => tx_compute_units(&rpc, s).await,
            None => None,
        };

        // Whatever the sink could not cover comes from the master, by system
        // transfer. Never a faucet call: the faucet is rate-limited and this run
        // is long, so one pre-funded master is the only funding source.
        for p in &participants {
            let bal = mirror_soak::lamports(client.as_ref(), &p.pubkey())
                .await
                .unwrap_or(0);
            if bal < bucket + 2_000_000 {
                if let Err(e) = transfer_from_master(
                    &args.rpc_url,
                    &master,
                    &p.pubkey(),
                    participant_target(bucket).saturating_sub(bal),
                ) {
                    errors.push(format!("topup: {e}"));
                }
            }
        }
        let relay_bal = mirror_soak::lamports(client.as_ref(), &relay.pubkey())
            .await
            .unwrap_or(0);
        if relay_bal < 10_000_000 {
            if let Err(e) =
                transfer_from_master(&args.rpc_url, &master, &relay.pubkey(), 30_000_000)
            {
                errors.push(format!("relay topup: {e}"));
            }
        }

        let master_lamports = mirror_soak::lamports(client.as_ref(), &master_pubkey)
            .await
            .unwrap_or(0);
        let record = Round {
            i: round_index,
            t: now_unix(),
            el: started.elapsed().as_secs(),
            epoch: epoch_id,
            k,
            slot,
            commit_sigs,
            commit_ms,
            settle_sig,
            settle_ms,
            settle_cu,
            commit_cu,
            settled,
            nf_ok,
            sink_delta,
            root_onchain,
            root_host,
            drift,
            drift_checked,
            master_lamports,
            spent_lamports: master_start.saturating_sub(master_lamports),
            errors,
        };
        if record.errors.is_empty() {
            consecutive_failures = 0;
        } else {
            consecutive_failures += 1;
        }
        println!(
            "  round {:>3}  el={:>5}s  epoch={}  settle={}  errs={}  master={} lamports",
            record.i,
            record.el,
            record.epoch,
            if record.settled { "ok" } else { "NO" },
            record.errors.len(),
            record.master_lamports
        );
        append_jsonl(&rounds_path, &record)?;
        rounds.push(record);
        round_index += 1;

        // Pace from the START of the round, so the cadence is the configured
        // one regardless of how long a round took.
        let spent = round_started.elapsed().as_secs();
        if spent < args.round_interval_secs {
            tokio::time::sleep(Duration::from_secs(args.round_interval_secs - spent)).await;
        }
    }

    sampler.abort();

    // -- report -------------------------------------------------------------
    let wall = started.elapsed().as_secs();
    let master_end = mirror_soak::lamports(client.as_ref(), &master_pubkey)
        .await
        .unwrap_or(0);
    let pool_end = client.get_account(&pool).await.ok().flatten();
    let pv = pool_end
        .as_ref()
        .and_then(|a| PoolView::decode(&a.data).ok());
    let samples: Vec<Sample> = read_jsonl(&samples_path).unwrap_or_default();

    let mut report = Report::default();
    report.check(
        "run sustained for the configured window",
        wall + args.round_interval_secs >= args.duration_secs,
        format!(
            "{wall} s of wall clock, {} rounds, stop reason: {stop_reason}",
            rounds.len()
        ),
    );
    report.check(
        "every round settled on-chain",
        rounds.iter().all(|r| r.settled),
        format!(
            "{}/{} rounds marked settled",
            rounds.iter().filter(|r| r.settled).count(),
            rounds.len()
        ),
    );
    report.check(
        "no accumulator drift across the whole run",
        rounds.iter().all(|r| !r.drift) && rounds.iter().any(|r| r.drift_checked),
        format!(
            "{} leaves appended; {} rounds root-checked against the off-chain reference, {} drifted",
            pv.as_ref().map(|p| p.commitment_count).unwrap_or(0),
            rounds.iter().filter(|r| r.drift_checked).count(),
            rounds.iter().filter(|r| r.drift).count()
        ),
    );
    report.check(
        "anti-replay held for every settled round",
        rounds.iter().all(|r| !r.settled || r.nf_ok == k),
        format!(
            "{} nullifier PDAs created",
            rounds.iter().map(|r| r.nf_ok).sum::<usize>()
        ),
    );
    report.check(
        "settlement compute stayed within one narrow band",
        {
            let cus: Vec<u64> = rounds.iter().filter_map(|r| r.settle_cu).collect();
            match (cus.iter().min(), cus.iter().max()) {
                (Some(lo), Some(hi)) => hi - lo <= 4_000,
                _ => false,
            }
        },
        {
            let cus: Vec<u64> = rounds.iter().filter_map(|r| r.settle_cu).collect();
            format!(
                "settle CU min {} max {} over {} settlements",
                cus.iter().min().copied().unwrap_or(0),
                cus.iter().max().copied().unwrap_or(0),
                cus.len()
            )
        },
    );

    let agg = aggregate(&rounds);
    let passive = aggregate_samples(&samples);
    let meta = serde_json::json!({
        "suite": "sustained",
        "rpc_url": args.rpc_url,
        "program_id": program_id.to_string(),
        "pool": pool.to_string(),
        "pool_authority_relay": relay.pubkey().to_string(),
        "sink": sink.pubkey().to_string(),
        "alt": alt.key.to_string(),
        "init_pool_sig": init_sig,
        "config": {
            "participants": k,
            "epoch_slots": w,
            "k_floor": args.k_floor,
            "entry_fee": args.entry_fee,
            "reward_bps": args.reward_bps,
            "bucket_lamports": bucket,
            "duration_secs_target": args.duration_secs,
            "round_interval_secs": args.round_interval_secs,
            "sample_interval_secs": args.sample_interval_secs,
        },
        "started_unix": start_unix,
        "ended_unix": now_unix(),
        "wall_clock_secs": wall,
        "stop_reason": stop_reason,
        "master_lamports_start": master_start,
        "master_lamports_end": master_end,
        "lamports_spent": master_start.saturating_sub(master_end),
        "pool_commitment_count_end": pv.as_ref().map(|p| p.commitment_count).unwrap_or(0),
        "pool_reward_pool_end": pv.as_ref().map(|p| p.reward_pool).unwrap_or(0),
        "pool_version_end": pv.as_ref().map(|p| p.version).unwrap_or(0),
        "pool_epoch_slots_end": pv.as_ref().map(|p| p.epoch_slots).unwrap_or(0),
        "pool_k_floor_end": pv.as_ref().map(|p| p.k_floor).unwrap_or(0),
        "aggregate": agg,
        "passive": passive,
    });
    mirror_soak::write_report_json(&report_path.to_string_lossy(), meta, &report)?;

    println!();
    println!("== sustained run complete ==");
    println!("  wall clock:     {wall} s");
    println!("  rounds:         {}", rounds.len());
    println!("  stop reason:    {stop_reason}");
    println!(
        "  spent:          {} lamports",
        master_start.saturating_sub(master_end)
    );
    println!("  evidence:       {}", rounds_path.display());
    println!("                  {}", samples_path.display());
    println!("                  {}", report_path.display());
    let passed = report.checks.iter().filter(|(_, p, _)| *p).count();
    println!("  checks:         {passed}/{}", report.checks.len());
    if passed != report.checks.len() {
        println!("  NOT every check passed: read the report before quoting it.");
    }
    Ok(())
}
