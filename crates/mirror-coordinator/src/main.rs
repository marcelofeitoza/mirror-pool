//! The mirror-pool coordinator binary.
//!
//! Two modes, because the two halves of the coordinator are at different stages:
//!
//! - `funding` (default when a cluster is configured) runs the FUNDING service
//!   against a real cluster: it polls the chain slot, ingests `mirror-cli
//!   fund-commit` emits from an intake directory, batches them into slot rounds,
//!   and releases each round through the gasless relay. This is real RPC
//!   operation, not a simulation.
//! - `demo` runs the epoch scheduler loop against the in-memory submitter with a
//!   simulated slot clock and synthetic participants, so the batching / k-floor /
//!   rotation pipeline is observable with no validator. The crowd path's
//!   production submitter (`RpcSettleSubmitter`) exists and is exercised by
//!   `mirror-soak`; wiring it into this binary is TODO(milestone-4).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};

use mirror_coordinator::client::{RpcSolanaClient, SolanaClient};
use mirror_coordinator::{
    Config, Coordinator, DirectoryIntake, FeePayer, FundingIntake, FundingRoundConfig,
    FundingService, FundingServiceConfig, InMemorySubmitter, PoolEntry, RelaySet, RoundOutcome,
    SettleSubmitter, TxProfile,
};
use mirror_core::{commit, nullifier, ActionClass, Epoch, EpochSchedule, Secret, SizeBucket};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use tracing_subscriber::EnvFilter;

const DEFAULT_RPC_URL: &str = "http://127.0.0.1:8899";

#[derive(Parser)]
#[command(
    name = "mirror-coordinator",
    about = "mirror-pool coordinator: the funding-round service (live) and the epoch-scheduler demo"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the funding-round service against a live cluster.
    Funding(FundingArgs),
    /// Run the epoch scheduler against the in-memory submitter (no validator).
    Demo,
}

#[derive(Args)]
struct FundingArgs {
    /// RPC endpoint (default: the local Surfpool mainnet mirror).
    #[arg(long, default_value = DEFAULT_RPC_URL)]
    rpc_url: String,
    /// mirror-pool program id (base58). Requests naming any other program are
    /// quarantined at the intake.
    #[arg(long)]
    program_id: String,
    /// Relay keypair file(s): the ValuePool authority for each funding pool this
    /// coordinator serves. Repeat the flag to serve several pools.
    #[arg(long = "relay", required = true)]
    relays: Vec<PathBuf>,
    /// Intake root. Participants write their `fund-commit --out` emit into
    /// `<dir>/inbox`; accepted and rejected requests are filed alongside.
    #[arg(long)]
    intake_dir: PathBuf,
    /// Round length in slots.
    #[arg(long, default_value_t = mirror_coordinator::DEFAULT_ROUND_SLOTS)]
    round_slots: u64,
    /// Minimum withdrawals before a round may release. Below this the round
    /// rolls forward rather than releasing into a crowd too small to hide in.
    #[arg(long, default_value_t = mirror_coordinator::DEFAULT_MIN_ROUND_SIZE)]
    min_round_size: usize,
    /// The funding pool's fixed denomination in lamports. Strongly recommended:
    /// a uniform withdrawal amount is what makes deposit-to-withdrawal matching
    /// hard. Omit only for a free-amount pool, whose withdrawal amounts are
    /// public and distinctive.
    #[arg(long)]
    denomination: Option<u64>,
    /// Normalized compute-unit limit applied to every funding withdrawal.
    #[arg(long, default_value_t = TxProfile::default().cu_limit)]
    cu_limit: u32,
    /// Normalized priority fee (micro-lamports per CU) applied to every funding
    /// withdrawal.
    #[arg(long, default_value_t = TxProfile::default().priority_fee_micro_lamports)]
    priority_fee: u64,
    /// Slot poll interval in milliseconds.
    #[arg(long, default_value_t = 400)]
    poll_ms: u64,
    /// Run a single pass and exit (useful for scripted operation and soaks).
    #[arg(long)]
    once: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    match Cli::parse().command {
        Some(Command::Funding(args)) => run_funding(args).await,
        Some(Command::Demo) | None => run_demo().await,
    }
}

fn load_keypair(path: &PathBuf) -> Result<Keypair> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading relay keypair {}", path.display()))?;
    let bytes: Vec<u8> = serde_json::from_str(&raw)
        .with_context(|| format!("parsing {} as a JSON byte array", path.display()))?;
    Keypair::try_from(bytes.as_slice())
        .map_err(|e| anyhow::anyhow!("invalid keypair in {}: {e}", path.display()))
}

async fn run_funding(args: FundingArgs) -> Result<()> {
    let program_id: Pubkey = args
        .program_id
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid --program-id: {e}"))?;
    let tx_profile = TxProfile {
        cu_limit: args.cu_limit,
        priority_fee_micro_lamports: args.priority_fee,
    };

    let mut relays = RelaySet::default();
    for path in &args.relays {
        relays.insert(load_keypair(path)?);
    }

    let intake = DirectoryIntake::new(&args.intake_dir, program_id, tx_profile)?;
    let inbox = intake.inbox().to_path_buf();
    let intake: Arc<dyn FundingIntake> = Arc::new(intake);
    let client: Arc<dyn SolanaClient> = Arc::new(RpcSolanaClient::new(args.rpc_url.clone()));

    let config = FundingServiceConfig {
        rounds: FundingRoundConfig {
            round_slots: args.round_slots,
            min_round_size: args.min_round_size,
            denomination: args.denomination,
        },
        poll_interval: Duration::from_millis(args.poll_ms),
    };
    let mut service = FundingService::new(config, relays, intake, client)?;

    tracing::info!(
        rpc = %args.rpc_url,
        program = %program_id,
        inbox = %inbox.display(),
        round_slots = args.round_slots,
        min_round_size = args.min_round_size,
        denomination = ?args.denomination,
        cu_limit = tx_profile.cu_limit,
        "funding service starting (slot-driven rounds, gasless relay-only release)"
    );
    if args.denomination.is_none() {
        tracing::warn!(
            "this funding pool has NO fixed denomination, so every withdrawal amount is public \
             and distinctive; batching still destroys arrival order but it cannot close the \
             amount channel"
        );
    }

    if args.once {
        let tick = service.tick().await?;
        log_tick(&tick);
        return Ok(());
    }
    service
        .run(|tick| {
            log_tick(tick);
            false
        })
        .await
}

fn log_tick(tick: &mirror_coordinator::FundingTick) {
    for (wallet, round) in &tick.ingested {
        tracing::info!(slot = tick.slot, commit_wallet = %wallet, round, "ingested");
    }
    for outcome in &tick.outcomes {
        match outcome {
            RoundOutcome::Released {
                round,
                release_slot,
                size,
                signatures,
            } => tracing::info!(
                round,
                release_slot,
                size,
                signatures = signatures.len(),
                "round released"
            ),
            RoundOutcome::RolledForward { round, to, size } => {
                tracing::warn!(round, to, size, "round rolled forward (below the floor)")
            }
        }
    }
}

async fn run_demo() -> Result<()> {
    // Demo-only fee payers: opaque local bytes, never real keys. In production
    // these come from the operator keystore (TODO(milestone-4)).
    let config = Config {
        schedule: EpochSchedule {
            epoch_slots: 10,
            k_floor: 3,
        },
        fee_payers: vec![FeePayer([1; 32]), FeePayer([2; 32]), FeePayer([3; 32])],
        tx_profile: TxProfile::default(),
    };
    tracing::info!(
        epoch_slots = config.schedule.epoch_slots,
        k_floor = config.schedule.k_floor,
        fee_payers = config.fee_payers.len(),
        cu_limit = config.tx_profile.cu_limit,
        "starting coordinator demo (in-memory submitter, simulated slots)"
    );

    let mut coordinator = Coordinator::new(config, InMemorySubmitter::default())?;

    // Synthetic participants, all committing to the identical action shape
    // (one pool = one ActionClass; heterogeneous shapes would leak).
    let swap = ActionClass::Swap {
        mint_in: [0xAA; 32],
        mint_out: [0xBB; 32],
        size: SizeBucket::Small,
    };

    // Epoch 0: four real participants. real_k = 4 >= 3, so it settles.
    for seed in 1..=4u8 {
        seed_commit(&mut coordinator, &swap, Epoch(0), seed, false);
    }
    // Epoch 1: two real participants plus one operator decoy. real_k = 2 < 3,
    // so it rolls forward instead of executing into a deanonymizable set.
    for seed in 5..=6u8 {
        seed_commit(&mut coordinator, &swap, Epoch(1), seed, false);
    }
    seed_commit(&mut coordinator, &swap, Epoch(1), 7, true);

    // Simulated clock: slots 0..=30 covers epoch 0 settling at slot 10 and
    // epoch 1 rolling forward at slot 20 (and again at 30, still under-floor).
    coordinator
        .run_simulated(0, 30, Duration::from_millis(10))
        .await?;

    tracing::info!(
        settled_epochs = coordinator.submitter().submitted.len(),
        pending_epochs = coordinator.pool_mut().pending_epochs().len(),
        "demo run complete"
    );
    Ok(())
}

/// Simulate one participant: derive the commitment and (v1 reveal-phase)
/// nullifier from a throwaway secret and insert into the commit pool.
fn seed_commit<S: SettleSubmitter>(
    coordinator: &mut Coordinator<S>,
    action: &ActionClass,
    epoch: Epoch,
    seed: u8,
    operator_owned: bool,
) {
    let secret = Secret::from_bytes([seed; 32]);
    coordinator.pool_mut().insert(
        epoch,
        PoolEntry {
            commitment: commit(&secret, action, epoch),
            nullifier: nullifier(&secret, epoch),
            operator_owned,
            // Demo participants are all treated as independent; real Sybil
            // detection is an off-chain heuristic (see docs/THREAT_MODEL.md).
            sybil_suspected: false,
        },
    );
}
