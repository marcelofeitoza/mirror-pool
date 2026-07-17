//! Demo binary for the mirror-pool coordinator.
//!
//! Wires a [`Config`] and runs the epoch scheduler loop against the in-memory
//! submitter with a simulated slot clock and synthetic participants, so the
//! whole batching / k-floor / rotation pipeline is observable with no
//! validator. Production swaps in `RpcSubmitter` and a real slot source
//! without touching the scheduler (TODO(milestone-4)).

use std::time::Duration;

use mirror_coordinator::{
    Config, Coordinator, FeePayer, InMemorySubmitter, PoolEntry, SettleSubmitter, TxProfile,
};
use mirror_core::{commit, nullifier, ActionClass, Epoch, EpochSchedule, Secret, SizeBucket};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

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
