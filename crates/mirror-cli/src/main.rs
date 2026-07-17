//! mirror-cli: the participant-side entrypoint for mirror-pool.
//!
//! mirror-pool hides *who initiated an action*, not funds. The privacy comes
//! from four properties this CLI is shaped around:
//!
//! 1. **Shared-epoch batching.** A participant never picks a "random delay";
//!    per-actor jitter is exactly what FIFO temporal matching eats for
//!    breakfast (up to 49% linkage empirically). Instead, everyone who commits
//!    inside the same slot window settles together on one timestamp, so timing
//!    carries zero bits about which committer maps to which action.
//! 2. **k_floor.** An epoch may only execute once the *real* anonymity set
//!    (distinct, non-operator, non-Sybil participants) meets the pool's floor.
//!    Below the floor the epoch rolls forward. This CLI therefore treats a
//!    commit as "queued until the floor is met", never "will execute at T".
//! 3. **Gasless rotating relay.** The participant's wallet posts only the
//!    commitment. Settlement is submitted and paid for by the rotating
//!    coordinator, so no acting wallet funds or signs its own execution and
//!    the fee-payer cannot be used as a consolidation node.
//! 4. **Fixed action shape.** Every action in a pool has an identical
//!    observable shape (same `ActionClass`, same `SizeBucket`). Amounts are
//!    bucketed, never free-form: public studies show variable amounts leak a
//!    large fraction of anonymity to amount-matching alone.
//!
//! v1 flow: `commit` derives a deterministic secret from a seed, computes the
//! epoch-bound commitment via `mirror_core::commit`, and prints the note the
//! participant must keep. `status` reports pool/epoch info (stubbed until the
//! on-chain reads land). `prove` is a v2 placeholder for ZK-deniable
//! initiation (Poseidon + Groth16 membership proof, see docs/ROADMAP.md).

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use mirror_core::{wire, ActionClass, EpochSchedule, Hash32, KAnon, Secret, SizeBucket};
use serde::Serialize;
use sha2::{Digest, Sha256};

/// Domain-separation tags local to the CLI, so a hash computed here can never
/// collide with mirror-core's commitment/nullifier domains.
mod domain {
    /// Stretches a user seed into a participant `Secret`.
    pub const SEED: &[u8] = b"mirror-cli:v1:seed";
    /// Turns a human label (e.g. "USDC-local") into a stand-in 32-byte id.
    pub const LABEL: &[u8] = b"mirror-cli:v1:label";
}

/// Stub epoch schedule until `status`/`commit` read the pool's on-chain
/// `InitPool` config. 150 slots is roughly one minute on mainnet; k_floor 10
/// mirrors the ROADMAP examples: never settle into a set an observer could
/// deanonymize by elimination.
/// TODO(milestone: v1 deliverable 2/3, docs/ROADMAP.md): fetch the real
/// `EpochSchedule` from the pool account instead of this constant.
const STUB_SCHEDULE: EpochSchedule = EpochSchedule {
    epoch_slots: 150,
    k_floor: 10,
};

/// Stub "current slot" so the CLI is runnable and deterministic offline.
/// TODO(milestone: v1 deliverable 7, docs/ROADMAP.md): replace with an RPC
/// `getSlot` against Surfpool/devnet.
const STUB_CURRENT_SLOT: u64 = 1_500_000;

#[derive(Parser)]
#[command(
    name = "mirror-cli",
    version,
    about = "Participant CLI for mirror-pool: commit an action into the current shared epoch, inspect pool status.",
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Commit an action into the current epoch and print the note to keep.
    ///
    /// The commitment binds (secret, action, epoch), so the coordinator that
    /// later settles the epoch cannot substitute a different action for the
    /// one committed. Only the 32-byte commitment would go on-chain; the
    /// action and secret stay client-side until settlement.
    Commit(CommitArgs),
    /// Show pool and epoch status (window, settle slot, k-anonymity floor).
    Status(StatusArgs),
    /// (v2 placeholder) Produce a ZK-deniable initiation proof.
    Prove,
}

#[derive(Args)]
struct CommitArgs {
    /// Pool identifier (a label for now; the pool account address once
    /// on-chain reads land).
    #[arg(long)]
    pool: String,

    /// Seed for the participant secret. The secret is derived
    /// deterministically from (pool, seed) so test flows are reproducible.
    /// v2 replaces this with OS randomness plus an encrypted note file.
    #[arg(long)]
    seed: String,

    /// Slot to derive the current epoch from. Defaults to an offline stub;
    /// pass the real slot when driving Surfpool/devnet by hand.
    #[arg(long)]
    slot: Option<u64>,

    /// The pooled action to commit to. Its shape must match the pool's fixed
    /// ActionClass exactly; heterogeneous actions leak like mixed
    /// denominations.
    #[command(subcommand)]
    action: ActionArg,
}

#[derive(Args)]
struct StatusArgs {
    /// Pool identifier.
    #[arg(long)]
    pool: String,

    /// Slot to evaluate the epoch at. Defaults to the offline stub.
    #[arg(long)]
    slot: Option<u64>,
}

/// CLI-facing action parameters. Mints/validators accept either a 64-char hex
/// id or a free-form label (hashed to a stand-in id for local testing).
/// Amounts are intentionally absent: only a `SizeBucket` is accepted, because
/// free-form amounts are an amount-matching oracle.
#[derive(Subcommand)]
enum ActionArg {
    /// Pooled Jupiter swap: every participant swaps the same mint pair in the
    /// same size bucket.
    Swap {
        /// Input mint (64-char hex, or a label hashed for local testing).
        #[arg(long)]
        mint_in: String,
        /// Output mint (64-char hex, or a label hashed for local testing).
        #[arg(long)]
        mint_out: String,
        /// Fixed size bucket (the behavioral analog of a fixed denomination).
        #[arg(long, value_enum)]
        size: SizeArg,
    },
    /// Pooled stake: every participant stakes the same size bucket to the
    /// same validator.
    Stake {
        /// Validator identity (64-char hex, or a label hashed for testing).
        #[arg(long)]
        validator: String,
        /// Fixed size bucket.
        #[arg(long, value_enum)]
        size: SizeArg,
    },
}

impl ActionArg {
    fn to_action_class(&self) -> ActionClass {
        match self {
            ActionArg::Swap {
                mint_in,
                mint_out,
                size,
            } => ActionClass::Swap {
                mint_in: parse_hash32(mint_in),
                mint_out: parse_hash32(mint_out),
                size: (*size).into(),
            },
            ActionArg::Stake { validator, size } => ActionClass::Stake {
                validator: parse_hash32(validator),
                size: (*size).into(),
            },
        }
    }
}

/// clap-parsable mirror of `mirror_core::SizeBucket`. Kept as a separate enum
/// so mirror-core stays free of CLI dependencies.
#[derive(Clone, Copy, ValueEnum)]
enum SizeArg {
    Nano,
    Small,
    Medium,
    Large,
}

impl From<SizeArg> for SizeBucket {
    fn from(s: SizeArg) -> Self {
        match s {
            SizeArg::Nano => SizeBucket::Nano,
            SizeArg::Small => SizeBucket::Small,
            SizeArg::Medium => SizeBucket::Medium,
            SizeArg::Large => SizeBucket::Large,
        }
    }
}

/// The client-side record a participant must keep to be counted at
/// settlement: the secret is the pre-image proving the commitment is theirs,
/// and the nullifier is what settlement reveals to prevent double-acting
/// within the epoch.
///
/// TODO(milestone: v1 deliverable 5 hardening, docs/ROADMAP.md): persist this
/// to disk (mode 0600) instead of printing; v2 encrypts it.
#[derive(Serialize)]
struct Note {
    version: u32,
    pool: String,
    slot: u64,
    epoch: u64,
    action: ActionClass,
    secret_hex: String,
    commitment_hex: String,
    nullifier_hex: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Commit(args) => run_commit(args),
        Command::Status(args) => run_status(args),
        Command::Prove => {
            println!("not yet: ZK-deniable initiation is v2");
            Ok(())
        }
    }
}

fn run_commit(args: CommitArgs) -> Result<()> {
    let secret = derive_secret(&args.pool, &args.seed);
    let action = args.action.to_action_class();
    let slot = args.slot.unwrap_or(STUB_CURRENT_SLOT);
    let epoch = STUB_SCHEDULE.epoch_of_slot(slot);

    let commitment = mirror_core::commit(&secret, &action, epoch);
    // Pre-derive the nullifier for this epoch so the note is self-contained.
    // It is epoch-scoped: the same secret in a later epoch (e.g. after a
    // below-floor roll-forward) yields a different nullifier.
    let nf = mirror_core::nullifier(&secret, epoch);

    println!("pool:         {}", args.pool);
    println!("slot:         {slot}");
    println!(
        "epoch:        {} (window {} slots, settles at slot {})",
        epoch.0,
        STUB_SCHEDULE.epoch_slots,
        STUB_SCHEDULE.settle_slot(epoch)
    );
    println!("commitment:   {}", to_hex(&commitment.0));
    println!(
        "would submit: COMMIT instruction, {} bytes: [tag={}][commitment(32)]",
        wire::COMMIT_LEN,
        wire::tag::COMMIT
    );
    // TODO(milestone: v1 deliverables 2+7, docs/ROADMAP.md): actually build
    // and send the COMMIT transaction to the on-chain program on
    // Surfpool/devnet. Settlement itself is never submitted from here: the
    // rotating gasless coordinator (v1 deliverable 3) is the sole
    // fee-payer/signer for SETTLE_EPOCH, so this wallet never funds or signs
    // its own execution.
    println!();
    println!(
        "note is only counted if epoch {} reaches real k >= {} (below the floor it rolls forward)",
        epoch.0, STUB_SCHEDULE.k_floor
    );
    println!();

    let note = Note {
        version: 1,
        pool: args.pool,
        slot,
        epoch: epoch.0,
        action,
        secret_hex: to_hex(&secret.0),
        commitment_hex: to_hex(&commitment.0),
        nullifier_hex: to_hex(&nf.0),
    };
    println!("note (KEEP PRIVATE; anyone holding it can act as you at settlement):");
    println!(
        "{}",
        serde_json::to_string_pretty(&note).context("serializing note")?
    );
    Ok(())
}

fn run_status(args: StatusArgs) -> Result<()> {
    let slot = args.slot.unwrap_or(STUB_CURRENT_SLOT);
    let epoch = STUB_SCHEDULE.epoch_of_slot(slot);
    // TODO(milestone: v1 deliverable 2/3, docs/ROADMAP.md): read the pool
    // account + commitment accumulator on-chain and report the coordinator's
    // honest KAnon (nominal minus operator-owned/Sybil exclusions), never the
    // raw commit count.
    let k = KAnon::default();

    println!("pool:          {}", args.pool);
    println!("current slot:  {slot} (stub; pass --slot for a real chain slot)");
    println!("current epoch: {}", epoch.0);
    println!(
        "epoch window:  {} slots, settles at slot {}",
        STUB_SCHEDULE.epoch_slots,
        STUB_SCHEDULE.settle_slot(epoch)
    );
    println!("k_floor:       {}", STUB_SCHEDULE.k_floor);
    println!(
        "anonymity set: nominal={} excluded={} real_k={} (stub)",
        k.nominal,
        k.excluded,
        k.real_k()
    );
    if k.meets_floor(&STUB_SCHEDULE) {
        println!("verdict:       floor met; epoch may settle when its window closes");
    } else {
        println!("verdict:       below floor; epoch rolls forward instead of executing");
    }
    Ok(())
}

/// Derive the participant `Secret` deterministically from (pool, seed).
///
/// Length-prefixed so ("ab", "c") and ("a", "bc") cannot collide, and
/// domain-tagged so the digest can never be confused with a commitment or
/// nullifier. Binding the pool in means one seed reused across pools still
/// yields unlinkable secrets.
fn derive_secret(pool: &str, seed: &str) -> Secret {
    let mut h = Sha256::new();
    h.update(domain::SEED);
    h.update((pool.len() as u64).to_le_bytes());
    h.update(pool.as_bytes());
    h.update((seed.len() as u64).to_le_bytes());
    h.update(seed.as_bytes());
    Secret::from_bytes(h.finalize().into())
}

/// Parse a 32-byte identifier. Exactly 64 hex chars decode literally;
/// anything else is treated as a human label and hashed (domain-tagged) into
/// a stand-in id, which keeps local test flows free of real addresses.
fn parse_hash32(s: &str) -> Hash32 {
    let bytes = s.as_bytes();
    if bytes.len() == 64 && bytes.iter().all(u8::is_ascii_hexdigit) {
        let mut out = [0u8; 32];
        for (i, pair) in bytes.chunks_exact(2).enumerate() {
            out[i] = (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]);
        }
        return out;
    }
    let mut h = Sha256::new();
    h.update(domain::LABEL);
    h.update(bytes);
    h.finalize().into()
}

fn hex_nibble(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => unreachable!("caller validated hex digits"),
    }
}

fn to_hex(bytes: &[u8]) -> String {
    use core::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(s, "{b:02x}").expect("writing to a String cannot fail");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use mirror_core::Epoch;

    fn test_action() -> ActionClass {
        ActionClass::Swap {
            mint_in: parse_hash32("USDC-local"),
            mint_out: parse_hash32("JUP-local"),
            size: SizeBucket::Small,
        }
    }

    #[test]
    fn commit_is_deterministic_for_fixed_seed_and_epoch() {
        let epoch = Epoch(42);
        let a = mirror_core::commit(&derive_secret("pool-1", "seed-1"), &test_action(), epoch);
        let b = mirror_core::commit(&derive_secret("pool-1", "seed-1"), &test_action(), epoch);
        assert_eq!(a, b, "same (pool, seed, action, epoch) must reproduce");

        let other_seed =
            mirror_core::commit(&derive_secret("pool-1", "seed-2"), &test_action(), epoch);
        assert_ne!(a, other_seed, "a different seed must change the commitment");

        let other_epoch = mirror_core::commit(
            &derive_secret("pool-1", "seed-1"),
            &test_action(),
            Epoch(43),
        );
        assert_ne!(
            a, other_epoch,
            "a different epoch must change the commitment"
        );
    }

    #[test]
    fn secret_derivation_is_length_prefixed_and_pool_bound() {
        assert_ne!(
            derive_secret("ab", "c").0,
            derive_secret("a", "bc").0,
            "length prefixing must prevent boundary collisions"
        );
        assert_ne!(
            derive_secret("pool-1", "seed-1").0,
            derive_secret("pool-2", "seed-1").0,
            "one seed across two pools must yield unlinkable secrets"
        );
    }

    #[test]
    fn parse_hash32_handles_hex_and_labels() {
        let hex = format!("{}ff", "00".repeat(31));
        let decoded = parse_hash32(&hex);
        assert_eq!(decoded[31], 0xff);
        assert_eq!(decoded[..31], [0u8; 31]);

        assert_eq!(parse_hash32("USDC-local"), parse_hash32("USDC-local"));
        assert_ne!(parse_hash32("USDC-local"), parse_hash32("USDT-local"));
    }

    #[test]
    fn cli_definition_is_consistent() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }
}
