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
//!    commitment (crowd path) or the escrow + commitment (ZK opt-in path).
//!    Settlement is submitted and paid for by the rotating coordinator, so no
//!    acting wallet funds or signs its own execution and the fee-payer cannot be
//!    used as a consolidation node. That is why `prove` EMITS the `SettleZk`
//!    instruction for the coordinator instead of submitting it.
//! 4. **Fixed action shape.** Every action in a pool has an identical
//!    observable shape (same `ActionClass`, same `SizeBucket`). Amounts are
//!    bucketed, never free-form: public studies show variable amounts leak a
//!    large fraction of anonymity to amount-matching alone.
//!
//! A fifth property lives on the FUNDING leg rather than the settlement leg:
//! `fund-commit` withdraws from the confidential-value pool into a fresh commit
//! wallet, so the public graph carries no edge from the participant's main wallet
//! to the wallet they commit from. That edge is the common-funding-source anchor,
//! the dominant real-world deanonymizer; what the mechanism does and does not
//! hide is spelled out in [`crate::funding`] and measured in
//! `docs/EFFECTIVE_K.md`.
//!
//! Subcommands: `init-pool` (admin: create + fix a pool's config), `commit`
//! (crowd path: post a commitment binding secret+action+epoch), `deposit-commit`
//! (ZK opt-in: escrow lamports + post a commitment binding secret+recipient+amount),
//! `prove` (ZK opt-in: rebuild the Merkle path, generate + verify a Groth16
//! membership proof, and emit the `SettleZk` instruction), `fund-commit` (funding:
//! unshield into a fresh commit wallet), and `status` (inspect the pool + current
//! epoch on-chain).

mod association;
mod ceremony;
mod chain;
mod funding;
mod groth16;
mod note;
mod prove;
mod prove_rust;
mod tree;
mod util;
mod value;
mod value_note;
mod vk;

use anyhow::{anyhow, Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use mirror_core::{ActionClass, Epoch, Hash32, Secret, SizeBucket};
use sha2::{Digest, Sha256};
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use std::path::PathBuf;
use std::str::FromStr;

use crate::chain::Chain;
use crate::note::{ActionRecord, Note, NOTE_VERSION};
use crate::util::to_hex;

/// Domain-separation tags local to the CLI, so a hash computed here can never
/// collide with mirror-core's commitment/nullifier domains.
mod domain {
    /// Stretches a user seed into a participant `Secret`.
    pub const SEED: &[u8] = b"mirror-cli:v1:seed";
    /// Turns a human label (e.g. "USDC-local") into a stand-in 32-byte id.
    pub const LABEL: &[u8] = b"mirror-cli:v1:label";
}

/// Default local RPC: the Surfpool mainnet mirror.
const DEFAULT_RPC_URL: &str = "http://127.0.0.1:8899";
/// Default directory for saved notes (gitignored).
const DEFAULT_NOTE_DIR: &str = "notes";

/// Default transaction-circuit artifacts (gitignored build outputs of
/// `bash circuits/build_transaction.sh`).
const DEFAULT_TX_WASM: &str = "circuits/transaction_js/transaction.wasm";
const DEFAULT_TX_R1CS: &str = "circuits/transaction.r1cs";
const DEFAULT_TX_ZKEY: &str = "circuits/transaction_final.zkey";
const DEFAULT_TX_VK: &str = "circuits/artifacts/transaction_verification_key.json";

/// Default association-circuit artifacts (gitignored build outputs of
/// `bash circuits/build_association.sh`).
const DEFAULT_ASSOC_WASM: &str = "circuits/association_js/association.wasm";
const DEFAULT_ASSOC_R1CS: &str = "circuits/association.r1cs";
const DEFAULT_ASSOC_ZKEY: &str = "circuits/association_final.zkey";
const DEFAULT_ASSOC_VK: &str = "circuits/artifacts/association_verification_key.json";

#[derive(Parser)]
#[command(
    name = "mirror-cli",
    version,
    about = "Participant CLI for mirror-pool: init a pool, commit into the current shared epoch, escrow + commit for the ZK opt-in path, produce Groth16 membership proofs, and inspect pool status.",
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// (admin) Create a pool and fix its config forever, then print the Pool PDA.
    InitPool(InitPoolArgs),
    /// (deployment, permissionless) Publish a circuit's verifying key into its
    /// write-once registry PDA. One call per circuit per deployment; there is no
    /// update instruction and nothing to choose - the program accepts only the
    /// key whose digest it pins at compile time.
    InitVk(InitVkArgs),
    /// (crowd path) Commit an action into the current epoch and save the note.
    Commit(CommitArgs),
    /// (ZK opt-in) Escrow lamports + commit a transfer to a fresh recipient.
    DepositCommit(DepositCommitArgs),
    /// (ZK opt-in) Rebuild the Merkle path, prove membership, and emit SettleZk.
    Prove(ProveArgs),
    /// (ZK opt-in, OPTIONAL) Prove membership AND inclusion in a curator's
    /// association set, then emit SettleZkAssociated. Purely additive: plain
    /// `prove` still works and no curator can block it.
    ProveAssociated(ProveAssociatedArgs),
    /// (curator) Association-set tooling: build a curated root, emit the update.
    #[command(subcommand_help_heading = "Association sets")]
    Assoc(AssocArgs),
    /// (OPTIONAL) Publish or rotate the X25519 viewing key your address can be
    /// addressed at. Nothing requires it: no settle path reads it.
    #[command(subcommand_help_heading = "Selective disclosure")]
    ViewingKey(ViewingKeyArgs),
    /// (OPTIONAL) Disclose ONE of your own settled actions to ONE auditor you
    /// chose, sealed to their registered viewing key.
    Disclose(DiscloseArgs),
    /// (auditor) Scan the chain for disclosure records sealed to your viewing
    /// key, open them, and verify each against the chain.
    #[command(subcommand_help_heading = "Selective disclosure")]
    Audit(AuditArgs),
    /// Show pool config + current epoch on-chain.
    Status(StatusArgs),
    /// (confidential value) Derive a value spend + viewing keypair and save a keyfile.
    ValueKeygen(ValueKeygenArgs),
    /// (confidential value, admin) Create a ValuePool + vault; print the ValuePool PDA.
    InitValuePool(InitValuePoolArgs),
    /// (confidential value) Deposit into a fresh shielded note; prove + emit Transact.
    Shield(ShieldArgs),
    /// (confidential value) Spend a note to a recipient + change; prove + emit Transact.
    Transfer(TransferArgs),
    /// (confidential value) Withdraw a note to a public recipient; prove + emit Transact.
    Unshield(UnshieldArgs),
    /// (funding) Fund a FRESH commit wallet by unshielding, so no funding edge
    /// links your main wallet to the wallet you commit from.
    FundCommit(FundCommitArgs),
    /// Multi-party Groth16 phase-2 trusted-setup ceremony: start, contribute,
    /// beacon, verify, export the verifying key.
    #[command(subcommand_help_heading = "Trusted setup")]
    Ceremony(ceremony::CeremonyArgs),
    /// (confidential value) Trial-decrypt enc blobs and save recovered spendable notes.
    Scan(ScanArgs),
}

/// Shared transaction-circuit artifact arguments for the value commands. Proving is
/// in-process pure Rust by default; `--use-snarkjs` selects the Node fallback.
#[derive(Args)]
struct TxProveArgs {
    /// Circuit witness generator (gitignored; `bash circuits/build_transaction.sh`).
    #[arg(long, default_value = DEFAULT_TX_WASM)]
    wasm: PathBuf,
    /// Compiled R1CS (gitignored; `bash circuits/build_transaction.sh`). Used by the
    /// default in-process Rust prover.
    #[arg(long, default_value = DEFAULT_TX_R1CS)]
    r1cs: PathBuf,
    /// Groth16 proving key (gitignored; `bash circuits/build_transaction.sh`).
    /// This is the DEV setup key. The deployed JoinSplit verifying key came from
    /// the phase-2 ceremony, so a proof made under this default is well-formed but
    /// WILL be rejected on chain. Use `--proving-key` to land one.
    #[arg(long, default_value = DEFAULT_TX_ZKEY)]
    zkey: PathBuf,
    /// Prove under a CEREMONY-produced key (`key_NNNN.mpk`) instead of `--zkey`.
    /// This is the key the deployed program's verifying key was exported from, so
    /// this is the flag that produces a proof the program accepts.
    #[arg(long, conflicts_with = "use_snarkjs")]
    proving_key: Option<PathBuf>,
    /// Groth16 verification key (committed under circuits/artifacts/). Only used by
    /// the `--use-snarkjs` fallback.
    #[arg(long, default_value = DEFAULT_TX_VK)]
    vk: PathBuf,
    /// Use the legacy snarkjs shell-out (needs Node) instead of the default
    /// in-process Rust prover. The default path spawns NO Node process.
    #[arg(long)]
    use_snarkjs: bool,
    /// snarkjs invocation (default `snarkjs`; `node <dir>/cli.cjs` also works). Only
    /// used with `--use-snarkjs`.
    #[arg(long, default_value = "snarkjs")]
    snarkjs: String,
    /// Directory for input.json/proof.json/public.json (snarkjs path only; default:
    /// a temp dir).
    #[arg(long)]
    work_dir: Option<PathBuf>,
    /// Also write the emitted Transact bundle (JSON) to this path.
    #[arg(long)]
    out: Option<PathBuf>,
}

impl TxProveArgs {
    fn to_opts(&self) -> value::TransactProveOpts {
        value::TransactProveOpts {
            snarkjs: self.snarkjs.clone(),
            use_snarkjs: self.use_snarkjs,
            wasm: self.wasm.clone(),
            r1cs: self.r1cs.clone(),
            zkey: self.zkey.clone(),
            proving_key: self.proving_key.clone(),
            vk: self.vk.clone(),
            work_dir: self.work_dir.clone(),
        }
    }
}

/// The two flags every on-chain subcommand takes. Flattened rather than repeated,
/// so the CLI surface is unchanged: each subcommand still accepts `--rpc-url` and
/// `--program-id` exactly as before.
#[derive(Args)]
struct ChainArgs {
    /// RPC endpoint.
    #[arg(long, default_value = DEFAULT_RPC_URL)]
    rpc_url: String,
    /// mirror-pool program id (base58).
    #[arg(long)]
    program_id: String,
}

#[derive(Args)]
struct ValueKeygenArgs {
    /// Seed for a deterministic (reproducible) wallet. Omit for OS randomness.
    #[arg(long)]
    seed: Option<String>,
    /// Where to write the keyfile (both secrets; gitignored).
    #[arg(long, default_value = "notes/value-key.json")]
    out: PathBuf,
}

#[derive(Args)]
struct InitValuePoolArgs {
    #[command(flatten)]
    chain: ChainArgs,
    /// Keypair that becomes `vpool.authority` (the Transact relay). Signs InitValuePool.
    #[arg(long)]
    authority: PathBuf,
    /// Keypair that funds the ValuePool + vault rent (defaults to the authority).
    #[arg(long)]
    payer: Option<PathBuf>,
    /// Relay fee (lamports) bound into every Transact's ext-data.
    #[arg(long)]
    fee: u64,
    /// Fixed denomination (lamports): when set, every public deposit/withdraw must
    /// move exactly this amount (enforced on-chain as DenominationMismatch).
    #[arg(long)]
    denomination: Option<u64>,
}

#[derive(Args)]
struct ShieldArgs {
    #[command(flatten)]
    chain: ChainArgs,
    /// The ValuePool PDA (base58) to deposit into.
    #[arg(long)]
    pool: String,
    /// Depositor keypair: funds + co-signs the deposit (shield is not gasless).
    #[arg(long)]
    depositor: PathBuf,
    /// The recipient value+viewing address ("<value_pub_hex>:<viewing_pub_hex>").
    #[arg(long)]
    to: String,
    /// Lamports to deposit into the shielded note. Must be > 0.
    #[arg(long)]
    amount: u64,
    /// Directory to save the note record into (gitignored).
    #[arg(long, default_value = DEFAULT_NOTE_DIR)]
    note_dir: PathBuf,
    #[command(flatten)]
    prove: TxProveArgs,
}

#[derive(Args)]
struct TransferArgs {
    #[command(flatten)]
    chain: ChainArgs,
    /// The ValuePool PDA (base58).
    #[arg(long)]
    pool: String,
    /// The spendable input note record (from `scan`).
    #[arg(long)]
    note: PathBuf,
    /// The recipient value+viewing address ("<value_pub_hex>:<viewing_pub_hex>").
    #[arg(long)]
    to: String,
    /// Amount to pay the recipient; the remainder returns to self as change.
    #[arg(long)]
    amount: u64,
    /// Change destination address (default: the input note's own owner).
    #[arg(long)]
    change_to: Option<String>,
    /// Directory to save note records into (gitignored).
    #[arg(long, default_value = DEFAULT_NOTE_DIR)]
    note_dir: PathBuf,
    #[command(flatten)]
    prove: TxProveArgs,
}

#[derive(Args)]
struct UnshieldArgs {
    #[command(flatten)]
    chain: ChainArgs,
    /// The ValuePool PDA (base58).
    #[arg(long)]
    pool: String,
    /// The spendable input note record (from `scan`).
    #[arg(long)]
    note: PathBuf,
    /// The public Solana account (base58) credited by the withdrawal.
    #[arg(long)]
    recipient: String,
    /// Lamports to withdraw to the recipient; the remainder returns to self.
    #[arg(long)]
    amount: u64,
    /// Directory to save note records into (gitignored).
    #[arg(long, default_value = DEFAULT_NOTE_DIR)]
    note_dir: PathBuf,
    #[command(flatten)]
    prove: TxProveArgs,
}

/// `fund-commit`: the funding leg of the protocol. Withdraws from the shielded
/// value pool into a FRESH commit wallet, so the public graph never carries an
/// edge from the participant's main wallet to the wallet they commit from. The
/// residual (deposit/withdrawal amounts and slots are public) is handled by the
/// pool's fixed denomination plus the coordinator's funding rounds; see
/// `crate::funding` and `docs/EFFECTIVE_K.md`.
#[derive(Args)]
struct FundCommitArgs {
    #[command(flatten)]
    chain: ChainArgs,
    /// The ValuePool PDA (base58) to withdraw from. Prefer a DENOMINATED pool:
    /// a uniform withdrawal amount is what makes deposit-to-withdrawal matching hard.
    #[arg(long)]
    pool: String,
    /// The spendable input note record (from `scan`) that funds the withdrawal.
    #[arg(long)]
    note: PathBuf,
    /// Where to write the FRESH commit-wallet keypair (refuses to overwrite).
    #[arg(long, default_value = "notes/commit-wallet.json")]
    out_keypair: PathBuf,
    /// Reuse an existing commit-wallet keypair instead of generating a fresh one.
    /// A fresh wallet per commit is the default for a reason: reusing one links
    /// your epochs to each other.
    #[arg(long, conflicts_with = "out_keypair")]
    commit_wallet: Option<PathBuf>,
    /// Lamports to withdraw. Optional (and pinned) when the pool is denominated;
    /// required when it is not.
    #[arg(long)]
    amount: Option<u64>,
    /// Directory to save note records into (gitignored).
    #[arg(long, default_value = DEFAULT_NOTE_DIR)]
    note_dir: PathBuf,
    #[command(flatten)]
    prove: TxProveArgs,
}

#[derive(Args)]
struct ScanArgs {
    /// The wallet keyfile (from `value-keygen`) whose viewing key trial-decrypts.
    #[arg(long)]
    viewing_key: PathBuf,
    /// A file of on-chain `enc` blobs, one hex blob per non-empty line.
    #[arg(long)]
    blobs: PathBuf,
    /// Optional ordered on-chain value commitments (one hex per line) to recover
    /// each hit's leaf index + inclusion path (needed on a no-history validator).
    #[arg(long)]
    leaves: Option<PathBuf>,
    /// RPC endpoint (optional; used to verify a recovered note's root is on-chain).
    #[arg(long)]
    rpc_url: Option<String>,
    /// The ValuePool PDA (base58); required to verify roots and save spendable notes.
    #[arg(long)]
    pool: Option<String>,
    /// mirror-pool program id (base58); required to save spendable note records.
    #[arg(long)]
    program_id: Option<String>,
    /// Directory to save recovered spendable notes into (gitignored).
    #[arg(long, default_value = DEFAULT_NOTE_DIR)]
    note_dir: PathBuf,
}

#[derive(Args)]
struct InitVkArgs {
    #[command(flatten)]
    chain: ChainArgs,
    /// Which circuit's key to publish: membership, transaction, or association.
    /// Publish every circuit the deployment will actually use; a verify path
    /// whose registry is missing fails closed.
    #[arg(long)]
    circuit: String,
    /// Keypair file that funds the registry PDA's rent. It signs, but it does
    /// NOT get to choose the key: the program hashes the bytes and refuses
    /// anything but the one key its bytecode pins.
    #[arg(long)]
    payer: PathBuf,
    /// Print the canonical encoding's digest and address and exit, without
    /// submitting anything. Useful for checking a deployment out of band.
    #[arg(long)]
    dry_run: bool,
}

#[derive(Args)]
struct InitPoolArgs {
    #[command(flatten)]
    chain: ChainArgs,
    /// Keypair file that becomes `pool.authority` (the settle relay). It must
    /// sign InitPool, so its keypair is required here.
    #[arg(long)]
    authority: PathBuf,
    /// Keypair file that funds the Pool PDA rent (defaults to the authority).
    #[arg(long)]
    payer: Option<PathBuf>,
    /// Slots per epoch window.
    #[arg(long)]
    epoch_slots: u64,
    /// Minimum commits before an epoch may settle (must be >= 2).
    #[arg(long)]
    k_floor: u32,
    /// Per-commit anti-Sybil entry fee in lamports (0 disables it).
    #[arg(long, default_value_t = 0)]
    entry_fee: u64,
    /// Basis-point share of each entry fee that accrues to the on-chain reward
    /// pool (0..=10000; fixed forever at init). See docs/INCENTIVES.md.
    #[arg(long, default_value_t = 0)]
    reward_bps: u16,
    /// The single ZK opt-in escrow size in lamports, fixed forever at init and
    /// required to be non-zero. `deposit-commit` escrows exactly this and a
    /// settle pays exactly this, which is what stops a settle drawing more than
    /// its leaf escrowed. A pool serving several sizes is several pools.
    #[arg(long)]
    zk_denomination: u64,
}

#[derive(Args)]
struct CommitArgs {
    #[command(flatten)]
    chain: ChainArgs,
    /// The Pool PDA (base58) to commit into.
    #[arg(long)]
    pool: String,
    /// Participant keypair: signs the Commit and pays the fee + rent.
    #[arg(long)]
    keypair: PathBuf,
    /// Seed for the participant secret; derived deterministically from
    /// (pool, seed) so test flows are reproducible. v2 replaces this with OS
    /// randomness plus an encrypted note file.
    #[arg(long)]
    seed: String,
    /// Slot to derive the current epoch from (defaults to a fresh `getSlot`).
    #[arg(long)]
    slot: Option<u64>,
    /// Directory to save the note into (gitignored).
    #[arg(long, default_value = DEFAULT_NOTE_DIR)]
    note_dir: PathBuf,
    /// The pooled action to commit to. Its shape must match the pool's fixed
    /// ActionClass exactly; heterogeneous actions leak like mixed denominations.
    #[command(subcommand)]
    action: ActionArg,
}

#[derive(Args)]
struct DepositCommitArgs {
    #[command(flatten)]
    chain: ChainArgs,
    /// The Pool PDA (base58) to commit into.
    #[arg(long)]
    pool: String,
    /// Depositor keypair: signs CommitDeposit and pays the escrow + rent.
    #[arg(long)]
    keypair: PathBuf,
    /// Seed for the participant secret (deterministic from (pool, seed)).
    #[arg(long)]
    seed: String,
    /// Fresh recipient (base58) that receives the escrow at SettleZk. Its address
    /// and `amount` are bound into the commitment's actionHash so the relay
    /// cannot redirect the escrow.
    #[arg(long)]
    recipient: String,
    /// Lamports to escrow (and the amount bound into actionHash). Must be > 0.
    #[arg(long)]
    amount: u64,
    /// Slot to derive the current epoch from (defaults to a fresh `getSlot`).
    #[arg(long)]
    slot: Option<u64>,
    /// Directory to save the note into (gitignored).
    #[arg(long, default_value = DEFAULT_NOTE_DIR)]
    note_dir: PathBuf,
}

#[derive(Args)]
struct ProveArgs {
    /// The saved ZK opt-in note (from `deposit-commit`).
    #[arg(long)]
    note: PathBuf,
    /// RPC endpoint (used to confirm the proof root is a known recent root).
    #[arg(long, default_value = DEFAULT_RPC_URL)]
    rpc_url: String,
    /// Circuit witness generator (gitignored; produced by `bash circuits/build.sh`).
    #[arg(long, default_value = "circuits/membership_js/membership.wasm")]
    wasm: PathBuf,
    /// Compiled R1CS (gitignored; produced by `bash circuits/build.sh`). Used by the
    /// default in-process Rust prover.
    #[arg(long, default_value = "circuits/membership.r1cs")]
    r1cs: PathBuf,
    /// Groth16 proving key (gitignored; produced by `bash circuits/build.sh`).
    /// This is the DEV key: the deployed membership verifying key came from the
    /// phase-2 ceremony (docs/CEREMONY.md), so a proof made under this default is
    /// well-formed but WILL be rejected on chain. Use `--proving-key` to land one.
    #[arg(long, default_value = "circuits/membership_final.zkey")]
    zkey: PathBuf,
    /// Prove under a CEREMONY-produced key (`key_NNNN.mpk`) instead of `--zkey`.
    /// This is what the DEPLOYED membership verifying key was exported from, so
    /// this is the path that produces a proof the program accepts. The program
    /// must pin the matching key's digest (`ceremony export-vk --out-rust` plus
    /// the constant in `programs/mirror-pool/src/vk_digest.rs`) for it to land.
    #[arg(long, conflicts_with = "use_snarkjs")]
    proving_key: Option<PathBuf>,
    /// Groth16 verification key (committed under circuits/artifacts/). Only used by
    /// the `--use-snarkjs` fallback.
    #[arg(long, default_value = "circuits/artifacts/verification_key.json")]
    vk: PathBuf,
    /// Use the legacy snarkjs shell-out (needs Node) instead of the default
    /// in-process Rust prover. The default path spawns NO Node process.
    #[arg(long)]
    use_snarkjs: bool,
    /// snarkjs invocation (default `snarkjs`; `node <dir>/cli.cjs` also works). Only
    /// used with `--use-snarkjs`.
    #[arg(long, default_value = "snarkjs")]
    snarkjs: String,
    /// Optional full leaf set (hex, one per line) to rebuild the whole tree and
    /// prove against the CURRENT root instead of the note's frontier snapshot.
    #[arg(long)]
    leaves: Option<PathBuf>,
    /// Directory for input.json/proof.json/public.json (snarkjs path only; default:
    /// a temp dir).
    #[arg(long)]
    work_dir: Option<PathBuf>,
    /// Also write the emitted SettleZk bundle (JSON) to this path.
    #[arg(long)]
    out: Option<PathBuf>,
    /// Prove even though the window's commit count is below the pool's k_floor.
    /// `prove` refuses by default: SettleZk publishes the epoch and the amount,
    /// so a thin window means the output can be attributed by elimination. The
    /// program cannot refuse this for you (a settle-time floor would strand the
    /// escrow, which has no refund path), so the choice is yours and it is
    /// recorded in the emitted bundle.
    #[arg(long)]
    accept_thin_set: bool,
}

/// `prove-associated`: the opt-in compliance proof. Mirrors [`ProveArgs`], with
/// the association circuit's artifacts and the curator's identity + leaf list.
#[derive(Args)]
struct ProveAssociatedArgs {
    /// The saved ZK opt-in note (from `deposit-commit`).
    #[arg(long)]
    note: PathBuf,
    /// RPC endpoint (used to confirm both roots are known on-chain).
    #[arg(long, default_value = DEFAULT_RPC_URL)]
    rpc_url: String,
    /// The curator whose association set to prove against (base58). Together with
    /// the pool this fixes the AssociationSet PDA `["assoc", pool, curator]`.
    #[arg(long)]
    curator: String,
    /// The curator's PUBLISHED curated leaf list (hex commitments, one per line,
    /// in the curator's ordering). The association root is rebuilt from this, so
    /// anyone can independently check what the curator actually vouched for.
    #[arg(long)]
    association_leaves: PathBuf,
    /// Circuit witness generator (gitignored; `bash circuits/build_association.sh`).
    #[arg(long, default_value = DEFAULT_ASSOC_WASM)]
    wasm: PathBuf,
    /// Compiled R1CS (gitignored; `bash circuits/build_association.sh`). Used by
    /// the default in-process Rust prover.
    #[arg(long, default_value = DEFAULT_ASSOC_R1CS)]
    r1cs: PathBuf,
    /// Groth16 proving key (gitignored; `bash circuits/build_association.sh`).
    /// This is the DEV setup key. The deployed association verifying key came from
    /// the phase-2 ceremony, so a proof made under this default is well-formed but
    /// WILL be rejected on chain. Use `--proving-key` to land one.
    #[arg(long, default_value = DEFAULT_ASSOC_ZKEY)]
    zkey: PathBuf,
    /// Prove under a CEREMONY-produced key (`key_NNNN.mpk`) instead of `--zkey`.
    #[arg(long, conflicts_with = "use_snarkjs")]
    proving_key: Option<PathBuf>,
    /// Groth16 verification key (committed under circuits/artifacts/). Only used
    /// by the `--use-snarkjs` fallback.
    #[arg(long, default_value = DEFAULT_ASSOC_VK)]
    vk: PathBuf,
    /// Use the legacy snarkjs shell-out (needs Node) instead of the default
    /// in-process Rust prover. The default path spawns NO Node process.
    #[arg(long)]
    use_snarkjs: bool,
    /// snarkjs invocation (default `snarkjs`). Only used with `--use-snarkjs`.
    #[arg(long, default_value = "snarkjs")]
    snarkjs: String,
    /// Optional full POOL leaf set (hex, one per line) to rebuild the whole pool
    /// tree and prove against the CURRENT pool root instead of the note's
    /// frontier snapshot.
    #[arg(long)]
    leaves: Option<PathBuf>,
    /// Directory for input.json/proof.json/public.json (snarkjs path only).
    #[arg(long)]
    work_dir: Option<PathBuf>,
    /// Also write the emitted SettleZkAssociated bundle (JSON) to this path.
    #[arg(long)]
    out: Option<PathBuf>,
}

/// `assoc`: curator-side association-set tooling.
#[derive(Args)]
struct AssocArgs {
    #[command(subcommand)]
    command: AssocCommand,
}

#[derive(Subcommand)]
enum AssocCommand {
    /// Rebuild the Merkle root of a curated leaf list and emit the
    /// `UpdateAssociationRoot` instruction data for the curator to submit.
    BuildRoot(AssocBuildRootArgs),
    /// (curator) Register an association set for a pool. Permissionless: anyone
    /// may become a curator, and whether their attestation is worth anything is
    /// judged off-chain by whoever reads it.
    Init(AssocInitArgs),
    /// (curator) Rebuild the root from a curated leaf list and publish it on-chain.
    Publish(AssocPublishArgs),
    /// Show a curator's association set: pool, curator, update count, recent roots.
    Show(AssocShowArgs),
}

#[derive(Args)]
struct AssocInitArgs {
    #[command(flatten)]
    chain: ChainArgs,
    /// The Pool PDA (base58) this set will curate.
    #[arg(long)]
    pool: String,
    /// Curator keypair (JSON byte array). Signs for itself.
    #[arg(long)]
    curator: PathBuf,
    /// Fee payer keypair; defaults to the curator.
    #[arg(long)]
    payer: Option<PathBuf>,
}

#[derive(Args)]
struct AssocPublishArgs {
    #[command(flatten)]
    chain: ChainArgs,
    /// The Pool PDA (base58) this set curates.
    #[arg(long)]
    pool: String,
    /// Curator keypair (JSON byte array). Must be the registered curator.
    #[arg(long)]
    curator: PathBuf,
    /// The curated leaf list (hex commitments, one per line). Publish this file
    /// alongside the root: the chain cannot check what the root covers.
    #[arg(long)]
    leaves: PathBuf,
}

#[derive(Args)]
struct AssocShowArgs {
    #[command(flatten)]
    chain: ChainArgs,
    /// The Pool PDA (base58).
    #[arg(long)]
    pool: String,
    /// The curator (base58).
    #[arg(long)]
    curator: String,
}

#[derive(Args)]
struct AssocBuildRootArgs {
    /// The curated leaf list (hex commitments, one per line; `#` comments and
    /// blank lines ignored). Duplicates are rejected so the reported set size is
    /// the real anonymity set.
    #[arg(long)]
    leaves: PathBuf,
    /// mirror-pool program id (base58). Optional; with --pool and --curator it
    /// also reports the AssociationSet PDA to pass.
    #[arg(long)]
    program_id: Option<String>,
    /// The Pool PDA (base58) this set curates. Optional; see --program-id.
    #[arg(long)]
    pool: Option<String>,
    /// The curator (base58). Optional; see --program-id.
    #[arg(long)]
    curator: Option<String>,
    /// Also write the emitted JSON to this path.
    #[arg(long)]
    out: Option<PathBuf>,
}

/// `viewing-key`: the OPT-IN on-chain viewing-key directory.
#[derive(Args)]
struct ViewingKeyArgs {
    #[command(subcommand)]
    command: ViewingKeyCommand,
}

#[derive(Subcommand)]
enum ViewingKeyCommand {
    /// Publish (or rotate) the X25519 viewing key for your own address. The
    /// account is your PDA, so nobody else can ever write it - and nothing on
    /// this chain requires you to write it either.
    Register(ViewingKeyRegisterArgs),
    /// Show the viewing key an address has published, if any.
    Show(ViewingKeyShowArgs),
}

#[derive(Args)]
struct ViewingKeyRegisterArgs {
    #[command(flatten)]
    chain: ChainArgs,
    /// The authority keypair (JSON byte array). Signs for its own registration.
    #[arg(long)]
    authority: PathBuf,
    /// A value keyfile (from `value-keygen`) whose viewing key to publish.
    /// Mutually exclusive with --viewing-pub.
    #[arg(long)]
    wallet: Option<PathBuf>,
    /// The raw X25519 viewing public key (64 hex chars), for a reader whose
    /// secret lives elsewhere. Mutually exclusive with --wallet.
    #[arg(long)]
    viewing_pub: Option<String>,
    /// Fee payer keypair; defaults to the authority.
    #[arg(long)]
    payer: Option<PathBuf>,
}

#[derive(Args)]
struct ViewingKeyShowArgs {
    #[command(flatten)]
    chain: ChainArgs,
    /// The address to look up (base58).
    #[arg(long)]
    authority: String,
}

#[derive(Args)]
struct DiscloseArgs {
    #[command(flatten)]
    chain: ChainArgs,
    /// The ZK-path note (from `deposit-commit`) for the action to disclose.
    #[arg(long)]
    note: PathBuf,
    /// The auditor's address (base58). They must have registered a viewing key;
    /// the key is read from that account, never from this command line.
    #[arg(long)]
    auditor: String,
    /// The keypair of the note's bound recipient. It MUST sign: the program
    /// recomputes the record's address from this signer, which is what stops
    /// anyone publishing a record about somebody else's settlement.
    #[arg(long)]
    recipient: PathBuf,
    /// Fee payer keypair; defaults to the recipient. Paying from another wallet
    /// links that wallet to this action, which the settlement did not.
    #[arg(long)]
    payer: Option<PathBuf>,
    /// Publish even if the action has not settled yet. Disclosing early lets the
    /// reader settle it at a moment of their choosing (they cannot redirect the
    /// payout, but they can pick a thinner window than you would have).
    #[arg(long)]
    allow_unsettled: bool,
}

/// `audit`: the reader's side of the disclosure layer.
#[derive(Args)]
struct AuditArgs {
    #[command(subcommand)]
    command: AuditCommand,
}

#[derive(Subcommand)]
enum AuditCommand {
    /// Find every disclosure sealed to your viewing key, open it, and check what
    /// it claims against the chain.
    Scan(AuditScanArgs),
}

#[derive(Args)]
struct AuditScanArgs {
    #[command(flatten)]
    chain: ChainArgs,
    /// The value keyfile (from `value-keygen`) holding your viewing secret.
    #[arg(long)]
    wallet: PathBuf,
    /// Only report records about this Pool (base58).
    #[arg(long)]
    pool: Option<String>,
}

#[derive(Args)]
struct StatusArgs {
    /// RPC endpoint.
    #[arg(long, default_value = DEFAULT_RPC_URL)]
    rpc_url: String,
    /// mirror-pool program id (base58). Optional; only used to echo it back.
    #[arg(long)]
    program_id: Option<String>,
    /// The Pool PDA (base58) to inspect.
    #[arg(long)]
    pool: String,
    /// Slot to evaluate the epoch at (defaults to a fresh `getSlot`).
    #[arg(long)]
    slot: Option<u64>,
}

/// CLI-facing action parameters for the crowd path. Mints/validators accept
/// either a 64-char hex id or a free-form label (hashed to a stand-in id for
/// local testing). Amounts are intentionally absent: only a `SizeBucket` is
/// accepted, because free-form amounts are an amount-matching oracle.
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

/// clap-parsable mirror of `mirror_core::SizeBucket`. Kept as a separate enum so
/// mirror-core stays free of CLI dependencies.
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

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::InitPool(args) => run_init_pool(args),
        Command::InitVk(args) => run_init_vk(args),
        Command::Commit(args) => run_commit(args),
        Command::DepositCommit(args) => run_deposit_commit(args),
        Command::Prove(args) => run_prove(args),
        Command::ProveAssociated(args) => run_prove_associated(args),
        Command::Assoc(args) => match args.command {
            AssocCommand::BuildRoot(a) => run_assoc_build_root(a),
            AssocCommand::Init(a) => run_assoc_init(a),
            AssocCommand::Publish(a) => run_assoc_publish(a),
            AssocCommand::Show(a) => run_assoc_show(a),
        },
        Command::ViewingKey(args) => match args.command {
            ViewingKeyCommand::Register(a) => run_viewing_key_register(a),
            ViewingKeyCommand::Show(a) => run_viewing_key_show(a),
        },
        Command::Disclose(args) => run_disclose(args),
        Command::Audit(args) => match args.command {
            AuditCommand::Scan(a) => run_audit_scan(a),
        },
        Command::Status(args) => run_status(args),
        Command::ValueKeygen(args) => run_value_keygen(args),
        Command::InitValuePool(args) => run_init_value_pool(args),
        Command::Shield(args) => run_shield(args),
        Command::Transfer(args) => run_transfer(args),
        Command::Unshield(args) => run_unshield(args),
        Command::FundCommit(args) => run_fund_commit(args),
        Command::Scan(args) => run_scan(args),
        Command::Ceremony(args) => ceremony::run(args),
    }
}

fn run_init_pool(args: InitPoolArgs) -> Result<()> {
    let program_id = parse_pubkey(&args.chain.program_id, "program-id")?;
    if args.reward_bps > 10_000 {
        return Err(anyhow!("--reward-bps must be <= 10000 (basis points)"));
    }
    if args.zk_denomination == 0 {
        return Err(anyhow!(
            "--zk-denomination must be non-zero: a zero denomination would mean the ZK path \
             accepts any amount, which is the escrow-accounting hole it exists to close"
        ));
    }
    let authority_kp = chain::read_keypair(&args.authority)?;
    let payer_kp = match &args.payer {
        Some(p) => chain::read_keypair(p)?,
        None => chain::read_keypair(&args.authority)?,
    };
    let authority = authority_kp.pubkey();
    let payer = payer_kp.pubkey();
    let pool = chain::pool_pda(&program_id, &authority);

    let ix = chain::init_pool_ix(
        &program_id,
        &pool,
        &authority,
        &payer,
        args.epoch_slots,
        args.k_floor,
        args.entry_fee,
        args.reward_bps,
        args.zk_denomination,
    );

    // Fee payer first; add the authority only if it is a distinct signer.
    let mut signers: Vec<&solana_keypair::Keypair> = vec![&payer_kp];
    if authority != payer {
        signers.push(&authority_kp);
    }

    let chain = Chain::new(args.chain.rpc_url);
    let sig = chain
        .submit(&[ix], &signers)
        .context("submitting InitPool")?;

    println!("pool authority: {authority}");
    println!("pool PDA:       {pool}");
    println!("epoch_slots:    {}", args.epoch_slots);
    println!("k_floor:        {}", args.k_floor);
    println!("entry_fee:      {} lamports", args.entry_fee);
    println!("reward_bps:     {}", args.reward_bps);
    println!("zk_denomination:{} lamports", args.zk_denomination);
    println!("signature:      {sig}");
    Ok(())
}

/// Publish a circuit's verifying key into its write-once registry PDA.
///
/// This is a PUBLICATION step, not a configuration step. There is exactly one
/// byte string the program will accept per circuit (the canonical encoding of
/// the key its `vk_digest` constants commit to), the caller cannot choose it,
/// and once written no instruction in the program can change it. What the step
/// buys is that the key in force becomes readable straight off the chain
/// instead of only by disassembling the program. See `docs/VK_REGISTRY.md`.
fn run_init_vk(args: InitVkArgs) -> Result<()> {
    let program_id = parse_pubkey(&args.chain.program_id, "program-id")?;
    let circuit_id = vk::circuit_id(&args.circuit)?;
    let canonical = vk::canonical(circuit_id)?;
    let registry = chain::vk_registry_pda(&program_id, circuit_id);
    let digest = vk::digest(&canonical);

    println!("circuit:        {} (id {circuit_id})", args.circuit);
    println!("registry PDA:   {registry}");
    println!("vk bytes:       {}", canonical.len());
    println!("sha256(vk):     {digest}");
    if args.dry_run {
        println!("dry run: nothing submitted");
        return Ok(());
    }

    let payer_kp = chain::read_keypair(&args.payer)?;
    let ix = chain::init_vk_ix(&program_id, &payer_kp.pubkey(), circuit_id, &canonical);
    let chain = Chain::new(args.chain.rpc_url);
    let sig = chain
        .submit(&[ix], &[&payer_kp])
        .context("submitting InitVk")?;
    println!("signature:      {sig}");
    Ok(())
}

fn run_commit(args: CommitArgs) -> Result<()> {
    let program_id = parse_pubkey(&args.chain.program_id, "program-id")?;
    let pool = parse_pubkey(&args.pool, "pool")?;
    let participant_kp = chain::read_keypair(&args.keypair)?;
    let participant = participant_kp.pubkey();

    let chain = Chain::new(args.chain.rpc_url);
    let pool_state = chain.pool_state(&pool)?;
    let slot = match args.slot {
        Some(s) => s,
        None => chain.slot()?,
    };
    if pool_state.epoch_slots == 0 {
        return Err(anyhow!("pool epoch_slots is 0"));
    }
    let epoch = slot / pool_state.epoch_slots;

    let secret = derive_secret(&args.pool, &args.seed);
    let action = args.action.to_action_class();
    let commitment = mirror_core::commit(&secret, &action, Epoch(epoch));
    let nf = mirror_core::nullifier(&secret, Epoch(epoch));

    let epoch_pda = chain::epoch_pda(&program_id, &pool, epoch);
    let ix = chain::commit_ix(&program_id, &pool, &epoch_pda, &participant, &commitment.0);
    let sig = chain
        .submit(&[ix], &[&participant_kp])
        .context("submitting Commit")?;

    let note = Note {
        version: NOTE_VERSION,
        program_id: program_id.to_string(),
        pool: pool.to_string(),
        slot,
        epoch,
        secret_hex: to_hex(&secret.0),
        commitment_hex: to_hex(&commitment.0),
        nullifier_hex: to_hex(&nf.0),
        action: ActionRecord::Crowd { action },
        leaf_index: None,
        frontier_pre: None,
    };
    let path = note.save(&args.note_dir)?;

    println!("pool:         {pool}");
    println!("participant:  {participant}");
    println!(
        "epoch:        {epoch} (window {} slots, settles at slot {})",
        pool_state.epoch_slots,
        (epoch + 1) * pool_state.epoch_slots
    );
    println!("commitment:   {}", note.commitment_hex);
    println!("nullifier:    {}", note.nullifier_hex);
    println!("signature:    {sig}");
    println!("note saved:   {}", path.display());
    println!();
    println!(
        "queued: counted only once epoch {epoch} reaches real k >= {} (below the floor it rolls forward).",
        pool_state.k_floor
    );
    println!("settlement is submitted by the rotating gasless coordinator, never this wallet.");
    Ok(())
}

fn run_deposit_commit(args: DepositCommitArgs) -> Result<()> {
    if args.amount == 0 {
        return Err(anyhow!(
            "--amount must be > 0 (a zero escrow has no action to settle)"
        ));
    }
    let program_id = parse_pubkey(&args.chain.program_id, "program-id")?;
    let pool = parse_pubkey(&args.pool, "pool")?;
    let recipient = parse_pubkey(&args.recipient, "recipient")?;
    let depositor_kp = chain::read_keypair(&args.keypair)?;
    let depositor = depositor_kp.pubkey();

    let chain = Chain::new(args.chain.rpc_url);
    // Read the pool BEFORE the append: commitment_count is our leaf index, and
    // filled_subtrees is the pre-insert frontier snapshot `prove` walks.
    let pool_state = chain.pool_state(&pool)?;
    if pool_state.epoch_slots == 0 {
        return Err(anyhow!("pool epoch_slots is 0"));
    }
    // Fail fast on the pool's fixed ZK escrow size rather than paying for a
    // transaction the program will reject. The program is the authority here;
    // this only saves the round trip and explains why.
    if let Some(denomination) = pool_state.zk_denomination {
        if args.amount != denomination {
            return Err(anyhow!(
                "--amount {} does not match the pool's fixed ZK denomination of {} lamports. \
                 The ZK path admits exactly one size on both sides, which is what stops a \
                 settle drawing more than its leaf escrowed; a pool serving another size is \
                 another pool.",
                args.amount,
                denomination
            ));
        }
    }
    let slot = match args.slot {
        Some(s) => s,
        None => chain.slot()?,
    };
    let epoch = slot / pool_state.epoch_slots;
    let leaf_index = pool_state.commitment_count;
    let frontier_pre: Vec<String> = pool_state.frontier.iter().map(|h| to_hex(h)).collect();

    let secret = derive_secret(&args.pool, &args.seed);
    let action_hash = mirror_core::transfer_action_hash(&recipient.to_bytes(), args.amount);
    let commitment = mirror_core::commit_with_action_hash(&secret, &action_hash, Epoch(epoch));
    let nf = mirror_core::nullifier(&secret, Epoch(epoch));

    let epoch_pda = chain::epoch_pda(&program_id, &pool, epoch);
    let ix = chain::commit_deposit_ix(
        &program_id,
        &pool,
        &epoch_pda,
        &depositor,
        &commitment.0,
        args.amount,
    );
    let sig = chain
        .submit(&[ix], &[&depositor_kp])
        .context("submitting CommitDeposit")?;

    let note = Note {
        version: NOTE_VERSION,
        program_id: program_id.to_string(),
        pool: pool.to_string(),
        slot,
        epoch,
        secret_hex: to_hex(&secret.0),
        commitment_hex: to_hex(&commitment.0),
        nullifier_hex: to_hex(&nf.0),
        action: ActionRecord::Transfer {
            recipient: recipient.to_string(),
            amount: args.amount,
        },
        leaf_index: Some(leaf_index),
        frontier_pre: Some(frontier_pre),
    };
    let path = note.save(&args.note_dir)?;

    println!("pool:         {pool}");
    println!("depositor:    {depositor}");
    println!("recipient:    {recipient}");
    println!("amount:       {} lamports (escrowed)", args.amount);
    println!(
        "epoch:        {epoch} (window {} slots, settles at slot {})",
        pool_state.epoch_slots,
        (epoch + 1) * pool_state.epoch_slots
    );
    println!("leaf index:   {leaf_index}");
    println!("commitment:   {}", note.commitment_hex);
    println!("action hash:  {}", to_hex(&action_hash));
    println!("nullifier:    {}", note.nullifier_hex);
    println!("signature:    {sig}");
    println!("note saved:   {}", path.display());
    println!();
    println!(
        "next: `mirror-cli prove --note {}` to produce the SettleZk the coordinator submits.",
        path.display()
    );
    Ok(())
}

fn run_prove(args: ProveArgs) -> Result<()> {
    let use_snarkjs = args.use_snarkjs;
    let emit = prove::run(prove::ProveOpts {
        note_path: args.note,
        rpc_url: args.rpc_url,
        wasm: args.wasm,
        r1cs: args.r1cs,
        zkey: args.zkey,
        proving_key: args.proving_key,
        vk: args.vk,
        snarkjs: args.snarkjs,
        use_snarkjs,
        leaves: args.leaves,
        work_dir: args.work_dir,
        out: args.out,
        accept_thin_set: args.accept_thin_set,
    })?;

    if use_snarkjs {
        println!("proof generated and VERIFIED by snarkjs (fallback path).");
    } else {
        println!("proof generated and VERIFIED in-process (pure Rust; no Node process).");
    }
    println!();
    println!("anonymity set for this settle (measured by the client, NOT checked on-chain):");
    println!("  epoch:          {}", emit.anonymity.epoch);
    println!(
        "  nominal_k:      {}  (commits in the window: crowd + ZK, every amount; an UPPER bound)",
        emit.anonymity.nominal_k
    );
    println!("  k_floor:        {}", emit.anonymity.k_floor);
    if emit.anonymity.accepted_below_floor {
        println!("  WAIVED:         settling below the floor at your explicit request");
    }
    println!();
    println!("SettleZk instruction (submit from the pool authority / rotating coordinator):");
    println!("  program_id:     {}", emit.program_id);
    println!("  epoch:          {}", emit.epoch);
    println!("  amount:         {} lamports", emit.amount);
    println!("  root:           {}", emit.root_hex);
    println!("  nullifierHash:  {}", emit.nullifier_hash_hex);
    println!("  actionHash:     {}", emit.action_hash_hex);
    println!();
    println!("  accounts (in order):");
    println!("    0. pool           {}  (writable)", emit.pool);
    println!(
        "    1. authority      {}  (signer, writable)",
        emit.authority
    );
    println!("    2. nullifier PDA  {}  (writable)", emit.nullifier_pda);
    println!("    3. recipient      {}  (writable)", emit.recipient);
    println!("    4. system_program {}", emit.system_program);
    println!("    5. clock sysvar   {}", emit.clock_sysvar);
    println!();
    println!("  data ({} bytes, hex):", emit.settle_zk_data_hex.len() / 2);
    println!("    {}", emit.settle_zk_data_hex);
    println!();
    println!(
        "{}",
        serde_json::to_string_pretty(&emit).context("serializing emit")?
    );
    Ok(())
}

fn run_prove_associated(args: ProveAssociatedArgs) -> Result<()> {
    let curator = parse_pubkey(&args.curator, "curator")?;
    let use_snarkjs = args.use_snarkjs;
    let emit = association::run(association::ProveAssociatedOpts {
        note_path: args.note,
        rpc_url: args.rpc_url,
        wasm: args.wasm,
        r1cs: args.r1cs,
        zkey: args.zkey,
        proving_key: args.proving_key,
        vk: args.vk,
        snarkjs: args.snarkjs,
        use_snarkjs,
        curator,
        association_leaves: args.association_leaves,
        leaves: args.leaves,
        work_dir: args.work_dir,
        out: args.out,
    })?;

    if use_snarkjs {
        println!("association proof generated and VERIFIED by snarkjs (fallback path).");
    } else {
        println!(
            "association proof generated and VERIFIED in-process (pure Rust; no Node process)."
        );
    }
    println!();
    println!("SettleZkAssociated instruction (submit from the pool authority / coordinator):");
    println!("  program_id:      {}", emit.program_id);
    println!("  epoch:           {}", emit.epoch);
    println!("  amount:          {} lamports", emit.amount);
    println!("  root:            {}", emit.root_hex);
    println!("  nullifierHash:   {}", emit.nullifier_hash_hex);
    println!("  actionHash:      {}", emit.action_hash_hex);
    println!("  associationRoot: {}", emit.association_root_hex);
    println!("  curator:         {}", emit.curator);
    println!();
    println!("  accounts (in order):");
    println!("    0. pool           {}  (writable)", emit.pool);
    println!(
        "    1. authority      {}  (signer, writable)",
        emit.authority
    );
    println!("    2. nullifier PDA  {}  (writable)", emit.nullifier_pda);
    println!("    3. recipient      {}  (writable)", emit.recipient);
    println!("    4. system_program {}", emit.system_program);
    println!("    5. clock sysvar   {}", emit.clock_sysvar);
    println!("    6. association    {}", emit.association_pda);
    println!();
    println!(
        "  data ({} bytes, hex):",
        emit.settle_zk_associated_data_hex.len() / 2
    );
    println!("    {}", emit.settle_zk_associated_data_hex);
    println!();
    // The honest bound, printed every time rather than buried in docs.
    println!(
        "  anonymity note: this attestation hides you inside the curated set of {} leaves. \
         Against a set that small an observer learns correspondingly much; the pool's own \
         anonymity set does not rescue a tiny association set.",
        emit.association_set_size
    );
    println!();
    println!(
        "{}",
        serde_json::to_string_pretty(&emit).context("serializing emit")?
    );
    Ok(())
}

fn run_assoc_build_root(args: AssocBuildRootArgs) -> Result<()> {
    // The PDA is only reported when all three of program-id/pool/curator are
    // given; a partial set is a user mistake worth naming rather than ignoring.
    let ctx = match (&args.program_id, &args.pool, &args.curator) {
        (Some(p), Some(pool), Some(cur)) => Some((
            parse_pubkey(p, "program-id")?,
            parse_pubkey(pool, "pool")?,
            parse_pubkey(cur, "curator")?,
        )),
        (None, None, None) => None,
        _ => {
            return Err(anyhow!(
                "--program-id, --pool and --curator must be given together (or all omitted)"
            ))
        }
    };
    let emit = association::build_root(
        &args.leaves,
        ctx.as_ref().map(|(p, pool, cur)| (p, pool, cur)),
    )?;

    println!("association root:  {}", emit.association_root_hex);
    println!("curated set size:  {}", emit.set_size);
    if let Some(pda) = &emit.association_pda {
        println!("association PDA:   {pda}");
    }
    println!();
    println!("UpdateAssociationRoot instruction (submit signed by the curator):");
    println!("  accounts (in order):");
    println!("    0. association    (writable)");
    println!("    1. curator        (signer)");
    println!(
        "  data ({} bytes, hex): {}",
        emit.update_root_data_hex.len() / 2,
        emit.update_root_data_hex
    );
    println!();
    println!(
        "  PUBLISH the leaf list alongside this root. The program cannot check that the root \
         covers the commitments you claim; only publication lets anyone verify it."
    );
    println!();
    if let Some(out) = &args.out {
        let json = serde_json::to_string_pretty(&emit).context("serializing emit")?;
        std::fs::write(out, json).with_context(|| format!("writing {}", out.display()))?;
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&emit).context("serializing emit")?
    );
    Ok(())
}

fn run_assoc_init(args: AssocInitArgs) -> Result<()> {
    let program_id = parse_pubkey(&args.chain.program_id, "program-id")?;
    let pool = parse_pubkey(&args.pool, "pool")?;
    let curator_kp = chain::read_keypair(&args.curator)?;
    let payer_kp = match &args.payer {
        Some(p) => chain::read_keypair(p)?,
        None => chain::read_keypair(&args.curator)?,
    };
    let curator = curator_kp.pubkey();
    let payer = payer_kp.pubkey();
    let assoc = chain::association_pda(&program_id, &pool, &curator);

    let ix = chain::init_association_ix(&program_id, &assoc, &pool, &curator, &payer);
    // Fee payer first; add the curator only if it is a distinct signer.
    let mut signers: Vec<&solana_keypair::Keypair> = vec![&payer_kp];
    if curator != payer {
        signers.push(&curator_kp);
    }
    let chain_client = Chain::new(args.chain.rpc_url);
    let sig = chain_client
        .submit(&[ix], &signers)
        .context("submitting InitAssociation")?;

    println!("association set registered.");
    println!("  pool:            {pool}");
    println!("  curator:         {curator}");
    println!("  association PDA: {assoc}");
    println!("  signature:       {sig}");
    println!();
    println!(
        "  No root is published yet, so this set vouches for nothing. Run \
         `mirror-cli assoc publish` with your curated leaf list next."
    );
    Ok(())
}

fn run_assoc_publish(args: AssocPublishArgs) -> Result<()> {
    let program_id = parse_pubkey(&args.chain.program_id, "program-id")?;
    let pool = parse_pubkey(&args.pool, "pool")?;
    let curator_kp = chain::read_keypair(&args.curator)?;
    let curator = curator_kp.pubkey();
    let assoc = chain::association_pda(&program_id, &pool, &curator);

    let emit = association::build_root(&args.leaves, Some((&program_id, &pool, &curator)))?;
    let root = util::from_hex32(&emit.association_root_hex)?;

    let ix = chain::update_association_root_ix(&program_id, &assoc, &curator, &root);
    let chain_client = Chain::new(args.chain.rpc_url);
    let sig = chain_client
        .submit(&[ix], &[&curator_kp])
        .context("submitting UpdateAssociationRoot")?;

    println!("association root published.");
    println!("  association PDA:  {assoc}");
    println!("  root:             {}", emit.association_root_hex);
    println!("  curated set size: {}", emit.set_size);
    println!("  signature:        {sig}");
    println!();
    println!(
        "  PUBLISH {} alongside this root. The program cannot check that the root covers the \
         commitments you claim; only publication lets anyone verify it.",
        args.leaves.display()
    );
    Ok(())
}

fn run_assoc_show(args: AssocShowArgs) -> Result<()> {
    let program_id = parse_pubkey(&args.chain.program_id, "program-id")?;
    let pool = parse_pubkey(&args.pool, "pool")?;
    let curator = parse_pubkey(&args.curator, "curator")?;
    let assoc = chain::association_pda(&program_id, &pool, &curator);

    let chain_client = Chain::new(args.chain.rpc_url);
    let state = chain_client.association_state(&assoc)?;

    println!("association set {assoc}");
    println!("  pool:          {}", state.pool);
    println!("  curator:       {}", state.curator);
    println!("  roots published: {}", state.update_count);
    println!("  recent roots (accepted by SettleZkAssociated):");
    for (i, root) in state.root_ring.iter().enumerate() {
        let label = if root == &[0u8; 32] {
            "  (unwritten)"
        } else {
            ""
        };
        println!("    [{i}] {}{label}", to_hex(root));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Opt-in disclosure layer: viewing-key directory, disclosing, auditing.
// ---------------------------------------------------------------------------

/// Publish (or rotate) the X25519 viewing key for the signing address.
fn run_viewing_key_register(args: ViewingKeyRegisterArgs) -> Result<()> {
    let program_id = parse_pubkey(&args.chain.program_id, "program-id")?;
    let authority_kp = chain::read_keypair(&args.authority)?;
    let payer_kp = match &args.payer {
        Some(p) => chain::read_keypair(p)?,
        None => chain::read_keypair(&args.authority)?,
    };
    let authority = authority_kp.pubkey();
    let payer = payer_kp.pubkey();

    let viewing_pub = match (&args.wallet, &args.viewing_pub) {
        (Some(_), Some(_)) => return Err(anyhow!("pass --wallet or --viewing-pub, not both")),
        (Some(path), None) => {
            let keyfile = value_note::ValueKeyfile::load(path)?;
            let wallet = value_note::ValueWallet::from_keyfile(&keyfile)?;
            wallet.viewing.public()
        }
        (None, Some(hex)) => util::from_hex32(hex).context("--viewing-pub")?,
        (None, None) => return Err(anyhow!("pass --wallet or --viewing-pub")),
    };
    // Refuse locally exactly what the chain refuses, with the reason.
    if !mirror_core::encrypted_note::is_acceptable_x25519_pubkey(&viewing_pub) {
        return Err(anyhow!(
            "that is not an acceptable X25519 viewing key: it is either a non-canonical encoding \
             or a small-order point, and anything sealed to a small-order key is readable by \
             everybody. The program rejects it too (InvalidViewingKey)."
        ));
    }

    let viewkey = chain::viewing_key_pda(&program_id, &authority);
    let chain_client = Chain::new(args.chain.rpc_url);
    let existing = chain_client.viewing_key_state(&viewkey)?;

    let ix =
        chain::register_viewing_key_ix(&program_id, &viewkey, &authority, &payer, &viewing_pub);
    let mut signers: Vec<&solana_keypair::Keypair> = vec![&payer_kp];
    if authority != payer {
        signers.push(&authority_kp);
    }
    let sig = chain_client
        .submit(&[ix], &signers)
        .context("submitting RegisterViewingKey")?;

    match existing {
        None => println!("viewing key registered."),
        Some(prev) => {
            println!("viewing key rotated.");
            println!("  previous key:    {}", to_hex(&prev.viewing_public_key));
        }
    }
    println!("  authority:       {authority}");
    println!("  viewing key:     {}", to_hex(&viewing_pub));
    println!("  viewing-key PDA: {viewkey}");
    println!("  signature:       {sig}");
    println!();
    println!(
        "  This account is PUBLIC and permanent: it links {authority} to this key forever, and \
         anyone can read it. It is also optional - no settle path reads it, so not registering \
         costs you nothing."
    );
    Ok(())
}

/// Show what viewing key an address has published, if any.
fn run_viewing_key_show(args: ViewingKeyShowArgs) -> Result<()> {
    let program_id = parse_pubkey(&args.chain.program_id, "program-id")?;
    let authority = parse_pubkey(&args.authority, "authority")?;
    let viewkey = chain::viewing_key_pda(&program_id, &authority);
    let chain_client = Chain::new(args.chain.rpc_url);

    match chain_client.viewing_key_state(&viewkey)? {
        None => {
            println!("{authority} has not registered a viewing key.");
            println!("  expected PDA: {viewkey}");
            println!("  That is the default, and it blocks nothing.");
        }
        Some(state) => {
            println!("viewing key {viewkey}");
            println!("  authority:   {}", state.authority);
            println!("  viewing key: {}", to_hex(&state.viewing_public_key));
            println!("  rotations:   {}", state.rotation_count);
        }
    }
    Ok(())
}

/// Seal one ZK-path action to an auditor's registered viewing key and publish the
/// record.
fn run_disclose(args: DiscloseArgs) -> Result<()> {
    let program_id = parse_pubkey(&args.chain.program_id, "program-id")?;
    let auditor = parse_pubkey(&args.auditor, "auditor")?;
    let note = Note::load(&args.note)?;
    let pool = parse_pubkey(&note.pool, "pool (from the note)")?;

    let (note_recipient, amount) = match &note.action {
        ActionRecord::Transfer { recipient, amount } => (recipient.clone(), *amount),
        ActionRecord::Crowd { .. } => {
            return Err(anyhow!(
                "this note is a CROWD-path note. The disclosure layer covers the ZK opt-in path, \
                 whose settlement binds a recipient address the record is derived from; a crowd \
                 action has no such address."
            ))
        }
    };

    let recipient_kp = chain::read_keypair(&args.recipient)?;
    let recipient = recipient_kp.pubkey();
    if recipient.to_string() != note_recipient {
        return Err(anyhow!(
            "--recipient is {recipient}, but this note is bound to {note_recipient}. Only the \
             bound recipient can publish a record about this settlement: the program derives the \
             record's address from the signer."
        ));
    }
    let payer_kp = match &args.payer {
        Some(p) => chain::read_keypair(p)?,
        None => chain::read_keypair(&args.recipient)?,
    };
    let payer = payer_kp.pubkey();

    // The reader must have registered. The key comes from that account.
    let auditor_viewkey = chain::viewing_key_pda(&program_id, &auditor);
    let chain_client = Chain::new(args.chain.rpc_url);
    let auditor_state = chain_client
        .viewing_key_state(&auditor_viewkey)?
        .ok_or_else(|| {
            anyhow!(
            "{auditor} has not registered a viewing key ({auditor_viewkey} is empty), so there is \
             nothing to seal to. Ask them to run `mirror-cli viewing-key register`."
        )
        })?;

    // Has it settled? A disclosure about an unsettled action is publishable, but
    // the reader could then choose when it settles.
    let secret = Secret(util::from_hex32(&note.secret_hex)?);
    let epoch = Epoch(note.epoch);
    let nullifier = mirror_core::nullifier(&secret, epoch);
    let nf_pda = chain::nullifier_pda(&program_id, &pool, epoch.0, &nullifier.0);
    let settled = chain_client.nullifier_exists(&nf_pda)?;
    if !settled && !args.allow_unsettled {
        return Err(anyhow!(
            "this action has not settled yet ({nf_pda} does not exist). Disclosing the secret now \
             lets the reader settle it whenever they like - they cannot redirect the payout, which \
             the commitment binds, but they can pick a thinner window than you would have. Wait \
             for the settle, or pass --allow-unsettled if that is what you want."
        ));
    }

    let blob = mirror_core::disclosure::seal(&auditor_state.viewing_public_key, epoch, &secret);
    let action_hash = mirror_core::transfer_action_hash(&recipient.to_bytes(), amount);
    let record = chain::disclosure_pda(
        &program_id,
        &pool,
        &action_hash,
        &auditor_state.viewing_public_key,
    );

    let ix = chain::publish_disclosure_ix(
        &program_id,
        &record,
        &pool,
        &recipient,
        &auditor_viewkey,
        &payer,
        amount,
        &blob,
    );
    let mut signers: Vec<&solana_keypair::Keypair> = vec![&payer_kp];
    if recipient != payer {
        signers.push(&recipient_kp);
    }
    let sig = chain_client
        .submit(&[ix], &signers)
        .context("submitting PublishDisclosure")?;

    println!("disclosure published.");
    println!("  pool:            {pool}");
    println!("  recipient:       {recipient}");
    println!("  auditor:         {auditor}");
    println!(
        "  auditor key:     {}",
        to_hex(&auditor_state.viewing_public_key)
    );
    println!("  action hash:     {}", to_hex(&action_hash));
    println!("  record PDA:      {record}");
    println!("  settled already: {settled}");
    println!("  signature:       {sig}");
    println!();
    println!(
        "  What {auditor} can now read: this ONE action's deposit leaf and spend tag, so they can \
         find the deposit that funded it and the settlement that paid it. Nothing about your other \
         actions, and nothing about anyone else's."
    );
    println!(
        "  What everyone else can now read: that the settlement to {recipient} has a disclosure \
         addressed to that auditor. The commitment is NOT on this record; it is inside the sealed \
         blob."
    );
    Ok(())
}

/// Find, open, and verify every disclosure sealed to this reader's viewing key.
fn run_audit_scan(args: AuditScanArgs) -> Result<()> {
    let program_id = parse_pubkey(&args.chain.program_id, "program-id")?;
    let pool_filter = match &args.pool {
        Some(p) => Some(parse_pubkey(p, "pool")?),
        None => None,
    };
    let keyfile = value_note::ValueKeyfile::load(&args.wallet)?;
    let wallet = value_note::ValueWallet::from_keyfile(&keyfile)?;
    let viewing_secret = wallet.viewing.to_secret_bytes();
    let my_pub = wallet.viewing.public();

    let chain_client = Chain::new(args.chain.rpc_url);
    let records = chain_client.disclosure_records(&program_id)?;

    println!("scanned {} disclosure record(s).", records.len());
    let mut opened = 0usize;
    for (address, record) in &records {
        if let Some(pool) = pool_filter {
            if record.pool != pool {
                continue;
            }
        }
        // The record names the key it was sealed to, so skip the ones that are
        // not ours before spending a trial decryption on them. The AEAD check
        // below is what actually decides.
        if record.auditor_view_pub != my_pub {
            continue;
        }
        let Some(disclosed) = mirror_core::disclosure::open(&viewing_secret, &record.blob) else {
            println!();
            println!("record {address}: sealed to my key but does NOT open.");
            println!("  The publisher sealed to a different key, or the blob is junk. Nothing to");
            println!("  verify; the record is worthless and its publisher signed it.");
            continue;
        };
        opened += 1;
        let action = mirror_core::disclosure::derive_action(&disclosed, &record.action_hash);
        let nf_pda = chain::nullifier_pda(
            &program_id,
            &record.pool,
            action.epoch.0,
            &action.nullifier.0,
        );
        let settled = chain_client.nullifier_exists(&nf_pda)?;

        println!();
        println!("record {address}");
        println!("  pool:          {}", record.pool);
        println!("  published by:  {} (signed)", record.recipient);
        println!("  addressed to:  {}", record.auditor);
        println!("  amount:        {} lamports", record.amount);
        println!("  epoch:         {}", action.epoch.0);
        println!("  commitment:    {}", to_hex(&action.commitment.0));
        println!("  nullifier:     {}", to_hex(&action.nullifier.0));
        println!("  nullifier PDA: {nf_pda}");
        if settled {
            println!("  VERIFIED:      that nullifier PDA exists, so this action really settled.");
            println!(
                "                 The deposit that funded it is the CommitDeposit carrying the \
                 commitment above."
            );
        } else {
            println!(
                "  UNVERIFIED:    no nullifier PDA at that address, so nothing on-chain supports"
            );
            println!(
                "                 this claim yet. Either the action has not settled, or the \
                 record is false."
            );
        }
    }
    println!();
    println!("{opened} record(s) were addressed to this viewing key.");
    if opened == 0 {
        println!(
            "  Nothing to read. Records are found by scanning, not by lookup: a reader cannot \
             derive a record's address without already knowing the settlement it is about."
        );
    }
    Ok(())
}

fn run_status(args: StatusArgs) -> Result<()> {
    let pool = parse_pubkey(&args.pool, "pool")?;
    let chain = Chain::new(args.rpc_url);
    let pool_state = chain.pool_state(&pool)?;
    let slot = match args.slot {
        Some(s) => s,
        None => chain.slot()?,
    };
    let epoch = if pool_state.epoch_slots == 0 {
        0
    } else {
        slot / pool_state.epoch_slots
    };

    if let Some(pid) = &args.program_id {
        println!("program id:        {pid}");
    }
    println!("pool:              {pool}");
    println!("authority:         {}", pool_state.authority);
    println!("epoch_slots:       {}", pool_state.epoch_slots);
    println!("k_floor:           {}", pool_state.k_floor);
    println!("entry_fee:         {} lamports", pool_state.entry_fee);
    match pool_state.zk_denomination {
        Some(d) => println!("zk_denomination:   {d} lamports"),
        None => println!("zk_denomination:   (absent: pre-denomination pool layout)"),
    }
    println!("commitment_count:  {}", pool_state.commitment_count);
    println!("current_root:      {}", to_hex(&pool_state.current_root));
    println!("current slot:      {slot}");
    println!("current epoch:     {epoch}");
    if pool_state.epoch_slots > 0 {
        println!(
            "settles at slot:   {}",
            (epoch + 1) * pool_state.epoch_slots
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Confidential-value layer handlers.
// ---------------------------------------------------------------------------

fn run_value_keygen(args: ValueKeygenArgs) -> Result<()> {
    let wallet = match &args.seed {
        Some(seed) => value_note::ValueWallet::from_seed(seed),
        None => value_note::ValueWallet::random(),
    };
    let addr = wallet.address();
    wallet.to_keyfile().save(&args.out)?;

    println!("value public key:   {}", to_hex(&addr.value_public_key));
    println!("viewing public key: {}", to_hex(&addr.viewing_public_key));
    println!("address:            {}", addr.to_encoded());
    println!("keyfile saved:      {}", args.out.display());
    if args.seed.is_none() {
        println!("(random wallet; keep the keyfile safe - it is the only copy of the secrets)");
    }
    Ok(())
}

fn run_init_value_pool(args: InitValuePoolArgs) -> Result<()> {
    let program_id = parse_pubkey(&args.chain.program_id, "program-id")?;
    let authority_kp = chain::read_keypair(&args.authority)?;
    let payer_kp = match &args.payer {
        Some(p) => chain::read_keypair(p)?,
        None => chain::read_keypair(&args.authority)?,
    };
    let authority = authority_kp.pubkey();
    let payer = payer_kp.pubkey();
    let vpool = chain::value_pool_pda(&program_id, &authority);
    let vault = chain::value_vault_pda(&program_id, &vpool);

    let ix = chain::init_value_pool_ix(
        &program_id,
        &vpool,
        &vault,
        &authority,
        &payer,
        args.fee,
        args.denomination,
    );

    // Fee payer first; add the authority only if it is a distinct signer.
    let mut signers: Vec<&solana_keypair::Keypair> = vec![&payer_kp];
    if authority != payer {
        signers.push(&authority_kp);
    }
    let chain = Chain::new(args.chain.rpc_url);
    let sig = chain
        .submit(&[ix], &signers)
        .context("submitting InitValuePool")?;

    println!("value pool authority: {authority}");
    println!("value pool PDA:       {vpool}");
    println!("vault PDA:            {vault}");
    println!("fee:                  {} lamports", args.fee);
    match args.denomination {
        Some(d) => println!("denomination:         {d} lamports (enforced on-chain)"),
        None => println!("denomination:         none"),
    }
    println!("signature:            {sig}");
    Ok(())
}

fn run_shield(args: ShieldArgs) -> Result<()> {
    let program_id = parse_pubkey(&args.chain.program_id, "program-id")?;
    let value_pool = parse_pubkey(&args.pool, "pool")?;
    let to = value_note::ValueAddress::parse(&args.to).context("--to")?;
    let depositor_kp = chain::read_keypair(&args.depositor)?;

    let emit = value::run_shield(value::ShieldOpts {
        rpc_url: args.chain.rpc_url,
        program_id,
        value_pool,
        depositor: depositor_kp.pubkey(),
        to,
        amount: args.amount,
        note_dir: args.note_dir,
        prove: args.prove.to_opts(),
        out: args.prove.out.clone(),
    })?;
    print_transact_emit(&emit, args.prove.use_snarkjs)?;
    Ok(())
}

fn run_transfer(args: TransferArgs) -> Result<()> {
    let program_id = parse_pubkey(&args.chain.program_id, "program-id")?;
    let value_pool = parse_pubkey(&args.pool, "pool")?;
    let to = value_note::ValueAddress::parse(&args.to).context("--to")?;
    let change_to = match &args.change_to {
        Some(s) => Some(value_note::ValueAddress::parse(s).context("--change-to")?),
        None => None,
    };

    let emit = value::run_transfer(value::TransferOpts {
        rpc_url: args.chain.rpc_url,
        program_id,
        value_pool,
        note: args.note,
        to,
        amount: args.amount,
        change_to,
        note_dir: args.note_dir,
        prove: args.prove.to_opts(),
        out: args.prove.out.clone(),
    })?;
    print_transact_emit(&emit, args.prove.use_snarkjs)?;
    Ok(())
}

fn run_unshield(args: UnshieldArgs) -> Result<()> {
    let program_id = parse_pubkey(&args.chain.program_id, "program-id")?;
    let value_pool = parse_pubkey(&args.pool, "pool")?;
    let recipient = parse_pubkey(&args.recipient, "recipient")?;

    let emit = value::run_unshield(value::UnshieldOpts {
        rpc_url: args.chain.rpc_url,
        program_id,
        value_pool,
        note: args.note,
        recipient,
        amount: args.amount,
        note_dir: args.note_dir,
        prove: args.prove.to_opts(),
        out: args.prove.out.clone(),
    })?;
    print_transact_emit(&emit, args.prove.use_snarkjs)?;
    Ok(())
}

fn run_fund_commit(args: FundCommitArgs) -> Result<()> {
    let program_id = parse_pubkey(&args.chain.program_id, "program-id")?;
    let value_pool = parse_pubkey(&args.pool, "pool")?;

    // The pool's denomination decides the withdrawal amount: under a denominated
    // pool every funding withdrawal is the same number, which is what makes the
    // deposit-to-withdrawal matching hard. Read it from chain rather than trusting
    // a flag.
    let chain = Chain::new(args.chain.rpc_url.clone());
    let vpool = chain
        .value_pool_state(&value_pool)
        .context("reading the value pool")?;
    let amount = funding::resolve_funding_amount(vpool.denomination, args.amount)?;

    let (commit_wallet, keypair_path, fresh) = match &args.commit_wallet {
        Some(path) => (funding::load_commit_wallet(path)?, path.clone(), false),
        None => (
            funding::create_commit_wallet(&args.out_keypair)?,
            args.out_keypair.clone(),
            true,
        ),
    };
    let recipient = commit_wallet.pubkey();

    let emit = value::run_unshield(value::UnshieldOpts {
        rpc_url: args.chain.rpc_url,
        program_id,
        value_pool,
        note: args.note,
        recipient,
        amount,
        note_dir: args.note_dir,
        prove: args.prove.to_opts(),
        out: args.prove.out.clone(),
    })?;

    println!("commit wallet:  {}", funding::address(&commit_wallet));
    println!(
        "keypair:        {} ({})",
        keypair_path.display(),
        if fresh { "freshly generated" } else { "reused" }
    );
    println!("funding amount: {amount} lamports");
    match vpool.denomination {
        Some(d) => println!("denomination:   {d} lamports (enforced on-chain)"),
        None => println!("denomination:   none (free-amount pool)"),
    }
    println!();
    print_transact_emit(&emit, args.prove.use_snarkjs)?;
    println!();
    println!("funding notes:");
    for note in funding::funding_notes(vpool.denomination.is_some()) {
        println!("  - {note}");
    }
    println!();
    println!("next: `mirror-cli commit --keypair {}` (or `deposit-commit`) from the funded wallet, once a coordinator funding round has released this withdrawal. No shipped service ingests this request yet: releasing it is currently the operator's job.", keypair_path.display());
    Ok(())
}

fn run_scan(args: ScanArgs) -> Result<()> {
    let value_pool = match &args.pool {
        Some(s) => Some(parse_pubkey(s, "pool")?),
        None => None,
    };
    let program_id = match &args.program_id {
        Some(s) => Some(parse_pubkey(s, "program-id")?),
        None => None,
    };
    let found = value::run_scan(value::ScanOpts {
        viewing_key: args.viewing_key,
        blobs: args.blobs,
        leaves: args.leaves,
        rpc_url: args.rpc_url,
        value_pool,
        program_id,
        note_dir: args.note_dir,
    })?;

    println!(
        "scan: {} note(s) addressed to this viewing key",
        found.len()
    );
    for (i, n) in found.iter().enumerate() {
        println!(
            "  [{i}] amount={} commitment={} leaf_index={}",
            n.amount,
            to_hex(&n.commitment),
            n.leaf_index
                .map(|x| x.to_string())
                .unwrap_or_else(|| "unknown (pass --leaves)".to_string())
        );
        if let Some(p) = &n.saved_path {
            println!("      spendable note saved: {}", p.display());
        }
    }
    Ok(())
}

/// Print the emitted Transact bundle: a human summary then the machine-readable JSON.
fn print_transact_emit(emit: &value::TransactEmit, use_snarkjs: bool) -> Result<()> {
    if use_snarkjs {
        println!("proof generated and VERIFIED by snarkjs (fallback path).");
    } else {
        println!("proof generated and VERIFIED in-process (pure Rust; no Node process).");
    }
    println!();
    let submitter = if emit.shield_requires_depositor_signature {
        "the relay authority (fee payer + signer) AND the depositor (co-signs + funds the deposit)"
    } else {
        "the gasless relay authority ONLY (no user signature - this is the unlinkability)"
    };
    println!("Transact ({}) - submit signed by {}:", emit.op, submitter);
    println!("  program_id:     {}", emit.program_id);
    println!("  value pool:     {}", emit.value_pool);
    println!("  authority:      {}", emit.authority);
    println!("  vault:          {}", emit.vault);
    println!("  fee:            {} lamports", emit.fee);
    println!("  publicAmount:   {}", emit.public_amount_hex);
    println!("  root:           {}", emit.root_hex);
    println!("  extDataHash:    {}", emit.ext_data_hash_hex);
    println!("  in nullifier0:  {}", emit.in_nullifier0_hex);
    println!("  in nullifier1:  {}", emit.in_nullifier1_hex);
    println!("  out commit0:    {}", emit.out_commitment0_hex);
    println!("  out commit1:    {}", emit.out_commitment1_hex);
    println!();
    println!("  accounts (in order):");
    for (i, a) in emit.accounts.iter().enumerate() {
        let s = if a.is_signer { "signer" } else { "-" };
        let w = if a.is_writable {
            "writable"
        } else {
            "readonly"
        };
        println!("    {i}. {:<16} {} ({s}, {w})", a.role, a.pubkey);
    }
    println!();
    println!("  data ({} bytes, hex):", emit.transact_data_hex.len() / 2);
    println!("    {}", emit.transact_data_hex);
    println!();
    println!(
        "{}",
        serde_json::to_string_pretty(emit).context("serializing emit")?
    );
    Ok(())
}

/// Parse a base58 pubkey argument with a helpful error label.
fn parse_pubkey(s: &str, what: &str) -> Result<Pubkey> {
    Pubkey::from_str(s).map_err(|e| anyhow!("--{what} is not a valid base58 pubkey: {e}"))
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

/// Parse a 32-byte identifier. Exactly 64 hex chars decode literally; anything
/// else is treated as a human label and hashed (domain-tagged) into a stand-in
/// id, which keeps local test flows free of real addresses.
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

#[cfg(test)]
mod tests {
    use super::*;

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
