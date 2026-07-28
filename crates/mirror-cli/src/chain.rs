//! The on-chain boundary: PDA derivation, Pool-account readback, instruction
//! builders, keypair loading, and transaction submission.
//!
//! No program id, pool, or key is baked in: every address arrives from the CLI
//! arguments. The instruction bodies are built from `mirror_core::wire` (the
//! shared byte layout the on-chain program parses), and the PDA seeds and
//! Pool-account field offsets are redefined here as protocol constants,
//! byte-identical to the program's `pda` and `state::pool` modules - the same
//! way the coordinator mirrors them. If either side changes, both change in one
//! commit; the layout asserts and the live soak catch drift.

use anyhow::{anyhow, bail, Context, Result};
use mirror_core::{wire, Hash32};
use solana_commitment_config::CommitmentConfig;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_rpc_client::rpc_client::RpcClient;
use solana_signer::Signer;

// ---------------------------------------------------------------------------
// Fixed public system addresses.
// ---------------------------------------------------------------------------

/// System program (create-account / transfer CPIs).
pub const SYSTEM_PROGRAM_ID: Pubkey = Pubkey::from_str_const("11111111111111111111111111111111");

/// The Clock sysvar read to derive the current epoch (`slot / epoch_slots`).
pub const CLOCK_SYSVAR_ID: Pubkey =
    Pubkey::from_str_const("SysvarC1ock11111111111111111111111111111111");

// ---------------------------------------------------------------------------
// PDA seeds, byte-identical to the on-chain `pda` module.
// ---------------------------------------------------------------------------

pub const POOL_SEED: &[u8] = b"pool";
pub const EPOCH_SEED: &[u8] = b"epoch";
pub const NULLIFIER_SEED: &[u8] = b"nf";

/// Confidential-value seed prefixes, byte-identical to the on-chain `pda` module.
pub const VALUE_POOL_SEED: &[u8] = b"vpool";
pub const VALUE_VAULT_SEED: &[u8] = b"vvault";
pub const VALUE_NULLIFIER_SEED: &[u8] = b"vnf";

/// Opt-in compliance layer: a curator's AssociationSet PDA seed prefix,
/// byte-identical to the on-chain `pda` module.
pub const ASSOCIATION_SEED: &[u8] = b"assoc";

/// Derive the Pool PDA: seeds `[b"pool", authority]`.
pub fn pool_pda(program_id: &Pubkey, authority: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[POOL_SEED, authority.as_ref()], program_id).0
}

/// Derive the Epoch PDA: seeds `[b"epoch", pool, epoch_id(8 LE)]`.
pub fn epoch_pda(program_id: &Pubkey, pool: &Pubkey, epoch: u64) -> Pubkey {
    Pubkey::find_program_address(
        &[EPOCH_SEED, pool.as_ref(), &epoch.to_le_bytes()],
        program_id,
    )
    .0
}

/// Derive a Nullifier PDA: seeds `[b"nf", pool, epoch_id(8 LE), nullifier(32)]`.
pub fn nullifier_pda(program_id: &Pubkey, pool: &Pubkey, epoch: u64, nullifier: &Hash32) -> Pubkey {
    Pubkey::find_program_address(
        &[
            NULLIFIER_SEED,
            pool.as_ref(),
            &epoch.to_le_bytes(),
            nullifier,
        ],
        program_id,
    )
    .0
}

/// Derive a curator's AssociationSet PDA: seeds `[b"assoc", pool, curator]`.
///
/// The curator is part of the seeds, so several curators can publish competing
/// curated sets over the same pool.
pub fn association_pda(program_id: &Pubkey, pool: &Pubkey, curator: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(
        &[ASSOCIATION_SEED, pool.as_ref(), curator.as_ref()],
        program_id,
    )
    .0
}

/// Derive the ValuePool PDA: seeds `[b"vpool", authority]`.
pub fn value_pool_pda(program_id: &Pubkey, authority: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[VALUE_POOL_SEED, authority.as_ref()], program_id).0
}

/// Derive the value vault PDA (holds commingled lamports): seeds `[b"vvault", vpool]`.
pub fn value_vault_pda(program_id: &Pubkey, vpool: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[VALUE_VAULT_SEED, vpool.as_ref()], program_id).0
}

/// Derive a value nullifier PDA (global spent-set): seeds `[b"vnf", vpool, nullifier(32)]`.
/// A value nullifier is position-bound by the transaction circuit, so unlike the
/// behavioral nullifier it is NOT epoch-scoped.
pub fn value_nullifier_pda(program_id: &Pubkey, vpool: &Pubkey, nullifier: &Hash32) -> Pubkey {
    Pubkey::find_program_address(
        &[VALUE_NULLIFIER_SEED, vpool.as_ref(), nullifier],
        program_id,
    )
    .0
}

// ---------------------------------------------------------------------------
// Pool account layout, byte-identical to the on-chain `state::pool` module.
// (LE integers; see programs/mirror-pool/src/state/pool.rs.)
// ---------------------------------------------------------------------------

// Every offset is kept for documentation even where the decoder does not read it
// (e.g. BUMP), so this stays a faithful mirror of the program's pool layout.
#[allow(dead_code)]
mod pool_off {
    /// Merkle depth; must equal the program's and the circuit's DEPTH.
    pub const DEPTH: usize = crate::tree::DEPTH;
    pub const VERSION: usize = 0;
    pub const EPOCH_SLOTS: usize = 1;
    pub const K_FLOOR: usize = 9;
    pub const COMMITMENT_COUNT: usize = 13;
    pub const CURRENT_ROOT: usize = 21;
    pub const AUTHORITY: usize = 53;
    pub const ENTRY_FEE: usize = 85;
    pub const BUMP: usize = 93;
    pub const FRONTIER: usize = 94;
    pub const FRONTIER_LEN: usize = DEPTH * 32;
    pub const ROOT_HISTORY_SIZE: usize = 32;
    pub const ROOT_HEAD: usize = FRONTIER + FRONTIER_LEN; // 734
    pub const ROOT_RING: usize = ROOT_HEAD + 4; // 738
    pub const ROOT_RING_LEN: usize = ROOT_HISTORY_SIZE * 32;

    /// Everything the CLI decodes lives in the prefix ending here (through the
    /// root-history ring). The participation-incentive tail below is ADDITIVE and
    /// not read by the CLI, so the decoder accepts any account at least this long,
    /// which keeps it working as the program adds further additive fields.
    pub const MIN_LEN: usize = ROOT_RING + ROOT_RING_LEN; // 1762

    // Additive incentive layer (documented; not read by the CLI).
    pub const REWARD_BPS: usize = MIN_LEN; // 1762
    pub const REWARD_POOL: usize = REWARD_BPS + 2; // 1764
    pub const TOTAL_UNCLAIMED_DWELL: usize = REWARD_POOL + 8; // 1772
    /// The full account length at the time of writing.
    pub const LEN: usize = TOTAL_UNCLAIMED_DWELL + 8; // 1780
}

/// A decoded snapshot of a Pool account, as read over RPC.
#[derive(Clone, Debug)]
pub struct PoolState {
    pub epoch_slots: u64,
    pub k_floor: u32,
    pub commitment_count: u64,
    pub current_root: Hash32,
    pub authority: Pubkey,
    pub entry_fee: u64,
    /// `filled_subtrees`, one 32-byte sibling per level (the frontier).
    pub frontier: Vec<Hash32>,
    /// The recent-root ring buffer (the last `ROOT_HISTORY_SIZE` roots).
    pub root_ring: Vec<Hash32>,
}

impl PoolState {
    /// Decode the raw Pool account bytes. Fails closed on a wrong length or an
    /// uninitialized account.
    pub fn decode(data: &[u8]) -> Result<PoolState> {
        if data.len() < pool_off::MIN_LEN {
            bail!(
                "pool account is {} bytes, expected at least {} (layout drift or not a pool account)",
                data.len(),
                pool_off::MIN_LEN
            );
        }
        if data[pool_off::VERSION] == 0 {
            bail!("pool account is not initialized (version 0)");
        }
        let read_u64 = |off: usize| -> u64 {
            u64::from_le_bytes(data[off..off + 8].try_into().expect("8 bytes in range"))
        };
        let read_u32 = |off: usize| -> u32 {
            u32::from_le_bytes(data[off..off + 4].try_into().expect("4 bytes in range"))
        };
        let read_hash =
            |off: usize| -> Hash32 { data[off..off + 32].try_into().expect("32 bytes in range") };

        let mut frontier = Vec::with_capacity(pool_off::DEPTH);
        for level in 0..pool_off::DEPTH {
            frontier.push(read_hash(pool_off::FRONTIER + level * 32));
        }
        let mut root_ring = Vec::with_capacity(pool_off::ROOT_HISTORY_SIZE);
        for i in 0..pool_off::ROOT_HISTORY_SIZE {
            root_ring.push(read_hash(pool_off::ROOT_RING + i * 32));
        }

        Ok(PoolState {
            epoch_slots: read_u64(pool_off::EPOCH_SLOTS),
            k_floor: read_u32(pool_off::K_FLOOR),
            commitment_count: read_u64(pool_off::COMMITMENT_COUNT),
            current_root: read_hash(pool_off::CURRENT_ROOT),
            authority: Pubkey::new_from_array(read_hash(pool_off::AUTHORITY)),
            entry_fee: read_u64(pool_off::ENTRY_FEE),
            frontier,
            root_ring,
        })
    }

    /// Whether `root` is one of the last `ROOT_HISTORY_SIZE` roots (or the current
    /// root), i.e. a root `SettleZk` would accept.
    pub fn is_known_root(&self, root: &Hash32) -> bool {
        root == &self.current_root || self.root_ring.iter().any(|r| r == root)
    }
}

// ---------------------------------------------------------------------------
// Epoch account layout, byte-identical to the on-chain `state::epoch` module.
// (LE integers; see programs/mirror-pool/src/state/epoch.rs.)
// ---------------------------------------------------------------------------

#[allow(dead_code)]
mod epoch_off {
    pub const VERSION: usize = 0;
    pub const EPOCH_ID: usize = 1;
    pub const NOMINAL_K: usize = 9;
    pub const SETTLED: usize = 13;
    pub const BUMP: usize = 14;
    /// Everything the CLI decodes lives in the prefix ending here; the program
    /// keeps 17 reserved bytes after it, so the decoder accepts any account at
    /// least this long and keeps working as reserved fields are claimed.
    pub const MIN_LEN: usize = BUMP + 1; // 15
}

/// A decoded snapshot of an Epoch account, as read over RPC.
#[derive(Clone, Debug)]
pub struct EpochState {
    pub epoch_id: u64,
    /// The window's raw commit count: every `Commit` AND `CommitDeposit` that
    /// landed in it, of any amount. An UPPER bound on the real anonymity set
    /// (operator and Sybil commits cannot be subtracted on-chain), which is why
    /// the program's own module docs call it `nominal_k`.
    pub nominal_k: u32,
    /// Whether the CROWD half of this window has settled. Decoded to keep this
    /// a faithful mirror of the account (the same reason `epoch_off` keeps every
    /// offset); the ZK path never consults it, since `SettleZk` neither reads
    /// the Epoch account nor is blocked by a settled crowd epoch.
    #[allow(dead_code)]
    pub settled: bool,
}

impl EpochState {
    /// Decode the raw Epoch account bytes. Fails closed on a short account or an
    /// uninitialized one.
    pub fn decode(data: &[u8]) -> Result<EpochState> {
        if data.len() < epoch_off::MIN_LEN {
            bail!(
                "epoch account is {} bytes, expected at least {} (layout drift or not an epoch account)",
                data.len(),
                epoch_off::MIN_LEN
            );
        }
        if data[epoch_off::VERSION] == 0 {
            bail!("epoch account is not initialized (version 0)");
        }
        Ok(EpochState {
            epoch_id: u64::from_le_bytes(
                data[epoch_off::EPOCH_ID..epoch_off::EPOCH_ID + 8]
                    .try_into()
                    .expect("8 bytes in range"),
            ),
            nominal_k: u32::from_le_bytes(
                data[epoch_off::NOMINAL_K..epoch_off::NOMINAL_K + 4]
                    .try_into()
                    .expect("4 bytes in range"),
            ),
            settled: data[epoch_off::SETTLED] != 0,
        })
    }
}

// AssociationSet account layout, byte-identical to the on-chain
// `state::association`. (LE integers; see
// programs/mirror-pool/src/state/association.rs.)
// ---------------------------------------------------------------------------

#[allow(dead_code)]
mod assoc_off {
    pub const VERSION: usize = 0;
    pub const POOL: usize = 1;
    pub const CURATOR: usize = 33;
    pub const BUMP: usize = 65;
    pub const UPDATE_COUNT: usize = 66;
    pub const ROOT_HEAD: usize = 74;
    pub const ROOT_RING: usize = ROOT_HEAD + 4; // 78
    pub const ROOT_HISTORY_SIZE: usize = 8;
    pub const ROOT_RING_LEN: usize = ROOT_HISTORY_SIZE * 32;
    pub const LEN: usize = ROOT_RING + ROOT_RING_LEN; // 334
}

/// A decoded snapshot of an AssociationSet account, as read over RPC.
#[derive(Clone, Debug)]
pub struct AssociationState {
    pub pool: Pubkey,
    pub curator: Pubkey,
    /// Total roots ever published by this curator (monotonic).
    pub update_count: u64,
    /// The recent published-root ring (the last `ROOT_HISTORY_SIZE` roots).
    pub root_ring: Vec<Hash32>,
}

impl AssociationState {
    /// Decode the raw AssociationSet account bytes. Fails closed on a wrong
    /// length or an uninitialized account.
    pub fn decode(data: &[u8]) -> Result<AssociationState> {
        if data.len() != assoc_off::LEN {
            bail!(
                "association account is {} bytes, expected {} (layout drift or not an association set)",
                data.len(),
                assoc_off::LEN
            );
        }
        if data[assoc_off::VERSION] == 0 {
            bail!("association account is not initialized (version 0)");
        }
        let read_hash =
            |off: usize| -> Hash32 { data[off..off + 32].try_into().expect("32 bytes in range") };
        let mut root_ring = Vec::with_capacity(assoc_off::ROOT_HISTORY_SIZE);
        for i in 0..assoc_off::ROOT_HISTORY_SIZE {
            root_ring.push(read_hash(assoc_off::ROOT_RING + i * 32));
        }
        Ok(AssociationState {
            pool: Pubkey::new_from_array(read_hash(assoc_off::POOL)),
            curator: Pubkey::new_from_array(read_hash(assoc_off::CURATOR)),
            update_count: u64::from_le_bytes(
                data[assoc_off::UPDATE_COUNT..assoc_off::UPDATE_COUNT + 8]
                    .try_into()
                    .expect("8 bytes in range"),
            ),
            root_ring,
        })
    }

    /// Whether `root` is one of the last `ROOT_HISTORY_SIZE` published roots,
    /// i.e. a root `SettleZkAssociated` would accept.
    ///
    /// The all-zero sentinel (an unwritten ring slot) is never a match, mirroring
    /// the on-chain `association::is_known_root`: a set that has published nothing
    /// accepts nothing.
    pub fn is_known_root(&self, root: &Hash32) -> bool {
        if root == &[0u8; 32] {
            return false;
        }
        self.root_ring.iter().any(|r| r == root)
    }
}

// ---------------------------------------------------------------------------
// ValuePool account layout, byte-identical to the on-chain `state::value_pool`.
// (LE integers; see programs/mirror-pool/src/state/value_pool.rs.)
// ---------------------------------------------------------------------------

#[allow(dead_code)]
mod value_pool_off {
    pub const DEPTH: usize = crate::tree::DEPTH;
    pub const VERSION: usize = 0;
    pub const AUTHORITY: usize = 1;
    pub const FEE: usize = 33;
    pub const DENOM_FLAG: usize = 41;
    pub const DENOM: usize = 42;
    pub const BUMP: usize = 50;
    pub const VAULT_BUMP: usize = 51;
    pub const COMMITMENT_COUNT: usize = 52;
    pub const CURRENT_ROOT: usize = 60;
    pub const FRONTIER: usize = 92;
    pub const FRONTIER_LEN: usize = DEPTH * 32;
    pub const ROOT_HISTORY_SIZE: usize = 32;
    pub const ROOT_HEAD: usize = FRONTIER + FRONTIER_LEN; // 732
    pub const ROOT_RING: usize = ROOT_HEAD + 4; // 736
    pub const ROOT_RING_LEN: usize = ROOT_HISTORY_SIZE * 32;
    pub const LEN: usize = ROOT_RING + ROOT_RING_LEN; // 1760
}

/// A decoded snapshot of a ValuePool account, as read over RPC.
#[derive(Clone, Debug)]
pub struct ValuePoolState {
    pub authority: Pubkey,
    pub fee: u64,
    pub denomination: Option<u64>,
    pub commitment_count: u64,
    pub current_root: Hash32,
    /// `filled_subtrees`, one 32-byte sibling per level (the frontier).
    pub frontier: Vec<Hash32>,
    /// The recent-root ring buffer (the last `ROOT_HISTORY_SIZE` roots).
    pub root_ring: Vec<Hash32>,
}

impl ValuePoolState {
    /// Decode the raw ValuePool account bytes. Fails closed on a wrong length or an
    /// uninitialized account.
    pub fn decode(data: &[u8]) -> Result<ValuePoolState> {
        if data.len() != value_pool_off::LEN {
            bail!(
                "value pool account is {} bytes, expected {} (layout drift or not a value pool)",
                data.len(),
                value_pool_off::LEN
            );
        }
        if data[value_pool_off::VERSION] == 0 {
            bail!("value pool account is not initialized (version 0)");
        }
        let read_u64 = |off: usize| -> u64 {
            u64::from_le_bytes(data[off..off + 8].try_into().expect("8 bytes in range"))
        };
        let read_hash =
            |off: usize| -> Hash32 { data[off..off + 32].try_into().expect("32 bytes in range") };

        let denomination = if data[value_pool_off::DENOM_FLAG] == 0 {
            None
        } else {
            Some(read_u64(value_pool_off::DENOM))
        };
        let mut frontier = Vec::with_capacity(value_pool_off::DEPTH);
        for level in 0..value_pool_off::DEPTH {
            frontier.push(read_hash(value_pool_off::FRONTIER + level * 32));
        }
        let mut root_ring = Vec::with_capacity(value_pool_off::ROOT_HISTORY_SIZE);
        for i in 0..value_pool_off::ROOT_HISTORY_SIZE {
            root_ring.push(read_hash(value_pool_off::ROOT_RING + i * 32));
        }
        Ok(ValuePoolState {
            authority: Pubkey::new_from_array(read_hash(value_pool_off::AUTHORITY)),
            fee: read_u64(value_pool_off::FEE),
            denomination,
            commitment_count: read_u64(value_pool_off::COMMITMENT_COUNT),
            current_root: read_hash(value_pool_off::CURRENT_ROOT),
            frontier,
            root_ring,
        })
    }

    /// Whether `root` is the current root or one of the last `ROOT_HISTORY_SIZE`
    /// roots (i.e. a root a Transact would accept).
    pub fn is_known_root(&self, root: &Hash32) -> bool {
        root == &self.current_root || self.root_ring.iter().any(|r| r == root)
    }
}

/// A thin blocking RPC wrapper. Pure transport; no keys or ids baked in.
pub struct Chain {
    rpc: RpcClient,
}

impl Chain {
    /// Connect to `rpc_url` (e.g. the local Surfpool mainnet mirror at
    /// `http://127.0.0.1:8899`), confirming at the `confirmed` commitment.
    pub fn new(rpc_url: impl Into<String>) -> Self {
        Self {
            rpc: RpcClient::new_with_commitment(rpc_url.into(), CommitmentConfig::confirmed()),
        }
    }

    /// The current slot.
    pub fn slot(&self) -> Result<u64> {
        self.rpc.get_slot().context("get_slot")
    }

    /// Read and decode a Pool account.
    pub fn pool_state(&self, pool: &Pubkey) -> Result<PoolState> {
        let account = self
            .rpc
            .get_account(pool)
            .with_context(|| format!("reading pool account {pool}"))?;
        PoolState::decode(&account.data)
    }

    /// Read and decode an Epoch account, or `None` when the window has no Epoch
    /// PDA at all (nothing was ever committed into it). `None` is a real answer,
    /// not an error: it means the window's commit count is zero.
    pub fn epoch_state(&self, epoch_pda: &Pubkey) -> Result<Option<EpochState>> {
        let account = self
            .rpc
            .get_account_with_commitment(epoch_pda, self.rpc.commitment())
            .with_context(|| format!("reading epoch account {epoch_pda}"))?
            .value;
        match account {
            None => Ok(None),
            Some(account) if account.data.is_empty() => Ok(None),
            Some(account) => EpochState::decode(&account.data).map(Some),
        }
    }

    /// Read and decode an AssociationSet account (opt-in compliance layer).
    pub fn association_state(&self, assoc: &Pubkey) -> Result<AssociationState> {
        let account = self
            .rpc
            .get_account(assoc)
            .with_context(|| format!("reading association account {assoc}"))?;
        AssociationState::decode(&account.data)
    }

    /// Read and decode a ValuePool account.
    pub fn value_pool_state(&self, vpool: &Pubkey) -> Result<ValuePoolState> {
        let account = self
            .rpc
            .get_account(vpool)
            .with_context(|| format!("reading value pool account {vpool}"))?;
        ValuePoolState::decode(&account.data)
    }

    /// Build, sign, and submit a v0 transaction whose fee payer is the first
    /// signer, returning the confirmed signature string.
    pub fn submit(&self, instructions: &[Instruction], signers: &[&Keypair]) -> Result<String> {
        use solana_message::{v0, VersionedMessage};
        use solana_transaction::versioned::VersionedTransaction;

        let payer = signers
            .first()
            .ok_or_else(|| anyhow!("at least one signer (the fee payer) is required"))?;
        let blockhash = self
            .rpc
            .get_latest_blockhash()
            .context("get_latest_blockhash")?;
        let message = v0::Message::try_compile(&payer.pubkey(), instructions, &[], blockhash)
            .context("compiling v0 message")?;
        let tx = VersionedTransaction::try_new(VersionedMessage::V0(message), signers)
            .context("signing transaction")?;
        let sig = self
            .rpc
            .send_and_confirm_transaction(&tx)
            .context("send_and_confirm_transaction")?;
        Ok(sig.to_string())
    }
}

// ---------------------------------------------------------------------------
// Instruction builders (bodies from mirror_core::wire).
// ---------------------------------------------------------------------------

/// Build the `InitPool` instruction.
///
/// Body: `[epoch_slots(8 LE)][k_floor(4 LE)][entry_fee(8 LE)][reward_bps(2 LE)]`.
/// `reward_bps` is the basis-point share of each entry fee that accrues to the
/// on-chain reward pool (must be `<= 10_000`); the program fixes it forever at
/// init. Accounts (see `instructions::init_pool`): pool(w), authority(signer),
/// payer(signer, w), system_program. `authority` becomes `pool.authority`, so it
/// must sign; `payer` funds the Pool PDA rent.
#[allow(clippy::too_many_arguments)]
pub fn init_pool_ix(
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
    debug_assert_eq!(data.len(), wire::INIT_POOL_LEN);
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

/// Build the `InitAssociation` instruction (opt-in compliance layer).
///
/// Body: none (just the tag). Accounts (see `instructions::init_association`):
/// assoc(w), pool(readonly), curator(signer), payer(signer, w), system_program.
/// The curator signs for itself: registration is permissionless by design, so any
/// number of curators can publish competing sets over the same pool.
pub fn init_association_ix(
    program_id: &Pubkey,
    assoc: &Pubkey,
    pool: &Pubkey,
    curator: &Pubkey,
    payer: &Pubkey,
) -> Instruction {
    let data = vec![wire::tag::INIT_ASSOCIATION];
    debug_assert_eq!(data.len(), wire::INIT_ASSOCIATION_LEN);
    Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(*assoc, false),
            AccountMeta::new_readonly(*pool, false),
            AccountMeta::new_readonly(*curator, true),
            AccountMeta::new(*payer, true),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
        ],
        data,
    }
}

/// Build the `UpdateAssociationRoot` instruction (opt-in compliance layer).
///
/// Body: `[root(32)]`. Accounts (see `instructions::update_association_root`):
/// assoc(w), curator(signer).
pub fn update_association_root_ix(
    program_id: &Pubkey,
    assoc: &Pubkey,
    curator: &Pubkey,
    root: &Hash32,
) -> Instruction {
    let mut data = Vec::with_capacity(wire::UPDATE_ASSOCIATION_ROOT_LEN);
    data.push(wire::tag::UPDATE_ASSOCIATION_ROOT);
    data.extend_from_slice(root);
    debug_assert_eq!(data.len(), wire::UPDATE_ASSOCIATION_ROOT_LEN);
    Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(*assoc, false),
            AccountMeta::new_readonly(*curator, true),
        ],
        data,
    }
}

/// Build the crowd-path `Commit` instruction.
///
/// Accounts (see `instructions::commit`): pool(w), epoch(w), participant(signer,
/// w), system_program, clock sysvar.
pub fn commit_ix(
    program_id: &Pubkey,
    pool: &Pubkey,
    epoch_pda: &Pubkey,
    participant: &Pubkey,
    commitment: &Hash32,
) -> Instruction {
    let mut data = Vec::with_capacity(wire::COMMIT_LEN);
    data.push(wire::tag::COMMIT);
    data.extend_from_slice(commitment);
    debug_assert_eq!(data.len(), wire::COMMIT_LEN);
    Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(*pool, false),
            AccountMeta::new(*epoch_pda, false),
            AccountMeta::new(*participant, true),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
            AccountMeta::new_readonly(CLOCK_SYSVAR_ID, false),
        ],
        data,
    }
}

/// Build the ZK-opt-in `CommitDeposit` instruction (escrow + commit).
///
/// Accounts (see `instructions::commit_deposit`): pool(w), epoch(w),
/// depositor(signer, w), system_program, clock sysvar.
pub fn commit_deposit_ix(
    program_id: &Pubkey,
    pool: &Pubkey,
    epoch_pda: &Pubkey,
    depositor: &Pubkey,
    commitment: &Hash32,
    amount: u64,
) -> Instruction {
    let mut data = Vec::with_capacity(wire::COMMIT_DEPOSIT_LEN);
    data.push(wire::tag::COMMIT_DEPOSIT);
    data.extend_from_slice(commitment);
    data.extend_from_slice(&amount.to_le_bytes());
    debug_assert_eq!(data.len(), wire::COMMIT_DEPOSIT_LEN);
    Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(*pool, false),
            AccountMeta::new(*epoch_pda, false),
            AccountMeta::new(*depositor, true),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
            AccountMeta::new_readonly(CLOCK_SYSVAR_ID, false),
        ],
        data,
    }
}

/// Build the `InitValuePool` instruction (confidential-value layer).
///
/// Body: `[fee(8 LE)][denom_flag(1)][denomination(8 LE)]`. Accounts (see
/// `instructions::init_value_pool`): vpool(w), vault(w), authority(signer),
/// payer(signer, w), system_program. `authority` becomes `vpool.authority` (the
/// Transact relay), so it must sign; `payer` funds both PDAs' rent. `denomination`,
/// when set, is enforced on-chain: every public deposit/withdraw must move exactly
/// that amount, or the Transact is rejected with `DenominationMismatch`.
pub fn init_value_pool_ix(
    program_id: &Pubkey,
    vpool: &Pubkey,
    vault: &Pubkey,
    authority: &Pubkey,
    payer: &Pubkey,
    fee: u64,
    denomination: Option<u64>,
) -> Instruction {
    let mut data = Vec::with_capacity(wire::INIT_VALUE_POOL_LEN);
    data.push(wire::tag::INIT_VALUE_POOL);
    data.extend_from_slice(&fee.to_le_bytes());
    match denomination {
        Some(d) => {
            data.push(1);
            data.extend_from_slice(&d.to_le_bytes());
        }
        None => {
            data.push(0);
            data.extend_from_slice(&0u64.to_le_bytes());
        }
    }
    debug_assert_eq!(data.len(), wire::INIT_VALUE_POOL_LEN);
    Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(*vpool, false),
            AccountMeta::new(*vault, false),
            AccountMeta::new_readonly(*authority, true),
            AccountMeta::new(*payer, true),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
        ],
        data,
    }
}

/// Read a Solana CLI keypair file (a JSON array of 64 bytes) into a `Keypair`.
pub fn read_keypair(path: &std::path::Path) -> Result<Keypair> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading keypair file {}", path.display()))?;
    let bytes: Vec<u8> = serde_json::from_str(&raw).with_context(|| {
        format!(
            "parsing keypair file {} as a JSON byte array",
            path.display()
        )
    })?;
    Keypair::try_from(bytes.as_slice())
        .map_err(|e| anyhow!("invalid keypair in {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_layout_offsets_match_program() {
        // The decoder reads the prefix through the root-history ring; keep the
        // offsets pinned to the program's pool layout.
        assert_eq!(pool_off::MIN_LEN, 1762);
        assert_eq!(pool_off::ROOT_HEAD, 734);
        assert_eq!(pool_off::ROOT_RING, 738);
        // The additive incentive tail (documented; not read by the CLI).
        assert_eq!(pool_off::LEN, 1780);
    }

    #[test]
    fn epoch_layout_offsets_match_program() {
        // Mirrors `programs/mirror-pool/src/state/epoch.rs`.
        assert_eq!(epoch_off::EPOCH_ID, 1);
        assert_eq!(epoch_off::NOMINAL_K, 9);
        assert_eq!(epoch_off::SETTLED, 13);
        assert_eq!(epoch_off::MIN_LEN, 15);
    }

    /// The epoch decoder reads the window's commit count, tolerates the
    /// program's reserved tail, and fails closed on a short or uninitialized
    /// account (a wrong count silently read as 0 would understate, but a wrong
    /// count read as large would OVERSTATE an anonymity set, so this decode is
    /// never allowed to guess).
    #[test]
    fn epoch_state_decodes_and_fails_closed() {
        let mut data = vec![0u8; 32]; // program LEN, including the reserved tail
        data[epoch_off::VERSION] = 1;
        data[epoch_off::EPOCH_ID..epoch_off::EPOCH_ID + 8].copy_from_slice(&7u64.to_le_bytes());
        data[epoch_off::NOMINAL_K..epoch_off::NOMINAL_K + 4].copy_from_slice(&5u32.to_le_bytes());
        data[epoch_off::SETTLED] = 1;
        let state = EpochState::decode(&data).expect("valid epoch account");
        assert_eq!(state.epoch_id, 7);
        assert_eq!(state.nominal_k, 5);
        assert!(state.settled);

        // Uninitialized (version 0) and short accounts are rejected, not guessed.
        let mut zeroed = data.clone();
        zeroed[epoch_off::VERSION] = 0;
        assert!(EpochState::decode(&zeroed).is_err());
        assert!(EpochState::decode(&data[..epoch_off::MIN_LEN - 1]).is_err());
    }

    #[test]
    fn init_pool_ix_layout() {
        let program = Pubkey::new_from_array([9u8; 32]);
        let pool = Pubkey::new_from_array([1u8; 32]);
        let authority = Pubkey::new_from_array([2u8; 32]);
        let payer = Pubkey::new_from_array([3u8; 32]);
        let ix = init_pool_ix(&program, &pool, &authority, &payer, 150, 10, 1_000, 2_500);
        assert_eq!(ix.program_id, program);
        assert_eq!(ix.data.len(), wire::INIT_POOL_LEN);
        assert_eq!(ix.data[0], wire::tag::INIT_POOL);
        assert_eq!(ix.data[1..9], 150u64.to_le_bytes());
        assert_eq!(ix.data[9..13], 10u32.to_le_bytes());
        assert_eq!(ix.data[13..21], 1_000u64.to_le_bytes());
        assert_eq!(ix.data[21..23], 2_500u16.to_le_bytes());
        // pool(w, !s), authority(!w, s), payer(w, s), system(!w, !s).
        assert!(ix.accounts[0].is_writable && !ix.accounts[0].is_signer);
        assert!(!ix.accounts[1].is_writable && ix.accounts[1].is_signer);
        assert!(ix.accounts[2].is_writable && ix.accounts[2].is_signer);
        assert_eq!(ix.accounts[3].pubkey, SYSTEM_PROGRAM_ID);
    }

    #[test]
    fn commit_ix_layout() {
        let program = Pubkey::new_from_array([9u8; 32]);
        let pool = Pubkey::new_from_array([1u8; 32]);
        let epoch = Pubkey::new_from_array([2u8; 32]);
        let participant = Pubkey::new_from_array([3u8; 32]);
        let commitment = [7u8; 32];
        let ix = commit_ix(&program, &pool, &epoch, &participant, &commitment);
        assert_eq!(ix.data.len(), wire::COMMIT_LEN);
        assert_eq!(ix.data[0], wire::tag::COMMIT);
        assert_eq!(ix.data[1..33], commitment);
        assert_eq!(ix.accounts.len(), 5);
        // Only the participant signs; pool + epoch + participant are writable.
        assert!(ix.accounts[2].is_signer && ix.accounts[2].is_writable);
        assert_eq!(ix.accounts.iter().filter(|a| a.is_signer).count(), 1);
        assert_eq!(ix.accounts[4].pubkey, CLOCK_SYSVAR_ID);
    }

    #[test]
    fn commit_deposit_ix_layout() {
        let program = Pubkey::new_from_array([9u8; 32]);
        let pool = Pubkey::new_from_array([1u8; 32]);
        let epoch = Pubkey::new_from_array([2u8; 32]);
        let depositor = Pubkey::new_from_array([3u8; 32]);
        let commitment = [7u8; 32];
        let ix = commit_deposit_ix(
            &program,
            &pool,
            &epoch,
            &depositor,
            &commitment,
            250_000_000,
        );
        assert_eq!(ix.data.len(), wire::COMMIT_DEPOSIT_LEN);
        assert_eq!(ix.data[0], wire::tag::COMMIT_DEPOSIT);
        assert_eq!(ix.data[1..33], commitment);
        assert_eq!(ix.data[33..41], 250_000_000u64.to_le_bytes());
        assert_eq!(ix.accounts.len(), 5);
        assert!(ix.accounts[2].is_signer && ix.accounts[2].is_writable);
    }

    #[test]
    fn pda_derivation_is_deterministic() {
        let program = Pubkey::new_from_array([9u8; 32]);
        let authority = Pubkey::new_from_array([2u8; 32]);
        let pool = pool_pda(&program, &authority);
        assert_eq!(pool, pool_pda(&program, &authority));
        let e0 = epoch_pda(&program, &pool, 0);
        let e1 = epoch_pda(&program, &pool, 1);
        assert_ne!(e0, e1, "distinct epochs yield distinct PDAs");
        let nf = [5u8; 32];
        assert_eq!(
            nullifier_pda(&program, &pool, 7, &nf),
            nullifier_pda(&program, &pool, 7, &nf)
        );
    }

    #[test]
    fn value_pool_layout_offsets_match_program() {
        // Keep the value-pool decoder pinned to the program's state::value_pool.
        assert_eq!(value_pool_off::FRONTIER, 92);
        assert_eq!(value_pool_off::ROOT_HEAD, 732);
        assert_eq!(value_pool_off::ROOT_RING, 736);
        assert_eq!(value_pool_off::LEN, 1760);
    }

    #[test]
    fn init_value_pool_ix_layout() {
        let program = Pubkey::new_from_array([9u8; 32]);
        let authority = Pubkey::new_from_array([2u8; 32]);
        let vpool = value_pool_pda(&program, &authority);
        let vault = value_vault_pda(&program, &vpool);
        let payer = Pubkey::new_from_array([3u8; 32]);
        let ix = init_value_pool_ix(
            &program,
            &vpool,
            &vault,
            &authority,
            &payer,
            5_000,
            Some(1_000),
        );
        assert_eq!(ix.program_id, program);
        assert_eq!(ix.data.len(), wire::INIT_VALUE_POOL_LEN);
        assert_eq!(ix.data[0], wire::tag::INIT_VALUE_POOL);
        assert_eq!(ix.data[1..9], 5_000u64.to_le_bytes());
        assert_eq!(ix.data[9], 1, "denom flag = Some");
        assert_eq!(ix.data[10..18], 1_000u64.to_le_bytes());
        // vpool(w,!s), vault(w,!s), authority(!w,s), payer(w,s), system(!w,!s).
        assert!(ix.accounts[0].is_writable && !ix.accounts[0].is_signer);
        assert!(ix.accounts[1].is_writable && !ix.accounts[1].is_signer);
        assert!(!ix.accounts[2].is_writable && ix.accounts[2].is_signer);
        assert!(ix.accounts[3].is_writable && ix.accounts[3].is_signer);
        assert_eq!(ix.accounts[4].pubkey, SYSTEM_PROGRAM_ID);

        // denom_flag = None encodes flag 0 and a zero denomination.
        let ix_none = init_value_pool_ix(&program, &vpool, &vault, &authority, &payer, 0, None);
        assert_eq!(ix_none.data[9], 0, "denom flag = None");
        assert_eq!(ix_none.data[10..18], 0u64.to_le_bytes());
    }

    #[test]
    fn value_pda_derivation_is_deterministic() {
        let program = Pubkey::new_from_array([9u8; 32]);
        let authority = Pubkey::new_from_array([2u8; 32]);
        let vpool = value_pool_pda(&program, &authority);
        assert_eq!(vpool, value_pool_pda(&program, &authority));
        let vault = value_vault_pda(&program, &vpool);
        assert_eq!(vault, value_vault_pda(&program, &vpool));
        let nf = [5u8; 32];
        assert_eq!(
            value_nullifier_pda(&program, &vpool, &nf),
            value_nullifier_pda(&program, &vpool, &nf)
        );
        // A value nullifier PDA is NOT epoch-scoped; a distinct nullifier differs.
        let nf2 = [6u8; 32];
        assert_ne!(
            value_nullifier_pda(&program, &vpool, &nf),
            value_nullifier_pda(&program, &vpool, &nf2)
        );
    }
}
