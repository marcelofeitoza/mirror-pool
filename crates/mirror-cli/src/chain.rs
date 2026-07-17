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
}
