//! Integration tests for the mirror-pool on-chain program.
//!
//! These load the COMPILED SBF program into mollusk's in-process SVM and drive
//! real instructions, so run `cargo build-sbf` first (the DoD build step). The
//! `.so` is located via `SBF_OUT_DIR`, which each test sets to this crate's
//! `target/deploy` so the tests are runnable regardless of the working
//! directory.
//!
//! Coverage:
//!  - INIT_POOL creates a v1 pool; re-init fails (PoolAlreadyInitialized).
//!  - COMMIT bumps the epoch commit count, the pool commitment count, and the
//!    accumulator root; the entry fee lands in the pool.
//!  - SETTLE_EPOCH fails closed before the window closes (EpochNotClosed), below
//!    the k-floor (BelowKFloor), and for a non-authority signer (Unauthorized).
//!  - Happy path: window closed + count >= k_floor settles, creates the
//!    nullifier PDAs, and marks the epoch settled; a second settle fails
//!    (EpochAlreadySettled) and a duplicate nullifier fails (NullifierSpent).

use std::collections::{HashMap, HashSet};

use mollusk_svm::{
    program::keyed_account_for_system_program,
    result::{Check, InstructionResult},
    Mollusk,
};
use solana_account::Account;
use solana_instruction::{AccountMeta, Instruction};
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;

use mirror_pool::{
    pda::{EPOCH_SEED, NULLIFIER_SEED, POOL_SEED},
    state::{epoch, nullifier, pool},
    wire::tag,
    MirrorPoolError,
};

const SOL: u64 = 1_000_000_000;

/// Map a program error code to the `ProgramError` mollusk compares against.
fn custom(e: MirrorPoolError) -> ProgramError {
    ProgramError::Custom(e as u32)
}

/// A tiny stateful harness: owns the Mollusk instance, a persistent account
/// map, and the slot clock. Resulting accounts are written back after every
/// successful instruction so flows (init -> commit -> settle) compose.
struct Env {
    mollusk: Mollusk,
    program_id: Pubkey,
    system_id: Pubkey,
    clock_id: Pubkey,
    accounts: HashMap<Pubkey, Account>,
}

impl Env {
    fn new() -> Self {
        // Point mollusk at the compiled program regardless of cwd.
        std::env::set_var(
            "SBF_OUT_DIR",
            concat!(env!("CARGO_MANIFEST_DIR"), "/target/deploy"),
        );
        let program_id = Pubkey::new_unique();
        let mollusk = Mollusk::new(&program_id, "mirror_pool");
        let system_id = keyed_account_for_system_program().0;
        let clock_id = mollusk.sysvars.keyed_account_for_clock_sysvar().0;
        Env {
            mollusk,
            program_id,
            system_id,
            clock_id,
            accounts: HashMap::new(),
        }
    }

    fn fund(&mut self, key: Pubkey, lamports: u64) {
        self.accounts
            .insert(key, Account::new(lamports, 0, &self.system_id));
    }

    fn get(&self, key: &Pubkey) -> Account {
        self.accounts.get(key).cloned().unwrap_or_default()
    }

    fn warp(&mut self, slot: u64) {
        self.mollusk.warp_to_slot(slot);
    }

    /// Build the deduplicated `(pubkey, account)` list an instruction needs,
    /// sourcing sysvar/builtin accounts fresh and everything else from the map.
    fn accounts_for(&self, ix: &Instruction) -> Vec<(Pubkey, Account)> {
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for meta in &ix.accounts {
            if !seen.insert(meta.pubkey) {
                continue;
            }
            let account = if meta.pubkey == self.system_id {
                keyed_account_for_system_program().1
            } else if meta.pubkey == self.clock_id {
                self.mollusk.sysvars.keyed_account_for_clock_sysvar().1
            } else {
                self.get(&meta.pubkey)
            };
            out.push((meta.pubkey, account));
        }
        out
    }

    fn process(&mut self, ix: &Instruction, checks: &[Check]) -> InstructionResult {
        let accts = self.accounts_for(ix);
        let result = self
            .mollusk
            .process_and_validate_instruction(ix, &accts, checks);
        for (key, account) in &result.resulting_accounts {
            if *key != self.system_id && *key != self.clock_id {
                self.accounts.insert(*key, account.clone());
            }
        }
        result
    }

    fn pool_pda(&self, authority: &Pubkey) -> Pubkey {
        Pubkey::find_program_address(&[POOL_SEED, authority.as_ref()], &self.program_id).0
    }

    fn epoch_pda(&self, pool: &Pubkey, epoch_id: u64) -> Pubkey {
        Pubkey::find_program_address(
            &[EPOCH_SEED, pool.as_ref(), &epoch_id.to_le_bytes()],
            &self.program_id,
        )
        .0
    }

    fn nf_pda(&self, pool: &Pubkey, epoch_id: u64, nf: &[u8; 32]) -> Pubkey {
        Pubkey::find_program_address(
            &[NULLIFIER_SEED, pool.as_ref(), &epoch_id.to_le_bytes(), nf],
            &self.program_id,
        )
        .0
    }

    fn init_ix(
        &self,
        pool: &Pubkey,
        authority: &Pubkey,
        payer: &Pubkey,
        epoch_slots: u64,
        k_floor: u32,
        entry_fee: u64,
    ) -> Instruction {
        let mut data = Vec::with_capacity(mirror_pool::wire::INIT_POOL_LEN);
        data.push(tag::INIT_POOL);
        data.extend_from_slice(&epoch_slots.to_le_bytes());
        data.extend_from_slice(&k_floor.to_le_bytes());
        data.extend_from_slice(&entry_fee.to_le_bytes());
        Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new(*pool, false),
                AccountMeta::new_readonly(*authority, true),
                AccountMeta::new(*payer, true),
                AccountMeta::new_readonly(self.system_id, false),
            ],
            data,
        }
    }

    fn commit_ix(
        &self,
        pool: &Pubkey,
        epoch_acct: &Pubkey,
        participant: &Pubkey,
        commitment: &[u8; 32],
    ) -> Instruction {
        let mut data = Vec::with_capacity(mirror_pool::wire::COMMIT_LEN);
        data.push(tag::COMMIT);
        data.extend_from_slice(commitment);
        Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new(*pool, false),
                AccountMeta::new(*epoch_acct, false),
                AccountMeta::new(*participant, true),
                AccountMeta::new_readonly(self.system_id, false),
                AccountMeta::new_readonly(self.clock_id, false),
            ],
            data,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn settle_ix(
        &self,
        pool: &Pubkey,
        epoch_acct: &Pubkey,
        authority: &Pubkey,
        nf_pdas: &[Pubkey],
        nullifiers: &[[u8; 32]],
        payer: &Pubkey,
        epoch_id: u64,
    ) -> Instruction {
        let mut data =
            Vec::with_capacity(mirror_pool::wire::SETTLE_HEADER_LEN + nullifiers.len() * 32);
        data.push(tag::SETTLE_EPOCH);
        data.extend_from_slice(&epoch_id.to_le_bytes());
        data.extend_from_slice(&(nullifiers.len() as u32).to_le_bytes());
        for nf in nullifiers {
            data.extend_from_slice(nf);
        }
        let mut accounts = vec![
            AccountMeta::new(*pool, false),
            AccountMeta::new(*epoch_acct, false),
            AccountMeta::new_readonly(*authority, true),
        ];
        for nf in nf_pdas {
            accounts.push(AccountMeta::new(*nf, false));
        }
        accounts.push(AccountMeta::new(*payer, true));
        accounts.push(AccountMeta::new_readonly(self.system_id, false));
        accounts.push(AccountMeta::new_readonly(self.clock_id, false));
        Instruction {
            program_id: self.program_id,
            accounts,
            data,
        }
    }
}

/// Init a pool and return (authority, payer, pool_pda). `payer` is well funded.
fn init_pool(
    env: &mut Env,
    epoch_slots: u64,
    k_floor: u32,
    entry_fee: u64,
) -> (Pubkey, Pubkey, Pubkey) {
    let authority = Pubkey::new_unique();
    let payer = Pubkey::new_unique();
    env.fund(payer, 100 * SOL);
    // The authority is only a signer here; give it a home account.
    env.fund(authority, SOL);
    let pool = env.pool_pda(&authority);

    let ix = env.init_ix(&pool, &authority, &payer, epoch_slots, k_floor, entry_fee);
    env.process(&ix, &[Check::success()]);
    (authority, payer, pool)
}

#[test]
fn init_pool_creates_v1_and_reinit_fails() {
    let mut env = Env::new();
    let (authority, payer, pool) = init_pool(&mut env, 10, 3, 5_000);

    let acct = env.get(&pool);
    assert_eq!(acct.owner, env.program_id, "pool must be program-owned");
    assert_eq!(acct.data.len(), pool::LEN, "pool must be exactly pool::LEN");
    assert_eq!(pool::version(&acct.data).unwrap(), pool::VERSION_V1);
    assert_eq!(pool::epoch_slots(&acct.data).unwrap(), 10);
    assert_eq!(pool::k_floor(&acct.data).unwrap(), 3);
    assert_eq!(pool::entry_fee(&acct.data).unwrap(), 5_000);
    assert_eq!(pool::commitment_count(&acct.data).unwrap(), 0);
    assert_eq!(&pool::authority(&acct.data).unwrap(), authority.as_ref());
    assert_ne!(
        pool::current_root(&acct.data).unwrap(),
        [0u8; 32],
        "empty-tree root is a non-zero keccak chain"
    );

    // Re-initializing the same pool must fail closed.
    let ix = env.init_ix(&pool, &authority, &payer, 10, 3, 5_000);
    env.process(
        &ix,
        &[Check::err(custom(MirrorPoolError::PoolAlreadyInitialized))],
    );
}

#[test]
fn commit_bumps_counts_root_and_collects_fee() {
    let mut env = Env::new();
    let entry_fee = 7_000u64;
    let (_authority, payer, pool) = init_pool(&mut env, 10, 2, entry_fee);

    let pool_lamports_after_init = env.get(&pool).lamports;
    let root0 = pool::current_root(&env.get(&pool).data).unwrap();

    // Commit at slot 3 -> epoch 0.
    env.warp(3);
    let epoch_id = 0u64;
    let epoch_acct = env.epoch_pda(&pool, epoch_id);

    let c1 = [11u8; 32];
    let ix = env.commit_ix(&pool, &epoch_acct, &payer, &c1);
    env.process(&ix, &[Check::success()]);

    let pool_acct = env.get(&pool);
    assert_eq!(pool::commitment_count(&pool_acct.data).unwrap(), 1);
    let root1 = pool::current_root(&pool_acct.data).unwrap();
    assert_ne!(root1, root0, "root must change after the first append");

    let epoch_acct_data = env.get(&epoch_acct);
    assert_eq!(epoch_acct_data.owner, env.program_id);
    assert_eq!(epoch::epoch_id(&epoch_acct_data.data).unwrap(), epoch_id);
    assert_eq!(epoch::commit_count(&epoch_acct_data.data).unwrap(), 1);

    // Second, distinct commit in the same epoch.
    let c2 = [22u8; 32];
    let ix = env.commit_ix(&pool, &epoch_acct, &payer, &c2);
    env.process(&ix, &[Check::success()]);

    let pool_acct = env.get(&pool);
    assert_eq!(pool::commitment_count(&pool_acct.data).unwrap(), 2);
    let root2 = pool::current_root(&pool_acct.data).unwrap();
    assert_ne!(root2, root1, "root must change after the second append");
    assert_eq!(epoch::commit_count(&env.get(&epoch_acct).data).unwrap(), 2);

    // Both entry fees landed in the pool.
    assert_eq!(
        env.get(&pool).lamports,
        pool_lamports_after_init + 2 * entry_fee,
        "entry fees must accumulate in the pool"
    );
}

#[test]
fn settle_before_window_closes_fails() {
    let mut env = Env::new();
    let (authority, payer, pool) = init_pool(&mut env, 10, 2, 0);
    let epoch_id = 0u64;
    let epoch_acct = env.epoch_pda(&pool, epoch_id);

    env.warp(3);
    for c in [[1u8; 32], [2u8; 32]] {
        let ix = env.commit_ix(&pool, &epoch_acct, &payer, &c);
        env.process(&ix, &[Check::success()]);
    }

    // Still inside the window: settle_slot(0) = 10, current slot 5 < 10.
    env.warp(5);
    let nf = [9u8; 32];
    let nf_pda = env.nf_pda(&pool, epoch_id, &nf);
    let ix = env.settle_ix(
        &pool,
        &epoch_acct,
        &authority,
        &[nf_pda],
        &[nf],
        &payer,
        epoch_id,
    );
    env.process(&ix, &[Check::err(custom(MirrorPoolError::EpochNotClosed))]);
}

#[test]
fn settle_below_k_floor_fails() {
    let mut env = Env::new();
    let (authority, payer, pool) = init_pool(&mut env, 10, 3, 0);
    let epoch_id = 0u64;
    let epoch_acct = env.epoch_pda(&pool, epoch_id);

    // Only 2 commits, but k_floor = 3.
    env.warp(3);
    for c in [[1u8; 32], [2u8; 32]] {
        let ix = env.commit_ix(&pool, &epoch_acct, &payer, &c);
        env.process(&ix, &[Check::success()]);
    }

    env.warp(10);
    let nfs = [[9u8; 32], [8u8; 32]];
    let nf_pdas: Vec<Pubkey> = nfs
        .iter()
        .map(|nf| env.nf_pda(&pool, epoch_id, nf))
        .collect();
    let ix = env.settle_ix(
        &pool,
        &epoch_acct,
        &authority,
        &nf_pdas,
        &nfs,
        &payer,
        epoch_id,
    );
    env.process(&ix, &[Check::err(custom(MirrorPoolError::BelowKFloor))]);
}

#[test]
fn settle_by_non_authority_fails() {
    let mut env = Env::new();
    let (_authority, payer, pool) = init_pool(&mut env, 10, 2, 0);
    let epoch_id = 0u64;
    let epoch_acct = env.epoch_pda(&pool, epoch_id);

    env.warp(3);
    for c in [[1u8; 32], [2u8; 32]] {
        let ix = env.commit_ix(&pool, &epoch_acct, &payer, &c);
        env.process(&ix, &[Check::success()]);
    }

    env.warp(10);
    let imposter = Pubkey::new_unique();
    env.fund(imposter, SOL);
    let nf = [9u8; 32];
    let nf_pda = env.nf_pda(&pool, epoch_id, &nf);
    // A different (but validly signing) key must not be able to settle.
    let ix = env.settle_ix(
        &pool,
        &epoch_acct,
        &imposter,
        &[nf_pda],
        &[nf],
        &payer,
        epoch_id,
    );
    env.process(&ix, &[Check::err(custom(MirrorPoolError::Unauthorized))]);
}

#[test]
fn settle_happy_path_then_double_settle_fails() {
    let mut env = Env::new();
    let (authority, payer, pool) = init_pool(&mut env, 10, 2, 0);
    let epoch_id = 0u64;
    let epoch_acct = env.epoch_pda(&pool, epoch_id);

    env.warp(3);
    for c in [[1u8; 32], [2u8; 32]] {
        let ix = env.commit_ix(&pool, &epoch_acct, &payer, &c);
        env.process(&ix, &[Check::success()]);
    }

    // Window closed (>= settle_slot(0) = 10), count (2) >= k_floor (2).
    env.warp(12);
    let nfs = [[9u8; 32], [8u8; 32]];
    let nf_pdas: Vec<Pubkey> = nfs
        .iter()
        .map(|nf| env.nf_pda(&pool, epoch_id, nf))
        .collect();
    let ix = env.settle_ix(
        &pool,
        &epoch_acct,
        &authority,
        &nf_pdas,
        &nfs,
        &payer,
        epoch_id,
    );
    env.process(&ix, &[Check::success()]);

    // Epoch is marked settled and each nullifier PDA now exists (spent).
    assert!(epoch::is_settled(&env.get(&epoch_acct).data).unwrap());
    for nf_pda in &nf_pdas {
        let acct = env.get(nf_pda);
        assert_eq!(acct.owner, env.program_id, "nullifier PDA must be created");
        assert_eq!(acct.data.len(), nullifier::LEN);
        assert_eq!(acct.data[0], nullifier::SPENT);
    }

    // Settling the same epoch again must fail closed.
    let ix = env.settle_ix(
        &pool,
        &epoch_acct,
        &authority,
        &nf_pdas,
        &nfs,
        &payer,
        epoch_id,
    );
    env.process(
        &ix,
        &[Check::err(custom(MirrorPoolError::EpochAlreadySettled))],
    );
}

#[test]
fn settle_duplicate_nullifier_fails() {
    let mut env = Env::new();
    let (authority, payer, pool) = init_pool(&mut env, 10, 2, 0);
    let epoch_id = 0u64;
    let epoch_acct = env.epoch_pda(&pool, epoch_id);

    env.warp(3);
    for c in [[1u8; 32], [2u8; 32]] {
        let ix = env.commit_ix(&pool, &epoch_acct, &payer, &c);
        env.process(&ix, &[Check::success()]);
    }

    env.warp(10);
    // The same nullifier appears twice in one settle: the second create sees an
    // already-spent (program-owned) PDA.
    let nf = [9u8; 32];
    let nf_pda = env.nf_pda(&pool, epoch_id, &nf);
    let ix = env.settle_ix(
        &pool,
        &epoch_acct,
        &authority,
        &[nf_pda, nf_pda],
        &[nf, nf],
        &payer,
        epoch_id,
    );
    env.process(&ix, &[Check::err(custom(MirrorPoolError::NullifierSpent))]);
}
