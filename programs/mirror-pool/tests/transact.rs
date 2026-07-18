//! Integration tests for the confidential-value layer (InitValuePool + Transact).
//!
//! These load the COMPILED SBF program into mollusk's in-process SVM and drive
//! real instructions, so run `cargo build-sbf` first. Coverage:
//!  - INIT_VALUE_POOL creates a v1 ValuePool + vault; re-init fails.
//!  - Transact with the committed TRANSFER fixture verifies on-chain, creates
//!    both input-nullifier PDAs, inserts both output commitments (root changes),
//!    and binds extDataHash. This is the decisive on-chain proof-verify path.
//!  - Mutating a public input rejects the proof with no state change.
//!  - Replaying a nullifier fails NullifierSpent.
//!  - The SHIELD fixture (publicAmount = +10) credits the vault; the UNSHIELD
//!    fixture (publicAmount = r - 7) credits the recipient and debits the vault.
//!
//! The SHIELD/UNSHIELD proofs are converted offline into the groth16-solana byte
//! layout by scratchpad `gen_tx_consts.js`, which is validated by reproducing the
//! committed TRANSFER `transaction_proof_fixture.rs` byte-for-byte.

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
    pda::{VALUE_NULLIFIER_SEED, VALUE_POOL_SEED, VALUE_VAULT_SEED},
    state::{nullifier, value_pool},
    wire::tag,
    MirrorPoolError,
};

const SOL: u64 = 1_000_000_000;

/// Committed, known-good TRANSFER JoinSplit proof + public inputs (groth16-solana
/// byte layout). PUBLIC_INPUTS order:
/// [root, publicAmount, extDataHash, inNf0, inNf1, outC0, outC1].
mod transfer {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../circuits/artifacts/transaction_proof_fixture.rs"
    ));
}

/// SHIELD + UNSHIELD proofs (generated offline, validated against the committed
/// TRANSFER fixture). Same PUBLIC_INPUTS order as `transfer`.
mod extra {
    include!("fixtures/transaction_extra.rs");
}

/// Map a program error code to the `ProgramError` mollusk compares against.
fn custom(e: MirrorPoolError) -> ProgramError {
    ProgramError::Custom(e as u32)
}

/// The fixed 32-byte recipient bound into every fixture's ext-data: bytes
/// 0x01..0x20 (matches `gen_transaction_fixture.js`).
fn fixture_recipient() -> Pubkey {
    let mut b = [0u8; 32];
    for (i, x) in b.iter_mut().enumerate() {
        *x = (i + 1) as u8;
    }
    Pubkey::new_from_array(b)
}

/// The fixed 32-byte relayer bound into every fixture's ext-data: bytes
/// 0x20..0x01. The on-chain Transact uses the AUTHORITY account as the relayer in
/// the extDataHash preimage, so the ValuePool authority must be this key.
fn fixture_relayer_authority() -> Pubkey {
    let mut b = [0u8; 32];
    for (i, x) in b.iter_mut().enumerate() {
        *x = (0x20 - i) as u8;
    }
    Pubkey::new_from_array(b)
}

/// The deterministic encrypted-note payload (48 bytes), byte-identical to
/// `gen_transaction_fixture.js`'s `payload(seed)`.
fn payload(seed: u64) -> Vec<u8> {
    (0..48u64)
        .map(|i| ((seed * 131 + i * 17) & 0xff) as u8)
        .collect()
}

/// The circuit's canonical empty-tree root, computed on the host with
/// `light-poseidon` (the same Poseidon the on-chain `sol_poseidon` is built on).
fn circuit_empty_root() -> [u8; 32] {
    use ark_bn254::Fr;
    use ark_ff::{BigInteger, PrimeField};
    use light_poseidon::{Poseidon, PoseidonHasher};

    let mut z = Fr::from(0u64);
    for _ in 0..mirror_pool::state::merkle::DEPTH {
        let mut h = Poseidon::<Fr>::new_circom(2).unwrap();
        z = h.hash(&[z, z]).unwrap();
    }
    let be = z.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - be.len()..].copy_from_slice(&be);
    out
}

/// A tiny stateful harness (mirrors `integration.rs`'s `Env`).
struct Env {
    mollusk: Mollusk,
    program_id: Pubkey,
    system_id: Pubkey,
    clock_id: Pubkey,
    accounts: HashMap<Pubkey, Account>,
}

impl Env {
    fn new() -> Self {
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

    fn vpool_pda(&self, authority: &Pubkey) -> Pubkey {
        Pubkey::find_program_address(&[VALUE_POOL_SEED, authority.as_ref()], &self.program_id).0
    }

    fn vault_pda(&self, vpool: &Pubkey) -> Pubkey {
        Pubkey::find_program_address(&[VALUE_VAULT_SEED, vpool.as_ref()], &self.program_id).0
    }

    fn vnf_pda(&self, vpool: &Pubkey, nf: &[u8; 32]) -> Pubkey {
        Pubkey::find_program_address(
            &[VALUE_NULLIFIER_SEED, vpool.as_ref(), nf],
            &self.program_id,
        )
        .0
    }

    fn init_value_pool_ix(
        &self,
        vpool: &Pubkey,
        vault: &Pubkey,
        authority: &Pubkey,
        payer: &Pubkey,
        fee: u64,
        denom: Option<u64>,
    ) -> Instruction {
        let mut data = Vec::with_capacity(mirror_pool::wire::INIT_VALUE_POOL_LEN);
        data.push(tag::INIT_VALUE_POOL);
        data.extend_from_slice(&fee.to_le_bytes());
        match denom {
            Some(d) => {
                data.push(1);
                data.extend_from_slice(&d.to_le_bytes());
            }
            None => {
                data.push(0);
                data.extend_from_slice(&0u64.to_le_bytes());
            }
        }
        Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new(*vpool, false),
                AccountMeta::new(*vault, false),
                AccountMeta::new_readonly(*authority, true),
                AccountMeta::new(*payer, true),
                AccountMeta::new_readonly(self.system_id, false),
            ],
            data,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn transact_ix(
        &self,
        vpool: &Pubkey,
        authority: &Pubkey,
        nf0: &Pubkey,
        nf1: &Pubkey,
        recipient: &Pubkey,
        depositor: &Pubkey,
        vault: &Pubkey,
        public_inputs: &[[u8; 32]; 7],
        proof_a: &[u8; 64],
        proof_b: &[u8; 128],
        proof_c: &[u8; 64],
        fee: u64,
        enc0: &[u8],
        enc1: &[u8],
    ) -> Instruction {
        // public_inputs order: [root, publicAmount, extDataHash, inNf0, inNf1, outC0, outC1].
        // Wire header order:    [publicAmount, extDataHash, root, inNf0, inNf1, outC0, outC1].
        let mut data = Vec::with_capacity(mirror_pool::wire::TRANSACT_HEADER_LEN + 4 + 96);
        data.push(tag::TRANSACT);
        data.extend_from_slice(&public_inputs[1]); // publicAmount
        data.extend_from_slice(&public_inputs[2]); // extDataHash
        data.extend_from_slice(&public_inputs[0]); // root
        data.extend_from_slice(&public_inputs[3]); // inNf0
        data.extend_from_slice(&public_inputs[4]); // inNf1
        data.extend_from_slice(&public_inputs[5]); // outC0
        data.extend_from_slice(&public_inputs[6]); // outC1
        data.extend_from_slice(proof_a);
        data.extend_from_slice(proof_b);
        data.extend_from_slice(proof_c);
        data.extend_from_slice(&fee.to_le_bytes());
        data.extend_from_slice(&(enc0.len() as u16).to_le_bytes());
        data.extend_from_slice(enc0);
        data.extend_from_slice(&(enc1.len() as u16).to_le_bytes());
        data.extend_from_slice(enc1);
        Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new(*vpool, false),
                AccountMeta::new(*authority, true),
                AccountMeta::new(*nf0, false),
                AccountMeta::new(*nf1, false),
                AccountMeta::new(*recipient, false),
                AccountMeta::new(*depositor, true),
                AccountMeta::new_readonly(self.system_id, false),
                AccountMeta::new_readonly(self.clock_id, false),
                AccountMeta::new(*vault, false),
            ],
            data,
        }
    }
}

/// Build a program-owned, initialized ValuePool directly (bypassing the frontier
/// build-up) whose recent-root ring already contains `root_snapshot`, plus a
/// program-owned vault funded with `vault_lamports`. The fixtures' trees cannot
/// be reproduced by a live deposit sequence, so the test injects the snapshot,
/// exactly as `integration.rs`'s `build_zk_pool` does for the behavioral pool.
fn build_value_pool(
    env: &mut Env,
    authority: &Pubkey,
    fee: u64,
    denom: Option<u64>,
    root_snapshot: &[u8; 32],
    vault_lamports: u64,
) -> (Pubkey, Pubkey) {
    let vpool = env.vpool_pda(authority);
    let (_, bump) =
        Pubkey::find_program_address(&[VALUE_POOL_SEED, authority.as_ref()], &env.program_id);
    let vault = env.vault_pda(&vpool);
    let (_, vault_bump) =
        Pubkey::find_program_address(&[VALUE_VAULT_SEED, vpool.as_ref()], &env.program_id);

    let empty_root = circuit_empty_root();
    let mut data = vec![0u8; value_pool::LEN];
    value_pool::init(
        &mut data,
        &authority.to_bytes(),
        fee,
        denom,
        bump,
        vault_bump,
        &empty_root,
    )
    .unwrap();
    value_pool::record_root_history(&mut data, root_snapshot).unwrap();
    assert!(
        value_pool::is_known_root(&data, root_snapshot).unwrap(),
        "injected root must be a known recent root"
    );

    let mut vpool_account = Account::new(10 * SOL, value_pool::LEN, &env.program_id);
    vpool_account.data = data;
    env.accounts.insert(vpool, vpool_account);

    // Program-owned, zero-data vault holding the commingled lamports.
    let vault_account = Account::new(vault_lamports, 0, &env.program_id);
    env.accounts.insert(vault, vault_account);

    (vpool, vault)
}

#[test]
fn init_value_pool_creates_v1_and_reinit_fails() {
    let mut env = Env::new();
    let authority = Pubkey::new_unique();
    let payer = Pubkey::new_unique();
    env.fund(payer, 100 * SOL);
    env.fund(authority, SOL);
    let vpool = env.vpool_pda(&authority);
    let vault = env.vault_pda(&vpool);

    let ix = env.init_value_pool_ix(&vpool, &vault, &authority, &payer, 5_000, None);
    env.process(&ix, &[Check::success()]);

    let vp = env.get(&vpool);
    assert_eq!(vp.owner, env.program_id, "vpool must be program-owned");
    assert_eq!(vp.data.len(), value_pool::LEN);
    assert_eq!(
        value_pool::version(&vp.data).unwrap(),
        value_pool::VERSION_V1
    );
    assert_eq!(
        &value_pool::authority(&vp.data).unwrap(),
        authority.as_ref()
    );
    assert_eq!(value_pool::fee(&vp.data).unwrap(), 5_000);
    assert_eq!(value_pool::denomination(&vp.data).unwrap(), None);
    assert_eq!(value_pool::commitment_count(&vp.data).unwrap(), 0);
    assert_ne!(
        value_pool::current_root(&vp.data).unwrap(),
        [0u8; 32],
        "empty-tree root is a non-zero Poseidon zero ladder"
    );
    assert_eq!(
        value_pool::current_root(&vp.data).unwrap(),
        circuit_empty_root(),
        "on-chain value-pool empty root must equal the circuit's zero ladder"
    );

    let va = env.get(&vault);
    assert_eq!(va.owner, env.program_id, "vault must be program-owned");
    assert_eq!(va.data.len(), 0, "vault holds lamports, not data");
    assert!(va.lamports > 0, "vault must be rent-exempt");

    // Re-init must fail closed.
    let ix = env.init_value_pool_ix(&vpool, &vault, &authority, &payer, 5_000, None);
    env.process(
        &ix,
        &[Check::err(custom(
            MirrorPoolError::ValuePoolAlreadyInitialized,
        ))],
    );
}

#[test]
fn init_value_pool_stores_denomination() {
    let mut env = Env::new();
    let authority = Pubkey::new_unique();
    let payer = Pubkey::new_unique();
    env.fund(payer, 100 * SOL);
    env.fund(authority, SOL);
    let vpool = env.vpool_pda(&authority);
    let vault = env.vault_pda(&vpool);

    // denomination is stored (RESERVED) but not enforced yet.
    let ix = env.init_value_pool_ix(&vpool, &vault, &authority, &payer, 0, Some(1_000_000));
    env.process(&ix, &[Check::success()]);
    assert_eq!(
        value_pool::denomination(&env.get(&vpool).data).unwrap(),
        Some(1_000_000)
    );
}

#[test]
fn transact_transfer_verifies_and_inserts_commitments() {
    let mut env = Env::new();
    let authority = fixture_relayer_authority();
    env.fund(authority, 5 * SOL); // pays the two nullifier PDAs' rent
    let (vpool, vault) = build_value_pool(
        &mut env,
        &authority,
        0,
        None,
        &transfer::PUBLIC_INPUTS[0],
        5 * SOL,
    );
    let vault_start = env.get(&vault).lamports;

    let recipient = fixture_recipient();
    env.fund(recipient, 0);
    let depositor = Pubkey::new_unique();
    env.fund(depositor, SOL);

    let nf0 = env.vnf_pda(&vpool, &transfer::PUBLIC_INPUTS[3]);
    let nf1 = env.vnf_pda(&vpool, &transfer::PUBLIC_INPUTS[4]);
    let root0 = value_pool::current_root(&env.get(&vpool).data).unwrap();

    let ix = env.transact_ix(
        &vpool,
        &authority,
        &nf0,
        &nf1,
        &recipient,
        &depositor,
        &vault,
        &transfer::PUBLIC_INPUTS,
        &transfer::PROOF_A,
        &transfer::PROOF_B,
        &transfer::PROOF_C,
        0,
        &payload(3),
        &payload(4),
    );
    // DECISIVE: the committed TRANSFER proof verifies on-chain and settles.
    env.process(&ix, &[Check::success()]);

    // Both input-nullifier PDAs created (spent).
    for nf_pda in [&nf0, &nf1] {
        let acct = env.get(nf_pda);
        assert_eq!(acct.owner, env.program_id, "nullifier PDA must be created");
        assert_eq!(acct.data.len(), nullifier::LEN);
        assert_eq!(acct.data[0], nullifier::SPENT);
    }

    // Both output commitments inserted -> count == 2 and the root moved.
    let vp = env.get(&vpool);
    assert_eq!(
        value_pool::commitment_count(&vp.data).unwrap(),
        2,
        "both output commitments must be appended"
    );
    let root1 = value_pool::current_root(&vp.data).unwrap();
    assert_ne!(root1, root0, "root must change after inserting outputs");
    assert!(
        value_pool::is_known_root(&vp.data, &root1).unwrap(),
        "the new root must be in the recent-root ring"
    );

    // A pure transfer moves no lamports.
    assert_eq!(env.get(&recipient).lamports, 0, "transfer credits no one");
    assert_eq!(env.get(&vault).lamports, vault_start, "vault untouched");
}

#[test]
fn transact_rejects_mutated_public_input() {
    let mut env = Env::new();
    let authority = fixture_relayer_authority();
    env.fund(authority, 5 * SOL);
    let (vpool, vault) = build_value_pool(
        &mut env,
        &authority,
        0,
        None,
        &transfer::PUBLIC_INPUTS[0],
        5 * SOL,
    );
    let vault_start = env.get(&vault).lamports;
    let recipient = fixture_recipient();
    env.fund(recipient, 0);
    let depositor = Pubkey::new_unique();
    env.fund(depositor, SOL);

    // Flip one byte of outputCommitment[0]; extDataHash/root/nullifiers are
    // unaffected, so the flow reaches proof verification and fails there.
    let mut mutated = transfer::PUBLIC_INPUTS;
    mutated[5][31] ^= 0x01;

    let nf0 = env.vnf_pda(&vpool, &mutated[3]);
    let nf1 = env.vnf_pda(&vpool, &mutated[4]);
    let ix = env.transact_ix(
        &vpool,
        &authority,
        &nf0,
        &nf1,
        &recipient,
        &depositor,
        &vault,
        &mutated,
        &transfer::PROOF_A,
        &transfer::PROOF_B,
        &transfer::PROOF_C,
        0,
        &payload(3),
        &payload(4),
    );
    env.process(
        &ix,
        &[Check::err(custom(MirrorPoolError::ProofVerificationFailed))],
    );

    // Fail-closed: no nullifier PDA, no commitments inserted, no lamports moved.
    assert_eq!(
        env.get(&nf0).owner,
        Pubkey::default(),
        "no nullifier PDA on a rejected proof"
    );
    let vp = env.get(&vpool);
    assert_eq!(value_pool::commitment_count(&vp.data).unwrap(), 0);
    assert_eq!(env.get(&vault).lamports, vault_start);
    assert_eq!(env.get(&recipient).lamports, 0);
}

#[test]
fn transact_replay_fails_nullifier_spent() {
    let mut env = Env::new();
    let authority = fixture_relayer_authority();
    env.fund(authority, 5 * SOL);
    let (vpool, vault) = build_value_pool(
        &mut env,
        &authority,
        0,
        None,
        &transfer::PUBLIC_INPUTS[0],
        5 * SOL,
    );
    let recipient = fixture_recipient();
    env.fund(recipient, 0);
    let depositor = Pubkey::new_unique();
    env.fund(depositor, SOL);

    let nf0 = env.vnf_pda(&vpool, &transfer::PUBLIC_INPUTS[3]);
    let nf1 = env.vnf_pda(&vpool, &transfer::PUBLIC_INPUTS[4]);
    let ix = env.transact_ix(
        &vpool,
        &authority,
        &nf0,
        &nf1,
        &recipient,
        &depositor,
        &vault,
        &transfer::PUBLIC_INPUTS,
        &transfer::PROOF_A,
        &transfer::PROOF_B,
        &transfer::PROOF_C,
        0,
        &payload(3),
        &payload(4),
    );
    env.process(&ix, &[Check::success()]);

    // Re-submitting the same nullifiers fails closed: the PDA already exists.
    let ix2 = env.transact_ix(
        &vpool,
        &authority,
        &nf0,
        &nf1,
        &recipient,
        &depositor,
        &vault,
        &transfer::PUBLIC_INPUTS,
        &transfer::PROOF_A,
        &transfer::PROOF_B,
        &transfer::PROOF_C,
        0,
        &payload(3),
        &payload(4),
    );
    env.process(&ix2, &[Check::err(custom(MirrorPoolError::NullifierSpent))]);
}

#[test]
fn transact_wrong_ext_data_fails() {
    let mut env = Env::new();
    let authority = fixture_relayer_authority();
    env.fund(authority, 5 * SOL);
    let (vpool, vault) = build_value_pool(
        &mut env,
        &authority,
        0,
        None,
        &transfer::PUBLIC_INPUTS[0],
        5 * SOL,
    );
    let recipient = fixture_recipient();
    env.fund(recipient, 0);
    let depositor = Pubkey::new_unique();
    env.fund(depositor, SOL);

    let nf0 = env.vnf_pda(&vpool, &transfer::PUBLIC_INPUTS[3]);
    let nf1 = env.vnf_pda(&vpool, &transfer::PUBLIC_INPUTS[4]);
    // Tamper with an encrypted payload: the recomputed extDataHash no longer
    // matches the proof's, so it is rejected before proof verification.
    let ix = env.transact_ix(
        &vpool,
        &authority,
        &nf0,
        &nf1,
        &recipient,
        &depositor,
        &vault,
        &transfer::PUBLIC_INPUTS,
        &transfer::PROOF_A,
        &transfer::PROOF_B,
        &transfer::PROOF_C,
        0,
        &payload(99), // wrong enc0
        &payload(4),
    );
    env.process(&ix, &[Check::err(custom(MirrorPoolError::ExtDataMismatch))]);
    assert_eq!(env.get(&nf0).owner, Pubkey::default(), "no state change");
}

#[test]
fn transact_unknown_root_fails() {
    let mut env = Env::new();
    let authority = fixture_relayer_authority();
    env.fund(authority, 5 * SOL);
    // Inject only the empty root, NOT the TRANSFER root.
    let empty = circuit_empty_root();
    let (vpool, vault) = build_value_pool(&mut env, &authority, 0, None, &empty, 5 * SOL);
    let recipient = fixture_recipient();
    env.fund(recipient, 0);
    let depositor = Pubkey::new_unique();
    env.fund(depositor, SOL);

    let nf0 = env.vnf_pda(&vpool, &transfer::PUBLIC_INPUTS[3]);
    let nf1 = env.vnf_pda(&vpool, &transfer::PUBLIC_INPUTS[4]);
    let ix = env.transact_ix(
        &vpool,
        &authority,
        &nf0,
        &nf1,
        &recipient,
        &depositor,
        &vault,
        &transfer::PUBLIC_INPUTS,
        &transfer::PROOF_A,
        &transfer::PROOF_B,
        &transfer::PROOF_C,
        0,
        &payload(3),
        &payload(4),
    );
    env.process(&ix, &[Check::err(custom(MirrorPoolError::RootNotKnown))]);
}

#[test]
fn transact_by_non_authority_fails() {
    let mut env = Env::new();
    let authority = fixture_relayer_authority();
    env.fund(authority, 5 * SOL);
    let (vpool, vault) = build_value_pool(
        &mut env,
        &authority,
        0,
        None,
        &transfer::PUBLIC_INPUTS[0],
        5 * SOL,
    );
    let recipient = fixture_recipient();
    env.fund(recipient, 0);
    let depositor = Pubkey::new_unique();
    env.fund(depositor, SOL);
    let imposter = Pubkey::new_unique();
    env.fund(imposter, 5 * SOL);

    let nf0 = env.vnf_pda(&vpool, &transfer::PUBLIC_INPUTS[3]);
    let nf1 = env.vnf_pda(&vpool, &transfer::PUBLIC_INPUTS[4]);
    // A validly-signing but wrong key must not be able to settle.
    let ix = env.transact_ix(
        &vpool,
        &imposter,
        &nf0,
        &nf1,
        &recipient,
        &depositor,
        &vault,
        &transfer::PUBLIC_INPUTS,
        &transfer::PROOF_A,
        &transfer::PROOF_B,
        &transfer::PROOF_C,
        0,
        &payload(3),
        &payload(4),
    );
    env.process(&ix, &[Check::err(custom(MirrorPoolError::Unauthorized))]);
}

#[test]
fn transact_shield_credits_vault() {
    let mut env = Env::new();
    let authority = fixture_relayer_authority();
    env.fund(authority, 5 * SOL);
    // SHIELD's root is the empty-tree root (dummy inputs are unchecked).
    let (vpool, vault) = build_value_pool(
        &mut env,
        &authority,
        0,
        None,
        &extra::SHIELD_PUBLIC_INPUTS[0],
        SOL,
    );
    let vault_start = env.get(&vault).lamports;

    let recipient = fixture_recipient();
    env.fund(recipient, 0);
    let depositor = Pubkey::new_unique();
    env.fund(depositor, SOL);
    let depositor_start = env.get(&depositor).lamports;

    let nf0 = env.vnf_pda(&vpool, &extra::SHIELD_PUBLIC_INPUTS[3]);
    let nf1 = env.vnf_pda(&vpool, &extra::SHIELD_PUBLIC_INPUTS[4]);
    let ix = env.transact_ix(
        &vpool,
        &authority,
        &nf0,
        &nf1,
        &recipient,
        &depositor,
        &vault,
        &extra::SHIELD_PUBLIC_INPUTS,
        &extra::SHIELD_PROOF_A,
        &extra::SHIELD_PROOF_B,
        &extra::SHIELD_PROOF_C,
        0,
        &payload(1),
        &payload(2),
    );
    env.process(&ix, &[Check::success()]);

    // publicAmount = +10: the vault is credited by 10 and the depositor debited.
    assert_eq!(
        env.get(&vault).lamports,
        vault_start + 10,
        "vault must be credited by the deposit magnitude"
    );
    assert_eq!(env.get(&depositor).lamports, depositor_start - 10);
    assert_eq!(
        value_pool::commitment_count(&env.get(&vpool).data).unwrap(),
        2
    );
}

#[test]
fn transact_unshield_credits_recipient() {
    let mut env = Env::new();
    let authority = fixture_relayer_authority();
    env.fund(authority, 5 * SOL);
    let (vpool, vault) = build_value_pool(
        &mut env,
        &authority,
        0,
        None,
        &extra::UNSHIELD_PUBLIC_INPUTS[0],
        SOL,
    );
    let vault_start = env.get(&vault).lamports;

    let recipient = fixture_recipient();
    env.fund(recipient, 0);
    let depositor = Pubkey::new_unique();
    env.fund(depositor, SOL);

    let nf0 = env.vnf_pda(&vpool, &extra::UNSHIELD_PUBLIC_INPUTS[3]);
    let nf1 = env.vnf_pda(&vpool, &extra::UNSHIELD_PUBLIC_INPUTS[4]);
    let ix = env.transact_ix(
        &vpool,
        &authority,
        &nf0,
        &nf1,
        &recipient,
        &depositor,
        &vault,
        &extra::UNSHIELD_PUBLIC_INPUTS,
        &extra::UNSHIELD_PROOF_A,
        &extra::UNSHIELD_PROOF_B,
        &extra::UNSHIELD_PROOF_C,
        0,
        &payload(5),
        &payload(6),
    );
    env.process(&ix, &[Check::success()]);

    // publicAmount = r - 7: the recipient is credited by 7 and the vault debited.
    assert_eq!(
        env.get(&recipient).lamports,
        7,
        "recipient must be credited the withdraw magnitude"
    );
    assert_eq!(env.get(&vault).lamports, vault_start - 7);
    assert_eq!(
        value_pool::commitment_count(&env.get(&vpool).data).unwrap(),
        2
    );
}

// --- Fixed-denomination mode (Level 1 amount privacy) ---------------------------
//
// A ValuePool with `denomination = Some(d)` accepts a PUBLIC deposit/withdraw only
// when its magnitude equals `d`, giving amount k-anonymity (every public value
// crossing is byte-identical). Internal transfers (publicAmount == 0) are exempt.
// The SHIELD fixture deposits 10 and the UNSHIELD fixture withdraws 7, so those are
// the "matching" denominations; any other `d` yields DenominationMismatch. The
// denomination check runs BEFORE proof verification (and before any nullifier PDA
// is created), so a mismatch is rejected cheaply and fail-closed with no state
// change.

#[test]
fn transact_fixed_denom_accepts_matching_shield() {
    let mut env = Env::new();
    let authority = fixture_relayer_authority();
    env.fund(authority, 5 * SOL);
    // Denomination equals the SHIELD fixture's deposit magnitude (10).
    let (vpool, vault) = build_value_pool(
        &mut env,
        &authority,
        0,
        Some(10),
        &extra::SHIELD_PUBLIC_INPUTS[0],
        SOL,
    );
    let vault_start = env.get(&vault).lamports;

    let recipient = fixture_recipient();
    env.fund(recipient, 0);
    let depositor = Pubkey::new_unique();
    env.fund(depositor, SOL);
    let depositor_start = env.get(&depositor).lamports;

    let nf0 = env.vnf_pda(&vpool, &extra::SHIELD_PUBLIC_INPUTS[3]);
    let nf1 = env.vnf_pda(&vpool, &extra::SHIELD_PUBLIC_INPUTS[4]);
    let ix = env.transact_ix(
        &vpool,
        &authority,
        &nf0,
        &nf1,
        &recipient,
        &depositor,
        &vault,
        &extra::SHIELD_PUBLIC_INPUTS,
        &extra::SHIELD_PROOF_A,
        &extra::SHIELD_PROOF_B,
        &extra::SHIELD_PROOF_C,
        0,
        &payload(1),
        &payload(2),
    );
    // A shield of exactly D verifies on-chain and credits the vault.
    env.process(&ix, &[Check::success()]);
    assert_eq!(env.get(&vault).lamports, vault_start + 10);
    assert_eq!(env.get(&depositor).lamports, depositor_start - 10);
    assert_eq!(
        value_pool::commitment_count(&env.get(&vpool).data).unwrap(),
        2
    );
}

#[test]
fn transact_fixed_denom_rejects_mismatched_shield() {
    let mut env = Env::new();
    let authority = fixture_relayer_authority();
    env.fund(authority, 5 * SOL);
    // Pool pins D = 11 but the SHIELD fixture deposits 10 (a shield of D+1 relative
    // to the fixture): the amounts differ, so it is rejected.
    let (vpool, vault) = build_value_pool(
        &mut env,
        &authority,
        0,
        Some(11),
        &extra::SHIELD_PUBLIC_INPUTS[0],
        SOL,
    );
    let vault_start = env.get(&vault).lamports;

    let recipient = fixture_recipient();
    env.fund(recipient, 0);
    let depositor = Pubkey::new_unique();
    env.fund(depositor, SOL);
    let depositor_start = env.get(&depositor).lamports;

    let nf0 = env.vnf_pda(&vpool, &extra::SHIELD_PUBLIC_INPUTS[3]);
    let nf1 = env.vnf_pda(&vpool, &extra::SHIELD_PUBLIC_INPUTS[4]);
    let ix = env.transact_ix(
        &vpool,
        &authority,
        &nf0,
        &nf1,
        &recipient,
        &depositor,
        &vault,
        &extra::SHIELD_PUBLIC_INPUTS,
        &extra::SHIELD_PROOF_A,
        &extra::SHIELD_PROOF_B,
        &extra::SHIELD_PROOF_C,
        0,
        &payload(1),
        &payload(2),
    );
    env.process(
        &ix,
        &[Check::err(custom(MirrorPoolError::DenominationMismatch))],
    );
    // Fail-closed: rejected before proof verify, so no nullifier PDA, no
    // commitments, and no lamports moved.
    assert_eq!(
        env.get(&nf0).owner,
        Pubkey::default(),
        "no nullifier PDA on a denomination mismatch"
    );
    assert_eq!(
        value_pool::commitment_count(&env.get(&vpool).data).unwrap(),
        0
    );
    assert_eq!(env.get(&vault).lamports, vault_start, "vault untouched");
    assert_eq!(env.get(&depositor).lamports, depositor_start);
}

#[test]
fn transact_fixed_denom_accepts_matching_unshield() {
    let mut env = Env::new();
    let authority = fixture_relayer_authority();
    env.fund(authority, 5 * SOL);
    // Denomination equals the UNSHIELD fixture's withdraw magnitude (7).
    let (vpool, vault) = build_value_pool(
        &mut env,
        &authority,
        0,
        Some(7),
        &extra::UNSHIELD_PUBLIC_INPUTS[0],
        SOL,
    );
    let vault_start = env.get(&vault).lamports;

    let recipient = fixture_recipient();
    env.fund(recipient, 0);
    let depositor = Pubkey::new_unique();
    env.fund(depositor, SOL);

    let nf0 = env.vnf_pda(&vpool, &extra::UNSHIELD_PUBLIC_INPUTS[3]);
    let nf1 = env.vnf_pda(&vpool, &extra::UNSHIELD_PUBLIC_INPUTS[4]);
    let ix = env.transact_ix(
        &vpool,
        &authority,
        &nf0,
        &nf1,
        &recipient,
        &depositor,
        &vault,
        &extra::UNSHIELD_PUBLIC_INPUTS,
        &extra::UNSHIELD_PROOF_A,
        &extra::UNSHIELD_PROOF_B,
        &extra::UNSHIELD_PROOF_C,
        0,
        &payload(5),
        &payload(6),
    );
    // An unshield of exactly D verifies on-chain and credits the recipient.
    env.process(&ix, &[Check::success()]);
    assert_eq!(env.get(&recipient).lamports, 7);
    assert_eq!(env.get(&vault).lamports, vault_start - 7);
    assert_eq!(
        value_pool::commitment_count(&env.get(&vpool).data).unwrap(),
        2
    );
}

#[test]
fn transact_fixed_denom_rejects_mismatched_unshield() {
    let mut env = Env::new();
    let authority = fixture_relayer_authority();
    env.fund(authority, 5 * SOL);
    // Pool pins D = 8 but the UNSHIELD fixture withdraws 7: the amounts differ.
    let (vpool, vault) = build_value_pool(
        &mut env,
        &authority,
        0,
        Some(8),
        &extra::UNSHIELD_PUBLIC_INPUTS[0],
        SOL,
    );
    let vault_start = env.get(&vault).lamports;

    let recipient = fixture_recipient();
    env.fund(recipient, 0);
    let depositor = Pubkey::new_unique();
    env.fund(depositor, SOL);

    let nf0 = env.vnf_pda(&vpool, &extra::UNSHIELD_PUBLIC_INPUTS[3]);
    let nf1 = env.vnf_pda(&vpool, &extra::UNSHIELD_PUBLIC_INPUTS[4]);
    let ix = env.transact_ix(
        &vpool,
        &authority,
        &nf0,
        &nf1,
        &recipient,
        &depositor,
        &vault,
        &extra::UNSHIELD_PUBLIC_INPUTS,
        &extra::UNSHIELD_PROOF_A,
        &extra::UNSHIELD_PROOF_B,
        &extra::UNSHIELD_PROOF_C,
        0,
        &payload(5),
        &payload(6),
    );
    env.process(
        &ix,
        &[Check::err(custom(MirrorPoolError::DenominationMismatch))],
    );
    // Fail-closed: no nullifier PDA, no commitments, no lamports moved.
    assert_eq!(
        env.get(&nf0).owner,
        Pubkey::default(),
        "no nullifier PDA on a denomination mismatch"
    );
    assert_eq!(
        value_pool::commitment_count(&env.get(&vpool).data).unwrap(),
        0
    );
    assert_eq!(env.get(&vault).lamports, vault_start, "vault untouched");
    assert_eq!(env.get(&recipient).lamports, 0);
}

#[test]
fn transact_fixed_denom_allows_transfer() {
    let mut env = Env::new();
    let authority = fixture_relayer_authority();
    env.fund(authority, 5 * SOL);
    // A fixed-denom pool (D = 10) must still allow internal transfers, which move
    // no public value (publicAmount == 0), regardless of the denomination.
    let (vpool, vault) = build_value_pool(
        &mut env,
        &authority,
        0,
        Some(10),
        &transfer::PUBLIC_INPUTS[0],
        5 * SOL,
    );
    let vault_start = env.get(&vault).lamports;

    let recipient = fixture_recipient();
    env.fund(recipient, 0);
    let depositor = Pubkey::new_unique();
    env.fund(depositor, SOL);

    let nf0 = env.vnf_pda(&vpool, &transfer::PUBLIC_INPUTS[3]);
    let nf1 = env.vnf_pda(&vpool, &transfer::PUBLIC_INPUTS[4]);
    let ix = env.transact_ix(
        &vpool,
        &authority,
        &nf0,
        &nf1,
        &recipient,
        &depositor,
        &vault,
        &transfer::PUBLIC_INPUTS,
        &transfer::PROOF_A,
        &transfer::PROOF_B,
        &transfer::PROOF_C,
        0,
        &payload(3),
        &payload(4),
    );
    // The transfer is unaffected by the denomination: it verifies and settles.
    env.process(&ix, &[Check::success()]);
    assert_eq!(
        value_pool::commitment_count(&env.get(&vpool).data).unwrap(),
        2,
        "transfer inserts both output commitments"
    );
    // No public value moved.
    assert_eq!(env.get(&recipient).lamports, 0);
    assert_eq!(env.get(&vault).lamports, vault_start, "vault untouched");
}
