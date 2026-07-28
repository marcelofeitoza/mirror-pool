//! Adversarial tests for the write-once, digest-pinned verifying-key registry.
//!
//! These load the COMPILED SBF program into mollusk, so run `cargo build-sbf`
//! first. The question every test here answers is the one that made moving a
//! verifying key out of the bytecode look unsafe in the first place: **can
//! anybody get a verifying key of their own choosing in front of the verifier?**
//!
//! The interesting adversary is not someone who submits garbage. It is someone
//! who submits a PERFECTLY WELL-FORMED verifying key - right length, right
//! `nr_pubinputs`, right `ic_len`, valid curve points - whose trapdoor they hold,
//! and which therefore accepts proofs of false statements. A registry that
//! validates FORMAT ONLY waves that key straight through. So the tests below
//! deliberately build such a key (`foreign_membership_vk`) and check it is
//! refused at install AND at verify.
//!
//! Coverage:
//!  - INIT_VK installs the pinned key, and the account holds exactly the
//!    canonical encoding the compile-time digest is taken over.
//!  - INIT_VK rejects a single flipped byte, a well-formed foreign key, an
//!    unknown circuit id, and any body of the wrong length - all before the
//!    account is created, so a rejected install costs no rent.
//!  - INIT_VK is WRITE-ONCE: a second install fails and cannot swap the key.
//!  - No instruction in the program - all 256 tags, driven with the registry in
//!    the first, writable account slot - can alter a live registry.
//!  - SETTLE_ZK re-validates on EVERY verify: a tampered registry, a foreign key
//!    at the right address, a missing registry, a system-owned registry, a
//!    registry at a non-canonical address, and another circuit's registry are
//!    each rejected with no state change.
//!  - All three pinned circuits install independently (multi-circuit pools), and
//!    a key that is valid for one circuit is refused for another.

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
    pda::{NULLIFIER_SEED, POOL_SEED},
    state::{pool, vk_registry},
    wire::{self, tag},
    MirrorPoolError,
};

const SOL: u64 = 1_000_000_000;

/// The committed membership proof + public inputs (see `integration.rs`).
mod fixture {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../circuits/artifacts/proof_fixture.rs"
    ));
}

/// The fixture's epoch (public signal [3] = 7).
const ZK_EPOCH: u64 = 7;
/// The escrow amount bound into the fixture's actionHash.
const ZK_AMOUNT: u64 = 250_000_000;

/// The fresh recipient bound into the fixture's actionHash: bytes 0x01..0x20.
fn zk_recipient() -> Pubkey {
    let mut b = [0u8; 32];
    for (i, x) in b.iter_mut().enumerate() {
        *x = (i + 1) as u8;
    }
    Pubkey::new_from_array(b)
}

fn custom(e: MirrorPoolError) -> ProgramError {
    ProgramError::Custom(e as u32)
}

/// Shared helpers for the registry (see `fixtures/vk_install.rs`), the same
/// ones every other mollusk test binary uses.
#[allow(dead_code)]
mod vk_fixture {
    include!("fixtures/vk_install.rs");
}

use vk_fixture::canonical_vk;

/// A verifying key that a FORMAT-ONLY validator cannot tell from the real one.
///
/// It is the pinned membership key with `vk_delta_g2` replaced by `vk_beta_g2`,
/// so: identical length (769), identical `nr_pubinputs` byte, identical
/// `ic_len`, and every point is a real BN254 point lifted straight out of a
/// genuine key. Length-and-`ic_len` validation accepts it. It is nonetheless a
/// DIFFERENT key: whoever chose delta chose the toxic waste that goes with it,
/// which is precisely the capability that lets a key's holder forge proofs.
fn foreign_membership_vk() -> Vec<u8> {
    let mut vk = canonical_vk(wire::CIRCUIT_MEMBERSHIP);
    let beta = vk[wire::VK_BETA_G2_OFF..wire::VK_BETA_G2_OFF + wire::G2_LEN].to_vec();
    vk[wire::VK_DELTA_G2_OFF..wire::VK_DELTA_G2_OFF + wire::G2_LEN].copy_from_slice(&beta);
    assert_eq!(vk.len(), 769, "the foreign key must be the same length");
    assert_eq!(
        vk[wire::VK_NR_PUBINPUTS_OFF], 4,
        "and carry the same nr_pubinputs"
    );
    assert_ne!(
        vk,
        canonical_vk(wire::CIRCUIT_MEMBERSHIP),
        "but it must not be the pinned key"
    );
    vk
}

/// A tiny stateful harness (the same shape `integration.rs` uses), minus the
/// automatic registry install: these tests control installation themselves.
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

    fn warp(&mut self, slot: u64) {
        self.mollusk.warp_to_slot(slot);
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

    fn vk_registry_pda(&self, circuit_id: u8) -> Pubkey {
        vk_fixture::vk_registry_pda(&self.program_id, circuit_id)
    }

    fn nf_pda(&self, pool: &Pubkey, epoch_id: u64, nf: &[u8; 32]) -> Pubkey {
        Pubkey::find_program_address(
            &[NULLIFIER_SEED, pool.as_ref(), &epoch_id.to_le_bytes(), nf],
            &self.program_id,
        )
        .0
    }

    fn init_vk_ix(&self, payer: &Pubkey, circuit_id: u8, vk: &[u8]) -> Instruction {
        vk_fixture::init_vk_ix(&self.program_id, &self.system_id, payer, circuit_id, vk)
    }

    fn init_vk_ix_at(
        &self,
        registry: &Pubkey,
        payer: &Pubkey,
        circuit_id: u8,
        vk: &[u8],
    ) -> Instruction {
        vk_fixture::init_vk_ix_at(
            &self.program_id,
            &self.system_id,
            registry,
            payer,
            circuit_id,
            vk,
        )
    }

    /// Install a circuit's pinned key through the real `INIT_VK` instruction.
    fn install(&mut self, circuit_id: u8) -> Pubkey {
        let payer = Pubkey::new_unique();
        self.fund(payer, SOL);
        let vk = canonical_vk(circuit_id);
        let ix = self.init_vk_ix(&payer, circuit_id, &vk);
        self.process(&ix, &[Check::success()]);
        self.vk_registry_pda(circuit_id)
    }

    #[allow(clippy::too_many_arguments)]
    fn settle_zk_ix_with_registry(
        &self,
        pool: &Pubkey,
        authority: &Pubkey,
        nf_pda: &Pubkey,
        recipient: &Pubkey,
        registry: &Pubkey,
        epoch_id: u64,
        amount: u64,
    ) -> Instruction {
        let mut data = Vec::with_capacity(wire::SETTLE_ZK_LEN);
        data.push(tag::SETTLE_ZK);
        data.extend_from_slice(&epoch_id.to_le_bytes());
        data.extend_from_slice(&amount.to_le_bytes());
        data.extend_from_slice(&fixture::PROOF_A);
        data.extend_from_slice(&fixture::PROOF_B);
        data.extend_from_slice(&fixture::PROOF_C);
        for pi in &fixture::PUBLIC_INPUTS {
            data.extend_from_slice(pi);
        }
        Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new(*pool, false),
                AccountMeta::new(*authority, true),
                AccountMeta::new(*nf_pda, false),
                AccountMeta::new(*recipient, false),
                AccountMeta::new_readonly(self.system_id, false),
                AccountMeta::new_readonly(self.clock_id, false),
                AccountMeta::new_readonly(*registry, false),
            ],
            data,
        }
    }
}

/// The circuit's `zeros[DEPTH]` empty root, recomputed host-side.
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

/// Synthesize a funded pool whose recent-root ring already contains the
/// fixture's root, so a settle only has the verifying key left to fail on.
fn build_zk_pool(env: &mut Env, authority: &Pubkey, lamports: u64) -> Pubkey {
    let (pool_key, bump) =
        Pubkey::find_program_address(&[POOL_SEED, authority.as_ref()], &env.program_id);
    let mut data = vec![0u8; pool::LEN];
    pool::init(
        &mut data,
        10,
        2,
        0,
        0,
        ZK_AMOUNT,
        &authority.to_bytes(),
        bump,
        &circuit_empty_root(),
    )
    .unwrap();
    pool::record_root_history(&mut data, &fixture::PUBLIC_INPUTS[0]).unwrap();
    let mut account = Account::new(lamports, pool::LEN, &env.program_id);
    account.data = data;
    env.accounts.insert(pool_key, account);
    pool_key
}

/// A pool + authority + recipient ready to settle the fixture at slot 80.
fn zk_stage(env: &mut Env) -> (Pubkey, Pubkey, Pubkey) {
    let authority = Pubkey::new_unique();
    env.fund(authority, SOL);
    let pool = build_zk_pool(env, &authority, 5 * SOL + ZK_AMOUNT);
    let recipient = zk_recipient();
    env.fund(recipient, 0);
    env.warp(80);
    (authority, pool, recipient)
}

// ---------------------------------------------------------------------------
// INIT_VK
// ---------------------------------------------------------------------------

#[test]
fn init_vk_installs_exactly_the_canonical_pinned_key() {
    let mut env = Env::new();
    let registry = env.install(wire::CIRCUIT_MEMBERSHIP);

    let account = env.get(&registry);
    assert_eq!(account.owner, env.program_id, "registry must be program-owned");
    assert_eq!(
        account.data.len(),
        vk_registry::account_len(4),
        "size is fixed by the pinned circuit, never by the caller"
    );
    assert_eq!(vk_registry::version(&account.data).unwrap(), 1);
    assert_eq!(
        vk_registry::circuit_id(&account.data).unwrap(),
        wire::CIRCUIT_MEMBERSHIP
    );
    let expected_bump = Pubkey::find_program_address(
        &[mirror_pool::pda::VK_REGISTRY_SEED, &[wire::CIRCUIT_MEMBERSHIP]],
        &env.program_id,
    )
    .1;
    assert_eq!(vk_registry::bump(&account.data).unwrap(), expected_bump);
    assert_eq!(account.data[3], 0, "the reserved byte must be zero");
    // Rent for the membership registry, recorded so docs/VK_REGISTRY.md quotes a
    // measured number rather than an estimate.
    assert_eq!(
        account.lamports, 6_270_960,
        "773-byte registry, rent-exempt minimum"
    );

    // The decisive equality: what is on-chain is byte-for-byte the vendored key
    // the compile-time digest was taken over, so this account is the SAME root
    // of trust the embedded constant used to be, just readable.
    assert_eq!(
        vk_registry::vk_bytes(&account.data).unwrap(),
        canonical_vk(wire::CIRCUIT_MEMBERSHIP).as_slice()
    );
}

#[test]
fn init_vk_rejects_a_single_flipped_byte_and_creates_nothing() {
    let mut env = Env::new();
    let payer = Pubkey::new_unique();
    env.fund(payer, SOL);
    let registry = env.vk_registry_pda(wire::CIRCUIT_MEMBERSHIP);

    // Flip one bit in the middle of the IC vector.
    let mut vk = canonical_vk(wire::CIRCUIT_MEMBERSHIP);
    let idx = wire::VK_IC_OFF + 7;
    vk[idx] ^= 0x01;

    let ix = env.init_vk_ix(&payer, wire::CIRCUIT_MEMBERSHIP, &vk);
    env.process(&ix, &[Check::err(custom(MirrorPoolError::VkNotApproved))]);

    let account = env.get(&registry);
    assert_eq!(account.data.len(), 0, "no account may be created");
    assert_eq!(account.lamports, 0, "and no rent may be spent on one");
}

#[test]
fn init_vk_rejects_a_well_formed_foreign_key() {
    let mut env = Env::new();
    let payer = Pubkey::new_unique();
    env.fund(payer, SOL);

    // Right length, right nr_pubinputs, right ic_len, real curve points: a
    // format-only validator (the shape the reviewed alternative uses) accepts
    // this. The digest pin does not.
    let ix = env.init_vk_ix(
        &payer,
        wire::CIRCUIT_MEMBERSHIP,
        &foreign_membership_vk(),
    );
    env.process(&ix, &[Check::err(custom(MirrorPoolError::VkNotApproved))]);
    assert_eq!(
        env.get(&env.vk_registry_pda(wire::CIRCUIT_MEMBERSHIP))
            .data
            .len(),
        0
    );
}

#[test]
fn init_vk_rejects_an_unknown_circuit_id() {
    let mut env = Env::new();
    let payer = Pubkey::new_unique();
    env.fund(payer, SOL);
    // Circuit 3 is pinned to nothing, so no bytes can satisfy it.
    let ix = env.init_vk_ix(&payer, 3, &canonical_vk(wire::CIRCUIT_MEMBERSHIP));
    env.process(&ix, &[Check::err(custom(MirrorPoolError::VkNotApproved))]);
}

#[test]
fn init_vk_rejects_bodies_of_the_wrong_length() {
    let mut env = Env::new();
    let payer = Pubkey::new_unique();
    env.fund(payer, SOL);
    let full = canonical_vk(wire::CIRCUIT_MEMBERSHIP);

    // Short by one, long by one, empty, and the association key's length under
    // the membership id: all rejected on shape, before any hashing.
    for vk in [
        full[..full.len() - 1].to_vec(),
        {
            let mut v = full.clone();
            v.push(0);
            v
        },
        Vec::new(),
        canonical_vk(wire::CIRCUIT_ASSOCIATION),
    ] {
        let ix = env.init_vk_ix(&payer, wire::CIRCUIT_MEMBERSHIP, &vk);
        env.process(
            &ix,
            &[Check::err(custom(MirrorPoolError::MalformedInstruction))],
        );
    }

    // A body with no circuit id at all is malformed too.
    let ix = Instruction {
        program_id: env.program_id,
        accounts: vec![
            AccountMeta::new(env.vk_registry_pda(wire::CIRCUIT_MEMBERSHIP), false),
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(env.system_id, false),
        ],
        data: vec![tag::INIT_VK],
    };
    env.process(
        &ix,
        &[Check::err(custom(MirrorPoolError::MalformedInstruction))],
    );
}

#[test]
fn init_vk_is_write_once_and_cannot_swap_the_key() {
    let mut env = Env::new();
    let registry = env.install(wire::CIRCUIT_MEMBERSHIP);
    let before = env.get(&registry).data.clone();

    let payer = Pubkey::new_unique();
    env.fund(payer, SOL);

    // Re-installing the SAME key is still refused: the registry is write-once,
    // not idempotent, so nothing can be smuggled in behind a "harmless" retry.
    let ix = env.init_vk_ix(
        &payer,
        wire::CIRCUIT_MEMBERSHIP,
        &canonical_vk(wire::CIRCUIT_MEMBERSHIP),
    );
    env.process(
        &ix,
        &[Check::err(custom(
            MirrorPoolError::VkRegistryAlreadyInitialized,
        ))],
    );

    // And a swap attempt with a well-formed foreign key fails on the pin.
    let ix = env.init_vk_ix(&payer, wire::CIRCUIT_MEMBERSHIP, &foreign_membership_vk());
    env.process(&ix, &[Check::err(custom(MirrorPoolError::VkNotApproved))]);

    assert_eq!(
        env.get(&registry).data,
        before,
        "a live registry's bytes must never change"
    );
}

#[test]
fn init_vk_rejects_a_registry_at_a_non_canonical_address() {
    let mut env = Env::new();
    let payer = Pubkey::new_unique();
    env.fund(payer, SOL);
    let rogue = Pubkey::new_unique();
    let ix = env.init_vk_ix_at(
        &rogue,
        &payer,
        wire::CIRCUIT_MEMBERSHIP,
        &canonical_vk(wire::CIRCUIT_MEMBERSHIP),
    );
    env.process(&ix, &[Check::err(custom(MirrorPoolError::InvalidPda))]);
}

#[test]
fn all_three_pinned_circuits_install_independently() {
    let mut env = Env::new();
    for circuit_id in [
        wire::CIRCUIT_MEMBERSHIP,
        wire::CIRCUIT_TRANSACTION,
        wire::CIRCUIT_ASSOCIATION,
    ] {
        let registry = env.install(circuit_id);
        let account = env.get(&registry);
        assert_eq!(vk_registry::circuit_id(&account.data).unwrap(), circuit_id);
        assert_eq!(
            vk_registry::vk_bytes(&account.data).unwrap(),
            canonical_vk(circuit_id).as_slice(),
            "each registry must hold its own circuit's pinned key"
        );
    }
    // Each registry is a distinct account, so one program serves many circuits.
    let addrs: HashSet<Pubkey> = [
        wire::CIRCUIT_MEMBERSHIP,
        wire::CIRCUIT_TRANSACTION,
        wire::CIRCUIT_ASSOCIATION,
    ]
    .iter()
    .map(|c| env.vk_registry_pda(*c))
    .collect();
    assert_eq!(addrs.len(), 3);
}

#[test]
fn a_key_valid_for_one_circuit_is_refused_for_another() {
    let mut env = Env::new();
    let payer = Pubkey::new_unique();
    env.fund(payer, SOL);
    // The association key is a genuine, ceremony-produced key this very program
    // pins - just not for this circuit id. Its length differs, so it fails on
    // shape; the same-length case is covered by the foreign-key test.
    let ix = env.init_vk_ix(
        &payer,
        wire::CIRCUIT_TRANSACTION,
        &canonical_vk(wire::CIRCUIT_ASSOCIATION),
    );
    env.process(
        &ix,
        &[Check::err(custom(MirrorPoolError::MalformedInstruction))],
    );
}

// ---------------------------------------------------------------------------
// No update path
// ---------------------------------------------------------------------------

/// Drive EVERY instruction tag with a live registry in the first (writable)
/// account slot and assert the registry is never altered.
///
/// This is the mechanical form of "there is no update instruction": rather than
/// trusting a reading of the dispatcher, it asks the compiled program directly,
/// for all 256 tags and several body shapes.
#[test]
fn no_instruction_tag_can_alter_a_live_registry() {
    let mut env = Env::new();
    let registry = env.install(wire::CIRCUIT_MEMBERSHIP);
    let before = env.get(&registry);

    let signer = Pubkey::new_unique();
    env.fund(signer, 10 * SOL);
    let filler: Vec<Pubkey> = (0..6).map(|_| Pubkey::new_unique()).collect();
    for f in &filler {
        env.fund(*f, SOL);
    }

    for t in 0u8..=255 {
        // Bodies long enough to reach every handler's parse: empty, a commit
        // body, a settle_zk body, and a transact header.
        for body_len in [0usize, 32, 400, 500] {
            let mut data = vec![t];
            data.extend(std::iter::repeat_n(t, body_len));
            let mut accounts = vec![
                AccountMeta::new(registry, false),
                AccountMeta::new(signer, true),
            ];
            for f in &filler {
                accounts.push(AccountMeta::new(*f, false));
            }
            accounts.push(AccountMeta::new_readonly(env.system_id, false));
            accounts.push(AccountMeta::new_readonly(env.clock_id, false));
            let ix = Instruction {
                program_id: env.program_id,
                accounts,
                data,
            };
            env.process(&ix, &[]);
            let after = env.get(&registry);
            assert_eq!(
                after.data, before.data,
                "tag {t} with a {body_len}-byte body altered the registry data"
            );
            assert_eq!(
                after.lamports, before.lamports,
                "tag {t} with a {body_len}-byte body moved registry lamports"
            );
            assert_eq!(after.owner, before.owner, "tag {t} changed the registry owner");
        }
    }
}

// ---------------------------------------------------------------------------
// SETTLE_ZK re-validates on every verify
// ---------------------------------------------------------------------------

#[test]
fn settle_zk_accepts_the_pinned_registry() {
    let mut env = Env::new();
    let registry = env.install(wire::CIRCUIT_MEMBERSHIP);
    let (authority, pool, recipient) = zk_stage(&mut env);
    let nf = fixture::PUBLIC_INPUTS[1];
    let nf_pda = env.nf_pda(&pool, ZK_EPOCH, &nf);

    let ix = env.settle_zk_ix_with_registry(
        &pool,
        &authority,
        &nf_pda,
        &recipient,
        &registry,
        ZK_EPOCH,
        ZK_AMOUNT,
    );
    env.process(&ix, &[Check::success()]);
    assert_eq!(env.get(&recipient).lamports, ZK_AMOUNT);
}

#[test]
fn settle_zk_rejects_a_tampered_registry() {
    let mut env = Env::new();
    let registry = env.install(wire::CIRCUIT_MEMBERSHIP);

    // Simulate the failure this design exists to survive: the stored key changed
    // after install, by any means whatsoever. The per-verify digest catches it
    // even though the account is still program-owned, still at the canonical
    // address, and still exactly the right size and version.
    let mut account = env.get(&registry);
    account.data[vk_registry::VK_OFF + wire::VK_DELTA_G2_OFF] ^= 0x80;
    env.accounts.insert(registry, account);

    let (authority, pool, recipient) = zk_stage(&mut env);
    let nf = fixture::PUBLIC_INPUTS[1];
    let nf_pda = env.nf_pda(&pool, ZK_EPOCH, &nf);
    let ix = env.settle_zk_ix_with_registry(
        &pool,
        &authority,
        &nf_pda,
        &recipient,
        &registry,
        ZK_EPOCH,
        ZK_AMOUNT,
    );
    env.process(&ix, &[Check::err(custom(MirrorPoolError::VkNotApproved))]);
    assert_eq!(env.get(&recipient).lamports, 0, "no escrow may move");
    assert_eq!(
        env.get(&nf_pda).data.len(),
        0,
        "and no nullifier may be recorded"
    );
}

#[test]
fn settle_zk_rejects_a_well_formed_foreign_key_at_the_registry_address() {
    let mut env = Env::new();
    let registry = env.install(wire::CIRCUIT_MEMBERSHIP);

    // The strongest version of the attack: a program-owned, correctly sized,
    // correctly versioned registry at the canonical address, holding a key that
    // passes every format check and whose trapdoor the attacker holds.
    let mut account = env.get(&registry);
    let foreign = foreign_membership_vk();
    account.data[vk_registry::VK_OFF..].copy_from_slice(&foreign);
    env.accounts.insert(registry, account);

    let (authority, pool, recipient) = zk_stage(&mut env);
    let nf = fixture::PUBLIC_INPUTS[1];
    let nf_pda = env.nf_pda(&pool, ZK_EPOCH, &nf);
    let ix = env.settle_zk_ix_with_registry(
        &pool,
        &authority,
        &nf_pda,
        &recipient,
        &registry,
        ZK_EPOCH,
        ZK_AMOUNT,
    );
    env.process(&ix, &[Check::err(custom(MirrorPoolError::VkNotApproved))]);
    assert_eq!(env.get(&recipient).lamports, 0);
}

#[test]
fn settle_zk_rejects_a_missing_registry() {
    let mut env = Env::new();
    let registry = env.vk_registry_pda(wire::CIRCUIT_MEMBERSHIP);
    let (authority, pool, recipient) = zk_stage(&mut env);
    let nf = fixture::PUBLIC_INPUTS[1];
    let nf_pda = env.nf_pda(&pool, ZK_EPOCH, &nf);
    let ix = env.settle_zk_ix_with_registry(
        &pool,
        &authority,
        &nf_pda,
        &recipient,
        &registry,
        ZK_EPOCH,
        ZK_AMOUNT,
    );
    env.process(
        &ix,
        &[Check::err(custom(MirrorPoolError::VkRegistryNotInitialized))],
    );
}

#[test]
fn settle_zk_rejects_a_system_owned_registry() {
    let mut env = Env::new();
    let registry = env.install(wire::CIRCUIT_MEMBERSHIP);

    // Same address, same bytes, wrong owner: an account this program did not
    // write is not a registry, whatever it contains.
    let mut account = env.get(&registry);
    account.owner = env.system_id;
    env.accounts.insert(registry, account);

    let (authority, pool, recipient) = zk_stage(&mut env);
    let nf = fixture::PUBLIC_INPUTS[1];
    let nf_pda = env.nf_pda(&pool, ZK_EPOCH, &nf);
    let ix = env.settle_zk_ix_with_registry(
        &pool,
        &authority,
        &nf_pda,
        &recipient,
        &registry,
        ZK_EPOCH,
        ZK_AMOUNT,
    );
    env.process(
        &ix,
        &[Check::err(custom(MirrorPoolError::VkRegistryNotInitialized))],
    );
}

#[test]
fn settle_zk_rejects_a_registry_at_a_non_canonical_address() {
    let mut env = Env::new();
    let real = env.install(wire::CIRCUIT_MEMBERSHIP);

    // A byte-perfect copy of the registry, at an address that is not the
    // canonical PDA. Content alone must not be enough.
    let rogue = Pubkey::new_unique();
    let copy = env.get(&real);
    env.accounts.insert(rogue, copy);

    let (authority, pool, recipient) = zk_stage(&mut env);
    let nf = fixture::PUBLIC_INPUTS[1];
    let nf_pda = env.nf_pda(&pool, ZK_EPOCH, &nf);
    let ix = env.settle_zk_ix_with_registry(
        &pool,
        &authority,
        &nf_pda,
        &recipient,
        &rogue,
        ZK_EPOCH,
        ZK_AMOUNT,
    );
    env.process(&ix, &[Check::err(custom(MirrorPoolError::InvalidPda))]);
}

#[test]
fn settle_zk_rejects_another_circuits_registry() {
    let mut env = Env::new();
    env.install(wire::CIRCUIT_MEMBERSHIP);
    let association_registry = env.install(wire::CIRCUIT_ASSOCIATION);

    let (authority, pool, recipient) = zk_stage(&mut env);
    let nf = fixture::PUBLIC_INPUTS[1];
    let nf_pda = env.nf_pda(&pool, ZK_EPOCH, &nf);
    let ix = env.settle_zk_ix_with_registry(
        &pool,
        &authority,
        &nf_pda,
        &recipient,
        &association_registry,
        ZK_EPOCH,
        ZK_AMOUNT,
    );
    env.process(&ix, &[Check::err(custom(MirrorPoolError::InvalidPda))]);
}

#[test]
fn settle_zk_rejects_a_truncated_registry() {
    let mut env = Env::new();
    let registry = env.install(wire::CIRCUIT_MEMBERSHIP);
    let mut account = env.get(&registry);
    account.data.truncate(vk_registry::account_len(4) - 1);
    env.accounts.insert(registry, account);

    let (authority, pool, recipient) = zk_stage(&mut env);
    let nf = fixture::PUBLIC_INPUTS[1];
    let nf_pda = env.nf_pda(&pool, ZK_EPOCH, &nf);
    let ix = env.settle_zk_ix_with_registry(
        &pool,
        &authority,
        &nf_pda,
        &recipient,
        &registry,
        ZK_EPOCH,
        ZK_AMOUNT,
    );
    env.process(
        &ix,
        &[Check::err(custom(MirrorPoolError::VkRegistryNotInitialized))],
    );
}
