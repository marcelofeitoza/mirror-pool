//! INIT_VK: install a digest-pinned verifying key into its registry PDA, ONCE.
//!
//! This is the ONLY instruction in the program that writes a VkRegistry account,
//! and there is deliberately no counterpart that rewrites one. A registry that
//! already holds a key is refused
//! ([`MirrorPoolError::VkRegistryAlreadyInitialized`]), so the key a verify path
//! reads is immutable for the life of the deployment.
//!
//! Installation is PERMISSIONLESS and that is safe, because the caller does not
//! choose the key. The bytes are accepted only if they hash to the digest this
//! program pins at compile time for that circuit ([`crate::vk_digest`]), so the
//! only thing a caller can do is pay rent to publish the one key the program
//! already committed to. A caller who submits a key of their own - even a
//! perfectly well-formed one whose trapdoor they hold, which is exactly what a
//! format-only check (right length, right `ic_len`) would wave through - is
//! rejected here with [`MirrorPoolError::VkNotApproved`], before any account is
//! created and before any rent is spent.
//!
//! Body layout after the tag byte (see `wire::INIT_VK_HEADER_LEN`):
//!
//! ```text
//! [circuit_id(1)][vk(vk_encoded_len(nr_pubinputs))]
//! ```
//!
//! `vk` is the canonical encoding documented in [`crate::state::vk_registry`].
//! Its length is fixed by the circuit id, so the total body length is exact and
//! any other length is malformed. The largest key (the JoinSplit's 961 bytes)
//! leaves the instruction inside a single 1232-byte transaction.
//!
//! Accounts:
//!
//! ```text
//! 0. registry       writable   VkRegistry PDA to create; seeds [b"vk", circuit_id]
//! 1. payer          signer     writable; funds the PDA rent
//! 2. system_program            for the create-account CPI
//! ```
//!
//! Checks run IN ORDER and fail closed: (1) the circuit id is one this program
//! pins; (2) the body length is exactly that circuit's; (3) the encoded
//! `nr_pubinputs` byte agrees with the pinned circuit; (4) the bytes hash to the
//! pinned digest; only then (5) the PDA is derived and verified, (6) refused if
//! it already exists, (7) created, and (8) written.

use pinocchio::{cpi::Seed, error::ProgramError, AccountView, Address, ProgramResult};
use pinocchio_log::log;

use crate::{
    pda,
    state::vk_registry,
    wire::{vk_encoded_len, VK_NR_PUBINPUTS_OFF},
    MirrorPoolError,
};

pub fn process(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    // (1) Which circuit. An id outside the pinned table is pinned to nothing.
    let (&circuit_id, vk) = data
        .split_first()
        .ok_or(MirrorPoolError::MalformedInstruction)?;
    let circuit = vk_registry::approved(circuit_id)?;

    // (2)/(3) Shape, before anything is hashed or created. The length is a pure
    // function of the pinned circuit, never of what the caller claims.
    if vk.len() != vk_encoded_len(circuit.nr_pubinputs) {
        return Err(MirrorPoolError::MalformedInstruction.into());
    }
    if vk[VK_NR_PUBINPUTS_OFF] as usize != circuit.nr_pubinputs {
        return Err(MirrorPoolError::MalformedInstruction.into());
    }

    // (4) THE PIN. Runs before the account is created so a rejected key costs
    // the submitter a failed transaction and nothing else.
    if vk_registry::sha256(vk) != circuit.digest {
        return Err(MirrorPoolError::VkNotApproved.into());
    }

    let [registry_account, payer, _system_program, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !payer.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !registry_account.is_writable() {
        return Err(ProgramError::InvalidAccountData);
    }

    // (5) The canonical registry PDA for this circuit: seeds = [b"vk", circuit_id].
    let seed_id = [circuit.id];
    let bump = pda::verify_pda(
        registry_account,
        &[pda::VK_REGISTRY_SEED, &seed_id],
        program_id,
    )?;

    // (6) WRITE-ONCE. A live account already has data; refuse rather than
    // overwrite. There is no other code path in this program that writes here.
    if registry_account.data_len() != 0 {
        return Err(MirrorPoolError::VkRegistryAlreadyInitialized.into());
    }

    // (7) Create it, sized by the pinned circuit.
    let bump_seed = [bump];
    let signer_seeds = [
        Seed::from(pda::VK_REGISTRY_SEED),
        Seed::from(&seed_id[..]),
        Seed::from(&bump_seed[..]),
    ];
    pda::create_pda_account(
        payer,
        registry_account,
        program_id,
        vk_registry::account_len(circuit.nr_pubinputs),
        &signer_seeds,
    )?;

    // (8) Write the layout.
    let mut registry_data = registry_account.try_borrow_mut()?;
    if vk_registry::is_initialized(&registry_data)? {
        return Err(MirrorPoolError::VkRegistryAlreadyInitialized.into());
    }
    vk_registry::init(&mut registry_data, circuit, bump, vk)?;

    log!(
        "mirror-pool: init_vk circuit={} nr_pubinputs={} len={}",
        circuit.id,
        circuit.nr_pubinputs,
        vk.len()
    );
    Ok(())
}
