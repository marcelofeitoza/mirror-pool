// Shared helpers for the write-once, digest-pinned verifying-key registry.
//
// Every verifying instruction (SETTLE_ZK, TRANSACT, SETTLE_ZK_ASSOCIATED) reads
// its key from a program-owned registry account instead of the program's own
// code, so every mollusk test binary has to install one before it can settle
// anything. These are the helpers all of them share, kept in one file so a
// change to the INIT_VK wire shape cannot land in three near-copies with two of
// them corrected.
//
// `include!`d from a `mod` in each test binary (see `host_frontier.rs` for the
// same pattern). Paths are fully qualified so the file does not depend on what
// its includer happens to have in scope.

/// Canonical encoding of a circuit's pinned verifying key: exactly the bytes
/// `INIT_VK` expects, and exactly the bytes `src/vk_digest.rs` hashes.
///
/// Sourced from the key modules the program vendors, so a test can never offer
/// a key the program was not built to accept.
pub fn canonical_vk(circuit_id: u8) -> Vec<u8> {
    use mirror_pool::{state::vk_registry, wire};
    let mut buf = [0u8; wire::VK_MAX_ENCODED_LEN];
    let len = match circuit_id {
        wire::CIRCUIT_MEMBERSHIP => {
            vk_registry::encode_into(&mirror_pool::vk::VERIFYINGKEY, &mut buf)
        }
        wire::CIRCUIT_TRANSACTION => {
            vk_registry::encode_into(&mirror_pool::transaction_vk::VERIFYINGKEY, &mut buf)
        }
        wire::CIRCUIT_ASSOCIATION => {
            vk_registry::encode_into(&mirror_pool::association_vk::VERIFYINGKEY, &mut buf)
        }
        other => panic!("no vendored verifying key for circuit {other}"),
    }
    .expect("canonical encoding of a vendored verifying key");
    buf[..len].to_vec()
}

/// The canonical registry PDA for a circuit: seeds `[b"vk", circuit_id]`.
pub fn vk_registry_pda(program_id: &solana_pubkey::Pubkey, circuit_id: u8) -> solana_pubkey::Pubkey {
    solana_pubkey::Pubkey::find_program_address(
        &[mirror_pool::pda::VK_REGISTRY_SEED, &[circuit_id]],
        program_id,
    )
    .0
}

/// An `INIT_VK` instruction over ARBITRARY bytes at an ARBITRARY address.
///
/// Both are parameters on purpose: the adversarial tests pass tampered blobs
/// and rogue addresses through exactly the instruction a real client would use,
/// rather than through a test-only shortcut.
pub fn init_vk_ix_at(
    program_id: &solana_pubkey::Pubkey,
    system_id: &solana_pubkey::Pubkey,
    registry: &solana_pubkey::Pubkey,
    payer: &solana_pubkey::Pubkey,
    circuit_id: u8,
    vk: &[u8],
) -> solana_instruction::Instruction {
    let mut data = Vec::with_capacity(mirror_pool::wire::INIT_VK_HEADER_LEN + vk.len());
    data.push(mirror_pool::wire::tag::INIT_VK);
    data.push(circuit_id);
    data.extend_from_slice(vk);
    solana_instruction::Instruction {
        program_id: *program_id,
        accounts: vec![
            solana_instruction::AccountMeta::new(*registry, false),
            solana_instruction::AccountMeta::new(*payer, true),
            solana_instruction::AccountMeta::new_readonly(*system_id, false),
        ],
        data,
    }
}

/// An `INIT_VK` instruction at the canonical registry address for `circuit_id`.
pub fn init_vk_ix(
    program_id: &solana_pubkey::Pubkey,
    system_id: &solana_pubkey::Pubkey,
    payer: &solana_pubkey::Pubkey,
    circuit_id: u8,
    vk: &[u8],
) -> solana_instruction::Instruction {
    init_vk_ix_at(
        program_id,
        system_id,
        &vk_registry_pda(program_id, circuit_id),
        payer,
        circuit_id,
        vk,
    )
}
