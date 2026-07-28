//! Program entrypoint: dispatch on the first instruction byte.
//!
//! The dispatcher is fail-closed: empty instruction data and unknown tags are
//! rejected, never treated as a no-op. Handlers receive the instruction data
//! with the tag byte already stripped and are responsible for exact-length
//! validation of their own body.

use pinocchio::{
    default_allocator, default_panic_handler, error::ProgramError, program_entrypoint, AccountView,
    Address, ProgramResult,
};

use crate::{instructions, wire};

program_entrypoint!(process_instruction);
default_allocator!();
default_panic_handler!();

/// Route an instruction to its handler based on the leading tag byte.
///
/// `program_id` is threaded to every handler because the PDAs (pool, epoch,
/// nullifier) are derived under it, and creating them requires signing with
/// their seeds.
///
/// TODO: once deployed, additionally pin the program id here (compile-time
/// constant, e.g. via `five8_const`) and reject a mismatched `program_id`
/// (standard Solana program-id pinning). Deliberately not hardcoded: no
/// placeholder key must ever look like a real deployment.
pub fn process_instruction(
    program_id: &Address,
    accounts: &[AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    let (tag, data) = instruction_data
        .split_first()
        .ok_or(ProgramError::InvalidInstructionData)?;

    match *tag {
        wire::tag::INIT_POOL => instructions::init_pool::process(program_id, accounts, data),
        wire::tag::COMMIT => instructions::commit::process(program_id, accounts, data),
        wire::tag::SETTLE_EPOCH => instructions::settle_epoch::process(program_id, accounts, data),
        wire::tag::COMMIT_DEPOSIT => {
            instructions::commit_deposit::process(program_id, accounts, data)
        }
        wire::tag::SETTLE_ZK => instructions::settle_zk::process(program_id, accounts, data),
        wire::tag::CLAIM_REWARD => instructions::claim_reward::process(program_id, accounts, data),
        wire::tag::INIT_VALUE_POOL => {
            instructions::init_value_pool::process(program_id, accounts, data)
        }
        wire::tag::TRANSACT => instructions::transact::process(program_id, accounts, data),
        wire::tag::INIT_ASSOCIATION => {
            instructions::init_association::process(program_id, accounts, data)
        }
        wire::tag::UPDATE_ASSOCIATION_ROOT => {
            instructions::update_association_root::process(program_id, accounts, data)
        }
        wire::tag::SETTLE_ZK_ASSOCIATED => {
            instructions::settle_zk_associated::process(program_id, accounts, data)
        }
        // Write-once install of a digest-pinned verifying key. Note what is NOT
        // in this table: there is no UPDATE_VK tag, so once a registry PDA holds
        // a key no instruction in this program can change it.
        wire::tag::INIT_VK => instructions::init_vk::process(program_id, accounts, data),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}
