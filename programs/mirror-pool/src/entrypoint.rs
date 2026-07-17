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
        _ => Err(ProgramError::InvalidInstructionData),
    }
}
