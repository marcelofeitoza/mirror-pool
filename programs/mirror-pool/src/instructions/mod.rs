//! Instruction handlers.
//!
//! Conventions shared by every handler:
//!
//! - Every handler takes `(program_id, accounts, data)`. `data` arrives with
//!   the tag byte already stripped by the dispatcher; `program_id` is needed
//!   because the pool/epoch/nullifier accounts are PDAs derived (and signed for)
//!   under it.
//! - Length checks are EXACT and run before any account is touched. Trailing
//!   bytes, short bodies and out-of-range counts are malformed input and are
//!   rejected (fail closed), never truncated or ignored.
//! - Account and PDA-derivation checks are likewise fail-closed: a passed
//!   account that is not the expected PDA, not program-owned, or not a required
//!   signer is rejected before any state changes.

pub mod commit;
pub mod commit_deposit;
pub mod init_pool;
pub mod settle_epoch;
pub mod settle_zk;
