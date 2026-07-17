//! Instruction handlers.
//!
//! Conventions shared by every handler:
//!
//! - `data` arrives with the tag byte already stripped by the dispatcher.
//! - Length checks are EXACT and run before any account is touched. Trailing
//!   bytes, short bodies and out-of-range counts are malformed input and are
//!   rejected (fail closed), never truncated or ignored.
//! - Handlers whose settlement logic has not landed yet finish with
//!   `MirrorPoolError::NotImplemented` after validating, so a skeleton deploy
//!   cannot silently accept state-changing calls.

pub mod commit;
pub mod init_pool;
pub mod settle_epoch;
