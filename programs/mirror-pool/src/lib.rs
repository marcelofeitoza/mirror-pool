//! mirror-pool on-chain program (Pinocchio skeleton).
//!
//! mirror-pool is a shared anonymity network over the *initiators* of an
//! action rather than over denominations. The on-chain program is the
//! settlement layer for three phases:
//!
//! - `INIT_POOL`: fix a pool's parameters forever. One pool serves exactly one
//!   [`ActionClass`-shaped action]: heterogeneous actions leak like mixed
//!   denominations, so every action a pool emits must be byte-shape identical.
//! - `COMMIT`: a participant posts a 32-byte commitment binding their secret to
//!   the action and the epoch. Nothing else is revealed; the only remaining
//!   signal is timing, which shared-epoch batching absorbs.
//! - `SETTLE_EPOCH`: a gasless, rotating relay settles a whole epoch in one
//!   transaction on one timestamp. Batch settlement is what defeats FIFO
//!   temporal matching (empirically the strongest attack on Tornado-style
//!   pools, up to 49% linkage). The relay is untrusted: commitments bind the
//!   action, so it cannot substitute one, and the k-anonymity floor
//!   (`k_floor`) means an epoch below the floor rolls forward instead of
//!   executing into a set small enough to deanonymize by elimination.
//!
//! Skeleton status: entrypoint dispatch and fail-closed instruction parsing
//! are wired; state accounts have byte-offset layouts and accessors; the
//! settlement logic itself is TODO(v1) (see `docs/ROADMAP.md`). Handlers that
//! are not implemented return [`MirrorPoolError::NotImplemented`] after
//! validating their inputs, so a partially built deploy can never be mistaken
//! for a working one.
//!
//! Build:
//!
//! ```text
//! cargo build-sbf --manifest-path programs/mirror-pool/Cargo.toml
//! ```

use pinocchio::error::ProgramError;

pub mod instructions;
pub mod state;

#[cfg(not(feature = "no-entrypoint"))]
mod entrypoint;

/// The on-chain wire format, mirrored from `mirror-core::wire`.
///
/// These constants are REDEFINED here on purpose: a Solana program must not
/// depend on the std host crate `mirror-core` (it pulls in serde, sha2 and
/// thiserror host machinery). They MUST stay byte-for-byte identical to
/// `mirror-core::wire`; if either side changes, both change in the same
/// commit.
///
/// TODO(v1): add a host-side test in `crates/mirror-harness` that asserts
/// these constants equal `mirror_core::wire`'s so the mirror cannot drift
/// silently.
pub mod wire {
    /// Instruction discriminators (first byte of instruction data).
    /// MUST match `mirror_core::wire::tag`.
    pub mod tag {
        pub const INIT_POOL: u8 = 0;
        pub const COMMIT: u8 = 1;
        pub const SETTLE_EPOCH: u8 = 2;
    }

    /// COMMIT layout: `[tag(1)][commitment(32)]`.
    /// MUST match `mirror_core::wire::COMMIT_LEN`.
    pub const COMMIT_LEN: usize = 1 + 32;

    /// SETTLE_EPOCH header: `[tag(1)][epoch(8 LE)][n_nullifiers(4 LE)]`
    /// followed by `n_nullifiers * 32` bytes of nullifiers.
    /// MUST match `mirror_core::wire::SETTLE_HEADER_LEN`.
    pub const SETTLE_HEADER_LEN: usize = 1 + 8 + 4;

    /// INIT_POOL layout: `[tag(1)][epoch_slots(8 LE)][k_floor(4 LE)]`.
    ///
    /// TODO(v1): promote this constant into `mirror-core::wire` when the
    /// coordinator starts building INIT_POOL instructions, so both sides
    /// share one definition. Until then this is the single source of truth.
    pub const INIT_POOL_LEN: usize = 1 + 8 + 4;

    /// Size of one commitment / nullifier on the wire.
    pub const HASH_LEN: usize = 32;

    /// Hard upper bound on nullifiers per SETTLE_EPOCH call. Bounds the
    /// `n * 32` length arithmetic (no overflow) and keeps a single settle
    /// inside transaction and compute limits. Larger epochs settle in
    /// multiple calls; TODO(v1): make multi-call settlement atomic per epoch.
    pub const MAX_SETTLE_NULLIFIERS: usize = 32;

    // Layout sanity: keep the documented sizes honest at compile time.
    const _: () = assert!(COMMIT_LEN == 33);
    const _: () = assert!(SETTLE_HEADER_LEN == 13);
    const _: () = assert!(INIT_POOL_LEN == 13);
}

/// Program-local error codes, surfaced on-chain as `ProgramError::Custom`.
///
/// The variants intentionally mirror `mirror_core::MirrorError` so the
/// off-chain crates can map custom codes back to the shared taxonomy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum MirrorPoolError {
    /// Instruction data does not match the wire layout exactly. Fail closed:
    /// wrong length, trailing bytes and out-of-range counts are all rejected.
    MalformedInstruction = 0,
    /// SETTLE_EPOCH arrived before the epoch's slot window closed.
    EpochNotClosed = 1,
    /// Settling would execute into an anonymity set below `k_floor`. The
    /// epoch must roll forward instead; never settle a set small enough to
    /// deanonymize by elimination.
    BelowKFloor = 2,
    /// The nullifier was already spent this epoch (replay of a participant).
    NullifierSpent = 3,
    /// INIT_POOL on a pool account that is already configured.
    PoolAlreadyInitialized = 4,
    /// The referenced pool account has not been initialized.
    PoolNotInitialized = 5,
    /// Skeleton guard: the handler validated its inputs but the settlement
    /// logic has not landed yet (see TODO(v1) markers).
    NotImplemented = 100,
}

impl From<MirrorPoolError> for ProgramError {
    fn from(e: MirrorPoolError) -> Self {
        ProgramError::Custom(e as u32)
    }
}
