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
//! v1 status: all three instructions are implemented. `INIT_POOL` creates the
//! program-owned Pool PDA (system-program CPI) and fixes its config; `COMMIT`
//! appends a leaf to a frontier Merkle accumulator, lazily creates the Epoch
//! PDA, bumps its commit count, and collects the anti-Sybil entry fee;
//! `SETTLE_EPOCH` enforces the relay authority, the closed-window gate, the
//! on-chain k-floor, and per-nullifier anti-replay via PDA existence, then
//! marks the epoch settled.
//!
//! Honesty note: v1 does NOT cryptographically bind each settled nullifier to a
//! distinct prior commitment - that soundness is the v2 Groth16 membership
//! proof (see `docs/ROADMAP.md`). What v1 enforces on-chain is shared-epoch
//! batching, the k-anonymity floor (via the Epoch account's commit count),
//! nullifier anti-replay, relay-authority, and fail-closed parsing. The pooled
//! behavior execution (a CPI to the swap/stake) is a documented v2 hook; the
//! settlement handler marks the point where it plugs in.
//!
//! Build:
//!
//! ```text
//! cargo build-sbf --manifest-path programs/mirror-pool/Cargo.toml
//! ```

use pinocchio::error::ProgramError;

pub mod instructions;
pub mod pda;
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

    /// INIT_POOL layout: `[tag(1)][epoch_slots(8 LE)][k_floor(4 LE)][entry_fee(8 LE)]`.
    /// MUST match `mirror_core::wire::INIT_POOL_LEN`.
    ///
    /// `entry_fee` is a per-commit anti-Sybil deposit (lamports) transferred
    /// into the pool at COMMIT time; `0` disables it.
    pub const INIT_POOL_LEN: usize = 1 + 8 + 4 + 8;

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
    const _: () = assert!(INIT_POOL_LEN == 21);
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
    /// SETTLE_EPOCH on an epoch that has already been settled (double-settle).
    EpochAlreadySettled = 6,
    /// The settle signer is not the pool's configured settlement authority.
    Unauthorized = 7,
    /// A passed account does not match its expected program-derived address
    /// (pool / epoch / nullifier PDA derivation check failed).
    InvalidPda = 8,
    /// The intent accumulator is full (2^DEPTH leaves appended).
    TreeFull = 9,
    /// A checked integer operation overflowed (commit counter, settle-slot
    /// arithmetic). Fail closed rather than wrap.
    ArithmeticOverflow = 10,
    /// The epoch account's stored id does not match the id derived/requested
    /// for this instruction.
    EpochMismatch = 11,
    /// Skeleton guard: reserved for handlers whose logic has not landed yet.
    /// Unused in v1 (all three instructions are implemented) but kept so the
    /// off-chain error mapping stays stable.
    NotImplemented = 100,
}

impl From<MirrorPoolError> for ProgramError {
    fn from(e: MirrorPoolError) -> Self {
        ProgramError::Custom(e as u32)
    }
}
