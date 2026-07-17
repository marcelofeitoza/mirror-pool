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
//! v1 status: all six instructions are implemented. `INIT_POOL` creates the
//! program-owned Pool PDA (system-program CPI) and fixes its config; `COMMIT`
//! appends a leaf to a frontier Merkle accumulator, lazily creates the Epoch
//! PDA, bumps its commit count, and collects the anti-Sybil entry fee;
//! `SETTLE_EPOCH` enforces the relay authority, the closed-window gate, the
//! on-chain k-floor, and per-nullifier anti-replay via PDA existence, then
//! marks the epoch settled.
//!
//! Incentive layer (additive; see `docs/INCENTIVES.md`). Each entry fee is split
//! at `INIT_POOL` by `reward_bps`: that basis-point share accrues to an on-chain
//! reward pool (`reward_pool_lamports` on the Pool), the remainder is the
//! settlement reserve. On the CROWD path (identified signers) `COMMIT` may also
//! bump a per-participant Dwell PDA (seeds `["dwell", pool, participant]`) once
//! per epoch, and `CLAIM_REWARD` pays a claimant a dwell-proportional, drain-safe
//! share of the reward pool. The ZK path stays anonymous: `COMMIT_DEPOSIT` funds
//! the reward pool via its entry fee but is never tied to a dwell identity; an
//! anonymity-preserving ZK dwell claim is documented (not implemented) in
//! `docs/INCENTIVES.md`. All of this is appended AFTER the Pool root-history ring
//! so no existing account offset shifts.
//!
//! There are two settlement paths:
//!
//! - The CROWD path (`COMMIT` / `SETTLE_EPOCH`): participants sign their own
//!   identical actions and the coordinator composes them. It does NOT
//!   cryptographically bind each settled nullifier to a distinct prior
//!   commitment; what it enforces on-chain is shared-epoch batching, the
//!   k-anonymity floor (via the Epoch account's commit count), nullifier
//!   anti-replay, relay-authority, and fail-closed parsing.
//! - The ZK OPT-IN path (`COMMIT_DEPOSIT` / `SETTLE_ZK`): a participant escrows
//!   the action input into the pool at commit; at settle a relay proves in zero
//!   knowledge (Groth16 over the SAME Poseidon accumulator) that an output
//!   corresponds to SOME committed member without revealing which, and the action
//!   executes to a FRESH address. This cryptographically hides which participant
//!   initiated. `SETTLE_ZK` verifies the membership proof against a recent root
//!   (a small root-history ring buffer on the Pool), enforces per-nullifier
//!   anti-replay, binds the recipient+amount into the proof's `actionHash` so the
//!   relay cannot redirect, and executes the v1 action (transfer the escrow to
//!   the fresh recipient). Swap/stake-from-pool are documented extensions of the
//!   same pattern (execute a different action from the pool authority via CPI).
//!
//! Build:
//!
//! ```text
//! cargo build-sbf --manifest-path programs/mirror-pool/Cargo.toml
//! ```

use pinocchio::error::ProgramError;

pub mod action;
pub mod instructions;
pub mod pda;
pub mod state;

/// Vendored Groth16 verifying key (`src/vk.rs`, copied from
/// `circuits/artifacts/vk.rs`). Consumed only by the SETTLE_ZK handler.
pub mod vk;

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
        /// ZK opt-in path: escrow + commit (see [`super::COMMIT_DEPOSIT_LEN`]).
        pub const COMMIT_DEPOSIT: u8 = 3;
        /// ZK opt-in path: settle one membership (see [`super::SETTLE_ZK_LEN`]).
        pub const SETTLE_ZK: u8 = 4;
        /// Crowd-path participation incentive: claim a dwell-proportional share
        /// of the on-chain reward pool (see [`super::CLAIM_REWARD_LEN`]).
        pub const CLAIM_REWARD: u8 = 5;
    }

    /// COMMIT layout: `[tag(1)][commitment(32)]`.
    /// MUST match `mirror_core::wire::COMMIT_LEN`.
    pub const COMMIT_LEN: usize = 1 + 32;

    /// SETTLE_EPOCH header: `[tag(1)][epoch(8 LE)][n_nullifiers(4 LE)]`
    /// followed by `n_nullifiers * 32` bytes of nullifiers.
    /// MUST match `mirror_core::wire::SETTLE_HEADER_LEN`.
    pub const SETTLE_HEADER_LEN: usize = 1 + 8 + 4;

    /// INIT_POOL layout:
    /// `[tag(1)][epoch_slots(8 LE)][k_floor(4 LE)][entry_fee(8 LE)][reward_bps(2 LE)]`.
    /// MUST match `mirror_core::wire::INIT_POOL_LEN`.
    ///
    /// `entry_fee` is a per-commit anti-Sybil deposit (lamports) transferred
    /// into the pool at COMMIT / COMMIT_DEPOSIT time; `0` disables it.
    /// `reward_bps` is the basis-point share of each entry fee that accrues to
    /// the on-chain reward pool (`reward_pool_lamports`); the remainder stays in
    /// the pool as the settlement reserve. `reward_bps` must be `<= 10_000`; a
    /// zero `entry_fee` (or zero `reward_bps`) leaves the reward pool empty.
    pub const INIT_POOL_LEN: usize = 1 + 8 + 4 + 8 + 2;

    /// CLAIM_REWARD layout: `[tag(1)]` (no body). The claimant signs; their dwell
    /// PDA carries the accumulated dwell used to size the payout.
    /// MUST match `mirror_core::wire::CLAIM_REWARD_LEN`.
    pub const CLAIM_REWARD_LEN: usize = 1;

    /// Basis-point denominator for the entry-fee reward split. 100% = 10_000 bps.
    pub const BPS_DENOMINATOR: u16 = 10_000;

    /// COMMIT_DEPOSIT layout: `[tag(1)][commitment(32)][amount(8 LE)]`.
    /// MUST match `mirror_core::wire::COMMIT_DEPOSIT_LEN`.
    ///
    /// The ZK opt-in escrow: escrow `amount` lamports into the pool and append
    /// the commitment (whose `actionHash` binds `(recipient, amount)`) to the
    /// SAME frontier accumulator the crowd `COMMIT` path uses.
    pub const COMMIT_DEPOSIT_LEN: usize = 1 + 32 + 8;

    /// SETTLE_ZK layout (ONE membership per call; batch at the coordinator).
    /// MUST match `mirror_core::wire::SETTLE_ZK_LEN`.
    ///
    /// ```text
    /// [tag(1)][epoch(8 LE)][amount(8 LE)]
    ///   [proof_a(64)][proof_b(128)][proof_c(64)]
    ///   [root(32)][nullifierHash(32)][actionHash(32)][epoch(32 BE)]
    /// ```
    ///
    /// The four trailing 32-byte values are the Groth16 public inputs in the
    /// FIXED order [root, nullifierHash, actionHash, epoch].
    pub const SETTLE_ZK_LEN: usize = 1 + 8 + 8 + 64 + 128 + 64 + 32 + 32 + 32 + 32;

    /// Groth16 proof component sizes (groth16-solana v0.2.0 byte layout).
    pub const PROOF_A_LEN: usize = 64;
    pub const PROOF_B_LEN: usize = 128;
    pub const PROOF_C_LEN: usize = 64;
    /// One Groth16 public input (a canonical big-endian BN254 scalar).
    pub const PUBLIC_INPUT_LEN: usize = 32;
    /// Number of public inputs: [root, nullifierHash, actionHash, epoch].
    pub const N_PUBLIC_INPUTS: usize = 4;

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
    const _: () = assert!(INIT_POOL_LEN == 23);
    const _: () = assert!(COMMIT_DEPOSIT_LEN == 41);
    const _: () = assert!(SETTLE_ZK_LEN == 401);
    const _: () = assert!(CLAIM_REWARD_LEN == 1);
    const _: () = assert!(
        SETTLE_ZK_LEN == 1 + 8 + 8 + PROOF_A_LEN + PROOF_B_LEN + PROOF_C_LEN + 4 * PUBLIC_INPUT_LEN
    );
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
    /// SETTLE_ZK: the Groth16 membership proof did not verify against the
    /// supplied public inputs (or a public input was not a canonical BN254
    /// scalar). Fail closed: no nullifier is created and no escrow is moved.
    ProofVerificationFailed = 12,
    /// SETTLE_ZK: the proof's `root` is not in the pool's recent-root ring
    /// buffer. A proof is made against a root snapshot, so settle accepts any
    /// recent root; a root that never existed (or has aged out) is rejected.
    RootNotKnown = 13,
    /// SETTLE_ZK: the recomputed `actionHash` (from the settle recipient and
    /// amount) does not equal the proof's `actionHash` public input, i.e. the
    /// relay tried to redirect the escrow to a different recipient/amount than
    /// the one the committed member bound.
    ActionHashMismatch = 14,
    /// SETTLE_ZK: the pool does not hold enough lamports to pay the bound
    /// `amount` while staying rent-exempt (escrow accounting error).
    InsufficientEscrow = 15,
    /// CLAIM_REWARD: the caller has no reward to claim - no accrued dwell, all
    /// accrued dwell already claimed (double-claim), or the reward pool is empty
    /// so the proportional share rounds to zero. Fail closed: no lamports move
    /// and no dwell is consumed.
    NothingToClaim = 16,
    /// CLAIM_REWARD: paying the computed reward would drop the pool below rent
    /// exemption. Never drain the account below rent; fail closed instead.
    RewardPoolInsufficient = 17,
    /// Skeleton guard: reserved for handlers whose logic has not landed yet.
    /// Unused in v1 (all five instructions are implemented) but kept so the
    /// off-chain error mapping stays stable.
    NotImplemented = 100,
}

impl From<MirrorPoolError> for ProgramError {
    fn from(e: MirrorPoolError) -> Self {
        ProgramError::Custom(e as u32)
    }
}
