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
//!   executes to an address the member bound at commit time (clients bind a fresh
//!   one). This cryptographically hides which member initiated, up to what the
//!   settle publishes. `SETTLE_ZK` verifies the membership proof against a recent
//!   root (a small root-history ring buffer on the Pool), enforces per-nullifier
//!   anti-replay, binds the recipient+amount into the proof's `actionHash` so the
//!   relay cannot redirect, and executes the v1 action (transfer the escrow to
//!   the bound recipient). It enforces NO k-anonymity floor and NO recipient
//!   freshness: the `settle_zk` module header states exactly why neither can be a
//!   settle-time check on a path whose escrow has no refund, and where the
//!   compensating control lives instead.
//!
//! Escrow soundness on the ZK path rests on two on-chain rules, both stated in
//! full in the `settle_zk` module header. LEAF DOMAIN: a crowd `COMMIT` appends
//! `Poseidon(CROWD_LEAF_DOMAIN, commitment)` while `COMMIT_DEPOSIT` appends its
//! commitment verbatim, so the only leaves in the domain the ZK circuits prove
//! membership in are leaves that paid an escrow. DENOMINATION: `COMMIT_DEPOSIT`
//! takes exactly `pool.zk_denomination` and both ZK settle paths pay exactly it,
//! so a settle cannot draw more than its leaf put in. Together they bound total
//! settled by total escrowed: distinct settles burn distinct nullifiers, which
//! means distinct leaves, each of which escrowed one denomination.
//!   Swap/stake-from-pool are documented extensions of the same pattern (execute
//!   a different action from the pool authority via CPI).
//!
//! Opt-in compliance layer (additive; see `docs/COMPLIANCE.md`). A curator may
//! register an `AssociationSet` (`INIT_ASSOCIATION`, seeds
//! `["assoc", pool, curator]`) and publish the Merkle root of a CURATED subset of
//! this pool's commitments (`UPDATE_ASSOCIATION_ROOT`). A user may then settle via
//! `SETTLE_ZK_ASSOCIATED`, which verifies a DIFFERENT circuit
//! (`circuits/association.circom`, its own verifying key in `src/association_vk.rs`)
//! proving the settling commitment is in the pool tree AND in that curator's set,
//! still without revealing which commitment it is. This is the Privacy Pools
//! association-set idea, enforced in the execute path rather than checked
//! off-chain.
//!
//! It is strictly OPT-IN and there is deliberately no pool-level switch making it
//! mandatory: `SETTLE_ZK` is untouched, so a curator can decline to vouch for
//! someone but cannot stop them settling. Registration is permissionless and the
//! set PDA is keyed by curator, so competing curators can coexist and the user
//! chooses. What an attestation is WORTH is an off-chain judgement about that
//! curator; the program only proves the inclusion proof really was verified.
//!
//! Opt-in disclosure layer (additive; see `docs/COMPLIANCE.md`). The second,
//! complementary compliance primitive: where an association proof says "my funds
//! are in the acceptable set" to EVERYONE while revealing nothing, a disclosure
//! reveals ONE action to ONE reader the user picked. `REGISTER_VIEWING_KEY`
//! publishes an X25519 viewing key under the signer's own address (seeds
//! `["view", authority]`), and `PUBLISH_DISCLOSURE` posts a sealed record about a
//! settlement (seeds `["disc", pool, action_hash, auditor_view_pub]`) whose
//! payload only that reader can open.
//!
//! The authentication is the seed derivation, not a check: `action_hash` is
//! recomputed ON-CHAIN from the SIGNING recipient's address and the settled
//! amount, and the settling commitment binds that same `actionHash`, so the only
//! party who can write a record about a settlement is the address that
//! settlement was bound to pay. Squatting somebody else's slot is not forbidden,
//! it is underivable.
//!
//! Neither instruction is read by any settle path, so not registering degrades
//! nothing: a pool that required disclosure would be a surveillance pool. What
//! the program cannot do is verify the sealed payload (it holds no secret and
//! cannot decrypt); `state::disclosure` and `docs/COMPLIANCE.md` state exactly
//! which half of the claim is enforced on-chain and which half the reader checks
//! for themselves.
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

/// Vendored Groth16 verifying key for the membership circuit (`src/vk.rs`,
/// copied verbatim from `circuits/artifacts/vk.rs`). It is the source of truth
/// for [`vk_digest::MEMBERSHIP_VK_SHA256`]; the key the SETTLE_ZK handler
/// actually verifies with is read from the registry account and accepted only if
/// it hashes to that digest.
///
/// PROVENANCE: this key is the output of a real phase-2 ceremony (1 independent
/// contributor, closed by a public Solana mainnet-beta blockhash beacon). See
/// `docs/CEREMONY.md` and `docs/ceremony-run/membership-deployed-transcript.json`.
pub mod vk;

/// Vendored Groth16 verifying key for the 2-in/2-out JoinSplit transaction
/// circuit (`src/transaction_vk.rs`, copied verbatim from
/// `circuits/artifacts/transaction_vk.rs`), pinned by
/// [`vk_digest::TRANSACTION_VK_SHA256`] and used by the TRANSACT handler.
///
/// PROVENANCE: still a `circuits/build.sh` DEV setup, NOT a ceremony key.
pub mod transaction_vk;

/// Vendored Groth16 verifying key for the opt-in association circuit
/// (`src/association_vk.rs`, copied verbatim from
/// `circuits/artifacts/association_vk.rs`), pinned by
/// [`vk_digest::ASSOCIATION_VK_SHA256`] and used by the SETTLE_ZK_ASSOCIATED
/// handler.
///
/// PROVENANCE: still a `circuits/build.sh` DEV setup, NOT a ceremony key.
///
/// This is a DIFFERENT key from [`vk`]: the association statement is a different
/// circuit with 5 public inputs, so a plain membership proof can never satisfy
/// the association path and vice versa.
pub mod association_vk;

/// Compile-time SHA-256 digests of the three vendored verifying keys
/// (`src/vk_digest.rs`). This is the PIN: the verifying key a verify path
/// actually uses is read from a program-owned registry account, and is accepted
/// only if it hashes to the digest recorded here. Moving the key bytes into an
/// account without pinning them would let whoever writes the account install a
/// key whose trapdoor they hold; the digest is what makes the account model as
/// safe as the compile-time constant it replaces. See `docs/VK_REGISTRY.md`.
pub mod vk_digest;

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
        /// Confidential-value layer: create a ValuePool (see
        /// [`super::INIT_VALUE_POOL_LEN`]).
        pub const INIT_VALUE_POOL: u8 = 6;
        /// Confidential-value layer: settle one 2-in/2-out JoinSplit (see
        /// [`super::TRANSACT_HEADER_LEN`]).
        pub const TRANSACT: u8 = 7;
        /// Opt-in compliance layer: register a curator's association set (see
        /// [`super::INIT_ASSOCIATION_LEN`]).
        pub const INIT_ASSOCIATION: u8 = 8;
        /// Opt-in compliance layer: publish a new curated-set root (see
        /// [`super::UPDATE_ASSOCIATION_ROOT_LEN`]).
        pub const UPDATE_ASSOCIATION_ROOT: u8 = 9;
        /// Opt-in compliance layer: settle one membership that ALSO carries a
        /// curated-set inclusion proof (see [`super::SETTLE_ZK_ASSOCIATED_LEN`]).
        pub const SETTLE_ZK_ASSOCIATED: u8 = 10;
        /// Write-once install of a digest-pinned verifying key into its
        /// program-owned registry PDA (see [`super::INIT_VK_HEADER_LEN`]).
        /// There is deliberately NO matching update tag.
        pub const INIT_VK: u8 = 11;
        /// Opt-in disclosure layer: register (or rotate) an X25519 viewing key
        /// under the SIGNER'S OWN address (see
        /// [`super::REGISTER_VIEWING_KEY_LEN`]).
        pub const REGISTER_VIEWING_KEY: u8 = 12;
        /// Opt-in disclosure layer: publish one sealed disclosure record about a
        /// settlement whose bound recipient is the signer (see
        /// [`super::PUBLISH_DISCLOSURE_LEN`]).
        pub const PUBLISH_DISCLOSURE: u8 = 13;
    }

    /// COMMIT layout: `[tag(1)][commitment(32)]`.
    /// MUST match `mirror_core::wire::COMMIT_LEN`.
    ///
    /// The appended leaf is `state::merkle::crowd_leaf(commitment)`, NOT the
    /// posted bytes: crowd leaves live in their own hash domain so a free commit
    /// can never be spent by the ZK settle paths.
    pub const COMMIT_LEN: usize = 1 + 32;

    /// SETTLE_EPOCH header: `[tag(1)][epoch(8 LE)][n_nullifiers(4 LE)]`
    /// followed by `n_nullifiers * 32` bytes of nullifiers.
    /// MUST match `mirror_core::wire::SETTLE_HEADER_LEN`.
    pub const SETTLE_HEADER_LEN: usize = 1 + 8 + 4;

    /// INIT_POOL layout:
    /// `[tag(1)][epoch_slots(8 LE)][k_floor(4 LE)][entry_fee(8 LE)][reward_bps(2 LE)]
    /// [zk_denomination(8 LE)]`.
    /// MUST match `mirror_core::wire::INIT_POOL_LEN`.
    ///
    /// `entry_fee` is a per-commit anti-Sybil deposit (lamports) transferred
    /// into the pool at COMMIT / COMMIT_DEPOSIT time; `0` disables it.
    /// `reward_bps` is the basis-point share of each entry fee that accrues to
    /// the on-chain reward pool (`reward_pool_lamports`); the remainder stays in
    /// the pool as the settlement reserve. `reward_bps` must be `<= 10_000`; a
    /// zero `entry_fee` (or zero `reward_bps`) leaves the reward pool empty.
    /// `zk_denomination` is the single escrow size the ZK opt-in path accepts
    /// and must be non-zero: COMMIT_DEPOSIT takes exactly it and both ZK settle
    /// paths pay exactly it, which is what caps a settle at what its leaf
    /// escrowed.
    pub const INIT_POOL_LEN: usize = 1 + 8 + 4 + 8 + 2 + 8;

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
    /// SAME frontier accumulator the crowd `COMMIT` path uses - but VERBATIM,
    /// where a crowd commit is domain-wrapped first, so only a leaf that paid an
    /// escrow lands in the domain the ZK circuits prove membership in. `amount`
    /// must equal the pool's `zk_denomination`.
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

    // --- Confidential-value layer (ADDITIVE): ValuePool + Transact. These are
    // REDEFINED here (not imported from `mirror-core`) for the same reason the
    // rest of this module is: a Solana program must not depend on the std host
    // crate. They MUST stay byte-for-byte identical to `mirror_core::wire`; the
    // compile-time asserts below (and mirror-core's) pin the numbers. ---

    /// INIT_VALUE_POOL layout: `[tag(1)][fee(8 LE)][denom_flag(1)][denomination(8 LE)]`.
    /// MUST match `mirror_core::wire::INIT_VALUE_POOL_LEN`.
    pub const INIT_VALUE_POOL_LEN: usize = 1 + 8 + 1 + 8;

    /// Number of transaction public inputs, in the fixed order
    /// [root, publicAmount, extDataHash, inNullifier0, inNullifier1,
    /// outCommitment0, outCommitment1]. MUST match `mirror_core::wire`.
    pub const TRANSACT_N_PUBLIC_INPUTS: usize = 7;
    /// Per-blob cap on an encrypted output-note payload (bytes).
    pub const TRANSACT_MAX_ENC_LEN: usize = 256;

    // Field offsets inside the fixed Transact header (after the tag byte). These
    // MUST match `mirror_core::wire`'s TRANSACT_* offsets.
    pub const TRANSACT_PUBLIC_AMOUNT_OFF: usize = 0;
    pub const TRANSACT_EXT_DATA_HASH_OFF: usize = 32;
    pub const TRANSACT_ROOT_OFF: usize = 64;
    pub const TRANSACT_IN_NULLIFIER0_OFF: usize = 96;
    pub const TRANSACT_IN_NULLIFIER1_OFF: usize = 128;
    pub const TRANSACT_OUT_COMMIT0_OFF: usize = 160;
    pub const TRANSACT_OUT_COMMIT1_OFF: usize = 192;
    pub const TRANSACT_PROOF_A_OFF: usize = 224;
    pub const TRANSACT_PROOF_B_OFF: usize = TRANSACT_PROOF_A_OFF + PROOF_A_LEN; // 288
    pub const TRANSACT_PROOF_C_OFF: usize = TRANSACT_PROOF_B_OFF + PROOF_B_LEN; // 416
    pub const TRANSACT_FEE_OFF: usize = TRANSACT_PROOF_C_OFF + PROOF_C_LEN; // 480
    /// First byte of the two length-prefixed encrypted-note blobs.
    pub const TRANSACT_ENC_OFF: usize = TRANSACT_FEE_OFF + 8; // 488

    /// Fixed Transact header length (body after the tag byte, before the two
    /// length-prefixed enc blobs). See `mirror_core::wire::TRANSACT_HEADER_LEN`
    /// for the full documented layout. MUST match it byte-for-byte.
    pub const TRANSACT_HEADER_LEN: usize =
        7 * PUBLIC_INPUT_LEN + PROOF_A_LEN + PROOF_B_LEN + PROOF_C_LEN + 8;

    // --- Opt-in compliance layer (ADDITIVE): AssociationSet + SettleZkAssociated.
    // REDEFINED here for the same reason the rest of this module is, and pinned by
    // the compile-time asserts below in lockstep with `mirror_core::wire`. ---

    /// INIT_ASSOCIATION layout: `[tag(1)]` (no body). The pool and the curator are
    /// both accounts, so nothing needs encoding.
    /// MUST match `mirror_core::wire::INIT_ASSOCIATION_LEN`.
    pub const INIT_ASSOCIATION_LEN: usize = 1;

    /// UPDATE_ASSOCIATION_ROOT layout: `[tag(1)][root(32)]`.
    /// MUST match `mirror_core::wire::UPDATE_ASSOCIATION_ROOT_LEN`.
    pub const UPDATE_ASSOCIATION_ROOT_LEN: usize = 1 + 32;

    /// Number of association public inputs, in the fixed order
    /// [root, nullifierHash, actionHash, epoch, associationRoot]. The first four
    /// are byte-for-byte the membership circuit's, in the same order.
    /// MUST match `mirror_core::wire::ASSOCIATION_N_PUBLIC_INPUTS`.
    pub const ASSOCIATION_N_PUBLIC_INPUTS: usize = 5;

    /// SETTLE_ZK_ASSOCIATED layout (ONE membership per call).
    /// MUST match `mirror_core::wire::SETTLE_ZK_ASSOCIATED_LEN`.
    ///
    /// ```text
    /// [tag(1)][epoch(8 LE)][amount(8 LE)]
    ///   [proof_a(64)][proof_b(128)][proof_c(64)]
    ///   [root(32)][nullifierHash(32)][actionHash(32)][epoch(32 BE)][associationRoot(32)]
    /// ```
    ///
    /// A strict EXTENSION of [`SETTLE_ZK_LEN`]: identical through the first four
    /// public inputs, with `associationRoot` appended.
    pub const SETTLE_ZK_ASSOCIATED_LEN: usize = SETTLE_ZK_LEN + PUBLIC_INPUT_LEN;

    // --- Digest-pinned verifying-key registry (ADDITIVE). REDEFINED here for the
    // same reason the rest of this module is, and pinned by the compile-time
    // asserts below in lockstep with `mirror_core::wire`. ---

    /// Circuit ids. One registry PDA per id (seeds `["vk", circuit_id]`), each
    /// holding exactly the key whose digest this program pins at compile time.
    /// MUST match `mirror_core::wire::CIRCUIT_*`.
    pub const CIRCUIT_MEMBERSHIP: u8 = 0;
    pub const CIRCUIT_TRANSACTION: u8 = 1;
    pub const CIRCUIT_ASSOCIATION: u8 = 2;

    /// Byte offsets inside the CANONICAL verifying-key encoding, the single
    /// serialization the digest is taken over and the registry account stores:
    ///
    /// ```text
    /// [nr_pubinputs(1)][alpha_g1(64)][beta_g2(128)][gamma_g2(128)][delta_g2(128)]
    ///   [ic(64 * (nr_pubinputs + 1))]
    /// ```
    ///
    /// Big-endian, uncompressed, byte-identical to the `groth16-solana` in-memory
    /// layout. MUST match `mirror_core::wire::VK_*`.
    pub const VK_NR_PUBINPUTS_OFF: usize = 0;
    pub const VK_ALPHA_G1_OFF: usize = 1;
    pub const VK_BETA_G2_OFF: usize = VK_ALPHA_G1_OFF + G1_LEN;
    pub const VK_GAMMA_G2_OFF: usize = VK_BETA_G2_OFF + G2_LEN;
    pub const VK_DELTA_G2_OFF: usize = VK_GAMMA_G2_OFF + G2_LEN;
    pub const VK_IC_OFF: usize = VK_DELTA_G2_OFF + G2_LEN;

    /// One uncompressed G1 point (`x || y`).
    pub const G1_LEN: usize = 64;
    /// One uncompressed G2 point (`x_c1 || x_c0 || y_c1 || y_c0`).
    pub const G2_LEN: usize = 128;

    /// Largest public-input count any pinned circuit uses (the JoinSplit's 7).
    /// Bounds the fixed-size decode buffer, so the decoder never allocates and
    /// never sizes anything from untrusted account data.
    pub const VK_MAX_PUBLIC_INPUTS: usize = 7;
    /// Largest IC vector (`nr_pubinputs + 1`).
    pub const VK_MAX_IC: usize = VK_MAX_PUBLIC_INPUTS + 1;

    /// Length of the canonical encoding for a key with `nr_pubinputs` inputs.
    /// MUST match `mirror_core::wire::vk_encoded_len`.
    pub const fn vk_encoded_len(nr_pubinputs: usize) -> usize {
        VK_IC_OFF + G1_LEN * (nr_pubinputs + 1)
    }

    /// Longest canonical encoding across the pinned circuits.
    pub const VK_MAX_ENCODED_LEN: usize = vk_encoded_len(VK_MAX_PUBLIC_INPUTS);

    // --- Opt-in disclosure layer (ADDITIVE): on-chain viewing keys + sealed
    // disclosure records. REDEFINED here for the same reason the rest of this
    // module is, and pinned by the compile-time asserts below in lockstep with
    // `mirror_core::wire`. ---

    /// REGISTER_VIEWING_KEY layout: `[tag(1)][viewing_pub(32)]`. The authority and
    /// the rent payer are both accounts, so the body is just the key.
    /// MUST match `mirror_core::wire::REGISTER_VIEWING_KEY_LEN`.
    pub const REGISTER_VIEWING_KEY_LEN: usize = 1 + 32;

    /// The one sealed blob a disclosure record carries: exactly one
    /// `mirror_core::encrypted_note` ciphertext,
    /// `ephemeral_pub(32) || nonce(12) || ct+tag(56)`. Any other length is
    /// malformed. MUST match `mirror_core::wire::DISCLOSURE_BLOB_LEN` (and
    /// therefore `mirror_core::encrypted_note::ENC_NOTE_BLOB_LEN`).
    pub const DISCLOSURE_BLOB_LEN: usize = 100;

    /// PUBLISH_DISCLOSURE layout: `[tag(1)][amount(8 LE)][blob(100)]`.
    ///
    /// `amount` is the settled action's public amount; with the SIGNING recipient
    /// it is what the handler's on-chain Poseidon recomputation turns into the
    /// record's own address. MUST match
    /// `mirror_core::wire::PUBLISH_DISCLOSURE_LEN`.
    pub const PUBLISH_DISCLOSURE_LEN: usize = 1 + 8 + DISCLOSURE_BLOB_LEN;

    /// INIT_VK layout: `[tag(1)][circuit_id(1)][vk(vk_encoded_len(n))]`, where
    /// `n` is the circuit's pinned public-input count. The body length is
    /// therefore fixed per circuit, and any other length is malformed.
    /// MUST match `mirror_core::wire::INIT_VK_HEADER_LEN`.
    pub const INIT_VK_HEADER_LEN: usize = 1 + 1;

    /// Hard upper bound on nullifiers per SETTLE_EPOCH call. Bounds the
    /// `n * 32` length arithmetic (no overflow) and keeps a single settle
    /// inside transaction and compute limits. Larger epochs settle in
    /// multiple calls; TODO(v1): make multi-call settlement atomic per epoch.
    pub const MAX_SETTLE_NULLIFIERS: usize = 32;

    // Layout sanity: keep the documented sizes honest at compile time.
    const _: () = assert!(COMMIT_LEN == 33);
    const _: () = assert!(SETTLE_HEADER_LEN == 13);
    const _: () = assert!(INIT_POOL_LEN == 31);
    const _: () = assert!(COMMIT_DEPOSIT_LEN == 41);
    const _: () = assert!(SETTLE_ZK_LEN == 401);
    const _: () = assert!(CLAIM_REWARD_LEN == 1);
    const _: () = assert!(
        SETTLE_ZK_LEN == 1 + 8 + 8 + PROOF_A_LEN + PROOF_B_LEN + PROOF_C_LEN + 4 * PUBLIC_INPUT_LEN
    );
    // Confidential-value layer: pin the Transact / ValuePool sizes in lockstep
    // with `mirror_core::wire` (which asserts the same numbers).
    const _: () = assert!(INIT_VALUE_POOL_LEN == 18);
    const _: () = assert!(TRANSACT_HEADER_LEN == 488);
    const _: () = assert!(TRANSACT_ENC_OFF == TRANSACT_HEADER_LEN);
    const _: () = assert!(TRANSACT_PROOF_B_OFF == 288);
    const _: () = assert!(TRANSACT_PROOF_C_OFF == 416);
    const _: () = assert!(TRANSACT_FEE_OFF == 480);
    const _: () = assert!(TRANSACT_N_PUBLIC_INPUTS == 7);
    // Opt-in compliance layer: pin the association sizes in lockstep with
    // `mirror_core::wire` (which asserts the same numbers).
    const _: () = assert!(INIT_ASSOCIATION_LEN == 1);
    const _: () = assert!(UPDATE_ASSOCIATION_ROOT_LEN == 33);
    const _: () = assert!(ASSOCIATION_N_PUBLIC_INPUTS == 5);
    const _: () = assert!(SETTLE_ZK_ASSOCIATED_LEN == 433);
    // Digest-pinned VK registry: pin the canonical encoding sizes in lockstep
    // with `mirror_core::wire` (which asserts the same numbers). The 769 is the
    // membership key's encoding; a blob of any other length is rejected on shape
    // alone, before the digest is even computed.
    const _: () = assert!(VK_IC_OFF == 449);
    const _: () = assert!(vk_encoded_len(4) == 769);
    const _: () = assert!(vk_encoded_len(5) == 833);
    const _: () = assert!(vk_encoded_len(7) == 961);
    const _: () = assert!(VK_MAX_ENCODED_LEN == 961);
    const _: () = assert!(INIT_VK_HEADER_LEN == 2);
    // Opt-in disclosure layer: pin the sizes in lockstep with `mirror_core::wire`
    // (which asserts the same numbers, and additionally asserts that
    // DISCLOSURE_BLOB_LEN is the encrypted-note blob length).
    const _: () = assert!(REGISTER_VIEWING_KEY_LEN == 33);
    const _: () = assert!(DISCLOSURE_BLOB_LEN == 100);
    const _: () = assert!(PUBLISH_DISCLOSURE_LEN == 109);
    const _: () = assert!(
        SETTLE_ZK_ASSOCIATED_LEN
            == 1 + 8
                + 8
                + PROOF_A_LEN
                + PROOF_B_LEN
                + PROOF_C_LEN
                + ASSOCIATION_N_PUBLIC_INPUTS * PUBLIC_INPUT_LEN
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
    /// TRANSACT: the recomputed `extDataHash` (keccak256 over
    /// `recipient || relayer || fee_be || enc0 || enc1`, reduced mod r) does not
    /// equal the proof's `extDataHash` public input, i.e. the relay tampered with
    /// the recipient, relayer, fee, or an encrypted payload. Fail closed.
    ExtDataMismatch = 18,
    /// TRANSACT: the `publicAmount` public input is in neither the deposit range
    /// `[0, 2^248)` nor the withdraw range `(r - 2^248, r)`, or its decoded
    /// magnitude does not fit a `u64`. Not a representable signed token amount.
    InvalidPublicAmount = 19,
    /// TRANSACT: the value vault does not hold enough lamports to pay the decoded
    /// withdraw amount while staying rent-exempt. Never drain below rent.
    InsufficientVault = 20,
    /// INIT_VALUE_POOL on a ValuePool account that is already configured.
    ValuePoolAlreadyInitialized = 21,
    /// The referenced ValuePool account has not been initialized.
    ValuePoolNotInitialized = 22,
    /// A fixed-denomination pool was handed an off-denomination amount.
    ///
    /// Two callers raise it. TRANSACT: the ValuePool pins a denomination
    /// (`denomination = Some(d)`) and the public deposit/withdraw magnitude is
    /// not exactly `d` (internal transfers, `publicAmount == 0`, move no public
    /// value and are exempt). COMMIT_DEPOSIT / SETTLE_ZK / SETTLE_ZK_ASSOCIATED:
    /// the behavioral Pool's `zk_denomination` is the ONE escrow size the ZK
    /// opt-in path accepts, and the settled `amount` must be exactly it.
    ///
    /// Fixed denominations buy amount k-anonymity - every value crossing the
    /// boundary is byte-identical, so amounts cannot single out a participant -
    /// and, on the behavioral pool, they are also the SOUNDNESS control that caps
    /// a settle at what its leaf escrowed: nothing on-chain can read the amount a
    /// leaf's `actionHash` bound, so the only way to keep the two equal is to
    /// admit exactly one size on both sides. Fail closed: the check runs before
    /// the Groth16 proof is verified, so a mismatch is rejected with no state
    /// change.
    DenominationMismatch = 23,
    /// INIT_ASSOCIATION on an AssociationSet PDA that is already registered.
    AssociationAlreadyInitialized = 24,
    /// The referenced AssociationSet account has not been registered, is not
    /// program-owned, or does not parse as an association set.
    AssociationNotInitialized = 25,
    /// SETTLE_ZK_ASSOCIATED: the passed AssociationSet curates a DIFFERENT pool
    /// than the one being settled. Fail closed: a curator's attestation is scoped
    /// to the pool it registered against and must not be reusable across pools.
    AssociationPoolMismatch = 26,
    /// SETTLE_ZK_ASSOCIATED: the proof's `associationRoot` is not in the
    /// AssociationSet's recent-root ring. Either the curator never published it,
    /// or it has aged out behind newer publications. Fail closed: no nullifier is
    /// created and no escrow moves.
    AssociationRootNotKnown = 27,
    /// INIT_VK on a verifying-key registry PDA that is already written. The
    /// registry is WRITE-ONCE: there is no update instruction, and re-running
    /// init over a live account fails here rather than overwriting the key.
    VkRegistryAlreadyInitialized = 28,
    /// A verify path was handed a verifying-key registry account that is missing,
    /// not program-owned, not the canonical registry PDA for the circuit it
    /// claims, the wrong size, or not a v1 registry. Fail closed: no proof is
    /// verified against an account this program cannot vouch for.
    VkRegistryNotInitialized = 29,
    /// The verifying key does not hash to the digest this program pins at compile
    /// time for that circuit. This is the check that makes the registry safe:
    /// an arbitrary key blob (including a well-formed one whose trapdoor the
    /// submitter holds) can be neither installed at INIT_VK nor used at verify.
    /// Also returned for an unknown circuit id, which is pinned to nothing.
    VkNotApproved = 30,
    /// A 32-byte X25519 public key handed to the disclosure layer failed the
    /// structural test in `state::viewing_key::is_acceptable_viewing_pub`: a
    /// non-canonical encoding (top bit set, or a value `>= p`, both of which alias
    /// to another encoding of the same key and would make a key-derived PDA
    /// malleable) or a small-order point (whose ECDH output is independent of the
    /// peer's secret, so anything "sealed" to it is public). Raised by
    /// REGISTER_VIEWING_KEY for the key being registered, and by
    /// PUBLISH_DISCLOSURE for the key it re-reads from the registry account.
    InvalidViewingKey = 31,
    /// PUBLISH_DISCLOSURE was handed a viewing-key account that is missing, not
    /// program-owned, the wrong size, not a v1 registration, or not the canonical
    /// `["view", authority]` PDA for the authority it stores. Fail closed: a
    /// disclosure is never sealed to a key this program cannot attribute.
    ViewingKeyNotInitialized = 32,
    /// PUBLISH_DISCLOSURE on a Disclosure PDA that already holds a record. The
    /// record is WRITE-ONCE: there is no update and no close instruction, so a
    /// published disclosure cannot be rewritten by its publisher afterwards.
    DisclosureAlreadyInitialized = 33,
    /// PUBLISH_DISCLOSURE: the sealed blob failed structural validation - its
    /// ephemeral X25519 public key is non-canonical or small-order, which is the
    /// case where a user believes they sealed to one reader but every reader can
    /// open it. The program cannot check more than the blob's SHAPE (it holds no
    /// secret and cannot decrypt); what it cannot check is stated in
    /// `state::disclosure` and `docs/COMPLIANCE.md`.
    InvalidDisclosureBlob = 34,
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
