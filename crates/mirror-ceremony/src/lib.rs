//! A distributable multi-party Groth16 **phase-2** trusted-setup ceremony for the
//! mirror-pool circuits.
//!
//! # What this is
//!
//! Groth16 needs a per-circuit structured reference string. It is produced in two
//! phases:
//!
//! - **Phase 1** (universal, circuit-independent "powers of tau"). mirror-pool does
//!   NOT run its own phase 1. It imports a PUBLIC one - the perpetual
//!   powers-of-tau, whose contribution list is recorded in the file itself and can
//!   be read back with [`ptau::read_provenance`].
//! - **Phase 2** (per circuit). This crate. Starting from the phase-1-derived
//!   initial proving key, every contributor multiplies the secret `delta` by a
//!   fresh scalar they alone know and then destroy. The final key is safe as long
//!   as **at least one** contributor was honest (1-of-N), because `delta` is the
//!   product of every contribution.
//!
//! # What a contribution does
//!
//! A phase-2 contribution re-randomizes `delta` with a scalar `s`. To keep the
//! proving key valid for the *same* circuit, every place `delta` appears must move
//! together:
//!
//! ```text
//! delta_g1' = delta_g1 * s          l_query'[i] = l_query[i] * s^-1
//! delta_g2' = delta_g2 * s          h_query'[i] = h_query[i] * s^-1
//! ```
//!
//! and nothing else changes: `alpha_g1`, `beta_g1`, `beta_g2`, `gamma_g2`,
//! `gamma_abc_g1`, `a_query`, `b_g1_query` and `b_g2_query` are byte-identical from
//! the initial key to the final key. `l_query` / `h_query` are exactly the parts of
//! the key that are divided by `delta`, so scaling them by `s^-1` cancels the `s`
//! introduced in `delta_g1` / `delta_g2` and the pairing equation is preserved.
//!
//! # What binds a contribution to its contributor
//!
//! Each contribution carries a Schnorr proof of knowledge of `s` with respect to
//! the base `delta_g1` of the PREVIOUS key ([`pok`]). Its Fiat-Shamir challenge
//! commits to the running transcript hash, the contribution index and the
//! contributor identifier, so a proof cannot be replayed at another position in the
//! chain or re-attributed to a different operator. The PoK is what stops a
//! contributor from "contributing" a value they do not know the discrete log of
//! (which would let them cancel an honest contributor's randomness).
//!
//! # What verification checks
//!
//! [`verify::verify`] recomputes the entire chain from the initial key to the final
//! key and rejects, among other things: a tampered delta, a forged or replayed PoK,
//! a reordered chain, and a truncated chain. See that module for the full list.
//!
//! # What this does NOT give you
//!
//! - It does not make a ceremony trustworthy by itself. 1-of-N honest means you
//!   need a reason to believe at least one contributor destroyed their `s`.
//! - [`independence`] counts *independent* contributors with a deliberately
//!   conservative heuristic. It refuses to count self-runs, but it is NOT a Sybil
//!   defence: contributor identifiers are self-asserted.
//! - The beacon ([`beacon`]) removes the last contributor's ability to grind the
//!   final key. It adds no secrecy, so it is never counted as an independent
//!   contributor.

pub mod beacon;
pub mod contribute;
pub mod error;
pub mod hexfmt;
pub mod independence;
pub mod key;
pub mod points;
pub mod pok;
pub mod ptau;
pub mod session;
pub mod transcript;
pub mod verify;
pub mod vk_export;

pub use error::CeremonyError;
pub use key::CeremonyKey;
pub use session::Session;
pub use transcript::{ContributionKind, ContributionRecord, EntropySource, Provenance, Transcript};

/// Result alias for the whole crate.
pub type Result<T> = std::result::Result<T, CeremonyError>;
