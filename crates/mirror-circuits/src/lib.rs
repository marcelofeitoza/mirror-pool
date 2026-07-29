//! An arkworks-native path for every circuit in this repo, alongside the circom
//! one.
//!
//! # The toolchain question this answers
//!
//! Proving in this repo is already pure Rust: `ark-circom` runs the compiled
//! witness calculator in-process under `wasmer` and `ark-groth16` produces the
//! proof, so no Node process is spawned at runtime. What remains circom-shaped is
//! everything UPSTREAM of that: the circuit is `.circom` source, so producing the
//! `.r1cs` / `.wasm` / `.zkey` artifacts and running the trusted setup needs
//! `circom`, `snarkjs`, `node` and `npm`. Those four are still in the build and
//! supply chain.
//!
//! This crate removes them for ALL THREE circuits: behavioral membership, the
//! confidential-value JoinSplit, and the opt-in association statement. The
//! constraint systems, the Poseidon gadget, the setups and the proofs are Rust;
//! the only inputs are crates already in the lockfile. `cargo test -p
//! mirror-circuits` generates keys and proofs and checks them with the same
//! `groth16-solana` verifier the on-chain program links, with no circom artifact
//! of any kind on disk.
//!
//! # What it does NOT do
//!
//! - It does not replace the deployed circuits. The circom membership and
//!   JoinSplit circuits, their committed verifying keys, and the digests the
//!   program pins are untouched. Same statements, different constraint systems,
//!   therefore different keys: an arkworks proof is NOT accepted by the deployed
//!   program, and could only be by pinning a second digest in a program upgrade.
//! - It is not a ceremony. [`setup`] is single-party.
//!
//! # Layout
//!
//! - [`poseidon`] - the in-circuit Poseidon gadget and the native reference.
//! - `gadgets` (internal) - the non-hash circomlib gadgets (`Num2Bits`,
//!   `Switcher`, `ForceEqualIfEnabled`) the JoinSplit needs, at circom's cost.
//! - [`membership`] - the behavioral statement: depth-20 Merkle inclusion,
//!   epoch-scoped nullifier, action binding, 4 public inputs.
//! - [`transaction`] - the confidential-value statement: a 2-in / 2-out
//!   JoinSplit with note commitments, owner-and-leaf-bound nullifiers, value
//!   conservation, 248-bit range proofs and the `extDataHash` binding, 7 public
//!   inputs.
//! - [`association`] - the opt-in compliance statement: everything `membership`
//!   proves, plus a second inclusion of the SAME commitment under a curator's
//!   published root, 5 public inputs. Its membership half is not a copy - it
//!   calls the same path-walking helpers `membership` does.
//! - [`setup`] - Groth16 setup / prove / verify and constraint accounting for
//!   all three circuits.
//! - [`onchain`] - the `groth16-solana` byte encodings, reusing the exporters
//!   the ceremony crate already owns.
//!
//! `docs/ARKWORKS.md` records the measured comparison against the committed
//! circom `.r1cs` files and states exactly what the cross-checks do and do not
//! prove.

pub mod association;
pub mod membership;
pub mod onchain;
pub mod poseidon;
pub mod setup;
pub mod transaction;

pub(crate) mod gadgets;

pub use association::{AssociationCircuit, AssociationWitness};
pub use membership::{MembershipCircuit, MembershipWitness, DEPTH, N_PUBLIC_INPUTS};
pub use poseidon::{hash_native, hash_var};
pub use transaction::{InputNote, OutputNote, TransactionCircuit, TransactionWitness};
