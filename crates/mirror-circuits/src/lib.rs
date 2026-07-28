//! An arkworks-native path for the membership circuit, alongside the circom one.
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
//! This crate removes them for ONE circuit. The constraint system, the Poseidon
//! gadget, the setup and the proof are Rust; the only inputs are crates already
//! in the lockfile. `cargo test -p mirror-circuits` generates a key and a proof
//! and checks it with the same `groth16-solana` verifier the on-chain program
//! links, with no circom artifact of any kind on disk.
//!
//! # What it does NOT do
//!
//! - It does not replace the deployed circuit. The circom membership circuit,
//!   its committed verifying key, and the digest the program pins are untouched.
//!   Same statement, different constraint system, therefore a different key: an
//!   arkworks proof is NOT accepted by the deployed program, and could only be
//!   by pinning a second digest in a program upgrade.
//! - It does not cover the confidential-value JoinSplit circuit.
//! - It is not a ceremony. [`setup`] is single-party.
//!
//! # Layout
//!
//! - [`poseidon`] - the in-circuit Poseidon gadget and the native reference.
//! - [`membership`] - the statement: depth-20 Merkle inclusion, epoch-scoped
//!   nullifier, action binding, 4 public inputs.
//! - [`setup`] - Groth16 setup / prove / verify and constraint accounting.
//! - [`onchain`] - the `groth16-solana` byte encodings, reusing the exporters
//!   the ceremony crate already owns.
//!
//! `docs/ARKWORKS.md` records the measured comparison against the committed
//! circom `.r1cs` and states exactly what the cross-checks do and do not prove.

pub mod membership;
pub mod onchain;
pub mod poseidon;
pub mod setup;

pub use membership::{MembershipCircuit, MembershipWitness, DEPTH, N_PUBLIC_INPUTS};
pub use poseidon::{hash_native, hash_var};
