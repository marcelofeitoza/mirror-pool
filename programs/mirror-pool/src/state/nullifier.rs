//! Nullifier account: anti-replay by existence.
//!
//! One PDA per (pool, epoch, nullifier) at seeds
//! `[b"nf", pool, epoch_id LE, nullifier]`. The account carries a single marker
//! byte; its *existence* (program-owned) is what marks the nullifier spent.
//! Creating it a second time is impossible (the runtime rejects re-creating a
//! live account), so a double-spend within an epoch fails closed. Scoping the
//! seed by epoch means the same secret yields a fresh, unlinkable nullifier in a
//! later epoch while staying single-use within its own.

/// Account size: a single marker byte (`SPENT`).
pub const LEN: usize = 1;

/// Written into the one data byte when the PDA is created.
pub const SPENT: u8 = 1;
