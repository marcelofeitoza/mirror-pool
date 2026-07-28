//! On-chain `actionHash` derivation for the ZK opt-in settlement action.
//!
//! The v1 opt-in action is "transfer `amount` lamports to `recipient`", where
//! clients bind a freshly generated address (a convention the program cannot
//! check; see the `settle_zk` module header). `actionHash` binds BOTH the
//! recipient and the amount so the settling relay cannot redirect the escrow,
//! and it is the value the membership proof commits to as a public input:
//!
//! ```text
//! actionHash = Poseidon(recipientHi128, recipientLo128, amount)
//! ```
//!
//! The 32-byte `recipient` is split into two big-endian 128-bit halves (each
//! < 2^128 < r, so both are canonical BN254 scalars: no modular reduction is
//! needed and no collision resistance is lost), and `amount` is the `u64` as a
//! field element. This is computed with circomlib Poseidon over BN254 via the
//! `sol_poseidon` syscall, byte-identical to `mirror_core::transfer_action_hash`
//! on the host and to the value the CLI prover feeds the circuit. The on-chain
//! SETTLE_ZK handler recomputes this and requires it to equal the proof's
//! `actionHash` public input.

/// circomlib Poseidon of three 32-byte big-endian BN254 field elements.
///
/// Each input must be a canonical big-endian field element (< r); every value
/// [`transfer_action_hash`] passes satisfies that (two 128-bit halves and a
/// `u64`). Uses the same syscall parameters as the Merkle accumulator's
/// `hash_pair`, so the Poseidon instance matches the circuit and `light-poseidon`
/// on the host.
#[cfg(any(target_os = "solana", target_arch = "bpf"))]
#[inline(always)]
fn poseidon3(a: &[u8; 32], b: &[u8; 32], c: &[u8; 32]) -> [u8; 32] {
    // parameters = 0 -> Parameters::Bn254X5 (circomlib BN254)
    // endianness = 0 -> Endianness::BigEndian (matches circom / groth16-solana)
    const BN254X5: u64 = 0;
    const BIG_ENDIAN: u64 = 0;
    let chunks: [&[u8]; 3] = [a, b, c];
    let mut out = [0u8; 32];
    unsafe {
        pinocchio::syscalls::sol_poseidon(
            BN254X5,
            BIG_ENDIAN,
            chunks.as_ptr() as *const u8,
            chunks.len() as u64,
            out.as_mut_ptr(),
        );
    }
    out
}

#[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
#[inline(always)]
fn poseidon3(_a: &[u8; 32], _b: &[u8; 32], _c: &[u8; 32]) -> [u8; 32] {
    unreachable!("Poseidon hashing uses an on-chain syscall and never runs on the host")
}

/// `actionHash = Poseidon(recipientHi128, recipientLo128, amount)`.
///
/// Byte-identical to `mirror_core::transfer_action_hash(recipient, amount)`.
pub fn transfer_action_hash(recipient: &[u8; 32], amount: u64) -> [u8; 32] {
    let mut hi = [0u8; 32];
    hi[16..].copy_from_slice(&recipient[0..16]);
    let mut lo = [0u8; 32];
    lo[16..].copy_from_slice(&recipient[16..32]);
    let mut amt = [0u8; 32];
    amt[24..].copy_from_slice(&amount.to_be_bytes());
    poseidon3(&hi, &lo, &amt)
}
