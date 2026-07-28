//! TRANSACT: settle one confidential-value 2-in/2-out JoinSplit.
//!
//! This is the value-carrying, Tornado-Nova-style settlement (the counterpart to
//! the behavioral `SETTLE_ZK`). A single universal statement covers three
//! operations, distinguished only by the signed `publicAmount`:
//!
//! - **shield** (deposit): `publicAmount = +v`, dummy inputs. Lamports move
//!   depositor -> vault.
//! - **transfer**: `publicAmount = 0`, real inputs and outputs. No lamports move.
//! - **unshield** (withdraw): `publicAmount = r - v`. Lamports move vault ->
//!   recipient.
//!
//! The membership + balance proof (Groth16 over `circuits/transaction.circom`) is
//! verified on-chain with `groth16-solana` against the vendored transaction
//! verifying key (`src/transaction_vk.rs`).
//!
//! Body layout after the tag byte (see `wire::TRANSACT_HEADER_LEN` and the
//! `wire::TRANSACT_*_OFF` offsets):
//!
//! ```text
//! [publicAmount(32)][extDataHash(32)][root(32)]
//!   [inputNullifier[0](32)][inputNullifier[1](32)]
//!   [outputCommitment[0](32)][outputCommitment[1](32)]
//!   [proof_a(64)][proof_b(128)][proof_c(64)]
//!   [fee(8 LE)]
//!   [enc0_len(2 LE)][enc0 bytes][enc1_len(2 LE)][enc1 bytes]
//! ```
//!
//! Accounts:
//!
//! ```text
//! 0. vpool          writable   initialized ValuePool PDA (its own accumulator)
//! 1. authority      signer     writable; MUST equal vpool.authority; pays nf rent
//! 2. nullifier0     writable   value nullifier PDA to create (anti-replay);
//!                              seeds [b"vnf", vpool, inputNullifier[0]]
//! 3. nullifier1     writable   value nullifier PDA to create; seeds as above
//! 4. recipient      writable   withdraw output address; credited on unshield
//! 5. depositor      signer     writable; funds the shield deposit
//! 6. system_program            for the create-account / transfer CPIs
//! 7. clock          sysvar     (accepted for wire stability; unused here)
//! 8. vault          writable   ValuePool vault PDA; seeds [b"vvault", vpool]
//! 9. vk_registry    readonly   write-once, digest-pinned JoinSplit verifying
//!                              key; seeds [b"vk", CIRCUIT_TRANSACTION]
//! ```
//!
//! # Where the verifying key comes from
//!
//! Account 9, not this program's `.rodata`. It is a program-owned PDA that
//! `INIT_VK` filled ONCE and that no instruction can rewrite, and step (5)
//! re-checks its SHA-256 against [`crate::vk_digest::TRANSACTION_VK_SHA256`]
//! before the bytes reach the verifier. See `docs/VK_REGISTRY.md`.
//!
//! Checks run IN ORDER and fail closed: (1) authority is a signer and equals
//! vpool.authority; (2) `root` is a known recent root; (3) the recomputed
//! `extDataHash` from (recipient, authority/relayer, fee, enc0, enc1) equals the
//! proof's `extDataHash`; (4) create each input nullifier PDA (an all-zero dummy
//! sentinel is skipped; `NullifierSpent` on replay); (5) the Groth16 proof
//! verifies against the 7 public inputs in the fixed order; (6) both output
//! commitments are inserted into the value accumulator; (7) lamports move per the
//! decoded `publicAmount`, keeping the vault rent-exempt; (8) enc0/enc1 are
//! emitted as return data for client discovery.

use pinocchio::{
    cpi::Seed,
    error::ProgramError,
    sysvars::{rent::Rent, Sysvar},
    AccountView, Address, ProgramResult,
};
use pinocchio_log::log;
use pinocchio_system::instructions::Transfer;

use crate::{
    pda,
    state::{nullifier, value_pool, vk_registry},
    wire, MirrorPoolError,
};

/// BN254 scalar-field modulus r, canonical big-endian. `extDataHash` is
/// `keccak256(...) mod r`, and a withdraw `publicAmount` is `r - v`; both need
/// this constant for the on-chain reduction / negation.
const R_BE: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

/// The net public value crossing the shielded boundary, decoded from
/// `publicAmount` with the FIELD_SIZE offset (mirrors
/// `mirror_core::note::SignedAmount`).
#[derive(Clone, Copy)]
enum SignedAmount {
    /// transfer: no public value moves.
    Transfer,
    /// shield / deposit of `v` lamports into the vault.
    Deposit(u64),
    /// unshield / withdraw of `v` lamports out of the vault.
    Withdraw(u64),
}

pub fn process(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    // (0) Fail closed on shape. The fixed header plus the two u16 length
    // prefixes (both blobs may be empty) is the minimum well-formed body.
    if data.len() < wire::TRANSACT_HEADER_LEN + 4 {
        return Err(MirrorPoolError::MalformedInstruction.into());
    }

    let public_amount = read32(data, wire::TRANSACT_PUBLIC_AMOUNT_OFF)?;
    let ext_data_hash = read32(data, wire::TRANSACT_EXT_DATA_HASH_OFF)?;
    let root = read32(data, wire::TRANSACT_ROOT_OFF)?;
    let in_nullifier0 = read32(data, wire::TRANSACT_IN_NULLIFIER0_OFF)?;
    let in_nullifier1 = read32(data, wire::TRANSACT_IN_NULLIFIER1_OFF)?;
    let out_commitment0 = read32(data, wire::TRANSACT_OUT_COMMIT0_OFF)?;
    let out_commitment1 = read32(data, wire::TRANSACT_OUT_COMMIT1_OFF)?;
    let proof_a: [u8; 64] = data[wire::TRANSACT_PROOF_A_OFF..wire::TRANSACT_PROOF_B_OFF]
        .try_into()
        .map_err(|_| MirrorPoolError::MalformedInstruction)?;
    let proof_b: [u8; 128] = data[wire::TRANSACT_PROOF_B_OFF..wire::TRANSACT_PROOF_C_OFF]
        .try_into()
        .map_err(|_| MirrorPoolError::MalformedInstruction)?;
    let proof_c: [u8; 64] = data[wire::TRANSACT_PROOF_C_OFF..wire::TRANSACT_FEE_OFF]
        .try_into()
        .map_err(|_| MirrorPoolError::MalformedInstruction)?;
    let fee = u64::from_le_bytes(
        data[wire::TRANSACT_FEE_OFF..wire::TRANSACT_ENC_OFF]
            .try_into()
            .map_err(|_| MirrorPoolError::MalformedInstruction)?,
    );

    // Two length-prefixed, bounded encrypted-note blobs. Exact consumption: the
    // parse must land on the end of the data, no trailing bytes.
    let (enc0, off) = read_blob(data, wire::TRANSACT_ENC_OFF)?;
    let (enc1, off) = read_blob(data, off)?;
    if off != data.len() {
        return Err(MirrorPoolError::MalformedInstruction.into());
    }

    let [vpool_account, authority, nullifier0, nullifier1, recipient, depositor, _system_program, _clock, vault, vk_account, ..] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // (1) Authority must be a signer AND equal the ValuePool's stored authority.
    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !vpool_account.is_writable()
        || !authority.is_writable()
        || !nullifier0.is_writable()
        || !nullifier1.is_writable()
        || !recipient.is_writable()
        || !vault.is_writable()
    {
        return Err(ProgramError::InvalidAccountData);
    }
    if !vpool_account.owned_by(program_id) {
        return Err(MirrorPoolError::ValuePoolNotInitialized.into());
    }

    // ValuePool integrity + authority binding + (2) known-root + fixed
    // denomination, in one borrow.
    let denomination = {
        let vpool_data = vpool_account.try_borrow()?;
        if vpool_data.len() != value_pool::LEN || !value_pool::is_initialized(&vpool_data)? {
            return Err(MirrorPoolError::ValuePoolNotInitialized.into());
        }
        if &value_pool::authority(&vpool_data)? != authority.address().as_array() {
            return Err(MirrorPoolError::Unauthorized.into());
        }
        // (2) The proof's root must be a known recent root.
        if !value_pool::is_known_root(&vpool_data, &root)? {
            return Err(MirrorPoolError::RootNotKnown.into());
        }
        value_pool::denomination(&vpool_data)?
    };

    // (2b) Fixed-denomination enforcement (Level 1 amount privacy). Decode the
    // signed publicAmount once and reuse the result for the lamport move below.
    // When the pool pins a denomination, every PUBLIC deposit/withdraw must move
    // exactly that amount, so all public value crossings are byte-identical and an
    // amount cannot single out a participant (amount k-anonymity). Internal
    // transfers (publicAmount == 0) move no public value and are always allowed.
    //
    // Check order: this runs BEFORE the ext-data recompute, before any input
    // nullifier PDA is created, and before the expensive Groth16 verification, so a
    // denomination mismatch is rejected cheaply and fail-closed with NO state
    // change. When `denomination` is `None` the behavior is unchanged (arbitrary
    // amounts). Decoding here also fails an out-of-range publicAmount before any
    // state change (a strict superset of the pre-existing decode below).
    let signed_amount = decode_public_amount(&public_amount)?;
    if let Some(d) = denomination {
        match signed_amount {
            SignedAmount::Transfer => {}
            SignedAmount::Deposit(v) | SignedAmount::Withdraw(v) => {
                if v != d {
                    return Err(MirrorPoolError::DenominationMismatch.into());
                }
            }
        }
    }

    // Verify the vault PDA and its program ownership (needed for any lamport move
    // and to keep a wrong vault from being substituted).
    let vpool_key = vpool_account.address();
    pda::verify_pda(
        vault,
        &[pda::VALUE_VAULT_SEED, vpool_key.as_ref()],
        program_id,
    )?;
    if !vault.owned_by(program_id) {
        return Err(MirrorPoolError::ValuePoolNotInitialized.into());
    }

    // (3) ext-data binding: recompute extDataHash = keccak256(recipient ||
    // relayer(authority) || fee_be || enc0 || enc1) mod r and require it equals
    // the proof's extDataHash public input, so the relay cannot tamper with the
    // recipient, relayer, fee, or encrypted payloads.
    let fee_be = fee.to_be_bytes();
    let recomputed = ext_data_hash_keccak(
        recipient.address().as_array(),
        authority.address().as_array(),
        &fee_be,
        enc0,
        enc1,
    );
    if recomputed != ext_data_hash {
        return Err(MirrorPoolError::ExtDataMismatch.into());
    }

    // (4) Anti-replay: create each input nullifier PDA (an all-zero dummy
    // sentinel is skipped). The circuit forbids `inputNullifier[0] ==
    // inputNullifier[1]`, and dummy inputs still carry distinct, non-zero
    // nullifiers, so both real and dummy nullifiers are marked spent.
    spend_value_nullifier(program_id, vpool_key, authority, nullifier0, &in_nullifier0)?;
    spend_value_nullifier(program_id, vpool_key, authority, nullifier1, &in_nullifier1)?;

    // (5) Verify the Groth16 proof against the fixed public-input order
    // [root, publicAmount, extDataHash, inNullifier0, inNullifier1,
    // outCommitment0, outCommitment1]. `verify()` also rejects any public input
    // that is not a canonical BN254 scalar.
    //
    // The JoinSplit verifying key is READ FROM THE CHAIN, not from this
    // program's code: `verify_pinned` loads the write-once VkRegistry PDA for
    // CIRCUIT_TRANSACTION and re-checks its SHA-256 against the digest pinned in
    // `crate::vk_digest` before the key touches the verifier. This is the path
    // that moves value, so it gets the same treatment as the others: the key in
    // force is publicly readable, and is still exactly the key the bytecode
    // committed to.
    let public_inputs: [[u8; 32]; wire::TRANSACT_N_PUBLIC_INPUTS] = [
        root,
        public_amount,
        ext_data_hash,
        in_nullifier0,
        in_nullifier1,
        out_commitment0,
        out_commitment1,
    ];
    vk_registry::verify_pinned(
        vk_account,
        program_id,
        wire::CIRCUIT_TRANSACTION,
        &proof_a,
        &proof_b,
        &proof_c,
        &public_inputs,
    )?;

    // (6) Insert both output commitments into the value accumulator (updates the
    // root and pushes it to the recent-root ring).
    let new_root = {
        let mut vpool_data = vpool_account.try_borrow_mut()?;
        value_pool::append(&mut vpool_data, &out_commitment0)?;
        value_pool::append(&mut vpool_data, &out_commitment1)?
    };

    // (7) Move lamports per the decoded publicAmount (decoded once above, and
    // already checked against any fixed denomination), keeping the vault
    // rent-exempt. deposit: depositor -> vault; withdraw: vault -> recipient;
    // transfer: nothing.
    match signed_amount {
        SignedAmount::Transfer => {}
        SignedAmount::Deposit(v) => {
            if v > 0 {
                if !depositor.is_signer() {
                    return Err(ProgramError::MissingRequiredSignature);
                }
                if !depositor.is_writable() {
                    return Err(ProgramError::InvalidAccountData);
                }
                Transfer {
                    from: depositor,
                    to: vault,
                    lamports: v,
                }
                .invoke()?;
            }
        }
        SignedAmount::Withdraw(v) => {
            // The vault is program-owned, so move lamports directly (a system
            // transfer only moves lamports out of system-owned accounts).
            let rent_min = Rent::get()?.try_minimum_balance(0)?;
            let vault_balance = vault.lamports();
            let remaining = vault_balance
                .checked_sub(v)
                .ok_or(MirrorPoolError::InsufficientVault)?;
            if remaining < rent_min {
                return Err(MirrorPoolError::InsufficientVault.into());
            }
            let recipient_balance = recipient
                .lamports()
                .checked_add(v)
                .ok_or(MirrorPoolError::ArithmeticOverflow)?;
            vault.set_lamports(remaining);
            recipient.set_lamports(recipient_balance);
        }
    }

    // (8) Emit the encrypted output-note payloads for client discovery.
    emit_enc(enc0, enc1);

    log!(
        "mirror-pool: transact fee={} enc0_len={} enc1_len={} new_root0={}",
        fee,
        enc0.len() as u64,
        enc1.len() as u64,
        new_root[0]
    );
    Ok(())
}

/// Read a fixed 32-byte field at `offset` (caller has range-checked the header).
#[inline]
fn read32(data: &[u8], offset: usize) -> Result<[u8; 32], ProgramError> {
    data.get(offset..offset + 32)
        .ok_or(MirrorPoolError::MalformedInstruction)?
        .try_into()
        .map_err(|_| MirrorPoolError::MalformedInstruction.into())
}

/// Read one length-prefixed, bounded blob at `offset`: `[len: u16 LE][bytes]`.
/// Returns the blob slice and the offset just past it. Fails closed on a length
/// that exceeds the cap or runs past the end of `data`.
#[inline]
fn read_blob(data: &[u8], offset: usize) -> Result<(&[u8], usize), ProgramError> {
    let len_bytes = data
        .get(offset..offset + 2)
        .ok_or(MirrorPoolError::MalformedInstruction)?;
    let len = u16::from_le_bytes([len_bytes[0], len_bytes[1]]) as usize;
    if len > wire::TRANSACT_MAX_ENC_LEN {
        return Err(MirrorPoolError::MalformedInstruction.into());
    }
    let start = offset + 2;
    let end = start
        .checked_add(len)
        .ok_or(MirrorPoolError::MalformedInstruction)?;
    let blob = data
        .get(start..end)
        .ok_or(MirrorPoolError::MalformedInstruction)?;
    Ok((blob, end))
}

/// Create the value nullifier PDA marking `nullifier` spent (skip an all-zero
/// dummy sentinel). Seeds `[b"vnf", vpool, nullifier]`; `payer` funds the rent.
/// `NullifierSpent` if the PDA already exists (replay).
fn spend_value_nullifier(
    program_id: &Address,
    vpool_key: &Address,
    payer: &AccountView,
    nf_account: &AccountView,
    nullifier_hash: &[u8; 32],
) -> ProgramResult {
    if nullifier_hash == &[0u8; 32] {
        // Dummy sentinel convention: nothing to mark spent.
        return Ok(());
    }
    let nf_bump = pda::verify_pda(
        nf_account,
        &[
            pda::VALUE_NULLIFIER_SEED,
            vpool_key.as_ref(),
            nullifier_hash,
        ],
        program_id,
    )?;
    if nf_account.owned_by(program_id) {
        return Err(MirrorPoolError::NullifierSpent.into());
    }
    let bump_seed = [nf_bump];
    let signer_seeds = [
        Seed::from(pda::VALUE_NULLIFIER_SEED),
        Seed::from(vpool_key.as_ref()),
        Seed::from(&nullifier_hash[..]),
        Seed::from(&bump_seed[..]),
    ];
    pda::create_pda_account(payer, nf_account, program_id, nullifier::LEN, &signer_seeds)?;
    let mut nf_data = nf_account.try_borrow_mut()?;
    nf_data[0] = nullifier::SPENT;
    Ok(())
}

/// Decode a `publicAmount` field element (canonical big-endian, < r) to a
/// [`SignedAmount`], exactly as `mirror_core::note::decode_public_amount` does:
/// the deposit range `[0, 2^248)` (top byte zero) and the withdraw range
/// `(r - 2^248, r)` are disjoint, so the sign is unambiguous. Rejects a value in
/// neither range and a valid encoding whose magnitude does not fit `u64`.
fn decode_public_amount(public_amount: &[u8; 32]) -> Result<SignedAmount, MirrorPoolError> {
    if public_amount == &[0u8; 32] {
        return Ok(SignedAmount::Transfer);
    }
    // publicAmount < 2^248  <=>  its most-significant byte is zero.
    if public_amount[0] == 0 {
        return Ok(SignedAmount::Deposit(magnitude_to_u64(public_amount)?));
    }
    // r - publicAmount < 2^248  <=>  the negation's top byte is zero.
    let neg = r_minus(public_amount);
    if neg[0] == 0 {
        return Ok(SignedAmount::Withdraw(magnitude_to_u64(&neg)?));
    }
    Err(MirrorPoolError::InvalidPublicAmount)
}

/// Extract a `u64` from a canonical big-endian magnitude, erroring if it does
/// not fit (any of the top 24 bytes are non-zero).
fn magnitude_to_u64(be: &[u8; 32]) -> Result<u64, MirrorPoolError> {
    if be[..24].iter().any(|&b| b != 0) {
        return Err(MirrorPoolError::InvalidPublicAmount);
    }
    let mut low = [0u8; 8];
    low.copy_from_slice(&be[24..32]);
    Ok(u64::from_be_bytes(low))
}

/// `a >= b` for 32-byte big-endian integers. Used by [`mod_r`] on the deployed
/// (solana) target and by the unit tests; unreferenced on a host non-test build.
#[allow(dead_code)]
#[inline]
fn ge(a: &[u8; 32], b: &[u8; 32]) -> bool {
    for i in 0..32 {
        if a[i] != b[i] {
            return a[i] > b[i];
        }
    }
    true
}

/// `a -= b` for 32-byte big-endian integers (caller guarantees `a >= b`).
#[inline]
fn sub_assign(a: &mut [u8; 32], b: &[u8; 32]) {
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let diff = a[i] as i16 - b[i] as i16 - borrow;
        if diff < 0 {
            a[i] = (diff + 256) as u8;
            borrow = 1;
        } else {
            a[i] = diff as u8;
            borrow = 0;
        }
    }
}

/// `r - x` for a 32-byte big-endian `x` with `0 < x < r` (canonical scalar).
#[inline]
fn r_minus(x: &[u8; 32]) -> [u8; 32] {
    let mut out = R_BE;
    sub_assign(&mut out, x);
    out
}

/// Reduce a 32-byte big-endian integer modulo r. A keccak256 digest is `< 2^256`
/// and `2^256 / r < 6`, so at most a handful of subtractions of r are needed.
/// Used by [`ext_data_hash_keccak`] on the deployed (solana) target and by the
/// unit tests; unreferenced on a host non-test build.
#[allow(dead_code)]
fn mod_r(mut x: [u8; 32]) -> [u8; 32] {
    while ge(&x, &R_BE) {
        sub_assign(&mut x, &R_BE);
    }
    x
}

/// `extDataHash = keccak256(recipient || relayer || fee_be || enc0 || enc1) mod r`
/// via the `sol_keccak256` syscall, byte-identical to
/// `mirror_core::note::ext_data_hash` and the fixture generator.
#[cfg(any(target_os = "solana", target_arch = "bpf"))]
#[inline(always)]
fn ext_data_hash_keccak(
    recipient: &[u8; 32],
    relayer: &[u8; 32],
    fee_be: &[u8; 8],
    enc0: &[u8],
    enc1: &[u8],
) -> [u8; 32] {
    let chunks: [&[u8]; 5] = [recipient, relayer, fee_be, enc0, enc1];
    let mut out = [0u8; 32];
    unsafe {
        pinocchio::syscalls::sol_keccak256(
            chunks.as_ptr() as *const u8,
            chunks.len() as u64,
            out.as_mut_ptr(),
        );
    }
    mod_r(out)
}

#[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
#[inline(always)]
fn ext_data_hash_keccak(
    _recipient: &[u8; 32],
    _relayer: &[u8; 32],
    _fee_be: &[u8; 8],
    _enc0: &[u8],
    _enc1: &[u8],
) -> [u8; 32] {
    unreachable!("keccak256 uses an on-chain syscall and never runs on the host")
}

/// Emit `enc0 || enc1` as return data for client discovery of the output notes.
#[cfg(any(target_os = "solana", target_arch = "bpf"))]
#[inline(always)]
fn emit_enc(enc0: &[u8], enc1: &[u8]) {
    let mut buf = [0u8; 2 * wire::TRANSACT_MAX_ENC_LEN];
    let l0 = enc0.len();
    let l1 = enc1.len();
    buf[..l0].copy_from_slice(enc0);
    buf[l0..l0 + l1].copy_from_slice(enc1);
    unsafe {
        pinocchio::syscalls::sol_set_return_data(buf.as_ptr(), (l0 + l1) as u64);
    }
}

#[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
#[inline(always)]
fn emit_enc(_enc0: &[u8], _enc1: &[u8]) {}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_ff::{BigInteger, PrimeField};

    // Canonical big-endian encoding of an `Fr`.
    fn fr_be(f: Fr) -> [u8; 32] {
        let be = f.into_bigint().to_bytes_be();
        let mut out = [0u8; 32];
        out[32 - be.len()..].copy_from_slice(&be);
        out
    }

    #[test]
    fn mod_r_matches_ark_reduction() {
        // A spread of 32-byte big-endian inputs, including values above r, exercise
        // the repeated-subtraction reduction against ark's field reduction.
        let samples: [[u8; 32]; 5] = [
            [0xff; 32],
            [
                0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81,
                0x58, 0x5d, 0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93,
                0xf0, 0x00, 0x00, 0x01,
            ], // exactly r -> 0
            [
                0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81,
                0x58, 0x5d, 0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93,
                0xf0, 0x00, 0x00, 0x00,
            ], // r - 1 (already reduced)
            [0x00; 32],
            [
                0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33,
                0x44, 0x55, 0x66, 0x77,
            ],
        ];
        for s in samples {
            let expected = fr_be(Fr::from_be_bytes_mod_order(&s));
            assert_eq!(mod_r(s), expected, "mod_r must match ark reduction");
        }
    }

    #[test]
    fn r_minus_is_field_negation() {
        // r - x for a small x equals the canonical encoding of (-x) in Fr.
        for v in [1u64, 7, 10, 250_000_000, u64::MAX] {
            let x = fr_be(Fr::from(v));
            let expected = fr_be(-Fr::from(v));
            assert_eq!(r_minus(&x), expected, "r - x must equal field negation");
        }
    }

    #[test]
    fn decode_public_amount_round_trips() {
        // Deposit(v): the plain big-endian u64.
        for v in [1u64, 10, 250_000_000, u64::MAX] {
            let pa = fr_be(Fr::from(v));
            assert!(matches!(decode_public_amount(&pa), Ok(SignedAmount::Deposit(d)) if d == v));
        }
        // Withdraw(v): r - v.
        for v in [1u64, 7, 250_000_000] {
            let pa = r_minus(&fr_be(Fr::from(v)));
            assert!(matches!(decode_public_amount(&pa), Ok(SignedAmount::Withdraw(w)) if w == v));
        }
        // Transfer: 0.
        assert!(matches!(
            decode_public_amount(&[0u8; 32]),
            Ok(SignedAmount::Transfer)
        ));
        // A deposit-range value whose magnitude exceeds u64 is rejected.
        let mut big = [0u8; 32];
        big[31 - 12] = 1 << 4; // bit 100 set
        assert!(matches!(
            decode_public_amount(&big),
            Err(MirrorPoolError::InvalidPublicAmount)
        ));
        // 2^248 exactly (top byte 0x01): in neither disjoint range.
        let mut two_pow_248 = [0u8; 32];
        two_pow_248[0] = 0x01;
        assert!(matches!(
            decode_public_amount(&two_pow_248),
            Err(MirrorPoolError::InvalidPublicAmount)
        ));
    }
}
