//! Disclosure account: one sealed, attributable disclosure about one settlement.
//!
//! The record half of the OPT-IN disclosure layer. It says, publicly: *the
//! settlement of `action_hash` on `pool` has a disclosure sealed to
//! `auditor_view_pub`, published by `recipient`*. It does NOT say what was
//! disclosed - the payload is a `blob` only the auditor's viewing secret opens -
//! and it deliberately does not name the deposit commitment anywhere, so the
//! deposit side of the link stays hidden from everyone except the reader the user
//! chose.
//!
//! WHAT MAKES THE SLOT UNSQUATTABLE. `action_hash` is not accepted from the
//! caller: `PUBLISH_DISCLOSURE` recomputes it on-chain as
//! `Poseidon(recipientHi128, recipientLo128, amount)` from the SIGNING
//! recipient's address (`action::transfer_action_hash`, the identical hash
//! `SETTLE_ZK` binds), and that value is a PDA seed. The address of a record is
//! therefore a function of a key the publisher must hold. Since the settling
//! commitment binds `actionHash`, and `actionHash` binds the recipient, the
//! signer is the party the disclosed commitment itself designated. That is the
//! authentication, and it is derivation rather than a comparison, so there is
//! nothing to forget to check.
//!
//! WHAT THE PROGRAM STILL CANNOT DO, stated plainly because a disclosure feature
//! that overclaims is worse than none. It cannot decrypt, so it cannot verify
//! that the blob opens at all, that it opens to a secret matching any real
//! commitment, or that it was sealed to the key the record names. What it
//! enforces is the frame: who published (a signature), about which settlement (a
//! derived address), to which registered reader (a program-owned ViewingKey PDA),
//! in what shape (a fixed-length blob whose ephemeral key passes the structural
//! X25519 test). A false record is possible, occupies only its own publisher's
//! slot, is detected by the auditor in one Poseidon hash, and is signed. See
//! `docs/COMPLIANCE.md`.
//!
//! Layout (all integers little-endian):
//!
//! ```text
//! offset  size  field
//! 0       1     version           0 = uninitialized, 1 = v1
//! 1       32    pool              the Pool whose settlement this discloses
//! 33      32    recipient         the signer; the address bound by action_hash
//! 65      32    auditor           the ViewingKey account's authority
//! 97      32    auditor_view_pub  the key the blob is sealed to (a PDA seed)
//! 129     32    action_hash       recomputed on-chain from (recipient, amount)
//! 161     8     amount            the settled action's public amount
//! 169     1     bump              Disclosure PDA bump
//! 170     100   blob              the sealed ciphertext (see mirror-core)
//! ```
//!
//! The record is WRITE-ONCE. There is no update or close instruction: a published
//! disclosure is evidence, and evidence a publisher can rewrite later is worth
//! less. The cost of that choice is stated in the docs - disclosure is one-way,
//! and there is no revocation.

use pinocchio::error::ProgramError;

use super::{read_bytes32, read_u64, read_u8, write_bytes32, write_u64, write_u8};

pub const VERSION_OFF: usize = 0;
pub const POOL_OFF: usize = 1;
pub const RECIPIENT_OFF: usize = 33;
pub const AUDITOR_OFF: usize = 65;
pub const AUDITOR_VIEW_PUB_OFF: usize = 97;
pub const ACTION_HASH_OFF: usize = 129;
pub const AMOUNT_OFF: usize = 161;
pub const BUMP_OFF: usize = 169;
pub const BLOB_OFF: usize = 170;

/// Sealed-blob length: exactly one `mirror_core::encrypted_note` ciphertext,
/// `ephemeral_pub(32) || nonce(12) || ct+tag(56)`. Mirrored from
/// `crate::wire::DISCLOSURE_BLOB_LEN`.
pub const BLOB_LEN: usize = crate::wire::DISCLOSURE_BLOB_LEN;

/// Byte offset of the blob's ephemeral X25519 public key (its first field).
pub const BLOB_EPHEMERAL_PUB_OFF: usize = 0;

/// Total account size. A layout constant, never inferred from the account.
pub const LEN: usize = BLOB_OFF + BLOB_LEN;

pub const VERSION_UNINITIALIZED: u8 = 0;
pub const VERSION_V1: u8 = 1;

pub fn version(data: &[u8]) -> Result<u8, ProgramError> {
    read_u8(data, VERSION_OFF)
}

pub fn is_initialized(data: &[u8]) -> Result<bool, ProgramError> {
    Ok(version(data)? != VERSION_UNINITIALIZED)
}

/// The Pool whose settlement this record discloses.
pub fn pool(data: &[u8]) -> Result<[u8; 32], ProgramError> {
    read_bytes32(data, POOL_OFF)
}

/// The publisher: the address the disclosed commitment bound as its payout.
pub fn recipient(data: &[u8]) -> Result<[u8; 32], ProgramError> {
    read_bytes32(data, RECIPIENT_OFF)
}

/// The reader's on-chain identity (the ViewingKey account's authority).
pub fn auditor(data: &[u8]) -> Result<[u8; 32], ProgramError> {
    read_bytes32(data, AUDITOR_OFF)
}

/// The X25519 key the blob is sealed to, copied from the ViewingKey account.
pub fn auditor_view_pub(data: &[u8]) -> Result<[u8; 32], ProgramError> {
    read_bytes32(data, AUDITOR_VIEW_PUB_OFF)
}

/// `Poseidon(recipientHi128, recipientLo128, amount)`, recomputed on-chain.
pub fn action_hash(data: &[u8]) -> Result<[u8; 32], ProgramError> {
    read_bytes32(data, ACTION_HASH_OFF)
}

/// The settled action's public amount (the pool's fixed `zk_denomination`).
pub fn amount(data: &[u8]) -> Result<u64, ProgramError> {
    read_u64(data, AMOUNT_OFF)
}

/// Stored Disclosure PDA bump.
pub fn bump(data: &[u8]) -> Result<u8, ProgramError> {
    read_u8(data, BUMP_OFF)
}

/// The sealed ciphertext.
pub fn blob(data: &[u8]) -> Result<&[u8], ProgramError> {
    data.get(BLOB_OFF..BLOB_OFF + BLOB_LEN)
        .ok_or(ProgramError::AccountDataTooSmall)
}

/// One-time initialization. The caller is responsible for having already
/// validated every field and rejected an initialized account; this only writes
/// the layout.
#[allow(clippy::too_many_arguments)]
pub fn init(
    data: &mut [u8],
    pool: &[u8; 32],
    recipient: &[u8; 32],
    auditor: &[u8; 32],
    auditor_view_pub: &[u8; 32],
    action_hash: &[u8; 32],
    amount: u64,
    bump: u8,
    blob: &[u8],
) -> Result<(), ProgramError> {
    if data.len() != LEN || blob.len() != BLOB_LEN {
        return Err(ProgramError::InvalidAccountData);
    }
    write_u8(data, VERSION_OFF, VERSION_V1)?;
    write_bytes32(data, POOL_OFF, pool)?;
    write_bytes32(data, RECIPIENT_OFF, recipient)?;
    write_bytes32(data, AUDITOR_OFF, auditor)?;
    write_bytes32(data, AUDITOR_VIEW_PUB_OFF, auditor_view_pub)?;
    write_bytes32(data, ACTION_HASH_OFF, action_hash)?;
    write_u64(data, AMOUNT_OFF, amount)?;
    write_u8(data, BUMP_OFF, bump)?;
    let dst = data
        .get_mut(BLOB_OFF..BLOB_OFF + BLOB_LEN)
        .ok_or(ProgramError::AccountDataTooSmall)?;
    dst.copy_from_slice(blob);
    Ok(())
}
