//! ViewingKey account: one address's published X25519 viewing key.
//!
//! This is the directory half of the OPT-IN disclosure layer. An account publishes
//! the viewing key it can be addressed at, under seeds `["view", authority]`, and
//! signs for it. Two different parties use it for two different reasons:
//!
//! - An AUDITOR publishes a key so users have something to seal a disclosure to
//!   without an out-of-band exchange, and so a record can name a key that is
//!   demonstrably somebody's rather than 32 arbitrary bytes.
//! - A USER may publish one so a sender can encrypt a confidential-value note to
//!   them (`crates/mirror-core/src/encrypted_note.rs`) knowing only their address.
//!
//! WHAT THIS ACCOUNT IS NOT. It is not consulted by any settle path. No
//! instruction that moves value reads it, so not registering costs nothing and
//! blocks nothing; a pool that required a registration would be a surveillance
//! pool. See `docs/COMPLIANCE.md`.
//!
//! WHY THE AUTHORITY IS THE ONLY VARIABLE SEED. It makes the directory
//! unsquattable by construction rather than by a check: the only PDA a signer can
//! satisfy is their own, so there is no first-come race for anybody else's slot
//! and no "registered first, wins" failure mode. Rotation is allowed (the same
//! authority may overwrite its own key, bumping `rotation_count`), and because
//! disclosure records are keyed by the KEY rather than by the authority, rotating
//! never invalidates or displaces a record already published to the old key.
//!
//! Layout (all integers little-endian):
//!
//! ```text
//! offset  size  field
//! 0       1     version          0 = uninitialized, 1 = v1
//! 1       32    authority        the only signer that may write this account
//! 33      32    viewing_pub      X25519 public key, canonical and non-small-order
//! 65      1     bump             ViewingKey PDA bump
//! 66      8     rotation_count   times the key has been replaced (0 at first write)
//! ```

use pinocchio::error::ProgramError;

use super::{read_bytes32, read_u64, read_u8, write_bytes32, write_u64, write_u8};
use crate::MirrorPoolError;

pub const VERSION_OFF: usize = 0;
pub const AUTHORITY_OFF: usize = 1;
pub const VIEWING_PUB_OFF: usize = 33;
pub const BUMP_OFF: usize = 65;
pub const ROTATION_COUNT_OFF: usize = 66;

/// Total account size. A layout constant, never inferred from the account.
pub const LEN: usize = ROTATION_COUNT_OFF + 8;

pub const VERSION_UNINITIALIZED: u8 = 0;
pub const VERSION_V1: u8 = 1;

/// Little-endian encoding of the curve25519 field prime `p = 2^255 - 19`.
/// Used only for the byte-wise canonicality test below; no field arithmetic
/// happens on-chain.
///
/// MIRRORED from `mirror_core::encrypted_note`; the mollusk suite asserts the two
/// copies agree instead of trusting this comment.
const CURVE25519_P_LE: [u8; 32] = [
    0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
];

/// The CANONICAL small-order X25519 public keys. The non-canonical members of the
/// classic blacklist (`p`, `p+1`, and every high-bit-set variant) are rejected by
/// the canonicality test instead, so they are deliberately not repeated here.
///
/// MIRRORED from `mirror_core::encrypted_note`.
const SMALL_ORDER_X25519: [[u8; 32]; 5] = [
    [0u8; 32],
    [
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ],
    [
        0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4,
        0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49,
        0xb8, 0x00,
    ],
    [
        0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef,
        0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f,
        0x11, 0x57,
    ],
    [
        0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
];

/// Structural acceptance test for a 32-byte X25519 public key, applied to every
/// key this program stores and to the ephemeral key inside every sealed blob.
///
/// It is a BYTE test, not a curve-membership proof, and it rejects exactly two
/// classes:
///
/// 1. **Non-canonical encodings** (top bit set, or a value `>= p`). X25519 ignores
///    the top bit and reduces mod `p`, so several byte strings denote one key.
///    This program derives a PDA from a viewing key, so accepting the aliases
///    would mean two accounts for one key - malleability in an identifier. The
///    canonical encoding is unique.
/// 2. **Small-order points**, whose ECDH output does not depend on the peer's
///    secret at all. Anything "sealed" against one is readable by everybody, so a
///    user who published a disclosure to such a key would have published it to the
///    world while believing otherwise.
///
/// An honestly generated key never trips either branch; this is a guard against a
/// broken or hostile client, not a happy-path check. What it does NOT do: prove
/// the bytes are a point on the curve (X25519 accepts any 32 bytes, and a real
/// check needs field arithmetic this program will not spend compute on), and it
/// cannot say anything at all about whether the holder of the matching secret is
/// who a record claims. MIRRORED from
/// `mirror_core::encrypted_note::is_acceptable_x25519_pubkey`.
pub fn is_acceptable_viewing_pub(pubkey: &[u8; 32]) -> bool {
    if pubkey[31] & 0x80 != 0 {
        return false;
    }
    let mut canonical = false;
    let mut i = 32;
    while i > 0 {
        i -= 1;
        if pubkey[i] < CURVE25519_P_LE[i] {
            canonical = true;
            break;
        }
        if pubkey[i] > CURVE25519_P_LE[i] {
            return false;
        }
    }
    if !canonical {
        return false;
    }
    let mut j = 0;
    while j < SMALL_ORDER_X25519.len() {
        if pubkey == &SMALL_ORDER_X25519[j] {
            return false;
        }
        j += 1;
    }
    true
}

pub fn version(data: &[u8]) -> Result<u8, ProgramError> {
    read_u8(data, VERSION_OFF)
}

pub fn is_initialized(data: &[u8]) -> Result<bool, ProgramError> {
    Ok(version(data)? != VERSION_UNINITIALIZED)
}

/// The only signer allowed to write this account.
pub fn authority(data: &[u8]) -> Result<[u8; 32], ProgramError> {
    read_bytes32(data, AUTHORITY_OFF)
}

/// The published X25519 viewing key.
pub fn viewing_pub(data: &[u8]) -> Result<[u8; 32], ProgramError> {
    read_bytes32(data, VIEWING_PUB_OFF)
}

/// Stored ViewingKey PDA bump.
pub fn bump(data: &[u8]) -> Result<u8, ProgramError> {
    read_u8(data, BUMP_OFF)
}

/// How many times the key has been replaced (0 for a never-rotated registration).
pub fn rotation_count(data: &[u8]) -> Result<u64, ProgramError> {
    read_u64(data, ROTATION_COUNT_OFF)
}

/// One-time initialization. The caller is responsible for having already
/// validated the key and rejected an initialized account; this only writes the
/// layout.
pub fn init(
    data: &mut [u8],
    authority: &[u8; 32],
    viewing_pub: &[u8; 32],
    bump: u8,
) -> Result<(), ProgramError> {
    if data.len() != LEN {
        return Err(ProgramError::InvalidAccountData);
    }
    write_u8(data, VERSION_OFF, VERSION_V1)?;
    write_bytes32(data, AUTHORITY_OFF, authority)?;
    write_bytes32(data, VIEWING_PUB_OFF, viewing_pub)?;
    write_u8(data, BUMP_OFF, bump)?;
    write_u64(data, ROTATION_COUNT_OFF, 0)?;
    Ok(())
}

/// Replace the published key, bumping the monotonic rotation counter.
///
/// Fails closed on counter overflow rather than wrapping. The caller is
/// responsible for having checked the signer against the stored authority.
pub fn rotate(data: &mut [u8], viewing_pub: &[u8; 32]) -> Result<u64, ProgramError> {
    write_bytes32(data, VIEWING_PUB_OFF, viewing_pub)?;
    let count = rotation_count(data)?
        .checked_add(1)
        .ok_or(MirrorPoolError::ArithmeticOverflow)?;
    write_u64(data, ROTATION_COUNT_OFF, count)?;
    Ok(count)
}
