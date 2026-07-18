//! ValuePool account: a dedicated confidential-value accumulator.
//!
//! This is the value-carrying counterpart to the behavioral [`super::pool`]. It
//! is a SEPARATE account (the behavioral Pool never grows): its own frontier
//! Poseidon accumulator over value-note commitments (the Merkle leaves of the
//! 2-in/2-out JoinSplit `circuits/transaction.circom`), its own recent-root ring
//! so a proof made against a root snapshot still verifies after later appends,
//! and its own config. A separate `["vvault", vpool]` PDA holds the commingled
//! lamports so this data account's balance stays pure rent.
//!
//! Layout (all integers little-endian):
//!
//! ```text
//! offset  size            field
//! 0       1               version            0 = uninitialized, 1 = v1
//! 1       32              authority          relay pubkey allowed to submit Transact
//! 33      8               fee                relay fee (lamports) bound into ext-data
//! 41      1               denom_flag         0 = None, 1 = Some(denomination)
//! 42      8               denomination       fixed-denom (RESERVED; not enforced yet)
//! 50      1               bump               ValuePool PDA bump (seeds [b"vpool", authority])
//! 51      1               vault_bump         vault PDA bump (seeds [b"vvault", vpool])
//! 52      8               commitment_count   total value-note leaves ever appended
//! 60      32              current_root       frontier accumulator root (latest)
//! 92      DEPTH*32        filled_subtrees    frontier right-edge sibling hashes
//! 732     4               root_head          ring index of the NEXT root write
//! 736     RING*32         root_ring          recent-root ring buffer
//! ```
//!
//! The frontier bytes are stored inline and driven through [`super::merkle`]'s
//! shared [`FrontierStore`](super::merkle::FrontierStore) insert, so the value
//! accumulator reuses the exact Tornado frontier math the behavioral pool uses.
//!
//! `denomination` is an `Option<u64>` reserved for the fixed-denomination mode
//! landing next: it is written at init and read back, but NOT enforced in this
//! version (a `None`/`0` default leaves every amount free).

use pinocchio::error::ProgramError;

use super::merkle::{FrontierStore, DEPTH};
use super::{
    read_bytes32, read_u32, read_u64, read_u8, write_bytes32, write_u32, write_u64, write_u8,
};

pub const VERSION_OFF: usize = 0;
pub const AUTHORITY_OFF: usize = 1;
pub const FEE_OFF: usize = 33;
pub const DENOM_FLAG_OFF: usize = 41;
pub const DENOM_OFF: usize = 42;
pub const BUMP_OFF: usize = 50;
pub const VAULT_BUMP_OFF: usize = 51;
pub const COMMITMENT_COUNT_OFF: usize = 52;
pub const CURRENT_ROOT_OFF: usize = 60;
pub const FRONTIER_OFF: usize = 92;

/// Bytes of frontier state (one 32-byte sibling per level).
pub const FRONTIER_LEN: usize = DEPTH * 32;

/// Number of recent roots kept for [`is_known_root`]. A JoinSplit proof is made
/// against a root snapshot, so Transact accepts any of the last `ROOT_HISTORY_SIZE`
/// roots.
pub const ROOT_HISTORY_SIZE: usize = 32;

/// Ring index of the NEXT root write (little-endian u32).
pub const ROOT_HEAD_OFF: usize = FRONTIER_OFF + FRONTIER_LEN;
/// First byte of the recent-root ring buffer.
pub const ROOT_RING_OFF: usize = ROOT_HEAD_OFF + 4;
/// Bytes of ring-buffer state (one 32-byte root per slot).
pub const ROOT_RING_LEN: usize = ROOT_HISTORY_SIZE * 32;

/// Total account size. A layout constant, never inferred from the account.
pub const LEN: usize = ROOT_RING_OFF + ROOT_RING_LEN;

pub const VERSION_UNINITIALIZED: u8 = 0;
pub const VERSION_V1: u8 = 1;

pub fn version(data: &[u8]) -> Result<u8, ProgramError> {
    read_u8(data, VERSION_OFF)
}

pub fn is_initialized(data: &[u8]) -> Result<bool, ProgramError> {
    Ok(version(data)? != VERSION_UNINITIALIZED)
}

/// Settlement authority (the relay allowed to submit Transact).
pub fn authority(data: &[u8]) -> Result<[u8; 32], ProgramError> {
    read_bytes32(data, AUTHORITY_OFF)
}

/// Relay fee (lamports) bound into every Transact's ext-data.
pub fn fee(data: &[u8]) -> Result<u64, ProgramError> {
    read_u64(data, FEE_OFF)
}

/// The fixed denomination, if any (`None` when the flag byte is 0). RESERVED:
/// stored but not enforced in this version.
pub fn denomination(data: &[u8]) -> Result<Option<u64>, ProgramError> {
    if read_u8(data, DENOM_FLAG_OFF)? == 0 {
        Ok(None)
    } else {
        Ok(Some(read_u64(data, DENOM_OFF)?))
    }
}

/// Stored ValuePool PDA bump.
pub fn bump(data: &[u8]) -> Result<u8, ProgramError> {
    read_u8(data, BUMP_OFF)
}

/// Stored vault PDA bump.
pub fn vault_bump(data: &[u8]) -> Result<u8, ProgramError> {
    read_u8(data, VAULT_BUMP_OFF)
}

/// Total value-note commitments ever appended (= next leaf index).
pub fn commitment_count(data: &[u8]) -> Result<u64, ProgramError> {
    read_u64(data, COMMITMENT_COUNT_OFF)
}

/// Current root of the frontier accumulator.
pub fn current_root(data: &[u8]) -> Result<[u8; 32], ProgramError> {
    read_bytes32(data, CURRENT_ROOT_OFF)
}

/// One frontier sibling hash at `level` (0 = leaf level).
pub fn filled_subtree(data: &[u8], level: usize) -> Result<[u8; 32], ProgramError> {
    if level >= DEPTH {
        return Err(ProgramError::InvalidAccountData);
    }
    read_bytes32(data, FRONTIER_OFF + level * 32)
}

pub fn set_filled_subtree(
    data: &mut [u8],
    level: usize,
    value: &[u8; 32],
) -> Result<(), ProgramError> {
    if level >= DEPTH {
        return Err(ProgramError::InvalidAccountData);
    }
    write_bytes32(data, FRONTIER_OFF + level * 32, value)
}

pub fn set_commitment_count(data: &mut [u8], count: u64) -> Result<(), ProgramError> {
    write_u64(data, COMMITMENT_COUNT_OFF, count)
}

pub fn set_current_root(data: &mut [u8], root: &[u8; 32]) -> Result<(), ProgramError> {
    write_bytes32(data, CURRENT_ROOT_OFF, root)
}

/// Ring index of the next root write.
pub fn root_head(data: &[u8]) -> Result<u32, ProgramError> {
    read_u32(data, ROOT_HEAD_OFF)
}

/// One recent root at ring slot `i` (`i < ROOT_HISTORY_SIZE`).
pub fn root_history_entry(data: &[u8], i: usize) -> Result<[u8; 32], ProgramError> {
    if i >= ROOT_HISTORY_SIZE {
        return Err(ProgramError::InvalidAccountData);
    }
    read_bytes32(data, ROOT_RING_OFF + i * 32)
}

/// Record `root` as the most recent root: write it at the head slot and advance
/// the head (wrapping). Called by [`super::merkle::append_with`] on every append.
pub fn record_root_history(data: &mut [u8], root: &[u8; 32]) -> Result<(), ProgramError> {
    let head = read_u32(data, ROOT_HEAD_OFF)? as usize;
    if head >= ROOT_HISTORY_SIZE {
        return Err(ProgramError::InvalidAccountData);
    }
    write_bytes32(data, ROOT_RING_OFF + head * 32, root)?;
    let next = ((head + 1) % ROOT_HISTORY_SIZE) as u32;
    write_u32(data, ROOT_HEAD_OFF, next)?;
    Ok(())
}

/// Whether `root` is one of the last [`ROOT_HISTORY_SIZE`] roots. A JoinSplit
/// proof is made against a root snapshot, so Transact accepts any recent root.
pub fn is_known_root(data: &[u8], root: &[u8; 32]) -> Result<bool, ProgramError> {
    for i in 0..ROOT_HISTORY_SIZE {
        if &root_history_entry(data, i)? == root {
            return Ok(true);
        }
    }
    Ok(false)
}

/// One-time initialization. The caller (init_value_pool) must have already
/// rejected an initialized account; this only writes the layout. The frontier
/// bytes are left zeroed (a fresh account is zero-filled and each sibling is
/// written before it is read); only the empty-tree root is set, and every
/// root-ring slot is seeded with it so no slot is a never-a-real-root value.
#[allow(clippy::too_many_arguments)]
pub fn init(
    data: &mut [u8],
    authority: &[u8; 32],
    fee: u64,
    denomination: Option<u64>,
    bump: u8,
    vault_bump: u8,
    empty_root: &[u8; 32],
) -> Result<(), ProgramError> {
    if data.len() != LEN {
        return Err(ProgramError::InvalidAccountData);
    }
    write_u8(data, VERSION_OFF, VERSION_V1)?;
    write_bytes32(data, AUTHORITY_OFF, authority)?;
    write_u64(data, FEE_OFF, fee)?;
    match denomination {
        Some(d) => {
            write_u8(data, DENOM_FLAG_OFF, 1)?;
            write_u64(data, DENOM_OFF, d)?;
        }
        None => {
            write_u8(data, DENOM_FLAG_OFF, 0)?;
            write_u64(data, DENOM_OFF, 0)?;
        }
    }
    write_u8(data, BUMP_OFF, bump)?;
    write_u8(data, VAULT_BUMP_OFF, vault_bump)?;
    write_u64(data, COMMITMENT_COUNT_OFF, 0)?;
    write_bytes32(data, CURRENT_ROOT_OFF, empty_root)?;
    write_u32(data, ROOT_HEAD_OFF, 0)?;
    for slot in 0..ROOT_HISTORY_SIZE {
        write_bytes32(data, ROOT_RING_OFF + slot * 32, empty_root)?;
    }
    Ok(())
}

/// The confidential-value frontier: drives [`super::merkle::append_with`] over
/// this account's byte layout so the value accumulator reuses the exact Tornado
/// insert the behavioral pool uses.
pub struct ValuePoolFrontier;

impl FrontierStore for ValuePoolFrontier {
    fn commitment_count(data: &[u8]) -> Result<u64, ProgramError> {
        commitment_count(data)
    }
    fn set_commitment_count(data: &mut [u8], count: u64) -> Result<(), ProgramError> {
        set_commitment_count(data, count)
    }
    fn filled_subtree(data: &[u8], level: usize) -> Result<[u8; 32], ProgramError> {
        filled_subtree(data, level)
    }
    fn set_filled_subtree(
        data: &mut [u8],
        level: usize,
        value: &[u8; 32],
    ) -> Result<(), ProgramError> {
        set_filled_subtree(data, level, value)
    }
    fn set_current_root(data: &mut [u8], root: &[u8; 32]) -> Result<(), ProgramError> {
        set_current_root(data, root)
    }
    fn record_root_history(data: &mut [u8], root: &[u8; 32]) -> Result<(), ProgramError> {
        record_root_history(data, root)
    }
}

/// Append a value-note commitment leaf to this ValuePool's accumulator, updating
/// the root and recent-root ring. Returns the new root. Thin wrapper over the
/// shared [`super::merkle::append_with`] pinned to [`ValuePoolFrontier`].
pub fn append(data: &mut [u8], leaf: &[u8; 32]) -> Result<[u8; 32], ProgramError> {
    super::merkle::append_with::<ValuePoolFrontier>(data, leaf)
}
