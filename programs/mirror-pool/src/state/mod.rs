//! Account state layouts.
//!
//! Every account layout in this program is defined as explicit byte offsets
//! with bounds-checked little-endian accessors. No `unsafe`, no transmutes,
//! no `#[repr(C)]` casts: the account data is an untrusted byte slice and is
//! treated as such at every read and write.

use pinocchio::error::ProgramError;

pub mod association;
pub mod epoch;
pub mod merkle;
pub mod nullifier;
pub mod participant;
pub mod pool;
pub mod value_pool;
pub mod vk_registry;

/// Read a single byte at `offset`.
pub(crate) fn read_u8(data: &[u8], offset: usize) -> Result<u8, ProgramError> {
    data.get(offset)
        .copied()
        .ok_or(ProgramError::AccountDataTooSmall)
}

/// Read a little-endian `u16` at `offset`.
pub(crate) fn read_u16(data: &[u8], offset: usize) -> Result<u16, ProgramError> {
    let bytes = data
        .get(offset..offset + 2)
        .ok_or(ProgramError::AccountDataTooSmall)?;
    let bytes: [u8; 2] = bytes
        .try_into()
        .map_err(|_| ProgramError::InvalidAccountData)?;
    Ok(u16::from_le_bytes(bytes))
}

/// Read a little-endian `u32` at `offset`.
pub(crate) fn read_u32(data: &[u8], offset: usize) -> Result<u32, ProgramError> {
    let bytes = data
        .get(offset..offset + 4)
        .ok_or(ProgramError::AccountDataTooSmall)?;
    let bytes: [u8; 4] = bytes
        .try_into()
        .map_err(|_| ProgramError::InvalidAccountData)?;
    Ok(u32::from_le_bytes(bytes))
}

/// Read a little-endian `u64` at `offset`.
pub(crate) fn read_u64(data: &[u8], offset: usize) -> Result<u64, ProgramError> {
    let bytes = data
        .get(offset..offset + 8)
        .ok_or(ProgramError::AccountDataTooSmall)?;
    let bytes: [u8; 8] = bytes
        .try_into()
        .map_err(|_| ProgramError::InvalidAccountData)?;
    Ok(u64::from_le_bytes(bytes))
}

/// Read a 32-byte value (hash, root) at `offset`.
pub(crate) fn read_bytes32(data: &[u8], offset: usize) -> Result<[u8; 32], ProgramError> {
    let bytes = data
        .get(offset..offset + 32)
        .ok_or(ProgramError::AccountDataTooSmall)?;
    bytes
        .try_into()
        .map_err(|_| ProgramError::InvalidAccountData)
}

/// Write a single byte at `offset`.
pub(crate) fn write_u8(data: &mut [u8], offset: usize, value: u8) -> Result<(), ProgramError> {
    let dst = data
        .get_mut(offset)
        .ok_or(ProgramError::AccountDataTooSmall)?;
    *dst = value;
    Ok(())
}

/// Write a little-endian `u16` at `offset`.
pub(crate) fn write_u16(data: &mut [u8], offset: usize, value: u16) -> Result<(), ProgramError> {
    let dst = data
        .get_mut(offset..offset + 2)
        .ok_or(ProgramError::AccountDataTooSmall)?;
    dst.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

/// Write a little-endian `u32` at `offset`.
pub(crate) fn write_u32(data: &mut [u8], offset: usize, value: u32) -> Result<(), ProgramError> {
    let dst = data
        .get_mut(offset..offset + 4)
        .ok_or(ProgramError::AccountDataTooSmall)?;
    dst.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

/// Write a little-endian `u64` at `offset`.
pub(crate) fn write_u64(data: &mut [u8], offset: usize, value: u64) -> Result<(), ProgramError> {
    let dst = data
        .get_mut(offset..offset + 8)
        .ok_or(ProgramError::AccountDataTooSmall)?;
    dst.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

/// Write a 32-byte value at `offset`.
pub(crate) fn write_bytes32(
    data: &mut [u8],
    offset: usize,
    value: &[u8; 32],
) -> Result<(), ProgramError> {
    let dst = data
        .get_mut(offset..offset + 32)
        .ok_or(ProgramError::AccountDataTooSmall)?;
    dst.copy_from_slice(value);
    Ok(())
}
