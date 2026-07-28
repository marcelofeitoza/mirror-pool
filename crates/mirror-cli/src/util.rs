//! Small encoding helpers shared across the CLI.

use std::path::Path;

use anyhow::{bail, Context, Result};
use mirror_core::Hash32;
use num_bigint::BigUint;

/// Lowercase hex of a byte slice.
pub fn to_hex(bytes: &[u8]) -> String {
    use core::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(s, "{b:02x}").expect("writing to a String cannot fail");
    }
    s
}

/// Parse exactly 64 hex chars into a 32-byte array.
pub fn from_hex32(s: &str) -> Result<Hash32> {
    let s = s.trim();
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("expected 64 hex chars, got {:?}", s);
    }
    let mut out = [0u8; 32];
    for (i, pair) in s.as_bytes().chunks_exact(2).enumerate() {
        out[i] = (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]);
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => unreachable!("caller validated hex digits"),
    }
}

/// Read a leaf set: one 64-char hex commitment per non-empty, non-comment line,
/// in the file's order - which IS the ordering the root is built over, so this
/// parser is what binds a proof to a set. Every command that takes `--leaves`
/// reads it through here.
pub fn read_leaves(path: &Path) -> Result<Vec<Hash32>> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading leaves file {}", path.display()))?;
    let mut leaves = Vec::new();
    for (i, line) in raw.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        leaves.push(
            from_hex32(line)
                .with_context(|| format!("leaf on line {} of {}", i + 1, path.display()))?,
        );
    }
    Ok(leaves)
}

/// Decimal string of a 32-byte big-endian field element (for snarkjs input.json).
pub fn be32_to_decimal(bytes: &Hash32) -> String {
    BigUint::from_bytes_be(bytes).to_str_radix(10)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips() {
        let bytes: Hash32 = core::array::from_fn(|i| i as u8);
        let hex = to_hex(&bytes);
        assert_eq!(hex.len(), 64);
        assert_eq!(from_hex32(&hex).unwrap(), bytes);
    }

    #[test]
    fn from_hex32_rejects_bad_input() {
        assert!(from_hex32("xyz").is_err());
        assert!(from_hex32(&"00".repeat(31)).is_err()); // too short
    }

    #[test]
    fn decimal_of_one() {
        let mut b = [0u8; 32];
        b[31] = 1;
        assert_eq!(be32_to_decimal(&b), "1");
    }
}
