//! Small encoding helpers shared across the CLI.

use anyhow::{bail, Result};
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
