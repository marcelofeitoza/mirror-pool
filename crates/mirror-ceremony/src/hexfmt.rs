//! Lowercase hex, with a strict decoder. The transcript is a human-readable JSON
//! document, so every binary field in it is hex.

use crate::error::CeremonyError;

/// Lowercase hex encoding of `bytes`.
pub fn encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Decode hex, rejecting odd lengths, non-hex characters, and (when `expect_len`
/// is given) a wrong byte length.
pub fn decode(
    what: &'static str,
    s: &str,
    expect_len: Option<usize>,
) -> Result<Vec<u8>, CeremonyError> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return Err(CeremonyError::malformed(
            "hex field",
            format!("{what}: odd length {}", s.len()),
        ));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for pair in bytes.chunks(2) {
        let hi = nibble(what, pair[0])?;
        let lo = nibble(what, pair[1])?;
        out.push((hi << 4) | lo);
    }
    if let Some(n) = expect_len {
        if out.len() != n {
            return Err(CeremonyError::malformed(
                "hex field",
                format!("{what}: expected {n} bytes, got {}", out.len()),
            ));
        }
    }
    Ok(out)
}

/// Decode hex into a fixed-size array.
pub fn decode32(what: &'static str, s: &str) -> Result<[u8; 32], CeremonyError> {
    let v = decode(what, s, Some(32))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    Ok(out)
}

fn nibble(what: &'static str, c: u8) -> Result<u8, CeremonyError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(CeremonyError::malformed(
            "hex field",
            format!("{what}: non-hex character {:?}", c as char),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let bytes = [0x00u8, 0x0f, 0xa5, 0xff];
        assert_eq!(encode(&bytes), "000fa5ff");
        assert_eq!(decode("t", "000fa5ff", Some(4)).unwrap(), bytes);
    }

    #[test]
    fn rejects_bad_input() {
        assert!(decode("t", "abc", None).is_err());
        assert!(decode("t", "zz", None).is_err());
        assert!(decode("t", "abcd", Some(1)).is_err());
    }
}
