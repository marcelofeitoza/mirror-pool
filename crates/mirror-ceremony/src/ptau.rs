//! Read the provenance of a PUBLIC phase-1 powers-of-tau file.
//!
//! mirror-pool does not run its own phase 1. It imports one of the public
//! perpetual powers-of-tau files, whose whole point is that a long list of
//! independent people contributed to it. That list is recorded *inside the file*
//! (section 7), so it can be read back and pinned into a ceremony transcript
//! instead of being asserted in prose.
//!
//! The `.ptau` container is a small section format:
//!
//! ```text
//! "ptau" | u32 version | u32 nSections | { u32 id | u64 size | size bytes }*
//! ```
//!
//! all integers little-endian. Two sections matter here:
//!
//! - **section 1 (header)**: `u32 n8 | n8 bytes prime (LE) | u32 power | u32 ceremonyPower`
//! - **section 7 (contributions)**: `u32 count`, then per contribution a fixed
//!   `38*n8 + 216 + 64` byte block (the contributed points, the public key of the
//!   contribution, the partial hash and the next challenge), then `u32 type`,
//!   `u32 paramLength`, and a type-length-value parameter block in which tag `1`
//!   carries the contributor's self-declared name and tag `2` a beacon.
//!
//! Nothing here is trusted: the reader is strict about lengths, and the caller
//! decides what to do with a file that has too few contributions.

use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::CeremonyError;
use crate::hexfmt;
use crate::Result;

/// BN254's base-field modulus, little-endian - what a `bn128`/`bn254` ptau carries
/// in its header.
const BN254_Q_LE: [u8; 32] = [
    0x47, 0xfd, 0x7c, 0xd8, 0x16, 0x8c, 0x20, 0x3c, 0x8d, 0xca, 0x71, 0x68, 0x91, 0x6a, 0x81, 0x97,
    0x5d, 0x58, 0x81, 0x81, 0xb6, 0x45, 0x50, 0xb8, 0x29, 0xa0, 0x31, 0xe1, 0x72, 0x4e, 0x64, 0x30,
];

/// What a ceremony transcript records about the phase-1 file it started from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Phase1Provenance {
    /// SHA-256 of the whole `.ptau` file, hex. This is the value to compare against
    /// the digest of your own download of the same public file.
    pub digest: String,
    /// The curve the file's header declares (`bn254`, or `unknown` if the modulus
    /// is not BN254's).
    pub curve: String,
    /// `log2` of the supported constraint count.
    pub power: u32,
    /// The power the original ceremony ran at (>= `power` for a truncated file).
    pub ceremony_power: u32,
    /// How many phase-1 contributions the file records.
    pub contributions: u32,
    /// The self-declared name of each contribution, in order. Self-asserted, like
    /// every name in every ceremony: their value is that they can be compared
    /// against the published list for the file you believe you have.
    pub contributor_names: Vec<String>,
}

impl Phase1Provenance {
    /// A phase 1 with a single contribution (or none) is a self-generated setup,
    /// not a public one.
    pub fn looks_public(&self) -> bool {
        self.contributions >= 2
    }
}

/// Read a `.ptau` file's provenance, hashing the file as it goes.
pub fn read_provenance(path: &Path) -> Result<Phase1Provenance> {
    let digest = file_digest(path)?;

    let file = File::open(path)
        .map_err(|e| CeremonyError::io(format!("opening ptau {}", path.display()), e))?;
    let mut r = BufReader::new(file);

    let mut magic = [0u8; 4];
    r.read_exact(&mut magic)
        .map_err(|e| CeremonyError::io("reading ptau magic", e))?;
    if &magic != b"ptau" {
        return Err(CeremonyError::malformed(
            "ptau",
            format!("{}: bad magic {magic:?}", path.display()),
        ));
    }
    let _version = read_u32(&mut r)?;
    let n_sections = read_u32(&mut r)?;
    if n_sections == 0 || n_sections > 64 {
        return Err(CeremonyError::malformed(
            "ptau",
            format!("implausible section count {n_sections}"),
        ));
    }

    let mut header: Option<(u32, u32, [u8; 32])> = None;
    let mut contributions_section: Option<Vec<u8>> = None;

    for _ in 0..n_sections {
        let id = read_u32(&mut r)?;
        let size = read_u64(&mut r)?;
        let start = r
            .stream_position()
            .map_err(|e| CeremonyError::io("locating ptau section", e))?;
        match id {
            1 => {
                let n8 = read_u32(&mut r)?;
                if n8 != 32 {
                    return Err(CeremonyError::malformed(
                        "ptau",
                        format!("unsupported field width n8={n8} (expected 32)"),
                    ));
                }
                let mut q = [0u8; 32];
                r.read_exact(&mut q)
                    .map_err(|e| CeremonyError::io("reading ptau prime", e))?;
                let power = read_u32(&mut r)?;
                let ceremony_power = read_u32(&mut r)?;
                header = Some((power, ceremony_power, q));
            }
            7 => {
                if size > 64 * 1024 * 1024 {
                    return Err(CeremonyError::malformed(
                        "ptau",
                        format!("contributions section is implausibly large ({size} bytes)"),
                    ));
                }
                let mut buf = vec![0u8; size as usize];
                r.read_exact(&mut buf)
                    .map_err(|e| CeremonyError::io("reading ptau contributions", e))?;
                contributions_section = Some(buf);
            }
            _ => {}
        }
        r.seek(SeekFrom::Start(start + size))
            .map_err(|e| CeremonyError::io("skipping ptau section", e))?;
    }

    let (power, ceremony_power, q) = header.ok_or_else(|| {
        CeremonyError::malformed("ptau", "file has no header section (section 1)")
    })?;
    let curve = if q == BN254_Q_LE { "bn254" } else { "unknown" };

    let (contributions, contributor_names) = match contributions_section {
        Some(buf) => parse_contributions(&buf)?,
        None => (0, Vec::new()),
    };

    Ok(Phase1Provenance {
        digest: hexfmt::encode(&digest),
        curve: curve.to_string(),
        power,
        ceremony_power,
        contributions,
        contributor_names,
    })
}

/// Parse section 7 into `(count, names)`.
fn parse_contributions(buf: &[u8]) -> Result<(u32, Vec<String>)> {
    // Per-contribution fixed block: tauG1 + tauG2 + alphaG1 + betaG1 + betaG2
    // (14 * n8) plus the three-part public key (24 * n8), then the partial hash and
    // the next challenge.
    const N8: usize = 32;
    const POINTS: usize = 38 * N8;
    const PARTIAL_HASH: usize = 216;
    const NEXT_CHALLENGE: usize = 64;
    const FIXED: usize = POINTS + PARTIAL_HASH + NEXT_CHALLENGE;

    let mut cur = Cursor::new(buf);
    let count = cur
        .u32()
        .map_err(|()| CeremonyError::malformed("ptau", "contributions section has no count"))?;
    if count > 4096 {
        return Err(CeremonyError::malformed(
            "ptau",
            format!("implausible phase-1 contribution count {count}"),
        ));
    }
    let mut names = Vec::with_capacity(count as usize);
    for i in 0..count {
        cur.skip(FIXED)
            .map_err(|()| truncated(i, "fixed contribution block"))?;
        let _kind = cur.u32().map_err(|()| truncated(i, "contribution type"))?;
        let param_len = cur.u32().map_err(|()| truncated(i, "parameter length"))? as usize;
        let params = cur
            .take(param_len)
            .map_err(|()| truncated(i, "parameter block"))?;
        names.push(parse_name(params));
    }
    Ok((count, names))
}

fn truncated(index: u32, what: &str) -> CeremonyError {
    CeremonyError::malformed(
        "ptau",
        format!("contributions section is truncated at contribution {index} ({what})"),
    )
}

/// Pull the name (parameter tag 1) out of a contribution's parameter block. An
/// unnamed contribution yields an empty string rather than an error: the name is
/// self-declared metadata, not something to validate.
fn parse_name(params: &[u8]) -> String {
    let mut i = 0usize;
    while i < params.len() {
        let tag = params[i];
        i += 1;
        if i >= params.len() {
            break;
        }
        let len = params[i] as usize;
        i += 1;
        if i + len > params.len() {
            break;
        }
        let value = &params[i..i + len];
        i += len;
        match tag {
            // 1 = name.
            1 => return String::from_utf8_lossy(value).to_string(),
            // 2 = beacon: the value is followed by a one-byte iteration exponent,
            // which this reader does not need.
            2 => return format!("<beacon {}>", hexfmt::encode(value)),
            _ => {}
        }
    }
    String::new()
}

/// SHA-256 of a whole file, streamed.
pub fn file_digest(path: &Path) -> Result<[u8; 32]> {
    let file = File::open(path)
        .map_err(|e| CeremonyError::io(format!("opening {}", path.display()), e))?;
    let mut r = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = r
            .read(&mut buf)
            .map_err(|e| CeremonyError::io(format!("reading {}", path.display()), e))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().into())
}

fn read_u32<R: Read>(r: &mut R) -> Result<u32> {
    let mut b = [0u8; 4];
    r.read_exact(&mut b)
        .map_err(|e| CeremonyError::io("reading ptau u32", e))?;
    Ok(u32::from_le_bytes(b))
}

fn read_u64<R: Read>(r: &mut R) -> Result<u64> {
    let mut b = [0u8; 8];
    r.read_exact(&mut b)
        .map_err(|e| CeremonyError::io("reading ptau u64", e))?;
    Ok(u64::from_le_bytes(b))
}

/// A minimal bounds-checked cursor over the contributions section.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Cursor { buf, pos: 0 }
    }

    fn u32(&mut self) -> std::result::Result<u32, ()> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn skip(&mut self, n: usize) -> std::result::Result<(), ()> {
        self.take(n).map(|_| ())
    }

    fn take(&mut self, n: usize) -> std::result::Result<&'a [u8], ()> {
        let end = self.pos.checked_add(n).ok_or(())?;
        if end > self.buf.len() {
            return Err(());
        }
        let out = &self.buf[self.pos..end];
        self.pos = end;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_name_parameter_block() {
        let mut params = vec![1u8, 6];
        params.extend_from_slice(b"alice3");
        assert_eq!(parse_name(&params), "alice3");
    }

    #[test]
    fn unnamed_contribution_is_empty_not_an_error() {
        assert_eq!(parse_name(&[]), "");
        assert_eq!(parse_name(&[9, 2, 0, 0]), "");
    }

    #[test]
    fn rejects_a_truncated_contributions_section() {
        // A count of one, but nothing after it.
        let buf = 1u32.to_le_bytes().to_vec();
        assert!(parse_contributions(&buf).is_err());
    }
}
