//! The proving key a ceremony passes from contributor to contributor, plus its
//! canonical on-disk container.
//!
//! # Why a container of our own
//!
//! `ark_circom::read_zkey` READS the snarkjs `.zkey` that `snarkjs groth16 setup`
//! derives from the circuit r1cs and a public powers-of-tau, but arkworks ships no
//! zkey WRITER. Rather than reimplement snarkjs's section format (and inherit its
//! ambiguities), a ceremony key is stored in a small explicit container around
//! arkworks' own canonical uncompressed serialization of
//! [`ark_groth16::ProvingKey`]:
//!
//! ```text
//! "MPK1"                      magic
//! u32 big-endian              container version (1)
//! u32 big-endian              circuit label length
//! bytes                       circuit label ("membership" / "transaction")
//! u64 big-endian              payload length
//! bytes                       ProvingKey<Bn254>, serialize_uncompressed
//! ```
//!
//! The key **digest** that the transcript commits to is
//! `SHA-256(ProvingKey serialize_uncompressed)` - the payload only. It therefore
//! does not depend on the container header, so a key imported from a `.zkey` and
//! the same key round-tripped through a `.mpk` have the same digest.
//!
//! mirror-cli's in-process prover consumes a `ProvingKey<Bn254>` directly, so a
//! ceremony output can be used to prove without ever going back through snarkjs.
//! `vk_export` writes the verifying key out in both the snarkjs
//! `verification_key.json` shape and the on-chain `groth16-solana` byte layout.

use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;

use ark_bn254::{Bn254, G1Affine, G2Affine};
use ark_groth16::ProvingKey;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use sha2::{Digest, Sha256};

use crate::error::CeremonyError;
use crate::Result;

/// Container magic.
const MAGIC: &[u8; 4] = b"MPK1";
/// Container version.
const VERSION: u32 = 1;
/// Refuse to allocate for an absurd declared length, so a corrupt or hostile header
/// cannot make the loader reserve gigabytes before the read fails. The largest real
/// key here (the transaction circuit, 27278 constraints) is about 11 MB, so 512 MB
/// leaves room for far bigger circuits while staying a bounded allocation.
const MAX_PAYLOAD: u64 = 512 << 20;

/// A Groth16 proving key together with the digest the transcript commits to.
#[derive(Clone)]
pub struct CeremonyKey {
    /// Circuit label, e.g. `membership` or `transaction`. Purely descriptive: the
    /// binding that matters is the r1cs digest recorded in the transcript header.
    pub circuit: String,
    /// The key itself.
    pub pk: ProvingKey<Bn254>,
    digest: [u8; 32],
    payload: Vec<u8>,
}

impl CeremonyKey {
    /// Wrap a proving key, computing its canonical digest.
    pub fn new(circuit: impl Into<String>, pk: ProvingKey<Bn254>) -> Result<Self> {
        let mut payload = Vec::new();
        pk.serialize_uncompressed(&mut payload)
            .map_err(|e| CeremonyError::malformed("proving key", format!("serialize: {e}")))?;
        let digest = Sha256::digest(&payload).into();
        Ok(CeremonyKey {
            circuit: circuit.into(),
            pk,
            digest,
            payload,
        })
    }

    /// Import the phase-1-derived initial key from a snarkjs `.zkey`.
    ///
    /// `snarkjs groth16 setup <circuit>.r1cs <public>.ptau <circuit>_0000.zkey` is
    /// deterministic: the same r1cs and the same powers-of-tau give a byte-identical
    /// zkey, so anyone can re-derive this file and check its digest against the one
    /// the transcript records.
    pub fn from_zkey(circuit: impl Into<String>, path: &Path) -> Result<Self> {
        let mut file = File::open(path)
            .map_err(|e| CeremonyError::io(format!("opening zkey {}", path.display()), e))?;
        let (pk, _matrices) = ark_circom::read_zkey(&mut file)
            .map_err(|e| CeremonyError::malformed("zkey", format!("{}: {e}", path.display())))?;
        CeremonyKey::new(circuit, pk)
    }

    /// Load a ceremony key container.
    pub fn load(path: &Path) -> Result<Self> {
        let file = File::open(path)
            .map_err(|e| CeremonyError::io(format!("opening key {}", path.display()), e))?;
        let mut r = BufReader::new(file);

        let mut magic = [0u8; 4];
        read_exact(&mut r, &mut magic, "key magic")?;
        if &magic != MAGIC {
            return Err(CeremonyError::malformed(
                "ceremony key",
                format!("{}: bad magic {magic:?}", path.display()),
            ));
        }
        let version = read_u32(&mut r, "key version")?;
        if version != VERSION {
            return Err(CeremonyError::malformed(
                "ceremony key",
                format!("unsupported container version {version} (expected {VERSION})"),
            ));
        }
        let label_len = read_u32(&mut r, "circuit label length")? as usize;
        if label_len > 256 {
            return Err(CeremonyError::malformed(
                "ceremony key",
                format!("circuit label length {label_len} is implausible"),
            ));
        }
        let mut label = vec![0u8; label_len];
        read_exact(&mut r, &mut label, "circuit label")?;
        let circuit = String::from_utf8(label).map_err(|e| {
            CeremonyError::malformed("ceremony key", format!("circuit label is not UTF-8: {e}"))
        })?;

        let payload_len = read_u64(&mut r, "payload length")?;
        if payload_len > MAX_PAYLOAD {
            return Err(CeremonyError::malformed(
                "ceremony key",
                format!("declared payload length {payload_len} is implausible"),
            ));
        }
        let mut payload = vec![0u8; payload_len as usize];
        read_exact(&mut r, &mut payload, "proving key payload")?;

        let pk = ProvingKey::<Bn254>::deserialize_uncompressed(&payload[..]).map_err(|e| {
            CeremonyError::malformed("ceremony key", format!("{}: {e}", path.display()))
        })?;
        let digest = Sha256::digest(&payload).into();
        Ok(CeremonyKey {
            circuit,
            pk,
            digest,
            payload,
        })
    }

    /// Write a ceremony key container.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(dir) = path.parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(dir)
                    .map_err(|e| CeremonyError::io(format!("creating {}", dir.display()), e))?;
            }
        }
        let file = File::create(path)
            .map_err(|e| CeremonyError::io(format!("creating key {}", path.display()), e))?;
        let mut w = BufWriter::new(file);
        let label = self.circuit.as_bytes();
        let ctx = || format!("writing key {}", path.display());
        w.write_all(MAGIC)
            .and_then(|()| w.write_all(&VERSION.to_be_bytes()))
            .and_then(|()| w.write_all(&(label.len() as u32).to_be_bytes()))
            .and_then(|()| w.write_all(label))
            .and_then(|()| w.write_all(&(self.payload.len() as u64).to_be_bytes()))
            .and_then(|()| w.write_all(&self.payload))
            .and_then(|()| w.flush())
            .map_err(|e| CeremonyError::io(ctx(), e))?;
        Ok(())
    }

    /// `SHA-256(ProvingKey serialize_uncompressed)`.
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// The key's `delta * G1`.
    pub fn delta_g1(&self) -> G1Affine {
        self.pk.delta_g1
    }

    /// The key's `delta * G2` (the verifying key's `vk_delta_g2`).
    pub fn delta_g2(&self) -> G2Affine {
        self.pk.vk.delta_g2
    }

    /// Every part of the key a phase-2 contribution must leave untouched. Returns
    /// the name of the first part that differs, or `None` when all match.
    ///
    /// `delta_g1`, `vk.delta_g2`, `h_query` and `l_query` are deliberately absent:
    /// those are exactly the parts a contribution moves.
    pub fn first_fixed_part_mismatch(&self, other: &CeremonyKey) -> Option<&'static str> {
        let a = &self.pk;
        let b = &other.pk;
        if a.vk.alpha_g1 != b.vk.alpha_g1 {
            return Some("vk.alpha_g1");
        }
        if a.vk.beta_g2 != b.vk.beta_g2 {
            return Some("vk.beta_g2");
        }
        if a.vk.gamma_g2 != b.vk.gamma_g2 {
            return Some("vk.gamma_g2");
        }
        if a.vk.gamma_abc_g1 != b.vk.gamma_abc_g1 {
            return Some("vk.gamma_abc_g1");
        }
        if a.beta_g1 != b.beta_g1 {
            return Some("beta_g1");
        }
        if a.a_query != b.a_query {
            return Some("a_query");
        }
        if a.b_g1_query != b.b_g1_query {
            return Some("b_g1_query");
        }
        if a.b_g2_query != b.b_g2_query {
            return Some("b_g2_query");
        }
        if a.h_query.len() != b.h_query.len() {
            return Some("h_query length");
        }
        if a.l_query.len() != b.l_query.len() {
            return Some("l_query length");
        }
        None
    }
}

fn read_exact<R: Read>(r: &mut R, buf: &mut [u8], what: &str) -> Result<()> {
    r.read_exact(buf)
        .map_err(|e| CeremonyError::io(format!("reading {what}"), e))
}

fn read_u32<R: Read>(r: &mut R, what: &str) -> Result<u32> {
    let mut b = [0u8; 4];
    read_exact(r, &mut b, what)?;
    Ok(u32::from_be_bytes(b))
}

fn read_u64<R: Read>(r: &mut R, what: &str) -> Result<u64> {
    let mut b = [0u8; 8];
    read_exact(r, &mut b, what)?;
    Ok(u64::from_be_bytes(b))
}
