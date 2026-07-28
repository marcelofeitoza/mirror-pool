//! The on-disk shape of a ceremony, and the operations a participant runs on it.
//!
//! A ceremony directory is deliberately boring, so it can be zipped, emailed,
//! uploaded, or served over HTTP without any tooling:
//!
//! ```text
//! <dir>/transcript.json     the chain (human-readable, hash-linked)
//! <dir>/key_0000.mpk        the phase-1-derived initial proving key
//! <dir>/key_0001.mpk        after contribution 0
//! <dir>/key_0002.mpk        after contribution 1
//! ...
//! ```
//!
//! A contributor needs only the transcript and the newest key file. They run
//! `contribute`, and hand on the transcript plus the key file it produced. A
//! verifier needs the transcript, `key_0000.mpk` (or the ability to re-derive it),
//! and the final key file.

use std::path::{Path, PathBuf};

use crate::contribute::{self, Entropy};
use crate::error::CeremonyError;
use crate::hexfmt;
use crate::key::CeremonyKey;
use crate::ptau;
use crate::transcript::{ContributionRecord, Transcript};
use crate::verify::{self, Report};
use crate::Result;

/// Name of the transcript inside a ceremony directory.
pub const TRANSCRIPT_FILE: &str = "transcript.json";

/// What [`Session::start`] needs.
pub struct StartOptions<'a> {
    /// Directory to create the ceremony in.
    pub dir: &'a Path,
    /// Circuit label, e.g. `membership`.
    pub circuit: &'a str,
    /// The compiled `.r1cs`; only its digest is recorded.
    pub r1cs: &'a Path,
    /// The PUBLIC phase-1 powers-of-tau the initial key was derived from.
    pub ptau: &'a Path,
    /// The initial `.zkey`, i.e. the output of
    /// `snarkjs groth16 setup <r1cs> <ptau> <out>.zkey`, which is deterministic.
    pub initial_zkey: &'a Path,
}

/// An open ceremony directory.
pub struct Session {
    /// The directory.
    pub dir: PathBuf,
    /// The transcript, as loaded or as being built.
    pub transcript: Transcript,
}

impl Session {
    /// Create a new ceremony from a phase-1-derived initial key.
    pub fn start(opts: StartOptions) -> Result<Session> {
        let phase1 = ptau::read_provenance(opts.ptau)?;
        let r1cs_digest = ptau::file_digest(opts.r1cs)?;
        let initial = CeremonyKey::from_zkey(opts.circuit, opts.initial_zkey)?;

        let transcript = Transcript::new(opts.circuit, r1cs_digest, phase1, &initial);

        let session = Session {
            dir: opts.dir.to_path_buf(),
            transcript,
        };
        std::fs::create_dir_all(&session.dir)
            .map_err(|e| CeremonyError::io(format!("creating {}", session.dir.display()), e))?;
        initial.save(&session.key_path(0))?;
        session.save_transcript()?;
        Ok(session)
    }

    /// Open an existing ceremony directory.
    pub fn open(dir: &Path) -> Result<Session> {
        let path = dir.join(TRANSCRIPT_FILE);
        let text = std::fs::read_to_string(&path)
            .map_err(|e| CeremonyError::io(format!("reading {}", path.display()), e))?;
        Ok(Session {
            dir: dir.to_path_buf(),
            transcript: Transcript::from_json(&text)?,
        })
    }

    /// Path of the key file after `n` contributions (`n = 0` is the initial key).
    pub fn key_path(&self, n: usize) -> PathBuf {
        self.dir.join(format!("key_{n:04}.mpk"))
    }

    /// Path of the newest key file.
    pub fn head_key_path(&self) -> PathBuf {
        self.key_path(self.transcript.contributions.len())
    }

    /// Load the phase-1-derived initial key.
    pub fn load_initial_key(&self) -> Result<CeremonyKey> {
        CeremonyKey::load(&self.key_path(0))
    }

    /// Load the newest key.
    pub fn load_head_key(&self) -> Result<CeremonyKey> {
        CeremonyKey::load(&self.head_key_path())
    }

    /// Write the transcript back out.
    pub fn save_transcript(&self) -> Result<()> {
        let path = self.dir.join(TRANSCRIPT_FILE);
        std::fs::write(&path, self.transcript.to_json()?)
            .map_err(|e| CeremonyError::io(format!("writing {}", path.display()), e))
    }

    /// Whether the ceremony has been closed by its beacon.
    ///
    /// A closed ceremony accepts no further step: [`Session::contribute`] and
    /// [`Session::beacon`] both refuse, because [`contribute::contribute`] does.
    pub fn closed_by_beacon(&self) -> bool {
        self.transcript.closed_by_beacon()
    }

    /// Add an entropy contribution and write out the new key and transcript.
    ///
    /// Refuses once the ceremony has been closed by a beacon.
    pub fn contribute(
        &mut self,
        contributor_id: &str,
        entropy: &Entropy,
    ) -> Result<ContributionRecord> {
        let head = self.load_head_key()?;
        let out = contribute::contribute(&mut self.transcript, &head, contributor_id, entropy)?;
        self.finish_step(&out.key, &out.record)
    }

    /// Add a beacon step and write out the new key and transcript. This closes the
    /// ceremony: nothing can be appended afterwards.
    pub fn beacon(
        &mut self,
        contributor_id: &str,
        source: &[u8],
        iterations_exp: u32,
    ) -> Result<ContributionRecord> {
        let head = self.load_head_key()?;
        let out = contribute::contribute_beacon(
            &mut self.transcript,
            &head,
            contributor_id,
            source,
            iterations_exp,
        )?;
        self.finish_step(&out.key, &out.record)
    }

    fn finish_step(
        &mut self,
        key: &CeremonyKey,
        record: &ContributionRecord,
    ) -> Result<ContributionRecord> {
        key.save(&self.head_key_path())?;
        self.save_transcript()?;
        Ok(record.clone())
    }

    /// Verify the ceremony from the initial key on disk to the newest key on disk.
    pub fn verify(&self) -> Result<Report> {
        let initial = self.load_initial_key()?;
        let final_key = self.load_head_key()?;
        verify::verify(&self.transcript, &initial, &final_key)
    }

    /// Check that a `.r1cs` on disk is the one this ceremony is pinned to.
    pub fn check_r1cs(&self, r1cs: &Path) -> Result<()> {
        let digest = hexfmt::encode(&ptau::file_digest(r1cs)?);
        if digest != self.transcript.circuit_r1cs_digest {
            return Err(CeremonyError::malformed(
                "ceremony",
                format!(
                    "{} hashes to {digest}, but this transcript is for r1cs {}",
                    r1cs.display(),
                    self.transcript.circuit_r1cs_digest
                ),
            ));
        }
        Ok(())
    }
}
