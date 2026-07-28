//! VkRegistry account: a WRITE-ONCE, DIGEST-PINNED home for a Groth16
//! verifying key, one PDA per circuit (seeds `["vk", circuit_id]`).
//!
//! # Why this exists, and why the pin is the whole point
//!
//! A verifying key is the root of trust of every proof this program accepts.
//! Embed it as a compile-time constant and it is fixed by auditable bytecode.
//! Move it into an account and it becomes mutable data - and whoever can write
//! that data can install a key whose trapdoor they hold and forge a proof for a
//! statement that is false, which on the settle paths means draining escrow.
//! That is the reason a naive "put the vk in a config account" design is a
//! downgrade, not an upgrade, and it is why the operator-supplied,
//! FORMAT-ONLY-validated variant (check the length, check `ic_len`, accept
//! anything else) is unsafe: a 769-byte blob is a perfectly well-formed
//! verifying key, and being well-formed says nothing about who knows its
//! trapdoor.
//!
//! Two properties together remove that risk here:
//!
//! 1. **Write-once.** The registry is created and filled by `INIT_VK` and there
//!    is NO update instruction anywhere in this program. Nothing can rewrite a
//!    live registry account; a second `INIT_VK` fails with
//!    [`crate::MirrorPoolError::VkRegistryAlreadyInitialized`].
//! 2. **Pinned.** `INIT_VK` accepts the bytes only if they hash to the digest
//!    the program pins at compile time for that circuit
//!    ([`crate::vk_digest`]), and EVERY verify re-checks the same digest over
//!    the stored bytes before using them. So the set of keys this program can
//!    ever verify against is fixed by its bytecode, exactly as it was when the
//!    key was a `const`. What the account buys is not freedom to choose the key;
//!    it is that the key in force is readable on-chain by anyone, without
//!    disassembling the program.
//!
//! Read `docs/VK_REGISTRY.md` for the honest ledger of what that does and does
//! not buy, including the fact that rotating to a post-ceremony key still needs
//! a program upgrade (to move the pinned digest), because a pin that a
//! third party could move would not be a pin.
//!
//! # Canonical encoding (what the digest is taken over)
//!
//! ```text
//! offset  size                     field
//! 0       1                        nr_pubinputs
//! 1       64                       vk_alpha_g1        G1: x || y
//! 65      128                      vk_beta_g2         G2: x_c1 || x_c0 || y_c1 || y_c0
//! 193     128                      vk_gamma_g2
//! 321     128                      vk_delta_g2
//! 449     64 * (nr_pubinputs + 1)  vk_ic
//! ```
//!
//! All big-endian and uncompressed, i.e. byte-identical to the `groth16-solana`
//! in-memory layout, so decoding is a copy and never a re-encoding. The
//! membership key is 769 bytes, the association key 833, the JoinSplit key 961.
//!
//! # Account layout
//!
//! ```text
//! offset  size   field
//! 0       1      version        0 = uninitialized, 1 = v1
//! 1       1      circuit_id     which pinned circuit this registry serves
//! 2       1      bump           VkRegistry PDA bump
//! 3       1      reserved       always 0; a non-zero byte fails the load
//! 4       N      vk             the canonical encoding above
//! ```
//!
//! The total size is a pure function of the circuit's pinned public-input count,
//! never inferred from the account, so a resized or truncated account fails on
//! shape before anything is hashed.

use groth16_solana::groth16::{Groth16Verifier, Groth16Verifyingkey};
use pinocchio::{error::ProgramError, AccountView, Address};

use super::{read_u8, write_u8};
use crate::{
    pda, vk_digest,
    wire::{
        vk_encoded_len, CIRCUIT_ASSOCIATION, CIRCUIT_MEMBERSHIP, CIRCUIT_TRANSACTION, G1_LEN,
        G2_LEN, VK_ALPHA_G1_OFF, VK_BETA_G2_OFF, VK_DELTA_G2_OFF, VK_GAMMA_G2_OFF, VK_IC_OFF,
        VK_MAX_IC, VK_MAX_PUBLIC_INPUTS, VK_NR_PUBINPUTS_OFF,
    },
    MirrorPoolError,
};

pub const VERSION_OFF: usize = 0;
pub const CIRCUIT_OFF: usize = 1;
pub const BUMP_OFF: usize = 2;
pub const RESERVED_OFF: usize = 3;
pub const VK_OFF: usize = 4;

pub const VERSION_UNINITIALIZED: u8 = 0;
pub const VERSION_V1: u8 = 1;

/// Total account size for a circuit with `nr_pubinputs` public inputs.
pub const fn account_len(nr_pubinputs: usize) -> usize {
    VK_OFF + vk_encoded_len(nr_pubinputs)
}

/// One circuit this program is willing to verify against, ever.
///
/// The table below is the program's entire trust anchor for proof verification.
/// A circuit id that is not in it is pinned to nothing and is rejected.
pub struct ApprovedCircuit {
    /// Wire id, also the second PDA seed.
    pub id: u8,
    /// The circuit's public-input count. Fixes both the encoding length and the
    /// `nr_pubinputs` byte the stored key must carry.
    pub nr_pubinputs: usize,
    /// SHA-256 over the canonical encoding of the one approved key.
    pub digest: [u8; 32],
}

/// The pinned circuits. Adding one is a deliberate, diffable program upgrade.
pub const APPROVED: [ApprovedCircuit; 3] = [
    ApprovedCircuit {
        id: CIRCUIT_MEMBERSHIP,
        nr_pubinputs: 4,
        digest: vk_digest::MEMBERSHIP_VK_SHA256,
    },
    ApprovedCircuit {
        id: CIRCUIT_TRANSACTION,
        nr_pubinputs: 7,
        digest: vk_digest::TRANSACTION_VK_SHA256,
    },
    ApprovedCircuit {
        id: CIRCUIT_ASSOCIATION,
        nr_pubinputs: 5,
        digest: vk_digest::ASSOCIATION_VK_SHA256,
    },
];

/// Look a circuit id up in [`APPROVED`]. An unknown id is pinned to nothing, so
/// it is rejected with the same error as a key that fails its digest.
pub fn approved(circuit_id: u8) -> Result<&'static ApprovedCircuit, ProgramError> {
    let mut i = 0;
    while i < APPROVED.len() {
        if APPROVED[i].id == circuit_id {
            return Ok(&APPROVED[i]);
        }
        i += 1;
    }
    Err(MirrorPoolError::VkNotApproved.into())
}

pub fn version(data: &[u8]) -> Result<u8, ProgramError> {
    read_u8(data, VERSION_OFF)
}

pub fn is_initialized(data: &[u8]) -> Result<bool, ProgramError> {
    Ok(version(data)? != VERSION_UNINITIALIZED)
}

/// Which circuit this registry serves.
pub fn circuit_id(data: &[u8]) -> Result<u8, ProgramError> {
    read_u8(data, CIRCUIT_OFF)
}

/// Stored VkRegistry PDA bump.
pub fn bump(data: &[u8]) -> Result<u8, ProgramError> {
    read_u8(data, BUMP_OFF)
}

/// The stored canonical verifying-key encoding.
pub fn vk_bytes(data: &[u8]) -> Result<&[u8], ProgramError> {
    data.get(VK_OFF..).ok_or(ProgramError::AccountDataTooSmall)
}

/// One-time initialization. The caller is responsible for having already
/// rejected an initialized account AND for having checked `vk` against the
/// pinned digest; this only writes the layout.
pub fn init(
    data: &mut [u8],
    circuit: &ApprovedCircuit,
    bump: u8,
    vk: &[u8],
) -> Result<(), ProgramError> {
    if data.len() != account_len(circuit.nr_pubinputs)
        || vk.len() != vk_encoded_len(circuit.nr_pubinputs)
    {
        return Err(ProgramError::InvalidAccountData);
    }
    write_u8(data, VERSION_OFF, VERSION_V1)?;
    write_u8(data, CIRCUIT_OFF, circuit.id)?;
    write_u8(data, BUMP_OFF, bump)?;
    write_u8(data, RESERVED_OFF, 0)?;
    let dst = data
        .get_mut(VK_OFF..)
        .ok_or(ProgramError::AccountDataTooSmall)?;
    dst.copy_from_slice(vk);
    Ok(())
}

/// Fixed-size scratch for the decoded IC vector.
///
/// `groth16_solana::Groth16Verifyingkey` borrows its IC vector as
/// `&[[u8; 64]]`, and this program does not cast account bytes (see the
/// `state` module header), so the decoder copies into a caller-owned buffer
/// sized by the compile-time [`VK_MAX_IC`] rather than by anything the account
/// says. 512 bytes, no allocation, no `unsafe`.
pub struct IcScratch {
    ic: [[u8; G1_LEN]; VK_MAX_IC],
}

impl IcScratch {
    pub const fn new() -> Self {
        Self {
            ic: [[0u8; G1_LEN]; VK_MAX_IC],
        }
    }
}

impl Default for IcScratch {
    fn default() -> Self {
        Self::new()
    }
}

/// Serialize a verifying key into the canonical encoding, returning its length.
///
/// Pure byte shuffling, so it runs on the host too: the mollusk tests and the
/// off-chain CLI use it to build `INIT_VK` data, which is what keeps the digest
/// the program pins and the digest a client produces the same number.
pub fn encode_into(vk: &Groth16Verifyingkey, out: &mut [u8]) -> Result<usize, ProgramError> {
    let n = vk.nr_pubinputs;
    if n > VK_MAX_PUBLIC_INPUTS || vk.vk_ic.len() != n + 1 {
        return Err(MirrorPoolError::MalformedInstruction.into());
    }
    let len = vk_encoded_len(n);
    let dst = out
        .get_mut(..len)
        .ok_or(ProgramError::AccountDataTooSmall)?;
    dst[VK_NR_PUBINPUTS_OFF] = n as u8;
    dst[VK_ALPHA_G1_OFF..VK_ALPHA_G1_OFF + G1_LEN].copy_from_slice(&vk.vk_alpha_g1);
    dst[VK_BETA_G2_OFF..VK_BETA_G2_OFF + G2_LEN].copy_from_slice(&vk.vk_beta_g2);
    dst[VK_GAMMA_G2_OFF..VK_GAMMA_G2_OFF + G2_LEN].copy_from_slice(&vk.vk_gamme_g2);
    dst[VK_DELTA_G2_OFF..VK_DELTA_G2_OFF + G2_LEN].copy_from_slice(&vk.vk_delta_g2);
    for (i, ic) in vk.vk_ic.iter().enumerate() {
        let off = VK_IC_OFF + i * G1_LEN;
        dst[off..off + G1_LEN].copy_from_slice(ic);
    }
    Ok(len)
}

/// Decode the canonical encoding into a `Groth16Verifyingkey` borrowing
/// `scratch`. Fail-closed on shape: the length must be EXACTLY the pinned
/// circuit's, and the stored `nr_pubinputs` byte must agree with it.
pub fn decode<'s>(
    vk: &[u8],
    circuit: &ApprovedCircuit,
    scratch: &'s mut IcScratch,
) -> Result<Groth16Verifyingkey<'s>, ProgramError> {
    let n = circuit.nr_pubinputs;
    if n > VK_MAX_PUBLIC_INPUTS || vk.len() != vk_encoded_len(n) {
        return Err(MirrorPoolError::MalformedInstruction.into());
    }
    if vk[VK_NR_PUBINPUTS_OFF] as usize != n {
        return Err(MirrorPoolError::MalformedInstruction.into());
    }
    let n_ic = n + 1;
    for (i, slot) in scratch.ic[..n_ic].iter_mut().enumerate() {
        let off = VK_IC_OFF + i * G1_LEN;
        slot.copy_from_slice(&vk[off..off + G1_LEN]);
    }
    Ok(Groth16Verifyingkey {
        nr_pubinputs: n,
        vk_alpha_g1: read_g1(vk, VK_ALPHA_G1_OFF)?,
        vk_beta_g2: read_g2(vk, VK_BETA_G2_OFF)?,
        vk_gamme_g2: read_g2(vk, VK_GAMMA_G2_OFF)?,
        vk_delta_g2: read_g2(vk, VK_DELTA_G2_OFF)?,
        vk_ic: &scratch.ic[..n_ic],
    })
}

fn read_g1(data: &[u8], off: usize) -> Result<[u8; G1_LEN], ProgramError> {
    data.get(off..off + G1_LEN)
        .ok_or(ProgramError::AccountDataTooSmall)?
        .try_into()
        .map_err(|_| ProgramError::InvalidAccountData)
}

fn read_g2(data: &[u8], off: usize) -> Result<[u8; G2_LEN], ProgramError> {
    data.get(off..off + G2_LEN)
        .ok_or(ProgramError::AccountDataTooSmall)?
        .try_into()
        .map_err(|_| ProgramError::InvalidAccountData)
}

/// SHA-256 over one contiguous slice, via the `sol_sha256` syscall.
#[cfg(any(target_os = "solana", target_arch = "bpf"))]
#[inline(always)]
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let chunks: [&[u8]; 1] = [bytes];
    let mut out = [0u8; 32];
    unsafe {
        pinocchio::syscalls::sol_sha256(chunks.as_ptr() as *const u8, 1, out.as_mut_ptr());
    }
    out
}

#[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
#[inline(always)]
pub fn sha256(_bytes: &[u8]) -> [u8; 32] {
    unreachable!("SHA-256 uses an on-chain syscall and never runs on the host")
}

/// Load the verifying key a verify path must use, re-validating the pin.
///
/// Runs on EVERY verify, in this order, and fails closed at the first failure:
///
/// 1. the account is owned by this program (nobody else can have written it);
/// 2. it is the canonical registry PDA for `circuit_id` (so a program-owned
///    account of some other kind, or a second registry, cannot be substituted);
/// 3. its size, version, stored circuit id and reserved byte are exactly right;
/// 4. **the stored key hashes to the digest pinned at compile time**;
/// 5. it decodes into a `Groth16Verifyingkey` of the pinned shape.
///
/// Step 4 is the one that matters. Steps 1-3 already make it very hard to get
/// foreign bytes in front of the verifier, but they are ownership arguments;
/// step 4 is a content argument, and it holds even if an ownership argument
/// turns out to be wrong.
pub fn load_pinned<'s>(
    account: &AccountView,
    program_id: &Address,
    circuit_id_wanted: u8,
    scratch: &'s mut IcScratch,
) -> Result<Groth16Verifyingkey<'s>, ProgramError> {
    let circuit = approved(circuit_id_wanted)?;

    // (1) Program-owned. A registry this program did not write is not a registry.
    if !account.owned_by(program_id) {
        return Err(MirrorPoolError::VkRegistryNotInitialized.into());
    }
    // (2) The canonical registry PDA for this circuit, and no other account.
    let seed_id = [circuit.id];
    pda::verify_pda(account, &[pda::VK_REGISTRY_SEED, &seed_id], program_id)?;

    let data = account.try_borrow()?;
    // (3) Exact shape. Nothing here is inferred from the account.
    if data.len() != account_len(circuit.nr_pubinputs)
        || version(&data)? != VERSION_V1
        || circuit_id(&data)? != circuit.id
        || read_u8(&data, RESERVED_OFF)? != 0
    {
        return Err(MirrorPoolError::VkRegistryNotInitialized.into());
    }

    // (4) THE PIN.
    let vk = vk_bytes(&data)?;
    if sha256(vk) != circuit.digest {
        return Err(MirrorPoolError::VkNotApproved.into());
    }

    // (5) Structural decode into the caller's scratch.
    decode(vk, circuit, scratch)
}

/// THE single entry point every verify path uses: load the pinned key for
/// `circuit_id_wanted` out of its registry account, re-check the pin, and verify
/// the proof under it.
///
/// All three verifying instructions - `SETTLE_ZK` (membership), `TRANSACT`
/// (JoinSplit) and `SETTLE_ZK_ASSOCIATED` (association) - call exactly this, so
/// there is ONE place where a verifying key reaches a verifier and ONE place the
/// digest is re-checked. `docs/VK_REGISTRY.md` records that concentration as the
/// answer to the design's own main cost: an account-backed key is a second place
/// a mistake can live, and the mitigation is to keep it to a single function.
///
/// Generic over the public-input count so the same code serves circuits with 4,
/// 5 and 7 inputs. `#[inline(never)]` keeps the ~1 KB of decode scratch (the IC
/// buffer plus the `Groth16Verifyingkey` value) in its own SBF stack frame
/// instead of widening every caller's.
#[inline(never)]
pub fn verify_pinned<const N: usize>(
    account: &AccountView,
    program_id: &Address,
    circuit_id_wanted: u8,
    proof_a: &[u8; crate::wire::PROOF_A_LEN],
    proof_b: &[u8; crate::wire::PROOF_B_LEN],
    proof_c: &[u8; crate::wire::PROOF_C_LEN],
    public_inputs: &[[u8; 32]; N],
) -> Result<(), ProgramError> {
    let mut scratch = IcScratch::new();
    let verifying_key = load_pinned(account, program_id, circuit_id_wanted, &mut scratch)?;
    let mut verifier =
        Groth16Verifier::new(proof_a, proof_b, proof_c, public_inputs, &verifying_key)
            .map_err(|_| MirrorPoolError::ProofVerificationFailed)?;
    verifier
        .verify()
        .map_err(|_| MirrorPoolError::ProofVerificationFailed)?;
    Ok(())
}
