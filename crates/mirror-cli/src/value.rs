//! The confidential-value layer: build, prove, and emit a 2-in/2-out JoinSplit
//! `Transact` (shield / transfer / unshield), and scan on-chain `enc` blobs for
//! spendable notes.
//!
//! This is the value-carrying counterpart to [`crate::prove`] (the behavioral
//! `SettleZk`). Each operation is the SAME universal statement over
//! `circuits/transaction.circom`, distinguished only by the signed `publicAmount`:
//!
//! - **shield**  (deposit `v`): 2 dummy inputs, one real output to the recipient,
//!   `publicAmount = +v`. The depositor funds and co-signs (not gasless).
//! - **transfer** (`publicAmount = 0`): 1 real input + 1 dummy, a recipient output
//!   and a change output to self. Emitted for the gasless relay to submit with NO
//!   user signature (the unlinkability).
//! - **unshield** (withdraw `v`): 1 real input + 1 dummy, a change output to self,
//!   `publicAmount = r - v`, lamports leave the vault to a public recipient.
//!
//! Like `prove`, none of these SUBMIT: they rebuild the value Merkle path
//! off-chain, generate + verify a Groth16 proof with snarkjs, convert it to the
//! `groth16-solana` layout, and EMIT the Transact instruction data + account list
//! for the coordinator/relay to submit. The value accumulator path is rebuilt the
//! same way `prove` does the behavioral one: from the frontier snapshot captured
//! at the note's output time, verified against the on-chain value root ring.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use mirror_core::encrypted_note;
use mirror_core::note::{self, Note, SignedAmount, ValueKeypair};
use mirror_core::{wire, Hash32};
use serde::Serialize;
use solana_pubkey::Pubkey;

use crate::chain::{self, Chain, ValuePoolState};
use crate::groth16::{self, SnarkjsProof};
use crate::tree;
use crate::util::{be32_to_decimal, to_hex};
use crate::value_note::{ValueAddress, ValueNoteRecord, ValueWallet, VALUE_NOTE_VERSION};

/// One JoinSplit input: a value note plus everything needed to place it in the
/// witness. A dummy input has `amount == 0`, `leaf_index 0`, and the zero-ladder
/// siblings; its in-circuit Merkle membership check is disabled, but it still
/// carries a distinct, non-zero nullifier that the program marks spent.
pub struct ValueInput {
    pub note: Note,
    pub keypair: ValueKeypair,
    pub leaf_index: u64,
    /// Exactly [`tree::DEPTH`] sibling hashes, leaf to root.
    pub path_elements: Vec<Hash32>,
}

impl ValueInput {
    /// Build a fresh dummy input (`amount == 0`) with a random key + blinding, so
    /// its nullifier is unique per Transact (two identical dummies would collide
    /// on-chain as `NullifierSpent`).
    pub fn random_dummy() -> Self {
        let keypair = ValueKeypair::from_private_key(random_field_element());
        let note = Note::new(0, keypair.public_key(), random_field_element());
        Self {
            note,
            keypair,
            leaf_index: 0,
            path_elements: tree::zero_ladder(tree::DEPTH)[..tree::DEPTH].to_vec(),
        }
    }

    /// A deterministic dummy from explicit field elements (fixture reproduction).
    #[cfg(test)]
    pub fn dummy_from(private_key: Hash32, blinding: Hash32) -> Self {
        let keypair = ValueKeypair::from_private_key(private_key);
        let note = Note::new(0, keypair.public_key(), blinding);
        Self {
            note,
            keypair,
            leaf_index: 0,
            path_elements: tree::zero_ladder(tree::DEPTH)[..tree::DEPTH].to_vec(),
        }
    }

    pub fn nullifier(&self) -> Hash32 {
        note::note_nullifier(&self.keypair, &self.note, self.leaf_index)
    }
}

/// The external data bound (off-chain) into `extDataHash`. The circuit only binds
/// this against malleation; the program recomputes it from the accounts + payloads
/// it receives and requires equality.
pub struct ExtData {
    /// The withdraw-recipient Solana account (a placeholder for shield/transfer).
    pub recipient: [u8; 32],
    /// The relayer Solana account (the ValuePool authority).
    pub relayer: [u8; 32],
    pub fee: u64,
    pub enc0: Vec<u8>,
    pub enc1: Vec<u8>,
}

impl ExtData {
    pub fn hash(&self) -> Hash32 {
        note::ext_data_hash(
            &self.recipient,
            &self.relayer,
            self.fee,
            &self.enc0,
            &self.enc1,
        )
    }
}

/// A fully-specified 2-in / 2-out JoinSplit witness. Pure data: it computes every
/// public input and the circom `input.json` with no I/O, so it is exhaustively
/// unit-testable against the committed fixtures.
pub struct TransactWitness {
    pub inputs: [ValueInput; 2],
    pub outputs: [Note; 2],
    pub signed_amount: SignedAmount,
    /// The Merkle root the real input(s) prove against (a known recent on-chain root).
    pub root: Hash32,
    pub ext: ExtData,
}

impl TransactWitness {
    /// `publicAmount` as the canonical FIELD_SIZE-offset field element.
    pub fn public_amount(&self) -> Hash32 {
        note::public_amount(self.signed_amount)
    }

    /// The circuit's `(publicAmountMagnitude, publicAmountSign)` witness pair.
    pub fn magnitude_sign(&self) -> (u64, u8) {
        match self.signed_amount {
            SignedAmount::Transfer => (0, 0),
            SignedAmount::Deposit(v) => (v, 0),
            SignedAmount::Withdraw(v) => (v, 1),
        }
    }

    pub fn input_nullifiers(&self) -> [Hash32; 2] {
        [self.inputs[0].nullifier(), self.inputs[1].nullifier()]
    }

    pub fn output_commitments(&self) -> [Hash32; 2] {
        [self.outputs[0].commitment(), self.outputs[1].commitment()]
    }

    /// The Groth16 public inputs in the fixed on-chain order
    /// `[root, publicAmount, extDataHash, inNf0, inNf1, outC0, outC1]`.
    pub fn public_inputs(&self) -> [Hash32; wire::TRANSACT_N_PUBLIC_INPUTS] {
        let nf = self.input_nullifiers();
        let out = self.output_commitments();
        [
            self.root,
            self.public_amount(),
            self.ext.hash(),
            nf[0],
            nf[1],
            out[0],
            out[1],
        ]
    }

    /// The circom `input.json` object, byte-for-byte in the shape
    /// `gen_transaction_fixture.js` produces (decimal field-element strings).
    pub fn to_input_json(&self) -> serde_json::Value {
        let (mag, sign) = self.magnitude_sign();
        let nf = self.input_nullifiers();
        let out = self.output_commitments();
        serde_json::json!({
            "root": be32_to_decimal(&self.root),
            "publicAmount": be32_to_decimal(&self.public_amount()),
            "extDataHash": be32_to_decimal(&self.ext.hash()),
            "inputNullifier": [be32_to_decimal(&nf[0]), be32_to_decimal(&nf[1])],
            "outputCommitment": [be32_to_decimal(&out[0]), be32_to_decimal(&out[1])],
            "inAmount": [
                self.inputs[0].note.amount.to_string(),
                self.inputs[1].note.amount.to_string(),
            ],
            "inPrivateKey": [
                be32_to_decimal(&self.inputs[0].keypair.private_key),
                be32_to_decimal(&self.inputs[1].keypair.private_key),
            ],
            "inBlinding": [
                be32_to_decimal(&self.inputs[0].note.blinding),
                be32_to_decimal(&self.inputs[1].note.blinding),
            ],
            "inPathIndices": [
                self.inputs[0].leaf_index.to_string(),
                self.inputs[1].leaf_index.to_string(),
            ],
            "inPathElements": [
                self.inputs[0].path_elements.iter().map(be32_to_decimal).collect::<Vec<_>>(),
                self.inputs[1].path_elements.iter().map(be32_to_decimal).collect::<Vec<_>>(),
            ],
            "outAmount": [
                self.outputs[0].amount.to_string(),
                self.outputs[1].amount.to_string(),
            ],
            "outPubkey": [
                be32_to_decimal(&self.outputs[0].public_key),
                be32_to_decimal(&self.outputs[1].public_key),
            ],
            "outBlinding": [
                be32_to_decimal(&self.outputs[0].blinding),
                be32_to_decimal(&self.outputs[1].blinding),
            ],
            "publicAmountMagnitude": mag.to_string(),
            "publicAmountSign": sign.to_string(),
        })
    }

    /// In-circuit value conservation must hold before proving: for a valid
    /// JoinSplit `sum(inAmount) + publicAmount == sum(outAmount)` in the integers
    /// (a `u64` view is exact here because every amount and the magnitude fit u64).
    pub fn check_balanced(&self) -> Result<()> {
        let sum_in = self.inputs[0].note.amount as u128 + self.inputs[1].note.amount as u128;
        let sum_out = self.outputs[0].amount as u128 + self.outputs[1].amount as u128;
        let ok = match self.signed_amount {
            SignedAmount::Transfer => sum_in == sum_out,
            SignedAmount::Deposit(v) => sum_in + v as u128 == sum_out,
            SignedAmount::Withdraw(v) => sum_in == sum_out + v as u128,
        };
        if !ok {
            bail!(
                "unbalanced JoinSplit: sum(in)={sum_in}, sum(out)={sum_out}, {:?}",
                self.signed_amount
            );
        }
        // The circuit also forbids inputNullifier[0] == inputNullifier[1].
        let nf = self.input_nullifiers();
        if nf[0] == nf[1] {
            bail!("the two input nullifiers are equal (in-transaction double spend)");
        }
        Ok(())
    }
}

/// Artifact paths (+ optional snarkjs fallback) for proving a Transact.
pub struct TransactProveOpts {
    /// snarkjs invocation (only used by the `--use-snarkjs` fallback).
    pub snarkjs: String,
    /// Use the legacy snarkjs shell-out instead of the default in-process Rust
    /// prover. The default (false) spawns NO Node process.
    pub use_snarkjs: bool,
    pub wasm: PathBuf,
    /// Compiled R1CS (gitignored build output), needed by the in-process Rust prover.
    pub r1cs: PathBuf,
    pub zkey: PathBuf,
    pub vk: PathBuf,
    pub work_dir: Option<PathBuf>,
}

/// Generate + VERIFY the Groth16 proof for `witness`, cross-check the public
/// signals, and return the proof in the `groth16-solana` byte layout (`proof_a`
/// already negated). Fails loudly if the proof does not verify.
///
/// Default: in-process pure Rust (`ark-circom` + `ark-groth16`), spawning NO Node
/// process. Fallback (`--use-snarkjs`): shell out to `snarkjs groth16 fullprove`.
pub fn prove_transact(
    witness: &TransactWitness,
    opts: &TransactProveOpts,
) -> Result<groth16::ProofBytes> {
    witness.check_balanced()?;
    if opts.use_snarkjs {
        prove_transact_snarkjs(witness, opts)
    } else {
        // In-process Rust proving. `prove_rust::prove` computes the witness by
        // running the compiled transaction.wasm under wasmer, reads the proving key
        // from transaction_final.zkey, proves + verifies with ark-groth16, and
        // cross-checks the circuit's 7 public signals against the witness's.
        crate::prove_rust::prove(
            &crate::prove_rust::Artifacts {
                wasm: &opts.wasm,
                r1cs: &opts.r1cs,
                zkey: &opts.zkey,
            },
            &witness.to_input_json(),
            &witness.public_inputs(),
        )
        .context("in-process Rust Groth16 proving (transaction circuit)")
    }
}

/// Legacy fallback: shell out to snarkjs `groth16 fullprove` + `verify` (needs Node).
fn prove_transact_snarkjs(
    witness: &TransactWitness,
    opts: &TransactProveOpts,
) -> Result<groth16::ProofBytes> {
    let work_dir = match &opts.work_dir {
        Some(d) => d.clone(),
        None => std::env::temp_dir().join(format!(
            "mirror-cli-transact-{}",
            to_hex(&witness.output_commitments()[0])
        )),
    };
    std::fs::create_dir_all(&work_dir)
        .with_context(|| format!("creating work dir {}", work_dir.display()))?;

    let input_path = work_dir.join("input.json");
    std::fs::write(
        &input_path,
        serde_json::to_string_pretty(&witness.to_input_json())?,
    )
    .with_context(|| format!("writing {}", input_path.display()))?;

    let proof_path = work_dir.join("proof.json");
    let public_path = work_dir.join("public.json");
    crate::prove::run_fullprove(
        &opts.snarkjs,
        &input_path,
        &opts.wasm,
        &opts.zkey,
        &proof_path,
        &public_path,
    )?;
    crate::prove::verify_proof(&opts.snarkjs, &opts.vk, &public_path, &proof_path)?;

    cross_check_public(&public_path, &witness.public_inputs())?;

    let proof_json = std::fs::read_to_string(&proof_path)
        .with_context(|| format!("reading {}", proof_path.display()))?;
    SnarkjsProof::parse(&proof_json)?.to_bytes()
}

/// Confirm snarkjs's `public.json` equals our computed public inputs, in the fixed
/// circuit declaration order `[root, publicAmount, extDataHash, inNf0, inNf1,
/// outC0, outC1]`.
fn cross_check_public(
    public_path: &Path,
    expected: &[Hash32; wire::TRANSACT_N_PUBLIC_INPUTS],
) -> Result<()> {
    let raw = std::fs::read_to_string(public_path)
        .with_context(|| format!("reading {}", public_path.display()))?;
    let signals: Vec<String> = serde_json::from_str(&raw).context("parsing snarkjs public.json")?;
    if signals.len() != expected.len() {
        bail!(
            "public.json has {} signals, expected {}",
            signals.len(),
            expected.len()
        );
    }
    let names = [
        "root",
        "publicAmount",
        "extDataHash",
        "inputNullifier[0]",
        "inputNullifier[1]",
        "outputCommitment[0]",
        "outputCommitment[1]",
    ];
    for (i, exp) in expected.iter().enumerate() {
        let want = be32_to_decimal(exp);
        if signals[i] != want {
            bail!(
                "public signal {} ({}) from snarkjs ({}) != computed ({})",
                i,
                names[i],
                signals[i],
                want
            );
        }
    }
    Ok(())
}

/// The account list entry the CLI emits: pubkey + signer/writable flags + a role
/// label, so a soak driver can rebuild the exact `AccountMeta`s in order.
#[derive(Serialize)]
pub struct AccountMetaJson {
    pub pubkey: String,
    pub is_signer: bool,
    pub is_writable: bool,
    pub role: String,
}

/// The `Transact` bundle the CLI emits (machine-readable + text), analogous to
/// [`crate::prove::SettleZkEmit`].
#[derive(Serialize)]
pub struct TransactEmit {
    /// "shield" | "transfer" | "unshield".
    pub op: String,
    pub program_id: String,
    pub value_pool: String,
    /// The ValuePool authority (relay) that MUST sign every Transact.
    pub authority: String,
    pub vault: String,
    pub nullifier0_pda: String,
    pub nullifier1_pda: String,
    pub recipient: String,
    pub depositor: String,
    pub system_program: String,
    pub clock_sysvar: String,
    pub fee: u64,
    pub public_amount_hex: String,
    pub ext_data_hash_hex: String,
    pub root_hex: String,
    pub in_nullifier0_hex: String,
    pub in_nullifier1_hex: String,
    pub out_commitment0_hex: String,
    pub out_commitment1_hex: String,
    pub enc0_hex: String,
    pub enc1_hex: String,
    /// The full Transact instruction data (tag + body), hex.
    pub transact_data_hex: String,
    /// The account list in Transact order.
    pub accounts: Vec<AccountMetaJson>,
    /// True for shield: the depositor (account 5) must co-sign and fund the
    /// deposit. False for transfer/unshield: only the relay authority signs.
    pub shield_requires_depositor_signature: bool,
}

/// Which JoinSplit operation is being built (drives account roles + who signs).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Op {
    Shield,
    Transfer,
    Unshield,
}

impl Op {
    fn as_str(self) -> &'static str {
        match self {
            Op::Shield => "shield",
            Op::Transfer => "transfer",
            Op::Unshield => "unshield",
        }
    }
}

/// Assemble the emit (instruction data + account list) from a proven witness.
#[allow(clippy::too_many_arguments)]
fn build_emit(
    op: Op,
    program_id: &Pubkey,
    vpool: &Pubkey,
    vault: &Pubkey,
    authority: &Pubkey,
    recipient: &Pubkey,
    depositor: &Pubkey,
    witness: &TransactWitness,
    proof: &groth16::ProofBytes,
    fee: u64,
) -> Result<TransactEmit> {
    let pi = witness.public_inputs();
    // pi order: [root, publicAmount, extDataHash, nf0, nf1, out0, out1].
    let (root, public_amount, ext_data_hash) = (&pi[0], &pi[1], &pi[2]);
    let (nf0, nf1) = (&pi[3], &pi[4]);
    let (out0, out1) = (&pi[5], &pi[6]);

    let data = groth16::transact_data(
        public_amount,
        ext_data_hash,
        root,
        nf0,
        nf1,
        out0,
        out1,
        proof,
        fee,
        &witness.ext.enc0,
        &witness.ext.enc1,
    )?;

    let nf0_pda = chain::value_nullifier_pda(program_id, vpool, nf0);
    let nf1_pda = chain::value_nullifier_pda(program_id, vpool, nf1);
    let depositor_signs = op == Op::Shield;

    // Transact account order (see instructions::transact):
    // 0 vpool(w) 1 authority(signer,w) 2 nf0(w) 3 nf1(w) 4 recipient(w)
    // 5 depositor(signer for shield, w) 6 system 7 clock 8 vault(w).
    let accounts = vec![
        AccountMetaJson {
            pubkey: vpool.to_string(),
            is_signer: false,
            is_writable: true,
            role: "vpool".into(),
        },
        AccountMetaJson {
            pubkey: authority.to_string(),
            is_signer: true,
            is_writable: true,
            role: "authority/relay".into(),
        },
        AccountMetaJson {
            pubkey: nf0_pda.to_string(),
            is_signer: false,
            is_writable: true,
            role: "nullifier0".into(),
        },
        AccountMetaJson {
            pubkey: nf1_pda.to_string(),
            is_signer: false,
            is_writable: true,
            role: "nullifier1".into(),
        },
        AccountMetaJson {
            pubkey: recipient.to_string(),
            is_signer: false,
            is_writable: true,
            role: "recipient".into(),
        },
        AccountMetaJson {
            pubkey: depositor.to_string(),
            is_signer: depositor_signs,
            is_writable: true,
            role: "depositor".into(),
        },
        AccountMetaJson {
            pubkey: chain::SYSTEM_PROGRAM_ID.to_string(),
            is_signer: false,
            is_writable: false,
            role: "system_program".into(),
        },
        AccountMetaJson {
            pubkey: chain::CLOCK_SYSVAR_ID.to_string(),
            is_signer: false,
            is_writable: false,
            role: "clock_sysvar".into(),
        },
        AccountMetaJson {
            pubkey: vault.to_string(),
            is_signer: false,
            is_writable: true,
            role: "vault".into(),
        },
    ];

    Ok(TransactEmit {
        op: op.as_str().to_string(),
        program_id: program_id.to_string(),
        value_pool: vpool.to_string(),
        authority: authority.to_string(),
        vault: vault.to_string(),
        nullifier0_pda: nf0_pda.to_string(),
        nullifier1_pda: nf1_pda.to_string(),
        recipient: recipient.to_string(),
        depositor: depositor.to_string(),
        system_program: chain::SYSTEM_PROGRAM_ID.to_string(),
        clock_sysvar: chain::CLOCK_SYSVAR_ID.to_string(),
        fee,
        public_amount_hex: to_hex(public_amount),
        ext_data_hash_hex: to_hex(ext_data_hash),
        root_hex: to_hex(root),
        in_nullifier0_hex: to_hex(nf0),
        in_nullifier1_hex: to_hex(nf1),
        out_commitment0_hex: to_hex(out0),
        out_commitment1_hex: to_hex(out1),
        enc0_hex: to_hex(&witness.ext.enc0),
        enc1_hex: to_hex(&witness.ext.enc1),
        transact_data_hex: to_hex(&data),
        accounts,
        shield_requires_depositor_signature: depositor_signs,
    })
}

// --- Command orchestration --------------------------------------------------

/// `shield` arguments.
pub struct ShieldOpts {
    pub rpc_url: String,
    pub program_id: Pubkey,
    pub value_pool: Pubkey,
    /// The depositor Solana account (funds + co-signs the deposit).
    pub depositor: Pubkey,
    /// The value+viewing address the shielded note is created for.
    pub to: ValueAddress,
    pub amount: u64,
    pub note_dir: PathBuf,
    pub prove: TransactProveOpts,
    pub out: Option<PathBuf>,
}

/// Build + prove + emit a SHIELD (deposit `amount` into a fresh output note to
/// `--to`). Two dummy inputs, `publicAmount = +amount`.
pub fn run_shield(opts: ShieldOpts) -> Result<TransactEmit> {
    if opts.amount == 0 {
        bail!("--amount must be > 0 for a shield");
    }
    let chain = Chain::new(opts.rpc_url.clone());
    let vpool = chain
        .value_pool_state(&opts.value_pool)
        .context("reading the value pool account")?;
    check_denomination(&vpool, opts.amount)?;
    let authority = vpool.authority;
    let vault = chain::value_vault_pda(&opts.program_id, &opts.value_pool);

    // Dummies (unchecked): prove against the CURRENT on-chain root (always known).
    let root = vpool.current_root;
    let inputs = [ValueInput::random_dummy(), ValueInput::random_dummy()];

    // Two outputs to the recipient value key: the real note + a zero note.
    let blinding0 = random_field_element();
    let blinding1 = random_field_element();
    let out0 = Note::new(opts.amount, opts.to.value_public_key, blinding0);
    let out1 = Note::new(0, opts.to.value_public_key, blinding1);
    let enc0 = encrypted_note::encrypt_note(&opts.to.viewing_public_key, opts.amount, &blinding0);
    let enc1 = encrypted_note::encrypt_note(&opts.to.viewing_public_key, 0, &blinding1);

    // recipient (account 4) is a placeholder for a deposit (no withdrawal): bind
    // the authority. relayer is always the authority.
    let ext = ExtData {
        recipient: authority.to_bytes(),
        relayer: authority.to_bytes(),
        fee: vpool.fee,
        enc0,
        enc1,
    };
    let witness = TransactWitness {
        inputs,
        outputs: [out0, out1],
        signed_amount: SignedAmount::Deposit(opts.amount),
        root,
        ext,
    };

    let proof = prove_transact(&witness, &opts.prove)?;
    let emit = build_emit(
        Op::Shield,
        &opts.program_id,
        &opts.value_pool,
        &vault,
        &authority,
        &authority, // recipient placeholder
        &opts.depositor,
        &witness,
        &proof,
        vpool.fee,
    )?;

    // Save the sender's informational record of the real output (no private key;
    // the recipient recovers a spendable note via `scan`). out0 lands at
    // commitment_count; its pre-insert frontier is the current on-chain frontier.
    let count_pre = vpool.commitment_count;
    save_output_record(
        &opts.program_id,
        &opts.value_pool,
        &out0,
        count_pre,
        &vpool.frontier,
        None,
        Some(opts.to.viewing_public_key),
        &opts.note_dir,
    )?;

    maybe_write_out(&emit, opts.out.as_deref())?;
    Ok(emit)
}

/// `transfer` arguments.
pub struct TransferOpts {
    pub rpc_url: String,
    pub program_id: Pubkey,
    pub value_pool: Pubkey,
    /// The spendable input note record (from `scan`).
    pub note: PathBuf,
    pub to: ValueAddress,
    pub amount: u64,
    /// Where the change goes; defaults to the input note's own owner.
    pub change_to: Option<ValueAddress>,
    pub note_dir: PathBuf,
    pub prove: TransactProveOpts,
    pub out: Option<PathBuf>,
}

/// Build + prove + emit a TRANSFER: spend the input note, pay `amount` to `--to`
/// and the change back to self, `publicAmount = 0`. Emitted for the gasless relay.
pub fn run_transfer(opts: TransferOpts) -> Result<TransactEmit> {
    let input_rec = ValueNoteRecord::load(&opts.note)?;
    let spend = spend_input(&input_rec)?;
    let spend_kp = spend.keypair;
    let change = spend
        .input
        .note
        .amount
        .checked_sub(opts.amount)
        .ok_or_else(|| {
            anyhow!(
                "transfer amount {} exceeds the note value {}",
                opts.amount,
                spend.input.note.amount
            )
        })?;

    let chain = Chain::new(opts.rpc_url.clone());
    let vpool = chain
        .value_pool_state(&opts.value_pool)
        .context("reading the value pool account")?;
    let authority = vpool.authority;
    let vault = chain::value_vault_pda(&opts.program_id, &opts.value_pool);

    verify_known_root(&spend.root, &vpool)?;
    let root = spend.root;

    // Change destination: self by default (needs the owner's viewing key), or an
    // explicit --change-to address.
    let (change_value_pub, change_viewing_pub, change_is_self) =
        change_destination(&input_rec, &spend_kp, opts.change_to, change)?;

    // out0 = change to self, out1 = the recipient payment.
    let b_change = random_field_element();
    let b_pay = random_field_element();
    let out0 = Note::new(change, change_value_pub, b_change);
    let out1 = Note::new(opts.amount, opts.to.value_public_key, b_pay);
    let enc0 = encrypted_note::encrypt_note(&change_viewing_pub, change, &b_change);
    let enc1 = encrypted_note::encrypt_note(&opts.to.viewing_public_key, opts.amount, &b_pay);

    let ext = ExtData {
        recipient: authority.to_bytes(), // placeholder (no withdrawal)
        relayer: authority.to_bytes(),
        fee: vpool.fee,
        enc0,
        enc1,
    };
    let witness = TransactWitness {
        inputs: [spend.input, ValueInput::random_dummy()],
        outputs: [out0, out1],
        signed_amount: SignedAmount::Transfer,
        root,
        ext,
    };

    let proof = prove_transact(&witness, &opts.prove)?;
    let emit = build_emit(
        Op::Transfer,
        &opts.program_id,
        &opts.value_pool,
        &vault,
        &authority,
        &authority, // recipient placeholder (transfer moves no public lamports)
        &authority, // depositor slot unused for transfer
        &witness,
        &proof,
        vpool.fee,
    )?;

    // Save the change (out0) as spendable iff it went back to us; save the
    // recipient (out1) informationally. out0 lands at commitment_count, out1 next.
    let count_pre = vpool.commitment_count;
    let change_priv = change_is_self.then_some(spend_kp.private_key);
    if change > 0 {
        save_output_record(
            &opts.program_id,
            &opts.value_pool,
            &witness.outputs[0],
            count_pre,
            &vpool.frontier,
            change_priv,
            Some(change_viewing_pub),
            &opts.note_dir,
        )?;
    }
    let mut frontier_after0 = vpool.frontier.clone();
    let _ = tree::append_incremental(
        &mut frontier_after0,
        count_pre,
        &witness.output_commitments()[0],
    );
    save_output_record(
        &opts.program_id,
        &opts.value_pool,
        &witness.outputs[1],
        count_pre + 1,
        &frontier_after0,
        None,
        Some(opts.to.viewing_public_key),
        &opts.note_dir,
    )?;

    maybe_write_out(&emit, opts.out.as_deref())?;
    Ok(emit)
}

/// `unshield` arguments.
pub struct UnshieldOpts {
    pub rpc_url: String,
    pub program_id: Pubkey,
    pub value_pool: Pubkey,
    /// The spendable input note record (from `scan`).
    pub note: PathBuf,
    /// The public Solana account credited by the withdrawal.
    pub recipient: Pubkey,
    pub amount: u64,
    pub note_dir: PathBuf,
    pub prove: TransactProveOpts,
    pub out: Option<PathBuf>,
}

/// Build + prove + emit an UNSHIELD: spend the input note, withdraw `amount`
/// lamports to `--recipient`, change back to self, `publicAmount = r - amount`.
/// Emitted for the gasless relay.
pub fn run_unshield(opts: UnshieldOpts) -> Result<TransactEmit> {
    if opts.amount == 0 {
        bail!("--amount must be > 0 for an unshield");
    }
    let input_rec = ValueNoteRecord::load(&opts.note)?;
    let spend = spend_input(&input_rec)?;
    let spend_kp = spend.keypair;
    let change = spend
        .input
        .note
        .amount
        .checked_sub(opts.amount)
        .ok_or_else(|| {
            anyhow!(
                "withdraw amount {} exceeds the note value {}",
                opts.amount,
                spend.input.note.amount
            )
        })?;

    let chain = Chain::new(opts.rpc_url.clone());
    let vpool = chain
        .value_pool_state(&opts.value_pool)
        .context("reading the value pool account")?;
    let authority = vpool.authority;
    let vault = chain::value_vault_pda(&opts.program_id, &opts.value_pool);
    check_denomination(&vpool, opts.amount)?;
    verify_known_root(&spend.root, &vpool)?;
    let root = spend.root;

    // Change goes back to self (needs the owner's viewing key, stored by scan).
    let (change_value_pub, change_viewing_pub, _self) =
        change_destination(&input_rec, &spend_kp, None, change)?;

    // out0 = change to self, out1 = zero note to self.
    let b_change = random_field_element();
    let b_zero = random_field_element();
    let out0 = Note::new(change, change_value_pub, b_change);
    let out1 = Note::new(0, change_value_pub, b_zero);
    let enc0 = encrypted_note::encrypt_note(&change_viewing_pub, change, &b_change);
    let enc1 = encrypted_note::encrypt_note(&change_viewing_pub, 0, &b_zero);

    let ext = ExtData {
        recipient: opts.recipient.to_bytes(),
        relayer: authority.to_bytes(),
        fee: vpool.fee,
        enc0,
        enc1,
    };
    let witness = TransactWitness {
        inputs: [spend.input, ValueInput::random_dummy()],
        outputs: [out0, out1],
        signed_amount: SignedAmount::Withdraw(opts.amount),
        root,
        ext,
    };

    let proof = prove_transact(&witness, &opts.prove)?;
    let emit = build_emit(
        Op::Unshield,
        &opts.program_id,
        &opts.value_pool,
        &vault,
        &authority,
        &opts.recipient,
        &authority, // depositor slot unused for unshield
        &witness,
        &proof,
        vpool.fee,
    )?;

    // Save the change (out0) as spendable; out0 lands at commitment_count.
    if change > 0 {
        save_output_record(
            &opts.program_id,
            &opts.value_pool,
            &witness.outputs[0],
            vpool.commitment_count,
            &vpool.frontier,
            Some(spend_kp.private_key),
            Some(change_viewing_pub),
            &opts.note_dir,
        )?;
    }

    maybe_write_out(&emit, opts.out.as_deref())?;
    Ok(emit)
}

/// `scan` arguments.
pub struct ScanOpts {
    pub viewing_key: PathBuf,
    /// A file of on-chain `enc` blobs, one hex blob per non-empty line.
    pub blobs: PathBuf,
    /// Optional ordered on-chain value commitments (one hex per line) to recover
    /// each hit's leaf index + inclusion path (needed on a no-history validator).
    pub leaves: Option<PathBuf>,
    pub rpc_url: Option<String>,
    pub value_pool: Option<Pubkey>,
    pub program_id: Option<Pubkey>,
    pub note_dir: PathBuf,
}

/// A recovered note the wallet can spend.
pub struct ScannedNote {
    pub amount: u64,
    pub commitment: Hash32,
    pub leaf_index: Option<u64>,
    pub saved_path: Option<PathBuf>,
}

/// Trial-decrypt each `enc` blob with the wallet's viewing key; for each hit,
/// rebuild the note commitment from the wallet's value public key, recover its
/// leaf index + inclusion path from the ordered on-chain commitments (verifying
/// the rebuilt root is a known recent on-chain root), and save a spendable note.
pub fn run_scan(opts: ScanOpts) -> Result<Vec<ScannedNote>> {
    let keyfile = crate::value_note::ValueKeyfile::load(&opts.viewing_key)?;
    let wallet = ValueWallet::from_keyfile(&keyfile)?;
    let value_pub = wallet.value.public_key();
    let viewing_pub = wallet.viewing.public();

    let blobs = read_hex_lines(&opts.blobs)?;
    let leaf_set = match &opts.leaves {
        Some(p) => Some(read_leaves(p)?),
        None => None,
    };
    let vpool_state = match (&opts.rpc_url, &opts.value_pool) {
        (Some(url), Some(vpool)) => Some(Chain::new(url.clone()).value_pool_state(vpool)?),
        _ => None,
    };

    let mut out = Vec::new();
    for blob in &blobs {
        let Some(dec) = encrypted_note::try_decrypt_note(&wallet.viewing.to_secret_bytes(), blob)
        else {
            continue; // not addressed to us (or a decoy): silently skip
        };
        let commitment = dec.to_note(value_pub).commitment();

        // Recover the leaf index + frontier snapshot from the ordered commitments.
        let (leaf_index, frontier_pre) = match &leaf_set {
            Some(leaves) => match leaves.iter().position(|c| c == &commitment) {
                Some(idx) => {
                    let idx = idx as u64;
                    // Rebuild the frontier BEFORE this leaf (the state after leaves
                    // 0..idx) so a later spend can walk it with incremental_path.
                    let mut frontier = vec![tree::ZERO_LEAF; tree::DEPTH];
                    for (i, leaf) in leaves.iter().take(idx as usize).enumerate() {
                        let _ = tree::append_incremental(&mut frontier, i as u64, leaf);
                    }
                    // Verify the rebuilt inclusion path's root is a known on-chain root.
                    if let Some(state) = &vpool_state {
                        let path = tree::incremental_path(&commitment, idx, &frontier);
                        if !state.is_known_root(&path.root) {
                            bail!(
                                "recovered note {} rebuilds to root {}, which is not a known \
                                 recent on-chain root (stale --leaves?)",
                                to_hex(&commitment),
                                to_hex(&path.root)
                            );
                        }
                    }
                    (Some(idx), Some(frontier))
                }
                None => (None, None),
            },
            None => (None, None),
        };

        // Save a spendable record when we have located the note in the accumulator.
        let saved_path = if let (Some(program_id), Some(vpool), Some(idx), Some(frontier)) = (
            opts.program_id,
            opts.value_pool,
            leaf_index,
            frontier_pre.as_ref(),
        ) {
            let rec = ValueNoteRecord {
                version: VALUE_NOTE_VERSION,
                program_id: program_id.to_string(),
                value_pool: vpool.to_string(),
                amount: dec.amount,
                public_key_hex: to_hex(&value_pub),
                blinding_hex: to_hex(&dec.blinding),
                commitment_hex: to_hex(&commitment),
                private_key_hex: Some(to_hex(&wallet.value.private_key)),
                owner_viewing_public_key_hex: Some(to_hex(&viewing_pub)),
                leaf_index: Some(idx),
                frontier_pre: Some(frontier.iter().map(|h| to_hex(h)).collect()),
            };
            Some(rec.save(&opts.note_dir)?)
        } else {
            None
        };

        out.push(ScannedNote {
            amount: dec.amount,
            commitment,
            leaf_index,
            saved_path,
        });
    }
    Ok(out)
}

// --- shared helpers ---------------------------------------------------------

/// The rebuilt real input plus the Merkle root its inclusion path leads to.
struct SpendInput {
    input: ValueInput,
    keypair: ValueKeypair,
    root: Hash32,
}

/// Reconstruct the real input (note + inclusion path + root) from a spendable note
/// record, rebuilding the path off-chain by walking the note's frontier snapshot
/// (exactly as the behavioral `prove` does).
fn spend_input(rec: &ValueNoteRecord) -> Result<SpendInput> {
    let keypair = rec.keypair()?; // errors if the record is not spendable
    let note = rec.note()?;
    if keypair.public_key() != note.public_key {
        bail!("note record public_key does not match its private key");
    }
    let leaf_index = rec
        .leaf_index
        .ok_or_else(|| anyhow!("note record has no leaf_index; re-scan with --leaves"))?;
    let frontier_hex = rec
        .frontier_pre
        .as_ref()
        .ok_or_else(|| anyhow!("note record has no frontier snapshot; re-scan with --leaves"))?;
    if frontier_hex.len() != tree::DEPTH {
        bail!(
            "note frontier snapshot has {} levels, expected {}",
            frontier_hex.len(),
            tree::DEPTH
        );
    }
    let mut frontier = Vec::with_capacity(tree::DEPTH);
    for h in frontier_hex {
        frontier.push(crate::util::from_hex32(h)?);
    }
    let path = tree::incremental_path(&note.commitment(), leaf_index, &frontier);
    if tree::verify_path(&note.commitment(), &path.elements, &path.indices) != path.root {
        bail!("client-side input path does not verify to its root (rebuild bug)");
    }
    Ok(SpendInput {
        input: ValueInput {
            note,
            keypair,
            leaf_index,
            path_elements: path.elements,
        },
        keypair,
        root: path.root,
    })
}

/// Fail fast if the ValuePool pins a fixed denomination and the public amount
/// (a deposit or withdraw magnitude) does not match it. Mirrors the on-chain
/// `DenominationMismatch` check so the CLI rejects a doomed Transact before
/// spending time on a proof. Internal transfers (amount not applicable) are exempt.
fn check_denomination(vpool: &ValuePoolState, amount: u64) -> Result<()> {
    if let Some(d) = vpool.denomination {
        if amount != d {
            bail!(
                "this value pool pins a fixed denomination of {d} lamports; \
                 a public deposit/withdraw must move exactly that amount (got {amount})"
            );
        }
    }
    Ok(())
}

/// Confirm a rebuilt input root is a root the ValuePool currently accepts.
fn verify_known_root(root: &Hash32, vpool: &ValuePoolState) -> Result<()> {
    if !vpool.is_known_root(root) {
        bail!(
            "input note root {} is not a known recent on-chain root (it may have aged out of \
             the {}-root history; spend sooner, or re-scan)",
            to_hex(root),
            vpool.root_ring.len()
        );
    }
    Ok(())
}

/// Resolve the change destination `(value_pub, viewing_pub, is_self)`.
fn change_destination(
    input_rec: &ValueNoteRecord,
    spend_kp: &ValueKeypair,
    change_to: Option<ValueAddress>,
    change: u64,
) -> Result<(Hash32, [u8; 32], bool)> {
    if let Some(addr) = change_to {
        let is_self = addr.value_public_key == spend_kp.public_key();
        return Ok((addr.value_public_key, addr.viewing_public_key, is_self));
    }
    // Default: back to the input note's own owner. Needs the owner's viewing key,
    // which `scan` records on the spendable note.
    let value_pub = spend_kp.public_key();
    let viewing_hex = input_rec.owner_viewing_public_key_hex.as_ref();
    match viewing_hex {
        Some(h) => Ok((value_pub, crate::util::from_hex32(h)?, true)),
        None if change == 0 => {
            // No change to hide: a zero note back to self, viewing key irrelevant.
            Ok((value_pub, [0u8; 32], true))
        }
        None => bail!(
            "the input note has no owner viewing key to send the change to; \
             re-scan it (which records the viewing key) or pass --change-to"
        ),
    }
}

/// Save one output-note record (spendable when `private_key` is Some).
#[allow(clippy::too_many_arguments)]
fn save_output_record(
    program_id: &Pubkey,
    vpool: &Pubkey,
    note: &Note,
    leaf_index: u64,
    frontier_pre: &[Hash32],
    private_key: Option<Hash32>,
    owner_viewing_pub: Option<[u8; 32]>,
    note_dir: &Path,
) -> Result<PathBuf> {
    let rec = ValueNoteRecord {
        version: VALUE_NOTE_VERSION,
        program_id: program_id.to_string(),
        value_pool: vpool.to_string(),
        amount: note.amount,
        public_key_hex: to_hex(&note.public_key),
        blinding_hex: to_hex(&note.blinding),
        commitment_hex: to_hex(&note.commitment()),
        private_key_hex: private_key.map(|k| to_hex(&k)),
        owner_viewing_public_key_hex: owner_viewing_pub.map(|v| to_hex(&v)),
        leaf_index: Some(leaf_index),
        frontier_pre: Some(frontier_pre.iter().map(|h| to_hex(h)).collect()),
    };
    rec.save(note_dir)
}

/// A field element uniformly random in `[0, 2^248)`, so it is always a canonical
/// BN254 scalar (< r) with no reduction needed (top byte cleared).
fn random_field_element() -> Hash32 {
    use rand::RngCore;
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b[0] = 0; // < 2^248 < r
    b
}

fn maybe_write_out(emit: &TransactEmit, out: Option<&Path>) -> Result<()> {
    if let Some(path) = out {
        let json = serde_json::to_string_pretty(emit).context("serializing emit")?;
        std::fs::write(path, json).with_context(|| format!("writing {}", path.display()))?;
    }
    Ok(())
}

/// Read a file of hex byte strings (one per non-empty, non-`#` line) into blobs.
fn read_hex_lines(path: &Path) -> Result<Vec<Vec<u8>>> {
    let raw =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let mut out = Vec::new();
    for (i, line) in raw.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        out.push(
            hex_bytes(line)
                .with_context(|| format!("blob on line {} of {}", i + 1, path.display()))?,
        );
    }
    Ok(out)
}

/// Read a leaf set (one 64-char hex commitment per non-empty line, in order).
fn read_leaves(path: &Path) -> Result<Vec<Hash32>> {
    let raw =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let mut leaves = Vec::new();
    for (i, line) in raw.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        leaves.push(
            crate::util::from_hex32(line)
                .with_context(|| format!("leaf on line {} of {}", i + 1, path.display()))?,
        );
    }
    Ok(leaves)
}

/// Decode an even-length hex string into bytes.
fn hex_bytes(s: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("expected an even-length hex string");
    }
    Ok((0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("validated hex"))
        .collect())
}

#[cfg(test)]
mod tests;
