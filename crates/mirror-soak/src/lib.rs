//! Shared scaffolding for the three soak binaries.
//!
//! `mirror-soak` (behavioral), `mirror-soak-value` (confidential value) and
//! `mirror-soak-funding` (funding rounds) each drive a different property, but
//! they all talk to the same chain the same way: shell out to the shipped
//! `mirror-cli`, fund keys off the faucet (or off a master payer on a public
//! cluster), build the same two wire-format instructions, send v0 transactions,
//! and accumulate PASS/FAIL checks into a report.
//!
//! That scaffolding lives here ONCE. Nothing in this module decides anything
//! about what is proved; it is transport, process spawning, and byte layout.
//! Each binary keeps its own assertions, its own prose, and its own `main`.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};

use mirror_coordinator::client::SolanaClient;

use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_message::{v0, AddressLookupTableAccount, VersionedMessage};
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;

/// The default local RPC: the Surfpool mainnet mirror.
pub const DEFAULT_RPC_URL: &str = "http://127.0.0.1:8899";

// ---------------------------------------------------------------------------
// Fixed addresses + PDA seeds (byte-identical to the on-chain `pda` module)
// ---------------------------------------------------------------------------

pub const SYSTEM_PROGRAM_ID: Pubkey = Pubkey::from_str_const("11111111111111111111111111111111");
pub const CLOCK_SYSVAR_ID: Pubkey =
    Pubkey::from_str_const("SysvarC1ock11111111111111111111111111111111");
pub const VALUE_POOL_SEED: &[u8] = b"vpool";
pub const VALUE_VAULT_SEED: &[u8] = b"vvault";
pub const VALUE_NULLIFIER_SEED: &[u8] = b"vnf";

/// Derive the Pool PDA: seeds `[b"pool", authority]`.
pub fn pool_pda(program_id: &Pubkey, authority: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[b"pool", authority.as_ref()], program_id).0
}

pub fn value_pool_pda(program_id: &Pubkey, authority: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[VALUE_POOL_SEED, authority.as_ref()], program_id).0
}

pub fn value_vault_pda(program_id: &Pubkey, vpool: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[VALUE_VAULT_SEED, vpool.as_ref()], program_id).0
}

pub fn value_nullifier_pda(program_id: &Pubkey, vpool: &Pubkey, nullifier: &[u8; 32]) -> Pubkey {
    Pubkey::find_program_address(
        &[VALUE_NULLIFIER_SEED, vpool.as_ref(), nullifier],
        program_id,
    )
    .0
}

// ---------------------------------------------------------------------------
// Report accumulation
// ---------------------------------------------------------------------------

/// Every assertion a soak makes, plus every signature it captured, in order,
/// plus the honest observations that are NOT assertions.
#[derive(Default)]
pub struct Report {
    pub checks: Vec<(String, bool, String)>,
    pub sigs: Vec<(String, String)>,
    pub notes: Vec<String>,
}

impl Report {
    pub fn check(&mut self, label: &str, pass: bool, detail: impl Into<String>) {
        self.checks.push((label.to_string(), pass, detail.into()));
        let mark = if pass { "PASS" } else { "FAIL" };
        println!("  [{mark}] {label} - {}", self.checks.last().unwrap().2);
    }
    pub fn sig(&mut self, label: &str, sig: impl Into<String>) {
        let sig = sig.into();
        println!("  tx  {label}: {sig}");
        self.sigs.push((label.to_string(), sig));
    }
    /// An honest observation that is not a pass/fail assertion.
    pub fn note(&mut self, note: impl Into<String>) {
        let note = note.into();
        println!("  note: {note}");
        self.notes.push(note);
    }
    pub fn all_passed(&self) -> bool {
        self.checks.iter().all(|(_, p, _)| *p)
    }
}

/// Emit a machine-readable JSON report (metadata + every assertion + every
/// captured signature) for the public-devnet path, where the caller assembles
/// docs/PROOF.md out of band (adding Finalized confirmation + CU per signature).
pub fn write_report_json(path: &str, meta: serde_json::Value, report: &Report) -> Result<()> {
    let checks: Vec<serde_json::Value> = report
        .checks
        .iter()
        .map(|(label, pass, detail)| {
            serde_json::json!({ "label": label, "pass": pass, "detail": detail })
        })
        .collect();
    let sigs: Vec<serde_json::Value> = report
        .sigs
        .iter()
        .map(|(label, sig)| serde_json::json!({ "label": label, "sig": sig }))
        .collect();
    let mut v = meta;
    v["checks"] = serde_json::Value::Array(checks);
    v["sigs"] = serde_json::Value::Array(sigs);
    v["passed"] = serde_json::json!(report.checks.iter().filter(|(_, p, _)| *p).count());
    v["total"] = serde_json::json!(report.checks.len());
    std::fs::write(path, serde_json::to_string_pretty(&v)?)
        .with_context(|| format!("writing report json {path}"))?;
    Ok(())
}

/// Open a `docs/PROOF.md` section that REPLACES the previous run of the same
/// soak: keep everything written before `marker`, then re-open the section under
/// it. Returns the buffer to append to plus this run's unix timestamp.
pub fn begin_proof_section(root: &Path, marker: &str) -> Result<(String, u64)> {
    let docs = root.join("docs");
    std::fs::create_dir_all(&docs)?;
    let mut base = std::fs::read_to_string(docs.join("PROOF.md")).unwrap_or_default();
    if let Some(pos) = base.find(marker) {
        base.truncate(pos);
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    Ok((format!("{}\n\n{marker}\n", base.trim_end()), now))
}

/// The assertion table, under a `##` or `###` heading depending on whether the
/// caller owns the whole file or appends a section to it.
pub fn checks_table(s: &mut String, report: &Report, heading: &str) {
    let passed = report.checks.iter().filter(|(_, p, _)| *p).count();
    s.push_str(&format!(
        "{heading} On-chain assertions\n\n{passed}/{} assertions passed.\n\n\
         | result | assertion | detail |\n| --- | --- | --- |\n",
        report.checks.len()
    ));
    for (label, pass, detail) in &report.checks {
        s.push_str(&format!(
            "| {} | {label} | {} |\n",
            if *pass { "PASS" } else { "FAIL" },
            detail.replace('|', "\\|")
        ));
    }
    s.push('\n');
}

/// The captured-signature table, under a `##` or `###` heading.
pub fn sigs_table(s: &mut String, report: &Report, heading: &str) {
    s.push_str(&format!(
        "{heading} Captured transaction signatures\n\n| step | signature |\n| --- | --- |\n"
    ));
    for (label, sig) in &report.sigs {
        s.push_str(&format!("| {label} | `{sig}` |\n"));
    }
    s.push('\n');
}

// ---------------------------------------------------------------------------
// Environment / external-binary helpers
// ---------------------------------------------------------------------------

/// The workspace root: `<root>/target/<profile>/<soak binary>` -> `<root>`.
pub fn repo_root() -> Result<PathBuf> {
    if let Ok(r) = std::env::var("MIRROR_REPO_ROOT") {
        return Ok(PathBuf::from(r));
    }
    let exe = std::env::current_exe().context("current_exe")?;
    let root = exe
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
        .ok_or_else(|| anyhow!("cannot derive repo root from {}", exe.display()))?;
    Ok(root.to_path_buf())
}

/// The `mirror-cli` binary that ships alongside this soak binary.
pub fn cli_bin() -> Result<PathBuf> {
    if let Ok(p) = std::env::var("MIRROR_CLI_BIN") {
        return Ok(PathBuf::from(p));
    }
    let exe = std::env::current_exe().context("current_exe")?;
    let sibling = exe
        .parent()
        .ok_or_else(|| anyhow!("no parent for {}", exe.display()))?
        .join("mirror-cli");
    if sibling.exists() {
        return Ok(sibling);
    }
    bail!(
        "mirror-cli binary not found at {} (build it with `cargo build -p mirror-cli`, or set MIRROR_CLI_BIN)",
        sibling.display()
    )
}

/// The HEAD proving key of a local phase-2 ceremony directory, e.g.
/// `ceremony/transaction/key_0002.mpk`.
///
/// The deployed verifying keys are ceremony outputs, so a proof made under the
/// `circuits/*_final.zkey` dev key cannot land. The soak therefore proves under
/// the ceremony key, and this resolves which file that is: the highest-numbered
/// `key_NNNN.mpk` in the directory. Key files are multi-megabyte and gitignored
/// (only the transcript is published), exactly like the `.zkey`/`.wasm` the soak
/// already requires, so a missing one is a setup error rather than a skip.
///
/// `MIRROR_<CIRCUIT>_PROVING_KEY` overrides the lookup for a ceremony directory
/// kept somewhere else.
pub fn ceremony_head_key(root: &Path, circuit: &str) -> Result<PathBuf> {
    let env_var = format!("MIRROR_{}_PROVING_KEY", circuit.to_uppercase());
    if let Ok(p) = std::env::var(&env_var) {
        let p = PathBuf::from(p);
        if !p.exists() {
            bail!("{env_var} points at {}, which does not exist", p.display());
        }
        return Ok(p);
    }
    let dir = root.join("ceremony").join(circuit);
    let mut best: Option<(u32, PathBuf)> = None;
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
                continue;
            };
            let Some(index) = name
                .strip_prefix("key_")
                .and_then(|s| s.strip_suffix(".mpk"))
                .and_then(|s| s.parse::<u32>().ok())
            else {
                continue;
            };
            if best.as_ref().is_none_or(|(b, _)| index > *b) {
                best = Some((index, path));
            }
        }
    }
    match best {
        Some((_, path)) => Ok(path),
        None => bail!(
            "no ceremony proving key found in {} (run the {circuit} ceremony as described in \
             docs/CEREMONY.md, or set {env_var})",
            dir.display()
        ),
    }
}

/// Resolve `bin` on PATH, or `None` if it is not installed.
pub fn which(bin: &str) -> Option<String> {
    let out = Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {bin}"))
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// Airdrop `sol` SOL to `pubkey` via the local validator faucet.
pub fn airdrop(rpc_url: &str, pubkey: &Pubkey, sol: u64) -> Result<()> {
    let out = Command::new("solana")
        .args([
            "airdrop",
            &sol.to_string(),
            &pubkey.to_string(),
            "--url",
            rpc_url,
        ])
        .output()
        .context("spawning `solana airdrop`")?;
    if !out.status.success() {
        bail!(
            "solana airdrop {sol} {pubkey} failed:\n{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(())
}

/// System-transfer `lamports` from the pre-funded master payer to `to`.
///
/// The devnet funding path: a public cluster rate-limits faucet airdrops, so the
/// run airdrops ONE master payer and fans out to every relay/participant via
/// ordinary system transfers instead of one airdrop per key.
pub fn transfer_from_master(rpc_url: &str, master: &str, to: &Pubkey, lamports: u64) -> Result<()> {
    let sol = format!(
        "{}.{:09}",
        lamports / 1_000_000_000,
        lamports % 1_000_000_000
    );
    let out = Command::new("solana")
        .args([
            "transfer",
            &to.to_string(),
            &sol,
            "--keypair",
            master,
            "--fee-payer",
            master,
            "--url",
            rpc_url,
            "--allow-unfunded-recipient",
            "--commitment",
            "confirmed",
        ])
        .output()
        .context("spawning `solana transfer`")?;
    if !out.status.success() {
        bail!(
            "solana transfer {sol} -> {to} failed:\n{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(())
}

/// Fund `pubkey`. On a public cluster (when `MIRROR_FUNDING_KEYPAIR` names the
/// pre-funded master payer) this is a system transfer of `devnet_lamports` from
/// that master; otherwise it is a local faucet airdrop of `local_sol` whole SOL
/// (the Surfpool path, unchanged).
pub fn fund(rpc_url: &str, pubkey: &Pubkey, local_sol: u64, devnet_lamports: u64) -> Result<()> {
    if let Ok(master) = std::env::var("MIRROR_FUNDING_KEYPAIR") {
        transfer_from_master(rpc_url, &master, pubkey, devnet_lamports)
    } else {
        airdrop(rpc_url, pubkey, local_sol)
    }
}

/// Generate a fresh keypair and persist it (gitignored) so a run is auditable.
pub fn new_keypair(dir: &Path, name: &str) -> Result<Keypair> {
    let kp = Keypair::new();
    let path = dir.join(format!("{name}.json"));
    std::fs::write(&path, serde_json::to_string(&kp.to_bytes().to_vec())?)
        .with_context(|| format!("writing keypair {}", path.display()))?;
    Ok(kp)
}

/// Deep-copy a keypair (Keypair is not Clone; go via its 64 bytes).
pub fn clone_keypair(kp: &Keypair) -> Keypair {
    Keypair::try_from(kp.to_bytes().as_slice()).expect("a keypair round-trips through its bytes")
}

/// Load a keypair from a `solana-keygen`-style JSON byte array.
pub fn load_keypair(path: &Path) -> Result<Keypair> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading keypair {}", path.display()))?;
    let bytes: Vec<u8> = serde_json::from_str(&raw)
        .with_context(|| format!("parsing {} as a JSON byte array", path.display()))?;
    Keypair::try_from(bytes.as_slice()).map_err(|e| anyhow!("invalid keypair: {e}"))
}

/// Shell out to the shipped `mirror-cli`, returning stdout (bails on nonzero).
pub fn run_cli(cli: &Path, cwd: &Path, args: &[&str]) -> Result<String> {
    let out = Command::new(cli)
        .current_dir(cwd)
        .args(args)
        .output()
        .with_context(|| format!("spawning {}", cli.display()))?;
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    if !out.status.success() {
        bail!(
            "mirror-cli {:?} failed:\n{stdout}\n{}",
            args,
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(stdout)
}

/// Run `mirror-cli` EXPECTING failure; return the combined stdout+stderr on a
/// nonzero exit, or `Err` if the command unexpectedly succeeded.
pub fn run_cli_expect_fail(cli: &Path, cwd: &Path, args: &[&str]) -> Result<String> {
    let out = Command::new(cli)
        .current_dir(cwd)
        .args(args)
        .output()
        .with_context(|| format!("spawning {}", cli.display()))?;
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    if out.status.success() {
        bail!("mirror-cli {:?} unexpectedly SUCCEEDED:\n{combined}", args);
    }
    Ok(combined)
}

/// Publish a circuit's verifying key into its write-once, digest-pinned registry
/// PDA, through the SHIPPED `mirror-cli init-vk`.
///
/// Every verifying instruction now reads its key from a registry account instead
/// of from the program's own code, so a fresh deployment needs one of these per
/// circuit it will use. Nothing here is a choice: the program hashes the bytes
/// and accepts only the key its bytecode pins, so this is publication, not
/// configuration. See docs/VK_REGISTRY.md.
///
/// Idempotent, because the registry is per-PROGRAM and not per-pool: a second run
/// against the same program id finds the key already published. `init-vk` handles
/// that by reading the account back and confirming it holds exactly the committed
/// key, so it returns success with no signature to report; a registry holding a
/// DIFFERENT key still fails, which is the case worth stopping on.
pub fn install_vk(
    cli: &Path,
    cwd: &Path,
    rpc_url: &str,
    program_id: &Pubkey,
    payer_path: &Path,
    circuit: &str,
) -> Result<String> {
    let out = run_cli(
        cli,
        cwd,
        &[
            "init-vk",
            "--rpc-url",
            rpc_url,
            "--program-id",
            &program_id.to_string(),
            "--circuit",
            circuit,
            "--payer",
            &payer_path.to_string_lossy(),
        ],
    )?;
    // A fresh publication prints `signature: <sig>`; an idempotent no-op prints
    // `already published: ...`. Both mean the registry now holds exactly the
    // committed key, which is the property the caller asserts, so report which
    // one happened rather than returning an empty string that reads as a failure.
    if let Some(sig) = parse_kv(&out, "signature:") {
        return Ok(sig);
    }
    if out.contains("already published") {
        return Ok("already published (registry holds exactly the committed key)".to_string());
    }
    bail!("init-vk for {circuit} neither published nor reported an existing key:\n{out}")
}

/// Pull the value of a `key: value` line out of CLI output.
pub fn parse_kv(text: &str, key: &str) -> Option<String> {
    text.lines()
        .find_map(|l| l.trim().strip_prefix(key).map(|v| v.trim().to_string()))
}

/// Flatten a multi-line message to one bounded line, for report details.
pub fn first_line(s: &str) -> String {
    s.replace('\n', " ").chars().take(240).collect()
}

pub fn write_lines(path: &Path, lines: &[String]) -> Result<()> {
    std::fs::write(path, format!("{}\n", lines.join("\n")))
        .with_context(|| format!("writing {}", path.display()))
}

pub fn hex_decode(s: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        bail!("odd-length hex");
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| anyhow!("bad hex: {e}")))
        .collect()
}

/// Read a saved value-note record and report whether it is spendable (carries the
/// owner's private key), i.e. `scan` recovered a real spendable note.
pub fn note_is_spendable(path: &Path) -> Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading note {}", path.display()))?;
    let v: serde_json::Value = serde_json::from_str(&raw).context("parsing note json")?;
    Ok(v.get("private_key_hex")
        .and_then(|k| k.as_str())
        .map(|s| !s.is_empty())
        .unwrap_or(false))
}

// ---------------------------------------------------------------------------
// Instruction builders (wire layout from mirror_core::wire)
// ---------------------------------------------------------------------------

/// Build the `InitPool` instruction (see instructions::init_pool).
///
/// `zk_denomination` is the single escrow size the ZK opt-in path accepts and
/// must be non-zero; `DepositCommit` takes exactly it and a settle pays exactly
/// it.
#[allow(clippy::too_many_arguments)]
pub fn init_pool_ix(
    program_id: &Pubkey,
    pool: &Pubkey,
    authority: &Pubkey,
    payer: &Pubkey,
    epoch_slots: u64,
    k_floor: u32,
    entry_fee: u64,
    reward_bps: u16,
    zk_denomination: u64,
) -> Instruction {
    let mut data = Vec::with_capacity(mirror_core::wire::INIT_POOL_LEN);
    data.push(mirror_core::wire::tag::INIT_POOL);
    data.extend_from_slice(&epoch_slots.to_le_bytes());
    data.extend_from_slice(&k_floor.to_le_bytes());
    data.extend_from_slice(&entry_fee.to_le_bytes());
    data.extend_from_slice(&reward_bps.to_le_bytes());
    data.extend_from_slice(&zk_denomination.to_le_bytes());
    debug_assert_eq!(data.len(), mirror_core::wire::INIT_POOL_LEN);
    Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(*pool, false),
            AccountMeta::new_readonly(*authority, true),
            AccountMeta::new(*payer, true),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
        ],
        data,
    }
}

/// Build the crowd-path `Commit` instruction (see instructions::commit).
pub fn commit_ix(
    program_id: &Pubkey,
    pool: &Pubkey,
    epoch_account: &Pubkey,
    participant: &Pubkey,
    commitment: &[u8; 32],
) -> Instruction {
    let mut data = Vec::with_capacity(mirror_core::wire::COMMIT_LEN);
    data.push(mirror_core::wire::tag::COMMIT);
    data.extend_from_slice(commitment);
    Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(*pool, false),
            AccountMeta::new(*epoch_account, false),
            AccountMeta::new(*participant, true),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
            AccountMeta::new_readonly(CLOCK_SYSVAR_ID, false),
        ],
        data,
    }
}

// ---------------------------------------------------------------------------
// Submission + polling helpers
// ---------------------------------------------------------------------------

/// Build, sign, and send a v0 transaction. `signers[0]` is the fee payer.
/// Returns `Ok(signature)` on success or `Err(error string)` on any failure.
pub async fn send(
    client: &dyn SolanaClient,
    ixs: &[Instruction],
    signers: &[&Keypair],
    alts: &[AddressLookupTableAccount],
) -> std::result::Result<String, String> {
    // Render the FULL anyhow chain (`{:#}`) so a rejected tx surfaces its
    // `custom program error: 0x..` code, not just the top-level context.
    let payer = signers.first().ok_or_else(|| "no signers".to_string())?;
    let blockhash = client
        .get_latest_blockhash()
        .await
        .map_err(|e| format!("{e:#}"))?;
    let msg = v0::Message::try_compile(&payer.pubkey(), ixs, alts, blockhash)
        .map_err(|e| format!("{e:#}"))?;
    let tx = VersionedTransaction::try_new(VersionedMessage::V0(msg), signers)
        .map_err(|e| format!("{e:#}"))?;
    client
        .send_and_confirm_transaction(&tx)
        .await
        .map(|s| s.to_string())
        .map_err(|e| format!("{e:#}"))
}

/// Whether an error string reports a specific mirror-pool custom program error.
pub fn is_custom(err: &str, code: u32) -> bool {
    err.contains(&format!("custom program error: 0x{code:x}"))
        || err.contains(&format!("Custom({code})"))
}

/// Poll `get_slot` until it reaches `target`.
pub async fn wait_until_slot(client: &dyn SolanaClient, target: u64) -> Result<u64> {
    loop {
        let s = client.get_slot().await?;
        if s >= target {
            return Ok(s);
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

// ---------------------------------------------------------------------------
// On-chain reads
// ---------------------------------------------------------------------------

pub async fn lamports(client: &dyn SolanaClient, key: &Pubkey) -> Result<u64> {
    Ok(client
        .get_account(key)
        .await?
        .map(|a| a.lamports)
        .unwrap_or(0))
}

/// The `state::value_pool` fields the soaks read, at the on-chain offsets:
/// version 0, authority 1, fee 33, denom_flag 41, denom 42, commitment_count 52,
/// current_root 60.
pub struct VPoolView {
    pub authority: [u8; 32],
    pub fee: u64,
    pub denomination: Option<u64>,
    pub commitment_count: u64,
    pub current_root: [u8; 32],
}

impl VPoolView {
    pub fn decode(data: &[u8]) -> Result<VPoolView> {
        if data.len() < 92 {
            bail!("value pool account too short: {} bytes", data.len());
        }
        let read_u64 = |off: usize| u64::from_le_bytes(data[off..off + 8].try_into().unwrap());
        let mut authority = [0u8; 32];
        authority.copy_from_slice(&data[1..33]);
        let mut current_root = [0u8; 32];
        current_root.copy_from_slice(&data[60..92]);
        let denomination = if data[41] == 0 {
            None
        } else {
            Some(read_u64(42))
        };
        Ok(VPoolView {
            authority,
            fee: read_u64(33),
            denomination,
            commitment_count: read_u64(52),
            current_root,
        })
    }
}

pub async fn read_vpool(client: &dyn SolanaClient, vpool: &Pubkey) -> Result<VPoolView> {
    let acc = client
        .get_account(vpool)
        .await?
        .ok_or_else(|| anyhow!("value pool {vpool} not found"))?;
    VPoolView::decode(&acc.data)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Report {
        let mut r = Report::default();
        r.checks
            .push(("vault credited".into(), true, "delta=100".into()));
        r.checks
            .push(("replay rejected".into(), false, "got | pipe".into()));
        r.sigs.push(("shield".into(), "sig1".into()));
        r
    }

    /// The three soaks publish docs/PROOF.md through these emitters, so their
    /// exact bytes are the evidence format. Pin them.
    #[test]
    fn checks_table_is_stable_markdown() {
        let mut s = String::new();
        checks_table(&mut s, &sample(), "###");
        assert_eq!(
            s,
            "### On-chain assertions\n\n1/2 assertions passed.\n\n\
             | result | assertion | detail |\n| --- | --- | --- |\n\
             | PASS | vault credited | delta=100 |\n\
             | FAIL | replay rejected | got \\| pipe |\n\n"
        );
    }

    #[test]
    fn sigs_table_is_stable_markdown() {
        let mut s = String::new();
        sigs_table(&mut s, &sample(), "##");
        assert_eq!(
            s,
            "## Captured transaction signatures\n\n| step | signature |\n\
             | --- | --- |\n| shield | `sig1` |\n\n"
        );
    }

    #[test]
    fn proof_section_keeps_everything_before_the_marker() {
        let dir = std::env::temp_dir().join(format!("mirror-soak-proof-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("docs")).unwrap();
        std::fs::write(dir.join("docs/PROOF.md"), "# base\n\n<!-- m -->\nold run\n").unwrap();
        let (s, _now) = begin_proof_section(&dir, "<!-- m -->").unwrap();
        assert_eq!(s, "# base\n\n<!-- m -->\n");
        std::fs::remove_dir_all(&dir).ok();
    }
}
