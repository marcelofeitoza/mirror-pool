//! `fund-commit`: fund a fresh commit wallet out of the shielded value pool.
//!
//! # Why this command exists
//!
//! Every other privacy property of this protocol is undone by one boring
//! transaction: topping up your fresh commit wallet from your main wallet. That
//! transfer is a public edge, and the common-funding-source heuristic walks it
//! backwards to whoever the main wallet already belongs to. It is the channel the
//! effective-anonymity literature found to be dominant, and no amount of
//! shared-epoch batching at settlement time repairs it.
//!
//! So the funding leg gets its own mechanism: the participant withdraws from the
//! confidential-value pool to the fresh wallet. On-chain the sender is the pool
//! vault, the only signature is the relay's, and the participant's main wallet
//! appears nowhere in the transaction.
//!
//! # What this command does NOT hide
//!
//! `publicAmount` is visible for both boundary crossings. An observer sees the
//! deposits into the pool (with amounts and slots) and the withdrawals out of it
//! (with amounts and slots), and can try to match them up. Two rules keep that
//! matching hard, and this module enforces the first and prints the second:
//!
//! 1. **Move the pool's denomination, nothing else.** Under a denominated pool
//!    ([`resolve_funding_amount`]) every withdrawal is the same number, so the
//!    amount carries no information. The on-chain program enforces it too
//!    (`DenominationMismatch`); refusing here just saves a failed transaction.
//! 2. **Let the coordinator batch the release.** The emitted `Transact` is meant
//!    to be handed to the coordinator's funding round
//!    (`mirror_coordinator::funding::FundingRounds`), which holds it to the round
//!    boundary and submits it in an order that is not the arrival order. A
//!    withdrawal submitted the instant it is proved re-links itself by timing.
//!
//! # What is NOT wired
//!
//! This command PRINTS the emitted request; it does not post it anywhere. No
//! shipped component ingests it into a `FundingRounds` instance, and the
//! coordinator binary is an in-memory scheduler demo, so today rule 2 is a
//! recommendation to whoever operates the pool rather than something the tree
//! performs. Rule 1 (denomination) is enforced here and on-chain regardless.
//!
//! What survives both is measured, not assumed: see `docs/EFFECTIVE_K.md`. Those
//! numbers describe the design, not an observed deployment.

use anyhow::{anyhow, bail, Context, Result};
use solana_keypair::Keypair;
use solana_signer::Signer;
use std::path::Path;

/// Decide how many lamports the funding withdrawal moves.
///
/// - Denominated pool: the amount is the denomination. A caller may pass it
///   explicitly (it must match) but never a different one, because a distinctive
///   withdrawal amount is exactly the signal that re-links a funder to a fundee.
/// - Free-amount pool: the caller must say, and there is no uniformity to lean
///   on; the caller is told so.
pub fn resolve_funding_amount(
    pool_denomination: Option<u64>,
    requested: Option<u64>,
) -> Result<u64> {
    match (pool_denomination, requested) {
        (Some(d), None) => Ok(d),
        (Some(d), Some(r)) if r == d => Ok(d),
        (Some(d), Some(r)) => bail!(
            "this value pool is denominated at {d} lamports; --amount {r} would be rejected \
             on-chain (DenominationMismatch) and a distinctive amount re-links the funder \
             to the funded wallet anyway"
        ),
        (None, Some(r)) if r > 0 => Ok(r),
        (None, Some(_)) => bail!("--amount must be > 0"),
        (None, None) => bail!(
            "this value pool has no fixed denomination, so --amount is required. \
             Prefer a denominated pool for funding: a uniform withdrawal amount is what \
             makes the deposit-to-withdrawal matching hard"
        ),
    }
}

/// Create a fresh commit wallet and write it as a Solana CLI keypair file (a JSON
/// array of 64 bytes), refusing to clobber an existing file.
///
/// A fresh key per commit is the point: reusing one commit wallet across epochs
/// re-links those epochs to each other no matter how the wallet was funded.
pub fn create_commit_wallet(path: &Path) -> Result<Keypair> {
    if path.exists() {
        bail!(
            "{} already exists; refusing to overwrite a commit-wallet keypair \
             (use --commit-wallet to reuse it deliberately, but a fresh wallet per commit \
             is what keeps epochs unlinkable)",
            path.display()
        );
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating directory {}", parent.display()))?;
        }
    }
    let keypair = Keypair::new();
    let bytes: Vec<u8> = keypair.to_bytes().to_vec();
    let json = serde_json::to_string(&bytes).context("serializing the commit-wallet keypair")?;
    std::fs::write(path, json)
        .with_context(|| format!("writing commit-wallet keypair {}", path.display()))?;
    Ok(keypair)
}

/// Load an existing commit wallet keypair file.
pub fn load_commit_wallet(path: &Path) -> Result<Keypair> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading commit-wallet keypair {}", path.display()))?;
    let bytes: Vec<u8> = serde_json::from_str(&raw)
        .with_context(|| format!("parsing {} as a JSON byte array", path.display()))?;
    Keypair::try_from(bytes.as_slice())
        .map_err(|e| anyhow!("invalid keypair in {}: {e}", path.display()))
}

/// The guidance printed after a funding withdrawal is emitted. Kept as data (not
/// inline `println!`s) so the wording is unit-testable and cannot silently drift
/// into overclaiming.
pub fn funding_notes(denominated: bool) -> Vec<&'static str> {
    let mut notes = vec![
        "this withdrawal is signed by the relay alone: your main wallet never appears on it.",
        "hand the emitted Transact to a coordinator funding round; do NOT submit it \
         yourself the moment it is proved (an immediate withdrawal re-links itself by timing). \
         NOTE: no shipped service ingests this request today, so batching is on the operator.",
        "never top this wallet up from your main wallet afterwards: one direct transfer \
         undoes the whole funding path.",
    ];
    if denominated {
        notes.push(
            "the pool is denominated, so this withdrawal is the same amount as every other \
             one in the round and carries no amount signal.",
        );
    } else {
        notes.push(
            "WARNING: this pool has no fixed denomination, so the withdrawal amount is public \
             and distinctive. An observer who sees a matching deposit shortly before it can \
             re-link the funder. Use a denominated pool for funding.",
        );
    }
    notes
}

/// The address of a keypair, for printing.
pub fn address(keypair: &Keypair) -> String {
    keypair.pubkey().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn denominated_pool_pins_the_amount() {
        assert_eq!(
            resolve_funding_amount(Some(1_000_000), None).unwrap(),
            1_000_000
        );
        assert_eq!(
            resolve_funding_amount(Some(1_000_000), Some(1_000_000)).unwrap(),
            1_000_000
        );
        let err = resolve_funding_amount(Some(1_000_000), Some(999_999)).unwrap_err();
        assert!(
            err.to_string().contains("DenominationMismatch"),
            "the error must name the on-chain rule, got: {err}"
        );
    }

    #[test]
    fn free_amount_pool_requires_an_explicit_amount() {
        assert_eq!(resolve_funding_amount(None, Some(42)).unwrap(), 42);
        assert!(resolve_funding_amount(None, Some(0)).is_err());
        let err = resolve_funding_amount(None, None).unwrap_err();
        assert!(err.to_string().contains("--amount is required"));
    }

    #[test]
    fn commit_wallet_is_fresh_written_and_reloadable() {
        let dir = std::env::temp_dir().join(format!("mirror-cli-funding-{}", std::process::id()));
        let path = dir.join("commit-wallet.json");
        let _ = std::fs::remove_file(&path);

        let created = create_commit_wallet(&path).expect("fresh wallet");
        let loaded = load_commit_wallet(&path).expect("reload");
        assert_eq!(created.pubkey(), loaded.pubkey());

        // Two calls must never produce the same key, and the second must refuse to
        // clobber the first.
        assert!(
            create_commit_wallet(&path).is_err(),
            "an existing commit wallet must not be silently overwritten"
        );
        let other = dir.join("commit-wallet-2.json");
        let _ = std::fs::remove_file(&other);
        let second = create_commit_wallet(&other).expect("second wallet");
        assert_ne!(
            created.pubkey(),
            second.pubkey(),
            "each commit wallet must be fresh"
        );

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&other);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn free_amount_pools_are_warned_about() {
        let notes = funding_notes(false);
        assert!(
            notes.iter().any(|n| n.contains("WARNING")),
            "a free-amount funding pool must carry an explicit warning"
        );
        assert!(funding_notes(true).iter().all(|n| !n.contains("WARNING")));
        // Neither variant may claim the funding link is erased.
        for notes in [funding_notes(true), funding_notes(false)] {
            assert!(notes.iter().all(|n| !n.contains("untraceable")));
        }
    }
}
