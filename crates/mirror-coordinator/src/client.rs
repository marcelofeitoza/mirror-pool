//! The RPC boundary the crowd-path submitter is built on.
//!
//! Everything that actually talks to a validator lives behind the
//! [`SolanaClient`] trait so the transaction-building logic in [`crate::crowd`]
//! can be unit-tested with a mock and never needs a running validator. The
//! real implementation ([`RpcSolanaClient`]) is a thin async wrapper over the
//! public `solana-rpc-client` nonblocking client; the mock
//! ([`MockSolanaClient`], test-only) returns canned values and records the
//! transactions it was asked to send.
//!
//! Only the calls the coordinator needs are exposed: fetch a recent blockhash,
//! read the slot, send+confirm a transaction, create/extend the pool's Address
//! Lookup Table, and read an account. Keeping the surface this small is what
//! makes the trait cheap to mock.

use anyhow::{Context, Result};
use async_trait::async_trait;
use solana_hash::Hash;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;

/// A signer usable across the async client boundary. `Send + Sync` is required
/// because `async_trait` boxes each method's future as `Send`, so any signer
/// held across an `await` must be shareable between threads. `Keypair` satisfies
/// this, so callers just pass `&keypair`.
pub type DynSigner = dyn Signer + Send + Sync;

/// A minimal, version-agnostic view of an on-chain account.
///
/// The trait returns this instead of a `solana-account` `Account` so callers
/// never take a direct dependency on that crate's exact version; the RPC impl
/// maps whatever the client returns onto these fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountSnapshot {
    pub lamports: u64,
    pub owner: Pubkey,
    pub data: Vec<u8>,
    pub executable: bool,
}

/// The RPC calls the coordinator needs, behind one mockable async seam.
///
/// `Send + Sync` so the submitter can hold one behind an `Arc` across tasks.
/// Async-fn-in-trait is stable but not dyn-compatible, so the methods are
/// desugared with `async_trait` and the client is used as `Arc<dyn SolanaClient>`.
#[async_trait]
pub trait SolanaClient: Send + Sync {
    /// A recent blockhash to stamp a transaction with.
    async fn get_latest_blockhash(&self) -> Result<Hash>;

    /// The current slot (used to derive an Address Lookup Table and as the
    /// production slot source that drives [`crate::scheduler::Coordinator::on_slot`]).
    async fn get_slot(&self) -> Result<u64>;

    /// Submit a fully-signed transaction and wait for confirmation.
    async fn send_and_confirm_transaction(&self, tx: &VersionedTransaction) -> Result<Signature>;

    /// Read an account, or `None` if it does not exist.
    async fn get_account(&self, address: &Pubkey) -> Result<Option<AccountSnapshot>>;

    /// Create a fresh Address Lookup Table owned by `authority`, funded by
    /// `payer`. Returns the derived table address and the creating signature.
    /// The table is empty; use [`SolanaClient::extend_lookup_table`] to add the
    /// pool's shared accounts.
    async fn create_lookup_table(
        &self,
        authority: &DynSigner,
        payer: &DynSigner,
    ) -> Result<(Pubkey, Signature)>;

    /// Append `addresses` to an existing Address Lookup Table.
    async fn extend_lookup_table(
        &self,
        table: &Pubkey,
        authority: &DynSigner,
        payer: &DynSigner,
        addresses: Vec<Pubkey>,
    ) -> Result<Signature>;
}

/// Real JSON-RPC client backed by the public nonblocking `solana-rpc-client`.
///
/// No program id, pool, or key is baked in here: the client is pure transport.
/// All addresses and keys arrive from configuration / the caller.
pub struct RpcSolanaClient {
    rpc: solana_rpc_client::nonblocking::rpc_client::RpcClient,
}

impl RpcSolanaClient {
    /// Connect to `rpc_url` (e.g. the local Surfpool mainnet mirror at
    /// `http://127.0.0.1:8899`), confirming transactions at `confirmed`.
    pub fn new(rpc_url: impl Into<String>) -> Self {
        use solana_commitment_config::CommitmentConfig;
        Self {
            rpc: solana_rpc_client::nonblocking::rpc_client::RpcClient::new_with_commitment(
                rpc_url.into(),
                CommitmentConfig::confirmed(),
            ),
        }
    }

    /// Borrow the underlying nonblocking client for calls not surfaced on the
    /// trait (kept for the live soak harness).
    pub fn inner(&self) -> &solana_rpc_client::nonblocking::rpc_client::RpcClient {
        &self.rpc
    }

    /// Build, sign, and send a single-instruction v0 transaction. Shared by the
    /// ALT create/extend paths, which are one-off setup transactions.
    async fn send_setup_ix(
        &self,
        ix: solana_instruction::Instruction,
        authority: &DynSigner,
        payer: &DynSigner,
    ) -> Result<Signature> {
        use solana_message::{v0, VersionedMessage};
        let blockhash = self.get_latest_blockhash().await?;
        let message = v0::Message::try_compile(&payer.pubkey(), &[ix], &[], blockhash)
            .context("compile ALT setup message")?;
        // Sign with exactly the keys the message requires, deduped. This matters
        // because the two ALT setup instructions have different signer sets:
        // `create_lookup_table` needs only the payer to sign (the authority is
        // NOT a signer on modern clusters), while `extend_lookup_table` needs the
        // authority as well; and the authority and payer may be the same key.
        // Passing a fixed `[authority, payer]` over-counts for create and fails
        // with "too many signers", so instead select from the message's required
        // signer prefix. `Send + Sync` is preserved so the future stays `Send`.
        let num_required = message.header.num_required_signatures as usize;
        let required = &message.account_keys[..num_required];
        let mut signers: Vec<&DynSigner> = Vec::with_capacity(2);
        for s in [authority, payer] {
            let key = s.pubkey();
            if required.contains(&key) && !signers.iter().any(|existing| existing.pubkey() == key) {
                signers.push(s);
            }
        }
        let tx = VersionedTransaction::try_new(VersionedMessage::V0(message), signers.as_slice())
            .context("sign ALT setup transaction")?;
        self.send_and_confirm_transaction(&tx).await
    }
}

#[async_trait]
impl SolanaClient for RpcSolanaClient {
    async fn get_latest_blockhash(&self) -> Result<Hash> {
        self.rpc
            .get_latest_blockhash()
            .await
            .context("get_latest_blockhash")
    }

    async fn get_slot(&self) -> Result<u64> {
        self.rpc.get_slot().await.context("get_slot")
    }

    async fn send_and_confirm_transaction(&self, tx: &VersionedTransaction) -> Result<Signature> {
        self.rpc
            .send_and_confirm_transaction(tx)
            .await
            .context("send_and_confirm_transaction")
    }

    async fn get_account(&self, address: &Pubkey) -> Result<Option<AccountSnapshot>> {
        use solana_commitment_config::CommitmentConfig;
        let resp = self
            .rpc
            .get_account_with_commitment(address, CommitmentConfig::confirmed())
            .await
            .context("get_account_with_commitment")?;
        Ok(resp.value.map(|a| AccountSnapshot {
            lamports: a.lamports,
            owner: a.owner,
            data: a.data,
            executable: a.executable,
        }))
    }

    async fn create_lookup_table(
        &self,
        authority: &DynSigner,
        payer: &DynSigner,
    ) -> Result<(Pubkey, Signature)> {
        // The table address is derived from (authority, recent_slot); the slot
        // is bound into the create instruction, so both must agree.
        let recent_slot = self.get_slot().await?;
        let (ix, table) = solana_address_lookup_table_interface::instruction::create_lookup_table(
            authority.pubkey(),
            payer.pubkey(),
            recent_slot,
        );
        let sig = self.send_setup_ix(ix, authority, payer).await?;
        Ok((table, sig))
    }

    async fn extend_lookup_table(
        &self,
        table: &Pubkey,
        authority: &DynSigner,
        payer: &DynSigner,
        addresses: Vec<Pubkey>,
    ) -> Result<Signature> {
        let ix = solana_address_lookup_table_interface::instruction::extend_lookup_table(
            *table,
            authority.pubkey(),
            Some(payer.pubkey()),
            addresses,
        );
        self.send_setup_ix(ix, authority, payer).await
    }
}

/// Test-only mock: canned blockhash/slot, a deterministic ALT address, and a
/// record of every transaction it was asked to send. Lets the crowd-path
/// builder and submitter be exercised end-to-end with no validator.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct MockSolanaClient {
    pub blockhash: Hash,
    pub slot: u64,
    pub table: Pubkey,
    pub sent: std::sync::Mutex<Vec<VersionedTransaction>>,
}

#[cfg(test)]
impl MockSolanaClient {
    pub fn new() -> Self {
        Self {
            // A fixed, nonzero blockhash so signed transactions are stable.
            blockhash: Hash::new_from_array([7u8; 32]),
            slot: 123,
            table: Pubkey::new_from_array([0xA1; 32]),
            sent: std::sync::Mutex::new(Vec::new()),
        }
    }

    pub fn sent_count(&self) -> usize {
        self.sent.lock().unwrap().len()
    }
}

#[cfg(test)]
#[async_trait]
impl SolanaClient for MockSolanaClient {
    async fn get_latest_blockhash(&self) -> Result<Hash> {
        Ok(self.blockhash)
    }

    async fn get_slot(&self) -> Result<u64> {
        Ok(self.slot)
    }

    async fn send_and_confirm_transaction(&self, tx: &VersionedTransaction) -> Result<Signature> {
        let sig = tx.signatures.first().copied().unwrap_or_default();
        self.sent.lock().unwrap().push(tx.clone());
        Ok(sig)
    }

    async fn get_account(&self, _address: &Pubkey) -> Result<Option<AccountSnapshot>> {
        Ok(None)
    }

    async fn create_lookup_table(
        &self,
        _authority: &DynSigner,
        _payer: &DynSigner,
    ) -> Result<(Pubkey, Signature)> {
        Ok((self.table, Signature::default()))
    }

    async fn extend_lookup_table(
        &self,
        _table: &Pubkey,
        _authority: &DynSigner,
        _payer: &DynSigner,
        _addresses: Vec<Pubkey>,
    ) -> Result<Signature> {
        Ok(Signature::default())
    }
}

#[cfg(test)]
mod live_tests {
    use super::*;

    /// Live connectivity smoke test for the real RPC transport. Ignored by
    /// default and additionally gated on `MIRROR_LIVE_RPC_URL` (e.g.
    /// `http://127.0.0.1:8899` for Surfpool), so it never runs in CI and never
    /// needs a validator for the normal `cargo test` path. The full end-to-end
    /// settlement submit is covered by the Surfpool soak harness.
    ///
    /// Run with:
    /// `MIRROR_LIVE_RPC_URL=http://127.0.0.1:8899 cargo test -p mirror-coordinator -- --ignored live`
    #[tokio::test]
    #[ignore = "requires a live RPC endpoint via MIRROR_LIVE_RPC_URL"]
    async fn live_rpc_reports_slot_and_blockhash() {
        let Ok(url) = std::env::var("MIRROR_LIVE_RPC_URL") else {
            eprintln!("MIRROR_LIVE_RPC_URL unset; skipping live RPC smoke test");
            return;
        };
        let client = RpcSolanaClient::new(url);
        let slot = client.get_slot().await.expect("get_slot");
        let blockhash = client
            .get_latest_blockhash()
            .await
            .expect("get_latest_blockhash");
        assert!(slot > 0, "a live cluster should report a nonzero slot");
        assert_ne!(
            blockhash,
            Hash::default(),
            "a live cluster should return a real blockhash"
        );
    }
}
