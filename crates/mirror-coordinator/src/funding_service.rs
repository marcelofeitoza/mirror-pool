//! The shipped ingestion path: participant requests in, released rounds out.
//!
//! [`crate::funding`] holds the privacy-critical decisions (which round a
//! withdrawal belongs to, whether a round is thick enough to release, what order
//! it goes out in). This module is the thing that actually FEEDS it on a live
//! cluster, which is the piece the funding path was missing: `mirror-cli
//! fund-commit` emitted a proved unshield and then nothing shipped turned that
//! emit into a [`FundingRounds`] entry.
//!
//! The shape mirrors the crowd path deliberately:
//!
//! - **Slot-window scheduler.** [`FundingService::run`] polls the real chain
//!   slot through the same [`SolanaClient`] seam the settlement path uses, and
//!   drives [`FundingRounds::on_slot_with_relays`] with it. Round boundaries are
//!   chain slots, not wall clock, so a stalled validator cannot release a round
//!   early.
//! - **Normalized [`TxProfile`].** The service stamps the pool-wide compute-unit
//!   limit and priority fee onto every request it ingests and DISCARDS whatever
//!   the participant's emit asked for. A participant-chosen compute budget
//!   fingerprints a withdrawal exactly like a distinctive amount does.
//! - **Mockable RPC seam.** Everything that touches a validator goes through
//!   [`SolanaClient`], and everything that touches a participant goes through
//!   [`FundingIntake`], so the whole ingest-batch-release loop is unit-testable
//!   with no validator and no filesystem.
//!
//! # What a participant does
//!
//! ```text
//! mirror-cli fund-commit ... --out <inbox>/<anything>.json
//! ```
//!
//! and that is the whole handoff. The emit is public data: it is a proved
//! `Transact` that only the pool authority can submit, so an observer who reads
//! the inbox learns the withdrawal is coming but cannot submit it, redirect it
//! (the recipient is bound into `extDataHash`), or link it to the participant's
//! main wallet.
//!
//! # Delivery semantics, stated honestly
//!
//! [`DirectoryIntake`] claims a request by moving its file out of the inbox
//! AFTER the batcher has accepted it. If the coordinator dies in the window
//! between those two steps, the request is ingested twice on restart. The
//! duplicate fails on-chain with `NullifierSpent` and the round's re-queue path
//! handles it, so nothing is lost, but the round it failed in released fewer
//! withdrawals than intended. The reverse ordering (claim first) would instead
//! LOSE the request, stranding the participant's value in the pool, which is the
//! worse of the two. [`FundingRounds`] itself is in-memory, exactly like
//! [`crate::pool::CommitPool`], so a restart drops any round that has not
//! released yet and those requests must be re-emitted.
//! TODO(milestone-3): persist pending rounds so a restart cannot orphan them.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use solana_pubkey::Pubkey;

use crate::client::SolanaClient;
use crate::config::TxProfile;
use crate::funding::{FundingRequest, FundingRoundConfig, FundingRounds, RelaySet, RoundOutcome};

/// One request as the intake handed it over, plus the handle used to
/// acknowledge or quarantine it.
pub struct IncomingRequest {
    /// Intake-scoped identifier (the file name, for [`DirectoryIntake`]).
    pub id: String,
    pub request: FundingRequest,
}

/// Where funding requests come from.
///
/// Behind a trait so the service's ingest-batch-release loop can be tested
/// without a filesystem, a network listener, or a validator, the same way
/// [`SolanaClient`] keeps the submit path testable.
#[async_trait]
pub trait FundingIntake: Send + Sync {
    /// Every request that has arrived and not yet been acknowledged.
    ///
    /// An entry that cannot be parsed into a [`FundingRequest`] must be
    /// quarantined by the intake itself and never returned, so one malformed
    /// request cannot stall the round.
    async fn poll(&self) -> Result<Vec<IncomingRequest>>;

    /// The batcher took this request; stop offering it.
    async fn accepted(&self, id: &str) -> Result<()>;

    /// The batcher refused this request (wrong amount for a denominated pool, a
    /// deposit rather than a withdrawal, an authority this coordinator does not
    /// serve); stop offering it and record why.
    async fn rejected(&self, id: &str, reason: &str) -> Result<()>;
}

/// Filesystem intake: participants drop their `fund-commit` emit JSON into an
/// inbox directory.
///
/// Chosen over a network listener on purpose. The emit is inert without the
/// relay key, so the transport carries no secret, and a directory is something a
/// reviewer can inspect, replay, and reason about without running a server. A
/// coordinator that wants an HTTP intake implements [`FundingIntake`] over its
/// own queue and the batching logic does not change.
///
/// Layout, all created on demand:
///
/// ```text
/// <root>/inbox/     participants write here
/// <root>/accepted/  batched into a round
/// <root>/rejected/  refused, with a sibling .reason file saying why
/// ```
pub struct DirectoryIntake {
    inbox: PathBuf,
    accepted: PathBuf,
    rejected: PathBuf,
    program_id: Pubkey,
    tx_profile: TxProfile,
}

impl DirectoryIntake {
    /// Create the intake directories under `root` and serve requests for
    /// `program_id`, stamping `tx_profile` onto each one.
    pub fn new(root: impl AsRef<Path>, program_id: Pubkey, tx_profile: TxProfile) -> Result<Self> {
        let root = root.as_ref();
        let intake = Self {
            inbox: root.join("inbox"),
            accepted: root.join("accepted"),
            rejected: root.join("rejected"),
            program_id,
            tx_profile,
        };
        for dir in [&intake.inbox, &intake.accepted, &intake.rejected] {
            std::fs::create_dir_all(dir)
                .with_context(|| format!("creating intake directory {}", dir.display()))?;
        }
        Ok(intake)
    }

    /// The directory participants write their `fund-commit --out` emit into.
    pub fn inbox(&self) -> &Path {
        &self.inbox
    }

    fn quarantine(&self, id: &str, reason: &str) -> Result<()> {
        let from = self.inbox.join(id);
        let to = self.rejected.join(id);
        if from.exists() {
            std::fs::rename(&from, &to)
                .with_context(|| format!("quarantining {}", from.display()))?;
        }
        std::fs::write(self.rejected.join(format!("{id}.reason")), reason)
            .with_context(|| format!("writing the rejection reason for {id}"))?;
        Ok(())
    }
}

#[async_trait]
impl FundingIntake for DirectoryIntake {
    async fn poll(&self) -> Result<Vec<IncomingRequest>> {
        let mut names: Vec<String> = Vec::new();
        for entry in std::fs::read_dir(&self.inbox)
            .with_context(|| format!("reading intake inbox {}", self.inbox.display()))?
        {
            let entry = entry.context("reading an intake inbox entry")?;
            let name = entry.file_name().to_string_lossy().to_string();
            if entry.path().is_file() && name.ends_with(".json") {
                names.push(name);
            }
        }
        // Deterministic order in, so a run is reproducible. It does NOT decide
        // the order out: `FundingRounds::release_order` does, precisely so that
        // arrival order (and therefore this listing) never reaches the chain.
        names.sort();

        let mut out = Vec::with_capacity(names.len());
        for name in names {
            let path = self.inbox.join(&name);
            let parsed = std::fs::read_to_string(&path)
                .with_context(|| format!("reading {}", path.display()))
                .and_then(|raw| {
                    serde_json::from_str::<serde_json::Value>(&raw)
                        .with_context(|| format!("parsing {} as JSON", path.display()))
                })
                .and_then(|json| {
                    FundingRequest::from_emit_json(&json, &self.program_id, self.tx_profile)
                });
            match parsed {
                Ok(request) => out.push(IncomingRequest { id: name, request }),
                Err(e) => {
                    // A malformed emit is the intake's problem, not the round's:
                    // quarantine it here so it is never offered to the batcher.
                    let reason = format!("{e:#}");
                    tracing::warn!(request = %name, reason, "quarantining a malformed funding emit");
                    self.quarantine(&name, &reason)?;
                }
            }
        }
        Ok(out)
    }

    async fn accepted(&self, id: &str) -> Result<()> {
        let from = self.inbox.join(id);
        let to = self.accepted.join(id);
        std::fs::rename(&from, &to)
            .with_context(|| format!("moving {} into the accepted directory", from.display()))
    }

    async fn rejected(&self, id: &str, reason: &str) -> Result<()> {
        self.quarantine(id, reason)
    }
}

/// Static configuration for the funding service.
///
/// No longer `Copy`: `rounds` carries owned lookup-table addresses.
#[derive(Clone, Debug)]
pub struct FundingServiceConfig {
    /// Round length, minimum round size, and the pool denomination.
    pub rounds: FundingRoundConfig,
    /// How often the real slot is polled. Only affects how promptly a round
    /// boundary is noticed; the boundary itself is a slot, never wall clock.
    pub poll_interval: Duration,
}

impl Default for FundingServiceConfig {
    fn default() -> Self {
        Self {
            rounds: FundingRoundConfig::default(),
            poll_interval: Duration::from_millis(400),
        }
    }
}

/// What one pass of the service did.
#[derive(Debug, Default)]
pub struct FundingTick {
    /// The chain slot the pass ran at.
    pub slot: u64,
    /// Requests batched this pass, as (commit wallet, round).
    pub ingested: Vec<(Pubkey, u64)>,
    /// Requests the batcher refused, as (intake id, reason).
    pub rejected: Vec<(String, String)>,
    /// Rounds that released or rolled forward this pass.
    pub outcomes: Vec<RoundOutcome>,
    /// A round that failed part-way through releasing. Reported rather than
    /// returned as an error: the remainder has already been re-queued into the
    /// next round by [`FundingRounds`], and a coordinator that exits here would
    /// strand every other participant's value in the pool.
    pub release_error: Option<String>,
}

/// The funding coordinator: ingest requests, batch them into slot rounds,
/// release each round through the gasless relay.
pub struct FundingService {
    config: FundingServiceConfig,
    rounds: FundingRounds,
    relays: RelaySet,
    intake: Arc<dyn FundingIntake>,
    client: Arc<dyn SolanaClient>,
}

impl FundingService {
    pub fn new(
        config: FundingServiceConfig,
        relays: RelaySet,
        intake: Arc<dyn FundingIntake>,
        client: Arc<dyn SolanaClient>,
    ) -> Result<Self> {
        anyhow::ensure!(
            !relays.is_empty(),
            "the funding service needs at least one relay key"
        );
        Ok(Self {
            rounds: FundingRounds::new(config.rounds.clone())?,
            config,
            relays,
            intake,
            client,
        })
    }

    pub fn config(&self) -> &FundingServiceConfig {
        &self.config
    }

    /// The batcher, for inspection (pending rounds, sizes, release order).
    pub fn rounds(&self) -> &FundingRounds {
        &self.rounds
    }

    /// One pass: read the chain slot, ingest whatever arrived, then release
    /// every round whose window has closed and which meets the floor.
    ///
    /// Returns `Err` only for failures that make the pass meaningless (the slot
    /// could not be read, or the intake could not be listed). A request the
    /// batcher refuses lands in `rejected`, and a round that fails part-way
    /// through releasing lands in `release_error`, because in both cases the
    /// right move is to keep serving everybody else.
    pub async fn tick(&mut self) -> Result<FundingTick> {
        let slot = self.client.get_slot().await.context("reading the slot")?;
        let mut tick = FundingTick {
            slot,
            ..Default::default()
        };

        for incoming in self.intake.poll().await.context("polling the intake")? {
            let commit_wallet = incoming.request.commit_wallet;
            match self.rounds.accept(slot, incoming.request) {
                Ok(round) => {
                    self.intake.accepted(&incoming.id).await?;
                    tracing::info!(
                        request = %incoming.id,
                        commit_wallet = %commit_wallet,
                        round,
                        slot,
                        "funding request batched"
                    );
                    tick.ingested.push((commit_wallet, round));
                }
                Err(e) => {
                    let reason = format!("{e:#}");
                    tracing::warn!(
                        request = %incoming.id,
                        commit_wallet = %commit_wallet,
                        reason,
                        "funding request refused"
                    );
                    self.intake.rejected(&incoming.id, &reason).await?;
                    tick.rejected.push((incoming.id, reason));
                }
            }
        }

        match self
            .rounds
            .on_slot_with_relays(slot, self.client.as_ref(), &self.relays)
            .await
        {
            Ok(outcomes) => tick.outcomes = outcomes,
            Err(e) => {
                let rendered = format!("{e:#}");
                tracing::error!(
                    slot,
                    error = rendered,
                    "a funding round failed part-way through releasing; the remainder was \
                     re-queued and the service is continuing"
                );
                tick.release_error = Some(rendered);
            }
        }
        Ok(tick)
    }

    /// Drive [`FundingService::tick`] against the real slot clock until
    /// `until` returns true (checked after every pass), or forever if it never
    /// does.
    ///
    /// The predicate takes the pass that just ran, so a caller can stop on
    /// "every pending round has released" without reaching into the batcher.
    pub async fn run(&mut self, mut until: impl FnMut(&FundingTick) -> bool) -> Result<()> {
        loop {
            let tick = self.tick().await?;
            if until(&tick) {
                return Ok(());
            }
            tokio::time::sleep(self.config.poll_interval).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::MockSolanaClient;
    use crate::funding::DEFAULT_ROUND_SLOTS;
    use mirror_core::note::{public_amount, SignedAmount};
    use mirror_core::wire;
    use solana_keypair::Keypair;
    use solana_signer::Signer;
    use std::sync::Mutex;

    const SYSTEM_PROGRAM_ID: &str = "11111111111111111111111111111111";

    fn program_id() -> Pubkey {
        Pubkey::new_from_array([0x11; 32])
    }

    /// A Transact body carrying `signed` as its publicAmount. Nothing in the
    /// ingestion path inspects the proof, so the rest is zero.
    fn transact_data_hex(signed: SignedAmount) -> String {
        let mut data = vec![wire::tag::TRANSACT];
        data.extend(std::iter::repeat_n(0u8, wire::TRANSACT_HEADER_LEN));
        let pa = public_amount(signed);
        let start = 1 + wire::TRANSACT_PUBLIC_AMOUNT_OFF;
        data[start..start + 32].copy_from_slice(&pa);
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// A well-formed `fund-commit` emit, as the CLI writes it.
    fn emit(authority: &Pubkey, commit_wallet: &Pubkey, signed: SignedAmount) -> serde_json::Value {
        let account = |pubkey: String, is_signer: bool, is_writable: bool| serde_json::json!({ "pubkey": pubkey, "is_signer": is_signer, "is_writable": is_writable });
        serde_json::json!({
            "op": "unshield",
            "program_id": program_id().to_string(),
            "recipient": commit_wallet.to_string(),
            "shield_requires_depositor_signature": false,
            "transact_data_hex": transact_data_hex(signed),
            "accounts": [
                account(Pubkey::new_from_array([0x22; 32]).to_string(), false, true),
                account(authority.to_string(), true, true),
                account(Pubkey::new_from_array([0x31; 32]).to_string(), false, true),
                account(Pubkey::new_from_array([0x32; 32]).to_string(), false, true),
                account(commit_wallet.to_string(), false, true),
                account(authority.to_string(), false, true),
                account(SYSTEM_PROGRAM_ID.to_string(), false, false),
                account(SYSTEM_PROGRAM_ID.to_string(), false, false),
                account(Pubkey::new_from_array([0x88; 32]).to_string(), false, true),
                // The write-once, digest-pinned JoinSplit verifying-key registry
                // the on-chain Transact now reads its key from. Readonly, never
                // a signer, and always last, so the index-based checks above are
                // unaffected.
                account(Pubkey::new_from_array([0x99; 32]).to_string(), false, false),
            ],
        })
    }

    /// In-memory intake: hands out queued requests and records the verdicts.
    #[derive(Default)]
    struct MockIntake {
        queued: Mutex<Vec<(String, serde_json::Value)>>,
        pub accepted: Mutex<Vec<String>>,
        pub rejected: Mutex<Vec<(String, String)>>,
        tx_profile: TxProfile,
    }

    impl MockIntake {
        fn push(&self, id: &str, emit: serde_json::Value) {
            self.queued.lock().unwrap().push((id.to_string(), emit));
        }
    }

    #[async_trait]
    impl FundingIntake for MockIntake {
        async fn poll(&self) -> Result<Vec<IncomingRequest>> {
            let queued = std::mem::take(&mut *self.queued.lock().unwrap());
            let mut out = Vec::new();
            for (id, json) in queued {
                match FundingRequest::from_emit_json(&json, &program_id(), self.tx_profile) {
                    Ok(request) => out.push(IncomingRequest { id, request }),
                    Err(e) => self
                        .rejected
                        .lock()
                        .unwrap()
                        .push((id, format!("intake: {e:#}"))),
                }
            }
            Ok(out)
        }
        async fn accepted(&self, id: &str) -> Result<()> {
            self.accepted.lock().unwrap().push(id.to_string());
            Ok(())
        }
        async fn rejected(&self, id: &str, reason: &str) -> Result<()> {
            self.rejected
                .lock()
                .unwrap()
                .push((id.to_string(), reason.to_string()));
            Ok(())
        }
    }

    fn service(
        relay: Keypair,
        intake: Arc<MockIntake>,
        client: Arc<MockSolanaClient>,
        denomination: Option<u64>,
        min_round_size: usize,
    ) -> FundingService {
        FundingService::new(
            FundingServiceConfig {
                rounds: FundingRoundConfig {
                    round_slots: 100,
                    min_round_size,
                    denomination,
                    lookup_tables: Vec::new(),
                },
                poll_interval: Duration::from_millis(1),
            },
            RelaySet::single(relay),
            intake,
            client,
        )
        .expect("service")
    }

    #[tokio::test]
    async fn ingested_requests_release_at_the_round_boundary() {
        let relay = Keypair::new();
        let intake = Arc::new(MockIntake::default());
        let client = Arc::new(MockSolanaClient::at_slot(7));
        let mut svc = service(
            relay.insecure_clone(),
            intake.clone(),
            client.clone(),
            Some(1_000),
            3,
        );

        let wallets: Vec<Pubkey> = (0..3).map(|_| Pubkey::new_unique()).collect();
        for (i, w) in wallets.iter().enumerate() {
            intake.push(
                &format!("req-{i}.json"),
                emit(&relay.pubkey(), w, SignedAmount::Withdraw(1_000)),
            );
        }

        // Slot 7: all three ingest into round 0; the window is still open, so
        // NOTHING reaches the chain.
        let tick = svc.tick().await.unwrap();
        assert_eq!(tick.ingested.len(), 3);
        assert!(tick.outcomes.is_empty());
        assert_eq!(
            client.sent_count(),
            0,
            "an open round must not reach the chain"
        );
        assert_eq!(intake.accepted.lock().unwrap().len(), 3);

        // Slot 100: the window closed and the round meets the floor.
        client.set_slot(100);
        let tick = svc.tick().await.unwrap();
        assert_eq!(tick.outcomes.len(), 1);
        match &tick.outcomes[0] {
            RoundOutcome::Released { round, size, .. } => {
                assert_eq!(*round, 0);
                assert_eq!(*size, 3);
            }
            other => panic!("expected Released, got {other:?}"),
        }
        assert_eq!(client.sent_count(), 3);
        // Every released withdrawal is relay-only signed: the participant is not
        // on the transaction that funds their commit wallet.
        for tx in client.sent.lock().unwrap().iter() {
            assert_eq!(tx.signatures.len(), 1);
            assert_eq!(tx.message.static_account_keys()[0], relay.pubkey());
        }
    }

    #[tokio::test]
    async fn a_thin_round_rolls_forward_and_never_reaches_the_chain() {
        let relay = Keypair::new();
        let intake = Arc::new(MockIntake::default());
        let client = Arc::new(MockSolanaClient::at_slot(5));
        let mut svc = service(
            relay.insecure_clone(),
            intake.clone(),
            client.clone(),
            None,
            3,
        );

        for i in 0..2 {
            intake.push(
                &format!("thin-{i}.json"),
                emit(
                    &relay.pubkey(),
                    &Pubkey::new_unique(),
                    SignedAmount::Withdraw(10),
                ),
            );
        }
        svc.tick().await.unwrap();

        client.set_slot(100);
        let tick = svc.tick().await.unwrap();
        assert_eq!(
            tick.outcomes,
            vec![RoundOutcome::RolledForward {
                round: 0,
                to: 1,
                size: 2
            }]
        );
        assert_eq!(
            client.sent_count(),
            0,
            "a round below the floor must never reach the chain"
        );
        assert_eq!(svc.rounds().len(1), 2);
    }

    #[tokio::test]
    async fn an_off_denomination_request_is_refused_before_it_costs_a_signature() {
        let relay = Keypair::new();
        let intake = Arc::new(MockIntake::default());
        let client = Arc::new(MockSolanaClient::at_slot(1));
        let mut svc = service(
            relay.insecure_clone(),
            intake.clone(),
            client.clone(),
            Some(1_000_000),
            2,
        );

        intake.push(
            "good.json",
            emit(
                &relay.pubkey(),
                &Pubkey::new_unique(),
                SignedAmount::Withdraw(1_000_000),
            ),
        );
        intake.push(
            "bad.json",
            emit(
                &relay.pubkey(),
                &Pubkey::new_unique(),
                SignedAmount::Withdraw(1_000_001),
            ),
        );

        let tick = svc.tick().await.unwrap();
        assert_eq!(tick.ingested.len(), 1);
        assert_eq!(tick.rejected.len(), 1);
        assert_eq!(tick.rejected[0].0, "bad.json");
        assert!(
            tick.rejected[0].1.contains("denomination"),
            "the rejection must name the denomination rule, got: {}",
            tick.rejected[0].1
        );
        assert_eq!(client.sent_count(), 0);
        assert_eq!(intake.rejected.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_request_for_an_unserved_pool_is_refused_at_release() {
        // The emit names an authority this coordinator does not hold a key for.
        // It must not become a transaction that cannot be signed.
        let relay = Keypair::new();
        let stranger = Keypair::new();
        let intake = Arc::new(MockIntake::default());
        let client = Arc::new(MockSolanaClient::at_slot(1));
        let mut svc = service(
            relay.insecure_clone(),
            intake.clone(),
            client.clone(),
            None,
            2,
        );

        for i in 0..2 {
            intake.push(
                &format!("stranger-{i}.json"),
                emit(
                    &stranger.pubkey(),
                    &Pubkey::new_unique(),
                    SignedAmount::Withdraw(10),
                ),
            );
        }
        svc.tick().await.unwrap();
        client.set_slot(100);
        let tick = svc.tick().await.unwrap();

        let error = tick
            .release_error
            .expect("releasing under an unheld authority must be reported");
        assert!(
            error.contains("no relay key"),
            "the error should name the missing relay key, got: {error}"
        );
        assert_eq!(client.sent_count(), 0);
        assert_eq!(
            svc.rounds().len(1),
            2,
            "the un-releasable requests were re-queued, not dropped"
        );
    }

    #[tokio::test]
    async fn the_service_normalizes_the_tx_profile_it_was_configured_with() {
        // A participant's emit carries no compute budget at all; the coordinator
        // supplies the pool-wide one. Two withdrawals released together must
        // therefore share one compute fingerprint.
        let relay = Keypair::new();
        let profile = TxProfile {
            cu_limit: 123_456,
            priority_fee_micro_lamports: 777,
        };
        let intake = Arc::new(MockIntake {
            tx_profile: profile,
            ..Default::default()
        });
        let client = Arc::new(MockSolanaClient::at_slot(1));
        let mut svc = service(
            relay.insecure_clone(),
            intake.clone(),
            client.clone(),
            None,
            2,
        );
        for i in 0..2 {
            intake.push(
                &format!("p-{i}.json"),
                emit(
                    &relay.pubkey(),
                    &Pubkey::new_unique(),
                    SignedAmount::Withdraw(5),
                ),
            );
        }
        svc.tick().await.unwrap();
        client.set_slot(100);
        svc.tick().await.unwrap();

        let sent = client.sent.lock().unwrap();
        assert_eq!(sent.len(), 2);
        // Both transactions carry the identical instruction shape: two
        // ComputeBudget instructions then the Transact.
        let shapes: Vec<Vec<usize>> = sent
            .iter()
            .map(|tx| match &tx.message {
                solana_message::VersionedMessage::V0(v0) => {
                    v0.instructions.iter().map(|ci| ci.data.len()).collect()
                }
                _ => panic!("expected v0"),
            })
            .collect();
        assert_eq!(shapes[0], shapes[1], "one normalized compute fingerprint");
        assert_eq!(shapes[0].len(), 3, "2 ComputeBudget + 1 Transact");
    }

    #[test]
    fn a_shield_emit_is_not_a_funding_request() {
        let relay = Keypair::new();
        let wallet = Pubkey::new_unique();
        let mut e = emit(&relay.pubkey(), &wallet, SignedAmount::Withdraw(10));
        e["op"] = serde_json::json!("shield");
        let err = FundingRequest::from_emit_json(&e, &program_id(), TxProfile::default())
            .expect_err("a shield funds no commit wallet");
        assert!(err.to_string().contains("shield"), "got: {err}");
    }

    #[test]
    fn an_emit_with_a_second_signer_is_refused() {
        // This is the privacy-critical parse check: a second signature would put
        // another wallet onto the funding transaction.
        let relay = Keypair::new();
        let wallet = Pubkey::new_unique();
        let mut e = emit(&relay.pubkey(), &wallet, SignedAmount::Withdraw(10));
        e["accounts"][5]["is_signer"] = serde_json::json!(true);
        let err = FundingRequest::from_emit_json(&e, &program_id(), TxProfile::default())
            .expect_err("a co-signed funding withdrawal must be refused");
        assert!(
            err.to_string().contains("relay authority ALONE"),
            "got: {err}"
        );
    }

    #[test]
    fn an_emit_for_another_program_is_refused() {
        let relay = Keypair::new();
        let wallet = Pubkey::new_unique();
        let e = emit(&relay.pubkey(), &wallet, SignedAmount::Withdraw(10));
        let other = Pubkey::new_from_array([0x99; 32]);
        let err = FundingRequest::from_emit_json(&e, &other, TxProfile::default())
            .expect_err("a request must not aim a relay signature at another program");
        assert!(err.to_string().contains("this coordinator serves"));
    }

    #[test]
    fn a_redirected_recipient_is_refused() {
        let relay = Keypair::new();
        let wallet = Pubkey::new_unique();
        let mut e = emit(&relay.pubkey(), &wallet, SignedAmount::Withdraw(10));
        e["recipient"] = serde_json::json!(Pubkey::new_unique().to_string());
        let err = FundingRequest::from_emit_json(&e, &program_id(), TxProfile::default())
            .expect_err("a doctored recipient must be refused");
        assert!(err.to_string().contains("does not match"));
    }

    #[tokio::test]
    async fn the_directory_intake_round_trips_an_emit_and_quarantines_junk() {
        let relay = Keypair::new();
        let wallet = Pubkey::new_unique();
        let dir = std::env::temp_dir().join(format!(
            "mirror-funding-intake-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let intake = DirectoryIntake::new(&dir, program_id(), TxProfile::default()).unwrap();

        std::fs::write(
            intake.inbox().join("good.json"),
            serde_json::to_string(&emit(
                &relay.pubkey(),
                &wallet,
                SignedAmount::Withdraw(4_242),
            ))
            .unwrap(),
        )
        .unwrap();
        std::fs::write(intake.inbox().join("junk.json"), "{not json").unwrap();

        let polled = intake.poll().await.unwrap();
        assert_eq!(polled.len(), 1, "the malformed emit was not offered");
        assert_eq!(polled[0].id, "good.json");
        assert_eq!(polled[0].request.commit_wallet, wallet);
        assert_eq!(polled[0].request.withdraw_amount().unwrap(), 4_242);
        assert!(
            dir.join("rejected/junk.json").exists(),
            "the malformed emit was quarantined"
        );

        intake.accepted("good.json").await.unwrap();
        assert!(dir.join("accepted/good.json").exists());
        assert!(intake.poll().await.unwrap().is_empty());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_default_round_is_a_quarter_of_the_modeled_epoch() {
        // Guards the documented relationship in docs/EFFECTIVE_K.md: a
        // participant who funds and commits in the same epoch crosses at least
        // one round boundary.
        assert_eq!(DEFAULT_ROUND_SLOTS, 150);
        assert_eq!(FundingServiceConfig::default().rounds.round_slots, 150);
    }
}
