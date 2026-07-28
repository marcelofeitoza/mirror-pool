//! Funding rounds: the shielded path that funds a fresh commit wallet.
//!
//! # The channel this closes
//!
//! A participant needs a fresh wallet to post their commitment from. If they top
//! that wallet up with an ordinary transfer from their main wallet, the funding
//! edge is written straight into the public transaction graph, and the
//! common-funding-source heuristic re-links the commit wallet to whoever the main
//! wallet already belongs to. That single edge is enough to partition an epoch's
//! committers into funding-provenance classes, which is what collapses the
//! effective anonymity set of a naive pool (see `docs/EFFECTIVE_K.md`).
//!
//! The mechanism: the participant funds the commit wallet by **unshielding from
//! the confidential-value pool** ([`crate::value`]) instead. The withdrawal is
//! relay-signed (the participant never signs it), the vault is the on-chain
//! sender, and no transaction anywhere links the main wallet to the commit
//! wallet.
//!
//! # The residual leak, stated up front
//!
//! `publicAmount` is on-chain-visible on both boundary crossings: a shield
//! exposes (depositor, amount, slot) and an unshield exposes (recipient, amount,
//! slot). So the funding edge is not erased, it is turned into a **matching
//! problem**: an observer sees a set of deposits and a set of withdrawals and has
//! to guess which produced which. A pass-through (shield exactly the amount you
//! are about to withdraw, withdraw it immediately) makes that matching trivial,
//! and the channel is barely dented. Two protocol-side properties make the
//! matching hard, and this module implements both:
//!
//! 1. **Uniform denomination.** A [`FundingRoundConfig::denomination`] pool
//!    accepts a withdrawal of exactly one amount (the on-chain program enforces
//!    it as `DenominationMismatch`; [`FundingRounds::accept`] rejects it
//!    client-side first so a bad request never burns a relay signature). Every
//!    withdrawal in the round is then the same number, and the amount channel
//!    carries zero bits.
//! 2. **Batching.** Withdrawals are held until the round's release
//!    slot and submitted together in an order derived from the round, not from
//!    arrival ([`FundingRounds::release_order`]), so per-request arrival time
//!    never reaches the chain. A round below [`FundingRoundConfig::min_round_size`]
//!    rolls forward instead of releasing, exactly like the epoch `k_floor`: a
//!    round of one is a direct link, no matter how good the cryptography is.
//!
//! A third property, **dwell** (how many rounds a participant leaves value
//! shielded before asking for the withdrawal), also widens the matching problem,
//! and this module does NOT implement it: there is no dwell field in
//! [`FundingRoundConfig`] and nothing here can make a participant wait. It is a
//! recommendation the protocol can publish and the harness can measure, not a
//! rule it enforces, which is why `docs/EFFECTIVE_K.md` reports the dwell-0
//! number as the guarantee.
//!
//! The residual that survives both is the round window itself (an observer still
//! learns which round a withdrawal belongs to, and the deposits that could have
//! funded it are the ones in the preceding rounds). `crates/mirror-harness`
//! measures the size of that residual instead of assuming it away, and
//! `docs/EFFECTIVE_K.md` publishes the number.
//!
//! # What this module is not
//!
//! It does not hide that the pool exists, and it does not launder history: the
//! shield leg is still the participant's own transaction from their own wallet.
//! What it removes is the *edge* from that wallet to the commit wallet.
//!
//! It is also not a running service. This is a library type: something has to
//! construct it, feed it [`FundingRequest`]s (the CLI's `fund-commit` prints one
//! rather than posting it anywhere), and drive [`FundingRounds::on_slot`] from a
//! slot clock. Nothing in this repository does that yet, so no funding round has
//! ever released a withdrawal on any cluster.
//!
//! # Failure behavior
//!
//! If the RPC dies part-way through releasing a round, the withdrawals that did
//! not reach the chain are re-queued into the next round rather than dropped (a
//! lost funding withdrawal is a participant whose value is stuck shielded and who
//! cannot commit), and the error is surfaced. The ones that DID land were released
//! as a batch smaller than the round, which is a smaller crowd than intended; that
//! is logged at error level rather than papered over, because it is a real, if
//! transient, privacy regression for those participants.

use std::collections::BTreeMap;
use std::str::FromStr;

use anyhow::{anyhow, bail, ensure, Context, Result};
use mirror_core::{
    note::{decode_public_amount, SignedAmount},
    wire,
};
use solana_instruction::AccountMeta;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;

use crate::client::SolanaClient;
use crate::config::TxProfile;
use crate::value::{submit_transact, ValueTransactRequest};

/// The account index the ValuePool authority (the relay) occupies in a
/// `Transact` account list. Fixed by the on-chain program's account order.
const AUTHORITY_ACCOUNT_INDEX: usize = 1;
/// The account index the withdrawal recipient (the fresh commit wallet)
/// occupies in a `Transact` account list.
const RECIPIENT_ACCOUNT_INDEX: usize = 4;
/// The number of accounts a `Transact` takes: vpool, authority, nf0, nf1,
/// recipient, depositor, system, clock, vault, vk_registry.
///
/// The last slot is the write-once, digest-pinned JoinSplit verifying-key
/// registry the program reads its key from (see docs/VK_REGISTRY.md). It is
/// readonly and never a signer, so the two index constants above are unchanged;
/// this count is checked exactly so an emit that silently DROPS it is refused
/// rather than submitted and failed on-chain.
const TRANSACT_ACCOUNTS: usize = 10;

/// Default funding-round length in slots. A quarter of the 600-slot epoch window
/// the harness models, so a participant who funds and commits in the same epoch
/// still crosses at least one round boundary.
pub const DEFAULT_ROUND_SLOTS: u64 = 150;

/// Default minimum withdrawals before a round may release. Two is the absolute
/// floor at which a matching problem exists at all; four is the default because a
/// round of two leaves a coin-flip. This is the funding-side analog of the epoch
/// `k_floor` and is enforced the same way (roll forward, never release thin).
pub const DEFAULT_MIN_ROUND_SIZE: usize = 4;

/// Configuration for the funding-round batcher.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FundingRoundConfig {
    /// Round length in slots. Every withdrawal accepted in `[r*n, (r+1)*n)` is
    /// released together at slot `(r+1)*n`.
    pub round_slots: u64,
    /// Minimum withdrawals before a round may release. Below this the round rolls
    /// forward into the next one.
    pub min_round_size: usize,
    /// The value pool's fixed denomination, when it has one. Every accepted
    /// withdrawal must move exactly this amount, so the amount channel carries no
    /// information. `None` means the pool is free-amount, in which case the
    /// participant's withdrawal amount is public and distinctive: the batcher
    /// still hides arrival order, but it cannot hide the amount, and it says so.
    pub denomination: Option<u64>,
}

impl Default for FundingRoundConfig {
    fn default() -> Self {
        Self {
            round_slots: DEFAULT_ROUND_SLOTS,
            min_round_size: DEFAULT_MIN_ROUND_SIZE,
            denomination: None,
        }
    }
}

/// One participant's request to have a fresh commit wallet funded out of the
/// shielded pool: the unshield `Transact` their CLI already proved and emitted.
#[derive(Debug)]
pub struct FundingRequest {
    /// The emitted unshield: vault -> fresh commit wallet, relay-signed.
    pub transact: ValueTransactRequest,
    /// The fresh commit wallet the withdrawal credits. Held for logging and for
    /// the deterministic release order; the authoritative recipient is the one
    /// bound into the proof's `extDataHash`, not this field.
    pub commit_wallet: Pubkey,
}

impl FundingRequest {
    /// The withdrawal magnitude encoded in the Transact's `publicAmount`.
    ///
    /// Fails when the request is not a well-formed `Transact`, or when it is a
    /// transfer or a deposit rather than a withdrawal: a funding request that does
    /// not move public value out of the vault is not a funding request, and the
    /// relay refuses to sign it blind.
    pub fn withdraw_amount(&self) -> Result<u64> {
        let data = &self.transact.transact_data;
        ensure!(
            data.first() == Some(&wire::tag::TRANSACT),
            "funding request is not a Transact instruction"
        );
        let body = &data[1..];
        let end = wire::TRANSACT_PUBLIC_AMOUNT_OFF + 32;
        ensure!(
            body.len() >= wire::TRANSACT_HEADER_LEN,
            "funding request body is shorter than a Transact header"
        );
        let public_amount: [u8; 32] = body[wire::TRANSACT_PUBLIC_AMOUNT_OFF..end]
            .try_into()
            .context("reading publicAmount")?;
        match decode_public_amount(&public_amount).context("decoding publicAmount")? {
            SignedAmount::Withdraw(v) => Ok(v),
            SignedAmount::Deposit(_) => {
                bail!("funding request is a deposit; a funding withdrawal must move value OUT")
            }
            SignedAmount::Transfer => {
                bail!("funding request is an internal transfer; it funds no commit wallet")
            }
        }
    }

    /// The ValuePool authority (the relay) this withdrawal is bound to.
    ///
    /// The on-chain program checks that account 1 is the pool's authority and
    /// that it signed, so this is the key the coordinator must hold to release
    /// the request at all.
    pub fn authority(&self) -> Result<Pubkey> {
        let meta = self
            .transact
            .accounts
            .get(AUTHORITY_ACCOUNT_INDEX)
            .ok_or_else(|| anyhow!("funding request has no authority account"))?;
        ensure!(
            meta.is_signer,
            "the authority account of a funding request must be marked signer"
        );
        Ok(meta.pubkey)
    }

    /// Parse a `mirror-cli fund-commit` emit (the JSON the participant's CLI
    /// writes with `--out`) into a request the batcher can hold.
    ///
    /// This is the wire format between the participant and the coordinator, and
    /// it is where a malformed or hostile request is supposed to die. Everything
    /// checked here is checked because letting it through would either burn a
    /// relay signature on a doomed transaction or, worse, put the participant
    /// back onto the funding transaction:
    ///
    /// - the op must be an **unshield** (a shield or an internal transfer funds
    ///   no commit wallet, and a shield needs the depositor's signature);
    /// - the program id must be the one the coordinator was configured with, so
    ///   a request cannot aim a relay signature at some other program;
    /// - the account list must be the program's fixed 9-account `Transact`
    ///   order, and the recipient slot must agree with the emit's stated
    ///   recipient, so a doctored emit cannot redirect the withdrawal (the
    ///   proof's `extDataHash` binds the real recipient, so a mismatch here is
    ///   a request that would fail on-chain anyway);
    /// - **exactly one account may be a signer, and it must be the authority.**
    ///   This is the privacy-critical one. If any other account were marked
    ///   signer, the released transaction would carry a second signature, and
    ///   whoever that key belongs to is written into the funding transaction
    ///   forever. Relay-only signing is the entire point of routing the funding
    ///   leg through the pool.
    ///
    /// The [`TxProfile`] is supplied by the COORDINATOR, not read from the
    /// emit: a participant-chosen compute-unit limit or priority fee
    /// fingerprints their withdrawal exactly like a distinctive amount does, so
    /// the pool-wide normalized shape is stamped on here and the emit's opinion
    /// (if any) is discarded.
    pub fn from_emit_json(
        emit: &serde_json::Value,
        expected_program_id: &Pubkey,
        tx_profile: TxProfile,
    ) -> Result<FundingRequest> {
        let s = |key: &str| -> Result<&str> {
            emit[key]
                .as_str()
                .ok_or_else(|| anyhow!("funding emit missing string field `{key}`"))
        };

        let op = s("op")?;
        ensure!(
            op == "unshield",
            "funding emit is a `{op}`; only an unshield funds a commit wallet"
        );
        if emit["shield_requires_depositor_signature"]
            .as_bool()
            .unwrap_or(false)
        {
            bail!("funding emit demands a depositor co-signature; a funding withdrawal is relay-only signed");
        }

        let program_id = Pubkey::from_str(s("program_id")?)
            .map_err(|e| anyhow!("funding emit has an invalid program_id: {e}"))?;
        ensure!(
            program_id == *expected_program_id,
            "funding emit targets program {program_id}, but this coordinator serves \
             {expected_program_id}"
        );

        let accounts = emit
            .get("accounts")
            .and_then(|a| a.as_array())
            .ok_or_else(|| anyhow!("funding emit missing `accounts` array"))?
            .iter()
            .map(|a| {
                let pubkey = Pubkey::from_str(
                    a["pubkey"]
                        .as_str()
                        .ok_or_else(|| anyhow!("funding emit account missing `pubkey`"))?,
                )
                .map_err(|e| anyhow!("funding emit account has an invalid pubkey: {e}"))?;
                Ok(AccountMeta {
                    pubkey,
                    is_signer: a["is_signer"].as_bool().unwrap_or(false),
                    is_writable: a["is_writable"].as_bool().unwrap_or(false),
                })
            })
            .collect::<Result<Vec<AccountMeta>>>()?;
        ensure!(
            accounts.len() == TRANSACT_ACCOUNTS,
            "funding emit carries {} accounts; a Transact takes exactly {TRANSACT_ACCOUNTS}",
            accounts.len()
        );

        let signers: Vec<Pubkey> = accounts
            .iter()
            .filter(|a| a.is_signer)
            .map(|a| a.pubkey)
            .collect();
        ensure!(
            signers.len() == 1 && signers[0] == accounts[AUTHORITY_ACCOUNT_INDEX].pubkey,
            "a funding withdrawal must be signed by the relay authority ALONE, but this emit \
             marks {} account(s) as signer ({signers:?}); a second signature writes another \
             wallet into the funding transaction",
            signers.len()
        );

        let stated_recipient = Pubkey::from_str(s("recipient")?)
            .map_err(|e| anyhow!("funding emit has an invalid recipient: {e}"))?;
        ensure!(
            accounts[RECIPIENT_ACCOUNT_INDEX].pubkey == stated_recipient,
            "funding emit's recipient {stated_recipient} does not match its recipient account \
             {}",
            accounts[RECIPIENT_ACCOUNT_INDEX].pubkey
        );

        let transact_data = decode_hex(s("transact_data_hex")?)
            .context("decoding the funding emit's transact_data_hex")?;

        let request = FundingRequest {
            transact: ValueTransactRequest {
                program_id,
                transact_data,
                accounts,
                tx_profile,
            },
            commit_wallet: stated_recipient,
        };
        // Reject a non-withdrawal here rather than at `accept`, so a bad emit is
        // named at the boundary it entered through.
        request
            .withdraw_amount()
            .context("the funding emit's publicAmount")?;
        Ok(request)
    }
}

/// Decode a lowercase-or-uppercase hex string into bytes.
fn decode_hex(s: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    ensure!(s.len().is_multiple_of(2), "odd-length hex string");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| anyhow!("bad hex: {e}")))
        .collect()
}

/// The relay keys this coordinator can release funding withdrawals with, indexed
/// by the ValuePool authority each one is.
///
/// **Why this is not a `FeePayerRing`.** The crowd path rotates over a set of
/// fee payers so that no single payer key becomes a stable cluster label across
/// settlements. A funding withdrawal cannot rotate the same way, and saying why
/// is more useful than pretending it can: the on-chain `Transact` requires the
/// ValuePool **authority** to sign, and that signer is also the transaction fee
/// payer. Paying from some other key would put a SECOND signature on the
/// transaction, and a two-signature funding withdrawal is a strictly worse
/// linkage handle than a predictable payer, because the extra key is per-relay
/// state an observer can follow.
///
/// So within one pool the payer is pinned to that pool's authority by
/// construction, and rotation happens ACROSS pools: a coordinator serving
/// several denominated funding pools holds one relay key per pool and releases
/// each request under the authority it is bound to. A request naming an
/// authority this coordinator does not hold is refused rather than turned into a
/// transaction that cannot be signed.
#[derive(Default)]
pub struct RelaySet {
    by_authority: BTreeMap<Pubkey, Keypair>,
}

impl std::fmt::Debug for RelaySet {
    /// Prints the authorities only. A relay key is a secret and must never reach
    /// a log line through a `Debug` impl.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelaySet")
            .field("authorities", &self.by_authority.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl RelaySet {
    /// A set holding one relay (the single-funding-pool case).
    pub fn single(relay: Keypair) -> Self {
        let mut set = Self::default();
        set.insert(relay);
        set
    }

    /// Build from several relay keys. Rejects an empty set: a coordinator with
    /// no relay key can never release a round.
    pub fn new(relays: impl IntoIterator<Item = Keypair>) -> Result<Self> {
        let mut set = Self::default();
        for relay in relays {
            set.insert(relay);
        }
        ensure!(
            !set.by_authority.is_empty(),
            "the relay set must hold at least one key"
        );
        Ok(set)
    }

    pub fn insert(&mut self, relay: Keypair) {
        self.by_authority.insert(relay.pubkey(), relay);
    }

    pub fn authorities(&self) -> Vec<Pubkey> {
        self.by_authority.keys().copied().collect()
    }

    pub fn len(&self) -> usize {
        self.by_authority.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_authority.is_empty()
    }

    /// The relay key for `authority`, or `None` if this coordinator does not
    /// serve that pool.
    pub fn get(&self, authority: &Pubkey) -> Option<&Keypair> {
        self.by_authority.get(authority)
    }
}

/// How a release loop finds the key to sign a given request with.
enum RelaySelector<'a> {
    /// One relay for every request (the shape [`FundingRounds::on_slot`] has
    /// always had; behavior is unchanged).
    Single(&'a Keypair),
    /// Per-request lookup by the request's bound authority.
    Set(&'a RelaySet),
}

impl RelaySelector<'_> {
    fn resolve(&self, request: &FundingRequest) -> Result<&Keypair> {
        match self {
            RelaySelector::Single(relay) => Ok(relay),
            RelaySelector::Set(set) => {
                let authority = request.authority()?;
                set.get(&authority).ok_or_else(|| {
                    anyhow!(
                        "no relay key for value-pool authority {authority}; this coordinator \
                         serves {:?}",
                        set.authorities()
                    )
                })
            }
        }
    }
}

/// What happened to one closable funding round.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RoundOutcome {
    /// The round met the floor and every withdrawal in it was submitted.
    Released {
        round: u64,
        release_slot: u64,
        /// Number of withdrawals released together.
        size: usize,
        /// Signatures in submission order (which is the release order, not the
        /// arrival order).
        signatures: Vec<Signature>,
    },
    /// The round was below the floor; its withdrawals moved into round `to`.
    RolledForward { round: u64, to: u64, size: usize },
}

/// The funding-round batcher: accepts unshield requests, holds them to the round
/// boundary, and releases each round as one batch through the gasless relay.
#[derive(Debug)]
pub struct FundingRounds {
    config: FundingRoundConfig,
    pending: BTreeMap<u64, Vec<FundingRequest>>,
}

impl FundingRounds {
    /// Build a batcher. Rejects a zero-length round (every withdrawal would
    /// release instantly, which is the un-batched case) and a floor below 2 (a
    /// round of one withdrawal is a direct shield-to-unshield link).
    pub fn new(config: FundingRoundConfig) -> Result<Self> {
        ensure!(
            config.round_slots > 0,
            "round_slots must be > 0 (a zero-length round is no batching at all)"
        );
        ensure!(
            config.min_round_size >= 2,
            "min_round_size must be >= 2 (a round of one is a direct funding link)"
        );
        Ok(Self {
            config,
            pending: BTreeMap::new(),
        })
    }

    pub fn config(&self) -> &FundingRoundConfig {
        &self.config
    }

    /// The round a slot belongs to.
    pub fn round_of(&self, slot: u64) -> u64 {
        slot / self.config.round_slots
    }

    /// The slot a round releases at: the first slot after its window closes.
    pub fn release_slot(&self, round: u64) -> u64 {
        (round + 1) * self.config.round_slots
    }

    /// Rounds still holding unreleased withdrawals, oldest first.
    pub fn pending_rounds(&self) -> Vec<u64> {
        self.pending.keys().copied().collect()
    }

    /// Withdrawals currently batched for `round`.
    pub fn len(&self, round: u64) -> usize {
        self.pending.get(&round).map_or(0, Vec::len)
    }

    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Accept a funding withdrawal submitted at `slot`, returning the round it
    /// was batched into.
    ///
    /// Validates before batching, because an invalid request that reaches the
    /// chain costs a relay signature and, worse, a distinguishable failed
    /// transaction: the request must be a withdrawal, and under a denominated
    /// pool it must move exactly the denomination. The on-chain program enforces
    /// the same rule (`DenominationMismatch`); this is the fail-fast copy.
    pub fn accept(&mut self, slot: u64, request: FundingRequest) -> Result<u64> {
        let amount = request.withdraw_amount()?;
        if let Some(denomination) = self.config.denomination {
            ensure!(
                amount == denomination,
                "funding withdrawal of {amount} does not match the pool denomination \
                 {denomination}; a distinctive amount re-links the funder to the fundee"
            );
        }
        let round = self.round_of(slot);
        self.pending.entry(round).or_default().push(request);
        Ok(round)
    }

    /// The order a round's withdrawals are submitted in: a deterministic
    /// permutation derived from the round number and each request's commit
    /// wallet, never the arrival order.
    ///
    /// This is not a cryptographic shuffle and does not need to be. Its only job
    /// is to make sure the submission sequence carries no information about who
    /// asked first; the ordering key is public data an observer already has.
    pub fn release_order(&self, round: u64) -> Vec<usize> {
        let requests = self.pending.get(&round).map_or(&[][..], Vec::as_slice);
        let mut order: Vec<usize> = (0..requests.len()).collect();
        order.sort_by_key(|&i| {
            (
                order_key(round, &requests[i].commit_wallet),
                requests[i].commit_wallet.to_bytes(),
            )
        });
        order
    }

    /// Process one observed slot: release every round whose window has closed and
    /// which meets the floor, and roll the rest forward.
    ///
    /// `relay` is the value pool authority and the transaction fee payer. An
    /// unshield is relay-only signed, so no participant signature is needed here;
    /// that is exactly what keeps the participant off the funding transaction.
    ///
    /// Rounds that roll forward are reconsidered when the round they moved into
    /// closes, on a later call, so a thin round can never be released just because
    /// the scheduler happened to catch up several rounds at once.
    pub async fn on_slot(
        &mut self,
        slot: u64,
        client: &dyn SolanaClient,
        relay: &Keypair,
    ) -> Result<Vec<RoundOutcome>> {
        self.release_due(slot, client, &RelaySelector::Single(relay))
            .await
    }

    /// [`FundingRounds::on_slot`] for a coordinator serving more than one
    /// funding pool: each request is released under the relay key for the
    /// ValuePool authority it is bound to (see [`RelaySet`]).
    ///
    /// A request whose authority this coordinator does not hold fails the round
    /// exactly like a failed submit does: the remainder is re-queued and the
    /// error is surfaced, because silently dropping it would strand the
    /// participant's value in the pool.
    pub async fn on_slot_with_relays(
        &mut self,
        slot: u64,
        client: &dyn SolanaClient,
        relays: &RelaySet,
    ) -> Result<Vec<RoundOutcome>> {
        self.release_due(slot, client, &RelaySelector::Set(relays))
            .await
    }

    async fn release_due(
        &mut self,
        slot: u64,
        client: &dyn SolanaClient,
        relays: &RelaySelector<'_>,
    ) -> Result<Vec<RoundOutcome>> {
        let closable: Vec<u64> = self
            .pending_rounds()
            .into_iter()
            .filter(|round| self.release_slot(*round) <= slot)
            .collect();

        let mut outcomes = Vec::with_capacity(closable.len());
        for round in closable {
            let size = self.len(round);
            if size < self.config.min_round_size {
                let to = round + 1;
                let moved = self.pending.remove(&round).unwrap_or_default();
                self.pending.entry(to).or_default().extend(moved);
                tracing::warn!(
                    round,
                    size,
                    min_round_size = self.config.min_round_size,
                    to,
                    "funding round below the floor: rolling forward instead of releasing"
                );
                outcomes.push(RoundOutcome::RolledForward { round, to, size });
                continue;
            }

            let order = self.release_order(round);
            // Held as `Option`s so a request that has been submitted can be taken
            // out of the batch while the ones that have not stay owned here: if the
            // RPC dies halfway through a round, the remainder must go back into the
            // batcher rather than evaporate. A dropped funding withdrawal is a
            // participant who cannot commit and whose value is stuck shielded.
            let mut requests: Vec<Option<FundingRequest>> = self
                .pending
                .remove(&round)
                .unwrap_or_default()
                .into_iter()
                .map(Some)
                .collect();
            let mut signatures = Vec::with_capacity(order.len());
            let mut failure = None;
            for &i in &order {
                let request = requests[i]
                    .as_ref()
                    .expect("the release order visits each request exactly once");
                let relay = match relays.resolve(request) {
                    Ok(relay) => relay,
                    Err(e) => {
                        failure = Some(e.context(format!(
                            "resolving the relay key for round {round} (index {i})"
                        )));
                        break;
                    }
                };
                match submit_transact(client, relay, &request.transact, &[]).await {
                    Ok(signature) => {
                        signatures.push(signature);
                        requests[i] = None;
                    }
                    Err(e) => {
                        failure = Some(e.context(format!(
                            "submitting funding withdrawal in round {round} (index {i})"
                        )));
                        break;
                    }
                }
            }
            if let Some(error) = failure {
                let leftovers: Vec<FundingRequest> = requests.into_iter().flatten().collect();
                let requeued = leftovers.len();
                self.pending.entry(round + 1).or_default().extend(leftovers);
                tracing::error!(
                    round,
                    submitted = signatures.len(),
                    requeued,
                    min_round_size = self.config.min_round_size,
                    "funding round failed mid-release: the remainder was re-queued into the next \
                     round, but the withdrawals that DID land were released as a batch smaller \
                     than the round, which is a smaller crowd than intended"
                );
                return Err(error);
            }
            tracing::info!(
                round,
                size,
                release_slot = self.release_slot(round),
                denomination = ?self.config.denomination,
                "funding round released (uniform amount, arrival order destroyed)"
            );
            outcomes.push(RoundOutcome::Released {
                round,
                release_slot: self.release_slot(round),
                size,
                signatures,
            });
        }
        Ok(outcomes)
    }
}

/// splitmix64 over the round number mixed with the commit wallet: a cheap,
/// deterministic, arrival-independent ordering key. Not a hash function anyone
/// should rely on for anything else.
fn order_key(round: u64, wallet: &Pubkey) -> u64 {
    let mut x = round.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    for chunk in wallet.to_bytes().chunks_exact(8) {
        let word = u64::from_le_bytes(chunk.try_into().expect("chunks_exact(8) yields 8 bytes"));
        x = x.wrapping_add(word).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        x ^= x >> 31;
    }
    x ^= x >> 30;
    x = x.wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::MockSolanaClient;
    use crate::config::TxProfile;
    use mirror_core::note::public_amount;
    use solana_instruction::AccountMeta;
    use solana_signer::Signer;

    const SYSTEM_PROGRAM_ID: Pubkey = Pubkey::from_str_const("11111111111111111111111111111111");

    /// A Transact body carrying `signed` as its publicAmount; every other field is
    /// zero, which is fine because nothing here inspects the proof.
    fn transact_data(signed: SignedAmount) -> Vec<u8> {
        let mut data = vec![wire::tag::TRANSACT];
        data.extend(std::iter::repeat_n(0u8, wire::TRANSACT_HEADER_LEN));
        let pa = public_amount(signed);
        let start = 1 + wire::TRANSACT_PUBLIC_AMOUNT_OFF;
        data[start..start + 32].copy_from_slice(&pa);
        data.extend_from_slice(&0u16.to_le_bytes()); // enc0 empty
        data.extend_from_slice(&0u16.to_le_bytes()); // enc1 empty
        data
    }

    fn request(relay: &Pubkey, commit_wallet: Pubkey, signed: SignedAmount) -> FundingRequest {
        FundingRequest {
            transact: ValueTransactRequest {
                program_id: Pubkey::new_from_array([0x11; 32]),
                transact_data: transact_data(signed),
                accounts: vec![
                    AccountMeta::new(Pubkey::new_from_array([0x22; 32]), false), // vpool
                    AccountMeta::new(*relay, true),                              // authority
                    AccountMeta::new(Pubkey::new_from_array([0x31; 32]), false), // nf0
                    AccountMeta::new(Pubkey::new_from_array([0x32; 32]), false), // nf1
                    AccountMeta::new(commit_wallet, false),                      // recipient
                    AccountMeta::new(*relay, false),                             // depositor slot
                    AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
                    AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
                    AccountMeta::new(Pubkey::new_from_array([0x88; 32]), false), // vault
                ],
                tx_profile: TxProfile::default(),
            },
            commit_wallet,
        }
    }

    fn wallet(seed: u8) -> Pubkey {
        Pubkey::new_from_array([seed; 32])
    }

    fn config(denomination: Option<u64>) -> FundingRoundConfig {
        FundingRoundConfig {
            round_slots: 100,
            min_round_size: 3,
            denomination,
        }
    }

    #[test]
    fn withdraw_amount_decodes_and_rejects_non_withdrawals() {
        let relay = Pubkey::new_unique();
        assert_eq!(
            request(&relay, wallet(1), SignedAmount::Withdraw(7_000))
                .withdraw_amount()
                .unwrap(),
            7_000
        );
        // A deposit or a transfer is not a funding request: the relay must not be
        // tricked into signing something that moves no value to a commit wallet.
        assert!(request(&relay, wallet(1), SignedAmount::Deposit(7_000))
            .withdraw_amount()
            .is_err());
        assert!(request(&relay, wallet(1), SignedAmount::Transfer)
            .withdraw_amount()
            .is_err());
    }

    #[test]
    fn denominated_round_rejects_a_distinctive_amount() {
        let relay = Pubkey::new_unique();
        let mut rounds = FundingRounds::new(config(Some(1_000_000))).unwrap();
        rounds
            .accept(
                10,
                request(&relay, wallet(1), SignedAmount::Withdraw(1_000_000)),
            )
            .expect("the exact denomination is accepted");
        let err = rounds
            .accept(
                10,
                request(&relay, wallet(2), SignedAmount::Withdraw(1_000_001)),
            )
            .expect_err("an off-denomination amount must be refused before it reaches the chain");
        assert!(
            err.to_string().contains("denomination"),
            "error should name the denomination rule, got: {err}"
        );
        assert_eq!(rounds.len(0), 1, "the bad request was not batched");
    }

    #[test]
    fn free_amount_pool_accepts_any_amount_but_says_so() {
        // With no denomination the batcher still works, it just cannot claim the
        // amount channel is closed. Both amounts are accepted.
        let relay = Pubkey::new_unique();
        let mut rounds = FundingRounds::new(config(None)).unwrap();
        rounds
            .accept(1, request(&relay, wallet(1), SignedAmount::Withdraw(3)))
            .unwrap();
        rounds
            .accept(1, request(&relay, wallet(2), SignedAmount::Withdraw(999)))
            .unwrap();
        assert_eq!(rounds.len(0), 2);
    }

    #[test]
    fn rounds_are_derived_from_the_submission_slot() {
        let relay = Pubkey::new_unique();
        let mut rounds = FundingRounds::new(config(None)).unwrap();
        assert_eq!(
            rounds
                .accept(0, request(&relay, wallet(1), SignedAmount::Withdraw(1)))
                .unwrap(),
            0
        );
        assert_eq!(
            rounds
                .accept(99, request(&relay, wallet(2), SignedAmount::Withdraw(1)))
                .unwrap(),
            0
        );
        assert_eq!(
            rounds
                .accept(100, request(&relay, wallet(3), SignedAmount::Withdraw(1)))
                .unwrap(),
            1
        );
        assert_eq!(rounds.release_slot(0), 100);
        assert_eq!(rounds.release_slot(1), 200);
    }

    #[test]
    fn release_order_is_not_arrival_order_and_is_a_permutation() {
        let relay = Pubkey::new_unique();
        let mut rounds = FundingRounds::new(config(None)).unwrap();
        for seed in 1..=8u8 {
            rounds
                .accept(
                    1,
                    request(&relay, wallet(seed), SignedAmount::Withdraw(1_000)),
                )
                .unwrap();
        }
        let order = rounds.release_order(0);
        let mut sorted = order.clone();
        sorted.sort_unstable();
        assert_eq!(
            sorted,
            (0..8).collect::<Vec<_>>(),
            "the release order must be a permutation of the round"
        );
        assert_ne!(
            order,
            (0..8).collect::<Vec<_>>(),
            "the release order must not be the arrival order"
        );
        assert_eq!(
            order,
            rounds.release_order(0),
            "the release order must be deterministic"
        );
    }

    #[tokio::test]
    async fn thin_round_rolls_forward_instead_of_releasing() {
        let relay = Keypair::new();
        let client = MockSolanaClient::new();
        let mut rounds = FundingRounds::new(config(None)).unwrap();
        // Two withdrawals, floor of three.
        for seed in 1..=2u8 {
            rounds
                .accept(
                    5,
                    request(&relay.pubkey(), wallet(seed), SignedAmount::Withdraw(10)),
                )
                .unwrap();
        }

        // Window still open: nothing happens.
        let outcomes = rounds.on_slot(99, &client, &relay).await.unwrap();
        assert!(outcomes.is_empty());
        assert_eq!(client.sent_count(), 0);

        // Window closed but below the floor: roll forward, submit nothing.
        let outcomes = rounds.on_slot(100, &client, &relay).await.unwrap();
        assert_eq!(
            outcomes,
            vec![RoundOutcome::RolledForward {
                round: 0,
                to: 1,
                size: 2
            }]
        );
        assert_eq!(
            client.sent_count(),
            0,
            "a thin funding round must never reach the chain"
        );
        assert_eq!(
            rounds.len(1),
            2,
            "the withdrawals moved into the next round"
        );
    }

    #[tokio::test]
    async fn full_round_releases_every_withdrawal_relay_signed() {
        let relay = Keypair::new();
        let client = MockSolanaClient::new();
        let mut rounds = FundingRounds::new(config(Some(1_000))).unwrap();
        for seed in 1..=4u8 {
            rounds
                .accept(
                    7,
                    request(&relay.pubkey(), wallet(seed), SignedAmount::Withdraw(1_000)),
                )
                .unwrap();
        }

        let outcomes = rounds.on_slot(100, &client, &relay).await.unwrap();
        assert_eq!(outcomes.len(), 1);
        match &outcomes[0] {
            RoundOutcome::Released {
                round,
                release_slot,
                size,
                signatures,
            } => {
                assert_eq!(*round, 0);
                assert_eq!(*release_slot, 100);
                assert_eq!(*size, 4);
                assert_eq!(signatures.len(), 4);
            }
            other => panic!("expected Released, got {other:?}"),
        }
        assert_eq!(client.sent_count(), 4);

        // Every funding withdrawal is signed by the relay ALONE: the participant
        // never signs the transaction that funds their commit wallet, which is the
        // whole point of routing it through the pool.
        {
            let sent = client.sent.lock().unwrap();
            for tx in sent.iter() {
                assert_eq!(
                    tx.signatures.len(),
                    1,
                    "a funding withdrawal must be relay-only signed"
                );
                assert_eq!(
                    tx.message.static_account_keys()[0],
                    relay.pubkey(),
                    "the relay is the fee payer"
                );
            }
        }

        // The round is gone; a later slot releases nothing again.
        assert!(rounds.is_empty());
        let outcomes = rounds.on_slot(500, &client, &relay).await.unwrap();
        assert!(outcomes.is_empty());
        assert_eq!(client.sent_count(), 4);
    }

    #[tokio::test]
    async fn a_failed_submit_requeues_the_rest_of_the_round() {
        // The RPC dies halfway through a batch. The withdrawals that did not
        // reach the chain must go back into the batcher, not disappear: a lost
        // funding withdrawal is a participant whose value is stuck shielded and
        // who cannot commit. The error is still surfaced.
        let relay = Keypair::new();
        let client = MockSolanaClient::failing_after(2);
        let mut rounds = FundingRounds::new(config(Some(1_000))).unwrap();
        for seed in 1..=5u8 {
            rounds
                .accept(
                    7,
                    request(&relay.pubkey(), wallet(seed), SignedAmount::Withdraw(1_000)),
                )
                .unwrap();
        }

        let err = rounds
            .on_slot(100, &client, &relay)
            .await
            .expect_err("the mid-round RPC failure must be surfaced, not swallowed");
        assert!(
            err.to_string().contains("funding withdrawal in round 0"),
            "the error should name the round, got: {err}"
        );
        assert_eq!(client.sent_count(), 2, "only the accepted sends landed");
        assert_eq!(
            rounds.len(1),
            3,
            "the three unsubmitted withdrawals moved into the next round"
        );
        assert_eq!(
            rounds.len(0),
            0,
            "the failed round is not left half-drained"
        );
    }

    #[tokio::test]
    async fn rolled_forward_round_releases_once_it_meets_the_floor() {
        let relay = Keypair::new();
        let client = MockSolanaClient::new();
        let mut rounds = FundingRounds::new(config(None)).unwrap();
        // Round 0: two (thin). Round 1: one more, so the merged round meets 3.
        for seed in 1..=2u8 {
            rounds
                .accept(
                    5,
                    request(&relay.pubkey(), wallet(seed), SignedAmount::Withdraw(10)),
                )
                .unwrap();
        }
        rounds.on_slot(100, &client, &relay).await.unwrap();
        rounds
            .accept(
                150,
                request(&relay.pubkey(), wallet(3), SignedAmount::Withdraw(10)),
            )
            .unwrap();

        let outcomes = rounds.on_slot(200, &client, &relay).await.unwrap();
        assert_eq!(outcomes.len(), 1);
        assert!(matches!(
            outcomes[0],
            RoundOutcome::Released {
                round: 1,
                size: 3,
                ..
            }
        ));
        assert_eq!(client.sent_count(), 3);
    }

    #[test]
    fn config_rejects_degenerate_rounds() {
        assert!(FundingRounds::new(FundingRoundConfig {
            round_slots: 0,
            ..config(None)
        })
        .is_err());
        assert!(FundingRounds::new(FundingRoundConfig {
            min_round_size: 1,
            ..config(None)
        })
        .is_err());
    }
}
