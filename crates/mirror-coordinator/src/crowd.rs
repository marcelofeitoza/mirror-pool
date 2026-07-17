//! The crowd path: composing one atomic settlement transaction out of the
//! on-chain `SettleEpoch` instruction plus every participant's own pooled
//! action.
//!
//! This is where the "N identical actions on one shared timestamp, paid by a
//! rotating relay" property is physically built. One settlement is a single v0
//! (versioned) transaction:
//!
//! ```text
//!   ix[0]  ComputeBudget SetComputeUnitLimit   (from TxProfile, pool-wide)
//!   ix[1]  ComputeBudget SetComputeUnitPrice   (from TxProfile, pool-wide)
//!   ix[2]  SettleEpoch { epoch, [nullifier..] } (mirror-pool program)
//!   ix[3..]  participant_i behavior instruction(s)  (identical shape per i)
//! ```
//!
//! Signer set is `N + 1`: the rotating coordinator fee-payer (transaction fee
//! payer at index 0, which also fills the `SettleEpoch` authority and payer
//! roles) plus each participant, who signs only their own action. Solana forbids
//! a signer from being loaded through an Address Lookup Table, so every signer
//! is a static key; the pool's shared, non-signer accounts (program ids, the
//! Pool PDA, the clock sysvar, the shared sink) live in the ALT. Per-settlement
//! accounts that change every epoch (the Epoch PDA and the per-participant
//! Nullifier PDAs) stay in the static key list because a create-once ALT cannot
//! carry them.
//!
//! ## Why one coordinator signer, not two
//! The `SettleEpoch` instruction takes an `authority` (must equal the pool
//! authority) and a `payer` (funds the nullifier-PDA rent). The crowd path
//! collapses both onto the single rotating fee-payer at index 0, so a settlement
//! carries exactly `N + 1` signatures. Splitting them to rotate only the payer
//! while keeping a fixed authority is possible, but a fixed authority key would
//! itself become the stable cluster label that rotation exists to remove, so the
//! pool is initialized with the rotating relay as its authority.
//!
//! ## Packet limit
//! A signed transaction must fit the 1232-byte packet. For the [`PlainTransfer`]
//! SOL baseline that caps one settlement at [`PLAIN_TRANSFER_MAX_PER_TX`]
//! participants (derivation on the constant). [`build_crowd_message`] fails
//! closed if a built message would exceed the limit, and [`plan_settlements`]
//! chunks a larger epoch into tx-sized groups.
//!
//! [`PlainTransfer`]: mirror_behaviors::PlainTransfer

use std::collections::BTreeMap;
use std::sync::Arc;

use anyhow::{ensure, Context, Result};
use mirror_behaviors::Behavior;
use mirror_core::{Epoch, Nullifier, SizeBucket};
use solana_hash::Hash;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_message::{v0, AddressLookupTableAccount, VersionedMessage};
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;

use crate::client::{DynSigner, SolanaClient};
use crate::config::TxProfile;
use crate::submit::{settle_epoch_data, SettleBatch, SettleReceipt, SettleSubmitter};

/// The maximum size of a serialized Solana transaction packet, in bytes.
pub const PACKET_DATA_SIZE: usize = 1232;

/// PDA seed prefixes, byte-identical to the on-chain program's `pda` module.
/// These are protocol constants, not secrets or keys.
pub const POOL_SEED: &[u8] = b"pool";
pub const EPOCH_SEED: &[u8] = b"epoch";
pub const NULLIFIER_SEED: &[u8] = b"nf";

/// The ComputeBudget program (fixed, public system address).
pub const COMPUTE_BUDGET_PROGRAM_ID: Pubkey =
    Pubkey::from_str_const("ComputeBudget111111111111111111111111111111");

/// The Clock sysvar account read by `SettleEpoch` for the window-closed gate.
pub const CLOCK_SYSVAR_ID: Pubkey =
    Pubkey::from_str_const("SysvarC1ock11111111111111111111111111111111");

/// Participants that fit in one 1232-byte settlement for the PlainTransfer SOL
/// baseline, with the pool's shared accounts in the ALT.
///
/// Each extra participant adds, at minimum, a 64-byte signature, a 32-byte
/// signer key, a 32-byte Nullifier-PDA key, a 32-byte nullifier in the
/// SettleEpoch data, a System `Transfer` instruction (~17 bytes), and the
/// account-index bytes that reference them. That is roughly 180 bytes each; five
/// participants serialize to 1234 bytes (2 over), so the baseline cap is four.
/// Behaviors with a larger per-participant account footprint (a Jupiter swap)
/// fit fewer; always trust the fail-closed size check in [`build_crowd_message`]
/// over this constant.
pub const PLAIN_TRANSFER_MAX_PER_TX: usize = 4;

/// Derive the Epoch PDA: seeds `[b"epoch", pool, epoch_id(8 LE)]`.
pub fn epoch_pda(program_id: &Pubkey, pool: &Pubkey, epoch: Epoch) -> Pubkey {
    Pubkey::find_program_address(
        &[EPOCH_SEED, pool.as_ref(), &epoch.0.to_le_bytes()],
        program_id,
    )
    .0
}

/// Derive a Nullifier PDA: seeds `[b"nf", pool, epoch_id(8 LE), nullifier(32)]`.
pub fn nullifier_pda(
    program_id: &Pubkey,
    pool: &Pubkey,
    epoch: Epoch,
    nullifier: &Nullifier,
) -> Pubkey {
    Pubkey::find_program_address(
        &[
            NULLIFIER_SEED,
            pool.as_ref(),
            &epoch.0.to_le_bytes(),
            &nullifier.0,
        ],
        program_id,
    )
    .0
}

/// One participant in a crowd settlement: the wallet that signs its own action,
/// the pooled behavior it performs, the fixed size bucket, and its epoch-scoped
/// nullifier (the anti-replay tag revealed at settlement).
#[derive(Clone)]
pub struct SettleParticipant {
    /// The participant's wallet; signs only its own behavior instruction.
    pub signer: Pubkey,
    /// The pooled action, identical in shape across all participants.
    pub behavior: Arc<dyn Behavior>,
    /// The pool-wide fixed size bucket (equals the behavior's action-class size).
    pub size: SizeBucket,
    /// The nullifier revealed for this participant this epoch.
    pub nullifier: Nullifier,
}

impl std::fmt::Debug for SettleParticipant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SettleParticipant")
            .field("signer", &self.signer)
            .field("behavior", &self.behavior.describe())
            .field("size", &self.size)
            .field("nullifier", &self.nullifier)
            .finish()
    }
}

/// Pool-wide settlement context, fixed for the pool's lifetime. No key material
/// here: `program_id` and `pool` arrive from deploy-time config, and `alt` is
/// created once by [`setup_pool_alt`].
#[derive(Clone, Debug)]
pub struct SettleContext {
    /// The mirror-pool program id (from configuration, never hardcoded).
    pub program_id: Pubkey,
    /// The Pool PDA being settled.
    pub pool: Pubkey,
    /// The pool's Address Lookup Table holding the shared, non-signer accounts.
    pub alt: AddressLookupTableAccount,
}

/// One crowd-settlement build request.
pub struct CrowdSettleRequest<'a> {
    pub ctx: &'a SettleContext,
    pub epoch: Epoch,
    /// The rotating coordinator: transaction fee payer, and the `SettleEpoch`
    /// authority + payer.
    pub fee_payer: Pubkey,
    /// Participants in a fixed order; `participants[i]` pairs with the i-th
    /// nullifier and the i-th behavior instruction block.
    pub participants: &'a [SettleParticipant],
    /// The pool-wide normalized CU limit + priority fee (the only CU source).
    pub tx_profile: TxProfile,
    pub recent_blockhash: Hash,
}

/// The two normalized ComputeBudget instructions, from the pool's [`TxProfile`].
/// Fixed per pool so every settlement has the same compute fingerprint.
pub fn compute_budget_instructions(tx_profile: &TxProfile) -> [Instruction; 2] {
    use solana_compute_budget_interface::ComputeBudgetInstruction;
    [
        ComputeBudgetInstruction::set_compute_unit_limit(tx_profile.cu_limit),
        ComputeBudgetInstruction::set_compute_unit_price(tx_profile.priority_fee_micro_lamports),
    ]
}

/// Build the `SettleEpoch` instruction for the crowd path.
///
/// Account order matches the on-chain program exactly:
/// `[pool, epoch, authority, nullifier*n, payer, system_program, clock]`. The
/// rotating `fee_payer` fills both the authority and payer slots.
pub fn settle_epoch_instruction(
    ctx: &SettleContext,
    epoch: Epoch,
    fee_payer: &Pubkey,
    nullifiers: &[Nullifier],
) -> Instruction {
    let mut accounts = Vec::with_capacity(nullifiers.len() + 6);
    // 0: pool (read-only), 1: epoch (writable), 2: authority (signer).
    accounts.push(AccountMeta::new_readonly(ctx.pool, false));
    accounts.push(AccountMeta::new(
        epoch_pda(&ctx.program_id, &ctx.pool, epoch),
        false,
    ));
    accounts.push(AccountMeta::new_readonly(*fee_payer, true));
    // 3..3+n: one Nullifier PDA per revealed nullifier (writable).
    for nf in nullifiers {
        accounts.push(AccountMeta::new(
            nullifier_pda(&ctx.program_id, &ctx.pool, epoch, nf),
            false,
        ));
    }
    // 3+n: payer (signer, writable) == the same rotating fee-payer.
    accounts.push(AccountMeta::new(*fee_payer, true));
    // 4+n: system_program, 5+n: clock sysvar.
    accounts.push(AccountMeta::new_readonly(
        mirror_behaviors::programs::SYSTEM_PROGRAM_ID,
        false,
    ));
    accounts.push(AccountMeta::new_readonly(CLOCK_SYSVAR_ID, false));

    Instruction {
        program_id: ctx.program_id,
        accounts,
        data: settle_epoch_data(epoch, nullifiers),
    }
}

/// The serialized size, in bytes, of the fully-signed transaction for `message`
/// (message bytes plus the fixed-size signature section). This is the number
/// checked against [`PACKET_DATA_SIZE`].
pub fn signed_transaction_len(message: &VersionedMessage) -> usize {
    let num_sigs = message.header().num_required_signatures as usize;
    let message_len = message.serialize().len();
    shortvec_len(num_sigs) + 64 * num_sigs + message_len
}

/// compact-u16 (shortvec) encoded length of `n`.
fn shortvec_len(n: usize) -> usize {
    if n < 0x80 {
        1
    } else if n < 0x4000 {
        2
    } else {
        3
    }
}

/// Build one crowd-settlement v0 message: normalized ComputeBudget, then
/// `SettleEpoch`, then every participant's behavior instruction(s), compiled
/// against the pool ALT.
///
/// Fails closed if the request is empty, if the participant/nullifier counts are
/// out of range, or if the signed transaction would exceed [`PACKET_DATA_SIZE`]
/// (use [`plan_settlements`] to chunk a larger epoch).
pub async fn build_crowd_message(req: CrowdSettleRequest<'_>) -> Result<VersionedMessage> {
    ensure!(
        !req.participants.is_empty(),
        "crowd settlement needs at least one participant"
    );

    let nullifiers: Vec<Nullifier> = req.participants.iter().map(|p| p.nullifier).collect();

    let mut instructions = Vec::with_capacity(3 + req.participants.len());
    instructions.extend(compute_budget_instructions(&req.tx_profile));
    instructions.push(settle_epoch_instruction(
        req.ctx,
        req.epoch,
        &req.fee_payer,
        &nullifiers,
    ));

    // Each participant's own action. build_instructions is async (a behavior may
    // reach a quote API); PlainTransfer resolves offline.
    for p in req.participants {
        let ixs = p
            .behavior
            .build_instructions(&p.signer, p.size)
            .await
            .with_context(|| format!("build behavior instructions for {}", p.signer))?;
        instructions.extend(ixs);
    }

    let message = v0::Message::try_compile(
        &req.fee_payer,
        &instructions,
        std::slice::from_ref(&req.ctx.alt),
        req.recent_blockhash,
    )
    .context("compile crowd settlement message")?;
    let message = VersionedMessage::V0(message);

    let len = signed_transaction_len(&message);
    ensure!(
        len <= PACKET_DATA_SIZE,
        "settlement transaction is {len} bytes for {} participants, over the {PACKET_DATA_SIZE}-byte packet limit; reduce participants per tx (see plan_settlements)",
        req.participants.len()
    );

    Ok(message)
}

/// Sign a crowd-settlement message with the coordinator fee-payer followed by
/// each participant keypair. The keypair order does not need to match the
/// message account order; the transaction matches each signature to its key.
pub fn sign_settlement(
    message: VersionedMessage,
    signers: &[&Keypair],
) -> Result<VersionedTransaction> {
    let signer_refs: Vec<&dyn Signer> = signers.iter().map(|k| *k as &dyn Signer).collect();
    VersionedTransaction::try_new(message, signer_refs.as_slice())
        .context("sign crowd settlement transaction")
}

/// Chunk `participants` into groups that each settle in one transaction.
///
/// The k-anonymity floor is an epoch-level gate enforced before settlement (in
/// [`crate::scheduler::Coordinator::on_slot`]); chunking does not change the
/// epoch's real k, and each chunk carries a disjoint nullifier subset whose
/// union is the whole epoch, so per-nullifier anti-replay stays correct.
///
/// Caveat: the current on-chain `SettleEpoch` marks the epoch settled and
/// rejects a second call, so more than one chunk per epoch requires either
/// growing the ALT to also carry the Nullifier PDAs (raising the single-tx cap)
/// or an additive settle-in-parts program capability. Prefer sizing an epoch to
/// one chunk; this planner exists so the split is correct when that capability
/// lands.
pub fn plan_settlements(
    participants: &[SettleParticipant],
    max_per_tx: usize,
) -> Vec<&[SettleParticipant]> {
    if max_per_tx == 0 {
        return Vec::new();
    }
    participants.chunks(max_per_tx).collect()
}

/// The shared, non-signer accounts that belong in a PlainTransfer pool's ALT.
///
/// Program ids are included per the ALT-holds-everything-shared convention; the
/// message compiler keeps invoked programs in the static keys automatically
/// (they cannot be loaded from a table), so listing them here is harmless and
/// keeps the ALT the single source of "shared accounts".
pub fn plain_transfer_shared_accounts(ctx: &SettleContext, sink: &Pubkey) -> Vec<Pubkey> {
    vec![
        ctx.program_id,
        ctx.pool,
        mirror_behaviors::programs::SYSTEM_PROGRAM_ID,
        CLOCK_SYSVAR_ID,
        COMPUTE_BUDGET_PROGRAM_ID,
        *sink,
    ]
}

/// Create the pool's Address Lookup Table and populate it with `shared`
/// accounts. One-time setup; the returned [`AddressLookupTableAccount`] is
/// stored in [`SettleContext::alt`] and reused for every settlement.
///
/// The soak harness calls this once after `InitPool`.
pub async fn setup_pool_alt(
    client: &dyn SolanaClient,
    authority: &DynSigner,
    payer: &DynSigner,
    shared: Vec<Pubkey>,
) -> Result<AddressLookupTableAccount> {
    let (table, _sig) = client.create_lookup_table(authority, payer).await?;
    client
        .extend_lookup_table(&table, authority, payer, shared.clone())
        .await?;
    Ok(AddressLookupTableAccount {
        key: table,
        addresses: shared,
    })
}

/// The real crowd-path submitter: builds, signs, and sends one atomic
/// settlement per epoch over a [`SolanaClient`].
///
/// It gets the per-participant behaviors and signers out of band from the
/// nullifier-only [`SettleBatch`]: a driver (the CLI intake path or the Surfpool
/// soak) registers each epoch's participant roster with [`register_epoch`] and
/// the signing keypairs (rotating fee-payers plus participant wallets) with
/// [`register_signer`] before the epoch closes. At settlement time the submitter
/// looks the roster up by `batch.epoch` and the keypairs up by pubkey.
///
/// [`register_epoch`]: RpcSettleSubmitter::register_epoch
/// [`register_signer`]: RpcSettleSubmitter::register_signer
pub struct RpcSettleSubmitter {
    client: Arc<dyn SolanaClient>,
    ctx: SettleContext,
    // Epoch is Ord but not Hash, so the roster is a BTreeMap.
    roster: BTreeMap<Epoch, Vec<SettleParticipant>>,
    signers: std::collections::HashMap<Pubkey, Arc<Keypair>>,
}

impl RpcSettleSubmitter {
    pub fn new(client: Arc<dyn SolanaClient>, ctx: SettleContext) -> Self {
        Self {
            client,
            ctx,
            roster: BTreeMap::new(),
            signers: std::collections::HashMap::new(),
        }
    }

    /// Register the participant roster for `epoch` (pubkey + behavior + size +
    /// nullifier, in settlement order).
    pub fn register_epoch(&mut self, epoch: Epoch, participants: Vec<SettleParticipant>) {
        self.roster.insert(epoch, participants);
    }

    /// Register a signing keypair (a rotating fee-payer or a participant
    /// wallet), keyed by its pubkey.
    pub fn register_signer(&mut self, keypair: Arc<Keypair>) {
        self.signers.insert(keypair.pubkey(), keypair);
    }

    /// Borrow the settlement context (program id, pool, ALT).
    pub fn context(&self) -> &SettleContext {
        &self.ctx
    }

    /// Build, sign, and submit one atomic settlement for `batch.epoch`. This is
    /// the primary (async) entry point the soak harness calls directly.
    pub async fn submit_crowd(&self, batch: &SettleBatch) -> Result<SettleReceipt> {
        let participants = self
            .roster
            .get(&batch.epoch)
            .with_context(|| format!("no participant roster registered for {:?}", batch.epoch))?;

        // The scheduler-built batch and the registered roster must agree on the
        // nullifier set (order included), or the SettleEpoch and the behaviors
        // would settle different participants.
        ensure!(
            batch.nullifiers.len() == participants.len()
                && batch
                    .nullifiers
                    .iter()
                    .zip(participants.iter())
                    .all(|(n, p)| *n == p.nullifier),
            "batch nullifiers do not match the registered roster for {:?}",
            batch.epoch
        );

        let fee_payer = Pubkey::new_from_array(batch.fee_payer.0);
        let blockhash = self.client.get_latest_blockhash().await?;
        let message = build_crowd_message(CrowdSettleRequest {
            ctx: &self.ctx,
            epoch: batch.epoch,
            fee_payer,
            participants,
            tx_profile: batch.tx_profile,
            recent_blockhash: blockhash,
        })
        .await?;

        // Gather signers: the rotating fee-payer, then each participant wallet.
        let fee_kp = self
            .signers
            .get(&fee_payer)
            .with_context(|| format!("no keypair registered for fee payer {fee_payer}"))?
            .clone();
        let mut keypairs: Vec<Arc<Keypair>> = Vec::with_capacity(participants.len() + 1);
        keypairs.push(fee_kp);
        for p in participants {
            let kp = self
                .signers
                .get(&p.signer)
                .with_context(|| format!("no keypair registered for participant {}", p.signer))?
                .clone();
            keypairs.push(kp);
        }
        let signer_refs: Vec<&Keypair> = keypairs.iter().map(|k| k.as_ref()).collect();
        let tx = sign_settlement(message, &signer_refs)?;

        let signature = self.client.send_and_confirm_transaction(&tx).await?;
        Ok(SettleReceipt {
            epoch: batch.epoch,
            signature: signature.to_string(),
        })
    }
}

impl SettleSubmitter for RpcSettleSubmitter {
    /// Bridge the synchronous scheduler seam to the async crowd path. Must run
    /// inside a multi-thread Tokio runtime; production drivers should prefer
    /// [`RpcSettleSubmitter::submit_crowd`] (async) directly.
    fn submit_settle(&mut self, batch: &SettleBatch) -> Result<SettleReceipt> {
        let handle = tokio::runtime::Handle::try_current().context(
            "RpcSettleSubmitter::submit_settle must run inside a Tokio runtime; \
             prefer submit_crowd() from async code",
        )?;
        tokio::task::block_in_place(|| handle.block_on(self.submit_crowd(batch)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::MockSolanaClient;
    use crate::config::{FeePayer, TxProfile};
    use mirror_behaviors::PlainTransfer;
    use mirror_core::nullifier as derive_nullifier;
    use mirror_core::Secret;

    fn sink() -> Pubkey {
        Pubkey::new_from_array([0x55; 32])
    }

    fn ctx_with_alt() -> SettleContext {
        let program_id = Pubkey::new_from_array([0x11; 32]);
        let pool = Pubkey::new_from_array([0x22; 32]);
        let ctx0 = SettleContext {
            program_id,
            pool,
            alt: AddressLookupTableAccount {
                key: Pubkey::new_from_array([0xA1; 32]),
                addresses: Vec::new(),
            },
        };
        let addresses = plain_transfer_shared_accounts(&ctx0, &sink());
        SettleContext {
            alt: AddressLookupTableAccount {
                key: Pubkey::new_from_array([0xA1; 32]),
                addresses,
            },
            ..ctx0
        }
    }

    fn participants(n: usize, epoch: Epoch) -> Vec<SettleParticipant> {
        let behavior: Arc<dyn Behavior> = Arc::new(PlainTransfer::sol(sink(), SizeBucket::Small));
        (0..n)
            .map(|i| {
                let signer = Pubkey::new_from_array([0x30 + i as u8; 32]);
                let secret = Secret::from_bytes([0x80 + i as u8; 32]);
                SettleParticipant {
                    signer,
                    behavior: behavior.clone(),
                    size: SizeBucket::Small,
                    nullifier: derive_nullifier(&secret, epoch),
                }
            })
            .collect()
    }

    fn fee_payer() -> Pubkey {
        Pubkey::new_from_array([0x01; 32])
    }

    #[tokio::test]
    async fn instruction_order_is_cu_settle_then_behaviors() {
        let ctx = ctx_with_alt();
        let parts = participants(3, Epoch(4));
        // Build the raw instruction list the same way the message builder does,
        // so we can assert order before it is compiled away into indices.
        let mut instructions = Vec::new();
        instructions.extend(compute_budget_instructions(&TxProfile::default()));
        let nullifiers: Vec<Nullifier> = parts.iter().map(|p| p.nullifier).collect();
        instructions.push(settle_epoch_instruction(
            &ctx,
            Epoch(4),
            &fee_payer(),
            &nullifiers,
        ));
        for p in &parts {
            instructions.extend(
                p.behavior
                    .build_instructions(&p.signer, p.size)
                    .await
                    .unwrap(),
            );
        }

        assert_eq!(instructions.len(), 2 + 1 + 3, "2 CU + settle + 3 transfers");
        assert_eq!(instructions[0].program_id, COMPUTE_BUDGET_PROGRAM_ID);
        assert_eq!(instructions[1].program_id, COMPUTE_BUDGET_PROGRAM_ID);
        assert_eq!(instructions[2].program_id, ctx.program_id, "settle epoch");
        assert_eq!(
            instructions[2].data[0],
            mirror_core::wire::tag::SETTLE_EPOCH
        );
        for ix in &instructions[3..] {
            assert_eq!(
                ix.program_id,
                mirror_behaviors::programs::SYSTEM_PROGRAM_ID,
                "participant actions are System transfers"
            );
        }
    }

    #[tokio::test]
    async fn fee_payer_is_index_zero_and_participants_are_static_signers() {
        let ctx = ctx_with_alt();
        let parts = participants(4, Epoch(0));
        let message = build_crowd_message(CrowdSettleRequest {
            ctx: &ctx,
            epoch: Epoch(0),
            fee_payer: fee_payer(),
            participants: &parts,
            tx_profile: TxProfile::default(),
            recent_blockhash: Hash::new_from_array([9u8; 32]),
        })
        .await
        .unwrap();

        let keys = message.static_account_keys();
        // Fee payer is always static key 0.
        assert_eq!(
            keys[0],
            fee_payer(),
            "rotating fee-payer is the tx fee payer"
        );
        // N + 1 required signatures: fee-payer + 4 participants.
        assert_eq!(message.header().num_required_signatures, 5);

        // Every participant is present as a static (non-ALT) signer key.
        for p in &parts {
            let idx = keys
                .iter()
                .position(|k| *k == p.signer)
                .expect("participant signer must be a static key, never in the ALT");
            assert!(
                (idx as u8) < message.header().num_required_signatures,
                "participant must be within the signer prefix of the static keys"
            );
        }
    }

    #[tokio::test]
    async fn shared_accounts_load_from_alt_signers_do_not() {
        let ctx = ctx_with_alt();
        let parts = participants(4, Epoch(0));
        let message = build_crowd_message(CrowdSettleRequest {
            ctx: &ctx,
            epoch: Epoch(0),
            fee_payer: fee_payer(),
            participants: &parts,
            tx_profile: TxProfile::default(),
            recent_blockhash: Hash::new_from_array([9u8; 32]),
        })
        .await
        .unwrap();

        let VersionedMessage::V0(v0) = &message else {
            panic!("expected a v0 message");
        };
        // The shared sink and Pool PDA are loaded from the ALT, not static.
        assert_eq!(v0.address_table_lookups.len(), 1, "one pool ALT");
        let lookups = &v0.address_table_lookups[0];
        let loaded: Vec<u8> = lookups
            .writable_indexes
            .iter()
            .chain(lookups.readonly_indexes.iter())
            .copied()
            .collect();
        assert!(!loaded.is_empty(), "shared accounts must load from the ALT");

        let statics = message.static_account_keys();
        // Signers are never in the ALT; they are always static keys.
        assert!(statics.contains(&fee_payer()));
        for p in &parts {
            assert!(statics.contains(&p.signer));
        }
        // The invoked programs stay static (they cannot be loaded from a table).
        assert!(statics.contains(&ctx.program_id));
        assert!(statics.contains(&mirror_behaviors::programs::SYSTEM_PROGRAM_ID));
        assert!(statics.contains(&COMPUTE_BUDGET_PROGRAM_ID));
        // The shared sink is NOT a static key (it lives in the ALT).
        assert!(
            !statics.contains(&sink()),
            "shared sink must be loaded from the ALT, not a static key"
        );
    }

    #[tokio::test]
    async fn four_participants_fit_five_do_not() {
        let ctx = ctx_with_alt();

        let four = participants(PLAIN_TRANSFER_MAX_PER_TX, Epoch(0));
        let message = build_crowd_message(CrowdSettleRequest {
            ctx: &ctx,
            epoch: Epoch(0),
            fee_payer: fee_payer(),
            participants: &four,
            tx_profile: TxProfile::default(),
            recent_blockhash: Hash::new_from_array([9u8; 32]),
        })
        .await
        .expect("four participants fit one settlement tx");
        assert!(signed_transaction_len(&message) <= PACKET_DATA_SIZE);

        let five = participants(PLAIN_TRANSFER_MAX_PER_TX + 1, Epoch(0));
        let err = build_crowd_message(CrowdSettleRequest {
            ctx: &ctx,
            epoch: Epoch(0),
            fee_payer: fee_payer(),
            participants: &five,
            tx_profile: TxProfile::default(),
            recent_blockhash: Hash::new_from_array([9u8; 32]),
        })
        .await
        .expect_err("five participants must overflow the packet limit");
        assert!(err.to_string().contains("packet limit"), "{err}");
    }

    #[test]
    fn plan_settlements_chunks_and_preserves_all_participants() {
        let parts = participants(10, Epoch(0));
        let chunks = plan_settlements(&parts, PLAIN_TRANSFER_MAX_PER_TX);
        assert_eq!(chunks.len(), 3, "10 / 4 -> 4 + 4 + 2");
        let total: usize = chunks.iter().map(|c| c.len()).sum();
        assert_eq!(total, parts.len(), "no participant dropped when chunking");
        // Nullifier subsets are disjoint and their union is the whole epoch.
        let mut seen = std::collections::HashSet::new();
        for c in &chunks {
            for p in *c {
                assert!(seen.insert(p.nullifier), "nullifiers must not repeat");
            }
        }
        assert_eq!(seen.len(), parts.len());
    }

    #[tokio::test]
    async fn submitter_builds_signs_and_sends_via_client() {
        // End-to-end crowd submission with no validator: real message build +
        // real signing + a recording mock client.
        let ctx = ctx_with_alt();
        let epoch = Epoch(0);

        // Three participant keypairs, and derive their nullifiers from the same
        // secrets so the roster and the batch agree.
        let mut roster = Vec::new();
        let mut keypairs = Vec::new();
        let behavior: Arc<dyn Behavior> = Arc::new(PlainTransfer::sol(sink(), SizeBucket::Small));
        for i in 0..3u8 {
            let kp = Arc::new(Keypair::new());
            let secret = Secret::from_bytes([0x90 + i; 32]);
            roster.push(SettleParticipant {
                signer: kp.pubkey(),
                behavior: behavior.clone(),
                size: SizeBucket::Small,
                nullifier: derive_nullifier(&secret, epoch),
            });
            keypairs.push(kp);
        }
        let nullifiers: Vec<Nullifier> = roster.iter().map(|p| p.nullifier).collect();

        let fee_kp = Arc::new(Keypair::new());
        let client = Arc::new(MockSolanaClient::new());
        let mut submitter = RpcSettleSubmitter::new(client.clone(), ctx);
        submitter.register_epoch(epoch, roster.clone());
        submitter.register_signer(fee_kp.clone());
        for kp in &keypairs {
            submitter.register_signer(kp.clone());
        }

        let batch = SettleBatch {
            epoch,
            nullifiers,
            fee_payer: FeePayer(fee_kp.pubkey().to_bytes()),
            tx_profile: TxProfile::default(),
        };

        let receipt = submitter.submit_crowd(&batch).await.expect("crowd submit");
        assert_eq!(receipt.epoch, epoch);
        assert_eq!(client.sent_count(), 1, "exactly one settlement tx sent");

        // The sent transaction carries N + 1 signatures (fee-payer + 3).
        let sent = client.sent.lock().unwrap();
        assert_eq!(sent[0].signatures.len(), 4);
    }
}
