//! The gasless confidential submit path: build, sign, and send one `Transact`.
//!
//! This is the value-carrying counterpart to the crowd path ([`crate::crowd`]).
//! The CLI (`mirror-cli shield|transfer|unshield`) proves a JoinSplit off-chain
//! and EMITS the Transact instruction data + account list; this module turns that
//! emit into a submitted transaction through the same [`SolanaClient`] boundary
//! the crowd path uses, so it is fully mockable without a validator.
//!
//! ## Who signs
//!
//! Every Transact requires the ValuePool **authority** (the relay) to sign, and
//! that authority is also the transaction fee payer (index 0). The relay is the
//! rotating gasless submitter:
//!
//! - **transfer / unshield** (`publicAmount <= 0`): the relay is the ONLY signer.
//!   The user provides no signature - that is the unlinkability.
//! - **shield** (`publicAmount = +v`): the depositor must additionally co-sign to
//!   authorize + fund the deposit, so it is passed in `extra_signers`. (Shield is
//!   "not gasless" in that the depositor actively authorizes its own deposit.)
//!
//! The normalized [`TxProfile`] (compute-unit limit + priority fee) is applied to
//! every Transact, exactly like the crowd path, so all settlements share one
//! compute fingerprint.

use anyhow::{Context, Result};
use solana_hash::Hash;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_message::{v0, VersionedMessage};
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;

use crate::client::SolanaClient;
use crate::config::TxProfile;
use crate::crowd::compute_budget_instructions;

/// One confidential `Transact` to submit: the emitted instruction data + accounts
/// plus the pool-wide normalized tx shape.
#[derive(Debug)]
pub struct ValueTransactRequest {
    /// The mirror-pool program id.
    pub program_id: Pubkey,
    /// The full Transact instruction data (tag + body), as emitted by the CLI.
    pub transact_data: Vec<u8>,
    /// The Transact account list, in the program's fixed order (see
    /// `instructions::transact`): vpool, authority, nf0, nf1, recipient, depositor,
    /// system, clock, vault.
    pub accounts: Vec<AccountMeta>,
    /// Normalized CU limit + priority fee (the only compute-budget source).
    pub tx_profile: TxProfile,
}

impl ValueTransactRequest {
    /// The mirror-pool `Transact` instruction.
    pub fn instruction(&self) -> Instruction {
        Instruction {
            program_id: self.program_id,
            accounts: self.accounts.clone(),
            data: self.transact_data.clone(),
        }
    }
}

/// Build the v0 message for a Transact: normalized ComputeBudget (limit + price)
/// then the `Transact` instruction, with `fee_payer` (the relay authority) as the
/// transaction fee payer. No Address Lookup Table: a Transact's accounts are
/// per-settlement (the two nullifier PDAs change every time), so they stay static.
pub fn build_transact_message(
    fee_payer: &Pubkey,
    req: &ValueTransactRequest,
    recent_blockhash: Hash,
) -> Result<VersionedMessage> {
    let mut instructions = Vec::with_capacity(3);
    instructions.extend(compute_budget_instructions(&req.tx_profile));
    instructions.push(req.instruction());
    let message = v0::Message::try_compile(fee_payer, &instructions, &[], recent_blockhash)
        .context("compile transact message")?;
    Ok(VersionedMessage::V0(message))
}

/// Build + sign + send one confidential Transact through the gasless relay.
///
/// `relay` is the rotating fee payer AND the ValuePool authority (the Transact's
/// account index 1 must equal `relay.pubkey()`). `extra_signers` co-sign: empty
/// for transfer/unshield (relay-only), the depositor for a shield. Duplicate
/// signers (e.g. a depositor equal to the relay) are de-duplicated.
pub async fn submit_transact(
    client: &dyn SolanaClient,
    relay: &Keypair,
    req: &ValueTransactRequest,
    extra_signers: &[&Keypair],
) -> Result<Signature> {
    let blockhash = client.get_latest_blockhash().await?;
    let message = build_transact_message(&relay.pubkey(), req, blockhash)?;

    // The relay signs first (fee payer + authority), then any extra co-signers.
    let mut signers: Vec<&Keypair> = Vec::with_capacity(1 + extra_signers.len());
    signers.push(relay);
    for s in extra_signers {
        if !signers.iter().any(|k| k.pubkey() == s.pubkey()) {
            signers.push(s);
        }
    }
    let signer_refs: Vec<&dyn Signer> = signers.iter().map(|k| *k as &dyn Signer).collect();
    let tx = VersionedTransaction::try_new(message, signer_refs.as_slice())
        .context("sign transact transaction")?;

    client.send_and_confirm_transaction(&tx).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::MockSolanaClient;
    use mirror_core::wire;

    const CLOCK_SYSVAR_ID: Pubkey =
        Pubkey::from_str_const("SysvarC1ock11111111111111111111111111111111");
    const SYSTEM_PROGRAM_ID: Pubkey = Pubkey::from_str_const("11111111111111111111111111111111");
    const COMPUTE_BUDGET_PROGRAM_ID: Pubkey =
        Pubkey::from_str_const("ComputeBudget111111111111111111111111111111");

    fn program_id() -> Pubkey {
        Pubkey::new_from_array([0x11; 32])
    }
    fn vpool() -> Pubkey {
        Pubkey::new_from_array([0x22; 32])
    }
    fn vault() -> Pubkey {
        Pubkey::new_from_array([0x88; 32])
    }

    /// A minimal well-formed Transact body (correct length, contents irrelevant to
    /// message composition, which never inspects the bytes).
    fn dummy_transact_data() -> Vec<u8> {
        let mut d = vec![wire::tag::TRANSACT];
        d.extend(std::iter::repeat_n(0u8, wire::TRANSACT_HEADER_LEN));
        d.extend_from_slice(&0u16.to_le_bytes()); // enc0 empty
        d.extend_from_slice(&0u16.to_le_bytes()); // enc1 empty
        d
    }

    /// The Transact account list in program order. For transfer/unshield the
    /// depositor slot is the authority (non-signer); for shield it is a distinct
    /// signing depositor.
    fn accounts(authority: Pubkey, depositor: Pubkey, depositor_signs: bool) -> Vec<AccountMeta> {
        vec![
            AccountMeta::new(vpool(), false),
            AccountMeta::new(authority, true),
            AccountMeta::new(Pubkey::new_from_array([0x31; 32]), false), // nf0
            AccountMeta::new(Pubkey::new_from_array([0x32; 32]), false), // nf1
            AccountMeta::new(authority, false),                          // recipient placeholder
            AccountMeta::new(depositor, depositor_signs),                // depositor
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
            AccountMeta::new_readonly(CLOCK_SYSVAR_ID, false),
            AccountMeta::new(vault(), false),
        ]
    }

    fn request(
        authority: Pubkey,
        depositor: Pubkey,
        depositor_signs: bool,
    ) -> ValueTransactRequest {
        ValueTransactRequest {
            program_id: program_id(),
            transact_data: dummy_transact_data(),
            accounts: accounts(authority, depositor, depositor_signs),
            tx_profile: TxProfile::default(),
        }
    }

    /// Program ids of a compiled v0 message's instructions, in order.
    fn instruction_program_ids(message: &VersionedMessage) -> Vec<Pubkey> {
        let VersionedMessage::V0(v0) = message else {
            panic!("expected a v0 message");
        };
        v0.instructions
            .iter()
            .map(|ci| v0.account_keys[ci.program_id_index as usize])
            .collect()
    }

    #[test]
    fn message_is_cu_limit_price_then_transact_paid_by_relay() {
        let relay = Keypair::new();
        let req = request(relay.pubkey(), relay.pubkey(), false);
        let message =
            build_transact_message(&relay.pubkey(), &req, Hash::new_from_array([7u8; 32])).unwrap();

        // Fee payer is always static key 0 (the relay authority).
        assert_eq!(message.static_account_keys()[0], relay.pubkey());

        // Instruction order: ComputeBudget limit, ComputeBudget price, then Transact.
        let progs = instruction_program_ids(&message);
        assert_eq!(progs.len(), 3, "2 ComputeBudget + 1 Transact");
        assert_eq!(progs[0], COMPUTE_BUDGET_PROGRAM_ID);
        assert_eq!(progs[1], COMPUTE_BUDGET_PROGRAM_ID);
        assert_eq!(
            progs[2],
            program_id(),
            "the third instruction is the Transact"
        );

        // The Transact instruction carries the emitted data + all 9 accounts.
        let VersionedMessage::V0(v0) = &message else {
            panic!("expected v0");
        };
        assert_eq!(v0.instructions[2].data[0], wire::tag::TRANSACT);
        assert_eq!(v0.instructions[2].accounts.len(), 9);
    }

    #[tokio::test]
    async fn transfer_is_relay_only_signed() {
        // transfer/unshield: the depositor slot is the authority (non-signer), so
        // the relay is the ONLY required signature (gasless; no user signature).
        let relay = Keypair::new();
        let req = request(relay.pubkey(), relay.pubkey(), false);
        let message =
            build_transact_message(&relay.pubkey(), &req, Hash::new_from_array([9u8; 32])).unwrap();
        assert_eq!(
            message.header().num_required_signatures,
            1,
            "transfer/unshield needs only the relay signature"
        );

        let client = MockSolanaClient::new();
        submit_transact(&client, &relay, &req, &[])
            .await
            .expect("relay-only submit");
        assert_eq!(client.sent_count(), 1, "exactly one Transact submitted");
        let sent = client.sent.lock().unwrap();
        assert_eq!(sent[0].signatures.len(), 1, "one signature (the relay)");
    }

    #[tokio::test]
    async fn shield_is_co_signed_by_relay_and_depositor() {
        // shield: a distinct depositor co-signs (authorizes + funds the deposit),
        // so the transaction carries two signatures (relay authority + depositor).
        let relay = Keypair::new();
        let depositor = Keypair::new();
        let req = request(relay.pubkey(), depositor.pubkey(), true);
        let message =
            build_transact_message(&relay.pubkey(), &req, Hash::new_from_array([5u8; 32])).unwrap();
        assert_eq!(
            message.header().num_required_signatures,
            2,
            "shield needs the relay + the depositor"
        );

        let client = MockSolanaClient::new();
        submit_transact(&client, &relay, &req, &[&depositor])
            .await
            .expect("shield co-signed submit");
        let sent = client.sent.lock().unwrap();
        assert_eq!(sent[0].signatures.len(), 2, "relay + depositor signatures");
    }

    #[test]
    fn authority_must_be_the_relay_at_account_index_one() {
        // The account list's index 1 (authority) must equal the relay fee payer, or
        // the on-chain Unauthorized check rejects the Transact.
        let relay = Keypair::new();
        let req = request(relay.pubkey(), relay.pubkey(), false);
        assert_eq!(
            req.accounts[1].pubkey,
            relay.pubkey(),
            "account 1 (authority) must be the relay"
        );
        assert!(req.accounts[1].is_signer && req.accounts[1].is_writable);
    }
}
