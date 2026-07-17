//! [`JupiterSwap`] - pooled swap built on the public Jupiter v6 API.
//!
//! Every participant swaps the same mint pair at the same bucketed amount, so
//! all N swaps are identical in mints and size. The route itself is chosen by
//! Jupiter per participant; the coordinator is responsible for normalizing the
//! remaining tx-level shape (compute budget, priority fee, ALTs) pool-wide, so
//! this builder deliberately drops the per-participant `computeBudgetInstructions`
//! Jupiter returns (they are a wallet fingerprint) and emits only the
//! setup / swap / cleanup instructions.
//!
//! Network is confined to [`JupiterSwap::build_instructions`]. Everything else -
//! request URL, request body, response parsing - is a pure function unit-tested
//! against a recorded fixture, so `cargo test` never touches the network. The
//! one live call is an `#[ignore]`d integration test gated on `MIRROR_JUP_LIVE`.

use crate::{bucket_base_units, Behavior};
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use mirror_core::{ActionClass, SizeBucket};
use serde::Deserialize;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use std::str::FromStr;

/// Default public Jupiter v6 quote/swap base URL.
pub const DEFAULT_JUPITER_BASE_URL: &str = "https://quote-api.jup.ag/v6";

/// A pooled Jupiter swap: fixed mint pair + fixed bucketed input amount.
#[derive(Clone, Debug)]
pub struct JupiterSwap {
    pub mint_in: Pubkey,
    pub mint_out: Pubkey,
    /// Decimals of `mint_in`; the input amount is `bucket_base_units(size,
    /// decimals_in)`, so every participant sends the identical amount.
    pub decimals_in: u8,
    pub size: SizeBucket,
    /// Slippage tolerance in basis points passed to the quote endpoint.
    pub slippage_bps: u16,
    /// Quote/swap API base URL (override for a proxy or a pinned host).
    pub base_url: String,
}

impl JupiterSwap {
    pub fn new(mint_in: Pubkey, mint_out: Pubkey, decimals_in: u8, size: SizeBucket) -> Self {
        Self {
            mint_in,
            mint_out,
            decimals_in,
            size,
            slippage_bps: 50,
            base_url: DEFAULT_JUPITER_BASE_URL.to_string(),
        }
    }

    /// The fixed input amount, in `mint_in` base units, for `size`.
    pub fn input_amount(&self, size: SizeBucket) -> u64 {
        bucket_base_units(size, self.decimals_in)
    }

    /// Build the `GET /quote` URL for `amount` base units of `mint_in`.
    pub fn quote_url(&self, amount: u64) -> String {
        format!(
            "{}/quote?inputMint={}&outputMint={}&amount={}&slippageBps={}&swapMode=ExactIn",
            self.base_url.trim_end_matches('/'),
            self.mint_in,
            self.mint_out,
            amount,
            self.slippage_bps
        )
    }

    /// Build the `POST /swap-instructions` request body. `quote` is the verbatim
    /// JSON object returned by `/quote`.
    pub fn swap_request_body(
        &self,
        quote: &serde_json::Value,
        participant: &Pubkey,
    ) -> serde_json::Value {
        serde_json::json!({
            "userPublicKey": participant.to_string(),
            "quoteResponse": quote,
            // The coordinator normalizes compute budget pool-wide; do not let
            // Jupiter attach a per-participant priority fee.
            "prioritizationFeeLamports": 0,
            "wrapAndUnwrapSol": true,
            "useSharedAccounts": true,
        })
    }

    async fn fetch_quote(
        &self,
        client: &reqwest::Client,
        amount: u64,
    ) -> Result<serde_json::Value> {
        let url = self.quote_url(amount);
        let resp = client
            .get(&url)
            .send()
            .await
            .context("jupiter /quote request failed")?
            .error_for_status()
            .context("jupiter /quote returned an error status")?;
        resp.json::<serde_json::Value>()
            .await
            .context("jupiter /quote returned non-JSON")
    }

    async fn fetch_swap_instructions(
        &self,
        client: &reqwest::Client,
        quote: &serde_json::Value,
        participant: &Pubkey,
    ) -> Result<SwapInstructionsResponse> {
        let body = self.swap_request_body(quote, participant);
        let resp = client
            .post(format!(
                "{}/swap-instructions",
                self.base_url.trim_end_matches('/')
            ))
            .json(&body)
            .send()
            .await
            .context("jupiter /swap-instructions request failed")?
            .error_for_status()
            .context("jupiter /swap-instructions returned an error status")?;
        resp.json::<SwapInstructionsResponse>()
            .await
            .context("jupiter /swap-instructions returned an unexpected shape")
    }
}

#[async_trait]
impl Behavior for JupiterSwap {
    fn action_class(&self) -> ActionClass {
        ActionClass::Swap {
            mint_in: self.mint_in.to_bytes(),
            mint_out: self.mint_out.to_bytes(),
            size: self.size,
        }
    }

    fn describe(&self) -> String {
        format!(
            "JupiterSwap: {} base units of {} -> {} (bucket {:?}, {} bps slippage)",
            self.input_amount(self.size),
            self.mint_in,
            self.mint_out,
            self.size,
            self.slippage_bps
        )
    }

    async fn build_instructions(
        &self,
        participant: &Pubkey,
        size: SizeBucket,
    ) -> Result<Vec<Instruction>> {
        let client = reqwest::Client::new();
        let amount = self.input_amount(size);
        let quote = self.fetch_quote(&client, amount).await?;
        let resp = self
            .fetch_swap_instructions(&client, &quote, participant)
            .await?;
        resp.into_instructions()
    }
}

// ---- Wire DTOs for the /swap-instructions response --------------------------

#[derive(Debug, Deserialize)]
struct JupAccountMeta {
    pubkey: String,
    #[serde(rename = "isSigner")]
    is_signer: bool,
    #[serde(rename = "isWritable")]
    is_writable: bool,
}

#[derive(Debug, Deserialize)]
struct JupInstruction {
    #[serde(rename = "programId")]
    program_id: String,
    accounts: Vec<JupAccountMeta>,
    /// base64-encoded instruction data.
    data: String,
}

impl JupInstruction {
    fn into_instruction(self) -> Result<Instruction> {
        let program_id = Pubkey::from_str(&self.program_id)
            .map_err(|e| anyhow!("bad programId {}: {e}", self.program_id))?;
        let accounts = self
            .accounts
            .into_iter()
            .map(|a| {
                let pk = Pubkey::from_str(&a.pubkey)
                    .map_err(|e| anyhow!("bad account pubkey {}: {e}", a.pubkey))?;
                Ok(if a.is_writable {
                    AccountMeta::new(pk, a.is_signer)
                } else {
                    AccountMeta::new_readonly(pk, a.is_signer)
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let data = B64
            .decode(self.data.as_bytes())
            .context("instruction data is not valid base64")?;
        Ok(Instruction {
            program_id,
            accounts,
            data,
        })
    }
}

/// The subset of the Jupiter `/swap-instructions` response this crate consumes.
///
/// `computeBudgetInstructions` is intentionally NOT parsed into the output: the
/// coordinator sets one pool-wide compute budget, so per-participant CU/priority
/// settings must never leak through this builder.
#[derive(Debug, Deserialize)]
pub struct SwapInstructionsResponse {
    #[serde(rename = "setupInstructions", default)]
    setup_instructions: Vec<JupInstruction>,
    #[serde(rename = "swapInstruction")]
    swap_instruction: JupInstruction,
    #[serde(rename = "cleanupInstruction", default)]
    cleanup_instruction: Option<JupInstruction>,
    /// ALTs the coordinator must load to keep the composed tx under 1232 bytes.
    #[serde(rename = "addressLookupTableAddresses", default)]
    pub address_lookup_table_addresses: Vec<String>,
}

impl SwapInstructionsResponse {
    /// Parse a `/swap-instructions` JSON body.
    pub fn from_json(s: &str) -> Result<Self> {
        serde_json::from_str(s).context("failed to parse /swap-instructions response")
    }

    /// Convert to the ordered instruction list to compose: setup, then swap,
    /// then cleanup. Compute-budget instructions are dropped by design.
    pub fn into_instructions(self) -> Result<Vec<Instruction>> {
        let mut out = Vec::new();
        for s in self.setup_instructions {
            out.push(s.into_instruction()?);
        }
        out.push(self.swap_instruction.into_instruction()?);
        if let Some(c) = self.cleanup_instruction {
            out.push(c.into_instruction()?);
        }
        Ok(out)
    }

    /// Parse the ALT addresses the coordinator should load.
    pub fn lookup_tables(&self) -> Result<Vec<Pubkey>> {
        self.address_lookup_table_addresses
            .iter()
            .map(|s| Pubkey::from_str(s).map_err(|e| anyhow!("bad ALT address {s}: {e}")))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A recorded /swap-instructions body: one setup ix (ATA create), the swap
    // ix, one cleanup ix (close wSOL), a compute-budget ix that must be dropped,
    // and one ALT. All pubkeys are valid base58; all data is valid base64.
    const FIXTURE: &str = r#"{
      "computeBudgetInstructions": [
        {"programId":"ComputeBudget111111111111111111111111111111","accounts":[],"data":"AsBcFQA="}
      ],
      "setupInstructions": [
        {"programId":"ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL",
         "accounts":[
           {"pubkey":"So11111111111111111111111111111111111111112","isSigner":false,"isWritable":false}
         ],
         "data":"AQ=="}
      ],
      "swapInstruction": {
        "programId":"JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4",
        "accounts":[
          {"pubkey":"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA","isSigner":false,"isWritable":false},
          {"pubkey":"So11111111111111111111111111111111111111112","isSigner":false,"isWritable":true},
          {"pubkey":"11111111111111111111111111111111","isSigner":true,"isWritable":true}
        ],
        "data":"AQIDBAUGBwg="
      },
      "cleanupInstruction": {
        "programId":"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
        "accounts":[
          {"pubkey":"So11111111111111111111111111111111111111112","isSigner":false,"isWritable":true}
        ],
        "data":"CQ=="
      },
      "addressLookupTableAddresses":["SysvarC1ock11111111111111111111111111111111"]
    }"#;

    fn swap() -> JupiterSwap {
        JupiterSwap::new(
            Pubkey::from_str("So11111111111111111111111111111111111111112").unwrap(),
            Pubkey::from_str("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v").unwrap(),
            9,
            SizeBucket::Small,
        )
    }

    #[test]
    fn quote_url_carries_the_bucketed_amount_and_pair() {
        let s = swap();
        let amount = s.input_amount(SizeBucket::Small);
        let url = s.quote_url(amount);
        assert!(url.starts_with("https://quote-api.jup.ag/v6/quote?"));
        assert!(url.contains("inputMint=So11111111111111111111111111111111111111112"));
        assert!(url.contains("outputMint=EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"));
        assert!(url.contains(&format!("amount={amount}")));
        assert!(url.contains("slippageBps=50"));
        assert!(url.contains("swapMode=ExactIn"));
    }

    #[test]
    fn swap_request_body_pins_participant_and_zeroes_priority_fee() {
        let s = swap();
        let participant = Pubkey::from_str("11111111111111111111111111111111").unwrap();
        let quote = serde_json::json!({"outAmount": "123", "routePlan": []});
        let body = s.swap_request_body(&quote, &participant);
        assert_eq!(body["userPublicKey"], participant.to_string());
        assert_eq!(body["quoteResponse"], quote);
        assert_eq!(body["prioritizationFeeLamports"], 0);
        assert_eq!(body["wrapAndUnwrapSol"], true);
    }

    #[test]
    fn parses_fixture_into_ordered_instructions_dropping_compute_budget() {
        let resp = SwapInstructionsResponse::from_json(FIXTURE).unwrap();
        let alts = resp.lookup_tables().unwrap();
        let ixs = resp.into_instructions().unwrap();

        // setup + swap + cleanup == 3; compute-budget dropped.
        assert_eq!(ixs.len(), 3);

        // [0] setup: ATA program.
        assert_eq!(
            ixs[0].program_id,
            Pubkey::from_str("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL").unwrap()
        );
        // [1] swap: Jupiter program, 3 accounts, data decodes to 1..=8.
        assert_eq!(
            ixs[1].program_id,
            Pubkey::from_str("JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4").unwrap()
        );
        assert_eq!(ixs[1].accounts.len(), 3);
        assert!(ixs[1].accounts[2].is_signer && ixs[1].accounts[2].is_writable);
        assert!(!ixs[1].accounts[0].is_writable);
        assert_eq!(ixs[1].data, vec![1, 2, 3, 4, 5, 6, 7, 8]);
        // [2] cleanup: token program, data == [9].
        assert_eq!(
            ixs[2].program_id,
            Pubkey::from_str("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").unwrap()
        );
        assert_eq!(ixs[2].data, vec![9]);

        // ALT parsed.
        assert_eq!(alts.len(), 1);
        assert_eq!(
            alts[0],
            Pubkey::from_str("SysvarC1ock11111111111111111111111111111111").unwrap()
        );
    }

    #[test]
    fn rejects_bad_base64_data() {
        let bad = r#"{
          "swapInstruction":{"programId":"11111111111111111111111111111111","accounts":[],"data":"!!!not-base64"}
        }"#;
        let resp = SwapInstructionsResponse::from_json(bad).unwrap();
        assert!(resp.into_instructions().is_err());
    }

    #[test]
    fn action_class_reflects_the_fixed_pair_and_bucket() {
        let s = swap();
        assert_eq!(
            s.action_class(),
            ActionClass::Swap {
                mint_in: s.mint_in.to_bytes(),
                mint_out: s.mint_out.to_bytes(),
                size: SizeBucket::Small,
            }
        );
    }

    // Live integration: hits the real Jupiter API. Ignored by default; run with
    //   MIRROR_JUP_LIVE=1 cargo test -p mirror-behaviors -- --ignored jupiter_live
    #[tokio::test]
    #[ignore = "network: set MIRROR_JUP_LIVE=1 to run against the live Jupiter API"]
    async fn jupiter_live_build_instructions() {
        if std::env::var("MIRROR_JUP_LIVE").is_err() {
            eprintln!("skipping: MIRROR_JUP_LIVE not set");
            return;
        }
        // wSOL -> USDC, a tiny bucketed amount.
        let s = swap();
        let participant = Pubkey::from_str("So11111111111111111111111111111111111111112").unwrap();
        let ixs = s
            .build_instructions(&participant, SizeBucket::Nano)
            .await
            .expect("live jupiter swap instructions");
        assert!(!ixs.is_empty(), "expected at least the swap instruction");
    }
}
