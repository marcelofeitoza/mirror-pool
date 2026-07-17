//! Pooled-action adapters for mirror-pool.
//!
//! This crate is v1 deliverable 4 in `docs/ROADMAP.md`: a [`Behavior`] trait
//! plus adapters that make every participant in an epoch perform an
//! *identical* action. Uniformity is the whole point:
//!
//! - **Fixed action shape.** One anonymity set exists per
//!   [`mirror_core::ActionClass`]. If two participants in the same pool
//!   emitted observably different instructions (different mint pair, route
//!   depth, account count, or amount), an observer could cluster by shape and
//!   the set would fracture, exactly like mixed denominations in Tornado.
//!   A `Behavior` therefore pins its `ActionClass` at construction and every
//!   settlement instruction it builds must be byte-shape-identical across
//!   participants (only the nullifier list varies).
//! - **Shared-epoch batching.** Settlement bytes are built for a whole
//!   [`mirror_core::Epoch`] at once, so all actions land on one timestamp and
//!   FIFO temporal matching (the strongest empirical attack, up to 49%
//!   linkage) collapses to the 1/k random baseline.
//! - **k_floor.** Builders take the epoch's nullifier set as a slice so the
//!   coordinator can refuse to build anything until
//!   `KAnon::real_k >= EpochSchedule::k_floor`. A behavior never executes into
//!   a set small enough to deanonymize by elimination.
//! - **Gasless rotating relay.** The bytes produced here are instruction
//!   *data* only. Fee-payer selection, CU limit, priority fee, tx version,
//!   account ordering, and ALT normalization all belong to the coordinator
//!   (v1 deliverable 3), so no acting wallet funds or signs its own execution
//!   and the ~37% wallet-fingerprint attack finds one pool-wide shape.
//!
//! v1 ships the trait and two stub adapters that emit the `SETTLE_EPOCH` wire
//! shape from [`mirror_core::wire`]. The inner CPI payloads (Jupiter route,
//! stake-pool deposit) land in the milestones noted on each adapter.

use anyhow::{bail, Result};
use mirror_core::{wire, ActionClass, Epoch, Hash32, Nullifier, SizeBucket};
use std::collections::HashMap;

/// A pooled action every participant in an epoch performs identically.
///
/// Implementations must be `Send + Sync` so the coordinator can hold a
/// registry of them across its scheduler threads.
pub trait Behavior: Send + Sync {
    /// The fixed action shape this behavior settles. All commitments in the
    /// pool bind to this exact class via
    /// [`mirror_core::commit`], so a relayer cannot substitute a different
    /// action at settlement without invalidating every commitment.
    fn action_class(&self) -> ActionClass;

    /// Build the instruction data for settling `epoch` with the given
    /// nullifier set.
    ///
    /// v1 stub: returns the `SETTLE_EPOCH` wire bytes
    /// (`[tag(1)][epoch(8)][n_nullifiers(4)][n * 32]`) that the on-chain
    /// program parses. The behavior-specific execution payload (swap route,
    /// stake deposit) is appended in later milestones; its shape must stay
    /// constant across participants so settlement stays uniform.
    ///
    /// Callers pass the *entire* epoch's nullifiers: the whole epoch settles
    /// atomically in one instruction (N-party atomicity beyond Jito's 5-tx
    /// bundle cap must live program-side).
    fn build_settlement_ix(&self, epoch: Epoch, nullifiers: &[Nullifier]) -> Result<Vec<u8>>;

    /// Human-readable description, used by the CLI `status` output and the
    /// harness reports.
    fn describe(&self) -> &str;
}

/// Encode the `SETTLE_EPOCH` wire bytes shared by every behavior.
///
/// Kept as one helper so no adapter can drift from
/// [`mirror_core::wire::SETTLE_HEADER_LEN`]; shape drift between two adapters
/// would itself be a fingerprint.
fn settle_epoch_wire_bytes(epoch: Epoch, nullifiers: &[Nullifier]) -> Result<Vec<u8>> {
    if nullifiers.is_empty() {
        // An empty settlement is always a coordinator bug: the k_floor check
        // must have rolled the epoch forward long before byte-building.
        bail!("refusing to build a settlement for an empty nullifier set");
    }
    let n: u32 = nullifiers
        .len()
        .try_into()
        .map_err(|_| anyhow::anyhow!("nullifier count exceeds u32"))?;
    let mut data = Vec::with_capacity(wire::SETTLE_HEADER_LEN + nullifiers.len() * 32);
    data.push(wire::tag::SETTLE_EPOCH);
    data.extend_from_slice(&epoch.0.to_le_bytes());
    data.extend_from_slice(&n.to_le_bytes());
    for nf in nullifiers {
        data.extend_from_slice(&nf.0);
    }
    debug_assert_eq!(data.len(), wire::SETTLE_HEADER_LEN + nullifiers.len() * 32);
    Ok(data)
}

/// Pooled Jupiter swap: every participant swaps the same mint pair at the
/// same [`SizeBucket`].
///
/// Built fresh in this crate against the public Jupiter v6 quote + swap API
/// (quote fetch, route selection, and swap-instruction construction). The
/// account list and route depth must be normalized pool-wide, because a
/// per-participant route choice is an instant fingerprint.
///
/// Mints are stored as opaque 32-byte values supplied at pool init; this
/// crate never hardcodes a mainnet mint or program id.
#[derive(Clone, Copy, Debug)]
pub struct JupiterSwap {
    /// Input mint (32 raw bytes of the mint address, supplied by pool init).
    pub mint_in: Hash32,
    /// Output mint.
    pub mint_out: Hash32,
    /// The fixed size bucket; variable and round-number amounts leak a large
    /// fraction of anonymity to amount-matching alone (Wang et al.,
    /// arXiv:2201.09035; the Tornado study, arXiv:2510.09433), while
    /// fixed/stratified denominations sharply reduce it, so the bucket is
    /// mandatory.
    pub size: SizeBucket,
}

impl Behavior for JupiterSwap {
    fn action_class(&self) -> ActionClass {
        ActionClass::Swap {
            mint_in: self.mint_in,
            mint_out: self.mint_out,
            size: self.size,
        }
    }

    fn build_settlement_ix(&self, epoch: Epoch, nullifiers: &[Nullifier]) -> Result<Vec<u8>> {
        // TODO(v1 deliverable 4, docs/ROADMAP.md): append the uniform Jupiter
        // swap payload after the settle header (technique: the public Jupiter
        // v6 quote + swap API, quote fetch + route selection + swap-ix
        // construction, built fresh), pinning one route shape per pool per
        // epoch so every participant's execution is byte-shape-identical.
        // Output lands in a public ATA; the ATA re-link vector must be
        // documented alongside.
        settle_epoch_wire_bytes(epoch, nullifiers)
    }

    fn describe(&self) -> &str {
        "Pooled Jupiter swap (fixed mint pair + size bucket); execution payload built fresh on the public jupiter v6 swap API"
    }
}

/// Pooled jitoSOL stake: every participant stakes the same size bucket to the
/// same validator/stake-pool target.
///
/// Built fresh against the public Jito stake-pool program (an SPL stake-pool
/// deposit): the SOL to jitoSOL stake-pool deposit whose account meta list is
/// fixed, which makes it a naturally uniform pooled action.
#[derive(Clone, Copy, Debug)]
pub struct JitoSolStake {
    /// Stake target identity (32 raw bytes, supplied by pool init; never a
    /// hardcoded mainnet address).
    pub validator: Hash32,
    /// The fixed size bucket shared by the whole pool.
    pub size: SizeBucket,
}

impl Behavior for JitoSolStake {
    fn action_class(&self) -> ActionClass {
        ActionClass::Stake {
            validator: self.validator,
            size: self.size,
        }
    }

    fn build_settlement_ix(&self, epoch: Epoch, nullifiers: &[Nullifier]) -> Result<Vec<u8>> {
        // TODO(v1 deliverable 4, docs/ROADMAP.md): append the uniform
        // stake-pool deposit payload after the settle header (technique: the
        // public Jito stake-pool program, an SPL stake-pool deposit, built
        // fresh). One deposit shape per pool; only the nullifier list may vary.
        settle_epoch_wire_bytes(epoch, nullifiers)
    }

    fn describe(&self) -> &str {
        "Pooled jitoSOL stake (fixed validator + size bucket); execution payload built fresh on the public Jito stake-pool program"
    }
}

/// Name-keyed registry of pooled behaviors.
///
/// The coordinator resolves a pool's configured behavior by name at startup;
/// the CLI uses the same names in `commit --behavior <name>`. Keeping one
/// registry keeps the set of deployable action shapes explicit and auditable,
/// so nobody quietly adds a heterogeneous action to a live pool.
#[derive(Default)]
pub struct BehaviorRegistry {
    entries: HashMap<String, Box<dyn Behavior>>,
}

impl BehaviorRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `behavior` under `name`, replacing any previous entry with
    /// the same name.
    pub fn register(&mut self, name: impl Into<String>, behavior: Box<dyn Behavior>) {
        self.entries.insert(name.into(), behavior);
    }

    pub fn get(&self, name: &str) -> Option<&dyn Behavior> {
        self.entries.get(name).map(|b| b.as_ref())
    }

    /// Registered names, sorted for stable CLI/help output.
    pub fn names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.entries.keys().map(String::as_str).collect();
        names.sort_unstable();
        names
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test-local inverse of `ActionClass::canonical_bytes`. mirror-core
    /// deliberately exposes only the encoder (the chain never needs to decode
    /// a class back out of a commitment pre-image), so the round-trip decoder
    /// lives here to prove the encoding is unambiguous per class.
    fn decode_action_class(bytes: &[u8]) -> ActionClass {
        fn bucket(raw: u8) -> SizeBucket {
            *SizeBucket::ALL
                .iter()
                .find(|b| **b as u8 == raw)
                .expect("valid size bucket byte")
        }
        match bytes[0] {
            0 => {
                assert_eq!(bytes.len(), 1 + 32 + 32 + 1);
                ActionClass::Swap {
                    mint_in: bytes[1..33].try_into().unwrap(),
                    mint_out: bytes[33..65].try_into().unwrap(),
                    size: bucket(bytes[65]),
                }
            }
            1 => {
                assert_eq!(bytes.len(), 1 + 32 + 1);
                ActionClass::Stake {
                    validator: bytes[1..33].try_into().unwrap(),
                    size: bucket(bytes[33]),
                }
            }
            other => panic!("unknown action class tag {other}"),
        }
    }

    fn swap() -> JupiterSwap {
        JupiterSwap {
            mint_in: [0xAA; 32],
            mint_out: [0xBB; 32],
            size: SizeBucket::Medium,
        }
    }

    fn stake() -> JitoSolStake {
        JitoSolStake {
            validator: [0xCC; 32],
            size: SizeBucket::Small,
        }
    }

    #[test]
    fn swap_action_class_round_trips_through_canonical_bytes() {
        let class = swap().action_class();
        let bytes = class.canonical_bytes();
        assert_eq!(decode_action_class(&bytes), class);
        // Deterministic: same class, same bytes, every time.
        assert_eq!(bytes, class.canonical_bytes());
    }

    #[test]
    fn stake_action_class_round_trips_through_canonical_bytes() {
        let class = stake().action_class();
        let bytes = class.canonical_bytes();
        assert_eq!(decode_action_class(&bytes), class);
        assert_eq!(bytes, class.canonical_bytes());
    }

    #[test]
    fn behaviors_encode_to_distinct_classes() {
        // Two behaviors must never share canonical bytes; one anonymity set
        // exists per class and cross-class collisions would merge pools.
        assert_ne!(
            swap().action_class().canonical_bytes(),
            stake().action_class().canonical_bytes()
        );
    }

    #[test]
    fn settlement_ix_matches_wire_shape() {
        let nfs = vec![Nullifier([1u8; 32]), Nullifier([2u8; 32])];
        for behavior in [&swap() as &dyn Behavior, &stake() as &dyn Behavior] {
            let data = behavior
                .build_settlement_ix(Epoch(7), &nfs)
                .expect("stub settlement bytes");
            assert_eq!(data.len(), wire::SETTLE_HEADER_LEN + nfs.len() * 32);
            assert_eq!(data[0], wire::tag::SETTLE_EPOCH);
            assert_eq!(data[1..9], 7u64.to_le_bytes());
            assert_eq!(data[9..13], 2u32.to_le_bytes());
            assert_eq!(&data[13..45], &[1u8; 32]);
            assert_eq!(&data[45..77], &[2u8; 32]);
        }
    }

    #[test]
    fn settlement_refuses_empty_epoch() {
        assert!(swap().build_settlement_ix(Epoch(0), &[]).is_err());
    }

    #[test]
    fn registry_resolves_by_name() {
        let mut reg = BehaviorRegistry::new();
        reg.register("jupiter-swap", Box::new(swap()));
        reg.register("jitosol-stake", Box::new(stake()));

        assert_eq!(reg.len(), 2);
        assert_eq!(reg.names(), vec!["jitosol-stake", "jupiter-swap"]);
        assert!(reg.get("missing").is_none());

        let b = reg.get("jupiter-swap").expect("registered");
        assert_eq!(b.action_class(), swap().action_class());
        assert!(b.describe().contains("jupiter"));
    }
}
