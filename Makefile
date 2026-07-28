# mirror-pool developer tasks.
#
# Development and testing ALWAYS run against Surfpool (a local mainnet mirror on
# http://127.0.0.1:8899). We treat Surfpool as mainnet: no localnet-only
# shortcuts, no early-exits. A public devnet deploy is used only to produce the
# explorer-linked proof in PROOF.md.

SURFPOOL_RPC ?= http://127.0.0.1:8899
PROGRAM_MANIFEST := programs/mirror-pool/Cargo.toml

.PHONY: all fmt fmt-check clippy test build build-sbf harness soak soak-funding ceremony-test ceremony-verify-run check clean

all: fmt-check clippy test build-sbf

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

clippy:
	cargo clippy --all-targets -- -D warnings

# Host workspace (off-chain crates): core, coordinator, cli, harness, behaviors.
test:
	cargo test --workspace

build:
	cargo build --workspace

# On-chain program (standalone crate, built for SBF).
build-sbf:
	cargo build-sbf --manifest-path $(PROGRAM_MANIFEST)

# The decisive trusted-setup check: run a real multi-contribution phase-2 ceremony
# over the membership circuit, prove under the ceremony-produced key, and verify with
# the on-chain groth16-solana verifier. Needs the gitignored circuit build artifacts
# (bash circuits/build.sh) plus the powers-of-tau and the initial zkey. See
# docs/CEREMONY.md. With MIRROR_PROVE_LIVE=1 set, a missing artifact FAILS this
# target rather than skipping, so a green run means it really ran.
ceremony-test:
	MIRROR_PROVE_LIVE=1 cargo test -p mirror-cli -- --ignored ceremony_key --nocapture

# Re-verify the published transcripts of the recorded demonstration run
# (docs/ceremony-run/) the way a third party would: no key files, beacon
# pre-commitment supplied. Needs a built mirror-cli.
ceremony-verify-run:
	cargo run -p mirror-cli -- ceremony verify-transcript \
	  --file docs/ceremony-run/membership-transcript.json \
	  --beacon-source-text "mirror-pool demo beacon 2026-07-27" \
	  --beacon-iterations-exp 16
	cargo run -p mirror-cli -- ceremony verify-transcript \
	  --file docs/ceremony-run/transaction-transcript.json \
	  --beacon-source-text "mirror-pool demo beacon 2026-07-27" \
	  --beacon-iterations-exp 16

# Run the adversarial evaluation harness (prints the attacker-advantage table).
harness:
	cargo run -p mirror-harness --release

# End-to-end soak against Surfpool. Requires `surfpool start` running locally.
soak:
	@echo "Soaking against Surfpool at $(SURFPOOL_RPC) (treated as mainnet)"
	SOLANA_RPC=$(SURFPOOL_RPC) cargo run -p mirror-coordinator --release

# The FUNDING-ROUND soak: fund-commit -> coordinator ingestion -> thin-round
# roll-forward -> batched gasless release -> commit from the funded wallet, with
# on-chain funding-provenance verification. Needs a running Surfpool, a freshly
# deployed program id (PROGRAM_ID=...), and the transaction-circuit artifacts.
soak-funding:
	@test -n "$(PROGRAM_ID)" || (echo "set PROGRAM_ID=<freshly deployed program id>" && false)
	cargo run -p mirror-soak --release --bin mirror-soak-funding -- \
	  --rpc-url $(SURFPOOL_RPC) --program-id $(PROGRAM_ID)

# The SUSTAINED run: one fixed crowd shape repeated on a paced cadence for hours
# against a live cluster, recording latency, leader spread, state growth and
# accumulator drift as they change over time. Unlike the targets above this one
# is meant for a PUBLIC cluster, so it never airdrops: MIRROR_FUNDING_KEYPAIR
# must name a pre-funded master payer that every wallet is funded from by system
# transfer, and the loop stops itself at BUDGET_FLOOR lamports.
#
#   make soak-sustained PROGRAM_ID=<id> RPC=https://api.devnet.solana.com \
#     MIRROR_FUNDING_KEYPAIR=<master.json> DURATION=14400
RPC ?= $(SURFPOOL_RPC)
DURATION ?= 14400
ROUND_INTERVAL ?= 200
BUDGET_FLOOR ?= 15000000
soak-sustained:
	@test -n "$(PROGRAM_ID)" || (echo "set PROGRAM_ID=<deployed program id>" && false)
	@test -n "$(MIRROR_FUNDING_KEYPAIR)" || (echo "set MIRROR_FUNDING_KEYPAIR=<pre-funded master payer>" && false)
	cargo run -p mirror-soak --bin mirror-soak-sustained -- \
	  --rpc-url $(RPC) --program-id $(PROGRAM_ID) \
	  --duration-secs $(DURATION) --round-interval-secs $(ROUND_INTERVAL) \
	  --budget-floor-lamports $(BUDGET_FLOOR)

# Re-derive the sustained run's aggregate report from the committed evidence
# alone: no RPC, no keys, no cluster. Every number in docs/DEVNET.md comes from
# this, so a reader can recompute it.
soak-sustained-summary:
	cargo run -p mirror-soak --bin mirror-soak-sustained -- \
	  --summarize docs/devnet-run/sustained-devnet-rounds.jsonl

check: fmt-check clippy test

clean:
	cargo clean
	cargo clean --manifest-path $(PROGRAM_MANIFEST)
