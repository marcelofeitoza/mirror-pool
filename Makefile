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

check: fmt-check clippy test

clean:
	cargo clean
	cargo clean --manifest-path $(PROGRAM_MANIFEST)
