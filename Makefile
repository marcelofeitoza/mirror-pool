# mirror-pool developer tasks.
#
# Development and testing ALWAYS run against Surfpool (a local mainnet mirror on
# http://127.0.0.1:8899). We treat Surfpool as mainnet: no localnet-only
# shortcuts, no early-exits. A public devnet deploy is used only to produce the
# explorer-linked proof in PROOF.md.

SURFPOOL_RPC ?= http://127.0.0.1:8899
PROGRAM_MANIFEST := programs/mirror-pool/Cargo.toml

.PHONY: all fmt fmt-check clippy test build build-sbf harness soak check clean

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

# Run the adversarial evaluation harness (prints the attacker-advantage table).
harness:
	cargo run -p mirror-harness --release

# End-to-end soak against Surfpool. Requires `surfpool start` running locally.
soak:
	@echo "Soaking against Surfpool at $(SURFPOOL_RPC) (treated as mainnet)"
	SOLANA_RPC=$(SURFPOOL_RPC) cargo run -p mirror-coordinator --release

check: fmt-check clippy test

clean:
	cargo clean
	cargo clean --manifest-path $(PROGRAM_MANIFEST)
