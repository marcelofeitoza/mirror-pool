#!/usr/bin/env bash
#
# build.sh - compile the mirror-pool membership circuit and run a DEV/TEST
# Groth16 trusted setup, then export the verifying key, a known-good proof
# fixture, and the Rust-consumable forms for the on-chain groth16-solana verifier.
#
# WARNING: this is a DEVELOPMENT / TEST setup only. The phase-2 contribution uses
# a hard-coded entropy string so the build is reproducible. It is NOT a secure
# ceremony and MUST NOT be used to secure real value. A real multi-party trusted
# setup ceremony is a separate deliverable.
#
# Requirements: circom 2.x, node, and the npm deps (circomlib, snarkjs) installed
# via `npm install` in this directory.
#
# Usage:
#   npm install      # once
#   bash build.sh
#
set -euo pipefail
cd "$(dirname "$0")"

CIRCUIT=membership
DEPTH_POWER=16                       # 2^16 = 65536 >> circuit constraint count
PTAU="pot${DEPTH_POWER}_final.ptau"  # phase-1 SRS (universal, gitignored)
ENTROPY="mirror-pool-dev-setup-not-secure-v1"
ARTIFACTS=artifacts

mkdir -p "$ARTIFACTS"

echo "==> [1/5] Compiling $CIRCUIT.circom"
circom "$CIRCUIT.circom" --r1cs --wasm --sym -l node_modules
snarkjs r1cs info "$CIRCUIT.r1cs"

echo "==> [2/5] Ensuring phase-1 powers of tau ($PTAU)"
if [ -f "$PTAU" ]; then
  echo "    Using existing $PTAU (universal, circuit-independent SRS)."
else
  echo "    $PTAU not found; generating a reproducible 2^${DEPTH_POWER} phase-1."
  echo "    (This is slow; a universal ptau can also be dropped in as $PTAU.)"
  snarkjs powersoftau new bn128 "$DEPTH_POWER" pot_0000.ptau -v
  snarkjs powersoftau contribute pot_0000.ptau pot_0001.ptau \
    --name="mirror-pool dev phase1" -v -e="$ENTROPY-phase1"
  snarkjs powersoftau prepare phase2 pot_0001.ptau "$PTAU" -v
  rm -f pot_0000.ptau pot_0001.ptau
fi

echo "==> [3/5] Groth16 phase-2 setup + contribution"
snarkjs groth16 setup "$CIRCUIT.r1cs" "$PTAU" "${CIRCUIT}_0000.zkey"
snarkjs zkey contribute "${CIRCUIT}_0000.zkey" "${CIRCUIT}_final.zkey" \
  --name="mirror-pool dev phase2" -v -e="$ENTROPY-phase2"
snarkjs zkey export verificationkey "${CIRCUIT}_final.zkey" \
  "$ARTIFACTS/verification_key.json"

echo "==> [4/5] Generating proof fixture (gen_fixture.js) + snarkjs verify"
node gen_fixture.js

echo "==> [5/5] Emitting Rust constants for groth16-solana (vk.rs, proof_fixture.rs)"
node convert_to_rust.js

echo
echo "Build complete. Committed artifacts in $ARTIFACTS/:"
echo "  verification_key.json  vk.json  vk.rs  proof_fixture.json  proof_fixture.rs"
echo "Uncommitted build outputs (gitignored): *.r1cs *.sym *.wasm *_js/ *.zkey *.ptau"
