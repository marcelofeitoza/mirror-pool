#!/usr/bin/env bash
#
# build_transaction.sh - compile the mirror-pool transaction circuit (2-in/2-out
# confidential-value JoinSplit) and run a DEV/TEST Groth16 trusted setup, then
# export the verifying key, three known-good proof fixtures (shield / transfer /
# unshield), and the Rust-consumable forms for the on-chain groth16-solana verifier.
#
# WARNING: this is a DEVELOPMENT / TEST setup only. snarkjs mixes fresh randomness
# into every phase-2 contribution, so the verifying key is NOT byte-reproducible
# across rebuilds; trust here rests on the committed verifying key + proof fixtures
# verifying (they do) and the on-chain program embedding that committed key, not on
# rebuild determinism. It is NOT a secure ceremony and MUST NOT be used to secure
# real value.
#
# A real multi-party phase-2 ceremony IS implemented: see docs/CEREMONY.md and
# `mirror-cli ceremony start | contribute | beacon | verify | export-vk`. To produce
# a key that is not this one, run the ceremony over the DETERMINISTIC initial key
# (`snarkjs groth16 setup <r1cs> <public>.ptau <circuit>_0000.zkey`, which this
# script also produces in step 3) and export its verifying key over artifacts/.
#
# NOTE: re-running this OVERWRITES circuits/artifacts/* with a fresh vk + fixtures
# that will NOT match the committed on-chain vk. Run `git checkout -- circuits/artifacts`
# before the on-chain tests, or the embedded-vk proofs will fail to verify.
#
# Requirements: circom 2.x, node, and the npm deps (circomlib, circomlibjs,
# snarkjs, ethers) installed via `npm install` in this directory.
#
# Usage:
#   npm install      # once
#   bash build_transaction.sh
#
set -euo pipefail
cd "$(dirname "$0")"

CIRCUIT=transaction
# The transaction circuit has ~27.3k R1CS constraints, which needs a 2^15 domain;
# the local universal 2^16 powers-of-tau (pot16_final.ptau) covers it comfortably.
# If a future change pushes the constraint count above 2^16, copy the public 2^17
# powers-of-tau in as pot17_final.ptau and set DEPTH_POWER=17.
DEPTH_POWER=16
PTAU="pot${DEPTH_POWER}_final.ptau"   # phase-1 SRS (universal, gitignored)
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
  echo "    WARNING: $PTAU not found. Generating a SINGLE-CONTRIBUTION phase-1 from"
  echo "    a fixed entropy string. This is for offline development ONLY: a real"
  echo "    deployment must use a PUBLIC perpetual powers-of-tau file dropped in as"
  echo "    $PTAU (inspect it with \`mirror-cli ceremony inspect-ptau\`)."
  echo "    (This is also slow.)"
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
  "$ARTIFACTS/transaction_verification_key.json"

echo "==> [4/5] Generating proof fixtures (gen_transaction_fixture.js) + snarkjs verify"
node gen_transaction_fixture.js

echo "==> [5/5] Emitting Rust constants for groth16-solana (transaction_vk.rs, transaction_proof_fixture.rs)"
node convert_to_rust.js --circuit=transaction

echo
echo "Build complete. Committed artifacts in $ARTIFACTS/:"
echo "  transaction_verification_key.json  transaction_vk.rs"
echo "  transaction_proof_fixture.json  transaction_proof_fixture.rs"
echo "  transaction_fixture_meta.json"
echo "  (plus transaction_shield_fixture.json / transaction_unshield_fixture.json)"
echo "Uncommitted build outputs (gitignored): *.r1cs *.sym *.wasm *_js/ *.zkey *.ptau"
