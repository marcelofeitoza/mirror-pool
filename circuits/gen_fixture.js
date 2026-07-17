// gen_fixture.js
//
// Builds a known-good witness for the mirror-pool membership circuit, produces a
// Groth16 proof with snarkjs, verifies it, and writes the fixture the on-chain
// Rust verifier and its test consume:
//
//   artifacts/proof_fixture.json  { proof, publicSignals }
//   artifacts/vk.json             (copy of the snarkjs verification key)
//
// The tree is built with circomlibjs Poseidon, whose constants match the
// circomlib Poseidon used inside the circuit, so the JS-computed root equals the
// circuit-recomputed root. We insert a single known commitment at a fixed leaf
// index in an otherwise-empty depth-20 tree; every sibling is the canonical
// empty-subtree hash for its level, and pathIndices are the bits of the index.
//
// MIT licensed. Clean-room; circomlibjs + snarkjs only.

const fs = require("fs");
const path = require("path");
const snarkjs = require("snarkjs");
const { buildPoseidon } = require("circomlibjs");

const HERE = __dirname;
const ARTIFACTS = path.join(HERE, "artifacts");
const WASM = path.join(HERE, "membership_js", "membership.wasm");
const ZKEY = path.join(HERE, "membership_final.zkey");
const VK = path.join(ARTIFACTS, "verification_key.json");

const MERKLE_DEPTH = 20;

// --- fixed, human-picked field elements for a reproducible fixture ---
// (arbitrary BN254 scalar-field elements; not secret in a real deployment)
const secret     = 111122223333444455556666777788889999n;
const epoch      = 7n;                                       // small realistic epoch id
const LEAF_INDEX = 21n;                                      // 0b10101 -> exercises both path-index bits

// --- ZK opt-in settlement action binding (v1: transfer to a fresh address) ---
// The action executed at SettleZk is "transfer AMOUNT lamports to RECIPIENT".
// actionHash binds BOTH, so a relay cannot redirect the escrow: it is the
// 3-input circom Poseidon over the recipient (split into two 128-bit big-endian
// halves, each < 2^128 < r so no modular reduction is needed and no collision
// resistance is lost) and the amount as a field element:
//
//   actionHash = Poseidon(recipientHi128, recipientLo128, amount)
//
// This is the exact value the on-chain program recomputes with `sol_poseidon`
// and the exact value `mirror_core::transfer_action_hash` computes on the host,
// so the value the prover commits to and the value the program enforces match.
// RECIPIENT is the 32 bytes 0x01,0x02,..,0x20 and AMOUNT is 0.25 SOL; the
// integration test uses the identical recipient/amount.
const RECIPIENT = Buffer.from(
  Array.from({ length: 32 }, (_, i) => i + 1)
); // bytes 0x01..0x20
const AMOUNT_LAMPORTS = 250000000n; // 0.25 SOL, escrowed at CommitDeposit
const recipientHi = BigInt("0x" + RECIPIENT.subarray(0, 16).toString("hex"));
const recipientLo = BigInt("0x" + RECIPIENT.subarray(16, 32).toString("hex"));

async function main() {
  const poseidon = await buildPoseidon();
  const F = poseidon.F;
  const H = (arr) => F.toObject(poseidon(arr)); // hash BigInt[] -> BigInt

  // actionHash = Poseidon(recipientHi128, recipientLo128, amount) (see above).
  const actionHash = H([recipientHi, recipientLo, AMOUNT_LAMPORTS]);

  // commitment = Poseidon(secret, actionHash, epoch)   (the Merkle leaf)
  const commitment = H([secret, actionHash, epoch]);
  // nullifierHash = Poseidon(secret, epoch)
  const nullifierHash = H([secret, epoch]);

  // Canonical empty-subtree hashes: zeros[0] = 0, zeros[i] = Poseidon(zeros[i-1], zeros[i-1]).
  const zeros = [0n];
  for (let i = 1; i <= MERKLE_DEPTH; i++) zeros.push(H([zeros[i - 1], zeros[i - 1]]));

  // Inclusion path for a single leaf at LEAF_INDEX in an otherwise-empty tree.
  const pathElements = [];
  const pathIndices = [];
  let cur = commitment;
  for (let level = 0; level < MERKLE_DEPTH; level++) {
    const bit = Number((LEAF_INDEX >> BigInt(level)) & 1n);
    const sibling = zeros[level];
    pathElements.push(sibling);
    pathIndices.push(bit);
    cur = bit === 0 ? H([cur, sibling]) : H([sibling, cur]);
  }
  const root = cur;

  const input = {
    root: root.toString(),
    nullifierHash: nullifierHash.toString(),
    actionHash: actionHash.toString(),
    epoch: epoch.toString(),
    secret: secret.toString(),
    pathElements: pathElements.map((x) => x.toString()),
    pathIndices: pathIndices.map((x) => x.toString()),
  };

  console.log("Fixture inputs:");
  console.log("  commitment (leaf) =", commitment.toString());
  console.log("  root              =", root.toString());
  console.log("  nullifierHash     =", nullifierHash.toString());
  console.log("  actionHash        =", actionHash.toString());
  console.log("  epoch             =", epoch.toString());
  console.log("  leafIndex         =", LEAF_INDEX.toString());

  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);

  console.log("\npublicSignals (order emitted by snarkjs):");
  publicSignals.forEach((s, i) => console.log(`  [${i}] ${s}`));

  // Label the public-signal order by matching against the known input values.
  const known = new Map([
    [root.toString(), "root"],
    [nullifierHash.toString(), "nullifierHash"],
    [actionHash.toString(), "actionHash"],
    [epoch.toString(), "epoch"],
  ]);
  const order = publicSignals.map((s) => known.get(s) || "unknown");
  console.log("\npublic-input order:", order.join(", "));

  const vk = JSON.parse(fs.readFileSync(VK, "utf8"));
  const ok = await snarkjs.groth16.verify(vk, publicSignals, proof);
  if (!ok) {
    console.error("\nsnarkjs.groth16.verify: FAILED");
    process.exit(1);
  }
  console.log("\nsnarkjs.groth16.verify (in-process): OK");

  fs.writeFileSync(
    path.join(ARTIFACTS, "proof_fixture.json"),
    JSON.stringify({ proof, publicSignals }, null, 2) + "\n"
  );
  fs.writeFileSync(path.join(ARTIFACTS, "vk.json"), JSON.stringify(vk, null, 2) + "\n");
  fs.writeFileSync(
    path.join(ARTIFACTS, "fixture_meta.json"),
    JSON.stringify({ publicInputOrder: order, nPublic: publicSignals.length }, null, 2) + "\n"
  );
  console.log("\nWrote artifacts/proof_fixture.json, artifacts/vk.json, artifacts/fixture_meta.json");

  // snarkjs keeps worker threads alive; exit explicitly.
  process.exit(0);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
