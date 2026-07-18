// gen_transaction_fixture.js
//
// Builds three known-good witnesses for the mirror-pool transaction circuit (the
// 2-in/2-out confidential-value JoinSplit), produces a Groth16 proof for each
// with snarkjs, verifies each both in-process and with the `snarkjs groth16
// verify` CLI (must print OK), and writes the fixtures the on-chain Rust verifier
// and its tests consume:
//
//   artifacts/transaction_proof_fixture.json     the TRANSFER case (canonical;
//                                                consumed by convert_to_rust.js)
//   artifacts/transaction_shield_fixture.json    SHIELD   (2 dummy in, +v)
//   artifacts/transaction_unshield_fixture.json  UNSHIELD (real in, -v)
//   artifacts/transaction_fixture_meta.json      public-input order + nPublic
//
// The Poseidon tree is built with circomlibjs, whose constants match the
// circomlib Poseidon used inside the circuit, so JS-computed roots/commitments
// equal the circuit-recomputed ones. Big-endian byte encoding throughout, to
// match the existing pipeline.
//
// Canonical value-note scheme (see transaction.circom / TRANSACTION.md):
//   publicKey  = Poseidon(privateKey)
//   commitment = Poseidon(amount, publicKey, blinding)
//   signature  = Poseidon(privateKey, commitment, merklePathIndices)
//   nullifier  = Poseidon(commitment, merklePathIndices, signature)
//   node       = Poseidon(left, right),  zeros[0] = 0
//
// MIT licensed. Clean-room; circomlibjs + snarkjs + ethers (keccak256) only.
// Design follows the public Tornado-Nova transaction circuit.

const fs = require("fs");
const os = require("os");
const path = require("path");
const { execFileSync } = require("child_process");
const snarkjs = require("snarkjs");
const { buildPoseidon } = require("circomlibjs");
const ethers = require("ethers");

const HERE = __dirname;
const ARTIFACTS = path.join(HERE, "artifacts");
const WASM = path.join(HERE, "transaction_js", "transaction.wasm");
const ZKEY = path.join(HERE, "transaction_final.zkey");
const VK = path.join(ARTIFACTS, "transaction_verification_key.json");
// snarkjs restricts package exports, so reference the CLI entry by path.
const SNARKJS_CLI = path.join(HERE, "node_modules", "snarkjs", "build", "cli.cjs");

const MERKLE_DEPTH = 20;
const MAX_AMOUNT_BITS = 248;

// BN254 scalar field modulus r ("FIELD_SIZE"). This is the offset used to encode
// a negative publicAmount: withdraw of v -> publicAmount = FIELD_SIZE - v.
const FIELD_SIZE =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

const keccak256 = ethers.keccak256 || ethers.utils.keccak256;

// ------------------------------------------------------------------ helpers ---

// Encode a signed integer amount into the field with the FIELD_SIZE offset, and
// return the (magnitude, sign) witness the circuit's range gadget expects.
function encodePublicAmount(signed) {
  if (signed >= 0n) {
    return { publicAmount: signed % FIELD_SIZE, mag: signed, sign: 0n };
  }
  const mag = -signed;
  return { publicAmount: (FIELD_SIZE - mag) % FIELD_SIZE, mag, sign: 1n };
}

// keccak256(extData) mod r. extData preimage (big-endian, concatenated):
//   recipient(32) || relayer(32) || fee_u64_be(8) || encOut0 || encOut1
// The program recomputes this from the ext data it receives and checks it equals
// the extDataHash public input; the circuit only binds it against malleation.
function extDataHash({ recipient, relayer, fee, encOut0, encOut1 }) {
  const feeBE = Buffer.alloc(8);
  feeBE.writeBigUInt64BE(BigInt(fee));
  const preimage = Buffer.concat([
    Buffer.from(recipient),
    Buffer.from(relayer),
    feeBE,
    Buffer.from(encOut0),
    Buffer.from(encOut1),
  ]);
  const digest = BigInt(keccak256(preimage));
  return digest % FIELD_SIZE;
}

// Sparse Poseidon Merkle tree (depth `MERKLE_DEPTH`) with the canonical zero
// ladder for empty subtrees. Leaves are appended left to right.
class MerkleTree {
  constructor(depth, H, zeros) {
    this.depth = depth;
    this.H = H;
    this.zeros = zeros;
    this.nodes = new Map(); // `${level}:${index}` -> BigInt
    this.nextIndex = 0;
  }
  _get(level, index) {
    const k = `${level}:${index}`;
    return this.nodes.has(k) ? this.nodes.get(k) : this.zeros[level];
  }
  insert(leaf) {
    const index = this.nextIndex++;
    let cur = leaf;
    let idx = index;
    this.nodes.set(`0:${idx}`, cur);
    for (let level = 0; level < this.depth; level++) {
      const isRight = idx & 1;
      const sibIdx = isRight ? idx - 1 : idx + 1;
      const sibling = this._get(level, sibIdx);
      cur = isRight ? this.H([sibling, cur]) : this.H([cur, sibling]);
      idx = idx >> 1;
      this.nodes.set(`${level + 1}:${idx}`, cur);
    }
    return index;
  }
  root() {
    return this._get(this.depth, 0);
  }
  proof(index) {
    const pathElements = [];
    let idx = index;
    for (let level = 0; level < this.depth; level++) {
      const isRight = idx & 1;
      const sibIdx = isRight ? idx - 1 : idx + 1;
      pathElements.push(this._get(level, sibIdx));
      idx = idx >> 1;
    }
    return { pathElements, pathIndices: BigInt(index) };
  }
}

// A random-ish but FIXED byte payload, so fixtures are reproducible.
function payload(seed, len = 48) {
  return Buffer.from(Array.from({ length: len }, (_, i) => (seed * 131 + i * 17) & 0xff));
}

async function main() {
  const poseidon = await buildPoseidon();
  const F = poseidon.F;
  const H = (arr) => F.toObject(poseidon(arr)); // BigInt[] -> BigInt

  // Note-scheme primitives.
  const pubKeyOf = (privKey) => H([privKey]);
  const commit = (amount, pubKey, blinding) => H([amount, pubKey, blinding]);
  const sign = (privKey, commitment, pathIndices) => H([privKey, commitment, pathIndices]);
  const nullify = (commitment, pathIndices, sig) => H([commitment, pathIndices, sig]);

  // Canonical zero ladder: zeros[0] = 0, zeros[i] = Poseidon(zeros[i-1], zeros[i-1]).
  const zeros = [0n];
  for (let i = 1; i <= MERKLE_DEPTH; i++) zeros.push(H([zeros[i - 1], zeros[i - 1]]));

  // Fixed keypairs (arbitrary field elements; not secret in a real deployment).
  const ALICE_SK = 100000000000000000000000000000000001n;
  const BOB_SK   = 200000000000000000000000000000000002n;
  const DUMMY_SK = 300000000000000000000000000000000003n;
  const ALICE_PK = pubKeyOf(ALICE_SK);
  const BOB_PK   = pubKeyOf(BOB_SK);
  const DUMMY_PK = pubKeyOf(DUMMY_SK);

  const RECIPIENT = Buffer.from(Array.from({ length: 32 }, (_, i) => i + 1));   // 0x01..0x20
  const RELAYER   = Buffer.from(Array.from({ length: 32 }, (_, i) => 0x20 - i)); // 0x20..0x01

  // Build one dummy (amount==0) input; its membership check is disabled, so its
  // path is the zero ladder and pathIndices=0. `salt` keeps blindings distinct.
  function dummyInput(salt) {
    const privateKey = DUMMY_SK + BigInt(salt);
    const blinding = 555000000000000000000000000000000000n + BigInt(salt);
    const amount = 0n;
    const pubKey = pubKeyOf(privateKey);
    const c = commit(amount, pubKey, blinding);
    const pathIndices = 0n;
    const sig = sign(privateKey, c, pathIndices);
    const nf = nullify(c, pathIndices, sig);
    return {
      amount,
      privateKey,
      blinding,
      pathIndices,
      pathElements: zeros.slice(0, MERKLE_DEPTH),
      nullifier: nf,
    };
  }

  // Insert a real note's commitment into `tree`, recording enough to finalize its
  // proof AFTER every leaf is inserted (so siblings are the final, not stale, values).
  function insertReal(tree, { amount, privateKey, blinding }) {
    const pubKey = pubKeyOf(privateKey);
    const c = commit(amount, pubKey, blinding);
    const index = tree.insert(c);
    return { amount, privateKey, blinding, commitment: c, index };
  }

  // Finalize a real input against the completed tree: proof, signature, nullifier.
  function finalizeReal(tree, pending) {
    const { pathElements, pathIndices } = tree.proof(pending.index);
    const sig = sign(pending.privateKey, pending.commitment, pathIndices);
    const nf = nullify(pending.commitment, pathIndices, sig);
    return {
      amount: pending.amount,
      privateKey: pending.privateKey,
      blinding: pending.blinding,
      pathIndices,
      pathElements,
      nullifier: nf,
    };
  }

  function makeOutput({ amount, pubKey, blinding }) {
    return { amount, pubKey, blinding, commitment: commit(amount, pubKey, blinding) };
  }

  // Assemble the full circuit input object + the expected public signals (in the
  // fixed public order) from a case description.
  function assemble({ root, signedPublicAmount, ext, inputs, outputs }) {
    const enc = encodePublicAmount(signedPublicAmount);
    const edh = extDataHash(ext);

    const input = {
      root: root.toString(),
      publicAmount: enc.publicAmount.toString(),
      extDataHash: edh.toString(),
      inputNullifier: inputs.map((x) => x.nullifier.toString()),
      outputCommitment: outputs.map((x) => x.commitment.toString()),

      inAmount: inputs.map((x) => x.amount.toString()),
      inPrivateKey: inputs.map((x) => x.privateKey.toString()),
      inBlinding: inputs.map((x) => x.blinding.toString()),
      inPathIndices: inputs.map((x) => x.pathIndices.toString()),
      inPathElements: inputs.map((x) => x.pathElements.map((e) => e.toString())),

      outAmount: outputs.map((x) => x.amount.toString()),
      outPubkey: outputs.map((x) => x.pubKey.toString()),
      outBlinding: outputs.map((x) => x.blinding.toString()),

      publicAmountMagnitude: enc.mag.toString(),
      publicAmountSign: enc.sign.toString(),
    };

    // Expected public signals, in the fixed on-chain order.
    const expected = [
      { label: "root", value: root },
      { label: "publicAmount", value: enc.publicAmount },
      { label: "extDataHash", value: edh },
      { label: "inputNullifier[0]", value: inputs[0].nullifier },
      { label: "inputNullifier[1]", value: inputs[1].nullifier },
      { label: "outputCommitment[0]", value: outputs[0].commitment },
      { label: "outputCommitment[1]", value: outputs[1].commitment },
    ];
    return { input, expected };
  }

  // -------------------------------------------------------------- cases ------

  // SHIELD: 2 dummy inputs, deposit +10, one real output + one empty output.
  function buildShield() {
    const emptyTree = new MerkleTree(MERKLE_DEPTH, H, zeros);
    const inputs = [dummyInput(1), dummyInput(2)];
    const outputs = [
      makeOutput({ amount: 10n, pubKey: ALICE_PK, blinding: 11n }),
      makeOutput({ amount: 0n, pubKey: ALICE_PK, blinding: 12n }),
    ];
    return assemble({
      root: emptyTree.root(), // fresh tree; inputs are dummy so the root is unchecked
      signedPublicAmount: 10n,
      ext: { recipient: RECIPIENT, relayer: RELAYER, fee: 0, encOut0: payload(1), encOut1: payload(2) },
      inputs,
      outputs,
    });
  }

  // TRANSFER: 2 real inputs (30 + 20), 2 real outputs (35 + 15), publicAmount 0.
  function buildTransfer() {
    const tree = new MerkleTree(MERKLE_DEPTH, H, zeros);
    // Insert both leaves first, then finalize proofs against the completed tree.
    const pending = [
      insertReal(tree, { amount: 30n, privateKey: ALICE_SK, blinding: 31n }),
      insertReal(tree, { amount: 20n, privateKey: ALICE_SK, blinding: 32n }),
    ];
    const inputs = pending.map((p) => finalizeReal(tree, p));
    const outputs = [
      makeOutput({ amount: 35n, pubKey: BOB_PK, blinding: 41n }),
      makeOutput({ amount: 15n, pubKey: ALICE_PK, blinding: 42n }),
    ];
    return assemble({
      root: tree.root(),
      signedPublicAmount: 0n,
      ext: { recipient: RECIPIENT, relayer: RELAYER, fee: 0, encOut0: payload(3), encOut1: payload(4) },
      inputs,
      outputs,
    });
  }

  // UNSHIELD: 1 real input (20) + 1 dummy, withdraw -7, change output 13 + empty.
  function buildUnshield() {
    const tree = new MerkleTree(MERKLE_DEPTH, H, zeros);
    const pending = insertReal(tree, { amount: 20n, privateKey: ALICE_SK, blinding: 51n });
    const real = finalizeReal(tree, pending);
    const inputs = [real, dummyInput(9)];
    const outputs = [
      makeOutput({ amount: 13n, pubKey: ALICE_PK, blinding: 61n }),
      makeOutput({ amount: 0n, pubKey: ALICE_PK, blinding: 62n }),
    ];
    return assemble({
      root: tree.root(),
      signedPublicAmount: -7n,
      ext: { recipient: RECIPIENT, relayer: RELAYER, fee: 0, encOut0: payload(5), encOut1: payload(6) },
      inputs,
      outputs,
    });
  }

  // ------------------------------------------------------- prove + verify ----

  const vk = JSON.parse(fs.readFileSync(VK, "utf8"));
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "mp-tx-"));

  async function proveVerify(name, built) {
    console.log(`\n===== ${name} =====`);
    console.log("  value check: sum(in) + publicAmount == sum(out)");

    const { proof, publicSignals } = await snarkjs.groth16.fullProve(built.input, WASM, ZKEY);

    // Assert the public signals equal the expected values IN ORDER (this both
    // pins the on-chain public-input order and validates the witness).
    if (publicSignals.length !== built.expected.length) {
      throw new Error(`${name}: expected ${built.expected.length} public signals, got ${publicSignals.length}`);
    }
    built.expected.forEach((e, i) => {
      if (publicSignals[i] !== e.value.toString()) {
        throw new Error(
          `${name}: public signal [${i}] (${e.label}) mismatch:\n` +
            `    expected ${e.value.toString()}\n    got      ${publicSignals[i]}`
        );
      }
      console.log(`  [${i}] ${e.label} = ${publicSignals[i]}`);
    });

    // In-process verify.
    const okInProc = await snarkjs.groth16.verify(vk, publicSignals, proof);
    if (!okInProc) throw new Error(`${name}: in-process snarkjs.groth16.verify FAILED`);
    console.log(`  in-process snarkjs.groth16.verify: OK`);

    // CLI verify (`snarkjs groth16 verify` must print OK).
    const proofFile = path.join(tmp, `${name}_proof.json`);
    const pubFile = path.join(tmp, `${name}_public.json`);
    fs.writeFileSync(proofFile, JSON.stringify(proof, null, 2));
    fs.writeFileSync(pubFile, JSON.stringify(publicSignals, null, 2));
    const out = execFileSync(
      process.execPath,
      [SNARKJS_CLI, "groth16", "verify", VK, pubFile, proofFile],
      { encoding: "utf8" }
    );
    const clean = out.replace(/\x1b\[[0-9;]*m/g, ""); // strip ANSI color codes
    const cliOk = /snarkJS: OK!/.test(clean);
    console.log(`  CLI snarkjs groth16 verify: ${cliOk ? "OK!" : "FAILED"}`);
    console.log(clean.trim().split("\n").map((l) => "    " + l).join("\n"));
    if (!cliOk) throw new Error(`${name}: CLI groth16 verify did not print OK`);

    return { proof, publicSignals, order: built.expected.map((e) => e.label) };
  }

  const shield = await proveVerify("SHIELD", buildShield());
  const transfer = await proveVerify("TRANSFER", buildTransfer());
  const unshield = await proveVerify("UNSHIELD", buildUnshield());

  // The TRANSFER fixture is the canonical one consumed by convert_to_rust.js and
  // the on-chain test.
  fs.writeFileSync(
    path.join(ARTIFACTS, "transaction_proof_fixture.json"),
    JSON.stringify({ proof: transfer.proof, publicSignals: transfer.publicSignals }, null, 2) + "\n"
  );
  fs.writeFileSync(
    path.join(ARTIFACTS, "transaction_shield_fixture.json"),
    JSON.stringify({ proof: shield.proof, publicSignals: shield.publicSignals }, null, 2) + "\n"
  );
  fs.writeFileSync(
    path.join(ARTIFACTS, "transaction_unshield_fixture.json"),
    JSON.stringify({ proof: unshield.proof, publicSignals: unshield.publicSignals }, null, 2) + "\n"
  );

  const meta = {
    circuit: "transaction",
    scheme: "2-in/2-out JoinSplit (Tornado-Nova style)",
    merkleDepth: MERKLE_DEPTH,
    maxAmountBits: MAX_AMOUNT_BITS,
    fieldSize: FIELD_SIZE.toString(),
    publicInputOrder: transfer.order,
    nPublic: transfer.publicSignals.length,
    note: "publicAmount is signed with the FIELD_SIZE offset: withdraw v -> FIELD_SIZE - v.",
  };
  fs.writeFileSync(
    path.join(ARTIFACTS, "transaction_fixture_meta.json"),
    JSON.stringify(meta, null, 2) + "\n"
  );

  fs.rmSync(tmp, { recursive: true, force: true });

  console.log("\nWrote:");
  console.log("  artifacts/transaction_proof_fixture.json   (TRANSFER, canonical)");
  console.log("  artifacts/transaction_shield_fixture.json");
  console.log("  artifacts/transaction_unshield_fixture.json");
  console.log("  artifacts/transaction_fixture_meta.json");
  console.log(`\npublic-input order: ${transfer.order.join(", ")}`);
  console.log(`nPublic = ${transfer.publicSignals.length}  ->  vk_ic has ${transfer.publicSignals.length + 1} entries`);

  process.exit(0); // snarkjs keeps worker threads alive
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
