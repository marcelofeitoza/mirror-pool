// gen_association_fixture.js
//
// Builds a known-good witness for the mirror-pool ASSOCIATION circuit, produces a
// Groth16 proof with snarkjs, verifies it, and writes the fixture the on-chain
// Rust verifier and its tests consume:
//
//   artifacts/association_proof_fixture.json  { proof, publicSignals }
//   artifacts/association_fixture_meta.json   { publicInputOrder, nPublic, scenario }
//
// THE SCENARIO IS THE POINT. Unlike the membership fixture (a single leaf in an
// otherwise-empty tree), this fixture models what an association set actually
// looks like in use:
//
//   - the POOL tree holds 5 deposit commitments, ours at index 3;
//   - the curator's ASSOCIATION tree holds only 3 of those 5, ours at index 1.
//
// Two pool deposits are therefore EXCLUDED by the curator. The proof shows our
// commitment is in the pool AND in the curated subset, and reveals neither which
// pool leaf nor which association leaf it is. Building it this way means the
// committed fixture exercises real, non-empty sibling paths on both sides rather
// than the degenerate all-zeros path.
//
// Every value here is deliberately DIFFERENT from the membership fixture's
// (different secret, epoch, recipient and amount) so an on-chain test that
// accepts this proof cannot be passing by accidentally reusing membership state.
//
// The trees are built with circomlibjs Poseidon, whose constants match the
// circomlib Poseidon inside the circuit, so JS-computed roots equal the
// circuit-recomputed roots.
//
// MIT licensed. Clean-room; circomlibjs + snarkjs only.

const fs = require("fs");
const path = require("path");
const snarkjs = require("snarkjs");
const { buildPoseidon } = require("circomlibjs");

const HERE = __dirname;
const ARTIFACTS = path.join(HERE, "artifacts");
const WASM = path.join(HERE, "association_js", "association.wasm");
const ZKEY = path.join(HERE, "association_final.zkey");
const VK = path.join(ARTIFACTS, "association_verification_key.json");

const MERKLE_DEPTH = 20;

// --- fixed, human-picked field elements for a reproducible fixture ---
// (arbitrary BN254 scalar-field elements; not secret in a real deployment)
const secret = 424242424242000111222333444555666777n;
const epoch = 11n;

// Where our commitment sits in each tree. Both are non-trivial indices with
// mixed path-index bits, so the fixture exercises both branches of PathSelector
// on both trees.
const POOL_LEAF_INDEX = 3; // 0b011
const ASSOC_LEAF_INDEX = 1; // 0b001

// --- the settlement action this membership is bound to ---
// actionHash = Poseidon(recipientHi128, recipientLo128, amount), exactly as
// `mirror_core::transfer_action_hash` and the on-chain `action::transfer_action_hash`
// compute it. RECIPIENT is the 32 bytes 0x21..0x40 (distinct from the membership
// fixture's 0x01..0x20) and AMOUNT is 0.75 SOL.
const RECIPIENT = Buffer.from(Array.from({ length: 32 }, (_, i) => i + 0x21));
const AMOUNT_LAMPORTS = 750000000n; // 0.75 SOL, escrowed at CommitDeposit
const recipientHi = BigInt("0x" + RECIPIENT.subarray(0, 16).toString("hex"));
const recipientLo = BigInt("0x" + RECIPIENT.subarray(16, 32).toString("hex"));

/// Build a depth-`d` sparse Merkle tree over a dense prefix of `leaves` and return
/// { root, path(index) }. Empty positions hash as the canonical zero ladder, which
/// is exactly what the on-chain frontier accumulator and `mirror-cli`'s
/// `SparseMerkle::from_leaves` produce for the same leaf list.
function buildTree(H, depth, leaves) {
  const zeros = [0n];
  for (let i = 1; i <= depth; i++) zeros.push(H([zeros[i - 1], zeros[i - 1]]));

  // level[0] = the dense leaf row; each level up is the pairwise hash, padding a
  // missing right sibling with the zero hash for that level.
  const levels = [leaves.slice()];
  for (let level = 0; level < depth; level++) {
    const cur = levels[level];
    const next = [];
    for (let i = 0; i < cur.length; i += 2) {
      const left = cur[i];
      const right = i + 1 < cur.length ? cur[i + 1] : zeros[level];
      next.push(H([left, right]));
    }
    levels.push(next);
  }
  const root = levels[depth].length > 0 ? levels[depth][0] : zeros[depth];

  const pathFor = (index) => {
    const elements = [];
    const indices = [];
    let idx = index;
    for (let level = 0; level < depth; level++) {
      const bit = idx & 1;
      const siblingIdx = bit === 0 ? idx + 1 : idx - 1;
      const row = levels[level];
      const sibling = siblingIdx < row.length ? row[siblingIdx] : zeros[level];
      elements.push(sibling);
      indices.push(bit);
      idx >>= 1;
    }
    return { elements, indices };
  };

  return { root, pathFor, zeros };
}

/// Recompute a root from a leaf and its path, the way the circuit does, so the
/// generator self-checks its own tree math before it costs a proof.
function walkPath(H, leaf, elements, indices) {
  let cur = leaf;
  for (let i = 0; i < elements.length; i++) {
    cur = indices[i] === 0 ? H([cur, elements[i]]) : H([elements[i], cur]);
  }
  return cur;
}

async function main() {
  const poseidon = await buildPoseidon();
  const F = poseidon.F;
  const H = (arr) => F.toObject(poseidon(arr)); // hash BigInt[] -> BigInt

  // actionHash = Poseidon(recipientHi128, recipientLo128, amount).
  const actionHash = H([recipientHi, recipientLo, AMOUNT_LAMPORTS]);

  // commitment = Poseidon(secret, actionHash, epoch)   (the leaf of BOTH trees)
  const commitment = H([secret, actionHash, epoch]);
  // nullifierHash = Poseidon(secret, epoch)
  const nullifierHash = H([secret, epoch]);

  // The POOL tree: 5 deposits, ours at POOL_LEAF_INDEX. The other four are
  // arbitrary distinct field elements standing in for other participants'
  // commitments (their preimages are irrelevant to this proof).
  const otherPoolLeaves = [
    1111111111111111111111111111111111n,
    2222222222222222222222222222222222n,
    3333333333333333333333333333333333n,
    4444444444444444444444444444444444n,
  ];
  const poolLeaves = [];
  let k = 0;
  for (let i = 0; i < 5; i++) {
    poolLeaves.push(i === POOL_LEAF_INDEX ? commitment : otherPoolLeaves[k++]);
  }

  // The curator's ASSOCIATION tree: a curated SUBSET of the pool leaves. The
  // curator vouches for pool leaves 0, 3 (ours) and 4, and EXCLUDES pool leaves
  // 1 and 2. Ours lands at ASSOC_LEAF_INDEX in the curated ordering.
  const assocLeaves = [poolLeaves[0], commitment, poolLeaves[4]];
  if (assocLeaves[ASSOC_LEAF_INDEX] !== commitment) {
    throw new Error("fixture bug: our commitment is not at ASSOC_LEAF_INDEX");
  }

  const poolTree = buildTree(H, MERKLE_DEPTH, poolLeaves);
  const assocTree = buildTree(H, MERKLE_DEPTH, assocLeaves);
  const poolPath = poolTree.pathFor(POOL_LEAF_INDEX);
  const assocPath = assocTree.pathFor(ASSOC_LEAF_INDEX);

  // Self-check both paths before proving.
  const poolWalk = walkPath(H, commitment, poolPath.elements, poolPath.indices);
  if (poolWalk !== poolTree.root) throw new Error("pool path does not walk to the pool root");
  const assocWalk = walkPath(H, commitment, assocPath.elements, assocPath.indices);
  if (assocWalk !== assocTree.root) {
    throw new Error("association path does not walk to the association root");
  }

  const input = {
    root: poolTree.root.toString(),
    nullifierHash: nullifierHash.toString(),
    actionHash: actionHash.toString(),
    epoch: epoch.toString(),
    associationRoot: assocTree.root.toString(),
    secret: secret.toString(),
    pathElements: poolPath.elements.map((x) => x.toString()),
    pathIndices: poolPath.indices.map((x) => x.toString()),
    assocPathElements: assocPath.elements.map((x) => x.toString()),
    assocPathIndices: assocPath.indices.map((x) => x.toString()),
  };

  console.log("Association fixture inputs:");
  console.log("  commitment (leaf) =", commitment.toString());
  console.log("  pool root         =", poolTree.root.toString());
  console.log("  association root  =", assocTree.root.toString());
  console.log("  nullifierHash     =", nullifierHash.toString());
  console.log("  actionHash        =", actionHash.toString());
  console.log("  epoch             =", epoch.toString());
  console.log("  pool leaves       =", poolLeaves.length, "(ours at", POOL_LEAF_INDEX + ")");
  console.log("  assoc leaves      =", assocLeaves.length, "(ours at", ASSOC_LEAF_INDEX + ")");

  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);

  console.log("\npublicSignals (order emitted by snarkjs):");
  publicSignals.forEach((s, i) => console.log(`  [${i}] ${s}`));

  // Label the public-signal order by matching against the known input values.
  const known = new Map([
    [poolTree.root.toString(), "root"],
    [nullifierHash.toString(), "nullifierHash"],
    [actionHash.toString(), "actionHash"],
    [epoch.toString(), "epoch"],
    [assocTree.root.toString(), "associationRoot"],
  ]);
  const order = publicSignals.map((s) => known.get(s) || "unknown");
  console.log("\npublic-input order:", order.join(", "));
  if (order.includes("unknown")) {
    throw new Error("could not label every public signal; refusing to write an ambiguous fixture");
  }

  const vk = JSON.parse(fs.readFileSync(VK, "utf8"));
  const ok = await snarkjs.groth16.verify(vk, publicSignals, proof);
  if (!ok) {
    console.error("\nsnarkjs.groth16.verify: FAILED");
    process.exit(1);
  }
  console.log("\nsnarkjs.groth16.verify (in-process): OK");

  fs.writeFileSync(
    path.join(ARTIFACTS, "association_proof_fixture.json"),
    JSON.stringify({ proof, publicSignals }, null, 2) + "\n"
  );
  fs.writeFileSync(
    path.join(ARTIFACTS, "association_fixture_meta.json"),
    JSON.stringify(
      {
        publicInputOrder: order,
        nPublic: publicSignals.length,
        scenario: {
          note: "5 pool deposits, curator vouches for 3 of them (pool leaves 0, 3, 4); ours is pool leaf 3 / association leaf 1",
          secret: secret.toString(),
          epoch: Number(epoch),
          amountLamports: Number(AMOUNT_LAMPORTS),
          recipientHex: RECIPIENT.toString("hex"),
          poolLeafIndex: POOL_LEAF_INDEX,
          assocLeafIndex: ASSOC_LEAF_INDEX,
          poolLeaves: poolLeaves.map((x) => x.toString()),
          assocLeaves: assocLeaves.map((x) => x.toString()),
        },
      },
      null,
      2
    ) + "\n"
  );
  console.log(
    "\nWrote artifacts/association_proof_fixture.json, artifacts/association_fixture_meta.json"
  );

  // snarkjs keeps worker threads alive; exit explicitly.
  process.exit(0);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
