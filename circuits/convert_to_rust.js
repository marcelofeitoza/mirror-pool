// convert_to_rust.js
//
// Converts the snarkjs verification_key.json and proof_fixture.json into Rust
// byte-array constants in the exact layout the groth16-solana crate (v0.2.0)
// consumes for on-chain verification:
//
//   artifacts/vk.rs             pub const VERIFYINGKEY: Groth16Verifyingkey
//   artifacts/proof_fixture.rs  PROOF_A / PROOF_B / PROOF_C / PUBLIC_INPUTS
//
// Three circuits share this converter:
//   (default)              membership  -> verification_key.json, proof_fixture.json,
//                                         fixture_meta.json -> vk.rs, proof_fixture.rs
//   --circuit=transaction  transaction -> transaction_verification_key.json,
//                                         transaction_proof_fixture.json,
//                                         transaction_fixture_meta.json ->
//                                         transaction_vk.rs, transaction_proof_fixture.rs
//   --circuit=association  association -> association_verification_key.json,
//                                         association_proof_fixture.json,
//                                         association_fixture_meta.json ->
//                                         association_vk.rs, association_proof_fixture.rs
//
// Byte layout (all big-endian, uncompressed - as the alt_bn128 syscalls expect):
//   G1 point  = x_be(32) || y_be(32)                       (64 bytes)
//   G2 point  = x_c1_be(32) || x_c0_be(32) || y_c1_be(32) || y_c0_be(32)  (128 bytes)
//               i.e. each Fp2 coordinate is imaginary-part-first.
//   field elt = value_be(32)
//
// PROOF_A is emitted ALREADY NEGATED, because Groth16Verifier::new expects the
// negated A (the pairing check uses e(-A, B) * ... == 1 and does not negate A
// internally). Negation is -(x, y) = (x, q - y) over the BN254 base field Fq.
//
// MIT licensed. Clean-room; no external deps (native BigInt only).

const fs = require("fs");
const path = require("path");

const ARTIFACTS = path.join(__dirname, "artifacts");

// BN254 base field (Fq) modulus - used for G1 point negation.
const FQ = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;

// BigInt / decimal-string -> 32-byte big-endian array of numbers.
function toBE32(v) {
  let n = BigInt(v) % FQ;
  if (n < 0n) n += FQ;
  const out = new Array(32).fill(0);
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
}

// G1 = [x, y, "1"] -> x_be || y_be  (64 bytes)
function g1(p) {
  return [...toBE32(p[0]), ...toBE32(p[1])];
}
// G1 negated = x_be || (q - y)_be  (64 bytes)
function g1Neg(p) {
  const negY = (FQ - (BigInt(p[1]) % FQ)) % FQ;
  return [...toBE32(p[0]), ...toBE32(negY)];
}
// G2 = [[x0, x1], [y0, y1], ...] -> x1_be || x0_be || y1_be || y0_be  (128 bytes)
function g2(p) {
  return [
    ...toBE32(p[0][1]), ...toBE32(p[0][0]),
    ...toBE32(p[1][1]), ...toBE32(p[1][0]),
  ];
}

// Pretty-print a flat byte array as a Rust literal body, 12 bytes per line.
function fmtBytes(bytes, indent) {
  const lines = [];
  for (let i = 0; i < bytes.length; i += 12) {
    lines.push(indent + bytes.slice(i, i + 12).join(", ") + ",");
  }
  return lines.join("\n");
}

function main() {
  // Optional --circuit=<name>. Default (membership) keeps the original filenames;
  // --circuit=transaction / --circuit=association read/write the prefixed artifacts.
  const circuitArg = process.argv.slice(2).find((a) => a.startsWith("--circuit="));
  const circuit = circuitArg ? circuitArg.slice("--circuit=".length) : "membership";

  // One table instead of nested ternaries, so adding a fourth circuit is a row.
  const CIRCUITS = {
    membership: {
      vkFile: "verification_key.json",
      fixtureFile: "proof_fixture.json",
      metaFile: "fixture_meta.json",
      vkRsFile: "vk.rs",
      proofRsFile: "proof_fixture.rs",
      label: "mirror-pool membership",
    },
    transaction: {
      vkFile: "transaction_verification_key.json",
      fixtureFile: "transaction_proof_fixture.json",
      metaFile: "transaction_fixture_meta.json",
      vkRsFile: "transaction_vk.rs",
      proofRsFile: "transaction_proof_fixture.rs",
      label: "mirror-pool transaction (2-in/2-out JoinSplit)",
    },
    association: {
      vkFile: "association_verification_key.json",
      fixtureFile: "association_proof_fixture.json",
      metaFile: "association_fixture_meta.json",
      vkRsFile: "association_vk.rs",
      proofRsFile: "association_proof_fixture.rs",
      label: "mirror-pool association (opt-in curated-set membership)",
    },
  };

  const spec = CIRCUITS[circuit];
  if (!spec) {
    console.error(
      `unknown --circuit=${circuit}; expected one of ${Object.keys(CIRCUITS).join(", ")}`
    );
    process.exit(1);
  }
  const { vkFile, fixtureFile, metaFile, vkRsFile, proofRsFile, label } = spec;

  const vk = JSON.parse(fs.readFileSync(path.join(ARTIFACTS, vkFile), "utf8"));
  const fixture = JSON.parse(fs.readFileSync(path.join(ARTIFACTS, fixtureFile), "utf8"));
  const meta = JSON.parse(fs.readFileSync(path.join(ARTIFACTS, metaFile), "utf8"));

  const nPublic = vk.nPublic;
  const order = meta.publicInputOrder;

  // ---------- vk.rs ----------
  const alpha = g1(vk.vk_alpha_1);
  const beta = g2(vk.vk_beta_2);
  const gamma = g2(vk.vk_gamma_2);
  const delta = g2(vk.vk_delta_2);
  const ic = vk.IC.map((p) => g1(p)); // length = nPublic + 1

  let s = "";
  s += "// @generated by convert_to_rust.js - DO NOT EDIT BY HAND.\n";
  s += `// ${label} verifying key, groth16-solana v0.2.0 layout.\n`;
  s += "// All big-endian, uncompressed. G1 = x||y (64B). G2 = x_c1||x_c0||y_c1||y_c0 (128B).\n";
  s += "// DEV/TEST trusted setup - reproducible, NOT from a secure ceremony.\n";
  s += `// Public inputs (${nPublic}), in order: ${order.join(", ")}.\n`;
  s += "// vk_ic has nPublic + 1 = " + ic.length + " entries (IC[0] is the constant term).\n";
  s += "use groth16_solana::groth16::Groth16Verifyingkey;\n\n";
  s += "pub const VERIFYINGKEY: Groth16Verifyingkey = Groth16Verifyingkey {\n";
  s += `    nr_pubinputs: ${nPublic},\n\n`;
  s += "    vk_alpha_g1: [\n" + fmtBytes(alpha, "        ") + "\n    ],\n\n";
  s += "    vk_beta_g2: [\n" + fmtBytes(beta, "        ") + "\n    ],\n\n";
  // NOTE: 'vk_gamme_g2' spelling matches the (typo'd) field name in groth16-solana 0.2.0.
  s += "    vk_gamme_g2: [\n" + fmtBytes(gamma, "        ") + "\n    ],\n\n";
  s += "    vk_delta_g2: [\n" + fmtBytes(delta, "        ") + "\n    ],\n\n";
  s += "    vk_ic: &[\n";
  for (const entry of ic) {
    s += "        [\n" + fmtBytes(entry, "            ") + "\n        ],\n";
  }
  s += "    ],\n";
  s += "};\n";
  fs.writeFileSync(path.join(ARTIFACTS, vkRsFile), s);

  // ---------- proof_fixture.rs ----------
  const proofA = g1Neg(fixture.proof.pi_a);
  const proofB = g2(fixture.proof.pi_b);
  const proofC = g1(fixture.proof.pi_c);
  const publicInputs = fixture.publicSignals.map((x) => toBE32(x));

  let p = "";
  p += "// @generated by convert_to_rust.js - DO NOT EDIT BY HAND.\n";
  p += `// Known-good ${label} proof + public inputs, groth16-solana v0.2.0 layout.\n`;
  p += `// Public inputs (${nPublic}), in order: ${order.join(", ")}.\n`;
  p += "// PROOF_A is ALREADY NEGATED - pass it directly to Groth16Verifier::new.\n";
  p += "//\n";
  p += "// Example on-chain / test usage:\n";
  p += "//   let mut v = Groth16Verifier::new(&PROOF_A, &PROOF_B, &PROOF_C, &PUBLIC_INPUTS, &VERIFYINGKEY)?;\n";
  p += "//   v.verify()?;\n\n";
  p += "pub const PROOF_A: [u8; 64] = [\n" + fmtBytes(proofA, "    ") + "\n];\n\n";
  p += "pub const PROOF_B: [u8; 128] = [\n" + fmtBytes(proofB, "    ") + "\n];\n\n";
  p += "pub const PROOF_C: [u8; 64] = [\n" + fmtBytes(proofC, "    ") + "\n];\n\n";
  p += `pub const PUBLIC_INPUTS: [[u8; 32]; ${publicInputs.length}] = [\n`;
  for (const inp of publicInputs) {
    p += "    [\n" + fmtBytes(inp, "        ") + "\n    ],\n";
  }
  p += "];\n";
  fs.writeFileSync(path.join(ARTIFACTS, proofRsFile), p);

  console.log(`Wrote artifacts/${vkRsFile} and artifacts/${proofRsFile}`);
  console.log(`  nPublic=${nPublic}, vk_ic entries=${ic.length}, public-input order: ${order.join(", ")}`);
}

main();
