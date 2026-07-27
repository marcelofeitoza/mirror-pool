pragma circom 2.1.6;

// mirror-pool membership circuit (ZK-deniable initiation).
//
// Proves, in zero knowledge, that a settled action corresponds to SOME member
// committed into the on-chain Poseidon Merkle accumulator, without revealing
// which member. This is the "Tornado Cash for behavior" heart of mirror-pool.
//
// Canonical commitment scheme (the on-chain accumulator and off-chain crates
// MUST match this exact Poseidon input order):
//
//   commitment    = Poseidon(secret, actionHash, epoch)   // the Merkle leaf
//   nullifierHash = Poseidon(secret, epoch)               // epoch-scoped tag
//
// All values are BN254 scalar-field elements. Binding actionHash and epoch as
// PUBLIC inputs is what stops a relay from re-targeting the action or replaying
// a proof across epochs: the proof is only valid for the exact (actionHash,
// epoch) pair the prover committed to.
//
// MIT licensed. Clean-room; depends only on circomlib (public).

include "circomlib/circuits/poseidon.circom";
// HashLeftRight / PathSelector / MerkleProof(depth). Extracted VERBATIM from this
// file so `association.circom` can reuse the identical Merkle math instead of
// forking it. circom inlines templates at their use site, so this extraction
// leaves the compiled `.r1cs` byte-identical (verified; see circuits/README.md).
include "merkle.circom";

// Top-level membership statement.
//
// Public  inputs: root, nullifierHash, actionHash, epoch
// Private inputs: secret, pathElements[depth], pathIndices[depth]
template Membership(depth) {
    // --- public ---
    signal input root;
    signal input nullifierHash;
    signal input actionHash;
    signal input epoch;

    // --- private ---
    signal input secret;
    signal input pathElements[depth];
    signal input pathIndices[depth];

    // 1. Recompute the committed leaf: commitment = Poseidon(secret, actionHash, epoch).
    component commitmentHasher = Poseidon(3);
    commitmentHasher.inputs[0] <== secret;
    commitmentHasher.inputs[1] <== actionHash;
    commitmentHasher.inputs[2] <== epoch;

    // 2. Bind the epoch-scoped nullifier: nullifierHash == Poseidon(secret, epoch).
    component nullifierHasher = Poseidon(2);
    nullifierHasher.inputs[0] <== secret;
    nullifierHasher.inputs[1] <== epoch;
    nullifierHash === nullifierHasher.out;

    // 3. Verify Merkle inclusion of the recomputed leaf under the public root.
    component merkle = MerkleProof(depth);
    merkle.leaf <== commitmentHasher.out;
    for (var i = 0; i < depth; i++) {
        merkle.pathElements[i] <== pathElements[i];
        merkle.pathIndices[i] <== pathIndices[i];
    }
    root === merkle.root;
}

// MERKLE_DEPTH = 20, fixed to match the on-chain accumulator.
// Public signal order is fixed here: root, nullifierHash, actionHash, epoch.
component main {public [root, nullifierHash, actionHash, epoch]} = Membership(20);
