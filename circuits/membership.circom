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

// Poseidon(left, right) over two field elements: one internal Merkle node.
template HashLeftRight() {
    signal input left;
    signal input right;
    signal output hash;

    component h = Poseidon(2);
    h.inputs[0] <== left;
    h.inputs[1] <== right;
    hash <== h.out;
}

// Orders a (current, sibling) pair for hashing based on a binary selector `s`.
//   s == 0  -> node is the LEFT child, sibling is the RIGHT child
//   s == 1  -> sibling is the LEFT child, node is the RIGHT child
// `s` is constrained to be exactly 0 or 1.
template PathSelector() {
    signal input in[2]; // in[0] = current node hash, in[1] = provided sibling
    signal input s;     // path index bit
    signal output outL;
    signal output outR;

    // Enforce s is binary.
    s * (1 - s) === 0;

    // Branchless mux:
    //   outL = s ? in[1] : in[0]
    //   outR = s ? in[0] : in[1]
    outL <== (in[1] - in[0]) * s + in[0];
    outR <== (in[0] - in[1]) * s + in[1];
}

// Recomputes a Merkle root from a leaf and its inclusion path.
// Internal nodes use Poseidon(left, right).
template MerkleProof(depth) {
    signal input leaf;
    signal input pathElements[depth];
    signal input pathIndices[depth];
    signal output root;

    component selectors[depth];
    component hashers[depth];

    // cur[i] is the running hash climbing from leaf (cur[0]) to root (cur[depth]).
    signal cur[depth + 1];
    cur[0] <== leaf;

    for (var i = 0; i < depth; i++) {
        selectors[i] = PathSelector();
        selectors[i].in[0] <== cur[i];
        selectors[i].in[1] <== pathElements[i];
        selectors[i].s <== pathIndices[i];

        hashers[i] = HashLeftRight();
        hashers[i].left <== selectors[i].outL;
        hashers[i].right <== selectors[i].outR;

        cur[i + 1] <== hashers[i].hash;
    }

    root <== cur[depth];
}

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
