pragma circom 2.1.6;

// Shared Poseidon Merkle-inclusion templates.
//
// These templates were originally written inline in `membership.circom` and are
// extracted here VERBATIM so a second circuit can prove inclusion against a
// second tree without a copy-paste fork of the Merkle math. Any circuit that
// includes this file recomputes a root exactly the way the on-chain frontier
// accumulator (`programs/mirror-pool/src/state/merkle.rs`) and the host tree
// (`crates/mirror-cli/src/tree.rs`) do.
//
// ARTIFACT-STABILITY NOTE. Extracting these templates does NOT change the
// compiled constraint system: circom inlines templates at their use site, so
// `membership.circom` compiles to a BYTE-IDENTICAL `.r1cs` before and after the
// extraction. That equality is checked explicitly in `circuits/README.md`'s
// artifact-consistency procedure, because the committed proving/verifying keys
// are bound to the exact r1cs they were generated from and must not drift.
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
