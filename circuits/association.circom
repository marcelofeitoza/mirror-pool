pragma circom 2.1.6;

// mirror-pool association circuit (Privacy-Pools-style set membership).
//
// This is the OPT-IN compliance statement. It proves everything the membership
// circuit proves, AND additionally that the very same commitment is a leaf of a
// second, CURATED tree published by a curator - all without revealing which leaf
// it is in either tree.
//
// In plain words the prover says:
//
//   "One of the deposits in this pool is mine, and it is also one of the
//    deposits in the set this curator vouches for. I will not tell you which."
//
// That is the Privacy Pools association-set idea (Buterin, Illum, Nadler,
// Schaer, Soleimani): an honest user dissociates from funds a curator has
// excluded WITHOUT giving up anonymity inside the remaining set.
//
// The scheme is deliberately additive. It is a SEPARATE circuit with its own
// proving/verifying key and its own on-chain instruction; the deployed
// `membership.circom` statement, its key, and its settle path are untouched, so
// a user who wants nothing to do with a curator keeps settling exactly as
// before. See docs/COMPLIANCE.md for the trust and censorship analysis.
//
// Commitment scheme, identical to membership.circom (the on-chain accumulator
// and the off-chain crates MUST match this exact Poseidon input order):
//
//   commitment    = Poseidon(secret, actionHash, epoch)   // leaf of BOTH trees
//   nullifierHash = Poseidon(secret, epoch)               // epoch-scoped tag
//
// PUBLIC INPUTS (5), in this exact declaration order:
//
//   [0] root             pool accumulator root; the same recent-root ring the
//                        plain membership path checks against
//   [1] nullifierHash    Poseidon(secret, epoch); the epoch-scoped double-spend tag
//   [2] actionHash       binds (recipient, amount) so a relay cannot redirect
//   [3] epoch            32-byte big-endian encoding of the u64 epoch id
//   [4] associationRoot  root of the curator's curated leaf set
//
// The first four are byte-for-byte the membership circuit's public inputs in the
// same order, so the on-chain wire layout is a strict EXTENSION of SettleZk's:
// one extra 32-byte public input appended. Nothing else is added, because
// nothing else has to be: the curator's identity is carried by the on-chain
// account the root was read from, not by the proof, which keeps the public-input
// count (and therefore the on-chain verification cost) minimal.
//
// LIMITS, stated plainly. The anonymity this gives you is the SIZE OF THE
// INTERSECTION of the pool tree and the association tree. A curator who
// publishes a root over a single leaf learns exactly who settled against it. The
// circuit cannot and does not defend against that; only a large, honestly
// curated set can. See docs/COMPLIANCE.md.
//
// MIT licensed. Clean-room; depends only on circomlib (public).

include "circomlib/circuits/poseidon.circom";
// HashLeftRight / PathSelector / MerkleProof(depth), shared VERBATIM with
// membership.circom so both circuits recompute a root the same way.
include "merkle.circom";

// Top-level association statement.
//
// Public  inputs: root, nullifierHash, actionHash, epoch, associationRoot
// Private inputs: secret,
//                 pathElements[depth],      pathIndices[depth],       (pool tree)
//                 assocPathElements[depth], assocPathIndices[depth]   (curated tree)
template Association(depth) {
    // --- public ---
    signal input root;
    signal input nullifierHash;
    signal input actionHash;
    signal input epoch;
    signal input associationRoot;

    // --- private ---
    signal input secret;
    signal input pathElements[depth];
    signal input pathIndices[depth];
    signal input assocPathElements[depth];
    signal input assocPathIndices[depth];

    // 1. Recompute the committed leaf: commitment = Poseidon(secret, actionHash, epoch).
    //    ONE commitment feeds BOTH inclusion proofs below, which is the whole
    //    point: it is what ties "a deposit of mine" to "a deposit the curator
    //    vouches for". Two independent inclusion proofs over two unrelated leaves
    //    would prove nothing.
    component commitmentHasher = Poseidon(3);
    commitmentHasher.inputs[0] <== secret;
    commitmentHasher.inputs[1] <== actionHash;
    commitmentHasher.inputs[2] <== epoch;

    // 2. Bind the epoch-scoped nullifier: nullifierHash == Poseidon(secret, epoch).
    //    Identical to membership.circom, so a commitment settled through the
    //    association path burns the SAME nullifier it would have burned through
    //    the plain path. A user cannot spend once with an association proof and
    //    again without one.
    component nullifierHasher = Poseidon(2);
    nullifierHasher.inputs[0] <== secret;
    nullifierHasher.inputs[1] <== epoch;
    nullifierHash === nullifierHasher.out;

    // 3. Verify Merkle inclusion of the recomputed leaf under the POOL root.
    component merkle = MerkleProof(depth);
    merkle.leaf <== commitmentHasher.out;
    for (var i = 0; i < depth; i++) {
        merkle.pathElements[i] <== pathElements[i];
        merkle.pathIndices[i] <== pathIndices[i];
    }
    root === merkle.root;

    // 4. Verify Merkle inclusion of the SAME leaf under the ASSOCIATION root.
    //    The leaf index in the curated tree is unrelated to the pool leaf index
    //    (the curator lists a subset in its own order), so this needs its own
    //    independent path; only the leaf value is shared.
    component assoc = MerkleProof(depth);
    assoc.leaf <== commitmentHasher.out;
    for (var i = 0; i < depth; i++) {
        assoc.pathElements[i] <== assocPathElements[i];
        assoc.pathIndices[i] <== assocPathIndices[i];
    }
    associationRoot === assoc.root;
}

// MERKLE_DEPTH = 20 for BOTH trees, matching the on-chain accumulator, so the
// same zero ladder and the same host tree code serve both.
// Public signal order is fixed here:
//   root, nullifierHash, actionHash, epoch, associationRoot.
component main {public [root, nullifierHash, actionHash, epoch, associationRoot]} = Association(20);
