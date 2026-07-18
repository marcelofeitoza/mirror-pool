pragma circom 2.1.6;

// mirror-pool transaction circuit (confidential-value shielded UTXOs).
//
// A 2-in / 2-out Groth16 JoinSplit. This is the value-carrying counterpart to
// membership.circom: instead of proving "some committed member acted", it proves
// a balanced spend of shielded value notes (UTXOs) while hiding amounts, owners,
// and which notes were spent. It supports shield (deposit), private transfer,
// and unshield (withdraw) in one universal statement.
//
// Design follows the PUBLIC, open-source Tornado-Nova transaction circuit (the
// standard reference for a Poseidon-based JoinSplit on BN254). Clean-room: this
// file was written from that public specification and depends only on circomlib
// (Poseidon, comparators, bitify, switcher). MIT licensed.
//
// ---------------------------------------------------------------------------
// Canonical value-note scheme (the on-chain program and mirror-core MUST match
// this exact Poseidon input order; all values are BN254 scalar-field elements):
//
//   publicKey  = Poseidon(privateKey)                              // 1-input
//   commitment = Poseidon(amount, publicKey, blinding)            // 3-input, the leaf
//   signature  = Poseidon(privateKey, commitment, merklePathIndices)  // 3-input
//   nullifier  = Poseidon(commitment, merklePathIndices, signature)   // 3-input
//
//   merklePathIndices is the leaf index as a single field element; the circuit
//   decomposes it into `levels` little-endian bits (bit i selects L/R at level i;
//   0 = node is the left child, sibling on the right).
//
//   Internal Merkle nodes: node = Poseidon(left, right)           // 2-input
//   Empty-subtree ladder:  zeros[0] = 0, zeros[i] = Poseidon(zeros[i-1], zeros[i-1])
//   MERKLE_DEPTH = 20 (matches the existing accumulator).
//
// Value conservation (in the field):
//   sum(inAmount) + publicAmount === sum(outAmount)
//   publicAmount is a SIGNED value under the standard FIELD_SIZE offset:
//     deposit  of v : publicAmount = v            (0 <= v < 2^248)
//     withdraw of v : publicAmount = FIELD_SIZE - v  (i.e. -v mod r)
//   The circuit range-binds |publicAmount| < 2^248 via the (mag, sign) witness.
//
// extDataHash: a public input, bound (not recomputed) by the circuit through the
// standard tamper-evidence trick `extDataHash * extDataHash === extDataHashSquare`
// so it cannot be malleated within a proof. It commits, off-chain, to recipient +
// relayer + fee + the encrypted-note payloads. Its preimage/hash is a program
// choice; see TRANSACTION.md.
// ---------------------------------------------------------------------------

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/switcher.circom";

// Poseidon(left, right): one internal Merkle node.
template HashLeftRight() {
    signal input left;
    signal input right;
    signal output hash;

    component h = Poseidon(2);
    h.inputs[0] <== left;
    h.inputs[1] <== right;
    hash <== h.out;
}

// keypair: publicKey = Poseidon(privateKey).
template Keypair() {
    signal input privateKey;
    signal output publicKey;

    component h = Poseidon(1);
    h.inputs[0] <== privateKey;
    publicKey <== h.out;
}

// signature = Poseidon(privateKey, commitment, merklePathIndices).
// Binding the leaf index makes the nullifier position-specific.
template Signature() {
    signal input privateKey;
    signal input commitment;
    signal input merklePathIndices;
    signal output out;

    component h = Poseidon(3);
    h.inputs[0] <== privateKey;
    h.inputs[1] <== commitment;
    h.inputs[2] <== merklePathIndices;
    out <== h.out;
}

// Recomputes a Merkle root from a leaf and its inclusion path. The leaf index is
// supplied as a single field element and decomposed into `levels` bits; bit i is
// the left/right selector at level i (0 => leaf on the left, sibling on the right).
// Internal nodes use Poseidon(left, right).
template MerkleProof(levels) {
    signal input leaf;
    signal input pathElements[levels];
    signal input pathIndices;      // leaf index as a field element
    signal output root;

    component indexBits = Num2Bits(levels);
    indexBits.in <== pathIndices;

    component switcher[levels];
    component hasher[levels];

    for (var i = 0; i < levels; i++) {
        switcher[i] = Switcher();
        switcher[i].L <== i == 0 ? leaf : hasher[i - 1].hash;
        switcher[i].R <== pathElements[i];
        switcher[i].sel <== indexBits.out[i];

        hasher[i] = HashLeftRight();
        hasher[i].left <== switcher[i].outL;
        hasher[i].right <== switcher[i].outR;
    }

    root <== hasher[levels - 1].hash;
}

// Universal JoinSplit with nIns inputs and nOuts outputs over a depth-`levels`
// Poseidon Merkle accumulator. `maxAmountBits` bounds each output amount and the
// magnitude of publicAmount so no field wraparound can forge value.
template Transaction(levels, nIns, nOuts, maxAmountBits) {
    // ----- PUBLIC inputs (declared first, in the exact witness/verifier order) -----
    signal input root;
    signal input publicAmount;                 // signed, FIELD_SIZE-offset encoded
    signal input extDataHash;                  // binds ext data (recipient/relayer/fee/payload)
    signal input inputNullifier[nIns];
    signal input outputCommitment[nOuts];

    // ----- PRIVATE inputs -----
    signal input inAmount[nIns];
    signal input inPrivateKey[nIns];
    signal input inBlinding[nIns];
    signal input inPathIndices[nIns];          // leaf index per input
    signal input inPathElements[nIns][levels];

    signal input outAmount[nOuts];
    signal input outPubkey[nOuts];
    signal input outBlinding[nOuts];

    // publicAmount range witness: publicAmount = mag * (1 - 2*sign), |publicAmount| = mag.
    signal input publicAmountMagnitude;        // = abs(publicAmount)
    signal input publicAmountSign;             // 0 = deposit (>=0), 1 = withdraw (<0)

    // --- verify inputs (spends) ---
    component inKeypair[nIns];
    component inCommitmentHasher[nIns];
    component inSignature[nIns];
    component inNullifierHasher[nIns];
    component inTree[nIns];
    component inCheckRoot[nIns];

    signal inSum[nIns + 1];
    inSum[0] <== 0;

    for (var t = 0; t < nIns; t++) {
        inKeypair[t] = Keypair();
        inKeypair[t].privateKey <== inPrivateKey[t];

        inCommitmentHasher[t] = Poseidon(3);
        inCommitmentHasher[t].inputs[0] <== inAmount[t];
        inCommitmentHasher[t].inputs[1] <== inKeypair[t].publicKey;
        inCommitmentHasher[t].inputs[2] <== inBlinding[t];

        inSignature[t] = Signature();
        inSignature[t].privateKey <== inPrivateKey[t];
        inSignature[t].commitment <== inCommitmentHasher[t].out;
        inSignature[t].merklePathIndices <== inPathIndices[t];

        // nullifier = Poseidon(commitment, merklePathIndices, signature)
        inNullifierHasher[t] = Poseidon(3);
        inNullifierHasher[t].inputs[0] <== inCommitmentHasher[t].out;
        inNullifierHasher[t].inputs[1] <== inPathIndices[t];
        inNullifierHasher[t].inputs[2] <== inSignature[t].out;
        inNullifierHasher[t].out === inputNullifier[t];

        inTree[t] = MerkleProof(levels);
        inTree[t].leaf <== inCommitmentHasher[t].out;
        inTree[t].pathIndices <== inPathIndices[t];
        for (var i = 0; i < levels; i++) {
            inTree[t].pathElements[i] <== inPathElements[t][i];
        }

        // Membership is enforced only for real inputs (amount != 0); a dummy input
        // (amount == 0) skips the root check, letting shields use dummy inputs.
        inCheckRoot[t] = ForceEqualIfEnabled();
        inCheckRoot[t].enabled <== inAmount[t];
        inCheckRoot[t].in[0] <== root;
        inCheckRoot[t].in[1] <== inTree[t].root;

        inSum[t + 1] <== inSum[t] + inAmount[t];
    }

    // --- verify outputs (fresh notes) ---
    component outCommitmentHasher[nOuts];
    component outAmountRange[nOuts];

    signal outSum[nOuts + 1];
    outSum[0] <== 0;

    for (var t = 0; t < nOuts; t++) {
        outCommitmentHasher[t] = Poseidon(3);
        outCommitmentHasher[t].inputs[0] <== outAmount[t];
        outCommitmentHasher[t].inputs[1] <== outPubkey[t];
        outCommitmentHasher[t].inputs[2] <== outBlinding[t];
        outCommitmentHasher[t].out === outputCommitment[t];

        // Range: each output amount must fit in maxAmountBits (prevents overflow).
        outAmountRange[t] = Num2Bits(maxAmountBits);
        outAmountRange[t].in <== outAmount[t];

        outSum[t + 1] <== outSum[t] + outAmount[t];
    }

    // --- publicAmount range + signed decoding ---
    // publicAmountSign is boolean; magnitude fits in maxAmountBits; and
    // publicAmount == magnitude * (1 - 2*sign) reproduces the FIELD_SIZE offset
    // encoding: sign=0 -> +mag, sign=1 -> -mag (= r - mag). Ranges [0,2^b) and
    // (r-2^b, r) are disjoint for b < 253, so the decoding is unambiguous.
    publicAmountSign * (1 - publicAmountSign) === 0;

    component publicAmountRange = Num2Bits(maxAmountBits);
    publicAmountRange.in <== publicAmountMagnitude;

    signal signFactor;
    signFactor <== 1 - 2 * publicAmountSign;
    publicAmount === publicAmountMagnitude * signFactor;

    // --- value conservation: sum(in) + publicAmount == sum(out) ---
    inSum[nIns] + publicAmount === outSum[nOuts];

    // --- no in-transaction double spend: all input nullifiers distinct ---
    var nPairs = nIns * (nIns - 1) / 2;
    component sameNullifier[nPairs > 0 ? nPairs : 1];
    var p = 0;
    for (var i = 0; i < nIns - 1; i++) {
        for (var j = i + 1; j < nIns; j++) {
            sameNullifier[p] = IsEqual();
            sameNullifier[p].in[0] <== inputNullifier[i];
            sameNullifier[p].in[1] <== inputNullifier[j];
            sameNullifier[p].out === 0;
            p++;
        }
    }

    // --- extDataHash tamper-evidence: bind it so it cannot be malleated ---
    signal extDataHashSquare;
    extDataHashSquare <== extDataHash * extDataHash;
}

// MERKLE_DEPTH = 20; 2 inputs, 2 outputs; amounts bounded to 248 bits.
// Public signal order (fixed; the on-chain verifier depends on it):
//   root, publicAmount, extDataHash,
//   inputNullifier[0], inputNullifier[1],
//   outputCommitment[0], outputCommitment[1]   (7 public inputs).
component main {
    public [root, publicAmount, extDataHash, inputNullifier, outputCommitment]
} = Transaction(20, 2, 2, 248);
