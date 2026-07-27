// Host-side reference implementation of the frontier Merkle accumulator, used to
// cross-check the roots the on-chain accumulator writes.
//
// This is a deliberate second statement of the same algorithm: it keeps the full
// precomputed zeros ladder instead of advancing a running zero hash the way the
// program does, so a transcription error on either side shows up as a root
// mismatch rather than cancelling out.
//
// SCOPE OF THE CHECK. The host hashes with `light-poseidon`; the on-chain side
// hashes with the `sol_poseidon` syscall, and agave implements that syscall on
// top of `light-poseidon` itself. So this is NOT two independent Poseidon
// implementations agreeing. What it does pin, and what the end-to-end soaks
// otherwise only demonstrate implicitly, is the wiring: the same parameter set
// (Bn254X5, width t = 3), the same big-endian byte encoding of field elements,
// the same argument order in `Poseidon(left, right)`, and the same frontier
// insert (which sibling is used at which level, and in which order the two
// output commitments are appended). Independence from circomlib is established
// separately, by the committed circuit fixtures.
//
// Included with `include!` from both test binaries (see `transaction_extra.rs`
// for the same pattern), so the reference exists exactly once.

use ark_bn254::Fr;
use light_poseidon::{Poseidon, PoseidonBytesHasher};

use mirror_pool::state::merkle::DEPTH;

/// `Poseidon(left, right)` over two canonical big-endian BN254 field elements,
/// in the parameterization the `sol_poseidon` syscall selects on-chain:
/// `Parameters::Bn254X5` (circomlib BN254, width t = 3) and
/// `Endianness::BigEndian`.
pub fn poseidon2(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Poseidon::<Fr>::new_circom(2).expect("circom Poseidon width 2");
    hasher
        .hash_bytes_be(&[left, right])
        .expect("canonical BN254 inputs")
}

/// Append-only frontier accumulator over `DEPTH` levels: the host mirror of
/// `mirror_pool::state::merkle::append_with`.
pub struct HostFrontier {
    /// `zeros[i]` is the root of an all-empty subtree of height `i`.
    zeros: [[u8; 32]; DEPTH + 1],
    /// Recorded left sibling per level (only meaningful where already written).
    filled: [[u8; 32]; DEPTH],
    /// Leaves appended so far (= index of the next leaf).
    count: u64,
    root: [u8; 32],
}

impl HostFrontier {
    /// An empty accumulator: the root is the zero ladder `zeros[DEPTH]`.
    pub fn new() -> Self {
        let mut zeros = [[0u8; 32]; DEPTH + 1];
        for level in 1..=DEPTH {
            zeros[level] = poseidon2(&zeros[level - 1], &zeros[level - 1]);
        }
        HostFrontier {
            filled: [[0u8; 32]; DEPTH],
            count: 0,
            root: zeros[DEPTH],
            zeros,
        }
    }

    /// Append `leaf` and return the new root.
    pub fn append(&mut self, leaf: &[u8; 32]) -> [u8; 32] {
        let mut index = self.count;
        let mut node = *leaf;
        for level in 0..DEPTH {
            node = if index & 1 == 0 {
                // Left child: the right sibling is the empty subtree of this
                // height, and this node becomes the level's left sibling.
                self.filled[level] = node;
                poseidon2(&node, &self.zeros[level])
            } else {
                // Right child: pair with the recorded left sibling.
                poseidon2(&self.filled[level], &node)
            };
            index >>= 1;
        }
        self.count += 1;
        self.root = node;
        node
    }

    /// The current root.
    pub fn root(&self) -> [u8; 32] {
        self.root
    }

    /// The recorded left sibling at `level` (0 = leaf level).
    pub fn filled_subtree(&self, level: usize) -> [u8; 32] {
        self.filled[level]
    }
}
