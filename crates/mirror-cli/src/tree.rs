//! Client-side Poseidon Merkle accumulator: rebuild inclusion paths off-chain.
//!
//! The on-chain Pool account (see the program's `state::pool` / `state::merkle`)
//! stores only the frontier right-edge (`filled_subtrees`, one sibling per
//! level), the running root, and a small recent-root ring. It does NOT store the
//! leaves. So a prover cannot ask the chain for "the path to my leaf"; it must
//! reconstruct it. This module offers the two reconstructions `prove` needs, both
//! hashing with `mirror_core::merkle_node` (circomlib Poseidon over BN254, the
//! exact node hash the circuit and the on-chain accumulator use), so a path this
//! module builds verifies against a root the chain produced:
//!
//! 1. [`incremental_path`] rebuilds the path from the pre-insert frontier
//!    snapshot captured at commit time plus the leaf's index. This is the
//!    "walk the frontier" reconstruction: it needs no other leaf, works on a
//!    Surfpool fork with no historical transactions, and reproduces exactly the
//!    root the on-chain `merkle::append` recorded the instant the leaf landed.
//! 2. [`SparseMerkle`] rebuilds a whole tree from an ordered leaf set (the
//!    "replay the commits" reconstruction) and extracts a path against the
//!    current root. Used by `prove --leaves` and by the unit tests.
//!
//! [`verify_path`] recomputes a root from a leaf and its path, so both builders
//! and the circuit's own recomputation can be cross-checked.
//!
//! # Two leaf domains
//!
//! The accumulator carries leaves from both settlement paths, and they are NOT
//! the same shape. A `CommitDeposit` appends its commitment
//! `Poseidon(secret, actionHash, epoch)` verbatim; a crowd `Commit` appends
//! `mirror_core::crowd_leaf(commitment)`, a domain-wrapped value, because that
//! path escrows nothing and would otherwise be a free way to place a spendable
//! ZK leaf. Both builders here are agnostic - they hash whatever leaves they are
//! given - so the caller owns the distinction:
//!
//! - [`incremental_path`] needs no other leaf at all (it walks the frontier
//!   snapshot), so nothing to do: pass the deposit commitment.
//! - [`SparseMerkle`] replays an ordered leaf set, so any CROWD commitment in
//!   that list must be passed through `mirror_core::crowd_leaf` first, or the
//!   rebuilt root will not match the chain's.

use mirror_core::{merkle_node, Hash32};

/// Tree height. Fixed at 20 to match the on-chain accumulator (`state::merkle`'s
/// `DEPTH`) and the circuit (`circuits/membership.circom`'s `MERKLE_DEPTH`).
pub const DEPTH: usize = 20;

/// The empty-leaf value (a canonical zero field element).
pub const ZERO_LEAF: Hash32 = [0u8; 32];

/// The canonical zero ladder up to `depth`: `zeros[0] = 0`,
/// `zeros[i] = Poseidon(zeros[i-1], zeros[i-1])`. `zeros[i]` is the hash of a
/// completely empty subtree of height `i`, so `zeros[depth]` is the empty-tree
/// root. Byte-identical to the on-chain accumulator's zero ladder.
pub fn zero_ladder(depth: usize) -> Vec<Hash32> {
    let mut zeros = Vec::with_capacity(depth + 1);
    let mut z = ZERO_LEAF;
    zeros.push(z);
    for _ in 0..depth {
        z = merkle_node(&z, &z);
        zeros.push(z);
    }
    zeros
}

/// Recompute the Merkle root implied by `leaf` and its inclusion path.
///
/// `path_indices[level]` is the path bit: `0` means the current node is the LEFT
/// child (sibling on the right), `1` means it is the RIGHT child (sibling on the
/// left) - exactly the convention the circuit's `PathSelector` enforces. Panics
/// only on a caller bug (mismatched slice lengths).
pub fn verify_path(leaf: &Hash32, path_elements: &[Hash32], path_indices: &[u8]) -> Hash32 {
    assert_eq!(
        path_elements.len(),
        path_indices.len(),
        "path elements and indices must have equal length"
    );
    let mut cur = *leaf;
    for (sibling, bit) in path_elements.iter().zip(path_indices.iter()) {
        cur = if *bit == 0 {
            merkle_node(&cur, sibling) // current is the left child
        } else {
            merkle_node(sibling, &cur) // current is the right child
        };
    }
    cur
}

/// The inclusion path of a single leaf: sibling hashes and path bits, leaf to
/// root, plus the resulting root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerklePath {
    pub elements: Vec<Hash32>,
    pub indices: Vec<u8>,
    pub root: Hash32,
}

/// Rebuild a leaf's inclusion path from the frontier snapshot taken the instant
/// before the leaf was appended, without any other leaf.
///
/// `frontier_pre[level]` must be the on-chain `filled_subtrees[level]` read from
/// the Pool account immediately BEFORE this leaf's `Commit` / `CommitDeposit`
/// landed (i.e. the frontier after the previous leaf). This reproduces the exact
/// arithmetic of the on-chain `merkle::append`:
///
/// - at a level where the running index bit is `0` the node is a left child, so
///   its sibling is the empty subtree `zeros[level]` (nothing exists to the
///   right yet) and the bit is `0`;
/// - at a level where the bit is `1` the node is a right child, so its sibling is
///   the recorded left sibling `frontier_pre[level]` and the bit is `1`.
///
/// The returned `root` is therefore byte-identical to the root the chain recorded
/// in its recent-root ring the instant this leaf landed, so `prove` can settle
/// against it for as long as it stays within the ring
/// (`ROOT_HISTORY_SIZE` later appends).
pub fn incremental_path(leaf: &Hash32, leaf_index: u64, frontier_pre: &[Hash32]) -> MerklePath {
    assert_eq!(
        frontier_pre.len(),
        DEPTH,
        "frontier snapshot must have exactly DEPTH siblings"
    );
    let zeros = zero_ladder(DEPTH);
    let mut elements = Vec::with_capacity(DEPTH);
    let mut indices = Vec::with_capacity(DEPTH);
    let mut cur = *leaf;
    let mut idx = leaf_index;
    for level in 0..DEPTH {
        if idx & 1 == 0 {
            elements.push(zeros[level]);
            indices.push(0);
            cur = merkle_node(&cur, &zeros[level]);
        } else {
            elements.push(frontier_pre[level]);
            indices.push(1);
            cur = merkle_node(&frontier_pre[level], &cur);
        }
        idx >>= 1;
    }
    MerklePath {
        elements,
        indices,
        root: cur,
    }
}

/// Append `leaf` at position `count` to a frontier snapshot (`filled_subtrees`),
/// mutating it exactly like the on-chain `merkle::append`, and return the new root.
///
/// This is the non-test counterpart to [`Frontier::append`]. A confidential
/// Transact appends TWO output commitments in one call: out0 lands at index
/// `commitment_count` (its pre-insert frontier is the one read off-chain before the
/// Transact), and out1 lands at `commitment_count + 1` (its pre-insert frontier is
/// the frontier AFTER out0 was appended). This lets the CLI derive out1's frontier
/// snapshot so a later spend can rebuild its inclusion path with
/// [`incremental_path`].
pub fn append_incremental(frontier: &mut [Hash32], count: u64, leaf: &Hash32) -> Hash32 {
    assert_eq!(
        frontier.len(),
        DEPTH,
        "frontier snapshot must have exactly DEPTH siblings"
    );
    let zeros = zero_ladder(DEPTH);
    let mut current_index = count;
    let mut current_hash = *leaf;
    for level in 0..DEPTH {
        if current_index & 1 == 0 {
            frontier[level] = current_hash;
            current_hash = merkle_node(&current_hash, &zeros[level]);
        } else {
            current_hash = merkle_node(&frontier[level], &current_hash);
        }
        current_index >>= 1;
    }
    current_hash
}

/// A sparse Poseidon Merkle tree rebuilt from an ordered leaf set.
///
/// "Sparse" because the right part of the tree is empty: any missing right
/// sibling is the canonical zero subtree for its level, so only the filled prefix
/// is materialized (O(n), not O(2^depth)). This is the "replay every commit"
/// reconstruction; it produces the CURRENT root and a path against it.
pub struct SparseMerkle {
    depth: usize,
    zeros: Vec<Hash32>,
    /// `levels[0]` = leaves, `levels[l+1]` = parents of `levels[l]`.
    levels: Vec<Vec<Hash32>>,
    root: Hash32,
}

impl SparseMerkle {
    /// Build the tree over `leaves` in insertion order (leaf 0 first).
    pub fn from_leaves(depth: usize, leaves: &[Hash32]) -> Self {
        let zeros = zero_ladder(depth);
        let mut levels: Vec<Vec<Hash32>> = Vec::with_capacity(depth + 1);
        levels.push(leaves.to_vec());
        for level in 0..depth {
            let cur = &levels[level];
            let mut next = Vec::with_capacity(cur.len().div_ceil(2));
            let mut i = 0;
            while i < cur.len() {
                let left = cur[i];
                let right = cur.get(i + 1).copied().unwrap_or(zeros[level]);
                next.push(merkle_node(&left, &right));
                i += 2;
            }
            levels.push(next);
        }
        let root = levels[depth].first().copied().unwrap_or(zeros[depth]);
        Self {
            depth,
            zeros,
            levels,
            root,
        }
    }

    /// The current Merkle root (the empty-tree root if there are no leaves).
    /// A natural accessor; the `--leaves` prove path reads the root off the
    /// returned [`MerklePath`], so in the binary this is exercised only by tests.
    #[allow(dead_code)]
    pub fn root(&self) -> Hash32 {
        self.root
    }

    /// The number of leaves inserted.
    pub fn leaf_count(&self) -> usize {
        self.levels[0].len()
    }

    /// The inclusion path of the leaf at `index` against the current root.
    pub fn path(&self, index: usize) -> MerklePath {
        assert!(index < self.leaf_count(), "leaf index out of range");
        let mut elements = Vec::with_capacity(self.depth);
        let mut indices = Vec::with_capacity(self.depth);
        let mut idx = index;
        for level in 0..self.depth {
            let sibling_index = idx ^ 1;
            let sibling = self.levels[level]
                .get(sibling_index)
                .copied()
                .unwrap_or(self.zeros[level]);
            elements.push(sibling);
            indices.push((idx & 1) as u8);
            idx >>= 1;
        }
        MerklePath {
            elements,
            indices,
            root: self.root,
        }
    }
}

/// Simulate the on-chain `merkle::append` to derive the frontier snapshots a
/// prover would have captured at commit time.
///
/// Appending a leaf updates `filled_subtrees` exactly as the program does, so
/// `snapshot()` after appending leaves `0..i` equals the on-chain
/// `filled_subtrees` a participant committing leaf `i` would read immediately
/// before their `Commit` landed. Used by the tests to tie [`incremental_path`] to
/// [`SparseMerkle`] (and thus to the on-chain algorithm) without a validator.
#[cfg(test)]
#[derive(Clone)]
pub struct Frontier {
    depth: usize,
    filled: Vec<Hash32>,
    count: u64,
}

#[cfg(test)]
impl Frontier {
    pub fn new(depth: usize) -> Self {
        Self {
            depth,
            filled: vec![ZERO_LEAF; depth],
            count: 0,
        }
    }

    /// The current frontier (`filled_subtrees`), i.e. the pre-insert snapshot for
    /// the next leaf.
    pub fn snapshot(&self) -> Vec<Hash32> {
        self.filled.clone()
    }

    /// Append one leaf, mutating the frontier exactly like `merkle::append`, and
    /// return the new root.
    pub fn append(&mut self, leaf: &Hash32) -> Hash32 {
        let mut current_index = self.count;
        let mut current_hash = *leaf;
        let mut current_zero = ZERO_LEAF;
        for level in 0..self.depth {
            let (left, right) = if current_index & 1 == 0 {
                self.filled[level] = current_hash;
                (current_hash, current_zero)
            } else {
                (self.filled[level], current_hash)
            };
            current_hash = merkle_node(&left, &right);
            current_zero = merkle_node(&current_zero, &current_zero);
            current_index >>= 1;
        }
        self.count += 1;
        current_hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_tree_root_matches_zero_ladder() {
        let zeros = zero_ladder(DEPTH);
        let tree = SparseMerkle::from_leaves(DEPTH, &[]);
        assert_eq!(
            tree.root(),
            zeros[DEPTH],
            "an empty sparse tree must hash up to the empty-tree root"
        );
    }

    #[test]
    fn sparse_path_verifies_to_root_small_tree() {
        // A small in-memory tree (depth 3), root recomputed with mirror_core.
        const D: usize = 3;
        let leaves: Vec<Hash32> = (1u8..=5).map(|b| [b; 32]).collect();
        let tree = SparseMerkle::from_leaves(D, &leaves);

        for (i, leaf) in leaves.iter().enumerate() {
            let p = tree.path(i);
            assert_eq!(p.elements.len(), D);
            assert_eq!(p.indices.len(), D);
            assert_eq!(
                verify_path(leaf, &p.elements, &p.indices),
                tree.root(),
                "path for leaf {i} must verify to the tree root"
            );
        }
    }

    #[test]
    fn sparse_root_matches_hand_computation() {
        // Depth-2 tree with two leaves: verify against a hand-built root.
        const D: usize = 2;
        let a = [1u8; 32];
        let b = [2u8; 32];
        let tree = SparseMerkle::from_leaves(D, &[a, b]);
        let zeros = zero_ladder(D);
        // level 1: node(a,b) and node(zeros0, zeros0)=zeros1; root = node(that, zeros1).
        let n01 = merkle_node(&a, &b);
        let expected = merkle_node(&n01, &zeros[1]);
        assert_eq!(tree.root(), expected);
    }

    #[test]
    fn append_incremental_matches_test_frontier_and_enables_second_output_path() {
        // append_incremental (non-test) must mutate the frontier and compute the
        // root identically to the test-only Frontier::append, and the mutated
        // frontier must be a valid pre-insert snapshot for the NEXT leaf. This is
        // exactly how the CLI derives the frontier snapshot for a Transact's second
        // output commitment (out1 at index count+1).
        const D: usize = 20;
        let leaves: Vec<Hash32> = (0u8..6).map(|b| [b.wrapping_add(1); 32]).collect();

        let mut reference = Frontier::new(D);
        let mut frontier = vec![ZERO_LEAF; D];
        for (i, leaf) in leaves.iter().enumerate() {
            let ref_root = reference.append(leaf);
            let root = append_incremental(&mut frontier, i as u64, leaf);
            assert_eq!(root, ref_root, "roots must agree at {i}");
            assert_eq!(
                frontier,
                reference.snapshot(),
                "frontiers must agree at {i}"
            );
        }

        // Simulate a Transact appending out0 then out1: out1's pre-insert frontier
        // is the frontier after out0, and incremental_path over it must reproduce
        // the full-rebuild path for out1.
        let count_pre = leaves.len() as u64;
        let out0 = [0x40u8; 32];
        let out1 = [0x41u8; 32];
        let snap0 = frontier.clone(); // pre-insert frontier for out0
        let _ = append_incremental(&mut frontier, count_pre, &out0); // frontier now pre-insert for out1
        let snap1 = frontier.clone();

        let inc0 = incremental_path(&out0, count_pre, &snap0);
        let inc1 = incremental_path(&out1, count_pre + 1, &snap1);

        // inc0 is the path as of out0's insertion (before out1 exists), so it must
        // match a rebuild of leaves-up-to-out0; inc1 matches the final tree.
        let mut with_out0 = leaves.clone();
        with_out0.push(out0);
        let full0 = SparseMerkle::from_leaves(D, &with_out0);
        assert_eq!(inc0.elements, full0.path(count_pre as usize).elements);
        assert_eq!(
            inc0.root,
            full0.root(),
            "out0 path must verify to the post-out0 root"
        );

        let mut all = with_out0.clone();
        all.push(out1);
        let full1 = SparseMerkle::from_leaves(D, &all);
        assert_eq!(inc1.elements, full1.path(count_pre as usize + 1).elements);
        assert_eq!(
            inc1.root,
            full1.root(),
            "out1 path must verify to the final root"
        );
    }

    #[test]
    fn incremental_path_matches_full_rebuild() {
        // Prove that walking the frontier snapshot reproduces the same path and
        // root as rebuilding the whole tree from every leaf up to that index.
        const D: usize = 20;
        let leaves: Vec<Hash32> = (0u8..12).map(|b| [b.wrapping_add(1); 32]).collect();

        let mut frontier = Frontier::new(D);
        for (i, leaf) in leaves.iter().enumerate() {
            let pre = frontier.snapshot(); // frontier BEFORE inserting leaf i
            let snapshot_root = frontier.append(leaf); // append -> new root

            // The full rebuild over leaves[0..=i] is the snapshot the incremental
            // path is proving against (everything to the right of i is empty).
            let full = SparseMerkle::from_leaves(D, &leaves[..=i]);
            assert_eq!(full.root(), snapshot_root, "snapshot root must agree");

            let inc = incremental_path(leaf, i as u64, &pre);
            let full_path = full.path(i);
            assert_eq!(
                inc.indices, full_path.indices,
                "path bits must agree at {i}"
            );
            assert_eq!(
                inc.elements, full_path.elements,
                "path siblings must agree at {i}"
            );
            assert_eq!(
                inc.root, snapshot_root,
                "incremental root must agree at {i}"
            );
            assert_eq!(
                verify_path(leaf, &inc.elements, &inc.indices),
                snapshot_root,
                "incremental path must verify to the snapshot root at {i}"
            );
        }
    }
}
