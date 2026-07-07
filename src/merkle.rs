//! SHA3-256 Merkle tree for binding the sequence of SIS hiding commitments
//! `{u_i = b * d_i}`.
//!
//! Leaf hashing: `H(0x00 || serialize(u_i))`.
//! Internal node: `H(0x01 || left || right)`.
//!
//! The tree root (32 bytes) is the public CPC commitment `com`.

use sha3::{Digest, Sha3_256};

/// 32-byte Merkle root / hash output.
pub type Hash = [u8; 32];

/// A Merkle tree over `L` leaves, each a serialized `Poly` (`u_i`).
///
/// Internally the tree is padded to the next power of two with empty-hash
/// leaves; this is invisible to callers.
pub struct MerkleTree {
    /// All nodes, level-order: `[leaves..., parents..., ..., root]`.
    nodes: Vec<Hash>,
    /// Number of *real* leaves (before padding).
    leaf_count: usize,
}

/// Authentication path for one leaf.
///
/// Carries the leaf index so that verification can recompute direction bits
/// without an extra parameter.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone)]
pub struct MerklePath {
    /// Leaf index in `[0, leaf_count)`.
    pub index: usize,
    /// Sibling hashes from leaf level up to (but not including) the root.
    pub siblings: Vec<Hash>,
}

/// Hash a leaf: `H(0x00 || leaf_bytes)`.
fn hash_leaf(leaf: &[u8]) -> Hash {
    let mut h = Sha3_256::new();
    h.update([0x00]);
    h.update(leaf);
    let out = h.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(&out);
    r
}

/// Hash an internal node: `H(0x01 || left || right)`.
fn hash_pair(left: &Hash, right: &Hash) -> Hash {
    let mut h = Sha3_256::new();
    h.update([0x01]);
    h.update(left);
    h.update(right);
    let out = h.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(&out);
    r
}

impl MerkleTree {
    /// Build a tree from raw leaf bytes (each entry = `Poly::to_bytes(u_i)`).
    ///
    /// The tree is padded to the next power of two with all-zero placeholder
    /// hashes. These padding leaves are never exposed via [`generate_path`]
    /// (which rejects out-of-range indices).
    pub fn build(leaves: &[Vec<u8>]) -> Self {
        assert!(!leaves.is_empty(), "MerkleTree::build: at least one leaf required");
        let leaf_count = leaves.len();
        let padded = leaf_count.next_power_of_two();
        let mut nodes: Vec<Hash> = Vec::with_capacity(2 * padded);
        // Leaf level (with padding).
        for i in 0..padded {
            if i < leaf_count {
                nodes.push(hash_leaf(&leaves[i]));
            } else {
                nodes.push([0u8; 32]);
            }
        }
        // Build internal levels bottom-up.
        let mut level_start = 0usize;
        let mut level_size = padded;
        while level_size > 1 {
            for i in 0..level_size / 2 {
                let left = nodes[level_start + 2 * i];
                let right = nodes[level_start + 2 * i + 1];
                nodes.push(hash_pair(&left, &right));
            }
            level_start += level_size;
            level_size /= 2;
        }
        Self { nodes, leaf_count }
    }

    /// The 32-byte Merkle root (the CPC commitment `com`).
    pub fn root(&self) -> Hash {
        *self
            .nodes
            .last()
            .expect("MerkleTree invariant: at least one node (the root)")
    }

    /// Number of real leaves.
    pub fn leaf_count(&self) -> usize {
        self.leaf_count
    }

    /// Authentication path for leaf `index`.
    ///
    /// Panics if `index >= leaf_count`.
    pub fn generate_path(&self, index: usize) -> MerklePath {
        assert!(
            index < self.leaf_count,
            "MerkleTree::generate_path: index {} out of range (leaf_count={})",
            index,
            self.leaf_count
        );
        let padded = self.leaf_count.next_power_of_two();
        let mut siblings = Vec::with_capacity(padded.trailing_zeros() as usize);
        let mut idx = index;
        let mut level_start = 0usize;
        let mut level_size = padded;
        while level_size > 1 {
            let sibling = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
            siblings.push(self.nodes[level_start + sibling]);
            idx /= 2;
            level_start += level_size;
            level_size /= 2;
        }
        MerklePath { index, siblings }
    }
}

/// Verify that `leaf_bytes` is the leaf at `path.index` under `root`.
///
/// Recomputes the leaf hash as `H(0x00 || leaf_bytes)`, then walks the
/// sibling list using direction bits from `path.index`, recomputing the
/// root and comparing.
pub fn verify_path(root: &Hash, leaf_bytes: &[u8], path: &MerklePath) -> bool {
    let mut h = hash_leaf(leaf_bytes);
    let mut idx = path.index;
    for &sibling in &path.siblings {
        if idx % 2 == 0 {
            h = hash_pair(&h, &sibling);
        } else {
            h = hash_pair(&sibling, &h);
        }
        idx /= 2;
    }
    h == *root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_and_verify_round_trip() {
        let leaves: Vec<Vec<u8>> = (0..8).map(|i| vec![i as u8; 32]).collect();
        let tree = MerkleTree::build(&leaves);
        let root = tree.root();
        for i in 0..8 {
            let path = tree.generate_path(i);
            assert!(verify_path(&root, &leaves[i], &path), "valid path for leaf {i} must verify");
        }
        // Tampered leaf rejected.
        let path = tree.generate_path(3);
        let mut bad = leaves[3].clone();
        bad[0] ^= 0xFF;
        assert!(!verify_path(&root, &bad, &path), "tampered leaf must be rejected");
        // Wrong leaf under existing path rejected.
        let path3 = tree.generate_path(3);
        assert!(!verify_path(&root, &leaves[5], &path3), "leaf 5 under path 3 must be rejected");
    }
}
