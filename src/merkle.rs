//! AOS Merkle State Tree
//!
//! Provides a Merkle root hash over key-value state entries.
//! Each keyspace maintains its own Merkle root. State transitions
//! produce a new root hash for external verification.

/// Simple SHA-256-like hash (use a lightweight hash for bare metal).
/// For Stage-3, we use a simple FNV-1a 64-bit hash doubled to 128-bit.
/// Full SHA-256 can be added in Stage-4 for cryptographic security.
pub type MerkleHash = [u8; 16]; // 128-bit hash

const MAX_LEAVES: usize = 64;  // Max entries per keyspace
const TREE_SIZE: usize = 128;  // Internal nodes (next power of 2 above MAX_LEAVES)

pub struct MerkleTree {
    /// Leaf hashes (one per key-value entry)
    leaves: [MerkleHash; MAX_LEAVES],
    /// Number of active leaves
    leaf_count: usize,
    /// Root hash (recomputed on every mutation)
    root: MerkleHash,
}

impl MerkleTree {
    pub const fn new() -> Self {
        MerkleTree {
            leaves: [[0u8; 16]; MAX_LEAVES],
            leaf_count: 0,
            root: [0u8; 16],
        }
    }

    /// Update a leaf at the given index with a new key-value hash
    pub fn update_leaf(&mut self, index: usize, key: u64, value: &[u8]) {
        if index >= MAX_LEAVES { return; }
        self.leaves[index] = hash_kv(key, value);
        if index >= self.leaf_count {
            self.leaf_count = index + 1;
        }
        self.recompute_root();
    }

    /// Remove a leaf (set to zero hash)
    pub fn remove_leaf(&mut self, index: usize) {
        if index >= MAX_LEAVES { return; }
        self.leaves[index] = [0u8; 16];
        self.recompute_root();
    }

    /// Get the current Merkle root
    pub fn root(&self) -> &MerkleHash {
        &self.root
    }

    /// Get leaf count
    pub fn leaf_count(&self) -> usize {
        self.leaf_count
    }

    /// Recompute root from leaves (simple binary tree hash)
    fn recompute_root(&mut self) {
        if self.leaf_count == 0 {
            self.root = [0u8; 16];
            return;
        }
        // Build tree bottom-up: hash pairs of nodes
        let mut level: [MerkleHash; TREE_SIZE] = [[0u8; 16]; TREE_SIZE];
        // Copy leaves to bottom level
        for i in 0..self.leaf_count {
            level[i] = self.leaves[i];
        }
        let mut count = self.leaf_count;
        // Round up to next power of 2
        let mut n = 1;
        while n < count { n *= 2; }
        count = n;

        while count > 1 {
            let half = count / 2;
            for i in 0..half {
                level[i] = hash_pair(&level[i * 2], &level[i * 2 + 1]);
            }
            count = half;
        }
        self.root = level[0];
    }

    /// Generate a Merkle proof for a leaf at the given index.
    /// Returns the sibling hashes along the path from leaf to root.
    pub fn proof(&self, index: usize) -> MerkleProof {
        let mut proof = MerkleProof {
            siblings: [[0u8; 16]; 7], // log2(128) = 7 levels max
            depth: 0,
            leaf_index: index,
        };

        if index >= self.leaf_count {
            return proof;
        }

        // Rebuild tree to extract siblings
        let mut level: [MerkleHash; TREE_SIZE] = [[0u8; 16]; TREE_SIZE];
        for i in 0..self.leaf_count {
            level[i] = self.leaves[i];
        }
        let mut count = 1;
        while count < self.leaf_count { count *= 2; }

        let mut idx = index;
        let mut n = count;
        let mut depth = 0;

        while n > 1 && depth < 7 {
            let sibling = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
            if sibling < n {
                proof.siblings[depth] = level[sibling];
            }
            // Compute next level
            let half = n / 2;
            for i in 0..half {
                level[i] = hash_pair(&level[i * 2], &level[i * 2 + 1]);
            }
            idx /= 2;
            n = half;
            depth += 1;
        }
        proof.depth = depth;
        proof
    }
}

/// A Merkle proof: the sibling hashes from leaf to root
pub struct MerkleProof {
    pub siblings: [MerkleHash; 7],
    pub depth: usize,
    pub leaf_index: usize,
}

impl MerkleProof {
    /// Verify this proof against a given root and leaf value
    pub fn verify(&self, root: &MerkleHash, key: u64, value: &[u8]) -> bool {
        let mut hash = hash_kv(key, value);
        let mut idx = self.leaf_index;

        for i in 0..self.depth {
            if idx % 2 == 0 {
                hash = hash_pair(&hash, &self.siblings[i]);
            } else {
                hash = hash_pair(&self.siblings[i], &hash);
            }
            idx /= 2;
        }

        &hash == root
    }
}

/// Hash a key-value pair into a leaf hash
fn hash_kv(key: u64, value: &[u8]) -> MerkleHash {
    let mut data = [0u8; 264]; // 8 (key) + 256 (max value)
    data[0..8].copy_from_slice(&key.to_le_bytes());
    let len = value.len().min(256);
    data[8..8 + len].copy_from_slice(&value[..len]);
    fnv_hash_128(&data[..8 + len])
}

/// Hash two child hashes into a parent hash
fn hash_pair(left: &MerkleHash, right: &MerkleHash) -> MerkleHash {
    let mut data = [0u8; 32];
    data[0..16].copy_from_slice(left);
    data[16..32].copy_from_slice(right);
    fnv_hash_128(&data)
}

/// FNV-1a 128-bit hash (simple, non-cryptographic, suitable for Stage-3)
fn fnv_hash_128(data: &[u8]) -> MerkleHash {
    // FNV-1a with 64-bit, run twice with different offsets for 128-bit
    let h1 = fnv1a_64(data, 0xcbf29ce484222325);
    let h2 = fnv1a_64(data, 0x84222325cbf29ce4); // different seed
    let mut result = [0u8; 16];
    result[0..8].copy_from_slice(&h1.to_le_bytes());
    result[8..16].copy_from_slice(&h2.to_le_bytes());
    result
}

fn fnv1a_64(data: &[u8], offset_basis: u64) -> u64 {
    let mut hash = offset_basis;
    for &byte in data {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

// ─── Per-keyspace Merkle roots ─────────────────────────────────────────────

use crate::agent::{KeyspaceId, MAX_AGENTS};

static mut MERKLE_TREES: [Option<MerkleTree>; MAX_AGENTS] = [const { None }; MAX_AGENTS];

/// Initialize a Merkle tree for a keyspace
pub fn init_tree(keyspace: KeyspaceId) {
    unsafe {
        let idx = keyspace as usize;
        if idx < MAX_AGENTS {
            MERKLE_TREES[idx] = Some(MerkleTree::new());
        }
    }
}

/// Update Merkle tree when a state entry changes
pub fn on_state_put(keyspace: KeyspaceId, entry_index: usize, key: u64, value: &[u8]) {
    unsafe {
        let idx = keyspace as usize;
        if idx < MAX_AGENTS {
            if let Some(ref mut tree) = MERKLE_TREES[idx] {
                tree.update_leaf(entry_index, key, value);
            }
        }
    }
}

/// Get the Merkle root for a keyspace
pub fn get_root(keyspace: KeyspaceId) -> Option<MerkleHash> {
    unsafe {
        let idx = keyspace as usize;
        if idx < MAX_AGENTS {
            if let Some(ref tree) = MERKLE_TREES[idx] {
                return Some(*tree.root());
            }
        }
        None
    }
}

/// Generate a Merkle proof for a specific entry
pub fn generate_proof(keyspace: KeyspaceId, entry_index: usize) -> Option<MerkleProof> {
    unsafe {
        let idx = keyspace as usize;
        if idx < MAX_AGENTS {
            if let Some(ref tree) = MERKLE_TREES[idx] {
                return Some(tree.proof(entry_index));
            }
        }
        None
    }
}
