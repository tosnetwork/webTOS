//! ATOS State Object Subsystem
//!
//! Implements an in-memory key-value subsystem organized into keyspaces.
//! Each agent is automatically assigned a private keyspace at creation.
//! Access to any keyspace requires the corresponding CAP_STATE_READ or
//! CAP_STATE_WRITE capability. An agent always has implicit access to
//! its own private keyspace.

use crate::agent::{KeyspaceId, MAX_AGENTS, E_INVALID_ARG, E_NOT_FOUND, E_QUOTA_EXCEEDED, E_PAYLOAD_TOO_LARGE};
use crate::merkle::{self, MerkleHash};

const MAX_ENTRIES_PER_KEYSPACE: usize = 64;
const MAX_VALUE_SIZE: usize = 256;

// ─── State entry ────────────────────────────────────────────────────────────

#[derive(Clone)]
struct StateEntry {
    key: u64,
    value: [u8; MAX_VALUE_SIZE],
    len: usize,
    active: bool,
}

impl StateEntry {
    const fn empty() -> Self {
        StateEntry {
            key: 0,
            value: [0u8; MAX_VALUE_SIZE],
            len: 0,
            active: false,
        }
    }
}

// ─── Encryption context ─────────────────────────────────────────────────────

/// Encryption context for sealed keyspaces.
///
/// Uses simple XOR-based encryption as a placeholder.  Real crypto would use
/// AES or similar, but the API surface is identical.
pub struct KeyspaceEncryption {
    pub enabled: bool,
    pub key: [u8; 32],
}

// ─── State access mode ─────────────────────────────────────────────────────

/// How state is handled during cross-node agent migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateAccessMode {
    /// State moves with the agent to the new node.
    MoveWithAgent,
    /// State stays on the original node, accessed via remote broker.
    RemoteBroker,
    /// State is snapshot'd, agent gets a copy, reconcile later.
    SnapshotAndReconcile,
}

// ─── Keyspace ───────────────────────────────────────────────────────────────

/// Maximum number of version roots retained in history.
const MAX_ROOT_HISTORY: usize = 16;

struct Keyspace {
    id: KeyspaceId,
    entries: [StateEntry; MAX_ENTRIES_PER_KEYSPACE],
    /// Monotonically increasing version counter, advanced on each commit.
    pub version: u32,
    /// Ring buffer of the last `MAX_ROOT_HISTORY` version roots.
    pub root_history: [(u32, MerkleHash); MAX_ROOT_HISTORY],
    /// Number of entries written into `root_history` (capped at `MAX_ROOT_HISTORY`).
    pub root_history_count: u8,
}

impl Keyspace {
    fn new(id: KeyspaceId) -> Self {
        Keyspace {
            id,
            entries: [const { StateEntry::empty() }; MAX_ENTRIES_PER_KEYSPACE],
            version: 0,
            root_history: [(0u32, [0u8; 16]); MAX_ROOT_HISTORY],
            root_history_count: 0,
        }
    }

    /// Compute the current Merkle root for this keyspace by delegating to the
    /// global Merkle tree table.
    fn compute_root(&self) -> MerkleHash {
        merkle::get_root(self.id).unwrap_or([0u8; 16])
    }

    /// Advance the version counter and snapshot the current Merkle root into
    /// the history ring buffer.
    pub fn advance_version(&mut self) {
        self.version = self.version.wrapping_add(1);
        let root = self.compute_root();
        let idx = if (self.root_history_count as usize) < MAX_ROOT_HISTORY {
            let i = self.root_history_count as usize;
            self.root_history_count += 1;
            i
        } else {
            // Ring-buffer wrap: overwrite oldest entry
            ((self.version as usize).wrapping_sub(1)) % MAX_ROOT_HISTORY
        };
        self.root_history[idx] = (self.version, root);
    }

    /// Return the current version number.
    pub fn get_version(&self) -> u32 {
        self.version
    }

    /// Look up a historical root by version number.
    pub fn get_historical_root(&self, version: u32) -> Option<MerkleHash> {
        let count = self.root_history_count as usize;
        for i in 0..count {
            if self.root_history[i].0 == version {
                return Some(self.root_history[i].1);
            }
        }
        None
    }

    /// Encrypt a value before storing (XOR placeholder).
    pub fn encrypt_value(&self, value: &mut [u8], enc: &KeyspaceEncryption) {
        if !enc.enabled { return; }
        for (i, b) in value.iter_mut().enumerate() {
            *b ^= enc.key[i % 32];
        }
    }

    /// Decrypt a value after loading (XOR is symmetric).
    pub fn decrypt_value(&self, value: &mut [u8], enc: &KeyspaceEncryption) {
        // XOR is symmetric
        self.encrypt_value(value, enc);
    }

    fn get(&self, key: u64) -> Option<&[u8]> {
        for entry in self.entries.iter() {
            if entry.active && entry.key == key {
                return Some(&entry.value[..entry.len]);
            }
        }
        None
    }

    fn put(&mut self, key: u64, value: &[u8]) -> Result<usize, i64> {
        if value.len() > MAX_VALUE_SIZE {
            return Err(E_PAYLOAD_TOO_LARGE);
        }

        // Try to find an existing entry with this key
        for (i, entry) in self.entries.iter_mut().enumerate() {
            if entry.active && entry.key == key {
                entry.value[..value.len()].copy_from_slice(value);
                entry.len = value.len();
                return Ok(i); // return entry index for Merkle update
            }
        }

        // Find a free slot
        for (i, entry) in self.entries.iter_mut().enumerate() {
            if !entry.active {
                entry.key = key;
                entry.value[..value.len()].copy_from_slice(value);
                entry.len = value.len();
                entry.active = true;
                return Ok(i); // return entry index for Merkle update
            }
        }

        Err(E_QUOTA_EXCEEDED)
    }
}

// ─── Global keyspace table ──────────────────────────────────────────────────

// Safety: single-core, no preemption during state access in Stage-1.
static mut KEYSPACES: [Option<Keyspace>; MAX_AGENTS] = [const { None }; MAX_AGENTS];

// ─── Public API ─────────────────────────────────────────────────────────────

/// Create a new keyspace with the given ID.
pub fn create_keyspace(id: KeyspaceId) -> Result<(), i64> {
    // Safety: single-core, no preemption during state access
    unsafe {
        let idx = id as usize;
        if idx >= MAX_AGENTS {
            return Err(E_INVALID_ARG);
        }
        if KEYSPACES[idx].is_some() {
            return Err(E_INVALID_ARG);
        }
        KEYSPACES[idx] = Some(Keyspace::new(id));
        merkle::init_tree(id);
        Ok(())
    }
}

/// Destroy a keyspace and free its slot.
pub fn destroy_keyspace(id: KeyspaceId) {
    // Safety: single-core, no preemption during state access
    unsafe {
        let idx = id as usize;
        if idx < MAX_AGENTS {
            KEYSPACES[idx] = None;
        }
    }
}

/// Get a value by key from an agent's keyspace.
///
/// The keyspace is identified by the agent's ID (1:1 binding in Stage-1).
/// Returns `Some(slice)` if the key is found, `None` otherwise.
///
/// This is the API used by syscall.rs for SYS_STATE_GET.
pub fn get(keyspace: KeyspaceId, key: u64) -> Option<&'static [u8]> {
    // Safety: single-core, no preemption during state access
    unsafe {
        let idx = keyspace as usize;
        if idx >= MAX_AGENTS {
            return None;
        }
        match KEYSPACES[idx].as_ref() {
            Some(ks) => ks.get(key),
            None => None,
        }
    }
}

/// Put a value by key into an agent's keyspace.
///
/// The keyspace is identified by the agent's ID (1:1 binding in Stage-1).
/// Creates the entry if it doesn't exist, overwrites if it does.
///
/// This is the API used by syscall.rs for SYS_STATE_PUT.
pub fn put(keyspace: KeyspaceId, key: u64, value: &[u8]) -> Result<(), i64> {
    // Safety: single-core, no preemption during state access
    unsafe {
        let idx = keyspace as usize;
        if idx >= MAX_AGENTS {
            return Err(E_INVALID_ARG);
        }
        match KEYSPACES[idx].as_mut() {
            Some(ks) => {
                let entry_idx = ks.put(key, value)?;
                // Update Merkle tree with the new/changed entry
                merkle::on_state_put(keyspace, entry_idx, key, value);
                Ok(())
            }
            None => Err(E_NOT_FOUND),
        }
    }
}

/// Get a value with a copy (returns owned array).
///
/// Returns `Some((value_copy, len))` if found.
pub fn state_get(keyspace: KeyspaceId, key: u64) -> Option<([u8; MAX_VALUE_SIZE], usize)> {
    match get(keyspace, key) {
        Some(data) => {
            let mut buf = [0u8; MAX_VALUE_SIZE];
            buf[..data.len()].copy_from_slice(data);
            Some((buf, data.len()))
        }
        None => None,
    }
}

/// Put a value by key (alias for `put`).
///
/// Each direct put advances the keyspace version so that the state root
/// history reflects every mutation.
pub fn state_put(keyspace: KeyspaceId, key: u64, value: &[u8]) -> Result<(), i64> {
    put(keyspace, key, value)?;
    advance_version(keyspace);
    Ok(())
}

// ─── Versioned state helpers ────────────────────────────────────────────────

/// Advance the version counter for a keyspace and snapshot its Merkle root.
pub fn advance_version(keyspace: KeyspaceId) {
    unsafe {
        let idx = keyspace as usize;
        if idx < MAX_AGENTS {
            if let Some(ks) = KEYSPACES[idx].as_mut() {
                ks.advance_version();
            }
        }
    }
}

/// Return the current version number for a keyspace, or `None` if it doesn't exist.
pub fn get_version(keyspace: KeyspaceId) -> Option<u32> {
    unsafe {
        let idx = keyspace as usize;
        if idx < MAX_AGENTS {
            if let Some(ks) = KEYSPACES[idx].as_ref() {
                return Some(ks.get_version());
            }
        }
        None
    }
}

/// Return the Merkle root that was recorded at a particular version.
pub fn get_historical_root(keyspace: KeyspaceId, version: u32) -> Option<MerkleHash> {
    unsafe {
        let idx = keyspace as usize;
        if idx < MAX_AGENTS {
            if let Some(ks) = KEYSPACES[idx].as_ref() {
                return ks.get_historical_root(version);
            }
        }
        None
    }
}

/// Return the current Merkle root for a keyspace.
pub fn get_root(keyspace: KeyspaceId) -> Option<MerkleHash> {
    merkle::get_root(keyspace)
}

// ─── State transaction model ────────────────────────────────────────────────

/// An atomic multi-key mutation batch.
///
/// Up to 8 key-value mutations are buffered and applied atomically on commit.
/// The keyspace version is advanced exactly once per committed transaction.
pub struct StateTransaction {
    pub keyspace_id: KeyspaceId,
    pub mutations: [(u64, [u8; MAX_VALUE_SIZE], usize); 8],  // (key, value, len)
    pub mutation_count: u8,
    pub tx_id: u64,
    pub committed: bool,
}

impl StateTransaction {
    pub fn new(keyspace_id: KeyspaceId, tx_id: u64) -> Self {
        StateTransaction {
            keyspace_id,
            mutations: [(0u64, [0u8; MAX_VALUE_SIZE], 0usize); 8],
            mutation_count: 0,
            tx_id,
            committed: false,
        }
    }

    /// Buffer a key-value mutation.  Returns `true` on success, `false` if
    /// the mutation limit (8) has been reached.
    pub fn add_mutation(&mut self, key: u64, value: &[u8]) -> bool {
        if self.mutation_count >= 8 {
            return false;
        }
        let idx = self.mutation_count as usize;
        self.mutations[idx].0 = key;
        let len = value.len().min(MAX_VALUE_SIZE);
        self.mutations[idx].1[..len].copy_from_slice(&value[..len]);
        self.mutations[idx].2 = len;
        self.mutation_count += 1;
        true
    }

    /// Apply all buffered mutations atomically to the keyspace and advance its
    /// version.  Returns `true` on success, `false` if already committed or if
    /// any individual put fails.
    pub fn commit(&mut self) -> bool {
        if self.committed {
            return false;
        }
        for i in 0..self.mutation_count as usize {
            let (key, ref value, len) = self.mutations[i];
            if put(self.keyspace_id, key, &value[..len]).is_err() {
                return false;
            }
        }
        advance_version(self.keyspace_id);
        self.committed = true;
        true
    }
}

// ─── Per-agent transaction slot ─────────────────────────────────────────────

/// One pending transaction slot per agent (single-core, no preemption).
static mut TX_SLOTS: [Option<StateTransaction>; MAX_AGENTS] = [const { None }; MAX_AGENTS];
/// Monotonic transaction ID counter.
static mut NEXT_TX_ID: u64 = 1;

/// Begin a new transaction for the given agent and keyspace.
/// Returns the transaction ID, or `Err` if one is already in progress.
pub fn tx_begin(agent_id: u16, keyspace_id: KeyspaceId) -> Result<u64, i64> {
    unsafe {
        let idx = agent_id as usize;
        if idx >= MAX_AGENTS {
            return Err(E_INVALID_ARG);
        }
        if TX_SLOTS[idx].is_some() {
            return Err(E_INVALID_ARG); // transaction already in progress
        }
        let tx_id = NEXT_TX_ID;
        NEXT_TX_ID += 1;
        TX_SLOTS[idx] = Some(StateTransaction::new(keyspace_id, tx_id));
        Ok(tx_id)
    }
}

/// Commit the pending transaction for the given agent.
/// Returns `Ok(())` on success.
pub fn tx_commit(agent_id: u16) -> Result<(), i64> {
    unsafe {
        let idx = agent_id as usize;
        if idx >= MAX_AGENTS {
            return Err(E_INVALID_ARG);
        }
        match TX_SLOTS[idx].as_mut() {
            Some(tx) => {
                if tx.commit() {
                    TX_SLOTS[idx] = None;
                    crate::persist::save_state_to_disk();
                    Ok(())
                } else {
                    Err(E_INVALID_ARG)
                }
            }
            None => Err(E_NOT_FOUND),
        }
    }
}

/// Add a mutation to the agent's pending transaction.
pub fn tx_add_mutation(agent_id: u16, key: u64, value: &[u8]) -> Result<(), i64> {
    unsafe {
        let idx = agent_id as usize;
        if idx >= MAX_AGENTS {
            return Err(E_INVALID_ARG);
        }
        match TX_SLOTS[idx].as_mut() {
            Some(tx) => {
                if tx.add_mutation(key, value) {
                    Ok(())
                } else {
                    Err(E_QUOTA_EXCEEDED) // mutation limit reached
                }
            }
            None => Err(E_NOT_FOUND),
        }
    }
}
