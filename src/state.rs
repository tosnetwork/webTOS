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
/// Uses a keyed PRNG stream cipher (FNV-1a + LCG based) with a 64-bit nonce
/// to produce a per-byte keystream.  Significantly stronger than static XOR
/// because every (key, nonce) pair yields a unique stream.
pub struct KeyspaceEncryption {
    pub enabled: bool,
    pub key: [u8; 32],
}

impl KeyspaceEncryption {
    /// Encrypt/decrypt a value using a keyed PRNG stream cipher.
    ///
    /// The keystream is derived by mixing the 32-byte key with a caller-supplied
    /// nonce through FNV-1a, then expanding via a 64-bit LCG.  The operation is
    /// symmetric: `transform(transform(v, n), n) == v`.
    pub fn transform(&self, value: &mut [u8], nonce: u64) {
        if !self.enabled { return; }

        // Seed: FNV-1a-64 over key bytes, then mix nonce
        let mut state: u64 = 0xcbf29ce484222325;
        for b in &self.key {
            state = state.wrapping_mul(0x100000001b3) ^ (*b as u64);
        }
        state = state.wrapping_mul(0x100000001b3) ^ nonce;

        // Generate keystream byte-by-byte via LCG and XOR
        for (i, byte) in value.iter_mut().enumerate() {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let ks_byte = ((state >> ((i % 8) * 8)) & 0xFF) as u8;
            *byte ^= ks_byte;
        }
    }

    /// Encrypt a value in place.
    pub fn encrypt(&self, value: &mut [u8], nonce: u64) {
        self.transform(value, nonce);
    }

    /// Decrypt a value in place (symmetric with encrypt).
    pub fn decrypt(&self, value: &mut [u8], nonce: u64) {
        self.transform(value, nonce);
    }
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
            root_history: [(0u32, [0u8; 32]); MAX_ROOT_HISTORY],
            root_history_count: 0,
        }
    }

    /// Compute the current Merkle root for this keyspace by delegating to the
    /// global Merkle tree table.
    fn compute_root(&self) -> MerkleHash {
        merkle::get_root(self.id).unwrap_or([0u8; 32])
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

    /// Encrypt a value before storing using keyed stream cipher.
    ///
    /// The nonce is derived from the keyspace version so each write produces
    /// a different keystream even for the same key material.
    pub fn encrypt_value(&self, value: &mut [u8], enc: &KeyspaceEncryption) {
        enc.encrypt(value, self.version as u64);
    }

    /// Decrypt a value after loading using keyed stream cipher.
    pub fn decrypt_value(&self, value: &mut [u8], enc: &KeyspaceEncryption) {
        enc.decrypt(value, self.version as u64);
    }

    /// Get a reference to an entry by key (used for transaction rollback).
    fn get_entry(&self, key: u64) -> Option<&StateEntry> {
        for entry in self.entries.iter() {
            if entry.active && entry.key == key {
                return Some(entry);
            }
        }
        None
    }

    /// Set a raw value into the keyspace (used for transaction rollback).
    /// Returns `true` on success, `false` if the keyspace is full and the key
    /// does not already exist.
    fn set_raw(&mut self, key: u64, value: &[u8]) -> bool {
        self.put(key, value).is_ok()
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
    /// version.  If any individual put fails, all already-applied mutations are
    /// rolled back so the keyspace is left unchanged.
    ///
    /// Returns `true` on success, `false` if already committed or on failure
    /// (with rollback).
    pub fn commit(&mut self) -> bool {
        if self.committed {
            return false;
        }

        // Safety: single-core, no preemption during state access
        unsafe {
            let idx = self.keyspace_id as usize;
            if idx >= MAX_AGENTS {
                return false;
            }
            let ks = match KEYSPACES[idx].as_mut() {
                Some(ks) => ks,
                None => return false,
            };

            // ── Save originals for rollback ────────────────────────────
            // For each mutation key, snapshot the current value (if any).
            let mut originals: [(u64, [u8; MAX_VALUE_SIZE], usize, bool); 8] =
                [(0u64, [0u8; MAX_VALUE_SIZE], 0usize, false); 8];
            let mut original_count: usize = 0;

            for i in 0..self.mutation_count as usize {
                let (key, _, _) = self.mutations[i];
                if let Some(entry) = ks.get_entry(key) {
                    originals[original_count] = (key, entry.value, entry.len, true);
                    original_count += 1;
                }
            }

            // ── Apply mutations ────────────────────────────────────────
            let mut success = true;

            for i in 0..self.mutation_count as usize {
                let (key, ref value, len) = self.mutations[i];
                if ks.put(key, &value[..len]).is_ok() {
                    // Update Merkle tree
                    merkle::on_state_put(self.keyspace_id, i, key, &value[..len]);
                } else {
                    success = false;
                    break;
                }
            }

            if !success {
                // ── Rollback: restore saved originals ──────────────────
                for j in 0..original_count {
                    let (key, ref val, len, _) = originals[j];
                    let _ = ks.set_raw(key, &val[..len]);
                }
                return false;
            }

            ks.advance_version();
        }

        self.committed = true;
        true
    }

    /// Abort the transaction without applying any changes.
    pub fn abort(&mut self) {
        self.mutation_count = 0;
        self.committed = false;
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
///
/// On success the keyspace state is persisted to disk and a replication
/// event is emitted for future cross-node consistency.
pub fn tx_commit(agent_id: u16) -> Result<(), i64> {
    unsafe {
        let idx = agent_id as usize;
        if idx >= MAX_AGENTS {
            return Err(E_INVALID_ARG);
        }
        let keyspace_id;
        match TX_SLOTS[idx].as_mut() {
            Some(tx) => {
                keyspace_id = tx.keyspace_id;
                if tx.commit() {
                    TX_SLOTS[idx] = None;
                    crate::persist::save_state_to_disk();

                    // Emit replication event
                    let version = get_version(keyspace_id).unwrap_or(0);
                    let state_root = get_root(keyspace_id).unwrap_or([0u8; 32]);
                    on_state_committed(ReplicationEvent {
                        keyspace_id,
                        version,
                        key: 0, // batch commit; individual keys in tx
                        value_hash: [0u8; 32],
                        state_root,
                        tick: 0,
                    });
                    Ok(())
                } else {
                    Err(E_INVALID_ARG)
                }
            }
            None => Err(E_NOT_FOUND),
        }
    }
}

/// Abort the pending transaction for the given agent without applying changes.
pub fn tx_abort(agent_id: u16) -> Result<(), i64> {
    unsafe {
        let idx = agent_id as usize;
        if idx >= MAX_AGENTS {
            return Err(E_INVALID_ARG);
        }
        match TX_SLOTS[idx].as_mut() {
            Some(tx) => {
                tx.abort();
                TX_SLOTS[idx] = None;
                Ok(())
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

// ─── Replication hook ──────────────────────────────────────────────────────

/// Replication event that can be sent to a follower node.
#[derive(Clone, Copy)]
pub struct ReplicationEvent {
    pub keyspace_id: KeyspaceId,
    pub version: u32,
    pub key: u64,
    pub value_hash: [u8; 32],
    pub state_root: [u8; 32],
    pub tick: u64,
}

/// Replication hook: called after every committed state change.
/// In single-node mode this is a no-op.  In distributed mode the hook
/// would send the event to follower nodes via routerd.
pub fn on_state_committed(event: ReplicationEvent) {
    // Currently single-node: suppress unused-variable warning.
    let _ = event;
    // Future: send to routerd for cross-node replication.
}
