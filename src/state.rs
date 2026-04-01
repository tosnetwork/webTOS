//! TOS State Object Subsystem
//!
//! Implements an in-memory key-value subsystem organized into keyspaces.
//! Each agent is automatically assigned a private keyspace at creation.
//! Access to any keyspace requires the corresponding CAP_STATE_READ or
//! CAP_STATE_WRITE capability. An agent always has implicit access to
//! its own private keyspace.

use crate::agent::{
    KeyspaceId, E_INVALID_ARG, E_NOT_FOUND, E_PAYLOAD_TOO_LARGE, E_QUOTA_EXCEEDED, MAX_AGENTS,
};
use crate::merkle::{self, MerkleHash};

const MAX_ENTRIES_PER_KEYSPACE: usize = 320;
pub const MAX_VALUE_SIZE: usize = 256;

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
    // Route base-image keyspace to embedded files first, then the
    // dedicated mutable hash table for runtime-installed additions.
    if keyspace == BASE_IMAGE_KEYSPACE {
        if let Some(value) = crate::base_image::state_get(key) {
            return Some(value);
        }
        return base_image_state_get(key);
    }
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
    if keyspace == BASE_IMAGE_KEYSPACE {
        let _ = base_image_put(key, value);
        return Ok(());
    }
    put(keyspace, key, value)?;
    advance_version(keyspace);
    Ok(())
}

/// Delete a key from a keyspace by marking its entry as inactive.
///
/// Returns `Ok(())` if the key was found and deleted, or `Err(E_NOT_FOUND)`
/// if it did not exist.
pub fn state_delete(keyspace: KeyspaceId, key: u64) -> Result<(), i64> {
    unsafe {
        let idx = keyspace as usize;
        if idx >= MAX_AGENTS {
            return Err(E_INVALID_ARG);
        }
        match KEYSPACES[idx].as_mut() {
            Some(ks) => {
                for entry in ks.entries.iter_mut() {
                    if entry.active && entry.key == key {
                        entry.active = false;
                        entry.len = 0;
                        ks.advance_version();
                        return Ok(());
                    }
                }
                Err(E_NOT_FOUND)
            }
            None => Err(E_NOT_FOUND),
        }
    }
}

/// Iterate over active entries in a keyspace, calling `f` for each one.
///
/// The callback receives `(key, value_slice)`.  Returns the number of
/// entries visited.
pub fn iter_entries<F>(keyspace: KeyspaceId, mut f: F) -> usize
where
    F: FnMut(u64, &[u8]) -> bool,
{
    unsafe {
        let idx = keyspace as usize;
        if idx >= MAX_AGENTS {
            return 0;
        }
        match KEYSPACES[idx].as_ref() {
            Some(ks) => {
                let mut count = 0usize;
                for entry in ks.entries.iter() {
                    if entry.active {
                        count += 1;
                        if !f(entry.key, &entry.value[..entry.len]) {
                            break;
                        }
                    }
                }
                count
            }
            None => 0,
        }
    }
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

/// Find the entry index for a key in a keyspace.
///
/// Returns `Some(index)` if the key exists in the keyspace, where `index` is
/// the position in the entries array (and thus the Merkle tree leaf index).
pub fn find_entry_index(keyspace: KeyspaceId, key: u64) -> Option<usize> {
    unsafe {
        let idx = keyspace as usize;
        if idx >= MAX_AGENTS {
            return None;
        }
        match KEYSPACES[idx].as_ref() {
            Some(ks) => {
                for (i, entry) in ks.entries.iter().enumerate() {
                    if entry.active && entry.key == key {
                        return Some(i);
                    }
                }
                None
            }
            None => None,
        }
    }
}

/// Return the current Merkle root for a keyspace.
pub fn get_root(keyspace: KeyspaceId) -> Option<MerkleHash> {
    merkle::get_root(keyspace)
}

/// Compact a keyspace's root history by trimming it to the most recent `keep`
/// entries.  Returns `true` if entries were actually removed, `false` if the
/// history was already at or below `keep`.
pub fn compact_keyspace_history(keyspace_id: KeyspaceId, keep: u8) -> bool {
    unsafe {
        let idx = keyspace_id as usize;
        if idx >= MAX_AGENTS {
            return false;
        }
        let ks = match KEYSPACES[idx].as_mut() {
            Some(ks) => ks,
            None => return false,
        };
        let count = ks.root_history_count as usize;
        let keep = keep as usize;
        if count <= keep {
            return false;
        }
        // Keep the most recent `keep` entries: they sit at indices [count-keep .. count).
        // Shift them to the front of the array.
        let start = count - keep;
        for i in 0..keep {
            ks.root_history[i] = ks.root_history[start + i];
        }
        // Zero out the vacated tail slots
        for i in keep..count {
            ks.root_history[i] = (0u32, [0u8; 32]);
        }
        ks.root_history_count = keep as u8;
        true
    }
}

// ─── State transaction model ────────────────────────────────────────────────

/// An atomic multi-key mutation batch.
///
/// Up to 8 key-value mutations are buffered and applied atomically on commit.
/// The keyspace version is advanced exactly once per committed transaction.
pub struct StateTransaction {
    pub keyspace_id: KeyspaceId,
    pub mutations: [(u64, [u8; MAX_VALUE_SIZE], usize); 8], // (key, value, len)
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
/// On success the keyspace state is persisted to disk.
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

// ─── Large value storage (chunked) ────────────────────────────────────────

/// Large value storage via chunked keyspace entries.
///
/// Key `LARGE_VALUE_META_KEY` = metadata: total_len (u32 LE) + chunk_count (u16 LE).
/// Keys `LARGE_VALUE_CHUNK_BASE` .. `LARGE_VALUE_CHUNK_BASE + chunk_count - 1` = chunk data
/// (up to 256 bytes each).
pub const LARGE_VALUE_META_KEY: u64 = 0xFFFF_0000;
pub const LARGE_VALUE_CHUNK_BASE: u64 = 0xFFFF_0001;

/// Maximum number of chunks for a large value (256 chunks * 256 bytes = 64 KB).
const MAX_LARGE_VALUE_CHUNKS: usize = 256;

/// Store a large value into a keyspace using chunked entries.
///
/// Splits `data` into 256-byte chunks and stores metadata at `LARGE_VALUE_META_KEY`.
/// Maximum supported size is 65536 bytes (256 chunks of 256 bytes).
///
/// Returns `Ok(())` on success, or an error code on failure.
pub fn store_large_value(keyspace: KeyspaceId, data: &[u8]) -> Result<(), i64> {
    if data.is_empty() {
        return Err(E_INVALID_ARG);
    }
    if data.len() > MAX_LARGE_VALUE_CHUNKS * MAX_VALUE_SIZE {
        return Err(E_PAYLOAD_TOO_LARGE);
    }

    // Compute chunk count.
    let chunk_count = (data.len() + MAX_VALUE_SIZE - 1) / MAX_VALUE_SIZE;

    // Store metadata: total_len (4 bytes LE) + chunk_count (2 bytes LE).
    let total_len = data.len() as u32;
    let mut meta = [0u8; 6];
    meta[0..4].copy_from_slice(&total_len.to_le_bytes());
    meta[4..6].copy_from_slice(&(chunk_count as u16).to_le_bytes());
    put(keyspace, LARGE_VALUE_META_KEY, &meta)?;

    // Store each chunk.
    for i in 0..chunk_count {
        let start = i * MAX_VALUE_SIZE;
        let end = (start + MAX_VALUE_SIZE).min(data.len());
        let chunk_key = LARGE_VALUE_CHUNK_BASE + i as u64;
        put(keyspace, chunk_key, &data[start..end])?;
    }

    // Advance version once for the entire store operation.
    advance_version(keyspace);
    Ok(())
}

/// Load a large value from a keyspace that was stored via `store_large_value`.
///
/// Reads the metadata at `LARGE_VALUE_META_KEY`, then reassembles chunks into `buf`.
/// Returns the total number of bytes read, or 0 if no large value is stored.
pub fn load_large_value(keyspace: KeyspaceId, buf: &mut [u8]) -> usize {
    // Read metadata.
    let (meta_buf, meta_len) = match state_get(keyspace, LARGE_VALUE_META_KEY) {
        Some(v) => v,
        None => return 0,
    };

    if meta_len < 6 {
        return 0;
    }

    let total_len =
        u32::from_le_bytes([meta_buf[0], meta_buf[1], meta_buf[2], meta_buf[3]]) as usize;
    let chunk_count = u16::from_le_bytes([meta_buf[4], meta_buf[5]]) as usize;

    if total_len == 0 || chunk_count == 0 || total_len > buf.len() {
        return 0;
    }

    // Read each chunk and copy into buf.
    let mut offset = 0;
    for i in 0..chunk_count {
        let chunk_key = LARGE_VALUE_CHUNK_BASE + i as u64;
        let (chunk_buf, chunk_len) = match state_get(keyspace, chunk_key) {
            Some(v) => v,
            None => return 0, // missing chunk — corrupt data
        };
        let copy_len = chunk_len.min(total_len - offset);
        buf[offset..offset + copy_len].copy_from_slice(&chunk_buf[..copy_len]);
        offset += copy_len;
        if offset >= total_len {
            break;
        }
    }

    total_len
}

/// Query the size of a large value stored via `store_large_value`.
///
/// Returns the total length in bytes, or 0 if no valid large value is present.
pub fn query_large_value_size(keyspace: KeyspaceId) -> usize {
    let (meta_buf, meta_len) = match state_get(keyspace, LARGE_VALUE_META_KEY) {
        Some(v) => v,
        None => return 0,
    };

    if meta_len < 6 {
        return 0;
    }

    let total_len =
        u32::from_le_bytes([meta_buf[0], meta_buf[1], meta_buf[2], meta_buf[3]]) as usize;
    let chunk_count = u16::from_le_bytes([meta_buf[4], meta_buf[5]]) as usize;

    if total_len == 0 || chunk_count == 0 || total_len > MAX_LARGE_VALUE_CHUNKS * MAX_VALUE_SIZE {
        return 0;
    }

    total_len
}

// ─── Multi-segment large value storage ─────────────────────────────────────
//
// Files larger than 64 KB (e.g. libjvm.so at 22 MB) are split into 64 KB
// "segments", each stored via `store_large_value()`.  A metadata entry at
// `base_key` records the total size and segment count.  Segments are stored
// at keys `base_key + 1` through `base_key + N`.
//
// Because `store_large_value` itself chunks each 64 KB segment into 256-byte
// entries inside a keyspace, and our per-keyspace entry limit is small, we
// use a separate dedicated storage table for the base image (see below).

/// Maximum size of a single segment (64 KB, matching `store_large_value` limit).
pub const MULTI_SEGMENT_SIZE: usize = MAX_LARGE_VALUE_CHUNKS * MAX_VALUE_SIZE; // 65536

/// Key stride between consecutive segments.  Each segment occupies 1 metadata
/// key + up to MAX_LARGE_VALUE_CHUNKS chunk keys = 257 keys total.
const SEGMENT_KEY_STRIDE: u64 = (MAX_LARGE_VALUE_CHUNKS as u64) + 2; // 258

// ─── Base image dedicated storage ──────────────────────────────────────────
//
// The base image keyspace (0xFFFE) cannot use the normal per-agent KEYSPACES
// table (which only has MAX_AGENTS=28 slots).  Instead, base image data is
// stored in a flat static table keyed by u64.  Each entry holds up to 256
// bytes, just like a normal keyspace entry.

/// Maximum number of entries in the base image store.
///
/// For 22 MB files stored in 256-byte chunks we need ~90K entries.
/// We use a power-of-two size for efficient hash-table indexing.
const BASE_IMAGE_MAX_ENTRIES: usize = 131072; // 128K slots — holds up to ~32 MB
const MAX_BASE_IMAGE_PATHS: usize = 512;
const MAX_BASE_IMAGE_PATH_LEN: usize = 256;

struct BaseImageEntry {
    key: u64,
    value: [u8; MAX_VALUE_SIZE],
    len: usize,
    active: bool,
}

impl BaseImageEntry {
    const fn empty() -> Self {
        BaseImageEntry {
            key: 0,
            value: [0u8; MAX_VALUE_SIZE],
            len: 0,
            active: false,
        }
    }
}

// Safety: single-core, no preemption.
static mut BASE_IMAGE_STORE: [BaseImageEntry; BASE_IMAGE_MAX_ENTRIES] =
    [const { BaseImageEntry::empty() }; BASE_IMAGE_MAX_ENTRIES];

#[derive(Clone, Copy)]
struct BaseImagePathEntry {
    active: bool,
    namespace: u8,
    rel_len: u16,
    rel_path: [u8; MAX_BASE_IMAGE_PATH_LEN],
}

impl BaseImagePathEntry {
    const fn empty() -> Self {
        BaseImagePathEntry {
            active: false,
            namespace: 0,
            rel_len: 0,
            rel_path: [0u8; MAX_BASE_IMAGE_PATH_LEN],
        }
    }
}

static mut BASE_IMAGE_PATHS: [BaseImagePathEntry; MAX_BASE_IMAGE_PATHS] =
    [const { BaseImagePathEntry::empty() }; MAX_BASE_IMAGE_PATHS];

fn record_base_image_path(path: &[u8]) {
    let Some((namespace, relative)) = crate::linux_compat::vfs::classify_base_image_path(path)
    else {
        return;
    };
    let rel_len = relative.len().min(MAX_BASE_IMAGE_PATH_LEN);

    unsafe {
        for entry in BASE_IMAGE_PATHS.iter() {
            if entry.active
                && entry.namespace == namespace as u8
                && entry.rel_len as usize == rel_len
                && entry.rel_path[..rel_len] == relative[..rel_len]
            {
                return;
            }
        }

        for entry in BASE_IMAGE_PATHS.iter_mut() {
            if !entry.active {
                entry.active = true;
                entry.namespace = namespace as u8;
                entry.rel_len = rel_len as u16;
                entry.rel_path[..rel_len].copy_from_slice(&relative[..rel_len]);
                return;
            }
        }
    }
}

pub fn iter_base_image_paths<F>(mut f: F) -> usize
where
    F: FnMut(crate::linux_compat::vfs::BaseImageNamespace, &[u8]) -> bool,
{
    let mut count = 0usize;
    let mut stopped = false;
    count += crate::base_image::iter_paths(|namespace, relative| {
        let keep_going = f(namespace, relative);
        if !keep_going {
            stopped = true;
        }
        keep_going
    });
    if stopped {
        return count;
    }

    unsafe {
        for entry in BASE_IMAGE_PATHS.iter() {
            if !entry.active {
                continue;
            }

            let namespace = match entry.namespace {
                x if x == crate::linux_compat::vfs::BaseImageNamespace::Lib as u8 => {
                    crate::linux_compat::vfs::BaseImageNamespace::Lib
                }
                x if x == crate::linux_compat::vfs::BaseImageNamespace::Jdk as u8 => {
                    crate::linux_compat::vfs::BaseImageNamespace::Jdk
                }
                x if x == crate::linux_compat::vfs::BaseImageNamespace::Etc as u8 => {
                    crate::linux_compat::vfs::BaseImageNamespace::Etc
                }
                x if x == crate::linux_compat::vfs::BaseImageNamespace::UsrBin as u8 => {
                    crate::linux_compat::vfs::BaseImageNamespace::UsrBin
                }
                _ => continue,
            };

            count += 1;
            if !f(namespace, &entry.rel_path[..entry.rel_len as usize]) {
                break;
            }
        }
        count
    }
}

/// Hash a u64 key to a slot index (Fibonacci hashing).
#[inline]
fn base_image_hash(key: u64) -> usize {
    // Multiply by golden-ratio constant, take top bits
    let h = key.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    (h >> (64 - 17)) as usize // 17 bits = 131072 slots
}

/// Read a value from the base image store (hash-table lookup).
fn base_image_get(key: u64) -> Option<&'static [u8]> {
    unsafe {
        let mask = BASE_IMAGE_MAX_ENTRIES - 1; // power-of-two
        let mut idx = base_image_hash(key) & mask;
        for _ in 0..BASE_IMAGE_MAX_ENTRIES {
            let entry = &BASE_IMAGE_STORE[idx];
            if !entry.active {
                return None; // empty slot means key not present
            }
            if entry.key == key {
                return Some(&entry.value[..entry.len]);
            }
            idx = (idx + 1) & mask;
        }
        None
    }
}

/// Write a value to the base image store (hash-table with linear probing).
fn base_image_put(key: u64, value: &[u8]) -> Result<(), i64> {
    if value.len() > MAX_VALUE_SIZE {
        return Err(E_PAYLOAD_TOO_LARGE);
    }
    unsafe {
        let mask = BASE_IMAGE_MAX_ENTRIES - 1;
        let mut idx = base_image_hash(key) & mask;
        for _ in 0..BASE_IMAGE_MAX_ENTRIES {
            let entry = &mut BASE_IMAGE_STORE[idx];
            if entry.active && entry.key == key {
                // Update existing entry
                entry.value[..value.len()].copy_from_slice(value);
                entry.len = value.len();
                return Ok(());
            }
            if !entry.active {
                // Insert into empty slot
                entry.key = key;
                entry.value[..value.len()].copy_from_slice(value);
                entry.len = value.len();
                entry.active = true;
                return Ok(());
            }
            idx = (idx + 1) & mask;
        }
        Err(E_QUOTA_EXCEEDED)
    }
}

/// Read a value from the base image store with a copy.
fn base_image_state_get(key: u64) -> Option<([u8; MAX_VALUE_SIZE], usize)> {
    match base_image_get(key) {
        Some(data) => {
            let mut buf = [0u8; MAX_VALUE_SIZE];
            buf[..data.len()].copy_from_slice(data);
            Some((buf, data.len()))
        }
        None => None,
    }
}

/// The base image keyspace ID (must match `linux_compat::vfs::BASE_IMAGE_KEYSPACE`).
pub const BASE_IMAGE_KEYSPACE: u16 = 0xFFFE;

/// Store a large value into the base image keyspace using chunked entries.
///
/// This mirrors `store_large_value` but targets the dedicated base image
/// store instead of a normal per-agent keyspace.
fn store_large_value_base_image(base_key: u64, data: &[u8]) -> Result<(), i64> {
    if data.is_empty() {
        return Err(E_INVALID_ARG);
    }
    if data.len() > MAX_LARGE_VALUE_CHUNKS * MAX_VALUE_SIZE {
        return Err(E_PAYLOAD_TOO_LARGE);
    }

    let chunk_count = (data.len() + MAX_VALUE_SIZE - 1) / MAX_VALUE_SIZE;

    // Metadata: total_len(u32 LE) + chunk_count(u16 LE)
    let total_len = data.len() as u32;
    let mut meta = [0u8; 6];
    meta[0..4].copy_from_slice(&total_len.to_le_bytes());
    meta[4..6].copy_from_slice(&(chunk_count as u16).to_le_bytes());
    base_image_put(base_key, &meta)?;

    for i in 0..chunk_count {
        let start = i * MAX_VALUE_SIZE;
        let end = (start + MAX_VALUE_SIZE).min(data.len());
        let chunk_key = base_key.wrapping_add(1).wrapping_add(i as u64);
        base_image_put(chunk_key, &data[start..end])?;
    }

    Ok(())
}

/// Load a large value from the base image keyspace.
fn load_large_value_base_image(base_key: u64, buf: &mut [u8]) -> usize {
    let (meta_buf, meta_len) = match base_image_state_get(base_key) {
        Some(v) => v,
        None => return 0,
    };
    if meta_len < 6 {
        return 0;
    }

    let total_len =
        u32::from_le_bytes([meta_buf[0], meta_buf[1], meta_buf[2], meta_buf[3]]) as usize;
    let chunk_count = u16::from_le_bytes([meta_buf[4], meta_buf[5]]) as usize;

    if total_len == 0 || chunk_count == 0 || total_len > buf.len() {
        return 0;
    }

    let mut offset = 0;
    for i in 0..chunk_count {
        let chunk_key = base_key.wrapping_add(1).wrapping_add(i as u64);
        let (chunk_buf, chunk_len) = match base_image_state_get(chunk_key) {
            Some(v) => v,
            None => return 0,
        };
        let copy_len = chunk_len.min(total_len - offset);
        buf[offset..offset + copy_len].copy_from_slice(&chunk_buf[..copy_len]);
        offset += copy_len;
        if offset >= total_len {
            break;
        }
    }

    total_len
}

/// Extended large value storage for files >64KB.
///
/// Splits data into 64KB segments, each stored as a separate large value.
///
/// Segment layout:
/// - Key `base_key`: metadata — total_size(u32 LE) + segment_count(u16 LE)
/// - Key `base_key + 1` .. `base_key + N`: each segment stored via
///   `store_large_value_base_image()` (64KB each, last may be smaller)
///
/// For normal keyspaces this delegates to `store_large_value()` when the
/// data fits in a single segment (<=64KB).  For the base image keyspace,
/// the dedicated base image store is used.
pub fn store_multi_segment(keyspace: KeyspaceId, base_key: u64, data: &[u8]) -> Result<(), i64> {
    if data.is_empty() {
        return Err(E_INVALID_ARG);
    }

    let segment_count = (data.len() + MULTI_SEGMENT_SIZE - 1) / MULTI_SEGMENT_SIZE;

    // Store metadata at base_key: total_size(u32 LE) + segment_count(u16 LE)
    let mut meta = [0u8; 6];
    meta[0..4].copy_from_slice(&(data.len() as u32).to_le_bytes());
    meta[4..6].copy_from_slice(&(segment_count as u16).to_le_bytes());

    if keyspace == BASE_IMAGE_KEYSPACE {
        base_image_put(base_key, &meta)?;
    } else {
        put(keyspace, base_key, &meta)?;
    }

    // Store each segment as a large value at base_key + 1 + i
    // Each segment itself is chunked into 256-byte entries.
    for i in 0..segment_count {
        let start = i * MULTI_SEGMENT_SIZE;
        let end = (start + MULTI_SEGMENT_SIZE).min(data.len());
        let segment_data = &data[start..end];

        // Each segment occupies SEGMENT_KEY_STRIDE keys (metadata + chunks).
        // Spacing them apart prevents key collisions between segments.
        let segment_key = base_key
            .wrapping_add(1)
            .wrapping_add((i as u64) * SEGMENT_KEY_STRIDE);

        // We store the segment as a "large value" rooted at segment_key.
        // For the base image this uses the dedicated store; for normal
        // keyspaces it uses the standard store_large_value approach.
        if keyspace == BASE_IMAGE_KEYSPACE {
            store_large_value_base_image(segment_key, segment_data)?;
        } else {
            // For normal keyspaces, fall back to direct chunked storage
            // at the segment key offset.  This reuses the base image
            // chunking logic but targeting the agent keyspace.
            let chunk_count = (segment_data.len() + MAX_VALUE_SIZE - 1) / MAX_VALUE_SIZE;
            let mut seg_meta = [0u8; 6];
            seg_meta[0..4].copy_from_slice(&(segment_data.len() as u32).to_le_bytes());
            seg_meta[4..6].copy_from_slice(&(chunk_count as u16).to_le_bytes());
            put(keyspace, segment_key, &seg_meta)?;
            for c in 0..chunk_count {
                let cs = c * MAX_VALUE_SIZE;
                let ce = (cs + MAX_VALUE_SIZE).min(segment_data.len());
                put(
                    keyspace,
                    segment_key.wrapping_add(1).wrapping_add(c as u64),
                    &segment_data[cs..ce],
                )?;
            }
        }
    }

    if keyspace != BASE_IMAGE_KEYSPACE {
        advance_version(keyspace);
    }
    Ok(())
}

/// Load a multi-segment value that was stored via `store_multi_segment`.
///
/// Reads the metadata at `base_key`, then reassembles all segments into
/// `buf`.  Returns the total number of bytes read, or 0 on failure.
/// Query the size of a file stored via `store_multi_segment`.
///
/// Returns the total size in bytes, or 0 if the key doesn't exist or
/// is not a multi-segment value.
pub fn query_multi_segment_size(keyspace: KeyspaceId, base_key: u64) -> usize {
    if keyspace == BASE_IMAGE_KEYSPACE {
        if let Some(size) = crate::base_image::file_size(base_key) {
            if size > MAX_VALUE_SIZE {
                return size;
            }
        }
    }

    let (meta_buf, meta_len) = if keyspace == BASE_IMAGE_KEYSPACE {
        match base_image_state_get(base_key) {
            Some(v) => v,
            None => return 0,
        }
    } else {
        match state_get(keyspace, base_key) {
            Some(v) => v,
            None => return 0,
        }
    };

    if meta_len < 6 {
        // Not a multi-segment value — could be a plain value
        return 0;
    }

    u32::from_le_bytes([meta_buf[0], meta_buf[1], meta_buf[2], meta_buf[3]]) as usize
}

/// Query the total size of a file in a keyspace.
///
/// Tries multi-segment first (metadata = 6 bytes with size+count),
/// then falls back to plain value size. Returns 0 if key not found.
pub fn query_file_size(keyspace: KeyspaceId, key: u64) -> usize {
    if keyspace == BASE_IMAGE_KEYSPACE {
        if let Some(size) = crate::base_image::file_size(key) {
            return size;
        }
    }

    let ms = query_multi_segment_size(keyspace, key);
    if ms > 0 {
        return ms;
    }
    // Fall back to plain value
    let (_, len) = if keyspace == BASE_IMAGE_KEYSPACE {
        match base_image_state_get(key) {
            Some(v) => v,
            None => return 0,
        }
    } else {
        match state_get(keyspace, key) {
            Some(v) => v,
            None => return 0,
        }
    };
    len
}

fn load_large_value_range(keyspace: KeyspaceId, base_key: u64, offset: usize, buf: &mut [u8]) -> usize {
    if buf.is_empty() {
        return 0;
    }

    let (meta_buf, meta_len) = match state_get(keyspace, base_key) {
        Some(v) => v,
        None => return 0,
    };
    if meta_len < 6 {
        return 0;
    }

    let total_len =
        u32::from_le_bytes([meta_buf[0], meta_buf[1], meta_buf[2], meta_buf[3]]) as usize;
    let chunk_count = u16::from_le_bytes([meta_buf[4], meta_buf[5]]) as usize;
    if total_len == 0 || chunk_count == 0 || offset >= total_len {
        return 0;
    }

    let mut copied = 0usize;
    let mut remaining = buf.len().min(total_len - offset);
    let mut chunk_index = offset / MAX_VALUE_SIZE;
    let mut chunk_offset = offset % MAX_VALUE_SIZE;

    while remaining > 0 && chunk_index < chunk_count {
        let chunk_key = base_key.wrapping_add(1).wrapping_add(chunk_index as u64);
        let (chunk_buf, chunk_len) = match state_get(keyspace, chunk_key) {
            Some(v) => v,
            None => break,
        };
        if chunk_offset >= chunk_len {
            break;
        }

        let copy_len = remaining.min(chunk_len - chunk_offset);
        buf[copied..copied + copy_len]
            .copy_from_slice(&chunk_buf[chunk_offset..chunk_offset + copy_len]);
        copied += copy_len;
        remaining -= copy_len;
        chunk_index += 1;
        chunk_offset = 0;
    }

    copied
}

/// Copy a file range into `buf` without materializing the whole file.
///
/// This is the range-read primitive used by Linux file I/O and lazy
/// file-backed page faults. It works for:
/// - embedded base-image files,
/// - plain small values,
/// - multi-segment files stored in keyspaces or the mutable base-image store.
pub fn load_file_range(keyspace: KeyspaceId, base_key: u64, offset: usize, buf: &mut [u8]) -> usize {
    if buf.is_empty() {
        return 0;
    }

    if keyspace == BASE_IMAGE_KEYSPACE {
        if let Some(entry) = crate::base_image::find_by_key(base_key) {
            if offset >= entry.data.len() {
                return 0;
            }
            let copy_len = buf.len().min(entry.data.len() - offset);
            buf[..copy_len].copy_from_slice(&entry.data[offset..offset + copy_len]);
            return copy_len;
        }
    }

    let (value, value_len) = match state_get(keyspace, base_key) {
        Some(v) => v,
        None => return 0,
    };

    let maybe_multi_segment = if value_len == 6 {
        let total = u32::from_le_bytes([value[0], value[1], value[2], value[3]]) as usize;
        let segment_count = u16::from_le_bytes([value[4], value[5]]) as usize;
        segment_count > 0 && total > MAX_VALUE_SIZE
    } else {
        false
    };

    if !maybe_multi_segment {
        if offset >= value_len {
            return 0;
        }
        let copy_len = buf.len().min(value_len - offset);
        buf[..copy_len].copy_from_slice(&value[offset..offset + copy_len]);
        return copy_len;
    }

    let total_size = u32::from_le_bytes([value[0], value[1], value[2], value[3]]) as usize;
    let segment_count = u16::from_le_bytes([value[4], value[5]]) as usize;
    if total_size == 0 || segment_count == 0 || offset >= total_size {
        return 0;
    }

    let mut copied = 0usize;
    let mut remaining = buf.len().min(total_size - offset);
    let mut segment_index = offset / MULTI_SEGMENT_SIZE;
    let mut segment_offset = offset % MULTI_SEGMENT_SIZE;

    while remaining > 0 && segment_index < segment_count {
        let segment_key = base_key
            .wrapping_add(1)
            .wrapping_add((segment_index as u64) * SEGMENT_KEY_STRIDE);
        let segment_limit =
            MULTI_SEGMENT_SIZE.min(total_size - segment_index * MULTI_SEGMENT_SIZE);
        if segment_offset >= segment_limit {
            break;
        }

        let target = remaining.min(segment_limit - segment_offset);
        let loaded = load_large_value_range(
            keyspace,
            segment_key,
            segment_offset,
            &mut buf[copied..copied + target],
        );

        if loaded == 0 {
            break;
        }
        copied += loaded;
        remaining -= loaded;
        segment_index += 1;
        segment_offset = 0;
    }

    copied
}

pub fn load_multi_segment(keyspace: KeyspaceId, base_key: u64, buf: &mut [u8]) -> usize {
    if keyspace == BASE_IMAGE_KEYSPACE {
        let loaded = crate::base_image::load_file(base_key, buf);
        if loaded > 0 {
            return loaded;
        }
    }

    // Read top-level metadata
    let (meta_buf, meta_len) = if keyspace == BASE_IMAGE_KEYSPACE {
        match base_image_state_get(base_key) {
            Some(v) => v,
            None => return 0,
        }
    } else {
        match state_get(keyspace, base_key) {
            Some(v) => v,
            None => return 0,
        }
    };

    if meta_len < 6 {
        return 0;
    }

    let total_size =
        u32::from_le_bytes([meta_buf[0], meta_buf[1], meta_buf[2], meta_buf[3]]) as usize;
    let segment_count = u16::from_le_bytes([meta_buf[4], meta_buf[5]]) as usize;

    if total_size == 0 || segment_count == 0 || total_size > buf.len() {
        return 0;
    }

    let mut offset = 0;
    for i in 0..segment_count {
        let segment_key = base_key
            .wrapping_add(1)
            .wrapping_add((i as u64) * SEGMENT_KEY_STRIDE);
        let segment_size = MULTI_SEGMENT_SIZE.min(total_size - offset);

        let loaded = if keyspace == BASE_IMAGE_KEYSPACE {
            load_large_value_base_image(segment_key, &mut buf[offset..offset + segment_size])
        } else {
            // Load segment from normal keyspace using chunked reads
            let (seg_meta_buf, seg_meta_len) = match state_get(keyspace, segment_key) {
                Some(v) => v,
                None => return 0,
            };
            if seg_meta_len < 6 {
                return 0;
            }
            let seg_total = u32::from_le_bytes([
                seg_meta_buf[0],
                seg_meta_buf[1],
                seg_meta_buf[2],
                seg_meta_buf[3],
            ]) as usize;
            let seg_chunks = u16::from_le_bytes([seg_meta_buf[4], seg_meta_buf[5]]) as usize;
            if seg_total == 0 || seg_chunks == 0 || seg_total > segment_size {
                return 0;
            }
            let mut seg_off = 0;
            for c in 0..seg_chunks {
                let ck = segment_key.wrapping_add(1).wrapping_add(c as u64);
                let (cbuf, clen) = match state_get(keyspace, ck) {
                    Some(v) => v,
                    None => return 0,
                };
                let copy = clen.min(seg_total - seg_off);
                buf[offset + seg_off..offset + seg_off + copy].copy_from_slice(&cbuf[..copy]);
                seg_off += copy;
                if seg_off >= seg_total {
                    break;
                }
            }
            seg_total
        };

        if loaded == 0 {
            return 0;
        }
        offset += loaded;
        if offset >= total_size {
            break;
        }
    }

    total_size
}

/// Install a file into the base image keyspace.
///
/// The file is stored using multi-segment storage at the key derived from
/// the given path (via `vfs::sha256_key`).  This is the entry point for
/// pre-installing `.so` files, JDK binaries, and other base image assets.
/// Install a file into the base image keyspace.
///
/// The `path` must be a Linux absolute path (e.g. `/lib/ld-musl-x86_64.so.1`).
/// The key is derived via the same VFS resolution as `openat`/`stat` so that
/// subsequent file I/O finds the correct data.
pub fn install_base_image_file(path: &[u8], data: &[u8]) -> Result<(), i64> {
    let (ks, key) = crate::linux_compat::vfs::resolve_path(0, path);
    // Sanity: this should always resolve to BASE_IMAGE_KEYSPACE for /lib/ etc.
    debug_assert_eq!(ks, BASE_IMAGE_KEYSPACE);
    store_multi_segment(BASE_IMAGE_KEYSPACE, key, data)?;
    record_base_image_path(path);
    Ok(())
}
