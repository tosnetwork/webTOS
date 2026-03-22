//! AOS State Object Subsystem
//!
//! Implements an in-memory key-value subsystem organized into keyspaces.
//! Each agent is automatically assigned a private keyspace at creation.
//! Access to any keyspace requires the corresponding CAP_STATE_READ or
//! CAP_STATE_WRITE capability. An agent always has implicit access to
//! its own private keyspace.

use crate::agent::{KeyspaceId, MAX_AGENTS, E_INVALID_ARG, E_NOT_FOUND, E_QUOTA_EXCEEDED, E_PAYLOAD_TOO_LARGE};

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

// ─── Keyspace ───────────────────────────────────────────────────────────────

struct Keyspace {
    id: KeyspaceId,
    entries: [StateEntry; MAX_ENTRIES_PER_KEYSPACE],
}

impl Keyspace {
    fn new(id: KeyspaceId) -> Self {
        Keyspace {
            id,
            entries: [const { StateEntry::empty() }; MAX_ENTRIES_PER_KEYSPACE],
        }
    }

    fn get(&self, key: u64) -> Option<&[u8]> {
        for entry in self.entries.iter() {
            if entry.active && entry.key == key {
                return Some(&entry.value[..entry.len]);
            }
        }
        None
    }

    fn put(&mut self, key: u64, value: &[u8]) -> Result<(), i64> {
        if value.len() > MAX_VALUE_SIZE {
            return Err(E_PAYLOAD_TOO_LARGE);
        }

        // Try to find an existing entry with this key
        for entry in self.entries.iter_mut() {
            if entry.active && entry.key == key {
                entry.value[..value.len()].copy_from_slice(value);
                entry.len = value.len();
                return Ok(());
            }
        }

        // Find a free slot
        for entry in self.entries.iter_mut() {
            if !entry.active {
                entry.key = key;
                entry.value[..value.len()].copy_from_slice(value);
                entry.len = value.len();
                entry.active = true;
                return Ok(());
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
            Some(ks) => ks.put(key, value),
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
pub fn state_put(keyspace: KeyspaceId, key: u64, value: &[u8]) -> Result<(), i64> {
    put(keyspace, key, value)
}
