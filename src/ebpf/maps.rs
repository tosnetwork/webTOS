//! eBPF-lite maps — shared key-value data structures.
//!
//! Fixed-size hash maps for communication between eBPF programs
//! and the kernel or agents.

use super::types::EbpfError;

pub const MAX_MAPS: usize = 8;
pub const MAX_MAP_ENTRIES: usize = 64;
pub const MAX_KEY_SIZE: usize = 8;
pub const MAX_VALUE_SIZE: usize = 64;

/// A single entry in an eBPF map.
#[derive(Clone, Copy)]
pub struct MapEntry {
    pub key: [u8; MAX_KEY_SIZE],
    pub value: [u8; MAX_VALUE_SIZE],
    pub key_len: usize,
    pub value_len: usize,
    pub occupied: bool,
}

impl MapEntry {
    const fn empty() -> Self {
        MapEntry {
            key: [0; MAX_KEY_SIZE],
            value: [0; MAX_VALUE_SIZE],
            key_len: 0,
            value_len: 0,
            occupied: false,
        }
    }
}

/// An eBPF map instance with fixed-size storage.
pub struct EbpfMap {
    pub id: u32,
    pub entries: [MapEntry; MAX_MAP_ENTRIES],
    pub count: usize,
}

impl EbpfMap {
    /// Create an empty map with the given ID.
    pub const fn new(id: u32) -> Self {
        EbpfMap {
            id,
            entries: [MapEntry::empty(); MAX_MAP_ENTRIES],
            count: 0,
        }
    }

    /// Look up a value by key. Returns a reference to the value bytes.
    pub fn lookup(&self, key: &[u8]) -> Option<&[u8]> {
        for entry in self.entries.iter() {
            if entry.occupied && entry.key_len == key.len() {
                if &entry.key[..entry.key_len] == key {
                    return Some(&entry.value[..entry.value_len]);
                }
            }
        }
        None
    }

    /// Insert or update a key-value pair.
    pub fn update(&mut self, key: &[u8], value: &[u8]) -> Result<(), EbpfError> {
        if key.len() > MAX_KEY_SIZE {
            return Err(EbpfError::KeyTooLarge);
        }
        if value.len() > MAX_VALUE_SIZE {
            return Err(EbpfError::ValueTooLarge);
        }

        // Check if key already exists — update in place
        for entry in self.entries.iter_mut() {
            if entry.occupied && entry.key_len == key.len() {
                if entry.key[..entry.key_len] == *key {
                    entry.value[..value.len()].copy_from_slice(value);
                    entry.value_len = value.len();
                    return Ok(());
                }
            }
        }

        // Insert into first free slot
        for entry in self.entries.iter_mut() {
            if !entry.occupied {
                entry.key[..key.len()].copy_from_slice(key);
                entry.key_len = key.len();
                entry.value[..value.len()].copy_from_slice(value);
                entry.value_len = value.len();
                entry.occupied = true;
                self.count += 1;
                return Ok(());
            }
        }

        Err(EbpfError::MapFull)
    }

    /// Delete an entry by key. Returns true if the key was found.
    pub fn delete(&mut self, key: &[u8]) -> bool {
        for entry in self.entries.iter_mut() {
            if entry.occupied && entry.key_len == key.len() {
                if entry.key[..entry.key_len] == *key {
                    entry.occupied = false;
                    entry.key_len = 0;
                    entry.value_len = 0;
                    self.count -= 1;
                    return true;
                }
            }
        }
        false
    }
}

// ─── Global map table ───────────────────────────────────────────────────────

// Safety: single-core, no preemption during map access in Stage-1.
static mut MAPS: [Option<EbpfMap>; MAX_MAPS] = [const { None }; MAX_MAPS];

/// Create a new map with the given ID.
///
/// Returns an error if all map slots are occupied.
pub fn create_map(id: u32) -> Result<(), EbpfError> {
    // Safety: single-core access
    unsafe {
        for slot in MAPS.iter_mut() {
            if slot.is_none() {
                *slot = Some(EbpfMap::new(id));
                return Ok(());
            }
        }
        Err(EbpfError::NoFreeSlot)
    }
}

/// Get an immutable reference to a map by ID.
pub fn get_map(id: u32) -> Option<&'static EbpfMap> {
    // Safety: single-core access
    unsafe {
        for slot in MAPS.iter() {
            if let Some(map) = slot {
                if map.id == id {
                    return Some(map);
                }
            }
        }
        None
    }
}

/// Get a mutable reference to a map by ID.
pub fn get_map_mut(id: u32) -> Option<&'static mut EbpfMap> {
    // Safety: single-core access
    unsafe {
        for slot in MAPS.iter_mut() {
            if let Some(map) = slot {
                if map.id == id {
                    return Some(map);
                }
            }
        }
        None
    }
}
