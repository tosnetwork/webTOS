//! eBPF-lite maps — shared key-value data structures.
//!
//! Fixed-size hash maps and array maps for communication between eBPF programs
//! and the kernel or agents. Protected by SpinLock for SMP safety.

use super::types::EbpfError;
use crate::sync::SpinLock;

pub const MAX_MAPS: usize = 8;
pub const MAX_MAP_ENTRIES: usize = 64;
pub const MAX_KEY_SIZE: usize = 8;
pub const MAX_VALUE_SIZE: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MapType {
    Hash,
    Array,
}

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
    pub map_type: MapType,
    pub entries: [MapEntry; MAX_MAP_ENTRIES],
    pub count: usize,
    pub persistent: bool,
    pub owner_keyspace: u16,
}

impl EbpfMap {
    /// Create an empty hash map with the given ID.
    pub const fn new(id: u32) -> Self {
        EbpfMap {
            id,
            map_type: MapType::Hash,
            entries: [MapEntry::empty(); MAX_MAP_ENTRIES],
            count: 0,
            persistent: false,
            owner_keyspace: 0,
        }
    }

    /// Create a map with the given ID and type.
    pub fn new_typed(id: u32, map_type: MapType) -> Self {
        EbpfMap {
            id,
            map_type,
            entries: [MapEntry::empty(); MAX_MAP_ENTRIES],
            count: 0,
            persistent: false,
            owner_keyspace: 0,
        }
    }

    /// Look up a value by key. Returns a reference to the value bytes.
    pub fn lookup(&self, key: &[u8]) -> Option<&[u8]> {
        match self.map_type {
            MapType::Array => {
                // Key is interpreted as a little-endian u32 index
                if key.len() < 4 { return None; }
                let idx = u32::from_le_bytes([key[0], key[1], key[2], key[3]]) as usize;
                if idx >= MAX_MAP_ENTRIES { return None; }
                let entry = &self.entries[idx];
                if entry.occupied {
                    Some(&entry.value[..entry.value_len])
                } else {
                    None
                }
            }
            MapType::Hash => {
                for entry in self.entries.iter() {
                    if entry.occupied && entry.key_len == key.len()
                        && entry.key[..entry.key_len] == key[..key.len()]
                    {
                        return Some(&entry.value[..entry.value_len]);
                    }
                }
                None
            }
        }
    }

    /// Insert or update a key-value pair.
    pub fn update(&mut self, key: &[u8], value: &[u8]) -> Result<(), EbpfError> {
        if key.len() > MAX_KEY_SIZE { return Err(EbpfError::KeyTooLarge); }
        if value.len() > MAX_VALUE_SIZE { return Err(EbpfError::ValueTooLarge); }

        match self.map_type {
            MapType::Array => {
                if key.len() < 4 { return Err(EbpfError::KeyTooLarge); }
                let idx = u32::from_le_bytes([key[0], key[1], key[2], key[3]]) as usize;
                if idx >= MAX_MAP_ENTRIES { return Err(EbpfError::OutOfBounds); }
                let entry = &mut self.entries[idx];
                if !entry.occupied {
                    self.count += 1;
                }
                entry.key[..key.len()].copy_from_slice(key);
                entry.key_len = key.len();
                entry.value[..value.len()].copy_from_slice(value);
                entry.value_len = value.len();
                entry.occupied = true;
                Ok(())
            }
            MapType::Hash => {
                // First, try to find existing key
                for entry in self.entries.iter_mut() {
                    if entry.occupied && entry.key_len == key.len()
                        && entry.key[..entry.key_len] == key[..key.len()]
                    {
                        entry.value[..value.len()].copy_from_slice(value);
                        entry.value_len = value.len();
                        return Ok(());
                    }
                }
                // Insert into first empty slot
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
        }
    }

    /// Delete an entry by key. Returns true if the key was found.
    pub fn delete(&mut self, key: &[u8]) -> bool {
        match self.map_type {
            MapType::Array => {
                if key.len() < 4 { return false; }
                let idx = u32::from_le_bytes([key[0], key[1], key[2], key[3]]) as usize;
                if idx >= MAX_MAP_ENTRIES { return false; }
                let entry = &mut self.entries[idx];
                if entry.occupied {
                    entry.occupied = false;
                    entry.key_len = 0;
                    entry.value_len = 0;
                    self.count -= 1;
                    true
                } else {
                    false
                }
            }
            MapType::Hash => {
                for entry in self.entries.iter_mut() {
                    if entry.occupied && entry.key_len == key.len()
                        && entry.key[..entry.key_len] == key[..key.len()]
                    {
                        entry.occupied = false;
                        entry.key_len = 0;
                        entry.value_len = 0;
                        self.count -= 1;
                        return true;
                    }
                }
                false
            }
        }
    }
}

// ─── Global map table ───────────────────────────────────────────────────────
//
// Two-level protection:
//   - MAPS_SLOT_LOCK (SpinLock): protects slot creation/deletion in MAPS array.
//     Only acquired by create_map/create_map_typed (called from init or policyd).
//   - MAPS (static mut): map data is accessed directly during eBPF VM execution.
//     Safety: eBPF execution is serialized by the PROGRAMS SpinLock in attach.rs.
//     No two eBPF programs execute concurrently, so map reads/writes cannot race.
//     Slot creation (create_map) only occurs outside eBPF execution contexts.

static MAPS_SLOT_LOCK: SpinLock<()> = SpinLock::new(());
static mut MAPS: [Option<EbpfMap>; MAX_MAPS] = [const { None }; MAX_MAPS];

/// Create a new hash map with the given ID.
///
/// Returns an error if all map slots are occupied.
pub fn create_map(id: u32) -> Result<(), EbpfError> {
    create_map_typed(id, MapType::Hash)
}

/// Create a new map with the given ID and type.
/// Protected by MAPS_SLOT_LOCK for SMP safety.
pub fn create_map_typed(id: u32, map_type: MapType) -> Result<(), EbpfError> {
    let _guard = MAPS_SLOT_LOCK.lock();
    // Safety: slot creation is serialized by MAPS_SLOT_LOCK
    unsafe {
        for slot in MAPS.iter_mut() {
            if slot.is_none() {
                *slot = Some(EbpfMap::new_typed(id, map_type));
                return Ok(());
            }
        }
    }
    Err(EbpfError::NoFreeSlot)
}

/// Get an immutable reference to a map by ID.
///
/// Safety: caller must ensure no concurrent mutation of the map table.
/// During eBPF execution this is guaranteed by the PROGRAMS SpinLock.
pub fn get_map(id: u32) -> Option<&'static EbpfMap> {
    // Safety: MAPS is static (never freed). Data access is serialized by
    // PROGRAMS lock — only one eBPF program executes at a time.
    unsafe {
        for slot in MAPS.iter() {
            if let Some(ref map) = slot {
                if map.id == id {
                    return Some(map);
                }
            }
        }
        None
    }
}

/// Get a mutable reference to a map by ID.
///
/// Safety: caller must ensure no concurrent access to the same map.
/// During eBPF execution this is guaranteed by the PROGRAMS SpinLock.
pub fn get_map_mut(id: u32) -> Option<&'static mut EbpfMap> {
    // Safety: see get_map. Mutable access is safe because only one eBPF
    // program runs at a time (PROGRAMS lock) and map slot structure doesn't
    // change during execution.
    unsafe {
        for slot in MAPS.iter_mut() {
            if let Some(ref mut map) = slot {
                if map.id == id {
                    return Some(map);
                }
            }
        }
        None
    }
}

/// Serialize a map's entries to the agent's keyspace for persistence.
///
/// Safety: accesses MAPS directly. Must be called from eBPF execution
/// context (serialized by PROGRAMS lock) or when no eBPF is running.
pub fn persist_map(map_id: u32, keyspace: u16) -> u32 {
    // Safety: called from eBPF helper during VM execution (PROGRAMS locked)
    let maps = unsafe { &MAPS };
    for slot in maps.iter() {
        if let Some(ref map) = slot {
            if map.id == map_id {
                // Store metadata at key = 0xFFFF_0000 | map_id
                let meta_key = 0xFFFF_0000u64 | map_id as u64;
                let mut meta = [0u8; 8];
                meta[0..4].copy_from_slice(&(map.count as u32).to_le_bytes());
                meta[4] = map.map_type as u8;
                if crate::state::put(keyspace, meta_key, &meta).is_err() {
                    return 1;
                }

                let mut entry_idx: u32 = 0;
                for entry in map.entries.iter() {
                    if entry.occupied {
                        let state_key = ((map_id as u64) << 32) | entry_idx as u64;
                        // Serialize: [key_len:2, val_len:2, key, value]
                        let mut buf = [0u8; 4 + MAX_KEY_SIZE + MAX_VALUE_SIZE];
                        buf[0..2].copy_from_slice(&(entry.key_len as u16).to_le_bytes());
                        buf[2..4].copy_from_slice(&(entry.value_len as u16).to_le_bytes());
                        buf[4..4 + entry.key_len].copy_from_slice(&entry.key[..entry.key_len]);
                        let val_off = 4 + MAX_KEY_SIZE;
                        buf[val_off..val_off + entry.value_len]
                            .copy_from_slice(&entry.value[..entry.value_len]);
                        let total = val_off + entry.value_len;
                        if crate::state::put(keyspace, state_key, &buf[..total]).is_err() {
                            return 1;
                        }
                        entry_idx += 1;
                    }
                }
                return 0;
            }
        }
    }
    1 // map not found
}

/// Restore a map's entries from the agent's keyspace.
///
/// Safety: accesses MAPS directly. Must be called from eBPF execution
/// context (serialized by PROGRAMS lock) or when no eBPF is running.
pub fn restore_map(map_id: u32, keyspace: u16) -> u32 {
    // Safety: called from eBPF helper during VM execution (PROGRAMS locked)
    let maps = unsafe { &mut MAPS };
    for slot in maps.iter_mut() {
        if let Some(ref mut map) = slot {
            if map.id == map_id {
                // Read metadata
                let meta_key = 0xFFFF_0000u64 | map_id as u64;
                let (meta_buf, meta_len) = match crate::state::state_get(keyspace, meta_key) {
                    Some(v) => v,
                    None => return 1,
                };
                if meta_len < 5 { return 1; }
                let entry_count = u32::from_le_bytes([meta_buf[0], meta_buf[1], meta_buf[2], meta_buf[3]]) as usize;

                // Clear existing entries
                for entry in map.entries.iter_mut() {
                    entry.occupied = false;
                    entry.key_len = 0;
                    entry.value_len = 0;
                }
                map.count = 0;

                // Restore entries
                for i in 0..entry_count {
                    let state_key = ((map_id as u64) << 32) | i as u64;
                    let (buf, buf_len) = match crate::state::state_get(keyspace, state_key) {
                        Some(v) => v,
                        None => continue,
                    };
                    if buf_len < 4 { continue; }
                    let key_len = u16::from_le_bytes([buf[0], buf[1]]) as usize;
                    let val_len = u16::from_le_bytes([buf[2], buf[3]]) as usize;
                    if key_len > MAX_KEY_SIZE || val_len > MAX_VALUE_SIZE { continue; }
                    if 4 + key_len > buf_len { continue; }

                    let val_off = 4 + MAX_KEY_SIZE;
                    if val_off + val_len > buf_len { continue; }

                    // Find an empty slot (for hash maps) or use index (for array)
                    let target_idx = if map.map_type == MapType::Array && key_len >= 4 {
                        u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]) as usize
                    } else {
                        // Find first empty slot
                        let mut found = MAX_MAP_ENTRIES;
                        for j in 0..MAX_MAP_ENTRIES {
                            if !map.entries[j].occupied {
                                found = j;
                                break;
                            }
                        }
                        found
                    };

                    if target_idx < MAX_MAP_ENTRIES {
                        let entry = &mut map.entries[target_idx];
                        entry.key[..key_len].copy_from_slice(&buf[4..4 + key_len]);
                        entry.key_len = key_len;
                        entry.value[..val_len].copy_from_slice(&buf[val_off..val_off + val_len]);
                        entry.value_len = val_len;
                        entry.occupied = true;
                        map.count += 1;
                    }
                }
                return 0;
            }
        }
    }
    1
}
