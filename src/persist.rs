//! AOS Persistent State Store
//!
//! Append-only log on disk with in-memory index for fast lookups.
//! Each log entry: [sequence: u64, keyspace_id: u16, key: u64, len: u16,
//!                  value: [u8; 256], crc32: u32]
//!
//! Falls back to in-memory-only storage when no disk is present.
//!
//! Reference: AOS Yellow Paper §24.5.

use crate::agent::{KeyspaceId, MAX_AGENTS, E_INVALID_ARG, E_NOT_FOUND, E_QUOTA_EXCEEDED, E_PAYLOAD_TOO_LARGE};
use crate::block::StorageDevice;

const MAX_ENTRIES_PER_KEYSPACE: usize = 64;
const MAX_VALUE_SIZE: usize = 256;
const STATE_START_SECTOR: u32 = 0;
const MAX_LOG_SECTORS: u32 = 1024; // ~512 KB state log region

// ─── CRC32 ──────────────────────────────────────────────────────────────────

/// CRC32 (ISO 3309 / ITU-T V.42) using a bit-by-bit loop.
/// No lookup table needed — saves static memory.
fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

// ─── On-disk log entry ──────────────────────────────────────────────────────

/// Size of a serialized log entry in bytes. Must be a multiple of
/// `SECTOR_SIZE` or we must pack/pad. For simplicity, we pad each entry
/// to exactly one sector (512 bytes).
///
/// Layout within a 512-byte sector:
///   offset  0: sequence   (u64, 8 bytes)
///   offset  8: keyspace_id (u16, 2 bytes)
///   offset 10: padding     (2 bytes, zeroed)
///   offset 12: reserved    (4 bytes, zeroed)
///   offset 16: key         (u64, 8 bytes)
///   offset 24: len         (u16, 2 bytes)
///   offset 26: padding     (2 bytes, zeroed)
///   offset 28: reserved    (4 bytes, zeroed — aligns value to offset 32)
///   offset 32: value       (256 bytes)
///   offset 288: crc32      (u32, 4 bytes)
///   offset 292..512: unused padding (zeroed)
///
/// The CRC32 covers bytes 0..288 (everything before the CRC field).
const ENTRY_SIZE: usize = 512; // one ATA/NVMe sector
const CRC_OFFSET: usize = 288;
const VALUE_OFFSET: usize = 32;

// ─── In-memory index ────────────────────────────────────────────────────────

#[derive(Clone)]
struct IndexEntry {
    key: u64,
    value: [u8; MAX_VALUE_SIZE],
    len: usize,
    active: bool,
}

impl IndexEntry {
    const fn empty() -> Self {
        IndexEntry {
            key: 0,
            value: [0u8; MAX_VALUE_SIZE],
            len: 0,
            active: false,
        }
    }
}

struct KeyspaceIndex {
    id: KeyspaceId,
    entries: [IndexEntry; MAX_ENTRIES_PER_KEYSPACE],
    active: bool,
}

impl KeyspaceIndex {
    fn new(id: KeyspaceId) -> Self {
        KeyspaceIndex {
            id,
            entries: [const { IndexEntry::empty() }; MAX_ENTRIES_PER_KEYSPACE],
            active: true,
        }
    }
}

// ─── Global State ───────────────────────────────────────────────────────────

// Safety: single-core, no preemption during state access in Stage-2.
static mut KEYSPACES: [Option<KeyspaceIndex>; MAX_AGENTS] = [const { None }; MAX_AGENTS];
static mut NEXT_SEQUENCE: u64 = 0;
static mut NEXT_SECTOR: u32 = STATE_START_SECTOR;
static mut DISK_AVAILABLE: bool = false;

// ─── Serialization Helpers ──────────────────────────────────────────────────

/// Write a u64 in little-endian to `buf` at `offset`.
fn put_u64(buf: &mut [u8], offset: usize, val: u64) {
    let bytes = val.to_le_bytes();
    buf[offset..offset + 8].copy_from_slice(&bytes);
}

/// Read a u64 in little-endian from `buf` at `offset`.
fn get_u64(buf: &[u8], offset: usize) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&buf[offset..offset + 8]);
    u64::from_le_bytes(bytes)
}

/// Write a u16 in little-endian to `buf` at `offset`.
fn put_u16(buf: &mut [u8], offset: usize, val: u16) {
    let bytes = val.to_le_bytes();
    buf[offset..offset + 2].copy_from_slice(&bytes);
}

/// Read a u16 in little-endian from `buf` at `offset`.
fn get_u16(buf: &[u8], offset: usize) -> u16 {
    let mut bytes = [0u8; 2];
    bytes.copy_from_slice(&buf[offset..offset + 2]);
    u16::from_le_bytes(bytes)
}

/// Write a u32 in little-endian to `buf` at `offset`.
fn put_u32(buf: &mut [u8], offset: usize, val: u32) {
    let bytes = val.to_le_bytes();
    buf[offset..offset + 4].copy_from_slice(&bytes);
}

/// Read a u32 in little-endian from `buf` at `offset`.
fn get_u32(buf: &[u8], offset: usize) -> u32 {
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&buf[offset..offset + 4]);
    u32::from_le_bytes(bytes)
}

/// Serialize a log entry into a 512-byte sector buffer.
fn serialize_entry(
    buf: &mut [u8; ENTRY_SIZE],
    sequence: u64,
    keyspace_id: KeyspaceId,
    key: u64,
    value: &[u8],
) {
    // Zero the buffer first
    buf.fill(0);

    put_u64(buf, 0, sequence);
    put_u16(buf, 8, keyspace_id);
    // bytes 10..16: padding/reserved (already zeroed)
    put_u64(buf, 16, key);
    put_u16(buf, 24, value.len() as u16);
    // bytes 26..32: padding/reserved (already zeroed)
    buf[VALUE_OFFSET..VALUE_OFFSET + value.len()].copy_from_slice(value);

    let checksum = crc32(&buf[..CRC_OFFSET]);
    put_u32(buf, CRC_OFFSET, checksum);
}

/// Deserialize a log entry from a 512-byte sector buffer.
/// Returns (sequence, keyspace_id, key, len) and the value is in
/// `buf[VALUE_OFFSET..VALUE_OFFSET + len]`.
/// Returns `None` if the entry is empty (all-zero sequence) or CRC mismatch.
fn deserialize_entry(buf: &[u8; ENTRY_SIZE]) -> Option<(u64, KeyspaceId, u64, usize)> {
    let sequence = get_u64(buf, 0);

    // An all-zero sector is considered the end of the log.
    if sequence == 0 {
        return None;
    }

    // Verify CRC
    let stored_crc = get_u32(buf, CRC_OFFSET);
    let computed_crc = crc32(&buf[..CRC_OFFSET]);
    if stored_crc != computed_crc {
        return None; // corrupted entry — stop replay
    }

    let keyspace_id = get_u16(buf, 8);
    let key = get_u64(buf, 16);
    let len = get_u16(buf, 24) as usize;

    if len > MAX_VALUE_SIZE {
        return None; // invalid
    }

    Some((sequence, keyspace_id, key, len))
}

// ─── In-memory index operations ─────────────────────────────────────────────

/// Apply a key-value pair to the in-memory index.
/// Creates the keyspace if it doesn't exist.
fn index_apply(keyspace_id: KeyspaceId, key: u64, value: &[u8]) {
    let idx = keyspace_id as usize;
    if idx >= MAX_AGENTS {
        return;
    }

    // Safety: single-core
    unsafe {
        // Create keyspace if it doesn't exist
        if KEYSPACES[idx].is_none() {
            KEYSPACES[idx] = Some(KeyspaceIndex::new(keyspace_id));
        }

        if let Some(ref mut ks) = KEYSPACES[idx] {
            // Try to update existing entry
            for entry in ks.entries.iter_mut() {
                if entry.active && entry.key == key {
                    entry.value[..value.len()].copy_from_slice(value);
                    entry.len = value.len();
                    return;
                }
            }
            // Find a free slot
            for entry in ks.entries.iter_mut() {
                if !entry.active {
                    entry.key = key;
                    entry.value[..value.len()].copy_from_slice(value);
                    entry.len = value.len();
                    entry.active = true;
                    return;
                }
            }
            // No free slot — silently drop during replay
        }
    }
}

// ─── Public API ─────────────────────────────────────────────────────────────

/// Initialize the persistent state store.
///
/// 1. Probes for an ATA disk on the primary channel.
/// 2. If found, replays the append-only log to rebuild the in-memory index.
/// 3. If not found, operates in in-memory-only mode (identical to Stage-1).
pub fn init() {
    let device = StorageDevice::detect();
    let disk_present = device.is_some();

    // Safety: single-core init
    unsafe {
        DISK_AVAILABLE = disk_present;
    }

    if !disk_present {
        crate::serial_println!("[persist] no storage device detected — in-memory only");
        return;
    }

    let device = device.unwrap();
    crate::serial_println!("[persist] {} detected — replaying state log...", device.name());

    // Replay log from sector 0
    let mut sector_buf = [0u8; ENTRY_SIZE];
    let mut replayed: u64 = 0;

    for sector in STATE_START_SECTOR..MAX_LOG_SECTORS {
        if device.read(sector as u64, 1, &mut sector_buf).is_err() {
            break;
        }

        let buf: &[u8; ENTRY_SIZE] = sector_buf[..ENTRY_SIZE]
            .try_into()
            .unwrap_or_else(|_| unreachable!());

        // Check for empty sector (all-zero sequence means end of log)
        let sequence = get_u64(buf, 0);
        if sequence == 0 {
            unsafe { NEXT_SECTOR = sector; }
            break;
        }

        // Verify CRC32 of the entry before replaying
        let stored_crc = get_u32(buf, CRC_OFFSET);
        let computed_crc = crc32(&buf[..CRC_OFFSET]);
        if stored_crc != computed_crc {
            crate::serial_println!(
                "[persist] CRC mismatch at sector {} (stored={:#010x}, computed={:#010x}), truncating log",
                sector, stored_crc, computed_crc
            );
            unsafe { NEXT_SECTOR = sector; }
            break; // Stop replay — this entry was partially written during a crash
        }

        match deserialize_entry(buf) {
            Some((sequence, keyspace_id, key, len)) => {
                let value = &sector_buf[VALUE_OFFSET..VALUE_OFFSET + len];
                index_apply(keyspace_id, key, value);
                // Safety: single-core init
                unsafe {
                    if sequence >= NEXT_SEQUENCE {
                        NEXT_SEQUENCE = sequence + 1;
                    }
                    NEXT_SECTOR = sector + 1;
                }
                replayed += 1;
            }
            None => {
                // Entry was invalid (e.g., len > MAX_VALUE_SIZE)
                crate::serial_println!("[persist] invalid entry at sector {}, stopping replay", sector);
                unsafe { NEXT_SECTOR = sector; }
                break;
            }
        }
    }

    crate::serial_println!("[persist] replayed {} log entries", replayed);
}

/// Create a new keyspace with the given ID.
pub fn create_keyspace(id: KeyspaceId) -> Result<(), i64> {
    let idx = id as usize;
    if idx >= MAX_AGENTS {
        return Err(E_INVALID_ARG);
    }

    // Safety: single-core
    unsafe {
        if KEYSPACES[idx].is_some() {
            return Err(E_INVALID_ARG);
        }
        KEYSPACES[idx] = Some(KeyspaceIndex::new(id));
    }

    Ok(())
}

/// Destroy a keyspace and free its slot.
pub fn destroy_keyspace(id: KeyspaceId) {
    let idx = id as usize;
    // Safety: single-core
    unsafe {
        if idx < MAX_AGENTS {
            KEYSPACES[idx] = None;
        }
    }
}

/// Get a value from the persistent state store.
///
/// Returns a slice of the value if found.
pub fn get(keyspace: KeyspaceId, key: u64) -> Option<&'static [u8]> {
    let idx = keyspace as usize;
    if idx >= MAX_AGENTS {
        return None;
    }

    // Safety: single-core
    unsafe {
        match KEYSPACES[idx].as_ref() {
            Some(ks) if ks.active => {
                for entry in ks.entries.iter() {
                    if entry.active && entry.key == key {
                        return Some(&entry.value[..entry.len]);
                    }
                }
                None
            }
            _ => None,
        }
    }
}

/// Put a value into the persistent state store.
///
/// 1. Updates the in-memory index.
/// 2. If a disk is available, appends a log entry (write-ahead).
pub fn put(keyspace: KeyspaceId, key: u64, value: &[u8]) -> Result<(), i64> {
    if value.len() > MAX_VALUE_SIZE {
        return Err(E_PAYLOAD_TOO_LARGE);
    }

    let idx = keyspace as usize;
    if idx >= MAX_AGENTS {
        return Err(E_INVALID_ARG);
    }

    // Safety: single-core
    unsafe {
        // Check keyspace exists
        if KEYSPACES[idx].is_none() {
            return Err(E_NOT_FOUND);
        }

        // Write to disk first (write-ahead) if available
        if DISK_AVAILABLE {
            if NEXT_SECTOR >= MAX_LOG_SECTORS {
                return Err(E_QUOTA_EXCEEDED); // log is full
            }

            let mut sector_buf = [0u8; ENTRY_SIZE];
            serialize_entry(&mut sector_buf, NEXT_SEQUENCE, keyspace, key, value);

            let dev = StorageDevice::detect();
            let write_ok = dev.map_or(false, |d| d.write(NEXT_SECTOR as u64, 1, &sector_buf).is_ok());
            if !write_ok {
                // Disk write failed — still update in-memory
                crate::serial_println!("[persist] WARNING: disk write failed at sector {}", NEXT_SECTOR);
            } else {
                NEXT_SEQUENCE += 1;
                NEXT_SECTOR += 1;
            }
        }

        // Update in-memory index
        let ks = KEYSPACES[idx].as_mut().unwrap();

        // Try to update existing entry
        for entry in ks.entries.iter_mut() {
            if entry.active && entry.key == key {
                entry.value[..value.len()].copy_from_slice(value);
                entry.len = value.len();
                return Ok(());
            }
        }

        // Find a free slot
        for entry in ks.entries.iter_mut() {
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

/// Get a value with a copy (returns owned array + length).
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
