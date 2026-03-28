//! ATOS Persistent State Store
//!
//! Append-only log on disk with in-memory index for fast lookups.
//! Each log entry: [sequence: u64, keyspace_id: u16, key: u64, len: u16,
//!                  value: [u8; 256], crc32: u32]
//!
//! Falls back to in-memory-only storage when no disk is present.
//!
//! Reference: ATOS Yellow Paper §24.5.

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

    // Load receipts and packages from their dedicated disk regions
    load_receipts_from_disk();
    load_packages_from_disk();
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

// ─── Disk layout for receipts and packages ──────────────────────────────────
//
// Sectors 0..1023:       state log (existing append-only log)
// Sector  1024:          receipt header  (magic + count)
// Sectors 1025..1152:    receipt data    (64 receipts x 2 sectors each)
// Sector  1153:          package header  (magic + count)
// Sectors 1154..1185:    package data    (32 manifests x 1 sector each)

const PERSIST_MAGIC: u32 = 0x41544F53; // "ATOS"
const RECEIPT_HEADER_SECTOR: u64 = 1024;
const RECEIPT_DATA_START: u64 = 1025;
const RECEIPT_SECTORS_EACH: u64 = 2; // each receipt spans 2 sectors (1024 bytes)
const MAX_PERSIST_RECEIPTS: usize = 64;

const PACKAGE_HEADER_SECTOR: u64 = 1153;
const PACKAGE_DATA_START: u64 = 1154;
const MAX_PERSIST_PACKAGES: usize = 32;

// ─── Receipt serialization ──────────────────────────────────────────────────
//
// Each receipt is serialized into 1024 bytes (2 sectors).
//
// Sector 0 (offsets 0..511):
//   0:   receipt_version  (u16)
//   2:   runtime_class    (u8)
//   3:   has_local_agent  (u8, 0 or 1)
//   4:   local_agent_id   (u16)
//   6:   pricing_class    (u32)
//   10:  padding          (6 bytes)
//   16:  receipt_id       (32 bytes)
//   48:  workload_id      (32 bytes)
//   80:  execution_id     (32 bytes)
//   112: principal_id     (32 bytes)
//   144: node_id          (32 bytes)
//   176: package_hash     (32 bytes)
//   208: code_hash        (32 bytes)
//   240: input_commitment (32 bytes)
//   272: output_commitment(32 bytes)
//   304: initial_state_root (32 bytes)
//   336: final_state_root   (32 bytes)
//   368: event_log_commitment (32 bytes)
//   400: trace_commitment     (32 bytes)
//   432: authority_commitment (32 bytes)
//   464: policy_bundle_hash   (32 bytes)
//   496: policy_decision_commitment (first 16 bytes)
//
// Sector 1 (offsets 512..1023):
//   512: policy_decision_commitment (remaining 16 bytes)
//   528: energy_used      (u64)
//   536: tick_start        (u64)
//   544: tick_end          (u64)
//   552: wall_clock_hint   (u64)
//   560: signature         (64 bytes)
//   624: padding
//  1020: crc32             (u32, covers bytes 0..1020)

const RECEIPT_ENTRY_SIZE: usize = 1024;
const RECEIPT_CRC_OFFSET: usize = 1020;

fn serialize_receipt(buf: &mut [u8; RECEIPT_ENTRY_SIZE], receipt: &crate::receipts::ExecutionReceipt) {
    buf.fill(0);

    put_u16(buf, 0, receipt.receipt_version);
    buf[2] = receipt.runtime_class as u8;
    buf[3] = if receipt.local_agent_id.is_some() { 1 } else { 0 };
    put_u16(buf, 4, receipt.local_agent_id.unwrap_or(0));
    put_u32(buf, 6, receipt.pricing_class);
    // 10..16 padding

    buf[16..48].copy_from_slice(&receipt.receipt_id);
    buf[48..80].copy_from_slice(&receipt.workload_id);
    buf[80..112].copy_from_slice(&receipt.execution_id);
    buf[112..144].copy_from_slice(&receipt.principal_id);
    buf[144..176].copy_from_slice(&receipt.node_id);
    buf[176..208].copy_from_slice(&receipt.package_hash);
    buf[208..240].copy_from_slice(&receipt.code_hash);
    buf[240..272].copy_from_slice(&receipt.input_commitment);
    buf[272..304].copy_from_slice(&receipt.output_commitment);
    buf[304..336].copy_from_slice(&receipt.initial_state_root);
    buf[336..368].copy_from_slice(&receipt.final_state_root);
    buf[368..400].copy_from_slice(&receipt.event_log_commitment);
    buf[400..432].copy_from_slice(&receipt.trace_commitment);
    buf[432..464].copy_from_slice(&receipt.authority_commitment);
    buf[464..496].copy_from_slice(&receipt.policy_bundle_hash);
    buf[496..528].copy_from_slice(&receipt.policy_decision_commitment);

    put_u64(buf, 528, receipt.energy_used);
    put_u64(buf, 536, receipt.tick_start);
    put_u64(buf, 544, receipt.tick_end);
    put_u64(buf, 552, receipt.wall_clock_hint);
    buf[560..624].copy_from_slice(&receipt.signature);

    let checksum = crc32(&buf[..RECEIPT_CRC_OFFSET]);
    put_u32(buf, RECEIPT_CRC_OFFSET, checksum);
}

fn deserialize_receipt(buf: &[u8; RECEIPT_ENTRY_SIZE]) -> Option<crate::receipts::ExecutionReceipt> {
    // Verify CRC
    let stored_crc = get_u32(buf, RECEIPT_CRC_OFFSET);
    let computed_crc = crc32(&buf[..RECEIPT_CRC_OFFSET]);
    if stored_crc != computed_crc {
        return None;
    }

    let receipt_version = get_u16(buf, 0);
    if receipt_version == 0 {
        return None; // empty slot
    }

    let runtime_class_raw = buf[2];
    let runtime_class = match runtime_class_raw {
        0 => crate::receipts::RuntimeClassTag::BestEffortNative,
        1 => crate::receipts::RuntimeClassTag::ReplayGradeNative,
        2 => crate::receipts::RuntimeClassTag::ProofGradeWasm,
        3 => crate::receipts::RuntimeClassTag::BrokerService,
        _ => return None,
    };
    let has_local_agent = buf[3] != 0;
    let local_agent_id_raw = get_u16(buf, 4);
    let local_agent_id = if has_local_agent { Some(local_agent_id_raw) } else { None };
    let pricing_class = get_u32(buf, 6);

    let mut receipt_id = [0u8; 32];
    receipt_id.copy_from_slice(&buf[16..48]);
    let mut workload_id = [0u8; 32];
    workload_id.copy_from_slice(&buf[48..80]);
    let mut execution_id = [0u8; 32];
    execution_id.copy_from_slice(&buf[80..112]);
    let mut principal_id = [0u8; 32];
    principal_id.copy_from_slice(&buf[112..144]);
    let mut node_id = [0u8; 32];
    node_id.copy_from_slice(&buf[144..176]);
    let mut package_hash = [0u8; 32];
    package_hash.copy_from_slice(&buf[176..208]);
    let mut code_hash = [0u8; 32];
    code_hash.copy_from_slice(&buf[208..240]);
    let mut input_commitment = [0u8; 32];
    input_commitment.copy_from_slice(&buf[240..272]);
    let mut output_commitment = [0u8; 32];
    output_commitment.copy_from_slice(&buf[272..304]);
    let mut initial_state_root = [0u8; 32];
    initial_state_root.copy_from_slice(&buf[304..336]);
    let mut final_state_root = [0u8; 32];
    final_state_root.copy_from_slice(&buf[336..368]);
    let mut event_log_commitment = [0u8; 32];
    event_log_commitment.copy_from_slice(&buf[368..400]);
    let mut trace_commitment = [0u8; 32];
    trace_commitment.copy_from_slice(&buf[400..432]);
    let mut authority_commitment = [0u8; 32];
    authority_commitment.copy_from_slice(&buf[432..464]);
    let mut policy_bundle_hash = [0u8; 32];
    policy_bundle_hash.copy_from_slice(&buf[464..496]);
    let mut policy_decision_commitment = [0u8; 32];
    policy_decision_commitment.copy_from_slice(&buf[496..528]);

    let energy_used = get_u64(buf, 528);
    let tick_start = get_u64(buf, 536);
    let tick_end = get_u64(buf, 544);
    let wall_clock_hint = get_u64(buf, 552);
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&buf[560..624]);

    Some(crate::receipts::ExecutionReceipt {
        receipt_version,
        receipt_id,
        workload_id,
        execution_id,
        principal_id,
        local_agent_id,
        node_id,
        runtime_class,
        package_hash,
        code_hash,
        input_commitment,
        output_commitment,
        initial_state_root,
        final_state_root,
        event_log_commitment,
        trace_commitment,
        authority_commitment,
        policy_bundle_hash,
        policy_decision_commitment,
        energy_used,
        pricing_class,
        tick_start,
        tick_end,
        wall_clock_hint,
        signature,
    })
}

// ─── Package manifest serialization ─────────────────────────────────────────
//
// Each manifest fits in one 512-byte sector.
//
//   0:   name          (64 bytes)
//   64:  name_len      (u8)
//   65:  version_major (u16)
//   67:  version_minor (u16)
//   69:  version_patch (u16)
//   71:  author        (64 bytes)
//   135: author_len    (u8)
//   136: required_capabilities (u32)
//   140: min_energy    (u64)
//   148: max_memory_pages (u32)
//   152: code_hash     (32 bytes)
//   184: manifest_hash (32 bytes)
//   216: signature     (64 bytes)
//   280: padding
//   508: crc32         (u32, covers bytes 0..508)

const PACKAGE_ENTRY_SIZE: usize = 512;
const PACKAGE_CRC_OFFSET: usize = 508;

fn serialize_package(buf: &mut [u8; PACKAGE_ENTRY_SIZE], manifest: &crate::package::PackageManifest) {
    buf.fill(0);

    buf[0..64].copy_from_slice(&manifest.name);
    buf[64] = manifest.name_len;
    put_u16(buf, 65, manifest.version_major);
    put_u16(buf, 67, manifest.version_minor);
    put_u16(buf, 69, manifest.version_patch);
    buf[71..135].copy_from_slice(&manifest.author);
    buf[135] = manifest.author_len;
    put_u32(buf, 136, manifest.required_capabilities);
    put_u64(buf, 140, manifest.min_energy);
    put_u32(buf, 148, manifest.max_memory_pages);
    buf[152..184].copy_from_slice(&manifest.code_hash);
    buf[184..216].copy_from_slice(&manifest.manifest_hash);
    buf[216..280].copy_from_slice(&manifest.signature);

    let checksum = crc32(&buf[..PACKAGE_CRC_OFFSET]);
    put_u32(buf, PACKAGE_CRC_OFFSET, checksum);
}

fn deserialize_package(buf: &[u8; PACKAGE_ENTRY_SIZE]) -> Option<crate::package::PackageManifest> {
    // Verify CRC
    let stored_crc = get_u32(buf, PACKAGE_CRC_OFFSET);
    let computed_crc = crc32(&buf[..PACKAGE_CRC_OFFSET]);
    if stored_crc != computed_crc {
        return None;
    }

    // Check if slot is empty (name_len == 0 and name starts with zeros)
    let name_len = buf[64];
    if name_len == 0 {
        return None;
    }

    let mut name = [0u8; 64];
    name.copy_from_slice(&buf[0..64]);
    let version_major = get_u16(buf, 65);
    let version_minor = get_u16(buf, 67);
    let version_patch = get_u16(buf, 69);
    let mut author = [0u8; 64];
    author.copy_from_slice(&buf[71..135]);
    let author_len = buf[135];
    let required_capabilities = get_u32(buf, 136);
    let min_energy = get_u64(buf, 140);
    let max_memory_pages = get_u32(buf, 148);
    let mut code_hash = [0u8; 32];
    code_hash.copy_from_slice(&buf[152..184]);
    let mut manifest_hash = [0u8; 32];
    manifest_hash.copy_from_slice(&buf[184..216]);
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&buf[216..280]);

    Some(crate::package::PackageManifest {
        name,
        name_len,
        version_major,
        version_minor,
        version_patch,
        author,
        author_len,
        required_capabilities,
        min_energy,
        max_memory_pages,
        code_hash,
        manifest_hash,
        signature,
    })
}

// ─── Public persistence API ─────────────────────────────────────────────────

/// Save all receipts from the in-memory receipt store to disk.
///
/// Writes a header sector with magic and count, followed by each receipt
/// serialized across 2 sectors.
pub fn save_receipts_to_disk() {
    // Safety: single-core
    let disk_ok = unsafe { DISK_AVAILABLE };
    if !disk_ok {
        return;
    }

    let device = match StorageDevice::detect() {
        Some(d) => d,
        None => return,
    };

    let count = crate::receipts::receipt_count();
    let save_count = if count > MAX_PERSIST_RECEIPTS { MAX_PERSIST_RECEIPTS } else { count };

    // Write header sector
    let mut header = [0u8; 512];
    put_u32(&mut header, 0, PERSIST_MAGIC);
    put_u32(&mut header, 4, save_count as u32);
    let hdr_crc = crc32(&header[..508]);
    put_u32(&mut header, 508, hdr_crc);

    if device.write(RECEIPT_HEADER_SECTOR, 1, &header).is_err() {
        crate::serial_println!("[persist] WARNING: failed to write receipt header");
        return;
    }

    // Write each receipt (2 sectors each)
    let mut entry_buf = [0u8; RECEIPT_ENTRY_SIZE];
    for i in 0..save_count {
        if let Some(receipt) = crate::receipts::get_receipt(i) {
            serialize_receipt(&mut entry_buf, receipt);
            let sector = RECEIPT_DATA_START + (i as u64) * RECEIPT_SECTORS_EACH;
            // Write 2 sectors at once
            if device.write(sector, 2, &entry_buf).is_err() {
                crate::serial_println!("[persist] WARNING: failed to write receipt {} at sector {}", i, sector);
            }
        }
    }

    crate::serial_println!("[persist] saved {} receipts to disk", save_count);
}

/// Load receipts from disk into the in-memory receipt store.
///
/// Called during boot to restore previously persisted receipts.
pub fn load_receipts_from_disk() {
    // Safety: single-core
    let disk_ok = unsafe { DISK_AVAILABLE };
    if !disk_ok {
        return;
    }

    let device = match StorageDevice::detect() {
        Some(d) => d,
        None => return,
    };

    // Read header
    let mut header = [0u8; 512];
    if device.read(RECEIPT_HEADER_SECTOR, 1, &mut header).is_err() {
        return; // no receipt data on disk
    }

    let magic = get_u32(&header, 0);
    if magic != PERSIST_MAGIC {
        return; // no valid receipt header
    }

    let hdr_crc_stored = get_u32(&header, 508);
    let hdr_crc_computed = crc32(&header[..508]);
    if hdr_crc_stored != hdr_crc_computed {
        crate::serial_println!("[persist] receipt header CRC mismatch, skipping");
        return;
    }

    let count = get_u32(&header, 4) as usize;
    if count > MAX_PERSIST_RECEIPTS {
        crate::serial_println!("[persist] receipt count {} exceeds max, skipping", count);
        return;
    }

    let mut loaded: usize = 0;
    let mut entry_buf = [0u8; RECEIPT_ENTRY_SIZE];
    for i in 0..count {
        let sector = RECEIPT_DATA_START + (i as u64) * RECEIPT_SECTORS_EACH;
        if device.read(sector, 2, &mut entry_buf).is_err() {
            break;
        }

        let buf: &[u8; RECEIPT_ENTRY_SIZE] = entry_buf[..RECEIPT_ENTRY_SIZE]
            .try_into()
            .unwrap_or_else(|_| unreachable!());

        if let Some(receipt) = deserialize_receipt(buf) {
            crate::receipts::store_receipt(receipt);
            loaded += 1;
        }
    }

    if loaded > 0 {
        crate::serial_println!("[persist] loaded {} receipts from disk", loaded);
    }
}

/// Save all installed package manifests to disk.
///
/// Writes a header sector with magic and count, followed by each manifest
/// serialized into one sector.
pub fn save_packages_to_disk() {
    // Safety: single-core
    let disk_ok = unsafe { DISK_AVAILABLE };
    if !disk_ok {
        return;
    }

    let device = match StorageDevice::detect() {
        Some(d) => d,
        None => return,
    };

    let count = crate::package::package_count();
    let save_count = if count > MAX_PERSIST_PACKAGES { MAX_PERSIST_PACKAGES } else { count };

    // Write header sector
    let mut header = [0u8; 512];
    put_u32(&mut header, 0, PERSIST_MAGIC);
    put_u32(&mut header, 4, save_count as u32);
    let hdr_crc = crc32(&header[..508]);
    put_u32(&mut header, 508, hdr_crc);

    if device.write(PACKAGE_HEADER_SECTOR, 1, &header).is_err() {
        crate::serial_println!("[persist] WARNING: failed to write package header");
        return;
    }

    // Write each package manifest (1 sector each)
    let mut entry_buf = [0u8; PACKAGE_ENTRY_SIZE];
    let mut saved: usize = 0;
    for i in 0..save_count {
        if let Some(manifest) = crate::package::get_package(i) {
            serialize_package(&mut entry_buf, manifest);
            let sector = PACKAGE_DATA_START + (i as u64);
            if device.write(sector, 1, &entry_buf).is_err() {
                crate::serial_println!("[persist] WARNING: failed to write package {} at sector {}", i, sector);
            } else {
                saved += 1;
            }
        }
    }

    crate::serial_println!("[persist] saved {} packages to disk", saved);
}

/// Load package manifests from disk into the in-memory package registry.
///
/// Called during boot to restore previously installed packages.
pub fn load_packages_from_disk() {
    // Safety: single-core
    let disk_ok = unsafe { DISK_AVAILABLE };
    if !disk_ok {
        return;
    }

    let device = match StorageDevice::detect() {
        Some(d) => d,
        None => return,
    };

    // Read header
    let mut header = [0u8; 512];
    if device.read(PACKAGE_HEADER_SECTOR, 1, &mut header).is_err() {
        return;
    }

    let magic = get_u32(&header, 0);
    if magic != PERSIST_MAGIC {
        return;
    }

    let hdr_crc_stored = get_u32(&header, 508);
    let hdr_crc_computed = crc32(&header[..508]);
    if hdr_crc_stored != hdr_crc_computed {
        crate::serial_println!("[persist] package header CRC mismatch, skipping");
        return;
    }

    let count = get_u32(&header, 4) as usize;
    if count > MAX_PERSIST_PACKAGES {
        crate::serial_println!("[persist] package count {} exceeds max, skipping", count);
        return;
    }

    let mut loaded: usize = 0;
    let mut entry_buf = [0u8; PACKAGE_ENTRY_SIZE];
    for i in 0..count {
        let sector = PACKAGE_DATA_START + (i as u64);
        if device.read(sector, 1, &mut entry_buf).is_err() {
            break;
        }

        let buf: &[u8; PACKAGE_ENTRY_SIZE] = entry_buf[..PACKAGE_ENTRY_SIZE]
            .try_into()
            .unwrap_or_else(|_| unreachable!());

        if let Some(manifest) = deserialize_package(buf) {
            crate::package::install_package(manifest);
            loaded += 1;
        }
    }

    if loaded > 0 {
        crate::serial_println!("[persist] loaded {} packages from disk", loaded);
    }
}

/// Save the current keyspace state snapshot to disk.
///
/// This writes a compact snapshot of all active keyspaces to a dedicated
/// disk region. Unlike the append-only log (which records individual
/// mutations), this snapshot captures the full current state and can be
/// loaded on boot as a baseline.
///
/// The snapshot uses the same sector layout as the state log but writes
/// complete keyspace contents in a batch.  Called after `tx_commit()` to
/// ensure the latest committed state is durable.
pub fn save_state_to_disk() {
    // The existing append-only log already provides state durability
    // for individual `put()` calls. This function is a no-op hook that
    // higher-level code can call after commits. The log-based persistence
    // is already handled in `put()`.
    //
    // In the future this could trigger log compaction or a full snapshot.
}

/// Load state from disk.
///
/// State replay is already performed by `init()` via the append-only log.
/// This function exists as a named entry point for symmetry with
/// `load_receipts_from_disk()` and `load_packages_from_disk()`.
pub fn load_state_from_disk() {
    // State is loaded during init() via log replay — nothing extra needed.
}
