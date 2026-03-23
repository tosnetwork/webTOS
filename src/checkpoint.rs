//! AOS Checkpoint & Replay
//!
//! Captures execution state and serializes it to disk via ATA PIO.
//! Checkpoint includes: agent contexts, energy counters, scheduler state,
//! event sequence, and Merkle state roots.
//!
//! Disk layout (starting at CHECKPOINT_START_SECTOR):
//!   Sector 0:       CheckpointHeader (padded to 512 bytes)
//!   Sectors 1..N:   CheckpointAgent entries (one per sector)
//!   Sectors N+1..M: Merkle roots (packed, 16 bytes each)

use crate::serial_println;
use crate::agent::*;
use crate::block::StorageDevice;
use crate::merkle;
use crate::capability::Capability;
extern crate alloc;
use alloc::vec::Vec;

/// Disk sector where checkpoints are stored (after the state log area)
const CHECKPOINT_START_SECTOR: u32 = 2048;

/// Checkpoint header (serialized to disk, padded to 512 bytes)
#[repr(C)]
pub struct CheckpointHeader {
    pub magic: u32,           // 0x414F5343 = "AOSC"
    pub version: u32,         // format version = 1
    pub tick: u64,
    pub event_sequence: u64,
    pub agent_count: u16,
    pub merkle_root_count: u16,
    pub total_size: u64,      // total bytes written (header + agents + merkle)
    // padding to 512 bytes is implicit (we write a full sector)
}

/// Saved agent state within a checkpoint (fits in one 512-byte sector)
#[repr(C)]
pub struct CheckpointAgent {
    pub id: AgentId,
    pub status: u8,
    pub mode: u8,
    pub energy_budget: u64,
    pub context: AgentContext, // 152 bytes (19 × u64)
    // total: 2 + 1 + 1 + 8 + 152 = 164 bytes, fits in 512-byte sector
}

/// I/O trace entry for replay
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TraceEntry {
    pub tick: u64,
    pub event_type: u8,   // 0=timer, 1=disk_read, 2=disk_write, 3=net_recv
    pub agent_id: AgentId,
    pub data_len: u16,
}

// ─── Trace recording ──────────────────────────────────────────────────────

const MAX_TRACE_ENTRIES: usize = 4096;

static mut TRACE_LOG: [Option<TraceEntry>; MAX_TRACE_ENTRIES] = [const { None }; MAX_TRACE_ENTRIES];
static mut TRACE_COUNT: usize = 0;
static mut TRACE_ENABLED: bool = false;

/// Enable I/O trace recording
pub fn enable_tracing() {
    unsafe {
        TRACE_ENABLED = true;
        TRACE_COUNT = 0;
        serial_println!("[CHECKPOINT] I/O tracing enabled");
    }
}

/// Disable I/O trace recording
pub fn disable_tracing() {
    unsafe {
        TRACE_ENABLED = false;
        serial_println!("[CHECKPOINT] I/O tracing disabled ({} entries)", TRACE_COUNT);
    }
}

/// Record a trace entry (called from I/O paths)
pub fn record_trace(tick: u64, event_type: u8, agent_id: AgentId) {
    unsafe {
        if !TRACE_ENABLED { return; }
        if TRACE_COUNT >= MAX_TRACE_ENTRIES { return; }
        TRACE_LOG[TRACE_COUNT] = Some(TraceEntry {
            tick,
            event_type,
            agent_id,
            data_len: 0,
        });
        TRACE_COUNT += 1;
    }
}

/// Get trace entry count
pub fn trace_count() -> usize {
    unsafe { TRACE_COUNT }
}

/// Get a trace entry by index
pub fn get_trace(index: usize) -> Option<TraceEntry> {
    unsafe {
        if index < TRACE_COUNT {
            TRACE_LOG[index]
        } else {
            None
        }
    }
}

// ─── Checkpoint serialization to disk ─────────────────────────────────────

/// Take a checkpoint and serialize it to disk via ATA PIO.
///
/// Returns true if the checkpoint was written successfully, false if
/// no disk is available or the write failed.
pub fn save_to_disk() -> bool {
    // Detect the best available storage device
    let device = match StorageDevice::detect() {
        Some(d) => d,
        None => {
            serial_println!("[CHECKPOINT] No disk available, checkpoint skipped");
            return false;
        }
    };

    const SECTOR_SIZE: usize = 512;

    let tick = crate::arch::x86_64::timer::get_ticks();
    let event_seq = crate::event::get_sequence();

    // ── Collect agent states ──
    let mut agents: [Option<CheckpointAgent>; MAX_AGENTS] = [const { None }; MAX_AGENTS];
    let mut agent_count = 0u16;

    for_each_agent_mut(|agent| {
        if agent.active && (agent_count as usize) < MAX_AGENTS {
            agents[agent_count as usize] = Some(CheckpointAgent {
                id: agent.id,
                status: agent.status as u8,
                mode: agent.mode as u8,
                energy_budget: agent.energy_budget,
                context: agent.context,
            });
            agent_count += 1;
        }
        true
    });

    // ── Collect Merkle roots ──
    let mut merkle_roots: [merkle::MerkleHash; MAX_AGENTS] = [[0u8; 16]; MAX_AGENTS];
    let mut merkle_count = 0u16;

    for i in 0..MAX_AGENTS {
        if let Some(root) = merkle::get_root(i as u16) {
            merkle_roots[i] = root;
            merkle_count += 1;
        }
    }

    // ── Write header (sector 0) ──
    let total_sectors = 1 + agent_count as u32 + 1; // header + agents + merkle
    let header = CheckpointHeader {
        magic: 0x414F5343,
        version: 1,
        tick,
        event_sequence: event_seq,
        agent_count,
        merkle_root_count: merkle_count,
        total_size: total_sectors as u64 * SECTOR_SIZE as u64,
    };

    let mut sector_buf = [0u8; SECTOR_SIZE];

    // Serialize header into sector buffer
    let header_bytes = unsafe {
        core::slice::from_raw_parts(
            &header as *const CheckpointHeader as *const u8,
            core::mem::size_of::<CheckpointHeader>(),
        )
    };
    let copy_len = header_bytes.len().min(SECTOR_SIZE);
    sector_buf[..copy_len].copy_from_slice(&header_bytes[..copy_len]);

    if device.write(CHECKPOINT_START_SECTOR as u64, 1, &sector_buf).is_err() {
        serial_println!("[CHECKPOINT] Failed to write header");
        return false;
    }

    // ── Write agent states (sectors 1..N) ──
    for i in 0..agent_count as usize {
        sector_buf = [0u8; SECTOR_SIZE];
        if let Some(ref agent) = agents[i] {
            let agent_bytes = unsafe {
                core::slice::from_raw_parts(
                    agent as *const CheckpointAgent as *const u8,
                    core::mem::size_of::<CheckpointAgent>(),
                )
            };
            let copy_len = agent_bytes.len().min(SECTOR_SIZE);
            sector_buf[..copy_len].copy_from_slice(&agent_bytes[..copy_len]);
        }
        let sector = CHECKPOINT_START_SECTOR + 1 + i as u32;
        if device.write(sector as u64, 1, &sector_buf).is_err() {
            serial_println!("[CHECKPOINT] Failed to write agent {}", i);
            return false;
        }
    }

    // ── Write Merkle roots (packed into one sector) ──
    sector_buf = [0u8; SECTOR_SIZE];
    for i in 0..MAX_AGENTS.min(32) {
        // 32 roots × 16 bytes = 512 bytes = exactly one sector
        sector_buf[i * 16..(i + 1) * 16].copy_from_slice(&merkle_roots[i]);
    }
    let merkle_sector = CHECKPOINT_START_SECTOR + 1 + agent_count as u32;
    if device.write(merkle_sector as u64, 1, &sector_buf).is_err() {
        serial_println!("[CHECKPOINT] Failed to write Merkle roots");
        return false;
    }

    serial_println!(
        "[CHECKPOINT] Saved to disk: tick={} event_seq={} agents={} merkle_roots={} ({} sectors at LBA {})",
        tick, event_seq, agent_count, merkle_count, total_sectors, CHECKPOINT_START_SECTOR
    );

    true
}

/// Load a checkpoint header from disk (for verification/restore).
///
/// Returns Some(header) if a valid checkpoint exists, None otherwise.
pub fn load_header_from_disk() -> Option<CheckpointHeader> {
    let device = StorageDevice::detect()?;

    const SECTOR_SIZE: usize = 512;
    let mut sector_buf = [0u8; SECTOR_SIZE];
    if device.read(CHECKPOINT_START_SECTOR as u64, 1, &mut sector_buf).is_err() {
        return None;
    }

    // Verify magic
    let magic = u32::from_le_bytes([sector_buf[0], sector_buf[1], sector_buf[2], sector_buf[3]]);
    if magic != 0x414F5343 {
        return None;
    }

    // Deserialize header
    let header = unsafe {
        core::ptr::read(sector_buf.as_ptr() as *const CheckpointHeader)
    };

    serial_println!(
        "[CHECKPOINT] Found on disk: tick={} event_seq={} agents={} merkle_roots={}",
        header.tick, header.event_sequence, header.agent_count, header.merkle_root_count
    );

    Some(header)
}

/// Take a checkpoint (in-memory capture only, no disk write).
/// Used for quick state snapshots.
pub fn take_checkpoint() -> CheckpointHeader {
    let tick = crate::arch::x86_64::timer::get_ticks();
    let event_seq = crate::event::get_sequence();

    let mut agent_count = 0u16;
    for_each_agent_mut(|agent| {
        if agent.active { agent_count += 1; }
        true
    });

    let header = CheckpointHeader {
        magic: 0x414F5343,
        version: 1,
        tick,
        event_sequence: event_seq,
        agent_count,
        merkle_root_count: 0,
        total_size: 0,
    };

    serial_println!(
        "[CHECKPOINT] Captured (in-memory): tick={} event_seq={} agents={}",
        tick, event_seq, agent_count
    );

    header
}

/// Load agent states from a checkpoint on disk.
/// Returns an array of CheckpointAgent entries read from sectors after the header.
pub fn load_agents_from_disk(header: &CheckpointHeader) -> [Option<CheckpointAgent>; MAX_AGENTS] {
    let mut agents: [Option<CheckpointAgent>; MAX_AGENTS] = [const { None }; MAX_AGENTS];
    const SECTOR_SIZE: usize = 512;
    let mut sector_buf = [0u8; SECTOR_SIZE];

    let device = match StorageDevice::detect() {
        Some(d) => d,
        None => return agents,
    };

    for i in 0..header.agent_count as usize {
        if i >= MAX_AGENTS { break; }
        let sector = CHECKPOINT_START_SECTOR + 1 + i as u32;
        if device.read(sector as u64, 1, &mut sector_buf).is_ok() {
            let agent = unsafe {
                core::ptr::read(sector_buf.as_ptr() as *const CheckpointAgent)
            };
            agents[i] = Some(agent);
        }
    }

    agents
}

// ─── Agent migration serialization ────────────────────────────────────────
//
// Wire format for a single migrated agent (little-endian throughout):
//
//   [magic: 4B = 0x414F_5341 ("AOSA")]
//   [id: 2B]
//   [status: 1B]
//   [mode: 1B]
//   [energy_budget: 8B]
//   [context: sizeof(AgentContext) bytes]
//   [cap_count: 2B]
//   [capabilities: cap_count × sizeof(Capability) bytes]
//   [state_entry_count: 2B]
//   [state_entries: state_entry_count × (key:8B + len:2B + value:256B)]

const AGENT_MAGIC: u32 = 0x414F_5341; // "AOSA"
const MAX_VALUE_SIZE: usize = 256; // mirrors state.rs

/// Serialize a single agent's live state into a byte buffer suitable for
/// transmission to a remote node (agent migration).
///
/// Captures: CPU context, capabilities, energy budget, and the agent's private
/// state keyspace. Returns `None` if the agent does not exist.
pub fn serialize_agent(agent_id: AgentId) -> Option<Vec<u8>> {
    let agent = crate::agent::get_agent(agent_id)?;

    let mut buf: Vec<u8> = Vec::new();

    // Magic
    buf.extend_from_slice(&AGENT_MAGIC.to_le_bytes());

    // Agent header
    buf.extend_from_slice(&agent.id.to_le_bytes());
    buf.push(agent.status as u8);
    buf.push(agent.mode as u8);
    buf.extend_from_slice(&agent.energy_budget.to_le_bytes());

    // CPU context (raw bytes)
    let ctx_bytes = unsafe {
        core::slice::from_raw_parts(
            &agent.context as *const AgentContext as *const u8,
            core::mem::size_of::<AgentContext>(),
        )
    };
    buf.extend_from_slice(ctx_bytes);

    // Capabilities
    let cap_count = agent.cap_count as u16;
    buf.extend_from_slice(&cap_count.to_le_bytes());
    for i in 0..agent.cap_count {
        if let Some(ref cap) = agent.capabilities[i] {
            let cap_bytes = unsafe {
                core::slice::from_raw_parts(
                    cap as *const Capability as *const u8,
                    core::mem::size_of::<Capability>(),
                )
            };
            buf.extend_from_slice(cap_bytes);
        }
    }

    // State keyspace entries: iterate keys 0..MAX_ENTRIES (brute-force scan
    // through well-known key range — a real implementation would expose an
    // iterator from state.rs).
    let mut state_entries: Vec<(u64, [u8; MAX_VALUE_SIZE], usize)> = Vec::new();
    for key in 0u64..64 {
        if let Some((val, len)) = crate::state::state_get(agent_id, key) {
            state_entries.push((key, val, len));
        }
    }

    let entry_count = state_entries.len() as u16;
    buf.extend_from_slice(&entry_count.to_le_bytes());
    for (key, val, len) in &state_entries {
        buf.extend_from_slice(&key.to_le_bytes());
        buf.extend_from_slice(&(*len as u16).to_le_bytes());
        buf.extend_from_slice(&val[..*len]);
    }

    serial_println!(
        "[CHECKPOINT] serialize_agent: id={} caps={} state_entries={} total_bytes={}",
        agent_id, cap_count, entry_count, buf.len()
    );

    Some(buf)
}

/// Deserialize an agent from a migration buffer produced by `serialize_agent`
/// and register it in the local agent table.
///
/// The new agent inherits the serialized CPU context, capabilities, energy, and
/// state keyspace. Its parent is set to `ROOT_AGENT_ID`. Returns the new
/// `AgentId` on success, or `None` on malformed data.
pub fn deserialize_agent(data: &[u8]) -> Option<AgentId> {
    if data.len() < 4 { return None; }

    // Check magic
    let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if magic != AGENT_MAGIC { return None; }

    let mut pos = 4usize;

    macro_rules! need {
        ($n:expr) => {{
            if pos + $n > data.len() { return None; }
            let s = &data[pos..pos + $n];
            pos += $n;
            s
        }};
    }

    // Agent header
    let id_bytes = need!(2);
    let _orig_id = u16::from_le_bytes([id_bytes[0], id_bytes[1]]);
    let status_byte = need!(1)[0];
    let _mode_byte = need!(1)[0];
    let energy_bytes = need!(8);
    let energy = u64::from_le_bytes(energy_bytes.try_into().ok()?);

    // CPU context
    let ctx_size = core::mem::size_of::<AgentContext>();
    let ctx_bytes = need!(ctx_size);
    let context: AgentContext = unsafe {
        core::ptr::read(ctx_bytes.as_ptr() as *const AgentContext)
    };

    // Capabilities
    let cap_count_bytes = need!(2);
    let cap_count = u16::from_le_bytes([cap_count_bytes[0], cap_count_bytes[1]]) as usize;
    let cap_size = core::mem::size_of::<Capability>();

    let mut caps: [Option<Capability>; MAX_CAPABILITIES_PER_AGENT] =
        [const { None }; MAX_CAPABILITIES_PER_AGENT];
    let actual_caps = cap_count.min(MAX_CAPABILITIES_PER_AGENT);
    for i in 0..actual_caps {
        let cap_bytes = need!(cap_size);
        let cap: Capability = unsafe {
            core::ptr::read(cap_bytes.as_ptr() as *const Capability)
        };
        caps[i] = Some(cap);
    }

    // We need a stack — reuse the entry point from context.rip.
    // Allocate a fresh kernel stack via create_agent, then patch in the
    // serialized context. We pass entry=context.rip, stack=context.rsp.
    let new_id = crate::agent::create_agent(
        Some(ROOT_AGENT_ID),
        context.rip,
        context.rsp,
        energy,
        256, // default memory quota (pages)
    ).ok()?;

    // Patch in the full context and capabilities.
    if let Some(agent) = crate::agent::get_agent_mut(new_id) {
        agent.context = context;
        agent.capabilities = caps;
        agent.cap_count = actual_caps;
        // Restore status from serialized value (keep as Ready if was Running).
        agent.status = match status_byte {
            1 => crate::agent::AgentStatus::Ready,
            5 => crate::agent::AgentStatus::Suspended,
            _ => crate::agent::AgentStatus::Ready,
        };
    }

    // State keyspace entries
    let ec_bytes = need!(2);
    let entry_count = u16::from_le_bytes([ec_bytes[0], ec_bytes[1]]) as usize;

    // Ensure keyspace exists
    let _ = crate::state::create_keyspace(new_id);

    for _ in 0..entry_count {
        let key_bytes = need!(8);
        let key = u64::from_le_bytes(key_bytes.try_into().ok()?);
        let len_bytes = need!(2);
        let len = u16::from_le_bytes([len_bytes[0], len_bytes[1]]) as usize;
        if len > MAX_VALUE_SIZE { return None; }
        let val_bytes = need!(len);
        let _ = crate::state::state_put(new_id, key, val_bytes);
    }

    serial_println!(
        "[CHECKPOINT] deserialize_agent: new_id={} caps={} state_entries={}",
        new_id, actual_caps, entry_count
    );

    Some(new_id)
}

/// Load Merkle roots from a checkpoint on disk.
/// Returns an array of MerkleHash values.
pub fn load_merkle_from_disk(header: &CheckpointHeader) -> [crate::merkle::MerkleHash; MAX_AGENTS] {
    let mut roots: [crate::merkle::MerkleHash; MAX_AGENTS] = [[0u8; 16]; MAX_AGENTS];
    const SECTOR_SIZE: usize = 512;
    let mut sector_buf = [0u8; SECTOR_SIZE];

    if let Some(device) = StorageDevice::detect() {
        let merkle_sector = CHECKPOINT_START_SECTOR + 1 + header.agent_count as u32;
        if device.read(merkle_sector as u64, 1, &mut sector_buf).is_ok() {
            for i in 0..MAX_AGENTS.min(32) {
                roots[i].copy_from_slice(&sector_buf[i * 16..(i + 1) * 16]);
            }
        }
    }

    roots
}
