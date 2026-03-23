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
use crate::arch::x86_64::ata;
use crate::merkle;

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
    // Check if ATA disk is available
    if !ata::init() {
        serial_println!("[CHECKPOINT] No disk available, checkpoint skipped");
        return false;
    }

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
        total_size: total_sectors as u64 * ata::SECTOR_SIZE as u64,
    };

    let mut sector_buf = [0u8; ata::SECTOR_SIZE];

    // Serialize header into sector buffer
    let header_bytes = unsafe {
        core::slice::from_raw_parts(
            &header as *const CheckpointHeader as *const u8,
            core::mem::size_of::<CheckpointHeader>(),
        )
    };
    let copy_len = header_bytes.len().min(ata::SECTOR_SIZE);
    sector_buf[..copy_len].copy_from_slice(&header_bytes[..copy_len]);

    if ata::write_sectors(CHECKPOINT_START_SECTOR, 1, &sector_buf).is_err() {
        serial_println!("[CHECKPOINT] Failed to write header");
        return false;
    }

    // ── Write agent states (sectors 1..N) ──
    for i in 0..agent_count as usize {
        sector_buf = [0u8; ata::SECTOR_SIZE];
        if let Some(ref agent) = agents[i] {
            let agent_bytes = unsafe {
                core::slice::from_raw_parts(
                    agent as *const CheckpointAgent as *const u8,
                    core::mem::size_of::<CheckpointAgent>(),
                )
            };
            let copy_len = agent_bytes.len().min(ata::SECTOR_SIZE);
            sector_buf[..copy_len].copy_from_slice(&agent_bytes[..copy_len]);
        }
        let sector = CHECKPOINT_START_SECTOR + 1 + i as u32;
        if ata::write_sectors(sector, 1, &sector_buf).is_err() {
            serial_println!("[CHECKPOINT] Failed to write agent {}", i);
            return false;
        }
    }

    // ── Write Merkle roots (packed into one sector) ──
    sector_buf = [0u8; ata::SECTOR_SIZE];
    for i in 0..MAX_AGENTS.min(32) {
        // 32 roots × 16 bytes = 512 bytes = exactly one sector
        sector_buf[i * 16..(i + 1) * 16].copy_from_slice(&merkle_roots[i]);
    }
    let merkle_sector = CHECKPOINT_START_SECTOR + 1 + agent_count as u32;
    if ata::write_sectors(merkle_sector, 1, &sector_buf).is_err() {
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
    if !ata::init() {
        return None;
    }

    let mut sector_buf = [0u8; ata::SECTOR_SIZE];
    if ata::read_sectors(CHECKPOINT_START_SECTOR, 1, &mut sector_buf).is_err() {
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
