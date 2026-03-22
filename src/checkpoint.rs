//! AOS Checkpoint & Replay
//!
//! Captures execution state for debugging and deterministic replay.
//! Checkpoint includes: agent contexts, mailbox state, energy counters,
//! scheduler state, event sequence, and Merkle state roots.

use crate::serial_println;
use crate::agent::*;

/// Checkpoint header (serialized to disk)
#[repr(C)]
pub struct CheckpointHeader {
    pub magic: u32,           // 0x414F5343 = "AOSC"
    pub version: u32,
    pub tick: u64,
    pub event_sequence: u64,
    pub agent_count: u16,
    pub merkle_root_count: u16,
    pub total_size: u64,
}

/// Saved agent state within a checkpoint
#[repr(C)]
pub struct CheckpointAgent {
    pub id: AgentId,
    pub status: u8,
    pub mode: u8,
    pub energy_budget: u64,
    pub context: AgentContext,
}

/// I/O trace entry for replay
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TraceEntry {
    pub tick: u64,
    pub event_type: u8,   // 0=timer, 1=disk_read, 2=disk_write, 3=net_recv
    pub agent_id: AgentId,
    pub data_len: u16,
    // data follows in serialized form
}

// ─── Checkpoint capture ────────────────────────────────────────────────────

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

/// Take a checkpoint: capture current system state
pub fn take_checkpoint() -> CheckpointHeader {
    let tick = crate::arch::x86_64::timer::get_ticks();
    let event_seq = crate::event::get_sequence();

    let mut agent_count = 0u16;
    crate::agent::for_each_agent_mut(|agent| {
        if agent.active {
            agent_count += 1;
        }
        true
    });

    let header = CheckpointHeader {
        magic: 0x414F5343,
        version: 1,
        tick,
        event_sequence: event_seq,
        agent_count,
        merkle_root_count: 0, // filled when Merkle trees are serialized
        total_size: 0,
    };

    serial_println!(
        "[CHECKPOINT] Captured: tick={} event_seq={} agents={}",
        tick, event_seq, agent_count
    );

    header
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
