//! ATOS Checkpoint Replay & Execution Diffing
//!
//! Loads a checkpoint from disk, enables deterministic scheduling,
//! and compares Merkle state roots after execution to detect divergence.

use crate::serial_println;
use crate::agent::*;
use crate::checkpoint;
use crate::merkle::{self, MerkleHash};
use crate::deterministic;

// ─── Replay state ────────────────────────────────────────────────────────

static mut REPLAY_ACTIVE: bool = false;
static mut SAVED_MERKLE_ROOTS: [MerkleHash; MAX_AGENTS] = [[0u8; 16]; MAX_AGENTS];
static mut SAVED_TICK: u64 = 0;
static mut SAVED_EVENT_SEQ: u64 = 0;
static mut SAVED_AGENT_COUNT: u16 = 0;

/// Check if replay mode is active
pub fn is_active() -> bool {
    unsafe { REPLAY_ACTIVE }
}

/// Enter replay mode: load checkpoint from disk and enable deterministic scheduling.
///
/// This loads the Merkle roots saved in the checkpoint so they can be compared
/// against the current state after re-execution. The deterministic scheduler
/// ensures agents run in the same order.
pub fn enter_replay() -> Result<(), i64> {
    // 1. Load checkpoint header
    let header = match checkpoint::load_header_from_disk() {
        Some(h) => h,
        None => {
            serial_println!("[REPLAY] No checkpoint found on disk");
            return Err(E_NOT_FOUND);
        }
    };

    unsafe {
        // 2. Save checkpoint metadata
        SAVED_TICK = header.tick;
        SAVED_EVENT_SEQ = header.event_sequence;
        SAVED_AGENT_COUNT = header.agent_count;

        // 3. Load and save Merkle roots from checkpoint
        SAVED_MERKLE_ROOTS = checkpoint::load_merkle_from_disk(&header);

        // 4. Load agent metadata (for logging/comparison, not full restore)
        let agents = checkpoint::load_agents_from_disk(&header);
        let mut loaded = 0;
        for agent in agents.iter() {
            if agent.is_some() { loaded += 1; }
        }

        serial_println!(
            "[REPLAY] Checkpoint loaded: tick={} event_seq={} agents={} merkle_roots loaded",
            SAVED_TICK, SAVED_EVENT_SEQ, loaded
        );

        // 5. Enable deterministic scheduler (fixed tick quotas)
        deterministic::enable(10);

        // 6. Enable I/O tracing for this replay run
        checkpoint::enable_tracing();

        // 7. Mark replay active
        REPLAY_ACTIVE = true;

        serial_println!("[REPLAY] Replay mode active — deterministic scheduling enabled");
    }

    Ok(())
}

/// Exit replay mode and generate a divergence report.
pub fn exit_replay() -> DiffReport {
    let report = check_divergence();
    print_report(&report);

    unsafe {
        REPLAY_ACTIVE = false;
        deterministic::disable();
        checkpoint::disable_tracing();
    }

    serial_println!("[REPLAY] Replay mode exited");
    report
}

// ─── Divergence detection ────────────────────────────────────────────────

/// Divergence report comparing checkpoint state to current state.
pub struct DiffReport {
    pub checkpoint_tick: u64,
    pub current_tick: u64,
    pub checkpoint_event_seq: u64,
    pub current_event_seq: u64,
    pub divergent_keyspaces: u16,
    pub total_keyspaces: u16,
    pub details: [Option<DiffEntry>; MAX_AGENTS],
    pub detail_count: usize,
}

/// A single keyspace divergence entry.
#[derive(Clone, Copy)]
pub struct DiffEntry {
    pub keyspace_id: KeyspaceId,
    pub saved_root: MerkleHash,
    pub current_root: MerkleHash,
}

/// Compare current Merkle roots against saved checkpoint roots.
pub fn check_divergence() -> DiffReport {
    let current_tick = crate::arch::x86_64::timer::get_ticks();
    let current_seq = crate::event::get_sequence();

    let mut report = DiffReport {
        checkpoint_tick: unsafe { SAVED_TICK },
        current_tick,
        checkpoint_event_seq: unsafe { SAVED_EVENT_SEQ },
        current_event_seq: current_seq,
        divergent_keyspaces: 0,
        total_keyspaces: 0,
        details: [const { None }; MAX_AGENTS],
        detail_count: 0,
    };

    unsafe {
        for i in 0..MAX_AGENTS {
            let saved = SAVED_MERKLE_ROOTS[i];
            // Skip empty roots (all zeros = no keyspace)
            let is_empty = saved.iter().all(|&b| b == 0);

            if let Some(current) = merkle::get_root(i as KeyspaceId) {
                report.total_keyspaces += 1;

                if !is_empty && saved != current {
                    // Divergence detected
                    report.divergent_keyspaces += 1;
                    if report.detail_count < MAX_AGENTS {
                        report.details[report.detail_count] = Some(DiffEntry {
                            keyspace_id: i as KeyspaceId,
                            saved_root: saved,
                            current_root: current,
                        });
                        report.detail_count += 1;
                    }
                }
            }
        }
    }

    report
}

/// Print a divergence report to serial output.
pub fn print_report(report: &DiffReport) {
    serial_println!("╔══════════════════════════════════════════════╗");
    serial_println!("║        EXECUTION DIFF REPORT                ║");
    serial_println!("╠══════════════════════════════════════════════╣");
    serial_println!("║ Checkpoint tick:    {:>20}     ║", report.checkpoint_tick);
    serial_println!("║ Current tick:       {:>20}     ║", report.current_tick);
    serial_println!("║ Checkpoint seq:     {:>20}     ║", report.checkpoint_event_seq);
    serial_println!("║ Current seq:        {:>20}     ║", report.current_event_seq);
    serial_println!("║ Total keyspaces:    {:>20}     ║", report.total_keyspaces);
    serial_println!("║ Divergent:          {:>20}     ║", report.divergent_keyspaces);
    serial_println!("╚══════════════════════════════════════════════╝");

    if report.divergent_keyspaces == 0 {
        serial_println!("[DIFF] ✓ No divergence detected — Merkle roots match");
    } else {
        serial_println!("[DIFF] ✗ {} keyspace(s) diverged:", report.divergent_keyspaces);
        for i in 0..report.detail_count {
            if let Some(entry) = &report.details[i] {
                serial_println!(
                    "[DIFF]   keyspace {} — saved root != current root",
                    entry.keyspace_id
                );
            }
        }
    }
}
