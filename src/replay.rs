//! ATOS Checkpoint Replay & Execution Diffing
//!
//! Loads a checkpoint from disk, enables deterministic scheduling,
//! and compares Merkle state roots after execution to detect divergence.

use crate::agent::*;
use crate::checkpoint;
use crate::deterministic;
use crate::merkle::{self, MerkleHash};
use crate::sched;
use crate::serial_println;

// ─── Replay state ────────────────────────────────────────────────────────

static mut REPLAY_ACTIVE: bool = false;
static mut SAVED_MERKLE_ROOTS: [MerkleHash; MAX_AGENTS] = [[0u8; 32]; MAX_AGENTS];
static mut SAVED_TICK: u64 = 0;
static mut SAVED_EVENT_SEQ: u64 = 0;
static mut SAVED_AGENT_COUNT: u16 = 0;

/// Check if replay mode is active
pub fn is_active() -> bool {
    unsafe { REPLAY_ACTIVE }
}

/// Check if replay mode is active (alias for use by I/O subsystems).
pub fn is_replay_mode() -> bool {
    unsafe { REPLAY_ACTIVE }
}

/// Restore execution state from a checkpoint on disk.
///
/// Loads the checkpoint header, agent states, and Merkle roots from disk.
/// For each agent: restores its context (registers, stack pointer, instruction
/// pointer), energy budget, and status. Resets the scheduler tick counter and
/// event sequence to the checkpoint's values, clears and rebuilds the run queue
/// with restored agents, and enables deterministic mode.
///
/// Returns `true` if the restore succeeded, `false` otherwise.
pub fn restore_from_checkpoint() -> bool {
    // 1. Load checkpoint header from disk
    let header = match checkpoint::load_header_from_disk() {
        Some(h) => h,
        None => {
            serial_println!("[REPLAY] restore_from_checkpoint: no checkpoint found on disk");
            return false;
        }
    };

    // 2. Load agent states from disk
    let checkpoint_agents = checkpoint::load_agents_from_disk(&header);

    // 3. Restore each agent's context, energy budget, and status
    let mut restored_count: u16 = 0;
    let mut restored_ids: [Option<AgentId>; MAX_AGENTS] = [None; MAX_AGENTS];

    for i in 0..MAX_AGENTS {
        if let Some(ref cp_agent) = checkpoint_agents[i] {
            // Try to find the agent in the live table by ID
            if let Some(agent) = get_agent_mut(cp_agent.id) {
                // Restore CPU context (registers, stack pointer, instruction pointer)
                agent.context = cp_agent.context;

                // Restore energy budget
                agent.energy_budget = cp_agent.energy_budget;

                // Restore status from serialized byte
                agent.status = match cp_agent.status {
                    0 => AgentStatus::Created,
                    1 => AgentStatus::Ready,
                    2 => AgentStatus::Running, // will be set to Ready for run queue
                    3 => AgentStatus::BlockedRecv,
                    4 => AgentStatus::BlockedSend,
                    5 => AgentStatus::Suspended,
                    6 => AgentStatus::Exited,
                    7 => AgentStatus::Faulted,
                    _ => AgentStatus::Ready,
                };

                if (restored_count as usize) < MAX_AGENTS {
                    restored_ids[restored_count as usize] = Some(cp_agent.id);
                    restored_count += 1;
                }

                serial_println!(
                    "[REPLAY] Restored agent {}: status={} energy={} rip={:#x} rsp={:#x}",
                    cp_agent.id,
                    cp_agent.status,
                    cp_agent.energy_budget,
                    cp_agent.context.rip,
                    cp_agent.context.rsp
                );
            } else {
                serial_println!(
                    "[REPLAY] Warning: agent {} from checkpoint not found in live table",
                    cp_agent.id
                );
            }
        }
    }

    // 4. Load Merkle roots from disk (save for later divergence comparison)
    let merkle_roots = checkpoint::load_merkle_from_disk(&header);
    unsafe {
        SAVED_MERKLE_ROOTS = merkle_roots;
        SAVED_TICK = header.tick;
        SAVED_EVENT_SEQ = header.event_sequence;
        SAVED_AGENT_COUNT = header.agent_count;
    }

    // 5. Reset the scheduler tick counter to the checkpoint's tick value
    crate::arch::x86_64::timer::set_ticks(header.tick);

    // 6. Reset the event sequence counter to the checkpoint's value
    crate::event::set_sequence(header.event_sequence);

    // 7. Clear and rebuild the run queue with restored agents
    sched::clear_run_queue();
    for i in 0..restored_count as usize {
        if let Some(agent_id) = restored_ids[i] {
            if let Some(agent) = get_agent_mut(agent_id) {
                // Only enqueue agents that should be schedulable
                match agent.status {
                    AgentStatus::Ready | AgentStatus::Running | AgentStatus::Created => {
                        agent.status = AgentStatus::Ready;
                        sched::add_to_run_queue(agent_id);
                    }
                    _ => {}
                }
            }
        }
    }

    // 8. Enable deterministic mode
    deterministic::enable(10);

    serial_println!(
        "[REPLAY] State restored from checkpoint: tick={} event_seq={} agents_restored={}",
        header.tick,
        header.event_sequence,
        restored_count
    );

    true
}

/// Enter replay mode: restore state from checkpoint and enable deterministic scheduling.
///
/// Loads the full checkpoint from disk, restores agent contexts, resets the
/// tick counter and event sequence, rebuilds the run queue, and enables
/// deterministic scheduling for reproducible re-execution.
pub fn enter_replay() -> Result<(), i64> {
    // Restore full state from checkpoint
    if !restore_from_checkpoint() {
        serial_println!("[REPLAY] Failed to restore from checkpoint");
        return Err(E_NOT_FOUND);
    }

    // Enable I/O tracing for this replay run
    checkpoint::enable_tracing();

    // Mark replay active
    unsafe {
        REPLAY_ACTIVE = true;
    }

    serial_println!(
        "[REPLAY] Replay mode active — state restored, deterministic scheduling enabled"
    );
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

// ─── Replay bundle verification ─────────────────────────────────────────

/// Structurally verify a replay bundle against its corresponding receipt.
///
/// Checks that:
/// 1. The bundle's receipt_id matches the receipt's receipt_id
/// 2. The bundle's initial_state matches the receipt's initial_state_root
/// 3. The transcript is non-empty (has actual recorded events)
/// 4. The checkpoint data is non-empty
///
/// This is a structural verification only. Full replay re-execution requires
/// running a second ATOS instance with deterministic scheduling.
pub fn verify_replay_bundle(
    bundle: &crate::receipts::ReplayBundle,
    receipt: &crate::receipts::ExecutionReceipt,
) -> bool {
    // 1. Check receipt_id match
    if bundle.receipt_id != receipt.receipt_id {
        serial_println!("[REPLAY] verify: receipt_id mismatch");
        return false;
    }

    // 2. Verify initial_state matches receipt's initial_state_root
    //    The bundle stores the 32-byte initial_state_root in initial_state[..32]
    if bundle.initial_state_len < 32 {
        serial_println!(
            "[REPLAY] verify: initial_state too short (len={})",
            bundle.initial_state_len
        );
        return false;
    }
    if bundle.initial_state[..32] != receipt.initial_state_root {
        serial_println!("[REPLAY] verify: initial_state_root mismatch");
        return false;
    }

    // 3. Verify transcript is non-empty
    if bundle.transcript_len == 0 {
        serial_println!("[REPLAY] verify: transcript is empty");
        return false;
    }

    // 4. Verify checkpoint data is non-empty
    if bundle.checkpoint_len == 0 {
        serial_println!("[REPLAY] verify: checkpoint data is empty");
        return false;
    }

    true
}

/// Print a divergence report to serial output.
pub fn print_report(report: &DiffReport) {
    serial_println!("╔══════════════════════════════════════════════╗");
    serial_println!("║        EXECUTION DIFF REPORT                ║");
    serial_println!("╠══════════════════════════════════════════════╣");
    serial_println!("║ Checkpoint tick:    {:>20}     ║", report.checkpoint_tick);
    serial_println!("║ Current tick:       {:>20}     ║", report.current_tick);
    serial_println!(
        "║ Checkpoint seq:     {:>20}     ║",
        report.checkpoint_event_seq
    );
    serial_println!(
        "║ Current seq:        {:>20}     ║",
        report.current_event_seq
    );
    serial_println!("║ Total keyspaces:    {:>20}     ║", report.total_keyspaces);
    serial_println!(
        "║ Divergent:          {:>20}     ║",
        report.divergent_keyspaces
    );
    serial_println!("╚══════════════════════════════════════════════╝");

    if report.divergent_keyspaces == 0 {
        serial_println!("[DIFF] ✓ No divergence detected — Merkle roots match");
    } else {
        serial_println!(
            "[DIFF] ✗ {} keyspace(s) diverged:",
            report.divergent_keyspaces
        );
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
