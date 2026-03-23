//! ATOS Deterministic Scheduling
//!
//! Provides a fixed-tick-quota scheduler mode for replay-compatible execution.
//! Each agent receives a fixed number of ticks per round. The execution
//! order is deterministic given the same initial state.

use crate::agent::*;
use crate::serial_println;

/// Configuration for deterministic scheduling
pub struct DeterministicConfig {
    /// Ticks per agent per scheduling round
    pub ticks_per_agent: u64,
    /// Whether deterministic mode is enabled
    pub enabled: bool,
    /// Current round number
    pub round: u64,
    /// Current agent index within the round
    pub current_slot: usize,
    /// Tick counter within current agent's slot
    pub slot_ticks: u64,
    /// Agent order for this round (fixed at round start)
    pub agent_order: [Option<AgentId>; MAX_AGENTS],
    pub agent_count: usize,
}

impl DeterministicConfig {
    pub const fn new() -> Self {
        DeterministicConfig {
            ticks_per_agent: 10, // Each agent gets 10 ticks per round
            enabled: false,
            round: 0,
            current_slot: 0,
            slot_ticks: 0,
            agent_order: [None; MAX_AGENTS],
            agent_count: 0,
        }
    }
}

// Safety: single-core Stage-2
static mut DETERMINISTIC: DeterministicConfig = DeterministicConfig::new();

/// Enable deterministic scheduling mode
pub fn enable(ticks_per_agent: u64) {
    unsafe {
        DETERMINISTIC.enabled = true;
        DETERMINISTIC.ticks_per_agent = ticks_per_agent;
        DETERMINISTIC.round = 0;
        DETERMINISTIC.current_slot = 0;
        DETERMINISTIC.slot_ticks = 0;
        rebuild_agent_order();
        serial_println!("[DETERMINISTIC] Enabled with {} ticks per agent", ticks_per_agent);
    }
}

/// Disable deterministic scheduling mode (return to round-robin)
pub fn disable() {
    unsafe {
        DETERMINISTIC.enabled = false;
        serial_println!("[DETERMINISTIC] Disabled");
    }
}

/// Check if deterministic mode is active
pub fn is_enabled() -> bool {
    unsafe { DETERMINISTIC.enabled }
}

/// Called from timer_tick() when deterministic mode is enabled.
/// Returns the AgentId that should run next, or None to keep current.
pub fn tick() -> Option<AgentId> {
    unsafe {
        if !DETERMINISTIC.enabled {
            return None;
        }

        DETERMINISTIC.slot_ticks += 1;

        // Check if current agent's time slot is exhausted
        if DETERMINISTIC.slot_ticks >= DETERMINISTIC.ticks_per_agent {
            DETERMINISTIC.slot_ticks = 0;
            DETERMINISTIC.current_slot += 1;

            // Check if round is complete
            if DETERMINISTIC.current_slot >= DETERMINISTIC.agent_count {
                DETERMINISTIC.current_slot = 0;
                DETERMINISTIC.round += 1;
                // Rebuild agent order at start of each round
                rebuild_agent_order();
            }

            // Return the next agent to run
            return DETERMINISTIC.agent_order[DETERMINISTIC.current_slot];
        }

        None // Keep running current agent
    }
}

/// Build the deterministic agent order from the run queue.
/// Agents are ordered by ID (ascending) for reproducibility.
fn rebuild_agent_order() {
    unsafe {
        DETERMINISTIC.agent_count = 0;

        // Collect all active, non-idle agents sorted by ID
        for id in 0..MAX_AGENTS as AgentId {
            if id == IDLE_AGENT_ID { continue; }
            if let Some(agent) = crate::agent::get_agent(id) {
                if agent.active && agent.status != AgentStatus::Exited
                    && agent.status != AgentStatus::Faulted {
                    let idx = DETERMINISTIC.agent_count;
                    if idx < MAX_AGENTS {
                        DETERMINISTIC.agent_order[idx] = Some(id);
                        DETERMINISTIC.agent_count += 1;
                    }
                }
            }
        }
    }
}

/// Get current deterministic scheduling state for audit/debug
pub fn get_state() -> (u64, usize, u64) {
    unsafe {
        (DETERMINISTIC.round, DETERMINISTIC.current_slot, DETERMINISTIC.slot_ticks)
    }
}
