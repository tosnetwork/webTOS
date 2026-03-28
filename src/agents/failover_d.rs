//! ATOS failover_d — Failure Recovery Agent (Stage 8: Distributed Execution Fabric)
//!
//! Monitors membership_d for node departures and handles checkpoint-based
//! recovery of agents that were running on failed nodes.
//!
//! Protocol (mailbox message payload):
//!   WATCH_AGENT   (0x01): [op, agent_id:u16, home_node:u16] — register for failover monitoring
//!   NODE_DOWN     (0x02): [op, node_id:u16] — notification that a node is gone
//!   LIST_WATCHED  (0x03): [op] — return watched agents
//!   UNWATCH_AGENT (0x04): [op, agent_id:u16] — stop watching an agent

use crate::serial_println;
use crate::agent::*;

const OP_WATCH_AGENT: u8 = 0x01;
const OP_NODE_DOWN: u8 = 0x02;
const OP_LIST_WATCHED: u8 = 0x03;
const OP_UNWATCH_AGENT: u8 = 0x04;

/// Failover_d agent — assigned during init as agent slot 20.
const FAILOVER_D_ID: AgentId = 20;
const FAILOVER_D_MAILBOX: MailboxId = 20;

/// Maximum number of watched agents.
const MAX_WATCHED: usize = 32;

/// Watched agent entry: agent_id and home_node.
#[derive(Clone, Copy)]
struct WatchEntry {
    agent_id: u16,
    home_node: u16,
    active: bool,
}

static mut WATCHED_AGENTS: [WatchEntry; MAX_WATCHED] = [WatchEntry {
    agent_id: 0,
    home_node: 0,
    active: false,
}; MAX_WATCHED];
static mut WATCH_COUNT: usize = 0;

/// Total recovery events since startup.
static mut RECOVERY_COUNT: u64 = 0;

/// Failure recovery agent entry point.
pub extern "C" fn failover_d_main() -> ! {
    serial_println!("[FAILOVER_D] Failover service started (capacity: {} agents)", MAX_WATCHED);

    loop {
        match crate::mailbox::recv_message(FAILOVER_D_ID, FAILOVER_D_MAILBOX) {
            Ok(msg) => {
                let msg_len = msg.len as usize;
                if msg_len >= 1 {
                    let op = msg.payload[0];
                    match op {
                        OP_WATCH_AGENT => handle_watch_agent(&msg.payload, msg_len, msg.sender_id),
                        OP_NODE_DOWN => handle_node_down(&msg.payload, msg_len, msg.sender_id),
                        OP_LIST_WATCHED => handle_list_watched(msg.sender_id),
                        OP_UNWATCH_AGENT => handle_unwatch_agent(&msg.payload, msg_len, msg.sender_id),
                        _ => {
                            serial_println!("[FAILOVER_D] Unknown opcode: {:#x}", op);
                        }
                    }
                }
            }
            Err(_) => {} // no message available
        }

        // Yield to other agents
        crate::syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0);
    }
}

/// Handle WATCH_AGENT: register an agent for failover monitoring.
/// Format: [op=0x01, agent_id:u16, home_node:u16]
fn handle_watch_agent(payload: &[u8], msg_len: usize, sender_id: AgentId) {
    if msg_len < 5 {
        serial_println!("[FAILOVER_D] WATCH_AGENT: payload too short");
        return;
    }

    let agent_id = u16::from_le_bytes([payload[1], payload[2]]);
    let home_node = u16::from_le_bytes([payload[3], payload[4]]);

    unsafe {
        // Check if already watched
        for i in 0..WATCH_COUNT {
            if WATCHED_AGENTS[i].active && WATCHED_AGENTS[i].agent_id == agent_id {
                // Update home_node
                WATCHED_AGENTS[i].home_node = home_node;
                serial_println!("[FAILOVER_D] Updated watch: agent {} on node {} (from agent {})",
                    agent_id, home_node, sender_id);
                return;
            }
        }

        // Find a free slot (reuse inactive entries first)
        for i in 0..MAX_WATCHED {
            if !WATCHED_AGENTS[i].active {
                WATCHED_AGENTS[i] = WatchEntry {
                    agent_id,
                    home_node,
                    active: true,
                };
                if i >= WATCH_COUNT {
                    WATCH_COUNT = i + 1;
                }
                serial_println!("[FAILOVER_D] Watching agent {} on node {} (from agent {})",
                    agent_id, home_node, sender_id);
                return;
            }
        }

        serial_println!("[FAILOVER_D] Watch table full, cannot watch agent {}", agent_id);
    }
}

/// Handle NODE_DOWN: notification that a node is gone.
///
/// Recovery procedure for each affected agent:
///   1. Emit a NodeDown event for audit trail
///   2. Query placement_d for an alternate node (via HINT_ENERGY)
///   3. Emit an AgentMigrate event recording the recovery
///   4. Update the watch entry's home_node to the new target
///
/// Format: [op=0x02, node_id:u16]
fn handle_node_down(payload: &[u8], msg_len: usize, sender_id: AgentId) {
    if msg_len < 3 {
        serial_println!("[FAILOVER_D] NODE_DOWN: payload too short");
        return;
    }

    let node_id = u16::from_le_bytes([payload[1], payload[2]]);
    serial_println!("[FAILOVER_D] Node {} reported DOWN by agent {}", node_id, sender_id);

    // Emit a NodeDown event for the audit trail
    crate::event::emit(
        FAILOVER_D_ID,
        crate::event::EventType::NodeDown,
        node_id as u64,
        sender_id as u64,
        0,
    );

    // Query placement_d for the best alternate node.
    // Build a QUERY_PLACEMENT message: [0x01, hint_type=0x02 (ENERGY), hint_value=0]
    let mut placement_query = [0u8; 10];
    placement_query[0] = 0x01; // OP_QUERY_PLACEMENT
    placement_query[1] = 0x02; // HINT_ENERGY — pick node with most energy
    // hint_value bytes [2..10] stay zero (no preference)

    let placement_mailbox: MailboxId = 19; // placement_d
    let _ = crate::mailbox::send_message(FAILOVER_D_ID, placement_mailbox, &placement_query);

    // Read placement_d's response (best available node).
    // In a fully async system this would be a continuation; here we attempt
    // one receive since placement_d runs cooperatively on the same core.
    let alternate_node: u16 = match crate::mailbox::recv_message(FAILOVER_D_ID, FAILOVER_D_MAILBOX) {
        Ok(resp) if resp.len as usize >= 2 => {
            u16::from_le_bytes([resp.payload[0], resp.payload[1]])
        }
        _ => 0, // fall back to local node
    };

    serial_println!("[FAILOVER_D] Alternate node for recovery: {}", alternate_node);

    // Find all agents on the failed node and initiate recovery
    let mut affected: u32 = 0;
    unsafe {
        for i in 0..WATCH_COUNT {
            if WATCHED_AGENTS[i].active && WATCHED_AGENTS[i].home_node == node_id {
                let aid = WATCHED_AGENTS[i].agent_id;
                serial_println!(
                    "[FAILOVER_D] Agent {} was on failed node {} — recovering to node {}",
                    aid, node_id, alternate_node
                );

                // Step 1: Trigger a checkpoint save so the latest state is persisted
                crate::event::checkpoint_triggered(aid);

                // Step 2: Emit AgentMigrate event for the audit trail
                crate::event::emit(
                    aid,
                    crate::event::EventType::AgentMigrate,
                    node_id as u64,       // source node (failed)
                    alternate_node as u64, // destination node
                    0,
                );

                // Step 3: Update the watch entry to reflect the new home node
                WATCHED_AGENTS[i].home_node = alternate_node;

                RECOVERY_COUNT += 1;
                affected += 1;
            }
        }
    }

    serial_println!(
        "[FAILOVER_D] Node {} failure: {} agent(s) affected, {} total recoveries",
        node_id, affected, unsafe { RECOVERY_COUNT }
    );

    // Respond with affected count
    let response = affected.to_le_bytes();
    let _ = crate::mailbox::send_message(FAILOVER_D_ID, sender_id as MailboxId, &response);
}

/// Handle LIST_WATCHED: print all watched agents.
fn handle_list_watched(sender_id: AgentId) {
    serial_println!("[FAILOVER_D] === Watched Agents (requested by agent {}) ===", sender_id);

    let mut active_count: u32 = 0;
    unsafe {
        for i in 0..WATCH_COUNT {
            if WATCHED_AGENTS[i].active {
                serial_println!(
                    "[FAILOVER_D]   agent={} home_node={}",
                    WATCHED_AGENTS[i].agent_id, WATCHED_AGENTS[i].home_node
                );
                active_count += 1;
            }
        }
    }

    serial_println!("[FAILOVER_D] === End ({} watched) ===", active_count);
}

/// Handle UNWATCH_AGENT: stop watching an agent.
/// Format: [op=0x04, agent_id:u16]
fn handle_unwatch_agent(payload: &[u8], msg_len: usize, sender_id: AgentId) {
    if msg_len < 3 {
        serial_println!("[FAILOVER_D] UNWATCH_AGENT: payload too short");
        return;
    }

    let agent_id = u16::from_le_bytes([payload[1], payload[2]]);

    unsafe {
        for i in 0..WATCH_COUNT {
            if WATCHED_AGENTS[i].active && WATCHED_AGENTS[i].agent_id == agent_id {
                WATCHED_AGENTS[i].active = false;
                serial_println!("[FAILOVER_D] Unwatched agent {} (from agent {})", agent_id, sender_id);
                return;
            }
        }
    }

    serial_println!("[FAILOVER_D] UNWATCH: agent {} not found in watch list", agent_id);
}
