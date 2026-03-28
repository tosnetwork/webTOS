//! ATOS placement_d — Placement Decision Agent (Stage 8: Distributed Execution Fabric)
//!
//! Decides where agents should run based on locality hints, available energy,
//! hardware class requirements, and policy constraints.
//!
//! Protocol (mailbox message payload):
//!   QUERY_PLACEMENT    (0x01): [op, hint_type:u8, hint_value:u64] -> [node_id:u16]
//!   REGISTER_CAPACITY  (0x02): [op, node_id:u16, cpu:u16, memory:u32, energy:u64]
//!   LIST_NODES         (0x03): [op] -> prints known nodes to serial

use crate::serial_println;
use crate::agent::*;

const OP_QUERY_PLACEMENT: u8 = 0x01;
const OP_REGISTER_CAPACITY: u8 = 0x02;
const OP_LIST_NODES: u8 = 0x03;

/// Placement_d agent — assigned during init as agent slot 19.
const PLACEMENT_D_ID: AgentId = 19;
const PLACEMENT_D_MAILBOX: MailboxId = 19;

/// Maximum number of tracked nodes.
const MAX_NODES: usize = 16;

/// Placement hint types.
const HINT_LOCALITY: u8 = 0x01;   // prefer co-location with another agent
const HINT_ENERGY: u8 = 0x02;     // prefer node with most available energy
const HINT_HARDWARE: u8 = 0x03;   // require specific hardware class

/// Node capacity record.
#[derive(Clone, Copy)]
struct NodeCapacity {
    node_id: u16,
    cpu_available: u16,      // available CPU units
    memory_available: u32,   // available memory in pages
    energy_available: u64,   // available energy budget
    hardware_class: u32,     // hardware class identifier (0 = generic)
    active: bool,
}

static mut NODE_TABLE: [NodeCapacity; MAX_NODES] = [NodeCapacity {
    node_id: 0,
    cpu_available: 0,
    memory_available: 0,
    energy_available: 0,
    hardware_class: 0,
    active: false,
}; MAX_NODES];
static mut NODE_COUNT: usize = 0;

/// Placement decision agent entry point.
pub extern "C" fn placement_d_main() -> ! {
    serial_println!("[PLACEMENT_D] Placement service started (max nodes: {})", MAX_NODES);

    // Register local node as node 0 with default capacity
    unsafe {
        NODE_TABLE[0] = NodeCapacity {
            node_id: 0,
            cpu_available: 256,
            memory_available: 4096,
            energy_available: 1_000_000,
            hardware_class: 0, // generic
            active: true,
        };
        NODE_COUNT = 1;
    }

    loop {
        match crate::mailbox::recv_message(PLACEMENT_D_ID, PLACEMENT_D_MAILBOX) {
            Ok(msg) => {
                let msg_len = msg.len as usize;
                if msg_len >= 1 {
                    let op = msg.payload[0];
                    match op {
                        OP_QUERY_PLACEMENT => handle_query_placement(&msg.payload, msg_len, msg.sender_id),
                        OP_REGISTER_CAPACITY => handle_register_capacity(&msg.payload, msg_len, msg.sender_id),
                        OP_LIST_NODES => handle_list_nodes(msg.sender_id),
                        _ => {
                            serial_println!("[PLACEMENT_D] Unknown opcode: {:#x}", op);
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

/// Select the best node for an agent based on hints and capacity.
///
/// Hint types:
///   0x00 = no preference (pick node with most available energy)
///   0x01 = locality (prefer node whose id matches hint_value)
///   0x02 = energy (pick node with most available energy — same as 0x00)
///   0x03 = hardware class (prefer node matching hint_value class)
fn select_best_node(hint_type: u8, hint_value: u64) -> u16 {
    let mut best_node: u16 = 0; // default: local node
    let mut best_score: u64 = 0;

    unsafe {
        for i in 0..NODE_COUNT {
            let node = &NODE_TABLE[i];
            if !node.active {
                continue;
            }

            let score = match hint_type {
                HINT_LOCALITY => {
                    // Locality: strongly prefer the node whose id matches hint_value.
                    // Fall back to energy-based ranking for other nodes.
                    if node.node_id == hint_value as u16 {
                        u64::MAX
                    } else {
                        node.energy_available
                    }
                }
                HINT_HARDWARE => {
                    // Hardware class: boost nodes that match the requested class.
                    if node.hardware_class == hint_value as u32 {
                        node.energy_available.saturating_add(1_000_000)
                    } else {
                        node.energy_available
                    }
                }
                // HINT_ENERGY (0x02) or no preference (0x00) or unknown:
                // rank purely by available energy.
                _ => node.energy_available,
            };

            if score > best_score {
                best_score = score;
                best_node = node.node_id;
            }
        }
    }

    best_node
}

/// Handle QUERY_PLACEMENT: given hints, return recommended node_id.
/// Format: [op=0x01, hint_type:u8, hint_value:u64]
fn handle_query_placement(payload: &[u8], msg_len: usize, sender_id: AgentId) {
    if msg_len < 10 {
        serial_println!("[PLACEMENT_D] QUERY_PLACEMENT: payload too short");
        // Default: recommend local node
        let response = 0u16.to_le_bytes();
        let _ = crate::mailbox::send_message(PLACEMENT_D_ID, sender_id as MailboxId, &response);
        return;
    }

    let hint_type = payload[1];
    let hint_value = u64::from_le_bytes([
        payload[2], payload[3], payload[4], payload[5],
        payload[6], payload[7], payload[8], payload[9],
    ]);

    let recommended = select_best_node(hint_type, hint_value);

    serial_println!("[PLACEMENT_D] Placement query: hint_type={} hint_value={} -> node {}",
        hint_type, hint_value, recommended);

    let response = recommended.to_le_bytes();
    let _ = crate::mailbox::send_message(PLACEMENT_D_ID, sender_id as MailboxId, &response);
}

/// Handle REGISTER_CAPACITY: node reports its available resources.
/// Format: [op=0x02, node_id:u16, cpu:u16, memory:u32, energy:u64, hw_class:u32]
/// Total: 1 + 2 + 2 + 4 + 8 + 4 = 21 bytes (17 bytes minimum for backward compat)
fn handle_register_capacity(payload: &[u8], msg_len: usize, sender_id: AgentId) {
    if msg_len < 17 {
        serial_println!("[PLACEMENT_D] REGISTER_CAPACITY: payload too short ({} < 17)", msg_len);
        return;
    }

    let node_id = u16::from_le_bytes([payload[1], payload[2]]);
    let cpu = u16::from_le_bytes([payload[3], payload[4]]);
    let memory = u32::from_le_bytes([payload[5], payload[6], payload[7], payload[8]]);
    let energy = u64::from_le_bytes([
        payload[9], payload[10], payload[11], payload[12],
        payload[13], payload[14], payload[15], payload[16],
    ]);
    // Hardware class is optional (backward compatible): default to 0 (generic)
    let hw_class = if msg_len >= 21 {
        u32::from_le_bytes([payload[17], payload[18], payload[19], payload[20]])
    } else {
        0
    };

    unsafe {
        // Update existing node or add new one
        let mut found = false;
        for i in 0..NODE_COUNT {
            if NODE_TABLE[i].node_id == node_id {
                NODE_TABLE[i].cpu_available = cpu;
                NODE_TABLE[i].memory_available = memory;
                NODE_TABLE[i].energy_available = energy;
                NODE_TABLE[i].hardware_class = hw_class;
                NODE_TABLE[i].active = true;
                found = true;
                break;
            }
        }

        if !found && NODE_COUNT < MAX_NODES {
            NODE_TABLE[NODE_COUNT] = NodeCapacity {
                node_id,
                cpu_available: cpu,
                memory_available: memory,
                energy_available: energy,
                hardware_class: hw_class,
                active: true,
            };
            NODE_COUNT += 1;
        }
    }

    serial_println!(
        "[PLACEMENT_D] Registered capacity for node {}: cpu={} mem={} energy={} hw_class={} (from agent {})",
        node_id, cpu, memory, energy, hw_class, sender_id
    );
}

/// Handle LIST_NODES: print all known nodes and their capacity.
fn handle_list_nodes(sender_id: AgentId) {
    serial_println!("[PLACEMENT_D] === Node List (requested by agent {}) ===", sender_id);

    unsafe {
        for i in 0..NODE_COUNT {
            let node = &NODE_TABLE[i];
            if node.active {
                serial_println!(
                    "[PLACEMENT_D]   node={} cpu={} mem={} energy={}",
                    node.node_id, node.cpu_available, node.memory_available, node.energy_available
                );
            }
        }
        serial_println!("[PLACEMENT_D] === End ({} nodes) ===", NODE_COUNT);
    }
}
