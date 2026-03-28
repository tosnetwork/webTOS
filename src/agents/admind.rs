//! ATOS admind — Remote Administration Agent (Yellow Paper Stage 10)
//!
//! System agent for remote administration. All admin operations go through
//! authenticated mailbox messages — no shell access (the ATOS way).
//!
//! Protocol (mailbox message payload):
//!   STATUS       (0x01): system health summary
//!   AGENT_LIST   (0x02): list running agents
//!   AGENT_KILL   (0x03): terminate agent by ID [op, agent_id: u16]
//!   ENERGY_REPORT(0x04): energy accounting summary
//!   METRICS      (0x05): system metrics snapshot

use crate::serial_println;
use crate::agent::*;
use crate::metrics;

const OP_STATUS: u8 = 0x01;
const OP_AGENT_LIST: u8 = 0x02;
const OP_AGENT_KILL: u8 = 0x03;
const OP_ENERGY_REPORT: u8 = 0x04;
const OP_METRICS: u8 = 0x05;

/// Admind agent mailbox — assigned during init as agent slot 14.
const ADMIND_ID: AgentId = 14;
const ADMIND_MAILBOX: MailboxId = 14;

/// Remote administration system agent.
/// All admin operations go through authenticated mailbox messages.
/// No shell access — this is the ATOS way.
pub fn admind_main() {
    serial_println!("[ADMIND] Administration service started");

    loop {
        match crate::mailbox::recv_message(ADMIND_ID, ADMIND_MAILBOX) {
            Ok(msg) => {
                let msg_len = msg.len as usize;
                if msg_len >= 1 {
                    let op = msg.payload[0];
                    match op {
                        OP_STATUS => handle_status(msg.sender_id),
                        OP_AGENT_LIST => handle_agent_list(msg.sender_id),
                        OP_AGENT_KILL => handle_agent_kill(&msg.payload, msg_len, msg.sender_id),
                        OP_ENERGY_REPORT => handle_energy_report(msg.sender_id),
                        OP_METRICS => handle_metrics(msg.sender_id),
                        _ => {
                            serial_println!("[ADMIND] Unknown command: {:#x}", op);
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

/// Handle STATUS: report system health summary.
fn handle_status(sender_id: AgentId) {
    let m = metrics::get_metrics();
    serial_println!("[ADMIND] System status for agent {}:", sender_id);
    serial_println!("[ADMIND]   uptime_ticks={}", m.uptime_ticks);
    serial_println!("[ADMIND]   agents_spawned={} exited={}", m.total_agents_spawned, m.total_agents_exited);
    serial_println!("[ADMIND]   total_syscalls={}", m.total_syscalls);
    serial_println!("[ADMIND]   total_energy={}", m.total_energy_consumed);

    // Count currently active agents
    let mut active_count: u16 = 0;
    for_each_agent_mut(|_agent| {
        active_count += 1;
        true // continue iteration
    });
    serial_println!("[ADMIND]   active_agents={}", active_count);

    // Send summary response: [status_ok, active_count_lo, active_count_hi]
    let response = [0x00u8, active_count as u8, (active_count >> 8) as u8];
    let _ = crate::mailbox::send_message(ADMIND_ID, sender_id as MailboxId, &response);
}

/// Handle AGENT_LIST: list all active agents.
fn handle_agent_list(sender_id: AgentId) {
    serial_println!("[ADMIND] === Active Agents (requested by {}) ===", sender_id);

    for_each_agent_mut(|agent| {
        serial_println!(
            "[ADMIND]   id={} status={:?} energy={} priority={:?}",
            agent.id,
            agent.status,
            agent.energy_budget,
            agent.priority,
        );
        true // continue iteration
    });

    serial_println!("[ADMIND] === End Agent List ===");
}

/// Handle AGENT_KILL: terminate an agent by ID.
/// Format: [op=0x03, target_id: u16]
fn handle_agent_kill(payload: &[u8], msg_len: usize, sender_id: AgentId) {
    if msg_len < 3 {
        serial_println!("[ADMIND] AGENT_KILL: payload too short");
        return;
    }

    // Only root agent can kill other agents
    if sender_id != ROOT_AGENT_ID {
        serial_println!("[ADMIND] AGENT_KILL denied: agent {} is not root", sender_id);
        return;
    }

    let target_id = u16::from_le_bytes([payload[1], payload[2]]);

    // Refuse to kill critical system agents (idle=0, root=1)
    if target_id <= ROOT_AGENT_ID {
        serial_println!("[ADMIND] AGENT_KILL refused: cannot kill system agent {}", target_id);
        return;
    }

    serial_println!("[ADMIND] Terminating agent {} (requested by root)", target_id);
    terminate_agent(target_id, AgentStatus::Exited);
    crate::event::agent_exited(target_id, 0);
    serial_println!("[ADMIND] Agent {} terminated", target_id);
}

/// Handle ENERGY_REPORT: per-agent energy usage summary.
fn handle_energy_report(sender_id: AgentId) {
    serial_println!("[ADMIND] === Energy Report (requested by {}) ===", sender_id);

    let m = metrics::get_metrics();
    serial_println!("[ADMIND]   total_energy_consumed={}", m.total_energy_consumed);

    for_each_agent_mut(|agent| {
        serial_println!(
            "[ADMIND]   agent {} energy_budget={}",
            agent.id,
            agent.energy_budget,
        );
        true // continue iteration
    });

    serial_println!("[ADMIND] === End Energy Report ===");
}

/// Handle METRICS: return a SystemMetrics snapshot.
fn handle_metrics(sender_id: AgentId) {
    let m = metrics::get_metrics();
    serial_println!(
        "[ADMIND] Metrics snapshot for agent {}: ticks={} syscalls={} spawned={} exited={} energy={} msgs_sent={} msgs_recv={}",
        sender_id,
        m.uptime_ticks,
        m.total_syscalls,
        m.total_agents_spawned,
        m.total_agents_exited,
        m.total_energy_consumed,
        m.total_messages_sent,
        m.total_messages_received,
    );

    // Send metrics as a compact binary response
    let mut response = [0u8; 33]; // 1 byte status + 4 x u64 fields
    response[0] = 0x00; // OK
    response[1..9].copy_from_slice(&m.uptime_ticks.to_le_bytes());
    response[9..17].copy_from_slice(&m.total_syscalls.to_le_bytes());
    response[17..25].copy_from_slice(&m.total_agents_spawned.to_le_bytes());
    response[25..33].copy_from_slice(&m.total_energy_consumed.to_le_bytes());
    let _ = crate::mailbox::send_message(ADMIND_ID, sender_id as MailboxId, &response);
}
