//! ATOS observabilityd — Observability and Diagnostics Agent (Yellow Paper Stage 10)
//!
//! System agent that collects and exports system metrics. Periodically logs
//! system health information and responds to metric queries via mailbox.
//!
//! Protocol (mailbox message payload):
//!   METRICS_QUERY (0x01): return current metrics snapshot
//!   AGENT_STATS   (0x02): return per-agent statistics

use crate::serial_println;
use crate::agent::*;
use crate::metrics;

const OP_METRICS_QUERY: u8 = 0x01;
const OP_AGENT_STATS: u8 = 0x02;

/// Observabilityd agent mailbox — assigned during init as agent slot 15.
const OBSERVABILITYD_ID: AgentId = 15;
const OBSERVABILITYD_MAILBOX: MailboxId = 15;

/// Periodic metrics logging interval (in scheduling ticks).
const METRICS_LOG_INTERVAL: u64 = 100;

/// Observability and diagnostics system agent.
/// Collects metrics, crash dumps, and forensic evidence.
pub fn observabilityd_main() {
    serial_println!("[OBSERVABILITYD] Observability service started");

    let mut tick_counter: u64 = 0;

    loop {
        tick_counter += 1;

        // Periodically log system metrics
        if tick_counter % METRICS_LOG_INTERVAL == 0 {
            log_system_metrics();
        }

        // Check mailbox for on-demand metric requests
        match crate::mailbox::recv_message(OBSERVABILITYD_ID, OBSERVABILITYD_MAILBOX) {
            Ok(msg) => {
                let msg_len = msg.len as usize;
                if msg_len >= 1 {
                    let op = msg.payload[0];
                    match op {
                        OP_METRICS_QUERY => handle_metrics_query(msg.sender_id),
                        OP_AGENT_STATS => handle_agent_stats(msg.sender_id),
                        _ => {
                            serial_println!("[OBSERVABILITYD] Unknown command: {:#x}", op);
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

/// Log a periodic system metrics summary to serial output.
fn log_system_metrics() {
    let m = metrics::get_metrics();
    serial_println!(
        "[METRICS] ticks={} syscalls={} agents_spawned={} agents_exited={} energy={} msgs={}",
        m.uptime_ticks,
        m.total_syscalls,
        m.total_agents_spawned,
        m.total_agents_exited,
        m.total_energy_consumed,
        m.total_messages_sent,
    );
}

/// Handle METRICS_QUERY: return a metrics snapshot to the requesting agent.
fn handle_metrics_query(sender_id: AgentId) {
    let m = metrics::get_metrics();
    serial_println!(
        "[OBSERVABILITYD] Metrics query from agent {}: ticks={} syscalls={}",
        sender_id, m.uptime_ticks, m.total_syscalls,
    );

    // Send compact metrics response
    let mut response = [0u8; 49]; // 1 + 6*u64
    response[0] = 0x00; // OK
    response[1..9].copy_from_slice(&m.uptime_ticks.to_le_bytes());
    response[9..17].copy_from_slice(&m.total_syscalls.to_le_bytes());
    response[17..25].copy_from_slice(&m.total_agents_spawned.to_le_bytes());
    response[25..33].copy_from_slice(&m.total_agents_exited.to_le_bytes());
    response[33..41].copy_from_slice(&m.total_energy_consumed.to_le_bytes());
    response[41..49].copy_from_slice(&m.total_messages_sent.to_le_bytes());
    let _ = crate::mailbox::send_message(OBSERVABILITYD_ID, sender_id as MailboxId, &response);
}

/// Handle AGENT_STATS: report per-agent statistics.
fn handle_agent_stats(sender_id: AgentId) {
    serial_println!("[OBSERVABILITYD] Agent stats requested by agent {}", sender_id);

    for_each_agent_mut(|agent| {
        serial_println!(
            "[OBSERVABILITYD]   agent={} status={:?} energy={} mem_used={}/{}",
            agent.id,
            agent.status,
            agent.energy_budget,
            agent.memory_used,
            agent.memory_quota,
        );
        true // continue iteration
    });
}
