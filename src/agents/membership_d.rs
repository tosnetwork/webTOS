//! ATOS membership_d — Cluster Membership Service  (Stage 8: Distributed Execution Fabric)
//!
//! Responsibilities
//! ────────────────
//! 1. Track known cluster nodes and their liveness via periodic heartbeats.
//! 2. Maintain a local view of cluster membership (join / leave / fail).
//! 3. Update the node identity heartbeat timestamp so other subsystems can
//!    query liveness.
//!
//! membership_d listens on its well-known mailbox (mailbox 13) for:
//!   - Heartbeat notifications forwarded by routerd from remote nodes.
//!   - Local queries about cluster membership state.
//!
//! In this initial implementation the agent simply logs its presence and
//! maintains heartbeat bookkeeping. Full protocol (protocol gossip, quorum
//! detection, split-brain resolution) is planned for Stage 9+.

use crate::serial_println;
use crate::agent::*;
use crate::syscall;

// ─── Cluster member tracking ─────────────────────────────────────────────

const MAX_MEMBERS: usize = 16;

#[derive(Clone, Copy)]
struct ClusterMember {
    node_id: [u8; 32],
    last_seen_tick: u64,
    is_alive: bool,
}

impl ClusterMember {
    const fn empty() -> Self {
        ClusterMember {
            node_id: [0; 32],
            last_seen_tick: 0,
            is_alive: false,
        }
    }
}

static mut MEMBERS: [ClusterMember; MAX_MEMBERS] = [const { ClusterMember::empty() }; MAX_MEMBERS];
static mut MEMBER_COUNT: usize = 0;

/// Register or refresh a cluster member.
fn upsert_member(node_id: &[u8; 32], tick: u64) {
    unsafe {
        // Update existing
        for m in MEMBERS.iter_mut() {
            if m.is_alive && m.node_id == *node_id {
                m.last_seen_tick = tick;
                return;
            }
        }
        // Insert new
        if MEMBER_COUNT < MAX_MEMBERS {
            for m in MEMBERS.iter_mut() {
                if !m.is_alive {
                    m.node_id = *node_id;
                    m.last_seen_tick = tick;
                    m.is_alive = true;
                    MEMBER_COUNT += 1;
                    serial_println!("[MEMBERSHIP_D] New member joined (total={})", MEMBER_COUNT);
                    return;
                }
            }
        }
    }
}

/// Mark members as dead if they haven't been seen within the timeout.
fn reap_dead_members(now: u64, timeout: u64) {
    unsafe {
        for m in MEMBERS.iter_mut() {
            if m.is_alive && now.wrapping_sub(m.last_seen_tick) > timeout {
                m.is_alive = false;
                MEMBER_COUNT -= 1;
                serial_println!("[MEMBERSHIP_D] Member timed out (remaining={})", MEMBER_COUNT);
            }
        }
    }
}

/// Return the current count of live cluster members.
pub fn member_count() -> usize {
    unsafe { MEMBER_COUNT }
}

// ─── Agent entry point ───────────────────────────────────────────────────

pub extern "C" fn membership_d_entry() -> ! {
    serial_println!("[MEMBERSHIP_D] Cluster membership service started");

    let my_mailbox: u64 = 13; // membership_d's well-known mailbox
    let mut recv_buf = [0u8; MAX_MESSAGE_PAYLOAD];

    // Register ourselves as the first cluster member.
    let my_id = crate::node::get_node_id();
    let tick = crate::arch::x86_64::timer::get_ticks();
    upsert_member(&my_id, tick);

    let mut last_reap_tick: u64 = 0;
    const REAP_INTERVAL: u64 = 1000;   // ticks between liveness sweeps
    const MEMBER_TIMEOUT: u64 = 5000;  // ticks before marking a member dead

    loop {
        // ── 1. Drain mailbox messages (heartbeats, queries) ──────────
        let len = syscall::syscall(
            SYS_RECV_TIMEOUT,
            my_mailbox,
            recv_buf.as_mut_ptr() as u64,
            recv_buf.len() as u64,
            1, // non-blocking (1-tick timeout)
            0,
        );

        if len > 0 {
            let msg_len = len as usize;
            // Simple heartbeat message: first 32 bytes = sender node_id
            if msg_len >= 32 {
                let mut sender_id = [0u8; 32];
                sender_id.copy_from_slice(&recv_buf[..32]);
                let now = crate::arch::x86_64::timer::get_ticks();
                upsert_member(&sender_id, now);
            }
        }

        // ── 2. Periodic liveness reaping ──────────────────────────────
        let now = crate::arch::x86_64::timer::get_ticks();
        if now.wrapping_sub(last_reap_tick) >= REAP_INTERVAL {
            last_reap_tick = now;
            reap_dead_members(now, MEMBER_TIMEOUT);
            // Update our own heartbeat
            crate::node::record_heartbeat(now);
        }

        syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0);
    }
}
