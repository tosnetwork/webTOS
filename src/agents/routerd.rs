//! ATOS routerd — Remote Mailbox Routing Agent  (Phase 19: Distributed Execution)
//!
//! Responsibilities
//! ────────────────
//! 1. Cross-node mailbox routing
//!    • Agents send a "remote forward" message to routerd's mailbox (mailbox 10)
//!      using the MSG_MAILBOX_FORWARD type.
//!    • routerd wraps the payload in the ATOS distributed packet format and sends
//!      it via kernel UDP (src/net.rs).
//!    • Incoming UDP packets are demultiplexed and delivered to the local mailbox
//!      of the target agent.
//!
//! 2. Node discovery (seed-based)
//!    • routerd periodically broadcasts a HELLO packet on UDP port 4001.
//!    • On receiving a HELLO it adds the sender to the peer table.
//!
//! Packet wire format (all fields little-endian)
//! ──────────────────────────────────────────────
//!   [magic:       4B  = 0x4154_5344 "ATSD"]
//!   [msg_type:    1B]
//!   [src_node:    4B]
//!   [dst_node:    4B]
//!   [src_agent:   2B]
//!   [dst_agent:   2B]
//!   [payload_len: 2B]
//!   [payload:     variable (0..=MAX_MESSAGE_PAYLOAD)]
//!
//! Total header: 4+1+4+4+2+2+2 = 19 bytes.

use crate::serial_println;
use crate::agent::*;
use crate::syscall;

// ─── ATOS Distributed packet constants ───────────────────────────────────────

/// Wire magic for ATOS distributed packets.
const ATOS_DIST_MAGIC: u32 = 0x4154_5344; // "ATSD"

/// Minimum packet size (header without payload).
const PKT_HEADER_LEN: usize = 19;

/// Maximum agent payload that fits in one UDP datagram together with the header.
/// We keep it well under the 1 400-byte net.rs limit.
const MAX_REMOTE_PAYLOAD: usize = 256; // == MAX_MESSAGE_PAYLOAD

// ─── msg_type values ─────────────────────────────────────────────────────────

/// Forward a message payload to a remote agent's mailbox.
const MSG_MAILBOX_FORWARD: u8 = 0x01;
/// Node discovery HELLO broadcast.
const MSG_NODE_HELLO: u8 = 0x02;
/// Acknowledgement of a HELLO (reserved, not yet used).
#[allow(dead_code)]
const MSG_NODE_ACK: u8 = 0x03;
/// Agent migration payload.
#[allow(dead_code)]
const MSG_AGENT_MIGRATE: u8 = 0x04;

// ─── UDP port assignments ────────────────────────────────────────────────────

/// Port used for all inter-node ATOS traffic (data + HELLO).
const ATOS_PORT: u16 = 4001;

/// Our own IP address (QEMU default guest).  In a real deployment this would
/// come from DHCP or a config file.
const LOCAL_IP: [u8; 4] = [10, 0, 2, 15];

/// Broadcast IP for HELLO packets.
const BCAST_IP: [u8; 4] = [255, 255, 255, 255];

// ─── Peer table ──────────────────────────────────────────────────────────────

const MAX_PEERS: usize = 8;

#[derive(Clone, Copy)]
struct Peer {
    node_id: u32,
    ip:      [u8; 4],
    active:  bool,
}

impl Peer {
    const fn empty() -> Self {
        Peer { node_id: 0, ip: [0; 4], active: false }
    }
}

static mut PEERS: [Peer; MAX_PEERS] = [const { Peer::empty() }; MAX_PEERS];

/// Add or update a peer entry. Silently drops if the table is full and the
/// peer is already unknown.
fn upsert_peer(node_id: u32, ip: [u8; 4]) {
    unsafe {
        // Update existing entry if present
        for p in PEERS.iter_mut() {
            if p.active && p.node_id == node_id {
                p.ip = ip;
                return;
            }
        }
        // Insert into first free slot
        for p in PEERS.iter_mut() {
            if !p.active {
                p.node_id = node_id;
                p.ip      = ip;
                p.active  = true;
                serial_println!("[ROUTERD] New peer: node_id={:#x} ip={}.{}.{}.{}",
                    node_id, ip[0], ip[1], ip[2], ip[3]);
                return;
            }
        }
        serial_println!("[ROUTERD] Peer table full, dropping node_id={:#x}", node_id);
    }
}

/// Look up a peer's IP by node_id.
fn peer_ip(node_id: u32) -> Option<[u8; 4]> {
    unsafe {
        for p in PEERS.iter() {
            if p.active && p.node_id == node_id {
                return Some(p.ip);
            }
        }
        None
    }
}

// ─── Packet helpers ──────────────────────────────────────────────────────────

/// Build an ATOS distributed packet into `out` and return its total byte length.
///
/// `out` must be at least PKT_HEADER_LEN + payload.len() bytes.
fn build_packet(
    out:      &mut [u8],
    msg_type: u8,
    src_node: u32,
    dst_node: u32,
    src_agent: u16,
    dst_agent: u16,
    payload:  &[u8],
) -> usize {
    let plen = payload.len().min(MAX_REMOTE_PAYLOAD);
    let total = PKT_HEADER_LEN + plen;
    if out.len() < total { return 0; }

    out[0..4].copy_from_slice(&ATOS_DIST_MAGIC.to_le_bytes());
    out[4]   = msg_type;
    out[5..9].copy_from_slice(&src_node.to_le_bytes());
    out[9..13].copy_from_slice(&dst_node.to_le_bytes());
    out[13..15].copy_from_slice(&src_agent.to_le_bytes());
    out[15..17].copy_from_slice(&dst_agent.to_le_bytes());
    out[17..19].copy_from_slice(&(plen as u16).to_le_bytes());
    out[19..19 + plen].copy_from_slice(&payload[..plen]);

    total
}

/// Parse the header fields from a raw ATOS distributed packet.
///
/// Returns `None` if the magic is wrong or the buffer is too short.
fn parse_packet(buf: &[u8]) -> Option<(u8, u32, u32, u16, u16, &[u8])> {
    if buf.len() < PKT_HEADER_LEN { return None; }
    let magic = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if magic != ATOS_DIST_MAGIC { return None; }

    let msg_type  = buf[4];
    let src_node  = u32::from_le_bytes([buf[5],  buf[6],  buf[7],  buf[8]]);
    let dst_node  = u32::from_le_bytes([buf[9],  buf[10], buf[11], buf[12]]);
    let src_agent = u16::from_le_bytes([buf[13], buf[14]]);
    let dst_agent = u16::from_le_bytes([buf[15], buf[16]]);
    let plen      = u16::from_le_bytes([buf[17], buf[18]]) as usize;

    if PKT_HEADER_LEN + plen > buf.len() { return None; }
    let payload = &buf[PKT_HEADER_LEN..PKT_HEADER_LEN + plen];

    Some((msg_type, src_node, dst_node, src_agent, dst_agent, payload))
}

// ─── Inbound packet dispatch ─────────────────────────────────────────────────

/// Handle a fully-parsed inbound packet received from a remote node.
fn handle_inbound(
    src_node: u32,
    src_ip:   [u8; 4],
    msg_type: u8,
    dst_agent: u16,
    payload:   &[u8],
) {
    match msg_type {
        MSG_NODE_HELLO => {
            // payload[0..4] = sender node_id (redundant but handy)
            let hello_id = if payload.len() >= 4 {
                u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]])
            } else {
                src_node
            };
            upsert_peer(hello_id, src_ip);
        }

        MSG_MAILBOX_FORWARD => {
            // Deliver payload to the local mailbox of dst_agent.
            // We use a kernel-side direct enqueue (sender_id = 0 = kernel).
            serial_println!("[ROUTERD] Delivering {} bytes from node {:#x} to local mailbox {}",
                payload.len(), src_node, dst_agent);

            // Ensure we have send capability; routerd runs as kernel agent 0
            // which has wildcard capabilities, so send_message should succeed.
            if let Err(e) = crate::mailbox::send_message(0, dst_agent, payload) {
                serial_println!("[ROUTERD] Deliver failed: {}", e);
            }
        }

        MSG_AGENT_MIGRATE => {
            // Deserialize the agent from the migration blob.
            serial_println!("[ROUTERD] Received agent migration blob ({} bytes)", payload.len());
            if let Some(new_id) = crate::checkpoint::deserialize_agent(payload) {
                serial_println!("[ROUTERD] Migrated agent assigned new_id={}", new_id);
                // Make it schedulable (unblock puts it into the run queue).
                crate::sched::unblock(new_id);
            } else {
                serial_println!("[ROUTERD] Agent migration deserialization failed");
            }
        }

        other => {
            serial_println!("[ROUTERD] Unknown msg_type={:#x}, {} bytes from node {:#x}",
                other, payload.len(), src_node);
        }
    }
}

// ─── Outbound helpers ────────────────────────────────────────────────────────

/// Send a HELLO broadcast so that peers can discover us.
fn send_hello(my_node_id: u32) {
    let src = crate::net::UdpEndpoint { ip: LOCAL_IP, port: ATOS_PORT };
    let dst = crate::net::UdpEndpoint { ip: BCAST_IP, port: ATOS_PORT };

    let mut pkt = [0u8; PKT_HEADER_LEN + 4];
    let plen = build_packet(
        &mut pkt,
        MSG_NODE_HELLO,
        my_node_id,
        0xFFFF_FFFF, // broadcast dst node
        0,
        0,
        &my_node_id.to_le_bytes(),
    );

    if let Err(e) = crate::net::send_udp(&src, &dst, &pkt[..plen]) {
        serial_println!("[ROUTERD] HELLO send failed: {}", e);
    }
}

/// Forward a local agent's message to a remote node.
///
/// `msg` layout expected by callers (same as Stage-1 routerd protocol):
///   [msg_type: 1B = MSG_MAILBOX_FORWARD]
///   [dst_node: 4B]
///   [dst_mailbox: 2B]
///   [payload: remaining bytes]
fn handle_forward_request(my_node_id: u32, msg: &[u8]) {
    if msg.len() < 7 { return; }
    // byte 0 is msg_type (already matched by caller)
    let dst_node    = u32::from_le_bytes([msg[1], msg[2], msg[3], msg[4]]);
    let dst_mailbox = u16::from_le_bytes([msg[5], msg[6]]);
    let payload     = &msg[7..];

    serial_println!("[ROUTERD] Forward request: {} bytes -> node {:#x} mailbox {}",
        payload.len(), dst_node, dst_mailbox);

    // Resolve the destination IP from the peer table.
    let dst_ip = match peer_ip(dst_node) {
        Some(ip) => ip,
        None => {
            serial_println!("[ROUTERD] Unknown peer {:#x}, dropping", dst_node);
            return;
        }
    };

    let src = crate::net::UdpEndpoint { ip: LOCAL_IP, port: ATOS_PORT };
    let dst = crate::net::UdpEndpoint { ip: dst_ip, port: ATOS_PORT };

    let mut pkt = [0u8; PKT_HEADER_LEN + MAX_REMOTE_PAYLOAD];
    let plen = build_packet(
        &mut pkt,
        MSG_MAILBOX_FORWARD,
        my_node_id,
        dst_node,
        0,           // src_agent: routerd itself
        dst_mailbox,
        payload,
    );

    if let Err(e) = crate::net::send_udp(&src, &dst, &pkt[..plen]) {
        serial_println!("[ROUTERD] UDP send failed: {}", e);
    }
}

// ─── Agent entry point ───────────────────────────────────────────────────────

pub extern "C" fn routerd_entry() -> ! {
    // Derive / read node ID (crate::node initialises lazily from MAC).
    let my_node_id = crate::node::node_id();

    serial_println!("[ROUTERD] Remote mailbox router started (node_id={:#x})", my_node_id);

    let my_mailbox: u64 = 10; // routerd's well-known mailbox
    let mut recv_buf = [0u8; MAX_MESSAGE_PAYLOAD];

    // Send initial HELLO so peers discover us immediately.
    send_hello(my_node_id);

    let mut hello_tick: u64 = 0;
    const HELLO_INTERVAL: u64 = 500; // ticks between HELLO broadcasts

    loop {
        // ── 1. Drain local mailbox messages ────────────────────────────────
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
            if msg_len >= 1 {
                match recv_buf[0] {
                    MSG_MAILBOX_FORWARD => {
                        handle_forward_request(my_node_id, &recv_buf[..msg_len]);
                    }
                    _ => {
                        serial_println!("[ROUTERD] Unknown local msg_type={:#x}", recv_buf[0]);
                    }
                }
            }
        }

        // ── 2. Poll for incoming UDP packets ───────────────────────────────
        let mut udp_buf = [0u8; PKT_HEADER_LEN + MAX_REMOTE_PAYLOAD + 8];
        if let Some((src_ep, udp_len)) = crate::net::recv_udp(&mut udp_buf) {
            // Only process packets destined for our port or broadcasts.
            if let Some((msg_type, src_node, dst_node, _src_agent, dst_agent, payload)) =
                parse_packet(&udp_buf[..udp_len])
            {
                // Accept packets addressed to us or to the broadcast node ID.
                if dst_node == my_node_id || dst_node == 0xFFFF_FFFF {
                    handle_inbound(src_node, src_ep.ip, msg_type, dst_agent, payload);
                }
            }
        }

        // ── 3. Periodic HELLO broadcast ────────────────────────────────────
        let now = crate::arch::x86_64::timer::get_ticks();
        if now.wrapping_sub(hello_tick) >= HELLO_INTERVAL {
            hello_tick = now;
            send_hello(my_node_id);
        }

        syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0);
    }
}
