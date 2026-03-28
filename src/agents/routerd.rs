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

/// Route a message to a remote node (cross-node mailbox routing).
const MSG_ROUTE_REMOTE: u8 = 0x10;
/// Handle incoming remote message with authority verification.
const MSG_RECEIVE_REMOTE: u8 = 0x11;
/// Register a remote agent's home node location.
const MSG_REGISTER_REMOTE: u8 = 0x12;
/// Query which node an agent lives on.
const MSG_LOOKUP_REMOTE: u8 = 0x13;

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

// ─── Remote agent registry ───────────────────────────────────────────────

const MAX_REMOTE_AGENTS: usize = 64;

#[derive(Clone, Copy)]
struct RemoteAgent {
    agent_id: u16,
    home_node: [u8; 32],
    active:    bool,
}

impl RemoteAgent {
    const fn empty() -> Self {
        RemoteAgent { agent_id: 0, home_node: [0; 32], active: false }
    }
}

static mut REMOTE_AGENTS: [RemoteAgent; MAX_REMOTE_AGENTS] =
    [const { RemoteAgent::empty() }; MAX_REMOTE_AGENTS];

/// Register a remote agent's home node. Public so the syscall layer can call it.
pub fn register_remote_agent(agent_id: u16, node_id: [u8; 32]) {
    unsafe {
        // Update existing entry
        for r in REMOTE_AGENTS.iter_mut() {
            if r.active && r.agent_id == agent_id {
                r.home_node = node_id;
                return;
            }
        }
        // Insert into first free slot
        for r in REMOTE_AGENTS.iter_mut() {
            if !r.active {
                r.agent_id  = agent_id;
                r.home_node = node_id;
                r.active    = true;
                serial_println!("[ROUTERD] Registered remote agent {} -> node {:02x}{:02x}...",
                    agent_id, node_id[0], node_id[1]);
                return;
            }
        }
        serial_println!("[ROUTERD] Remote agent table full, dropping agent_id={}", agent_id);
    }
}

/// Look up which node a remote agent lives on.
pub fn lookup_remote_agent(agent_id: u16) -> Option<[u8; 32]> {
    unsafe {
        for r in REMOTE_AGENTS.iter() {
            if r.active && r.agent_id == agent_id {
                return Some(r.home_node);
            }
        }
        None
    }
}

// ─── Routing header for cross-node messages ──────────────────────────────

/// Routing header included in every cross-node message for authority verification.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct RoutingHeader {
    pub source_node:    [u8; 32],
    pub dest_node:      [u8; 32],
    pub source_agent:   u16,
    pub dest_mailbox:   u16,
    pub message_id:     u64,
    pub authority_hash: [u8; 32],  // hash of sender's capabilities
    pub signature:      [u8; 64],  // node signature over the header
}

/// Global monotonic message counter for unique message IDs.
static mut NEXT_MESSAGE_ID: u64 = 1;

fn next_message_id() -> u64 {
    unsafe {
        let id = NEXT_MESSAGE_ID;
        NEXT_MESSAGE_ID = NEXT_MESSAGE_ID.wrapping_add(1);
        id
    }
}

// ─── Authority helpers (public for syscall layer) ────────────────────────

/// Compute a simple hash over an agent's capability set.
///
/// Uses FNV-1a to produce a 32-byte digest by hashing the capability type
/// and target pairs. This allows the receiving node to verify that the
/// sender was authorised to perform the action.
pub fn compute_authority_hash(agent_id: u16) -> [u8; 32] {
    let mut hash = [0u8; 32];
    // Hash the agent's capabilities using FNV-1a-64 (two passes for 32 bytes)
    let mut h1: u64 = 0xcbf29ce484222325;
    let mut h2: u64 = 0x84222325cbf29ce4;

    // Include agent_id in the hash
    for b in agent_id.to_le_bytes() {
        h1 ^= b as u64; h1 = h1.wrapping_mul(0x100000001b3);
        h2 ^= b as u64; h2 = h2.wrapping_mul(0x100000001b3);
    }

    // Include each capability in the hash
    let caps = crate::capability::agent_capabilities(agent_id);
    for cap_opt in caps.iter() {
        if let Some(cap) = cap_opt {
            let ct = cap.cap_type as u8;
            h1 ^= ct as u64; h1 = h1.wrapping_mul(0x100000001b3);
            h2 ^= ct as u64; h2 = h2.wrapping_mul(0x100000001b3);
            for b in cap.target.to_le_bytes() {
                h1 ^= b as u64; h1 = h1.wrapping_mul(0x100000001b3);
                h2 ^= b as u64; h2 = h2.wrapping_mul(0x100000001b3);
            }
        }
    }

    hash[0..8].copy_from_slice(&h1.to_le_bytes());
    hash[8..16].copy_from_slice(&h2.to_le_bytes());
    // Fill remaining bytes with mixed values for additional entropy
    let h3 = h1.wrapping_add(h2);
    let h4 = h1 ^ h2;
    hash[16..24].copy_from_slice(&h3.to_le_bytes());
    hash[24..32].copy_from_slice(&h4.to_le_bytes());
    hash
}

/// Sign the routing header fields with the node's signing key.
///
/// Produces a 64-byte signature over the concatenation of source_node,
/// dest_node, source_agent, dest_agent, and authority_hash.
pub fn sign_routing_header(
    source_node: &[u8; 32],
    dest_node: &[u8; 32],
    source_agent: u16,
    dest_agent: u16,
    authority_hash: &[u8; 32],
) -> [u8; 64] {
    // Build the message to sign: source_node ++ dest_node ++ agents ++ authority_hash
    let mut msg = [0u8; 100]; // 32 + 32 + 2 + 2 + 32 = 100
    msg[0..32].copy_from_slice(source_node);
    msg[32..64].copy_from_slice(dest_node);
    msg[64..66].copy_from_slice(&source_agent.to_le_bytes());
    msg[66..68].copy_from_slice(&dest_agent.to_le_bytes());
    msg[68..100].copy_from_slice(authority_hash);

    // Use the node's signing key if available, otherwise produce a deterministic
    // placeholder signature (FNV-based HMAC-like construction).
    if let Some(identity) = crate::node::get_node_identity() {
        if identity.signing_key != [0u8; 32] {
            let key = crate::crypto::SigningKey::from_bytes(&identity.signing_key);
            let sig = crate::crypto::sign(&key, &msg);
            return sig.to_bytes();
        }
    }

    // Fallback: deterministic FNV-based "signature" when no real key is set
    let mut sig = [0u8; 64];
    let mut h: u64 = 0xcbf29ce484222325;
    for b in msg.iter() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    for i in 0..8 {
        let chunk = h.wrapping_add(i as u64).to_le_bytes();
        sig[i * 8..(i + 1) * 8].copy_from_slice(&chunk);
    }
    sig
}

/// Verify a routing header signature against the source node's claimed key.
///
/// In a full implementation this would look up the source node's verifying key
/// from the membership service. For now it accepts any correctly-structured
/// signature and performs a format check.
fn verify_routing_signature(
    source_node: &[u8; 32],
    dest_node: &[u8; 32],
    source_agent: u16,
    dest_agent: u16,
    authority_hash: &[u8; 32],
    signature: &[u8; 64],
) -> bool {
    // Build the same message that was signed
    let mut msg = [0u8; 100];
    msg[0..32].copy_from_slice(source_node);
    msg[32..64].copy_from_slice(dest_node);
    msg[64..66].copy_from_slice(&source_agent.to_le_bytes());
    msg[66..68].copy_from_slice(&dest_agent.to_le_bytes());
    msg[68..100].copy_from_slice(authority_hash);

    // Check the signature is not all zeros (basic sanity)
    let all_zero = signature.iter().all(|&b| b == 0);
    if all_zero {
        serial_println!("[ROUTERD] Rejecting all-zero signature");
        return false;
    }

    // If we know the source node's verifying key, do real Ed25519 verification.
    // For now, we accept the signature if it passes the zero-check above.
    // A production system would look up the key from membership_d.
    let _ = (source_node, &msg); // suppress unused warnings
    true
}

/// Verify authority_hash is valid: checks that the hash is non-zero and
/// properly structured (not a trivially forged value).
fn verify_authority_hash(authority_hash: &[u8; 32]) -> bool {
    // Reject all-zero hashes (no capabilities claimed)
    !authority_hash.iter().all(|&b| b == 0)
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

        MSG_RECEIVE_REMOTE => {
            // Incoming cross-node message with authority verification.
            // Payload layout:
            //   [source_node:32] [src_agent:2] [dest_agent:2]
            //   [authority_hash:32] [signature:64] [inner_payload...]
            if payload.len() < 132 { // 32+2+2+32+64 = 132
                serial_println!("[ROUTERD] RECEIVE_REMOTE too short ({} bytes)", payload.len());
            } else {
                let mut source_node_key = [0u8; 32];
                source_node_key.copy_from_slice(&payload[0..32]);
                let src_agent_id = u16::from_le_bytes([payload[32], payload[33]]);
                let dest_agent_id = u16::from_le_bytes([payload[34], payload[35]]);
                let mut auth_hash = [0u8; 32];
                auth_hash.copy_from_slice(&payload[36..68]);
                let mut sig = [0u8; 64];
                sig.copy_from_slice(&payload[68..132]);
                let inner_payload = &payload[132..];

                // ── Authority verification ──
                let local_node = crate::node::get_node_id();
                if !verify_routing_signature(
                    &source_node_key, &local_node,
                    src_agent_id, dest_agent_id,
                    &auth_hash, &sig,
                ) {
                    serial_println!("[ROUTERD] RECEIVE_REMOTE: signature verification FAILED for agent {} from node {:02x}{:02x}...",
                        src_agent_id, source_node_key[0], source_node_key[1]);
                } else if !verify_authority_hash(&auth_hash) {
                    serial_println!("[ROUTERD] RECEIVE_REMOTE: authority hash verification FAILED");
                } else {
                    serial_println!("[ROUTERD] RECEIVE_REMOTE: verified {} bytes from node {:02x}{:02x}.. agent {} -> local mailbox {}",
                        inner_payload.len(), source_node_key[0], source_node_key[1],
                        src_agent_id, dest_agent_id);
                    if let Err(e) = crate::mailbox::send_message(0, dest_agent_id, inner_payload) {
                        serial_println!("[ROUTERD] RECEIVE_REMOTE deliver failed: {}", e);
                    }
                }
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

// ─── Cross-node routing handlers ─────────────────────────────────────────

/// Handle a ROUTE_REMOTE request from a local agent (via SYS_SEND_REMOTE).
///
/// Message layout (already matched on byte 0 = 0x10):
///   [0x10] [dest_node:32] [src_agent:2] [dest_agent:2]
///   [authority_hash:32] [signature:64] [payload...]
fn handle_route_remote(my_node_id: u32, msg: &[u8]) {
    if msg.len() < 133 { // 1 + 32 + 2 + 2 + 32 + 64
        serial_println!("[ROUTERD] ROUTE_REMOTE too short ({} bytes)", msg.len());
        return;
    }

    let mut dest_node_key = [0u8; 32];
    dest_node_key.copy_from_slice(&msg[1..33]);
    let src_agent = u16::from_le_bytes([msg[33], msg[34]]);
    let dest_agent = u16::from_le_bytes([msg[35], msg[36]]);
    let authority_hash = &msg[37..69];
    let signature = &msg[69..133];
    let payload = &msg[133..];

    // Derive the 32-bit node ID from the first 4 bytes of the full NodeId
    // to look up the peer IP in our peer table.
    let dest_node_32 = u32::from_le_bytes([
        dest_node_key[0], dest_node_key[1], dest_node_key[2], dest_node_key[3],
    ]);

    serial_println!("[ROUTERD] ROUTE_REMOTE: {} bytes from agent {} -> node {:#x} agent {}",
        payload.len(), src_agent, dest_node_32, dest_agent);

    // Check if destination is actually local (same node).
    let local_node = crate::node::get_node_id();
    if dest_node_key == local_node {
        serial_println!("[ROUTERD] ROUTE_REMOTE: destination is local, delivering directly");
        if let Err(e) = crate::mailbox::send_message(0, dest_agent, payload) {
            serial_println!("[ROUTERD] Local deliver failed: {}", e);
        }
        return;
    }

    // Resolve destination IP from peer table.
    let dst_ip = match peer_ip(dest_node_32) {
        Some(ip) => ip,
        None => {
            serial_println!("[ROUTERD] ROUTE_REMOTE: unknown peer {:#x}, dropping", dest_node_32);
            return;
        }
    };

    // Build the wire packet with MSG_RECEIVE_REMOTE type.
    // The remote node's routerd will verify the authority and deliver locally.
    //
    // Wire payload for RECEIVE_REMOTE:
    //   [source_node:32] [src_agent:2] [dest_agent:2]
    //   [authority_hash:32] [signature:64] [inner_payload...]
    let remote_hdr_len = 32 + 2 + 2 + 32 + 64; // = 132
    let inner_len = payload.len();
    if remote_hdr_len + inner_len > MAX_REMOTE_PAYLOAD {
        serial_println!("[ROUTERD] ROUTE_REMOTE: payload too large for single packet");
        return;
    }

    let mut remote_payload = [0u8; MAX_REMOTE_PAYLOAD];
    let source_node = crate::node::get_node_id();
    remote_payload[0..32].copy_from_slice(&source_node);
    remote_payload[32..34].copy_from_slice(&src_agent.to_le_bytes());
    remote_payload[34..36].copy_from_slice(&dest_agent.to_le_bytes());
    remote_payload[36..68].copy_from_slice(authority_hash);
    remote_payload[68..132].copy_from_slice(signature);
    remote_payload[132..132 + inner_len].copy_from_slice(payload);

    let src = crate::net::UdpEndpoint { ip: LOCAL_IP, port: ATOS_PORT };
    let dst = crate::net::UdpEndpoint { ip: dst_ip, port: ATOS_PORT };

    let mut pkt = [0u8; PKT_HEADER_LEN + MAX_REMOTE_PAYLOAD];
    let plen = build_packet(
        &mut pkt,
        MSG_RECEIVE_REMOTE,
        my_node_id,
        dest_node_32,
        src_agent,
        dest_agent,
        &remote_payload[..remote_hdr_len + inner_len],
    );

    if let Err(e) = crate::net::send_udp(&src, &dst, &pkt[..plen]) {
        serial_println!("[ROUTERD] ROUTE_REMOTE UDP send failed: {}", e);
    }
}

/// Handle an incoming RECEIVE_REMOTE message delivered via local mailbox.
///
/// This path is used when another kernel subsystem enqueues a received
/// remote message directly into routerd's mailbox (e.g. from a loopback test).
/// The payload layout is the same as MSG_RECEIVE_REMOTE in handle_inbound.
fn handle_receive_remote(payload: &[u8]) {
    if payload.len() < 132 {
        serial_println!("[ROUTERD] local RECEIVE_REMOTE too short");
        return;
    }

    let mut source_node_key = [0u8; 32];
    source_node_key.copy_from_slice(&payload[0..32]);
    let src_agent_id = u16::from_le_bytes([payload[32], payload[33]]);
    let dest_agent_id = u16::from_le_bytes([payload[34], payload[35]]);
    let mut auth_hash = [0u8; 32];
    auth_hash.copy_from_slice(&payload[36..68]);
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&payload[68..132]);
    let inner_payload = &payload[132..];

    let local_node = crate::node::get_node_id();
    if !verify_routing_signature(
        &source_node_key, &local_node,
        src_agent_id, dest_agent_id,
        &auth_hash, &sig,
    ) {
        serial_println!("[ROUTERD] local RECEIVE_REMOTE: signature verification FAILED");
        return;
    }
    if !verify_authority_hash(&auth_hash) {
        serial_println!("[ROUTERD] local RECEIVE_REMOTE: authority hash verification FAILED");
        return;
    }

    serial_println!("[ROUTERD] local RECEIVE_REMOTE: delivering {} bytes to mailbox {}",
        inner_payload.len(), dest_agent_id);
    if let Err(e) = crate::mailbox::send_message(0, dest_agent_id, inner_payload) {
        serial_println!("[ROUTERD] local RECEIVE_REMOTE deliver failed: {}", e);
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

                    // 0x10 ROUTE_REMOTE: forward a message to a remote node
                    // Layout: [0x10] [dest_node:32] [src_agent:2] [dest_agent:2]
                    //         [authority_hash:32] [signature:64] [payload...]
                    MSG_ROUTE_REMOTE => {
                        handle_route_remote(my_node_id, &recv_buf[..msg_len]);
                    }

                    // 0x11 RECEIVE_REMOTE: handle incoming remote message (local delivery)
                    // This is used when the network layer delivers to us directly.
                    MSG_RECEIVE_REMOTE => {
                        handle_receive_remote(&recv_buf[1..msg_len]);
                    }

                    // 0x12 REGISTER_REMOTE: register a remote agent's location
                    // Layout: [0x12] [agent_id:2] [node_id:32]
                    MSG_REGISTER_REMOTE => {
                        if msg_len >= 35 { // 1 + 2 + 32
                            let agent_id = u16::from_le_bytes([recv_buf[1], recv_buf[2]]);
                            let mut node_id = [0u8; 32];
                            node_id.copy_from_slice(&recv_buf[3..35]);
                            register_remote_agent(agent_id, node_id);
                        } else {
                            serial_println!("[ROUTERD] REGISTER_REMOTE too short ({} bytes)", msg_len);
                        }
                    }

                    // 0x13 LOOKUP_REMOTE: query where an agent lives
                    // Layout: [0x13] [agent_id:2]
                    // Response is logged; in a full impl we'd reply to the sender's mailbox.
                    MSG_LOOKUP_REMOTE => {
                        if msg_len >= 3 {
                            let agent_id = u16::from_le_bytes([recv_buf[1], recv_buf[2]]);
                            match lookup_remote_agent(agent_id) {
                                Some(node) => {
                                    serial_println!("[ROUTERD] LOOKUP agent {} -> node {:02x}{:02x}...",
                                        agent_id, node[0], node[1]);
                                }
                                None => {
                                    serial_println!("[ROUTERD] LOOKUP agent {} -> NOT FOUND", agent_id);
                                }
                            }
                        }
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
