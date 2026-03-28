//! ATOS Node Identity
//!
//! Each ATOS node has a 32-bit node ID used to uniquely identify it in a
//! distributed cluster. The default is derived from the low 4 bytes of the
//! NIC MAC address (same heuristic the old routerd used), but it can be
//! overridden at runtime via `set_node_id`.

/// Current node ID (mutable so boot code can override before scheduler starts).
static mut NODE_ID: u32 = 0;

/// Return this node's 32-bit ID.
///
/// If the node ID has not been set yet (still 0) a value is derived on the fly
/// from the MAC address so that a valid, non-zero ID is always returned.
pub fn node_id() -> u32 {
    // Safety: single-core access during early boot; later reads are
    // effectively immutable once set_node_id() has been called once.
    unsafe {
        if NODE_ID == 0 {
            let mac = crate::net::get_mac();
            NODE_ID = u32::from_le_bytes([mac[2], mac[3], mac[4], mac[5]]);
            // Ensure we never return 0 even on a zeroed MAC
            if NODE_ID == 0 {
                NODE_ID = 0x00_00_01_01; // fallback: 1.1
            }
        }
        NODE_ID
    }
}

/// Override this node's ID.
///
/// Should be called before the scheduler starts (i.e. before any agent that
/// uses the node ID is scheduled). Passing 0 is a no-op so that callers can
/// safely call this with an "unset" value without clobbering a derived ID.
pub fn set_node_id(id: u32) {
    if id != 0 {
        // Safety: called during single-threaded early boot.
        unsafe { NODE_ID = id; }
    }
}

// ─── Extended node identity (Stage 8: Distributed Execution Fabric) ──────

/// Full 32-byte node identifier for cluster-wide uniqueness.
pub type NodeId = [u8; 32];

/// Extended node identity with attestation and cluster membership info.
pub struct NodeIdentity {
    pub id: NodeId,
    pub signing_key: [u8; 32],
    /// Ed25519 verifying (public) key bytes for this node.
    pub verifying_key: [u8; 32],
    pub attestation_hash: [u8; 32],
    pub is_attested: bool,
    pub cluster_id: u32,
    pub last_heartbeat_tick: u64,
}

static mut LOCAL_NODE: Option<NodeIdentity> = None;

/// Initialise the extended node identity.
///
/// Derives a 32-byte `NodeId` by combining the legacy 32-bit node ID with
/// the TSC timestamp for additional uniqueness. Should be called once
/// during early boot, after the NIC is available (so `node_id()` works).
pub fn init_node_identity() {
    let legacy = node_id();
    let mut id = [0u8; 32];
    // First 4 bytes: legacy 32-bit node ID for backward compat.
    id[0..4].copy_from_slice(&legacy.to_le_bytes());
    // Bytes 4..12: TSC for uniqueness across reboots.
    unsafe {
        let lo: u32;
        let hi: u32;
        core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi);
        let tsc = (hi as u64) << 32 | lo as u64;
        id[4..12].copy_from_slice(&tsc.to_le_bytes());
    }
    // Generate a real Ed25519 keypair for this node.
    let (sk, vk) = crate::crypto::generate_keypair();
    let sk_bytes = sk.to_bytes();
    let vk_bytes = vk.to_bytes();
    unsafe {
        LOCAL_NODE = Some(NodeIdentity {
            id,
            signing_key: sk_bytes,
            verifying_key: vk_bytes,
            attestation_hash: [0; 32],
            is_attested: false,
            cluster_id: 0,
            last_heartbeat_tick: 0,
        });
    }
    crate::serial_println!("[NODE] Extended identity initialised (cluster_id=0, vk={:02x}{:02x}..)",
        vk_bytes[0], vk_bytes[1]);
}

/// Return the full 32-byte `NodeId`, or all-zeros if not yet initialised.
pub fn get_node_id() -> NodeId {
    unsafe { LOCAL_NODE.as_ref().map(|n| n.id).unwrap_or([0; 32]) }
}

/// Return a reference to the local `NodeIdentity`, if initialised.
pub fn get_node_identity() -> Option<&'static NodeIdentity> {
    unsafe { LOCAL_NODE.as_ref() }
}

/// Return the attestation hash, or all-zeros if not attested.
pub fn get_attestation_hash() -> [u8; 32] {
    unsafe {
        LOCAL_NODE
            .as_ref()
            .map(|n| n.attestation_hash)
            .unwrap_or([0; 32])
    }
}

/// Record a heartbeat at the given tick.
pub fn record_heartbeat(tick: u64) {
    unsafe {
        if let Some(ref mut node) = LOCAL_NODE {
            node.last_heartbeat_tick = tick;
        }
    }
}
