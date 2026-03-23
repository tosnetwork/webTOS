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
