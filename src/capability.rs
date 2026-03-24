//! ATOS Capability Model
//!
//! Implements the capability-based authority system. No meaningful action
//! succeeds unless the caller holds an appropriate capability.
//! Capabilities support grant (subset only), use-counting, and wildcard targets.

use crate::agent::{
    AgentId, CAP_TARGET_WILDCARD,
    MAX_CAPABILITIES_PER_AGENT, E_NO_CAP, E_QUOTA_EXCEEDED, E_INVALID_ARG, E_NOT_FOUND,
};

// ─── Capability types ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CapType {
    SendMailbox = 0,
    RecvMailbox = 1,
    EventEmit = 2,
    AgentSpawn = 3,
    StateRead = 4,
    StateWrite = 5,
    Network = 6,
    PolicyLoad = 7,
}

// ─── Capability struct ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Capability {
    pub cap_type: CapType,
    pub target: u16,        // target resource id, or CAP_TARGET_WILDCARD
    pub flags: u16,
    pub use_limit: u32,     // 0 = unlimited
    pub use_count: u32,
    /// Node that issued this capability (0 = local / unset).
    pub node_id: u32,
    /// Placeholder signature — FNV-1a hash of cap fields concatenated with the
    /// shared secret. A real implementation would use ed25519 here.
    pub signature: [u8; 32],
}

impl Capability {
    /// Create a new unlimited capability.
    pub fn new(cap_type: CapType, target: u16) -> Self {
        Capability {
            cap_type,
            target,
            flags: 0,
            use_limit: 0,
            use_count: 0,
            node_id: 0,
            signature: [0u8; 32],
        }
    }

    /// Create a capability with a use limit.
    pub fn with_limit(cap_type: CapType, target: u16, limit: u32) -> Self {
        Capability {
            cap_type,
            target,
            flags: 0,
            use_limit: limit,
            use_count: 0,
            node_id: 0,
            signature: [0u8; 32],
        }
    }

    /// Check if this capability matches a required type and target.
    ///
    /// A wildcard target matches any required target.
    pub fn matches(&self, required_type: CapType, required_target: u16) -> bool {
        self.cap_type == required_type
            && (self.target == CAP_TARGET_WILDCARD || self.target == required_target)
    }

    /// Try to exercise this capability. Returns `true` if permitted.
    ///
    /// For unlimited capabilities (use_limit == 0), always returns `true`.
    /// For limited capabilities, increments use_count and returns `false`
    /// if the limit has been reached.
    pub fn try_use(&mut self) -> bool {
        if self.use_limit == 0 {
            return true; // unlimited
        }
        if self.use_count >= self.use_limit {
            return false;
        }
        self.use_count += 1;
        true
    }

    /// Check if this capability is a valid narrowing (subset) of a parent capability.
    ///
    /// A capability is a subset if:
    /// - Same type
    /// - Parent has wildcard target, OR same specific target
    pub fn is_subset_of(&self, parent_cap: &Capability) -> bool {
        self.cap_type == parent_cap.cap_type
            && (parent_cap.target == CAP_TARGET_WILDCARD || self.target == parent_cap.target)
    }
}

// ─── Agent capability queries ───────────────────────────────────────────────

/// Check if an agent holds a capability matching the given type and target.
///
/// Does not consume a use. For checking without exercising.
pub fn agent_has_cap(agent_id: AgentId, cap_type: CapType, target: u16) -> bool {
    let agent = match crate::agent::get_agent(agent_id) {
        Some(a) => a,
        None => return false,
    };

    for i in 0..agent.cap_count {
        if let Some(ref cap) = agent.capabilities[i] {
            if cap.matches(cap_type, target) {
                return true;
            }
        }
    }
    false
}

/// Try to exercise a capability: checks the agent holds it and decrements use_count.
///
/// Returns `true` if the capability was found and successfully used.
pub fn agent_try_cap(agent_id: AgentId, cap_type: CapType, target: u16) -> bool {
    let agent = match crate::agent::get_agent_mut(agent_id) {
        Some(a) => a,
        None => return false,
    };

    for i in 0..agent.cap_count {
        if let Some(ref mut cap) = agent.capabilities[i] {
            if cap.matches(cap_type, target) {
                return cap.try_use();
            }
        }
    }
    false
}

/// Grant a capability from one agent to another.
///
/// Validates the subset rule: the granted capability must be a subset of
/// a capability held by the granting agent. The target agent must be a
/// direct child of the granting agent.
pub fn grant_cap(from_id: AgentId, to_id: AgentId, cap: Capability) -> Result<(), i64> {
    // Verify target is a direct child of the granting agent
    if !crate::agent::is_child_of(to_id, from_id) {
        return Err(E_INVALID_ARG);
    }

    // Verify the granting agent holds a parent capability
    let from_agent = match crate::agent::get_agent(from_id) {
        Some(a) => a,
        None => return Err(E_INVALID_ARG),
    };

    let mut has_parent_cap = false;
    for i in 0..from_agent.cap_count {
        if let Some(ref parent_cap) = from_agent.capabilities[i] {
            if cap.is_subset_of(parent_cap) {
                has_parent_cap = true;
                break;
            }
        }
    }

    if !has_parent_cap {
        return Err(E_NO_CAP);
    }

    // Add capability to the target agent
    let to_agent = match crate::agent::get_agent_mut(to_id) {
        Some(a) => a,
        None => return Err(E_INVALID_ARG),
    };

    if to_agent.cap_count >= MAX_CAPABILITIES_PER_AGENT {
        return Err(E_QUOTA_EXCEEDED);
    }

    to_agent.capabilities[to_agent.cap_count] = Some(cap);
    to_agent.cap_count += 1;

    Ok(())
}

/// Revoke a capability from a direct child agent.
///
/// The revoking agent must be the parent of the target agent.
/// Finds and removes the first matching capability from the child's array.
pub fn revoke_cap(from_id: AgentId, to_id: AgentId, cap_type: CapType, cap_target: u16) -> Result<(), i64> {
    // Verify target is a direct child of the revoking agent
    if !crate::agent::is_child_of(to_id, from_id) {
        return Err(E_INVALID_ARG);
    }

    // Find and remove the matching capability from the child
    let to_agent = match crate::agent::get_agent_mut(to_id) {
        Some(a) => a,
        None => return Err(E_INVALID_ARG),
    };

    for i in 0..to_agent.cap_count {
        if let Some(ref cap) = to_agent.capabilities[i] {
            if cap.cap_type == cap_type && cap.target == cap_target {
                // Remove by shifting remaining capabilities down
                let mut j = i;
                while j + 1 < to_agent.cap_count {
                    to_agent.capabilities[j] = to_agent.capabilities[j + 1];
                    j += 1;
                }
                to_agent.capabilities[to_agent.cap_count - 1] = None;
                to_agent.cap_count -= 1;
                return Ok(());
            }
        }
    }

    // No matching capability found
    Err(E_NOT_FOUND)
}

/// Create the full set of wildcard capabilities for the root agent.
///
/// The root agent gets wildcard capabilities for all capability types,
/// enabling it to delegate narrowed capabilities to children.
pub fn create_root_capabilities() -> [Option<Capability>; MAX_CAPABILITIES_PER_AGENT] {
    let mut caps: [Option<Capability>; MAX_CAPABILITIES_PER_AGENT] =
        [const { None }; MAX_CAPABILITIES_PER_AGENT];

    caps[0] = Some(Capability::new(CapType::SendMailbox, CAP_TARGET_WILDCARD));
    caps[1] = Some(Capability::new(CapType::RecvMailbox, CAP_TARGET_WILDCARD));
    caps[2] = Some(Capability::new(CapType::EventEmit, CAP_TARGET_WILDCARD));
    caps[3] = Some(Capability::new(CapType::AgentSpawn, CAP_TARGET_WILDCARD));
    caps[4] = Some(Capability::new(CapType::StateRead, CAP_TARGET_WILDCARD));
    caps[5] = Some(Capability::new(CapType::StateWrite, CAP_TARGET_WILDCARD));
    caps[6] = Some(Capability::new(CapType::Network, CAP_TARGET_WILDCARD));
    // PolicyLoad — root can load eBPF policies
    caps[7] = Some(Capability::new(CapType::PolicyLoad, CAP_TARGET_WILDCARD));

    caps
}

/// Return the number of root capabilities (for setting cap_count).
pub const ROOT_CAP_COUNT: usize = 8;

// ─── Cross-node capability signing ──────────────────────────────────────────

/// Compute a 32-byte signature over a capability and a 32-byte shared secret.
///
/// Algorithm: FNV-1a (64-bit) iterated over the serialised capability fields
/// concatenated with the secret, then expanded to 32 bytes by running four
/// independent FNV-1a streams with different seeds.
///
/// This is **not** cryptographically secure — it is a placeholder until a
/// proper ed25519 implementation is available for the `no_std` kernel.
pub fn sign_capability(cap: &Capability, secret: &[u8; 32]) -> [u8; 32] {
    // Build a flat byte representation of the fields that must be signed.
    // We deliberately exclude `use_count` and `signature` so that exercising
    // a capability does not invalidate its signature, and to avoid circularity.
    let mut buf = [0u8; 4 + 2 + 2 + 4 + 4]; // cap_type(1)+pad(3) + target(2) + flags(2) + use_limit(4) + node_id(4)
    buf[0] = cap.cap_type as u8;
    buf[1..3].copy_from_slice(&cap.target.to_le_bytes());
    buf[3..5].copy_from_slice(&cap.flags.to_le_bytes());
    buf[5..9].copy_from_slice(&cap.use_limit.to_le_bytes());
    buf[9..13].copy_from_slice(&cap.node_id.to_le_bytes());

    let mut sig = [0u8; 32];
    // Four 8-byte lanes, each starting from a different FNV offset basis.
    const FNV_PRIME: u64 = 0x0000_0100_0000_01B3;
    const SEEDS: [u64; 4] = [
        0xcbf2_9ce4_8422_2325, // standard FNV-1a offset basis
        0x0000_dead_beef_0001,
        0x0000_cafe_babe_0002,
        0xffff_0000_1234_5678,
    ];

    for (lane, &seed) in SEEDS.iter().enumerate() {
        let mut h: u64 = seed;
        for &b in buf.iter().chain(secret.iter()) {
            h ^= b as u64;
            h = h.wrapping_mul(FNV_PRIME);
        }
        let bytes = h.to_le_bytes();
        sig[lane * 8..(lane + 1) * 8].copy_from_slice(&bytes);
    }

    sig
}

/// Verify a capability signature produced by `sign_capability`.
///
/// Returns `true` if the computed signature matches `sig`.
pub fn verify_capability(cap: &Capability, sig: &[u8; 32], secret: &[u8; 32]) -> bool {
    let expected = sign_capability(cap, secret);
    // Constant-time comparison (avoids timing oracle; good enough for a
    // placeholder — a real implementation would use a proper CT library).
    let mut diff: u8 = 0;
    for (a, b) in expected.iter().zip(sig.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

/// Alias for `sign_capability` — SDK-facing name.
///
/// Create a 32-byte signature over the capability fields using a keyed
/// FNV-1a hash: hash(secret || cap_type || target || node_id).
#[inline]
pub fn cap_sign(cap: &Capability, secret: &[u8; 32]) -> [u8; 32] {
    sign_capability(cap, secret)
}

/// Alias for `verify_capability` — SDK-facing name.
///
/// Returns `true` if recomputing the signature from `cap` and `secret`
/// matches the provided `sig`.
#[inline]
pub fn cap_verify(cap: &Capability, sig: &[u8; 32], secret: &[u8; 32]) -> bool {
    verify_capability(cap, sig, secret)
}

/// A capability bundled with its cryptographic signature.
///
/// Wraps a `Capability` together with the pre-computed signature so that
/// it can be passed across trust boundaries and re-verified on arrival.
#[derive(Debug, Clone, Copy)]
pub struct SignedCapability {
    pub cap: Capability,
    pub signature: [u8; 32],
}

impl SignedCapability {
    /// Sign a capability with `secret` and bundle the result.
    pub fn new(cap: Capability, secret: &[u8; 32]) -> Self {
        let signature = cap_sign(&cap, secret);
        SignedCapability { cap, signature }
    }

    /// Verify the bundled signature against `secret`.
    pub fn verify(&self, secret: &[u8; 32]) -> bool {
        cap_verify(&self.cap, &self.signature, secret)
    }
}
