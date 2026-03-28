//! ATOS Capability Model
//!
//! Implements the capability-based authority system. No meaningful action
//! succeeds unless the caller holds an appropriate capability.
//! Capabilities support grant (subset only), use-counting, and wildcard targets.

use crate::agent::{
    AgentId, CAP_TARGET_WILDCARD,
    MAX_CAPABILITIES_PER_AGENT, E_NO_CAP, E_QUOTA_EXCEEDED, E_INVALID_ARG, E_NOT_FOUND,
};
use crate::principal::PrincipalId;
use crate::crypto;

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
    SendRemote = 8,
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
    // ── Stage 5: Trusted Authority Plane lease fields ────────────────────
    /// Principal that issued this capability.
    pub issuer_id: PrincipalId,
    /// Principal this capability is granted to.
    pub subject_id: PrincipalId,
    /// Tick at which this capability expires (0 = no expiry).
    pub expiry_ticks: u64,
    /// Unique nonce for replay protection.
    pub nonce: u64,
    /// Maximum delegation chain length (0 = cannot delegate further).
    pub delegation_depth: u8,
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
            issuer_id: [0u8; 32],
            subject_id: [0u8; 32],
            expiry_ticks: 0,
            nonce: 0,
            delegation_depth: 0,
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
            issuer_id: [0u8; 32],
            subject_id: [0u8; 32],
            expiry_ticks: 0,
            nonce: 0,
            delegation_depth: 0,
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

    // ── Stage 5: Lease / delegation methods ─────────────────────────────

    /// Check if this capability's lease has expired.
    ///
    /// A capability with `expiry_ticks == 0` never expires.
    pub fn is_expired(&self, current_tick: u64) -> bool {
        self.expiry_ticks > 0 && current_tick > self.expiry_ticks
    }

    /// Check if this capability can be delegated further.
    pub fn can_delegate(&self) -> bool {
        self.delegation_depth > 0
    }

    /// Create a delegated copy of this capability for `new_subject`.
    ///
    /// Returns `None` if delegation depth is exhausted.
    pub fn delegated(&self, new_subject: PrincipalId) -> Option<Capability> {
        if self.delegation_depth == 0 {
            return None;
        }
        let mut new = *self;
        new.issuer_id = self.subject_id;
        new.subject_id = new_subject;
        new.delegation_depth -= 1;
        Some(new)
    }
}

// ─── Agent capability queries ───────────────────────────────────────────────

/// Return a copy of the agent's capability array for hashing / inspection.
pub fn agent_capabilities(agent_id: AgentId) -> [Option<Capability>; MAX_CAPABILITIES_PER_AGENT] {
    match crate::agent::get_agent(agent_id) {
        Some(a) => a.capabilities,
        None => [const { None }; MAX_CAPABILITIES_PER_AGENT],
    }
}

/// Check if an agent holds a capability matching the given type and target.
///
/// Does not consume a use. For checking without exercising.
/// Enforces lease expiry: if the matching capability has expired, the check
/// emits an `AuthLeaseExpired` event and returns `false`.
pub fn agent_has_cap(agent_id: AgentId, cap_type: CapType, target: u16) -> bool {
    let agent = match crate::agent::get_agent(agent_id) {
        Some(a) => a,
        None => return false,
    };

    let current_tick = crate::arch::x86_64::timer::get_ticks();

    for i in 0..agent.cap_count {
        if let Some(ref cap) = agent.capabilities[i] {
            if cap.matches(cap_type, target) {
                if cap.is_expired(current_tick) {
                    crate::event::auth_lease_expired(agent_id, i as u64, cap.expiry_ticks);
                    return false;
                }
                return true;
            }
        }
    }
    false
}

/// Try to exercise a capability: checks the agent holds it and decrements use_count.
///
/// Returns `true` if the capability was found and successfully used.
/// Enforces lease expiry: if the matching capability has expired, the attempt
/// emits an `AuthLeaseExpired` event and returns `false`.
pub fn agent_try_cap(agent_id: AgentId, cap_type: CapType, target: u16) -> bool {
    let agent = match crate::agent::get_agent_mut(agent_id) {
        Some(a) => a,
        None => return false,
    };

    let current_tick = crate::arch::x86_64::timer::get_ticks();

    for i in 0..agent.cap_count {
        if let Some(ref mut cap) = agent.capabilities[i] {
            if cap.matches(cap_type, target) {
                if cap.is_expired(current_tick) {
                    crate::event::auth_lease_expired(agent_id, i as u64, cap.expiry_ticks);
                    return false;
                }
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

/// Compute a 32-byte Ed25519 signature over a capability's immutable fields.
///
/// Uses the provided `signing_key` to produce a real Ed25519 signature over
/// the serialised capability fields. The first 32 bytes of the 64-byte
/// signature are stored in the capability's `signature` field.
///
/// We deliberately exclude `use_count` and `signature` so that exercising
/// a capability does not invalidate its signature, and to avoid circularity.
pub fn sign_capability(cap: &Capability, signing_key: &crypto::SigningKey) -> [u8; 32] {
    let mut buf = [0u8; 128];
    let len = cap_signable_bytes(cap, &mut buf);
    let sig = crypto::sign(signing_key, &buf[..len]);
    let sig_bytes = sig.to_bytes();
    let mut result = [0u8; 32];
    result.copy_from_slice(&sig_bytes[..32]);
    result
}

/// Serialise capability fields into a buffer for signing/verification.
/// Returns the number of bytes written.
fn cap_signable_bytes(cap: &Capability, buf: &mut [u8; 128]) -> usize {
    let mut pos = 0;
    buf[pos] = cap.cap_type as u8;
    pos += 1;
    buf[pos..pos + 2].copy_from_slice(&cap.target.to_le_bytes());
    pos += 2;
    buf[pos..pos + 2].copy_from_slice(&cap.flags.to_le_bytes());
    pos += 2;
    buf[pos..pos + 4].copy_from_slice(&cap.use_limit.to_le_bytes());
    pos += 4;
    buf[pos..pos + 4].copy_from_slice(&cap.node_id.to_le_bytes());
    pos += 4;
    buf[pos..pos + 32].copy_from_slice(&cap.issuer_id);
    pos += 32;
    buf[pos..pos + 32].copy_from_slice(&cap.subject_id);
    pos += 32;
    buf[pos..pos + 8].copy_from_slice(&cap.expiry_ticks.to_le_bytes());
    pos += 8;
    buf[pos..pos + 8].copy_from_slice(&cap.nonce.to_le_bytes());
    pos += 8;
    buf[pos] = cap.delegation_depth;
    pos += 1;
    pos
}

/// Verify a capability signature produced by `sign_capability`.
///
/// Returns `true` if re-signing with the same key produces a matching signature.
pub fn verify_capability(cap: &Capability, sig: &[u8; 32], signing_key: &crypto::SigningKey) -> bool {
    let expected = sign_capability(cap, signing_key);
    // Constant-time comparison
    let mut diff: u8 = 0;
    for (a, b) in expected.iter().zip(sig.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

/// Alias for `sign_capability` — SDK-facing name.
///
/// Create a 32-byte Ed25519 signature over the capability fields.
#[inline]
pub fn cap_sign(cap: &Capability, signing_key: &crypto::SigningKey) -> [u8; 32] {
    sign_capability(cap, signing_key)
}

/// Alias for `verify_capability` — SDK-facing name.
///
/// Returns `true` if recomputing the signature from `cap` and `signing_key`
/// matches the provided `sig`.
#[inline]
pub fn cap_verify(cap: &Capability, sig: &[u8; 32], signing_key: &crypto::SigningKey) -> bool {
    verify_capability(cap, sig, signing_key)
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
    /// Sign a capability with `signing_key` and bundle the result.
    pub fn new(cap: Capability, signing_key: &crypto::SigningKey) -> Self {
        let signature = cap_sign(&cap, signing_key);
        SignedCapability { cap, signature }
    }

    /// Verify the bundled signature against `signing_key`.
    pub fn verify(&self, signing_key: &crypto::SigningKey) -> bool {
        cap_verify(&self.cap, &self.signature, signing_key)
    }
}

// ─── Lease signing with crypto module ────────────────────────────────────────

/// Serialise a capability's lease-relevant fields into a byte buffer for signing.
///
/// Includes: cap_type, target, flags, use_limit, node_id, issuer_id,
/// subject_id, expiry_ticks, nonce, delegation_depth.
///
/// Returns the number of bytes written.
fn lease_signable_bytes(cap: &Capability, buf: &mut [u8; 128]) -> usize {
    let mut pos = 0;
    buf[pos] = cap.cap_type as u8;
    pos += 1;
    buf[pos..pos + 2].copy_from_slice(&cap.target.to_le_bytes());
    pos += 2;
    buf[pos..pos + 2].copy_from_slice(&cap.flags.to_le_bytes());
    pos += 2;
    buf[pos..pos + 4].copy_from_slice(&cap.use_limit.to_le_bytes());
    pos += 4;
    buf[pos..pos + 4].copy_from_slice(&cap.node_id.to_le_bytes());
    pos += 4;
    buf[pos..pos + 32].copy_from_slice(&cap.issuer_id);
    pos += 32;
    buf[pos..pos + 32].copy_from_slice(&cap.subject_id);
    pos += 32;
    buf[pos..pos + 8].copy_from_slice(&cap.expiry_ticks.to_le_bytes());
    pos += 8;
    buf[pos..pos + 8].copy_from_slice(&cap.nonce.to_le_bytes());
    pos += 8;
    buf[pos] = cap.delegation_depth;
    pos += 1;
    pos
}

/// Sign a capability lease using the crypto module's keyed-hash signing.
///
/// Produces a 64-byte signature over the capability's lease fields.
pub fn sign_lease(cap: &Capability, key: &crypto::SigningKey) -> [u8; 64] {
    let mut buf = [0u8; 128];
    let len = lease_signable_bytes(cap, &mut buf);
    let sig = crypto::sign(key, &buf[..len]);
    sig.to_bytes()
}

/// Verify a capability lease signature using the crypto module.
pub fn verify_lease(cap: &Capability, sig_bytes: &[u8; 64], key: &crypto::VerifyingKey) -> bool {
    let mut buf = [0u8; 128];
    let len = lease_signable_bytes(cap, &mut buf);
    if let Ok(sig) = crypto::Signature::from_slice(sig_bytes) {
        crypto::verify(key, &buf[..len], &sig)
    } else {
        false
    }
}
