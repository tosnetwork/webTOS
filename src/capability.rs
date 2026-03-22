//! AOS Capability Model
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
}

// ─── Capability struct ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Capability {
    pub cap_type: CapType,
    pub target: u16,    // target resource id, or CAP_TARGET_WILDCARD
    pub flags: u16,
    pub use_limit: u32, // 0 = unlimited
    pub use_count: u32,
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

    caps
}

/// Return the number of root capabilities (for setting cap_count).
pub const ROOT_CAP_COUNT: usize = 6;
