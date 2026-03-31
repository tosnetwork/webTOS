//! ATOS Policy Bundle (Yellow Paper Stage 5 — Trusted Authority Plane)
//!
//! Defines fixed-size policy bundles for `no_std` environments. A policy
//! bundle groups up to 16 rules that govern capability access decisions.

type Hash256 = [u8; 32];

/// Maximum number of rules per policy bundle (fixed-size for no_std).
pub const MAX_POLICY_RULES: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PolicyRuleKind {
    Allow,
    Deny,
    RequireAttestation,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PolicyAction {
    Permit,
    Block,
    Audit,
}

#[derive(Debug, Clone, Copy)]
pub struct PolicyRule {
    pub kind: PolicyRuleKind,
    pub target_capability: u32, // capability bitmask
    pub action: PolicyAction,
}

impl PolicyRule {
    /// Create a zeroed/default rule (Allow + Permit, target 0).
    pub const fn empty() -> Self {
        PolicyRule {
            kind: PolicyRuleKind::Allow,
            target_capability: 0,
            action: PolicyAction::Permit,
        }
    }
}

pub struct PolicyBundle {
    pub version: u32,
    pub rules: [PolicyRule; MAX_POLICY_RULES],
    pub rule_count: u8,
    pub manifest_hash: Hash256,
}

impl PolicyBundle {
    /// Create an empty policy bundle with the given version.
    pub fn new(version: u32) -> Self {
        PolicyBundle {
            version,
            rules: [PolicyRule::empty(); MAX_POLICY_RULES],
            rule_count: 0,
            manifest_hash: [0u8; 32],
        }
    }

    /// Add a rule to the bundle. Returns `false` if the bundle is full.
    pub fn add_rule(&mut self, rule: PolicyRule) -> bool {
        if (self.rule_count as usize) >= MAX_POLICY_RULES {
            return false;
        }
        self.rules[self.rule_count as usize] = rule;
        self.rule_count += 1;
        true
    }

    /// Evaluate the policy bundle against a capability bitmask.
    /// Returns the action for the first matching rule, or `PolicyAction::Permit`
    /// if no rule matches.
    pub fn evaluate(&self, capability_mask: u32) -> PolicyAction {
        for i in 0..self.rule_count as usize {
            let rule = &self.rules[i];
            if rule.target_capability & capability_mask != 0 {
                return rule.action;
            }
        }
        PolicyAction::Permit
    }
}
