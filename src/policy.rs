//! ATOS Policy Bundle (Yellow Paper Stage 5 — Trusted Authority Plane)
//!
//! Defines fixed-size policy bundles for `no_std` environments. A policy
//! bundle groups up to 16 rules that govern capability access decisions.

use crate::principal::Hash256;
use crate::crypto;

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
    pub target_capability: u32,  // capability bitmask
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
    /// Cryptographic signature over (version || manifest_hash || rules).
    pub signature: crypto::Signature,
}

impl PolicyBundle {
    /// Create an empty policy bundle with the given version.
    pub fn new(version: u32) -> Self {
        PolicyBundle {
            version,
            rules: [PolicyRule::empty(); MAX_POLICY_RULES],
            rule_count: 0,
            manifest_hash: [0u8; 32],
            signature: [0u8; 64],
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

    /// Serialise the signable fields into a fixed-size buffer.
    ///
    /// Layout: version (4 bytes) || manifest_hash (32 bytes) || rules
    /// (rule_count * 7 bytes: kind(1) + target(4) + action(1) + pad(1)).
    /// Returns the number of valid bytes written.
    fn signable_bytes(&self, buf: &mut [u8; 256]) -> usize {
        let mut pos = 0;
        // version
        buf[pos..pos + 4].copy_from_slice(&self.version.to_le_bytes());
        pos += 4;
        // manifest_hash
        buf[pos..pos + 32].copy_from_slice(&self.manifest_hash);
        pos += 32;
        // rules
        for i in 0..self.rule_count as usize {
            let r = &self.rules[i];
            buf[pos] = r.kind as u8;
            pos += 1;
            buf[pos..pos + 4].copy_from_slice(&r.target_capability.to_le_bytes());
            pos += 4;
            buf[pos] = r.action as u8;
            pos += 1;
        }
        pos
    }

    /// Sign the bundle with a signing key and store the signature.
    pub fn sign_bundle(&mut self, key: &crypto::SigningKey) {
        let mut buf = [0u8; 256];
        let len = self.signable_bytes(&mut buf);
        self.signature = crypto::sign(key, &buf[..len]);
    }

    /// Verify the bundle signature against a verify key.
    pub fn verify_bundle(&self, key: &crypto::VerifyKey) -> bool {
        let mut buf = [0u8; 256];
        let len = self.signable_bytes(&mut buf);
        crypto::verify(key, &buf[..len], &self.signature)
    }
}
