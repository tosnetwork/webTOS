//! ATOS Principal Model (Yellow Paper Stage 5 — Trusted Authority Plane)
//!
//! A principal represents an authenticated identity in the system. Principals
//! are identified by a 256-bit hash and may be issued by other principals,
//! forming a trust chain. Each principal carries a revocation status and
//! organisation binding.

pub type Hash256 = [u8; 32];
pub type PrincipalId = Hash256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationStatus {
    Active,
    Revoked,
    Expired,
}

#[derive(Debug, Clone)]
pub struct Principal {
    pub id: PrincipalId,
    pub issuer: Option<PrincipalId>,
    pub org_id: u32,
    pub is_remote_node: bool,
    pub revocation_status: RevocationStatus,
    pub created_tick: u64,
}

impl Principal {
    pub fn new(id: PrincipalId, issuer: Option<PrincipalId>, org_id: u32) -> Self {
        Self {
            id,
            issuer,
            org_id,
            is_remote_node: false,
            revocation_status: RevocationStatus::Active,
            created_tick: 0,
        }
    }

    pub fn is_active(&self) -> bool {
        self.revocation_status == RevocationStatus::Active
    }
}
