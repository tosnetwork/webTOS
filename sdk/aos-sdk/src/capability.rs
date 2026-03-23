//! Capability query, grant, and revoke

use crate::syscall::*;
use crate::{AosResult, check};

#[repr(u64)]
#[derive(Debug, Clone, Copy)]
pub enum CapType {
    SendMailbox = 0,
    RecvMailbox = 1,
    EventEmit = 2,
    AgentSpawn = 3,
    StateRead = 4,
    StateWrite = 5,
    Network = 6,
}

/// Check if this agent has a specific capability.
pub fn has(cap_type: CapType, target: u16) -> bool {
    let ret = unsafe { syscall(SYS_CAP_QUERY, cap_type as u64, target as u64, 0, 0, 0) };
    ret == 1
}

/// Grant a capability to another agent.
pub fn grant(target_agent: u16, cap_type: CapType, cap_target: u16) -> AosResult<()> {
    let ret = unsafe {
        syscall(SYS_CAP_GRANT, target_agent as u64, cap_type as u64, cap_target as u64, 0, 0)
    };
    check(ret).map(|_| ())
}

/// Revoke a capability from another agent.
pub fn revoke(target_agent: u16, cap_type: CapType, cap_target: u16) -> AosResult<()> {
    let ret = unsafe {
        syscall(SYS_CAP_REVOKE, target_agent as u64, cap_type as u64, cap_target as u64, 0, 0)
    };
    check(ret).map(|_| ())
}
