//! Energy budget management

use crate::syscall::*;
use crate::{AosResult, check};

/// Get remaining energy budget.
pub fn remaining() -> u64 {
    let ret = unsafe { syscall(SYS_ENERGY_GET, 0, 0, 0, 0, 0) };
    ret as u64
}

/// Grant energy to a child agent.
pub fn grant(target_agent: u16, amount: u64) -> AosResult<()> {
    let ret = unsafe { syscall(SYS_ENERGY_GRANT, target_agent as u64, amount, 0, 0, 0) };
    check(ret).map(|_| ())
}
