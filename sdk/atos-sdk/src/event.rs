//! Structured audit event emission

use crate::syscall::*;
use crate::{AtosResult, check};

/// Emit a custom audit event with two arguments.
pub fn emit(arg0: u64, arg1: u64) -> AtosResult<()> {
    let ret = unsafe { syscall(SYS_EVENT_EMIT, arg0, arg1, 0, 0, 0) };
    check(ret).map(|_| ())
}
