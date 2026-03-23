//! Per-agent key-value state store

use crate::syscall::*;
use crate::{AosResult, check};

/// Read a value from the agent's private keyspace.
/// Returns the number of bytes read.
pub fn get(key: u64, buf: &mut [u8]) -> AosResult<usize> {
    let ret = unsafe {
        syscall(SYS_STATE_GET, key, buf.as_mut_ptr() as u64, buf.len() as u64, 0, 0)
    };
    check(ret).map(|n| n as usize)
}

/// Write a value to the agent's private keyspace.
pub fn put(key: u64, value: &[u8]) -> AosResult<()> {
    let ret = unsafe {
        syscall(SYS_STATE_PUT, key, value.as_ptr() as u64, value.len() as u64, 0, 0)
    };
    check(ret).map(|_| ())
}
