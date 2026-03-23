//! Agent lifecycle management

use crate::syscall::*;
use crate::{AosResult, check};

/// Spawn a new child agent.
/// Returns the new agent's ID.
pub fn spawn(entry: u64, energy: u64, mem_quota_pages: u64) -> AosResult<u16> {
    let ret = unsafe { syscall(SYS_SPAWN, entry, energy, mem_quota_pages, 0, 0) };
    check(ret).map(|id| id as u16)
}

/// Allocate memory pages. Returns the virtual address.
pub fn mmap(num_pages: u64) -> AosResult<u64> {
    let ret = unsafe { syscall(SYS_MMAP, num_pages, 0, 0, 0, 0) };
    check(ret).map(|addr| addr as u64)
}

/// Deallocate memory pages.
pub fn munmap(vaddr: u64, num_pages: u64) -> AosResult<()> {
    let ret = unsafe { syscall(SYS_MUNMAP, vaddr, num_pages, 0, 0, 0) };
    check(ret).map(|_| ())
}

/// Trigger a system checkpoint (root agent only).
pub fn checkpoint() -> AosResult<()> {
    let ret = unsafe { syscall(SYS_CHECKPOINT, 0, 0, 0, 0, 0) };
    check(ret).map(|_| ())
}

/// Enter replay mode (root agent only).
pub fn replay() -> AosResult<()> {
    let ret = unsafe { syscall(SYS_REPLAY, 0, 0, 0, 0, 0) };
    check(ret).map(|_| ())
}
