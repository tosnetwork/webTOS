//! Mailbox IPC — send and receive messages

use crate::syscall::*;
use crate::{AtosResult, check};

/// Send a message to a target mailbox (non-blocking).
pub fn send(target_mailbox: u16, payload: &[u8]) -> AtosResult<()> {
    let ret = unsafe {
        syscall(SYS_SEND, target_mailbox as u64, payload.as_ptr() as u64, payload.len() as u64, 0, 0)
    };
    check(ret).map(|_| ())
}

/// Send a message, blocking if the mailbox is full.
pub fn send_blocking(target_mailbox: u16, payload: &[u8]) -> AtosResult<()> {
    let ret = unsafe {
        syscall(SYS_SEND_BLOCKING, target_mailbox as u64, payload.as_ptr() as u64, payload.len() as u64, 0, 0)
    };
    check(ret).map(|_| ())
}

/// Receive a message from this agent's mailbox (blocking).
/// Returns the number of bytes received.
pub fn recv(mailbox_id: u16, buf: &mut [u8]) -> AtosResult<usize> {
    let ret = unsafe {
        syscall(SYS_RECV, mailbox_id as u64, buf.as_mut_ptr() as u64, buf.len() as u64, 0, 0)
    };
    check(ret).map(|n| n as usize)
}

/// Receive a message (non-blocking). Returns 0 if no message available.
pub fn recv_nonblocking(mailbox_id: u16, buf: &mut [u8]) -> AtosResult<usize> {
    let ret = unsafe {
        syscall(SYS_RECV_NONBLOCKING, mailbox_id as u64, buf.as_mut_ptr() as u64, buf.len() as u64, 0, 0)
    };
    check(ret).map(|n| n as usize)
}

/// Receive with timeout (in ticks). Returns Err(Timeout) on expiry.
pub fn recv_timeout(mailbox_id: u16, buf: &mut [u8], timeout_ticks: u64) -> AtosResult<usize> {
    let ret = unsafe {
        syscall(SYS_RECV_TIMEOUT, mailbox_id as u64, buf.as_mut_ptr() as u64, buf.len() as u64, timeout_ticks, 0)
    };
    check(ret).map(|n| n as usize)
}

/// Create an additional mailbox. Returns the new mailbox ID.
pub fn create() -> AtosResult<u16> {
    let ret = unsafe { syscall(SYS_MAILBOX_CREATE, 0, 0, 0, 0, 0) };
    check(ret).map(|id| id as u16)
}

/// Destroy a mailbox (not the agent's primary mailbox).
pub fn destroy(mailbox_id: u16) -> AtosResult<()> {
    let ret = unsafe { syscall(SYS_MAILBOX_DESTROY, mailbox_id as u64, 0, 0, 0, 0) };
    check(ret).map(|_| ())
}
