#![no_std]
//! AOS WASM Agent SDK
//!
//! Write WASM agents for AOS in Rust. This crate provides safe wrappers
//! around the AOS WASM host functions.
//!
//! # Example
//! ```rust,ignore
//! #![no_std]
//! use aos_wasm_sdk::*;
//!
//! #[no_mangle]
//! pub extern "C" fn run() {
//!     log_str("Hello from WASM agent!");
//!     let msg = b"ping";
//!     send(3, msg);
//!     loop { aos_yield(); }
//! }
//! ```

use core::panic::PanicInfo;

// ─── Host function imports (provided by AOS WASM runtime) ───────────

#[link(wasm_import_module = "aos")]
extern "C" {
    #[link_name = "sys_yield"]
    fn host_sys_yield() -> i32;

    #[link_name = "sys_send"]
    fn host_sys_send(mailbox_id: i32, ptr: i32, len: i32) -> i32;

    #[link_name = "sys_recv"]
    fn host_sys_recv(mailbox_id: i32, ptr: i32, capacity: i32) -> i32;

    #[link_name = "sys_exit"]
    fn host_sys_exit(code: i32);

    #[link_name = "sys_energy_get"]
    fn host_sys_energy_get() -> i64;

    #[link_name = "log"]
    fn host_log(ptr: i32, len: i32);
}

// ─── Safe wrappers ──────────────────────────────────────────────────

/// Yield the current timeslice to let other agents run.
pub fn aos_yield() -> i32 {
    unsafe { host_sys_yield() }
}

/// Send a message to a target mailbox.
/// Returns 0 on success, negative on error.
pub fn send(mailbox_id: u16, payload: &[u8]) -> i32 {
    unsafe { host_sys_send(mailbox_id as i32, payload.as_ptr() as i32, payload.len() as i32) }
}

/// Receive a message into a buffer.
/// Returns bytes received, or 0 if no message available.
pub fn recv(mailbox_id: u16, buf: &mut [u8]) -> i32 {
    unsafe { host_sys_recv(mailbox_id as i32, buf.as_mut_ptr() as i32, buf.len() as i32) }
}

/// Exit this agent with the given code.
pub fn exit(code: i32) -> ! {
    unsafe { host_sys_exit(code); }
    loop {} // unreachable
}

/// Get remaining energy/fuel.
pub fn energy_remaining() -> i64 {
    unsafe { host_sys_energy_get() }
}

/// Log a string to AOS serial output.
pub fn log_str(s: &str) {
    unsafe { host_log(s.as_ptr() as i32, s.len() as i32); }
}

/// Log raw bytes to serial output.
pub fn log_bytes(b: &[u8]) {
    unsafe { host_log(b.as_ptr() as i32, b.len() as i32); }
}

// ─── Panic handler (required for #![no_std]) ────────────────────────

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    exit(255)
}
