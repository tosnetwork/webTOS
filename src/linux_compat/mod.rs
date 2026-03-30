//! Deterministic Linux Syscall Compatibility Layer
//! Translates Linux x86_64 syscalls to ATOS deterministic primitives.

pub mod constants;
pub mod state;
pub mod dispatch;
pub mod memory;
pub mod fs;
pub mod process;
pub mod signal;
pub mod network;
pub mod epoll;
pub mod time;
pub mod identity;
