//! Deterministic Linux Syscall Compatibility Layer
//! Translates Linux x86_64 syscalls to ATOS deterministic primitives.

pub mod constants;
pub mod dispatch;
pub mod epoll;
pub mod fs;
pub mod identity;
pub mod memory;
pub mod network;
pub mod process;
pub mod signal;
pub mod state;
pub mod time;
pub mod vfs;
