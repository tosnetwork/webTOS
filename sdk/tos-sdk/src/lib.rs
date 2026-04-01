#![no_std]
//! TOS Agent SDK
//!
//! Safe Rust wrappers for TOS syscalls. Import this crate to build
//! native agents that run on TOS.
//!
//! # Example
//! ```rust,no_run
//! #![no_std]
//! #![no_main]
//! use tos_sdk::prelude::*;
//!
//! #[no_mangle]
//! pub extern "C" fn agent_main() -> ! {
//!     let msg = b"hello from agent";
//!     mailbox::send(1, msg).unwrap();
//!     loop { tos_yield(); }
//! }
//! ```

pub mod syscall;
pub mod mailbox;
pub mod state;
pub mod capability;
pub mod energy;
pub mod event;
pub mod agent;

/// Error type for TOS syscall results
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TosError {
    NoCapability,
    InvalidArg,
    NotFound,
    QuotaExceeded,
    PayloadTooLarge,
    MailboxFull,
    NoBudget,
    Timeout,
    Unknown(i64),
}

impl TosError {
    pub fn from_code(code: i64) -> Self {
        match code {
            -1 => TosError::NoCapability,
            -2 => TosError::InvalidArg,
            -3 => TosError::NotFound,
            -4 => TosError::QuotaExceeded,
            -5 => TosError::PayloadTooLarge,
            -6 => TosError::MailboxFull,
            -7 => TosError::NoBudget,
            -8 => TosError::Timeout,
            other => TosError::Unknown(other),
        }
    }
}

pub type TosResult<T> = Result<T, TosError>;

fn check(ret: i64) -> TosResult<i64> {
    if ret < 0 { Err(TosError::from_code(ret)) } else { Ok(ret) }
}

/// Yield the current timeslice.
pub fn tos_yield() {
    unsafe { syscall::syscall(syscall::SYS_YIELD, 0, 0, 0, 0, 0); }
}

/// Terminate this agent.
pub fn tos_exit(code: u64) -> ! {
    unsafe { syscall::syscall(syscall::SYS_EXIT, code, 0, 0, 0, 0); }
    loop {} // unreachable
}

/// Prelude — import everything commonly needed
pub mod prelude {
    pub use crate::{tos_exit, tos_yield, TosError, TosResult};
    pub use crate::mailbox;
    pub use crate::state;
    pub use crate::capability;
    pub use crate::energy;
    pub use crate::event;
    pub use crate::agent;
}
