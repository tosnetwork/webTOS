#![no_std]
//! AOS Agent SDK
//!
//! Safe Rust wrappers for AOS syscalls. Import this crate to build
//! native agents that run on AOS.
//!
//! # Example
//! ```rust,no_run
//! #![no_std]
//! #![no_main]
//! use aos_sdk::prelude::*;
//!
//! #[no_mangle]
//! pub extern "C" fn agent_main() -> ! {
//!     let msg = b"hello from agent";
//!     mailbox::send(1, msg).unwrap();
//!     loop { aos_yield(); }
//! }
//! ```

pub mod syscall;
pub mod mailbox;
pub mod state;
pub mod capability;
pub mod energy;
pub mod event;
pub mod agent;

/// Error type for AOS syscall results
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AosError {
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

impl AosError {
    pub fn from_code(code: i64) -> Self {
        match code {
            -1 => AosError::NoCapability,
            -2 => AosError::InvalidArg,
            -3 => AosError::NotFound,
            -4 => AosError::QuotaExceeded,
            -5 => AosError::PayloadTooLarge,
            -6 => AosError::MailboxFull,
            -7 => AosError::NoBudget,
            -8 => AosError::Timeout,
            other => AosError::Unknown(other),
        }
    }
}

pub type AosResult<T> = Result<T, AosError>;

fn check(ret: i64) -> AosResult<i64> {
    if ret < 0 { Err(AosError::from_code(ret)) } else { Ok(ret) }
}

/// Yield the current timeslice.
pub fn aos_yield() {
    unsafe { syscall::syscall(syscall::SYS_YIELD, 0, 0, 0, 0, 0); }
}

/// Terminate this agent.
pub fn aos_exit(code: u64) -> ! {
    unsafe { syscall::syscall(syscall::SYS_EXIT, code, 0, 0, 0, 0); }
    loop {} // unreachable
}

/// Prelude — import everything commonly needed
pub mod prelude {
    pub use crate::{aos_yield, aos_exit, AosError, AosResult};
    pub use crate::mailbox;
    pub use crate::state;
    pub use crate::capability;
    pub use crate::energy;
    pub use crate::event;
    pub use crate::agent;
}
