#![no_std]
//! ATOS Agent SDK
//!
//! Safe Rust wrappers for ATOS syscalls. Import this crate to build
//! native agents that run on ATOS.
//!
//! # Example
//! ```rust,no_run
//! #![no_std]
//! #![no_main]
//! use atos_sdk::prelude::*;
//!
//! #[no_mangle]
//! pub extern "C" fn agent_main() -> ! {
//!     let msg = b"hello from agent";
//!     mailbox::send(1, msg).unwrap();
//!     loop { atos_yield(); }
//! }
//! ```

pub mod syscall;
pub mod mailbox;
pub mod state;
pub mod capability;
pub mod energy;
pub mod event;
pub mod agent;

/// Error type for ATOS syscall results
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtosError {
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

impl AtosError {
    pub fn from_code(code: i64) -> Self {
        match code {
            -1 => AtosError::NoCapability,
            -2 => AtosError::InvalidArg,
            -3 => AtosError::NotFound,
            -4 => AtosError::QuotaExceeded,
            -5 => AtosError::PayloadTooLarge,
            -6 => AtosError::MailboxFull,
            -7 => AtosError::NoBudget,
            -8 => AtosError::Timeout,
            other => AtosError::Unknown(other),
        }
    }
}

pub type AtosResult<T> = Result<T, AtosError>;

fn check(ret: i64) -> AtosResult<i64> {
    if ret < 0 { Err(AtosError::from_code(ret)) } else { Ok(ret) }
}

/// Yield the current timeslice.
pub fn atos_yield() {
    unsafe { syscall::syscall(syscall::SYS_YIELD, 0, 0, 0, 0, 0); }
}

/// Terminate this agent.
pub fn atos_exit(code: u64) -> ! {
    unsafe { syscall::syscall(syscall::SYS_EXIT, code, 0, 0, 0, 0); }
    loop {} // unreachable
}

/// Prelude — import everything commonly needed
pub mod prelude {
    pub use crate::{atos_yield, atos_exit, AtosError, AtosResult};
    pub use crate::mailbox;
    pub use crate::state;
    pub use crate::capability;
    pub use crate::energy;
    pub use crate::event;
    pub use crate::agent;
}
