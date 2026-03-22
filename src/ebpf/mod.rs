//! eBPF-lite Policy Runtime
//!
//! A restricted bytecode runtime for policy enforcement, event filtering,
//! and validation rules. Runs inside the kernel (Yellow Paper §24.3.2).

pub mod types;
pub mod verifier;
pub mod runtime;
pub mod maps;
pub mod attach;
