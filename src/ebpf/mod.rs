//! eBPF-lite Policy Runtime
//!
//! A restricted bytecode runtime for policy enforcement, event filtering,
//! and validation rules. Runs inside the kernel (Yellow Paper §24.3.2).

pub mod attach;
pub mod maps;
pub mod runtime;
pub mod types;
pub mod verifier;
