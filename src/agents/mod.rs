//! ATOS Test Agents
//!
//! Built-in agents compiled directly into the kernel image for Stage-1.
//! These serve as the initial test workload to validate scheduling,
//! mailbox IPC, capability enforcement, and energy accounting.

pub mod root;
pub mod ping;
pub mod pong;
pub mod idle;
pub mod bad;
pub mod stated;
pub mod policyd;
pub mod wasm_agent;
pub mod accountd;
pub mod netd;
pub mod routerd;
pub mod skilld;
