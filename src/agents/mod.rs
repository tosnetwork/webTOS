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
pub mod authd;
pub mod upgraded;
pub mod admind;
pub mod observabilityd;
pub mod pkgd;
pub mod membership_d;
pub mod compactd;
pub mod placement_d;
pub mod failover_d;
pub mod auditd;
pub mod quotad;
pub mod verifierd;
pub mod billingd;
