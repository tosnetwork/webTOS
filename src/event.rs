//! AOS Event Log / Audit Subsystem
//!
//! Emits structured audit events over serial output. Every significant
//! kernel action produces an event with a monotonic sequence number.
//!
//! In Stage-1, events are printed to the serial console in a parseable format.
//! Later stages will write to a structured ring buffer for programmatic
//! consumption and checkpoint/replay support.

use crate::serial_println;
use crate::agent::AgentId;

// ─── Event types ────────────────────────────────────────────────────────────

/// Enumeration of all kernel audit event types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum EventType {
    SystemBoot = 0,
    AgentCreated = 1,
    AgentExited = 2,
    AgentFaulted = 3,
    MailboxSend = 4,
    MailboxRecv = 5,
    CapGrant = 6,
    CapDenied = 7,
    BudgetExhausted = 8,
    BudgetReplenished = 9,
    Fault = 10,
    SyscallFailed = 11,
    AgentSuspended = 12,
    /// Aliases used by syscall.rs for compatibility
    SyscallFailure = 13,
    CapabilityDenied = 14,
    CapabilityGranted = 15,
    Custom = 16,
}

impl EventType {
    /// Return a static string label for the event type.
    pub fn as_str(self) -> &'static str {
        match self {
            EventType::SystemBoot => "SYSTEM_BOOT",
            EventType::AgentCreated => "AGENT_CREATED",
            EventType::AgentExited => "AGENT_EXITED",
            EventType::AgentFaulted => "AGENT_FAULTED",
            EventType::MailboxSend => "MAILBOX_SEND",
            EventType::MailboxRecv => "MAILBOX_RECV",
            EventType::CapGrant => "CAP_GRANT",
            EventType::CapDenied => "CAP_DENIED",
            EventType::BudgetExhausted => "BUDGET_EXHAUSTED",
            EventType::BudgetReplenished => "BUDGET_REPLENISHED",
            EventType::Fault => "FAULT",
            EventType::SyscallFailed => "SYSCALL_FAILED",
            EventType::AgentSuspended => "AGENT_SUSPENDED",
            EventType::SyscallFailure => "SYSCALL_FAILURE",
            EventType::CapabilityDenied => "CAPABILITY_DENIED",
            EventType::CapabilityGranted => "CAPABILITY_GRANTED",
            EventType::Custom => "CUSTOM",
        }
    }
}

// ─── Event struct ───────────────────────────────────────────────────────────

/// Structured audit event record.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Event {
    pub sequence: u64,
    pub tick: u64,
    pub agent_id: AgentId,
    pub event_type: EventType,
    pub arg0: u64,
    pub arg1: u64,
    pub status: i64,
}

// ─── Global sequence counter ────────────────────────────────────────────────

// Safety: single-core, no preemption during event emission in Stage-1.
static mut EVENT_SEQUENCE: u64 = 0;

// ─── Core emit function ─────────────────────────────────────────────────────

/// Emit a structured audit event.
///
/// Increments the global sequence counter, captures the current tick,
/// and outputs a parseable log line over serial.
pub fn emit(agent_id: AgentId, event_type: EventType, arg0: u64, arg1: u64, status: i64) {
    // Safety: single-core, no preemption during event emission
    unsafe {
        let seq = EVENT_SEQUENCE;
        EVENT_SEQUENCE += 1;

        let t = crate::arch::x86_64::timer::get_ticks();

        serial_println!(
            "[EVENT seq={} tick={} agent={} type={} arg0={} arg1={} status={}]",
            seq, t, agent_id, event_type.as_str(), arg0, arg1, status
        );
    }
}

// ─── Timer tick ─────────────────────────────────────────────────────────────

/// Advance the kernel tick counter.
///
/// Called from the timer interrupt handler.
pub fn tick() {
    crate::arch::x86_64::timer::tick();
}

// ─── Convenience functions ──────────────────────────────────────────────────

/// Emit a system boot event.
pub fn boot() {
    emit(0, EventType::SystemBoot, 0, 0, 0);
}

/// Emit an agent creation event.
pub fn agent_created(agent_id: AgentId, parent_id: AgentId) {
    emit(agent_id, EventType::AgentCreated, parent_id as u64, 0, 0);
}

/// Emit an agent exit event.
pub fn agent_exited(agent_id: AgentId, status_code: u64) {
    emit(agent_id, EventType::AgentExited, status_code, 0, 0);
}

/// Emit an agent fault event.
pub fn agent_faulted(agent_id: AgentId, fault_code: u64) {
    emit(agent_id, EventType::AgentFaulted, fault_code, 0, 0);
}

/// Emit a mailbox send event.
pub fn mailbox_send(sender_id: AgentId, target_mailbox: u16, payload_len: u64) {
    emit(sender_id, EventType::MailboxSend, target_mailbox as u64, payload_len, 0);
}

/// Emit a mailbox receive event.
pub fn mailbox_recv(agent_id: AgentId, mailbox_id: u16, msg_len: u64) {
    emit(agent_id, EventType::MailboxRecv, mailbox_id as u64, msg_len, 0);
}

/// Emit a capability grant event.
pub fn cap_grant(agent_id: AgentId, target_agent: u64, cap_type: u64) {
    emit(agent_id, EventType::CapGrant, target_agent, cap_type, 0);
}

/// Emit a capability denial event.
pub fn cap_denied(agent_id: AgentId, cap_type: u64, target: u64) {
    emit(agent_id, EventType::CapDenied, cap_type, target, -1);
}

/// Emit a budget exhaustion event.
pub fn budget_exhausted(agent_id: AgentId, remaining: u64) {
    emit(agent_id, EventType::BudgetExhausted, remaining, 0, 0);
}

/// Emit an energy-exhausted event (alias for budget_exhausted).
pub fn energy_exhausted(agent_id: AgentId) {
    emit(agent_id, EventType::BudgetExhausted, 0, 0, 0);
}

/// Emit a budget replenishment event.
pub fn budget_replenished(agent_id: AgentId, amount: u64) {
    emit(agent_id, EventType::BudgetReplenished, amount, 0, 0);
}

/// Emit a fault event (hardware exception, protection violation, etc.).
pub fn fault(agent_id: AgentId, fault_vector: u64, error_code: u64) {
    emit(agent_id, EventType::Fault, fault_vector, error_code, -1);
}

/// Emit a syscall failure event.
pub fn syscall_failed(agent_id: AgentId, syscall_nr: u64, error: i64) {
    emit(agent_id, EventType::SyscallFailed, syscall_nr, 0, error);
}

/// Emit an agent suspended event.
pub fn agent_suspended(agent_id: AgentId, reason: u64) {
    emit(agent_id, EventType::AgentSuspended, reason, 0, 0);
}
