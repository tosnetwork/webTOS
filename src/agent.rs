//! ATOS Agent Model
//!
//! Defines the Agent struct, agent table, and lifecycle management.
//! An agent is the primary execution unit in ATOS, replacing the traditional process.

use crate::capability::Capability;

// ─── Canonical type aliases and constants ───────────────────────────────────

pub type AgentId = u16;
pub type MailboxId = u16; // In Stage-1, same as AgentId (1:1 binding)
pub type Tick = u64;
pub type EnergyUnit = u64;
pub type KeyspaceId = u16;

pub const MAX_AGENTS: usize = 16;
pub const IDLE_AGENT_ID: AgentId = 0;
pub const ROOT_AGENT_ID: AgentId = 1;
pub const MAX_MAILBOX_CAPACITY: usize = 16;
pub const MAX_MESSAGE_PAYLOAD: usize = 256;
pub const MAX_CAPABILITIES_PER_AGENT: usize = 32;
pub const SYSCALL_ENERGY_COST: EnergyUnit = 1;
pub const TICK_ENERGY_COST: EnergyUnit = 1;

pub const CAP_TARGET_WILDCARD: u16 = 0xFFFF;

// ─── Syscall numbers (Yellow Paper §14.2) ─────────────────────────────────

pub const SYS_YIELD: u64 = 0;
pub const SYS_SPAWN: u64 = 1;
pub const SYS_EXIT: u64 = 2;
pub const SYS_SEND: u64 = 3;
pub const SYS_RECV: u64 = 4;
pub const SYS_CAP_QUERY: u64 = 5;
pub const SYS_CAP_GRANT: u64 = 6;
pub const SYS_EVENT_EMIT: u64 = 7;
pub const SYS_ENERGY_GET: u64 = 8;
pub const SYS_STATE_GET: u64 = 9;
pub const SYS_STATE_PUT: u64 = 10;
pub const SYS_CAP_REVOKE: u64 = 11;
pub const SYS_RECV_NONBLOCKING: u64 = 12;
pub const SYS_SEND_BLOCKING: u64 = 13;
pub const SYS_ENERGY_GRANT: u64 = 14;
pub const SYS_CHECKPOINT: u64 = 15;
pub const SYS_MMAP: u64 = 16;
pub const SYS_MUNMAP: u64 = 17;
pub const SYS_MAILBOX_CREATE: u64 = 18;
pub const SYS_MAILBOX_DESTROY: u64 = 19;
pub const SYS_REPLAY: u64 = 20;
pub const SYS_RECV_TIMEOUT: u64 = 21;
pub const SYS_SPAWN_IMAGE: u64 = 22;

// ─── Error codes ────────────────────────────────────────────────────────────

pub const E_OK: i64 = 0;
pub const E_NO_CAP: i64 = -1;
pub const E_MAILBOX_FULL: i64 = -2;
pub const E_INVALID_ARG: i64 = -3;
pub const E_NO_BUDGET: i64 = -4;
pub const E_NOT_FOUND: i64 = -5;
pub const E_QUOTA_EXCEEDED: i64 = -6;
pub const E_PAYLOAD_TOO_LARGE: i64 = -7;
pub const E_CHECKPOINT_NOT_ROOT: i64 = -9;
pub const E_TIMEOUT: i64 = -10;
pub const E_BAD_IMAGE: i64 = -11;

// ─── Runtime kind ──────────────────────────────────────────────────────────

/// Runtime kind for agent loading (Yellow Paper §24.2.3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RuntimeKind {
    Native = 0,
    Wasm = 1,
}

/// Re-export RuntimeClass from wasm types for agent-level use.
pub use crate::wasm::types::RuntimeClass;

// ─── Agent priority ─────────────────────────────────────────────────────────

/// Agent scheduling priority (lower number = higher priority).
/// This is a scheduling hint, not a security feature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum AgentPriority {
    SystemCritical = 0,  // idle, root
    SystemService = 1,   // stated, policyd, accountd, netd
    Normal = 2,          // user agents (default)
    Background = 3,      // batch/idle workloads
}

// ─── Agent mode ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AgentMode {
    Kernel = 0,
    User = 1,
}

pub const KERNEL_STACK_SIZE: usize = 16384;

// ─── Agent status ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AgentStatus {
    Created = 0,
    Ready = 1,
    Running = 2,
    BlockedRecv = 3,
    BlockedSend = 4,
    Suspended = 5,
    Exited = 6,
    Faulted = 7,
}

// ─── Agent execution context (forward declaration) ──────────────────────────

/// Minimal agent execution context for Stage-1.
/// Holds the saved CPU register state for context switching.
///
/// The full implementation lives in `crate::arch::x86_64::context`.
/// This placeholder is used when the arch layer is not yet available.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct AgentContext {
    pub rsp: u64,
    pub rip: u64,
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rflags: u64,
    pub cr3: u64,
}

impl AgentContext {
    /// Create a zeroed context.
    pub const fn zero() -> Self {
        AgentContext {
            rsp: 0,
            rip: 0,
            rax: 0,
            rbx: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            rbp: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rflags: 0,
            cr3: 0,
        }
    }

    /// Create a new kernel-mode context with the given entry point and stack top.
    ///
    /// rflags is set with IF (interrupt flag) enabled (bit 9) so that
    /// timer interrupts can preempt the agent.
    pub fn new_kernel(entry: u64, stack_top: u64) -> Self {
        AgentContext {
            rsp: stack_top,
            rip: entry,
            rflags: 0x200, // IF=1
            ..Self::zero()
        }
    }
}

// ─── Agent struct ───────────────────────────────────────────────────────────

pub struct Agent {
    pub id: AgentId,
    pub parent_id: Option<AgentId>,
    pub status: AgentStatus,
    pub context: AgentContext,
    pub mailbox_id: MailboxId,
    pub capabilities: [Option<Capability>; MAX_CAPABILITIES_PER_AGENT],
    pub cap_count: usize,
    pub energy_budget: EnergyUnit,
    pub memory_quota: u32,  // in pages
    pub memory_used: u32,
    pub mode: AgentMode,
    pub kernel_stack_top: u64,
    pub stack_bottom: u64,   // address of stack guard canary (lowest stack address)
    pub active: bool,       // whether this slot is in use
    pub priority: AgentPriority,
}

impl Agent {
    /// Create a new agent with the given parameters.
    ///
    /// The agent is created in `Created` status. The caller must transition
    /// it to `Ready` and add it to the run queue.
    pub fn new(
        id: AgentId,
        parent_id: Option<AgentId>,
        entry: u64,
        stack_top: u64,
        energy: EnergyUnit,
        mem_quota: u32,
    ) -> Self {
        Agent {
            id,
            parent_id,
            status: AgentStatus::Created,
            context: AgentContext::new_kernel(entry, stack_top),
            mailbox_id: id, // Stage-1: 1:1 binding
            capabilities: [const { None }; MAX_CAPABILITIES_PER_AGENT],
            cap_count: 0,
            energy_budget: energy,
            memory_quota: mem_quota,
            memory_used: 0,
            mode: AgentMode::Kernel,
            kernel_stack_top: 0,
            stack_bottom: 0,
            active: true,
            priority: AgentPriority::Normal,
        }
    }
}

// ─── Global agent table ────────────────────────────────────────────────────

// Safety: single-core, no preemption during table access in Stage-1.
static mut AGENT_TABLE: [Option<Agent>; MAX_AGENTS] = [const { None }; MAX_AGENTS];
static mut NEXT_AGENT_ID: AgentId = 0;

// ─── Public API ─────────────────────────────────────────────────────────────

/// Create a new agent and add it to the agent table.
///
/// Returns the new agent's ID on success, or an error code on failure.
pub fn create_agent(
    parent_id: Option<AgentId>,
    entry: u64,
    stack_top: u64,
    energy: EnergyUnit,
    mem_quota: u32,
) -> Result<AgentId, i64> {
    // Safety: single-core, no preemption during table access
    unsafe {
        // Find a free slot
        let mut slot_idx: Option<usize> = None;
        for i in 0..MAX_AGENTS {
            if AGENT_TABLE[i].is_none() {
                slot_idx = Some(i);
                break;
            }
        }

        let idx = match slot_idx {
            Some(i) => i,
            None => return Err(E_QUOTA_EXCEEDED),
        };

        let id = NEXT_AGENT_ID;
        NEXT_AGENT_ID = NEXT_AGENT_ID.wrapping_add(1);

        let agent = Agent::new(id, parent_id, entry, stack_top, energy, mem_quota);
        AGENT_TABLE[idx] = Some(agent);

        Ok(id)
    }
}

/// Get an immutable reference to an agent by ID.
pub fn get_agent(id: AgentId) -> Option<&'static Agent> {
    // Safety: single-core, no preemption during table access
    unsafe {
        for slot in AGENT_TABLE.iter() {
            if let Some(agent) = slot {
                if agent.id == id && agent.active {
                    return Some(agent);
                }
            }
        }
        None
    }
}

/// Get a mutable reference to an agent by ID.
pub fn get_agent_mut(id: AgentId) -> Option<&'static mut Agent> {
    // Safety: single-core, no preemption during table access
    unsafe {
        for slot in AGENT_TABLE.iter_mut() {
            if let Some(agent) = slot {
                if agent.id == id && agent.active {
                    return Some(agent);
                }
            }
        }
        None
    }
}

/// Terminate an agent and cascade to all children.
///
/// When a parent terminates, all its direct children are cascading-terminated
/// (moved to `Faulted` with a "parent exited" reason). This cascades recursively.
pub fn terminate_agent(id: AgentId, status: AgentStatus) {
    // Safety: single-core, no preemption during table access
    unsafe {
        // First, collect children to terminate (avoid borrow conflicts)
        let mut children: [Option<AgentId>; MAX_AGENTS] = [None; MAX_AGENTS];
        let mut child_count = 0;

        for slot in AGENT_TABLE.iter() {
            if let Some(agent) = slot {
                if agent.parent_id == Some(id) && agent.active {
                    if child_count < MAX_AGENTS {
                        children[child_count] = Some(agent.id);
                        child_count += 1;
                    }
                }
            }
        }

        // Reparent children to root agent (instead of cascade termination)
        for i in 0..child_count {
            if let Some(child_id) = children[i] {
                for slot in AGENT_TABLE.iter_mut() {
                    if let Some(agent) = slot {
                        if agent.id == child_id && agent.active {
                            agent.parent_id = Some(ROOT_AGENT_ID);
                            break;
                        }
                    }
                }
                // Emit audit event for reparenting
                crate::event::child_adopted(child_id, ROOT_AGENT_ID, id);
            }
        }

        // Now terminate this agent
        for slot in AGENT_TABLE.iter_mut() {
            if let Some(agent) = slot {
                if agent.id == id && agent.active {
                    agent.status = status;
                    agent.active = false;
                    return;
                }
            }
        }
    }
}

/// Check if a given agent is a direct child of another.
pub fn is_child_of(child_id: AgentId, parent_id: AgentId) -> bool {
    match get_agent(child_id) {
        Some(agent) => agent.parent_id == Some(parent_id),
        None => false,
    }
}

/// Iterate over all active agents (callback-based to avoid iterator issues).
///
/// The callback receives a mutable reference to each active agent.
/// Returns early if the callback returns `false`.
pub fn for_each_agent_mut(mut f: impl FnMut(&mut Agent) -> bool) {
    // Safety: single-core, no preemption during table access
    unsafe {
        for slot in AGENT_TABLE.iter_mut() {
            if let Some(agent) = slot {
                if agent.active && !f(agent) {
                    return;
                }
            }
        }
    }
}
