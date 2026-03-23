//! AOS Scheduler
//!
//! Implements a simple round-robin scheduler for Stage-1.
//! Agents in the run queue are executed in order, with preemption
//! driven by the timer interrupt.
//!
//! The scheduler maintains a circular run queue of agent IDs.
//! The idle agent is special-cased and runs when the queue is empty.

use crate::serial_println;
use crate::agent::*;
use crate::arch::x86_64::context::context_switch;
use crate::agent::AgentMode;
use crate::arch::x86_64::gdt;

extern "C" {
    static mut CURRENT_KERNEL_RSP: u64;
}

/// Maximum run queue size (same as MAX_AGENTS).
const RUN_QUEUE_SIZE: usize = MAX_AGENTS;

/// Stack size for dynamically spawned agents (4 KiB).
const SPAWN_STACK_SIZE: usize = 4096;

/// Static stack pool for spawned agents.
///
/// Safety: each stack is used by exactly one agent. Single-core Stage-1.
static mut SPAWN_STACKS: [[u8; SPAWN_STACK_SIZE]; MAX_AGENTS] = [[0u8; SPAWN_STACK_SIZE]; MAX_AGENTS];
static mut NEXT_STACK_SLOT: usize = 4; // first 4 slots reserved for init agents

/// Circular run queue of agent IDs.
///
/// Safety: single-core, no concurrent access in Stage-1.
static mut RUN_QUEUE: [Option<AgentId>; RUN_QUEUE_SIZE] = [None; RUN_QUEUE_SIZE];
static mut RUN_QUEUE_LEN: usize = 0;
static mut CURRENT_INDEX: usize = 0;
static mut CURRENT_AGENT_ID: AgentId = IDLE_AGENT_ID;

/// Boot context: saves the kernel boot thread state when we switch to the
/// first agent. This lets schedule() always have a valid "old" context.
static mut BOOT_CONTEXT: AgentContext = AgentContext::zero();

/// Initialize the scheduler.
///
/// Must be called once during boot before any agents are added.
pub fn init() {
    unsafe {
        RUN_QUEUE = [None; RUN_QUEUE_SIZE];
        RUN_QUEUE_LEN = 0;
        CURRENT_INDEX = 0;
        CURRENT_AGENT_ID = IDLE_AGENT_ID;
    }
}

/// Get the currently running agent's ID.
///
/// Returns `IDLE_AGENT_ID` (0) if no agent is running.
pub fn current() -> AgentId {
    // Safety: single-core read
    unsafe { CURRENT_AGENT_ID }
}

/// Allocate a stack for a dynamically spawned agent.
///
/// Returns the stack top address (highest address, since x86_64 stacks grow down).
/// Returns 0 if no stack slots are available.
pub fn allocate_agent_stack() -> u64 {
    // Safety: single-core, no preemption during allocation
    unsafe {
        if NEXT_STACK_SLOT >= MAX_AGENTS {
            return 0;
        }
        let slot = NEXT_STACK_SLOT;
        NEXT_STACK_SLOT += 1;
        let ptr = SPAWN_STACKS[slot].as_ptr();
        (ptr as u64) + SPAWN_STACK_SIZE as u64
    }
}

/// Alias for `add_to_run_queue` -- used by syscall.rs.
pub fn enqueue(id: AgentId) {
    add_to_run_queue(id);
}

/// Add an agent to the run queue and mark it as Ready.
pub fn add_to_run_queue(agent_id: AgentId) {
    unsafe {
        // Don't add duplicates
        for i in 0..RUN_QUEUE_LEN {
            if RUN_QUEUE[i] == Some(agent_id) {
                return;
            }
        }

        if RUN_QUEUE_LEN >= RUN_QUEUE_SIZE {
            serial_println!("[SCHED] Run queue full, cannot add agent {}", agent_id);
            return;
        }

        // Mark the agent as Ready
        if let Some(agent) = get_agent_mut(agent_id) {
            if agent.status == AgentStatus::Created || agent.status == AgentStatus::Suspended {
                agent.status = AgentStatus::Ready;
            }
        }

        RUN_QUEUE[RUN_QUEUE_LEN] = Some(agent_id);
        RUN_QUEUE_LEN += 1;
    }
}

/// Remove an agent from the run queue.
pub fn remove_from_run_queue(agent_id: AgentId) {
    unsafe {
        for i in 0..RUN_QUEUE_LEN {
            if RUN_QUEUE[i] == Some(agent_id) {
                // Shift remaining entries down
                let mut j = i;
                while j + 1 < RUN_QUEUE_LEN {
                    RUN_QUEUE[j] = RUN_QUEUE[j + 1];
                    j += 1;
                }
                RUN_QUEUE[RUN_QUEUE_LEN - 1] = None;
                RUN_QUEUE_LEN -= 1;
                if CURRENT_INDEX >= RUN_QUEUE_LEN && RUN_QUEUE_LEN > 0 {
                    CURRENT_INDEX = 0;
                }
                return;
            }
        }
    }
}

/// Yield the current agent: move it back to Ready and trigger a context switch.
pub fn yield_current() {
    schedule();
}

/// Block the current agent with the given reason (e.g., BlockedRecv).
///
/// Removes the agent from the run queue and triggers a reschedule.
pub fn block_current(reason: AgentStatus) {
    unsafe {
        let id = CURRENT_AGENT_ID;
        if id == IDLE_AGENT_ID {
            return; // idle agent cannot block
        }

        if let Some(agent) = get_agent_mut(id) {
            agent.status = reason;
        }
        remove_from_run_queue(id);
        schedule();
    }
}

/// Unblock an agent and move it from blocked to Ready.
///
/// Adds the agent back to the run queue.
pub fn unblock(id: AgentId) {
    if let Some(agent) = get_agent_mut(id) {
        if agent.status == AgentStatus::BlockedRecv
            || agent.status == AgentStatus::BlockedSend
        {
            agent.status = AgentStatus::Ready;
            add_to_run_queue(id);
        }
    }
}

/// Select the next agent to run and perform a context switch.
///
/// Round-robin selection among Ready agents. If no agents are Ready,
/// falls back to the idle agent.
///
/// Interrupts are disabled during the scheduling decision and context
/// switch to prevent re-entrant schedule() calls from timer_tick().
pub fn schedule() {
    // Disable interrupts to prevent re-entrant schedule() from timer_tick()
    unsafe { core::arch::asm!("cli", options(nomem, nostack)); }

    unsafe {
        let old_id = CURRENT_AGENT_ID;

        // If the current agent is still Running, move it to Ready
        if old_id != IDLE_AGENT_ID {
            if let Some(agent) = get_agent_mut(old_id) {
                if agent.status == AgentStatus::Running {
                    agent.status = AgentStatus::Ready;
                }
            }
        } else {
            // Idle agent: mark as Ready so it can be selected again later
            if let Some(agent) = get_agent_mut(IDLE_AGENT_ID) {
                if agent.status == AgentStatus::Running {
                    agent.status = AgentStatus::Ready;
                }
            }
        }

        // Find the next Ready agent from the run queue
        let next_id = find_next_ready();

        if next_id == old_id {
            // Same agent, just re-mark as Running, no switch needed
            if let Some(agent) = get_agent_mut(old_id) {
                agent.status = AgentStatus::Running;
            }
            core::arch::asm!("sti", options(nomem, nostack));
            return;
        }

        // Mark the next agent as Running
        if let Some(agent) = get_agent_mut(next_id) {
            agent.status = AgentStatus::Running;
        }

        CURRENT_AGENT_ID = next_id;

        // For ring 3 agents: update TSS.rsp0 and CURRENT_KERNEL_RSP
        // so the CPU knows which kernel stack to use on interrupt/syscall
        if let Some(agent) = get_agent(next_id) {
            if agent.mode == AgentMode::User {
                gdt::set_tss_rsp0(agent.kernel_stack_top);
                unsafe { CURRENT_KERNEL_RSP = agent.kernel_stack_top; }
            }
        }

        // Get context pointers for old and new agents
        let old_ctx = get_old_context_ptr(old_id);
        let new_agent = match get_agent(next_id) {
            Some(a) => a,
            None => {
                // Agent was terminated between selection and switch; fall back to idle
                CURRENT_AGENT_ID = IDLE_AGENT_ID;
                if let Some(idle) = get_agent_mut(IDLE_AGENT_ID) {
                    idle.status = AgentStatus::Running;
                }
                core::arch::asm!("sti", options(nomem, nostack));
                return;
            }
        };
        let new_ctx = &new_agent.context as *const AgentContext;

        context_switch(old_ctx, new_ctx);

        // Debug: after resuming, check if agent 6's stack was corrupted
        // by inspecting the canary value we placed at the stack top area
        if CURRENT_AGENT_ID == 6 {
            // We just resumed as agent 6. Check the return address
            // that `ret` will pop. If it's 0x0202020202020202, log WHO corrupted it.
            let rsp: u64;
            core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nomem, nostack));
            let top_of_stack = core::ptr::read_volatile(rsp as *const u64);
            if top_of_stack == 0x0202020202020202 {
                serial_println!("[SCHED-CORRUPT] Agent 6 stack corrupted! rsp={:#x} value={:#x} old_id={} next_id={}",
                    rsp, top_of_stack, old_id, next_id);
            }
        }
        // We reach here when this agent is resumed by another context_switch.
        // Re-enable interrupts.
        core::arch::asm!("sti", options(nomem, nostack));
    }
}

/// Find the next Ready agent in round-robin order.
/// Returns IDLE_AGENT_ID if no agent is ready.
unsafe fn find_next_ready() -> AgentId {
    if RUN_QUEUE_LEN == 0 {
        return IDLE_AGENT_ID;
    }

    let start = CURRENT_INDEX % RUN_QUEUE_LEN.max(1);
    for offset in 0..RUN_QUEUE_LEN {
        let idx = (start + offset) % RUN_QUEUE_LEN;
        if let Some(agent_id) = RUN_QUEUE[idx] {
            if let Some(agent) = get_agent(agent_id) {
                if agent.status == AgentStatus::Ready {
                    CURRENT_INDEX = (idx + 1) % RUN_QUEUE_LEN.max(1);
                    return agent_id;
                }
            }
        }
    }

    IDLE_AGENT_ID
}

/// Get a mutable pointer to the old agent's context, or the boot context
/// if the old agent is no longer accessible (e.g., it just exited).
unsafe fn get_old_context_ptr(old_id: AgentId) -> *mut AgentContext {
    match get_agent_mut(old_id) {
        Some(agent) => &mut agent.context as *mut AgentContext,
        None => &mut BOOT_CONTEXT as *mut AgentContext,
    }
}

/// Start the scheduler by context-switching to the first agent.
///
/// This function does not return. The boot thread's context is saved
/// into BOOT_CONTEXT and can be resumed if all agents exit.
pub fn start() {
    serial_println!("[SCHED] Scheduler starting");

    unsafe {
        if RUN_QUEUE_LEN == 0 {
            serial_println!("[SCHED] No agents in run queue");
            return;
        }

        // Select the first agent
        let first_id = RUN_QUEUE[0].expect("No agents in run queue");
        CURRENT_AGENT_ID = first_id;
        CURRENT_INDEX = 1 % RUN_QUEUE_LEN.max(1);

        if let Some(agent) = get_agent_mut(first_id) {
            agent.status = AgentStatus::Running;
        }

        serial_println!("[SCHED] Context switching to first agent: id={}", first_id);

        // For ring 3 agents: update TSS.rsp0 and CURRENT_KERNEL_RSP
        // so the CPU knows which kernel stack to use on interrupt/syscall
        if let Some(agent) = get_agent(first_id) {
            if agent.mode == AgentMode::User {
                gdt::set_tss_rsp0(agent.kernel_stack_top);
                CURRENT_KERNEL_RSP = agent.kernel_stack_top;
            }
        }

        let new_ctx = &get_agent(first_id).unwrap().context as *const AgentContext;
        context_switch(&mut BOOT_CONTEXT as *mut AgentContext, new_ctx);
    }
}

/// Called from the timer interrupt handler to perform preemptive scheduling.
///
/// 1. Decrements the current agent's energy budget; suspends if exhausted.
/// 2. Decrements energy for all blocked agents; suspends if exhausted.
/// 3. Triggers a preemptive context switch (round-robin time slice).
pub fn timer_tick() {
    unsafe {
        let id = CURRENT_AGENT_ID;

        // Charge energy for current running agent (skip idle)
        if id != IDLE_AGENT_ID {
            if !crate::energy::tick_running(id) {
                // Energy exhausted: suspend the agent
                if let Some(agent) = get_agent_mut(id) {
                    agent.status = AgentStatus::Suspended;
                }
                crate::event::energy_exhausted(id);
                remove_from_run_queue(id);
                schedule();
                return;
            }
        }

        // Charge energy for blocked agents
        let mut blocked: [Option<AgentId>; MAX_AGENTS] = [None; MAX_AGENTS];
        let mut count = 0;

        for_each_agent_mut(|agent| {
            if (agent.status == AgentStatus::BlockedRecv
                || agent.status == AgentStatus::BlockedSend)
                && count < MAX_AGENTS
            {
                blocked[count] = Some(agent.id);
                count += 1;
            }
            true
        });

        for i in 0..count {
            if let Some(blocked_id) = blocked[i] {
                if !crate::energy::tick_blocked(blocked_id) {
                    if let Some(agent) = get_agent_mut(blocked_id) {
                        agent.status = AgentStatus::Suspended;
                    }
                    crate::event::energy_exhausted(blocked_id);
                }
            }
        }

        // Preemptive reschedule
        if crate::deterministic::is_enabled() {
            // In deterministic mode: use fixed-tick-quota scheduling
            // tick() returns Some(agent_id) when the current slot expires
            if crate::deterministic::tick().is_some() {
                schedule();
            }
            // If tick() returns None, keep running current agent (slot not expired)
        } else {
            // Normal mode: round-robin on every tick
            schedule();
        }
    }
}
