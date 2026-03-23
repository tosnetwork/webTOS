//! AOS Scheduler
//!
//! Implements a round-robin scheduler with SMP support.
//! The run queue is protected by a SpinLock for safe concurrent access
//! from multiple cores. Each core tracks its own current agent.

use crate::serial_println;
use crate::agent::*;
use crate::arch::x86_64::context::context_switch;
use crate::agent::AgentMode;
use crate::arch::x86_64::gdt;
use crate::init::STACK_GUARD_MAGIC;
use crate::sync::SpinLock;

extern "C" {
    static mut CURRENT_KERNEL_RSP: u64;
}

/// Maximum run queue size (same as MAX_AGENTS).
const RUN_QUEUE_SIZE: usize = MAX_AGENTS;

/// Stack size for dynamically spawned agents (4 KiB).
const SPAWN_STACK_SIZE: usize = 4096;

/// Static stack pool for spawned agents.
static mut SPAWN_STACKS: [[u8; SPAWN_STACK_SIZE]; MAX_AGENTS] = [[0u8; SPAWN_STACK_SIZE]; MAX_AGENTS];
static mut NEXT_STACK_SLOT: usize = 4;

/// Run queue state protected by SpinLock for SMP safety.
struct RunQueueState {
    queue: [Option<AgentId>; RUN_QUEUE_SIZE],
    len: usize,
    current_index: usize,
}

static SCHED_LOCK: SpinLock<RunQueueState> = SpinLock::new(RunQueueState {
    queue: [None; RUN_QUEUE_SIZE],
    len: 0,
    current_index: 0,
});

/// Per-core current agent ID (indexed by LAPIC ID, max 16 cores).
/// Each entry is only written by its own core, so no lock needed.
static mut PER_CORE_AGENT: [AgentId; 16] = [IDLE_AGENT_ID; 16];

/// Legacy single-core current agent (fallback when LAPIC not active).
static mut CURRENT_AGENT_ID: AgentId = IDLE_AGENT_ID;

/// Per-core boot/idle context. Each core saves its idle state here
/// instead of the shared idle agent context (which would be corrupted
/// if two cores both save to it simultaneously).
static mut BOOT_CONTEXTS: [AgentContext; 16] = [AgentContext::zero(); 16];

/// Initialize the scheduler.
pub fn init() {
    // SpinLock is already initialized via const fn
    serial_println!("[SCHED] Scheduler initialized (SMP-safe)");
}

/// Get the currently running agent's ID on this core.
pub fn current() -> AgentId {
    if crate::arch::x86_64::lapic::is_active() {
        let core_id = crate::arch::x86_64::lapic::id() as usize;
        if core_id < 16 {
            return unsafe { PER_CORE_AGENT[core_id] };
        }
    }
    unsafe { CURRENT_AGENT_ID }
}

/// Set the current agent ID for this core.
fn set_current(id: AgentId) {
    if crate::arch::x86_64::lapic::is_active() {
        let core_id = crate::arch::x86_64::lapic::id() as usize;
        if core_id < 16 {
            unsafe { PER_CORE_AGENT[core_id] = id; }
        }
    }
    unsafe { CURRENT_AGENT_ID = id; }
}

/// Allocate a stack for a dynamically spawned agent.
pub fn allocate_agent_stack() -> u64 {
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

/// Alias for `add_to_run_queue`.
pub fn enqueue(id: AgentId) {
    add_to_run_queue(id);
}

/// Add an agent to the run queue and mark it as Ready.
pub fn add_to_run_queue(agent_id: AgentId) {
    let mut rq = SCHED_LOCK.lock();

    // Don't add duplicates
    for i in 0..rq.len {
        if rq.queue[i] == Some(agent_id) {
            return;
        }
    }

    if rq.len >= RUN_QUEUE_SIZE {
        serial_println!("[SCHED] Run queue full, cannot add agent {}", agent_id);
        return;
    }

    // Mark the agent as Ready
    if let Some(agent) = get_agent_mut(agent_id) {
        if agent.status == AgentStatus::Created || agent.status == AgentStatus::Suspended {
            agent.status = AgentStatus::Ready;
        }
    }

    let idx = rq.len;
    rq.queue[idx] = Some(agent_id);
    rq.len += 1;
}

/// Remove an agent from the run queue.
pub fn remove_from_run_queue(agent_id: AgentId) {
    let mut rq = SCHED_LOCK.lock();

    for i in 0..rq.len {
        if rq.queue[i] == Some(agent_id) {
            let mut j = i;
            while j + 1 < rq.len {
                rq.queue[j] = rq.queue[j + 1];
                j += 1;
            }
            let last = rq.len - 1;
            rq.queue[last] = None;
            rq.len -= 1;
            if rq.current_index >= rq.len && rq.len > 0 {
                rq.current_index = 0;
            }
            return;
        }
    }
}

/// Yield the current agent: move it back to Ready and trigger a context switch.
pub fn yield_current() {
    schedule();
}

/// Block the current agent with the given reason (e.g., BlockedRecv).
pub fn block_current(reason: AgentStatus) {
    let id = current();
    if id == IDLE_AGENT_ID {
        return;
    }

    if let Some(agent) = get_agent_mut(id) {
        agent.status = reason;
    }
    remove_from_run_queue(id);
    schedule();
}

/// Unblock an agent and move it from blocked to Ready.
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
/// Protected by SpinLock: safe for concurrent calls from multiple cores.
pub fn schedule() {
    let old_id = current();

    // Mark old agent as Ready (if still Running)
    if old_id != IDLE_AGENT_ID {
        if let Some(agent) = get_agent_mut(old_id) {
            if agent.status == AgentStatus::Running {
                agent.status = AgentStatus::Ready;
            }
        }
    } else {
        if let Some(agent) = get_agent_mut(IDLE_AGENT_ID) {
            if agent.status == AgentStatus::Running {
                agent.status = AgentStatus::Ready;
            }
        }
    }

    let next_id = {
        let mut rq = SCHED_LOCK.lock();

        let mut found = IDLE_AGENT_ID;
        if rq.len > 0 {
            let start = rq.current_index % rq.len.max(1);
            for offset in 0..rq.len {
                let idx = (start + offset) % rq.len;
                if let Some(agent_id) = rq.queue[idx] {
                    if let Some(agent) = get_agent_mut(agent_id) {
                        if agent.status == AgentStatus::Ready {
                            // On AP cores, skip ring-3 agents: they need
                            // CURRENT_KERNEL_RSP which is a BSP-only global.
                            // Kernel-mode agents use direct Rust calls, not
                            // the SYSCALL instruction, so they are safe on APs.
                            let on_ap = crate::arch::x86_64::lapic::is_active()
                                && crate::arch::x86_64::lapic::id() != 0;
                            if on_ap && agent.mode == AgentMode::User {
                                continue;
                            }
                            // Claim this agent under the lock
                            agent.status = AgentStatus::Running;
                            rq.current_index = (idx + 1) % rq.len.max(1);
                            found = agent_id;
                            break;
                        }
                    }
                }
            }
        }
        found
    };
    // SpinLock dropped here — interrupts re-enabled

    if next_id == old_id {
        return;
    }

    if next_id == IDLE_AGENT_ID {
        // No Ready agent found; mark idle as running on this core
        if let Some(agent) = get_agent_mut(IDLE_AGENT_ID) {
            agent.status = AgentStatus::Running;
        }
    }

    set_current(next_id);

    // For ring 3 agents: update TSS.rsp0
    if let Some(agent) = get_agent(next_id) {
        if agent.mode == AgentMode::User {
            gdt::set_tss_rsp0(agent.kernel_stack_top);
            unsafe { CURRENT_KERNEL_RSP = agent.kernel_stack_top; }
        }
    }

    // Context switch — use per-core boot context for idle agent
    let old_ctx = unsafe {
        if old_id == IDLE_AGENT_ID {
            // Each core saves idle state to its own boot context
            let core_id = if crate::arch::x86_64::lapic::is_active() {
                crate::arch::x86_64::lapic::id() as usize
            } else { 0 };
            &mut BOOT_CONTEXTS[core_id.min(15)] as *mut AgentContext
        } else {
            match get_agent_mut(old_id) {
                Some(agent) => &mut agent.context as *mut AgentContext,
                None => &mut BOOT_CONTEXTS[0] as *mut AgentContext,
            }
        }
    };
    let new_agent = match get_agent(next_id) {
        Some(a) => a,
        None => {
            set_current(IDLE_AGENT_ID);
            if let Some(idle) = get_agent_mut(IDLE_AGENT_ID) {
                idle.status = AgentStatus::Running;
            }
            return;
        }
    };
    let new_ctx = &new_agent.context as *const AgentContext;

    unsafe {
        // Disable interrupts around context_switch to prevent timer from
        // re-entering schedule between here and the switch completing.
        core::arch::asm!("cli", options(nomem, nostack));
        context_switch(old_ctx, new_ctx);
        // Resumed. Re-enable interrupts.
        core::arch::asm!("sti", options(nomem, nostack));

        // Check stack guard canary of the old agent
        if old_id != IDLE_AGENT_ID {
            if let Some(old_agent) = get_agent(old_id) {
                if old_agent.stack_bottom != 0 {
                    let guard = core::ptr::read_volatile(old_agent.stack_bottom as *const u64);
                    if guard != STACK_GUARD_MAGIC {
                        serial_println!(
                            "[STACK OVERFLOW] Agent {} stack corrupted! guard={:#x} expected={:#x}",
                            old_id, guard, STACK_GUARD_MAGIC
                        );
                        if let Some(agent) = get_agent_mut(old_id) {
                            agent.status = AgentStatus::Faulted;
                        }
                        crate::event::agent_faulted(old_id, 0xFF);
                        remove_from_run_queue(old_id);
                    }
                }
            }
        }
    }
}

/// Start the scheduler by context-switching to the first agent.
pub fn start() {
    serial_println!("[SCHED] Scheduler starting");

    let first_id = {
        let rq = SCHED_LOCK.lock();
        if rq.len == 0 {
            serial_println!("[SCHED] No agents in run queue");
            return;
        }
        rq.queue[0].expect("No agents in run queue")
    };

    set_current(first_id);

    if let Some(agent) = get_agent_mut(first_id) {
        agent.status = AgentStatus::Running;
    }

    serial_println!("[SCHED] Context switching to first agent: id={}", first_id);

    if let Some(agent) = get_agent(first_id) {
        if agent.mode == AgentMode::User {
            gdt::set_tss_rsp0(agent.kernel_stack_top);
            unsafe { CURRENT_KERNEL_RSP = agent.kernel_stack_top; }
        }
    }

    let new_ctx = &get_agent(first_id).unwrap().context as *const AgentContext;
    unsafe {
        context_switch(&mut BOOT_CONTEXTS[0] as *mut AgentContext, new_ctx);
    }
}

/// Called from the timer interrupt handler for preemptive scheduling.
pub fn timer_tick() {
    let id = current();

    // Charge energy for current running agent (skip idle)
    if id != IDLE_AGENT_ID {
        if !crate::energy::tick_running(id) {
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
    unsafe {
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
    }

    // Preemptive reschedule
    if crate::deterministic::is_enabled() {
        if crate::deterministic::tick().is_some() {
            schedule();
        }
    } else {
        schedule();
    }
}
