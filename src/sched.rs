//! ATOS Scheduler
//!
//! Implements a round-robin scheduler with SMP support.
//! The run queue is protected by a SpinLock for safe concurrent access
//! from multiple cores. Each core tracks its own current agent.

use crate::agent::AgentMode;
use crate::agent::AgentPriority;
use crate::agent::*;
use crate::arch::x86_64::context::context_switch;
use crate::arch::x86_64::gdt;
use crate::init::STACK_GUARD_MAGIC;
use crate::serial_println;
use crate::sync::SpinLock;

extern "C" {
    static mut CURRENT_KERNEL_RSP: u64;
    static mut CURRENT_SYSCALL_FRAME: u64;
}

/// Maximum run queue size (same as MAX_AGENTS).
const RUN_QUEUE_SIZE: usize = MAX_AGENTS;

/// Kernel stack size for dynamically spawned agents.
///
/// Linux-compat paths like `execve` and dynamic loading can materialize
/// sizeable temporary buffers on the kernel stack. Keeping the spawned-agent
/// pool aligned with the global ring-3 kernel stack size avoids cross-agent
/// corruption when those deeper paths run.
const SPAWN_STACK_SIZE: usize = KERNEL_STACK_SIZE;

#[repr(align(4096))]
struct AlignedSpawnStacks<const SIZE: usize, const COUNT: usize> {
    stacks: [[u8; SIZE]; COUNT],
}

/// Static stack pool for spawned agents.
static mut SPAWN_STACKS: AlignedSpawnStacks<SPAWN_STACK_SIZE, MAX_AGENTS> = AlignedSpawnStacks {
    stacks: [[0u8; SPAWN_STACK_SIZE]; MAX_AGENTS],
};
static mut SPAWN_STACK_IN_USE: [bool; MAX_AGENTS] = [false; MAX_AGENTS];

#[inline]
unsafe fn write_guard_pair(bottom: *mut u64) {
    core::ptr::write_volatile(bottom, STACK_GUARD_MAGIC);
    core::ptr::write_volatile(bottom.add(1), STACK_GUARD_MAGIC);
}

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
            unsafe {
                PER_CORE_AGENT[core_id] = id;
            }
        }
    }
    unsafe {
        CURRENT_AGENT_ID = id;
    }
}

fn prepare_user_entry(agent_id: AgentId) {
    if let Some(agent) = get_agent_mut(agent_id) {
        gdt::set_tss_rsp0(agent.kernel_stack_top);
        unsafe {
            CURRENT_KERNEL_RSP = agent.kernel_stack_top;
            CURRENT_SYSCALL_FRAME = agent.saved_syscall_frame;
        }
        agent.saved_syscall_frame = 0;
        crate::linux_compat::identity::restore_thread_pointer_bases(agent.id);
    }
}

fn save_user_syscall_frame(agent_id: AgentId) {
    let saved = unsafe { CURRENT_SYSCALL_FRAME };
    if let Some(agent) = get_agent_mut(agent_id) {
        if agent.mode == AgentMode::User {
            agent.saved_syscall_frame = saved;
        }
    }
    unsafe {
        CURRENT_SYSCALL_FRAME = 0;
    }
}

/// Allocate a stack for a dynamically spawned agent.
pub fn allocate_agent_stack() -> u64 {
    unsafe {
        for slot in 4..MAX_AGENTS {
            if SPAWN_STACK_IN_USE[slot] {
                continue;
            }
            SPAWN_STACK_IN_USE[slot] = true;
            let ptr = SPAWN_STACKS.stacks[slot].as_ptr();
            write_guard_pair(ptr as *mut u64);
            return ((ptr as u64) + SPAWN_STACK_SIZE as u64) & !0xF;
        }
        0
    }
}

/// Return a dynamically spawned agent stack back to the reusable pool.
pub fn free_agent_stack(stack_top: u64) {
    if stack_top == 0 {
        return;
    }

    unsafe {
        let base = SPAWN_STACKS.stacks.as_ptr() as u64;
        let end = base + (SPAWN_STACK_SIZE as u64 * MAX_AGENTS as u64);
        let bottom = stack_top.saturating_sub(SPAWN_STACK_SIZE as u64);
        if bottom < base || bottom >= end {
            return;
        }
        let offset = bottom - base;
        if !offset.is_multiple_of(SPAWN_STACK_SIZE as u64) {
            return;
        }
        let slot = (offset / SPAWN_STACK_SIZE as u64) as usize;
        if slot >= 4 && slot < MAX_AGENTS {
            SPAWN_STACK_IN_USE[slot] = false;
        }
    }
}

#[inline]
pub fn stack_bottom_from_top(stack_top: u64) -> u64 {
    stack_top.saturating_sub(SPAWN_STACK_SIZE as u64)
}

fn check_stack_guard(agent_id: AgentId) -> bool {
    if agent_id == IDLE_AGENT_ID {
        return true;
    }

    let Some(agent) = get_agent_any_state(agent_id) else {
        return true;
    };
    if agent.stack_bottom == 0 {
        return true;
    }

    let guard = unsafe { core::ptr::read_volatile(agent.stack_bottom as *const u64) };
    if guard == STACK_GUARD_MAGIC {
        return true;
    }

    serial_println!(
        "[STACK OVERFLOW] Agent {} stack corrupted! guard={:#x} expected={:#x}",
        agent_id,
        guard,
        STACK_GUARD_MAGIC
    );
    false
}

/// Clear the run queue, removing all entries.
/// Used by replay to rebuild the queue from checkpoint state.
pub fn clear_run_queue() {
    let mut rq = SCHED_LOCK.lock();
    for i in 0..RUN_QUEUE_SIZE {
        rq.queue[i] = None;
    }
    rq.len = 0;
    rq.current_index = 0;
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
        if agent.status == AgentStatus::BlockedRecv || agent.status == AgentStatus::BlockedSend {
            agent.status = AgentStatus::Ready;
            add_to_run_queue(id);
        }
    }
}

fn select_next_ready_agent() -> AgentId {
    let mut rq = SCHED_LOCK.lock();

    let mut found = IDLE_AGENT_ID;
    if rq.len > 0 {
        let start = rq.current_index % rq.len.max(1);

        // Round-robin: `current_index` always points at the next candidate to
        // try, so the scan must begin at `start` itself. Starting at
        // `start + 1` permanently starves freshly appended agents because the
        // enqueue path stores them exactly at the next candidate slot.
        let mut best_id = IDLE_AGENT_ID;
        let mut best_idx = 0;

        for offset in 0..rq.len {
            let idx = (start + offset) % rq.len;
            if let Some(agent_id) = rq.queue[idx] {
                if let Some(agent) = get_agent_mut(agent_id) {
                    if agent.status == AgentStatus::Ready {
                        // On AP cores, skip ring-3 agents
                        let on_ap = crate::arch::x86_64::lapic::is_active()
                            && crate::arch::x86_64::lapic::id() != 0;
                        if on_ap && agent.mode == AgentMode::User {
                            continue;
                        }

                        best_id = agent_id;
                        best_idx = idx;
                        break;
                    }
                }
            }
        }

        if best_id != IDLE_AGENT_ID {
            if let Some(agent) = get_agent_mut(best_id) {
                agent.status = AgentStatus::Running;
            }
            rq.current_index = (best_idx + 1) % rq.len.max(1);
        }
        found = best_id;
    }

    found
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

    let next_id = select_next_ready_agent();
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
    save_user_syscall_frame(old_id);

    if let Some(agent) = get_agent(next_id) {
        if agent.mode == AgentMode::User {
            prepare_user_entry(next_id);
        }
    }

    // Context switch — use per-core boot context for idle agent
    let old_ctx = unsafe {
        if old_id == IDLE_AGENT_ID {
            // Each core saves idle state to its own boot context
            let core_id = if crate::arch::x86_64::lapic::is_active() {
                crate::arch::x86_64::lapic::id() as usize
            } else {
                0
            };
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

        if !check_stack_guard(old_id) {
            if let Some(agent) = get_agent_mut(old_id) {
                agent.status = AgentStatus::Faulted;
            }
            crate::event::agent_faulted(old_id, 0xFF);
            remove_from_run_queue(old_id);
        }
    }
}

/// Switch away from the current trap context without ever returning to the
/// interrupted stack frame.
///
/// This is used for faults and timer-driven budget exhaustion. The current
/// trap frame is already unusable as a normal resumable context, so we save
/// a scratch continuation into the per-core boot context and jump directly
/// into the next runnable agent.
pub fn switch_from_trap() -> ! {
    let old_id = current();
    let next_id = select_next_ready_agent();

    if next_id == IDLE_AGENT_ID {
        if let Some(agent) = get_agent_mut(IDLE_AGENT_ID) {
            agent.status = AgentStatus::Running;
        }
    }

    set_current(next_id);

    save_user_syscall_frame(old_id);

    if let Some(agent) = get_agent(next_id) {
        if agent.mode == AgentMode::User {
            prepare_user_entry(next_id);
        }
    }

    let new_ctx = match get_agent(next_id) {
        Some(agent) => &agent.context as *const AgentContext,
        None => loop {
            unsafe {
                core::arch::asm!("cli; hlt", options(nomem, nostack));
            }
        },
    };

    let core_id = if crate::arch::x86_64::lapic::is_active() {
        crate::arch::x86_64::lapic::id() as usize
    } else {
        0
    };
    let scratch_ctx = unsafe { &mut BOOT_CONTEXTS[core_id.min(15)] as *mut AgentContext };

    unsafe {
        core::arch::asm!("cli", options(nomem, nostack));
        context_switch(scratch_ctx, new_ctx);
    }

    loop {
        unsafe {
            core::arch::asm!("cli; hlt", options(nomem, nostack));
        }
    }
}

/// Switch away from the current syscall/exit path without leaving a resumable
/// continuation in the current agent context.
///
/// This is for paths like `exit(2)` / `execve(2)` success where the current
/// agent has already been removed from the run queue and must never return to
/// its saved kernel stack continuation.
pub fn switch_without_current() -> ! {
    let old_id = current();
    if !check_stack_guard(old_id) {
        crate::event::agent_faulted(old_id, 0xFF);
    }
    crate::agent::auto_reap_if_unwaitable(old_id);

    let next_id = select_next_ready_agent();

    if next_id == IDLE_AGENT_ID {
        if let Some(agent) = get_agent_mut(IDLE_AGENT_ID) {
            agent.status = AgentStatus::Running;
        }
    }

    set_current(next_id);

    unsafe {
        CURRENT_SYSCALL_FRAME = 0;
    }

    if let Some(agent) = get_agent(next_id) {
        if agent.mode == AgentMode::User {
            prepare_user_entry(next_id);
        }
    }

    let new_ctx = match get_agent(next_id) {
        Some(agent) => &agent.context as *const AgentContext,
        None => loop {
            unsafe {
                core::arch::asm!("cli; hlt", options(nomem, nostack));
            }
        },
    };

    let core_id = if crate::arch::x86_64::lapic::is_active() {
        crate::arch::x86_64::lapic::id() as usize
    } else {
        0
    };
    let scratch_ctx = unsafe { &mut BOOT_CONTEXTS[core_id.min(15)] as *mut AgentContext };

    unsafe {
        core::arch::asm!("cli", options(nomem, nostack));
        context_switch(scratch_ctx, new_ctx);
    }

    loop {
        unsafe {
            core::arch::asm!("cli; hlt", options(nomem, nostack));
        }
    }
}

/// Start the scheduler by context-switching to the first agent.
pub fn start() {
    serial_println!("[SCHED] Scheduler starting");

    // The BSP must not take timer IRQs while it is still resolving the first
    // runnable agent and building the initial boot-context switch.
    unsafe {
        core::arch::asm!("cli", options(nomem, nostack));
    }

    let first_id = {
        let rq = SCHED_LOCK.lock_raw();
        if rq.len == 0 {
            serial_println!("[SCHED] No agents in run queue");
            return;
        }
        rq.queue[0].expect("No agents in run queue")
    };

    set_current(first_id);

    let new_ctx = {
        let agent = get_agent_mut(first_id).expect("First agent not found");
        agent.status = AgentStatus::Running;
        &agent.context as *const AgentContext
    };

    if let Some(agent) = get_agent(first_id) {
        if agent.mode == AgentMode::User {
            prepare_user_entry(first_id);
        }
    }

    serial_println!("[SCHED] Context switching to first agent: id={}", first_id);

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
            switch_from_trap();
        }
    }

    crate::linux_compat::process::futex_tick();

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

    // ── eBPF TimerTick hook ──
    // Run any eBPF programs attached at TimerTick.
    // When no programs are attached, run_at short-circuits after
    // scanning 16 empty slots — trivial cost at 100 Hz.
    {
        let tick_count = crate::arch::x86_64::timer::get_ticks();
        let _action =
            crate::ebpf::attach::run_at(crate::ebpf::attach::AttachPoint::TimerTick, tick_count);
        // Action is ignored for TimerTick — observational only.
        // Programs use map helpers to record metrics or trigger alerts.
    }

    // Stage-1 trap handling does not save enough interrupted state to
    // preempt arbitrary code safely. Cooperative yields still switch
    // agents; timer IRQs only drive accounting and observability.
    if crate::deterministic::is_enabled() {
        let _ = crate::deterministic::tick();
    }
}
