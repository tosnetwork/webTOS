//! AOS System Initialization
//!
//! Creates the root agent, idle agent, and test agents (ping/pong) during boot.
//! Kernel-mode agents (idle, root, stated, policyd) run in ring 0.
//! User-mode agents (ping, pong, bad) run in ring 3 with per-agent page tables.

use crate::serial_println;
use crate::agent::*;
use crate::capability::*;
use crate::sched;
use crate::mailbox;
use crate::state;
use crate::event;
use crate::agents;
use crate::arch::x86_64::paging;
use crate::arch::x86_64::context::new_user_context;

/// Stack size for each agent (4 KiB for Stage-1).
const AGENT_STACK_SIZE: usize = 4096;

/// Static stacks for agents.
///
/// Each agent gets a fixed 4 KiB stack allocated in BSS. This avoids
/// the need for a dynamic allocator during early boot.
///
/// Safety: each stack is used by exactly one agent. Single-core Stage-1
/// guarantees no concurrent access.
static mut AGENT_STACKS: [[u8; AGENT_STACK_SIZE]; MAX_AGENTS] = [[0u8; AGENT_STACK_SIZE]; MAX_AGENTS];

/// Per-agent kernel stacks for ring 3 agents.
/// When a ring 3 agent takes a syscall or interrupt, the CPU switches
/// to this stack via TSS.rsp0.
static mut KERNEL_STACKS: [[u8; KERNEL_STACK_SIZE]; MAX_AGENTS] = [[0u8; KERNEL_STACK_SIZE]; MAX_AGENTS];

fn kernel_stack_top(agent_index: usize) -> u64 {
    unsafe {
        let ptr = KERNEL_STACKS[agent_index].as_ptr();
        (ptr as u64) + KERNEL_STACK_SIZE as u64
    }
}

/// Compute the stack top (highest address) for a given agent slot index.
///
/// x86_64 stacks grow downward, so the initial RSP must point to the
/// top of the stack allocation.
fn stack_top(agent_index: usize) -> u64 {
    unsafe {
        let ptr = AGENT_STACKS[agent_index].as_ptr();
        (ptr as u64) + AGENT_STACK_SIZE as u64
    }
}

extern "C" {
    fn user_ping_entry();
    fn user_ping_end();
    fn user_pong_entry();
    fn user_pong_end();
    fn user_bad_entry();
    fn user_bad_end();
}

/// User virtual address base for code (16 MB — outside the 0-16 MB
/// identity-mapped huge page region, avoiding conflicts with 2 MB PD entries).
/// Each user agent has its own page table, so all agents share these
/// virtual addresses but map them to different physical frames.
const USER_CODE_VADDR: u64 = 0x0100_0000; // 16 MB
const USER_STACK_VADDR: u64 = 0x0100_1000; // 16 MB + 4 KB

/// Create a user-mode agent with its own address space.
///
/// 1. Creates a new page table (PML4) with kernel mapped as supervisor-only
/// 2. Copies the agent's code to a user-accessible page at USER_CODE_VADDR
/// 3. Allocates a user stack page at USER_STACK_VADDR
/// 4. Maps both with PTE_USER
/// 5. Returns the agent ID
fn create_user_agent(
    parent_id: AgentId,
    code_start: u64,
    code_end: u64,
    agent_slot: usize,
    energy: u64,
    caps: &[(CapType, u16)],
) -> AgentId {
    // 1. Create isolated address space
    let agent_cr3 = paging::create_address_space()
        .expect("Failed to create address space");

    // 2. Allocate user code page and copy agent code
    let code_phys = paging::alloc_frame()
        .expect("Failed to allocate user code page");
    let code_size = (code_end - code_start) as usize;
    let code_size = code_size.min(paging::PAGE_SIZE);
    unsafe {
        core::ptr::write_bytes(code_phys as *mut u8, 0, paging::PAGE_SIZE);
        core::ptr::copy_nonoverlapping(
            code_start as *const u8,
            code_phys as *mut u8,
            code_size,
        );
    }
    // Map code page at USER_CODE_VADDR (not identity-mapped — avoids 2MB huge page conflict)
    paging::map_page(
        agent_cr3, USER_CODE_VADDR, code_phys,
        paging::PTE_PRESENT | paging::PTE_USER,
    ).expect("Failed to map user code page");

    // 3. Allocate user stack page
    let stack_phys = paging::alloc_frame()
        .expect("Failed to allocate user stack page");
    unsafe {
        core::ptr::write_bytes(stack_phys as *mut u8, 0, paging::PAGE_SIZE);
    }
    paging::map_page(
        agent_cr3, USER_STACK_VADDR, stack_phys,
        paging::PTE_PRESENT | paging::PTE_WRITABLE | paging::PTE_USER,
    ).expect("Failed to map user stack page");
    let user_stack_top = USER_STACK_VADDR + paging::PAGE_SIZE as u64;

    // 4. Get kernel stack for this agent
    let k_stack_top = kernel_stack_top(agent_slot);

    // 5. Create the agent (entry point is the user VIRTUAL address)
    let agent_id = create_agent(
        Some(parent_id),
        USER_CODE_VADDR,
        user_stack_top,
        energy,
        64,
    ).expect("Failed to create user agent");

    // 6. Set up user-mode context and metadata
    {
        let agent = get_agent_mut(agent_id).expect("Agent not found");
        agent.mode = AgentMode::User;
        agent.kernel_stack_top = k_stack_top;
        agent.context = new_user_context(USER_CODE_VADDR, user_stack_top, k_stack_top);
        agent.context.cr3 = agent_cr3;

        // Set capabilities
        for (i, &(cap_type, target)) in caps.iter().enumerate() {
            if i < MAX_CAPABILITIES_PER_AGENT {
                agent.capabilities[i] = Some(Capability::new(cap_type, target));
            }
        }
        agent.cap_count = caps.len();
    }

    // 7. Create mailbox and keyspace
    mailbox::create_mailbox(agent_id as MailboxId, agent_id).ok();
    state::create_keyspace(agent_id as u16).ok();

    agent_id
}

/// Perform full system initialization.
///
/// Creates the idle, root, ping, and pong agents with appropriate
/// capabilities and mailboxes, then adds non-idle agents to the run queue.
/// Kernel-mode agents (idle, root, stated, policyd) run in ring 0.
/// User-mode agents (ping, pong, bad) run in ring 3 with isolated address spaces.
pub fn init() {
    serial_println!("[INIT] Creating system agents...");

    // ── Idle agent (agent 0) ────────────────────────────────────────────
    // The idle agent runs when no other agent is ready. It has no
    // capabilities and unlimited energy so it never gets suspended.
    let idle_id = create_agent(
        None,                                // no parent
        agents::idle::idle_entry as *const () as u64,     // entry point
        stack_top(0),                        // stack
        u64::MAX,                            // unlimited energy
        16,                                  // minimal memory quota (pages)
    ).expect("Failed to create idle agent");
    serial_println!("[INIT] Idle agent created: id={}", idle_id);

    // ── Root agent (agent 1) ────────────────────────────────────────────
    let root_caps = create_root_capabilities();
    let root_id = create_agent(
        None,                                  // no parent (root)
        agents::root::root_entry as *const () as u64,       // entry point
        stack_top(1),                          // stack
        1_000_000,                             // large energy budget
        1024,                                  // memory quota (pages)
    ).expect("Failed to create root agent");

    // Grant root capabilities
    {
        let agent = get_agent_mut(root_id).expect("Root agent not found");
        agent.capabilities = root_caps;
        agent.cap_count = ROOT_CAP_COUNT;
    }

    // Create mailbox and keyspace for root
    mailbox::create_mailbox(root_id as MailboxId, root_id).ok();
    state::create_keyspace(root_id as u16).ok();

    serial_println!("[INIT] Root agent created: id={}", root_id);
    event::agent_created(root_id, 0);

    // ── Ping agent (agent 2) ── USER MODE ─────────────────────────────
    let ping_id = create_user_agent(
        root_id,
        user_ping_entry as *const () as u64,
        user_ping_end as *const () as u64,
        2,      // agent slot (for kernel stack)
        10_000, // energy
        &[(CapType::SendMailbox, 3), (CapType::EventEmit, 0)],
    );
    serial_println!("[INIT] Ping agent created: id={} (ring 3)", ping_id);
    event::agent_created(ping_id, root_id);

    // ── Pong agent (agent 3) ── USER MODE ─────────────────────────────
    let pong_id = create_user_agent(
        root_id,
        user_pong_entry as *const () as u64,
        user_pong_end as *const () as u64,
        3,
        10_000,
        &[(CapType::SendMailbox, 2), (CapType::EventEmit, 0)],
    );
    serial_println!("[INIT] Pong agent created: id={} (ring 3)", pong_id);
    event::agent_created(pong_id, root_id);

    // ── Bad agent (agent 4) ── USER MODE ──────────────────────────────
    let bad_id = create_user_agent(
        root_id,
        user_bad_entry as *const () as u64,
        user_bad_end as *const () as u64,
        4,
        10_000,
        &[(CapType::EventEmit, 0)],  // NO send capability
    );
    serial_println!("[INIT] Bad agent created: id={} (ring 3, no send caps)", bad_id);
    event::agent_created(bad_id, root_id);

    // ── Stated agent (agent 5) ── state persistence manager ──────────
    let stated_id = create_agent(
        Some(root_id),
        agents::stated::stated_entry as *const () as u64,
        stack_top(5),
        100_000,    // generous energy budget for system agent
        256,        // memory quota
    ).expect("Failed to create stated agent");
    {
        let agent = get_agent_mut(stated_id).expect("Stated agent not found");
        agent.capabilities[0] = Some(Capability::new(CapType::RecvMailbox, CAP_TARGET_WILDCARD));
        agent.capabilities[1] = Some(Capability::new(CapType::SendMailbox, CAP_TARGET_WILDCARD));
        agent.capabilities[2] = Some(Capability::new(CapType::EventEmit, 0));
        agent.capabilities[3] = Some(Capability::new(CapType::StateRead, CAP_TARGET_WILDCARD));
        agent.capabilities[4] = Some(Capability::new(CapType::StateWrite, CAP_TARGET_WILDCARD));
        agent.cap_count = 5;
    }
    mailbox::create_mailbox(stated_id as MailboxId, stated_id).ok();
    state::create_keyspace(stated_id as u16).ok();
    serial_println!("[INIT] Stated agent created: id={}", stated_id);
    event::agent_created(stated_id, root_id);

    // ── Policyd agent (agent 6) ── policy engine ─────────────────────
    let policyd_id = create_agent(
        Some(root_id),
        agents::policyd::policyd_entry as *const () as u64,
        stack_top(6),
        100_000,
        256,
    ).expect("Failed to create policyd agent");
    {
        let agent = get_agent_mut(policyd_id).expect("Policyd agent not found");
        agent.capabilities[0] = Some(Capability::new(CapType::RecvMailbox, CAP_TARGET_WILDCARD));
        agent.capabilities[1] = Some(Capability::new(CapType::SendMailbox, CAP_TARGET_WILDCARD));
        agent.capabilities[2] = Some(Capability::new(CapType::EventEmit, 0));
        agent.cap_count = 3;
    }
    mailbox::create_mailbox(policyd_id as MailboxId, policyd_id).ok();
    state::create_keyspace(policyd_id as u16).ok();
    serial_println!("[INIT] Policyd agent created: id={}", policyd_id);
    event::agent_created(policyd_id, root_id);

    // ── Set cr3 for KERNEL-MODE agents only ─────────────────────────────
    // User-mode agents already have their own cr3 set in create_user_agent().
    // Kernel-mode agents share the kernel page table.
    let cr3: u64;
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack));
    }
    for &id in &[idle_id, root_id, stated_id, policyd_id] {
        if let Some(agent) = get_agent_mut(id) {
            agent.context.cr3 = cr3;
        }
    }

    // ── Add agents to run queue ─────────────────────────────────────────
    // The idle agent is special-cased by the scheduler and not placed
    // in the normal run queue.
    sched::add_to_run_queue(root_id);
    sched::add_to_run_queue(ping_id);
    sched::add_to_run_queue(pong_id);
    sched::add_to_run_queue(bad_id);
    sched::add_to_run_queue(stated_id);
    sched::add_to_run_queue(policyd_id);

    serial_println!("[INIT] All agents created and queued");
}
