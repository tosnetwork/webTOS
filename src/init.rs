//! AOS System Initialization
//!
//! Creates the root agent, idle agent, and test agents (ping/pong) during boot.
//! Allocates static stacks and sets up mailboxes, keyspaces, and capabilities
//! for each agent.

use crate::serial_println;
use crate::agent::*;
use crate::capability::*;
use crate::sched;
use crate::mailbox;
use crate::state;
use crate::event;
use crate::agents;

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

/// Perform full system initialization.
///
/// Creates the idle, root, ping, and pong agents with appropriate
/// capabilities and mailboxes, then adds non-idle agents to the run queue.
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

    // ── Ping agent (agent 2) ────────────────────────────────────────────
    let ping_id = create_agent(
        Some(root_id),
        agents::ping::ping_entry as *const () as u64,
        stack_top(2),
        10_000,
        64,
    ).expect("Failed to create ping agent");

    // Grant capabilities to ping: send to pong's mailbox (3), emit events
    {
        let agent = get_agent_mut(ping_id).expect("Ping agent not found");
        agent.capabilities[0] = Some(Capability::new(CapType::SendMailbox, 3)); // send to pong
        agent.capabilities[1] = Some(Capability::new(CapType::EventEmit, 0));
        agent.cap_count = 2;
    }
    mailbox::create_mailbox(ping_id as MailboxId, ping_id).ok();
    state::create_keyspace(ping_id as u16).ok();
    serial_println!("[INIT] Ping agent created: id={}", ping_id);
    event::agent_created(ping_id, root_id);

    // ── Pong agent (agent 3) ────────────────────────────────────────────
    let pong_id = create_agent(
        Some(root_id),
        agents::pong::pong_entry as *const () as u64,
        stack_top(3),
        10_000,
        64,
    ).expect("Failed to create pong agent");

    // Grant capabilities to pong: send to ping's mailbox (2), emit events
    {
        let agent = get_agent_mut(pong_id).expect("Pong agent not found");
        agent.capabilities[0] = Some(Capability::new(CapType::SendMailbox, 2)); // send to ping
        agent.capabilities[1] = Some(Capability::new(CapType::EventEmit, 0));
        agent.cap_count = 2;
    }
    mailbox::create_mailbox(pong_id as MailboxId, pong_id).ok();
    state::create_keyspace(pong_id as u16).ok();
    serial_println!("[INIT] Pong agent created: id={}", pong_id);
    event::agent_created(pong_id, root_id);

    // ── Bad agent (agent 4) ── Demo 2: capability denial ────────────────
    let bad_id = create_agent(
        Some(root_id),
        agents::bad::bad_entry as *const () as u64,
        stack_top(4),
        10_000,
        64,
    ).expect("Failed to create bad agent");

    // Deliberately grant NO send capabilities — only EventEmit
    {
        let agent = get_agent_mut(bad_id).expect("Bad agent not found");
        agent.capabilities[0] = Some(Capability::new(CapType::EventEmit, 0));
        agent.cap_count = 1;
    }
    mailbox::create_mailbox(bad_id as MailboxId, bad_id).ok();
    state::create_keyspace(bad_id as u16).ok();
    serial_println!("[INIT] Bad agent created: id={} (no send caps)", bad_id);
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

    // ── Set cr3 for all agents ──────────────────────────────────────────
    // In Stage-1 all agents share the kernel page table. Read the current
    // CR3 (set up by arch::init) and store it in each agent's context so
    // that context_switch can restore it correctly.
    let cr3: u64;
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack));
    }

    for &id in &[idle_id, root_id, ping_id, pong_id, bad_id, stated_id, policyd_id] {
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
