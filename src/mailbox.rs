//! AOS Mailbox IPC
//!
//! Implements bounded message queues for inter-agent communication.
//! Each agent owns exactly one mailbox in Stage-1 (1:1 binding).
//! Messages carry kernel-stamped sender_id and tick for auditability.

use crate::agent::{
    AgentId, MailboxId, Tick, MAX_AGENTS, MAX_MAILBOX_CAPACITY, MAX_MESSAGE_PAYLOAD,
    E_MAILBOX_FULL, E_INVALID_ARG, E_NO_CAP, E_NOT_FOUND, E_PAYLOAD_TOO_LARGE,
};
use crate::capability::{agent_try_cap, agent_has_cap, CapType};

// ─── Message ────────────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
#[repr(C)]
pub struct Message {
    pub sender_id: AgentId,
    pub tick: Tick,
    pub len: u16,
    pub payload: [u8; MAX_MESSAGE_PAYLOAD],
}

impl Message {
    /// Create a new message from a payload slice.
    ///
    /// `sender_id` and `tick` are set by the kernel, not by the caller.
    pub fn new(sender_id: AgentId, tick: Tick, payload: &[u8]) -> Self {
        let len = payload.len().min(MAX_MESSAGE_PAYLOAD);
        let mut msg = Message {
            sender_id,
            tick,
            len: len as u16,
            payload: [0u8; MAX_MESSAGE_PAYLOAD],
        };
        msg.payload[..len].copy_from_slice(&payload[..len]);
        msg
    }
}

// ─── Mailbox ────────────────────────────────────────────────────────────────

pub struct Mailbox {
    pub id: MailboxId,
    pub owner: AgentId,
    pub buffer: [Option<Message>; MAX_MAILBOX_CAPACITY],
    pub read_pos: usize,
    pub write_pos: usize,
    pub count: usize,
}

impl Mailbox {
    /// Create a new empty mailbox.
    pub fn new(id: MailboxId, owner: AgentId) -> Self {
        Mailbox {
            id,
            owner,
            buffer: [const { None }; MAX_MAILBOX_CAPACITY],
            read_pos: 0,
            write_pos: 0,
            count: 0,
        }
    }

    /// Check if the mailbox is full.
    pub fn is_full(&self) -> bool {
        self.count >= MAX_MAILBOX_CAPACITY
    }

    /// Check if the mailbox is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Enqueue a message into the mailbox ring buffer.
    ///
    /// Returns `Err(E_MAILBOX_FULL)` if the mailbox is at capacity.
    pub fn enqueue(&mut self, msg: Message) -> Result<(), i64> {
        if self.is_full() {
            return Err(E_MAILBOX_FULL);
        }
        self.buffer[self.write_pos] = Some(msg);
        self.write_pos = (self.write_pos + 1) % MAX_MAILBOX_CAPACITY;
        self.count += 1;
        Ok(())
    }

    /// Dequeue the next message from the mailbox ring buffer.
    ///
    /// Returns `None` if the mailbox is empty.
    pub fn dequeue(&mut self) -> Option<Message> {
        if self.is_empty() {
            return None;
        }
        let msg = self.buffer[self.read_pos].take();
        self.read_pos = (self.read_pos + 1) % MAX_MAILBOX_CAPACITY;
        self.count -= 1;
        msg
    }
}

// ─── Global mailbox table ───────────────────────────────────────────────────

// Safety: single-core, no preemption during mailbox access in Stage-1.
static mut MAILBOXES: [Option<Mailbox>; MAX_AGENTS] = [const { None }; MAX_AGENTS];

// ─── Public API ─────────────────────────────────────────────────────────────

/// Create a new mailbox and register it in the global table.
///
/// In Stage-1, the mailbox ID is the same as the agent ID (1:1 binding).
pub fn create_mailbox(id: MailboxId, owner: AgentId) -> Result<(), i64> {
    // Safety: single-core, no preemption during mailbox access
    unsafe {
        let idx = id as usize;
        if idx >= MAX_AGENTS {
            return Err(E_INVALID_ARG);
        }
        if MAILBOXES[idx].is_some() {
            return Err(E_INVALID_ARG);
        }
        MAILBOXES[idx] = Some(Mailbox::new(id, owner));
        Ok(())
    }
}

/// Send a message to a target mailbox (non-blocking).
///
/// 1. Check capability (sender needs CAP_SEND_MAILBOX:target_mailbox)
/// 2. Check payload size <= MAX_MESSAGE_PAYLOAD
/// 3. Check mailbox not full
/// 4. Create message with sender_id and current tick
/// 5. Enqueue
pub fn send_message(sender_id: AgentId, target_mailbox: MailboxId, payload: &[u8]) -> Result<(), i64> {
    // Check payload size
    if payload.len() > MAX_MESSAGE_PAYLOAD {
        return Err(E_PAYLOAD_TOO_LARGE);
    }

    // Check capability: sender needs CAP_SEND_MAILBOX for the target mailbox
    if !agent_try_cap(sender_id, CapType::SendMailbox, target_mailbox) {
        crate::event::cap_denied(sender_id, CapType::SendMailbox as u64, target_mailbox as u64);
        return Err(E_NO_CAP);
    }

    // Safety: single-core, no preemption during mailbox access
    unsafe {
        let idx = target_mailbox as usize;
        if idx >= MAX_AGENTS {
            return Err(E_INVALID_ARG);
        }
        let mailbox = match MAILBOXES[idx].as_mut() {
            Some(m) => m,
            None => return Err(E_INVALID_ARG),
        };

        if mailbox.is_full() {
            return Err(E_MAILBOX_FULL);
        }

        // Get current tick for the message timestamp
        let tick = get_current_tick();
        let msg = Message::new(sender_id, tick, payload);
        mailbox.enqueue(msg)?;

        crate::event::mailbox_send(sender_id, target_mailbox, payload.len() as u64);
        Ok(())
    }
}

/// Receive a message from a mailbox (non-blocking dequeue).
///
/// An agent always has implicit recv permission for its own mailbox.
/// Receiving from another agent's mailbox requires CAP_RECV_MAILBOX.
/// Returns `Err(E_NOT_FOUND)` if the mailbox is empty (caller handles blocking).
/// Returns `Err(E_NO_CAP)` if the agent lacks permission.
pub fn recv_message(agent_id: AgentId, mailbox_id: MailboxId) -> Result<Message, i64> {
    // Check capability: implicit for own mailbox, otherwise needs CAP_RECV_MAILBOX
    if agent_id != mailbox_id {
        if !agent_has_cap(agent_id, CapType::RecvMailbox, mailbox_id) {
            crate::event::cap_denied(agent_id, CapType::RecvMailbox as u64, mailbox_id as u64);
            return Err(E_NO_CAP);
        }
    }

    // Safety: single-core, no preemption during mailbox access
    unsafe {
        let idx = mailbox_id as usize;
        if idx >= MAX_AGENTS {
            return Err(E_INVALID_ARG);
        }
        let mailbox = match MAILBOXES[idx].as_mut() {
            Some(m) => m,
            None => return Err(E_INVALID_ARG),
        };

        match mailbox.dequeue() {
            Some(msg) => {
                crate::event::mailbox_recv(agent_id, mailbox_id, msg.len as u64);
                Ok(msg)
            }
            None => Err(E_NOT_FOUND),
        }
    }
}

/// Destroy a mailbox and free its slot.
pub fn destroy_mailbox(id: MailboxId) {
    // Safety: single-core, no preemption during mailbox access
    unsafe {
        let idx = id as usize;
        if idx < MAX_AGENTS {
            MAILBOXES[idx] = None;
        }
    }
}

/// Get a reference to a mailbox by ID (for scheduler use, e.g., checking emptiness).
pub fn get_mailbox(id: MailboxId) -> Option<&'static Mailbox> {
    // Safety: single-core, no preemption during mailbox access
    unsafe {
        let idx = id as usize;
        if idx >= MAX_AGENTS {
            return None;
        }
        MAILBOXES[idx].as_ref()
    }
}

/// Get the owner agent ID of a mailbox.
///
/// Used by syscall.rs to unblock a receiver when a message is sent.
pub fn get_mailbox_owner(id: MailboxId) -> Option<AgentId> {
    get_mailbox(id).map(|m| m.owner)
}

// ─── Internal helpers ───────────────────────────────────────────────────────

/// Get the current tick count.
///
/// Wraps the arch timer to avoid direct arch dependency in the public API.
/// Falls back to 0 if the timer is not yet initialized.
fn get_current_tick() -> Tick {
    crate::arch::x86_64::timer::get_ticks()
}
