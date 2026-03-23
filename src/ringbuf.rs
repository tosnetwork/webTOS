//! AOS Kernel Event Ring Buffer
//!
//! Non-blocking circular buffer for audit events. Decouples fast event
//! emission (kernel) from slow consumption (serial output or auditd agent).

use crate::event::Event;

const RING_SIZE: usize = 1024;  // 1024 events, ~56 KB

pub struct EventRing {
    buffer: [Option<Event>; RING_SIZE],
    write_idx: usize,
    read_idx: usize,
    overflow_count: u64,
}

impl EventRing {
    pub const fn new() -> Self {
        EventRing {
            buffer: [const { None }; RING_SIZE],
            write_idx: 0,
            read_idx: 0,
            overflow_count: 0,
        }
    }

    /// Push an event into the ring buffer (non-blocking, O(1)).
    /// If full, overwrites the oldest event and increments overflow counter.
    pub fn push(&mut self, event: Event) {
        self.buffer[self.write_idx % RING_SIZE] = Some(event);
        self.write_idx += 1;

        // If we caught up to the reader, advance the reader (drop oldest)
        if self.write_idx - self.read_idx > RING_SIZE {
            self.read_idx = self.write_idx - RING_SIZE;
            self.overflow_count += 1;
        }
    }

    /// Pop the oldest event from the ring buffer.
    /// Returns None if the buffer is empty.
    pub fn pop(&mut self) -> Option<Event> {
        if self.read_idx >= self.write_idx {
            return None;
        }
        let event = self.buffer[self.read_idx % RING_SIZE].take();
        self.read_idx += 1;
        event
    }

    /// Number of events currently in the buffer.
    pub fn len(&self) -> usize {
        self.write_idx - self.read_idx
    }

    /// Number of events dropped due to overflow.
    pub fn overflows(&self) -> u64 {
        self.overflow_count
    }

    /// Check if the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.read_idx >= self.write_idx
    }
}

// Global ring buffer instance
// Safety: single-core access, protected by cli/sti in emit paths
static mut EVENT_RING: EventRing = EventRing::new();

/// Push an event to the kernel ring buffer.
pub fn ring_push(event: Event) {
    unsafe { EVENT_RING.push(event); }
}

/// Pop an event from the kernel ring buffer.
pub fn ring_pop() -> Option<Event> {
    unsafe { EVENT_RING.pop() }
}

/// Get ring buffer statistics.
pub fn ring_stats() -> (usize, u64) {
    unsafe { (EVENT_RING.len(), EVENT_RING.overflows()) }
}
