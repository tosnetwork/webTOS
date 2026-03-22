//! AOS Trap Handling
//!
//! Provides high-level trap and fault handling logic for the kernel.
//! The actual interrupt stubs and IDT setup live in arch::x86_64::idt.
//! This module provides the kernel-level policy for handling agent faults.
//!
//! The assembly stubs in trap_entry.asm push a uniform TrapFrame onto the
//! stack and call `trap_handler_common`. This module defines that frame
//! layout and the common handler.

use crate::serial_println;
use crate::agent::*;

// ─── TrapFrame ──────────────────────────────────────────────────────────────

/// Uniform trap/interrupt stack frame, matching the layout pushed by
/// trap_entry.asm (see that file for byte-offset documentation).
///
/// The registers are listed in the order they appear on the stack
/// (lowest address first), which is the reverse of the push order.
#[repr(C)]
pub struct TrapFrame {
    // Pushed by trap_common (in push order, so reversed on stack)
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rbp: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rbx: u64,
    pub rax: u64,
    // Pushed by stub
    pub vector: u64,
    pub error_code: u64,
    // Pushed by CPU (interrupt frame)
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

// ─── Common trap handler (called from assembly) ─────────────────────────────

/// Common trap handler called by trap_entry.asm after saving registers.
///
/// `frame` points to the TrapFrame on the current stack. For CPU exceptions
/// (vectors 0-19), this handler faults the current agent and reschedules.
/// For hardware interrupts (vectors 32+), it dispatches to device handlers.
#[no_mangle]
pub extern "C" fn trap_handler_common(frame: *const TrapFrame) {
    let frame = unsafe { &*frame };
    let vector = frame.vector;

    match vector {
        // ── CPU exceptions (vectors 0-19) ───────────────────────────────
        0..=19 => {
            let agent_id = crate::sched::current();
            serial_println!(
                "[TRAP] Exception vector={} error_code={:#x} agent={} rip={:#x}",
                vector, frame.error_code, agent_id, frame.rip
            );

            if agent_id != IDLE_AGENT_ID {
                // Fault the agent and reschedule
                handle_agent_fault(agent_id, vector);
                crate::sched::schedule();
            } else {
                // Fault in idle agent or kernel -- fatal
                serial_println!("[TRAP] FATAL: exception in idle/kernel context, halting");
                loop {
                    unsafe { core::arch::asm!("hlt"); }
                }
            }
        }

        // ── Timer interrupt (IRQ0, vector 32) ───────────────────────────
        32 => {
            crate::sched::timer_tick();
            // Send EOI to PIC
            unsafe {
                core::arch::asm!(
                    "mov al, 0x20",
                    "out 0x20, al",
                    options(nomem, nostack)
                );
            }
        }

        // ── Keyboard interrupt (IRQ1, vector 33) ────────────────────────
        33 => {
            // Read scancode to acknowledge the interrupt
            let _scancode: u8;
            unsafe {
                core::arch::asm!(
                    "in al, 0x60",
                    out("al") _scancode,
                    options(nomem, nostack)
                );
                // Send EOI
                core::arch::asm!(
                    "mov al, 0x20",
                    "out 0x20, al",
                    options(nomem, nostack)
                );
            }
        }

        _ => {
            serial_println!("[TRAP] Unhandled vector {}", vector);
        }
    }
}

// ─── Agent fault handler ────────────────────────────────────────────────────

/// Handle an agent fault.
///
/// Marks the agent as Faulted and removes it from the run queue.
pub fn handle_agent_fault(agent_id: AgentId, fault_type: u64) {
    serial_println!(
        "[TRAP] Agent {} faulted with type {}",
        agent_id, fault_type
    );

    terminate_agent(agent_id, AgentStatus::Faulted);
    crate::event::agent_faulted(agent_id, fault_type);
    crate::sched::remove_from_run_queue(agent_id);
}
