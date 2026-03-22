//! AOS x86_64 Execution Context
//!
//! Links to the assembly context_switch routine in switch.asm and provides
//! helpers for creating new agent contexts.

use crate::agent::AgentContext;

extern "C" {
    /// Switch CPU context from old to new agent.
    /// Implemented in asm/switch.asm.
    pub fn context_switch(old: *mut AgentContext, new: *const AgentContext);
}

/// Read the current value of CR3 (page table root).
pub fn read_cr3() -> u64 {
    let cr3: u64;
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
    }
    cr3
}

/// Create a new kernel-mode agent context.
///
/// Sets up RIP to the entry point, RSP to the top of the given stack,
/// rflags with IF=1 (interrupts enabled), and CR3 to the current page table.
pub fn new_kernel_context(entry: u64, stack_top: u64) -> AgentContext {
    AgentContext {
        rsp: stack_top,
        rip: entry,
        rflags: 0x200, // IF=1
        cr3: read_cr3(),
        ..AgentContext::zero()
    }
}

/// Create a new user-mode (ring 3) agent context.
///
/// On first context switch, switch.asm jumps to `enter_user_mode` which
/// reads the user entry point and stack from callee-saved registers and
/// performs an iretq to drop to ring 3.
pub fn new_user_context(entry: u64, user_stack_top: u64, kernel_stack_top: u64) -> AgentContext {
    extern "C" { fn enter_user_mode(); }

    AgentContext {
        rsp: kernel_stack_top,                    // initial RSP = kernel stack (for trampoline)
        rip: enter_user_mode as *const () as u64, // first switch jumps here
        r12: entry,                               // user RIP (passed to iretq)
        r13: user_stack_top,                      // user RSP (passed to iretq)
        r14: 0x23,                                // USER_CS (0x20 | RPL=3)
        r15: 0x1B,                                // USER_DS (0x18 | RPL=3)
        rflags: 0x200,                            // IF=1
        cr3: 0,                                   // filled by caller
        ..AgentContext::zero()
    }
}
