//! AOS Idle Agent
//!
//! The idle agent runs when no other agent is in the Ready state.
//! It executes an infinite HLT loop, allowing the CPU to enter a
//! low-power state until the next interrupt (typically the timer).
//!
//! The idle agent:
//! - Has unlimited energy (never gets suspended)
//! - Has no capabilities (cannot perform any actions)
//! - Is never removed from the system
//! - Is not placed in the normal run queue

/// Idle agent entry point.
///
/// Executes HLT in a loop. Each HLT waits for the next interrupt,
/// at which point the timer handler fires and the scheduler may
/// switch to a ready agent.
pub extern "C" fn idle_entry() -> ! {
    loop {
        unsafe {
            core::arch::asm!("hlt", options(nomem, nostack, preserves_flags));
        }
    }
}
