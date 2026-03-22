//! eBPF-lite attachment points and program management.
//!
//! Programs are loaded, verified, attached to hook points, and executed
//! when the corresponding kernel event occurs.

use super::types::*;
use super::runtime::EbpfVm;
use super::verifier;

/// Default instruction limit per program execution.
const DEFAULT_MAX_INSNS: usize = 10_000;

/// Where an eBPF program is attached.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AttachPoint {
    /// Filter before syscall N.
    SyscallEntry(u64),
    /// Inspect after syscall N.
    SyscallExit(u64),
    /// Filter sends to mailbox ID.
    MailboxSend(u16),
    /// Filter receives from mailbox ID.
    MailboxRecv(u16),
    /// Validate spawn parameters.
    AgentSpawn,
    /// Periodic policy checks.
    TimerTick,
}

/// A loaded eBPF-lite program.
pub struct AttachedProgram {
    pub program: [Insn; MAX_INSNS],
    pub len: usize,
    pub attach_point: AttachPoint,
    pub active: bool,
}

const MAX_ATTACHED: usize = 16;

// Safety: single-core, no preemption during program table access in Stage-1.
static mut PROGRAMS: [Option<AttachedProgram>; MAX_ATTACHED] = [const { None }; MAX_ATTACHED];

/// Load and attach a verified eBPF program.
///
/// The program is first verified by the static verifier. If verification
/// passes, it is copied into a free slot and marked active.
///
/// Returns the program index on success.
pub fn attach(program: &[Insn], point: AttachPoint) -> Result<usize, EbpfError> {
    // Verify the program
    verifier::verify(program)?;

    // Safety: single-core access
    unsafe {
        // Find a free slot
        for i in 0..MAX_ATTACHED {
            if PROGRAMS[i].is_none() {
                let mut attached = AttachedProgram {
                    program: [Insn {
                        opcode: 0,
                        regs: 0,
                        off: 0,
                        imm: 0,
                    }; MAX_INSNS],
                    len: program.len(),
                    attach_point: point,
                    active: true,
                };
                // Copy the program instructions
                for j in 0..program.len() {
                    attached.program[j] = program[j];
                }
                PROGRAMS[i] = Some(attached);
                return Ok(i);
            }
        }
        Err(EbpfError::NoFreeSlot)
    }
}

/// Detach a program by index.
pub fn detach(index: usize) {
    // Safety: single-core access
    unsafe {
        if index < MAX_ATTACHED {
            if let Some(ref mut prog) = PROGRAMS[index] {
                prog.active = false;
            }
            PROGRAMS[index] = None;
        }
    }
}

/// Run all programs attached at the given point.
///
/// `ctx` is a pointer to the context structure (e.g., SyscallContext).
/// Returns the most restrictive action: DENY > LOG > ALLOW.
pub fn run_at(point: AttachPoint, ctx: u64) -> Action {
    let mut result = Action::Allow;

    // Safety: single-core access
    unsafe {
        for i in 0..MAX_ATTACHED {
            if let Some(ref prog) = PROGRAMS[i] {
                if prog.active && prog.attach_point == point {
                    let mut vm = EbpfVm::new(DEFAULT_MAX_INSNS);
                    match vm.execute(&prog.program[..prog.len], ctx) {
                        Ok(ret) => {
                            let action = Action::from_u64(ret);
                            match action {
                                Action::Deny => return Action::Deny,
                                Action::Log => result = Action::Log,
                                Action::Allow => {}
                            }
                        }
                        Err(_) => {
                            // Program error — default deny
                            return Action::Deny;
                        }
                    }
                }
            }
        }
    }

    result
}

// ─── Context structures passed to eBPF programs ─────────────────────────────

/// Context for syscall entry/exit attachment points.
#[repr(C)]
pub struct SyscallContext {
    pub agent_id: u16,
    pub syscall_num: u64,
    pub arg0: u64,
    pub arg1: u64,
    pub arg2: u64,
}

/// Context for mailbox send/recv attachment points.
#[repr(C)]
pub struct MailboxContext {
    pub sender_id: u16,
    pub target_mailbox: u16,
    pub payload_len: u16,
}

/// Context for agent spawn attachment point.
#[repr(C)]
pub struct SpawnContext {
    pub parent_id: u16,
    pub energy_quota: u64,
    pub mem_quota: u32,
}
