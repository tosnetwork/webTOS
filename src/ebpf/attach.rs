//! eBPF-lite attachment points and program management.
//!
//! Programs are loaded, verified, attached to hook points, and executed
//! when the corresponding kernel event occurs.

use super::types::*;
use super::runtime::EbpfVm;
use super::verifier;
use crate::sync::SpinLock;

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
    pub priority: u8,  // lower value = higher priority, default 128
}

const MAX_ATTACHED: usize = 16;

static PROGRAMS: SpinLock<[Option<AttachedProgram>; MAX_ATTACHED]> =
    SpinLock::new([const { None }; MAX_ATTACHED]);

/// Load and attach a verified eBPF program.
///
/// The program is first verified by the static verifier. If verification
/// passes, it is copied into a free slot and marked active.
///
/// Returns the program index on success.
pub fn attach(program: &[Insn], point: AttachPoint, priority: u8) -> Result<usize, EbpfError> {
    verifier::verify(program)?;

    let mut programs = PROGRAMS.lock();
    for i in 0..MAX_ATTACHED {
        if programs[i].is_none() {
            let mut attached = AttachedProgram {
                program: [Insn { opcode: 0, regs: 0, off: 0, imm: 0 }; MAX_INSNS],
                len: program.len(),
                attach_point: point,
                active: true,
                priority,
            };
            for j in 0..program.len() {
                attached.program[j] = program[j];
            }
            programs[i] = Some(attached);
            return Ok(i);
        }
    }
    Err(EbpfError::NoFreeSlot)
}

/// Detach a program by index.
pub fn detach(index: usize) {
    let mut programs = PROGRAMS.lock();
    if index < MAX_ATTACHED {
        if let Some(ref mut prog) = programs[index] {
            prog.active = false;
        }
        programs[index] = None;
    }
}

/// Run all programs attached at the given point.
///
/// `ctx` is a pointer to the context structure (e.g., SyscallContext).
/// Returns the most restrictive action: DENY > LOG > ALLOW.
/// Programs are executed in priority order (lower value = higher priority).
pub fn run_at(point: AttachPoint, ctx: u64) -> Action {
    let mut result = Action::Allow;
    let programs = PROGRAMS.lock();

    // Collect matching programs sorted by priority
    let mut matched: [(u8, usize); MAX_ATTACHED] = [(255, 0); MAX_ATTACHED];
    let mut count = 0;
    for i in 0..MAX_ATTACHED {
        if let Some(ref prog) = programs[i] {
            if prog.active && prog.attach_point == point {
                matched[count] = (prog.priority, i);
                count += 1;
            }
        }
    }

    // Insertion sort by priority (lower = higher priority)
    for i in 1..count {
        let tmp = matched[i];
        let mut j = i;
        while j > 0 && matched[j - 1].0 > tmp.0 {
            matched[j] = matched[j - 1];
            j -= 1;
        }
        matched[j] = tmp;
    }

    // Execute in priority order
    for k in 0..count {
        let idx = matched[k].1;
        if let Some(ref prog) = programs[idx] {
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
                Err(_) => return Action::Deny,
            }
        }
    }
    result
}

/// Atomically replace an existing program's bytecode.
/// The attach point and priority are preserved.
pub fn replace(index: usize, new_program: &[Insn]) -> Result<(), EbpfError> {
    verifier::verify(new_program)?;

    let mut programs = PROGRAMS.lock();
    if index >= MAX_ATTACHED {
        return Err(EbpfError::OutOfBounds);
    }
    match programs[index] {
        Some(ref mut prog) => {
            // Clear and copy new bytecode
            for i in 0..MAX_INSNS {
                prog.program[i] = Insn { opcode: 0, regs: 0, off: 0, imm: 0 };
            }
            for j in 0..new_program.len() {
                prog.program[j] = new_program[j];
            }
            prog.len = new_program.len();
            Ok(())
        }
        None => Err(EbpfError::OutOfBounds),
    }
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

/// Iterate attached programs and call a callback for each active one.
/// Returns the count of active programs.
pub fn for_each_attached(mut f: impl FnMut(usize, &AttachPoint, usize)) -> usize {
    let programs = PROGRAMS.lock();
    let mut count = 0;
    for i in 0..MAX_ATTACHED {
        if let Some(ref prog) = programs[i] {
            if prog.active {
                f(i, &prog.attach_point, prog.len);
                count += 1;
            }
        }
    }
    count
}
