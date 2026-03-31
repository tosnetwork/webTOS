//! eBPF-lite static verifier.
//!
//! Ensures programs terminate and don't access invalid memory before loading.
//! Rejects backward jumps (no loops) for guaranteed termination.

use super::types::*;

#[inline(never)]
fn is_alu_class(opcode: u8) -> bool {
    let class = opcode & 0x07;
    class == BPF_ALU || class == BPF_ALU64
}

#[inline(never)]
fn is_jmp_class(opcode: u8) -> bool {
    (opcode & 0x07) == BPF_JMP
}

#[inline(never)]
fn is_ldx_class(opcode: u8) -> bool {
    (opcode & 0x07) == BPF_LDX
}

#[inline(never)]
fn is_st_class(opcode: u8) -> bool {
    (opcode & 0x07) == BPF_ST
}

#[inline(never)]
fn is_stx_class(opcode: u8) -> bool {
    (opcode & 0x07) == BPF_STX
}

#[inline(never)]
fn is_ld_class(opcode: u8) -> bool {
    (opcode & 0x07) == BPF_LD
}

#[inline(never)]
fn is_cond_jump_op(op: u8) -> bool {
    op == BPF_JEQ
        || op == BPF_JGT
        || op == BPF_JGE
        || op == BPF_JSET
        || op == BPF_JNE
        || op == BPF_JLT
        || op == BPF_JLE
        || op == BPF_JSGT
        || op == BPF_JSGE
        || op == BPF_JSLT
        || op == BPF_JSLE
}

#[inline(always)]
fn validate_jump_target(pc: usize, program_len: usize, off: i16) -> Result<usize, EbpfError> {
    let target = pc as i64 + 1 + off as i64;
    if target < 0 || target as usize >= program_len {
        return Err(EbpfError::VerificationFailed("jump target out of bounds"));
    }

    let target = target as usize;
    if target <= pc {
        return Err(EbpfError::VerificationFailed(
            "backward jump detected (no loops allowed)",
        ));
    }

    Ok(target)
}

#[inline(always)]
fn validate_reg_range(reg: usize) -> Result<(), EbpfError> {
    if reg >= NUM_REGS {
        Err(EbpfError::InvalidRegister(reg as u8))
    } else {
        Ok(())
    }
}

#[inline(always)]
fn validate_writable_dst(dst: usize) -> Result<(), EbpfError> {
    validate_reg_range(dst)?;
    if dst == 10 {
        return Err(EbpfError::VerificationFailed(
            "r10 (frame pointer) is read-only",
        ));
    }
    Ok(())
}

/// Verify an eBPF-lite program before loading.
///
/// Returns `Ok(())` if the program is safe to execute.
///
/// Checks performed:
/// 1. Program is non-empty and within MAX_INSNS
/// 2. Last instruction must be BPF_EXIT
/// 3. All jump targets are within bounds
/// 4. No backward jumps (ensures termination — simplified DAG check)
/// 5. All register accesses are valid (0-10)
/// 6. r10 is never written (frame pointer is read-only)
pub fn verify(program: &[Insn]) -> Result<(), EbpfError> {
    if program.is_empty() || program.len() > MAX_INSNS {
        return Err(EbpfError::ProgramTooLarge);
    }

    // Last instruction must be BPF_EXIT
    let last = &program[program.len() - 1];
    let last_class = last.opcode & 0x07;
    let last_op = last.opcode & 0xF0;
    if last_class != BPF_JMP || last_op != BPF_EXIT {
        return Err(EbpfError::VerificationFailed(
            "last instruction must be BPF_EXIT",
        ));
    }

    let mut skip_next = false;
    for (pc, insn) in program.iter().enumerate() {
        if skip_next {
            skip_next = false;
            continue;
        }
        let opcode = insn.opcode;
        let op = insn.opcode & 0xF0;

        // Validate register indices
        let dst = insn.dst();
        let src = insn.src();

        if is_alu_class(opcode) {
            validate_writable_dst(dst)?;
            if insn.opcode & BPF_X != 0 && op != BPF_NEG {
                validate_reg_range(src)?;
            }
            continue;
        }

        if is_jmp_class(opcode) {
            if op == BPF_EXIT || op == BPF_CALL {
                continue;
            }

            if op == BPF_JA {
                validate_jump_target(pc, program.len(), insn.off)?;
                continue;
            }

            if is_cond_jump_op(op) {
                if insn.opcode & BPF_X != 0 {
                    validate_reg_range(src)?;
                }
                validate_jump_target(pc, program.len(), insn.off)?;
                continue;
            }

            return Err(EbpfError::InvalidOpcode(insn.opcode));
        }

        if is_ldx_class(opcode) {
            validate_writable_dst(dst).map_err(|_| {
                EbpfError::VerificationFailed("invalid or read-only destination register")
            })?;
            validate_reg_range(src)?;
            continue;
        }

        if is_st_class(opcode) {
            validate_reg_range(dst)?;
            continue;
        }

        if is_stx_class(opcode) {
            validate_reg_range(dst)?;
            validate_reg_range(src)?;
            continue;
        }

        if is_ld_class(opcode) {
            if insn.opcode != 0x18 {
                return Err(EbpfError::InvalidOpcode(insn.opcode));
            }
            if pc + 1 >= program.len() {
                return Err(EbpfError::VerificationFailed(
                    "BPF_LD_IMM64 at end of program (missing second instruction)",
                ));
            }
            validate_writable_dst(dst)?;
            skip_next = true;
            continue;
        }

        return Err(EbpfError::InvalidOpcode(insn.opcode));
    }

    Ok(())
}
