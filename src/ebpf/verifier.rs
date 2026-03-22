//! eBPF-lite static verifier.
//!
//! Ensures programs terminate and don't access invalid memory before loading.
//! Rejects backward jumps (no loops) for guaranteed termination.

use super::types::*;

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

    for (pc, insn) in program.iter().enumerate() {
        let class = insn.opcode & 0x07;
        let op = insn.opcode & 0xF0;

        // Validate register indices
        let dst = insn.dst();
        let src = insn.src();

        match class {
            BPF_ALU | BPF_ALU64 => {
                if dst >= NUM_REGS {
                    return Err(EbpfError::InvalidRegister(dst as u8));
                }
                // r10 is read-only
                if dst == 10 {
                    return Err(EbpfError::VerificationFailed(
                        "r10 (frame pointer) is read-only",
                    ));
                }
                if insn.opcode & BPF_X != 0 && op != BPF_NEG {
                    if src >= NUM_REGS {
                        return Err(EbpfError::InvalidRegister(src as u8));
                    }
                }
            }
            BPF_JMP => {
                match op {
                    BPF_EXIT => {
                        // Valid, no further checks
                    }
                    BPF_CALL => {
                        // Helper call — imm is the helper ID, validated at runtime
                    }
                    BPF_JA => {
                        // Unconditional jump
                        let target = pc as i64 + 1 + insn.off as i64;
                        if target < 0 || target as usize >= program.len() {
                            return Err(EbpfError::VerificationFailed(
                                "jump target out of bounds",
                            ));
                        }
                        // No backward jumps
                        if (target as usize) <= pc {
                            return Err(EbpfError::VerificationFailed(
                                "backward jump detected (no loops allowed)",
                            ));
                        }
                    }
                    BPF_JEQ | BPF_JGT | BPF_JGE | BPF_JSET | BPF_JNE | BPF_JLT | BPF_JLE => {
                        // Conditional jump
                        if insn.opcode & BPF_X != 0 {
                            if src >= NUM_REGS {
                                return Err(EbpfError::InvalidRegister(src as u8));
                            }
                        }
                        let target = pc as i64 + 1 + insn.off as i64;
                        if target < 0 || target as usize >= program.len() {
                            return Err(EbpfError::VerificationFailed(
                                "jump target out of bounds",
                            ));
                        }
                        // No backward jumps
                        if (target as usize) <= pc {
                            return Err(EbpfError::VerificationFailed(
                                "backward jump detected (no loops allowed)",
                            ));
                        }
                    }
                    _ => {
                        return Err(EbpfError::InvalidOpcode(insn.opcode));
                    }
                }
            }
            BPF_LDX => {
                if dst >= NUM_REGS || dst == 10 {
                    return Err(EbpfError::VerificationFailed(
                        "invalid or read-only destination register",
                    ));
                }
                if src >= NUM_REGS {
                    return Err(EbpfError::InvalidRegister(src as u8));
                }
            }
            BPF_ST => {
                if dst >= NUM_REGS {
                    return Err(EbpfError::InvalidRegister(dst as u8));
                }
            }
            BPF_STX => {
                if dst >= NUM_REGS {
                    return Err(EbpfError::InvalidRegister(dst as u8));
                }
                if src >= NUM_REGS {
                    return Err(EbpfError::InvalidRegister(src as u8));
                }
            }
            _ => {
                return Err(EbpfError::InvalidOpcode(insn.opcode));
            }
        }
    }

    Ok(())
}
