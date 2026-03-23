//! Offline eBPF-lite static verifier.
//!
//! Mirrors the logic from `src/ebpf/verifier.rs` in the AOS kernel so that
//! the SDK can reject invalid programs before they are ever shipped to a
//! running kernel.
//!
//! Checks performed:
//! 1. Program is non-empty and within MAX_INSNS (256 instructions)
//! 2. Last instruction must be BPF_EXIT
//! 3. All jump targets are within program bounds
//! 4. No backward jumps (ensures termination — simplified DAG check)
//! 5. All register accesses use valid indices (0-10)
//! 6. r10 is never used as a write destination (frame pointer is read-only)

use crate::types::*;

/// A human-readable verification error.
#[derive(Debug)]
pub struct VerifyError {
    pub message: String,
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "verification failed: {}", self.message)
    }
}

impl std::error::Error for VerifyError {}

impl VerifyError {
    fn new(msg: impl Into<String>) -> Self {
        VerifyError { message: msg.into() }
    }
}

/// Verify an eBPF-lite program before writing it to a binary.
///
/// Returns `Ok(())` when the program passes all static checks, or a
/// `VerifyError` describing the first problem found.
pub fn verify(program: &[Insn]) -> Result<(), VerifyError> {
    if program.is_empty() {
        return Err(VerifyError::new("program is empty"));
    }
    if program.len() > MAX_INSNS {
        return Err(VerifyError::new(format!(
            "program too large: {} instructions (max {})",
            program.len(),
            MAX_INSNS
        )));
    }

    // Last instruction must be BPF_EXIT.
    let last = &program[program.len() - 1];
    let last_class = last.opcode & 0x07;
    let last_op = last.opcode & 0xF0;
    if last_class != BPF_JMP || last_op != BPF_EXIT {
        return Err(VerifyError::new(
            "last instruction must be 'exit' (BPF_EXIT)",
        ));
    }

    for (pc, insn) in program.iter().enumerate() {
        let class = insn.opcode & 0x07;
        let op    = insn.opcode & 0xF0;
        let dst   = insn.dst();
        let src   = insn.src();

        match class {
            BPF_ALU | BPF_ALU64 => {
                if dst >= NUM_REGS {
                    return Err(VerifyError::new(format!(
                        "pc={}: invalid destination register r{}",
                        pc, dst
                    )));
                }
                if dst == 10 {
                    return Err(VerifyError::new(format!(
                        "pc={}: r10 (frame pointer) is read-only",
                        pc
                    )));
                }
                // Register-source instructions (BPF_X) need a valid src register,
                // except for NEG which has no source.
                if insn.opcode & BPF_X != 0 && op != BPF_NEG {
                    if src >= NUM_REGS {
                        return Err(VerifyError::new(format!(
                            "pc={}: invalid source register r{}",
                            pc, src
                        )));
                    }
                }
            }

            BPF_JMP => {
                match op {
                    BPF_EXIT => {
                        // Valid; no operand constraints.
                    }
                    BPF_CALL => {
                        // Helper call — imm is the helper ID.
                        // Validated at runtime; nothing to check statically.
                    }
                    BPF_JA => {
                        // Unconditional forward jump.
                        let target = pc as i64 + 1 + insn.off as i64;
                        if target < 0 || target as usize >= program.len() {
                            return Err(VerifyError::new(format!(
                                "pc={}: jump target {} is out of bounds (program len={})",
                                pc, target, program.len()
                            )));
                        }
                        if target as usize <= pc {
                            return Err(VerifyError::new(format!(
                                "pc={}: backward jump detected (no loops allowed)",
                                pc
                            )));
                        }
                    }
                    BPF_JEQ | BPF_JGT | BPF_JGE | BPF_JSET | BPF_JNE | BPF_JLT | BPF_JLE => {
                        // Conditional jump.
                        if insn.opcode & BPF_X != 0 {
                            if src >= NUM_REGS {
                                return Err(VerifyError::new(format!(
                                    "pc={}: invalid source register r{}",
                                    pc, src
                                )));
                            }
                        }
                        let target = pc as i64 + 1 + insn.off as i64;
                        if target < 0 || target as usize >= program.len() {
                            return Err(VerifyError::new(format!(
                                "pc={}: jump target {} is out of bounds (program len={})",
                                pc, target, program.len()
                            )));
                        }
                        if target as usize <= pc {
                            return Err(VerifyError::new(format!(
                                "pc={}: backward jump detected (no loops allowed)",
                                pc
                            )));
                        }
                    }
                    _ => {
                        return Err(VerifyError::new(format!(
                            "pc={}: unknown JMP opcode 0x{:02x}",
                            pc, insn.opcode
                        )));
                    }
                }
            }

            BPF_LDX => {
                if dst >= NUM_REGS || dst == 10 {
                    return Err(VerifyError::new(format!(
                        "pc={}: invalid or read-only destination register r{}",
                        pc, dst
                    )));
                }
                if src >= NUM_REGS {
                    return Err(VerifyError::new(format!(
                        "pc={}: invalid source register r{}",
                        pc, src
                    )));
                }
            }

            BPF_ST => {
                if dst >= NUM_REGS {
                    return Err(VerifyError::new(format!(
                        "pc={}: invalid destination register r{}",
                        pc, dst
                    )));
                }
            }

            BPF_STX => {
                if dst >= NUM_REGS {
                    return Err(VerifyError::new(format!(
                        "pc={}: invalid destination register r{}",
                        pc, dst
                    )));
                }
                if src >= NUM_REGS {
                    return Err(VerifyError::new(format!(
                        "pc={}: invalid source register r{}",
                        pc, src
                    )));
                }
            }

            _ => {
                return Err(VerifyError::new(format!(
                    "pc={}: unknown instruction class in opcode 0x{:02x}",
                    pc, insn.opcode
                )));
            }
        }
    }

    Ok(())
}
