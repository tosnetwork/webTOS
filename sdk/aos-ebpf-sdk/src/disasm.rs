//! AOS eBPF-lite disassembler.
//!
//! Converts a list of `Insn` values back into human-readable assembly text.

use crate::types::*;

/// Disassemble a list of instructions to a human-readable string.
pub fn disassemble(insns: &[Insn]) -> String {
    let mut out = String::new();
    for (pc, insn) in insns.iter().enumerate() {
        let text = disasm_one(insn);
        out.push_str(&format!("{:4}: {}\n", pc, text));
    }
    out
}

/// Disassemble a single instruction.
pub fn disasm_one(insn: &Insn) -> String {
    let class = insn.opcode & 0x07;
    let op    = insn.opcode & 0xF0;
    let src_k = insn.opcode & 0x08 == 0; // BPF_K: immediate source
    let dst   = insn.dst();
    let src   = insn.src();
    let imm   = insn.imm;
    let off   = insn.off;

    match class {
        // -- ALU64 ---------------------------------------------------------
        BPF_ALU64 => {
            let mnem = alu_mnem(op);
            if op == BPF_NEG {
                return format!("neg  r{}", dst);
            }
            if src_k {
                format!("{}  r{}, {}", mnem, dst, imm)
            } else {
                format!("{}  r{}, r{}", mnem, dst, src)
            }
        }

        // -- ALU32 ---------------------------------------------------------
        BPF_ALU => {
            let mnem = alu_mnem(op);
            if op == BPF_NEG {
                return format!("neg32  r{}", dst);
            }
            if src_k {
                format!("{}32  r{}, {}", mnem, dst, imm)
            } else {
                format!("{}32  r{}, r{}", mnem, dst, src)
            }
        }

        // -- JMP -----------------------------------------------------------
        BPF_JMP => {
            match op {
                BPF_EXIT => "exit".to_string(),
                BPF_CALL => format!("call  {}", imm),
                BPF_JA   => format!("ja    {:+}", off),
                _ => {
                    let mnem = jmp_mnem(op);
                    let off_str = format!("{:+}", off);
                    if src_k {
                        format!("{}  r{}, {}, {}", mnem, dst, imm, off_str)
                    } else {
                        format!("{}  r{}, r{}, {}", mnem, dst, src, off_str)
                    }
                }
            }
        }

        // -- LDX -----------------------------------------------------------
        BPF_LDX => {
            let sz = size_suffix(insn.opcode & 0x18);
            format!("ldx{}  r{}, [r{}{}]", sz, dst, src, signed_off(off))
        }

        // -- STX -----------------------------------------------------------
        BPF_STX => {
            let sz = size_suffix(insn.opcode & 0x18);
            format!("stx{}  [r{}{}], r{}", sz, dst, signed_off(off), src)
        }

        // -- ST (immediate store) -----------------------------------------
        BPF_ST => {
            let sz = size_suffix(insn.opcode & 0x18);
            format!("st{}   [r{}{}], {}", sz, dst, signed_off(off), imm)
        }

        _ => format!("??? opcode=0x{:02x} regs=0x{:02x} off={} imm={}", insn.opcode, insn.regs, off, imm),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn alu_mnem(op: u8) -> &'static str {
    match op {
        BPF_ADD => "add",
        BPF_SUB => "sub",
        BPF_MUL => "mul",
        BPF_DIV => "div",
        BPF_MOD => "mod",
        BPF_MOV => "mov",
        BPF_AND => "and",
        BPF_OR  => "or",
        BPF_XOR => "xor",
        BPF_LSH => "lsh",
        BPF_RSH => "rsh",
        BPF_NEG => "neg",
        _       => "alu?",
    }
}

fn jmp_mnem(op: u8) -> &'static str {
    match op {
        BPF_JEQ  => "jeq",
        BPF_JNE  => "jne",
        BPF_JGT  => "jgt",
        BPF_JGE  => "jge",
        BPF_JLT  => "jlt",
        BPF_JLE  => "jle",
        BPF_JSET => "jset",
        _        => "jmp?",
    }
}

fn size_suffix(size_code: u8) -> &'static str {
    match size_code {
        BPF_B  => "b",
        BPF_H  => "h",
        BPF_W  => "w",
        BPF_DW => "dw",
        _      => "?",
    }
}

/// Format an offset as `+N` / `-N` / `` (empty when zero).
fn signed_off(off: i16) -> String {
    if off == 0 {
        String::new()
    } else if off > 0 {
        format!("+{}", off)
    } else {
        format!("{}", off)  // already has '-'
    }
}
