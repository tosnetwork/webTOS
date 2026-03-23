//! AOS eBPF-lite text assembler.
//!
//! Parses a line-oriented assembly language and produces a `Vec<Insn>`.
//!
//! # Syntax summary
//!
//! ```text
//! ; comment line
//! mov  r0, 0           ; r0 = immediate
//! mov  r0, r1          ; r0 = r1
//! add  r0, 1           ; r0 += imm
//! add  r0, r1          ; r0 += r1
//! sub  r0, r1          ; r0 -= r1
//! mul  r0, r1          ; r0 *= r1
//! div  r0, r1          ; r0 /= r1
//! mod  r0, r1          ; r0 %= r1
//! and  r0, r1          ; r0 &= r1
//! or   r0, r1          ; r0 |= r1
//! xor  r0, r1          ; r0 ^= r1
//! lsh  r0, 3           ; r0 <<= 3
//! rsh  r0, 3           ; r0 >>= 3
//! neg  r0               ; r0 = -r0
//! jeq  r0, 0, +2       ; if r0 == 0  jump +2 insns
//! jne  r0, 0, +2       ; if r0 != 0  jump +2 insns
//! jgt  r0, r1, +1      ; if r0 >  r1 jump +1
//! jge  r0, r1, +1      ; if r0 >= r1 jump +1
//! jlt  r0, r1, +1      ; if r0 <  r1 jump +1
//! jle  r0, r1, +1      ; if r0 <= r1 jump +1
//! ja   +3              ; unconditional jump +3
//! call 4               ; call helper #4
//! ldxb  r0, [r1+0]     ; r0 = *(u8*) (r1+0)
//! ldxw  r0, [r1+0]     ; r0 = *(u32*)(r1+0)
//! ldxdw r0, [r1+0]     ; r0 = *(u64*)(r1+0)
//! stxb  [r1+0], r0     ; *(u8*) (r1+0) = r0
//! stxw  [r1+0], r0     ; *(u32*)(r1+0) = r0
//! stxdw [r1+0], r0     ; *(u64*)(r1+0) = r0
//! exit                 ; return r0
//! ```

use crate::types::*;

/// An assembly error with file-position context.
#[derive(Debug)]
pub struct AsmError {
    pub line_no: usize,
    pub message: String,
}

impl std::fmt::Display for AsmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "line {}: {}", self.line_no, self.message)
    }
}

impl std::error::Error for AsmError {}

impl AsmError {
    fn at(line_no: usize, msg: impl Into<String>) -> Self {
        AsmError { line_no, message: msg.into() }
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Assemble the source text into a list of instructions.
pub fn assemble(source: &str) -> Result<Vec<Insn>, AsmError> {
    let mut insns = Vec::new();

    for (idx, raw_line) in source.lines().enumerate() {
        let line_no = idx + 1;

        // Strip comments and whitespace.
        let line = match raw_line.split(';').next() {
            Some(s) => s.trim(),
            None => continue,
        };
        if line.is_empty() {
            continue;
        }

        let insn = parse_line(line_no, line)?;
        insns.push(insn);
    }

    Ok(insns)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Parse a single non-empty, comment-stripped line into an `Insn`.
fn parse_line(line_no: usize, line: &str) -> Result<Insn, AsmError> {
    // Split on whitespace — first token is the mnemonic, rest are operands.
    let mut tokens = line.splitn(2, |c: char| c.is_whitespace());
    let mnemonic = tokens.next().unwrap_or("").to_ascii_lowercase();
    let rest     = tokens.next().unwrap_or("").trim();

    match mnemonic.as_str() {
        // -- exit ----------------------------------------------------------
        "exit" => Ok(Insn { opcode: BPF_JMP | BPF_EXIT, regs: 0, off: 0, imm: 0 }),

        // -- ALU64 ---------------------------------------------------------
        "mov" => alu64(line_no, rest, BPF_MOV),
        "add" => alu64(line_no, rest, BPF_ADD),
        "sub" => alu64(line_no, rest, BPF_SUB),
        "mul" => alu64(line_no, rest, BPF_MUL),
        "div" => alu64(line_no, rest, BPF_DIV),
        "mod" => alu64(line_no, rest, BPF_MOD),
        "and" => alu64(line_no, rest, BPF_AND),
        "or"  => alu64(line_no, rest, BPF_OR),
        "xor" => alu64(line_no, rest, BPF_XOR),
        "lsh" => alu64(line_no, rest, BPF_LSH),
        "rsh" => alu64(line_no, rest, BPF_RSH),
        "neg" => {
            // neg rD  — unary, no source operand
            let dst = parse_reg(line_no, rest.trim())?;
            Ok(Insn {
                opcode: BPF_ALU64 | BPF_NEG | BPF_K,
                regs: dst as u8,
                off: 0,
                imm: 0,
            })
        }

        // -- Jumps ---------------------------------------------------------
        "jeq"  => cond_jmp(line_no, rest, BPF_JEQ),
        "jne"  => cond_jmp(line_no, rest, BPF_JNE),
        "jgt"  => cond_jmp(line_no, rest, BPF_JGT),
        "jge"  => cond_jmp(line_no, rest, BPF_JGE),
        "jlt"  => cond_jmp(line_no, rest, BPF_JLT),
        "jle"  => cond_jmp(line_no, rest, BPF_JLE),
        "jset" => cond_jmp(line_no, rest, BPF_JSET),

        "ja" => {
            // ja +N  — unconditional jump
            let off = parse_offset(line_no, rest.trim())?;
            Ok(Insn { opcode: BPF_JMP | BPF_JA, regs: 0, off, imm: 0 })
        }

        "call" => {
            // call <helper_id>
            let id = parse_imm(line_no, rest.trim())?;
            Ok(Insn { opcode: BPF_JMP | BPF_CALL, regs: 0, off: 0, imm: id })
        }

        // -- Memory loads (LDX) -------------------------------------------
        "ldxb"  => ldx(line_no, rest, BPF_B),
        "ldxh"  => ldx(line_no, rest, BPF_H),
        "ldxw"  => ldx(line_no, rest, BPF_W),
        "ldxdw" => ldx(line_no, rest, BPF_DW),

        // -- Memory stores (STX) ------------------------------------------
        "stxb"  => stx(line_no, rest, BPF_B),
        "stxh"  => stx(line_no, rest, BPF_H),
        "stxw"  => stx(line_no, rest, BPF_W),
        "stxdw" => stx(line_no, rest, BPF_DW),

        _ => Err(AsmError::at(line_no, format!("unknown mnemonic '{}'", mnemonic))),
    }
}

// ---------------------------------------------------------------------------
// ALU helpers
// ---------------------------------------------------------------------------

/// Parse `rD, rS` or `rD, imm` for a 64-bit ALU instruction.
fn alu64(line_no: usize, rest: &str, op: u8) -> Result<Insn, AsmError> {
    let (lhs, rhs) = split2(line_no, rest)?;
    let dst = parse_reg(line_no, lhs)?;

    if looks_like_reg(rhs) {
        let src = parse_reg(line_no, rhs)?;
        Ok(Insn {
            opcode: BPF_ALU64 | op | BPF_X,
            regs:   make_regs(dst, src),
            off:    0,
            imm:    0,
        })
    } else {
        let imm = parse_imm(line_no, rhs)?;
        Ok(Insn {
            opcode: BPF_ALU64 | op | BPF_K,
            regs:   dst as u8,
            off:    0,
            imm,
        })
    }
}

// ---------------------------------------------------------------------------
// Conditional jump helpers
// ---------------------------------------------------------------------------

/// Parse `rD, rS/imm, +off` for a conditional jump instruction.
fn cond_jmp(line_no: usize, rest: &str, op: u8) -> Result<Insn, AsmError> {
    let parts = split3(line_no, rest)?;
    let dst = parse_reg(line_no, parts[0])?;
    let off = parse_offset(line_no, parts[2])?;

    if looks_like_reg(parts[1]) {
        let src = parse_reg(line_no, parts[1])?;
        Ok(Insn {
            opcode: BPF_JMP | op | BPF_X,
            regs:   make_regs(dst, src),
            off,
            imm:    0,
        })
    } else {
        let imm = parse_imm(line_no, parts[1])?;
        Ok(Insn {
            opcode: BPF_JMP | op | BPF_K,
            regs:   dst as u8,
            off,
            imm,
        })
    }
}

// ---------------------------------------------------------------------------
// Memory access helpers
// ---------------------------------------------------------------------------

/// Parse `rD, [rS+off]` for an LDX (load) instruction.
fn ldx(line_no: usize, rest: &str, size: u8) -> Result<Insn, AsmError> {
    let (lhs, rhs) = split2(line_no, rest)?;
    let dst = parse_reg(line_no, lhs)?;
    let (src, off) = parse_mem_ref(line_no, rhs)?;
    Ok(Insn {
        opcode: BPF_LDX | BPF_MEM | size,
        regs:   make_regs(dst, src),
        off,
        imm:    0,
    })
}

/// Parse `[rD+off], rS` for an STX (store) instruction.
fn stx(line_no: usize, rest: &str, size: u8) -> Result<Insn, AsmError> {
    let (lhs, rhs) = split2(line_no, rest)?;
    let (dst, off) = parse_mem_ref(line_no, lhs)?;
    let src = parse_reg(line_no, rhs)?;
    Ok(Insn {
        opcode: BPF_STX | BPF_MEM | size,
        regs:   make_regs(dst, src),
        off,
        imm:    0,
    })
}

/// Parse a memory reference like `[r1+8]` or `[r1-4]` or `[r1+0]`.
/// Returns (register_index, offset).
fn parse_mem_ref(line_no: usize, s: &str) -> Result<(usize, i16), AsmError> {
    let s = s.trim();
    let inner = s
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .ok_or_else(|| AsmError::at(line_no, format!("expected [rN+off], got '{}'", s)))?;

    // Split on '+' or '-', keeping the sign.
    let (reg_part, off_part) = if let Some(pos) = inner.rfind('+') {
        (&inner[..pos], &inner[pos..])  // off_part starts with '+'
    } else if let Some(pos) = inner.rfind('-') {
        (&inner[..pos], &inner[pos..])  // off_part starts with '-'
    } else {
        // No offset — treat as [rN+0]
        (inner, "+0")
    };

    let reg = parse_reg(line_no, reg_part.trim())?;
    let off_str = off_part.trim();
    let off: i16 = off_str.parse().map_err(|_| {
        AsmError::at(line_no, format!("invalid offset '{}' in memory reference", off_str))
    })?;

    Ok((reg, off))
}

// ---------------------------------------------------------------------------
// Primitive parsers
// ---------------------------------------------------------------------------

/// True if `s` looks like a register token (`rN`).
fn looks_like_reg(s: &str) -> bool {
    let s = s.trim();
    s.starts_with('r') || s.starts_with('R')
}

/// Parse `rN` → register index 0-10.
fn parse_reg(line_no: usize, s: &str) -> Result<usize, AsmError> {
    let s = s.trim();
    let digits = s
        .strip_prefix('r')
        .or_else(|| s.strip_prefix('R'))
        .ok_or_else(|| AsmError::at(line_no, format!("expected register like r0-r10, got '{}'", s)))?;

    let n: usize = digits.parse().map_err(|_| {
        AsmError::at(line_no, format!("invalid register number '{}'", digits))
    })?;

    if n >= NUM_REGS {
        return Err(AsmError::at(line_no, format!("register r{} out of range (max r{})", n, NUM_REGS - 1)));
    }
    Ok(n)
}

/// Parse a 32-bit immediate value (decimal or hex `0x…`, optionally signed).
fn parse_imm(line_no: usize, s: &str) -> Result<i32, AsmError> {
    let s = s.trim();
    parse_i64(line_no, s).and_then(|v| {
        if v < i32::MIN as i64 || v > i32::MAX as i64 {
            Err(AsmError::at(line_no, format!("immediate {} does not fit in i32", v)))
        } else {
            Ok(v as i32)
        }
    })
}

/// Parse a jump offset (`+N`, `-N`, or just `N`).
fn parse_offset(line_no: usize, s: &str) -> Result<i16, AsmError> {
    let s = s.trim();
    // Strip leading '+' that annotates positive offsets.
    let s = if s.starts_with('+') { &s[1..] } else { s };
    let v: i64 = parse_i64(line_no, s)?;
    if v < i16::MIN as i64 || v > i16::MAX as i64 {
        return Err(AsmError::at(line_no, format!("jump offset {} does not fit in i16", v)));
    }
    Ok(v as i16)
}

/// Parse an integer that may be decimal, hex `0x…`, or binary `0b…`.
fn parse_i64(line_no: usize, s: &str) -> Result<i64, AsmError> {
    let s = s.trim();
    let (neg, s) = if s.starts_with('-') { (true, &s[1..]) } else { (false, s) };

    let abs: u64 = if s.starts_with("0x") || s.starts_with("0X") {
        u64::from_str_radix(&s[2..], 16)
            .map_err(|_| AsmError::at(line_no, format!("invalid hex literal '{}'", s)))?
    } else if s.starts_with("0b") || s.starts_with("0B") {
        u64::from_str_radix(&s[2..], 2)
            .map_err(|_| AsmError::at(line_no, format!("invalid binary literal '{}'", s)))?
    } else {
        s.parse::<u64>()
            .map_err(|_| AsmError::at(line_no, format!("expected number, got '{}'", s)))?
    };

    Ok(if neg { -(abs as i64) } else { abs as i64 })
}

/// Encode dst (low nibble) and src (high nibble) into the `regs` byte.
fn make_regs(dst: usize, src: usize) -> u8 {
    ((src as u8) << 4) | (dst as u8)
}

// ---------------------------------------------------------------------------
// Operand splitters
// ---------------------------------------------------------------------------

/// Split operand list into exactly two comma-separated parts.
fn split2<'a>(line_no: usize, s: &'a str) -> Result<(&'a str, &'a str), AsmError> {
    let mut it = s.splitn(2, ',');
    let a = it.next().map(str::trim)
        .ok_or_else(|| AsmError::at(line_no, "expected two operands".to_string()))?;
    let b = it.next().map(str::trim)
        .ok_or_else(|| AsmError::at(line_no, "expected two operands".to_string()))?;
    if a.is_empty() || b.is_empty() {
        return Err(AsmError::at(line_no, "empty operand".to_string()));
    }
    Ok((a, b))
}

/// Split operand list into exactly three comma-separated parts.
fn split3<'a>(line_no: usize, s: &'a str) -> Result<[&'a str; 3], AsmError> {
    let parts: Vec<&str> = s.splitn(3, ',').map(str::trim).collect();
    if parts.len() < 3 || parts.iter().any(|p| p.is_empty()) {
        return Err(AsmError::at(line_no, "expected three operands".to_string()));
    }
    Ok([parts[0], parts[1], parts[2]])
}
