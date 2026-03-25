//! Numeric instruction execution (opcodes 0x45-0xC4, float comparison/arithmetic/conversion).

use super::*;

/// Execute a numeric instruction (0x45-0xC4 range).
/// Called from step() for opcodes in the numeric range.
pub(super) fn execute_numeric(inst: &mut WasmInstance, opcode: u8) -> ExecResult {
    macro_rules! try_exec {
        ($expr:expr) => {
            match $expr {
                Ok(v) => v,
                Err(e) => return ExecResult::Trap(e),
            }
        };
    }

    match opcode {
    // ── i32 Comparison ──────────────────────────────────────
    0x45 => {
        // i32.eqz
        let a = try_exec!(inst.pop_i32());
        try_exec!(inst.push(Value::I32(if a == 0 { 1 } else { 0 })));
    }
    0x46 => {
        // i32.eq
        let b = try_exec!(inst.pop_i32());
        let a = try_exec!(inst.pop_i32());
        try_exec!(inst.push(Value::I32(if a == b { 1 } else { 0 })));
    }
    0x47 => {
        // i32.ne
        let b = try_exec!(inst.pop_i32());
        let a = try_exec!(inst.pop_i32());
        try_exec!(inst.push(Value::I32(if a != b { 1 } else { 0 })));
    }
    0x48 => {
        // i32.lt_s
        let b = try_exec!(inst.pop_i32());
        let a = try_exec!(inst.pop_i32());
        try_exec!(inst.push(Value::I32(if a < b { 1 } else { 0 })));
    }
    0x49 => {
        // i32.lt_u
        let b = try_exec!(inst.pop_i32());
        let a = try_exec!(inst.pop_i32());
        try_exec!(inst.push(Value::I32(if (a as u32) < (b as u32) { 1 } else { 0 })));
    }
    0x4A => {
        // i32.gt_s
        let b = try_exec!(inst.pop_i32());
        let a = try_exec!(inst.pop_i32());
        try_exec!(inst.push(Value::I32(if a > b { 1 } else { 0 })));
    }
    0x4B => {
        // i32.gt_u
        let b = try_exec!(inst.pop_i32());
        let a = try_exec!(inst.pop_i32());
        try_exec!(inst.push(Value::I32(if (a as u32) > (b as u32) { 1 } else { 0 })));
    }
    0x4C => {
        // i32.le_s
        let b = try_exec!(inst.pop_i32());
        let a = try_exec!(inst.pop_i32());
        try_exec!(inst.push(Value::I32(if a <= b { 1 } else { 0 })));
    }
    0x4D => {
        // i32.le_u
        let b = try_exec!(inst.pop_i32());
        let a = try_exec!(inst.pop_i32());
        try_exec!(inst.push(Value::I32(if (a as u32) <= (b as u32) { 1 } else { 0 })));
    }
    0x4E => {
        // i32.ge_s
        let b = try_exec!(inst.pop_i32());
        let a = try_exec!(inst.pop_i32());
        try_exec!(inst.push(Value::I32(if a >= b { 1 } else { 0 })));
    }
    0x4F => {
        // i32.ge_u
        let b = try_exec!(inst.pop_i32());
        let a = try_exec!(inst.pop_i32());
        try_exec!(inst.push(Value::I32(if (a as u32) >= (b as u32) { 1 } else { 0 })));
    }

    // ── i64 Comparison ──────────────────────────────────────
    0x50 => {
        // i64.eqz
        let a = try_exec!(inst.pop_i64());
        try_exec!(inst.push(Value::I32(if a == 0 { 1 } else { 0 })));
    }
    0x51 => {
        // i64.eq
        let b = try_exec!(inst.pop_i64());
        let a = try_exec!(inst.pop_i64());
        try_exec!(inst.push(Value::I32(if a == b { 1 } else { 0 })));
    }
    0x52 => {
        // i64.ne
        let b = try_exec!(inst.pop_i64());
        let a = try_exec!(inst.pop_i64());
        try_exec!(inst.push(Value::I32(if a != b { 1 } else { 0 })));
    }
    0x53 => {
        // i64.lt_s
        let b = try_exec!(inst.pop_i64());
        let a = try_exec!(inst.pop_i64());
        try_exec!(inst.push(Value::I32(if a < b { 1 } else { 0 })));
    }
    0x54 => {
        // i64.lt_u
        let b = try_exec!(inst.pop_i64());
        let a = try_exec!(inst.pop_i64());
        try_exec!(inst.push(Value::I32(if (a as u64) < (b as u64) { 1 } else { 0 })));
    }
    0x55 => {
        // i64.gt_s
        let b = try_exec!(inst.pop_i64());
        let a = try_exec!(inst.pop_i64());
        try_exec!(inst.push(Value::I32(if a > b { 1 } else { 0 })));
    }
    0x56 => {
        // i64.gt_u
        let b = try_exec!(inst.pop_i64());
        let a = try_exec!(inst.pop_i64());
        try_exec!(inst.push(Value::I32(if (a as u64) > (b as u64) { 1 } else { 0 })));
    }
    0x57 => {
        // i64.le_s
        let b = try_exec!(inst.pop_i64());
        let a = try_exec!(inst.pop_i64());
        try_exec!(inst.push(Value::I32(if a <= b { 1 } else { 0 })));
    }
    0x58 => {
        // i64.le_u
        let b = try_exec!(inst.pop_i64());
        let a = try_exec!(inst.pop_i64());
        try_exec!(inst.push(Value::I32(if (a as u64) <= (b as u64) { 1 } else { 0 })));
    }
    0x59 => {
        // i64.ge_s
        let b = try_exec!(inst.pop_i64());
        let a = try_exec!(inst.pop_i64());
        try_exec!(inst.push(Value::I32(if a >= b { 1 } else { 0 })));
    }
    0x5A => {
        // i64.ge_u
        let b = try_exec!(inst.pop_i64());
        let a = try_exec!(inst.pop_i64());
        try_exec!(inst.push(Value::I32(if (a as u64) >= (b as u64) { 1 } else { 0 })));
    }

    // ── i32 Arithmetic ──────────────────────────────────────
    0x67 => {
        // i32.clz
        let a = try_exec!(inst.pop_i32());
        try_exec!(inst.push(Value::I32((a as u32).leading_zeros() as i32)));
    }
    0x68 => {
        // i32.ctz
        let a = try_exec!(inst.pop_i32());
        try_exec!(inst.push(Value::I32((a as u32).trailing_zeros() as i32)));
    }
    0x69 => {
        // i32.popcnt
        let a = try_exec!(inst.pop_i32());
        try_exec!(inst.push(Value::I32((a as u32).count_ones() as i32)));
    }
    0x6A => {
        // i32.add
        let b = try_exec!(inst.pop_i32());
        let a = try_exec!(inst.pop_i32());
        try_exec!(inst.push(Value::I32(a.wrapping_add(b))));
    }
    0x6B => {
        // i32.sub
        let b = try_exec!(inst.pop_i32());
        let a = try_exec!(inst.pop_i32());
        try_exec!(inst.push(Value::I32(a.wrapping_sub(b))));
    }
    0x6C => {
        // i32.mul
        let b = try_exec!(inst.pop_i32());
        let a = try_exec!(inst.pop_i32());
        try_exec!(inst.push(Value::I32(a.wrapping_mul(b))));
    }
    0x6D => {
        // i32.div_s
        let b = try_exec!(inst.pop_i32());
        let a = try_exec!(inst.pop_i32());
        if b == 0 {
            return ExecResult::Trap(WasmError::DivisionByZero);
        }
        if a == i32::MIN && b == -1 {
            return ExecResult::Trap(WasmError::IntegerOverflow);
        }
        try_exec!(inst.push(Value::I32(a.wrapping_div(b))));
    }
    0x6E => {
        // i32.div_u
        let b = try_exec!(inst.pop_i32());
        let a = try_exec!(inst.pop_i32());
        if b == 0 {
            return ExecResult::Trap(WasmError::DivisionByZero);
        }
        try_exec!(inst.push(Value::I32(((a as u32).wrapping_div(b as u32)) as i32)));
    }
    0x6F => {
        // i32.rem_s
        let b = try_exec!(inst.pop_i32());
        let a = try_exec!(inst.pop_i32());
        if b == 0 {
            return ExecResult::Trap(WasmError::DivisionByZero);
        }
        if a == i32::MIN && b == -1 {
            try_exec!(inst.push(Value::I32(0)));
        } else {
            try_exec!(inst.push(Value::I32(a.wrapping_rem(b))));
        }
    }
    0x70 => {
        // i32.rem_u
        let b = try_exec!(inst.pop_i32());
        let a = try_exec!(inst.pop_i32());
        if b == 0 {
            return ExecResult::Trap(WasmError::DivisionByZero);
        }
        try_exec!(inst.push(Value::I32(((a as u32).wrapping_rem(b as u32)) as i32)));
    }
    0x71 => {
        // i32.and
        let b = try_exec!(inst.pop_i32());
        let a = try_exec!(inst.pop_i32());
        try_exec!(inst.push(Value::I32(a & b)));
    }
    0x72 => {
        // i32.or
        let b = try_exec!(inst.pop_i32());
        let a = try_exec!(inst.pop_i32());
        try_exec!(inst.push(Value::I32(a | b)));
    }
    0x73 => {
        // i32.xor
        let b = try_exec!(inst.pop_i32());
        let a = try_exec!(inst.pop_i32());
        try_exec!(inst.push(Value::I32(a ^ b)));
    }
    0x74 => {
        // i32.shl
        let b = try_exec!(inst.pop_i32());
        let a = try_exec!(inst.pop_i32());
        try_exec!(inst.push(Value::I32(a.wrapping_shl(b as u32))));
    }
    0x75 => {
        // i32.shr_s
        let b = try_exec!(inst.pop_i32());
        let a = try_exec!(inst.pop_i32());
        try_exec!(inst.push(Value::I32(a.wrapping_shr(b as u32))));
    }
    0x76 => {
        // i32.shr_u
        let b = try_exec!(inst.pop_i32());
        let a = try_exec!(inst.pop_i32());
        try_exec!(inst.push(Value::I32(((a as u32).wrapping_shr(b as u32)) as i32)));
    }
    0x77 => {
        // i32.rotl
        let b = try_exec!(inst.pop_i32());
        let a = try_exec!(inst.pop_i32());
        try_exec!(inst.push(Value::I32((a as u32).rotate_left(b as u32) as i32)));
    }
    0x78 => {
        // i32.rotr
        let b = try_exec!(inst.pop_i32());
        let a = try_exec!(inst.pop_i32());
        try_exec!(inst.push(Value::I32((a as u32).rotate_right(b as u32) as i32)));
    }

    // ── i64 Arithmetic ──────────────────────────────────────
    0x79 => {
        // i64.clz
        let a = try_exec!(inst.pop_i64());
        try_exec!(inst.push(Value::I64((a as u64).leading_zeros() as i64)));
    }
    0x7A => {
        // i64.ctz
        let a = try_exec!(inst.pop_i64());
        try_exec!(inst.push(Value::I64((a as u64).trailing_zeros() as i64)));
    }
    0x7B => {
        // i64.popcnt
        let a = try_exec!(inst.pop_i64());
        try_exec!(inst.push(Value::I64((a as u64).count_ones() as i64)));
    }
    0x7C => {
        // i64.add
        let b = try_exec!(inst.pop_i64());
        let a = try_exec!(inst.pop_i64());
        try_exec!(inst.push(Value::I64(a.wrapping_add(b))));
    }
    0x7D => {
        // i64.sub
        let b = try_exec!(inst.pop_i64());
        let a = try_exec!(inst.pop_i64());
        try_exec!(inst.push(Value::I64(a.wrapping_sub(b))));
    }
    0x7E => {
        // i64.mul
        let b = try_exec!(inst.pop_i64());
        let a = try_exec!(inst.pop_i64());
        try_exec!(inst.push(Value::I64(a.wrapping_mul(b))));
    }
    0x7F => {
        // i64.div_s
        let b = try_exec!(inst.pop_i64());
        let a = try_exec!(inst.pop_i64());
        if b == 0 {
            return ExecResult::Trap(WasmError::DivisionByZero);
        }
        if a == i64::MIN && b == -1 {
            return ExecResult::Trap(WasmError::IntegerOverflow);
        }
        try_exec!(inst.push(Value::I64(a.wrapping_div(b))));
    }
    0x80 => {
        // i64.div_u
        let b = try_exec!(inst.pop_i64());
        let a = try_exec!(inst.pop_i64());
        if b == 0 {
            return ExecResult::Trap(WasmError::DivisionByZero);
        }
        try_exec!(inst.push(Value::I64(((a as u64).wrapping_div(b as u64)) as i64)));
    }
    0x81 => {
        // i64.rem_s
        let b = try_exec!(inst.pop_i64());
        let a = try_exec!(inst.pop_i64());
        if b == 0 {
            return ExecResult::Trap(WasmError::DivisionByZero);
        }
        if a == i64::MIN && b == -1 {
            try_exec!(inst.push(Value::I64(0)));
        } else {
            try_exec!(inst.push(Value::I64(a.wrapping_rem(b))));
        }
    }
    0x82 => {
        // i64.rem_u
        let b = try_exec!(inst.pop_i64());
        let a = try_exec!(inst.pop_i64());
        if b == 0 {
            return ExecResult::Trap(WasmError::DivisionByZero);
        }
        try_exec!(inst.push(Value::I64(((a as u64).wrapping_rem(b as u64)) as i64)));
    }
    0x83 => {
        // i64.and
        let b = try_exec!(inst.pop_i64());
        let a = try_exec!(inst.pop_i64());
        try_exec!(inst.push(Value::I64(a & b)));
    }
    0x84 => {
        // i64.or
        let b = try_exec!(inst.pop_i64());
        let a = try_exec!(inst.pop_i64());
        try_exec!(inst.push(Value::I64(a | b)));
    }
    0x85 => {
        // i64.xor
        let b = try_exec!(inst.pop_i64());
        let a = try_exec!(inst.pop_i64());
        try_exec!(inst.push(Value::I64(a ^ b)));
    }
    0x86 => {
        // i64.shl
        let b = try_exec!(inst.pop_i64());
        let a = try_exec!(inst.pop_i64());
        try_exec!(inst.push(Value::I64(a.wrapping_shl(b as u32))));
    }
    0x87 => {
        // i64.shr_s
        let b = try_exec!(inst.pop_i64());
        let a = try_exec!(inst.pop_i64());
        try_exec!(inst.push(Value::I64(a.wrapping_shr(b as u32))));
    }
    0x88 => {
        // i64.shr_u
        let b = try_exec!(inst.pop_i64());
        let a = try_exec!(inst.pop_i64());
        try_exec!(inst.push(Value::I64(((a as u64).wrapping_shr(b as u32)) as i64)));
    }
    0x89 => {
        // i64.rotl
        let b = try_exec!(inst.pop_i64());
        let a = try_exec!(inst.pop_i64());
        try_exec!(inst.push(Value::I64((a as u64).rotate_left(b as u32) as i64)));
    }
    0x8A => {
        // i64.rotr
        let b = try_exec!(inst.pop_i64());
        let a = try_exec!(inst.pop_i64());
        try_exec!(inst.push(Value::I64((a as u64).rotate_right(b as u32) as i64)));
    }

    // ── Conversion ──────────────────────────────────────────
    0xA7 => {
        // i32.wrap_i64
        let a = try_exec!(inst.pop_i64());
        try_exec!(inst.push(Value::I32(a as i32)));
    }
    0xAC => {
        // i64.extend_i32_s
        let a = try_exec!(inst.pop_i32());
        try_exec!(inst.push(Value::I64(a as i64)));
    }
    0xAD => {
        // i64.extend_i32_u (zero-extend)
        let a = try_exec!(inst.pop_i32());
        try_exec!(inst.push(Value::I64((a as u32) as i64)));
    }

    // ── Sign extension ──────────────────────────────────────
    0xC0 => {
        // i32.extend8_s
        let a = try_exec!(inst.pop_i32());
        try_exec!(inst.push(Value::I32((a as i8) as i32)));
    }
    0xC1 => {
        // i32.extend16_s
        let a = try_exec!(inst.pop_i32());
        try_exec!(inst.push(Value::I32((a as i16) as i32)));
    }
    0xC2 => {
        // i64.extend8_s
        let a = try_exec!(inst.pop_i64());
        try_exec!(inst.push(Value::I64((a as i8) as i64)));
    }
    0xC3 => {
        // i64.extend16_s
        let a = try_exec!(inst.pop_i64());
        try_exec!(inst.push(Value::I64((a as i16) as i64)));
    }
    0xC4 => {
        // i64.extend32_s
        let a = try_exec!(inst.pop_i64());
        try_exec!(inst.push(Value::I64((a as i32) as i64)));
    }

    // ── Float comparison ─────────────────────────────────────
    0x5B => { if inst.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let b = try_exec!(inst.pop_f32()); let a = try_exec!(inst.pop_f32()); try_exec!(inst.push(Value::I32(if a == b { 1 } else { 0 }))); }
    0x5C => { if inst.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let b = try_exec!(inst.pop_f32()); let a = try_exec!(inst.pop_f32()); try_exec!(inst.push(Value::I32(if a != b { 1 } else { 0 }))); }
    0x5D => { if inst.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let b = try_exec!(inst.pop_f32()); let a = try_exec!(inst.pop_f32()); try_exec!(inst.push(Value::I32(if a < b { 1 } else { 0 }))); }
    0x5E => { if inst.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let b = try_exec!(inst.pop_f32()); let a = try_exec!(inst.pop_f32()); try_exec!(inst.push(Value::I32(if a > b { 1 } else { 0 }))); }
    0x5F => { if inst.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let b = try_exec!(inst.pop_f32()); let a = try_exec!(inst.pop_f32()); try_exec!(inst.push(Value::I32(if a <= b { 1 } else { 0 }))); }
    0x60 => { if inst.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let b = try_exec!(inst.pop_f32()); let a = try_exec!(inst.pop_f32()); try_exec!(inst.push(Value::I32(if a >= b { 1 } else { 0 }))); }
    0x61 => { if inst.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let b = try_exec!(inst.pop_f64()); let a = try_exec!(inst.pop_f64()); try_exec!(inst.push(Value::I32(if a == b { 1 } else { 0 }))); }
    0x62 => { if inst.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let b = try_exec!(inst.pop_f64()); let a = try_exec!(inst.pop_f64()); try_exec!(inst.push(Value::I32(if a != b { 1 } else { 0 }))); }
    0x63 => { if inst.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let b = try_exec!(inst.pop_f64()); let a = try_exec!(inst.pop_f64()); try_exec!(inst.push(Value::I32(if a < b { 1 } else { 0 }))); }
    0x64 => { if inst.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let b = try_exec!(inst.pop_f64()); let a = try_exec!(inst.pop_f64()); try_exec!(inst.push(Value::I32(if a > b { 1 } else { 0 }))); }
    0x65 => { if inst.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let b = try_exec!(inst.pop_f64()); let a = try_exec!(inst.pop_f64()); try_exec!(inst.push(Value::I32(if a <= b { 1 } else { 0 }))); }
    0x66 => { if inst.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let b = try_exec!(inst.pop_f64()); let a = try_exec!(inst.pop_f64()); try_exec!(inst.push(Value::I32(if a >= b { 1 } else { 0 }))); }

    // ── f32 unary ───────────────────────────────────────────
    0x8B => { if inst.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(inst.pop_f32()); try_exec!(inst.push(Value::F32(libm::fabsf(a)))); }
    0x8C => { if inst.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(inst.pop_f32()); try_exec!(inst.push(Value::F32(-a))); }
    0x8D => { if inst.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(inst.pop_f32()); try_exec!(inst.push(Value::F32(WasmInstance::wasm_ceil_f32(a)))); }
    0x8E => { if inst.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(inst.pop_f32()); try_exec!(inst.push(Value::F32(WasmInstance::wasm_floor_f32(a)))); }
    0x8F => { if inst.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(inst.pop_f32()); try_exec!(inst.push(Value::F32(WasmInstance::wasm_trunc_f32(a)))); }
    0x90 => { if inst.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(inst.pop_f32()); try_exec!(inst.push(Value::F32(WasmInstance::wasm_nearest_f32(a)))); }
    0x91 => { if inst.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(inst.pop_f32()); try_exec!(inst.push(Value::F32(WasmInstance::wasm_sqrt_f32(a)))); }

    // ── f32 binary ──────────────────────────────────────────
    0x92 => { if inst.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let b = try_exec!(inst.pop_f32()); let a = try_exec!(inst.pop_f32()); try_exec!(inst.push(Value::F32(a + b))); }
    0x93 => { if inst.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let b = try_exec!(inst.pop_f32()); let a = try_exec!(inst.pop_f32()); try_exec!(inst.push(Value::F32(a - b))); }
    0x94 => { if inst.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let b = try_exec!(inst.pop_f32()); let a = try_exec!(inst.pop_f32()); try_exec!(inst.push(Value::F32(a * b))); }
    0x95 => { if inst.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let b = try_exec!(inst.pop_f32()); let a = try_exec!(inst.pop_f32()); try_exec!(inst.push(Value::F32(a / b))); }
    0x96 => { if inst.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let b = try_exec!(inst.pop_f32()); let a = try_exec!(inst.pop_f32()); try_exec!(inst.push(Value::F32(WasmInstance::wasm_min_f32(a, b)))); }
    0x97 => { if inst.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let b = try_exec!(inst.pop_f32()); let a = try_exec!(inst.pop_f32()); try_exec!(inst.push(Value::F32(WasmInstance::wasm_max_f32(a, b)))); }
    0x98 => { if inst.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let b = try_exec!(inst.pop_f32()); let a = try_exec!(inst.pop_f32()); try_exec!(inst.push(Value::F32(libm::copysignf(a, b)))); }

    // ── f64 unary ───────────────────────────────────────────
    0x99 => { if inst.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(inst.pop_f64()); try_exec!(inst.push(Value::F64(libm::fabs(a)))); }
    0x9A => { if inst.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(inst.pop_f64()); try_exec!(inst.push(Value::F64(-a))); }
    0x9B => { if inst.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(inst.pop_f64()); try_exec!(inst.push(Value::F64(WasmInstance::wasm_ceil_f64(a)))); }
    0x9C => { if inst.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(inst.pop_f64()); try_exec!(inst.push(Value::F64(WasmInstance::wasm_floor_f64(a)))); }
    0x9D => { if inst.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(inst.pop_f64()); try_exec!(inst.push(Value::F64(WasmInstance::wasm_trunc_f64(a)))); }
    0x9E => { if inst.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(inst.pop_f64()); try_exec!(inst.push(Value::F64(WasmInstance::wasm_nearest_f64(a)))); }
    0x9F => { if inst.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(inst.pop_f64()); try_exec!(inst.push(Value::F64(WasmInstance::wasm_sqrt_f64(a)))); }

    // ── f64 binary ──────────────────────────────────────────
    0xA0 => { if inst.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let b = try_exec!(inst.pop_f64()); let a = try_exec!(inst.pop_f64()); try_exec!(inst.push(Value::F64(a + b))); }
    0xA1 => { if inst.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let b = try_exec!(inst.pop_f64()); let a = try_exec!(inst.pop_f64()); try_exec!(inst.push(Value::F64(a - b))); }
    0xA2 => { if inst.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let b = try_exec!(inst.pop_f64()); let a = try_exec!(inst.pop_f64()); try_exec!(inst.push(Value::F64(a * b))); }
    0xA3 => { if inst.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let b = try_exec!(inst.pop_f64()); let a = try_exec!(inst.pop_f64()); try_exec!(inst.push(Value::F64(a / b))); }
    0xA4 => { if inst.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let b = try_exec!(inst.pop_f64()); let a = try_exec!(inst.pop_f64()); try_exec!(inst.push(Value::F64(WasmInstance::wasm_min_f64(a, b)))); }
    0xA5 => { if inst.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let b = try_exec!(inst.pop_f64()); let a = try_exec!(inst.pop_f64()); try_exec!(inst.push(Value::F64(WasmInstance::wasm_max_f64(a, b)))); }
    0xA6 => { if inst.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let b = try_exec!(inst.pop_f64()); let a = try_exec!(inst.pop_f64()); try_exec!(inst.push(Value::F64(libm::copysign(a, b)))); }

    // ── Float-integer conversion ─────────────────────────────
    // Trunc boundaries use exact float constants per WASM spec.
    // i32::MAX (2147483647) rounds up to 2147483648.0 in f32, so >= traps.
    0xA8 => { if inst.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(inst.pop_f32()); if a.is_nan() { return ExecResult::Trap(WasmError::InvalidConversionToInteger); } if a <= -2147483904.0_f32 || a >= 2147483648.0_f32 { return ExecResult::Trap(WasmError::IntegerOverflow); } try_exec!(inst.push(Value::I32(a as i32))); }
    0xA9 => { if inst.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(inst.pop_f32()); if a.is_nan() { return ExecResult::Trap(WasmError::InvalidConversionToInteger); } if a <= -1.0_f32 || a >= 4294967296.0_f32 { return ExecResult::Trap(WasmError::IntegerOverflow); } try_exec!(inst.push(Value::I32(a as u32 as i32))); }
    0xAA => { if inst.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(inst.pop_f64()); if a.is_nan() { return ExecResult::Trap(WasmError::InvalidConversionToInteger); } if a <= -2147483649.0_f64 || a >= 2147483648.0_f64 { return ExecResult::Trap(WasmError::IntegerOverflow); } try_exec!(inst.push(Value::I32(a as i32))); }
    0xAB => { if inst.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(inst.pop_f64()); if a.is_nan() { return ExecResult::Trap(WasmError::InvalidConversionToInteger); } if a <= -1.0_f64 || a >= 4294967296.0_f64 { return ExecResult::Trap(WasmError::IntegerOverflow); } try_exec!(inst.push(Value::I32(a as u32 as i32))); }
    0xAE => { if inst.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(inst.pop_f32()); if a.is_nan() { return ExecResult::Trap(WasmError::InvalidConversionToInteger); } if a <= -9223373136366403584.0_f32 || a >= 9223372036854775808.0_f32 { return ExecResult::Trap(WasmError::IntegerOverflow); } try_exec!(inst.push(Value::I64(a as i64))); }
    0xAF => { if inst.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(inst.pop_f32()); if a.is_nan() { return ExecResult::Trap(WasmError::InvalidConversionToInteger); } if a <= -1.0_f32 || a >= 18446744073709551616.0_f32 { return ExecResult::Trap(WasmError::IntegerOverflow); } try_exec!(inst.push(Value::I64(a as u64 as i64))); }
    0xB0 => { if inst.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(inst.pop_f64()); if a.is_nan() { return ExecResult::Trap(WasmError::InvalidConversionToInteger); } if a <= -9223372036854777856.0_f64 || a >= 9223372036854775808.0_f64 { return ExecResult::Trap(WasmError::IntegerOverflow); } try_exec!(inst.push(Value::I64(a as i64))); }
    0xB1 => { if inst.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(inst.pop_f64()); if a.is_nan() { return ExecResult::Trap(WasmError::InvalidConversionToInteger); } if a <= -1.0_f64 || a >= 18446744073709551616.0_f64 { return ExecResult::Trap(WasmError::IntegerOverflow); } try_exec!(inst.push(Value::I64(a as u64 as i64))); }
    // int → float
    0xB2 => { if inst.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(inst.pop_i32()); try_exec!(inst.push(Value::F32(a as f32))); }
    0xB3 => { if inst.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(inst.pop_i32()); try_exec!(inst.push(Value::F32((a as u32) as f32))); }
    0xB4 => { if inst.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(inst.pop_i64()); try_exec!(inst.push(Value::F32(a as f32))); }
    0xB5 => { if inst.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(inst.pop_i64()); try_exec!(inst.push(Value::F32((a as u64) as f32))); }
    0xB6 => { if inst.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(inst.pop_f64()); try_exec!(inst.push(Value::F32(a as f32))); }
    0xB7 => { if inst.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(inst.pop_i32()); try_exec!(inst.push(Value::F64(a as f64))); }
    0xB8 => { if inst.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(inst.pop_i32()); try_exec!(inst.push(Value::F64((a as u32) as f64))); }
    0xB9 => { if inst.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(inst.pop_i64()); try_exec!(inst.push(Value::F64(a as f64))); }
    0xBA => { if inst.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(inst.pop_i64()); try_exec!(inst.push(Value::F64((a as u64) as f64))); }
    0xBB => { if inst.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(inst.pop_f32()); try_exec!(inst.push(Value::F64(a as f64))); }
    // reinterpret
    0xBC => { if inst.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(inst.pop_f32()); try_exec!(inst.push(Value::I32(a.to_bits() as i32))); }
    0xBD => { if inst.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(inst.pop_f64()); try_exec!(inst.push(Value::I64(a.to_bits() as i64))); }
    0xBE => { if inst.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(inst.pop_i32()); try_exec!(inst.push(Value::F32(f32::from_bits(a as u32)))); }
    0xBF => { if inst.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(inst.pop_i64()); try_exec!(inst.push(Value::F64(f64::from_bits(a as u64)))); }


        _ => return ExecResult::Trap(WasmError::InvalidOpcode(opcode)),
    }

    ExecResult::Ok
}
