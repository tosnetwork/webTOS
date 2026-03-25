//! Constant expression evaluation: skip, scan, and evaluate init expressions.

use crate::wasm::types::*;
use super::reader::{read_byte, decode_leb128_u32, decode_leb128_i32, decode_leb128_i64};
use super::{GcTypeDef, InitExprInfo};

/// Skip past a constant init expression (read opcodes until 0x0B end marker).
/// Used for table init expressions and other places where we don't need the value.
pub(crate) fn skip_init_expr(bytes: &[u8], pos: &mut usize) -> Result<(), WasmError> {
    loop {
        if *pos >= bytes.len() {
            return Err(WasmError::UnexpectedEnd);
        }
        let opcode = read_byte(bytes, pos)?;
        match opcode {
            0x0B => return Ok(()), // end
            0x41 => { decode_leb128_i32(bytes, pos)?; } // i32.const
            0x42 => { decode_leb128_i64(bytes, pos)?; } // i64.const
            0x43 => { // f32.const
                if *pos + 4 > bytes.len() { return Err(WasmError::UnexpectedEnd); }
                *pos += 4;
            }
            0x44 => { // f64.const
                if *pos + 8 > bytes.len() { return Err(WasmError::UnexpectedEnd); }
                *pos += 8;
            }
            0x23 => { decode_leb128_u32(bytes, pos)?; } // global.get
            0xD0 => { decode_leb128_i32(bytes, pos)?; } // ref.null
            0xD2 => { decode_leb128_u32(bytes, pos)?; } // ref.func
            0xFD => { // SIMD prefix
                let sub = decode_leb128_u32(bytes, pos)?;
                if sub == 12 { // v128.const
                    if *pos + 16 > bytes.len() { return Err(WasmError::UnexpectedEnd); }
                    *pos += 16;
                }
            }
            0xFB => { // GC prefix
                let sub = decode_leb128_u32(bytes, pos)?;
                match sub {
                    0 | 1 | 6 | 7 => { decode_leb128_u32(bytes, pos)?; } // struct.new/default, array.new/default: typeidx
                    8 => { decode_leb128_u32(bytes, pos)?; decode_leb128_u32(bytes, pos)?; } // array.new_fixed: typeidx + count
                    9 | 10 => { decode_leb128_u32(bytes, pos)?; decode_leb128_u32(bytes, pos)?; } // array.new_data/elem: typeidx + idx
                    2 | 3 | 4 | 5 => { decode_leb128_u32(bytes, pos)?; decode_leb128_u32(bytes, pos)?; } // struct.get/get_s/get_u/set
                    11 | 12 | 13 | 14 => { decode_leb128_u32(bytes, pos)?; } // array.get/get_s/get_u/set
                    15 => {} // array.len
                    16 => { decode_leb128_u32(bytes, pos)?; } // array.fill
                    17 => { decode_leb128_u32(bytes, pos)?; decode_leb128_u32(bytes, pos)?; } // array.copy
                    18 | 19 => { decode_leb128_u32(bytes, pos)?; decode_leb128_u32(bytes, pos)?; } // array.init_data/elem
                    20 | 21 => { decode_leb128_i32(bytes, pos)?; } // ref.test/test_nullable: heaptype
                    22 | 23 => { decode_leb128_i32(bytes, pos)?; } // ref.cast/cast_nullable: heaptype
                    24 | 25 => { // br_on_cast, br_on_cast_fail
                        read_byte(bytes, pos)?; // flags
                        decode_leb128_u32(bytes, pos)?; // label
                        decode_leb128_i32(bytes, pos)?; // ht1
                        decode_leb128_i32(bytes, pos)?; // ht2
                    }
                    26 | 27 | 28 | 29 | 30 => {} // any.convert_extern, extern.convert_any, ref.i31, i31.get_s/u
                    _ => {} // unknown GC sub-opcode — assume no immediates
                }
            }
            // Extended-const ops (no immediates): i32.add/sub/mul, i64.add/sub/mul
            0x6A | 0x6B | 0x6C | 0x7C | 0x7D | 0x7E => {}
            _ => return Err(WasmError::InvalidSection),
        }
    }
}

/// Scan init expression bytes to extract validation info.
/// Returns InitExprInfo with global refs, result type, stack depth, etc.
pub fn scan_init_expr_info(bytes: &[u8], start: usize) -> InitExprInfo {
    scan_init_expr_info_gc(bytes, start, &[])
}

pub fn scan_init_expr_info_gc(bytes: &[u8], start: usize, gc_types: &[GcTypeDef]) -> InitExprInfo {
    let mut p = start;
    let mut info = InitExprInfo::default();
    // Track a small type stack
    let mut type_stack: [Option<ValType>; 16] = [None; 16];
    let mut sp: usize = 0;

    while p < bytes.len() {
        let b = bytes[p];
        p += 1;
        match b {
            0x0B => break, // end
            0x23 => {
                // global.get - read the index
                if let Ok(idx) = decode_leb128_u32(bytes, &mut p) {
                    info.global_ref = Some(match info.global_ref {
                        Some(cur) => cur.max(idx),
                        None => idx,
                    });
                    // We don't know the type without looking up the global,
                    // so push None (unknown type)
                    if sp < 16 { type_stack[sp] = None; sp += 1; }
                }
            }
            0x41 => {
                let _ = decode_leb128_i32(bytes, &mut p);
                if sp < 16 { type_stack[sp] = Some(ValType::I32); sp += 1; }
            }
            0x42 => {
                let _ = decode_leb128_i64(bytes, &mut p);
                if sp < 16 { type_stack[sp] = Some(ValType::I64); sp += 1; }
            }
            0x43 => {
                p += 4;
                if sp < 16 { type_stack[sp] = Some(ValType::F32); sp += 1; }
            }
            0x44 => {
                p += 8;
                if sp < 16 { type_stack[sp] = Some(ValType::F64); sp += 1; }
            }
            0xD0 => {
                let ht = decode_leb128_i32(bytes, &mut p);
                let vt = match ht {
                    Ok(-0x10) => Some(ValType::FuncRef),     // (ref null func) = funcref
                    Ok(-0x11) => Some(ValType::ExternRef),   // (ref null extern) = externref
                    Ok(-0x12) => Some(ValType::NullableAnyRef), // (ref null any) = anyref
                    Ok(-0x13) => Some(ValType::NullableEqRef), // (ref null eq) = eqref
                    Ok(-0x14) => Some(ValType::I31Ref),      // (ref null i31) = i31ref
                    Ok(-0x15) => Some(ValType::NullableStructRef), // (ref null struct) = structref
                    Ok(-0x16) => Some(ValType::NullableArrayRef), // (ref null array) = arrayref
                    Ok(-0x0F) => Some(ValType::NoneRef),     // (ref null none) = nullref
                    Ok(-0x0D) => Some(ValType::NullFuncRef),   // (ref null nofunc) = nullfuncref
                    Ok(-0x0E) => Some(ValType::NullExternRef), // (ref null noextern) = nullexternref
                    Ok(-0x17) => Some(ValType::ExnRef),      // (ref null exn) = exnref
                    Ok(-0x0C) => Some(ValType::ExnRef),      // (ref null noexn) = nullexnref
                    Ok(ht_idx) if ht_idx >= 0 => Some(ValType::NullableTypedFuncRef), // (ref null $t)
                    _ => None,
                };
                if sp < 16 { type_stack[sp] = vt; sp += 1; }
            }
            0xD2 => {
                if let Ok(idx) = decode_leb128_u32(bytes, &mut p) {
                    if info.func_ref.is_none() {
                        info.func_ref = Some(idx);
                    }
                }
                // ref.func produces (ref $t) = TypedFuncRef (non-nullable)
                if sp < 16 { type_stack[sp] = Some(ValType::TypedFuncRef); sp += 1; }
            }
            0xFD => {
                let _ = decode_leb128_u32(bytes, &mut p);
                p += 16;
                if sp < 16 { type_stack[sp] = Some(ValType::V128); sp += 1; }
            }
            0xFB => {
                // GC prefix in init expr
                if let Ok(sub) = decode_leb128_u32(bytes, &mut p) {
                    match sub {
                        0 => { // struct.new: pop N fields, push ref
                            if let Ok(type_idx) = decode_leb128_u32(bytes, &mut p) {
                                let field_count = if let Some(GcTypeDef::Struct { field_types, .. }) = gc_types.get(type_idx as usize) {
                                    field_types.len()
                                } else { 0 };
                                sp = sp.saturating_sub(field_count);
                            }
                            if sp < 16 { type_stack[sp] = None; sp += 1; }
                        }
                        1 => { // struct.new_default: pop 0, push ref
                            let _ = decode_leb128_u32(bytes, &mut p);
                            if sp < 16 { type_stack[sp] = None; sp += 1; }
                        }
                        6 => { // array.new: pop init_val + length, push ref
                            let _ = decode_leb128_u32(bytes, &mut p);
                            sp = sp.saturating_sub(2);
                            if sp < 16 { type_stack[sp] = None; sp += 1; }
                        }
                        7 => { // array.new_default: pop length, push ref
                            let _ = decode_leb128_u32(bytes, &mut p);
                            sp = sp.saturating_sub(1);
                            if sp < 16 { type_stack[sp] = None; sp += 1; }
                        }
                        8 => { // array.new_fixed: pop N values, push ref
                            let _ = decode_leb128_u32(bytes, &mut p);
                            if let Ok(count) = decode_leb128_u32(bytes, &mut p) {
                                sp = sp.saturating_sub(count as usize);
                            }
                            if sp < 16 { type_stack[sp] = None; sp += 1; }
                        }
                        9 | 10 => { // array.new_data/elem: pop offset + length, push ref (NOT const-valid)
                            info.has_non_const = true;
                            let _ = decode_leb128_u32(bytes, &mut p); let _ = decode_leb128_u32(bytes, &mut p);
                            sp = sp.saturating_sub(2);
                            if sp < 16 { type_stack[sp] = None; sp += 1; }
                        }
                        2 | 3 | 4 => { info.has_non_const = true; let _ = decode_leb128_u32(bytes, &mut p); let _ = decode_leb128_u32(bytes, &mut p);
                            // struct.get: pop ref, push val
                            if sp > 0 { type_stack[sp - 1] = None; }
                        }
                        5 => { info.has_non_const = true; let _ = decode_leb128_u32(bytes, &mut p); let _ = decode_leb128_u32(bytes, &mut p);
                            // struct.set: pop ref, pop val
                            if sp >= 2 { sp -= 2; }
                        }
                        11 | 12 | 13 => { info.has_non_const = true; let _ = decode_leb128_u32(bytes, &mut p);
                            // array.get: pop ref, pop idx, push val
                            if sp >= 2 { sp -= 1; type_stack[sp - 1] = None; }
                        }
                        14 => { info.has_non_const = true; let _ = decode_leb128_u32(bytes, &mut p);
                            // array.set: pop ref, pop idx, pop val
                            if sp >= 3 { sp -= 3; }
                        }
                        15 => { info.has_non_const = true; // array.len: pop ref, push i32
                            if sp > 0 { type_stack[sp - 1] = Some(ValType::I32); }
                        }
                        16 => { info.has_non_const = true; let _ = decode_leb128_u32(bytes, &mut p); } // array.fill
                        17 => { info.has_non_const = true; let _ = decode_leb128_u32(bytes, &mut p); let _ = decode_leb128_u32(bytes, &mut p); } // array.copy
                        18 | 19 => { info.has_non_const = true; let _ = decode_leb128_u32(bytes, &mut p); let _ = decode_leb128_u32(bytes, &mut p); } // array.init_data/elem
                        20 | 21 => { info.has_non_const = true; let _ = decode_leb128_i32(bytes, &mut p);
                            // ref.test: pop ref, push i32
                            if sp > 0 { type_stack[sp - 1] = Some(ValType::I32); }
                        }
                        22 | 23 => { info.has_non_const = true; let _ = decode_leb128_i32(bytes, &mut p);
                            // ref.cast: pop ref, push ref (same-ish)
                        }
                        24 | 25 => { info.has_non_const = true; // br_on_cast / br_on_cast_fail
                            let _ = read_byte(bytes, &mut p);
                            let _ = decode_leb128_u32(bytes, &mut p);
                            let _ = decode_leb128_i32(bytes, &mut p);
                            let _ = decode_leb128_i32(bytes, &mut p);
                        }
                        26 | 27 => {} // any.convert_extern, extern.convert_any: pop ref, push ref (const-valid)
                        28 => { // ref.i31: pop i32, push i31ref (const-valid)
                            if sp > 0 { type_stack[sp - 1] = Some(ValType::I31Ref); }
                            else if sp < 16 { type_stack[sp] = Some(ValType::I31Ref); sp += 1; }
                        }
                        29 | 30 => { // i31.get_s/u: pop i31ref, push i32 (NOT const-valid)
                            info.has_non_const = true;
                            if sp > 0 { type_stack[sp - 1] = Some(ValType::I32); }
                        }
                        _ => { info.has_non_const = true; } // non-const sub-opcode
                    }
                }
            }
            // i32 arithmetic (extended-const): pop 2, push 1
            0x6A | 0x6B | 0x6C => {
                if sp >= 2 { sp -= 1; type_stack[sp - 1] = Some(ValType::I32); }
            }
            // i64 arithmetic (extended-const): pop 2, push 1
            0x7C | 0x7D | 0x7E => {
                if sp >= 2 { sp -= 1; type_stack[sp - 1] = Some(ValType::I64); }
            }
            _ => {
                info.has_non_const = true;
                break;
            }
        }
    }

    info.stack_depth = sp as u32;
    info.result_type = if sp > 0 { type_stack[sp - 1] } else { None };
    info
}

/// Scan init expression bytes to find the maximum global.get reference index.
/// Wrapper for backward compat.
pub(crate) fn scan_init_expr_global_refs(bytes: &[u8], start: usize) -> Option<u32> {
    scan_init_expr_info(bytes, start).global_ref
}

/// Evaluate a constant init expression with known global values.
/// Used by the runner to re-evaluate offset expressions after globals are injected.
pub fn eval_init_expr_with_globals(bytes: &[u8], pos: &mut usize, globals: &[Value]) -> Result<Value, WasmError> {
    eval_init_expr_inner(bytes, pos, Some(globals))
}

/// Evaluate a constant init expression (for globals and segment offsets).
/// Supports MVP + extended-const proposal (multi-instruction expressions).
pub(crate) fn eval_init_expr(bytes: &[u8], pos: &mut usize) -> Result<Value, WasmError> {
    eval_init_expr_inner(bytes, pos, None)
}

fn eval_init_expr_inner(bytes: &[u8], pos: &mut usize, globals: Option<&[Value]>) -> Result<Value, WasmError> {
    if *pos >= bytes.len() {
        return Err(WasmError::UnexpectedEnd);
    }
    // Use a small stack to evaluate extended-const expressions
    let mut stack: [Value; 16] = [Value::I32(0); 16];
    let mut sp: usize = 0;

    loop {
        let opcode = read_byte(bytes, pos)?;
        match opcode {
            0x0B => {
                // end - return top of stack (or I32(0) if empty)
                return if sp > 0 { Ok(stack[sp - 1]) } else { Ok(Value::I32(0)) };
            }
            0x41 => {
                // i32.const
                let v = decode_leb128_i32(bytes, pos)?;
                if sp < 16 { stack[sp] = Value::I32(v); sp += 1; }
            }
            0x42 => {
                // i64.const
                let v = decode_leb128_i64(bytes, pos)?;
                if sp < 16 { stack[sp] = Value::I64(v); sp += 1; }
            }
            0x43 => {
                // f32.const
                if *pos + 4 > bytes.len() { return Err(WasmError::UnexpectedEnd); }
                let b0 = read_byte(bytes, pos)?;
                let b1 = read_byte(bytes, pos)?;
                let b2 = read_byte(bytes, pos)?;
                let b3 = read_byte(bytes, pos)?;
                let v = f32::from_le_bytes([b0, b1, b2, b3]);
                if sp < 16 { stack[sp] = Value::F32(v); sp += 1; }
            }
            0x44 => {
                // f64.const
                if *pos + 8 > bytes.len() { return Err(WasmError::UnexpectedEnd); }
                let mut b8 = [0u8; 8];
                b8.copy_from_slice(&bytes[*pos..*pos+8]);
                *pos += 8;
                if sp < 16 { stack[sp] = Value::F64(f64::from_le_bytes(b8)); sp += 1; }
            }
            0x23 => {
                // global.get (reference to imported or defined global — return placeholder)
                let idx = decode_leb128_u32(bytes, pos)?;
                let val = globals.and_then(|g| g.get(idx as usize).copied()).unwrap_or(Value::I32(0));
                if sp < 16 { stack[sp] = val; sp += 1; }
            }
            0xD0 => {
                // ref.null heaptype
                let _ = decode_leb128_i32(bytes, pos)?;
                if sp < 16 { stack[sp] = Value::NullRef; sp += 1; } // null ref sentinel
            }
            0xD2 => {
                // ref.func funcidx
                let idx = decode_leb128_u32(bytes, pos)?;
                if sp < 16 { stack[sp] = Value::I32(idx as i32); sp += 1; }
            }
            0xFD => {
                // SIMD prefix in init expr: only v128.const (sub-opcode 12) is valid
                let sub = decode_leb128_u32(bytes, pos)?;
                if sub == 12 {
                    if *pos + 16 > bytes.len() { return Err(WasmError::UnexpectedEnd); }
                    let mut v = [0u8; 16];
                    v.copy_from_slice(&bytes[*pos..*pos + 16]);
                    *pos += 16;
                    if sp < 16 { stack[sp] = Value::V128(crate::wasm::types::V128(v)); sp += 1; }
                } else {
                    return Err(WasmError::InvalidSection);
                }
            }
            0xFB => {
                // GC prefix in init expr
                let sub = decode_leb128_u32(bytes, pos)?;
                match sub {
                    0 | 1 | 6 | 7 => { decode_leb128_u32(bytes, pos)?; // type_idx
                        // struct.new: pop N params, push ref; struct.new_default: push ref
                        // array.new: pop init+len, push ref; array.new_default: pop len, push ref
                        // For now, produce a dummy ref (i32(0))
                        if sp < 16 { stack[sp] = Value::I32(0); sp += 1; }
                    }
                    8 => { decode_leb128_u32(bytes, pos)?; decode_leb128_u32(bytes, pos)?; // type_idx + count
                        if sp < 16 { stack[sp] = Value::I32(0); sp += 1; }
                    }
                    9 | 10 => { decode_leb128_u32(bytes, pos)?; decode_leb128_u32(bytes, pos)?; // type_idx + idx
                        if sp < 16 { stack[sp] = Value::I32(0); sp += 1; }
                    }
                    2 | 3 | 4 => { decode_leb128_u32(bytes, pos)?; decode_leb128_u32(bytes, pos)?;
                        // struct.get: pop ref, push val -> just replace TOS
                        if sp > 0 { stack[sp - 1] = Value::I32(0); }
                    }
                    5 => { decode_leb128_u32(bytes, pos)?; decode_leb128_u32(bytes, pos)?;
                        // struct.set: pop ref + val
                        if sp >= 2 { sp -= 2; }
                    }
                    11 | 12 | 13 => { decode_leb128_u32(bytes, pos)?;
                        // array.get: pop ref + idx, push val
                        if sp >= 2 { sp -= 1; stack[sp - 1] = Value::I32(0); }
                    }
                    14 => { decode_leb128_u32(bytes, pos)?;
                        // array.set: pop ref + idx + val
                        if sp >= 3 { sp -= 3; }
                    }
                    15 => { // array.len: pop ref, push i32
                        if sp > 0 { stack[sp - 1] = Value::I32(0); }
                    }
                    16 => { decode_leb128_u32(bytes, pos)?; } // array.fill
                    17 => { decode_leb128_u32(bytes, pos)?; decode_leb128_u32(bytes, pos)?; } // array.copy
                    18 | 19 => { decode_leb128_u32(bytes, pos)?; decode_leb128_u32(bytes, pos)?; } // array.init_data/elem
                    20 | 21 => { decode_leb128_i32(bytes, pos)?;
                        // ref.test: pop ref, push i32
                        if sp > 0 { stack[sp - 1] = Value::I32(0); }
                    }
                    22 | 23 => { decode_leb128_i32(bytes, pos)?;
                        // ref.cast: pop ref, push ref
                    }
                    24 | 25 => { // br_on_cast/fail
                        read_byte(bytes, pos)?;
                        decode_leb128_u32(bytes, pos)?;
                        decode_leb128_i32(bytes, pos)?;
                        decode_leb128_i32(bytes, pos)?;
                    }
                    26 | 27 => {} // any.convert_extern, extern.convert_any
                    28 => { // ref.i31: pop i32, push i31ref (represented as i32)
                        // don't change sp; the value stays as i32 on our eval stack
                    }
                    29 => { // i31.get_s: pop i31ref, sign-extend from 31 bits
                        if sp > 0 {
                            let v = match stack[sp-1] { Value::I32(v) => v, _ => 0 };
                            let masked = v & 0x7FFF_FFFF;
                            let sign_extended = if masked & 0x4000_0000 != 0 { masked | !0x7FFF_FFFFu32 as i32 } else { masked };
                            stack[sp-1] = Value::I32(sign_extended);
                        }
                    }
                    30 => { // i31.get_u: pop i31ref, mask to 31 bits
                        if sp > 0 {
                            let v = match stack[sp-1] { Value::I32(v) => v, _ => 0 };
                            stack[sp-1] = Value::I32(v & 0x7FFF_FFFF);
                        }
                    }
                    _ => {} // unknown GC sub-opcode
                }
            }
            // Extended-const: i32.add (0x6A), i32.sub (0x6B), i32.mul (0x6C)
            0x6A => {
                if sp >= 2 {
                    let b = match stack[sp-1] { Value::I32(v) => v, _ => 0 };
                    let a = match stack[sp-2] { Value::I32(v) => v, _ => 0 };
                    sp -= 1;
                    stack[sp-1] = Value::I32(a.wrapping_add(b));
                }
            }
            0x6B => {
                if sp >= 2 {
                    let b = match stack[sp-1] { Value::I32(v) => v, _ => 0 };
                    let a = match stack[sp-2] { Value::I32(v) => v, _ => 0 };
                    sp -= 1;
                    stack[sp-1] = Value::I32(a.wrapping_sub(b));
                }
            }
            0x6C => {
                if sp >= 2 {
                    let b = match stack[sp-1] { Value::I32(v) => v, _ => 0 };
                    let a = match stack[sp-2] { Value::I32(v) => v, _ => 0 };
                    sp -= 1;
                    stack[sp-1] = Value::I32(a.wrapping_mul(b));
                }
            }
            // Extended-const: i64.add (0x7C), i64.sub (0x7D), i64.mul (0x7E)
            0x7C => {
                if sp >= 2 {
                    let b = match stack[sp-1] { Value::I64(v) => v, _ => 0 };
                    let a = match stack[sp-2] { Value::I64(v) => v, _ => 0 };
                    sp -= 1;
                    stack[sp-1] = Value::I64(a.wrapping_add(b));
                }
            }
            0x7D => {
                if sp >= 2 {
                    let b = match stack[sp-1] { Value::I64(v) => v, _ => 0 };
                    let a = match stack[sp-2] { Value::I64(v) => v, _ => 0 };
                    sp -= 1;
                    stack[sp-1] = Value::I64(a.wrapping_sub(b));
                }
            }
            0x7E => {
                if sp >= 2 {
                    let b = match stack[sp-1] { Value::I64(v) => v, _ => 0 };
                    let a = match stack[sp-2] { Value::I64(v) => v, _ => 0 };
                    sp -= 1;
                    stack[sp-1] = Value::I64(a.wrapping_mul(b));
                }
            }
            _ => return Err(WasmError::InvalidSection),
        }
    }
}
