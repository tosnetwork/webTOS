//! 0xFC prefix instruction execution: saturating truncation, bulk memory, table ops, wide arithmetic.

use super::*;
use alloc::vec::Vec;

/// Execute a 0xFC-prefixed instruction.
/// Called after the 0xFC prefix has been read; reads and dispatches the sub-opcode.
pub(super) fn execute_fc(inst: &mut WasmInstance) -> ExecResult {
    macro_rules! try_exec {
        ($expr:expr) => {
            match $expr {
                Ok(v) => v,
                Err(e) => return ExecResult::Trap(e),
            }
        };
    }

    let sub_opcode = try_exec!(inst.read_leb128_u32());
    match sub_opcode {
        // Saturating float-to-int conversions (no trap on NaN/overflow)
        0 => { if inst.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(inst.pop_f32()); try_exec!(inst.push(Value::I32(sat_trunc_f32_i32(a)))); }
        1 => { if inst.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(inst.pop_f32()); try_exec!(inst.push(Value::I32(sat_trunc_f32_u32(a) as i32))); }
        2 => { if inst.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(inst.pop_f64()); try_exec!(inst.push(Value::I32(sat_trunc_f64_i32(a)))); }
        3 => { if inst.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(inst.pop_f64()); try_exec!(inst.push(Value::I32(sat_trunc_f64_u32(a) as i32))); }
        4 => { if inst.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(inst.pop_f32()); try_exec!(inst.push(Value::I64(sat_trunc_f32_i64(a)))); }
        5 => { if inst.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(inst.pop_f32()); try_exec!(inst.push(Value::I64(sat_trunc_f32_u64(a) as i64))); }
        6 => { if inst.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(inst.pop_f64()); try_exec!(inst.push(Value::I64(sat_trunc_f64_i64(a)))); }
        7 => { if inst.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(inst.pop_f64()); try_exec!(inst.push(Value::I64(sat_trunc_f64_u64(a) as i64))); }

        // memory.init (8)
        8 => {
            let seg_idx = try_exec!(inst.read_leb128_u32()) as usize;
            let mi = try_exec!(inst.read_leb128_u32()) as usize;
            let n = try_exec!(inst.pop_i32()) as u32;
            let s = try_exec!(inst.pop_i32()) as u32;
            let d = try_exec!(inst.pop_i32()) as u32;
            let msz = inst.mem_size(mi);
            let is_dropped = seg_idx < inst.dropped_data.len() && inst.dropped_data[seg_idx];
            if is_dropped {
                // Dropped segment: n=0 is OK, but still validate d
                if n != 0 || s != 0 {
                    return ExecResult::Trap(WasmError::MemoryOutOfBounds);
                }
                if (d as usize) > msz {
                    return ExecResult::Trap(WasmError::MemoryOutOfBounds);
                }
            } else if seg_idx < inst.module.data_segments.len() {
                let seg_data_offset = inst.module.data_segments[seg_idx].data_offset;
                let seg_data_len = inst.module.data_segments[seg_idx].data_len;
                let src_end = (s as u64) + (n as u64);
                let dst_end = (d as u64) + (n as u64);
                if src_end > seg_data_len as u64 || dst_end > msz as u64 {
                    return ExecResult::Trap(WasmError::MemoryOutOfBounds);
                }
                for i in 0..(n as usize) {
                    inst.memories[mi][(d as usize) + i] = inst.module.code[seg_data_offset + (s as usize) + i];
                }
            } else {
                return ExecResult::Trap(WasmError::MemoryOutOfBounds);
            }
        }
        // data.drop (9)
        9 => {
            let seg_idx = try_exec!(inst.read_leb128_u32()) as usize;
            if seg_idx < inst.dropped_data.len() {
                inst.dropped_data[seg_idx] = true;
            }
        }

        // memory.copy (10)
        10 => {
            let dst_mi = try_exec!(inst.read_leb128_u32()) as usize;
            let src_mi = try_exec!(inst.read_leb128_u32()) as usize;
            let n = try_exec!(inst.pop_i32()) as u32;
            let s = try_exec!(inst.pop_i32()) as u32;
            let d = try_exec!(inst.pop_i32()) as u32;
            let nu = n as usize; let su = s as usize; let du = d as usize;
            let src_msz = inst.mem_size(src_mi);
            let dst_msz = inst.mem_size(dst_mi);
            if su.saturating_add(nu) > src_msz || du.saturating_add(nu) > dst_msz {
                return ExecResult::Trap(WasmError::MemoryOutOfBounds);
            }
            if dst_mi == src_mi {
                if du <= su {
                    for i in 0..nu { inst.memories[dst_mi][du + i] = inst.memories[src_mi][su + i]; }
                } else {
                    for i in (0..nu).rev() { inst.memories[dst_mi][du + i] = inst.memories[src_mi][su + i]; }
                }
            } else {
                // Cross-memory copy: collect source bytes first to avoid borrow conflict
                let src_bytes: Vec<u8> = inst.memories[src_mi][su..su + nu].to_vec();
                inst.memories[dst_mi][du..du + nu].copy_from_slice(&src_bytes);
            }
        }
        // memory.fill (11)
        11 => {
            let mi = try_exec!(inst.read_leb128_u32()) as usize;
            let n = try_exec!(inst.pop_i32()) as u32;
            let val = try_exec!(inst.pop_i32()) as u8;
            let d = try_exec!(inst.pop_i32()) as u32;
            let nu = n as usize; let du = d as usize;
            let msz = inst.mem_size(mi);
            if du.saturating_add(nu) > msz {
                return ExecResult::Trap(WasmError::MemoryOutOfBounds);
            }
            for i in 0..nu { inst.memories[mi][du + i] = val; }
        }

        // table.init (12)
        12 => {
            let seg_idx = try_exec!(inst.read_leb128_u32()) as usize;
            let tbl_idx = try_exec!(inst.read_leb128_u32()) as usize;
            let is_t64 = tbl_idx < inst.module.tables.len() && inst.module.tables[tbl_idx].is_table64;
            let n = try_exec!(inst.pop_i32()) as u32; // n is always i32
            let s = try_exec!(inst.pop_i32()) as u32; // s is always i32
            let d = if is_t64 { try_exec!(inst.pop_i64()) as u32 } else { try_exec!(inst.pop_i32()) as u32 };
            let is_dropped = seg_idx < inst.dropped_elems.len() && inst.dropped_elems[seg_idx];
            if is_dropped {
                if n != 0 || s != 0 {
                    return ExecResult::Trap(WasmError::TableIndexOutOfBounds);
                }
                if tbl_idx >= inst.tables.len() || (d as usize) > inst.tables[inst.tbl(tbl_idx)].len() {
                    return ExecResult::Trap(WasmError::TableIndexOutOfBounds);
                }
            } else if seg_idx < inst.module.element_segments.len() {
                let seg_len = inst.module.element_segments[seg_idx].func_indices.len();
                if tbl_idx >= inst.tables.len() {
                    return ExecResult::Trap(WasmError::TableIndexOutOfBounds);
                }
                let tbl_len = inst.tables[inst.tbl(tbl_idx)].len();
                let src_end = (s as u64) + (n as u64);
                let dst_end = (d as u64) + (n as u64);
                if src_end > seg_len as u64 || dst_end > tbl_len as u64 {
                    return ExecResult::Trap(WasmError::TableIndexOutOfBounds);
                }
                let rt = resolve_alias(&inst.table_aliases, tbl_idx);
                for i in 0..(n as usize) {
                    let func_idx = inst.module.element_segments[seg_idx].func_indices[(s as usize) + i];
                    if func_idx == u32::MAX {
                        inst.tables[rt][(d as usize) + i] = None;
                    } else {
                        inst.tables[rt][(d as usize) + i] = Some(func_idx);
                    }
                }
            } else {
                return ExecResult::Trap(WasmError::TableIndexOutOfBounds);
            }
        }
        // elem.drop (13)
        13 => {
            let seg_idx = try_exec!(inst.read_leb128_u32()) as usize;
            if seg_idx < inst.dropped_elems.len() {
                inst.dropped_elems[seg_idx] = true;
            }
        }
        // table.copy (14)
        14 => {
            let dst_tbl = try_exec!(inst.read_leb128_u32()) as usize;
            let src_tbl = try_exec!(inst.read_leb128_u32()) as usize;
            let src_t64 = src_tbl < inst.module.tables.len() && inst.module.tables[src_tbl].is_table64;
            let dst_t64 = dst_tbl < inst.module.tables.len() && inst.module.tables[dst_tbl].is_table64;
            // n: smaller of src/dst (i32 if either is i32)
            let n_is_64 = src_t64 && dst_t64;
            let n = if n_is_64 { try_exec!(inst.pop_i64()) as u64 } else { try_exec!(inst.pop_i32()) as u32 as u64 };
            let s = if src_t64 { try_exec!(inst.pop_i64()) as u64 } else { try_exec!(inst.pop_i32()) as u32 as u64 };
            let d = if dst_t64 { try_exec!(inst.pop_i64()) as u64 } else { try_exec!(inst.pop_i32()) as u32 as u64 };
            let nu = n as usize; let su = s as usize; let du = d as usize;
            if dst_tbl >= inst.tables.len() || src_tbl >= inst.tables.len() {
                return ExecResult::Trap(WasmError::TableIndexOutOfBounds);
            }
            if su.saturating_add(nu) > inst.tables[inst.tbl(src_tbl)].len()
                || du.saturating_add(nu) > inst.tables[inst.tbl(dst_tbl)].len()
            {
                return ExecResult::Trap(WasmError::TableIndexOutOfBounds);
            }
            let rd = resolve_alias(&inst.table_aliases, dst_tbl);
            let rs = resolve_alias(&inst.table_aliases, src_tbl);
            if rd == rs {
                if du <= su {
                    for i in 0..nu { inst.tables[rd][du + i] = inst.tables[rd][su + i]; }
                } else {
                    for i in (0..nu).rev() { inst.tables[rd][du + i] = inst.tables[rd][su + i]; }
                }
            } else {
                for i in 0..nu {
                    let val = inst.tables[rs][su + i];
                    inst.tables[rd][du + i] = val;
                }
            }
        }
        // table.grow (15)
        15 => {
            let tbl_idx = try_exec!(inst.read_leb128_u32()) as usize;
            let is_t64 = tbl_idx < inst.module.tables.len() && inst.module.tables[tbl_idx].is_table64;
            let n = if is_t64 { try_exec!(inst.pop_i64()) as u64 } else { try_exec!(inst.pop_i32()) as u32 as u64 };
            let init = try_exec!(inst.pop());
            if tbl_idx >= inst.tables.len() {
                if is_t64 { try_exec!(inst.push(Value::I64(-1))); } else { try_exec!(inst.push(Value::I32(-1))); }
            } else {
                let old_size = inst.tables[inst.tbl(tbl_idx)].len() as u64;
                let new_size = old_size + n;
                let max = inst.module.tables.get(tbl_idx).and_then(|t| t.max);
                let limit = max.map_or(MAX_TABLE_SIZE as u64, |m| m as u64);
                if new_size > limit || new_size > MAX_TABLE_SIZE as u64 {
                    if is_t64 { try_exec!(inst.push(Value::I64(-1))); } else { try_exec!(inst.push(Value::I32(-1))); }
                } else {
                    let fill_val = match init {
                        Value::NullRef => None,
                        Value::I32(v) => if v < 0 { None } else { Some(v as u32) },
                        Value::GcRef(heap_idx) => Some(heap_idx | 0x8000_0000),
                        _ => None,
                    };
                    let rt = resolve_alias(&inst.table_aliases, tbl_idx);
                    inst.tables[rt].resize(new_size as usize, fill_val);
                    if is_t64 { try_exec!(inst.push(Value::I64(old_size as i64))); } else { try_exec!(inst.push(Value::I32(old_size as i32))); }
                }
            }
        }
        // table.size (16)
        16 => {
            let tbl_idx = try_exec!(inst.read_leb128_u32()) as usize;
            let size = if tbl_idx < inst.tables.len() { inst.tables[inst.tbl(tbl_idx)].len() } else { 0 };
            if tbl_idx < inst.module.tables.len() && inst.module.tables[tbl_idx].is_table64 {
                try_exec!(inst.push(Value::I64(size as i64)));
            } else {
                try_exec!(inst.push(Value::I32(size as i32)));
            }
        }
        // table.fill (17)
        17 => {
            let tbl_idx = try_exec!(inst.read_leb128_u32()) as usize;
            let is_t64 = tbl_idx < inst.module.tables.len() && inst.module.tables[tbl_idx].is_table64;
            let n = if is_t64 { try_exec!(inst.pop_i64()) as u64 } else { try_exec!(inst.pop_i32()) as u32 as u64 };
            let raw_val = try_exec!(inst.pop());
            let d = if is_t64 { try_exec!(inst.pop_i64()) as u64 } else { try_exec!(inst.pop_i32()) as u32 as u64 };
            let nu = n as usize; let du = d as usize;
            if tbl_idx >= inst.tables.len() || du.saturating_add(nu) > inst.tables[inst.tbl(tbl_idx)].len() {
                return ExecResult::Trap(WasmError::TableIndexOutOfBounds);
            }
            let entry = match raw_val {
                Value::NullRef => None,
                Value::I32(v) => if v < 0 { None } else { Some(v as u32) },
                Value::GcRef(heap_idx) => Some(heap_idx | 0x8000_0000),
                _ => None,
            };
            let rt = resolve_alias(&inst.table_aliases, tbl_idx);
            for i in 0..nu { inst.tables[rt][du + i] = entry; }
        }

        // ── Wide-arithmetic (0x13-0x16) ──
        // i64.add128: [i64, i64, i64, i64] -> [i64, i64]
        0x13 => {
            let b_hi = try_exec!(inst.pop_i64()) as u64;
            let b_lo = try_exec!(inst.pop_i64()) as u64;
            let a_hi = try_exec!(inst.pop_i64()) as u64;
            let a_lo = try_exec!(inst.pop_i64()) as u64;
            let a: u128 = (a_hi as u128) << 64 | a_lo as u128;
            let b: u128 = (b_hi as u128) << 64 | b_lo as u128;
            let result = a.wrapping_add(b);
            try_exec!(inst.push(Value::I64(result as u64 as i64)));
            try_exec!(inst.push(Value::I64((result >> 64) as u64 as i64)));
        }
        // i64.sub128: [i64, i64, i64, i64] -> [i64, i64]
        0x14 => {
            let b_hi = try_exec!(inst.pop_i64()) as u64;
            let b_lo = try_exec!(inst.pop_i64()) as u64;
            let a_hi = try_exec!(inst.pop_i64()) as u64;
            let a_lo = try_exec!(inst.pop_i64()) as u64;
            let a: u128 = (a_hi as u128) << 64 | a_lo as u128;
            let b: u128 = (b_hi as u128) << 64 | b_lo as u128;
            let result = a.wrapping_sub(b);
            try_exec!(inst.push(Value::I64(result as u64 as i64)));
            try_exec!(inst.push(Value::I64((result >> 64) as u64 as i64)));
        }
        // i64.mul_wide_s: [i64, i64] -> [i64, i64]
        0x15 => {
            let b = try_exec!(inst.pop_i64());
            let a = try_exec!(inst.pop_i64());
            let result = (a as i128).wrapping_mul(b as i128) as u128;
            try_exec!(inst.push(Value::I64(result as u64 as i64)));
            try_exec!(inst.push(Value::I64((result >> 64) as u64 as i64)));
        }
        // i64.mul_wide_u: [i64, i64] -> [i64, i64]
        0x16 => {
            let b = try_exec!(inst.pop_i64()) as u64;
            let a = try_exec!(inst.pop_i64()) as u64;
            let result = (a as u128).wrapping_mul(b as u128);
            try_exec!(inst.push(Value::I64(result as u64 as i64)));
            try_exec!(inst.push(Value::I64((result >> 64) as u64 as i64)));
        }

        _ => return ExecResult::Trap(WasmError::InvalidOpcode(0xFC)),
    }


    ExecResult::Ok
}
