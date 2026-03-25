//! SIMD (0xFD prefix) instruction execution.

use super::*;

/// Execute a 0xFD-prefixed SIMD instruction.
/// Called after the 0xFD prefix has been read; reads and dispatches the sub-opcode.
pub(super) fn execute_simd(inst: &mut WasmInstance) -> ExecResult {
    macro_rules! try_exec {
        ($expr:expr) => {
            match $expr {
                Ok(v) => v,
                Err(e) => return ExecResult::Trap(e),
            }
        };
    }

    let simd_op = try_exec!(inst.read_leb128_u32());
    match simd_op {
        // ── Memory (0x00-0x0b) ──────────────────────
        0x00 => { // v128.load
            let (mi, offset) = try_exec!(inst.read_memarg());
            let base = try_exec!(inst.pop_i32()) as u32;
            let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
            let val = try_exec!(inst.mem_load_v128(mi, addr));
            try_exec!(inst.push(Value::V128(val)));
        }
        0x01..=0x0a => { // v128.load*x*_s/u, load*_splat
            let (mi, offset) = try_exec!(inst.read_memarg());
            let base = try_exec!(inst.pop_i32()) as u32;
            let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
            let msz = inst.mem_size(mi);
            let m = inst.mem(mi);
            let val = match simd_op {
                0x01 => { if addr + 8 > msz { return ExecResult::Trap(WasmError::MemoryOutOfBounds); } let mut r = [0i16; 8]; for i in 0..8 { r[i] = m[addr+i] as i8 as i16; } V128::from_i16x8(r) }
                0x02 => { if addr + 8 > msz { return ExecResult::Trap(WasmError::MemoryOutOfBounds); } let mut r = [0i16; 8]; for i in 0..8 { r[i] = m[addr+i] as i16; } V128::from_i16x8(r) }
                0x03 => { if addr + 8 > msz { return ExecResult::Trap(WasmError::MemoryOutOfBounds); } let mut r = [0i32; 4]; for i in 0..4 { r[i] = i16::from_le_bytes([m[addr+i*2], m[addr+i*2+1]]) as i32; } V128::from_i32x4(r) }
                0x04 => { if addr + 8 > msz { return ExecResult::Trap(WasmError::MemoryOutOfBounds); } let mut r = [0i32; 4]; for i in 0..4 { r[i] = u16::from_le_bytes([m[addr+i*2], m[addr+i*2+1]]) as i32; } V128::from_i32x4(r) }
                0x05 => { if addr + 8 > msz { return ExecResult::Trap(WasmError::MemoryOutOfBounds); } let mut r = [0i64; 2]; for i in 0..2 { r[i] = i32::from_le_bytes([m[addr+i*4], m[addr+i*4+1], m[addr+i*4+2], m[addr+i*4+3]]) as i64; } V128::from_i64x2(r) }
                0x06 => { if addr + 8 > msz { return ExecResult::Trap(WasmError::MemoryOutOfBounds); } let mut r = [0i64; 2]; for i in 0..2 { r[i] = u32::from_le_bytes([m[addr+i*4], m[addr+i*4+1], m[addr+i*4+2], m[addr+i*4+3]]) as i64; } V128::from_i64x2(r) }
                0x07 => { if addr >= msz { return ExecResult::Trap(WasmError::MemoryOutOfBounds); } V128::from_u8x16([m[addr]; 16]) }
                0x08 => { if addr + 2 > msz { return ExecResult::Trap(WasmError::MemoryOutOfBounds); } let v = [m[addr], m[addr+1]]; let mut b = [0u8; 16]; for i in 0..8 { b[i*2] = v[0]; b[i*2+1] = v[1]; } V128(b) }
                0x09 => { if addr + 4 > msz { return ExecResult::Trap(WasmError::MemoryOutOfBounds); } let mut b = [0u8; 16]; for i in 0..4 { b[i*4..i*4+4].copy_from_slice(&m[addr..addr+4]); } V128(b) }
                0x0a => { if addr + 8 > msz { return ExecResult::Trap(WasmError::MemoryOutOfBounds); } let mut b = [0u8; 16]; b[0..8].copy_from_slice(&m[addr..addr+8]); b[8..16].copy_from_slice(&m[addr..addr+8]); V128(b) }
                _ => V128::ZERO,
            };
            try_exec!(inst.push(Value::V128(val)));
        }
        0x0b => { // v128.store
            let (mi, offset) = try_exec!(inst.read_memarg());
            let val = try_exec!(inst.pop_v128());
            let base = try_exec!(inst.pop_i32()) as u32;
            let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
            try_exec!(inst.mem_store_v128(mi, addr, val));
        }
        // ── Const/Shuffle/Swizzle (0x0c-0x0e) ────────
        0x0c => { let val = try_exec!(inst.read_v128()); try_exec!(inst.push(Value::V128(val))); }
        0x0d => { // i8x16.shuffle
            let mut lanes = [0u8; 16]; for i in 0..16 { lanes[i] = try_exec!(inst.read_byte()); }
            let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128());
            let mut combined = [0u8; 32]; combined[0..16].copy_from_slice(&a.0); combined[16..32].copy_from_slice(&b.0);
            let mut r = [0u8; 16]; for i in 0..16 { r[i] = combined[(lanes[i] & 31) as usize]; }
            try_exec!(inst.push(Value::V128(V128(r))));
        }
        0x0e => { // i8x16.swizzle
            let s = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128());
            let mut r = [0u8; 16]; for i in 0..16 { let idx = s.0[i]; r[i] = if idx < 16 { a.0[idx as usize] } else { 0 }; }
            try_exec!(inst.push(Value::V128(V128(r))));
        }
        // ── Splat (0x0f-0x14) ────────────────────────
        0x0f => { let v = try_exec!(inst.pop_i32()) as u8; try_exec!(inst.push(Value::V128(V128::from_u8x16([v; 16])))); }
        0x10 => { let v = try_exec!(inst.pop_i32()) as i16; try_exec!(inst.push(Value::V128(V128::from_i16x8([v; 8])))); }
        0x11 => { let v = try_exec!(inst.pop_i32()); try_exec!(inst.push(Value::V128(V128::from_i32x4([v; 4])))); }
        0x12 => { let v = try_exec!(inst.pop_i64()); try_exec!(inst.push(Value::V128(V128::from_i64x2([v; 2])))); }
        0x13 => { let v = try_exec!(inst.pop_f32()); try_exec!(inst.push(Value::V128(V128::from_f32x4([v; 4])))); }
        0x14 => { let v = try_exec!(inst.pop_f64()); try_exec!(inst.push(Value::V128(V128::from_f64x2([v; 2])))); }
        // ── Extract/Replace lane (0x15-0x22) ─────────
        0x15 => { let l = try_exec!(inst.read_byte()) as usize; let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::I32(a.as_i8x16()[l & 15] as i32))); }
        0x16 => { let l = try_exec!(inst.read_byte()) as usize; let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::I32(a.as_u8x16()[l & 15] as i32))); }
        0x17 => { let l = try_exec!(inst.read_byte()) as usize; let v = try_exec!(inst.pop_i32()) as u8; let mut a = try_exec!(inst.pop_v128()); a.0[l & 15] = v; try_exec!(inst.push(Value::V128(a))); }
        0x18 => { let l = try_exec!(inst.read_byte()) as usize; let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::I32(a.as_i16x8()[l & 7] as i32))); }
        0x19 => { let l = try_exec!(inst.read_byte()) as usize; let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::I32(a.as_u16x8()[l & 7] as i32))); }
        0x1a => { let l = try_exec!(inst.read_byte()) as usize; let v = try_exec!(inst.pop_i32()) as i16; let a = try_exec!(inst.pop_v128()); let mut arr = a.as_i16x8(); arr[l & 7] = v; try_exec!(inst.push(Value::V128(V128::from_i16x8(arr)))); }
        0x1b => { let l = try_exec!(inst.read_byte()) as usize; let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::I32(a.as_i32x4()[l & 3]))); }
        0x1c => { let l = try_exec!(inst.read_byte()) as usize; let v = try_exec!(inst.pop_i32()); let a = try_exec!(inst.pop_v128()); let mut arr = a.as_i32x4(); arr[l & 3] = v; try_exec!(inst.push(Value::V128(V128::from_i32x4(arr)))); }
        0x1d => { let l = try_exec!(inst.read_byte()) as usize; let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::I64(a.as_i64x2()[l & 1]))); }
        0x1e => { let l = try_exec!(inst.read_byte()) as usize; let v = try_exec!(inst.pop_i64()); let a = try_exec!(inst.pop_v128()); let mut arr = a.as_i64x2(); arr[l & 1] = v; try_exec!(inst.push(Value::V128(V128::from_i64x2(arr)))); }
        0x1f => { let l = try_exec!(inst.read_byte()) as usize; let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::F32(a.as_f32x4()[l & 3]))); }
        0x20 => { let l = try_exec!(inst.read_byte()) as usize; let v = try_exec!(inst.pop_f32()); let a = try_exec!(inst.pop_v128()); let mut arr = a.as_f32x4(); arr[l & 3] = v; try_exec!(inst.push(Value::V128(V128::from_f32x4(arr)))); }
        0x21 => { let l = try_exec!(inst.read_byte()) as usize; let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::F64(a.as_f64x2()[l & 1]))); }
        0x22 => { let l = try_exec!(inst.read_byte()) as usize; let v = try_exec!(inst.pop_f64()); let a = try_exec!(inst.pop_v128()); let mut arr = a.as_f64x2(); arr[l & 1] = v; try_exec!(inst.push(Value::V128(V128::from_f64x2(arr)))); }
        // ── i8x16 compare (0x23-0x2c) ────────────────
        0x23 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); let (aa, bb) = (a.as_i8x16(), b.as_i8x16()); let mut r = [0u8; 16]; for i in 0..16 { r[i] = if aa[i] == bb[i] { 0xFF } else { 0 }; } try_exec!(inst.push(Value::V128(V128(r)))); }
        0x24 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); let (aa, bb) = (a.as_i8x16(), b.as_i8x16()); let mut r = [0u8; 16]; for i in 0..16 { r[i] = if aa[i] != bb[i] { 0xFF } else { 0 }; } try_exec!(inst.push(Value::V128(V128(r)))); }
        0x25 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); let (aa, bb) = (a.as_i8x16(), b.as_i8x16()); let mut r = [0u8; 16]; for i in 0..16 { r[i] = if aa[i] < bb[i] { 0xFF } else { 0 }; } try_exec!(inst.push(Value::V128(V128(r)))); }
        0x26 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); let (aa, bb) = (a.as_u8x16(), b.as_u8x16()); let mut r = [0u8; 16]; for i in 0..16 { r[i] = if aa[i] < bb[i] { 0xFF } else { 0 }; } try_exec!(inst.push(Value::V128(V128(r)))); }
        0x27 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); let (aa, bb) = (a.as_i8x16(), b.as_i8x16()); let mut r = [0u8; 16]; for i in 0..16 { r[i] = if aa[i] > bb[i] { 0xFF } else { 0 }; } try_exec!(inst.push(Value::V128(V128(r)))); }
        0x28 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); let (aa, bb) = (a.as_u8x16(), b.as_u8x16()); let mut r = [0u8; 16]; for i in 0..16 { r[i] = if aa[i] > bb[i] { 0xFF } else { 0 }; } try_exec!(inst.push(Value::V128(V128(r)))); }
        0x29 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); let (aa, bb) = (a.as_i8x16(), b.as_i8x16()); let mut r = [0u8; 16]; for i in 0..16 { r[i] = if aa[i] <= bb[i] { 0xFF } else { 0 }; } try_exec!(inst.push(Value::V128(V128(r)))); }
        0x2a => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); let (aa, bb) = (a.as_u8x16(), b.as_u8x16()); let mut r = [0u8; 16]; for i in 0..16 { r[i] = if aa[i] <= bb[i] { 0xFF } else { 0 }; } try_exec!(inst.push(Value::V128(V128(r)))); }
        0x2b => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); let (aa, bb) = (a.as_i8x16(), b.as_i8x16()); let mut r = [0u8; 16]; for i in 0..16 { r[i] = if aa[i] >= bb[i] { 0xFF } else { 0 }; } try_exec!(inst.push(Value::V128(V128(r)))); }
        0x2c => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); let (aa, bb) = (a.as_u8x16(), b.as_u8x16()); let mut r = [0u8; 16]; for i in 0..16 { r[i] = if aa[i] >= bb[i] { 0xFF } else { 0 }; } try_exec!(inst.push(Value::V128(V128(r)))); }
        // ── i16x8 compare (0x2d-0x36) ────────────────
        0x2d => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); let (sa, sb) = (a.as_i16x8(), b.as_i16x8()); try_exec!(inst.push(Value::V128(V128::from_i16x8(core::array::from_fn(|i| if sa[i]==sb[i] {-1} else {0}))))); }
        0x2e => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); let (sa, sb) = (a.as_i16x8(), b.as_i16x8()); try_exec!(inst.push(Value::V128(V128::from_i16x8(core::array::from_fn(|i| if sa[i]!=sb[i] {-1} else {0}))))); }
        0x2f => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); let (sa, sb) = (a.as_i16x8(), b.as_i16x8()); try_exec!(inst.push(Value::V128(V128::from_i16x8(core::array::from_fn(|i| if sa[i]<sb[i] {-1} else {0}))))); }
        0x30 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); let (ua, ub) = (a.as_u16x8(), b.as_u16x8()); try_exec!(inst.push(Value::V128(V128::from_i16x8(core::array::from_fn(|i| if ua[i]<ub[i] {-1} else {0}))))); }
        0x31 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); let (sa, sb) = (a.as_i16x8(), b.as_i16x8()); try_exec!(inst.push(Value::V128(V128::from_i16x8(core::array::from_fn(|i| if sa[i]>sb[i] {-1} else {0}))))); }
        0x32 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); let (ua, ub) = (a.as_u16x8(), b.as_u16x8()); try_exec!(inst.push(Value::V128(V128::from_i16x8(core::array::from_fn(|i| if ua[i]>ub[i] {-1} else {0}))))); }
        0x33 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); let (sa, sb) = (a.as_i16x8(), b.as_i16x8()); try_exec!(inst.push(Value::V128(V128::from_i16x8(core::array::from_fn(|i| if sa[i]<=sb[i] {-1} else {0}))))); }
        0x34 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); let (ua, ub) = (a.as_u16x8(), b.as_u16x8()); try_exec!(inst.push(Value::V128(V128::from_i16x8(core::array::from_fn(|i| if ua[i]<=ub[i] {-1} else {0}))))); }
        0x35 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); let (sa, sb) = (a.as_i16x8(), b.as_i16x8()); try_exec!(inst.push(Value::V128(V128::from_i16x8(core::array::from_fn(|i| if sa[i]>=sb[i] {-1} else {0}))))); }
        0x36 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); let (ua, ub) = (a.as_u16x8(), b.as_u16x8()); try_exec!(inst.push(Value::V128(V128::from_i16x8(core::array::from_fn(|i| if ua[i]>=ub[i] {-1} else {0}))))); }
        // ── i32x4 compare (0x37-0x40) ────────────────
        0x37 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| if a.as_i32x4()[i]==b.as_i32x4()[i] {-1} else {0}))))); }
        0x38 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| if a.as_i32x4()[i]!=b.as_i32x4()[i] {-1} else {0}))))); }
        0x39 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| if a.as_i32x4()[i]<b.as_i32x4()[i] {-1} else {0}))))); }
        0x3a => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| if a.as_u32x4()[i]<b.as_u32x4()[i] {-1i32} else {0}))))); }
        0x3b => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| if a.as_i32x4()[i]>b.as_i32x4()[i] {-1} else {0}))))); }
        0x3c => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| if a.as_u32x4()[i]>b.as_u32x4()[i] {-1i32} else {0}))))); }
        0x3d => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| if a.as_i32x4()[i]<=b.as_i32x4()[i] {-1} else {0}))))); }
        0x3e => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| if a.as_u32x4()[i]<=b.as_u32x4()[i] {-1i32} else {0}))))); }
        0x3f => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| if a.as_i32x4()[i]>=b.as_i32x4()[i] {-1} else {0}))))); }
        0x40 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| if a.as_u32x4()[i]>=b.as_u32x4()[i] {-1i32} else {0}))))); }
        // ── f32x4 compare (0x41-0x46) ────────────────
        0x41 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| if a.as_f32x4()[i]==b.as_f32x4()[i] {-1} else {0}))))); }
        0x42 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| if a.as_f32x4()[i]!=b.as_f32x4()[i] {-1} else {0}))))); }
        0x43 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| if a.as_f32x4()[i]<b.as_f32x4()[i] {-1} else {0}))))); }
        0x44 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| if a.as_f32x4()[i]>b.as_f32x4()[i] {-1} else {0}))))); }
        0x45 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| if a.as_f32x4()[i]<=b.as_f32x4()[i] {-1} else {0}))))); }
        0x46 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| if a.as_f32x4()[i]>=b.as_f32x4()[i] {-1} else {0}))))); }
        // ── f64x2 compare (0x47-0x4c) ────────────────
        0x47 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_i64x2(core::array::from_fn(|i| if a.as_f64x2()[i]==b.as_f64x2()[i] {-1i64} else {0}))))); }
        0x48 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_i64x2(core::array::from_fn(|i| if a.as_f64x2()[i]!=b.as_f64x2()[i] {-1i64} else {0}))))); }
        0x49 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_i64x2(core::array::from_fn(|i| if a.as_f64x2()[i]<b.as_f64x2()[i] {-1i64} else {0}))))); }
        0x4a => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_i64x2(core::array::from_fn(|i| if a.as_f64x2()[i]>b.as_f64x2()[i] {-1i64} else {0}))))); }
        0x4b => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_i64x2(core::array::from_fn(|i| if a.as_f64x2()[i]<=b.as_f64x2()[i] {-1i64} else {0}))))); }
        0x4c => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_i64x2(core::array::from_fn(|i| if a.as_f64x2()[i]>=b.as_f64x2()[i] {-1i64} else {0}))))); }
        // ── v128 bitwise (0x4d-0x53) ─────────────────
        0x4d => { let a = try_exec!(inst.pop_v128()); let mut r = [0u8; 16]; for i in 0..16 { r[i] = !a.0[i]; } try_exec!(inst.push(Value::V128(V128(r)))); }
        0x4e => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); let mut r = [0u8; 16]; for i in 0..16 { r[i] = a.0[i] & b.0[i]; } try_exec!(inst.push(Value::V128(V128(r)))); }
        0x4f => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); let mut r = [0u8; 16]; for i in 0..16 { r[i] = a.0[i] & !b.0[i]; } try_exec!(inst.push(Value::V128(V128(r)))); }
        0x50 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); let mut r = [0u8; 16]; for i in 0..16 { r[i] = a.0[i] | b.0[i]; } try_exec!(inst.push(Value::V128(V128(r)))); }
        0x51 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); let mut r = [0u8; 16]; for i in 0..16 { r[i] = a.0[i] ^ b.0[i]; } try_exec!(inst.push(Value::V128(V128(r)))); }
        0x52 => { let c = try_exec!(inst.pop_v128()); let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); let mut r = [0u8; 16]; for i in 0..16 { r[i] = (a.0[i] & c.0[i]) | (b.0[i] & !c.0[i]); } try_exec!(inst.push(Value::V128(V128(r)))); }
        0x53 => { let a = try_exec!(inst.pop_v128()); let any = a.0.iter().any(|&b| b != 0); try_exec!(inst.push(Value::I32(if any { 1 } else { 0 }))); }
        // ── Load/Store lane (0x54-0x5b) ──────────────
        0x54..=0x57 => { // load8/16/32/64_lane
            let (mi, offset) = try_exec!(inst.read_memarg()); let lane = try_exec!(inst.read_byte()) as usize;
            let mut v = try_exec!(inst.pop_v128()); let base = try_exec!(inst.pop_i32()) as u32;
            let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
            let msz = inst.mem_size(mi);
            match simd_op {
                0x54 => { if addr >= msz { return ExecResult::Trap(WasmError::MemoryOutOfBounds); } v.0[lane & 15] = inst.mem(mi)[addr]; }
                0x55 => { if addr + 2 > msz { return ExecResult::Trap(WasmError::MemoryOutOfBounds); } let l = (lane & 7) * 2; let m = inst.mem(mi); v.0[l] = m[addr]; v.0[l+1] = m[addr+1]; }
                0x56 => { if addr + 4 > msz { return ExecResult::Trap(WasmError::MemoryOutOfBounds); } let l = (lane & 3) * 4; v.0[l..l+4].copy_from_slice(&inst.mem(mi)[addr..addr+4]); }
                0x57 => { if addr + 8 > msz { return ExecResult::Trap(WasmError::MemoryOutOfBounds); } let l = (lane & 1) * 8; v.0[l..l+8].copy_from_slice(&inst.mem(mi)[addr..addr+8]); }
                _ => {}
            }
            try_exec!(inst.push(Value::V128(v)));
        }
        0x58..=0x5b => { // store8/16/32/64_lane
            let (mi, offset) = try_exec!(inst.read_memarg()); let lane = try_exec!(inst.read_byte()) as usize;
            let v = try_exec!(inst.pop_v128()); let base = try_exec!(inst.pop_i32()) as u32;
            let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
            let msz = inst.mem_size(mi);
            match simd_op {
                0x58 => { if addr >= msz { return ExecResult::Trap(WasmError::MemoryOutOfBounds); } inst.mem_mut(mi)[addr] = v.0[lane & 15]; }
                0x59 => { if addr + 2 > msz { return ExecResult::Trap(WasmError::MemoryOutOfBounds); } let l = (lane & 7) * 2; let m = inst.mem_mut(mi); m[addr] = v.0[l]; m[addr+1] = v.0[l+1]; }
                0x5a => { if addr + 4 > msz { return ExecResult::Trap(WasmError::MemoryOutOfBounds); } let l = (lane & 3) * 4; inst.mem_mut(mi)[addr..addr+4].copy_from_slice(&v.0[l..l+4]); }
                0x5b => { if addr + 8 > msz { return ExecResult::Trap(WasmError::MemoryOutOfBounds); } let l = (lane & 1) * 8; inst.mem_mut(mi)[addr..addr+8].copy_from_slice(&v.0[l..l+8]); }
                _ => {}
            }
        }
        // ── Load zero (0x5c-0x5d) ────────────────────
        0x5c => { let (mi, o) = try_exec!(inst.read_memarg()); let b = try_exec!(inst.pop_i32()) as u32; let addr = try_exec!(b.checked_add(o).ok_or(WasmError::MemoryOutOfBounds)) as usize; let v = try_exec!(inst.mem_load_u32(mi, addr)); let mut r = [0u8; 16]; r[0..4].copy_from_slice(&v.to_le_bytes()); try_exec!(inst.push(Value::V128(V128(r)))); }
        0x5d => { let (mi, o) = try_exec!(inst.read_memarg()); let b = try_exec!(inst.pop_i32()) as u32; let addr = try_exec!(b.checked_add(o).ok_or(WasmError::MemoryOutOfBounds)) as usize; let msz = inst.mem_size(mi); if addr.checked_add(8).ok_or(WasmError::MemoryOutOfBounds).is_err() || addr + 8 > msz { return ExecResult::Trap(WasmError::MemoryOutOfBounds); } let mut r = [0u8; 16]; r[0..8].copy_from_slice(&inst.mem(mi)[addr..addr+8]); try_exec!(inst.push(Value::V128(V128(r)))); }
        // ── Conversion (0x5e-0x5f) ───────────────────
        0x5e => { let a = try_exec!(inst.pop_v128()); let aa = a.as_f64x2(); try_exec!(inst.push(Value::V128(V128::from_f32x4([aa[0] as f32, aa[1] as f32, 0.0, 0.0])))); }
        0x5f => { let a = try_exec!(inst.pop_v128()); let aa = a.as_f32x4(); try_exec!(inst.push(Value::V128(V128::from_f64x2([aa[0] as f64, aa[1] as f64])))); }
        // ── i8x16 arithmetic (0x60-0x7b) with interleaved f32x4/f64x2 rounding ──
        0x60 => { let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_i8x16(core::array::from_fn(|i| a.as_i8x16()[i].wrapping_abs()))))); }
        0x61 => { let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_i8x16(core::array::from_fn(|i| a.as_i8x16()[i].wrapping_neg()))))); }
        0x62 => { let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_u8x16(core::array::from_fn(|i| a.as_u8x16()[i].count_ones() as u8))))); }
        0x63 => { let a = try_exec!(inst.pop_v128()); let all = a.as_i8x16().iter().all(|&v| v != 0); try_exec!(inst.push(Value::I32(if all { 1 } else { 0 }))); }
        0x64 => { let a = try_exec!(inst.pop_v128()); let aa = a.as_u8x16(); let mut r = 0u32; for i in 0..16 { if aa[i] & 0x80 != 0 { r |= 1 << i; } } try_exec!(inst.push(Value::I32(r as i32))); }
        0x65 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); let (aa, bb) = (a.as_i16x8(), b.as_i16x8()); let mut r = [0u8; 16]; for i in 0..8 { r[i] = aa[i].clamp(-128,127) as i8 as u8; } for i in 0..8 { r[i+8] = bb[i].clamp(-128,127) as i8 as u8; } try_exec!(inst.push(Value::V128(V128(r)))); }
        0x66 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); let (aa, bb) = (a.as_i16x8(), b.as_i16x8()); let mut r = [0u8; 16]; for i in 0..8 { r[i] = aa[i].clamp(0,255) as u8; } for i in 0..8 { r[i+8] = bb[i].clamp(0,255) as u8; } try_exec!(inst.push(Value::V128(V128(r)))); }
        0x67 => { let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_f32x4(core::array::from_fn(|i| WasmInstance::wasm_ceil_f32(a.as_f32x4()[i])))))); }
        0x68 => { let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_f32x4(core::array::from_fn(|i| WasmInstance::wasm_floor_f32(a.as_f32x4()[i])))))); }
        0x69 => { let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_f32x4(core::array::from_fn(|i| WasmInstance::wasm_trunc_f32(a.as_f32x4()[i])))))); }
        0x6a => { let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_f32x4(core::array::from_fn(|i| WasmInstance::wasm_nearest_f32(a.as_f32x4()[i])))))); }
        0x6b => { let s = try_exec!(inst.pop_i32()) as u32; let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_u8x16(core::array::from_fn(|i| a.as_u8x16()[i].wrapping_shl(s & 7)))))); }
        0x6c => { let s = try_exec!(inst.pop_i32()) as u32; let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_i8x16(core::array::from_fn(|i| a.as_i8x16()[i].wrapping_shr(s & 7)))))); }
        0x6d => { let s = try_exec!(inst.pop_i32()) as u32; let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_u8x16(core::array::from_fn(|i| a.as_u8x16()[i].wrapping_shr(s & 7)))))); }
        0x6e => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_u8x16(core::array::from_fn(|i| a.as_u8x16()[i].wrapping_add(b.as_u8x16()[i])))))); }
        0x6f => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_i8x16(core::array::from_fn(|i| a.as_i8x16()[i].saturating_add(b.as_i8x16()[i])))))); }
        0x70 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_u8x16(core::array::from_fn(|i| a.as_u8x16()[i].saturating_add(b.as_u8x16()[i])))))); }
        0x71 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_u8x16(core::array::from_fn(|i| a.as_u8x16()[i].wrapping_sub(b.as_u8x16()[i])))))); }
        0x72 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_i8x16(core::array::from_fn(|i| a.as_i8x16()[i].saturating_sub(b.as_i8x16()[i])))))); }
        0x73 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_u8x16(core::array::from_fn(|i| a.as_u8x16()[i].saturating_sub(b.as_u8x16()[i])))))); }
        0x74 => { let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_f64x2(core::array::from_fn(|i| WasmInstance::wasm_ceil_f64(a.as_f64x2()[i])))))); }
        0x75 => { let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_f64x2(core::array::from_fn(|i| WasmInstance::wasm_floor_f64(a.as_f64x2()[i])))))); }
        0x76 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_i8x16(core::array::from_fn(|i| a.as_i8x16()[i].min(b.as_i8x16()[i])))))); }
        0x77 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_u8x16(core::array::from_fn(|i| a.as_u8x16()[i].min(b.as_u8x16()[i])))))); }
        0x78 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_i8x16(core::array::from_fn(|i| a.as_i8x16()[i].max(b.as_i8x16()[i])))))); }
        0x79 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_u8x16(core::array::from_fn(|i| a.as_u8x16()[i].max(b.as_u8x16()[i])))))); }
        0x7a => { let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_f64x2(core::array::from_fn(|i| WasmInstance::wasm_trunc_f64(a.as_f64x2()[i])))))); }
        0x7b => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_u8x16(core::array::from_fn(|i| ((a.as_u8x16()[i] as u16 + b.as_u8x16()[i] as u16 + 1) / 2) as u8))))); }
        // ── Pairwise add (0x7c-0x7f) ─────────────────
        0x7c => { let a = try_exec!(inst.pop_v128()); let aa = a.as_i8x16(); try_exec!(inst.push(Value::V128(V128::from_i16x8(core::array::from_fn(|i| aa[i*2] as i16 + aa[i*2+1] as i16))))); }
        0x7d => { let a = try_exec!(inst.pop_v128()); let aa = a.as_u8x16(); try_exec!(inst.push(Value::V128(V128::from_i16x8(core::array::from_fn(|i| aa[i*2] as i16 + aa[i*2+1] as i16))))); }
        0x7e => { let a = try_exec!(inst.pop_v128()); let aa = a.as_i16x8(); try_exec!(inst.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| aa[i*2] as i32 + aa[i*2+1] as i32))))); }
        0x7f => { let a = try_exec!(inst.pop_v128()); let aa = a.as_u16x8(); try_exec!(inst.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| aa[i*2] as i32 + aa[i*2+1] as i32))))); }
        // ── i16x8 arithmetic (0x80-0x9f) with interleaved f64x2 ──
        0x80 => { let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_i16x8(core::array::from_fn(|i| (a.as_i16x8()[i] as i32).unsigned_abs() as i16))))); }
        0x81 => { let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_i16x8(core::array::from_fn(|i| a.as_i16x8()[i].wrapping_neg()))))); }
        0x82 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); let (aa,bb) = (a.as_i16x8(), b.as_i16x8()); let r: [i16; 8] = core::array::from_fn(|i| { let x = aa[i] as i32; let y = bb[i] as i32; ((x*y+(1<<14))>>15).clamp(i16::MIN as i32, i16::MAX as i32) as i16 }); try_exec!(inst.push(Value::V128(V128::from_i16x8(r)))); }
        0x83 => { let a = try_exec!(inst.pop_v128()); let all = a.as_i16x8().iter().all(|&v| v != 0); try_exec!(inst.push(Value::I32(if all { 1 } else { 0 }))); }
        0x84 => { let a = try_exec!(inst.pop_v128()); let aa = a.as_u16x8(); let mut r = 0u32; for i in 0..8 { if aa[i] & 0x8000 != 0 { r |= 1 << i; } } try_exec!(inst.push(Value::I32(r as i32))); }
        0x85 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); let (aa,bb) = (a.as_i32x4(), b.as_i32x4()); let mut r = [0i16; 8]; for i in 0..4 { r[i] = aa[i].clamp(-32768,32767) as i16; } for i in 0..4 { r[i+4] = bb[i].clamp(-32768,32767) as i16; } try_exec!(inst.push(Value::V128(V128::from_i16x8(r)))); }
        0x86 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); let (aa,bb) = (a.as_i32x4(), b.as_i32x4()); let mut r = [0i16; 8]; for i in 0..4 { r[i] = aa[i].clamp(0,65535) as u16 as i16; } for i in 0..4 { r[i+4] = bb[i].clamp(0,65535) as u16 as i16; } try_exec!(inst.push(Value::V128(V128::from_i16x8(r)))); }
        0x87 => { let a = try_exec!(inst.pop_v128()); let aa = a.as_i8x16(); try_exec!(inst.push(Value::V128(V128::from_i16x8(core::array::from_fn(|i| aa[i] as i16))))); }
        0x88 => { let a = try_exec!(inst.pop_v128()); let aa = a.as_i8x16(); try_exec!(inst.push(Value::V128(V128::from_i16x8(core::array::from_fn(|i| aa[i+8] as i16))))); }
        0x89 => { let a = try_exec!(inst.pop_v128()); let aa = a.as_u8x16(); try_exec!(inst.push(Value::V128(V128::from_i16x8(core::array::from_fn(|i| aa[i] as i16))))); }
        0x8a => { let a = try_exec!(inst.pop_v128()); let aa = a.as_u8x16(); try_exec!(inst.push(Value::V128(V128::from_i16x8(core::array::from_fn(|i| aa[i+8] as i16))))); }
        0x8b => { let s = try_exec!(inst.pop_i32()) as u32; let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_i16x8(core::array::from_fn(|i| a.as_i16x8()[i].wrapping_shl(s & 15)))))); }
        0x8c => { let s = try_exec!(inst.pop_i32()) as u32; let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_i16x8(core::array::from_fn(|i| a.as_i16x8()[i].wrapping_shr(s & 15)))))); }
        0x8d => { let s = try_exec!(inst.pop_i32()) as u32; let a = try_exec!(inst.pop_v128()); let r: [i16; 8] = core::array::from_fn(|i| a.as_u16x8()[i].wrapping_shr(s & 15) as i16); try_exec!(inst.push(Value::V128(V128::from_i16x8(r)))); }
        0x8e => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_i16x8(core::array::from_fn(|i| a.as_i16x8()[i].wrapping_add(b.as_i16x8()[i])))))); }
        0x8f => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_i16x8(core::array::from_fn(|i| a.as_i16x8()[i].saturating_add(b.as_i16x8()[i])))))); }
        0x90 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); let r: [i16; 8] = core::array::from_fn(|i| a.as_u16x8()[i].saturating_add(b.as_u16x8()[i]) as i16); try_exec!(inst.push(Value::V128(V128::from_i16x8(r)))); }
        0x91 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_i16x8(core::array::from_fn(|i| a.as_i16x8()[i].wrapping_sub(b.as_i16x8()[i])))))); }
        0x92 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_i16x8(core::array::from_fn(|i| a.as_i16x8()[i].saturating_sub(b.as_i16x8()[i])))))); }
        0x93 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); let r: [i16; 8] = core::array::from_fn(|i| a.as_u16x8()[i].saturating_sub(b.as_u16x8()[i]) as i16); try_exec!(inst.push(Value::V128(V128::from_i16x8(r)))); }
        0x94 => { let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_f64x2(core::array::from_fn(|i| WasmInstance::wasm_nearest_f64(a.as_f64x2()[i])))))); }
        0x95 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_i16x8(core::array::from_fn(|i| a.as_i16x8()[i].wrapping_mul(b.as_i16x8()[i])))))); }
        0x96 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_i16x8(core::array::from_fn(|i| a.as_i16x8()[i].min(b.as_i16x8()[i])))))); }
        0x97 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); let r: [i16; 8] = core::array::from_fn(|i| a.as_u16x8()[i].min(b.as_u16x8()[i]) as i16); try_exec!(inst.push(Value::V128(V128::from_i16x8(r)))); }
        0x98 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_i16x8(core::array::from_fn(|i| a.as_i16x8()[i].max(b.as_i16x8()[i])))))); }
        0x99 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); let r: [i16; 8] = core::array::from_fn(|i| a.as_u16x8()[i].max(b.as_u16x8()[i]) as i16); try_exec!(inst.push(Value::V128(V128::from_i16x8(r)))); }
        0x9b => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); let r: [i16; 8] = core::array::from_fn(|i| ((a.as_u16x8()[i] as u32 + b.as_u16x8()[i] as u32 + 1) / 2) as i16); try_exec!(inst.push(Value::V128(V128::from_i16x8(r)))); }
        0x9c => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_i16x8(core::array::from_fn(|i| a.as_i8x16()[i] as i16 * b.as_i8x16()[i] as i16))))); }
        0x9d => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_i16x8(core::array::from_fn(|i| a.as_i8x16()[i+8] as i16 * b.as_i8x16()[i+8] as i16))))); }
        0x9e => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_i16x8(core::array::from_fn(|i| (a.as_u8x16()[i] as i16).wrapping_mul(b.as_u8x16()[i] as i16)))))); }
        0x9f => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_i16x8(core::array::from_fn(|i| (a.as_u8x16()[i+8] as i16).wrapping_mul(b.as_u8x16()[i+8] as i16)))))); }
        // ── i32x4 arithmetic (0xa0-0xbf) ─────────────
        0xa0 => { let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| a.as_i32x4()[i].wrapping_abs()))))); }
        0xa1 => { let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| a.as_i32x4()[i].wrapping_neg()))))); }
        0xa3 => { let a = try_exec!(inst.pop_v128()); let all = a.as_i32x4().iter().all(|&v| v != 0); try_exec!(inst.push(Value::I32(if all { 1 } else { 0 }))); }
        0xa4 => { let a = try_exec!(inst.pop_v128()); let aa = a.as_u32x4(); let mut r = 0u32; for i in 0..4 { if aa[i] & 0x8000_0000 != 0 { r |= 1 << i; } } try_exec!(inst.push(Value::I32(r as i32))); }
        0xa7 => { let a = try_exec!(inst.pop_v128()); let aa = a.as_i16x8(); try_exec!(inst.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| aa[i] as i32))))); }
        0xa8 => { let a = try_exec!(inst.pop_v128()); let aa = a.as_i16x8(); try_exec!(inst.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| aa[i+4] as i32))))); }
        0xa9 => { let a = try_exec!(inst.pop_v128()); let aa = a.as_u16x8(); try_exec!(inst.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| aa[i] as i32))))); }
        0xaa => { let a = try_exec!(inst.pop_v128()); let aa = a.as_u16x8(); try_exec!(inst.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| aa[i+4] as i32))))); }
        0xab => { let s = try_exec!(inst.pop_i32()) as u32; let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| a.as_i32x4()[i].wrapping_shl(s & 31)))))); }
        0xac => { let s = try_exec!(inst.pop_i32()) as u32; let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| a.as_i32x4()[i].wrapping_shr(s & 31)))))); }
        0xad => { let s = try_exec!(inst.pop_i32()) as u32; let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_u32x4(core::array::from_fn(|i| a.as_u32x4()[i].wrapping_shr(s & 31)))))); }
        0xae => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| a.as_i32x4()[i].wrapping_add(b.as_i32x4()[i])))))); }
        0xb1 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| a.as_i32x4()[i].wrapping_sub(b.as_i32x4()[i])))))); }
        0xb5 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| a.as_i32x4()[i].wrapping_mul(b.as_i32x4()[i])))))); }
        0xb6 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| a.as_i32x4()[i].min(b.as_i32x4()[i])))))); }
        0xb7 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_u32x4(core::array::from_fn(|i| a.as_u32x4()[i].min(b.as_u32x4()[i])))))); }
        0xb8 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| a.as_i32x4()[i].max(b.as_i32x4()[i])))))); }
        0xb9 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_u32x4(core::array::from_fn(|i| a.as_u32x4()[i].max(b.as_u32x4()[i])))))); }
        0xba => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); let (aa,bb) = (a.as_i16x8(), b.as_i16x8()); let r: [i32; 4] = core::array::from_fn(|i| ((aa[i*2] as i32)*(bb[i*2] as i32)).wrapping_add((aa[i*2+1] as i32)*(bb[i*2+1] as i32))); try_exec!(inst.push(Value::V128(V128::from_i32x4(r)))); }
        0xbc => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| a.as_i16x8()[i] as i32 * b.as_i16x8()[i] as i32))))); }
        0xbd => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| a.as_i16x8()[i+4] as i32 * b.as_i16x8()[i+4] as i32))))); }
        0xbe => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_u32x4(core::array::from_fn(|i| a.as_u16x8()[i] as u32 * b.as_u16x8()[i] as u32))))); }
        0xbf => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_u32x4(core::array::from_fn(|i| a.as_u16x8()[i+4] as u32 * b.as_u16x8()[i+4] as u32))))); }
        // ── i64x2 arithmetic (0xc0-0xdf) ─────────────
        0xc0 => { let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_i64x2(core::array::from_fn(|i| a.as_i64x2()[i].wrapping_abs()))))); }
        0xc1 => { let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_i64x2(core::array::from_fn(|i| a.as_i64x2()[i].wrapping_neg()))))); }
        0xc3 => { let a = try_exec!(inst.pop_v128()); let all = a.as_i64x2().iter().all(|&v| v != 0); try_exec!(inst.push(Value::I32(if all { 1 } else { 0 }))); }
        0xc4 => { let a = try_exec!(inst.pop_v128()); let aa = a.as_u64x2(); let mut r = 0u32; for i in 0..2 { if aa[i] & 0x8000_0000_0000_0000 != 0 { r |= 1 << i; } } try_exec!(inst.push(Value::I32(r as i32))); }
        0xc7 => { let a = try_exec!(inst.pop_v128()); let aa = a.as_i32x4(); try_exec!(inst.push(Value::V128(V128::from_i64x2([aa[0] as i64, aa[1] as i64])))); }
        0xc8 => { let a = try_exec!(inst.pop_v128()); let aa = a.as_i32x4(); try_exec!(inst.push(Value::V128(V128::from_i64x2([aa[2] as i64, aa[3] as i64])))); }
        0xc9 => { let a = try_exec!(inst.pop_v128()); let aa = a.as_u32x4(); try_exec!(inst.push(Value::V128(V128::from_i64x2([aa[0] as i64, aa[1] as i64])))); }
        0xca => { let a = try_exec!(inst.pop_v128()); let aa = a.as_u32x4(); try_exec!(inst.push(Value::V128(V128::from_i64x2([aa[2] as i64, aa[3] as i64])))); }
        0xcb => { let s = try_exec!(inst.pop_i32()) as u32; let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_i64x2(core::array::from_fn(|i| a.as_i64x2()[i].wrapping_shl(s & 63)))))); }
        0xcc => { let s = try_exec!(inst.pop_i32()) as u32; let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_i64x2(core::array::from_fn(|i| a.as_i64x2()[i].wrapping_shr(s & 63)))))); }
        0xcd => { let s = try_exec!(inst.pop_i32()) as u32; let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_i64x2(core::array::from_fn(|i| (a.as_u64x2()[i].wrapping_shr(s & 63)) as i64))))); }
        0xce => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_i64x2(core::array::from_fn(|i| a.as_i64x2()[i].wrapping_add(b.as_i64x2()[i])))))); }
        0xd1 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_i64x2(core::array::from_fn(|i| a.as_i64x2()[i].wrapping_sub(b.as_i64x2()[i])))))); }
        0xd5 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_i64x2(core::array::from_fn(|i| a.as_i64x2()[i].wrapping_mul(b.as_i64x2()[i])))))); }
        // ── i64x2 compare (0xd6-0xdb) ────────────────
        0xd6 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_i64x2(core::array::from_fn(|i| if a.as_i64x2()[i]==b.as_i64x2()[i] {-1} else {0}))))); }
        0xd7 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_i64x2(core::array::from_fn(|i| if a.as_i64x2()[i]!=b.as_i64x2()[i] {-1} else {0}))))); }
        0xd8 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_i64x2(core::array::from_fn(|i| if a.as_i64x2()[i]<b.as_i64x2()[i] {-1} else {0}))))); }
        0xd9 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_i64x2(core::array::from_fn(|i| if a.as_i64x2()[i]>b.as_i64x2()[i] {-1} else {0}))))); }
        0xda => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_i64x2(core::array::from_fn(|i| if a.as_i64x2()[i]<=b.as_i64x2()[i] {-1} else {0}))))); }
        0xdb => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_i64x2(core::array::from_fn(|i| if a.as_i64x2()[i]>=b.as_i64x2()[i] {-1} else {0}))))); }
        // ── i64x2 extmul (0xdc-0xdf) ─────────────────
        0xdc => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_i64x2([a.as_i32x4()[0] as i64 * b.as_i32x4()[0] as i64, a.as_i32x4()[1] as i64 * b.as_i32x4()[1] as i64])))); }
        0xdd => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_i64x2([a.as_i32x4()[2] as i64 * b.as_i32x4()[2] as i64, a.as_i32x4()[3] as i64 * b.as_i32x4()[3] as i64])))); }
        0xde => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_i64x2([(a.as_u32x4()[0] as u64 * b.as_u32x4()[0] as u64) as i64, (a.as_u32x4()[1] as u64 * b.as_u32x4()[1] as u64) as i64])))); }
        0xdf => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_i64x2([(a.as_u32x4()[2] as u64 * b.as_u32x4()[2] as u64) as i64, (a.as_u32x4()[3] as u64 * b.as_u32x4()[3] as u64) as i64])))); }
        // ── f32x4 arithmetic (0xe0-0xeb) ─────────────
        0xe0 => { let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_f32x4(core::array::from_fn(|i| libm::fabsf(a.as_f32x4()[i])))))); }
        0xe1 => { let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_f32x4(core::array::from_fn(|i| -a.as_f32x4()[i]))))); }
        0xe3 => { let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_f32x4(core::array::from_fn(|i| libm::sqrtf(a.as_f32x4()[i])))))); }
        0xe4 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_f32x4(core::array::from_fn(|i| a.as_f32x4()[i] + b.as_f32x4()[i]))))); }
        0xe5 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_f32x4(core::array::from_fn(|i| a.as_f32x4()[i] - b.as_f32x4()[i]))))); }
        0xe6 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_f32x4(core::array::from_fn(|i| a.as_f32x4()[i] * b.as_f32x4()[i]))))); }
        0xe7 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_f32x4(core::array::from_fn(|i| a.as_f32x4()[i] / b.as_f32x4()[i]))))); }
        0xe8 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_f32x4(core::array::from_fn(|i| WasmInstance::wasm_min_f32(a.as_f32x4()[i], b.as_f32x4()[i])))))); }
        0xe9 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_f32x4(core::array::from_fn(|i| WasmInstance::wasm_max_f32(a.as_f32x4()[i], b.as_f32x4()[i])))))); }
        0xea => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_f32x4(core::array::from_fn(|i| { let (x,y) = (a.as_f32x4()[i], b.as_f32x4()[i]); if y < x { y } else { x } }))))); }
        0xeb => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_f32x4(core::array::from_fn(|i| { let (x,y) = (a.as_f32x4()[i], b.as_f32x4()[i]); if x < y { y } else { x } }))))); }
        // ── f64x2 arithmetic (0xec-0xf7) ─────────────
        0xec => { let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_f64x2(core::array::from_fn(|i| libm::fabs(a.as_f64x2()[i])))))); }
        0xed => { let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_f64x2(core::array::from_fn(|i| -a.as_f64x2()[i]))))); }
        0xef => { let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_f64x2(core::array::from_fn(|i| libm::sqrt(a.as_f64x2()[i])))))); }
        0xf0 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_f64x2(core::array::from_fn(|i| a.as_f64x2()[i] + b.as_f64x2()[i]))))); }
        0xf1 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_f64x2(core::array::from_fn(|i| a.as_f64x2()[i] - b.as_f64x2()[i]))))); }
        0xf2 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_f64x2(core::array::from_fn(|i| a.as_f64x2()[i] * b.as_f64x2()[i]))))); }
        0xf3 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_f64x2(core::array::from_fn(|i| a.as_f64x2()[i] / b.as_f64x2()[i]))))); }
        0xf4 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_f64x2(core::array::from_fn(|i| WasmInstance::wasm_min_f64(a.as_f64x2()[i], b.as_f64x2()[i])))))); }
        0xf5 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_f64x2(core::array::from_fn(|i| WasmInstance::wasm_max_f64(a.as_f64x2()[i], b.as_f64x2()[i])))))); }
        0xf6 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_f64x2(core::array::from_fn(|i| { let (x,y) = (a.as_f64x2()[i], b.as_f64x2()[i]); if y < x { y } else { x } }))))); }
        0xf7 => { let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_f64x2(core::array::from_fn(|i| { let (x,y) = (a.as_f64x2()[i], b.as_f64x2()[i]); if x < y { y } else { x } }))))); }
        // ── Conversion (0xf8-0xff) ───────────────────
        0xf8 => { let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| sat_trunc_f32_i32(a.as_f32x4()[i])))))); }
        0xf9 => { let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_u32x4(core::array::from_fn(|i| sat_trunc_f32_u32(a.as_f32x4()[i])))))); }
        0xfa => { let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_f32x4(core::array::from_fn(|i| a.as_i32x4()[i] as f32))))); }
        0xfb => { let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_f32x4(core::array::from_fn(|i| a.as_u32x4()[i] as f32))))); }
        0xfc => { let a = try_exec!(inst.pop_v128()); let aa = a.as_f64x2(); try_exec!(inst.push(Value::V128(V128::from_i32x4([sat_trunc_f64_i32(aa[0]), sat_trunc_f64_i32(aa[1]), 0, 0])))); }
        0xfd => { let a = try_exec!(inst.pop_v128()); let aa = a.as_f64x2(); try_exec!(inst.push(Value::V128(V128::from_u32x4([sat_trunc_f64_u32(aa[0]), sat_trunc_f64_u32(aa[1]), 0, 0])))); }
        0xfe => { let a = try_exec!(inst.pop_v128()); let aa = a.as_i32x4(); try_exec!(inst.push(Value::V128(V128::from_f64x2([aa[0] as f64, aa[1] as f64])))); }
        0xff => { let a = try_exec!(inst.pop_v128()); let aa = a.as_u32x4(); try_exec!(inst.push(Value::V128(V128::from_f64x2([aa[0] as f64, aa[1] as f64])))); }
        // ── Relaxed SIMD (0x100-0x113) ────────────
        0x100 => { // i8x16.relaxed_swizzle (same as swizzle)
            let s = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128());
            let mut r = [0u8; 16]; for i in 0..16 { let idx = s.0[i]; r[i] = if idx < 16 { a.0[idx as usize] } else { 0 }; }
            try_exec!(inst.push(Value::V128(V128(r))));
        }
        0x101 => { // i32x4.relaxed_trunc_f32x4_s (same as trunc_sat)
            let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| sat_trunc_f32_i32(a.as_f32x4()[i]))))));
        }
        0x102 => { // i32x4.relaxed_trunc_f32x4_u
            let a = try_exec!(inst.pop_v128()); try_exec!(inst.push(Value::V128(V128::from_u32x4(core::array::from_fn(|i| sat_trunc_f32_u32(a.as_f32x4()[i]))))));
        }
        0x103 => { // i32x4.relaxed_trunc_f64x2_s_zero
            let a = try_exec!(inst.pop_v128()); let aa = a.as_f64x2(); try_exec!(inst.push(Value::V128(V128::from_i32x4([sat_trunc_f64_i32(aa[0]), sat_trunc_f64_i32(aa[1]), 0, 0]))));
        }
        0x104 => { // i32x4.relaxed_trunc_f64x2_u_zero
            let a = try_exec!(inst.pop_v128()); let aa = a.as_f64x2(); try_exec!(inst.push(Value::V128(V128::from_u32x4([sat_trunc_f64_u32(aa[0]), sat_trunc_f64_u32(aa[1]), 0, 0]))));
        }
        0x105 => { // f32x4.relaxed_madd (a*b+c)
            let c = try_exec!(inst.pop_v128()); let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128());
            let (aa, bb, cc) = (a.as_f32x4(), b.as_f32x4(), c.as_f32x4());
            try_exec!(inst.push(Value::V128(V128::from_f32x4(core::array::from_fn(|i| aa[i] * bb[i] + cc[i])))));
        }
        0x106 => { // f32x4.relaxed_nmadd (-a*b+c)
            let c = try_exec!(inst.pop_v128()); let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128());
            let (aa, bb, cc) = (a.as_f32x4(), b.as_f32x4(), c.as_f32x4());
            try_exec!(inst.push(Value::V128(V128::from_f32x4(core::array::from_fn(|i| -(aa[i] * bb[i]) + cc[i])))));
        }
        0x107 => { // f64x2.relaxed_madd (a*b+c)
            let c = try_exec!(inst.pop_v128()); let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128());
            let (aa, bb, cc) = (a.as_f64x2(), b.as_f64x2(), c.as_f64x2());
            try_exec!(inst.push(Value::V128(V128::from_f64x2(core::array::from_fn(|i| aa[i] * bb[i] + cc[i])))));
        }
        0x108 => { // f64x2.relaxed_nmadd (-a*b+c)
            let c = try_exec!(inst.pop_v128()); let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128());
            let (aa, bb, cc) = (a.as_f64x2(), b.as_f64x2(), c.as_f64x2());
            try_exec!(inst.push(Value::V128(V128::from_f64x2(core::array::from_fn(|i| -(aa[i] * bb[i]) + cc[i])))));
        }
        0x109 => { // i8x16.relaxed_laneselect (same as bitselect)
            let c = try_exec!(inst.pop_v128()); let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128());
            let mut r = [0u8; 16]; for i in 0..16 { r[i] = (a.0[i] & c.0[i]) | (b.0[i] & !c.0[i]); }
            try_exec!(inst.push(Value::V128(V128(r))));
        }
        0x10a => { // i16x8.relaxed_laneselect
            let c = try_exec!(inst.pop_v128()); let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128());
            let mut r = [0u8; 16]; for i in 0..16 { r[i] = (a.0[i] & c.0[i]) | (b.0[i] & !c.0[i]); }
            try_exec!(inst.push(Value::V128(V128(r))));
        }
        0x10b => { // i32x4.relaxed_laneselect
            let c = try_exec!(inst.pop_v128()); let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128());
            let mut r = [0u8; 16]; for i in 0..16 { r[i] = (a.0[i] & c.0[i]) | (b.0[i] & !c.0[i]); }
            try_exec!(inst.push(Value::V128(V128(r))));
        }
        0x10c => { // i64x2.relaxed_laneselect
            let c = try_exec!(inst.pop_v128()); let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128());
            let mut r = [0u8; 16]; for i in 0..16 { r[i] = (a.0[i] & c.0[i]) | (b.0[i] & !c.0[i]); }
            try_exec!(inst.push(Value::V128(V128(r))));
        }
        0x10d => { // f32x4.relaxed_min (same as min)
            let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128());
            try_exec!(inst.push(Value::V128(V128::from_f32x4(core::array::from_fn(|i| WasmInstance::wasm_min_f32(a.as_f32x4()[i], b.as_f32x4()[i]))))));
        }
        0x10e => { // f32x4.relaxed_max (same as max)
            let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128());
            try_exec!(inst.push(Value::V128(V128::from_f32x4(core::array::from_fn(|i| WasmInstance::wasm_max_f32(a.as_f32x4()[i], b.as_f32x4()[i]))))));
        }
        0x10f => { // f64x2.relaxed_min
            let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128());
            try_exec!(inst.push(Value::V128(V128::from_f64x2(core::array::from_fn(|i| WasmInstance::wasm_min_f64(a.as_f64x2()[i], b.as_f64x2()[i]))))));
        }
        0x110 => { // f64x2.relaxed_max
            let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128());
            try_exec!(inst.push(Value::V128(V128::from_f64x2(core::array::from_fn(|i| WasmInstance::wasm_max_f64(a.as_f64x2()[i], b.as_f64x2()[i]))))));
        }
        0x111 => { // i16x8.relaxed_q15mulr_s (same as q15mulr_sat_s)
            let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128());
            let (aa, bb) = (a.as_i16x8(), b.as_i16x8());
            let r: [i16; 8] = core::array::from_fn(|i| { let x = aa[i] as i32; let y = bb[i] as i32; ((x*y+(1<<14))>>15).clamp(i16::MIN as i32, i16::MAX as i32) as i16 });
            try_exec!(inst.push(Value::V128(V128::from_i16x8(r))));
        }
        0x112 => { // i16x8.relaxed_dot_i8x16_i7x16_s
            let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128());
            let (aa, bb) = (a.as_i8x16(), b.as_i8x16());
            let r: [i16; 8] = core::array::from_fn(|i| (aa[i*2] as i16 * bb[i*2] as i16).saturating_add(aa[i*2+1] as i16 * bb[i*2+1] as i16));
            try_exec!(inst.push(Value::V128(V128::from_i16x8(r))));
        }
        0x113 => { // i32x4.relaxed_dot_i8x16_i7x16_add_s
            let c = try_exec!(inst.pop_v128()); let b = try_exec!(inst.pop_v128()); let a = try_exec!(inst.pop_v128());
            let (aa, bb) = (a.as_i8x16(), b.as_i8x16()); let cc = c.as_i32x4();
            let r: [i32; 4] = core::array::from_fn(|i| {
                let base = i * 4;
                let dot = (aa[base] as i32 * bb[base] as i32) + (aa[base+1] as i32 * bb[base+1] as i32) + (aa[base+2] as i32 * bb[base+2] as i32) + (aa[base+3] as i32 * bb[base+3] as i32);
                dot.wrapping_add(cc[i])
            });
            try_exec!(inst.push(Value::V128(V128::from_i32x4(r))));
        }

        _ => { return ExecResult::Trap(WasmError::InvalidOpcode(0xFD)); }
    }


    ExecResult::Ok
}
