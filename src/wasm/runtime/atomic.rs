//! Atomic (0xFE prefix) instruction execution.

use super::*;

/// Execute a 0xFE-prefixed atomic instruction.
/// Called after the 0xFE prefix has been read; reads and dispatches the sub-opcode.
pub(super) fn execute_atomic(inst: &mut WasmInstance) -> ExecResult {
    macro_rules! try_exec {
        ($expr:expr) => {
            match $expr {
                Ok(v) => v,
                Err(e) => return ExecResult::Trap(e),
            }
        };
    }

    let sub = try_exec!(inst.read_leb128_u32());
    match sub {
        // memory.atomic.notify (0): [i32, i32] -> [i32]
        0x00 => {
            let (mi, offset) = try_exec!(inst.read_memarg());
            let _count = try_exec!(inst.pop_i32());
            let base = try_exec!(inst.pop_i32()) as u32;
            let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
            if addr % 4 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); }
            if addr + 4 > inst.mem_size(mi) { return ExecResult::Trap(WasmError::MemoryOutOfBounds); }
            try_exec!(inst.push(Value::I32(0)));
        }
        // memory.atomic.wait32 (1): [i32, i32, i64] -> [i32]
        0x01 => {
            let (mi, offset) = try_exec!(inst.read_memarg());
            let _timeout = try_exec!(inst.pop_i64());
            let _expected = try_exec!(inst.pop_i32());
            let base = try_exec!(inst.pop_i32()) as u32;
            let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
            if addr % 4 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); }
            if addr + 4 > inst.mem_size(mi) { return ExecResult::Trap(WasmError::MemoryOutOfBounds); }
            // Single-threaded: return 1 (not-equal/timeout)
            try_exec!(inst.push(Value::I32(1)));
        }
        // memory.atomic.wait64 (2): [i32, i64, i64] -> [i32]
        0x02 => {
            let (mi, offset) = try_exec!(inst.read_memarg());
            let _timeout = try_exec!(inst.pop_i64());
            let _expected = try_exec!(inst.pop_i64());
            let base = try_exec!(inst.pop_i32()) as u32;
            let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
            if addr % 8 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); }
            if addr + 8 > inst.mem_size(mi) { return ExecResult::Trap(WasmError::MemoryOutOfBounds); }
            try_exec!(inst.push(Value::I32(1)));
        }
        // atomic.fence (3)
        0x03 => { let _ = try_exec!(inst.read_byte()); }
        // i32.atomic.load (0x10)
        0x10 => {
            let (mi, offset) = try_exec!(inst.read_memarg());
            let base = try_exec!(inst.pop_i32()) as u32;
            let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
            if addr % 4 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); }
            let val = try_exec!(inst.mem_load_i32(mi, addr));
            try_exec!(inst.push(Value::I32(val)));
        }
        // i64.atomic.load (0x11)
        0x11 => {
            let (mi, offset) = try_exec!(inst.read_memarg());
            let base = try_exec!(inst.pop_i32()) as u32;
            let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
            if addr % 8 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); }
            let val = try_exec!(inst.mem_load_i64(mi, addr));
            try_exec!(inst.push(Value::I64(val)));
        }
        // i32.atomic.load8_u (0x12)
        0x12 => {
            let (mi, offset) = try_exec!(inst.read_memarg());
            let base = try_exec!(inst.pop_i32()) as u32;
            let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
            let val = try_exec!(inst.mem_load_u8(mi, addr));
            try_exec!(inst.push(Value::I32(val as i32)));
        }
        // i32.atomic.load16_u (0x13)
        0x13 => {
            let (mi, offset) = try_exec!(inst.read_memarg());
            let base = try_exec!(inst.pop_i32()) as u32;
            let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
            if addr % 2 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); }
            let val = try_exec!(inst.mem_load_u16(mi, addr));
            try_exec!(inst.push(Value::I32(val as i32)));
        }
        // i64.atomic.load8_u (0x14)
        0x14 => {
            let (mi, offset) = try_exec!(inst.read_memarg());
            let base = try_exec!(inst.pop_i32()) as u32;
            let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
            let val = try_exec!(inst.mem_load_u8(mi, addr));
            try_exec!(inst.push(Value::I64(val as i64)));
        }
        // i64.atomic.load16_u (0x15)
        0x15 => {
            let (mi, offset) = try_exec!(inst.read_memarg());
            let base = try_exec!(inst.pop_i32()) as u32;
            let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
            if addr % 2 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); }
            let val = try_exec!(inst.mem_load_u16(mi, addr));
            try_exec!(inst.push(Value::I64(val as i64)));
        }
        // i64.atomic.load32_u (0x16)
        0x16 => {
            let (mi, offset) = try_exec!(inst.read_memarg());
            let base = try_exec!(inst.pop_i32()) as u32;
            let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
            if addr % 4 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); }
            let val = try_exec!(inst.mem_load_u32(mi, addr));
            try_exec!(inst.push(Value::I64(val as i64)));
        }
        // i32.atomic.store (0x17)
        0x17 => {
            let (mi, offset) = try_exec!(inst.read_memarg());
            let val = try_exec!(inst.pop_i32());
            let base = try_exec!(inst.pop_i32()) as u32;
            let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
            if addr % 4 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); }
            try_exec!(inst.mem_store_i32(mi, addr, val));
        }
        // i64.atomic.store (0x18)
        0x18 => {
            let (mi, offset) = try_exec!(inst.read_memarg());
            let val = try_exec!(inst.pop_i64());
            let base = try_exec!(inst.pop_i32()) as u32;
            let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
            if addr % 8 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); }
            try_exec!(inst.mem_store_i64(mi, addr, val));
        }
        // i32.atomic.store8 (0x19)
        0x19 => {
            let (mi, offset) = try_exec!(inst.read_memarg());
            let val = try_exec!(inst.pop_i32());
            let base = try_exec!(inst.pop_i32()) as u32;
            let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
            try_exec!(inst.mem_store_u8(mi, addr, val as u8));
        }
        // i32.atomic.store16 (0x1a)
        0x1a => {
            let (mi, offset) = try_exec!(inst.read_memarg());
            let val = try_exec!(inst.pop_i32());
            let base = try_exec!(inst.pop_i32()) as u32;
            let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
            if addr % 2 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); }
            try_exec!(inst.mem_store_u16(mi, addr, val as u16));
        }
        // i64.atomic.store8 (0x1b)
        0x1b => {
            let (mi, offset) = try_exec!(inst.read_memarg());
            let val = try_exec!(inst.pop_i64());
            let base = try_exec!(inst.pop_i32()) as u32;
            let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
            try_exec!(inst.mem_store_u8(mi, addr, val as u8));
        }
        // i64.atomic.store16 (0x1c)
        0x1c => {
            let (mi, offset) = try_exec!(inst.read_memarg());
            let val = try_exec!(inst.pop_i64());
            let base = try_exec!(inst.pop_i32()) as u32;
            let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
            if addr % 2 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); }
            try_exec!(inst.mem_store_u16(mi, addr, val as u16));
        }
        // i64.atomic.store32 (0x1d)
        0x1d => {
            let (mi, offset) = try_exec!(inst.read_memarg());
            let val = try_exec!(inst.pop_i64());
            let base = try_exec!(inst.pop_i32()) as u32;
            let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
            if addr % 4 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); }
            try_exec!(inst.mem_store_u32(mi, addr, val as u32));
        }
        // ── Atomic RMW operations ──
        // i32.atomic.rmw.add..xchg (0x1e-0x47), i32/i64 variants
        0x1e => { let (mi, offset) = try_exec!(inst.read_memarg()); let val = try_exec!(inst.pop_i32()); let base = try_exec!(inst.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; if addr % 4 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); } let old = try_exec!(inst.mem_load_i32(mi, addr)); try_exec!(inst.mem_store_i32(mi, addr, old.wrapping_add(val))); try_exec!(inst.push(Value::I32(old))); }
        0x1f => { let (mi, offset) = try_exec!(inst.read_memarg()); let val = try_exec!(inst.pop_i64()); let base = try_exec!(inst.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; if addr % 8 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); } let old = try_exec!(inst.mem_load_i64(mi, addr)); try_exec!(inst.mem_store_i64(mi, addr, old.wrapping_add(val))); try_exec!(inst.push(Value::I64(old))); }
        0x20 => { let (mi, offset) = try_exec!(inst.read_memarg()); let val = try_exec!(inst.pop_i32()) as u8; let base = try_exec!(inst.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; let old = try_exec!(inst.mem_load_u8(mi, addr)); try_exec!(inst.mem_store_u8(mi, addr, old.wrapping_add(val))); try_exec!(inst.push(Value::I32(old as i32))); }
        0x21 => { let (mi, offset) = try_exec!(inst.read_memarg()); let val = try_exec!(inst.pop_i32()) as u16; let base = try_exec!(inst.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; if addr % 2 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); } let old = try_exec!(inst.mem_load_u16(mi, addr)); try_exec!(inst.mem_store_u16(mi, addr, old.wrapping_add(val))); try_exec!(inst.push(Value::I32(old as i32))); }
        0x22 => { let (mi, offset) = try_exec!(inst.read_memarg()); let val = try_exec!(inst.pop_i64()) as u8; let base = try_exec!(inst.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; let old = try_exec!(inst.mem_load_u8(mi, addr)); try_exec!(inst.mem_store_u8(mi, addr, old.wrapping_add(val))); try_exec!(inst.push(Value::I64(old as i64))); }
        0x23 => { let (mi, offset) = try_exec!(inst.read_memarg()); let val = try_exec!(inst.pop_i64()) as u16; let base = try_exec!(inst.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; if addr % 2 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); } let old = try_exec!(inst.mem_load_u16(mi, addr)); try_exec!(inst.mem_store_u16(mi, addr, old.wrapping_add(val))); try_exec!(inst.push(Value::I64(old as i64))); }
        0x24 => { let (mi, offset) = try_exec!(inst.read_memarg()); let val = try_exec!(inst.pop_i64()) as u32; let base = try_exec!(inst.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; if addr % 4 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); } let old = try_exec!(inst.mem_load_u32(mi, addr)); try_exec!(inst.mem_store_u32(mi, addr, old.wrapping_add(val))); try_exec!(inst.push(Value::I64(old as i64))); }
        // sub
        0x25 => { let (mi, offset) = try_exec!(inst.read_memarg()); let val = try_exec!(inst.pop_i32()); let base = try_exec!(inst.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; if addr % 4 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); } let old = try_exec!(inst.mem_load_i32(mi, addr)); try_exec!(inst.mem_store_i32(mi, addr, old.wrapping_sub(val))); try_exec!(inst.push(Value::I32(old))); }
        0x26 => { let (mi, offset) = try_exec!(inst.read_memarg()); let val = try_exec!(inst.pop_i64()); let base = try_exec!(inst.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; if addr % 8 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); } let old = try_exec!(inst.mem_load_i64(mi, addr)); try_exec!(inst.mem_store_i64(mi, addr, old.wrapping_sub(val))); try_exec!(inst.push(Value::I64(old))); }
        0x27 => { let (mi, offset) = try_exec!(inst.read_memarg()); let val = try_exec!(inst.pop_i32()) as u8; let base = try_exec!(inst.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; let old = try_exec!(inst.mem_load_u8(mi, addr)); try_exec!(inst.mem_store_u8(mi, addr, old.wrapping_sub(val))); try_exec!(inst.push(Value::I32(old as i32))); }
        0x28 => { let (mi, offset) = try_exec!(inst.read_memarg()); let val = try_exec!(inst.pop_i32()) as u16; let base = try_exec!(inst.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; if addr % 2 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); } let old = try_exec!(inst.mem_load_u16(mi, addr)); try_exec!(inst.mem_store_u16(mi, addr, old.wrapping_sub(val))); try_exec!(inst.push(Value::I32(old as i32))); }
        0x29 => { let (mi, offset) = try_exec!(inst.read_memarg()); let val = try_exec!(inst.pop_i64()) as u8; let base = try_exec!(inst.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; let old = try_exec!(inst.mem_load_u8(mi, addr)); try_exec!(inst.mem_store_u8(mi, addr, old.wrapping_sub(val))); try_exec!(inst.push(Value::I64(old as i64))); }
        0x2a => { let (mi, offset) = try_exec!(inst.read_memarg()); let val = try_exec!(inst.pop_i64()) as u16; let base = try_exec!(inst.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; if addr % 2 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); } let old = try_exec!(inst.mem_load_u16(mi, addr)); try_exec!(inst.mem_store_u16(mi, addr, old.wrapping_sub(val))); try_exec!(inst.push(Value::I64(old as i64))); }
        0x2b => { let (mi, offset) = try_exec!(inst.read_memarg()); let val = try_exec!(inst.pop_i64()) as u32; let base = try_exec!(inst.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; if addr % 4 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); } let old = try_exec!(inst.mem_load_u32(mi, addr)); try_exec!(inst.mem_store_u32(mi, addr, old.wrapping_sub(val))); try_exec!(inst.push(Value::I64(old as i64))); }
        // and
        0x2c => { let (mi, offset) = try_exec!(inst.read_memarg()); let val = try_exec!(inst.pop_i32()); let base = try_exec!(inst.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; if addr % 4 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); } let old = try_exec!(inst.mem_load_i32(mi, addr)); try_exec!(inst.mem_store_i32(mi, addr, old & val)); try_exec!(inst.push(Value::I32(old))); }
        0x2d => { let (mi, offset) = try_exec!(inst.read_memarg()); let val = try_exec!(inst.pop_i64()); let base = try_exec!(inst.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; if addr % 8 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); } let old = try_exec!(inst.mem_load_i64(mi, addr)); try_exec!(inst.mem_store_i64(mi, addr, old & val)); try_exec!(inst.push(Value::I64(old))); }
        0x2e => { let (mi, offset) = try_exec!(inst.read_memarg()); let val = try_exec!(inst.pop_i32()) as u8; let base = try_exec!(inst.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; let old = try_exec!(inst.mem_load_u8(mi, addr)); try_exec!(inst.mem_store_u8(mi, addr, old & val)); try_exec!(inst.push(Value::I32(old as i32))); }
        0x2f => { let (mi, offset) = try_exec!(inst.read_memarg()); let val = try_exec!(inst.pop_i32()) as u16; let base = try_exec!(inst.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; if addr % 2 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); } let old = try_exec!(inst.mem_load_u16(mi, addr)); try_exec!(inst.mem_store_u16(mi, addr, old & val)); try_exec!(inst.push(Value::I32(old as i32))); }
        0x30 => { let (mi, offset) = try_exec!(inst.read_memarg()); let val = try_exec!(inst.pop_i64()) as u8; let base = try_exec!(inst.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; let old = try_exec!(inst.mem_load_u8(mi, addr)); try_exec!(inst.mem_store_u8(mi, addr, old & val)); try_exec!(inst.push(Value::I64(old as i64))); }
        0x31 => { let (mi, offset) = try_exec!(inst.read_memarg()); let val = try_exec!(inst.pop_i64()) as u16; let base = try_exec!(inst.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; if addr % 2 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); } let old = try_exec!(inst.mem_load_u16(mi, addr)); try_exec!(inst.mem_store_u16(mi, addr, old & val)); try_exec!(inst.push(Value::I64(old as i64))); }
        0x32 => { let (mi, offset) = try_exec!(inst.read_memarg()); let val = try_exec!(inst.pop_i64()) as u32; let base = try_exec!(inst.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; if addr % 4 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); } let old = try_exec!(inst.mem_load_u32(mi, addr)); try_exec!(inst.mem_store_u32(mi, addr, old & val)); try_exec!(inst.push(Value::I64(old as i64))); }
        // or
        0x33 => { let (mi, offset) = try_exec!(inst.read_memarg()); let val = try_exec!(inst.pop_i32()); let base = try_exec!(inst.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; if addr % 4 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); } let old = try_exec!(inst.mem_load_i32(mi, addr)); try_exec!(inst.mem_store_i32(mi, addr, old | val)); try_exec!(inst.push(Value::I32(old))); }
        0x34 => { let (mi, offset) = try_exec!(inst.read_memarg()); let val = try_exec!(inst.pop_i64()); let base = try_exec!(inst.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; if addr % 8 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); } let old = try_exec!(inst.mem_load_i64(mi, addr)); try_exec!(inst.mem_store_i64(mi, addr, old | val)); try_exec!(inst.push(Value::I64(old))); }
        0x35 => { let (mi, offset) = try_exec!(inst.read_memarg()); let val = try_exec!(inst.pop_i32()) as u8; let base = try_exec!(inst.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; let old = try_exec!(inst.mem_load_u8(mi, addr)); try_exec!(inst.mem_store_u8(mi, addr, old | val)); try_exec!(inst.push(Value::I32(old as i32))); }
        0x36 => { let (mi, offset) = try_exec!(inst.read_memarg()); let val = try_exec!(inst.pop_i32()) as u16; let base = try_exec!(inst.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; if addr % 2 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); } let old = try_exec!(inst.mem_load_u16(mi, addr)); try_exec!(inst.mem_store_u16(mi, addr, old | val)); try_exec!(inst.push(Value::I32(old as i32))); }
        0x37 => { let (mi, offset) = try_exec!(inst.read_memarg()); let val = try_exec!(inst.pop_i64()) as u8; let base = try_exec!(inst.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; let old = try_exec!(inst.mem_load_u8(mi, addr)); try_exec!(inst.mem_store_u8(mi, addr, old | val)); try_exec!(inst.push(Value::I64(old as i64))); }
        0x38 => { let (mi, offset) = try_exec!(inst.read_memarg()); let val = try_exec!(inst.pop_i64()) as u16; let base = try_exec!(inst.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; if addr % 2 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); } let old = try_exec!(inst.mem_load_u16(mi, addr)); try_exec!(inst.mem_store_u16(mi, addr, old | val)); try_exec!(inst.push(Value::I64(old as i64))); }
        0x39 => { let (mi, offset) = try_exec!(inst.read_memarg()); let val = try_exec!(inst.pop_i64()) as u32; let base = try_exec!(inst.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; if addr % 4 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); } let old = try_exec!(inst.mem_load_u32(mi, addr)); try_exec!(inst.mem_store_u32(mi, addr, old | val)); try_exec!(inst.push(Value::I64(old as i64))); }
        // xor
        0x3a => { let (mi, offset) = try_exec!(inst.read_memarg()); let val = try_exec!(inst.pop_i32()); let base = try_exec!(inst.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; if addr % 4 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); } let old = try_exec!(inst.mem_load_i32(mi, addr)); try_exec!(inst.mem_store_i32(mi, addr, old ^ val)); try_exec!(inst.push(Value::I32(old))); }
        0x3b => { let (mi, offset) = try_exec!(inst.read_memarg()); let val = try_exec!(inst.pop_i64()); let base = try_exec!(inst.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; if addr % 8 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); } let old = try_exec!(inst.mem_load_i64(mi, addr)); try_exec!(inst.mem_store_i64(mi, addr, old ^ val)); try_exec!(inst.push(Value::I64(old))); }
        0x3c => { let (mi, offset) = try_exec!(inst.read_memarg()); let val = try_exec!(inst.pop_i32()) as u8; let base = try_exec!(inst.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; let old = try_exec!(inst.mem_load_u8(mi, addr)); try_exec!(inst.mem_store_u8(mi, addr, old ^ val)); try_exec!(inst.push(Value::I32(old as i32))); }
        0x3d => { let (mi, offset) = try_exec!(inst.read_memarg()); let val = try_exec!(inst.pop_i32()) as u16; let base = try_exec!(inst.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; if addr % 2 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); } let old = try_exec!(inst.mem_load_u16(mi, addr)); try_exec!(inst.mem_store_u16(mi, addr, old ^ val)); try_exec!(inst.push(Value::I32(old as i32))); }
        0x3e => { let (mi, offset) = try_exec!(inst.read_memarg()); let val = try_exec!(inst.pop_i64()) as u8; let base = try_exec!(inst.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; let old = try_exec!(inst.mem_load_u8(mi, addr)); try_exec!(inst.mem_store_u8(mi, addr, old ^ val)); try_exec!(inst.push(Value::I64(old as i64))); }
        0x3f => { let (mi, offset) = try_exec!(inst.read_memarg()); let val = try_exec!(inst.pop_i64()) as u16; let base = try_exec!(inst.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; if addr % 2 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); } let old = try_exec!(inst.mem_load_u16(mi, addr)); try_exec!(inst.mem_store_u16(mi, addr, old ^ val)); try_exec!(inst.push(Value::I64(old as i64))); }
        0x40 => { let (mi, offset) = try_exec!(inst.read_memarg()); let val = try_exec!(inst.pop_i64()) as u32; let base = try_exec!(inst.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; if addr % 4 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); } let old = try_exec!(inst.mem_load_u32(mi, addr)); try_exec!(inst.mem_store_u32(mi, addr, old ^ val)); try_exec!(inst.push(Value::I64(old as i64))); }
        // xchg
        0x41 => { let (mi, offset) = try_exec!(inst.read_memarg()); let val = try_exec!(inst.pop_i32()); let base = try_exec!(inst.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; if addr % 4 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); } let old = try_exec!(inst.mem_load_i32(mi, addr)); try_exec!(inst.mem_store_i32(mi, addr, val)); try_exec!(inst.push(Value::I32(old))); }
        0x42 => { let (mi, offset) = try_exec!(inst.read_memarg()); let val = try_exec!(inst.pop_i64()); let base = try_exec!(inst.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; if addr % 8 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); } let old = try_exec!(inst.mem_load_i64(mi, addr)); try_exec!(inst.mem_store_i64(mi, addr, val)); try_exec!(inst.push(Value::I64(old))); }
        0x43 => { let (mi, offset) = try_exec!(inst.read_memarg()); let val = try_exec!(inst.pop_i32()) as u8; let base = try_exec!(inst.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; let old = try_exec!(inst.mem_load_u8(mi, addr)); try_exec!(inst.mem_store_u8(mi, addr, val)); try_exec!(inst.push(Value::I32(old as i32))); }
        0x44 => { let (mi, offset) = try_exec!(inst.read_memarg()); let val = try_exec!(inst.pop_i32()) as u16; let base = try_exec!(inst.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; if addr % 2 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); } let old = try_exec!(inst.mem_load_u16(mi, addr)); try_exec!(inst.mem_store_u16(mi, addr, val)); try_exec!(inst.push(Value::I32(old as i32))); }
        0x45 => { let (mi, offset) = try_exec!(inst.read_memarg()); let val = try_exec!(inst.pop_i64()) as u8; let base = try_exec!(inst.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; let old = try_exec!(inst.mem_load_u8(mi, addr)); try_exec!(inst.mem_store_u8(mi, addr, val)); try_exec!(inst.push(Value::I64(old as i64))); }
        0x46 => { let (mi, offset) = try_exec!(inst.read_memarg()); let val = try_exec!(inst.pop_i64()) as u16; let base = try_exec!(inst.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; if addr % 2 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); } let old = try_exec!(inst.mem_load_u16(mi, addr)); try_exec!(inst.mem_store_u16(mi, addr, val)); try_exec!(inst.push(Value::I64(old as i64))); }
        0x47 => { let (mi, offset) = try_exec!(inst.read_memarg()); let val = try_exec!(inst.pop_i64()) as u32; let base = try_exec!(inst.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; if addr % 4 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); } let old = try_exec!(inst.mem_load_u32(mi, addr)); try_exec!(inst.mem_store_u32(mi, addr, val)); try_exec!(inst.push(Value::I64(old as i64))); }
        // cmpxchg
        0x48 => { let (mi, offset) = try_exec!(inst.read_memarg()); let replacement = try_exec!(inst.pop_i32()); let expected = try_exec!(inst.pop_i32()); let base = try_exec!(inst.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; if addr % 4 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); } let old = try_exec!(inst.mem_load_i32(mi, addr)); if old == expected { try_exec!(inst.mem_store_i32(mi, addr, replacement)); } try_exec!(inst.push(Value::I32(old))); }
        0x49 => { let (mi, offset) = try_exec!(inst.read_memarg()); let replacement = try_exec!(inst.pop_i64()); let expected = try_exec!(inst.pop_i64()); let base = try_exec!(inst.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; if addr % 8 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); } let old = try_exec!(inst.mem_load_i64(mi, addr)); if old == expected { try_exec!(inst.mem_store_i64(mi, addr, replacement)); } try_exec!(inst.push(Value::I64(old))); }
        0x4a => { let (mi, offset) = try_exec!(inst.read_memarg()); let replacement = try_exec!(inst.pop_i32()) as u8; let expected = try_exec!(inst.pop_i32()) as u8; let base = try_exec!(inst.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; let old = try_exec!(inst.mem_load_u8(mi, addr)); if old == expected { try_exec!(inst.mem_store_u8(mi, addr, replacement)); } try_exec!(inst.push(Value::I32(old as i32))); }
        0x4b => { let (mi, offset) = try_exec!(inst.read_memarg()); let replacement = try_exec!(inst.pop_i32()) as u16; let expected = try_exec!(inst.pop_i32()) as u16; let base = try_exec!(inst.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; if addr % 2 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); } let old = try_exec!(inst.mem_load_u16(mi, addr)); if old == expected { try_exec!(inst.mem_store_u16(mi, addr, replacement)); } try_exec!(inst.push(Value::I32(old as i32))); }
        0x4c => { let (mi, offset) = try_exec!(inst.read_memarg()); let replacement = try_exec!(inst.pop_i64()) as u8; let expected = try_exec!(inst.pop_i64()) as u8; let base = try_exec!(inst.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; let old = try_exec!(inst.mem_load_u8(mi, addr)); if old == expected { try_exec!(inst.mem_store_u8(mi, addr, replacement)); } try_exec!(inst.push(Value::I64(old as i64))); }
        0x4d => { let (mi, offset) = try_exec!(inst.read_memarg()); let replacement = try_exec!(inst.pop_i64()) as u16; let expected = try_exec!(inst.pop_i64()) as u16; let base = try_exec!(inst.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; if addr % 2 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); } let old = try_exec!(inst.mem_load_u16(mi, addr)); if old == expected { try_exec!(inst.mem_store_u16(mi, addr, replacement)); } try_exec!(inst.push(Value::I64(old as i64))); }
        0x4e => { let (mi, offset) = try_exec!(inst.read_memarg()); let replacement = try_exec!(inst.pop_i64()) as u32; let expected = try_exec!(inst.pop_i64()) as u32; let base = try_exec!(inst.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; if addr % 4 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); } let old = try_exec!(inst.mem_load_u32(mi, addr)); if old == expected { try_exec!(inst.mem_store_u32(mi, addr, replacement)); } try_exec!(inst.push(Value::I64(old as i64))); }
        _ => { return ExecResult::Trap(WasmError::InvalidOpcode(0xFE)); }
    }

    ExecResult::Ok
}
