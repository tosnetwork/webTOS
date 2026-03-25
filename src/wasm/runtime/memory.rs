//! Memory load/store instruction execution (opcodes 0x28-0x3E, 0x3F, 0x40).

use super::*;

/// Execute a memory-related instruction (0x28-0x40 range).
/// Called from step() for memory load/store/size/grow opcodes.
pub(super) fn execute_memory(inst: &mut WasmInstance, opcode: u8) -> ExecResult {
    macro_rules! try_exec {
        ($expr:expr) => {
            match $expr {
                Ok(v) => v,
                Err(e) => return ExecResult::Trap(e),
            }
        };
    }

    match opcode {
    // ── Memory ──────────────────────────────────────────────
    0x28 => {
        // i32.load
        let (mi, offset) = try_exec!(inst.read_memarg());
        let base = try_exec!(inst.pop_i32()) as u32;
        let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
        let val = try_exec!(inst.mem_load_i32(mi, addr));
        try_exec!(inst.push(Value::I32(val)));
    }
    0x29 => {
        // i64.load
        let (mi, offset) = try_exec!(inst.read_memarg());
        let base = try_exec!(inst.pop_i32()) as u32;
        let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
        let val = try_exec!(inst.mem_load_i64(mi, addr));
        try_exec!(inst.push(Value::I64(val)));
    }
    0x36 => {
        // i32.store
        let (mi, offset) = try_exec!(inst.read_memarg());
        let val = try_exec!(inst.pop_i32());
        let base = try_exec!(inst.pop_i32()) as u32;
        let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
        try_exec!(inst.mem_store_i32(mi, addr, val));
    }
    0x37 => {
        // i64.store
        let (mi, offset) = try_exec!(inst.read_memarg());
        let val = try_exec!(inst.pop_i64());
        let base = try_exec!(inst.pop_i32()) as u32;
        let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
        try_exec!(inst.mem_store_i64(mi, addr, val));
    }

    // ── Float memory ─────────────────────────────────────────
    0x2A => {
        // f32.load
        if inst.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); }
        let (mi, offset) = try_exec!(inst.read_memarg());
        let base = try_exec!(inst.pop_i32()) as u32;
        let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
        let val = try_exec!(inst.mem_load_f32(mi, addr));
        try_exec!(inst.push(Value::F32(val)));
    }
    0x2B => {
        // f64.load
        if inst.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); }
        let (mi, offset) = try_exec!(inst.read_memarg());
        let base = try_exec!(inst.pop_i32()) as u32;
        let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
        let val = try_exec!(inst.mem_load_f64(mi, addr));
        try_exec!(inst.push(Value::F64(val)));
    }

    // ── Sub-word loads ──────────────────────────────────────
    0x2C => {
        // i32.load8_s
        let (mi, offset) = try_exec!(inst.read_memarg());
        let base = try_exec!(inst.pop_i32()) as u32;
        let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
        let val = try_exec!(inst.mem_load_u8(mi, addr)) as i8;
        try_exec!(inst.push(Value::I32(val as i32)));
    }
    0x2D => {
        // i32.load8_u
        let (mi, offset) = try_exec!(inst.read_memarg());
        let base = try_exec!(inst.pop_i32()) as u32;
        let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
        let val = try_exec!(inst.mem_load_u8(mi, addr));
        try_exec!(inst.push(Value::I32(val as i32)));
    }
    0x2E => {
        // i32.load16_s
        let (mi, offset) = try_exec!(inst.read_memarg());
        let base = try_exec!(inst.pop_i32()) as u32;
        let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
        let val = try_exec!(inst.mem_load_u16(mi, addr)) as i16;
        try_exec!(inst.push(Value::I32(val as i32)));
    }
    0x2F => {
        // i32.load16_u
        let (mi, offset) = try_exec!(inst.read_memarg());
        let base = try_exec!(inst.pop_i32()) as u32;
        let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
        let val = try_exec!(inst.mem_load_u16(mi, addr));
        try_exec!(inst.push(Value::I32(val as i32)));
    }
    0x30 => {
        // i64.load8_s
        let (mi, offset) = try_exec!(inst.read_memarg());
        let base = try_exec!(inst.pop_i32()) as u32;
        let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
        let val = try_exec!(inst.mem_load_u8(mi, addr)) as i8;
        try_exec!(inst.push(Value::I64(val as i64)));
    }
    0x31 => {
        // i64.load8_u
        let (mi, offset) = try_exec!(inst.read_memarg());
        let base = try_exec!(inst.pop_i32()) as u32;
        let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
        let val = try_exec!(inst.mem_load_u8(mi, addr));
        try_exec!(inst.push(Value::I64(val as i64)));
    }
    0x32 => {
        // i64.load16_s
        let (mi, offset) = try_exec!(inst.read_memarg());
        let base = try_exec!(inst.pop_i32()) as u32;
        let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
        let val = try_exec!(inst.mem_load_u16(mi, addr)) as i16;
        try_exec!(inst.push(Value::I64(val as i64)));
    }
    0x33 => {
        // i64.load16_u
        let (mi, offset) = try_exec!(inst.read_memarg());
        let base = try_exec!(inst.pop_i32()) as u32;
        let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
        let val = try_exec!(inst.mem_load_u16(mi, addr));
        try_exec!(inst.push(Value::I64(val as i64)));
    }
    0x34 => {
        // i64.load32_s
        let (mi, offset) = try_exec!(inst.read_memarg());
        let base = try_exec!(inst.pop_i32()) as u32;
        let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
        let val = try_exec!(inst.mem_load_u32(mi, addr)) as i32;
        try_exec!(inst.push(Value::I64(val as i64)));
    }
    0x35 => {
        // i64.load32_u
        let (mi, offset) = try_exec!(inst.read_memarg());
        let base = try_exec!(inst.pop_i32()) as u32;
        let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
        let val = try_exec!(inst.mem_load_u32(mi, addr));
        try_exec!(inst.push(Value::I64(val as i64)));
    }

    // ── Sub-word stores ─────────────────────────────────────
    0x3A => {
        // i32.store8
        let (mi, offset) = try_exec!(inst.read_memarg());
        let val = try_exec!(inst.pop_i32());
        let base = try_exec!(inst.pop_i32()) as u32;
        let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
        try_exec!(inst.mem_store_u8(mi, addr, val as u8));
    }
    0x3B => {
        // i32.store16
        let (mi, offset) = try_exec!(inst.read_memarg());
        let val = try_exec!(inst.pop_i32());
        let base = try_exec!(inst.pop_i32()) as u32;
        let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
        try_exec!(inst.mem_store_u16(mi, addr, val as u16));
    }
    0x3C => {
        // i64.store8
        let (mi, offset) = try_exec!(inst.read_memarg());
        let val = try_exec!(inst.pop_i64());
        let base = try_exec!(inst.pop_i32()) as u32;
        let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
        try_exec!(inst.mem_store_u8(mi, addr, val as u8));
    }
    0x3D => {
        // i64.store16
        let (mi, offset) = try_exec!(inst.read_memarg());
        let val = try_exec!(inst.pop_i64());
        let base = try_exec!(inst.pop_i32()) as u32;
        let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
        try_exec!(inst.mem_store_u16(mi, addr, val as u16));
    }
    0x3E => {
        // i64.store32
        let (mi, offset) = try_exec!(inst.read_memarg());
        let val = try_exec!(inst.pop_i64());
        let base = try_exec!(inst.pop_i32()) as u32;
        let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
        try_exec!(inst.mem_store_u32(mi, addr, val as u32));
    }

    0x38 => {
        // f32.store
        if inst.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); }
        let (mi, offset) = try_exec!(inst.read_memarg());
        let val = try_exec!(inst.pop_f32());
        let base = try_exec!(inst.pop_i32()) as u32;
        let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
        try_exec!(inst.mem_store_f32(mi, addr, val));
    }
    0x39 => {
        // f64.store
        if inst.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); }
        let (mi, offset) = try_exec!(inst.read_memarg());
        let val = try_exec!(inst.pop_f64());
        let base = try_exec!(inst.pop_i32()) as u32;
        let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
        try_exec!(inst.mem_store_f64(mi, addr, val));
    }

    // ── Memory management ────────────────────────────────────
    0x3F => {
        // memory.size
        let mi = try_exec!(inst.read_leb128_u32()) as usize;
        let msz = inst.mem_size(mi);
        let page_size = if mi < inst.module.memories.len() {
            if let Some(log2) = inst.module.memories[mi].page_size_log2 {
                1usize << log2
            } else { WASM_PAGE_SIZE }
        } else { WASM_PAGE_SIZE };
        let pages = (msz / page_size) as i64;
        let is_mem64 = mi < inst.module.memories.len() && inst.module.memories[mi].is_memory64;
        if is_mem64 {
            try_exec!(inst.push(Value::I64(pages)));
        } else {
            try_exec!(inst.push(Value::I32(pages as i32)));
        }
    }
    0x40 => {
        // memory.grow
        let mi = try_exec!(inst.read_leb128_u32()) as usize;
        let is_mem64 = mi < inst.module.memories.len() && inst.module.memories[mi].is_memory64;
        let delta = if is_mem64 {
            try_exec!(inst.pop_i64()) as u32
        } else {
            try_exec!(inst.pop_i32()) as u32
        };
        let page_size = if mi < inst.module.memories.len() {
            if let Some(log2) = inst.module.memories[mi].page_size_log2 {
                1usize << log2
            } else { WASM_PAGE_SIZE }
        } else { WASM_PAGE_SIZE };
        let msz = inst.mem_size(mi);
        let old_pages = (msz / page_size) as u32;
        let new_pages = old_pages.saturating_add(delta);
        // Check both the module's declared max and the global hard limit
        let module_max = if mi < inst.module.memories.len() && inst.module.memories[mi].max_pages != u32::MAX {
            inst.module.memories[mi].max_pages as usize
        } else if inst.module.has_memory_max && mi == 0 && inst.module.memory_max_pages != u32::MAX {
            inst.module.memory_max_pages as usize
        } else {
            // For custom page sizes, compute a reasonable max in pages
            let max_bytes = MAX_MEMORY_PAGES * WASM_PAGE_SIZE;
            max_bytes / page_size
        };
        if new_pages as usize > module_max {
            // Failure: push -1
            if is_mem64 {
                try_exec!(inst.push(Value::I64(-1)));
            } else {
                try_exec!(inst.push(Value::I32(-1)));
            }
        } else {
            let new_size = (new_pages as usize).saturating_mul(page_size);
            if mi < inst.memories.len() {
                inst.memories[mi].resize(new_size, 0);
                inst.memory_sizes[mi] = new_size;
            }
            if is_mem64 {
                try_exec!(inst.push(Value::I64(old_pages as i64)));
            } else {
                try_exec!(inst.push(Value::I32(old_pages as i32)));
            }
        }
    }


        _ => return ExecResult::Trap(WasmError::InvalidOpcode(opcode)),
    }

    ExecResult::Ok
}
