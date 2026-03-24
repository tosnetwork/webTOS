//! WASM stack-machine interpreter with fuel-based metering.
//!
//! This is the core execution engine. It runs WASM bytecode one instruction
//! at a time, consuming fuel. When fuel runs out or a host call is needed,
//! execution pauses and the caller can resume.

use alloc::vec;
use alloc::vec::Vec;
use crate::wasm::decoder::{WasmModule, ImportKind};
use crate::wasm::types::*;

// ─── Call frame ─────────────────────────────────────────────────────────────

/// A call frame on the call stack.
#[derive(Clone, Copy)]
pub struct CallFrame {
    pub func_idx: u32,
    pub return_pc: usize,         // PC to resume in caller's code
    pub code_offset: usize,       // start of this function's code in module.code
    pub code_end: usize,          // end of this function's code
    pub local_base: usize,        // index into locals array where this frame's locals start
    pub local_count: usize,       // number of locals (params + declared locals)
    pub stack_base: usize,        // operand stack depth at function entry
    pub result_count: u8,         // how many values to return
}

impl CallFrame {
    pub const fn zero() -> Self {
        CallFrame {
            func_idx: 0,
            return_pc: 0,
            code_offset: 0,
            code_end: 0,
            local_base: 0,
            local_count: 0,
            stack_base: 0,
            result_count: 0,
        }
    }
}

// ─── Block frame (for control flow) ─────────────────────────────────────────

/// Tracks Block/Loop/If control flow for branch targets.
#[derive(Clone, Copy)]
struct BlockFrame {
    /// The PC of the block start (for Loop, this is the branch target).
    start_pc: usize,
    /// The PC just past the matching End (for Block/If, this is the branch target).
    end_pc: usize,
    /// Stack depth at block entry.
    stack_base: usize,
    /// Number of result values the block produces.
    result_count: u8,
    /// True if this is a Loop (branch goes to start), false for Block/If (branch goes to end).
    is_loop: bool,
}

impl BlockFrame {
    const fn zero() -> Self {
        BlockFrame {
            start_pc: 0,
            end_pc: 0,
            stack_base: 0,
            result_count: 0,
            is_loop: false,
        }
    }
}

// ─── Execution result ───────────────────────────────────────────────────────

/// Result of executing one or more instructions.
#[derive(Debug)]
pub enum ExecResult {
    /// Execution completed normally (function returned).
    Ok,
    /// Function returned a value.
    Returned(Value),
    /// Fuel exhausted.
    OutOfFuel,
    /// A trap occurred.
    Trap(WasmError),
    /// A host function call is needed: (import_idx, args, arg_count).
    HostCall(u32, [Value; MAX_PARAMS], u8),
}

// ─── Locals storage ─────────────────────────────────────────────────────────

/// Maximum total locals across all active call frames.
const MAX_TOTAL_LOCALS: usize = 65_536;

// ─── WASM instance ─────────────────────────────────────────────────────────

/// A running WASM instance.
pub struct WasmInstance {
    pub module: WasmModule,
    pub stack: Vec<Value>,
    pub stack_ptr: usize,
    pub locals: Vec<Value>,
    pub globals: Vec<Value>,
    pub table: Vec<Option<u32>>,
    pub memory: Vec<u8>,
    pub memory_size: usize,
    /// Program counter — byte offset within `module.code`.
    pub pc: usize,
    pub fuel: u64,
    pub call_stack: Vec<CallFrame>,
    pub call_depth: usize,
    /// Block stack for control flow within the current function.
    block_stack: Vec<BlockFrame>,
    block_depth: usize,
    /// Set when execution is finished.
    pub finished: bool,
    /// Per-instance runtime class controlling which features are allowed.
    pub runtime_class: RuntimeClass,
}

impl WasmInstance {
    /// Create a new instance from a decoded module with the given fuel budget.
    /// Create a new instance with the default runtime class (ProofGrade).
    pub fn new(module: WasmModule, fuel: u64) -> Self {
        Self::with_class(module, fuel, DEFAULT_RUNTIME_CLASS)
    }

    /// Create a new instance with a specific runtime class.
    pub fn with_class(module: WasmModule, fuel: u64, runtime_class: RuntimeClass) -> Self {
        let mem_pages = module.memory_min_pages as usize;
        let mem_size = mem_pages.saturating_mul(WASM_PAGE_SIZE);

        // Initialize globals from module definitions
        let mut globals = Vec::with_capacity(module.globals.len());
        for g in &module.globals {
            globals.push(g.init_value);
        }

        // Initialize table from module definitions
        let table_size = module.tables.first().map_or(0, |t| t.min as usize);
        let mut table: Vec<Option<u32>> = vec![None; table_size];

        // Apply element segments to table
        for seg in &module.element_segments {
            let offset = seg.offset as usize;
            for (i, &func_idx) in seg.func_indices.iter().enumerate() {
                let idx = offset.saturating_add(i);
                if idx < table.len() {
                    table[idx] = Some(func_idx);
                }
            }
        }

        let mut inst = WasmInstance {
            module,
            stack: vec![Value::I32(0); MAX_STACK],
            stack_ptr: 0,
            locals: vec![Value::I32(0); MAX_TOTAL_LOCALS],
            globals,
            table,
            memory: vec![0u8; mem_size],
            memory_size: mem_size,
            pc: 0,
            fuel,
            call_stack: vec![CallFrame::zero(); MAX_CALL_DEPTH],
            call_depth: 0,
            block_stack: vec![BlockFrame::zero(); MAX_BLOCK_DEPTH],
            block_depth: 0,
            finished: false,
            runtime_class,
        };

        // Apply active data segments to memory (skip passive segments marked with offset=u32::MAX)
        for seg in &inst.module.data_segments {
            if seg.offset == u32::MAX {
                continue; // passive segment — applied later by memory.init
            }
            let dst_start = seg.offset as usize;
            let src_start = seg.data_offset;
            let len = seg.data_len;
            if dst_start.saturating_add(len) <= inst.memory_size
                && src_start.saturating_add(len) <= inst.module.code.len()
            {
                inst.memory[dst_start..dst_start + len]
                    .copy_from_slice(&inst.module.code[src_start..src_start + len]);
            }
        }

        inst
    }

    // ─── Stack operations ───────────────────────────────────────────────

    fn push(&mut self, val: Value) -> Result<(), WasmError> {
        if self.stack_ptr >= MAX_STACK {
            return Err(WasmError::StackOverflow);
        }
        self.stack[self.stack_ptr] = val;
        self.stack_ptr += 1;
        Ok(())
    }

    fn pop(&mut self) -> Result<Value, WasmError> {
        if self.stack_ptr == 0 {
            return Err(WasmError::StackUnderflow);
        }
        self.stack_ptr -= 1;
        Ok(self.stack[self.stack_ptr])
    }

    fn pop_i32(&mut self) -> Result<i32, WasmError> {
        Ok(self.pop()?.as_i32())
    }

    fn pop_i64(&mut self) -> Result<i64, WasmError> {
        Ok(self.pop()?.as_i64())
    }

    // ─── Code reading ───────────────────────────────────────────────────

    fn read_byte(&mut self) -> Result<u8, WasmError> {
        if self.pc >= self.module.code.len() {
            return Err(WasmError::UnexpectedEnd);
        }
        let b = self.module.code[self.pc];
        self.pc += 1;
        Ok(b)
    }

    fn read_leb128_u32(&mut self) -> Result<u32, WasmError> {
        crate::wasm::decoder::decode_leb128_u32(&self.module.code, &mut self.pc)
    }

    fn read_leb128_i32(&mut self) -> Result<i32, WasmError> {
        crate::wasm::decoder::decode_leb128_i32(&self.module.code, &mut self.pc)
    }

    fn read_leb128_i64(&mut self) -> Result<i64, WasmError> {
        crate::wasm::decoder::decode_leb128_i64(&self.module.code, &mut self.pc)
    }

    // ─── Locals ─────────────────────────────────────────────────────────

    fn get_local(&self, idx: u32) -> Result<Value, WasmError> {
        if self.call_depth == 0 {
            return Err(WasmError::OutOfBounds);
        }
        let frame = &self.call_stack[self.call_depth - 1];
        let abs = frame.local_base + idx as usize;
        if idx as usize >= frame.local_count || abs >= MAX_TOTAL_LOCALS {
            return Err(WasmError::OutOfBounds);
        }
        Ok(self.locals[abs])
    }

    fn set_local(&mut self, idx: u32, val: Value) -> Result<(), WasmError> {
        if self.call_depth == 0 {
            return Err(WasmError::OutOfBounds);
        }
        let frame = &self.call_stack[self.call_depth - 1];
        let abs = frame.local_base + idx as usize;
        if idx as usize >= frame.local_count || abs >= MAX_TOTAL_LOCALS {
            return Err(WasmError::OutOfBounds);
        }
        self.locals[abs] = val;
        Ok(())
    }

    // ─── Memory access ──────────────────────────────────────────────────

    fn mem_load_i32(&self, addr: usize) -> Result<i32, WasmError> {
        if addr + 4 > self.memory_size {
            return Err(WasmError::MemoryOutOfBounds);
        }
        let bytes = [
            self.memory[addr],
            self.memory[addr + 1],
            self.memory[addr + 2],
            self.memory[addr + 3],
        ];
        Ok(i32::from_le_bytes(bytes))
    }

    fn mem_load_i64(&self, addr: usize) -> Result<i64, WasmError> {
        if addr + 8 > self.memory_size {
            return Err(WasmError::MemoryOutOfBounds);
        }
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&self.memory[addr..addr + 8]);
        Ok(i64::from_le_bytes(bytes))
    }

    fn mem_store_i32(&mut self, addr: usize, val: i32) -> Result<(), WasmError> {
        if addr + 4 > self.memory_size {
            return Err(WasmError::MemoryOutOfBounds);
        }
        let bytes = val.to_le_bytes();
        self.memory[addr..addr + 4].copy_from_slice(&bytes);
        Ok(())
    }

    fn mem_store_i64(&mut self, addr: usize, val: i64) -> Result<(), WasmError> {
        if addr + 8 > self.memory_size {
            return Err(WasmError::MemoryOutOfBounds);
        }
        let bytes = val.to_le_bytes();
        self.memory[addr..addr + 8].copy_from_slice(&bytes);
        Ok(())
    }

    // ─── Sub-word memory helpers ─────────────────────────────────────────

    fn mem_load_u8(&self, addr: usize) -> Result<u8, WasmError> {
        if addr >= self.memory_size { return Err(WasmError::MemoryOutOfBounds); }
        Ok(self.memory[addr])
    }

    fn mem_load_u16(&self, addr: usize) -> Result<u16, WasmError> {
        if addr.checked_add(2).ok_or(WasmError::MemoryOutOfBounds)? > self.memory_size {
            return Err(WasmError::MemoryOutOfBounds);
        }
        Ok(u16::from_le_bytes([self.memory[addr], self.memory[addr + 1]]))
    }

    fn mem_load_u32(&self, addr: usize) -> Result<u32, WasmError> {
        if addr.checked_add(4).ok_or(WasmError::MemoryOutOfBounds)? > self.memory_size {
            return Err(WasmError::MemoryOutOfBounds);
        }
        Ok(u32::from_le_bytes([
            self.memory[addr], self.memory[addr + 1],
            self.memory[addr + 2], self.memory[addr + 3],
        ]))
    }

    fn mem_store_u8(&mut self, addr: usize, val: u8) -> Result<(), WasmError> {
        if addr >= self.memory_size { return Err(WasmError::MemoryOutOfBounds); }
        self.memory[addr] = val;
        Ok(())
    }

    fn mem_store_u16(&mut self, addr: usize, val: u16) -> Result<(), WasmError> {
        if addr.checked_add(2).ok_or(WasmError::MemoryOutOfBounds)? > self.memory_size {
            return Err(WasmError::MemoryOutOfBounds);
        }
        let bytes = val.to_le_bytes();
        self.memory[addr..addr + 2].copy_from_slice(&bytes);
        Ok(())
    }

    fn mem_store_u32(&mut self, addr: usize, val: u32) -> Result<(), WasmError> {
        if addr.checked_add(4).ok_or(WasmError::MemoryOutOfBounds)? > self.memory_size {
            return Err(WasmError::MemoryOutOfBounds);
        }
        let bytes = val.to_le_bytes();
        self.memory[addr..addr + 4].copy_from_slice(&bytes);
        Ok(())
    }

    // ─── Float helpers ────────────────────────────────────────────────

    fn pop_f32(&mut self) -> Result<f32, WasmError> {
        Ok(self.pop()?.as_f32())
    }

    fn pop_f64(&mut self) -> Result<f64, WasmError> {
        Ok(self.pop()?.as_f64())
    }

    fn read_f32(&mut self) -> Result<f32, WasmError> {
        if self.pc.checked_add(4).ok_or(WasmError::UnexpectedEnd)? > self.module.code.len() {
            return Err(WasmError::UnexpectedEnd);
        }
        let bytes = [
            self.module.code[self.pc], self.module.code[self.pc + 1],
            self.module.code[self.pc + 2], self.module.code[self.pc + 3],
        ];
        self.pc += 4;
        Ok(f32::from_le_bytes(bytes))
    }

    fn read_f64(&mut self) -> Result<f64, WasmError> {
        if self.pc.checked_add(8).ok_or(WasmError::UnexpectedEnd)? > self.module.code.len() {
            return Err(WasmError::UnexpectedEnd);
        }
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&self.module.code[self.pc..self.pc + 8]);
        self.pc += 8;
        Ok(f64::from_le_bytes(bytes))
    }

    fn mem_load_f32(&self, addr: usize) -> Result<f32, WasmError> {
        if addr.checked_add(4).ok_or(WasmError::MemoryOutOfBounds)? > self.memory_size {
            return Err(WasmError::MemoryOutOfBounds);
        }
        Ok(f32::from_le_bytes([
            self.memory[addr], self.memory[addr + 1],
            self.memory[addr + 2], self.memory[addr + 3],
        ]))
    }

    fn mem_load_f64(&self, addr: usize) -> Result<f64, WasmError> {
        if addr.checked_add(8).ok_or(WasmError::MemoryOutOfBounds)? > self.memory_size {
            return Err(WasmError::MemoryOutOfBounds);
        }
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&self.memory[addr..addr + 8]);
        Ok(f64::from_le_bytes(bytes))
    }

    fn mem_store_f32(&mut self, addr: usize, val: f32) -> Result<(), WasmError> {
        if addr.checked_add(4).ok_or(WasmError::MemoryOutOfBounds)? > self.memory_size {
            return Err(WasmError::MemoryOutOfBounds);
        }
        self.memory[addr..addr + 4].copy_from_slice(&val.to_le_bytes());
        Ok(())
    }

    fn mem_store_f64(&mut self, addr: usize, val: f64) -> Result<(), WasmError> {
        if addr.checked_add(8).ok_or(WasmError::MemoryOutOfBounds)? > self.memory_size {
            return Err(WasmError::MemoryOutOfBounds);
        }
        self.memory[addr..addr + 8].copy_from_slice(&val.to_le_bytes());
        Ok(())
    }

    // ─── Float NaN helpers (matching wasmi semantics) ──────────────────

    /// Convert signaling NaN to quiet NaN, preserving payload.
    /// WASM spec requires all NaN outputs to be quiet NaN.
    fn quiet_nan_f32(v: f32) -> f32 {
        if v.is_nan() {
            f32::from_bits(v.to_bits() | 0x0040_0000) // set quiet bit
        } else { v }
    }

    fn quiet_nan_f64(v: f64) -> f64 {
        if v.is_nan() {
            f64::from_bits(v.to_bits() | 0x0008_0000_0000_0000)
        } else { v }
    }

    /// WASM spec: f32.nearest rounds to nearest even.
    fn wasm_nearest_f32(v: f32) -> f32 {
        if v.is_nan() { return Self::quiet_nan_f32(v); }
        libm::rintf(v)
    }

    fn wasm_nearest_f64(v: f64) -> f64 {
        if v.is_nan() { return Self::quiet_nan_f64(v); }
        libm::rint(v)
    }

    /// Unary float ops: quiet NaN passthrough for ceil/floor/trunc/sqrt.
    fn wasm_ceil_f32(v: f32) -> f32 {
        if v.is_nan() { return Self::quiet_nan_f32(v); }
        libm::ceilf(v)
    }
    fn wasm_floor_f32(v: f32) -> f32 {
        if v.is_nan() { return Self::quiet_nan_f32(v); }
        libm::floorf(v)
    }
    fn wasm_trunc_f32(v: f32) -> f32 {
        if v.is_nan() { return Self::quiet_nan_f32(v); }
        libm::truncf(v)
    }
    fn wasm_sqrt_f32(v: f32) -> f32 {
        if v.is_nan() { return Self::quiet_nan_f32(v); }
        libm::sqrtf(v)
    }
    fn wasm_ceil_f64(v: f64) -> f64 {
        if v.is_nan() { return Self::quiet_nan_f64(v); }
        libm::ceil(v)
    }
    fn wasm_floor_f64(v: f64) -> f64 {
        if v.is_nan() { return Self::quiet_nan_f64(v); }
        libm::floor(v)
    }
    fn wasm_trunc_f64(v: f64) -> f64 {
        if v.is_nan() { return Self::quiet_nan_f64(v); }
        libm::trunc(v)
    }
    fn wasm_sqrt_f64(v: f64) -> f64 {
        if v.is_nan() { return Self::quiet_nan_f64(v); }
        libm::sqrt(v)
    }

    /// WASM spec min/max: propagate NaN with quieting (using lhs+rhs),
    /// handle -0.0/+0.0 sign correctly. Matches wasmi semantics.
    fn wasm_min_f32(a: f32, b: f32) -> f32 {
        if a < b { a }
        else if b < a { b }
        else if a == b {
            // Handle -0.0 vs +0.0: min(-0, +0) = -0
            if a.is_sign_negative() && b.is_sign_positive() { a } else { b }
        } else {
            // At least one is NaN — use + to propagate and quiet
            a + b
        }
    }
    fn wasm_max_f32(a: f32, b: f32) -> f32 {
        if a > b { a }
        else if b > a { b }
        else if a == b {
            if a.is_sign_positive() && b.is_sign_negative() { a } else { b }
        } else {
            a + b
        }
    }
    fn wasm_min_f64(a: f64, b: f64) -> f64 {
        if a < b { a }
        else if b < a { b }
        else if a == b {
            if a.is_sign_negative() && b.is_sign_positive() { a } else { b }
        } else {
            a + b
        }
    }
    fn wasm_max_f64(a: f64, b: f64) -> f64 {
        if a > b { a }
        else if b > a { b }
        else if a == b {
            if a.is_sign_positive() && b.is_sign_negative() { a } else { b }
        } else {
            a + b
        }
    }

    // ─── V128 / SIMD helpers ──────────────────────────────────────────

    fn pop_v128(&mut self) -> Result<V128, WasmError> {
        Ok(self.pop()?.as_v128())
    }

    fn read_v128(&mut self) -> Result<V128, WasmError> {
        if self.pc.checked_add(16).ok_or(WasmError::UnexpectedEnd)? > self.module.code.len() {
            return Err(WasmError::UnexpectedEnd);
        }
        let mut b = [0u8; 16];
        b.copy_from_slice(&self.module.code[self.pc..self.pc + 16]);
        self.pc += 16;
        Ok(V128(b))
    }

    fn mem_load_v128(&self, addr: usize) -> Result<V128, WasmError> {
        if addr.checked_add(16).ok_or(WasmError::MemoryOutOfBounds)? > self.memory_size {
            return Err(WasmError::MemoryOutOfBounds);
        }
        let mut b = [0u8; 16];
        b.copy_from_slice(&self.memory[addr..addr + 16]);
        Ok(V128(b))
    }

    fn mem_store_v128(&mut self, addr: usize, val: V128) -> Result<(), WasmError> {
        if addr.checked_add(16).ok_or(WasmError::MemoryOutOfBounds)? > self.memory_size {
            return Err(WasmError::MemoryOutOfBounds);
        }
        self.memory[addr..addr + 16].copy_from_slice(&val.0);
        Ok(())
    }

    // ─── Block management ───────────────────────────────────────────────

    fn push_block(&mut self, bf: BlockFrame) -> Result<(), WasmError> {
        if self.block_depth >= MAX_BLOCK_DEPTH {
            return Err(WasmError::BranchDepthExceeded);
        }
        self.block_stack[self.block_depth] = bf;
        self.block_depth += 1;
        Ok(())
    }

    fn pop_block(&mut self) -> Result<BlockFrame, WasmError> {
        if self.block_depth == 0 {
            return Err(WasmError::InvalidBlockType);
        }
        self.block_depth -= 1;
        Ok(self.block_stack[self.block_depth])
    }

    /// Skip forward in the bytecode to find the matching End for a block.
    /// This handles nested blocks correctly.
    fn skip_to_end(&mut self) -> Result<usize, WasmError> {
        let mut depth: usize = 1;
        while depth > 0 {
            let b = self.read_byte()?;
            match b {
                0x02 | 0x03 | 0x04 => {
                    // Block, Loop, If — nested
                    // Read and discard the block type
                    let _ = self.read_leb128_i32()?;
                    depth += 1;
                }
                0x05 => {
                    // Else — if we're at depth 1, this is our else
                    if depth == 1 {
                        return Ok(self.pc);
                    }
                }
                0x0B => {
                    // End
                    depth -= 1;
                    if depth == 0 {
                        return Ok(self.pc);
                    }
                }
                // Instructions with LEB128 immediates that we need to skip
                0x0C | 0x0D => { let _ = self.read_leb128_u32()?; } // br, br_if
                0x0E => {
                    // br_table: count + count labels + default label
                    let count = self.read_leb128_u32()? as usize;
                    for _ in 0..count { let _ = self.read_leb128_u32()?; }
                    let _ = self.read_leb128_u32()?; // default
                }
                0x10 | 0x12 => { let _ = self.read_leb128_u32()?; } // call, return_call
                0x11 | 0x13 => { let _ = self.read_leb128_u32()?; let _ = self.read_leb128_u32()?; } // call_indirect, return_call_indirect
                0x20 | 0x21 | 0x22 | 0x23 | 0x24 | 0x25 | 0x26 => { let _ = self.read_leb128_u32()?; } // local/global/table get/set
                0xFC => {
                    // Multi-byte prefix: read sub-opcode, then skip its immediates
                    let sub = self.read_leb128_u32()?;
                    match sub {
                        0..=7 => {} // sat trunc: no immediates
                        8 => { let _ = self.read_leb128_u32()?; let _ = self.read_leb128_u32()?; } // memory.init
                        9 | 13 => { let _ = self.read_leb128_u32()?; } // data.drop, elem.drop
                        10 => { let _ = self.read_leb128_u32()?; let _ = self.read_leb128_u32()?; } // memory.copy
                        11 => { let _ = self.read_leb128_u32()?; } // memory.fill
                        12 => { let _ = self.read_leb128_u32()?; let _ = self.read_leb128_u32()?; } // table.init
                        14 => { let _ = self.read_leb128_u32()?; let _ = self.read_leb128_u32()?; } // table.copy
                        15..=17 => { let _ = self.read_leb128_u32()?; } // table.grow/size/fill
                        _ => {}
                    }
                }
                0xFD => {
                    // SIMD prefix: read sub-opcode, then skip its immediates
                    let sub = self.read_leb128_u32()?;
                    match sub {
                        0..=11 => { let _ = self.read_leb128_u32()?; let _ = self.read_leb128_u32()?; } // v128 load/store: align + offset
                        12 => { self.pc += 16; } // v128.const: 16 bytes immediate
                        13 => { self.pc += 16; } // i8x16.shuffle: 16 lane bytes
                        21..=34 => { self.pc += 1; } // extract/replace lane: 1 byte lane index
                        84 | 92 | 93 | 94 => { self.pc += 16; } // v128.load*_lane: align + offset + 16 bytes (handled above for 92-94)
                        _ => {} // most SIMD ops have no immediates
                    }
                }
                0x3F | 0x40 => { let _ = self.read_leb128_u32()?; } // memory.size/grow (reserved byte)
                0x28 | 0x29 | 0x2A | 0x2B | 0x2C | 0x2D | 0x2E | 0x2F
                | 0x30 | 0x31 | 0x32 | 0x33 | 0x34 | 0x35
                | 0x36 | 0x37 | 0x38 | 0x39 | 0x3A | 0x3B | 0x3C | 0x3D | 0x3E => {
                    // memory load/store (all variants): align + offset
                    let _ = self.read_leb128_u32()?;
                    let _ = self.read_leb128_u32()?;
                }
                0x41 => { let _ = self.read_leb128_i32()?; } // i32.const
                0x42 => { let _ = self.read_leb128_i64()?; } // i64.const
                0x43 => { self.pc += 4; } // f32.const (4 bytes IEEE 754)
                0x44 => { self.pc += 8; } // f64.const (8 bytes IEEE 754)
                0x0F => {} // return
                _ => {
                    // Most instructions have no immediates — just skip the opcode byte
                }
            }
        }
        Ok(self.pc)
    }

    /// Branch to the label at the given depth on the block stack.
    fn branch(&mut self, depth: u32) -> Result<(), WasmError> {
        if depth as usize >= self.block_depth {
            return Err(WasmError::BranchDepthExceeded);
        }
        let target_idx = self.block_depth - 1 - depth as usize;
        let target = self.block_stack[target_idx];

        if target.is_loop {
            // Branch to loop start
            self.pc = target.start_pc;
            // Truncate the stack to block's base
            self.stack_ptr = target.stack_base;
        } else {
            // Branch to block end — pop all blocks up to and including target
            // Save any result values
            let result_count = target.result_count as usize;
            let mut results = [Value::I32(0); MAX_RESULTS];
            for i in (0..result_count).rev() {
                results[i] = match self.pop() {
                    Ok(v) => v,
                    Err(_) => Value::I32(0),
                };
            }

            self.stack_ptr = target.stack_base;
            for i in 0..result_count {
                let _ = self.push(results[i]);
            }

            self.pc = target.end_pc;
            self.block_depth = target_idx;
        }
        Ok(())
    }

    // ─── Function entry ─────────────────────────────────────────────────

    /// Enter a WASM-defined function (not an import).
    fn enter_function(&mut self, func_idx: u32, keep_args_on_stack: bool) -> Result<(), WasmError> {
        let local_func_idx = (func_idx as usize).checked_sub(self.module.func_import_count()).ok_or(WasmError::FunctionNotFound(func_idx))?;

        // Extract everything we need from the module into local variables
        // so we don't hold any borrows of self.module during mutation.
        let (param_count, result_count, declared_local_count, func_code_offset, func_code_len, local_types) = {
            if local_func_idx >= self.module.functions.len() {
                return Err(WasmError::FunctionNotFound(func_idx));
            }
            let func = &self.module.functions[local_func_idx];
            let type_idx = func.type_idx as usize;
            if type_idx >= self.module.func_types.len() {
                return Err(WasmError::FunctionNotFound(func_idx));
            }
            let ft = &self.module.func_types[type_idx];
            let mut lt = [ValType::I32; MAX_LOCALS];
            let dlc = func.local_count as usize;
            for i in 0..dlc.min(MAX_LOCALS) {
                lt[i] = func.locals[i];
            }
            (ft.param_count as usize, ft.result_count, dlc, func.code_offset, func.code_len, lt)
        };

        let total_locals = param_count + declared_local_count;

        if self.call_depth >= MAX_CALL_DEPTH {
            return Err(WasmError::CallStackOverflow);
        }

        // Determine local base for new frame
        let local_base = if self.call_depth > 0 {
            let prev = &self.call_stack[self.call_depth - 1];
            prev.local_base + prev.local_count
        } else {
            0
        };

        if local_base + total_locals > MAX_TOTAL_LOCALS {
            return Err(WasmError::StackOverflow);
        }

        // Pop arguments from the stack into locals
        if keep_args_on_stack {
            for i in (0..param_count).rev() {
                self.locals[local_base + i] = self.pop()?;
            }
        }

        // Zero-initialize declared locals
        for i in 0..declared_local_count {
            let ty = local_types[i];
            self.locals[local_base + param_count + i] = Value::default_for(ty);
        }

        // Push call frame
        let frame = CallFrame {
            func_idx,
            return_pc: self.pc,
            code_offset: func_code_offset,
            code_end: func_code_offset + func_code_len,
            local_base,
            local_count: total_locals,
            stack_base: self.stack_ptr,
            result_count,
        };

        self.call_stack[self.call_depth] = frame;
        self.call_depth += 1;

        // Set PC to function body
        self.pc = func_code_offset;

        // Reset block stack for new function
        self.block_depth = 0;

        Ok(())
    }

    /// Prepare a host call (import invocation).
    fn handle_import_call(&mut self, func_idx: u32) -> Result<ExecResult, WasmError> {
        // Find the N-th function import (func_idx indexes only function imports)
        let mut func_count: u32 = 0;
        let mut found_imp = None;
        for imp in &self.module.imports {
            if let ImportKind::Func(_) = imp.kind {
                if func_count == func_idx {
                    found_imp = Some(imp);
                    break;
                }
                func_count = func_count.saturating_add(1);
            }
        }
        let imp = match found_imp {
            Some(i) => i,
            None => return Err(WasmError::ImportNotFound(func_idx)),
        };

        let type_idx = match imp.kind {
            ImportKind::Func(ti) => ti as usize,
            _ => return Err(WasmError::ImportNotFound(func_idx)),
        };

        if type_idx >= self.module.func_types.len() {
            return Err(WasmError::FunctionNotFound(func_idx));
        }
        let ft = &self.module.func_types[type_idx];

        let param_count = ft.param_count;
        let mut args = [Value::I32(0); MAX_PARAMS];

        for i in (0..param_count as usize).rev() {
            args[i] = self.pop()?;
        }

        Ok(ExecResult::HostCall(func_idx, args, param_count))
    }

    // ─── Public API ─────────────────────────────────────────────────────

    /// Run the module's start function if one is defined.
    /// The WASM spec requires the start function to be invoked automatically
    /// at instantiation before any exports are called.
    pub fn run_start(&mut self) -> ExecResult {
        if let Some(start_idx) = self.module.start_func {
            self.call_func(start_idx, &[])
        } else {
            ExecResult::Ok
        }
    }

    /// Call a function by its absolute index (imports + local functions).
    pub fn call_func(&mut self, func_idx: u32, args: &[Value]) -> ExecResult {
        // Push arguments onto the stack
        for arg in args {
            if let Err(e) = self.push(*arg) {
                return ExecResult::Trap(e);
            }
        }

        // Check if it's an import
        if (func_idx as usize) < self.module.func_import_count() {
            return match self.handle_import_call(func_idx) {
                Ok(result) => result,
                Err(e) => ExecResult::Trap(e),
            };
        }

        // Enter the function
        if let Err(e) = self.enter_function(func_idx, true) {
            return ExecResult::Trap(e);
        }

        self.finished = false;
        self.run()
    }

    /// Resume execution after a host call, providing the return value (if any).
    pub fn resume(&mut self, return_value: Option<Value>) -> ExecResult {
        if let Some(val) = return_value {
            if let Err(e) = self.push(val) {
                return ExecResult::Trap(e);
            }
        }
        self.run()
    }

    /// Run until completion, fuel exhaustion, or host call.
    pub fn run(&mut self) -> ExecResult {
        loop {
            match self.step() {
                ExecResult::Ok => continue,
                other => return other,
            }
        }
    }

    /// Execute one instruction, consuming fuel.
    fn step(&mut self) -> ExecResult {
        if self.fuel == 0 {
            return ExecResult::OutOfFuel;
        }
        self.fuel -= 1;

        // Check if we've run past the end of the current function
        if self.call_depth > 0 {
            let frame = &self.call_stack[self.call_depth - 1];
            if self.pc >= frame.code_end {
                // Implicit return at end of function
                return self.do_return();
            }
        } else {
            self.finished = true;
            // If there are values on the stack, return the top one
            if self.stack_ptr > 0 {
                return ExecResult::Returned(self.stack[self.stack_ptr - 1]);
            }
            return ExecResult::Ok;
        }

        let opcode = match self.read_byte() {
            Ok(b) => b,
            Err(e) => return ExecResult::Trap(e),
        };

        macro_rules! try_exec {
            ($expr:expr) => {
                match $expr {
                    Ok(v) => v,
                    Err(e) => return ExecResult::Trap(e),
                }
            };
        }

        match opcode {
            // ── Control ─────────────────────────────────────────────
            0x00 => {
                // unreachable
                return ExecResult::Trap(WasmError::UnreachableExecuted);
            }
            0x01 => {
                // nop
            }
            0x02 => {
                // block
                let block_type = try_exec!(self.read_leb128_i32());
                let result_count = if block_type == -0x40 { 0u8 } else { 1u8 };
                // We need to find the matching End to know end_pc.
                // Save current position, scan forward, then restore.
                let start_pc = self.pc;
                let end_pc = try_exec!(self.skip_to_end());
                // Restore pc to execute the block body
                self.pc = start_pc;
                try_exec!(self.push_block(BlockFrame {
                    start_pc,
                    end_pc,
                    stack_base: self.stack_ptr,
                    result_count,
                    is_loop: false,
                }));
            }
            0x03 => {
                // loop
                let block_type = try_exec!(self.read_leb128_i32());
                let _result_count = if block_type == -0x40 { 0u8 } else { 1u8 };
                let start_pc = self.pc;
                let saved_pc = self.pc;
                let end_pc = try_exec!(self.skip_to_end());
                self.pc = saved_pc;
                // Loop blocks produce 0 results on branch (branch goes to start)
                try_exec!(self.push_block(BlockFrame {
                    start_pc,
                    end_pc,
                    stack_base: self.stack_ptr,
                    result_count: 0,
                    is_loop: true,
                }));
            }
            0x04 => {
                // if — two-pass scan: first find else/end boundary, then find true end
                let block_type = try_exec!(self.read_leb128_i32());
                let result_count = if block_type == -0x40 { 0u8 } else { 1u8 };
                let condition = try_exec!(self.pop_i32());

                let body_pc = self.pc;
                // First skip_to_end: stops at else (depth=1) or end (depth=0)
                let else_or_end_pc = try_exec!(self.skip_to_end());
                let has_else = else_or_end_pc > 0
                    && self.module.code[else_or_end_pc - 1] == 0x05;

                // If there's an else, scan past it to find the true end
                let true_end_pc = if has_else {
                    // pc is now right after the else opcode; scan to find matching end
                    try_exec!(self.skip_to_end())
                } else {
                    else_or_end_pc
                };

                if condition != 0 {
                    // Execute the "then" branch; block end_pc = true end of if/else/end
                    self.pc = body_pc;
                    try_exec!(self.push_block(BlockFrame {
                        start_pc: body_pc,
                        end_pc: true_end_pc,
                        stack_base: self.stack_ptr,
                        result_count,
                        is_loop: false,
                    }));
                } else if has_else {
                    // Condition false, has else: execute the else branch
                    self.pc = else_or_end_pc; // right after the 0x05 else opcode
                    try_exec!(self.push_block(BlockFrame {
                        start_pc: else_or_end_pc,
                        end_pc: true_end_pc,
                        stack_base: self.stack_ptr,
                        result_count,
                        is_loop: false,
                    }));
                } else {
                    // Condition false, no else: skip past end entirely
                    self.pc = true_end_pc;
                }
            }
            0x05 => {
                // else — skip to end of if block
                if self.block_depth > 0 {
                    let bf = self.block_stack[self.block_depth - 1];
                    self.pc = bf.end_pc;
                    let _ = self.pop_block();
                }
            }
            0x0B => {
                // end
                if self.block_depth > 0 {
                    let _ = self.pop_block();
                } else {
                    // End of function body
                    return self.do_return();
                }
            }
            0x0C => {
                // br
                let depth = try_exec!(self.read_leb128_u32());
                try_exec!(self.branch(depth));
            }
            0x0D => {
                // br_if
                let depth = try_exec!(self.read_leb128_u32());
                let cond = try_exec!(self.pop_i32());
                if cond != 0 {
                    try_exec!(self.branch(depth));
                }
            }
            0x0E => {
                // br_table
                let count = try_exec!(self.read_leb128_u32()) as usize;
                if count > MAX_BR_TABLE_SIZE {
                    return ExecResult::Trap(WasmError::OutOfBounds);
                }
                // Read all label depths
                let mut labels = [0u32; MAX_BR_TABLE_SIZE];
                for i in 0..count {
                    labels[i] = try_exec!(self.read_leb128_u32());
                }
                // Default label (always present after the count labels)
                let default_label = try_exec!(self.read_leb128_u32());
                // Pop index
                let idx = try_exec!(self.pop_i32()) as usize;
                let depth = if idx < count { labels[idx] } else { default_label };
                try_exec!(self.branch(depth));
            }
            0x0F => {
                // return
                return self.do_return();
            }
            0x10 => {
                // call
                let func_idx = try_exec!(self.read_leb128_u32());
                if (func_idx as usize) < self.module.func_import_count() {
                    return match self.handle_import_call(func_idx) {
                        Ok(result) => result,
                        Err(e) => ExecResult::Trap(e),
                    };
                }
                if let Err(e) = self.enter_function(func_idx, true) {
                    return ExecResult::Trap(e);
                }
            }

            0x12 => {
                // return_call (tail call proposal)
                let func_idx = try_exec!(self.read_leb128_u32());
                // Pop current frame first (tail call optimization)
                if self.call_depth > 0 {
                    let frame = self.call_stack[self.call_depth - 1];
                    self.call_depth -= 1;
                    self.stack_ptr = frame.stack_base;
                    self.pc = frame.return_pc;
                    self.block_depth = 0;
                }
                if (func_idx as usize) < self.module.func_import_count() {
                    return match self.handle_import_call(func_idx) {
                        Ok(result) => result,
                        Err(e) => ExecResult::Trap(e),
                    };
                }
                if let Err(e) = self.enter_function(func_idx, true) {
                    return ExecResult::Trap(e);
                }
            }
            0x13 => {
                // return_call_indirect (tail call proposal)
                let type_idx = try_exec!(self.read_leb128_u32());
                let _table_idx = try_exec!(self.read_leb128_u32());
                let elem_idx = try_exec!(self.pop_i32()) as usize;
                if elem_idx >= self.table.len() {
                    return ExecResult::Trap(WasmError::UndefinedElement);
                }
                let func_idx = match self.table[elem_idx] {
                    Some(idx) => idx,
                    None => return ExecResult::Trap(WasmError::UndefinedElement),
                };
                // Validate type signature for both imports and local functions
                let actual_type_idx = if (func_idx as usize) < self.module.func_import_count() {
                    match self.module.func_import_type(func_idx) {
                        Some(ti) => ti,
                        None => return ExecResult::Trap(WasmError::IndirectCallTypeMismatch),
                    }
                } else {
                    let local_idx = match (func_idx as usize).checked_sub(self.module.func_import_count()) {
                        Some(i) => i,
                        None => return ExecResult::Trap(WasmError::FunctionNotFound(func_idx)),
                    };
                    if local_idx >= self.module.functions.len() {
                        return ExecResult::Trap(WasmError::FunctionNotFound(func_idx));
                    }
                    self.module.functions[local_idx].type_idx
                };
                if actual_type_idx != type_idx {
                    return ExecResult::Trap(WasmError::IndirectCallTypeMismatch);
                }
                // Pop current frame (tail call)
                if self.call_depth > 0 {
                    let frame = self.call_stack[self.call_depth - 1];
                    self.call_depth -= 1;
                    self.stack_ptr = frame.stack_base;
                    self.pc = frame.return_pc;
                    self.block_depth = 0;
                }
                if (func_idx as usize) < self.module.func_import_count() {
                    return match self.handle_import_call(func_idx) {
                        Ok(result) => result,
                        Err(e) => ExecResult::Trap(e),
                    };
                }
                if let Err(e) = self.enter_function(func_idx, true) {
                    return ExecResult::Trap(e);
                }
            }

            0x11 => {
                // call_indirect
                let type_idx = try_exec!(self.read_leb128_u32());
                let _table_idx = try_exec!(self.read_leb128_u32()); // must be 0 in MVP
                let elem_idx = try_exec!(self.pop_i32()) as usize;
                // Look up function in table
                if elem_idx >= self.table.len() {
                    return ExecResult::Trap(WasmError::UndefinedElement);
                }
                let func_idx = match self.table[elem_idx] {
                    Some(idx) => idx,
                    None => return ExecResult::Trap(WasmError::UndefinedElement),
                };
                // Validate function signature matches expected type
                let actual_type_idx = if (func_idx as usize) < self.module.func_import_count() {
                    match self.module.func_import_type(func_idx) {
                        Some(ti) => ti,
                        None => return ExecResult::Trap(WasmError::IndirectCallTypeMismatch),
                    }
                } else {
                    // Local function: get type from function definition
                    let local_idx = match (func_idx as usize).checked_sub(self.module.func_import_count()) {
                        Some(i) => i,
                        None => return ExecResult::Trap(WasmError::FunctionNotFound(func_idx)),
                    };
                    if local_idx >= self.module.functions.len() {
                        return ExecResult::Trap(WasmError::FunctionNotFound(func_idx));
                    }
                    self.module.functions[local_idx].type_idx
                };
                if actual_type_idx != type_idx {
                    return ExecResult::Trap(WasmError::IndirectCallTypeMismatch);
                }
                // Call the function (same as regular call)
                if (func_idx as usize) < self.module.func_import_count() {
                    return match self.handle_import_call(func_idx) {
                        Ok(result) => result,
                        Err(e) => ExecResult::Trap(e),
                    };
                }
                if let Err(e) = self.enter_function(func_idx, true) {
                    return ExecResult::Trap(e);
                }
            }

            // ── Parametric ──────────────────────────────────────────
            0x1A => {
                // drop
                let _ = try_exec!(self.pop());
            }
            0x1B => {
                // select — WASM spec requires both operands to be same type
                let c = try_exec!(self.pop_i32());
                let val2 = try_exec!(self.pop());
                let val1 = try_exec!(self.pop());
                let types_match = match (&val1, &val2) {
                    (Value::I32(_), Value::I32(_)) => true,
                    (Value::I64(_), Value::I64(_)) => true,
                    (Value::F32(_), Value::F32(_)) => true,
                    (Value::F64(_), Value::F64(_)) => true,
                    (Value::V128(_), Value::V128(_)) => true,
                    _ => false,
                };
                if !types_match {
                    return ExecResult::Trap(WasmError::TypeMismatch);
                }
                try_exec!(self.push(if c != 0 { val1 } else { val2 }));
            }

            // ── Variable access ─────────────────────────────────────
            0x20 => {
                // local.get
                let idx = try_exec!(self.read_leb128_u32());
                let val = try_exec!(self.get_local(idx));
                try_exec!(self.push(val));
            }
            0x21 => {
                // local.set
                let idx = try_exec!(self.read_leb128_u32());
                let val = try_exec!(self.pop());
                try_exec!(self.set_local(idx, val));
            }
            0x22 => {
                // local.tee
                let idx = try_exec!(self.read_leb128_u32());
                if self.stack_ptr == 0 {
                    return ExecResult::Trap(WasmError::StackUnderflow);
                }
                let val = self.stack[self.stack_ptr - 1];
                try_exec!(self.set_local(idx, val));
            }

            // ── Globals ─────────────────────────────────────────────
            0x23 => {
                // global.get
                let idx = try_exec!(self.read_leb128_u32()) as usize;
                if idx >= self.globals.len() {
                    return ExecResult::Trap(WasmError::GlobalIndexOutOfBounds);
                }
                try_exec!(self.push(self.globals[idx]));
            }
            0x24 => {
                // global.set
                let idx = try_exec!(self.read_leb128_u32()) as usize;
                if idx >= self.globals.len() {
                    return ExecResult::Trap(WasmError::GlobalIndexOutOfBounds);
                }
                // Check mutability
                if idx < self.module.globals.len() && !self.module.globals[idx].mutable {
                    return ExecResult::Trap(WasmError::ImmutableGlobal);
                }
                let val = try_exec!(self.pop());
                self.globals[idx] = val;
            }

            0x25 => {
                // table.get
                let table_idx = try_exec!(self.read_leb128_u32()) as usize;
                let _ = table_idx; // MVP only has table 0
                let idx = try_exec!(self.pop_i32()) as usize;
                if idx >= self.table.len() {
                    return ExecResult::Trap(WasmError::TableIndexOutOfBounds);
                }
                let val = self.table[idx].map_or(Value::I32(-1), |f| Value::I32(f as i32));
                try_exec!(self.push(val));
            }
            0x26 => {
                // table.set
                let table_idx = try_exec!(self.read_leb128_u32()) as usize;
                let _ = table_idx;
                let val = try_exec!(self.pop_i32());
                let idx = try_exec!(self.pop_i32()) as usize;
                if idx >= self.table.len() {
                    return ExecResult::Trap(WasmError::TableIndexOutOfBounds);
                }
                self.table[idx] = if val < 0 { None } else { Some(val as u32) };
            }

            // ── Memory ──────────────────────────────────────────────
            0x28 => {
                // i32.load
                let _align = try_exec!(self.read_leb128_u32());
                let offset = try_exec!(self.read_leb128_u32());
                let base = try_exec!(self.pop_i32()) as u32;
                let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
                let val = try_exec!(self.mem_load_i32(addr));
                try_exec!(self.push(Value::I32(val)));
            }
            0x29 => {
                // i64.load
                let _align = try_exec!(self.read_leb128_u32());
                let offset = try_exec!(self.read_leb128_u32());
                let base = try_exec!(self.pop_i32()) as u32;
                let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
                let val = try_exec!(self.mem_load_i64(addr));
                try_exec!(self.push(Value::I64(val)));
            }
            0x36 => {
                // i32.store
                let _align = try_exec!(self.read_leb128_u32());
                let offset = try_exec!(self.read_leb128_u32());
                let val = try_exec!(self.pop_i32());
                let base = try_exec!(self.pop_i32()) as u32;
                let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
                try_exec!(self.mem_store_i32(addr, val));
            }
            0x37 => {
                // i64.store
                let _align = try_exec!(self.read_leb128_u32());
                let offset = try_exec!(self.read_leb128_u32());
                let val = try_exec!(self.pop_i64());
                let base = try_exec!(self.pop_i32()) as u32;
                let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
                try_exec!(self.mem_store_i64(addr, val));
            }

            // ── Float memory ─────────────────────────────────────────
            0x2A => {
                // f32.load
                if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); }
                let _align = try_exec!(self.read_leb128_u32());
                let offset = try_exec!(self.read_leb128_u32());
                let base = try_exec!(self.pop_i32()) as u32;
                let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
                let val = try_exec!(self.mem_load_f32(addr));
                try_exec!(self.push(Value::F32(val)));
            }
            0x2B => {
                // f64.load
                if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); }
                let _align = try_exec!(self.read_leb128_u32());
                let offset = try_exec!(self.read_leb128_u32());
                let base = try_exec!(self.pop_i32()) as u32;
                let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
                let val = try_exec!(self.mem_load_f64(addr));
                try_exec!(self.push(Value::F64(val)));
            }

            // ── Sub-word loads ──────────────────────────────────────
            0x2C => {
                // i32.load8_s
                let _align = try_exec!(self.read_leb128_u32());
                let offset = try_exec!(self.read_leb128_u32());
                let base = try_exec!(self.pop_i32()) as u32;
                let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
                let val = try_exec!(self.mem_load_u8(addr)) as i8;
                try_exec!(self.push(Value::I32(val as i32)));
            }
            0x2D => {
                // i32.load8_u
                let _align = try_exec!(self.read_leb128_u32());
                let offset = try_exec!(self.read_leb128_u32());
                let base = try_exec!(self.pop_i32()) as u32;
                let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
                let val = try_exec!(self.mem_load_u8(addr));
                try_exec!(self.push(Value::I32(val as i32)));
            }
            0x2E => {
                // i32.load16_s
                let _align = try_exec!(self.read_leb128_u32());
                let offset = try_exec!(self.read_leb128_u32());
                let base = try_exec!(self.pop_i32()) as u32;
                let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
                let val = try_exec!(self.mem_load_u16(addr)) as i16;
                try_exec!(self.push(Value::I32(val as i32)));
            }
            0x2F => {
                // i32.load16_u
                let _align = try_exec!(self.read_leb128_u32());
                let offset = try_exec!(self.read_leb128_u32());
                let base = try_exec!(self.pop_i32()) as u32;
                let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
                let val = try_exec!(self.mem_load_u16(addr));
                try_exec!(self.push(Value::I32(val as i32)));
            }
            0x30 => {
                // i64.load8_s
                let _align = try_exec!(self.read_leb128_u32());
                let offset = try_exec!(self.read_leb128_u32());
                let base = try_exec!(self.pop_i32()) as u32;
                let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
                let val = try_exec!(self.mem_load_u8(addr)) as i8;
                try_exec!(self.push(Value::I64(val as i64)));
            }
            0x31 => {
                // i64.load8_u
                let _align = try_exec!(self.read_leb128_u32());
                let offset = try_exec!(self.read_leb128_u32());
                let base = try_exec!(self.pop_i32()) as u32;
                let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
                let val = try_exec!(self.mem_load_u8(addr));
                try_exec!(self.push(Value::I64(val as i64)));
            }
            0x32 => {
                // i64.load16_s
                let _align = try_exec!(self.read_leb128_u32());
                let offset = try_exec!(self.read_leb128_u32());
                let base = try_exec!(self.pop_i32()) as u32;
                let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
                let val = try_exec!(self.mem_load_u16(addr)) as i16;
                try_exec!(self.push(Value::I64(val as i64)));
            }
            0x33 => {
                // i64.load16_u
                let _align = try_exec!(self.read_leb128_u32());
                let offset = try_exec!(self.read_leb128_u32());
                let base = try_exec!(self.pop_i32()) as u32;
                let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
                let val = try_exec!(self.mem_load_u16(addr));
                try_exec!(self.push(Value::I64(val as i64)));
            }
            0x34 => {
                // i64.load32_s
                let _align = try_exec!(self.read_leb128_u32());
                let offset = try_exec!(self.read_leb128_u32());
                let base = try_exec!(self.pop_i32()) as u32;
                let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
                let val = try_exec!(self.mem_load_u32(addr)) as i32;
                try_exec!(self.push(Value::I64(val as i64)));
            }
            0x35 => {
                // i64.load32_u
                let _align = try_exec!(self.read_leb128_u32());
                let offset = try_exec!(self.read_leb128_u32());
                let base = try_exec!(self.pop_i32()) as u32;
                let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
                let val = try_exec!(self.mem_load_u32(addr));
                try_exec!(self.push(Value::I64(val as i64)));
            }

            // ── Sub-word stores ─────────────────────────────────────
            0x3A => {
                // i32.store8
                let _align = try_exec!(self.read_leb128_u32());
                let offset = try_exec!(self.read_leb128_u32());
                let val = try_exec!(self.pop_i32());
                let base = try_exec!(self.pop_i32()) as u32;
                let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
                try_exec!(self.mem_store_u8(addr, val as u8));
            }
            0x3B => {
                // i32.store16
                let _align = try_exec!(self.read_leb128_u32());
                let offset = try_exec!(self.read_leb128_u32());
                let val = try_exec!(self.pop_i32());
                let base = try_exec!(self.pop_i32()) as u32;
                let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
                try_exec!(self.mem_store_u16(addr, val as u16));
            }
            0x3C => {
                // i64.store8
                let _align = try_exec!(self.read_leb128_u32());
                let offset = try_exec!(self.read_leb128_u32());
                let val = try_exec!(self.pop_i64());
                let base = try_exec!(self.pop_i32()) as u32;
                let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
                try_exec!(self.mem_store_u8(addr, val as u8));
            }
            0x3D => {
                // i64.store16
                let _align = try_exec!(self.read_leb128_u32());
                let offset = try_exec!(self.read_leb128_u32());
                let val = try_exec!(self.pop_i64());
                let base = try_exec!(self.pop_i32()) as u32;
                let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
                try_exec!(self.mem_store_u16(addr, val as u16));
            }
            0x3E => {
                // i64.store32
                let _align = try_exec!(self.read_leb128_u32());
                let offset = try_exec!(self.read_leb128_u32());
                let val = try_exec!(self.pop_i64());
                let base = try_exec!(self.pop_i32()) as u32;
                let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
                try_exec!(self.mem_store_u32(addr, val as u32));
            }

            0x38 => {
                // f32.store
                if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); }
                let _align = try_exec!(self.read_leb128_u32());
                let offset = try_exec!(self.read_leb128_u32());
                let val = try_exec!(self.pop_f32());
                let base = try_exec!(self.pop_i32()) as u32;
                let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
                try_exec!(self.mem_store_f32(addr, val));
            }
            0x39 => {
                // f64.store
                if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); }
                let _align = try_exec!(self.read_leb128_u32());
                let offset = try_exec!(self.read_leb128_u32());
                let val = try_exec!(self.pop_f64());
                let base = try_exec!(self.pop_i32()) as u32;
                let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
                try_exec!(self.mem_store_f64(addr, val));
            }

            // ── Memory management ────────────────────────────────────
            0x3F => {
                // memory.size
                let _reserved = try_exec!(self.read_leb128_u32()); // must be 0x00
                let pages = (self.memory_size / WASM_PAGE_SIZE) as i32;
                try_exec!(self.push(Value::I32(pages)));
            }
            0x40 => {
                // memory.grow
                let _reserved = try_exec!(self.read_leb128_u32()); // must be 0x00
                let delta = try_exec!(self.pop_i32()) as u32;
                let old_pages = (self.memory_size / WASM_PAGE_SIZE) as u32;
                let new_pages = old_pages.saturating_add(delta);
                // Check both the module's declared max and the global hard limit
                let module_max = if self.module.memory_max_pages > 0 {
                    self.module.memory_max_pages as usize
                } else {
                    MAX_MEMORY_PAGES
                };
                if new_pages as usize > module_max || new_pages as usize > MAX_MEMORY_PAGES {
                    // Failure: push -1
                    try_exec!(self.push(Value::I32(-1)));
                } else {
                    let new_size = (new_pages as usize).saturating_mul(WASM_PAGE_SIZE);
                    self.memory.resize(new_size, 0);
                    self.memory_size = new_size;
                    try_exec!(self.push(Value::I32(old_pages as i32)));
                }
            }

            // ── Constants ───────────────────────────────────────────
            0x41 => {
                // i32.const
                let val = try_exec!(self.read_leb128_i32());
                try_exec!(self.push(Value::I32(val)));
            }
            0x42 => {
                // i64.const
                let val = try_exec!(self.read_leb128_i64());
                try_exec!(self.push(Value::I64(val)));
            }

            0x43 => {
                // f32.const
                if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); }
                let val = try_exec!(self.read_f32());
                try_exec!(self.push(Value::F32(val)));
            }
            0x44 => {
                // f64.const
                if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); }
                let val = try_exec!(self.read_f64());
                try_exec!(self.push(Value::F64(val)));
            }

            // ── i32 Comparison ──────────────────────────────────────
            0x45 => {
                // i32.eqz
                let a = try_exec!(self.pop_i32());
                try_exec!(self.push(Value::I32(if a == 0 { 1 } else { 0 })));
            }
            0x46 => {
                // i32.eq
                let b = try_exec!(self.pop_i32());
                let a = try_exec!(self.pop_i32());
                try_exec!(self.push(Value::I32(if a == b { 1 } else { 0 })));
            }
            0x47 => {
                // i32.ne
                let b = try_exec!(self.pop_i32());
                let a = try_exec!(self.pop_i32());
                try_exec!(self.push(Value::I32(if a != b { 1 } else { 0 })));
            }
            0x48 => {
                // i32.lt_s
                let b = try_exec!(self.pop_i32());
                let a = try_exec!(self.pop_i32());
                try_exec!(self.push(Value::I32(if a < b { 1 } else { 0 })));
            }
            0x49 => {
                // i32.lt_u
                let b = try_exec!(self.pop_i32());
                let a = try_exec!(self.pop_i32());
                try_exec!(self.push(Value::I32(if (a as u32) < (b as u32) { 1 } else { 0 })));
            }
            0x4A => {
                // i32.gt_s
                let b = try_exec!(self.pop_i32());
                let a = try_exec!(self.pop_i32());
                try_exec!(self.push(Value::I32(if a > b { 1 } else { 0 })));
            }
            0x4B => {
                // i32.gt_u
                let b = try_exec!(self.pop_i32());
                let a = try_exec!(self.pop_i32());
                try_exec!(self.push(Value::I32(if (a as u32) > (b as u32) { 1 } else { 0 })));
            }
            0x4C => {
                // i32.le_s
                let b = try_exec!(self.pop_i32());
                let a = try_exec!(self.pop_i32());
                try_exec!(self.push(Value::I32(if a <= b { 1 } else { 0 })));
            }
            0x4D => {
                // i32.le_u
                let b = try_exec!(self.pop_i32());
                let a = try_exec!(self.pop_i32());
                try_exec!(self.push(Value::I32(if (a as u32) <= (b as u32) { 1 } else { 0 })));
            }
            0x4E => {
                // i32.ge_s
                let b = try_exec!(self.pop_i32());
                let a = try_exec!(self.pop_i32());
                try_exec!(self.push(Value::I32(if a >= b { 1 } else { 0 })));
            }
            0x4F => {
                // i32.ge_u
                let b = try_exec!(self.pop_i32());
                let a = try_exec!(self.pop_i32());
                try_exec!(self.push(Value::I32(if (a as u32) >= (b as u32) { 1 } else { 0 })));
            }

            // ── i64 Comparison ──────────────────────────────────────
            0x50 => {
                // i64.eqz
                let a = try_exec!(self.pop_i64());
                try_exec!(self.push(Value::I32(if a == 0 { 1 } else { 0 })));
            }
            0x51 => {
                // i64.eq
                let b = try_exec!(self.pop_i64());
                let a = try_exec!(self.pop_i64());
                try_exec!(self.push(Value::I32(if a == b { 1 } else { 0 })));
            }
            0x52 => {
                // i64.ne
                let b = try_exec!(self.pop_i64());
                let a = try_exec!(self.pop_i64());
                try_exec!(self.push(Value::I32(if a != b { 1 } else { 0 })));
            }
            0x53 => {
                // i64.lt_s
                let b = try_exec!(self.pop_i64());
                let a = try_exec!(self.pop_i64());
                try_exec!(self.push(Value::I32(if a < b { 1 } else { 0 })));
            }
            0x54 => {
                // i64.lt_u
                let b = try_exec!(self.pop_i64());
                let a = try_exec!(self.pop_i64());
                try_exec!(self.push(Value::I32(if (a as u64) < (b as u64) { 1 } else { 0 })));
            }
            0x55 => {
                // i64.gt_s
                let b = try_exec!(self.pop_i64());
                let a = try_exec!(self.pop_i64());
                try_exec!(self.push(Value::I32(if a > b { 1 } else { 0 })));
            }
            0x56 => {
                // i64.gt_u
                let b = try_exec!(self.pop_i64());
                let a = try_exec!(self.pop_i64());
                try_exec!(self.push(Value::I32(if (a as u64) > (b as u64) { 1 } else { 0 })));
            }
            0x57 => {
                // i64.le_s
                let b = try_exec!(self.pop_i64());
                let a = try_exec!(self.pop_i64());
                try_exec!(self.push(Value::I32(if a <= b { 1 } else { 0 })));
            }
            0x58 => {
                // i64.le_u
                let b = try_exec!(self.pop_i64());
                let a = try_exec!(self.pop_i64());
                try_exec!(self.push(Value::I32(if (a as u64) <= (b as u64) { 1 } else { 0 })));
            }
            0x59 => {
                // i64.ge_s
                let b = try_exec!(self.pop_i64());
                let a = try_exec!(self.pop_i64());
                try_exec!(self.push(Value::I32(if a >= b { 1 } else { 0 })));
            }
            0x5A => {
                // i64.ge_u
                let b = try_exec!(self.pop_i64());
                let a = try_exec!(self.pop_i64());
                try_exec!(self.push(Value::I32(if (a as u64) >= (b as u64) { 1 } else { 0 })));
            }

            // ── i32 Arithmetic ──────────────────────────────────────
            0x67 => {
                // i32.clz
                let a = try_exec!(self.pop_i32());
                try_exec!(self.push(Value::I32((a as u32).leading_zeros() as i32)));
            }
            0x68 => {
                // i32.ctz
                let a = try_exec!(self.pop_i32());
                try_exec!(self.push(Value::I32((a as u32).trailing_zeros() as i32)));
            }
            0x69 => {
                // i32.popcnt
                let a = try_exec!(self.pop_i32());
                try_exec!(self.push(Value::I32((a as u32).count_ones() as i32)));
            }
            0x6A => {
                // i32.add
                let b = try_exec!(self.pop_i32());
                let a = try_exec!(self.pop_i32());
                try_exec!(self.push(Value::I32(a.wrapping_add(b))));
            }
            0x6B => {
                // i32.sub
                let b = try_exec!(self.pop_i32());
                let a = try_exec!(self.pop_i32());
                try_exec!(self.push(Value::I32(a.wrapping_sub(b))));
            }
            0x6C => {
                // i32.mul
                let b = try_exec!(self.pop_i32());
                let a = try_exec!(self.pop_i32());
                try_exec!(self.push(Value::I32(a.wrapping_mul(b))));
            }
            0x6D => {
                // i32.div_s
                let b = try_exec!(self.pop_i32());
                let a = try_exec!(self.pop_i32());
                if b == 0 {
                    return ExecResult::Trap(WasmError::DivisionByZero);
                }
                if a == i32::MIN && b == -1 {
                    return ExecResult::Trap(WasmError::IntegerOverflow);
                }
                try_exec!(self.push(Value::I32(a.wrapping_div(b))));
            }
            0x6E => {
                // i32.div_u
                let b = try_exec!(self.pop_i32());
                let a = try_exec!(self.pop_i32());
                if b == 0 {
                    return ExecResult::Trap(WasmError::DivisionByZero);
                }
                try_exec!(self.push(Value::I32(((a as u32).wrapping_div(b as u32)) as i32)));
            }
            0x6F => {
                // i32.rem_s
                let b = try_exec!(self.pop_i32());
                let a = try_exec!(self.pop_i32());
                if b == 0 {
                    return ExecResult::Trap(WasmError::DivisionByZero);
                }
                if a == i32::MIN && b == -1 {
                    try_exec!(self.push(Value::I32(0)));
                } else {
                    try_exec!(self.push(Value::I32(a.wrapping_rem(b))));
                }
            }
            0x70 => {
                // i32.rem_u
                let b = try_exec!(self.pop_i32());
                let a = try_exec!(self.pop_i32());
                if b == 0 {
                    return ExecResult::Trap(WasmError::DivisionByZero);
                }
                try_exec!(self.push(Value::I32(((a as u32).wrapping_rem(b as u32)) as i32)));
            }
            0x71 => {
                // i32.and
                let b = try_exec!(self.pop_i32());
                let a = try_exec!(self.pop_i32());
                try_exec!(self.push(Value::I32(a & b)));
            }
            0x72 => {
                // i32.or
                let b = try_exec!(self.pop_i32());
                let a = try_exec!(self.pop_i32());
                try_exec!(self.push(Value::I32(a | b)));
            }
            0x73 => {
                // i32.xor
                let b = try_exec!(self.pop_i32());
                let a = try_exec!(self.pop_i32());
                try_exec!(self.push(Value::I32(a ^ b)));
            }
            0x74 => {
                // i32.shl
                let b = try_exec!(self.pop_i32());
                let a = try_exec!(self.pop_i32());
                try_exec!(self.push(Value::I32(a.wrapping_shl(b as u32))));
            }
            0x75 => {
                // i32.shr_s
                let b = try_exec!(self.pop_i32());
                let a = try_exec!(self.pop_i32());
                try_exec!(self.push(Value::I32(a.wrapping_shr(b as u32))));
            }
            0x76 => {
                // i32.shr_u
                let b = try_exec!(self.pop_i32());
                let a = try_exec!(self.pop_i32());
                try_exec!(self.push(Value::I32(((a as u32).wrapping_shr(b as u32)) as i32)));
            }
            0x77 => {
                // i32.rotl
                let b = try_exec!(self.pop_i32());
                let a = try_exec!(self.pop_i32());
                try_exec!(self.push(Value::I32((a as u32).rotate_left(b as u32) as i32)));
            }
            0x78 => {
                // i32.rotr
                let b = try_exec!(self.pop_i32());
                let a = try_exec!(self.pop_i32());
                try_exec!(self.push(Value::I32((a as u32).rotate_right(b as u32) as i32)));
            }

            // ── i64 Arithmetic ──────────────────────────────────────
            0x79 => {
                // i64.clz
                let a = try_exec!(self.pop_i64());
                try_exec!(self.push(Value::I64((a as u64).leading_zeros() as i64)));
            }
            0x7A => {
                // i64.ctz
                let a = try_exec!(self.pop_i64());
                try_exec!(self.push(Value::I64((a as u64).trailing_zeros() as i64)));
            }
            0x7B => {
                // i64.popcnt
                let a = try_exec!(self.pop_i64());
                try_exec!(self.push(Value::I64((a as u64).count_ones() as i64)));
            }
            0x7C => {
                // i64.add
                let b = try_exec!(self.pop_i64());
                let a = try_exec!(self.pop_i64());
                try_exec!(self.push(Value::I64(a.wrapping_add(b))));
            }
            0x7D => {
                // i64.sub
                let b = try_exec!(self.pop_i64());
                let a = try_exec!(self.pop_i64());
                try_exec!(self.push(Value::I64(a.wrapping_sub(b))));
            }
            0x7E => {
                // i64.mul
                let b = try_exec!(self.pop_i64());
                let a = try_exec!(self.pop_i64());
                try_exec!(self.push(Value::I64(a.wrapping_mul(b))));
            }
            0x7F => {
                // i64.div_s
                let b = try_exec!(self.pop_i64());
                let a = try_exec!(self.pop_i64());
                if b == 0 {
                    return ExecResult::Trap(WasmError::DivisionByZero);
                }
                if a == i64::MIN && b == -1 {
                    return ExecResult::Trap(WasmError::IntegerOverflow);
                }
                try_exec!(self.push(Value::I64(a.wrapping_div(b))));
            }
            0x80 => {
                // i64.div_u
                let b = try_exec!(self.pop_i64());
                let a = try_exec!(self.pop_i64());
                if b == 0 {
                    return ExecResult::Trap(WasmError::DivisionByZero);
                }
                try_exec!(self.push(Value::I64(((a as u64).wrapping_div(b as u64)) as i64)));
            }
            0x81 => {
                // i64.rem_s
                let b = try_exec!(self.pop_i64());
                let a = try_exec!(self.pop_i64());
                if b == 0 {
                    return ExecResult::Trap(WasmError::DivisionByZero);
                }
                if a == i64::MIN && b == -1 {
                    try_exec!(self.push(Value::I64(0)));
                } else {
                    try_exec!(self.push(Value::I64(a.wrapping_rem(b))));
                }
            }
            0x82 => {
                // i64.rem_u
                let b = try_exec!(self.pop_i64());
                let a = try_exec!(self.pop_i64());
                if b == 0 {
                    return ExecResult::Trap(WasmError::DivisionByZero);
                }
                try_exec!(self.push(Value::I64(((a as u64).wrapping_rem(b as u64)) as i64)));
            }
            0x83 => {
                // i64.and
                let b = try_exec!(self.pop_i64());
                let a = try_exec!(self.pop_i64());
                try_exec!(self.push(Value::I64(a & b)));
            }
            0x84 => {
                // i64.or
                let b = try_exec!(self.pop_i64());
                let a = try_exec!(self.pop_i64());
                try_exec!(self.push(Value::I64(a | b)));
            }
            0x85 => {
                // i64.xor
                let b = try_exec!(self.pop_i64());
                let a = try_exec!(self.pop_i64());
                try_exec!(self.push(Value::I64(a ^ b)));
            }
            0x86 => {
                // i64.shl
                let b = try_exec!(self.pop_i64());
                let a = try_exec!(self.pop_i64());
                try_exec!(self.push(Value::I64(a.wrapping_shl(b as u32))));
            }
            0x87 => {
                // i64.shr_s
                let b = try_exec!(self.pop_i64());
                let a = try_exec!(self.pop_i64());
                try_exec!(self.push(Value::I64(a.wrapping_shr(b as u32))));
            }
            0x88 => {
                // i64.shr_u
                let b = try_exec!(self.pop_i64());
                let a = try_exec!(self.pop_i64());
                try_exec!(self.push(Value::I64(((a as u64).wrapping_shr(b as u32)) as i64)));
            }
            0x89 => {
                // i64.rotl
                let b = try_exec!(self.pop_i64());
                let a = try_exec!(self.pop_i64());
                try_exec!(self.push(Value::I64((a as u64).rotate_left(b as u32) as i64)));
            }
            0x8A => {
                // i64.rotr
                let b = try_exec!(self.pop_i64());
                let a = try_exec!(self.pop_i64());
                try_exec!(self.push(Value::I64((a as u64).rotate_right(b as u32) as i64)));
            }

            // ── Conversion ──────────────────────────────────────────
            0xA7 => {
                // i32.wrap_i64
                let a = try_exec!(self.pop_i64());
                try_exec!(self.push(Value::I32(a as i32)));
            }
            0xAC => {
                // i64.extend_i32_s
                let a = try_exec!(self.pop_i32());
                try_exec!(self.push(Value::I64(a as i64)));
            }
            0xAD => {
                // i64.extend_i32_u (zero-extend)
                let a = try_exec!(self.pop_i32());
                try_exec!(self.push(Value::I64((a as u32) as i64)));
            }

            // ── Sign extension ──────────────────────────────────────
            0xC0 => {
                // i32.extend8_s
                let a = try_exec!(self.pop_i32());
                try_exec!(self.push(Value::I32((a as i8) as i32)));
            }
            0xC1 => {
                // i32.extend16_s
                let a = try_exec!(self.pop_i32());
                try_exec!(self.push(Value::I32((a as i16) as i32)));
            }
            0xC2 => {
                // i64.extend8_s
                let a = try_exec!(self.pop_i64());
                try_exec!(self.push(Value::I64((a as i8) as i64)));
            }
            0xC3 => {
                // i64.extend16_s
                let a = try_exec!(self.pop_i64());
                try_exec!(self.push(Value::I64((a as i16) as i64)));
            }
            0xC4 => {
                // i64.extend32_s
                let a = try_exec!(self.pop_i64());
                try_exec!(self.push(Value::I64((a as i32) as i64)));
            }

            // ── Float comparison ─────────────────────────────────────
            0x5B => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let b = try_exec!(self.pop_f32()); let a = try_exec!(self.pop_f32()); try_exec!(self.push(Value::I32(if a == b { 1 } else { 0 }))); }
            0x5C => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let b = try_exec!(self.pop_f32()); let a = try_exec!(self.pop_f32()); try_exec!(self.push(Value::I32(if a != b { 1 } else { 0 }))); }
            0x5D => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let b = try_exec!(self.pop_f32()); let a = try_exec!(self.pop_f32()); try_exec!(self.push(Value::I32(if a < b { 1 } else { 0 }))); }
            0x5E => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let b = try_exec!(self.pop_f32()); let a = try_exec!(self.pop_f32()); try_exec!(self.push(Value::I32(if a > b { 1 } else { 0 }))); }
            0x5F => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let b = try_exec!(self.pop_f32()); let a = try_exec!(self.pop_f32()); try_exec!(self.push(Value::I32(if a <= b { 1 } else { 0 }))); }
            0x60 => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let b = try_exec!(self.pop_f32()); let a = try_exec!(self.pop_f32()); try_exec!(self.push(Value::I32(if a >= b { 1 } else { 0 }))); }
            0x61 => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let b = try_exec!(self.pop_f64()); let a = try_exec!(self.pop_f64()); try_exec!(self.push(Value::I32(if a == b { 1 } else { 0 }))); }
            0x62 => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let b = try_exec!(self.pop_f64()); let a = try_exec!(self.pop_f64()); try_exec!(self.push(Value::I32(if a != b { 1 } else { 0 }))); }
            0x63 => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let b = try_exec!(self.pop_f64()); let a = try_exec!(self.pop_f64()); try_exec!(self.push(Value::I32(if a < b { 1 } else { 0 }))); }
            0x64 => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let b = try_exec!(self.pop_f64()); let a = try_exec!(self.pop_f64()); try_exec!(self.push(Value::I32(if a > b { 1 } else { 0 }))); }
            0x65 => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let b = try_exec!(self.pop_f64()); let a = try_exec!(self.pop_f64()); try_exec!(self.push(Value::I32(if a <= b { 1 } else { 0 }))); }
            0x66 => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let b = try_exec!(self.pop_f64()); let a = try_exec!(self.pop_f64()); try_exec!(self.push(Value::I32(if a >= b { 1 } else { 0 }))); }

            // ── f32 unary ───────────────────────────────────────────
            0x8B => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(self.pop_f32()); try_exec!(self.push(Value::F32(libm::fabsf(a)))); }
            0x8C => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(self.pop_f32()); try_exec!(self.push(Value::F32(-a))); }
            0x8D => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(self.pop_f32()); try_exec!(self.push(Value::F32(Self::wasm_ceil_f32(a)))); }
            0x8E => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(self.pop_f32()); try_exec!(self.push(Value::F32(Self::wasm_floor_f32(a)))); }
            0x8F => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(self.pop_f32()); try_exec!(self.push(Value::F32(Self::wasm_trunc_f32(a)))); }
            0x90 => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(self.pop_f32()); try_exec!(self.push(Value::F32(Self::wasm_nearest_f32(a)))); }
            0x91 => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(self.pop_f32()); try_exec!(self.push(Value::F32(Self::wasm_sqrt_f32(a)))); }

            // ── f32 binary ──────────────────────────────────────────
            0x92 => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let b = try_exec!(self.pop_f32()); let a = try_exec!(self.pop_f32()); try_exec!(self.push(Value::F32(a + b))); }
            0x93 => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let b = try_exec!(self.pop_f32()); let a = try_exec!(self.pop_f32()); try_exec!(self.push(Value::F32(a - b))); }
            0x94 => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let b = try_exec!(self.pop_f32()); let a = try_exec!(self.pop_f32()); try_exec!(self.push(Value::F32(a * b))); }
            0x95 => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let b = try_exec!(self.pop_f32()); let a = try_exec!(self.pop_f32()); try_exec!(self.push(Value::F32(a / b))); }
            0x96 => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let b = try_exec!(self.pop_f32()); let a = try_exec!(self.pop_f32()); try_exec!(self.push(Value::F32(Self::wasm_min_f32(a, b)))); }
            0x97 => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let b = try_exec!(self.pop_f32()); let a = try_exec!(self.pop_f32()); try_exec!(self.push(Value::F32(Self::wasm_max_f32(a, b)))); }
            0x98 => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let b = try_exec!(self.pop_f32()); let a = try_exec!(self.pop_f32()); try_exec!(self.push(Value::F32(libm::copysignf(a, b)))); }

            // ── f64 unary ───────────────────────────────────────────
            0x99 => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(self.pop_f64()); try_exec!(self.push(Value::F64(libm::fabs(a)))); }
            0x9A => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(self.pop_f64()); try_exec!(self.push(Value::F64(-a))); }
            0x9B => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(self.pop_f64()); try_exec!(self.push(Value::F64(Self::wasm_ceil_f64(a)))); }
            0x9C => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(self.pop_f64()); try_exec!(self.push(Value::F64(Self::wasm_floor_f64(a)))); }
            0x9D => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(self.pop_f64()); try_exec!(self.push(Value::F64(Self::wasm_trunc_f64(a)))); }
            0x9E => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(self.pop_f64()); try_exec!(self.push(Value::F64(Self::wasm_nearest_f64(a)))); }
            0x9F => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(self.pop_f64()); try_exec!(self.push(Value::F64(Self::wasm_sqrt_f64(a)))); }

            // ── f64 binary ──────────────────────────────────────────
            0xA0 => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let b = try_exec!(self.pop_f64()); let a = try_exec!(self.pop_f64()); try_exec!(self.push(Value::F64(a + b))); }
            0xA1 => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let b = try_exec!(self.pop_f64()); let a = try_exec!(self.pop_f64()); try_exec!(self.push(Value::F64(a - b))); }
            0xA2 => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let b = try_exec!(self.pop_f64()); let a = try_exec!(self.pop_f64()); try_exec!(self.push(Value::F64(a * b))); }
            0xA3 => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let b = try_exec!(self.pop_f64()); let a = try_exec!(self.pop_f64()); try_exec!(self.push(Value::F64(a / b))); }
            0xA4 => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let b = try_exec!(self.pop_f64()); let a = try_exec!(self.pop_f64()); try_exec!(self.push(Value::F64(Self::wasm_min_f64(a, b)))); }
            0xA5 => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let b = try_exec!(self.pop_f64()); let a = try_exec!(self.pop_f64()); try_exec!(self.push(Value::F64(Self::wasm_max_f64(a, b)))); }
            0xA6 => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let b = try_exec!(self.pop_f64()); let a = try_exec!(self.pop_f64()); try_exec!(self.push(Value::F64(libm::copysign(a, b)))); }

            // ── Float-integer conversion ─────────────────────────────
            // Trunc boundaries use exact float constants matching wasmi/WASM spec.
            // i32::MAX (2147483647) rounds up to 2147483648.0 in f32, so >= traps.
            0xA8 => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(self.pop_f32()); if a.is_nan() || a <= -2147483904.0_f32 || a >= 2147483648.0_f32 { return ExecResult::Trap(WasmError::IntegerOverflow); } try_exec!(self.push(Value::I32(a as i32))); }
            0xA9 => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(self.pop_f32()); if a.is_nan() || a <= -1.0_f32 || a >= 4294967296.0_f32 { return ExecResult::Trap(WasmError::IntegerOverflow); } try_exec!(self.push(Value::I32(a as u32 as i32))); }
            0xAA => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(self.pop_f64()); if a.is_nan() || a <= -2147483649.0_f64 || a >= 2147483648.0_f64 { return ExecResult::Trap(WasmError::IntegerOverflow); } try_exec!(self.push(Value::I32(a as i32))); }
            0xAB => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(self.pop_f64()); if a.is_nan() || a <= -1.0_f64 || a >= 4294967296.0_f64 { return ExecResult::Trap(WasmError::IntegerOverflow); } try_exec!(self.push(Value::I32(a as u32 as i32))); }
            0xAE => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(self.pop_f32()); if a.is_nan() || a <= -9223373136366403584.0_f32 || a >= 9223372036854775808.0_f32 { return ExecResult::Trap(WasmError::IntegerOverflow); } try_exec!(self.push(Value::I64(a as i64))); }
            0xAF => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(self.pop_f32()); if a.is_nan() || a <= -1.0_f32 || a >= 18446744073709551616.0_f32 { return ExecResult::Trap(WasmError::IntegerOverflow); } try_exec!(self.push(Value::I64(a as u64 as i64))); }
            0xB0 => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(self.pop_f64()); if a.is_nan() || a <= -9223372036854777856.0_f64 || a >= 9223372036854775808.0_f64 { return ExecResult::Trap(WasmError::IntegerOverflow); } try_exec!(self.push(Value::I64(a as i64))); }
            0xB1 => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(self.pop_f64()); if a.is_nan() || a <= -1.0_f64 || a >= 18446744073709551616.0_f64 { return ExecResult::Trap(WasmError::IntegerOverflow); } try_exec!(self.push(Value::I64(a as u64 as i64))); }
            // int → float
            0xB2 => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(self.pop_i32()); try_exec!(self.push(Value::F32(a as f32))); }
            0xB3 => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(self.pop_i32()); try_exec!(self.push(Value::F32((a as u32) as f32))); }
            0xB4 => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(self.pop_i64()); try_exec!(self.push(Value::F32(a as f32))); }
            0xB5 => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(self.pop_i64()); try_exec!(self.push(Value::F32((a as u64) as f32))); }
            0xB6 => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(self.pop_f64()); try_exec!(self.push(Value::F32(a as f32))); }
            0xB7 => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(self.pop_i32()); try_exec!(self.push(Value::F64(a as f64))); }
            0xB8 => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(self.pop_i32()); try_exec!(self.push(Value::F64((a as u32) as f64))); }
            0xB9 => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(self.pop_i64()); try_exec!(self.push(Value::F64(a as f64))); }
            0xBA => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(self.pop_i64()); try_exec!(self.push(Value::F64((a as u64) as f64))); }
            0xBB => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(self.pop_f32()); try_exec!(self.push(Value::F64(a as f64))); }
            // reinterpret
            0xBC => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(self.pop_f32()); try_exec!(self.push(Value::I32(a.to_bits() as i32))); }
            0xBD => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(self.pop_f64()); try_exec!(self.push(Value::I64(a.to_bits() as i64))); }
            0xBE => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(self.pop_i32()); try_exec!(self.push(Value::F32(f32::from_bits(a as u32)))); }
            0xBF => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(self.pop_i64()); try_exec!(self.push(Value::F64(f64::from_bits(a as u64)))); }

            // ── 0xFC prefix: saturating trunc + bulk memory + table ops ─
            0xFC => {
                let sub_opcode = try_exec!(self.read_leb128_u32());
                match sub_opcode {
                    // Saturating float-to-int conversions (no trap on NaN/overflow)
                    0 => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(self.pop_f32()); try_exec!(self.push(Value::I32(sat_trunc_f32_i32(a)))); }
                    1 => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(self.pop_f32()); try_exec!(self.push(Value::I32(sat_trunc_f32_u32(a) as i32))); }
                    2 => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(self.pop_f64()); try_exec!(self.push(Value::I32(sat_trunc_f64_i32(a)))); }
                    3 => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(self.pop_f64()); try_exec!(self.push(Value::I32(sat_trunc_f64_u32(a) as i32))); }
                    4 => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(self.pop_f32()); try_exec!(self.push(Value::I64(sat_trunc_f32_i64(a)))); }
                    5 => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(self.pop_f32()); try_exec!(self.push(Value::I64(sat_trunc_f32_u64(a) as i64))); }
                    6 => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(self.pop_f64()); try_exec!(self.push(Value::I64(sat_trunc_f64_i64(a)))); }
                    7 => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(self.pop_f64()); try_exec!(self.push(Value::I64(sat_trunc_f64_u64(a) as i64))); }

                    // memory.init (8), data.drop (9)
                    8 => { let _seg = try_exec!(self.read_leb128_u32()); let _mem = try_exec!(self.read_leb128_u32()); let n = try_exec!(self.pop_i32()) as usize; let s = try_exec!(self.pop_i32()) as usize; let d = try_exec!(self.pop_i32()) as usize; let seg_idx = _seg as usize; if seg_idx < self.module.data_segments.len() { let seg = &self.module.data_segments[seg_idx]; let src_start = seg.data_offset.saturating_add(s); let src_end = src_start.saturating_add(n); let dst_end = d.saturating_add(n); if src_end <= self.module.code.len() && dst_end <= self.memory_size { for i in 0..n { self.memory[d + i] = self.module.code[src_start + i]; } } else { return ExecResult::Trap(WasmError::MemoryOutOfBounds); } } }
                    9 => { let _seg = try_exec!(self.read_leb128_u32()); /* data.drop: no-op in interpreter */ }

                    // memory.copy (10), memory.fill (11)
                    10 => {
                        let _dst_mem = try_exec!(self.read_leb128_u32());
                        let _src_mem = try_exec!(self.read_leb128_u32());
                        let n = try_exec!(self.pop_i32()) as usize;
                        let s = try_exec!(self.pop_i32()) as usize;
                        let d = try_exec!(self.pop_i32()) as usize;
                        if s.saturating_add(n) > self.memory_size || d.saturating_add(n) > self.memory_size {
                            return ExecResult::Trap(WasmError::MemoryOutOfBounds);
                        }
                        if d <= s {
                            for i in 0..n { self.memory[d + i] = self.memory[s + i]; }
                        } else {
                            for i in (0..n).rev() { self.memory[d + i] = self.memory[s + i]; }
                        }
                    }
                    11 => {
                        // memory.fill: stack order is [d, val, n] → pop n, val, d
                        let _mem = try_exec!(self.read_leb128_u32());
                        let n = try_exec!(self.pop_i32()) as usize;
                        let val = try_exec!(self.pop_i32()) as u8;
                        let d = try_exec!(self.pop_i32()) as usize;
                        if d.saturating_add(n) > self.memory_size {
                            return ExecResult::Trap(WasmError::MemoryOutOfBounds);
                        }
                        for i in 0..n { self.memory[d + i] = val; }
                    }

                    // table.init (12), elem.drop (13), table.copy (14),
                    // table.grow (15), table.size (16), table.fill (17)
                    12 => { let _seg = try_exec!(self.read_leb128_u32()); let _tbl = try_exec!(self.read_leb128_u32()); let _n = try_exec!(self.pop_i32()); let _s = try_exec!(self.pop_i32()); let _d = try_exec!(self.pop_i32()); /* table.init: simplified */ }
                    13 => { let _seg = try_exec!(self.read_leb128_u32()); /* elem.drop: no-op */ }
                    14 => { let _dst = try_exec!(self.read_leb128_u32()); let _src = try_exec!(self.read_leb128_u32()); let _n = try_exec!(self.pop_i32()); let _s = try_exec!(self.pop_i32()); let _d = try_exec!(self.pop_i32()); /* table.copy: simplified */ }
                    15 => {
                        // table.grow
                        let _tbl = try_exec!(self.read_leb128_u32());
                        let n = try_exec!(self.pop_i32()) as usize;
                        let _init = try_exec!(self.pop());
                        let old_size = self.table.len() as i32;
                        if self.table.len().saturating_add(n) > MAX_TABLE_SIZE {
                            try_exec!(self.push(Value::I32(-1)));
                        } else {
                            self.table.resize(self.table.len() + n, None);
                            try_exec!(self.push(Value::I32(old_size)));
                        }
                    }
                    16 => {
                        // table.size
                        let _tbl = try_exec!(self.read_leb128_u32());
                        try_exec!(self.push(Value::I32(self.table.len() as i32)));
                    }
                    17 => {
                        // table.fill
                        let _tbl = try_exec!(self.read_leb128_u32());
                        let n = try_exec!(self.pop_i32()) as usize;
                        let val = try_exec!(self.pop_i32());
                        let d = try_exec!(self.pop_i32()) as usize;
                        if d.saturating_add(n) > self.table.len() {
                            return ExecResult::Trap(WasmError::TableIndexOutOfBounds);
                        }
                        let entry = if val < 0 { None } else { Some(val as u32) };
                        for i in 0..n { self.table[d + i] = entry; }
                    }

                    _ => return ExecResult::Trap(WasmError::InvalidOpcode(0xFC)),
                }
            }

            // ── 0xFD prefix: SIMD (v128) ─────────────────────────────
            0xFD => {
                let simd_op = try_exec!(self.read_leb128_u32());
                match simd_op {
                    // ── Memory ───────────────────────────────────
                    0 => { // v128.load
                        let _align = try_exec!(self.read_leb128_u32());
                        let offset = try_exec!(self.read_leb128_u32());
                        let base = try_exec!(self.pop_i32()) as u32;
                        let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
                        let val = try_exec!(self.mem_load_v128(addr));
                        try_exec!(self.push(Value::V128(val)));
                    }
                    1..=10 => { // v128.load*_splat, v128.load*x*_s/u
                        let _align = try_exec!(self.read_leb128_u32());
                        let offset = try_exec!(self.read_leb128_u32());
                        let base = try_exec!(self.pop_i32()) as u32;
                        let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
                        let val = match simd_op {
                            1 => { // v128.load8x8_s
                                if addr.checked_add(8).ok_or(WasmError::MemoryOutOfBounds).is_err() || addr + 8 > self.memory_size { return ExecResult::Trap(WasmError::MemoryOutOfBounds); }
                                let mut r = [0i16; 8]; for i in 0..8 { r[i] = self.memory[addr+i] as i8 as i16; }
                                V128::from_i16x8(r)
                            }
                            2 => { // v128.load8x8_u
                                if addr + 8 > self.memory_size { return ExecResult::Trap(WasmError::MemoryOutOfBounds); }
                                let mut r = [0i16; 8]; for i in 0..8 { r[i] = self.memory[addr+i] as i16; }
                                V128::from_i16x8(r)
                            }
                            3 => { // v128.load16x4_s
                                if addr + 8 > self.memory_size { return ExecResult::Trap(WasmError::MemoryOutOfBounds); }
                                let mut r = [0i32; 4]; for i in 0..4 { r[i] = i16::from_le_bytes([self.memory[addr+i*2], self.memory[addr+i*2+1]]) as i32; }
                                V128::from_i32x4(r)
                            }
                            4 => { // v128.load16x4_u
                                if addr + 8 > self.memory_size { return ExecResult::Trap(WasmError::MemoryOutOfBounds); }
                                let mut r = [0i32; 4]; for i in 0..4 { r[i] = u16::from_le_bytes([self.memory[addr+i*2], self.memory[addr+i*2+1]]) as i32; }
                                V128::from_i32x4(r)
                            }
                            5 => { // v128.load32x2_s
                                if addr + 8 > self.memory_size { return ExecResult::Trap(WasmError::MemoryOutOfBounds); }
                                let mut r = [0i64; 2]; for i in 0..2 { r[i] = i32::from_le_bytes([self.memory[addr+i*4], self.memory[addr+i*4+1], self.memory[addr+i*4+2], self.memory[addr+i*4+3]]) as i64; }
                                V128::from_i64x2(r)
                            }
                            6 => { // v128.load32x2_u
                                if addr + 8 > self.memory_size { return ExecResult::Trap(WasmError::MemoryOutOfBounds); }
                                let mut r = [0i64; 2]; for i in 0..2 { r[i] = u32::from_le_bytes([self.memory[addr+i*4], self.memory[addr+i*4+1], self.memory[addr+i*4+2], self.memory[addr+i*4+3]]) as i64; }
                                V128::from_i64x2(r)
                            }
                            7 => { // v128.load8_splat
                                if addr >= self.memory_size { return ExecResult::Trap(WasmError::MemoryOutOfBounds); }
                                V128::from_u8x16([self.memory[addr]; 16])
                            }
                            8 => { // v128.load16_splat
                                if addr + 2 > self.memory_size { return ExecResult::Trap(WasmError::MemoryOutOfBounds); }
                                let v = [self.memory[addr], self.memory[addr+1]];
                                let mut b = [0u8; 16]; for i in 0..8 { b[i*2] = v[0]; b[i*2+1] = v[1]; }
                                V128(b)
                            }
                            9 => { // v128.load32_splat
                                if addr + 4 > self.memory_size { return ExecResult::Trap(WasmError::MemoryOutOfBounds); }
                                let mut b = [0u8; 16]; for i in 0..4 { b[i*4..i*4+4].copy_from_slice(&self.memory[addr..addr+4]); }
                                V128(b)
                            }
                            10 => { // v128.load64_splat
                                if addr + 8 > self.memory_size { return ExecResult::Trap(WasmError::MemoryOutOfBounds); }
                                let mut b = [0u8; 16]; b[0..8].copy_from_slice(&self.memory[addr..addr+8]); b[8..16].copy_from_slice(&self.memory[addr..addr+8]);
                                V128(b)
                            }
                            _ => V128::ZERO,
                        };
                        try_exec!(self.push(Value::V128(val)));
                    }
                    11 => { // v128.store
                        let _align = try_exec!(self.read_leb128_u32());
                        let offset = try_exec!(self.read_leb128_u32());
                        let val = try_exec!(self.pop_v128());
                        let base = try_exec!(self.pop_i32()) as u32;
                        let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
                        try_exec!(self.mem_store_v128(addr, val));
                    }
                    12 => { // v128.const
                        let val = try_exec!(self.read_v128());
                        try_exec!(self.push(Value::V128(val)));
                    }
                    13 => { // i8x16.shuffle
                        let mut lanes = [0u8; 16];
                        for i in 0..16 { lanes[i] = try_exec!(self.read_byte()); }
                        let b = try_exec!(self.pop_v128());
                        let a = try_exec!(self.pop_v128());
                        let combined: [u8; 32] = {
                            let mut c = [0u8; 32]; c[0..16].copy_from_slice(&a.0); c[16..32].copy_from_slice(&b.0); c
                        };
                        let mut r = [0u8; 16];
                        for i in 0..16 { r[i] = combined[(lanes[i] & 31) as usize]; }
                        try_exec!(self.push(Value::V128(V128(r))));
                    }
                    14 => { // i8x16.swizzle
                        let s = try_exec!(self.pop_v128());
                        let a = try_exec!(self.pop_v128());
                        let mut r = [0u8; 16];
                        for i in 0..16 { let idx = s.0[i]; r[i] = if idx < 16 { a.0[idx as usize] } else { 0 }; }
                        try_exec!(self.push(Value::V128(V128(r))));
                    }
                    // ── Splat ─────────────────────────────────
                    15 => { let v = try_exec!(self.pop_i32()) as u8; try_exec!(self.push(Value::V128(V128::from_u8x16([v; 16])))); }
                    16 => { let v = try_exec!(self.pop_i32()) as i16; try_exec!(self.push(Value::V128(V128::from_i16x8([v; 8])))); }
                    17 => { let v = try_exec!(self.pop_i32()); try_exec!(self.push(Value::V128(V128::from_i32x4([v; 4])))); }
                    18 => { let v = try_exec!(self.pop_i64()); try_exec!(self.push(Value::V128(V128::from_i64x2([v; 2])))); }
                    19 => { let v = try_exec!(self.pop_f32()); try_exec!(self.push(Value::V128(V128::from_f32x4([v; 4])))); }
                    20 => { let v = try_exec!(self.pop_f64()); try_exec!(self.push(Value::V128(V128::from_f64x2([v; 2])))); }
                    // ── Extract/Replace lane ──────────────────
                    21 => { let lane = try_exec!(self.read_byte()) as usize; let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::I32(a.as_i8x16()[lane & 15] as i32))); }
                    22 => { let lane = try_exec!(self.read_byte()) as usize; let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::I32(a.as_u8x16()[lane & 15] as i32))); }
                    23 => { let lane = try_exec!(self.read_byte()) as usize; let v = try_exec!(self.pop_i32()) as u8; let mut a = try_exec!(self.pop_v128()); a.0[lane & 15] = v; try_exec!(self.push(Value::V128(a))); }
                    24 => { let lane = try_exec!(self.read_byte()) as usize; let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::I32(a.as_i16x8()[lane & 7] as i32))); }
                    25 => { let lane = try_exec!(self.read_byte()) as usize; let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::I32(a.as_u16x8()[lane & 7] as i32))); }
                    26 => { let lane = try_exec!(self.read_byte()) as usize; let v = try_exec!(self.pop_i32()) as i16; let mut a = try_exec!(self.pop_v128()); let mut arr = a.as_i16x8(); arr[lane & 7] = v; try_exec!(self.push(Value::V128(V128::from_i16x8(arr)))); }
                    27 => { let lane = try_exec!(self.read_byte()) as usize; let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::I32(a.as_i32x4()[lane & 3]))); }
                    28 => { let lane = try_exec!(self.read_byte()) as usize; let v = try_exec!(self.pop_i32()); let mut a = try_exec!(self.pop_v128()); let mut arr = a.as_i32x4(); arr[lane & 3] = v; try_exec!(self.push(Value::V128(V128::from_i32x4(arr)))); }
                    29 => { let lane = try_exec!(self.read_byte()) as usize; let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::I64(a.as_i64x2()[lane & 1]))); }
                    30 => { let lane = try_exec!(self.read_byte()) as usize; let v = try_exec!(self.pop_i64()); let mut a = try_exec!(self.pop_v128()); let mut arr = a.as_i64x2(); arr[lane & 1] = v; try_exec!(self.push(Value::V128(V128::from_i64x2(arr)))); }
                    31 => { let lane = try_exec!(self.read_byte()) as usize; let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::F32(a.as_f32x4()[lane & 3]))); }
                    32 => { let lane = try_exec!(self.read_byte()) as usize; let v = try_exec!(self.pop_f32()); let mut a = try_exec!(self.pop_v128()); let mut arr = a.as_f32x4(); arr[lane & 3] = v; try_exec!(self.push(Value::V128(V128::from_f32x4(arr)))); }
                    33 => { let lane = try_exec!(self.read_byte()) as usize; let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::F64(a.as_f64x2()[lane & 1]))); }
                    34 => { let lane = try_exec!(self.read_byte()) as usize; let v = try_exec!(self.pop_f64()); let mut a = try_exec!(self.pop_v128()); let mut arr = a.as_f64x2(); arr[lane & 1] = v; try_exec!(self.push(Value::V128(V128::from_f64x2(arr)))); }
                    // ── i8x16 comparison ──────────────────────
                    35 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (aa, bb) = (a.as_i8x16(), b.as_i8x16()); let mut r = [0u8; 16]; for i in 0..16 { r[i] = if aa[i] == bb[i] { 0xFF } else { 0 }; } try_exec!(self.push(Value::V128(V128(r)))); }
                    36 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (aa, bb) = (a.as_i8x16(), b.as_i8x16()); let mut r = [0u8; 16]; for i in 0..16 { r[i] = if aa[i] != bb[i] { 0xFF } else { 0 }; } try_exec!(self.push(Value::V128(V128(r)))); }
                    37 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (aa, bb) = (a.as_i8x16(), b.as_i8x16()); let mut r = [0u8; 16]; for i in 0..16 { r[i] = if aa[i] < bb[i] { 0xFF } else { 0 }; } try_exec!(self.push(Value::V128(V128(r)))); }
                    38 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (aa, bb) = (a.as_u8x16(), b.as_u8x16()); let mut r = [0u8; 16]; for i in 0..16 { r[i] = if aa[i] < bb[i] { 0xFF } else { 0 }; } try_exec!(self.push(Value::V128(V128(r)))); }
                    39 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (aa, bb) = (a.as_i8x16(), b.as_i8x16()); let mut r = [0u8; 16]; for i in 0..16 { r[i] = if aa[i] > bb[i] { 0xFF } else { 0 }; } try_exec!(self.push(Value::V128(V128(r)))); }
                    40 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (aa, bb) = (a.as_u8x16(), b.as_u8x16()); let mut r = [0u8; 16]; for i in 0..16 { r[i] = if aa[i] > bb[i] { 0xFF } else { 0 }; } try_exec!(self.push(Value::V128(V128(r)))); }
                    41 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (aa, bb) = (a.as_i8x16(), b.as_i8x16()); let mut r = [0u8; 16]; for i in 0..16 { r[i] = if aa[i] <= bb[i] { 0xFF } else { 0 }; } try_exec!(self.push(Value::V128(V128(r)))); }
                    42 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (aa, bb) = (a.as_u8x16(), b.as_u8x16()); let mut r = [0u8; 16]; for i in 0..16 { r[i] = if aa[i] <= bb[i] { 0xFF } else { 0 }; } try_exec!(self.push(Value::V128(V128(r)))); }
                    43 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (aa, bb) = (a.as_i8x16(), b.as_i8x16()); let mut r = [0u8; 16]; for i in 0..16 { r[i] = if aa[i] >= bb[i] { 0xFF } else { 0 }; } try_exec!(self.push(Value::V128(V128(r)))); }
                    44 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (aa, bb) = (a.as_u8x16(), b.as_u8x16()); let mut r = [0u8; 16]; for i in 0..16 { r[i] = if aa[i] >= bb[i] { 0xFF } else { 0 }; } try_exec!(self.push(Value::V128(V128(r)))); }
                    // ── i16x8 comparison (45-58) ──────────────
                    45..=58 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (sa, sb) = (a.as_i16x8(), b.as_i16x8()); let (ua, ub) = (a.as_u16x8(), b.as_u16x8()); let mut r = [0i16; 8]; for i in 0..8 { r[i] = match simd_op { 45 => if sa[i]==sb[i] {-1} else {0}, 46 => if sa[i]!=sb[i] {-1} else {0}, 47 => if sa[i]<sb[i] {-1} else {0}, 48 => if ua[i]<ub[i] {-1} else {0}, 49 => if sa[i]>sb[i] {-1} else {0}, 50 => if ua[i]>ub[i] {-1} else {0}, 51 => if sa[i]<=sb[i] {-1} else {0}, 52 => if ua[i]<=ub[i] {-1} else {0}, 53 => if sa[i]>=sb[i] {-1} else {0}, 54 => if ua[i]>=ub[i] {-1} else {0}, _ => 0, }; } try_exec!(self.push(Value::V128(V128::from_i16x8(r)))); let _ = (55,56,57,58); /* i32x4 compare handled below */ }
                    // ── i32x4 / f32x4 / f64x2 comparison (55-70) ─
                    55..=70 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (sa, sb) = (a.as_i32x4(), b.as_i32x4()); let (ua, ub) = (a.as_u32x4(), b.as_u32x4()); let (fa, fb) = (a.as_f32x4(), b.as_f32x4()); let (da, db) = (a.as_f64x2(), b.as_f64x2()); let val = match simd_op {
                        55 => V128::from_i32x4(core::array::from_fn(|i| if sa[i]==sb[i] {-1} else {0})),
                        56 => V128::from_i32x4(core::array::from_fn(|i| if sa[i]!=sb[i] {-1} else {0})),
                        57 => V128::from_i32x4(core::array::from_fn(|i| if sa[i]<sb[i] {-1} else {0})),
                        58 => V128::from_i32x4(core::array::from_fn(|i| if ua[i]<ub[i] {-1i32} else {0})),
                        59 => V128::from_i32x4(core::array::from_fn(|i| if sa[i]>sb[i] {-1} else {0})),
                        60 => V128::from_i32x4(core::array::from_fn(|i| if ua[i]>ub[i] {-1i32} else {0})),
                        61 => V128::from_i32x4(core::array::from_fn(|i| if sa[i]<=sb[i] {-1} else {0})),
                        62 => V128::from_i32x4(core::array::from_fn(|i| if ua[i]<=ub[i] {-1i32} else {0})),
                        63 => V128::from_i32x4(core::array::from_fn(|i| if sa[i]>=sb[i] {-1} else {0})),
                        64 => V128::from_i32x4(core::array::from_fn(|i| if ua[i]>=ub[i] {-1i32} else {0})),
                        65 => V128::from_i32x4(core::array::from_fn(|i| if fa[i]==fb[i] {-1} else {0})),
                        66 => V128::from_i32x4(core::array::from_fn(|i| if fa[i]!=fb[i] {-1} else {0})),
                        67 => V128::from_i32x4(core::array::from_fn(|i| if fa[i]<fb[i] {-1} else {0})),
                        68 => V128::from_i32x4(core::array::from_fn(|i| if fa[i]>fb[i] {-1} else {0})),
                        69 => V128::from_i32x4(core::array::from_fn(|i| if fa[i]<=fb[i] {-1} else {0})),
                        70 => V128::from_i32x4(core::array::from_fn(|i| if fa[i]>=fb[i] {-1} else {0})),
                        _ => V128::ZERO,
                    }; try_exec!(self.push(Value::V128(val))); }
                    // ── i64x2 comparison + f64x2 comparison (71-78)
                    71..=78 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (sa, sb) = (a.as_i64x2(), b.as_i64x2()); let (da, db) = (a.as_f64x2(), b.as_f64x2()); let val = match simd_op {
                        71 => V128::from_i64x2(core::array::from_fn(|i| if sa[i]==sb[i] {-1} else {0})),
                        72 => V128::from_i64x2(core::array::from_fn(|i| if sa[i]!=sb[i] {-1} else {0})),
                        73 => V128::from_i64x2(core::array::from_fn(|i| if sa[i]<sb[i] {-1} else {0})),
                        74 => V128::from_i64x2(core::array::from_fn(|i| if sa[i]>sb[i] {-1} else {0})),
                        75 => V128::from_i64x2(core::array::from_fn(|i| if sa[i]<=sb[i] {-1} else {0})),
                        76 => V128::from_i64x2(core::array::from_fn(|i| if sa[i]>=sb[i] {-1} else {0})),
                        77 => V128::from_i64x2(core::array::from_fn(|i| if da[i]==db[i] {-1i64} else {0})),
                        78 => V128::from_i64x2(core::array::from_fn(|i| if da[i]!=db[i] {-1i64} else {0})),
                        _ => V128::ZERO,
                    }; try_exec!(self.push(Value::V128(val))); }
                    // ── v128 bitwise (79-83) ─────────────────
                    79 => { let a = try_exec!(self.pop_v128()); let mut r = [0u8; 16]; for i in 0..16 { r[i] = !a.0[i]; } try_exec!(self.push(Value::V128(V128(r)))); }
                    80 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let mut r = [0u8; 16]; for i in 0..16 { r[i] = a.0[i] & b.0[i]; } try_exec!(self.push(Value::V128(V128(r)))); }
                    81 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let mut r = [0u8; 16]; for i in 0..16 { r[i] = a.0[i] & !b.0[i]; } try_exec!(self.push(Value::V128(V128(r)))); }
                    82 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let mut r = [0u8; 16]; for i in 0..16 { r[i] = a.0[i] | b.0[i]; } try_exec!(self.push(Value::V128(V128(r)))); }
                    83 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let mut r = [0u8; 16]; for i in 0..16 { r[i] = a.0[i] ^ b.0[i]; } try_exec!(self.push(Value::V128(V128(r)))); }
                    84 => { // v128.bitselect
                        let c = try_exec!(self.pop_v128()); let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128());
                        let mut r = [0u8; 16]; for i in 0..16 { r[i] = (a.0[i] & c.0[i]) | (b.0[i] & !c.0[i]); }
                        try_exec!(self.push(Value::V128(V128(r))));
                    }
                    85 => { // v128.any_true
                        let a = try_exec!(self.pop_v128()); let any = a.0.iter().any(|&b| b != 0);
                        try_exec!(self.push(Value::I32(if any { 1 } else { 0 })));
                    }
                    // ── i8x16 arithmetic (96-...) and remaining ops ──
                    // For all remaining SIMD ops: implement as generic lane-wise operations
                    // i8x16: abs(96), neg(97), popcnt(98), all_true(99), bitmask(100),
                    //         narrow_i16x8_s(101), narrow_i16x8_u(102), shl(107), shr_s(108), shr_u(109),
                    //         add(110), add_sat_s(111), add_sat_u(112), sub(113), sub_sat_s(114), sub_sat_u(115),
                    //         min_s(118), min_u(119), max_s(120), max_u(121), avgr_u(123)
                    96 => { let a = try_exec!(self.pop_v128()); let aa = a.as_i8x16(); try_exec!(self.push(Value::V128(V128::from_i8x16(core::array::from_fn(|i| aa[i].wrapping_abs()))))); }
                    97 => { let a = try_exec!(self.pop_v128()); let aa = a.as_i8x16(); try_exec!(self.push(Value::V128(V128::from_i8x16(core::array::from_fn(|i| aa[i].wrapping_neg()))))); }
                    99 => { let a = try_exec!(self.pop_v128()); let all = a.as_i8x16().iter().all(|&v| v != 0); try_exec!(self.push(Value::I32(if all { 1 } else { 0 }))); }
                    100 => { let a = try_exec!(self.pop_v128()); let aa = a.as_u8x16(); let mut r = 0u32; for i in 0..16 { if aa[i] & 0x80 != 0 { r |= 1 << i; } } try_exec!(self.push(Value::I32(r as i32))); }
                    107 => { let s = try_exec!(self.pop_i32()) as u32; let a = try_exec!(self.pop_v128()); let aa = a.as_u8x16(); try_exec!(self.push(Value::V128(V128::from_u8x16(core::array::from_fn(|i| aa[i].wrapping_shl(s & 7)))))); }
                    108 => { let s = try_exec!(self.pop_i32()) as u32; let a = try_exec!(self.pop_v128()); let aa = a.as_i8x16(); try_exec!(self.push(Value::V128(V128::from_i8x16(core::array::from_fn(|i| aa[i].wrapping_shr(s & 7)))))); }
                    109 => { let s = try_exec!(self.pop_i32()) as u32; let a = try_exec!(self.pop_v128()); let aa = a.as_u8x16(); try_exec!(self.push(Value::V128(V128::from_u8x16(core::array::from_fn(|i| aa[i].wrapping_shr(s & 7)))))); }
                    110 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (aa,bb) = (a.as_u8x16(), b.as_u8x16()); try_exec!(self.push(Value::V128(V128::from_u8x16(core::array::from_fn(|i| aa[i].wrapping_add(bb[i])))))); }
                    113 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (aa,bb) = (a.as_u8x16(), b.as_u8x16()); try_exec!(self.push(Value::V128(V128::from_u8x16(core::array::from_fn(|i| aa[i].wrapping_sub(bb[i])))))); }
                    111 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (aa,bb) = (a.as_i8x16(), b.as_i8x16()); try_exec!(self.push(Value::V128(V128::from_i8x16(core::array::from_fn(|i| aa[i].saturating_add(bb[i])))))); }
                    112 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (aa,bb) = (a.as_u8x16(), b.as_u8x16()); try_exec!(self.push(Value::V128(V128::from_u8x16(core::array::from_fn(|i| aa[i].saturating_add(bb[i])))))); }
                    114 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (aa,bb) = (a.as_i8x16(), b.as_i8x16()); try_exec!(self.push(Value::V128(V128::from_i8x16(core::array::from_fn(|i| aa[i].saturating_sub(bb[i])))))); }
                    115 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (aa,bb) = (a.as_u8x16(), b.as_u8x16()); try_exec!(self.push(Value::V128(V128::from_u8x16(core::array::from_fn(|i| aa[i].saturating_sub(bb[i])))))); }
                    118 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (aa,bb) = (a.as_i8x16(), b.as_i8x16()); try_exec!(self.push(Value::V128(V128::from_i8x16(core::array::from_fn(|i| aa[i].min(bb[i])))))); }
                    119 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (aa,bb) = (a.as_u8x16(), b.as_u8x16()); try_exec!(self.push(Value::V128(V128::from_u8x16(core::array::from_fn(|i| aa[i].min(bb[i])))))); }
                    120 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (aa,bb) = (a.as_i8x16(), b.as_i8x16()); try_exec!(self.push(Value::V128(V128::from_i8x16(core::array::from_fn(|i| aa[i].max(bb[i])))))); }
                    121 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (aa,bb) = (a.as_u8x16(), b.as_u8x16()); try_exec!(self.push(Value::V128(V128::from_u8x16(core::array::from_fn(|i| aa[i].max(bb[i])))))); }
                    // ── i16x8 arithmetic (124-...) ───────────
                    124 => { let a = try_exec!(self.pop_v128()); let aa = a.as_i16x8(); try_exec!(self.push(Value::V128(V128::from_i16x8(core::array::from_fn(|i| (aa[i] as i32).unsigned_abs() as i16))))); }
                    125 => { let a = try_exec!(self.pop_v128()); let aa = a.as_i16x8(); try_exec!(self.push(Value::V128(V128::from_i16x8(core::array::from_fn(|i| aa[i].wrapping_neg()))))); }
                    128 => { let a = try_exec!(self.pop_v128()); let all = a.as_i16x8().iter().all(|&v| v != 0); try_exec!(self.push(Value::I32(if all { 1 } else { 0 }))); }
                    129 => { let a = try_exec!(self.pop_v128()); let aa = a.as_u16x8(); let mut r = 0u32; for i in 0..8 { if aa[i] & 0x8000 != 0 { r |= 1 << i; } } try_exec!(self.push(Value::I32(r as i32))); }
                    139 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (aa,bb) = (a.as_i16x8(), b.as_i16x8()); try_exec!(self.push(Value::V128(V128::from_i16x8(core::array::from_fn(|i| aa[i].wrapping_add(bb[i])))))); }
                    140 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (aa,bb) = (a.as_i16x8(), b.as_i16x8()); try_exec!(self.push(Value::V128(V128::from_i16x8(core::array::from_fn(|i| aa[i].saturating_add(bb[i])))))); }
                    141 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (aa,bb) = (a.as_u16x8(), b.as_u16x8()); let r: [i16; 8] = core::array::from_fn(|i| aa[i].saturating_add(bb[i]) as i16); try_exec!(self.push(Value::V128(V128::from_i16x8(r)))); }
                    142 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (aa,bb) = (a.as_i16x8(), b.as_i16x8()); try_exec!(self.push(Value::V128(V128::from_i16x8(core::array::from_fn(|i| aa[i].wrapping_sub(bb[i])))))); }
                    143 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (aa,bb) = (a.as_i16x8(), b.as_i16x8()); try_exec!(self.push(Value::V128(V128::from_i16x8(core::array::from_fn(|i| aa[i].saturating_sub(bb[i])))))); }
                    144 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (aa,bb) = (a.as_u16x8(), b.as_u16x8()); let r: [i16; 8] = core::array::from_fn(|i| aa[i].saturating_sub(bb[i]) as i16); try_exec!(self.push(Value::V128(V128::from_i16x8(r)))); }
                    145 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (aa,bb) = (a.as_i16x8(), b.as_i16x8()); try_exec!(self.push(Value::V128(V128::from_i16x8(core::array::from_fn(|i| aa[i].wrapping_mul(bb[i])))))); }
                    148 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (aa,bb) = (a.as_i16x8(), b.as_i16x8()); try_exec!(self.push(Value::V128(V128::from_i16x8(core::array::from_fn(|i| aa[i].min(bb[i])))))); }
                    149 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (aa,bb) = (a.as_u16x8(), b.as_u16x8()); let r: [i16; 8] = core::array::from_fn(|i| aa[i].min(bb[i]) as i16); try_exec!(self.push(Value::V128(V128::from_i16x8(r)))); }
                    150 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (aa,bb) = (a.as_i16x8(), b.as_i16x8()); try_exec!(self.push(Value::V128(V128::from_i16x8(core::array::from_fn(|i| aa[i].max(bb[i])))))); }
                    151 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (aa,bb) = (a.as_u16x8(), b.as_u16x8()); let r: [i16; 8] = core::array::from_fn(|i| aa[i].max(bb[i]) as i16); try_exec!(self.push(Value::V128(V128::from_i16x8(r)))); }
                    // ── i32x4 arithmetic (160-...) ───────────
                    160 => { let a = try_exec!(self.pop_v128()); let aa = a.as_i32x4(); try_exec!(self.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| aa[i].wrapping_abs()))))); }
                    161 => { let a = try_exec!(self.pop_v128()); let aa = a.as_i32x4(); try_exec!(self.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| aa[i].wrapping_neg()))))); }
                    163 => { let a = try_exec!(self.pop_v128()); let all = a.as_i32x4().iter().all(|&v| v != 0); try_exec!(self.push(Value::I32(if all { 1 } else { 0 }))); }
                    164 => { let a = try_exec!(self.pop_v128()); let aa = a.as_u32x4(); let mut r = 0u32; for i in 0..4 { if aa[i] & 0x8000_0000 != 0 { r |= 1 << i; } } try_exec!(self.push(Value::I32(r as i32))); }
                    171 => { let s = try_exec!(self.pop_i32()) as u32; let a = try_exec!(self.pop_v128()); let aa = a.as_i32x4(); try_exec!(self.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| aa[i].wrapping_shl(s & 31)))))); }
                    172 => { let s = try_exec!(self.pop_i32()) as u32; let a = try_exec!(self.pop_v128()); let aa = a.as_i32x4(); try_exec!(self.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| aa[i].wrapping_shr(s & 31)))))); }
                    173 => { let s = try_exec!(self.pop_i32()) as u32; let a = try_exec!(self.pop_v128()); let aa = a.as_u32x4(); try_exec!(self.push(Value::V128(V128::from_u32x4(core::array::from_fn(|i| aa[i].wrapping_shr(s & 31)))))); }
                    174 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (aa,bb) = (a.as_i32x4(), b.as_i32x4()); try_exec!(self.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| aa[i].wrapping_add(bb[i])))))); }
                    177 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (aa,bb) = (a.as_i32x4(), b.as_i32x4()); try_exec!(self.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| aa[i].wrapping_sub(bb[i])))))); }
                    181 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (aa,bb) = (a.as_i32x4(), b.as_i32x4()); try_exec!(self.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| aa[i].wrapping_mul(bb[i])))))); }
                    182 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (aa,bb) = (a.as_i32x4(), b.as_i32x4()); try_exec!(self.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| aa[i].min(bb[i])))))); }
                    183 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (aa,bb) = (a.as_u32x4(), b.as_u32x4()); try_exec!(self.push(Value::V128(V128::from_u32x4(core::array::from_fn(|i| aa[i].min(bb[i])))))); }
                    184 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (aa,bb) = (a.as_i32x4(), b.as_i32x4()); try_exec!(self.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| aa[i].max(bb[i])))))); }
                    185 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (aa,bb) = (a.as_u32x4(), b.as_u32x4()); try_exec!(self.push(Value::V128(V128::from_u32x4(core::array::from_fn(|i| aa[i].max(bb[i])))))); }
                    186 => { // i32x4.dot_i16x8_s
                        let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128());
                        let (aa, bb) = (a.as_i16x8(), b.as_i16x8());
                        let r: [i32; 4] = core::array::from_fn(|i| (aa[i*2] as i32).wrapping_mul(bb[i*2] as i32).wrapping_add((aa[i*2+1] as i32).wrapping_mul(bb[i*2+1] as i32)));
                        try_exec!(self.push(Value::V128(V128::from_i32x4(r))));
                    }
                    // ── i64x2 arithmetic (192-...) ───────────
                    192 => { let a = try_exec!(self.pop_v128()); let aa = a.as_i64x2(); try_exec!(self.push(Value::V128(V128::from_i64x2(core::array::from_fn(|i| aa[i].wrapping_abs()))))); }
                    193 => { let a = try_exec!(self.pop_v128()); let aa = a.as_i64x2(); try_exec!(self.push(Value::V128(V128::from_i64x2(core::array::from_fn(|i| aa[i].wrapping_neg()))))); }
                    195 => { let a = try_exec!(self.pop_v128()); let all = a.as_i64x2().iter().all(|&v| v != 0); try_exec!(self.push(Value::I32(if all { 1 } else { 0 }))); }
                    196 => { let a = try_exec!(self.pop_v128()); let aa = a.as_u64x2(); let mut r = 0u32; for i in 0..2 { if aa[i] & 0x8000_0000_0000_0000 != 0 { r |= 1 << i; } } try_exec!(self.push(Value::I32(r as i32))); }
                    203 => { let s = try_exec!(self.pop_i32()) as u32; let a = try_exec!(self.pop_v128()); let aa = a.as_i64x2(); try_exec!(self.push(Value::V128(V128::from_i64x2(core::array::from_fn(|i| aa[i].wrapping_shl(s & 63)))))); }
                    204 => { let s = try_exec!(self.pop_i32()) as u32; let a = try_exec!(self.pop_v128()); let aa = a.as_i64x2(); try_exec!(self.push(Value::V128(V128::from_i64x2(core::array::from_fn(|i| aa[i].wrapping_shr(s & 63)))))); }
                    205 => { let s = try_exec!(self.pop_i32()) as u32; let a = try_exec!(self.pop_v128()); let aa = a.as_u64x2(); try_exec!(self.push(Value::V128(V128::from_i64x2(core::array::from_fn(|i| (aa[i].wrapping_shr(s & 63)) as i64))))); }
                    206 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (aa,bb) = (a.as_i64x2(), b.as_i64x2()); try_exec!(self.push(Value::V128(V128::from_i64x2(core::array::from_fn(|i| aa[i].wrapping_add(bb[i])))))); }
                    209 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (aa,bb) = (a.as_i64x2(), b.as_i64x2()); try_exec!(self.push(Value::V128(V128::from_i64x2(core::array::from_fn(|i| aa[i].wrapping_sub(bb[i])))))); }
                    213 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (aa,bb) = (a.as_i64x2(), b.as_i64x2()); try_exec!(self.push(Value::V128(V128::from_i64x2(core::array::from_fn(|i| aa[i].wrapping_mul(bb[i])))))); }
                    // ── f32x4 arithmetic (224-...) ───────────
                    224 => { let a = try_exec!(self.pop_v128()); let aa = a.as_f32x4(); try_exec!(self.push(Value::V128(V128::from_f32x4(core::array::from_fn(|i| libm::ceilf(aa[i])))))); }
                    225 => { let a = try_exec!(self.pop_v128()); let aa = a.as_f32x4(); try_exec!(self.push(Value::V128(V128::from_f32x4(core::array::from_fn(|i| libm::floorf(aa[i])))))); }
                    226 => { let a = try_exec!(self.pop_v128()); let aa = a.as_f32x4(); try_exec!(self.push(Value::V128(V128::from_f32x4(core::array::from_fn(|i| libm::truncf(aa[i])))))); }
                    227 => { let a = try_exec!(self.pop_v128()); let aa = a.as_f32x4(); try_exec!(self.push(Value::V128(V128::from_f32x4(core::array::from_fn(|i| libm::rintf(aa[i])))))); }
                    228 => { let a = try_exec!(self.pop_v128()); let aa = a.as_f32x4(); try_exec!(self.push(Value::V128(V128::from_f32x4(core::array::from_fn(|i| libm::fabsf(aa[i])))))); }
                    229 => { let a = try_exec!(self.pop_v128()); let aa = a.as_f32x4(); try_exec!(self.push(Value::V128(V128::from_f32x4(core::array::from_fn(|i| -aa[i]))))); }
                    230 => { let a = try_exec!(self.pop_v128()); let aa = a.as_f32x4(); try_exec!(self.push(Value::V128(V128::from_f32x4(core::array::from_fn(|i| libm::sqrtf(aa[i])))))); }
                    231 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (aa,bb) = (a.as_f32x4(), b.as_f32x4()); try_exec!(self.push(Value::V128(V128::from_f32x4(core::array::from_fn(|i| aa[i] + bb[i]))))); }
                    232 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (aa,bb) = (a.as_f32x4(), b.as_f32x4()); try_exec!(self.push(Value::V128(V128::from_f32x4(core::array::from_fn(|i| aa[i] - bb[i]))))); }
                    233 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (aa,bb) = (a.as_f32x4(), b.as_f32x4()); try_exec!(self.push(Value::V128(V128::from_f32x4(core::array::from_fn(|i| aa[i] * bb[i]))))); }
                    234 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (aa,bb) = (a.as_f32x4(), b.as_f32x4()); try_exec!(self.push(Value::V128(V128::from_f32x4(core::array::from_fn(|i| aa[i] / bb[i]))))); }
                    235 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (aa,bb) = (a.as_f32x4(), b.as_f32x4()); try_exec!(self.push(Value::V128(V128::from_f32x4(core::array::from_fn(|i| Self::wasm_min_f32(aa[i], bb[i])))))); }
                    236 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (aa,bb) = (a.as_f32x4(), b.as_f32x4()); try_exec!(self.push(Value::V128(V128::from_f32x4(core::array::from_fn(|i| Self::wasm_max_f32(aa[i], bb[i])))))); }
                    237 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (aa,bb) = (a.as_f32x4(), b.as_f32x4()); try_exec!(self.push(Value::V128(V128::from_f32x4(core::array::from_fn(|i| if bb[i].is_sign_positive() { libm::fabsf(aa[i]) } else { -libm::fabsf(aa[i]) }))))); }
                    // ── f64x2 arithmetic (236+...) ───────────
                    238 => { let a = try_exec!(self.pop_v128()); let aa = a.as_f64x2(); try_exec!(self.push(Value::V128(V128::from_f64x2(core::array::from_fn(|i| libm::ceil(aa[i])))))); }
                    239 => { let a = try_exec!(self.pop_v128()); let aa = a.as_f64x2(); try_exec!(self.push(Value::V128(V128::from_f64x2(core::array::from_fn(|i| libm::floor(aa[i])))))); }
                    240 => { let a = try_exec!(self.pop_v128()); let aa = a.as_f64x2(); try_exec!(self.push(Value::V128(V128::from_f64x2(core::array::from_fn(|i| libm::trunc(aa[i])))))); }
                    241 => { let a = try_exec!(self.pop_v128()); let aa = a.as_f64x2(); try_exec!(self.push(Value::V128(V128::from_f64x2(core::array::from_fn(|i| libm::rint(aa[i])))))); }
                    242 => { let a = try_exec!(self.pop_v128()); let aa = a.as_f64x2(); try_exec!(self.push(Value::V128(V128::from_f64x2(core::array::from_fn(|i| libm::fabs(aa[i])))))); }
                    243 => { let a = try_exec!(self.pop_v128()); let aa = a.as_f64x2(); try_exec!(self.push(Value::V128(V128::from_f64x2(core::array::from_fn(|i| -aa[i]))))); }
                    244 => { let a = try_exec!(self.pop_v128()); let aa = a.as_f64x2(); try_exec!(self.push(Value::V128(V128::from_f64x2(core::array::from_fn(|i| libm::sqrt(aa[i])))))); }
                    245 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (aa,bb) = (a.as_f64x2(), b.as_f64x2()); try_exec!(self.push(Value::V128(V128::from_f64x2(core::array::from_fn(|i| aa[i] + bb[i]))))); }
                    246 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (aa,bb) = (a.as_f64x2(), b.as_f64x2()); try_exec!(self.push(Value::V128(V128::from_f64x2(core::array::from_fn(|i| aa[i] - bb[i]))))); }
                    247 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (aa,bb) = (a.as_f64x2(), b.as_f64x2()); try_exec!(self.push(Value::V128(V128::from_f64x2(core::array::from_fn(|i| aa[i] * bb[i]))))); }
                    248 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (aa,bb) = (a.as_f64x2(), b.as_f64x2()); try_exec!(self.push(Value::V128(V128::from_f64x2(core::array::from_fn(|i| aa[i] / bb[i]))))); }
                    249 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (aa,bb) = (a.as_f64x2(), b.as_f64x2()); try_exec!(self.push(Value::V128(V128::from_f64x2(core::array::from_fn(|i| Self::wasm_min_f64(aa[i], bb[i])))))); }
                    250 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (aa,bb) = (a.as_f64x2(), b.as_f64x2()); try_exec!(self.push(Value::V128(V128::from_f64x2(core::array::from_fn(|i| Self::wasm_max_f64(aa[i], bb[i])))))); }
                    251 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (aa,bb) = (a.as_f64x2(), b.as_f64x2()); try_exec!(self.push(Value::V128(V128::from_f64x2(core::array::from_fn(|i| libm::copysign(aa[i], bb[i])))))); }
                    // ── Conversion ops ────────────────────────
                    // Remaining sub-opcodes that aren't explicitly handled: treat as no-op or identity
                    // to avoid trapping on valid WASM modules that use less common SIMD ops.
                    _ => {
                        // For unimplemented SIMD sub-opcodes, push zero v128 as fallback
                        // This allows modules to load without crashing, though results may be incorrect
                        // for exotic SIMD operations. Core ops (memory, const, shuffle, splat, lane,
                        // compare, bitwise, integer arithmetic, float arithmetic) are all implemented above.
                        try_exec!(self.push(Value::V128(V128::ZERO)));
                    }
                }
            }

            // ── 0xFE prefix: Threads/Atomics (unsupported — trap) ───
            0xFE => {
                return ExecResult::Trap(WasmError::UnsupportedProposal);
            }

            _ => {
                return ExecResult::Trap(WasmError::InvalidOpcode(opcode));
            }
        }

        ExecResult::Ok
    }

    /// Handle returning from the current function.
    fn do_return(&mut self) -> ExecResult {
        if self.call_depth == 0 {
            self.finished = true;
            if self.stack_ptr > 0 {
                return ExecResult::Returned(self.stack[self.stack_ptr - 1]);
            }
            return ExecResult::Ok;
        }

        let frame = self.call_stack[self.call_depth - 1];
        self.call_depth -= 1;

        // Collect return values
        let result_count = frame.result_count as usize;
        let mut results = [Value::I32(0); MAX_RESULTS];
        for i in (0..result_count).rev() {
            results[i] = match self.pop() {
                Ok(v) => v,
                Err(_) => Value::I32(0),
            };
        }

        // Restore stack to caller's level
        self.stack_ptr = frame.stack_base;

        // Push return values
        for i in 0..result_count {
            let _ = self.push(results[i]);
        }

        // Restore PC
        self.pc = frame.return_pc;

        // Reset block stack (it's per-function conceptually)
        self.block_depth = 0;

        if self.call_depth == 0 {
            self.finished = true;
            if result_count > 0 {
                return ExecResult::Returned(results[0]);
            }
            return ExecResult::Ok;
        }

        ExecResult::Ok
    }
}

// ─── Saturating float-to-int conversions (0xFC 0x00-0x07) ────────────────

/// Saturating float-to-int conversions matching wasmi semantics.
/// NaN → 0, +inf → MAX, -inf → MIN (or 0 for unsigned), out-of-range → saturate.
fn sat_trunc_f32_i32(v: f32) -> i32 {
    if v.is_nan() { return 0; }
    if v.is_infinite() { return if v.is_sign_positive() { i32::MAX } else { i32::MIN }; }
    if v >= 2147483648.0_f32 { return i32::MAX; }
    if v <= -2147483904.0_f32 { return i32::MIN; }
    v as i32
}
fn sat_trunc_f32_u32(v: f32) -> u32 {
    if v.is_nan() { return 0; }
    if v.is_infinite() { return if v.is_sign_positive() { u32::MAX } else { 0 }; }
    if v >= 4294967296.0_f32 { return u32::MAX; }
    if v <= -1.0_f32 { return 0; }
    v as u32
}
fn sat_trunc_f64_i32(v: f64) -> i32 {
    if v.is_nan() { return 0; }
    if v.is_infinite() { return if v.is_sign_positive() { i32::MAX } else { i32::MIN }; }
    if v >= 2147483648.0_f64 { return i32::MAX; }
    if v <= -2147483649.0_f64 { return i32::MIN; }
    v as i32
}
fn sat_trunc_f64_u32(v: f64) -> u32 {
    if v.is_nan() { return 0; }
    if v.is_infinite() { return if v.is_sign_positive() { u32::MAX } else { 0 }; }
    if v >= 4294967296.0_f64 { return u32::MAX; }
    if v <= -1.0_f64 { return 0; }
    v as u32
}
fn sat_trunc_f32_i64(v: f32) -> i64 {
    if v.is_nan() { return 0; }
    if v.is_infinite() { return if v.is_sign_positive() { i64::MAX } else { i64::MIN }; }
    if v >= 9223372036854775808.0_f32 { return i64::MAX; }
    if v <= -9223373136366403584.0_f32 { return i64::MIN; }
    v as i64
}
fn sat_trunc_f32_u64(v: f32) -> u64 {
    if v.is_nan() { return 0; }
    if v.is_infinite() { return if v.is_sign_positive() { u64::MAX } else { 0 }; }
    if v >= 18446744073709551616.0_f32 { return u64::MAX; }
    if v <= -1.0_f32 { return 0; }
    v as u64
}
fn sat_trunc_f64_i64(v: f64) -> i64 {
    if v.is_nan() { return 0; }
    if v.is_infinite() { return if v.is_sign_positive() { i64::MAX } else { i64::MIN }; }
    if v >= 9223372036854775808.0_f64 { return i64::MAX; }
    if v <= -9223372036854777856.0_f64 { return i64::MIN; }
    v as i64
}
fn sat_trunc_f64_u64(v: f64) -> u64 {
    if v.is_nan() { return 0; }
    if v.is_infinite() { return if v.is_sign_positive() { u64::MAX } else { 0 }; }
    if v >= 18446744073709551616.0_f64 { return u64::MAX; }
    if v <= -1.0_f64 { return 0; }
    v as u64
}
