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
const MAX_TOTAL_LOCALS: usize = 256;

// ─── WASM instance ─────────────────────────────────────────────────────────

/// A running WASM instance.
pub struct WasmInstance {
    pub module: WasmModule,
    pub stack: Vec<Value>,
    pub stack_ptr: usize,
    pub locals: Vec<Value>,
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
}

impl WasmInstance {
    /// Create a new instance from a decoded module with the given fuel budget.
    pub fn new(module: WasmModule, fuel: u64) -> Self {
        let mem_pages = module.memory_min_pages as usize;
        let mem_size = mem_pages * WASM_PAGE_SIZE;
        WasmInstance {
            module,
            stack: vec![Value::I32(0); MAX_STACK],
            stack_ptr: 0,
            locals: vec![Value::I32(0); MAX_TOTAL_LOCALS],
            memory: vec![0u8; mem_size],
            memory_size: mem_size,
            pc: 0,
            fuel,
            call_stack: vec![CallFrame::zero(); MAX_CALL_DEPTH],
            call_depth: 0,
            block_stack: vec![BlockFrame::zero(); MAX_BLOCK_DEPTH],
            block_depth: 0,
            finished: false,
        }
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
                0x10 => { let _ = self.read_leb128_u32()?; } // call
                0x20 | 0x21 | 0x22 => { let _ = self.read_leb128_u32()?; } // local.get/set/tee
                0x28 | 0x29 | 0x36 | 0x37 => {
                    // memory load/store: align + offset
                    let _ = self.read_leb128_u32()?;
                    let _ = self.read_leb128_u32()?;
                }
                0x41 => { let _ = self.read_leb128_i32()?; } // i32.const
                0x42 => { let _ = self.read_leb128_i64()?; } // i64.const
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
                results[i] = self.pop().unwrap_or(Value::I32(0));
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
        let local_func_idx = func_idx as usize - self.module.imports.len();

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
    fn handle_import_call(&mut self, import_idx: u32) -> Result<ExecResult, WasmError> {
        let idx = import_idx as usize;
        if idx >= self.module.imports.len() {
            return Err(WasmError::ImportNotFound(import_idx));
        }
        let imp = &self.module.imports[idx];

        let type_idx = match imp.kind {
            ImportKind::Func(ti) => ti as usize,
        };

        if type_idx >= self.module.func_types.len() {
            return Err(WasmError::FunctionNotFound(import_idx));
        }
        let ft = &self.module.func_types[type_idx];

        let param_count = ft.param_count;
        let mut args = [Value::I32(0); MAX_PARAMS];

        for i in (0..param_count as usize).rev() {
            args[i] = self.pop()?;
        }

        Ok(ExecResult::HostCall(import_idx, args, param_count))
    }

    // ─── Public API ─────────────────────────────────────────────────────

    /// Call a function by its absolute index (imports + local functions).
    pub fn call_func(&mut self, func_idx: u32, args: &[Value]) -> ExecResult {
        // Push arguments onto the stack
        for arg in args {
            if let Err(e) = self.push(*arg) {
                return ExecResult::Trap(e);
            }
        }

        // Check if it's an import
        if (func_idx as usize) < self.module.imports.len() {
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
                // if
                let block_type = try_exec!(self.read_leb128_i32());
                let result_count = if block_type == -0x40 { 0u8 } else { 1u8 };
                let condition = try_exec!(self.pop_i32());

                let start_pc = self.pc;
                // Scan to find else/end
                let end_or_else_pc = try_exec!(self.skip_to_end());

                if condition != 0 {
                    // Execute the "then" branch
                    self.pc = start_pc;
                    // We need to re-scan to find the true end_pc
                    // The skip_to_end may have stopped at else
                    // We'll push a block and handle else/end in opcode 0x05/0x0B
                    let saved = self.pc;
                    let _end_pc = try_exec!(self.skip_to_end());
                    self.pc = saved;
                    // Actually, we need to properly find the end. Let's rescan from start.
                    // Re-approach: save current pc, skip to find structure
                    self.pc = start_pc;
                    try_exec!(self.push_block(BlockFrame {
                        start_pc,
                        end_pc: end_or_else_pc,
                        stack_base: self.stack_ptr,
                        result_count,
                        is_loop: false,
                    }));
                } else {
                    // Skip to else or end
                    self.pc = end_or_else_pc;
                    // Check if we stopped at else (byte before was 0x05) — tricky.
                    // Actually skip_to_end returns pc past the marker, so we need
                    // to check the byte before. For simplicity: check if the byte
                    // before end_or_else_pc is 0x05.
                    if end_or_else_pc > 0 && self.module.code[end_or_else_pc - 1] == 0x05 {
                        // We're at the else branch — push block for else→end
                        let saved = self.pc;
                        let real_end = try_exec!(self.skip_to_end());
                        self.pc = saved;
                        try_exec!(self.push_block(BlockFrame {
                            start_pc: self.pc,
                            end_pc: real_end,
                            stack_base: self.stack_ptr,
                            result_count,
                            is_loop: false,
                        }));
                    }
                    // else: condition false, no else branch → skip past end, no block pushed
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
            0x0F => {
                // return
                return self.do_return();
            }
            0x10 => {
                // call
                let func_idx = try_exec!(self.read_leb128_u32());
                if (func_idx as usize) < self.module.imports.len() {
                    return match self.handle_import_call(func_idx) {
                        Ok(result) => result,
                        Err(e) => ExecResult::Trap(e),
                    };
                }
                if let Err(e) = self.enter_function(func_idx, true) {
                    return ExecResult::Trap(e);
                }
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

            // ── Memory ──────────────────────────────────────────────
            0x28 => {
                // i32.load
                let _align = try_exec!(self.read_leb128_u32());
                let offset = try_exec!(self.read_leb128_u32());
                let base = try_exec!(self.pop_i32()) as u32;
                let addr = (base + offset) as usize;
                let val = try_exec!(self.mem_load_i32(addr));
                try_exec!(self.push(Value::I32(val)));
            }
            0x29 => {
                // i64.load
                let _align = try_exec!(self.read_leb128_u32());
                let offset = try_exec!(self.read_leb128_u32());
                let base = try_exec!(self.pop_i32()) as u32;
                let addr = (base + offset) as usize;
                let val = try_exec!(self.mem_load_i64(addr));
                try_exec!(self.push(Value::I64(val)));
            }
            0x36 => {
                // i32.store
                let _align = try_exec!(self.read_leb128_u32());
                let offset = try_exec!(self.read_leb128_u32());
                let val = try_exec!(self.pop_i32());
                let base = try_exec!(self.pop_i32()) as u32;
                let addr = (base + offset) as usize;
                try_exec!(self.mem_store_i32(addr, val));
            }
            0x37 => {
                // i64.store
                let _align = try_exec!(self.read_leb128_u32());
                let offset = try_exec!(self.read_leb128_u32());
                let val = try_exec!(self.pop_i64());
                let base = try_exec!(self.pop_i32()) as u32;
                let addr = (base + offset) as usize;
                try_exec!(self.mem_store_i64(addr, val));
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

            // ── Comparison ──────────────────────────────────────────
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
            0x4A => {
                // i32.gt_s
                let b = try_exec!(self.pop_i32());
                let a = try_exec!(self.pop_i32());
                try_exec!(self.push(Value::I32(if a > b { 1 } else { 0 })));
            }
            0x4C => {
                // i32.le_s
                let b = try_exec!(self.pop_i32());
                let a = try_exec!(self.pop_i32());
                try_exec!(self.push(Value::I32(if a <= b { 1 } else { 0 })));
            }
            0x4E => {
                // i32.ge_s
                let b = try_exec!(self.pop_i32());
                let a = try_exec!(self.pop_i32());
                try_exec!(self.push(Value::I32(if a >= b { 1 } else { 0 })));
            }

            // ── i32 Arithmetic ──────────────────────────────────────
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
                    return ExecResult::Trap(WasmError::DivisionByZero);
                }
                try_exec!(self.push(Value::I32(a.wrapping_div(b))));
            }
            0x6F => {
                // i32.rem_s
                let b = try_exec!(self.pop_i32());
                let a = try_exec!(self.pop_i32());
                if b == 0 {
                    return ExecResult::Trap(WasmError::DivisionByZero);
                }
                // rem of MIN / -1 is 0 (no trap)
                if a == i32::MIN && b == -1 {
                    try_exec!(self.push(Value::I32(0)));
                } else {
                    try_exec!(self.push(Value::I32(a.wrapping_rem(b))));
                }
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

            // ── i64 Arithmetic ──────────────────────────────────────
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
            results[i] = self.pop().unwrap_or(Value::I32(0));
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
