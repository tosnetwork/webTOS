//! WASM stack-machine interpreter with fuel-based metering.
//!
//! This is the core execution engine. It runs WASM bytecode one instruction
//! at a time, consuming fuel. When fuel runs out or a host call is needed,
//! execution pauses and the caller can resume.

#[path = "runtime/atomic.rs"]
mod atomic;
#[path = "runtime/simd.rs"]
mod simd;
#[path = "runtime/gc_ops.rs"]
mod gc_ops;
#[path = "runtime/fc_ops.rs"]
mod fc_ops;
#[path = "runtime/numeric.rs"]
mod numeric;
#[path = "runtime/memory.rs"]
mod memory;
#[path = "runtime/gc_helpers.rs"]
mod gc_helpers;
#[path = "runtime/float_helpers.rs"]
mod float_helpers;
#[path = "runtime/control.rs"]
mod control;

use alloc::vec;
use alloc::vec::Vec;
use crate::wasm::decoder::{WasmModule, ImportKind};
use crate::wasm::types::*;

/// Resolve an alias index without borrowing self.
#[inline]
fn resolve_alias(aliases: &[Option<usize>], idx: usize) -> usize {
    if idx < aliases.len() { aliases[idx].unwrap_or(idx) } else { idx }
}

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
    pub saved_block_depth: usize, // caller's block_depth to restore on return
    pub block_stack_base: usize,  // index in block_stack where this function's blocks start
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
            saved_block_depth: 0,
            block_stack_base: 0,
        }
    }
}

// ─── Block frame (for control flow) ─────────────────────────────────────────

/// Maximum number of catch clauses per try_table block.
const MAX_CATCH_CLAUSES: usize = 8;

/// A single catch clause within a try_table block.
#[derive(Clone, Copy)]
struct CatchClause {
    /// 0=catch(tag,label), 1=catch_ref(tag,label), 2=catch_all(label), 3=catch_all_ref(label)
    kind: u8,
    /// Tag index (only valid for kind 0 and 1).
    tag_idx: u32,
    /// Branch label depth (relative to the try_table's position in the block stack).
    label: u32,
}

impl CatchClause {
    const fn zero() -> Self {
        CatchClause { kind: 0, tag_idx: 0, label: 0 }
    }
}

/// Maximum number of catch handlers in a legacy try block.
const MAX_LEGACY_CATCHES: usize = 8;

/// A catch handler position within a legacy try block.
#[derive(Clone, Copy)]
struct LegacyCatch {
    /// PC of the catch/catch_all opcode (points to the byte AFTER the opcode+immediates).
    handler_pc: usize,
    /// Tag index for `catch` (u32::MAX for catch_all).
    tag_idx: u32,
}

impl LegacyCatch {
    const fn zero() -> Self {
        LegacyCatch { handler_pc: 0, tag_idx: 0 }
    }
}

/// Tracks Block/Loop/If control flow for branch targets.
#[derive(Clone, Copy)]
struct BlockFrame {
    /// The PC of the block start (for Loop, this is the branch target).
    start_pc: usize,
    /// The PC just past the matching End (for Block/If, this is the branch target).
    end_pc: usize,
    /// Stack depth at block entry.
    stack_base: usize,
    /// Number of values consumed/produced on branch.
    /// For blocks/if: this is the result count.
    /// For loops: this is the param count (branch restarts with params).
    result_count: u8,
    /// Number of result values produced when the block ends normally (falls through to End).
    /// For blocks/if: same as result_count.
    /// For loops: the actual result count from the block type.
    end_result_count: u8,
    /// True if this is a Loop (branch goes to start), false for Block/If (branch goes to end).
    is_loop: bool,
    /// True if this is a try_table block with catch clauses.
    is_try_table: bool,
    /// Number of catch clauses (0 for non-try_table blocks).
    catch_count: u8,
    /// Catch clauses for try_table blocks.
    catches: [CatchClause; MAX_CATCH_CLAUSES],
    /// True if this is a legacy try block (opcode 0x06).
    is_legacy_try: bool,
    /// Number of legacy catch handlers.
    legacy_catch_count: u8,
    /// Legacy catch handler positions.
    legacy_catches: [LegacyCatch; MAX_LEGACY_CATCHES],
    /// The tag_idx of the exception currently being handled (for rethrow). u32::MAX = none.
    legacy_exception_tag: u32,
    /// Index into WasmInstance.legacy_exception_store for rethrow values. u32::MAX = none.
    legacy_exception_store_idx: u32,
    /// Delegate label for legacy try-delegate blocks. u32::MAX = no delegate.
    legacy_delegate_label: u32,
}

impl BlockFrame {
    const fn zero() -> Self {
        BlockFrame {
            start_pc: 0,
            end_pc: 0,
            stack_base: 0,
            result_count: 0,
            end_result_count: 0,
            is_loop: false,
            is_try_table: false,
            catch_count: 0,
            catches: [CatchClause::zero(); MAX_CATCH_CLAUSES],
            is_legacy_try: false,
            legacy_catch_count: 0,
            legacy_catches: [LegacyCatch::zero(); MAX_LEGACY_CATCHES],
            legacy_exception_tag: u32::MAX,
            legacy_exception_store_idx: u32::MAX,
            legacy_delegate_label: u32::MAX,
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
    /// An exception was thrown: (tag_idx, exception values).
    Exception(u32, Vec<Value>),
}

// ─── Locals storage ─────────────────────────────────────────────────────────

/// Maximum total locals across all active call frames.
const MAX_TOTAL_LOCALS: usize = 65_536;

// ─── GC heap objects ─────────────────────────────────────────────────────────

/// A GC heap-allocated object (struct or array).
#[derive(Debug, Clone)]
pub enum GcObject {
    Struct { type_idx: u32, fields: Vec<Value> },
    Array { type_idx: u32, elements: Vec<Value> },
    /// Internalized extern (from any.convert_extern): wraps an externref into the any hierarchy
    Internalized { value: Value },
    /// Externalized any (from extern.convert_any): wraps an anyref into the extern hierarchy
    Externalized { value: Value },
}

impl GcObject {
    pub fn type_idx(&self) -> u32 {
        match self {
            GcObject::Struct { type_idx, .. } => *type_idx,
            GcObject::Array { type_idx, .. } => *type_idx,
            GcObject::Internalized { .. } | GcObject::Externalized { .. } => u32::MAX,
        }
    }
}

// ─── WASM instance ─────────────────────────────────────────────────────────

/// A running WASM instance.
pub struct WasmInstance {
    pub module: WasmModule,
    pub stack: Vec<Value>,
    pub stack_ptr: usize,
    pub locals: Vec<Value>,
    pub globals: Vec<Value>,
    /// Global index aliasing: if global_aliases[i] = Some(j), global i is an alias of global j.
    pub global_aliases: Vec<Option<usize>>,
    pub tables: Vec<Vec<Option<u32>>>,
    /// Table index aliasing: if table_aliases[i] = Some(j), table i is an alias of table j.
    pub table_aliases: Vec<Option<usize>>,
    /// Tracks which element segments have been dropped (by elem.drop or after active init).
    pub dropped_elems: Vec<bool>,
    /// Tracks which data segments have been dropped (by data.drop).
    pub dropped_data: Vec<bool>,
    pub memories: Vec<Vec<u8>>,
    pub memory_sizes: Vec<usize>,
    /// Memory index aliasing: if memory_aliases[i] = Some(j), memory i is an alias of memory j.
    pub memory_aliases: Vec<Option<usize>>,
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
    /// GC heap: heap-allocated structs and arrays.
    pub gc_heap: Vec<GcObject>,
    /// Re-evaluated element segment values (for GC proposal expression-based elements).
    pub elem_gc_values: Vec<Vec<Value>>,
    /// Storage for legacy EH exception values (for rethrow). Each entry is one caught exception's values.
    pub legacy_exception_store: Vec<Option<Vec<Value>>>,
    /// Reusable indices into legacy_exception_store.
    legacy_exception_free: Vec<u32>,
}

impl WasmInstance {
    /// Create a new instance from a decoded module with the given fuel budget.
    /// Create a new instance with the default runtime class (ProofGrade).
    pub fn new(module: WasmModule, fuel: u64) -> Result<Self, WasmError> {
        Self::with_class(module, fuel, DEFAULT_RUNTIME_CLASS)
    }

    /// Create a new instance with a specific runtime class.
    pub fn with_class(module: WasmModule, fuel: u64, runtime_class: RuntimeClass) -> Result<Self, WasmError> {
        // Initialize all memories from module.memories (includes imports + local defs)
        let mut memories: Vec<Vec<u8>> = Vec::with_capacity(module.memories.len().max(1));
        let mut memory_sizes: Vec<usize> = Vec::with_capacity(module.memories.len().max(1));
        if module.memories.is_empty() && module.has_memory {
            // Fallback for modules with memory but no MemoryDef entries (backward compat)
            let mem_pages = module.memory_min_pages as usize;
            let mem_size = mem_pages.saturating_mul(WASM_PAGE_SIZE);
            memories.push(vec![0u8; mem_size]);
            memory_sizes.push(mem_size);
        } else {
            for mdef in &module.memories {
                let mem_pages = mdef.min_pages as usize;
                let page_size = if let Some(log2) = mdef.page_size_log2 {
                    1usize << log2
                } else {
                    WASM_PAGE_SIZE
                };
                let mem_size = mem_pages.saturating_mul(page_size);
                memories.push(vec![0u8; mem_size]);
                memory_sizes.push(mem_size);
            }
        }

        // Initialize globals from module definitions.
        // For globals with init_global_ref, resolve sequentially so that each global
        // can reference previously initialized globals.
        let mut globals = Vec::with_capacity(module.globals.len());
        for g in &module.globals {
            if let Some(ref_idx) = g.init_global_ref {
                if let Some(&ref_val) = globals.get(ref_idx as usize) {
                    // The init_value was computed with global.get=0 at decode time.
                    // Add the actual referenced global's value.
                    let val = match (ref_val, g.init_value) {
                        (Value::I32(r), Value::I32(v)) => Value::I32(v.wrapping_add(r)),
                        (Value::I64(r), Value::I64(v)) => Value::I64(v.wrapping_add(r)),
                        (Value::F32(r), Value::F32(v)) => Value::F32(v + r),
                        (Value::F64(r), Value::F64(v)) => Value::F64(v + r),
                        (val, _) => val,
                    };
                    globals.push(val);
                } else {
                    globals.push(g.init_value);
                }
            } else {
                globals.push(g.init_value);
            }
        }

        // Initialize tables from module definitions (support multiple tables)
        // If a table has an init expression (GC proposal), evaluate it for default values.
        let mut tables: Vec<Vec<Option<u32>>> = Vec::with_capacity(module.tables.len());
        for t in &module.tables {
            let default_entry = if let Some(ref expr_bytes) = t.init_expr_bytes {
                let mut expr_pos = 0;
                let init_val = crate::wasm::decoder::eval_init_expr_with_globals(
                    expr_bytes, &mut expr_pos, &globals,
                );
                match init_val {
                    Ok(Value::NullRef) => None,
                    Ok(Value::I32(v)) if v >= 0 => Some(v as u32),
                    Ok(Value::GcRef(heap_idx)) => Some(heap_idx | 0x8000_0000),
                    _ => None,
                }
            } else {
                None
            };
            tables.push(vec![default_entry; t.min as usize]);
        }
        // Ensure at least one table exists if element segments reference table 0
        // (some modules have implicit table 0 via imports)

        // Total function count = imported functions + module-defined functions
        let num_imported_funcs = module.imports.iter().filter(|i| matches!(i.kind, ImportKind::Func(_))).count() as u32;
        let total_funcs = num_imported_funcs + module.functions.len() as u32;

        // Track dropped element/data segments
        let dropped_elems = vec![false; module.element_segments.len()];
        let dropped_data = vec![false; module.data_segments.len()];

        // Apply active element segments to tables
        use crate::wasm::decoder::ElemMode;
        for (seg_idx, seg) in module.element_segments.iter().enumerate() {
            if seg.mode != ElemMode::Active {
                continue;
            }
            let tbl_idx = seg.table_idx as usize;
            if tbl_idx >= tables.len() {
                return Err(WasmError::TableIndexOutOfBounds);
            }
            let offset = seg.offset as usize;
            let count = seg.func_indices.len();

            // Trap if segment goes out of bounds
            if offset.saturating_add(count) > tables[tbl_idx].len() {
                return Err(WasmError::TableIndexOutOfBounds);
            }

            // Trap if any function index is out of bounds (only for funcref tables)
            let is_func_table = tbl_idx < module.tables.len() && matches!(
                module.tables[tbl_idx].elem_type,
                ValType::FuncRef | ValType::TypedFuncRef | ValType::NonNullableFuncRef | ValType::NullableTypedFuncRef
            );
            let is_func_seg = matches!(seg.elem_type, ValType::FuncRef | ValType::TypedFuncRef | ValType::NonNullableFuncRef | ValType::NullableTypedFuncRef);
            if is_func_table && is_func_seg {
                for &func_idx in &seg.func_indices {
                    if func_idx != u32::MAX && func_idx >= total_funcs {
                        return Err(WasmError::UndefinedElement);
                    }
                }
            }

            for (i, &func_idx) in seg.func_indices.iter().enumerate() {
                if func_idx == u32::MAX {
                    tables[tbl_idx][offset + i] = None; // null ref
                } else {
                    tables[tbl_idx][offset + i] = Some(func_idx);
                }
            }
            // Active segments are considered dropped after initialization
            // (dropped_elems is not mutable yet, will set after inst creation)
            let _ = seg_idx;
        }

        let mut inst = WasmInstance {
            module,
            stack: vec![Value::I32(0); MAX_STACK],
            stack_ptr: 0,
            locals: vec![Value::I32(0); MAX_TOTAL_LOCALS],
            global_aliases: vec![None; globals.len()],
            globals,
            table_aliases: vec![None; tables.len()],
            tables,
            dropped_elems,
            dropped_data,
            memories,
            memory_aliases: vec![None; memory_sizes.len()],
            memory_sizes,
            pc: 0,
            fuel,
            call_stack: vec![CallFrame::zero(); MAX_CALL_DEPTH],
            call_depth: 0,
            block_stack: vec![BlockFrame::zero(); MAX_BLOCK_DEPTH],
            block_depth: 0,
            finished: false,
            runtime_class,
            gc_heap: Vec::new(),
            elem_gc_values: Vec::new(),
            legacy_exception_store: Vec::new(),
            legacy_exception_free: Vec::new(),
        };

        // Apply active data segments to memory (skip passive segments)
        for seg in &inst.module.data_segments {
            if !seg.is_active {
                continue; // passive segment — applied later by memory.init
            }
            let mem_idx = seg.memory_idx as usize;
            if mem_idx >= inst.memories.len() {
                return Err(WasmError::MemoryOutOfBounds);
            }
            let dst_start = seg.offset as usize;
            let src_start = seg.data_offset;
            let len = seg.data_len;

            // Trap if segment goes out of bounds of memory
            if dst_start.saturating_add(len) > inst.memory_sizes[mem_idx] {
                return Err(WasmError::MemoryOutOfBounds);
            }

            if src_start.saturating_add(len) <= inst.module.code.len() {
                inst.memories[mem_idx][dst_start..dst_start + len]
                    .copy_from_slice(&inst.module.code[src_start..src_start + len]);
            }
        }

        // Mark active and declarative element segments as dropped
        for (i, seg) in inst.module.element_segments.iter().enumerate() {
            if seg.mode == ElemMode::Active || seg.mode == ElemMode::Declarative {
                inst.dropped_elems[i] = true;
            }
        }

        // Evaluate GC const expressions for globals that need deferred evaluation
        inst.eval_gc_globals();

        // Re-evaluate expression-based element segment items (GC proposal)
        inst.eval_gc_elem_exprs();

        // Table init expressions are already applied during table construction above,
        // before elem segments, so no need to re-apply here.

        Ok(inst)
    }

    // ─── Table helpers ──────────────────────────────────────────────────

    /// Get a reference to a table by index (defaults to table 0).
    fn table(&self, tbl_idx: usize) -> &Vec<Option<u32>> {
        &self.tables[self.tbl(tbl_idx)]
    }

    /// Get a mutable reference to a table by index (defaults to table 0).
    fn table_mut(&mut self, tbl_idx: usize) -> &mut Vec<Option<u32>> {
        let resolved = resolve_alias(&self.table_aliases, tbl_idx);
        &mut self.tables[resolved]
    }

    // ─── Tag helpers (exception handling) ──────────────────────────────

    /// Get the function type index for a tag (considering imports).
    /// Tag index space: imported tags first, then local tags.
    fn tag_type_idx(&self, tag_idx: u32) -> Option<u32> {
        let mut import_tag_count = 0u32;
        for imp in &self.module.imports {
            if let ImportKind::Tag(type_idx) = imp.kind {
                if import_tag_count == tag_idx {
                    return Some(type_idx);
                }
                import_tag_count += 1;
            }
        }
        let local_tag_idx = tag_idx.checked_sub(import_tag_count)?;
        self.module.tag_types.get(local_tag_idx as usize).copied()
    }

    /// Get the parameter count for a tag's type signature.
    fn tag_param_count(&self, tag_idx: u32) -> usize {
        if let Some(type_idx) = self.tag_type_idx(tag_idx) {
            if let Some(ft) = self.module.func_types.get(type_idx as usize) {
                return ft.param_count as usize;
            }
        }
        0
    }

    /// Check if two tag indices refer to the same tag.
    /// Tags are the same if they have the same index, or if they are both imports
    /// from the same (module, name) pair.
    fn tags_match(&self, tag_a: u32, tag_b: u32) -> bool {
        if tag_a == tag_b {
            return true;
        }
        // Check if both are imports from the same (module, name)
        let import_a = self.tag_import_identity(tag_a);
        let import_b = self.tag_import_identity(tag_b);
        if let (Some((ma, fa)), Some((mb, fb))) = (import_a, import_b) {
            if ma == mb && fa == fb {
                return true;
            }
            // Also check if both come from the same module but different export names
            // that resolve to the same tag index (aliased exports)
            if ma == mb {
                // Same source module — they might be aliased exports of the same tag
                // We consider them matching (the runner sets this up for aliased imports)
                return true;
            }
        }
        false
    }

    /// Get the (module_name, field_name) for an imported tag, or None for local tags.
    fn tag_import_identity(&self, tag_idx: u32) -> Option<(&[u8], &[u8])> {
        let mut import_tag_count = 0u32;
        for imp in &self.module.imports {
            if let ImportKind::Tag(_) = imp.kind {
                if import_tag_count == tag_idx {
                    let mod_name = self.module.get_name(imp.module_name_offset, imp.module_name_len);
                    let field_name = self.module.get_name(imp.field_name_offset, imp.field_name_len);
                    return Some((mod_name, field_name));
                }
                import_tag_count += 1;
            }
        }
        None
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

    /// Resolve table alias: if table_aliases[idx] is set, redirect to the alias target.
    #[inline]
    fn tbl(&self, idx: usize) -> usize {
        resolve_alias(&self.table_aliases, idx)
    }

    /// Get memory slice reference by index, defaulting to memory 0.
    #[inline]
    fn mem(&self, idx: usize) -> &Vec<u8> {
        let ri = resolve_alias(&self.memory_aliases, idx);
        if ri < self.memories.len() { &self.memories[ri] } else { &self.memories[0] }
    }

    /// Get mutable memory slice reference by index, defaulting to memory 0.
    #[inline]
    fn mem_mut(&mut self, idx: usize) -> &mut Vec<u8> {
        let ri = resolve_alias(&self.memory_aliases, idx);
        if ri < self.memories.len() { &mut self.memories[ri] } else { &mut self.memories[0] }
    }

    /// Get memory size by index, defaulting to memory 0.
    #[inline]
    fn mem_size(&self, idx: usize) -> usize {
        let ri = resolve_alias(&self.memory_aliases, idx);
        if ri < self.memory_sizes.len() { self.memory_sizes[ri] } else { 0 }
    }

    /// Read a memarg: alignment flags + optional memory index + offset.
    /// Multi-memory: if bit 6 of flags is set, read an explicit memory index.
    /// Returns (mem_idx, offset).
    fn read_memarg(&mut self) -> Result<(usize, u32), WasmError> {
        let flags = self.read_leb128_u32()?;
        let mem_idx = if self.module.multi_memory_enabled && (flags & (1 << 6)) != 0 {
            self.read_leb128_u32()? as usize
        } else {
            0
        };
        let offset = self.read_leb128_u32()?;
        Ok((mem_idx, offset))
    }

    fn mem_load_i32(&self, mem_idx: usize, addr: usize) -> Result<i32, WasmError> {
        let msz = self.mem_size(mem_idx);
        if addr + 4 > msz {
            return Err(WasmError::MemoryOutOfBounds);
        }
        let m = self.mem(mem_idx);
        let bytes = [m[addr], m[addr + 1], m[addr + 2], m[addr + 3]];
        Ok(i32::from_le_bytes(bytes))
    }

    fn mem_load_i64(&self, mem_idx: usize, addr: usize) -> Result<i64, WasmError> {
        let msz = self.mem_size(mem_idx);
        if addr + 8 > msz {
            return Err(WasmError::MemoryOutOfBounds);
        }
        let m = self.mem(mem_idx);
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&m[addr..addr + 8]);
        Ok(i64::from_le_bytes(bytes))
    }

    fn mem_store_i32(&mut self, mem_idx: usize, addr: usize, val: i32) -> Result<(), WasmError> {
        let msz = self.mem_size(mem_idx);
        if addr + 4 > msz {
            return Err(WasmError::MemoryOutOfBounds);
        }
        let bytes = val.to_le_bytes();
        self.mem_mut(mem_idx)[addr..addr + 4].copy_from_slice(&bytes);
        Ok(())
    }

    fn mem_store_i64(&mut self, mem_idx: usize, addr: usize, val: i64) -> Result<(), WasmError> {
        let msz = self.mem_size(mem_idx);
        if addr + 8 > msz {
            return Err(WasmError::MemoryOutOfBounds);
        }
        let bytes = val.to_le_bytes();
        self.mem_mut(mem_idx)[addr..addr + 8].copy_from_slice(&bytes);
        Ok(())
    }

    // ─── Sub-word memory helpers ─────────────────────────────────────────

    fn mem_load_u8(&self, mem_idx: usize, addr: usize) -> Result<u8, WasmError> {
        if addr >= self.mem_size(mem_idx) { return Err(WasmError::MemoryOutOfBounds); }
        Ok(self.mem(mem_idx)[addr])
    }

    fn mem_load_u16(&self, mem_idx: usize, addr: usize) -> Result<u16, WasmError> {
        if addr.checked_add(2).ok_or(WasmError::MemoryOutOfBounds)? > self.mem_size(mem_idx) {
            return Err(WasmError::MemoryOutOfBounds);
        }
        let m = self.mem(mem_idx);
        Ok(u16::from_le_bytes([m[addr], m[addr + 1]]))
    }

    fn mem_load_u32(&self, mem_idx: usize, addr: usize) -> Result<u32, WasmError> {
        if addr.checked_add(4).ok_or(WasmError::MemoryOutOfBounds)? > self.mem_size(mem_idx) {
            return Err(WasmError::MemoryOutOfBounds);
        }
        let m = self.mem(mem_idx);
        Ok(u32::from_le_bytes([m[addr], m[addr + 1], m[addr + 2], m[addr + 3]]))
    }

    fn mem_store_u8(&mut self, mem_idx: usize, addr: usize, val: u8) -> Result<(), WasmError> {
        if addr >= self.mem_size(mem_idx) { return Err(WasmError::MemoryOutOfBounds); }
        self.mem_mut(mem_idx)[addr] = val;
        Ok(())
    }

    fn mem_store_u16(&mut self, mem_idx: usize, addr: usize, val: u16) -> Result<(), WasmError> {
        if addr.checked_add(2).ok_or(WasmError::MemoryOutOfBounds)? > self.mem_size(mem_idx) {
            return Err(WasmError::MemoryOutOfBounds);
        }
        let bytes = val.to_le_bytes();
        self.mem_mut(mem_idx)[addr..addr + 2].copy_from_slice(&bytes);
        Ok(())
    }

    fn mem_store_u32(&mut self, mem_idx: usize, addr: usize, val: u32) -> Result<(), WasmError> {
        if addr.checked_add(4).ok_or(WasmError::MemoryOutOfBounds)? > self.mem_size(mem_idx) {
            return Err(WasmError::MemoryOutOfBounds);
        }
        let bytes = val.to_le_bytes();
        self.mem_mut(mem_idx)[addr..addr + 4].copy_from_slice(&bytes);
        Ok(())
    }


    // ─── Type comparison ─────────────────────────────────────────────────

    /// Check if two type indices refer to structurally equivalent function types.
    fn types_structurally_equal(&self, type_a: u32, type_b: u32) -> bool {
        let types = &self.module.func_types;
        let (a_idx, b_idx) = (type_a as usize, type_b as usize);
        if a_idx >= types.len() || b_idx >= types.len() {
            return false;
        }
        let a = &types[a_idx];
        let b = &types[b_idx];
        if a.param_count != b.param_count || a.result_count != b.result_count {
            return false;
        }
        for i in 0..a.param_count as usize {
            if a.params[i] != b.params[i] {
                return false;
            }
        }
        for i in 0..a.result_count as usize {
            if a.results[i] != b.results[i] {
                return false;
            }
        }
        true
    }

    // ─── Block type decoding ────────────────────────────────────────────

    /// Decode a block type and return (param_count, result_count).
    fn decode_block_type(&self, block_type: i32) -> (u8, u8) {
        if block_type == -0x40 {
            // void block
            (0, 0)
        } else if block_type < 0 {
            // valtype: i32=-1, i64=-2, f32=-3, f64=-4, v128=-5
            // Also: ref null ht (-0x1D), ref ht (-0x1C), funcref (-0x10), externref (-0x11)
            (0, 1)
        } else {
            // type index: look up function type
            let type_idx = block_type as usize;
            if type_idx < self.module.func_types.len() {
                let ft = &self.module.func_types[type_idx];
                (ft.param_count, ft.result_count)
            } else {
                (0, 0)
            }
        }
    }

    /// Read a block type from the bytecode, handling multi-byte ref types.
    /// Returns the block type as i32 (same as read_leb128_i32), but additionally
    /// consumes any following heap type for ref type block types.
    fn read_block_type(&mut self) -> Result<i32, WasmError> {
        let block_type = self.read_leb128_i32()?;
        // For ref types (0x63 = -0x1D, 0x64 = -0x1C), read the heap type
        if block_type == -0x1D || block_type == -0x1C {
            let _heap_type = self.read_leb128_i32()?;
        }
        Ok(block_type)
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
        let bf = self.block_stack[self.block_depth];
        self.release_block_resources(bf);
        self.block_stack[self.block_depth] = BlockFrame::zero();
        Ok(bf)
    }

    #[inline]
    fn alloc_legacy_exception_values(&mut self, values: &[Value]) -> u32 {
        if let Some(idx) = self.legacy_exception_free.pop() {
            self.legacy_exception_store[idx as usize] = Some(values.to_vec());
            idx
        } else {
            let idx = self.legacy_exception_store.len() as u32;
            self.legacy_exception_store.push(Some(values.to_vec()));
            idx
        }
    }

    #[inline]
    fn release_legacy_exception_values(&mut self, idx: u32) {
        if idx == u32::MAX {
            return;
        }
        if let Some(slot) = self.legacy_exception_store.get_mut(idx as usize) {
            if slot.take().is_some() {
                self.legacy_exception_free.push(idx);
            }
        }
    }

    #[inline]
    fn release_block_resources(&mut self, bf: BlockFrame) {
        self.release_legacy_exception_values(bf.legacy_exception_store_idx);
    }

    fn truncate_blocks(&mut self, new_depth: usize) {
        while self.block_depth > new_depth {
            self.block_depth -= 1;
            let bf = self.block_stack[self.block_depth];
            self.release_block_resources(bf);
            self.block_stack[self.block_depth] = BlockFrame::zero();
        }
    }

    /// Scan a legacy try block to find catch/catch_all handler positions and the end PC.


    /// Branch to the label at the given depth on the block stack.
    fn branch(&mut self, depth: u32) -> Result<(), WasmError> {
        // Branch depth is relative to the current function's block scope.
        let base = if self.call_depth > 0 {
            self.call_stack[self.call_depth - 1].block_stack_base
        } else {
            0
        };
        let func_block_count = self.block_depth - base;
        if depth as usize >= func_block_count {
            return Err(WasmError::BranchDepthExceeded);
        }
        let target_idx = self.block_depth - 1 - depth as usize;
        let target = self.block_stack[target_idx];

        if target.is_loop {
            // Branch to loop start — pop all blocks above the loop
            // but keep the loop block itself (we re-enter it)
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
            self.pc = target.start_pc;
            // Pop blocks above the loop, keeping the loop itself
            self.truncate_blocks(target_idx + 1);
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
            self.truncate_blocks(target_idx);
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

        // Push call frame, saving caller's block_depth
        let frame = CallFrame {
            func_idx,
            return_pc: self.pc,
            code_offset: func_code_offset,
            code_end: func_code_offset + func_code_len,
            local_base,
            local_count: total_locals,
            stack_base: self.stack_ptr,
            result_count,
            saved_block_depth: self.block_depth,
            block_stack_base: self.block_depth,
        };

        self.call_stack[self.call_depth] = frame;
        self.call_depth += 1;

        // Set PC to function body
        self.pc = func_code_offset;

        // NOTE: We do NOT reset block_depth. The callee's blocks stack on top of the
        // caller's blocks so they don't clobber each other.

        // Push an implicit block frame for the function body.
        // This allows `br 0` at the function level to work correctly (behaves like return).
        self.push_block(BlockFrame {
            start_pc: func_code_offset,
            end_pc: func_code_offset + func_code_len,
            stack_base: self.stack_ptr,
            result_count,
            end_result_count: result_count,
            is_loop: false,
            ..BlockFrame::zero()
        })?;

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
        // Reset execution state for new call (important after traps)
        self.finished = false;
        self.call_depth = 0;
        self.truncate_blocks(0);

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

    /// Resume execution after a host call that threw an exception.
    /// The exception will be propagated through the caller's try_table handlers.
    pub fn resume_with_exception(&mut self, tag_idx: u32, values: Vec<Value>) -> ExecResult {
        // Inject the exception into the running instance's exception handling
        match self.handle_exception(tag_idx, &values) {
            Ok(()) => self.run(), // Exception was caught, continue
            Err(()) => ExecResult::Exception(tag_idx, values), // Propagate
        }
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
                ExecResult::Ok => {
                    if self.finished {
                        return ExecResult::Ok;
                    }
                }
                ExecResult::Exception(tag_idx, values) => {
                    match self.handle_exception(tag_idx, &values) {
                        Ok(()) => {} // Exception was caught, execution continues
                        Err(_) => {
                            // No catch found in any frame — propagate as uncaught exception
                            return ExecResult::Exception(tag_idx, values);
                        }
                    }
                }
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
                let block_type = try_exec!(self.read_block_type());
                let (param_count, result_count) = self.decode_block_type(block_type);
                // We need to find the matching End to know end_pc.
                let start_pc = self.pc;
                let end_pc = try_exec!(self.skip_to_end());
                self.pc = start_pc;
                // For multi-value blocks with params, the stack_base accounts for params
                let stack_base = self.stack_ptr - param_count as usize;
                try_exec!(self.push_block(BlockFrame {
                    start_pc,
                    end_pc,
                    stack_base,
                    result_count,
                    end_result_count: result_count,
                    is_loop: false,
                    ..BlockFrame::zero()
                }));
            }
            0x03 => {
                // loop
                let block_type = try_exec!(self.read_block_type());
                let (param_count, result_count) = self.decode_block_type(block_type);
                let start_pc = self.pc;
                let saved_pc = self.pc;
                let end_pc = try_exec!(self.skip_to_end());
                self.pc = saved_pc;
                // Loop blocks: on branch, jump back to start with params consumed
                // The result_count for loop branch is the param_count (loop restarts with params)
                let stack_base = self.stack_ptr - param_count as usize;
                try_exec!(self.push_block(BlockFrame {
                    start_pc,
                    end_pc,
                    stack_base,
                    result_count: param_count,
                    end_result_count: result_count,
                    is_loop: true,
                    ..BlockFrame::zero()
                }));
            }
            0x04 => {
                // if — two-pass scan: first find else/end boundary, then find true end
                let block_type = try_exec!(self.read_block_type());
                let (param_count, result_count) = self.decode_block_type(block_type);
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

                let stack_base = self.stack_ptr - param_count as usize;
                if condition != 0 {
                    // Execute the "then" branch; block end_pc = true end of if/else/end
                    self.pc = body_pc;
                    try_exec!(self.push_block(BlockFrame {
                        start_pc: body_pc,
                        end_pc: true_end_pc,
                        stack_base,
                        result_count,
                        end_result_count: result_count,
                        is_loop: false,
                        ..BlockFrame::zero()
                    }));
                } else if has_else {
                    // Condition false, has else: execute the else branch
                    self.pc = else_or_end_pc; // right after the 0x05 else opcode
                    try_exec!(self.push_block(BlockFrame {
                        start_pc: else_or_end_pc,
                        end_pc: true_end_pc,
                        stack_base,
                        result_count,
                        end_result_count: result_count,
                        is_loop: false,
                        ..BlockFrame::zero()
                    }));
                } else {
                    // Condition false, no else: skip past end entirely
                    self.pc = true_end_pc;
                }
            }
            0x05 => {
                // else — skip to end of if block (for the "then" path)
                let base05 = if self.call_depth > 0 { self.call_stack[self.call_depth - 1].block_stack_base } else { 0 };
                if self.block_depth > base05 {
                    let bf = self.block_stack[self.block_depth - 1];
                    self.pc = bf.end_pc;
                    let _ = self.pop_block();
                }
            }
            0x0B => {
                // end
                let base0b = if self.call_depth > 0 { self.call_stack[self.call_depth - 1].block_stack_base } else { 0 };
                if self.block_depth > base0b {
                    let bf = try_exec!(self.pop_block());
                    // Adjust stack: save results, reset to block's stack_base, push results back.
                    // This handles multi-value blocks where stack_base includes params.
                    // Use end_result_count for normal block end (not branch).
                    let result_count = bf.end_result_count as usize;
                    if self.stack_ptr != bf.stack_base + result_count {
                        let mut results = [Value::I32(0); MAX_RESULTS];
                        for i in (0..result_count).rev() {
                            results[i] = match self.pop() {
                                Ok(v) => v,
                                Err(_) => Value::I32(0),
                            };
                        }
                        self.stack_ptr = bf.stack_base;
                        for i in 0..result_count {
                            let _ = self.push(results[i]);
                        }
                    }
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
                // br_table — streaming: don't store all labels, just find the target
                let count = try_exec!(self.read_leb128_u32()) as usize;
                let idx = try_exec!(self.pop_i32()) as usize;
                let mut target_depth = 0u32;
                for i in 0..count {
                    let label = try_exec!(self.read_leb128_u32());
                    if i == idx {
                        target_depth = label;
                    }
                }
                let default_label = try_exec!(self.read_leb128_u32());
                let depth = if idx < count { target_depth } else { default_label };
                try_exec!(self.branch(depth));
            }
            0x08 => {
                // throw: read tag_idx, pop params, raise exception
                let tag_idx = try_exec!(self.read_leb128_u32());
                let param_count = self.tag_param_count(tag_idx);
                let mut values = Vec::with_capacity(param_count);
                for _ in 0..param_count {
                    values.push(try_exec!(self.pop()));
                }
                values.reverse(); // params were popped in reverse order
                return ExecResult::Exception(tag_idx, values);
            }
            0x0A => {
                // throw_ref: pop exnref, re-throw
                let exnref = try_exec!(self.pop());
                match exnref {
                    Value::NullRef => return ExecResult::Trap(WasmError::NullReference),
                    Value::I32(tag_idx) => {
                        // Our exnref encodes only the tag_idx; values are lost on re-throw
                        // For a complete implementation we'd store full exception objects
                        return ExecResult::Exception(tag_idx as u32, Vec::new());
                    }
                    _ => return ExecResult::Trap(WasmError::NullReference),
                }
            }
            0x0F => {
                // return
                return self.do_return();
            }
            0x1F => {
                // try_table: block with catch clauses
                let block_type = try_exec!(self.read_block_type());
                let (param_count, result_count) = self.decode_block_type(block_type);
                // Read catch clauses
                let catch_count = try_exec!(self.read_leb128_u32()) as usize;
                let effective_count = catch_count.min(MAX_CATCH_CLAUSES);
                let mut catches = [CatchClause::zero(); MAX_CATCH_CLAUSES];
                for i in 0..catch_count {
                    let clause_kind = try_exec!(self.read_byte());
                    let (tag_idx, label) = match clause_kind {
                        0 | 1 => { // catch, catch_ref: tag_idx + label
                            let t = try_exec!(self.read_leb128_u32());
                            let l = try_exec!(self.read_leb128_u32());
                            (t, l)
                        }
                        2 | 3 => { // catch_all, catch_all_ref: label only
                            let l = try_exec!(self.read_leb128_u32());
                            (0, l)
                        }
                        _ => (0, 0),
                    };
                    if i < effective_count {
                        catches[i] = CatchClause { kind: clause_kind, tag_idx, label };
                    }
                }
                // Set up block frame with catch clause info
                let start_pc = self.pc;
                let end_pc = try_exec!(self.skip_to_end());
                self.pc = start_pc;
                let stack_base = self.stack_ptr - param_count as usize;
                try_exec!(self.push_block(BlockFrame {
                    start_pc,
                    end_pc,
                    stack_base,
                    result_count,
                    end_result_count: result_count,
                    is_loop: false,
                    is_try_table: true,
                    catch_count: effective_count as u8,
                    catches,
                    ..BlockFrame::zero()
                }));
            }
            0x06 => {
                // Legacy try: opens a block with catch handlers
                let block_type = try_exec!(self.read_block_type());
                let (param_count, result_count) = self.decode_block_type(block_type);
                let (legacy_catches, legacy_catch_count, end_pc, delegate_label) = try_exec!(self.scan_legacy_try());
                let stack_base = self.stack_ptr - param_count as usize;
                let mut frame = BlockFrame::zero();
                frame.start_pc = self.pc;
                frame.end_pc = end_pc;
                frame.stack_base = stack_base;
                frame.result_count = result_count;
                frame.end_result_count = result_count;
                frame.is_legacy_try = true;
                frame.legacy_catch_count = legacy_catch_count;
                frame.legacy_catches = legacy_catches;
                frame.legacy_delegate_label = delegate_label;
                try_exec!(self.push_block(frame));
            }
            0x07 => {
                // Legacy catch tag_idx: during normal execution, skip to end
                // (we've finished the try body without throwing)
                let _tag_idx = try_exec!(self.read_leb128_u32());
                // Find the enclosing legacy try block and jump past it
                let base07 = if self.call_depth > 0 { self.call_stack[self.call_depth - 1].block_stack_base } else { 0 };
                if self.block_depth > base07 {
                    let bf = self.block_stack[self.block_depth - 1];
                    if bf.is_legacy_try {
                        let rc = bf.end_result_count as usize;
                        let mut results = [Value::I32(0); MAX_RESULTS];
                        for i in (0..rc).rev() {
                            results[i] = try_exec!(self.pop());
                        }
                        self.stack_ptr = bf.stack_base;
                        for i in 0..rc {
                            let _ = self.push(results[i]);
                        }
                        self.pc = bf.end_pc;
                        let _ = self.pop_block();
                    }
                }
            }
            0x09 => {
                // Legacy rethrow: re-throw the exception from a catch handler
                let label = try_exec!(self.read_leb128_u32());
                // Find the enclosing try/catch at the given label depth
                let target_depth = if label as usize <= self.block_depth {
                    self.block_depth - label as usize - 1
                } else {
                    return ExecResult::Trap(WasmError::BranchDepthExceeded);
                };
                // rethrow's label indexes through all blocks on the stack
                let mut found_tag = u32::MAX;
                let mut found_values: Vec<Value> = Vec::new();
                // The label refers to a block depth: label 0 = current block, etc.
                let target_idx = if (label as usize) < self.block_depth {
                    self.block_depth - 1 - label as usize
                } else {
                    return ExecResult::Trap(WasmError::BranchDepthExceeded);
                };
                let _ = target_depth;
                // The target block should be a legacy try with an active exception
                let bf = &self.block_stack[target_idx];
                if bf.is_legacy_try && bf.legacy_exception_tag != u32::MAX {
                    found_tag = bf.legacy_exception_tag;
                    let store_idx = bf.legacy_exception_store_idx as usize;
                    if let Some(Some(values)) = self.legacy_exception_store.get(store_idx) {
                        found_values = values.clone();
                    }
                }
                if found_tag == u32::MAX {
                    return ExecResult::Trap(WasmError::UncaughtException);
                }
                // Propagate the exception
                match self.handle_exception(found_tag, &found_values) {
                    Ok(()) => {}
                    Err(()) => {
                        return ExecResult::Exception(found_tag, found_values);
                    }
                }
            }
            0x18 => {
                // Legacy delegate label: during normal execution, acts like `end`
                let _label = try_exec!(self.read_leb128_u32());
                // Pop the try block frame (normal execution — no exception)
                if self.block_depth > 0 {
                    let bf = try_exec!(self.pop_block());
                    let rc = bf.end_result_count as usize;
                    let mut results = [Value::I32(0); 8];
                    for i in (0..rc).rev() {
                        results[i] = try_exec!(self.pop());
                    }
                    self.stack_ptr = bf.stack_base;
                    for i in 0..rc {
                        try_exec!(self.push(results[i]));
                    }
                }
            }
            0x19 => {
                // Legacy catch_all: during normal execution, skip to end
                let base19 = if self.call_depth > 0 { self.call_stack[self.call_depth - 1].block_stack_base } else { 0 };
                if self.block_depth > base19 {
                    let bf = self.block_stack[self.block_depth - 1];
                    if bf.is_legacy_try {
                        let rc = bf.end_result_count as usize;
                        let mut results = [Value::I32(0); MAX_RESULTS];
                        for i in (0..rc).rev() {
                            results[i] = try_exec!(self.pop());
                        }
                        self.stack_ptr = bf.stack_base;
                        for i in 0..rc {
                            let _ = self.push(results[i]);
                        }
                        self.pc = bf.end_pc;
                        let _ = self.pop_block();
                    }
                }
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
                // return_call (tail call proposal): tail-call optimization
                let func_idx = try_exec!(self.read_leb128_u32());

                // Get the number of parameters the target function expects
                let param_count = if (func_idx as usize) < self.module.func_import_count() {
                    match self.module.func_import_type(func_idx) {
                        Some(ti) => {
                            if (ti as usize) < self.module.func_types.len() {
                                self.module.func_types[ti as usize].param_count as usize
                            } else { 0 }
                        }
                        None => 0,
                    }
                } else {
                    let li = (func_idx as usize) - self.module.func_import_count();
                    if li < self.module.functions.len() {
                        let ti = self.module.functions[li].type_idx as usize;
                        if ti < self.module.func_types.len() {
                            self.module.func_types[ti].param_count as usize
                        } else { 0 }
                    } else { 0 }
                };

                // Save the arguments from the stack
                let mut args = [Value::I32(0); MAX_PARAMS];
                for i in (0..param_count).rev() {
                    args[i] = try_exec!(self.pop());
                }

                // Pop current frame (tail call: reuse the caller's slot)
                if self.call_depth > 0 {
                    let frame = self.call_stack[self.call_depth - 1];
                    self.call_depth -= 1;
                    self.stack_ptr = frame.stack_base;
                    self.pc = frame.return_pc;
                    self.truncate_blocks(frame.saved_block_depth);
                }

                // Push arguments back for the new function
                for i in 0..param_count {
                    try_exec!(self.push(args[i]));
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
                let table_idx = try_exec!(self.read_leb128_u32()) as usize;
                let elem_idx = try_exec!(self.pop_i32()) as usize;
                let tbl = if table_idx < self.tables.len() { &self.tables[self.tbl(table_idx)] } else { return ExecResult::Trap(WasmError::TableIndexOutOfBounds); };
                if elem_idx >= tbl.len() {
                    return ExecResult::Trap(WasmError::UndefinedElement);
                }
                let func_idx = match tbl[elem_idx] {
                    Some(idx) => idx,
                    None => return ExecResult::Trap(WasmError::UninitializedElement(elem_idx as u32)),
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
                    // GC: actual type must be a subtype of expected type
                    if !self.gc_is_subtype(actual_type_idx, type_idx) {
                        return ExecResult::Trap(WasmError::IndirectCallTypeMismatch);
                    }
                }

                // Get param count for the target function
                let param_count = if (type_idx as usize) < self.module.func_types.len() {
                    self.module.func_types[type_idx as usize].param_count as usize
                } else { 0 };

                // Save arguments
                let mut args = [Value::I32(0); MAX_PARAMS];
                for i in (0..param_count).rev() {
                    args[i] = try_exec!(self.pop());
                }

                // Pop current frame (tail call)
                if self.call_depth > 0 {
                    let frame = self.call_stack[self.call_depth - 1];
                    self.call_depth -= 1;
                    self.stack_ptr = frame.stack_base;
                    self.pc = frame.return_pc;
                    self.truncate_blocks(frame.saved_block_depth);
                }

                // Push arguments back
                for i in 0..param_count {
                    try_exec!(self.push(args[i]));
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

            0x14 => {
                // call_ref (typed function references proposal)
                let _type_idx = try_exec!(self.read_leb128_u32());
                let func_ref = try_exec!(self.pop_i32());
                if func_ref < 0 {
                    return ExecResult::Trap(WasmError::NullFunctionReference);
                }
                let func_idx = func_ref as u32;
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
            0x15 => {
                // return_call_ref (typed function references proposal)
                let type_idx = try_exec!(self.read_leb128_u32());
                let func_ref_val = try_exec!(self.pop());
                let func_ref = match func_ref_val {
                    Value::NullRef => -1,
                    Value::I32(v) => v,
                    Value::GcRef(idx) => idx as i32,
                    _ => -1,
                };
                if func_ref < 0 {
                    return ExecResult::Trap(WasmError::NullFunctionReference);
                }
                let func_idx = func_ref as u32;

                // Get the number of parameters the target function expects
                let param_count = if (type_idx as usize) < self.module.func_types.len() {
                    self.module.func_types[type_idx as usize].param_count as usize
                } else if (func_idx as usize) < self.module.func_import_count() {
                    match self.module.func_import_type(func_idx) {
                        Some(ti) => {
                            if (ti as usize) < self.module.func_types.len() {
                                self.module.func_types[ti as usize].param_count as usize
                            } else { 0 }
                        }
                        None => 0,
                    }
                } else {
                    let li = (func_idx as usize) - self.module.func_import_count();
                    if li < self.module.functions.len() {
                        let ti = self.module.functions[li].type_idx as usize;
                        if ti < self.module.func_types.len() {
                            self.module.func_types[ti].param_count as usize
                        } else { 0 }
                    } else { 0 }
                };

                // Save the arguments from the stack
                let mut args = [Value::I32(0); MAX_PARAMS];
                for i in (0..param_count).rev() {
                    args[i] = try_exec!(self.pop());
                }

                // Pop current frame (tail call: reuse the caller's slot)
                if self.call_depth > 0 {
                    let frame = self.call_stack[self.call_depth - 1];
                    self.call_depth -= 1;
                    self.stack_ptr = frame.stack_base;
                    self.pc = frame.return_pc;
                    self.truncate_blocks(frame.saved_block_depth);
                }

                // Push arguments back for the new function
                for i in 0..param_count {
                    try_exec!(self.push(args[i]));
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
                let table_idx = try_exec!(self.read_leb128_u32()) as usize;
                let elem_idx = try_exec!(self.pop_i32()) as usize;
                // Look up function in table
                let tbl = if table_idx < self.tables.len() { table_idx } else { 0 };
                if tbl >= self.tables.len() || elem_idx >= self.tables[self.tbl(tbl)].len() {
                    return ExecResult::Trap(WasmError::UndefinedElement);
                }
                let func_idx = match self.tables[self.tbl(tbl)][elem_idx] {
                    Some(idx) => idx,
                    None => return ExecResult::Trap(WasmError::UninitializedElement(elem_idx as u32)),
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
                    // GC: actual type must be a subtype of expected type
                    if !self.gc_is_subtype(actual_type_idx, type_idx) {
                        return ExecResult::Trap(WasmError::IndirectCallTypeMismatch);
                    }
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
                // select (untyped)
                let c = try_exec!(self.pop_i32());
                let val2 = try_exec!(self.pop());
                let val1 = try_exec!(self.pop());
                try_exec!(self.push(if c != 0 { val1 } else { val2 }));
            }
            0x1C => {
                // select (typed) — has a vector of value types
                let count = try_exec!(self.read_leb128_u32());
                for _ in 0..count {
                    let _ = try_exec!(self.read_leb128_u32()); // skip type annotations
                }
                let c = try_exec!(self.pop_i32());
                let val2 = try_exec!(self.pop());
                let val1 = try_exec!(self.pop());
                try_exec!(self.push(if c != 0 { val1 } else { val2 }));
            }
            0xD0 => {
                // ref.null heaptype
                let _ = try_exec!(self.read_leb128_i32());
                try_exec!(self.push(Value::NullRef)); // null ref sentinel
            }
            0xD1 => {
                // ref.is_null
                let val = try_exec!(self.pop());
                let is_null = match val {
                    Value::NullRef => 1i32,
                    Value::I32(-1) => 1i32, // legacy null sentinel (for func/extern refs from tables)
                    _ => 0i32,
                };
                try_exec!(self.push(Value::I32(is_null)));
            }
            0xD2 => {
                // ref.func funcidx
                let idx = try_exec!(self.read_leb128_u32());
                try_exec!(self.push(Value::I32(idx as i32)));
            }
            0xD3 => {
                // ref.eq: pop two eqrefs, compare identity, push i32
                let val2 = try_exec!(self.pop());
                let val1 = try_exec!(self.pop());
                let eq = match (val1, val2) {
                    (Value::NullRef, Value::NullRef) => true,
                    (Value::I32(-1), Value::NullRef) | (Value::NullRef, Value::I32(-1)) => true,
                    (Value::I32(-1), Value::I32(-1)) => true,
                    (Value::NullRef, _) | (_, Value::NullRef) => false,
                    (Value::I32(-1), _) | (_, Value::I32(-1)) => false,
                    (Value::I32(a), Value::I32(b)) => a == b,
                    (Value::GcRef(a), Value::GcRef(b)) => a == b,
                    _ => false,
                };
                try_exec!(self.push(Value::I32(if eq { 1 } else { 0 })));
            }
            0xD4 => {
                // ref.as_non_null
                let val = try_exec!(self.pop());
                match val {
                    Value::NullRef | Value::I32(-1) => {
                        return ExecResult::Trap(WasmError::NullReference);
                    }
                    _ => {
                        try_exec!(self.push(val));
                    }
                }
            }
            0xD5 => {
                // br_on_null: read label, pop ref, if null branch, else push ref back
                let label = try_exec!(self.read_leb128_u32());
                let val = try_exec!(self.pop());
                let is_null = matches!(val, Value::NullRef | Value::I32(-1));
                if is_null {
                    try_exec!(self.branch(label));
                } else {
                    try_exec!(self.push(val));
                }
            }
            0xD6 => {
                // br_on_non_null: read label, pop ref, if non-null push ref and branch, else continue
                let label = try_exec!(self.read_leb128_u32());
                let val = try_exec!(self.pop());
                let is_null = matches!(val, Value::NullRef | Value::I32(-1));
                if !is_null {
                    try_exec!(self.push(val));
                    try_exec!(self.branch(label));
                }
                // null — continue (don't push)
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
                let raw_idx = try_exec!(self.read_leb128_u32()) as usize;
                let idx = resolve_alias(&self.global_aliases, raw_idx);
                if idx >= self.globals.len() {
                    return ExecResult::Trap(WasmError::GlobalIndexOutOfBounds);
                }
                try_exec!(self.push(self.globals[idx]));
            }
            0x24 => {
                // global.set
                let raw_idx = try_exec!(self.read_leb128_u32()) as usize;
                let idx = resolve_alias(&self.global_aliases, raw_idx);
                if idx >= self.globals.len() {
                    return ExecResult::Trap(WasmError::GlobalIndexOutOfBounds);
                }
                // Check mutability
                if raw_idx < self.module.globals.len() && !self.module.globals[raw_idx].mutable {
                    return ExecResult::Trap(WasmError::ImmutableGlobal);
                }
                let val = try_exec!(self.pop());
                self.globals[idx] = val;
            }

            0x25 => {
                // table.get
                let table_idx = try_exec!(self.read_leb128_u32()) as usize;
                let is_t64 = table_idx < self.module.tables.len() && self.module.tables[table_idx].is_table64;
                let idx = if is_t64 { try_exec!(self.pop_i64()) as usize } else { try_exec!(self.pop_i32()) as usize };
                if table_idx >= self.tables.len() {
                    return ExecResult::Trap(WasmError::TableIndexOutOfBounds);
                }
                if idx >= self.tables[self.tbl(table_idx)].len() {
                    return ExecResult::Trap(WasmError::TableIndexOutOfBounds);
                }
                let val = match self.tables[self.tbl(table_idx)][idx] {
                    None => Value::NullRef,
                    Some(f) if f & 0x8000_0000 != 0 => Value::GcRef(f & 0x7FFF_FFFF),
                    Some(f) => Value::I32(f as i32),
                };
                try_exec!(self.push(val));
            }
            0x26 => {
                // table.set
                let table_idx = try_exec!(self.read_leb128_u32()) as usize;
                let raw_val = try_exec!(self.pop());
                let is_t64 = table_idx < self.module.tables.len() && self.module.tables[table_idx].is_table64;
                let idx = if is_t64 { try_exec!(self.pop_i64()) as usize } else { try_exec!(self.pop_i32()) as usize };
                if table_idx >= self.tables.len() {
                    return ExecResult::Trap(WasmError::TableIndexOutOfBounds);
                }
                if idx >= self.tables[self.tbl(table_idx)].len() {
                    return ExecResult::Trap(WasmError::TableIndexOutOfBounds);
                }
                let entry = match raw_val {
                    Value::NullRef => None,
                    Value::I32(v) => if v < 0 { None } else { Some(v as u32) },
                    Value::GcRef(heap_idx) => Some(heap_idx | 0x8000_0000), // encode gc refs with high bit
                    _ => None,
                };
                let rt = resolve_alias(&self.table_aliases, table_idx);
                self.tables[rt][idx] = entry;
            }

            // ── Memory (0x28-0x40) (see runtime/memory.rs) ───
            0x28..=0x40 => { return memory::execute_memory(self, opcode); }

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

            // ── Numeric instructions (0x45-0xC4) (see runtime/numeric.rs) ───
            0x45..=0xC4 => { return numeric::execute_numeric(self, opcode); }

            // ── 0xFC prefix: sat trunc + bulk memory + table ops (see runtime/fc_ops.rs) ─
            0xFC => { return fc_ops::execute_fc(self); }


            // ── 0xFD prefix: SIMD (v128) (see runtime/simd.rs) ───
            0xFD => { return simd::execute_simd(self); }


            // ── 0xFB prefix: GC proposal (see runtime/gc_ops.rs) ───
            0xFB => { return gc_ops::execute_gc(self); }


            // ── 0xFE prefix: Threads/Atomics (see runtime/atomic.rs) ───
            0xFE => { return atomic::execute_atomic(self); }


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

        // Restore PC and block depth
        self.pc = frame.return_pc;
        self.truncate_blocks(frame.saved_block_depth);

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

/// Saturating float-to-int conversions per WASM spec.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wasm::decoder::WasmModule;

    #[test]
    fn legacy_exception_slots_are_reused_after_block_unwind() {
        let mut inst = WasmInstance::with_class(WasmModule::new(), 0, DEFAULT_RUNTIME_CLASS)
            .expect("empty module should instantiate");

        let first_idx = inst.alloc_legacy_exception_values(&[Value::I32(7)]);
        let mut frame = BlockFrame::zero();
        frame.is_legacy_try = true;
        frame.legacy_exception_tag = 0;
        frame.legacy_exception_store_idx = first_idx;
        inst.push_block(frame).expect("push block");

        inst.truncate_blocks(0);

        let second_idx = inst.alloc_legacy_exception_values(&[Value::I32(9), Value::I32(11)]);
        assert_eq!(second_idx, first_idx);
        assert_eq!(inst.legacy_exception_store.len(), 1);

        let reused = inst.legacy_exception_store[second_idx as usize]
            .as_ref()
            .expect("reused slot must be populated");
        assert_eq!(reused.len(), 2);
        match reused[0] {
            Value::I32(v) => assert_eq!(v, 9),
            _ => panic!("unexpected value kind"),
        }
        match reused[1] {
            Value::I32(v) => assert_eq!(v, 11),
            _ => panic!("unexpected value kind"),
        }
    }
}
