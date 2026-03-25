//! WASM stack-machine interpreter with fuel-based metering.
//!
//! This is the core execution engine. It runs WASM bytecode one instruction
//! at a time, consuming fuel. When fuel runs out or a host call is needed,
//! execution pauses and the caller can resume.

use alloc::vec;
use alloc::vec::Vec;
use crate::wasm::decoder::{WasmModule, ImportKind, GcTypeDef, StorageType};
use crate::wasm::types::*;

/// Resolve table alias without borrowing self.
#[inline]
fn resolve_table_alias(aliases: &[Option<usize>], idx: usize) -> usize {
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
    /// Exception values for the currently handled exception (for rethrow).
    legacy_exception_values: [Value; 4],
    /// Number of exception values stored.
    legacy_exception_value_count: u8,
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
            legacy_exception_values: [Value::I32(0); 4],
            legacy_exception_value_count: 0,
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
    pub tables: Vec<Vec<Option<u32>>>,
    /// Table index aliasing: if table_aliases[i] = Some(j), table i is an alias of table j.
    /// All table ops on index i redirect to index j.
    pub table_aliases: Vec<Option<usize>>,
    /// Tracks which element segments have been dropped (by elem.drop or after active init).
    pub dropped_elems: Vec<bool>,
    /// Tracks which data segments have been dropped (by data.drop).
    pub dropped_data: Vec<bool>,
    pub memories: Vec<Vec<u8>>,
    pub memory_sizes: Vec<usize>,
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
    /// Indexed by segment index, contains re-evaluated Values for each item.
    pub elem_gc_values: Vec<Vec<Value>>,
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
            globals,
            table_aliases: vec![None; tables.len()],
            tables,
            dropped_elems,
            dropped_data,
            memories,
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
        let resolved = resolve_table_alias(&self.table_aliases, tbl_idx);
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
            return ma == mb && fa == fb;
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

    // ─── GC helpers ──────────────────────────────────────────────────────

    /// Evaluate GC const expressions for globals that need deferred evaluation.
    /// Called after instance creation when gc_heap is available.
    fn eval_gc_globals(&mut self) {
        // Collect init expression bytes to avoid borrow issues
        let global_info: Vec<(Vec<u8>, ValType)> = self.module.globals.iter()
            .map(|g| (g.init_expr_bytes.clone(), g.val_type))
            .collect();

        for (gi, (ref expr_bytes, val_type)) in global_info.iter().enumerate() {
            if expr_bytes.is_empty() { continue; }
            let needs_gc = matches!(val_type,
                ValType::AnyRef | ValType::NullableAnyRef | ValType::EqRef | ValType::NullableEqRef | ValType::I31Ref |
                ValType::StructRef | ValType::NullableStructRef | ValType::ArrayRef | ValType::NullableArrayRef |
                ValType::NoneRef | ValType::NullFuncRef | ValType::NullExternRef |
                ValType::TypedFuncRef | ValType::NonNullableFuncRef | ValType::NullableTypedFuncRef);
            if !needs_gc { continue; }
            if let Some(val) = self.eval_gc_const_expr(expr_bytes, 0) {
                self.globals[gi] = val;
            }
        }
    }

    /// Re-evaluate expression-based element segment items using the GC const expr evaluator.
    /// This is needed because at decode time, GC allocations (struct.new, array.new) can't
    /// be performed since the GC heap doesn't exist yet. We re-evaluate these expressions
    /// now that the instance is set up, and update both func_indices and tables.
    fn eval_gc_elem_exprs(&mut self) {
        use crate::wasm::decoder::ElemMode;
        let seg_count = self.module.element_segments.len();
        for seg_idx in 0..seg_count {
            let seg = &self.module.element_segments[seg_idx];
            if seg.item_expr_bytes.is_empty() { continue; }
            let expr_bytes_list = seg.item_expr_bytes.clone();
            let mode = seg.mode;
            let tbl_idx = seg.table_idx as usize;
            let offset = seg.offset as usize;
            // Re-evaluate each item expression
            let mut new_values: Vec<Value> = Vec::with_capacity(expr_bytes_list.len());
            for expr_bytes in &expr_bytes_list {
                if let Some(val) = self.eval_gc_const_expr(expr_bytes, 0) {
                    new_values.push(val);
                } else {
                    new_values.push(Value::NullRef);
                }
            }
            // Store re-evaluated GcRef values in elem_gc_values for use by gc_array_from_elem
            if self.elem_gc_values.len() <= seg_idx {
                self.elem_gc_values.resize(seg_count, Vec::new());
            }
            self.elem_gc_values[seg_idx] = new_values.clone();
            // Update tables for active segments
            if mode == ElemMode::Active && tbl_idx < self.tables.len() {
                for (i, val) in new_values.iter().enumerate() {
                    let idx = offset + i;
                    if idx < self.tables[self.tbl(tbl_idx)].len() {
                        let entry = match val {
                            Value::NullRef => None,
                            Value::I32(v) => if *v < 0 { None } else { Some(*v as u32) },
                            Value::GcRef(heap_idx) => Some(heap_idx | 0x8000_0000),
                            _ => None,
                        };
                        let rt = resolve_table_alias(&self.table_aliases, tbl_idx);
                        self.tables[rt][idx] = entry;
                    }
                }
            }
        }
    }

    /// Evaluate a GC-aware const expression, returning the resulting value.
    fn eval_gc_const_expr(&mut self, bytes: &[u8], start: usize) -> Option<Value> {
        use crate::wasm::decoder::{decode_leb128_u32, decode_leb128_i32, decode_leb128_i64};

        let mut pos = start;
        let mut stack: Vec<Value> = Vec::new();

        loop {
            if pos >= bytes.len() { return None; }
            let opcode = bytes[pos];
            pos += 1;
            match opcode {
                0x0B => return stack.pop(),
                0x41 => {
                    if let Ok(v) = decode_leb128_i32(bytes, &mut pos) { stack.push(Value::I32(v)); }
                }
                0x42 => {
                    if let Ok(v) = decode_leb128_i64(bytes, &mut pos) { stack.push(Value::I64(v)); }
                }
                0x43 => {
                    if pos + 4 > bytes.len() { return None; }
                    let v = f32::from_le_bytes([bytes[pos], bytes[pos+1], bytes[pos+2], bytes[pos+3]]);
                    pos += 4;
                    stack.push(Value::F32(v));
                }
                0x44 => {
                    if pos + 8 > bytes.len() { return None; }
                    let mut b8 = [0u8; 8];
                    b8.copy_from_slice(&bytes[pos..pos+8]);
                    pos += 8;
                    stack.push(Value::F64(f64::from_le_bytes(b8)));
                }
                0x23 => {
                    if let Ok(idx) = decode_leb128_u32(bytes, &mut pos) {
                        let val = self.globals.get(idx as usize).copied().unwrap_or(Value::I32(0));
                        stack.push(val);
                    }
                }
                0xD0 => {
                    let _ = decode_leb128_i32(bytes, &mut pos);
                    stack.push(Value::NullRef);
                }
                0xD2 => {
                    if let Ok(idx) = decode_leb128_u32(bytes, &mut pos) {
                        stack.push(Value::I32(idx as i32));
                    }
                }
                0xFB => {
                    if let Ok(sub) = decode_leb128_u32(bytes, &mut pos) {
                        match sub {
                            0 => { // struct.new
                                if let Ok(type_idx) = decode_leb128_u32(bytes, &mut pos) {
                                    let field_count = self.gc_struct_field_count(type_idx);
                                    let start_idx = stack.len().saturating_sub(field_count);
                                    let mut fields: Vec<Value> = stack.drain(start_idx..).collect();
                                    while fields.len() < field_count { fields.push(Value::I32(0)); }
                                    for i in 0..field_count {
                                        fields[i] = self.gc_wrap_field_value(type_idx, i, fields[i]);
                                    }
                                    let heap_idx = self.gc_heap.len() as u32;
                                    self.gc_heap.push(GcObject::Struct { type_idx, fields });
                                    stack.push(Value::GcRef(heap_idx));
                                }
                            }
                            1 => { // struct.new_default
                                if let Ok(type_idx) = decode_leb128_u32(bytes, &mut pos) {
                                    let field_count = self.gc_struct_field_count(type_idx);
                                    let mut fields = Vec::with_capacity(field_count);
                                    for i in 0..field_count {
                                        fields.push(self.gc_struct_field_default(type_idx, i));
                                    }
                                    let heap_idx = self.gc_heap.len() as u32;
                                    self.gc_heap.push(GcObject::Struct { type_idx, fields });
                                    stack.push(Value::GcRef(heap_idx));
                                }
                            }
                            6 => { // array.new
                                if let Ok(type_idx) = decode_leb128_u32(bytes, &mut pos) {
                                    let length = stack.pop().map(|v| v.as_i32() as u32).unwrap_or(0);
                                    let init_val = stack.pop().unwrap_or(Value::I32(0));
                                    let wrapped = self.gc_wrap_array_value(type_idx, init_val);
                                    let elements = vec![wrapped; length as usize];
                                    let heap_idx = self.gc_heap.len() as u32;
                                    self.gc_heap.push(GcObject::Array { type_idx, elements });
                                    stack.push(Value::GcRef(heap_idx));
                                }
                            }
                            7 => { // array.new_default
                                if let Ok(type_idx) = decode_leb128_u32(bytes, &mut pos) {
                                    let length = stack.pop().map(|v| v.as_i32() as u32).unwrap_or(0);
                                    let default_val = self.gc_array_elem_default(type_idx);
                                    let elements = vec![default_val; length as usize];
                                    let heap_idx = self.gc_heap.len() as u32;
                                    self.gc_heap.push(GcObject::Array { type_idx, elements });
                                    stack.push(Value::GcRef(heap_idx));
                                }
                            }
                            8 => { // array.new_fixed
                                if let Ok(type_idx) = decode_leb128_u32(bytes, &mut pos) {
                                    if let Ok(count) = decode_leb128_u32(bytes, &mut pos) {
                                        let count = count as usize;
                                        let start_idx = stack.len().saturating_sub(count);
                                        let mut elements: Vec<Value> = stack.drain(start_idx..).collect();
                                        for e in &mut elements {
                                            *e = self.gc_wrap_array_value(type_idx, *e);
                                        }
                                        let heap_idx = self.gc_heap.len() as u32;
                                        self.gc_heap.push(GcObject::Array { type_idx, elements });
                                        stack.push(Value::GcRef(heap_idx));
                                    }
                                }
                            }
                            28 => {} // ref.i31: value stays as I32
                            29 => { // i31.get_s
                                if let Some(val) = stack.last_mut() {
                                    let v = val.as_i32() & 0x7FFF_FFFF;
                                    *val = Value::I32(if v & 0x4000_0000 != 0 { v | !0x7FFF_FFFFu32 as i32 } else { v });
                                }
                            }
                            30 => { // i31.get_u
                                if let Some(val) = stack.last_mut() {
                                    *val = Value::I32(val.as_i32() & 0x7FFF_FFFF);
                                }
                            }
                            26 | 27 => {} // any.convert_extern, extern.convert_any
                            _ => return None,
                        }
                    }
                }
                0x6A => { if stack.len() >= 2 { let b = stack.pop().unwrap().as_i32(); let a = stack.pop().unwrap().as_i32(); stack.push(Value::I32(a.wrapping_add(b))); } }
                0x6B => { if stack.len() >= 2 { let b = stack.pop().unwrap().as_i32(); let a = stack.pop().unwrap().as_i32(); stack.push(Value::I32(a.wrapping_sub(b))); } }
                0x6C => { if stack.len() >= 2 { let b = stack.pop().unwrap().as_i32(); let a = stack.pop().unwrap().as_i32(); stack.push(Value::I32(a.wrapping_mul(b))); } }
                _ => return None,
            }
        }
    }

    /// Get the number of fields in a struct type.
    fn gc_struct_field_count(&self, type_idx: u32) -> usize {
        if let Some(GcTypeDef::Struct { field_types, .. }) = self.module.gc_types.get(type_idx as usize) {
            field_types.len()
        } else {
            0
        }
    }

    /// Get default value for a struct field.
    fn gc_struct_field_default(&self, type_idx: u32, field_idx: usize) -> Value {
        if let Some(GcTypeDef::Struct { field_types, .. }) = self.module.gc_types.get(type_idx as usize) {
            if let Some(st) = field_types.get(field_idx) {
                return Value::default_for(st.unpack());
            }
        }
        Value::I32(0)
    }

    /// Get default value for an array element.
    fn gc_array_elem_default(&self, type_idx: u32) -> Value {
        if let Some(GcTypeDef::Array { elem_type, .. }) = self.module.gc_types.get(type_idx as usize) {
            return Value::default_for(elem_type.unpack());
        }
        Value::I32(0)
    }

    /// Apply sign/zero extension for struct field packed types.
    fn gc_apply_field_extend(&self, type_idx: u32, field_idx: usize, val: Value, sub_opcode: u32) -> Value {
        if let Some(GcTypeDef::Struct { field_types, .. }) = self.module.gc_types.get(type_idx as usize) {
            if let Some(st) = field_types.get(field_idx) {
                let v = val.as_i32();
                return match st {
                    StorageType::I8 => {
                        if sub_opcode == 3 { Value::I32((v as i8) as i32) }
                        else { Value::I32(v & 0xFF) }
                    }
                    StorageType::I16 => {
                        if sub_opcode == 3 { Value::I32((v as i16) as i32) }
                        else { Value::I32(v & 0xFFFF) }
                    }
                    _ => val,
                };
            }
        }
        val
    }

    /// Apply sign/zero extension for array element packed types.
    fn gc_apply_array_extend(&self, type_idx: u32, val: Value, sub_opcode: u32) -> Value {
        if let Some(GcTypeDef::Array { elem_type, .. }) = self.module.gc_types.get(type_idx as usize) {
            let v = val.as_i32();
            return match elem_type {
                StorageType::I8 => {
                    if sub_opcode == 12 { Value::I32((v as i8) as i32) }
                    else { Value::I32(v & 0xFF) }
                }
                StorageType::I16 => {
                    if sub_opcode == 12 { Value::I32((v as i16) as i32) }
                    else { Value::I32(v & 0xFFFF) }
                }
                _ => val,
            };
        }
        val
    }

    /// Wrap a value for storing into a packed struct field.
    fn gc_wrap_field_value(&self, type_idx: u32, field_idx: usize, val: Value) -> Value {
        if let Some(GcTypeDef::Struct { field_types, .. }) = self.module.gc_types.get(type_idx as usize) {
            if let Some(st) = field_types.get(field_idx) {
                return match st {
                    StorageType::I8 => Value::I32(val.as_i32() & 0xFF),
                    StorageType::I16 => Value::I32(val.as_i32() & 0xFFFF),
                    _ => val,
                };
            }
        }
        val
    }

    /// Wrap a value for storing into a packed array element.
    fn gc_wrap_array_value(&self, type_idx: u32, val: Value) -> Value {
        if let Some(GcTypeDef::Array { elem_type, .. }) = self.module.gc_types.get(type_idx as usize) {
            return match elem_type {
                StorageType::I8 => Value::I32(val.as_i32() & 0xFF),
                StorageType::I16 => Value::I32(val.as_i32() & 0xFFFF),
                _ => val,
            };
        }
        val
    }

    /// Create array elements from a data segment.
    /// For dropped segments, the effective data length is 0 (offset 0 + length 0 succeeds).
    fn gc_array_from_data(&self, type_idx: u32, data_idx: usize, offset: u32, length: u32) -> Result<Vec<Value>, WasmError> {
        if data_idx >= self.module.data_segments.len() {
            return Err(WasmError::MemoryOutOfBounds);
        }
        // Dropped segments are treated as having length 0
        let is_dropped = data_idx < self.dropped_data.len() && self.dropped_data[data_idx];
        let data_len = if is_dropped {
            0usize
        } else {
            self.module.data_segments[data_idx].data_len
        };

        let elem_size = if let Some(GcTypeDef::Array { elem_type, .. }) = self.module.gc_types.get(type_idx as usize) {
            match elem_type {
                StorageType::I8 => 1usize,
                StorageType::I16 => 2,
                StorageType::Val(ValType::I32) | StorageType::Val(ValType::F32) => 4,
                StorageType::Val(ValType::I64) | StorageType::Val(ValType::F64) => 8,
                _ => 4,
            }
        } else { 4 };

        let total_bytes = length as usize * elem_size;
        let start = offset as usize;
        if start + total_bytes > data_len {
            return Err(WasmError::MemoryOutOfBounds);
        }
        if length == 0 {
            return Ok(Vec::new());
        }
        let seg = &self.module.data_segments[data_idx];
        let data = &self.module.code[seg.data_offset..seg.data_offset + seg.data_len];

        let mut elements = Vec::with_capacity(length as usize);
        for i in 0..length as usize {
            let pos = start + i * elem_size;
            let val = match elem_size {
                1 => Value::I32(data[pos] as i32),
                2 => Value::I32(u16::from_le_bytes([data[pos], data[pos+1]]) as i32),
                4 => {
                    let bytes = [data[pos], data[pos+1], data[pos+2], data[pos+3]];
                    if let Some(GcTypeDef::Array { elem_type: StorageType::Val(ValType::F32), .. }) = self.module.gc_types.get(type_idx as usize) {
                        Value::F32(f32::from_le_bytes(bytes))
                    } else {
                        Value::I32(i32::from_le_bytes(bytes))
                    }
                }
                8 => {
                    let mut b8 = [0u8; 8];
                    b8.copy_from_slice(&data[pos..pos+8]);
                    if let Some(GcTypeDef::Array { elem_type: StorageType::Val(ValType::F64), .. }) = self.module.gc_types.get(type_idx as usize) {
                        Value::F64(f64::from_le_bytes(b8))
                    } else {
                        Value::I64(i64::from_le_bytes(b8))
                    }
                }
                _ => Value::I32(0),
            };
            elements.push(val);
        }
        Ok(elements)
    }

    /// Create array elements from an element segment.
    /// For dropped segments, the effective element count is 0 (offset 0 + length 0 succeeds).
    fn gc_array_from_elem(&self, elem_idx: usize, offset: u32, length: u32) -> Result<Vec<Value>, WasmError> {
        if elem_idx >= self.module.element_segments.len() {
            return Err(WasmError::TableIndexOutOfBounds);
        }
        // Dropped segments are treated as having length 0
        let is_dropped = elem_idx < self.dropped_elems.len() && self.dropped_elems[elem_idx];
        let seg_len = if is_dropped {
            0usize
        } else {
            self.module.element_segments[elem_idx].func_indices.len()
        };
        let end = offset as usize + length as usize;
        if end > seg_len {
            return Err(WasmError::TableIndexOutOfBounds);
        }
        if length == 0 {
            return Ok(Vec::new());
        }
        // Use re-evaluated GC values if available (expression-based segments)
        if elem_idx < self.elem_gc_values.len() && !self.elem_gc_values[elem_idx].is_empty() {
            let gc_vals = &self.elem_gc_values[elem_idx];
            let mut elements = Vec::with_capacity(length as usize);
            for i in offset as usize..end {
                if i < gc_vals.len() {
                    elements.push(gc_vals[i]);
                } else {
                    elements.push(Value::NullRef);
                }
            }
            return Ok(elements);
        }
        let seg = &self.module.element_segments[elem_idx];
        let mut elements = Vec::with_capacity(length as usize);
        for i in offset as usize..end {
            let func_idx = seg.func_indices[i];
            if func_idx == u32::MAX {
                elements.push(Value::NullRef);
            } else {
                elements.push(Value::I32(func_idx as i32));
            }
        }
        Ok(elements)
    }

    /// Test if a reference value matches a heap type.
    // Heap type constants (signed LEB128 byte values):
    // -16 (0x70) = func, -17 (0x6F) = extern, -18 (0x6E) = any,
    // -19 (0x6D) = eq, -20 (0x6C) = i31, -21 (0x6B) = struct,
    // -22 (0x6A) = array, -13 (0x73) = nofunc, -14 (0x72) = noextern,
    // -15 (0x71) = none, -23 (0x69) = exn, -12 (0x74) = noexn
    const HT_FUNC: i32 = -16;
    const HT_EXTERN: i32 = -17;
    const HT_ANY: i32 = -18;
    const HT_EQ: i32 = -19;
    const HT_I31: i32 = -20;
    const HT_STRUCT: i32 = -21;
    const HT_ARRAY: i32 = -22;
    const HT_NOFUNC: i32 = -13;
    const HT_NOEXTERN: i32 = -14;
    const HT_NONE: i32 = -15;

    fn gc_ref_test(&self, val: Value, ht: i32, nullable: bool) -> bool {
        match val {
            Value::NullRef | Value::I32(-1) => nullable,
            Value::I32(v) => {
                // I32 values represent i31ref (from ref.i31) or funcref (function index)
                match ht {
                    Self::HT_ANY => true,      // i31 <: any
                    Self::HT_EQ => true,       // i31 <: eq
                    Self::HT_I31 => true,      // i31 <: i31
                    Self::HT_FUNC => true,     // i32 encoding for funcref
                    Self::HT_EXTERN => false,
                    Self::HT_STRUCT => false,
                    Self::HT_ARRAY => false,
                    Self::HT_NONE => false,
                    Self::HT_NOFUNC => false,
                    Self::HT_NOEXTERN => false,
                    _ if ht >= 0 => {
                        // Concrete type: check if this is a funcref and its type is a subtype
                        if v >= 0 {
                            let func_idx = v as u32;
                            let func_type = if (func_idx as usize) < self.module.func_import_count() {
                                self.module.func_import_type(func_idx)
                            } else {
                                let li = (func_idx as usize).wrapping_sub(self.module.func_import_count());
                                self.module.functions.get(li).map(|f| f.type_idx)
                            };
                            if let Some(fti) = func_type {
                                self.gc_is_subtype(fti, ht as u32)
                            } else {
                                false
                            }
                        } else {
                            false
                        }
                    }
                    _ => false,
                }
            }
            Value::GcRef(heap_idx) => {
                if heap_idx as usize >= self.gc_heap.len() {
                    return false;
                }
                let obj = &self.gc_heap[heap_idx as usize];
                // Internalized extern values (from any.convert_extern) only match HT_ANY
                if matches!(obj, GcObject::Internalized { .. }) {
                    return ht == Self::HT_ANY;
                }
                // Externalized any values (from extern.convert_any) match HT_EXTERN
                if matches!(obj, GcObject::Externalized { .. }) {
                    return ht == Self::HT_EXTERN;
                }
                let obj_type_idx = obj.type_idx();
                match ht {
                    Self::HT_ANY => true,      // all GC objects <: any
                    Self::HT_EQ => true,       // all GC objects <: eq
                    Self::HT_I31 => false,     // GC objects are not i31
                    Self::HT_STRUCT => matches!(obj, GcObject::Struct { .. }),
                    Self::HT_ARRAY => matches!(obj, GcObject::Array { .. }),
                    Self::HT_FUNC => false,
                    Self::HT_EXTERN => false,
                    Self::HT_NONE => false,
                    Self::HT_NOFUNC => false,
                    Self::HT_NOEXTERN => false,
                    _ if ht >= 0 => self.gc_is_subtype(obj_type_idx, ht as u32),
                    _ => false,
                }
            }
            _ => false,
        }
    }

    /// Check if two types are equivalent using rec-group-aware canonicalization.
    fn gc_types_equivalent(&self, type_a: u32, type_b: u32) -> bool {
        if type_a == type_b { return true; }
        crate::wasm::validator::types_equivalent_in_module(&self.module, type_a, type_b)
    }

    /// Check if type_a is a subtype of type_b (or equal).
    fn gc_is_subtype(&self, type_a: u32, type_b: u32) -> bool {
        if type_a == type_b {
            return true;
        }
        // Check canonical type equivalence
        if self.gc_types_equivalent(type_a, type_b) {
            return true;
        }
        let mut current = type_a;
        for _ in 0..100 {
            if let Some(info) = self.module.sub_types.get(current as usize) {
                if let Some(parent) = info.supertype {
                    if parent == type_b || self.gc_types_equivalent(parent, type_b) {
                        return true;
                    }
                    current = parent;
                } else {
                    return false;
                }
            } else {
                return false;
            }
        }
        false
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
        resolve_table_alias(&self.table_aliases, idx)
    }

    /// Get memory slice reference by index, defaulting to memory 0.
    #[inline]
    fn mem(&self, idx: usize) -> &Vec<u8> {
        if idx < self.memories.len() { &self.memories[idx] } else { &self.memories[0] }
    }

    /// Get mutable memory slice reference by index, defaulting to memory 0.
    #[inline]
    fn mem_mut(&mut self, idx: usize) -> &mut Vec<u8> {
        if idx < self.memories.len() { &mut self.memories[idx] } else { &mut self.memories[0] }
    }

    /// Get memory size by index, defaulting to memory 0.
    #[inline]
    fn mem_size(&self, idx: usize) -> usize {
        if idx < self.memory_sizes.len() { self.memory_sizes[idx] } else { 0 }
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

    fn mem_load_f32(&self, mem_idx: usize, addr: usize) -> Result<f32, WasmError> {
        if addr.checked_add(4).ok_or(WasmError::MemoryOutOfBounds)? > self.mem_size(mem_idx) {
            return Err(WasmError::MemoryOutOfBounds);
        }
        let m = self.mem(mem_idx);
        Ok(f32::from_le_bytes([m[addr], m[addr + 1], m[addr + 2], m[addr + 3]]))
    }

    fn mem_load_f64(&self, mem_idx: usize, addr: usize) -> Result<f64, WasmError> {
        if addr.checked_add(8).ok_or(WasmError::MemoryOutOfBounds)? > self.mem_size(mem_idx) {
            return Err(WasmError::MemoryOutOfBounds);
        }
        let m = self.mem(mem_idx);
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&m[addr..addr + 8]);
        Ok(f64::from_le_bytes(bytes))
    }

    fn mem_store_f32(&mut self, mem_idx: usize, addr: usize, val: f32) -> Result<(), WasmError> {
        if addr.checked_add(4).ok_or(WasmError::MemoryOutOfBounds)? > self.mem_size(mem_idx) {
            return Err(WasmError::MemoryOutOfBounds);
        }
        self.mem_mut(mem_idx)[addr..addr + 4].copy_from_slice(&val.to_le_bytes());
        Ok(())
    }

    fn mem_store_f64(&mut self, mem_idx: usize, addr: usize, val: f64) -> Result<(), WasmError> {
        if addr.checked_add(8).ok_or(WasmError::MemoryOutOfBounds)? > self.mem_size(mem_idx) {
            return Err(WasmError::MemoryOutOfBounds);
        }
        self.mem_mut(mem_idx)[addr..addr + 8].copy_from_slice(&val.to_le_bytes());
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

    fn mem_load_v128(&self, mem_idx: usize, addr: usize) -> Result<V128, WasmError> {
        if addr.checked_add(16).ok_or(WasmError::MemoryOutOfBounds)? > self.mem_size(mem_idx) {
            return Err(WasmError::MemoryOutOfBounds);
        }
        let m = self.mem(mem_idx);
        let mut b = [0u8; 16];
        b.copy_from_slice(&m[addr..addr + 16]);
        Ok(V128(b))
    }

    fn mem_store_v128(&mut self, mem_idx: usize, addr: usize, val: V128) -> Result<(), WasmError> {
        if addr.checked_add(16).ok_or(WasmError::MemoryOutOfBounds)? > self.mem_size(mem_idx) {
            return Err(WasmError::MemoryOutOfBounds);
        }
        self.mem_mut(mem_idx)[addr..addr + 16].copy_from_slice(&val.0);
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
        Ok(self.block_stack[self.block_depth])
    }

    /// Scan a legacy try block to find catch/catch_all handler positions and the end PC.
    /// Called right after reading the block type of a `try` instruction.
    /// Returns (legacy_catches, legacy_catch_count, end_pc, delegate_label).
    fn scan_legacy_try(&mut self) -> Result<([LegacyCatch; MAX_LEGACY_CATCHES], u8, usize, u32), WasmError> {
        let save_pc = self.pc;
        let mut catches = [LegacyCatch::zero(); MAX_LEGACY_CATCHES];
        let mut catch_count: u8 = 0;
        let mut depth: usize = 1;
        let mut end_pc = 0usize;
        let mut delegate_label: u32 = u32::MAX;

        while depth > 0 {
            let b = self.read_byte()?;
            match b {
                0x02 | 0x03 | 0x04 => {
                    let bt = self.read_leb128_i32()?;
                    if bt == -0x1D || bt == -0x1C { let _ = self.read_leb128_i32()?; }
                    depth += 1;
                }
                0x06 => {
                    let bt = self.read_leb128_i32()?;
                    if bt == -0x1D || bt == -0x1C { let _ = self.read_leb128_i32()?; }
                    depth += 1;
                }
                0x07 => { // catch tag_idx
                    let tag_idx = self.read_leb128_u32()?;
                    if depth == 1 && (catch_count as usize) < MAX_LEGACY_CATCHES {
                        catches[catch_count as usize] = LegacyCatch {
                            handler_pc: self.pc,
                            tag_idx,
                        };
                        catch_count += 1;
                    }
                }
                0x19 => { // catch_all
                    if depth == 1 && (catch_count as usize) < MAX_LEGACY_CATCHES {
                        catches[catch_count as usize] = LegacyCatch {
                            handler_pc: self.pc,
                            tag_idx: u32::MAX,
                        };
                        catch_count += 1;
                    }
                }
                0x18 => { // delegate
                    let label = self.read_leb128_u32()?;
                    depth -= 1;
                    if depth == 0 {
                        end_pc = self.pc;
                        delegate_label = label;
                    }
                }
                0x0B => {
                    depth -= 1;
                    if depth == 0 {
                        end_pc = self.pc;
                    }
                }
                0x05 => {} // else
                0x08 => { let _ = self.read_leb128_u32()?; } // throw
                0x09 => { let _ = self.read_leb128_u32()?; } // rethrow: label
                0x0A => {} // throw_ref
                0x1F => {
                    let bt = self.read_leb128_i32()?;
                    if bt == -0x1D || bt == -0x1C { let _ = self.read_leb128_i32()?; }
                    let cc = self.read_leb128_u32()? as usize;
                    for _ in 0..cc {
                        let ck = self.read_byte()?;
                        match ck {
                            0 | 1 => { let _ = self.read_leb128_u32()?; let _ = self.read_leb128_u32()?; }
                            2 | 3 => { let _ = self.read_leb128_u32()?; }
                            _ => {}
                        }
                    }
                    depth += 1;
                }
                0x0C | 0x0D => { let _ = self.read_leb128_u32()?; } // br, br_if
                0x0E => {
                    let count = self.read_leb128_u32()? as usize;
                    for _ in 0..count { let _ = self.read_leb128_u32()?; }
                    let _ = self.read_leb128_u32()?;
                }
                0x10 | 0x12 | 0x14 | 0x15 => { let _ = self.read_leb128_u32()?; }
                0x11 | 0x13 => { let _ = self.read_leb128_u32()?; let _ = self.read_leb128_u32()?; }
                0x20 | 0x21 | 0x22 | 0x23 | 0x24 | 0x25 | 0x26 => { let _ = self.read_leb128_u32()?; }
                0xFC => {
                    let sub = self.read_leb128_u32()?;
                    match sub {
                        0..=7 => {}
                        8 => { let _ = self.read_leb128_u32()?; let _ = self.read_leb128_u32()?; }
                        9 | 13 => { let _ = self.read_leb128_u32()?; }
                        10 => { let _ = self.read_leb128_u32()?; let _ = self.read_leb128_u32()?; }
                        11 | 16 => { let _ = self.read_byte()?; }
                        12 => { let _ = self.read_leb128_u32()?; let _ = self.read_leb128_u32()?; }
                        14 => { let _ = self.read_leb128_u32()?; let _ = self.read_leb128_u32()?; }
                        15 => { let _ = self.read_leb128_u32()?; }
                        17 => { let _ = self.read_leb128_u32()?; }
                        _ => {}
                    }
                }
                0xFD => {
                    let sub = self.read_leb128_u32()?;
                    match sub {
                        0..=11 | 92..=95 => { let _ = self.read_leb128_u32()?; let _ = self.read_leb128_u32()?; }
                        84..=91 => { let _ = self.read_leb128_u32()?; let _ = self.read_leb128_u32()?; let _ = self.read_byte()?; }
                        12 => { let mut buf = [0u8; 16]; for b in &mut buf { *b = self.read_byte()?; } }
                        13 => { let _ = self.read_leb128_u32()?; }
                        21..=34 => { let _ = self.read_leb128_u32()?; }
                        _ => {}
                    }
                }
                0xFE => {
                    let sub = self.read_leb128_u32()?;
                    match sub {
                        0x00..=0x4e => {
                            if sub <= 0x03 { let _ = self.read_leb128_u32()?; let _ = self.read_leb128_u32()?; }
                            else { let _ = self.read_leb128_u32()?; let _ = self.read_leb128_u32()?; }
                        }
                        _ => {}
                    }
                }
                0x28..=0x3E | 0x3F | 0x40 => {
                    let _ = self.read_leb128_u32()?;
                    let _ = self.read_leb128_u32()?;
                }
                0x41 => { let _ = self.read_leb128_i32()?; }
                0x42 => { let _ = self.read_leb128_i64()?; }
                0x43 => { for _ in 0..4 { let _ = self.read_byte()?; } }
                0x44 => { for _ in 0..8 { let _ = self.read_byte()?; } }
                0xD0 => { let _ = self.read_leb128_i32()?; } // ref.null
                0xD2 => { let _ = self.read_leb128_u32()?; } // ref.func
                0xFB => {
                    let sub = self.read_leb128_u32()?;
                    match sub {
                        0..=7 | 26..=30 => { let _ = self.read_leb128_u32()?; }
                        8 | 12 | 14..=17 => { let _ = self.read_leb128_u32()?; let _ = self.read_leb128_u32()?; }
                        _ => {}
                    }
                }
                _ => {} // most opcodes have no immediates
            }
        }
        self.pc = save_pc;
        Ok((catches, catch_count, end_pc, delegate_label))
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
                    // Read and discard the block type (may be multi-byte for ref types)
                    let bt = self.read_leb128_i32()?;
                    if bt == -0x1D || bt == -0x1C {
                        let _ = self.read_leb128_i32()?; // consume heap type
                    }
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
                0x06 => { // try (legacy exception handling) — opens a block
                    let bt = self.read_leb128_i32()?; // block type
                    if bt == -0x1D || bt == -0x1C {
                        let _ = self.read_leb128_i32()?; // consume heap type
                    }
                    depth += 1;
                }
                0x07 => { // catch (legacy): tag_idx
                    let _ = self.read_leb128_u32()?;
                }
                0x08 => { let _ = self.read_leb128_u32()?; } // throw: tag_idx
                0x09 => { let _ = self.read_leb128_u32()?; } // rethrow: label
                0x0A => {} // throw_ref: no immediates
                0x18 => { // delegate (legacy): label — ends the try block
                    let _ = self.read_leb128_u32()?;
                    depth -= 1;
                    if depth == 0 {
                        return Ok(self.pc);
                    }
                }
                0x19 => { // catch_all (legacy): no immediates
                }
                0x1F => {
                    // try_table: block_type + catch_count + catch clauses
                    let bt = self.read_leb128_i32()?;
                    if bt == -0x1D || bt == -0x1C {
                        let _ = self.read_leb128_i32()?; // consume heap type
                    }
                    let catch_count = self.read_leb128_u32()? as usize;
                    for _ in 0..catch_count {
                        let clause_kind = self.read_byte()?;
                        match clause_kind {
                            0 | 1 => { // catch, catch_ref: tag_idx + label
                                let _ = self.read_leb128_u32()?; // tag_idx
                                let _ = self.read_leb128_u32()?; // label
                            }
                            2 | 3 => { // catch_all, catch_all_ref: label
                                let _ = self.read_leb128_u32()?; // label
                            }
                            _ => {} // unknown clause kind
                        }
                    }
                    depth += 1;
                }
                // Instructions with LEB128 immediates that we need to skip
                0x0C | 0x0D => { let _ = self.read_leb128_u32()?; } // br, br_if
                0x0E => {
                    // br_table: count + count labels + default label
                    let count = self.read_leb128_u32()? as usize;
                    for _ in 0..count { let _ = self.read_leb128_u32()?; }
                    let _ = self.read_leb128_u32()?; // default
                }
                0x10 | 0x12 | 0x14 | 0x15 => { let _ = self.read_leb128_u32()?; } // call, return_call, call_ref, return_call_ref
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
                        0x00..=0x0b => { // v128 load/store: memarg (flags [+ memidx] + offset)
                            let flags = self.read_leb128_u32()?;
                            if self.module.multi_memory_enabled && (flags & (1 << 6)) != 0 { let _ = self.read_leb128_u32()?; }
                            let _ = self.read_leb128_u32()?;
                        }
                        0x0c => { self.pc += 16; } // v128.const: 16 bytes immediate
                        0x0d => { self.pc += 16; } // i8x16.shuffle: 16 lane bytes
                        0x15..=0x22 => { self.pc += 1; } // extract/replace lane: 1 byte lane index
                        0x54..=0x5b => { // load/store_lane: memarg + lane
                            let flags = self.read_leb128_u32()?;
                            if self.module.multi_memory_enabled && (flags & (1 << 6)) != 0 { let _ = self.read_leb128_u32()?; }
                            let _ = self.read_leb128_u32()?; self.pc += 1;
                        }
                        0x5c..=0x5d => { // load*_zero: memarg
                            let flags = self.read_leb128_u32()?;
                            if self.module.multi_memory_enabled && (flags & (1 << 6)) != 0 { let _ = self.read_leb128_u32()?; }
                            let _ = self.read_leb128_u32()?;
                        }
                        _ => {} // most SIMD ops have no immediates
                    }
                }
                0xFE => {
                    // Threads/Atomics prefix: read sub-opcode, then skip its immediates
                    let sub = self.read_leb128_u32()?;
                    match sub {
                        0x03 => { self.pc += 1; } // atomic.fence: 1 byte (0x00)
                        0x00..=0x02 | 0x10..=0x4e => {
                            // All atomic memory ops have a memarg
                            let flags = self.read_leb128_u32()?;
                            if self.module.multi_memory_enabled && (flags & (1 << 6)) != 0 { let _ = self.read_leb128_u32()?; }
                            let _ = self.read_leb128_u32()?;
                        }
                        _ => {}
                    }
                }
                0x3F | 0x40 => { let _ = self.read_leb128_u32()?; } // memory.size/grow (memory index)
                0x28 | 0x29 | 0x2A | 0x2B | 0x2C | 0x2D | 0x2E | 0x2F
                | 0x30 | 0x31 | 0x32 | 0x33 | 0x34 | 0x35
                | 0x36 | 0x37 | 0x38 | 0x39 | 0x3A | 0x3B | 0x3C | 0x3D | 0x3E => {
                    // memory load/store (all variants): memarg (flags [+ memidx] + offset)
                    let flags = self.read_leb128_u32()?;
                    if self.module.multi_memory_enabled && (flags & (1 << 6)) != 0 {
                        let _ = self.read_leb128_u32()?; // memory index
                    }
                    let _ = self.read_leb128_u32()?; // offset
                }
                0x41 => { let _ = self.read_leb128_i32()?; } // i32.const
                0x42 => { let _ = self.read_leb128_i64()?; } // i64.const
                0x43 => { self.pc += 4; } // f32.const (4 bytes IEEE 754)
                0x44 => { self.pc += 8; } // f64.const (8 bytes IEEE 754)
                0x0F => {} // return
                0x1C => {
                    // select (typed): vector of value types
                    let count = self.read_leb128_u32()? as usize;
                    for _ in 0..count { let _ = self.read_leb128_u32()?; }
                }
                0xD0 => { let _ = self.read_leb128_i32()?; } // ref.null heaptype
                0xD2 => { let _ = self.read_leb128_u32()?; } // ref.func funcidx
                // 0xD3, 0xD4 = ref.as_non_null: no immediates
                0xD5 | 0xD6 => { let _ = self.read_leb128_u32()?; } // br_on_null, br_on_non_null: label
                0xFB => {
                    // GC prefix: read sub-opcode, then skip its immediates
                    let sub = self.read_leb128_u32()?;
                    match sub {
                        0 | 1 => { let _ = self.read_leb128_u32()?; } // struct.new, struct.new_default: typeidx
                        2 | 3 | 4 | 5 => { let _ = self.read_leb128_u32()?; let _ = self.read_leb128_u32()?; } // struct.get/get_s/get_u/set: typeidx fieldidx
                        6 | 7 => { let _ = self.read_leb128_u32()?; } // array.new, array.new_default: typeidx
                        8 => { let _ = self.read_leb128_u32()?; let _ = self.read_leb128_u32()?; } // array.new_fixed: typeidx + size
                        9 | 10 => { let _ = self.read_leb128_u32()?; let _ = self.read_leb128_u32()?; } // array.new_data/elem: typeidx + idx
                        11 | 12 | 13 => { let _ = self.read_leb128_u32()?; } // array.get/get_s/get_u: typeidx
                        14 => { let _ = self.read_leb128_u32()?; } // array.set: typeidx
                        15 => {} // array.len: no immediates
                        16 => { let _ = self.read_leb128_u32()?; } // array.fill: typeidx
                        17 => { let _ = self.read_leb128_u32()?; let _ = self.read_leb128_u32()?; } // array.copy: typeidx typeidx
                        18 | 19 => { let _ = self.read_leb128_u32()?; let _ = self.read_leb128_u32()?; } // array.init_data/elem: typeidx + idx
                        20 | 21 => { let _ = self.read_leb128_i32()?; } // ref.test, ref.test (nullable): heaptype
                        22 | 23 => { let _ = self.read_leb128_i32()?; } // ref.cast, ref.cast (nullable): heaptype
                        24 | 25 => { // br_on_cast, br_on_cast_fail
                            let _ = self.read_byte()?; // flags
                            let _ = self.read_leb128_u32()?; // label
                            let _ = self.read_leb128_i32()?; // ht1
                            let _ = self.read_leb128_i32()?; // ht2
                        }
                        26 | 27 => {} // any.convert_extern, extern.convert_any: no immediates
                        28 | 29 | 30 => {} // ref.i31, i31.get_s, i31.get_u: no immediates
                        _ => {} // Unknown GC sub-opcode — assume no immediates
                    }
                }
                _ => {
                    // Most instructions have no immediates — just skip the opcode byte
                }
            }
        }
        Ok(self.pc)
    }

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
            self.block_depth = target_idx + 1;
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
        self.block_depth = 0;

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

    /// Try to handle an exception by scanning the block stack for matching try_table catch clauses.
    /// If a match is found, sets up the branch and returns Ok(()).
    /// If no match, returns Err(()) so the caller can propagate.
    fn handle_exception(&mut self, tag_idx: u32, values: &[Value]) -> Result<(), ()> {
        // Scan the block stack from top to bottom within the current function,
        // then unwind through call frames if needed.
        loop {
            let base = if self.call_depth > 0 {
                self.call_stack[self.call_depth - 1].block_stack_base
            } else {
                0
            };

            // Scan block stack from top to bottom for try_table or legacy try with matching catch
            let mut found_try_table = None;
            let mut found_legacy = None;
            let mut try_block_idx = self.block_depth;
            while try_block_idx > base {
                try_block_idx -= 1;
                let bf = self.block_stack[try_block_idx];

                // Check legacy try blocks
                if bf.is_legacy_try {
                    // If this is a delegate block (no catches, has delegate label),
                    // skip ahead by delegate_label levels
                    if bf.legacy_delegate_label != u32::MAX {
                        // Pop this block and skip delegate_label more blocks
                        let skip = bf.legacy_delegate_label as usize;
                        if try_block_idx >= skip {
                            try_block_idx -= skip;
                        } else {
                            try_block_idx = base;
                        }
                        continue;
                    }
                    for ci in 0..bf.legacy_catch_count as usize {
                        let lc = bf.legacy_catches[ci];
                        if lc.tag_idx == u32::MAX {
                            // catch_all: matches any exception
                            found_legacy = Some((try_block_idx, ci));
                            break;
                        } else if self.tags_match(lc.tag_idx, tag_idx) {
                            found_legacy = Some((try_block_idx, ci));
                            break;
                        }
                    }
                    if found_legacy.is_some() {
                        break;
                    }
                    continue;
                }

                if !bf.is_try_table {
                    continue;
                }
                // Check try_table catch clauses
                for ci in 0..bf.catch_count as usize {
                    let cc = bf.catches[ci];
                    match cc.kind {
                        0 => {
                            if self.tags_match(cc.tag_idx, tag_idx) {
                                found_try_table = Some((try_block_idx, ci, false));
                                break;
                            }
                        }
                        1 => {
                            if self.tags_match(cc.tag_idx, tag_idx) {
                                found_try_table = Some((try_block_idx, ci, true));
                                break;
                            }
                        }
                        2 => {
                            found_try_table = Some((try_block_idx, ci, false));
                            break;
                        }
                        3 => {
                            found_try_table = Some((try_block_idx, ci, true));
                            break;
                        }
                        _ => {}
                    }
                }
                if found_try_table.is_some() {
                    break;
                }
            }

            // Handle legacy try catch
            if let Some((try_idx, clause_idx)) = found_legacy {
                let lc = self.block_stack[try_idx].legacy_catches[clause_idx];
                let is_catch_all = lc.tag_idx == u32::MAX;
                let try_frame = self.block_stack[try_idx];

                // Reset stack to the try block's stack base
                self.stack_ptr = try_frame.stack_base;
                // Pop all blocks above AND including the try block
                self.block_depth = try_idx;

                // Push a "catch" frame to replace the try frame.
                // This frame represents the catch handler scope.
                // The validator does the same: pop_ctrl() + push_ctrl() for catch.
                let mut catch_frame = BlockFrame::zero();
                catch_frame.start_pc = lc.handler_pc;
                catch_frame.end_pc = try_frame.end_pc;
                catch_frame.stack_base = self.stack_ptr;
                catch_frame.result_count = try_frame.result_count;
                catch_frame.end_result_count = try_frame.end_result_count;
                catch_frame.is_legacy_try = true;
                // Store exception info for rethrow
                catch_frame.legacy_exception_tag = tag_idx;
                catch_frame.legacy_exception_value_count = values.len().min(4) as u8;
                for (i, v) in values.iter().enumerate().take(4) {
                    catch_frame.legacy_exception_values[i] = *v;
                }
                let _ = self.push_block(catch_frame);

                // Push exception values for catch (not catch_all)
                if !is_catch_all {
                    for v in values {
                        let _ = self.push(*v);
                    }
                }

                // Jump to the handler PC
                self.pc = lc.handler_pc;
                return Ok(());
            }

            if let Some((try_idx, clause_idx, push_exnref)) = found_try_table {
                let cc = self.block_stack[try_idx].catches[clause_idx];
                let label = cc.label;

                // Reset stack to the try_table's stack base
                let try_frame = self.block_stack[try_idx];
                self.stack_ptr = try_frame.stack_base;
                self.block_depth = try_idx;

                // Push the exception values onto the stack for catch/catch_ref
                match cc.kind {
                    0 | 1 => {
                        for v in values {
                            let _ = self.push(*v);
                        }
                    }
                    2 => {}
                    3 => {}
                    _ => {}
                }

                // For catch_ref / catch_all_ref, push exnref
                if push_exnref {
                    let _ = self.push(Value::I32(tag_idx as i32));
                }

                // Branch using the label from the catch clause
                if let Err(_e) = self.branch(label) {
                    return Err(());
                }
                return Ok(());
            }

            // No matching catch in this function's block stack.
            // Unwind the call frame and propagate to the caller.
            if self.call_depth == 0 {
                return Err(());
            }

            let frame = self.call_stack[self.call_depth - 1];
            self.call_depth -= 1;
            self.stack_ptr = frame.stack_base;
            self.pc = frame.return_pc;
            self.block_depth = frame.saved_block_depth;

            if self.call_depth == 0 {
                return Err(());
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
                        self.block_depth -= 1;
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
                    for vi in 0..bf.legacy_exception_value_count as usize {
                        found_values.push(bf.legacy_exception_values[vi]);
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
                    self.block_depth -= 1;
                    let bf = self.block_stack[self.block_depth];
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
                        self.block_depth -= 1;
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
                    self.block_depth = frame.saved_block_depth;
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
                    self.block_depth = frame.saved_block_depth;
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
                    self.block_depth = frame.saved_block_depth;
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
                let rt = resolve_table_alias(&self.table_aliases, table_idx);
                self.tables[rt][idx] = entry;
            }

            // ── Memory ──────────────────────────────────────────────
            0x28 => {
                // i32.load
                let (mi, offset) = try_exec!(self.read_memarg());
                let base = try_exec!(self.pop_i32()) as u32;
                let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
                let val = try_exec!(self.mem_load_i32(mi, addr));
                try_exec!(self.push(Value::I32(val)));
            }
            0x29 => {
                // i64.load
                let (mi, offset) = try_exec!(self.read_memarg());
                let base = try_exec!(self.pop_i32()) as u32;
                let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
                let val = try_exec!(self.mem_load_i64(mi, addr));
                try_exec!(self.push(Value::I64(val)));
            }
            0x36 => {
                // i32.store
                let (mi, offset) = try_exec!(self.read_memarg());
                let val = try_exec!(self.pop_i32());
                let base = try_exec!(self.pop_i32()) as u32;
                let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
                try_exec!(self.mem_store_i32(mi, addr, val));
            }
            0x37 => {
                // i64.store
                let (mi, offset) = try_exec!(self.read_memarg());
                let val = try_exec!(self.pop_i64());
                let base = try_exec!(self.pop_i32()) as u32;
                let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
                try_exec!(self.mem_store_i64(mi, addr, val));
            }

            // ── Float memory ─────────────────────────────────────────
            0x2A => {
                // f32.load
                if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); }
                let (mi, offset) = try_exec!(self.read_memarg());
                let base = try_exec!(self.pop_i32()) as u32;
                let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
                let val = try_exec!(self.mem_load_f32(mi, addr));
                try_exec!(self.push(Value::F32(val)));
            }
            0x2B => {
                // f64.load
                if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); }
                let (mi, offset) = try_exec!(self.read_memarg());
                let base = try_exec!(self.pop_i32()) as u32;
                let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
                let val = try_exec!(self.mem_load_f64(mi, addr));
                try_exec!(self.push(Value::F64(val)));
            }

            // ── Sub-word loads ──────────────────────────────────────
            0x2C => {
                // i32.load8_s
                let (mi, offset) = try_exec!(self.read_memarg());
                let base = try_exec!(self.pop_i32()) as u32;
                let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
                let val = try_exec!(self.mem_load_u8(mi, addr)) as i8;
                try_exec!(self.push(Value::I32(val as i32)));
            }
            0x2D => {
                // i32.load8_u
                let (mi, offset) = try_exec!(self.read_memarg());
                let base = try_exec!(self.pop_i32()) as u32;
                let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
                let val = try_exec!(self.mem_load_u8(mi, addr));
                try_exec!(self.push(Value::I32(val as i32)));
            }
            0x2E => {
                // i32.load16_s
                let (mi, offset) = try_exec!(self.read_memarg());
                let base = try_exec!(self.pop_i32()) as u32;
                let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
                let val = try_exec!(self.mem_load_u16(mi, addr)) as i16;
                try_exec!(self.push(Value::I32(val as i32)));
            }
            0x2F => {
                // i32.load16_u
                let (mi, offset) = try_exec!(self.read_memarg());
                let base = try_exec!(self.pop_i32()) as u32;
                let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
                let val = try_exec!(self.mem_load_u16(mi, addr));
                try_exec!(self.push(Value::I32(val as i32)));
            }
            0x30 => {
                // i64.load8_s
                let (mi, offset) = try_exec!(self.read_memarg());
                let base = try_exec!(self.pop_i32()) as u32;
                let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
                let val = try_exec!(self.mem_load_u8(mi, addr)) as i8;
                try_exec!(self.push(Value::I64(val as i64)));
            }
            0x31 => {
                // i64.load8_u
                let (mi, offset) = try_exec!(self.read_memarg());
                let base = try_exec!(self.pop_i32()) as u32;
                let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
                let val = try_exec!(self.mem_load_u8(mi, addr));
                try_exec!(self.push(Value::I64(val as i64)));
            }
            0x32 => {
                // i64.load16_s
                let (mi, offset) = try_exec!(self.read_memarg());
                let base = try_exec!(self.pop_i32()) as u32;
                let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
                let val = try_exec!(self.mem_load_u16(mi, addr)) as i16;
                try_exec!(self.push(Value::I64(val as i64)));
            }
            0x33 => {
                // i64.load16_u
                let (mi, offset) = try_exec!(self.read_memarg());
                let base = try_exec!(self.pop_i32()) as u32;
                let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
                let val = try_exec!(self.mem_load_u16(mi, addr));
                try_exec!(self.push(Value::I64(val as i64)));
            }
            0x34 => {
                // i64.load32_s
                let (mi, offset) = try_exec!(self.read_memarg());
                let base = try_exec!(self.pop_i32()) as u32;
                let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
                let val = try_exec!(self.mem_load_u32(mi, addr)) as i32;
                try_exec!(self.push(Value::I64(val as i64)));
            }
            0x35 => {
                // i64.load32_u
                let (mi, offset) = try_exec!(self.read_memarg());
                let base = try_exec!(self.pop_i32()) as u32;
                let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
                let val = try_exec!(self.mem_load_u32(mi, addr));
                try_exec!(self.push(Value::I64(val as i64)));
            }

            // ── Sub-word stores ─────────────────────────────────────
            0x3A => {
                // i32.store8
                let (mi, offset) = try_exec!(self.read_memarg());
                let val = try_exec!(self.pop_i32());
                let base = try_exec!(self.pop_i32()) as u32;
                let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
                try_exec!(self.mem_store_u8(mi, addr, val as u8));
            }
            0x3B => {
                // i32.store16
                let (mi, offset) = try_exec!(self.read_memarg());
                let val = try_exec!(self.pop_i32());
                let base = try_exec!(self.pop_i32()) as u32;
                let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
                try_exec!(self.mem_store_u16(mi, addr, val as u16));
            }
            0x3C => {
                // i64.store8
                let (mi, offset) = try_exec!(self.read_memarg());
                let val = try_exec!(self.pop_i64());
                let base = try_exec!(self.pop_i32()) as u32;
                let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
                try_exec!(self.mem_store_u8(mi, addr, val as u8));
            }
            0x3D => {
                // i64.store16
                let (mi, offset) = try_exec!(self.read_memarg());
                let val = try_exec!(self.pop_i64());
                let base = try_exec!(self.pop_i32()) as u32;
                let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
                try_exec!(self.mem_store_u16(mi, addr, val as u16));
            }
            0x3E => {
                // i64.store32
                let (mi, offset) = try_exec!(self.read_memarg());
                let val = try_exec!(self.pop_i64());
                let base = try_exec!(self.pop_i32()) as u32;
                let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
                try_exec!(self.mem_store_u32(mi, addr, val as u32));
            }

            0x38 => {
                // f32.store
                if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); }
                let (mi, offset) = try_exec!(self.read_memarg());
                let val = try_exec!(self.pop_f32());
                let base = try_exec!(self.pop_i32()) as u32;
                let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
                try_exec!(self.mem_store_f32(mi, addr, val));
            }
            0x39 => {
                // f64.store
                if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); }
                let (mi, offset) = try_exec!(self.read_memarg());
                let val = try_exec!(self.pop_f64());
                let base = try_exec!(self.pop_i32()) as u32;
                let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
                try_exec!(self.mem_store_f64(mi, addr, val));
            }

            // ── Memory management ────────────────────────────────────
            0x3F => {
                // memory.size
                let mi = try_exec!(self.read_leb128_u32()) as usize;
                let msz = self.mem_size(mi);
                let page_size = if mi < self.module.memories.len() {
                    if let Some(log2) = self.module.memories[mi].page_size_log2 {
                        1usize << log2
                    } else { WASM_PAGE_SIZE }
                } else { WASM_PAGE_SIZE };
                let pages = (msz / page_size) as i64;
                let is_mem64 = mi < self.module.memories.len() && self.module.memories[mi].is_memory64;
                if is_mem64 {
                    try_exec!(self.push(Value::I64(pages)));
                } else {
                    try_exec!(self.push(Value::I32(pages as i32)));
                }
            }
            0x40 => {
                // memory.grow
                let mi = try_exec!(self.read_leb128_u32()) as usize;
                let is_mem64 = mi < self.module.memories.len() && self.module.memories[mi].is_memory64;
                let delta = if is_mem64 {
                    try_exec!(self.pop_i64()) as u32
                } else {
                    try_exec!(self.pop_i32()) as u32
                };
                let page_size = if mi < self.module.memories.len() {
                    if let Some(log2) = self.module.memories[mi].page_size_log2 {
                        1usize << log2
                    } else { WASM_PAGE_SIZE }
                } else { WASM_PAGE_SIZE };
                let msz = self.mem_size(mi);
                let old_pages = (msz / page_size) as u32;
                let new_pages = old_pages.saturating_add(delta);
                // Check both the module's declared max and the global hard limit
                let module_max = if mi < self.module.memories.len() && self.module.memories[mi].max_pages != u32::MAX {
                    self.module.memories[mi].max_pages as usize
                } else if self.module.has_memory_max && mi == 0 && self.module.memory_max_pages != u32::MAX {
                    self.module.memory_max_pages as usize
                } else {
                    // For custom page sizes, compute a reasonable max in pages
                    let max_bytes = MAX_MEMORY_PAGES * WASM_PAGE_SIZE;
                    max_bytes / page_size
                };
                if new_pages as usize > module_max {
                    // Failure: push -1
                    if is_mem64 {
                        try_exec!(self.push(Value::I64(-1)));
                    } else {
                        try_exec!(self.push(Value::I32(-1)));
                    }
                } else {
                    let new_size = (new_pages as usize).saturating_mul(page_size);
                    if mi < self.memories.len() {
                        self.memories[mi].resize(new_size, 0);
                        self.memory_sizes[mi] = new_size;
                    }
                    if is_mem64 {
                        try_exec!(self.push(Value::I64(old_pages as i64)));
                    } else {
                        try_exec!(self.push(Value::I32(old_pages as i32)));
                    }
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
            0xA8 => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(self.pop_f32()); if a.is_nan() { return ExecResult::Trap(WasmError::InvalidConversionToInteger); } if a <= -2147483904.0_f32 || a >= 2147483648.0_f32 { return ExecResult::Trap(WasmError::IntegerOverflow); } try_exec!(self.push(Value::I32(a as i32))); }
            0xA9 => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(self.pop_f32()); if a.is_nan() { return ExecResult::Trap(WasmError::InvalidConversionToInteger); } if a <= -1.0_f32 || a >= 4294967296.0_f32 { return ExecResult::Trap(WasmError::IntegerOverflow); } try_exec!(self.push(Value::I32(a as u32 as i32))); }
            0xAA => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(self.pop_f64()); if a.is_nan() { return ExecResult::Trap(WasmError::InvalidConversionToInteger); } if a <= -2147483649.0_f64 || a >= 2147483648.0_f64 { return ExecResult::Trap(WasmError::IntegerOverflow); } try_exec!(self.push(Value::I32(a as i32))); }
            0xAB => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(self.pop_f64()); if a.is_nan() { return ExecResult::Trap(WasmError::InvalidConversionToInteger); } if a <= -1.0_f64 || a >= 4294967296.0_f64 { return ExecResult::Trap(WasmError::IntegerOverflow); } try_exec!(self.push(Value::I32(a as u32 as i32))); }
            0xAE => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(self.pop_f32()); if a.is_nan() { return ExecResult::Trap(WasmError::InvalidConversionToInteger); } if a <= -9223373136366403584.0_f32 || a >= 9223372036854775808.0_f32 { return ExecResult::Trap(WasmError::IntegerOverflow); } try_exec!(self.push(Value::I64(a as i64))); }
            0xAF => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(self.pop_f32()); if a.is_nan() { return ExecResult::Trap(WasmError::InvalidConversionToInteger); } if a <= -1.0_f32 || a >= 18446744073709551616.0_f32 { return ExecResult::Trap(WasmError::IntegerOverflow); } try_exec!(self.push(Value::I64(a as u64 as i64))); }
            0xB0 => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(self.pop_f64()); if a.is_nan() { return ExecResult::Trap(WasmError::InvalidConversionToInteger); } if a <= -9223372036854777856.0_f64 || a >= 9223372036854775808.0_f64 { return ExecResult::Trap(WasmError::IntegerOverflow); } try_exec!(self.push(Value::I64(a as i64))); }
            0xB1 => { if self.runtime_class == RuntimeClass::ProofGrade { return ExecResult::Trap(WasmError::FloatsDisabled); } let a = try_exec!(self.pop_f64()); if a.is_nan() { return ExecResult::Trap(WasmError::InvalidConversionToInteger); } if a <= -1.0_f64 || a >= 18446744073709551616.0_f64 { return ExecResult::Trap(WasmError::IntegerOverflow); } try_exec!(self.push(Value::I64(a as u64 as i64))); }
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

                    // memory.init (8)
                    8 => {
                        let seg_idx = try_exec!(self.read_leb128_u32()) as usize;
                        let mi = try_exec!(self.read_leb128_u32()) as usize;
                        let n = try_exec!(self.pop_i32()) as u32;
                        let s = try_exec!(self.pop_i32()) as u32;
                        let d = try_exec!(self.pop_i32()) as u32;
                        let msz = self.mem_size(mi);
                        let is_dropped = seg_idx < self.dropped_data.len() && self.dropped_data[seg_idx];
                        if is_dropped {
                            // Dropped segment: n=0 is OK, but still validate d
                            if n != 0 || s != 0 {
                                return ExecResult::Trap(WasmError::MemoryOutOfBounds);
                            }
                            if (d as usize) > msz {
                                return ExecResult::Trap(WasmError::MemoryOutOfBounds);
                            }
                        } else if seg_idx < self.module.data_segments.len() {
                            let seg_data_offset = self.module.data_segments[seg_idx].data_offset;
                            let seg_data_len = self.module.data_segments[seg_idx].data_len;
                            let src_end = (s as u64) + (n as u64);
                            let dst_end = (d as u64) + (n as u64);
                            if src_end > seg_data_len as u64 || dst_end > msz as u64 {
                                return ExecResult::Trap(WasmError::MemoryOutOfBounds);
                            }
                            for i in 0..(n as usize) {
                                self.memories[mi][(d as usize) + i] = self.module.code[seg_data_offset + (s as usize) + i];
                            }
                        } else {
                            return ExecResult::Trap(WasmError::MemoryOutOfBounds);
                        }
                    }
                    // data.drop (9)
                    9 => {
                        let seg_idx = try_exec!(self.read_leb128_u32()) as usize;
                        if seg_idx < self.dropped_data.len() {
                            self.dropped_data[seg_idx] = true;
                        }
                    }

                    // memory.copy (10)
                    10 => {
                        let dst_mi = try_exec!(self.read_leb128_u32()) as usize;
                        let src_mi = try_exec!(self.read_leb128_u32()) as usize;
                        let n = try_exec!(self.pop_i32()) as u32;
                        let s = try_exec!(self.pop_i32()) as u32;
                        let d = try_exec!(self.pop_i32()) as u32;
                        let nu = n as usize; let su = s as usize; let du = d as usize;
                        let src_msz = self.mem_size(src_mi);
                        let dst_msz = self.mem_size(dst_mi);
                        if su.saturating_add(nu) > src_msz || du.saturating_add(nu) > dst_msz {
                            return ExecResult::Trap(WasmError::MemoryOutOfBounds);
                        }
                        if dst_mi == src_mi {
                            if du <= su {
                                for i in 0..nu { self.memories[dst_mi][du + i] = self.memories[src_mi][su + i]; }
                            } else {
                                for i in (0..nu).rev() { self.memories[dst_mi][du + i] = self.memories[src_mi][su + i]; }
                            }
                        } else {
                            // Cross-memory copy: collect source bytes first to avoid borrow conflict
                            let src_bytes: Vec<u8> = self.memories[src_mi][su..su + nu].to_vec();
                            self.memories[dst_mi][du..du + nu].copy_from_slice(&src_bytes);
                        }
                    }
                    // memory.fill (11)
                    11 => {
                        let mi = try_exec!(self.read_leb128_u32()) as usize;
                        let n = try_exec!(self.pop_i32()) as u32;
                        let val = try_exec!(self.pop_i32()) as u8;
                        let d = try_exec!(self.pop_i32()) as u32;
                        let nu = n as usize; let du = d as usize;
                        let msz = self.mem_size(mi);
                        if du.saturating_add(nu) > msz {
                            return ExecResult::Trap(WasmError::MemoryOutOfBounds);
                        }
                        for i in 0..nu { self.memories[mi][du + i] = val; }
                    }

                    // table.init (12)
                    12 => {
                        let seg_idx = try_exec!(self.read_leb128_u32()) as usize;
                        let tbl_idx = try_exec!(self.read_leb128_u32()) as usize;
                        let is_t64 = tbl_idx < self.module.tables.len() && self.module.tables[tbl_idx].is_table64;
                        let n = try_exec!(self.pop_i32()) as u32; // n is always i32
                        let s = try_exec!(self.pop_i32()) as u32; // s is always i32
                        let d = if is_t64 { try_exec!(self.pop_i64()) as u32 } else { try_exec!(self.pop_i32()) as u32 };
                        let is_dropped = seg_idx < self.dropped_elems.len() && self.dropped_elems[seg_idx];
                        if is_dropped {
                            if n != 0 || s != 0 {
                                return ExecResult::Trap(WasmError::TableIndexOutOfBounds);
                            }
                            if tbl_idx >= self.tables.len() || (d as usize) > self.tables[self.tbl(tbl_idx)].len() {
                                return ExecResult::Trap(WasmError::TableIndexOutOfBounds);
                            }
                        } else if seg_idx < self.module.element_segments.len() {
                            let seg_len = self.module.element_segments[seg_idx].func_indices.len();
                            if tbl_idx >= self.tables.len() {
                                return ExecResult::Trap(WasmError::TableIndexOutOfBounds);
                            }
                            let tbl_len = self.tables[self.tbl(tbl_idx)].len();
                            let src_end = (s as u64) + (n as u64);
                            let dst_end = (d as u64) + (n as u64);
                            if src_end > seg_len as u64 || dst_end > tbl_len as u64 {
                                return ExecResult::Trap(WasmError::TableIndexOutOfBounds);
                            }
                            let rt = resolve_table_alias(&self.table_aliases, tbl_idx);
                            for i in 0..(n as usize) {
                                let func_idx = self.module.element_segments[seg_idx].func_indices[(s as usize) + i];
                                if func_idx == u32::MAX {
                                    self.tables[rt][(d as usize) + i] = None;
                                } else {
                                    self.tables[rt][(d as usize) + i] = Some(func_idx);
                                }
                            }
                        } else {
                            return ExecResult::Trap(WasmError::TableIndexOutOfBounds);
                        }
                    }
                    // elem.drop (13)
                    13 => {
                        let seg_idx = try_exec!(self.read_leb128_u32()) as usize;
                        if seg_idx < self.dropped_elems.len() {
                            self.dropped_elems[seg_idx] = true;
                        }
                    }
                    // table.copy (14)
                    14 => {
                        let dst_tbl = try_exec!(self.read_leb128_u32()) as usize;
                        let src_tbl = try_exec!(self.read_leb128_u32()) as usize;
                        let src_t64 = src_tbl < self.module.tables.len() && self.module.tables[src_tbl].is_table64;
                        let dst_t64 = dst_tbl < self.module.tables.len() && self.module.tables[dst_tbl].is_table64;
                        // n: smaller of src/dst (i32 if either is i32)
                        let n_is_64 = src_t64 && dst_t64;
                        let n = if n_is_64 { try_exec!(self.pop_i64()) as u64 } else { try_exec!(self.pop_i32()) as u32 as u64 };
                        let s = if src_t64 { try_exec!(self.pop_i64()) as u64 } else { try_exec!(self.pop_i32()) as u32 as u64 };
                        let d = if dst_t64 { try_exec!(self.pop_i64()) as u64 } else { try_exec!(self.pop_i32()) as u32 as u64 };
                        let nu = n as usize; let su = s as usize; let du = d as usize;
                        if dst_tbl >= self.tables.len() || src_tbl >= self.tables.len() {
                            return ExecResult::Trap(WasmError::TableIndexOutOfBounds);
                        }
                        if su.saturating_add(nu) > self.tables[self.tbl(src_tbl)].len()
                            || du.saturating_add(nu) > self.tables[self.tbl(dst_tbl)].len()
                        {
                            return ExecResult::Trap(WasmError::TableIndexOutOfBounds);
                        }
                        let rd = resolve_table_alias(&self.table_aliases, dst_tbl);
                        let rs = resolve_table_alias(&self.table_aliases, src_tbl);
                        if rd == rs {
                            if du <= su {
                                for i in 0..nu { self.tables[rd][du + i] = self.tables[rd][su + i]; }
                            } else {
                                for i in (0..nu).rev() { self.tables[rd][du + i] = self.tables[rd][su + i]; }
                            }
                        } else {
                            for i in 0..nu {
                                let val = self.tables[rs][su + i];
                                self.tables[rd][du + i] = val;
                            }
                        }
                    }
                    // table.grow (15)
                    15 => {
                        let tbl_idx = try_exec!(self.read_leb128_u32()) as usize;
                        let is_t64 = tbl_idx < self.module.tables.len() && self.module.tables[tbl_idx].is_table64;
                        let n = if is_t64 { try_exec!(self.pop_i64()) as u64 } else { try_exec!(self.pop_i32()) as u32 as u64 };
                        let init = try_exec!(self.pop());
                        if tbl_idx >= self.tables.len() {
                            if is_t64 { try_exec!(self.push(Value::I64(-1))); } else { try_exec!(self.push(Value::I32(-1))); }
                        } else {
                            let old_size = self.tables[self.tbl(tbl_idx)].len() as u64;
                            let new_size = old_size + n;
                            let max = self.module.tables.get(tbl_idx).and_then(|t| t.max);
                            let limit = max.map_or(MAX_TABLE_SIZE as u64, |m| m as u64);
                            if new_size > limit || new_size > MAX_TABLE_SIZE as u64 {
                                if is_t64 { try_exec!(self.push(Value::I64(-1))); } else { try_exec!(self.push(Value::I32(-1))); }
                            } else {
                                let fill_val = match init {
                                    Value::NullRef => None,
                                    Value::I32(v) => if v < 0 { None } else { Some(v as u32) },
                                    Value::GcRef(heap_idx) => Some(heap_idx | 0x8000_0000),
                                    _ => None,
                                };
                                let rt = resolve_table_alias(&self.table_aliases, tbl_idx);
                                self.tables[rt].resize(new_size as usize, fill_val);
                                if is_t64 { try_exec!(self.push(Value::I64(old_size as i64))); } else { try_exec!(self.push(Value::I32(old_size as i32))); }
                            }
                        }
                    }
                    // table.size (16)
                    16 => {
                        let tbl_idx = try_exec!(self.read_leb128_u32()) as usize;
                        let size = if tbl_idx < self.tables.len() { self.tables[self.tbl(tbl_idx)].len() } else { 0 };
                        if tbl_idx < self.module.tables.len() && self.module.tables[tbl_idx].is_table64 {
                            try_exec!(self.push(Value::I64(size as i64)));
                        } else {
                            try_exec!(self.push(Value::I32(size as i32)));
                        }
                    }
                    // table.fill (17)
                    17 => {
                        let tbl_idx = try_exec!(self.read_leb128_u32()) as usize;
                        let is_t64 = tbl_idx < self.module.tables.len() && self.module.tables[tbl_idx].is_table64;
                        let n = if is_t64 { try_exec!(self.pop_i64()) as u64 } else { try_exec!(self.pop_i32()) as u32 as u64 };
                        let raw_val = try_exec!(self.pop());
                        let d = if is_t64 { try_exec!(self.pop_i64()) as u64 } else { try_exec!(self.pop_i32()) as u32 as u64 };
                        let nu = n as usize; let du = d as usize;
                        if tbl_idx >= self.tables.len() || du.saturating_add(nu) > self.tables[self.tbl(tbl_idx)].len() {
                            return ExecResult::Trap(WasmError::TableIndexOutOfBounds);
                        }
                        let entry = match raw_val {
                            Value::NullRef => None,
                            Value::I32(v) => if v < 0 { None } else { Some(v as u32) },
                            Value::GcRef(heap_idx) => Some(heap_idx | 0x8000_0000),
                            _ => None,
                        };
                        let rt = resolve_table_alias(&self.table_aliases, tbl_idx);
                        for i in 0..nu { self.tables[rt][du + i] = entry; }
                    }

                    // ── Wide-arithmetic (0x13-0x16) ──
                    // i64.add128: [i64, i64, i64, i64] -> [i64, i64]
                    0x13 => {
                        let b_hi = try_exec!(self.pop_i64()) as u64;
                        let b_lo = try_exec!(self.pop_i64()) as u64;
                        let a_hi = try_exec!(self.pop_i64()) as u64;
                        let a_lo = try_exec!(self.pop_i64()) as u64;
                        let a: u128 = (a_hi as u128) << 64 | a_lo as u128;
                        let b: u128 = (b_hi as u128) << 64 | b_lo as u128;
                        let result = a.wrapping_add(b);
                        try_exec!(self.push(Value::I64(result as u64 as i64)));
                        try_exec!(self.push(Value::I64((result >> 64) as u64 as i64)));
                    }
                    // i64.sub128: [i64, i64, i64, i64] -> [i64, i64]
                    0x14 => {
                        let b_hi = try_exec!(self.pop_i64()) as u64;
                        let b_lo = try_exec!(self.pop_i64()) as u64;
                        let a_hi = try_exec!(self.pop_i64()) as u64;
                        let a_lo = try_exec!(self.pop_i64()) as u64;
                        let a: u128 = (a_hi as u128) << 64 | a_lo as u128;
                        let b: u128 = (b_hi as u128) << 64 | b_lo as u128;
                        let result = a.wrapping_sub(b);
                        try_exec!(self.push(Value::I64(result as u64 as i64)));
                        try_exec!(self.push(Value::I64((result >> 64) as u64 as i64)));
                    }
                    // i64.mul_wide_s: [i64, i64] -> [i64, i64]
                    0x15 => {
                        let b = try_exec!(self.pop_i64());
                        let a = try_exec!(self.pop_i64());
                        let result = (a as i128).wrapping_mul(b as i128) as u128;
                        try_exec!(self.push(Value::I64(result as u64 as i64)));
                        try_exec!(self.push(Value::I64((result >> 64) as u64 as i64)));
                    }
                    // i64.mul_wide_u: [i64, i64] -> [i64, i64]
                    0x16 => {
                        let b = try_exec!(self.pop_i64()) as u64;
                        let a = try_exec!(self.pop_i64()) as u64;
                        let result = (a as u128).wrapping_mul(b as u128);
                        try_exec!(self.push(Value::I64(result as u64 as i64)));
                        try_exec!(self.push(Value::I64((result >> 64) as u64 as i64)));
                    }

                    _ => return ExecResult::Trap(WasmError::InvalidOpcode(0xFC)),
                }
            }

            // ── 0xFD prefix: SIMD (v128) ──────────────────────────────
            // Sub-opcode numbering from wasmparser 0.228.0 binary_reader/simd.rs
            0xFD => {
                let simd_op = try_exec!(self.read_leb128_u32());
                match simd_op {
                    // ── Memory (0x00-0x0b) ──────────────────────
                    0x00 => { // v128.load
                        let (mi, offset) = try_exec!(self.read_memarg());
                        let base = try_exec!(self.pop_i32()) as u32;
                        let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
                        let val = try_exec!(self.mem_load_v128(mi, addr));
                        try_exec!(self.push(Value::V128(val)));
                    }
                    0x01..=0x0a => { // v128.load*x*_s/u, load*_splat
                        let (mi, offset) = try_exec!(self.read_memarg());
                        let base = try_exec!(self.pop_i32()) as u32;
                        let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
                        let msz = self.mem_size(mi);
                        let m = self.mem(mi);
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
                        try_exec!(self.push(Value::V128(val)));
                    }
                    0x0b => { // v128.store
                        let (mi, offset) = try_exec!(self.read_memarg());
                        let val = try_exec!(self.pop_v128());
                        let base = try_exec!(self.pop_i32()) as u32;
                        let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
                        try_exec!(self.mem_store_v128(mi, addr, val));
                    }
                    // ── Const/Shuffle/Swizzle (0x0c-0x0e) ────────
                    0x0c => { let val = try_exec!(self.read_v128()); try_exec!(self.push(Value::V128(val))); }
                    0x0d => { // i8x16.shuffle
                        let mut lanes = [0u8; 16]; for i in 0..16 { lanes[i] = try_exec!(self.read_byte()); }
                        let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128());
                        let mut combined = [0u8; 32]; combined[0..16].copy_from_slice(&a.0); combined[16..32].copy_from_slice(&b.0);
                        let mut r = [0u8; 16]; for i in 0..16 { r[i] = combined[(lanes[i] & 31) as usize]; }
                        try_exec!(self.push(Value::V128(V128(r))));
                    }
                    0x0e => { // i8x16.swizzle
                        let s = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128());
                        let mut r = [0u8; 16]; for i in 0..16 { let idx = s.0[i]; r[i] = if idx < 16 { a.0[idx as usize] } else { 0 }; }
                        try_exec!(self.push(Value::V128(V128(r))));
                    }
                    // ── Splat (0x0f-0x14) ────────────────────────
                    0x0f => { let v = try_exec!(self.pop_i32()) as u8; try_exec!(self.push(Value::V128(V128::from_u8x16([v; 16])))); }
                    0x10 => { let v = try_exec!(self.pop_i32()) as i16; try_exec!(self.push(Value::V128(V128::from_i16x8([v; 8])))); }
                    0x11 => { let v = try_exec!(self.pop_i32()); try_exec!(self.push(Value::V128(V128::from_i32x4([v; 4])))); }
                    0x12 => { let v = try_exec!(self.pop_i64()); try_exec!(self.push(Value::V128(V128::from_i64x2([v; 2])))); }
                    0x13 => { let v = try_exec!(self.pop_f32()); try_exec!(self.push(Value::V128(V128::from_f32x4([v; 4])))); }
                    0x14 => { let v = try_exec!(self.pop_f64()); try_exec!(self.push(Value::V128(V128::from_f64x2([v; 2])))); }
                    // ── Extract/Replace lane (0x15-0x22) ─────────
                    0x15 => { let l = try_exec!(self.read_byte()) as usize; let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::I32(a.as_i8x16()[l & 15] as i32))); }
                    0x16 => { let l = try_exec!(self.read_byte()) as usize; let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::I32(a.as_u8x16()[l & 15] as i32))); }
                    0x17 => { let l = try_exec!(self.read_byte()) as usize; let v = try_exec!(self.pop_i32()) as u8; let mut a = try_exec!(self.pop_v128()); a.0[l & 15] = v; try_exec!(self.push(Value::V128(a))); }
                    0x18 => { let l = try_exec!(self.read_byte()) as usize; let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::I32(a.as_i16x8()[l & 7] as i32))); }
                    0x19 => { let l = try_exec!(self.read_byte()) as usize; let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::I32(a.as_u16x8()[l & 7] as i32))); }
                    0x1a => { let l = try_exec!(self.read_byte()) as usize; let v = try_exec!(self.pop_i32()) as i16; let a = try_exec!(self.pop_v128()); let mut arr = a.as_i16x8(); arr[l & 7] = v; try_exec!(self.push(Value::V128(V128::from_i16x8(arr)))); }
                    0x1b => { let l = try_exec!(self.read_byte()) as usize; let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::I32(a.as_i32x4()[l & 3]))); }
                    0x1c => { let l = try_exec!(self.read_byte()) as usize; let v = try_exec!(self.pop_i32()); let a = try_exec!(self.pop_v128()); let mut arr = a.as_i32x4(); arr[l & 3] = v; try_exec!(self.push(Value::V128(V128::from_i32x4(arr)))); }
                    0x1d => { let l = try_exec!(self.read_byte()) as usize; let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::I64(a.as_i64x2()[l & 1]))); }
                    0x1e => { let l = try_exec!(self.read_byte()) as usize; let v = try_exec!(self.pop_i64()); let a = try_exec!(self.pop_v128()); let mut arr = a.as_i64x2(); arr[l & 1] = v; try_exec!(self.push(Value::V128(V128::from_i64x2(arr)))); }
                    0x1f => { let l = try_exec!(self.read_byte()) as usize; let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::F32(a.as_f32x4()[l & 3]))); }
                    0x20 => { let l = try_exec!(self.read_byte()) as usize; let v = try_exec!(self.pop_f32()); let a = try_exec!(self.pop_v128()); let mut arr = a.as_f32x4(); arr[l & 3] = v; try_exec!(self.push(Value::V128(V128::from_f32x4(arr)))); }
                    0x21 => { let l = try_exec!(self.read_byte()) as usize; let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::F64(a.as_f64x2()[l & 1]))); }
                    0x22 => { let l = try_exec!(self.read_byte()) as usize; let v = try_exec!(self.pop_f64()); let a = try_exec!(self.pop_v128()); let mut arr = a.as_f64x2(); arr[l & 1] = v; try_exec!(self.push(Value::V128(V128::from_f64x2(arr)))); }
                    // ── i8x16 compare (0x23-0x2c) ────────────────
                    0x23 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (aa, bb) = (a.as_i8x16(), b.as_i8x16()); let mut r = [0u8; 16]; for i in 0..16 { r[i] = if aa[i] == bb[i] { 0xFF } else { 0 }; } try_exec!(self.push(Value::V128(V128(r)))); }
                    0x24 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (aa, bb) = (a.as_i8x16(), b.as_i8x16()); let mut r = [0u8; 16]; for i in 0..16 { r[i] = if aa[i] != bb[i] { 0xFF } else { 0 }; } try_exec!(self.push(Value::V128(V128(r)))); }
                    0x25 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (aa, bb) = (a.as_i8x16(), b.as_i8x16()); let mut r = [0u8; 16]; for i in 0..16 { r[i] = if aa[i] < bb[i] { 0xFF } else { 0 }; } try_exec!(self.push(Value::V128(V128(r)))); }
                    0x26 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (aa, bb) = (a.as_u8x16(), b.as_u8x16()); let mut r = [0u8; 16]; for i in 0..16 { r[i] = if aa[i] < bb[i] { 0xFF } else { 0 }; } try_exec!(self.push(Value::V128(V128(r)))); }
                    0x27 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (aa, bb) = (a.as_i8x16(), b.as_i8x16()); let mut r = [0u8; 16]; for i in 0..16 { r[i] = if aa[i] > bb[i] { 0xFF } else { 0 }; } try_exec!(self.push(Value::V128(V128(r)))); }
                    0x28 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (aa, bb) = (a.as_u8x16(), b.as_u8x16()); let mut r = [0u8; 16]; for i in 0..16 { r[i] = if aa[i] > bb[i] { 0xFF } else { 0 }; } try_exec!(self.push(Value::V128(V128(r)))); }
                    0x29 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (aa, bb) = (a.as_i8x16(), b.as_i8x16()); let mut r = [0u8; 16]; for i in 0..16 { r[i] = if aa[i] <= bb[i] { 0xFF } else { 0 }; } try_exec!(self.push(Value::V128(V128(r)))); }
                    0x2a => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (aa, bb) = (a.as_u8x16(), b.as_u8x16()); let mut r = [0u8; 16]; for i in 0..16 { r[i] = if aa[i] <= bb[i] { 0xFF } else { 0 }; } try_exec!(self.push(Value::V128(V128(r)))); }
                    0x2b => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (aa, bb) = (a.as_i8x16(), b.as_i8x16()); let mut r = [0u8; 16]; for i in 0..16 { r[i] = if aa[i] >= bb[i] { 0xFF } else { 0 }; } try_exec!(self.push(Value::V128(V128(r)))); }
                    0x2c => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (aa, bb) = (a.as_u8x16(), b.as_u8x16()); let mut r = [0u8; 16]; for i in 0..16 { r[i] = if aa[i] >= bb[i] { 0xFF } else { 0 }; } try_exec!(self.push(Value::V128(V128(r)))); }
                    // ── i16x8 compare (0x2d-0x36) ────────────────
                    0x2d => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (sa, sb) = (a.as_i16x8(), b.as_i16x8()); try_exec!(self.push(Value::V128(V128::from_i16x8(core::array::from_fn(|i| if sa[i]==sb[i] {-1} else {0}))))); }
                    0x2e => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (sa, sb) = (a.as_i16x8(), b.as_i16x8()); try_exec!(self.push(Value::V128(V128::from_i16x8(core::array::from_fn(|i| if sa[i]!=sb[i] {-1} else {0}))))); }
                    0x2f => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (sa, sb) = (a.as_i16x8(), b.as_i16x8()); try_exec!(self.push(Value::V128(V128::from_i16x8(core::array::from_fn(|i| if sa[i]<sb[i] {-1} else {0}))))); }
                    0x30 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (ua, ub) = (a.as_u16x8(), b.as_u16x8()); try_exec!(self.push(Value::V128(V128::from_i16x8(core::array::from_fn(|i| if ua[i]<ub[i] {-1} else {0}))))); }
                    0x31 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (sa, sb) = (a.as_i16x8(), b.as_i16x8()); try_exec!(self.push(Value::V128(V128::from_i16x8(core::array::from_fn(|i| if sa[i]>sb[i] {-1} else {0}))))); }
                    0x32 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (ua, ub) = (a.as_u16x8(), b.as_u16x8()); try_exec!(self.push(Value::V128(V128::from_i16x8(core::array::from_fn(|i| if ua[i]>ub[i] {-1} else {0}))))); }
                    0x33 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (sa, sb) = (a.as_i16x8(), b.as_i16x8()); try_exec!(self.push(Value::V128(V128::from_i16x8(core::array::from_fn(|i| if sa[i]<=sb[i] {-1} else {0}))))); }
                    0x34 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (ua, ub) = (a.as_u16x8(), b.as_u16x8()); try_exec!(self.push(Value::V128(V128::from_i16x8(core::array::from_fn(|i| if ua[i]<=ub[i] {-1} else {0}))))); }
                    0x35 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (sa, sb) = (a.as_i16x8(), b.as_i16x8()); try_exec!(self.push(Value::V128(V128::from_i16x8(core::array::from_fn(|i| if sa[i]>=sb[i] {-1} else {0}))))); }
                    0x36 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (ua, ub) = (a.as_u16x8(), b.as_u16x8()); try_exec!(self.push(Value::V128(V128::from_i16x8(core::array::from_fn(|i| if ua[i]>=ub[i] {-1} else {0}))))); }
                    // ── i32x4 compare (0x37-0x40) ────────────────
                    0x37 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| if a.as_i32x4()[i]==b.as_i32x4()[i] {-1} else {0}))))); }
                    0x38 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| if a.as_i32x4()[i]!=b.as_i32x4()[i] {-1} else {0}))))); }
                    0x39 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| if a.as_i32x4()[i]<b.as_i32x4()[i] {-1} else {0}))))); }
                    0x3a => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| if a.as_u32x4()[i]<b.as_u32x4()[i] {-1i32} else {0}))))); }
                    0x3b => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| if a.as_i32x4()[i]>b.as_i32x4()[i] {-1} else {0}))))); }
                    0x3c => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| if a.as_u32x4()[i]>b.as_u32x4()[i] {-1i32} else {0}))))); }
                    0x3d => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| if a.as_i32x4()[i]<=b.as_i32x4()[i] {-1} else {0}))))); }
                    0x3e => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| if a.as_u32x4()[i]<=b.as_u32x4()[i] {-1i32} else {0}))))); }
                    0x3f => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| if a.as_i32x4()[i]>=b.as_i32x4()[i] {-1} else {0}))))); }
                    0x40 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| if a.as_u32x4()[i]>=b.as_u32x4()[i] {-1i32} else {0}))))); }
                    // ── f32x4 compare (0x41-0x46) ────────────────
                    0x41 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| if a.as_f32x4()[i]==b.as_f32x4()[i] {-1} else {0}))))); }
                    0x42 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| if a.as_f32x4()[i]!=b.as_f32x4()[i] {-1} else {0}))))); }
                    0x43 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| if a.as_f32x4()[i]<b.as_f32x4()[i] {-1} else {0}))))); }
                    0x44 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| if a.as_f32x4()[i]>b.as_f32x4()[i] {-1} else {0}))))); }
                    0x45 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| if a.as_f32x4()[i]<=b.as_f32x4()[i] {-1} else {0}))))); }
                    0x46 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| if a.as_f32x4()[i]>=b.as_f32x4()[i] {-1} else {0}))))); }
                    // ── f64x2 compare (0x47-0x4c) ────────────────
                    0x47 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_i64x2(core::array::from_fn(|i| if a.as_f64x2()[i]==b.as_f64x2()[i] {-1i64} else {0}))))); }
                    0x48 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_i64x2(core::array::from_fn(|i| if a.as_f64x2()[i]!=b.as_f64x2()[i] {-1i64} else {0}))))); }
                    0x49 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_i64x2(core::array::from_fn(|i| if a.as_f64x2()[i]<b.as_f64x2()[i] {-1i64} else {0}))))); }
                    0x4a => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_i64x2(core::array::from_fn(|i| if a.as_f64x2()[i]>b.as_f64x2()[i] {-1i64} else {0}))))); }
                    0x4b => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_i64x2(core::array::from_fn(|i| if a.as_f64x2()[i]<=b.as_f64x2()[i] {-1i64} else {0}))))); }
                    0x4c => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_i64x2(core::array::from_fn(|i| if a.as_f64x2()[i]>=b.as_f64x2()[i] {-1i64} else {0}))))); }
                    // ── v128 bitwise (0x4d-0x53) ─────────────────
                    0x4d => { let a = try_exec!(self.pop_v128()); let mut r = [0u8; 16]; for i in 0..16 { r[i] = !a.0[i]; } try_exec!(self.push(Value::V128(V128(r)))); }
                    0x4e => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let mut r = [0u8; 16]; for i in 0..16 { r[i] = a.0[i] & b.0[i]; } try_exec!(self.push(Value::V128(V128(r)))); }
                    0x4f => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let mut r = [0u8; 16]; for i in 0..16 { r[i] = a.0[i] & !b.0[i]; } try_exec!(self.push(Value::V128(V128(r)))); }
                    0x50 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let mut r = [0u8; 16]; for i in 0..16 { r[i] = a.0[i] | b.0[i]; } try_exec!(self.push(Value::V128(V128(r)))); }
                    0x51 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let mut r = [0u8; 16]; for i in 0..16 { r[i] = a.0[i] ^ b.0[i]; } try_exec!(self.push(Value::V128(V128(r)))); }
                    0x52 => { let c = try_exec!(self.pop_v128()); let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let mut r = [0u8; 16]; for i in 0..16 { r[i] = (a.0[i] & c.0[i]) | (b.0[i] & !c.0[i]); } try_exec!(self.push(Value::V128(V128(r)))); }
                    0x53 => { let a = try_exec!(self.pop_v128()); let any = a.0.iter().any(|&b| b != 0); try_exec!(self.push(Value::I32(if any { 1 } else { 0 }))); }
                    // ── Load/Store lane (0x54-0x5b) ──────────────
                    0x54..=0x57 => { // load8/16/32/64_lane
                        let (mi, offset) = try_exec!(self.read_memarg()); let lane = try_exec!(self.read_byte()) as usize;
                        let mut v = try_exec!(self.pop_v128()); let base = try_exec!(self.pop_i32()) as u32;
                        let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
                        let msz = self.mem_size(mi);
                        match simd_op {
                            0x54 => { if addr >= msz { return ExecResult::Trap(WasmError::MemoryOutOfBounds); } v.0[lane & 15] = self.mem(mi)[addr]; }
                            0x55 => { if addr + 2 > msz { return ExecResult::Trap(WasmError::MemoryOutOfBounds); } let l = (lane & 7) * 2; let m = self.mem(mi); v.0[l] = m[addr]; v.0[l+1] = m[addr+1]; }
                            0x56 => { if addr + 4 > msz { return ExecResult::Trap(WasmError::MemoryOutOfBounds); } let l = (lane & 3) * 4; v.0[l..l+4].copy_from_slice(&self.mem(mi)[addr..addr+4]); }
                            0x57 => { if addr + 8 > msz { return ExecResult::Trap(WasmError::MemoryOutOfBounds); } let l = (lane & 1) * 8; v.0[l..l+8].copy_from_slice(&self.mem(mi)[addr..addr+8]); }
                            _ => {}
                        }
                        try_exec!(self.push(Value::V128(v)));
                    }
                    0x58..=0x5b => { // store8/16/32/64_lane
                        let (mi, offset) = try_exec!(self.read_memarg()); let lane = try_exec!(self.read_byte()) as usize;
                        let v = try_exec!(self.pop_v128()); let base = try_exec!(self.pop_i32()) as u32;
                        let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
                        let msz = self.mem_size(mi);
                        match simd_op {
                            0x58 => { if addr >= msz { return ExecResult::Trap(WasmError::MemoryOutOfBounds); } self.mem_mut(mi)[addr] = v.0[lane & 15]; }
                            0x59 => { if addr + 2 > msz { return ExecResult::Trap(WasmError::MemoryOutOfBounds); } let l = (lane & 7) * 2; let m = self.mem_mut(mi); m[addr] = v.0[l]; m[addr+1] = v.0[l+1]; }
                            0x5a => { if addr + 4 > msz { return ExecResult::Trap(WasmError::MemoryOutOfBounds); } let l = (lane & 3) * 4; self.mem_mut(mi)[addr..addr+4].copy_from_slice(&v.0[l..l+4]); }
                            0x5b => { if addr + 8 > msz { return ExecResult::Trap(WasmError::MemoryOutOfBounds); } let l = (lane & 1) * 8; self.mem_mut(mi)[addr..addr+8].copy_from_slice(&v.0[l..l+8]); }
                            _ => {}
                        }
                    }
                    // ── Load zero (0x5c-0x5d) ────────────────────
                    0x5c => { let (mi, o) = try_exec!(self.read_memarg()); let b = try_exec!(self.pop_i32()) as u32; let addr = try_exec!(b.checked_add(o).ok_or(WasmError::MemoryOutOfBounds)) as usize; let v = try_exec!(self.mem_load_u32(mi, addr)); let mut r = [0u8; 16]; r[0..4].copy_from_slice(&v.to_le_bytes()); try_exec!(self.push(Value::V128(V128(r)))); }
                    0x5d => { let (mi, o) = try_exec!(self.read_memarg()); let b = try_exec!(self.pop_i32()) as u32; let addr = try_exec!(b.checked_add(o).ok_or(WasmError::MemoryOutOfBounds)) as usize; let msz = self.mem_size(mi); if addr.checked_add(8).ok_or(WasmError::MemoryOutOfBounds).is_err() || addr + 8 > msz { return ExecResult::Trap(WasmError::MemoryOutOfBounds); } let mut r = [0u8; 16]; r[0..8].copy_from_slice(&self.mem(mi)[addr..addr+8]); try_exec!(self.push(Value::V128(V128(r)))); }
                    // ── Conversion (0x5e-0x5f) ───────────────────
                    0x5e => { let a = try_exec!(self.pop_v128()); let aa = a.as_f64x2(); try_exec!(self.push(Value::V128(V128::from_f32x4([aa[0] as f32, aa[1] as f32, 0.0, 0.0])))); }
                    0x5f => { let a = try_exec!(self.pop_v128()); let aa = a.as_f32x4(); try_exec!(self.push(Value::V128(V128::from_f64x2([aa[0] as f64, aa[1] as f64])))); }
                    // ── i8x16 arithmetic (0x60-0x7b) with interleaved f32x4/f64x2 rounding ──
                    0x60 => { let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_i8x16(core::array::from_fn(|i| a.as_i8x16()[i].wrapping_abs()))))); }
                    0x61 => { let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_i8x16(core::array::from_fn(|i| a.as_i8x16()[i].wrapping_neg()))))); }
                    0x62 => { let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_u8x16(core::array::from_fn(|i| a.as_u8x16()[i].count_ones() as u8))))); }
                    0x63 => { let a = try_exec!(self.pop_v128()); let all = a.as_i8x16().iter().all(|&v| v != 0); try_exec!(self.push(Value::I32(if all { 1 } else { 0 }))); }
                    0x64 => { let a = try_exec!(self.pop_v128()); let aa = a.as_u8x16(); let mut r = 0u32; for i in 0..16 { if aa[i] & 0x80 != 0 { r |= 1 << i; } } try_exec!(self.push(Value::I32(r as i32))); }
                    0x65 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (aa, bb) = (a.as_i16x8(), b.as_i16x8()); let mut r = [0u8; 16]; for i in 0..8 { r[i] = aa[i].clamp(-128,127) as i8 as u8; } for i in 0..8 { r[i+8] = bb[i].clamp(-128,127) as i8 as u8; } try_exec!(self.push(Value::V128(V128(r)))); }
                    0x66 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (aa, bb) = (a.as_i16x8(), b.as_i16x8()); let mut r = [0u8; 16]; for i in 0..8 { r[i] = aa[i].clamp(0,255) as u8; } for i in 0..8 { r[i+8] = bb[i].clamp(0,255) as u8; } try_exec!(self.push(Value::V128(V128(r)))); }
                    0x67 => { let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_f32x4(core::array::from_fn(|i| Self::wasm_ceil_f32(a.as_f32x4()[i])))))); }
                    0x68 => { let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_f32x4(core::array::from_fn(|i| Self::wasm_floor_f32(a.as_f32x4()[i])))))); }
                    0x69 => { let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_f32x4(core::array::from_fn(|i| Self::wasm_trunc_f32(a.as_f32x4()[i])))))); }
                    0x6a => { let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_f32x4(core::array::from_fn(|i| Self::wasm_nearest_f32(a.as_f32x4()[i])))))); }
                    0x6b => { let s = try_exec!(self.pop_i32()) as u32; let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_u8x16(core::array::from_fn(|i| a.as_u8x16()[i].wrapping_shl(s & 7)))))); }
                    0x6c => { let s = try_exec!(self.pop_i32()) as u32; let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_i8x16(core::array::from_fn(|i| a.as_i8x16()[i].wrapping_shr(s & 7)))))); }
                    0x6d => { let s = try_exec!(self.pop_i32()) as u32; let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_u8x16(core::array::from_fn(|i| a.as_u8x16()[i].wrapping_shr(s & 7)))))); }
                    0x6e => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_u8x16(core::array::from_fn(|i| a.as_u8x16()[i].wrapping_add(b.as_u8x16()[i])))))); }
                    0x6f => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_i8x16(core::array::from_fn(|i| a.as_i8x16()[i].saturating_add(b.as_i8x16()[i])))))); }
                    0x70 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_u8x16(core::array::from_fn(|i| a.as_u8x16()[i].saturating_add(b.as_u8x16()[i])))))); }
                    0x71 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_u8x16(core::array::from_fn(|i| a.as_u8x16()[i].wrapping_sub(b.as_u8x16()[i])))))); }
                    0x72 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_i8x16(core::array::from_fn(|i| a.as_i8x16()[i].saturating_sub(b.as_i8x16()[i])))))); }
                    0x73 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_u8x16(core::array::from_fn(|i| a.as_u8x16()[i].saturating_sub(b.as_u8x16()[i])))))); }
                    0x74 => { let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_f64x2(core::array::from_fn(|i| Self::wasm_ceil_f64(a.as_f64x2()[i])))))); }
                    0x75 => { let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_f64x2(core::array::from_fn(|i| Self::wasm_floor_f64(a.as_f64x2()[i])))))); }
                    0x76 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_i8x16(core::array::from_fn(|i| a.as_i8x16()[i].min(b.as_i8x16()[i])))))); }
                    0x77 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_u8x16(core::array::from_fn(|i| a.as_u8x16()[i].min(b.as_u8x16()[i])))))); }
                    0x78 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_i8x16(core::array::from_fn(|i| a.as_i8x16()[i].max(b.as_i8x16()[i])))))); }
                    0x79 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_u8x16(core::array::from_fn(|i| a.as_u8x16()[i].max(b.as_u8x16()[i])))))); }
                    0x7a => { let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_f64x2(core::array::from_fn(|i| Self::wasm_trunc_f64(a.as_f64x2()[i])))))); }
                    0x7b => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_u8x16(core::array::from_fn(|i| ((a.as_u8x16()[i] as u16 + b.as_u8x16()[i] as u16 + 1) / 2) as u8))))); }
                    // ── Pairwise add (0x7c-0x7f) ─────────────────
                    0x7c => { let a = try_exec!(self.pop_v128()); let aa = a.as_i8x16(); try_exec!(self.push(Value::V128(V128::from_i16x8(core::array::from_fn(|i| aa[i*2] as i16 + aa[i*2+1] as i16))))); }
                    0x7d => { let a = try_exec!(self.pop_v128()); let aa = a.as_u8x16(); try_exec!(self.push(Value::V128(V128::from_i16x8(core::array::from_fn(|i| aa[i*2] as i16 + aa[i*2+1] as i16))))); }
                    0x7e => { let a = try_exec!(self.pop_v128()); let aa = a.as_i16x8(); try_exec!(self.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| aa[i*2] as i32 + aa[i*2+1] as i32))))); }
                    0x7f => { let a = try_exec!(self.pop_v128()); let aa = a.as_u16x8(); try_exec!(self.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| aa[i*2] as i32 + aa[i*2+1] as i32))))); }
                    // ── i16x8 arithmetic (0x80-0x9f) with interleaved f64x2 ──
                    0x80 => { let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_i16x8(core::array::from_fn(|i| (a.as_i16x8()[i] as i32).unsigned_abs() as i16))))); }
                    0x81 => { let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_i16x8(core::array::from_fn(|i| a.as_i16x8()[i].wrapping_neg()))))); }
                    0x82 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (aa,bb) = (a.as_i16x8(), b.as_i16x8()); let r: [i16; 8] = core::array::from_fn(|i| { let x = aa[i] as i32; let y = bb[i] as i32; ((x*y+(1<<14))>>15).clamp(i16::MIN as i32, i16::MAX as i32) as i16 }); try_exec!(self.push(Value::V128(V128::from_i16x8(r)))); }
                    0x83 => { let a = try_exec!(self.pop_v128()); let all = a.as_i16x8().iter().all(|&v| v != 0); try_exec!(self.push(Value::I32(if all { 1 } else { 0 }))); }
                    0x84 => { let a = try_exec!(self.pop_v128()); let aa = a.as_u16x8(); let mut r = 0u32; for i in 0..8 { if aa[i] & 0x8000 != 0 { r |= 1 << i; } } try_exec!(self.push(Value::I32(r as i32))); }
                    0x85 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (aa,bb) = (a.as_i32x4(), b.as_i32x4()); let mut r = [0i16; 8]; for i in 0..4 { r[i] = aa[i].clamp(-32768,32767) as i16; } for i in 0..4 { r[i+4] = bb[i].clamp(-32768,32767) as i16; } try_exec!(self.push(Value::V128(V128::from_i16x8(r)))); }
                    0x86 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (aa,bb) = (a.as_i32x4(), b.as_i32x4()); let mut r = [0i16; 8]; for i in 0..4 { r[i] = aa[i].clamp(0,65535) as u16 as i16; } for i in 0..4 { r[i+4] = bb[i].clamp(0,65535) as u16 as i16; } try_exec!(self.push(Value::V128(V128::from_i16x8(r)))); }
                    0x87 => { let a = try_exec!(self.pop_v128()); let aa = a.as_i8x16(); try_exec!(self.push(Value::V128(V128::from_i16x8(core::array::from_fn(|i| aa[i] as i16))))); }
                    0x88 => { let a = try_exec!(self.pop_v128()); let aa = a.as_i8x16(); try_exec!(self.push(Value::V128(V128::from_i16x8(core::array::from_fn(|i| aa[i+8] as i16))))); }
                    0x89 => { let a = try_exec!(self.pop_v128()); let aa = a.as_u8x16(); try_exec!(self.push(Value::V128(V128::from_i16x8(core::array::from_fn(|i| aa[i] as i16))))); }
                    0x8a => { let a = try_exec!(self.pop_v128()); let aa = a.as_u8x16(); try_exec!(self.push(Value::V128(V128::from_i16x8(core::array::from_fn(|i| aa[i+8] as i16))))); }
                    0x8b => { let s = try_exec!(self.pop_i32()) as u32; let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_i16x8(core::array::from_fn(|i| a.as_i16x8()[i].wrapping_shl(s & 15)))))); }
                    0x8c => { let s = try_exec!(self.pop_i32()) as u32; let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_i16x8(core::array::from_fn(|i| a.as_i16x8()[i].wrapping_shr(s & 15)))))); }
                    0x8d => { let s = try_exec!(self.pop_i32()) as u32; let a = try_exec!(self.pop_v128()); let r: [i16; 8] = core::array::from_fn(|i| a.as_u16x8()[i].wrapping_shr(s & 15) as i16); try_exec!(self.push(Value::V128(V128::from_i16x8(r)))); }
                    0x8e => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_i16x8(core::array::from_fn(|i| a.as_i16x8()[i].wrapping_add(b.as_i16x8()[i])))))); }
                    0x8f => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_i16x8(core::array::from_fn(|i| a.as_i16x8()[i].saturating_add(b.as_i16x8()[i])))))); }
                    0x90 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let r: [i16; 8] = core::array::from_fn(|i| a.as_u16x8()[i].saturating_add(b.as_u16x8()[i]) as i16); try_exec!(self.push(Value::V128(V128::from_i16x8(r)))); }
                    0x91 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_i16x8(core::array::from_fn(|i| a.as_i16x8()[i].wrapping_sub(b.as_i16x8()[i])))))); }
                    0x92 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_i16x8(core::array::from_fn(|i| a.as_i16x8()[i].saturating_sub(b.as_i16x8()[i])))))); }
                    0x93 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let r: [i16; 8] = core::array::from_fn(|i| a.as_u16x8()[i].saturating_sub(b.as_u16x8()[i]) as i16); try_exec!(self.push(Value::V128(V128::from_i16x8(r)))); }
                    0x94 => { let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_f64x2(core::array::from_fn(|i| Self::wasm_nearest_f64(a.as_f64x2()[i])))))); }
                    0x95 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_i16x8(core::array::from_fn(|i| a.as_i16x8()[i].wrapping_mul(b.as_i16x8()[i])))))); }
                    0x96 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_i16x8(core::array::from_fn(|i| a.as_i16x8()[i].min(b.as_i16x8()[i])))))); }
                    0x97 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let r: [i16; 8] = core::array::from_fn(|i| a.as_u16x8()[i].min(b.as_u16x8()[i]) as i16); try_exec!(self.push(Value::V128(V128::from_i16x8(r)))); }
                    0x98 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_i16x8(core::array::from_fn(|i| a.as_i16x8()[i].max(b.as_i16x8()[i])))))); }
                    0x99 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let r: [i16; 8] = core::array::from_fn(|i| a.as_u16x8()[i].max(b.as_u16x8()[i]) as i16); try_exec!(self.push(Value::V128(V128::from_i16x8(r)))); }
                    0x9b => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let r: [i16; 8] = core::array::from_fn(|i| ((a.as_u16x8()[i] as u32 + b.as_u16x8()[i] as u32 + 1) / 2) as i16); try_exec!(self.push(Value::V128(V128::from_i16x8(r)))); }
                    0x9c => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_i16x8(core::array::from_fn(|i| a.as_i8x16()[i] as i16 * b.as_i8x16()[i] as i16))))); }
                    0x9d => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_i16x8(core::array::from_fn(|i| a.as_i8x16()[i+8] as i16 * b.as_i8x16()[i+8] as i16))))); }
                    0x9e => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_i16x8(core::array::from_fn(|i| (a.as_u8x16()[i] as i16).wrapping_mul(b.as_u8x16()[i] as i16)))))); }
                    0x9f => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_i16x8(core::array::from_fn(|i| (a.as_u8x16()[i+8] as i16).wrapping_mul(b.as_u8x16()[i+8] as i16)))))); }
                    // ── i32x4 arithmetic (0xa0-0xbf) ─────────────
                    0xa0 => { let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| a.as_i32x4()[i].wrapping_abs()))))); }
                    0xa1 => { let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| a.as_i32x4()[i].wrapping_neg()))))); }
                    0xa3 => { let a = try_exec!(self.pop_v128()); let all = a.as_i32x4().iter().all(|&v| v != 0); try_exec!(self.push(Value::I32(if all { 1 } else { 0 }))); }
                    0xa4 => { let a = try_exec!(self.pop_v128()); let aa = a.as_u32x4(); let mut r = 0u32; for i in 0..4 { if aa[i] & 0x8000_0000 != 0 { r |= 1 << i; } } try_exec!(self.push(Value::I32(r as i32))); }
                    0xa7 => { let a = try_exec!(self.pop_v128()); let aa = a.as_i16x8(); try_exec!(self.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| aa[i] as i32))))); }
                    0xa8 => { let a = try_exec!(self.pop_v128()); let aa = a.as_i16x8(); try_exec!(self.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| aa[i+4] as i32))))); }
                    0xa9 => { let a = try_exec!(self.pop_v128()); let aa = a.as_u16x8(); try_exec!(self.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| aa[i] as i32))))); }
                    0xaa => { let a = try_exec!(self.pop_v128()); let aa = a.as_u16x8(); try_exec!(self.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| aa[i+4] as i32))))); }
                    0xab => { let s = try_exec!(self.pop_i32()) as u32; let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| a.as_i32x4()[i].wrapping_shl(s & 31)))))); }
                    0xac => { let s = try_exec!(self.pop_i32()) as u32; let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| a.as_i32x4()[i].wrapping_shr(s & 31)))))); }
                    0xad => { let s = try_exec!(self.pop_i32()) as u32; let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_u32x4(core::array::from_fn(|i| a.as_u32x4()[i].wrapping_shr(s & 31)))))); }
                    0xae => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| a.as_i32x4()[i].wrapping_add(b.as_i32x4()[i])))))); }
                    0xb1 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| a.as_i32x4()[i].wrapping_sub(b.as_i32x4()[i])))))); }
                    0xb5 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| a.as_i32x4()[i].wrapping_mul(b.as_i32x4()[i])))))); }
                    0xb6 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| a.as_i32x4()[i].min(b.as_i32x4()[i])))))); }
                    0xb7 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_u32x4(core::array::from_fn(|i| a.as_u32x4()[i].min(b.as_u32x4()[i])))))); }
                    0xb8 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| a.as_i32x4()[i].max(b.as_i32x4()[i])))))); }
                    0xb9 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_u32x4(core::array::from_fn(|i| a.as_u32x4()[i].max(b.as_u32x4()[i])))))); }
                    0xba => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); let (aa,bb) = (a.as_i16x8(), b.as_i16x8()); let r: [i32; 4] = core::array::from_fn(|i| (aa[i*2] as i32)*(bb[i*2] as i32)+(aa[i*2+1] as i32)*(bb[i*2+1] as i32)); try_exec!(self.push(Value::V128(V128::from_i32x4(r)))); }
                    0xbc => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| a.as_i16x8()[i] as i32 * b.as_i16x8()[i] as i32))))); }
                    0xbd => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| a.as_i16x8()[i+4] as i32 * b.as_i16x8()[i+4] as i32))))); }
                    0xbe => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_u32x4(core::array::from_fn(|i| a.as_u16x8()[i] as u32 * b.as_u16x8()[i] as u32))))); }
                    0xbf => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_u32x4(core::array::from_fn(|i| a.as_u16x8()[i+4] as u32 * b.as_u16x8()[i+4] as u32))))); }
                    // ── i64x2 arithmetic (0xc0-0xdf) ─────────────
                    0xc0 => { let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_i64x2(core::array::from_fn(|i| a.as_i64x2()[i].wrapping_abs()))))); }
                    0xc1 => { let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_i64x2(core::array::from_fn(|i| a.as_i64x2()[i].wrapping_neg()))))); }
                    0xc3 => { let a = try_exec!(self.pop_v128()); let all = a.as_i64x2().iter().all(|&v| v != 0); try_exec!(self.push(Value::I32(if all { 1 } else { 0 }))); }
                    0xc4 => { let a = try_exec!(self.pop_v128()); let aa = a.as_u64x2(); let mut r = 0u32; for i in 0..2 { if aa[i] & 0x8000_0000_0000_0000 != 0 { r |= 1 << i; } } try_exec!(self.push(Value::I32(r as i32))); }
                    0xc7 => { let a = try_exec!(self.pop_v128()); let aa = a.as_i32x4(); try_exec!(self.push(Value::V128(V128::from_i64x2([aa[0] as i64, aa[1] as i64])))); }
                    0xc8 => { let a = try_exec!(self.pop_v128()); let aa = a.as_i32x4(); try_exec!(self.push(Value::V128(V128::from_i64x2([aa[2] as i64, aa[3] as i64])))); }
                    0xc9 => { let a = try_exec!(self.pop_v128()); let aa = a.as_u32x4(); try_exec!(self.push(Value::V128(V128::from_i64x2([aa[0] as i64, aa[1] as i64])))); }
                    0xca => { let a = try_exec!(self.pop_v128()); let aa = a.as_u32x4(); try_exec!(self.push(Value::V128(V128::from_i64x2([aa[2] as i64, aa[3] as i64])))); }
                    0xcb => { let s = try_exec!(self.pop_i32()) as u32; let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_i64x2(core::array::from_fn(|i| a.as_i64x2()[i].wrapping_shl(s & 63)))))); }
                    0xcc => { let s = try_exec!(self.pop_i32()) as u32; let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_i64x2(core::array::from_fn(|i| a.as_i64x2()[i].wrapping_shr(s & 63)))))); }
                    0xcd => { let s = try_exec!(self.pop_i32()) as u32; let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_i64x2(core::array::from_fn(|i| (a.as_u64x2()[i].wrapping_shr(s & 63)) as i64))))); }
                    0xce => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_i64x2(core::array::from_fn(|i| a.as_i64x2()[i].wrapping_add(b.as_i64x2()[i])))))); }
                    0xd1 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_i64x2(core::array::from_fn(|i| a.as_i64x2()[i].wrapping_sub(b.as_i64x2()[i])))))); }
                    0xd5 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_i64x2(core::array::from_fn(|i| a.as_i64x2()[i].wrapping_mul(b.as_i64x2()[i])))))); }
                    // ── i64x2 compare (0xd6-0xdb) ────────────────
                    0xd6 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_i64x2(core::array::from_fn(|i| if a.as_i64x2()[i]==b.as_i64x2()[i] {-1} else {0}))))); }
                    0xd7 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_i64x2(core::array::from_fn(|i| if a.as_i64x2()[i]!=b.as_i64x2()[i] {-1} else {0}))))); }
                    0xd8 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_i64x2(core::array::from_fn(|i| if a.as_i64x2()[i]<b.as_i64x2()[i] {-1} else {0}))))); }
                    0xd9 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_i64x2(core::array::from_fn(|i| if a.as_i64x2()[i]>b.as_i64x2()[i] {-1} else {0}))))); }
                    0xda => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_i64x2(core::array::from_fn(|i| if a.as_i64x2()[i]<=b.as_i64x2()[i] {-1} else {0}))))); }
                    0xdb => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_i64x2(core::array::from_fn(|i| if a.as_i64x2()[i]>=b.as_i64x2()[i] {-1} else {0}))))); }
                    // ── i64x2 extmul (0xdc-0xdf) ─────────────────
                    0xdc => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_i64x2([a.as_i32x4()[0] as i64 * b.as_i32x4()[0] as i64, a.as_i32x4()[1] as i64 * b.as_i32x4()[1] as i64])))); }
                    0xdd => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_i64x2([a.as_i32x4()[2] as i64 * b.as_i32x4()[2] as i64, a.as_i32x4()[3] as i64 * b.as_i32x4()[3] as i64])))); }
                    0xde => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_i64x2([(a.as_u32x4()[0] as u64 * b.as_u32x4()[0] as u64) as i64, (a.as_u32x4()[1] as u64 * b.as_u32x4()[1] as u64) as i64])))); }
                    0xdf => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_i64x2([(a.as_u32x4()[2] as u64 * b.as_u32x4()[2] as u64) as i64, (a.as_u32x4()[3] as u64 * b.as_u32x4()[3] as u64) as i64])))); }
                    // ── f32x4 arithmetic (0xe0-0xeb) ─────────────
                    0xe0 => { let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_f32x4(core::array::from_fn(|i| libm::fabsf(a.as_f32x4()[i])))))); }
                    0xe1 => { let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_f32x4(core::array::from_fn(|i| -a.as_f32x4()[i]))))); }
                    0xe3 => { let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_f32x4(core::array::from_fn(|i| libm::sqrtf(a.as_f32x4()[i])))))); }
                    0xe4 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_f32x4(core::array::from_fn(|i| a.as_f32x4()[i] + b.as_f32x4()[i]))))); }
                    0xe5 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_f32x4(core::array::from_fn(|i| a.as_f32x4()[i] - b.as_f32x4()[i]))))); }
                    0xe6 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_f32x4(core::array::from_fn(|i| a.as_f32x4()[i] * b.as_f32x4()[i]))))); }
                    0xe7 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_f32x4(core::array::from_fn(|i| a.as_f32x4()[i] / b.as_f32x4()[i]))))); }
                    0xe8 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_f32x4(core::array::from_fn(|i| Self::wasm_min_f32(a.as_f32x4()[i], b.as_f32x4()[i])))))); }
                    0xe9 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_f32x4(core::array::from_fn(|i| Self::wasm_max_f32(a.as_f32x4()[i], b.as_f32x4()[i])))))); }
                    0xea => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_f32x4(core::array::from_fn(|i| { let (x,y) = (a.as_f32x4()[i], b.as_f32x4()[i]); if y < x { y } else { x } }))))); }
                    0xeb => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_f32x4(core::array::from_fn(|i| { let (x,y) = (a.as_f32x4()[i], b.as_f32x4()[i]); if x < y { y } else { x } }))))); }
                    // ── f64x2 arithmetic (0xec-0xf7) ─────────────
                    0xec => { let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_f64x2(core::array::from_fn(|i| libm::fabs(a.as_f64x2()[i])))))); }
                    0xed => { let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_f64x2(core::array::from_fn(|i| -a.as_f64x2()[i]))))); }
                    0xef => { let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_f64x2(core::array::from_fn(|i| libm::sqrt(a.as_f64x2()[i])))))); }
                    0xf0 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_f64x2(core::array::from_fn(|i| a.as_f64x2()[i] + b.as_f64x2()[i]))))); }
                    0xf1 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_f64x2(core::array::from_fn(|i| a.as_f64x2()[i] - b.as_f64x2()[i]))))); }
                    0xf2 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_f64x2(core::array::from_fn(|i| a.as_f64x2()[i] * b.as_f64x2()[i]))))); }
                    0xf3 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_f64x2(core::array::from_fn(|i| a.as_f64x2()[i] / b.as_f64x2()[i]))))); }
                    0xf4 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_f64x2(core::array::from_fn(|i| Self::wasm_min_f64(a.as_f64x2()[i], b.as_f64x2()[i])))))); }
                    0xf5 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_f64x2(core::array::from_fn(|i| Self::wasm_max_f64(a.as_f64x2()[i], b.as_f64x2()[i])))))); }
                    0xf6 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_f64x2(core::array::from_fn(|i| { let (x,y) = (a.as_f64x2()[i], b.as_f64x2()[i]); if y < x { y } else { x } }))))); }
                    0xf7 => { let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_f64x2(core::array::from_fn(|i| { let (x,y) = (a.as_f64x2()[i], b.as_f64x2()[i]); if x < y { y } else { x } }))))); }
                    // ── Conversion (0xf8-0xff) ───────────────────
                    0xf8 => { let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| sat_trunc_f32_i32(a.as_f32x4()[i])))))); }
                    0xf9 => { let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_u32x4(core::array::from_fn(|i| sat_trunc_f32_u32(a.as_f32x4()[i])))))); }
                    0xfa => { let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_f32x4(core::array::from_fn(|i| a.as_i32x4()[i] as f32))))); }
                    0xfb => { let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_f32x4(core::array::from_fn(|i| a.as_u32x4()[i] as f32))))); }
                    0xfc => { let a = try_exec!(self.pop_v128()); let aa = a.as_f64x2(); try_exec!(self.push(Value::V128(V128::from_i32x4([sat_trunc_f64_i32(aa[0]), sat_trunc_f64_i32(aa[1]), 0, 0])))); }
                    0xfd => { let a = try_exec!(self.pop_v128()); let aa = a.as_f64x2(); try_exec!(self.push(Value::V128(V128::from_u32x4([sat_trunc_f64_u32(aa[0]), sat_trunc_f64_u32(aa[1]), 0, 0])))); }
                    0xfe => { let a = try_exec!(self.pop_v128()); let aa = a.as_i32x4(); try_exec!(self.push(Value::V128(V128::from_f64x2([aa[0] as f64, aa[1] as f64])))); }
                    0xff => { let a = try_exec!(self.pop_v128()); let aa = a.as_u32x4(); try_exec!(self.push(Value::V128(V128::from_f64x2([aa[0] as f64, aa[1] as f64])))); }
                    // ── Relaxed SIMD (0x100-0x113) ────────────
                    0x100 => { // i8x16.relaxed_swizzle (same as swizzle)
                        let s = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128());
                        let mut r = [0u8; 16]; for i in 0..16 { let idx = s.0[i]; r[i] = if idx < 16 { a.0[idx as usize] } else { 0 }; }
                        try_exec!(self.push(Value::V128(V128(r))));
                    }
                    0x101 => { // i32x4.relaxed_trunc_f32x4_s (same as trunc_sat)
                        let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_i32x4(core::array::from_fn(|i| sat_trunc_f32_i32(a.as_f32x4()[i]))))));
                    }
                    0x102 => { // i32x4.relaxed_trunc_f32x4_u
                        let a = try_exec!(self.pop_v128()); try_exec!(self.push(Value::V128(V128::from_u32x4(core::array::from_fn(|i| sat_trunc_f32_u32(a.as_f32x4()[i]))))));
                    }
                    0x103 => { // i32x4.relaxed_trunc_f64x2_s_zero
                        let a = try_exec!(self.pop_v128()); let aa = a.as_f64x2(); try_exec!(self.push(Value::V128(V128::from_i32x4([sat_trunc_f64_i32(aa[0]), sat_trunc_f64_i32(aa[1]), 0, 0]))));
                    }
                    0x104 => { // i32x4.relaxed_trunc_f64x2_u_zero
                        let a = try_exec!(self.pop_v128()); let aa = a.as_f64x2(); try_exec!(self.push(Value::V128(V128::from_u32x4([sat_trunc_f64_u32(aa[0]), sat_trunc_f64_u32(aa[1]), 0, 0]))));
                    }
                    0x105 => { // f32x4.relaxed_madd (a*b+c)
                        let c = try_exec!(self.pop_v128()); let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128());
                        let (aa, bb, cc) = (a.as_f32x4(), b.as_f32x4(), c.as_f32x4());
                        try_exec!(self.push(Value::V128(V128::from_f32x4(core::array::from_fn(|i| aa[i] * bb[i] + cc[i])))));
                    }
                    0x106 => { // f32x4.relaxed_nmadd (-a*b+c)
                        let c = try_exec!(self.pop_v128()); let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128());
                        let (aa, bb, cc) = (a.as_f32x4(), b.as_f32x4(), c.as_f32x4());
                        try_exec!(self.push(Value::V128(V128::from_f32x4(core::array::from_fn(|i| -(aa[i] * bb[i]) + cc[i])))));
                    }
                    0x107 => { // f64x2.relaxed_madd (a*b+c)
                        let c = try_exec!(self.pop_v128()); let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128());
                        let (aa, bb, cc) = (a.as_f64x2(), b.as_f64x2(), c.as_f64x2());
                        try_exec!(self.push(Value::V128(V128::from_f64x2(core::array::from_fn(|i| aa[i] * bb[i] + cc[i])))));
                    }
                    0x108 => { // f64x2.relaxed_nmadd (-a*b+c)
                        let c = try_exec!(self.pop_v128()); let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128());
                        let (aa, bb, cc) = (a.as_f64x2(), b.as_f64x2(), c.as_f64x2());
                        try_exec!(self.push(Value::V128(V128::from_f64x2(core::array::from_fn(|i| -(aa[i] * bb[i]) + cc[i])))));
                    }
                    0x109 => { // i8x16.relaxed_laneselect (same as bitselect)
                        let c = try_exec!(self.pop_v128()); let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128());
                        let mut r = [0u8; 16]; for i in 0..16 { r[i] = (a.0[i] & c.0[i]) | (b.0[i] & !c.0[i]); }
                        try_exec!(self.push(Value::V128(V128(r))));
                    }
                    0x10a => { // i16x8.relaxed_laneselect
                        let c = try_exec!(self.pop_v128()); let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128());
                        let mut r = [0u8; 16]; for i in 0..16 { r[i] = (a.0[i] & c.0[i]) | (b.0[i] & !c.0[i]); }
                        try_exec!(self.push(Value::V128(V128(r))));
                    }
                    0x10b => { // i32x4.relaxed_laneselect
                        let c = try_exec!(self.pop_v128()); let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128());
                        let mut r = [0u8; 16]; for i in 0..16 { r[i] = (a.0[i] & c.0[i]) | (b.0[i] & !c.0[i]); }
                        try_exec!(self.push(Value::V128(V128(r))));
                    }
                    0x10c => { // i64x2.relaxed_laneselect
                        let c = try_exec!(self.pop_v128()); let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128());
                        let mut r = [0u8; 16]; for i in 0..16 { r[i] = (a.0[i] & c.0[i]) | (b.0[i] & !c.0[i]); }
                        try_exec!(self.push(Value::V128(V128(r))));
                    }
                    0x10d => { // f32x4.relaxed_min (same as min)
                        let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128());
                        try_exec!(self.push(Value::V128(V128::from_f32x4(core::array::from_fn(|i| Self::wasm_min_f32(a.as_f32x4()[i], b.as_f32x4()[i]))))));
                    }
                    0x10e => { // f32x4.relaxed_max (same as max)
                        let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128());
                        try_exec!(self.push(Value::V128(V128::from_f32x4(core::array::from_fn(|i| Self::wasm_max_f32(a.as_f32x4()[i], b.as_f32x4()[i]))))));
                    }
                    0x10f => { // f64x2.relaxed_min
                        let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128());
                        try_exec!(self.push(Value::V128(V128::from_f64x2(core::array::from_fn(|i| Self::wasm_min_f64(a.as_f64x2()[i], b.as_f64x2()[i]))))));
                    }
                    0x110 => { // f64x2.relaxed_max
                        let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128());
                        try_exec!(self.push(Value::V128(V128::from_f64x2(core::array::from_fn(|i| Self::wasm_max_f64(a.as_f64x2()[i], b.as_f64x2()[i]))))));
                    }
                    0x111 => { // i16x8.relaxed_q15mulr_s (same as q15mulr_sat_s)
                        let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128());
                        let (aa, bb) = (a.as_i16x8(), b.as_i16x8());
                        let r: [i16; 8] = core::array::from_fn(|i| { let x = aa[i] as i32; let y = bb[i] as i32; ((x*y+(1<<14))>>15).clamp(i16::MIN as i32, i16::MAX as i32) as i16 });
                        try_exec!(self.push(Value::V128(V128::from_i16x8(r))));
                    }
                    0x112 => { // i16x8.relaxed_dot_i8x16_i7x16_s
                        let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128());
                        let (aa, bb) = (a.as_i8x16(), b.as_i8x16());
                        let r: [i16; 8] = core::array::from_fn(|i| (aa[i*2] as i16 * bb[i*2] as i16).saturating_add(aa[i*2+1] as i16 * bb[i*2+1] as i16));
                        try_exec!(self.push(Value::V128(V128::from_i16x8(r))));
                    }
                    0x113 => { // i32x4.relaxed_dot_i8x16_i7x16_add_s
                        let c = try_exec!(self.pop_v128()); let b = try_exec!(self.pop_v128()); let a = try_exec!(self.pop_v128());
                        let (aa, bb) = (a.as_i8x16(), b.as_i8x16()); let cc = c.as_i32x4();
                        let r: [i32; 4] = core::array::from_fn(|i| {
                            let base = i * 4;
                            let dot = (aa[base] as i32 * bb[base] as i32) + (aa[base+1] as i32 * bb[base+1] as i32) + (aa[base+2] as i32 * bb[base+2] as i32) + (aa[base+3] as i32 * bb[base+3] as i32);
                            dot.wrapping_add(cc[i])
                        });
                        try_exec!(self.push(Value::V128(V128::from_i32x4(r))));
                    }

                    _ => { return ExecResult::Trap(WasmError::InvalidOpcode(0xFD)); }
                }
            }

            // ── 0xFB prefix: GC proposal ───
            0xFB => {
                let sub = try_exec!(self.read_leb128_u32());
                match sub {
                    28 => { // ref.i31: pop i32, push i31ref (represented as i32)
                        // i31ref stores the lower 31 bits
                        // No-op: value stays as-is on the stack, masking done at get time
                    }
                    29 => { // i31.get_s: pop i31ref, sign-extend from 31 bits, push i32
                        let val = try_exec!(self.pop());
                        match val {
                            Value::NullRef => {
                                return ExecResult::Trap(WasmError::NullI31Reference);
                            }
                            _ => {
                                let v = match val { Value::I32(v) => v, _ => 0 };
                                let masked = v & 0x7FFF_FFFF;
                                let sign_extended = if masked & 0x4000_0000 != 0 {
                                    masked | !0x7FFF_FFFFu32 as i32
                                } else {
                                    masked
                                };
                                try_exec!(self.push(Value::I32(sign_extended)));
                            }
                        }
                    }
                    30 => { // i31.get_u: pop i31ref, mask to 31 bits, push i32
                        let val = try_exec!(self.pop());
                        match val {
                            Value::NullRef => {
                                return ExecResult::Trap(WasmError::NullI31Reference);
                            }
                            _ => {
                                let v = match val { Value::I32(v) => v, _ => 0 };
                                try_exec!(self.push(Value::I32(v & 0x7FFF_FFFF)));
                            }
                        }
                    }
                    0 => { // struct.new: typeidx — pop fields (in reverse), push ref
                        let type_idx = try_exec!(self.read_leb128_u32());
                        let field_count = self.gc_struct_field_count(type_idx);
                        let mut fields = vec![Value::I32(0); field_count];
                        for i in (0..field_count).rev() {
                            fields[i] = try_exec!(self.pop());
                        }
                        let heap_idx = self.gc_heap.len() as u32;
                        self.gc_heap.push(GcObject::Struct { type_idx, fields });
                        try_exec!(self.push(Value::GcRef(heap_idx)));
                    }
                    1 => { // struct.new_default: typeidx — push ref with default fields
                        let type_idx = try_exec!(self.read_leb128_u32());
                        let field_count = self.gc_struct_field_count(type_idx);
                        let mut fields = Vec::with_capacity(field_count);
                        for i in 0..field_count {
                            fields.push(self.gc_struct_field_default(type_idx, i));
                        }
                        let heap_idx = self.gc_heap.len() as u32;
                        self.gc_heap.push(GcObject::Struct { type_idx, fields });
                        try_exec!(self.push(Value::GcRef(heap_idx)));
                    }
                    2 | 3 | 4 => { // struct.get / struct.get_s / struct.get_u
                        let type_idx = try_exec!(self.read_leb128_u32());
                        let field_idx = try_exec!(self.read_leb128_u32()) as usize;
                        let ref_val = try_exec!(self.pop());
                        let heap_idx = match ref_val {
                            Value::GcRef(idx) => idx as usize,
                            Value::NullRef => { return ExecResult::Trap(WasmError::NullStructReference); }
                            _ => { return ExecResult::Trap(WasmError::NullStructReference); }
                        };
                        if heap_idx >= self.gc_heap.len() {
                            return ExecResult::Trap(WasmError::NullStructReference);
                        }
                        let val = match &self.gc_heap[heap_idx] {
                            GcObject::Struct { fields, .. } => {
                                if field_idx >= fields.len() {
                                    return ExecResult::Trap(WasmError::OutOfBounds);
                                }
                                fields[field_idx]
                            }
                            _ => { return ExecResult::Trap(WasmError::TypeMismatch); }
                        };
                        // Apply sign/zero extension for packed types
                        let result = self.gc_apply_field_extend(type_idx, field_idx, val, sub);
                        try_exec!(self.push(result));
                    }
                    5 => { // struct.set: typeidx fieldidx — pop value + ref, set field
                        let type_idx = try_exec!(self.read_leb128_u32());
                        let field_idx = try_exec!(self.read_leb128_u32()) as usize;
                        let val = try_exec!(self.pop());
                        let ref_val = try_exec!(self.pop());
                        let heap_idx = match ref_val {
                            Value::GcRef(idx) => idx as usize,
                            Value::NullRef => { return ExecResult::Trap(WasmError::NullStructReference); }
                            _ => { return ExecResult::Trap(WasmError::NullStructReference); }
                        };
                        if heap_idx >= self.gc_heap.len() {
                            return ExecResult::Trap(WasmError::NullStructReference);
                        }
                        // Wrap value for packed field types
                        let wrapped = self.gc_wrap_field_value(type_idx, field_idx, val);
                        match &mut self.gc_heap[heap_idx] {
                            GcObject::Struct { fields, .. } => {
                                if field_idx >= fields.len() {
                                    return ExecResult::Trap(WasmError::OutOfBounds);
                                }
                                fields[field_idx] = wrapped;
                            }
                            _ => { return ExecResult::Trap(WasmError::TypeMismatch); }
                        }
                    }
                    6 => { // array.new: typeidx — pop init_value + length, allocate, push ref
                        let type_idx = try_exec!(self.read_leb128_u32());
                        let length = try_exec!(self.pop_i32()) as u32;
                        let init_val = try_exec!(self.pop());
                        let elements = vec![init_val; length as usize];
                        let heap_idx = self.gc_heap.len() as u32;
                        self.gc_heap.push(GcObject::Array { type_idx, elements });
                        try_exec!(self.push(Value::GcRef(heap_idx)));
                    }
                    7 => { // array.new_default: typeidx — pop length, allocate with defaults
                        let type_idx = try_exec!(self.read_leb128_u32());
                        let length = try_exec!(self.pop_i32()) as u32;
                        let default_val = self.gc_array_elem_default(type_idx);
                        let elements = vec![default_val; length as usize];
                        let heap_idx = self.gc_heap.len() as u32;
                        self.gc_heap.push(GcObject::Array { type_idx, elements });
                        try_exec!(self.push(Value::GcRef(heap_idx)));
                    }
                    8 => { // array.new_fixed: typeidx + count — pop count values, allocate
                        let type_idx = try_exec!(self.read_leb128_u32());
                        let count = try_exec!(self.read_leb128_u32()) as usize;
                        let mut elements = vec![Value::I32(0); count];
                        for i in (0..count).rev() {
                            elements[i] = try_exec!(self.pop());
                        }
                        let heap_idx = self.gc_heap.len() as u32;
                        self.gc_heap.push(GcObject::Array { type_idx, elements });
                        try_exec!(self.push(Value::GcRef(heap_idx)));
                    }
                    9 => { // array.new_data: typeidx + data_idx — pop offset + length
                        let type_idx = try_exec!(self.read_leb128_u32());
                        let data_idx = try_exec!(self.read_leb128_u32()) as usize;
                        let length = try_exec!(self.pop_i32()) as u32;
                        let offset = try_exec!(self.pop_i32()) as u32;
                        let elements = try_exec!(self.gc_array_from_data(type_idx, data_idx, offset, length));
                        let heap_idx = self.gc_heap.len() as u32;
                        self.gc_heap.push(GcObject::Array { type_idx, elements });
                        try_exec!(self.push(Value::GcRef(heap_idx)));
                    }
                    10 => { // array.new_elem: typeidx + elem_idx — pop offset + length
                        let type_idx = try_exec!(self.read_leb128_u32());
                        let elem_idx = try_exec!(self.read_leb128_u32()) as usize;
                        let length = try_exec!(self.pop_i32()) as u32;
                        let offset = try_exec!(self.pop_i32()) as u32;
                        let elements = try_exec!(self.gc_array_from_elem(elem_idx, offset, length));
                        let heap_idx = self.gc_heap.len() as u32;
                        self.gc_heap.push(GcObject::Array { type_idx, elements });
                        try_exec!(self.push(Value::GcRef(heap_idx)));
                    }
                    11 | 12 | 13 => { // array.get / array.get_s / array.get_u
                        let type_idx = try_exec!(self.read_leb128_u32());
                        let index = try_exec!(self.pop_i32()) as u32;
                        let ref_val = try_exec!(self.pop());
                        let heap_idx = match ref_val {
                            Value::GcRef(idx) => idx as usize,
                            Value::NullRef => { return ExecResult::Trap(WasmError::NullArrayReference); }
                            _ => { return ExecResult::Trap(WasmError::NullArrayReference); }
                        };
                        if heap_idx >= self.gc_heap.len() {
                            return ExecResult::Trap(WasmError::NullArrayReference);
                        }
                        let val = match &self.gc_heap[heap_idx] {
                            GcObject::Array { elements, .. } => {
                                if index as usize >= elements.len() {
                                    return ExecResult::Trap(WasmError::ArrayOutOfBounds);
                                }
                                elements[index as usize]
                            }
                            _ => { return ExecResult::Trap(WasmError::TypeMismatch); }
                        };
                        // Apply sign/zero extension for packed array element types
                        let result = self.gc_apply_array_extend(type_idx, val, sub);
                        try_exec!(self.push(result));
                    }
                    14 => { // array.set: typeidx — pop value + index + ref, set element
                        let type_idx = try_exec!(self.read_leb128_u32());
                        let val = try_exec!(self.pop());
                        let index = try_exec!(self.pop_i32()) as u32;
                        let ref_val = try_exec!(self.pop());
                        let heap_idx = match ref_val {
                            Value::GcRef(idx) => idx as usize,
                            Value::NullRef => { return ExecResult::Trap(WasmError::NullArrayReference); }
                            _ => { return ExecResult::Trap(WasmError::NullArrayReference); }
                        };
                        if heap_idx >= self.gc_heap.len() {
                            return ExecResult::Trap(WasmError::NullArrayReference);
                        }
                        let wrapped = self.gc_wrap_array_value(type_idx, val);
                        match &mut self.gc_heap[heap_idx] {
                            GcObject::Array { elements, .. } => {
                                if index as usize >= elements.len() {
                                    return ExecResult::Trap(WasmError::ArrayOutOfBounds);
                                }
                                elements[index as usize] = wrapped;
                            }
                            _ => { return ExecResult::Trap(WasmError::TypeMismatch); }
                        }
                    }
                    15 => { // array.len: pop ref, push length
                        let ref_val = try_exec!(self.pop());
                        let heap_idx = match ref_val {
                            Value::GcRef(idx) => idx as usize,
                            Value::NullRef => { return ExecResult::Trap(WasmError::NullArrayReference); }
                            _ => { return ExecResult::Trap(WasmError::NullArrayReference); }
                        };
                        if heap_idx >= self.gc_heap.len() {
                            return ExecResult::Trap(WasmError::NullArrayReference);
                        }
                        let len = match &self.gc_heap[heap_idx] {
                            GcObject::Array { elements, .. } => elements.len() as i32,
                            _ => { return ExecResult::Trap(WasmError::TypeMismatch); }
                        };
                        try_exec!(self.push(Value::I32(len)));
                    }
                    16 => { // array.fill: typeidx — pop length + value + offset + ref
                        let type_idx = try_exec!(self.read_leb128_u32());
                        let length = try_exec!(self.pop_i32()) as u32;
                        let val = try_exec!(self.pop());
                        let offset = try_exec!(self.pop_i32()) as u32;
                        let ref_val = try_exec!(self.pop());
                        let heap_idx = match ref_val {
                            Value::GcRef(idx) => idx as usize,
                            Value::NullRef => { return ExecResult::Trap(WasmError::NullArrayReference); }
                            _ => { return ExecResult::Trap(WasmError::NullArrayReference); }
                        };
                        if heap_idx >= self.gc_heap.len() {
                            return ExecResult::Trap(WasmError::NullArrayReference);
                        }
                        let wrapped = self.gc_wrap_array_value(type_idx, val);
                        match &mut self.gc_heap[heap_idx] {
                            GcObject::Array { elements, .. } => {
                                let end = offset as usize + length as usize;
                                if end > elements.len() {
                                    return ExecResult::Trap(WasmError::ArrayOutOfBounds);
                                }
                                for i in offset as usize..end {
                                    elements[i] = wrapped;
                                }
                            }
                            _ => { return ExecResult::Trap(WasmError::TypeMismatch); }
                        }
                    }
                    17 => { // array.copy: dst_type + src_type
                        let _dst_type = try_exec!(self.read_leb128_u32());
                        let _src_type = try_exec!(self.read_leb128_u32());
                        let length = try_exec!(self.pop_i32()) as u32;
                        let src_offset = try_exec!(self.pop_i32()) as u32;
                        let src_ref = try_exec!(self.pop());
                        let dst_offset = try_exec!(self.pop_i32()) as u32;
                        let dst_ref = try_exec!(self.pop());
                        let src_idx = match src_ref {
                            Value::GcRef(idx) => idx as usize,
                            Value::NullRef => { return ExecResult::Trap(WasmError::NullArrayReference); }
                            _ => { return ExecResult::Trap(WasmError::NullArrayReference); }
                        };
                        let dst_idx = match dst_ref {
                            Value::GcRef(idx) => idx as usize,
                            Value::NullRef => { return ExecResult::Trap(WasmError::NullArrayReference); }
                            _ => { return ExecResult::Trap(WasmError::NullArrayReference); }
                        };
                        {
                            // Check bounds even for zero-length copies per spec
                            let src_end = src_offset as usize + length as usize;
                            let dst_end = dst_offset as usize + length as usize;
                            // Check destination bounds first
                            match &self.gc_heap[dst_idx] {
                                GcObject::Array { elements, .. } => {
                                    if dst_end > elements.len() {
                                        return ExecResult::Trap(WasmError::ArrayOutOfBounds);
                                    }
                                }
                                _ => { return ExecResult::Trap(WasmError::TypeMismatch); }
                            }
                            // Check source bounds
                            match &self.gc_heap[src_idx] {
                                GcObject::Array { elements, .. } => {
                                    if src_end > elements.len() {
                                        return ExecResult::Trap(WasmError::ArrayOutOfBounds);
                                    }
                                }
                                _ => { return ExecResult::Trap(WasmError::TypeMismatch); }
                            }
                            if length > 0 {
                            // Copy elements, handling overlap
                            let src_elems = {
                                match &self.gc_heap[src_idx] {
                                    GcObject::Array { elements, .. } => {
                                        elements[src_offset as usize..src_end].to_vec()
                                    }
                                    _ => { return ExecResult::Trap(WasmError::TypeMismatch); }
                                }
                            };
                            // Then write to destination
                            match &mut self.gc_heap[dst_idx] {
                                GcObject::Array { elements, .. } => {
                                    for i in 0..length as usize {
                                        elements[dst_offset as usize + i] = src_elems[i];
                                    }
                                }
                                _ => { return ExecResult::Trap(WasmError::TypeMismatch); }
                            }
                            } // end if length > 0
                        }
                    }
                    18 => { // array.init_data: typeidx + data_idx
                        let type_idx = try_exec!(self.read_leb128_u32());
                        let data_idx = try_exec!(self.read_leb128_u32()) as usize;
                        let length = try_exec!(self.pop_i32()) as u32;
                        let src_offset = try_exec!(self.pop_i32()) as u32;
                        let dst_offset = try_exec!(self.pop_i32()) as u32;
                        let ref_val = try_exec!(self.pop());
                        let heap_idx = match ref_val {
                            Value::GcRef(idx) => idx as usize,
                            Value::NullRef => { return ExecResult::Trap(WasmError::NullArrayReference); }
                            _ => { return ExecResult::Trap(WasmError::NullArrayReference); }
                        };
                        // Check array (destination) bounds first per spec
                        match &self.gc_heap[heap_idx] {
                            GcObject::Array { elements, .. } => {
                                let dst_end = dst_offset as usize + length as usize;
                                if dst_end > elements.len() {
                                    return ExecResult::Trap(WasmError::ArrayOutOfBounds);
                                }
                            }
                            _ => { return ExecResult::Trap(WasmError::TypeMismatch); }
                        }
                        // Then check data source bounds
                        let src_elems = try_exec!(self.gc_array_from_data(type_idx, data_idx, src_offset, length));
                        match &mut self.gc_heap[heap_idx] {
                            GcObject::Array { elements, .. } => {
                                for i in 0..length as usize {
                                    elements[dst_offset as usize + i] = src_elems[i];
                                }
                            }
                            _ => { return ExecResult::Trap(WasmError::TypeMismatch); }
                        }
                    }
                    19 => { // array.init_elem: typeidx + elem_idx
                        let _type_idx = try_exec!(self.read_leb128_u32());
                        let elem_idx = try_exec!(self.read_leb128_u32()) as usize;
                        let length = try_exec!(self.pop_i32()) as u32;
                        let src_offset = try_exec!(self.pop_i32()) as u32;
                        let dst_offset = try_exec!(self.pop_i32()) as u32;
                        let ref_val = try_exec!(self.pop());
                        let heap_idx = match ref_val {
                            Value::GcRef(idx) => idx as usize,
                            Value::NullRef => { return ExecResult::Trap(WasmError::NullArrayReference); }
                            _ => { return ExecResult::Trap(WasmError::NullArrayReference); }
                        };
                        // Check array (destination) bounds first per spec
                        match &self.gc_heap[heap_idx] {
                            GcObject::Array { elements, .. } => {
                                let dst_end = dst_offset as usize + length as usize;
                                if dst_end > elements.len() {
                                    return ExecResult::Trap(WasmError::ArrayOutOfBounds);
                                }
                            }
                            _ => { return ExecResult::Trap(WasmError::TypeMismatch); }
                        }
                        // Then check element source bounds
                        let src_elems = try_exec!(self.gc_array_from_elem(elem_idx, src_offset, length));
                        match &mut self.gc_heap[heap_idx] {
                            GcObject::Array { elements, .. } => {
                                for i in 0..length as usize {
                                    elements[dst_offset as usize + i] = src_elems[i];
                                }
                            }
                            _ => { return ExecResult::Trap(WasmError::TypeMismatch); }
                        }
                    }
                    20 | 21 => { // ref.test / ref.test null: heaptype
                        let ht = try_exec!(self.read_leb128_i32());
                        let nullable = sub == 21;
                        let ref_val = try_exec!(self.pop());
                        let result = self.gc_ref_test(ref_val, ht, nullable);
                        try_exec!(self.push(Value::I32(if result { 1 } else { 0 })));
                    }
                    22 | 23 => { // ref.cast / ref.cast null: heaptype
                        let ht = try_exec!(self.read_leb128_i32());
                        let nullable = sub == 23;
                        let ref_val = try_exec!(self.pop());
                        let ok = self.gc_ref_test(ref_val, ht, nullable);
                        if !ok {
                            return ExecResult::Trap(WasmError::CastFailure);
                        }
                        try_exec!(self.push(ref_val));
                    }
                    24 => { // br_on_cast: flags + label + ht1 + ht2
                        let _flags = try_exec!(self.read_byte());
                        let label = try_exec!(self.read_leb128_u32());
                        let _ht1 = try_exec!(self.read_leb128_i32());
                        let ht2 = try_exec!(self.read_leb128_i32());
                        let ref_val = try_exec!(self.pop());
                        let nullable = (_flags & 2) != 0; // bit 1 = output nullable
                        if self.gc_ref_test(ref_val, ht2, nullable) {
                            try_exec!(self.push(ref_val));
                            try_exec!(self.branch(label));
                        } else {
                            try_exec!(self.push(ref_val));
                        }
                    }
                    25 => { // br_on_cast_fail: flags + label + ht1 + ht2
                        let _flags = try_exec!(self.read_byte());
                        let label = try_exec!(self.read_leb128_u32());
                        let _ht1 = try_exec!(self.read_leb128_i32());
                        let ht2 = try_exec!(self.read_leb128_i32());
                        let ref_val = try_exec!(self.pop());
                        let nullable = (_flags & 2) != 0; // bit 1 = output nullable
                        if !self.gc_ref_test(ref_val, ht2, nullable) {
                            try_exec!(self.push(ref_val));
                            try_exec!(self.branch(label));
                        } else {
                            try_exec!(self.push(ref_val));
                        }
                    }
                    26 => { // any.convert_extern: pop externref, push anyref
                        let val = try_exec!(self.pop());
                        match val {
                            Value::NullRef | Value::I32(-1) => { try_exec!(self.push(Value::NullRef)); }
                            _ => {
                                // Wrap externref into the any hierarchy as Internalized
                                let heap_idx = self.gc_heap.len() as u32;
                                self.gc_heap.push(GcObject::Internalized { value: val });
                                try_exec!(self.push(Value::GcRef(heap_idx)));
                            }
                        }
                    }
                    27 => { // extern.convert_any: pop anyref, push externref
                        let val = try_exec!(self.pop());
                        match val {
                            Value::NullRef | Value::I32(-1) => { try_exec!(self.push(Value::NullRef)); }
                            _ => {
                                // Wrap anyref into the extern hierarchy as Externalized
                                let heap_idx = self.gc_heap.len() as u32;
                                self.gc_heap.push(GcObject::Externalized { value: val });
                                try_exec!(self.push(Value::GcRef(heap_idx)));
                            }
                        }
                    }
                    _ => {
                        return ExecResult::Trap(WasmError::UnsupportedProposal);
                    }
                }
            }

            // ── 0xFE prefix: Threads/Atomics ───
            0xFE => {
                let sub = try_exec!(self.read_leb128_u32());
                match sub {
                    // memory.atomic.notify (0): [i32, i32] -> [i32]
                    0x00 => {
                        let (mi, offset) = try_exec!(self.read_memarg());
                        let _count = try_exec!(self.pop_i32());
                        let base = try_exec!(self.pop_i32()) as u32;
                        let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
                        if addr % 4 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); }
                        if addr + 4 > self.mem_size(mi) { return ExecResult::Trap(WasmError::MemoryOutOfBounds); }
                        try_exec!(self.push(Value::I32(0)));
                    }
                    // memory.atomic.wait32 (1): [i32, i32, i64] -> [i32]
                    0x01 => {
                        let (mi, offset) = try_exec!(self.read_memarg());
                        let _timeout = try_exec!(self.pop_i64());
                        let _expected = try_exec!(self.pop_i32());
                        let base = try_exec!(self.pop_i32()) as u32;
                        let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
                        if addr % 4 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); }
                        if addr + 4 > self.mem_size(mi) { return ExecResult::Trap(WasmError::MemoryOutOfBounds); }
                        // Single-threaded: return 1 (not-equal/timeout)
                        try_exec!(self.push(Value::I32(1)));
                    }
                    // memory.atomic.wait64 (2): [i32, i64, i64] -> [i32]
                    0x02 => {
                        let (mi, offset) = try_exec!(self.read_memarg());
                        let _timeout = try_exec!(self.pop_i64());
                        let _expected = try_exec!(self.pop_i64());
                        let base = try_exec!(self.pop_i32()) as u32;
                        let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
                        if addr % 8 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); }
                        if addr + 8 > self.mem_size(mi) { return ExecResult::Trap(WasmError::MemoryOutOfBounds); }
                        try_exec!(self.push(Value::I32(1)));
                    }
                    // atomic.fence (3)
                    0x03 => { let _ = try_exec!(self.read_byte()); }
                    // i32.atomic.load (0x10)
                    0x10 => {
                        let (mi, offset) = try_exec!(self.read_memarg());
                        let base = try_exec!(self.pop_i32()) as u32;
                        let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
                        if addr % 4 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); }
                        let val = try_exec!(self.mem_load_i32(mi, addr));
                        try_exec!(self.push(Value::I32(val)));
                    }
                    // i64.atomic.load (0x11)
                    0x11 => {
                        let (mi, offset) = try_exec!(self.read_memarg());
                        let base = try_exec!(self.pop_i32()) as u32;
                        let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
                        if addr % 8 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); }
                        let val = try_exec!(self.mem_load_i64(mi, addr));
                        try_exec!(self.push(Value::I64(val)));
                    }
                    // i32.atomic.load8_u (0x12)
                    0x12 => {
                        let (mi, offset) = try_exec!(self.read_memarg());
                        let base = try_exec!(self.pop_i32()) as u32;
                        let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
                        let val = try_exec!(self.mem_load_u8(mi, addr));
                        try_exec!(self.push(Value::I32(val as i32)));
                    }
                    // i32.atomic.load16_u (0x13)
                    0x13 => {
                        let (mi, offset) = try_exec!(self.read_memarg());
                        let base = try_exec!(self.pop_i32()) as u32;
                        let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
                        if addr % 2 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); }
                        let val = try_exec!(self.mem_load_u16(mi, addr));
                        try_exec!(self.push(Value::I32(val as i32)));
                    }
                    // i64.atomic.load8_u (0x14)
                    0x14 => {
                        let (mi, offset) = try_exec!(self.read_memarg());
                        let base = try_exec!(self.pop_i32()) as u32;
                        let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
                        let val = try_exec!(self.mem_load_u8(mi, addr));
                        try_exec!(self.push(Value::I64(val as i64)));
                    }
                    // i64.atomic.load16_u (0x15)
                    0x15 => {
                        let (mi, offset) = try_exec!(self.read_memarg());
                        let base = try_exec!(self.pop_i32()) as u32;
                        let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
                        if addr % 2 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); }
                        let val = try_exec!(self.mem_load_u16(mi, addr));
                        try_exec!(self.push(Value::I64(val as i64)));
                    }
                    // i64.atomic.load32_u (0x16)
                    0x16 => {
                        let (mi, offset) = try_exec!(self.read_memarg());
                        let base = try_exec!(self.pop_i32()) as u32;
                        let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
                        if addr % 4 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); }
                        let val = try_exec!(self.mem_load_u32(mi, addr));
                        try_exec!(self.push(Value::I64(val as i64)));
                    }
                    // i32.atomic.store (0x17)
                    0x17 => {
                        let (mi, offset) = try_exec!(self.read_memarg());
                        let val = try_exec!(self.pop_i32());
                        let base = try_exec!(self.pop_i32()) as u32;
                        let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
                        if addr % 4 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); }
                        try_exec!(self.mem_store_i32(mi, addr, val));
                    }
                    // i64.atomic.store (0x18)
                    0x18 => {
                        let (mi, offset) = try_exec!(self.read_memarg());
                        let val = try_exec!(self.pop_i64());
                        let base = try_exec!(self.pop_i32()) as u32;
                        let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
                        if addr % 8 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); }
                        try_exec!(self.mem_store_i64(mi, addr, val));
                    }
                    // i32.atomic.store8 (0x19)
                    0x19 => {
                        let (mi, offset) = try_exec!(self.read_memarg());
                        let val = try_exec!(self.pop_i32());
                        let base = try_exec!(self.pop_i32()) as u32;
                        let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
                        try_exec!(self.mem_store_u8(mi, addr, val as u8));
                    }
                    // i32.atomic.store16 (0x1a)
                    0x1a => {
                        let (mi, offset) = try_exec!(self.read_memarg());
                        let val = try_exec!(self.pop_i32());
                        let base = try_exec!(self.pop_i32()) as u32;
                        let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
                        if addr % 2 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); }
                        try_exec!(self.mem_store_u16(mi, addr, val as u16));
                    }
                    // i64.atomic.store8 (0x1b)
                    0x1b => {
                        let (mi, offset) = try_exec!(self.read_memarg());
                        let val = try_exec!(self.pop_i64());
                        let base = try_exec!(self.pop_i32()) as u32;
                        let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
                        try_exec!(self.mem_store_u8(mi, addr, val as u8));
                    }
                    // i64.atomic.store16 (0x1c)
                    0x1c => {
                        let (mi, offset) = try_exec!(self.read_memarg());
                        let val = try_exec!(self.pop_i64());
                        let base = try_exec!(self.pop_i32()) as u32;
                        let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
                        if addr % 2 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); }
                        try_exec!(self.mem_store_u16(mi, addr, val as u16));
                    }
                    // i64.atomic.store32 (0x1d)
                    0x1d => {
                        let (mi, offset) = try_exec!(self.read_memarg());
                        let val = try_exec!(self.pop_i64());
                        let base = try_exec!(self.pop_i32()) as u32;
                        let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize;
                        if addr % 4 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); }
                        try_exec!(self.mem_store_u32(mi, addr, val as u32));
                    }
                    // ── Atomic RMW operations ──
                    // i32.atomic.rmw.add..xchg (0x1e-0x47), i32/i64 variants
                    0x1e => { let (mi, offset) = try_exec!(self.read_memarg()); let val = try_exec!(self.pop_i32()); let base = try_exec!(self.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; if addr % 4 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); } let old = try_exec!(self.mem_load_i32(mi, addr)); try_exec!(self.mem_store_i32(mi, addr, old.wrapping_add(val))); try_exec!(self.push(Value::I32(old))); }
                    0x1f => { let (mi, offset) = try_exec!(self.read_memarg()); let val = try_exec!(self.pop_i64()); let base = try_exec!(self.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; if addr % 8 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); } let old = try_exec!(self.mem_load_i64(mi, addr)); try_exec!(self.mem_store_i64(mi, addr, old.wrapping_add(val))); try_exec!(self.push(Value::I64(old))); }
                    0x20 => { let (mi, offset) = try_exec!(self.read_memarg()); let val = try_exec!(self.pop_i32()) as u8; let base = try_exec!(self.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; let old = try_exec!(self.mem_load_u8(mi, addr)); try_exec!(self.mem_store_u8(mi, addr, old.wrapping_add(val))); try_exec!(self.push(Value::I32(old as i32))); }
                    0x21 => { let (mi, offset) = try_exec!(self.read_memarg()); let val = try_exec!(self.pop_i32()) as u16; let base = try_exec!(self.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; if addr % 2 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); } let old = try_exec!(self.mem_load_u16(mi, addr)); try_exec!(self.mem_store_u16(mi, addr, old.wrapping_add(val))); try_exec!(self.push(Value::I32(old as i32))); }
                    0x22 => { let (mi, offset) = try_exec!(self.read_memarg()); let val = try_exec!(self.pop_i64()) as u8; let base = try_exec!(self.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; let old = try_exec!(self.mem_load_u8(mi, addr)); try_exec!(self.mem_store_u8(mi, addr, old.wrapping_add(val))); try_exec!(self.push(Value::I64(old as i64))); }
                    0x23 => { let (mi, offset) = try_exec!(self.read_memarg()); let val = try_exec!(self.pop_i64()) as u16; let base = try_exec!(self.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; if addr % 2 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); } let old = try_exec!(self.mem_load_u16(mi, addr)); try_exec!(self.mem_store_u16(mi, addr, old.wrapping_add(val))); try_exec!(self.push(Value::I64(old as i64))); }
                    0x24 => { let (mi, offset) = try_exec!(self.read_memarg()); let val = try_exec!(self.pop_i64()) as u32; let base = try_exec!(self.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; if addr % 4 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); } let old = try_exec!(self.mem_load_u32(mi, addr)); try_exec!(self.mem_store_u32(mi, addr, old.wrapping_add(val))); try_exec!(self.push(Value::I64(old as i64))); }
                    // sub
                    0x25 => { let (mi, offset) = try_exec!(self.read_memarg()); let val = try_exec!(self.pop_i32()); let base = try_exec!(self.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; if addr % 4 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); } let old = try_exec!(self.mem_load_i32(mi, addr)); try_exec!(self.mem_store_i32(mi, addr, old.wrapping_sub(val))); try_exec!(self.push(Value::I32(old))); }
                    0x26 => { let (mi, offset) = try_exec!(self.read_memarg()); let val = try_exec!(self.pop_i64()); let base = try_exec!(self.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; if addr % 8 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); } let old = try_exec!(self.mem_load_i64(mi, addr)); try_exec!(self.mem_store_i64(mi, addr, old.wrapping_sub(val))); try_exec!(self.push(Value::I64(old))); }
                    0x27 => { let (mi, offset) = try_exec!(self.read_memarg()); let val = try_exec!(self.pop_i32()) as u8; let base = try_exec!(self.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; let old = try_exec!(self.mem_load_u8(mi, addr)); try_exec!(self.mem_store_u8(mi, addr, old.wrapping_sub(val))); try_exec!(self.push(Value::I32(old as i32))); }
                    0x28 => { let (mi, offset) = try_exec!(self.read_memarg()); let val = try_exec!(self.pop_i32()) as u16; let base = try_exec!(self.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; if addr % 2 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); } let old = try_exec!(self.mem_load_u16(mi, addr)); try_exec!(self.mem_store_u16(mi, addr, old.wrapping_sub(val))); try_exec!(self.push(Value::I32(old as i32))); }
                    0x29 => { let (mi, offset) = try_exec!(self.read_memarg()); let val = try_exec!(self.pop_i64()) as u8; let base = try_exec!(self.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; let old = try_exec!(self.mem_load_u8(mi, addr)); try_exec!(self.mem_store_u8(mi, addr, old.wrapping_sub(val))); try_exec!(self.push(Value::I64(old as i64))); }
                    0x2a => { let (mi, offset) = try_exec!(self.read_memarg()); let val = try_exec!(self.pop_i64()) as u16; let base = try_exec!(self.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; if addr % 2 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); } let old = try_exec!(self.mem_load_u16(mi, addr)); try_exec!(self.mem_store_u16(mi, addr, old.wrapping_sub(val))); try_exec!(self.push(Value::I64(old as i64))); }
                    0x2b => { let (mi, offset) = try_exec!(self.read_memarg()); let val = try_exec!(self.pop_i64()) as u32; let base = try_exec!(self.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; if addr % 4 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); } let old = try_exec!(self.mem_load_u32(mi, addr)); try_exec!(self.mem_store_u32(mi, addr, old.wrapping_sub(val))); try_exec!(self.push(Value::I64(old as i64))); }
                    // and
                    0x2c => { let (mi, offset) = try_exec!(self.read_memarg()); let val = try_exec!(self.pop_i32()); let base = try_exec!(self.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; if addr % 4 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); } let old = try_exec!(self.mem_load_i32(mi, addr)); try_exec!(self.mem_store_i32(mi, addr, old & val)); try_exec!(self.push(Value::I32(old))); }
                    0x2d => { let (mi, offset) = try_exec!(self.read_memarg()); let val = try_exec!(self.pop_i64()); let base = try_exec!(self.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; if addr % 8 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); } let old = try_exec!(self.mem_load_i64(mi, addr)); try_exec!(self.mem_store_i64(mi, addr, old & val)); try_exec!(self.push(Value::I64(old))); }
                    0x2e => { let (mi, offset) = try_exec!(self.read_memarg()); let val = try_exec!(self.pop_i32()) as u8; let base = try_exec!(self.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; let old = try_exec!(self.mem_load_u8(mi, addr)); try_exec!(self.mem_store_u8(mi, addr, old & val)); try_exec!(self.push(Value::I32(old as i32))); }
                    0x2f => { let (mi, offset) = try_exec!(self.read_memarg()); let val = try_exec!(self.pop_i32()) as u16; let base = try_exec!(self.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; if addr % 2 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); } let old = try_exec!(self.mem_load_u16(mi, addr)); try_exec!(self.mem_store_u16(mi, addr, old & val)); try_exec!(self.push(Value::I32(old as i32))); }
                    0x30 => { let (mi, offset) = try_exec!(self.read_memarg()); let val = try_exec!(self.pop_i64()) as u8; let base = try_exec!(self.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; let old = try_exec!(self.mem_load_u8(mi, addr)); try_exec!(self.mem_store_u8(mi, addr, old & val)); try_exec!(self.push(Value::I64(old as i64))); }
                    0x31 => { let (mi, offset) = try_exec!(self.read_memarg()); let val = try_exec!(self.pop_i64()) as u16; let base = try_exec!(self.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; if addr % 2 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); } let old = try_exec!(self.mem_load_u16(mi, addr)); try_exec!(self.mem_store_u16(mi, addr, old & val)); try_exec!(self.push(Value::I64(old as i64))); }
                    0x32 => { let (mi, offset) = try_exec!(self.read_memarg()); let val = try_exec!(self.pop_i64()) as u32; let base = try_exec!(self.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; if addr % 4 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); } let old = try_exec!(self.mem_load_u32(mi, addr)); try_exec!(self.mem_store_u32(mi, addr, old & val)); try_exec!(self.push(Value::I64(old as i64))); }
                    // or
                    0x33 => { let (mi, offset) = try_exec!(self.read_memarg()); let val = try_exec!(self.pop_i32()); let base = try_exec!(self.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; if addr % 4 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); } let old = try_exec!(self.mem_load_i32(mi, addr)); try_exec!(self.mem_store_i32(mi, addr, old | val)); try_exec!(self.push(Value::I32(old))); }
                    0x34 => { let (mi, offset) = try_exec!(self.read_memarg()); let val = try_exec!(self.pop_i64()); let base = try_exec!(self.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; if addr % 8 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); } let old = try_exec!(self.mem_load_i64(mi, addr)); try_exec!(self.mem_store_i64(mi, addr, old | val)); try_exec!(self.push(Value::I64(old))); }
                    0x35 => { let (mi, offset) = try_exec!(self.read_memarg()); let val = try_exec!(self.pop_i32()) as u8; let base = try_exec!(self.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; let old = try_exec!(self.mem_load_u8(mi, addr)); try_exec!(self.mem_store_u8(mi, addr, old | val)); try_exec!(self.push(Value::I32(old as i32))); }
                    0x36 => { let (mi, offset) = try_exec!(self.read_memarg()); let val = try_exec!(self.pop_i32()) as u16; let base = try_exec!(self.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; if addr % 2 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); } let old = try_exec!(self.mem_load_u16(mi, addr)); try_exec!(self.mem_store_u16(mi, addr, old | val)); try_exec!(self.push(Value::I32(old as i32))); }
                    0x37 => { let (mi, offset) = try_exec!(self.read_memarg()); let val = try_exec!(self.pop_i64()) as u8; let base = try_exec!(self.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; let old = try_exec!(self.mem_load_u8(mi, addr)); try_exec!(self.mem_store_u8(mi, addr, old | val)); try_exec!(self.push(Value::I64(old as i64))); }
                    0x38 => { let (mi, offset) = try_exec!(self.read_memarg()); let val = try_exec!(self.pop_i64()) as u16; let base = try_exec!(self.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; if addr % 2 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); } let old = try_exec!(self.mem_load_u16(mi, addr)); try_exec!(self.mem_store_u16(mi, addr, old | val)); try_exec!(self.push(Value::I64(old as i64))); }
                    0x39 => { let (mi, offset) = try_exec!(self.read_memarg()); let val = try_exec!(self.pop_i64()) as u32; let base = try_exec!(self.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; if addr % 4 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); } let old = try_exec!(self.mem_load_u32(mi, addr)); try_exec!(self.mem_store_u32(mi, addr, old | val)); try_exec!(self.push(Value::I64(old as i64))); }
                    // xor
                    0x3a => { let (mi, offset) = try_exec!(self.read_memarg()); let val = try_exec!(self.pop_i32()); let base = try_exec!(self.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; if addr % 4 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); } let old = try_exec!(self.mem_load_i32(mi, addr)); try_exec!(self.mem_store_i32(mi, addr, old ^ val)); try_exec!(self.push(Value::I32(old))); }
                    0x3b => { let (mi, offset) = try_exec!(self.read_memarg()); let val = try_exec!(self.pop_i64()); let base = try_exec!(self.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; if addr % 8 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); } let old = try_exec!(self.mem_load_i64(mi, addr)); try_exec!(self.mem_store_i64(mi, addr, old ^ val)); try_exec!(self.push(Value::I64(old))); }
                    0x3c => { let (mi, offset) = try_exec!(self.read_memarg()); let val = try_exec!(self.pop_i32()) as u8; let base = try_exec!(self.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; let old = try_exec!(self.mem_load_u8(mi, addr)); try_exec!(self.mem_store_u8(mi, addr, old ^ val)); try_exec!(self.push(Value::I32(old as i32))); }
                    0x3d => { let (mi, offset) = try_exec!(self.read_memarg()); let val = try_exec!(self.pop_i32()) as u16; let base = try_exec!(self.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; if addr % 2 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); } let old = try_exec!(self.mem_load_u16(mi, addr)); try_exec!(self.mem_store_u16(mi, addr, old ^ val)); try_exec!(self.push(Value::I32(old as i32))); }
                    0x3e => { let (mi, offset) = try_exec!(self.read_memarg()); let val = try_exec!(self.pop_i64()) as u8; let base = try_exec!(self.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; let old = try_exec!(self.mem_load_u8(mi, addr)); try_exec!(self.mem_store_u8(mi, addr, old ^ val)); try_exec!(self.push(Value::I64(old as i64))); }
                    0x3f => { let (mi, offset) = try_exec!(self.read_memarg()); let val = try_exec!(self.pop_i64()) as u16; let base = try_exec!(self.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; if addr % 2 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); } let old = try_exec!(self.mem_load_u16(mi, addr)); try_exec!(self.mem_store_u16(mi, addr, old ^ val)); try_exec!(self.push(Value::I64(old as i64))); }
                    0x40 => { let (mi, offset) = try_exec!(self.read_memarg()); let val = try_exec!(self.pop_i64()) as u32; let base = try_exec!(self.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; if addr % 4 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); } let old = try_exec!(self.mem_load_u32(mi, addr)); try_exec!(self.mem_store_u32(mi, addr, old ^ val)); try_exec!(self.push(Value::I64(old as i64))); }
                    // xchg
                    0x41 => { let (mi, offset) = try_exec!(self.read_memarg()); let val = try_exec!(self.pop_i32()); let base = try_exec!(self.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; if addr % 4 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); } let old = try_exec!(self.mem_load_i32(mi, addr)); try_exec!(self.mem_store_i32(mi, addr, val)); try_exec!(self.push(Value::I32(old))); }
                    0x42 => { let (mi, offset) = try_exec!(self.read_memarg()); let val = try_exec!(self.pop_i64()); let base = try_exec!(self.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; if addr % 8 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); } let old = try_exec!(self.mem_load_i64(mi, addr)); try_exec!(self.mem_store_i64(mi, addr, val)); try_exec!(self.push(Value::I64(old))); }
                    0x43 => { let (mi, offset) = try_exec!(self.read_memarg()); let val = try_exec!(self.pop_i32()) as u8; let base = try_exec!(self.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; let old = try_exec!(self.mem_load_u8(mi, addr)); try_exec!(self.mem_store_u8(mi, addr, val)); try_exec!(self.push(Value::I32(old as i32))); }
                    0x44 => { let (mi, offset) = try_exec!(self.read_memarg()); let val = try_exec!(self.pop_i32()) as u16; let base = try_exec!(self.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; if addr % 2 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); } let old = try_exec!(self.mem_load_u16(mi, addr)); try_exec!(self.mem_store_u16(mi, addr, val)); try_exec!(self.push(Value::I32(old as i32))); }
                    0x45 => { let (mi, offset) = try_exec!(self.read_memarg()); let val = try_exec!(self.pop_i64()) as u8; let base = try_exec!(self.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; let old = try_exec!(self.mem_load_u8(mi, addr)); try_exec!(self.mem_store_u8(mi, addr, val)); try_exec!(self.push(Value::I64(old as i64))); }
                    0x46 => { let (mi, offset) = try_exec!(self.read_memarg()); let val = try_exec!(self.pop_i64()) as u16; let base = try_exec!(self.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; if addr % 2 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); } let old = try_exec!(self.mem_load_u16(mi, addr)); try_exec!(self.mem_store_u16(mi, addr, val)); try_exec!(self.push(Value::I64(old as i64))); }
                    0x47 => { let (mi, offset) = try_exec!(self.read_memarg()); let val = try_exec!(self.pop_i64()) as u32; let base = try_exec!(self.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; if addr % 4 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); } let old = try_exec!(self.mem_load_u32(mi, addr)); try_exec!(self.mem_store_u32(mi, addr, val)); try_exec!(self.push(Value::I64(old as i64))); }
                    // cmpxchg
                    0x48 => { let (mi, offset) = try_exec!(self.read_memarg()); let replacement = try_exec!(self.pop_i32()); let expected = try_exec!(self.pop_i32()); let base = try_exec!(self.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; if addr % 4 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); } let old = try_exec!(self.mem_load_i32(mi, addr)); if old == expected { try_exec!(self.mem_store_i32(mi, addr, replacement)); } try_exec!(self.push(Value::I32(old))); }
                    0x49 => { let (mi, offset) = try_exec!(self.read_memarg()); let replacement = try_exec!(self.pop_i64()); let expected = try_exec!(self.pop_i64()); let base = try_exec!(self.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; if addr % 8 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); } let old = try_exec!(self.mem_load_i64(mi, addr)); if old == expected { try_exec!(self.mem_store_i64(mi, addr, replacement)); } try_exec!(self.push(Value::I64(old))); }
                    0x4a => { let (mi, offset) = try_exec!(self.read_memarg()); let replacement = try_exec!(self.pop_i32()) as u8; let expected = try_exec!(self.pop_i32()) as u8; let base = try_exec!(self.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; let old = try_exec!(self.mem_load_u8(mi, addr)); if old == expected { try_exec!(self.mem_store_u8(mi, addr, replacement)); } try_exec!(self.push(Value::I32(old as i32))); }
                    0x4b => { let (mi, offset) = try_exec!(self.read_memarg()); let replacement = try_exec!(self.pop_i32()) as u16; let expected = try_exec!(self.pop_i32()) as u16; let base = try_exec!(self.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; if addr % 2 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); } let old = try_exec!(self.mem_load_u16(mi, addr)); if old == expected { try_exec!(self.mem_store_u16(mi, addr, replacement)); } try_exec!(self.push(Value::I32(old as i32))); }
                    0x4c => { let (mi, offset) = try_exec!(self.read_memarg()); let replacement = try_exec!(self.pop_i64()) as u8; let expected = try_exec!(self.pop_i64()) as u8; let base = try_exec!(self.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; let old = try_exec!(self.mem_load_u8(mi, addr)); if old == expected { try_exec!(self.mem_store_u8(mi, addr, replacement)); } try_exec!(self.push(Value::I64(old as i64))); }
                    0x4d => { let (mi, offset) = try_exec!(self.read_memarg()); let replacement = try_exec!(self.pop_i64()) as u16; let expected = try_exec!(self.pop_i64()) as u16; let base = try_exec!(self.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; if addr % 2 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); } let old = try_exec!(self.mem_load_u16(mi, addr)); if old == expected { try_exec!(self.mem_store_u16(mi, addr, replacement)); } try_exec!(self.push(Value::I64(old as i64))); }
                    0x4e => { let (mi, offset) = try_exec!(self.read_memarg()); let replacement = try_exec!(self.pop_i64()) as u32; let expected = try_exec!(self.pop_i64()) as u32; let base = try_exec!(self.pop_i32()) as u32; let addr = try_exec!(base.checked_add(offset).ok_or(WasmError::MemoryOutOfBounds)) as usize; if addr % 4 != 0 { return ExecResult::Trap(WasmError::UnalignedAtomic); } let old = try_exec!(self.mem_load_u32(mi, addr)); if old == expected { try_exec!(self.mem_store_u32(mi, addr, replacement)); } try_exec!(self.push(Value::I64(old as i64))); }
                    _ => { return ExecResult::Trap(WasmError::InvalidOpcode(0xFE)); }
                }
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

        // Restore PC and block depth
        self.pc = frame.return_pc;
        self.block_depth = frame.saved_block_depth;

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
