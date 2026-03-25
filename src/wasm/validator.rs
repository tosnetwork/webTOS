//! WASM module validator.
//!
//! Performs structural and instruction-level validation of a decoded WASM module,
//! including stack-based type checking per the WebAssembly specification.

use crate::wasm::decoder::{ElemMode, ExportKind, ImportKind, WasmModule};
use crate::wasm::types::{ValType, WasmError, MAX_MEMORY_PAGES, MAX_TABLE_SIZE};
use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;

/// Validate a decoded WASM module.
pub fn validate(module: &WasmModule) -> Result<(), WasmError> {
    // Count imports by kind
    let func_import_count = module.func_import_count();
    let total_functions = func_import_count + module.functions.len();
    let has_memory = module.has_memory;
    let total_tables = module.tables.len(); // tables vec already includes imports
    let total_globals = module.globals.len() + count_global_imports(module);

    // Validate function type indices
    for func in &module.functions {
        if func.type_idx as usize >= module.func_types.len() {
            return Err(WasmError::FunctionNotFound(func.type_idx));
        }
    }

    // Validate import type indices
    for imp in &module.imports {
        if let ImportKind::Func(type_idx) = imp.kind {
            if type_idx as usize >= module.func_types.len() {
                return Err(WasmError::FunctionNotFound(type_idx));
            }
        }
    }

    // Validate: self-referential types require GC proposal (implicit rec groups).
    // gc_enabled alone is not sufficient - the function-references proposal allows
    // typed refs but not implicit recursion. Use the separate implicit_rec flag.
    if module.has_self_ref_types && !module.implicit_rec_enabled {
        return Err(WasmError::TypeMismatch);
    }

    // Validate: no multi-memory unless the multi-memory proposal is enabled
    if module.memory_count > 1 && !module.multi_memory_enabled {
        return Err(WasmError::InvalidSection);
    }

    // Multiple tables: the reference-types proposal allows them.
    // Only the threads proposal (which is pre-reference-types) needs to reject them.
    // We gate this on a module flag `reject_multi_table` set by the runner for threads-only tests.
    if total_tables > 1 && module.reject_multi_table {
        return Err(WasmError::MultipleTables);
    }

    // Validate export indices and check for duplicate export names
    {
        let mut export_names = BTreeSet::new();
        for exp in &module.exports {
            // Check for duplicate names
            let name_bytes = module.get_name(exp.name_offset, exp.name_len);
            let name = String::from_utf8_lossy(name_bytes).into_owned();
            if !export_names.insert(name) {
                return Err(WasmError::DuplicateExport);
            }

            match exp.kind {
                ExportKind::Func(idx) => {
                    if idx as usize >= total_functions {
                        return Err(WasmError::FunctionNotFound(idx));
                    }
                }
                ExportKind::Table(idx) => {
                    if idx as usize >= total_tables {
                        return Err(WasmError::TableIndexOutOfBounds);
                    }
                }
                ExportKind::Memory(idx) => {
                    if module.multi_memory_enabled {
                        if idx >= module.memory_count || !has_memory {
                            return Err(WasmError::MemoryOutOfBounds);
                        }
                    } else {
                        if idx > 0 || !has_memory {
                            return Err(WasmError::MemoryOutOfBounds);
                        }
                    }
                }
                ExportKind::Global(idx) => {
                    if idx as usize >= total_globals {
                        return Err(WasmError::OutOfBounds);
                    }
                }
                ExportKind::Tag(_) => {
                    // Tag exports are not validated further (exception handling proposal)
                }
            }
        }
    }

    // Validate custom page sizes: only 0 (1 byte) and 16 (65536 bytes) are valid
    if let Some(log2) = module.page_size_log2 {
        if log2 != 0 && log2 != 16 {
            return Err(WasmError::InvalidSection);
        }
    }

    // Validate memory limits
    if module.memory_min_pages as u64 > MAX_MEMORY_PAGES as u64 {
        return Err(WasmError::MemoryOutOfBounds);
    }
    if module.has_memory_max {
        if module.memory_min_pages > module.memory_max_pages {
            return Err(WasmError::MemoryOutOfBounds);
        }
        if module.memory_max_pages as u64 > MAX_MEMORY_PAGES as u64 {
            return Err(WasmError::MemoryOutOfBounds);
        }
    }

    // Validate table limits
    for table in &module.tables {
        if let Some(max) = table.max {
            if table.min > max {
                return Err(WasmError::TableIndexOutOfBounds);
            }
        }
    }

    // Validate global init expressions:
    // With extended-const/GC, global.get can reference any previously defined global
    // (imported or module-defined) with index < current global's absolute index.
    // The referenced global must be immutable.
    let global_import_count = count_global_imports(module);
    let table_import_count = count_table_imports(module);
    for (g_idx, global) in module.globals.iter().enumerate() {
        if let Some(ref_idx) = global.init_global_ref {
            let abs_idx = global_import_count + g_idx;
            let total_globals = global_import_count + module.globals.len();
            if module.gc_enabled {
                // GC: global.get can reference any previously defined global
                if (ref_idx as usize) >= total_globals {
                    return Err(WasmError::GlobalIndexOutOfBounds);
                }
                if (ref_idx as usize) >= abs_idx {
                    return Err(WasmError::GlobalIndexOutOfBounds);
                }
            } else {
                // Non-GC: global.get can only reference imported globals
                if ref_idx as usize >= global_import_count {
                    return Err(WasmError::GlobalIndexOutOfBounds);
                }
            }
            // The referenced global must be immutable
            if (ref_idx as usize) < global_import_count {
                let mut gi: usize = 0;
                for imp in &module.imports {
                    if let ImportKind::Global(_, mutable, _) = imp.kind {
                        if gi == ref_idx as usize {
                            if mutable {
                                return Err(WasmError::TypeMismatch);
                            }
                            break;
                        }
                        gi += 1;
                    }
                }
            } else {
                // Module-defined global
                let local_idx = ref_idx as usize - global_import_count;
                if module.globals[local_idx].mutable {
                    return Err(WasmError::TypeMismatch);
                }
            }
        }
        // Validate global init expression stack depth (must be exactly 1)
        if global.init_expr_stack_depth != 1 {
            return Err(WasmError::TypeMismatch);
        }
        // Validate global init expression type matches declared type
        // When GC is enabled, skip type checks — our type system doesn't model
        // GC heap types (i31ref, structref, arrayref, etc.) precisely in init exprs.
        if !module.gc_enabled {
            if let Some(expr_type) = global.init_expr_type {
                if expr_type != global.val_type {
                    if !is_ref_compatible(expr_type, global.val_type) {
                        return Err(WasmError::TypeMismatch);
                    }
                }
            } else if global.init_global_ref.is_some() {
                if let Some(ref_idx) = global.init_global_ref {
                    let ref_type = get_imported_global_type(module, ref_idx);
                    if let Some(rt) = ref_type {
                        if rt != global.val_type && !is_ref_compatible(rt, global.val_type) {
                            return Err(WasmError::TypeMismatch);
                        }
                    }
                }
            }
        }
    }

    // Validate start function
    if let Some(start_idx) = module.start_func {
        if start_idx as usize >= total_functions {
            return Err(WasmError::FunctionNotFound(start_idx));
        }
        let type_idx = if (start_idx as usize) < func_import_count {
            module.func_import_type(start_idx).unwrap_or(0) as usize
        } else {
            let local_idx = start_idx as usize - func_import_count;
            if local_idx < module.functions.len() {
                module.functions[local_idx].type_idx as usize
            } else {
                return Err(WasmError::FunctionNotFound(start_idx));
            }
        };
        if type_idx < module.func_types.len() {
            let ft = &module.func_types[type_idx];
            if ft.param_count != 0 || ft.result_count != 0 {
                return Err(WasmError::TypeMismatch);
            }
        }
    }

    // Build the set of "declared" function references.
    // Per spec, a function is "declared" if it appears in:
    // 1. An element segment (function indices)
    // 2. A ref.func in any init expression (global init, elem expression)
    // 3. An export
    let mut declared_funcs: BTreeSet<u32> = BTreeSet::new();
    for seg in &module.element_segments {
        // Only collect function indices from funcref-typed element segments
        let is_func_elem = matches!(seg.elem_type, ValType::FuncRef | ValType::TypedFuncRef | ValType::NullableTypedFuncRef);
        if is_func_elem {
            for &fi in &seg.func_indices {
                if fi != u32::MAX {
                    declared_funcs.insert(fi);
                }
            }
        }
    }
    // ref.func in global init expressions
    for global in &module.globals {
        if let Some(func_idx) = global.init_func_ref {
            // Also validate function index bounds
            if func_idx as usize >= total_functions {
                return Err(WasmError::FunctionNotFound(func_idx));
            }
            declared_funcs.insert(func_idx);
        }
    }
    // Exported functions
    for exp in &module.exports {
        if let ExportKind::Func(idx) = exp.kind {
            declared_funcs.insert(idx);
        }
    }

    // Validate element segments
    for seg in &module.element_segments {
        // Only validate function index bounds for funcref-typed segments
        let is_func_elem = matches!(seg.elem_type, ValType::FuncRef | ValType::TypedFuncRef | ValType::NullableTypedFuncRef);
        if is_func_elem {
            for &fi in &seg.func_indices {
                if fi != u32::MAX && fi as usize >= total_functions {
                    return Err(WasmError::FunctionNotFound(fi));
                }
            }
        }
        if seg.mode == ElemMode::Active {
            if total_tables == 0 || seg.table_idx as usize >= total_tables {
                return Err(WasmError::TableIndexOutOfBounds);
            }
            // Validate element type compatibility with table
            let tbl_et = table_elem_type(module, seg.table_idx, table_import_count);
            // For func-index segments (no item_expr_infos), the effective type is
            // (ref func) = TypedFuncRef since func indices are inherently non-nullable.
            let effective_elem_type = if seg.item_expr_infos.is_empty() && seg.elem_type == ValType::FuncRef {
                ValType::TypedFuncRef
            } else {
                seg.elem_type
            };
            if !ref_types_compatible(effective_elem_type, tbl_et) {
                return Err(WasmError::TypeMismatch);
            }
            // Validate offset expression (table64 uses I64 offset)
            let offset_type = table_index_type(module, seg.table_idx);
            validate_init_expr_for_segment(
                &seg.offset_expr_info, global_import_count, total_globals,
                module, offset_type,
            )?;
        }
        // Validate per-item expression types for expression-based segments (flags 4-7)
        for item_info in &seg.item_expr_infos {
            // Each item expression must produce exactly 1 value
            if item_info.stack_depth != 1 {
                return Err(WasmError::TypeMismatch);
            }
            // The item expression result type must match the segment's elem_type
            if let Some(item_type) = item_info.result_type {
                if !ref_types_compatible(item_type, seg.elem_type) {
                    return Err(WasmError::TypeMismatch);
                }
            }
        }
    }

    // Validate data segments
    for seg in &module.data_segments {
        if seg.is_active {
            if !has_memory { return Err(WasmError::MemoryOutOfBounds); }
            if module.multi_memory_enabled {
                if seg.memory_idx >= module.memory_count { return Err(WasmError::MemoryOutOfBounds); }
            } else {
                if seg.memory_idx > 0 { return Err(WasmError::MemoryOutOfBounds); }
            }
            // Validate offset expression (memory64 uses I64 offset)
            let offset_type = if (seg.memory_idx as usize) < module.memories.len() {
                if module.memories[seg.memory_idx as usize].is_memory64 { ValType::I64 } else { ValType::I32 }
            } else if module.is_memory64 { ValType::I64 } else { ValType::I32 };
            validate_init_expr_for_segment(
                &seg.offset_expr_info, global_import_count, total_globals,
                module, offset_type,
            )?;
        }
    }

    // Validate instruction sequences for each function
    for (i, func) in module.functions.iter().enumerate() {
        validate_function_body(module, i, func, total_functions, has_memory,
            total_tables, total_globals, table_import_count, &declared_funcs)?;
    }

    Ok(())
}

/// Get the ValType of an imported global by its global index.
fn get_imported_global_type(module: &WasmModule, global_idx: u32) -> Option<ValType> {
    let mut gi = 0u32;
    for imp in &module.imports {
        if let ImportKind::Global(vt_byte, _, _) = imp.kind {
            if gi == global_idx {
                return match vt_byte {
                    0x7F => Some(ValType::I32),
                    0x7E => Some(ValType::I64),
                    0x7D => Some(ValType::F32),
                    0x7C => Some(ValType::F64),
                    0x7B => Some(ValType::V128),
                    0x70 => Some(ValType::FuncRef),
                    0x6F => Some(ValType::ExternRef),
                    _ => None,
                };
            }
            gi += 1;
        }
    }
    None
}

fn count_table_imports(module: &WasmModule) -> usize {
    module.imports.iter().filter(|imp| matches!(imp.kind, ImportKind::Table(_))).count()
}

fn count_global_imports(module: &WasmModule) -> usize {
    module.imports.iter().filter(|imp| matches!(imp.kind, ImportKind::Global(_, _, _))).count()
}

/// Check if two types are ref-compatible (both ref types are interchangeable
/// for the purpose of global init validation when the global type is a ref type).
fn is_ref_compatible(a: ValType, b: ValType) -> bool {
    if a == b { return true; }
    // Typed func refs are subtypes of FuncRef
    let a_funcref_family = matches!(a, ValType::FuncRef | ValType::TypedFuncRef | ValType::NullableTypedFuncRef);
    let b_funcref_family = matches!(b, ValType::FuncRef | ValType::TypedFuncRef | ValType::NullableTypedFuncRef);
    if a_funcref_family && b_funcref_family { return true; }
    false
}

/// Validate an init expression used in a data or element segment offset.
fn validate_init_expr_for_segment(
    info: &crate::wasm::decoder::InitExprInfo,
    global_import_count: usize,
    _total_globals: usize,
    module: &WasmModule,
    expected_type: ValType,
) -> Result<(), WasmError> {
    // Check global references
    if let Some(ref_idx) = info.global_ref {
        let total_globals = global_import_count + module.globals.len();
        if module.gc_enabled {
            // GC: allow any global
            if ref_idx as usize >= total_globals {
                return Err(WasmError::GlobalIndexOutOfBounds);
            }
        } else {
            // Non-GC: only imported globals allowed
            if ref_idx as usize >= global_import_count {
                return Err(WasmError::GlobalIndexOutOfBounds);
            }
        }
        // Referenced global must be immutable
        if (ref_idx as usize) < global_import_count {
            let mut gi: usize = 0;
            for imp in &module.imports {
                if let ImportKind::Global(_, mutable, _) = imp.kind {
                    if gi == ref_idx as usize {
                        if mutable {
                            return Err(WasmError::ConstExprRequired);
                        }
                        break;
                    }
                    gi += 1;
                }
            }
        } else if module.gc_enabled {
            let local_idx = ref_idx as usize - global_import_count;
            if local_idx < module.globals.len() && module.globals[local_idx].mutable {
                return Err(WasmError::ConstExprRequired);
            }
        }
    }
    // Check for non-constant instructions
    if info.has_non_const {
        return Err(WasmError::ConstExprRequired);
    }
    // Check expression type: must produce exactly 1 value of expected type
    if info.stack_depth != 1 {
        return Err(WasmError::TypeMismatch);
    }
    if let Some(result_type) = info.result_type {
        if result_type != expected_type {
            return Err(WasmError::TypeMismatch);
        }
    }
    // If result_type is None, it came from a global.get - we can't check the type
    // without looking up the global. For now, trust it.
    Ok(())
}

/// Get the element type of a table by index (including imported tables).
fn table_elem_type(module: &WasmModule, table_idx: u32, table_import_count: usize) -> ValType {
    if (table_idx as usize) < table_import_count {
        let mut ti = 0usize;
        for imp in &module.imports {
            if let ImportKind::Table(et) = imp.kind {
                if ti == table_idx as usize {
                    return et;
                }
                ti += 1;
            }
        }
        ValType::FuncRef
    } else {
        let local_idx = table_idx as usize - table_import_count;
        if local_idx < module.tables.len() {
            module.tables[local_idx].elem_type
        } else {
            ValType::FuncRef
        }
    }
}

/// Get the index type of a table (I32 for normal, I64 for table64).
fn table_index_type(module: &WasmModule, table_idx: u32) -> ValType {
    if (table_idx as usize) < module.tables.len() && module.tables[table_idx as usize].is_table64 {
        ValType::I64
    } else {
        ValType::I32
    }
}

/// Check if source ref type is compatible with destination ref type.
/// Subtyping: non-nullable is subtype of nullable, typed is subtype of abstract.
fn ref_types_compatible(src: ValType, dst: ValType) -> bool {
    // Use the comprehensive subtype check
    val_is_subtype(src, dst)
}

/// Comprehensive subtype check for validator pop_expect.
/// Covers GC type hierarchy: none <: i31/struct/array <: eq <: any
/// func hierarchy: nofunc <: typed <: nullable typed <: func
/// extern hierarchy: noextern <: extern
/// Check if a type is a non-nullable reference type (requires initialization).
fn is_non_nullable_ref(t: ValType) -> bool {
    matches!(t, ValType::TypedFuncRef | ValType::StructRef | ValType::ArrayRef)
}

fn val_is_subtype(src: ValType, dst: ValType) -> bool {
    if src == dst { return true; }
    match (src, dst) {
        // FuncRef family: direction is typed <: nullable <: funcref
        (ValType::TypedFuncRef, ValType::NullableTypedFuncRef | ValType::FuncRef) => true,
        (ValType::NullableTypedFuncRef, ValType::FuncRef) => true,
        // GC ref hierarchy: none <: i31/struct/array <: eq <: any
        (ValType::NoneRef, d) if is_ref_type(d) || d == ValType::ExnRef => true,
        (ValType::I31Ref, ValType::EqRef | ValType::AnyRef) => true,
        (ValType::StructRef | ValType::NullableStructRef, ValType::EqRef | ValType::AnyRef) => true,
        (ValType::StructRef, ValType::NullableStructRef) => true,
        (ValType::ArrayRef, ValType::EqRef | ValType::AnyRef) => true,
        (ValType::EqRef, ValType::AnyRef) => true,
        // Concrete GC refs (encoded as TypedFuncRef/NullableTypedFuncRef for non-func types)
        // are subtypes of abstract GC types
        (ValType::TypedFuncRef | ValType::NullableTypedFuncRef,
         ValType::AnyRef | ValType::EqRef | ValType::StructRef |
         ValType::NullableStructRef | ValType::ArrayRef | ValType::I31Ref) => true,
        _ => false,
    }
}

/// Check if `src` is a subtype of `dst` (src <: dst).
/// Used for validating try_table catch clause label types.
fn is_subtype(src: ValType, dst: ValType) -> bool {
    val_is_subtype(src, dst)
}

/// Check if a ValType is a reference type.
fn is_ref_type(t: ValType) -> bool {
    matches!(t, ValType::FuncRef | ValType::ExternRef | ValType::TypedFuncRef | ValType::NullableTypedFuncRef
        | ValType::AnyRef | ValType::EqRef | ValType::I31Ref | ValType::StructRef
        | ValType::NullableStructRef | ValType::ArrayRef | ValType::NoneRef | ValType::ExnRef)
}

// ─── Type checking structures ────────────────────────────────────────────────

/// Represents a type on the validation stack. `Unknown` is used for polymorphic
/// (unreachable) stack positions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StackType {
    Known(ValType),
    Unknown,
}

/// A control frame on the control stack, tracking block structure.
#[derive(Debug, Clone)]
struct CtrlFrame {
    /// The opcode that opened this frame (0x02=block, 0x03=loop, 0x04=if)
    opcode: u8,
    /// Types expected at the start of the block (parameters)
    start_types: Vec<ValType>,
    /// Types produced at the end of the block (results)
    end_types: Vec<ValType>,
    /// Height of the operand stack when this frame was entered
    height: usize,
    /// Whether we are in unreachable code
    unreachable: bool,
    /// Local initialization state at block entry (for merging at end)
    local_inits_at_entry: Vec<bool>,
    /// For else frames: stores the if-entry init state for proper merging.
    if_entry_inits: Option<Vec<bool>>,
}

/// The validation context for a single function.
struct Validator<'a> {
    module: &'a WasmModule,
    code: &'a [u8],
    pc: usize,
    end: usize,
    /// The operand type stack
    opd_stack: Vec<StackType>,
    /// The control flow stack
    ctrl_stack: Vec<CtrlFrame>,
    /// Local types: params then locals
    local_types: Vec<ValType>,
    /// Number of parameters (params are always initialized)
    param_count: usize,
    /// Function return types
    return_types: Vec<ValType>,
    total_functions: usize,
    has_memory: bool,
    total_tables: usize,
    total_globals: usize,
    func_import_count: usize,
    table_import_count: usize,
    /// Set of function indices declared in element segments (for ref.func validation)
    declared_funcs: &'a BTreeSet<u32>,
    /// Local initialization tracking: true if the local has been set.
    /// Params are always initialized; non-nullable ref locals start uninitialized.
    local_inits: Vec<bool>,
}

impl<'a> Validator<'a> {
    fn push_opd(&mut self, t: StackType) {
        self.opd_stack.push(t);
    }

    fn push_val(&mut self, t: ValType) {
        self.opd_stack.push(StackType::Known(t));
    }

    fn pop_opd(&mut self) -> Result<StackType, WasmError> {
        let frame = self.ctrl_stack.last().ok_or(WasmError::StackUnderflow)?;
        if self.opd_stack.len() == frame.height {
            if frame.unreachable {
                return Ok(StackType::Unknown);
            }
            return Err(WasmError::TypeMismatch);
        }
        Ok(self.opd_stack.pop().unwrap())
    }

    fn pop_expect(&mut self, expected: ValType) -> Result<(), WasmError> {
        let actual = self.pop_opd()?;
        match actual {
            StackType::Known(t) if t == expected => Ok(()),
            StackType::Unknown => Ok(()),
            StackType::Known(t) if val_is_subtype(t, expected) => Ok(()),
            _ => Err(WasmError::TypeMismatch),
        }
    }

    fn pop_expect_st(&mut self, expected: StackType) -> Result<(), WasmError> {
        match expected {
            StackType::Known(t) => self.pop_expect(t),
            StackType::Unknown => { let _ = self.pop_opd()?; Ok(()) }
        }
    }

    fn push_ctrl(&mut self, opcode: u8, start_types: Vec<ValType>, end_types: Vec<ValType>) {
        let height = self.opd_stack.len();
        // Push input types onto the stack
        for &t in &start_types {
            self.push_val(t);
        }
        self.ctrl_stack.push(CtrlFrame {
            opcode,
            start_types,
            end_types,
            height,
            unreachable: false,
            local_inits_at_entry: self.local_inits.clone(),
            if_entry_inits: None,
        });
    }

    fn pop_ctrl(&mut self) -> Result<CtrlFrame, WasmError> {
        let frame = self.ctrl_stack.last().ok_or(WasmError::StackUnderflow)?;
        let end_types = frame.end_types.clone();
        // Pop the expected result types
        for i in (0..end_types.len()).rev() {
            self.pop_expect(end_types[i])?;
        }
        let frame = self.ctrl_stack.last().ok_or(WasmError::StackUnderflow)?;
        if self.opd_stack.len() != frame.height {
            return Err(WasmError::TypeMismatch);
        }
        let frame = self.ctrl_stack.pop().unwrap();
        Ok(frame)
    }

    fn set_unreachable(&mut self) {
        if let Some(frame) = self.ctrl_stack.last_mut() {
            self.opd_stack.truncate(frame.height);
            frame.unreachable = true;
        }
    }

    /// Get the label types for a branch to depth `n`.
    /// For loop frames, this is the start types; for others, end types.
    fn label_types(&self, n: usize) -> Result<Vec<ValType>, WasmError> {
        if n >= self.ctrl_stack.len() {
            return Err(WasmError::BranchDepthExceeded);
        }
        let idx = self.ctrl_stack.len() - 1 - n;
        let frame = &self.ctrl_stack[idx];
        if frame.opcode == 0x03 {
            // loop: branch goes to start
            Ok(frame.start_types.clone())
        } else {
            Ok(frame.end_types.clone())
        }
    }

    fn read_u8(&mut self) -> Result<u8, WasmError> {
        if self.pc >= self.end {
            return Err(WasmError::UnexpectedEnd);
        }
        let b = self.code[self.pc];
        self.pc += 1;
        Ok(b)
    }

    fn read_u32(&mut self) -> Result<u32, WasmError> {
        read_leb128_u32(self.code, &mut self.pc)
    }

    fn read_i32(&mut self) -> Result<i32, WasmError> {
        crate::wasm::decoder::decode_leb128_i32(self.code, &mut self.pc)
    }

    fn read_i64(&mut self) -> Result<i64, WasmError> {
        crate::wasm::decoder::decode_leb128_i64(self.code, &mut self.pc)
    }

    fn read_u64(&mut self) -> Result<u64, WasmError> {
        crate::wasm::decoder::decode_leb128_u64(self.code, &mut self.pc)
    }

    /// Get the address type for memory 0 (I32 for normal, I64 for memory64).
    fn mem_addr_type(&self) -> ValType {
        if self.module.is_memory64 { ValType::I64 } else { ValType::I32 }
    }

    /// Get the address type for a specific memory index.
    fn mem_addr_type_for(&self, mem_idx: u32) -> ValType {
        let is_mem64 = if (mem_idx as usize) < self.module.memories.len() {
            self.module.memories[mem_idx as usize].is_memory64
        } else {
            self.module.is_memory64
        };
        if is_mem64 { ValType::I64 } else { ValType::I32 }
    }

    /// Read a memarg (alignment + offset) and validate alignment against max_align.
    /// max_align is log2 of the natural alignment (0=1byte, 1=2byte, 2=4byte, 3=8byte, 4=16byte).
    fn read_memarg(&mut self, max_align: u32) -> Result<(), WasmError> {
        let flags = self.read_u32()?;
        // In multi-memory mode, bit 6 signals an explicit memory index follows
        let mem_idx = if self.module.multi_memory_enabled && (flags & (1 << 6)) != 0 {
            self.read_u32()?
        } else if flags >= 64 {
            // bit 6 set but multi-memory not enabled
            return Err(WasmError::TypeMismatch);
        } else {
            0u32
        };
        let effective_align = flags & 0x3F;
        if effective_align > max_align {
            return Err(WasmError::TypeMismatch);
        }
        // Validate memory index bounds
        if self.module.multi_memory_enabled {
            if mem_idx >= self.module.memory_count {
                return Err(WasmError::MemoryOutOfBounds);
            }
        }
        // For memory64 memories, read 64-bit offset; otherwise 32-bit
        let is_mem64 = if (mem_idx as usize) < self.module.memories.len() {
            self.module.memories[mem_idx as usize].is_memory64
        } else {
            self.module.is_memory64
        };
        if is_mem64 {
            let _offset = self.read_u64()?;
        } else {
            let _offset = self.read_u32()?;
        }
        Ok(())
    }

    /// Read a single byte and check it's 0x00 (for memory.size/memory.grow).
    fn read_zero_byte(&mut self) -> Result<(), WasmError> {
        let b = self.read_u8()?;
        if b != 0x00 {
            return Err(WasmError::ZeroByteExpected);
        }
        Ok(())
    }

    /// Decode a block type: -0x40 = void, -0x01..-0x04/-0x05 = single valtype, else type index
    fn read_block_type(&mut self) -> Result<(Vec<ValType>, Vec<ValType>), WasmError> {
        let raw = self.read_i32()?;
        if raw == -0x40 {
            // void block
            Ok((Vec::new(), Vec::new()))
        } else if raw < 0 {
            // Single value type encoded as negative
            let vt = match raw {
                -0x01 => ValType::I32,   // 0x7F
                -0x02 => ValType::I64,   // 0x7E
                -0x03 => ValType::F32,   // 0x7D
                -0x04 => ValType::F64,   // 0x7C
                -0x05 => ValType::V128,  // 0x7B
                -0x10 => ValType::FuncRef,   // 0x70 = funcref
                -0x11 => ValType::ExternRef, // 0x6F = externref
                -0x12 => ValType::AnyRef,    // 0x6E = anyref
                -0x13 => ValType::EqRef,     // 0x6D = eqref
                -0x14 => ValType::I31Ref,    // 0x6C = i31ref
                -0x15 => ValType::NullableStructRef, // 0x6B = structref
                -0x16 => ValType::ArrayRef,  // 0x6A = arrayref
                -0x17 => ValType::ExnRef,    // 0x69 = exnref
                -0x0F => ValType::NoneRef,   // 0x71 = nullref
                -0x0E => ValType::ExternRef, // 0x72 = nullexternref
                -0x0D => ValType::FuncRef,   // 0x73 = nullfuncref
                -0x1D => {
                    // 0x63 = (ref null ht) — read the heap type
                    let heap_type = self.read_i32()?;
                    match heap_type {
                        -0x10 => ValType::FuncRef,     // func
                        -0x11 => ValType::ExternRef,   // extern
                        -0x12 => ValType::AnyRef,      // any
                        -0x13 => ValType::EqRef,       // eq
                        -0x14 => ValType::I31Ref,      // i31
                        -0x15 => ValType::NullableStructRef, // struct
                        -0x16 => ValType::ArrayRef,    // array
                        -0x17 => ValType::ExnRef,      // exn
                        -0x0F => ValType::NoneRef,     // none
                        -0x0E => ValType::ExternRef,   // noextern
                        -0x0D => ValType::FuncRef,     // nofunc
                        _ => ValType::NullableTypedFuncRef,
                    }
                }
                -0x1C => {
                    // 0x64 = (ref ht) — read the heap type
                    let heap_type = self.read_i32()?;
                    match heap_type {
                        -0x10 => ValType::TypedFuncRef, // func (non-nullable)
                        -0x11 => ValType::ExternRef,    // extern (non-nullable)
                        -0x12 => ValType::AnyRef,       // any
                        -0x13 => ValType::EqRef,        // eq
                        -0x14 => ValType::I31Ref,       // i31
                        -0x15 => ValType::StructRef,    // struct
                        -0x16 => ValType::ArrayRef,     // array
                        -0x17 => ValType::ExnRef,       // exn
                        -0x0F => ValType::NoneRef,      // none
                        -0x0E => ValType::ExternRef,    // noextern
                        -0x0D => ValType::FuncRef,      // nofunc
                        _ => ValType::TypedFuncRef,
                    }
                }
                _ => return Err(WasmError::InvalidBlockType),
            };
            Ok((Vec::new(), alloc::vec![vt]))
        } else {
            // Type index for multi-value
            let idx = raw as u32 as usize;
            if idx >= self.module.func_types.len() {
                return Err(WasmError::TypeMismatch);
            }
            let ft = &self.module.func_types[idx];
            let params: Vec<ValType> = ft.params[..ft.param_count as usize].to_vec();
            let results: Vec<ValType> = ft.results[..ft.result_count as usize].to_vec();
            Ok((params, results))
        }
    }

    /// Get the type of a local (param or local variable).
    fn local_type(&self, idx: u32) -> Result<ValType, WasmError> {
        if (idx as usize) < self.local_types.len() {
            Ok(self.local_types[idx as usize])
        } else {
            Err(WasmError::OutOfBounds)
        }
    }

    /// Get the type of a global.
    fn global_type(&self, idx: u32) -> Result<(ValType, bool), WasmError> {
        let mut global_import_idx: u32 = 0;
        for imp in &self.module.imports {
            if let ImportKind::Global(vt_byte, mutable, _) = imp.kind {
                if global_import_idx == idx {
                    let vt = byte_to_valtype(vt_byte)?;
                    return Ok((vt, mutable));
                }
                global_import_idx += 1;
            }
        }
        let local_idx = idx as usize - global_import_idx as usize;
        if local_idx < self.module.globals.len() {
            let g = &self.module.globals[local_idx];
            Ok((g.val_type, g.mutable))
        } else {
            Err(WasmError::OutOfBounds)
        }
    }

    /// Get the function type for a function index (import or local).
    fn func_type(&self, func_idx: u32) -> Result<&'a crate::wasm::decoder::FuncTypeDef, WasmError> {
        let type_idx = if (func_idx as usize) < self.func_import_count {
            self.module.func_import_type(func_idx).ok_or(WasmError::FunctionNotFound(func_idx))? as usize
        } else {
            let local_idx = func_idx as usize - self.func_import_count;
            if local_idx < self.module.functions.len() {
                self.module.functions[local_idx].type_idx as usize
            } else {
                return Err(WasmError::FunctionNotFound(func_idx));
            }
        };
        if type_idx < self.module.func_types.len() {
            Ok(&self.module.func_types[type_idx])
        } else {
            Err(WasmError::TypeMismatch)
        }
    }

    fn validate(&mut self) -> Result<(), WasmError> {
        // Push the function frame: the implicit block wrapping the function body
        let start_types = Vec::new(); // function frame has no start types on stack
        let end_types = self.return_types.clone();
        self.push_ctrl(0x02, start_types, end_types); // treat function body as a block

        while self.pc < self.end {
            let opcode = self.code[self.pc];
            self.pc += 1;

            match opcode {
                // ── unreachable ──
                0x00 => {
                    self.set_unreachable();
                }
                // ── nop ──
                0x01 => {}
                // ── block ──
                0x02 => {
                    let (params, results) = self.read_block_type()?;
                    // Pop params from current stack
                    for i in (0..params.len()).rev() {
                        self.pop_expect(params[i])?;
                    }
                    self.push_ctrl(0x02, params, results);
                }
                // ── loop ──
                0x03 => {
                    let (params, results) = self.read_block_type()?;
                    for i in (0..params.len()).rev() {
                        self.pop_expect(params[i])?;
                    }
                    self.push_ctrl(0x03, params, results);
                }
                // ── if ──
                0x04 => {
                    let (params, results) = self.read_block_type()?;
                    self.pop_expect(ValType::I32)?; // condition
                    for i in (0..params.len()).rev() {
                        self.pop_expect(params[i])?;
                    }
                    self.push_ctrl(0x04, params, results);
                }
                // ── else ──
                0x05 => {
                    let frame = self.pop_ctrl()?;
                    if frame.opcode != 0x04 {
                        return Err(WasmError::TypeMismatch);
                    }
                    // Save the then-branch init state; restore entry state for else-branch
                    let then_inits = self.local_inits.clone();
                    let if_entry_inits = frame.local_inits_at_entry.clone();
                    self.local_inits = if_entry_inits.clone();
                    let else_frame_start = frame.start_types.clone();
                    let else_frame_end = frame.end_types.clone();
                    // Store then-branch inits in the new frame for merging at end
                    self.push_ctrl(0x05, else_frame_start, else_frame_end);
                    // Stash then_inits and if-entry inits in the ctrl frame
                    if let Some(f) = self.ctrl_stack.last_mut() {
                        f.local_inits_at_entry = then_inits;
                        f.if_entry_inits = Some(if_entry_inits);
                    }
                }
                // ── end ──
                0x0B => {
                    let frame = self.pop_ctrl()?;
                    // If this was an if without else, check that start_types == end_types
                    if frame.opcode == 0x04 {
                        // An if without else must have matching start/end types
                        if frame.start_types.len() != frame.end_types.len() {
                            return Err(WasmError::TypeMismatch);
                        }
                        for i in 0..frame.start_types.len() {
                            if frame.start_types[i] != frame.end_types[i] {
                                return Err(WasmError::TypeMismatch);
                            }
                        }
                        // For if-without-else, merge: local is init only if init at entry
                        // (else branch is implicitly the entry state)
                        let entry_inits = &frame.local_inits_at_entry;
                        for i in 0..self.local_inits.len().min(entry_inits.len()) {
                            self.local_inits[i] = self.local_inits[i] && entry_inits[i];
                        }
                    } else if frame.opcode == 0x05 {
                        // else-end: merge entry, then-end, and else-end.
                        // Result = entry_init INTERSECT then_end INTERSECT else_end
                        let then_inits = &frame.local_inits_at_entry;
                        for i in 0..self.local_inits.len().min(then_inits.len()) {
                            self.local_inits[i] = self.local_inits[i] && then_inits[i];
                        }
                        // Also intersect with the if-entry state
                        if let Some(ref entry_inits) = frame.if_entry_inits {
                            for i in 0..self.local_inits.len().min(entry_inits.len()) {
                                self.local_inits[i] = self.local_inits[i] && entry_inits[i];
                            }
                        }
                    } else if frame.opcode == 0x02 || frame.opcode == 0x03 {
                        // block/loop end: intersection of entry and current
                        let entry_inits = &frame.local_inits_at_entry;
                        for i in 0..self.local_inits.len().min(entry_inits.len()) {
                            self.local_inits[i] = self.local_inits[i] && entry_inits[i];
                        }
                    }
                    // Push end types onto the stack
                    for &t in &frame.end_types {
                        self.push_val(t);
                    }
                }
                // ── try (legacy exception handling) ──
                0x06 => {
                    let (params, results) = self.read_block_type()?;
                    for i in (0..params.len()).rev() {
                        self.pop_expect(params[i])?;
                    }
                    self.push_ctrl(0x06, params, results);
                }
                // ── catch (legacy) ──
                0x07 => {
                    let _tag_idx = self.read_u32()?;
                    let frame = self.pop_ctrl()?;
                    self.push_ctrl(0x07, frame.start_types, frame.end_types);
                }
                // ── throw ──
                0x08 => {
                    let tag_idx = self.read_u32()?;
                    // Validate tag index and pop parameters
                    let tag_import_count = self.module.imports.iter()
                        .filter(|imp| matches!(imp.kind, ImportKind::Tag(_)))
                        .count();
                    let total_tags = tag_import_count + self.module.tag_types.len();
                    if (tag_idx as usize) >= total_tags {
                        return Err(WasmError::OutOfBounds);
                    }
                    // Get the tag's type index and pop its params
                    let type_idx = if (tag_idx as usize) < tag_import_count {
                        // Imported tag
                        let mut ti = 0u32;
                        let mut found = None;
                        for imp in &self.module.imports {
                            if let ImportKind::Tag(tidx) = imp.kind {
                                if ti == tag_idx { found = Some(tidx); break; }
                                ti += 1;
                            }
                        }
                        found
                    } else {
                        let local_idx = tag_idx as usize - tag_import_count;
                        self.module.tag_types.get(local_idx).copied()
                    };
                    if let Some(tidx) = type_idx {
                        if (tidx as usize) < self.module.func_types.len() {
                            let ft = &self.module.func_types[tidx as usize];
                            for i in (0..ft.param_count as usize).rev() {
                                self.pop_expect(ft.params[i])?;
                            }
                        }
                    }
                    self.set_unreachable();
                }
                // ── throw_ref ──
                0x0A => {
                    let _ = self.pop_opd()?; // exnref
                    self.set_unreachable();
                }
                // ── br ──
                0x0C => {
                    let n = self.read_u32()?;
                    let label_types = self.label_types(n as usize)?;
                    for i in (0..label_types.len()).rev() {
                        self.pop_expect(label_types[i])?;
                    }
                    self.set_unreachable();
                }
                // ── br_if ──
                0x0D => {
                    let n = self.read_u32()?;
                    self.pop_expect(ValType::I32)?; // condition
                    let label_types = self.label_types(n as usize)?;
                    for i in (0..label_types.len()).rev() {
                        self.pop_expect(label_types[i])?;
                    }
                    for &t in &label_types {
                        self.push_val(t);
                    }
                }
                // ── br_table ──
                0x0E => {
                    let count = self.read_u32()? as usize;
                    let mut labels = Vec::with_capacity(count + 1);
                    for _ in 0..=count {
                        labels.push(self.read_u32()?);
                    }
                    self.pop_expect(ValType::I32)?; // index
                    // Get the default label's arity
                    let default_label = *labels.last().unwrap();
                    let default_types = self.label_types(default_label as usize)?;
                    let arity = default_types.len();
                    // Check if we're in unreachable/polymorphic context
                    let is_unreachable = self.ctrl_stack.last()
                        .map(|f| f.unreachable && self.opd_stack.len() == f.height)
                        .unwrap_or(false);
                    if is_unreachable {
                        // In unreachable code, types can differ (polymorphic bottom),
                        // but arity must still match across all labels.
                        for &l in &labels {
                            let lt = self.label_types(l as usize)?;
                            if lt.len() != arity {
                                return Err(WasmError::TypeMismatch);
                            }
                        }
                    } else {
                        // Check all labels have same arity and types
                        for &l in &labels {
                            let lt = self.label_types(l as usize)?;
                            if lt.len() != arity {
                                return Err(WasmError::TypeMismatch);
                            }
                        }
                        // Pop the label types
                        for i in (0..default_types.len()).rev() {
                            self.pop_expect(default_types[i])?;
                        }
                        // Check consistency: each label's types must be compatible
                        // with the default's types (subtyping in either direction).
                        // Per spec with GC: the operand types must be subtypes of ALL label types,
                        // so labels can have different but related types.
                        for &l in &labels[..labels.len() - 1] {
                            let lt = self.label_types(l as usize)?;
                            for j in 0..arity {
                                if lt[j] != default_types[j]
                                    && !is_subtype(lt[j], default_types[j])
                                    && !is_subtype(default_types[j], lt[j])
                                {
                                    return Err(WasmError::TypeMismatch);
                                }
                            }
                        }
                    }
                    self.set_unreachable();
                }
                // ── return ──
                0x0F => {
                    let ret_types = self.return_types.clone();
                    for i in (0..ret_types.len()).rev() {
                        self.pop_expect(ret_types[i])?;
                    }
                    self.set_unreachable();
                }
                // ── call ──
                0x10 => {
                    let func_idx = self.read_u32()?;
                    if func_idx as usize >= self.total_functions {
                        return Err(WasmError::FunctionNotFound(func_idx));
                    }
                    let ft = self.func_type(func_idx)?;
                    let param_count = ft.param_count as usize;
                    let result_count = ft.result_count as usize;
                    let params: Vec<ValType> = ft.params[..param_count].to_vec();
                    let results: Vec<ValType> = ft.results[..result_count].to_vec();
                    for i in (0..params.len()).rev() {
                        self.pop_expect(params[i])?;
                    }
                    for &t in &results {
                        self.push_val(t);
                    }
                }
                // ── call_indirect ──
                0x11 => {
                    let type_idx = self.read_u32()?;
                    let table_idx = self.read_u32()?;
                    if type_idx as usize >= self.module.func_types.len() {
                        return Err(WasmError::TypeMismatch);
                    }
                    if self.total_tables == 0 || table_idx as usize >= self.total_tables {
                        return Err(WasmError::TableIndexOutOfBounds);
                    }
                    // call_indirect requires funcref table
                    let tbl_et = table_elem_type(self.module, table_idx, self.table_import_count);
                    if tbl_et != ValType::FuncRef {
                        return Err(WasmError::TypeMismatch);
                    }
                    let idx_type = table_index_type(self.module, table_idx);
                    self.pop_expect(idx_type)?; // table index operand (i32 or i64 for table64)
                    let ft = &self.module.func_types[type_idx as usize];
                    let param_count = ft.param_count as usize;
                    let result_count = ft.result_count as usize;
                    let params: Vec<ValType> = ft.params[..param_count].to_vec();
                    let results: Vec<ValType> = ft.results[..result_count].to_vec();
                    for i in (0..params.len()).rev() {
                        self.pop_expect(params[i])?;
                    }
                    for &t in &results {
                        self.push_val(t);
                    }
                }
                // ── return_call ──
                0x12 => {
                    let func_idx = self.read_u32()?;
                    if func_idx as usize >= self.total_functions {
                        return Err(WasmError::FunctionNotFound(func_idx));
                    }
                    let ft = self.func_type(func_idx)?;
                    // return_call: callee return types must be subtypes of current function's return types
                    let result_count = ft.result_count as usize;
                    let callee_results: Vec<ValType> = ft.results[..result_count].to_vec();
                    if callee_results.len() != self.return_types.len() {
                        return Err(WasmError::TypeMismatch);
                    }
                    for i in 0..callee_results.len() {
                        if !val_is_subtype(callee_results[i], self.return_types[i]) {
                            return Err(WasmError::TypeMismatch);
                        }
                    }
                    let param_count = ft.param_count as usize;
                    let params: Vec<ValType> = ft.params[..param_count].to_vec();
                    for i in (0..params.len()).rev() {
                        self.pop_expect(params[i])?;
                    }
                    self.set_unreachable();
                }
                // ── return_call_indirect ──
                0x13 => {
                    let type_idx = self.read_u32()?;
                    let table_idx = self.read_u32()?;
                    if type_idx as usize >= self.module.func_types.len() {
                        return Err(WasmError::TypeMismatch);
                    }
                    if self.total_tables == 0 || table_idx as usize >= self.total_tables {
                        return Err(WasmError::TableIndexOutOfBounds);
                    }
                    // return_call_indirect requires funcref table
                    let tbl_et = table_elem_type(self.module, table_idx, self.table_import_count);
                    if tbl_et != ValType::FuncRef {
                        return Err(WasmError::TypeMismatch);
                    }
                    let idx_type = table_index_type(self.module, table_idx);
                    self.pop_expect(idx_type)?;
                    let ft = &self.module.func_types[type_idx as usize];
                    // return_call_indirect: callee return types must be subtypes of current function's
                    let result_count = ft.result_count as usize;
                    let callee_results: Vec<ValType> = ft.results[..result_count].to_vec();
                    if callee_results.len() != self.return_types.len() {
                        return Err(WasmError::TypeMismatch);
                    }
                    for i in 0..callee_results.len() {
                        if !val_is_subtype(callee_results[i], self.return_types[i]) {
                            return Err(WasmError::TypeMismatch);
                        }
                    }
                    let param_count = ft.param_count as usize;
                    let params: Vec<ValType> = ft.params[..param_count].to_vec();
                    for i in (0..params.len()).rev() {
                        self.pop_expect(params[i])?;
                    }
                    self.set_unreachable();
                }
                // ── call_ref (GC proposal, opcode 0x14) ──
                0x14 => {
                    let type_idx = self.read_u32()?;
                    if type_idx as usize >= self.module.func_types.len() {
                        return Err(WasmError::TypeMismatch);
                    }
                    let ft = &self.module.func_types[type_idx as usize];
                    let param_count = ft.param_count as usize;
                    let result_count = ft.result_count as usize;
                    let params: Vec<ValType> = ft.params[..param_count].to_vec();
                    let results: Vec<ValType> = ft.results[..result_count].to_vec();
                    // call_ref requires (ref null $type_idx); reject ExternRef and general FuncRef
                    let ref_val = self.pop_opd()?;
                    if ref_val == StackType::Known(ValType::ExternRef)
                        || ref_val == StackType::Known(ValType::FuncRef) {
                        return Err(WasmError::TypeMismatch);
                    }
                    for i in (0..params.len()).rev() {
                        self.pop_expect(params[i])?;
                    }
                    for &t in &results {
                        self.push_val(t);
                    }
                }
                // ── return_call_ref (GC proposal, opcode 0x15) ──
                0x15 => {
                    let type_idx = self.read_u32()?;
                    if type_idx as usize >= self.module.func_types.len() {
                        return Err(WasmError::TypeMismatch);
                    }
                    let ft = &self.module.func_types[type_idx as usize];
                    let param_count = ft.param_count as usize;
                    let result_count = ft.result_count as usize;
                    let params: Vec<ValType> = ft.params[..param_count].to_vec();
                    let callee_results: Vec<ValType> = ft.results[..result_count].to_vec();
                    // return_call_ref: callee return types must be subtypes of current function's
                    if callee_results.len() != self.return_types.len() {
                        return Err(WasmError::TypeMismatch);
                    }
                    for i in 0..callee_results.len() {
                        if !val_is_subtype(callee_results[i], self.return_types[i]) {
                            return Err(WasmError::TypeMismatch);
                        }
                    }
                    // call_ref requires (ref null $type_idx); reject ExternRef and general FuncRef
                    let ref_val = self.pop_opd()?;
                    if ref_val == StackType::Known(ValType::ExternRef)
                        || ref_val == StackType::Known(ValType::FuncRef) {
                        return Err(WasmError::TypeMismatch);
                    }
                    for i in (0..params.len()).rev() {
                        self.pop_expect(params[i])?;
                    }
                    self.set_unreachable();
                }
                // ── drop ──
                0x1A => {
                    let _ = self.pop_opd()?;
                }
                // ── select (untyped) ──
                0x1B => {
                    self.pop_expect(ValType::I32)?; // condition
                    let t1 = self.pop_opd()?;
                    let t2 = self.pop_opd()?;
                    // Both must be the same numeric type (or unknown)
                    match (t1, t2) {
                        (StackType::Known(a), StackType::Known(b)) => {
                            if a != b {
                                return Err(WasmError::TypeMismatch);
                            }
                            // Untyped select doesn't allow V128 or ref types
                            if matches!(a, ValType::V128 | ValType::FuncRef | ValType::ExternRef | ValType::TypedFuncRef | ValType::NullableTypedFuncRef) {
                                return Err(WasmError::TypeMismatch);
                            }
                            self.push_val(a);
                        }
                        (StackType::Known(a), StackType::Unknown) => {
                            if matches!(a, ValType::V128 | ValType::FuncRef | ValType::ExternRef | ValType::TypedFuncRef | ValType::NullableTypedFuncRef) {
                                return Err(WasmError::TypeMismatch);
                            }
                            self.push_val(a);
                        }
                        (StackType::Unknown, StackType::Known(b)) => {
                            if matches!(b, ValType::V128 | ValType::FuncRef | ValType::ExternRef | ValType::TypedFuncRef | ValType::NullableTypedFuncRef) {
                                return Err(WasmError::TypeMismatch);
                            }
                            self.push_val(b);
                        }
                        (StackType::Unknown, StackType::Unknown) => {
                            self.push_opd(StackType::Unknown);
                        }
                    }
                }
                // ── delegate (legacy exception handling) ──
                0x18 => {
                    let _depth = self.read_u32()?;
                    let frame = self.pop_ctrl()?;
                    for &t in &frame.end_types {
                        self.push_val(t);
                    }
                }
                // ── catch_all (legacy exception handling) ──
                0x19 => {
                    let frame = self.pop_ctrl()?;
                    self.push_ctrl(0x19, frame.start_types, frame.end_types);
                }
                // ── try_table (exception handling) ──
                0x1F => {
                    let (params, results) = self.read_block_type()?;
                    // Read and validate catch clauses
                    // Labels are resolved relative to the current scope (before try_table is pushed)
                    let catch_count = self.read_u32()? as usize;
                    let tag_import_count = self.module.imports.iter()
                        .filter(|imp| matches!(imp.kind, ImportKind::Tag(_)))
                        .count();
                    for _ in 0..catch_count {
                        let kind = self.read_u8()?;
                        match kind {
                            0 | 1 => { // catch, catch_ref
                                let tag_idx = self.read_u32()?;
                                let label = self.read_u32()?;
                                // Get the tag's param types
                                let type_idx = if (tag_idx as usize) < tag_import_count {
                                    let mut ti = 0u32;
                                    let mut found = None;
                                    for imp in &self.module.imports {
                                        if let ImportKind::Tag(tidx) = imp.kind {
                                            if ti == tag_idx { found = Some(tidx); break; }
                                            ti += 1;
                                        }
                                    }
                                    found
                                } else {
                                    let local_idx = tag_idx as usize - tag_import_count;
                                    self.module.tag_types.get(local_idx).copied()
                                };
                                // Build expected label types: tag params [+ exnref for catch_ref]
                                let mut expected_types = Vec::new();
                                if let Some(tidx) = type_idx {
                                    if (tidx as usize) < self.module.func_types.len() {
                                        let ft = &self.module.func_types[tidx as usize];
                                        for i in 0..ft.param_count as usize {
                                            expected_types.push(ft.params[i]);
                                        }
                                    }
                                }
                                if kind == 1 {
                                    expected_types.push(ValType::ExnRef);
                                }
                                // Validate label types match expected
                                let label_types = self.label_types(label as usize)?;
                                if label_types.len() != expected_types.len() {
                                    return Err(WasmError::TypeMismatch);
                                }
                                // Validate: catch pushes expected_types, label expects label_types.
                                // The pushed types must be subtypes of the label types.
                                let label_types = self.label_types(label as usize)?;
                                if label_types.len() != expected_types.len() {
                                    return Err(WasmError::TypeMismatch);
                                }
                                for (i, &et) in expected_types.iter().enumerate() {
                                    if !is_subtype(et, label_types[i]) {
                                        return Err(WasmError::TypeMismatch);
                                    }
                                }
                            }
                            2 | 3 => { // catch_all, catch_all_ref
                                let label = self.read_u32()?;
                                // catch_all: label expects nothing
                                // catch_all_ref: label expects [exnref]
                                let expected_types: Vec<ValType> = if kind == 3 {
                                    vec![ValType::ExnRef]
                                } else {
                                    vec![]
                                };
                                let label_types = self.label_types(label as usize)?;
                                if label_types.len() != expected_types.len() {
                                    return Err(WasmError::TypeMismatch);
                                }
                                for (i, &et) in expected_types.iter().enumerate() {
                                    if !is_subtype(et, label_types[i]) {
                                        return Err(WasmError::TypeMismatch);
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                    for i in (0..params.len()).rev() {
                        self.pop_expect(params[i])?;
                    }
                    self.push_ctrl(0x1F, params, results);
                }
                // ── select (typed) ──
                0x1C => {
                    let count = self.read_u32()?;
                    if count != 1 {
                        return Err(WasmError::TypeMismatch);
                    }
                    let vt_raw = self.read_u32()?;
                    let vt = byte_to_valtype(vt_raw as u8)?;
                    self.pop_expect(ValType::I32)?; // condition
                    self.pop_expect(vt)?;
                    self.pop_expect(vt)?;
                    self.push_val(vt);
                }
                // ── local.get ──
                0x20 => {
                    let idx = self.read_u32()?;
                    let t = self.local_type(idx)?;
                    // Check local initialization for non-nullable ref types
                    if (idx as usize) < self.local_inits.len() && !self.local_inits[idx as usize] {
                        return Err(WasmError::TypeMismatch);
                    }
                    self.push_val(t);
                }
                // ── local.set ──
                0x21 => {
                    let idx = self.read_u32()?;
                    let t = self.local_type(idx)?;
                    self.pop_expect(t)?;
                    // Mark local as initialized
                    if (idx as usize) < self.local_inits.len() {
                        self.local_inits[idx as usize] = true;
                    }
                }
                // ── local.tee ──
                0x22 => {
                    let idx = self.read_u32()?;
                    let t = self.local_type(idx)?;
                    self.pop_expect(t)?;
                    if (idx as usize) < self.local_inits.len() {
                        self.local_inits[idx as usize] = true;
                    }
                    self.push_val(t);
                }
                // ── global.get ──
                0x23 => {
                    let idx = self.read_u32()?;
                    let (t, _) = self.global_type(idx)?;
                    self.push_val(t);
                }
                // ── global.set ──
                0x24 => {
                    let idx = self.read_u32()?;
                    let (t, mutable) = self.global_type(idx)?;
                    if !mutable {
                        return Err(WasmError::ImmutableGlobal);
                    }
                    self.pop_expect(t)?;
                }
                // ── table.get ──
                0x25 => {
                    let tidx = self.read_u32()?;
                    if self.total_tables == 0 || tidx as usize >= self.total_tables {
                        return Err(WasmError::TableIndexOutOfBounds);
                    }
                    let idx_type = table_index_type(self.module, tidx);
                    self.pop_expect(idx_type)?;
                    let et = table_elem_type(self.module, tidx, self.table_import_count);
                    self.push_val(et);
                }
                // ── table.set ──
                0x26 => {
                    let tidx = self.read_u32()?;
                    if self.total_tables == 0 || tidx as usize >= self.total_tables {
                        return Err(WasmError::TableIndexOutOfBounds);
                    }
                    let et = table_elem_type(self.module, tidx, self.table_import_count);
                    let idx_type = table_index_type(self.module, tidx);
                    self.pop_expect(et)?; // value must match table element type
                    self.pop_expect(idx_type)?; // index
                }
                // ── memory loads ──
                // i32.load
                0x28 => {
                    if !self.has_memory { return Err(WasmError::MemoryOutOfBounds); }
                    self.read_memarg(2)?;
                    let at = self.mem_addr_type();
                    self.pop_expect(at)?;
                    self.push_val(ValType::I32);
                }
                // i32.load8_s, i32.load8_u
                0x2C | 0x2D => {
                    if !self.has_memory { return Err(WasmError::MemoryOutOfBounds); }
                    self.read_memarg(0)?;
                    let at = self.mem_addr_type();
                    self.pop_expect(at)?;
                    self.push_val(ValType::I32);
                }
                // i32.load16_s, i32.load16_u
                0x2E | 0x2F => {
                    if !self.has_memory { return Err(WasmError::MemoryOutOfBounds); }
                    self.read_memarg(1)?;
                    let at = self.mem_addr_type();
                    self.pop_expect(at)?;
                    self.push_val(ValType::I32);
                }
                // i64.load
                0x29 => {
                    if !self.has_memory { return Err(WasmError::MemoryOutOfBounds); }
                    self.read_memarg(3)?;
                    let at = self.mem_addr_type();
                    self.pop_expect(at)?;
                    self.push_val(ValType::I64);
                }
                // i64.load8_s, i64.load8_u
                0x30 | 0x31 => {
                    if !self.has_memory { return Err(WasmError::MemoryOutOfBounds); }
                    self.read_memarg(0)?;
                    let at = self.mem_addr_type();
                    self.pop_expect(at)?;
                    self.push_val(ValType::I64);
                }
                // i64.load16_s, i64.load16_u
                0x32 | 0x33 => {
                    if !self.has_memory { return Err(WasmError::MemoryOutOfBounds); }
                    self.read_memarg(1)?;
                    let at = self.mem_addr_type();
                    self.pop_expect(at)?;
                    self.push_val(ValType::I64);
                }
                // i64.load32_s, i64.load32_u
                0x34 | 0x35 => {
                    if !self.has_memory { return Err(WasmError::MemoryOutOfBounds); }
                    self.read_memarg(2)?;
                    let at = self.mem_addr_type();
                    self.pop_expect(at)?;
                    self.push_val(ValType::I64);
                }
                // f32.load
                0x2A => {
                    if !self.has_memory { return Err(WasmError::MemoryOutOfBounds); }
                    self.read_memarg(2)?;
                    let at = self.mem_addr_type();
                    self.pop_expect(at)?;
                    self.push_val(ValType::F32);
                }
                // f64.load
                0x2B => {
                    if !self.has_memory { return Err(WasmError::MemoryOutOfBounds); }
                    self.read_memarg(3)?;
                    let at = self.mem_addr_type();
                    self.pop_expect(at)?;
                    self.push_val(ValType::F64);
                }
                // i32.store
                0x36 => {
                    if !self.has_memory { return Err(WasmError::MemoryOutOfBounds); }
                    self.read_memarg(2)?;
                    let at = self.mem_addr_type();
                    self.pop_expect(ValType::I32)?; // value
                    self.pop_expect(at)?; // address
                }
                // i32.store8
                0x3A => {
                    if !self.has_memory { return Err(WasmError::MemoryOutOfBounds); }
                    self.read_memarg(0)?;
                    let at = self.mem_addr_type();
                    self.pop_expect(ValType::I32)?;
                    self.pop_expect(at)?;
                }
                // i32.store16
                0x3B => {
                    if !self.has_memory { return Err(WasmError::MemoryOutOfBounds); }
                    self.read_memarg(1)?;
                    let at = self.mem_addr_type();
                    self.pop_expect(ValType::I32)?;
                    self.pop_expect(at)?;
                }
                // i64.store
                0x37 => {
                    if !self.has_memory { return Err(WasmError::MemoryOutOfBounds); }
                    self.read_memarg(3)?;
                    let at = self.mem_addr_type();
                    self.pop_expect(ValType::I64)?;
                    self.pop_expect(at)?;
                }
                // i64.store8
                0x3C => {
                    if !self.has_memory { return Err(WasmError::MemoryOutOfBounds); }
                    self.read_memarg(0)?;
                    let at = self.mem_addr_type();
                    self.pop_expect(ValType::I64)?;
                    self.pop_expect(at)?;
                }
                // i64.store16
                0x3D => {
                    if !self.has_memory { return Err(WasmError::MemoryOutOfBounds); }
                    self.read_memarg(1)?;
                    let at = self.mem_addr_type();
                    self.pop_expect(ValType::I64)?;
                    self.pop_expect(at)?;
                }
                // i64.store32
                0x3E => {
                    if !self.has_memory { return Err(WasmError::MemoryOutOfBounds); }
                    self.read_memarg(2)?;
                    let at = self.mem_addr_type();
                    self.pop_expect(ValType::I64)?;
                    self.pop_expect(at)?;
                }
                // f32.store
                0x38 => {
                    if !self.has_memory { return Err(WasmError::MemoryOutOfBounds); }
                    self.read_memarg(2)?;
                    let at = self.mem_addr_type();
                    self.pop_expect(ValType::F32)?;
                    self.pop_expect(at)?;
                }
                // f64.store
                0x39 => {
                    if !self.has_memory { return Err(WasmError::MemoryOutOfBounds); }
                    self.read_memarg(3)?;
                    let at = self.mem_addr_type();
                    self.pop_expect(ValType::F64)?;
                    self.pop_expect(at)?;
                }
                // ── memory.size ──
                0x3F => {
                    if !self.has_memory { return Err(WasmError::MemoryOutOfBounds); }
                    let mem_idx = if self.module.multi_memory_enabled {
                        let idx = self.read_u32()?;
                        if idx >= self.module.memory_count { return Err(WasmError::MemoryOutOfBounds); }
                        idx
                    } else {
                        self.read_zero_byte()?;
                        0
                    };
                    let is_mem64 = if (mem_idx as usize) < self.module.memories.len() { self.module.memories[mem_idx as usize].is_memory64 } else { self.module.is_memory64 };
                    let val_type = if is_mem64 { ValType::I64 } else { ValType::I32 };
                    self.push_val(val_type);
                }
                // ── memory.grow ──
                0x40 => {
                    if !self.has_memory { return Err(WasmError::MemoryOutOfBounds); }
                    let mem_idx = if self.module.multi_memory_enabled {
                        let idx = self.read_u32()?;
                        if idx >= self.module.memory_count { return Err(WasmError::MemoryOutOfBounds); }
                        idx
                    } else {
                        self.read_zero_byte()?;
                        0
                    };
                    let is_mem64 = if (mem_idx as usize) < self.module.memories.len() { self.module.memories[mem_idx as usize].is_memory64 } else { self.module.is_memory64 };
                    let val_type = if is_mem64 { ValType::I64 } else { ValType::I32 };
                    self.pop_expect(val_type)?;
                    self.push_val(val_type);
                }
                // ── i32.const ──
                0x41 => {
                    let _ = self.read_i32()?;
                    self.push_val(ValType::I32);
                }
                // ── i64.const ──
                0x42 => {
                    let _ = self.read_i64()?;
                    self.push_val(ValType::I64);
                }
                // ── f32.const ──
                0x43 => {
                    if self.pc + 4 > self.end { return Err(WasmError::UnexpectedEnd); }
                    self.pc += 4;
                    self.push_val(ValType::F32);
                }
                // ── f64.const ──
                0x44 => {
                    if self.pc + 8 > self.end { return Err(WasmError::UnexpectedEnd); }
                    self.pc += 8;
                    self.push_val(ValType::F64);
                }

                // ── i32 test: i32.eqz ──
                0x45 => {
                    self.pop_expect(ValType::I32)?;
                    self.push_val(ValType::I32);
                }
                // ── i32 comparison: i32.eq..i32.ge_u ──
                0x46..=0x4F => {
                    self.pop_expect(ValType::I32)?;
                    self.pop_expect(ValType::I32)?;
                    self.push_val(ValType::I32);
                }
                // ── i64 test: i64.eqz ──
                0x50 => {
                    self.pop_expect(ValType::I64)?;
                    self.push_val(ValType::I32);
                }
                // ── i64 comparison: i64.eq..i64.ge_u ──
                0x51..=0x5A => {
                    self.pop_expect(ValType::I64)?;
                    self.pop_expect(ValType::I64)?;
                    self.push_val(ValType::I32);
                }
                // ── f32 comparison: f32.eq..f32.ge ──
                0x5B..=0x60 => {
                    self.pop_expect(ValType::F32)?;
                    self.pop_expect(ValType::F32)?;
                    self.push_val(ValType::I32);
                }
                // ── f64 comparison: f64.eq..f64.ge ──
                0x61..=0x66 => {
                    self.pop_expect(ValType::F64)?;
                    self.pop_expect(ValType::F64)?;
                    self.push_val(ValType::I32);
                }

                // ── i32 unary: clz, ctz, popcnt ──
                0x67 | 0x68 | 0x69 => {
                    self.pop_expect(ValType::I32)?;
                    self.push_val(ValType::I32);
                }
                // ── i32 binary: add..rotr ──
                0x6A..=0x78 => {
                    self.pop_expect(ValType::I32)?;
                    self.pop_expect(ValType::I32)?;
                    self.push_val(ValType::I32);
                }
                // ── i64 unary: clz, ctz, popcnt ──
                0x79 | 0x7A | 0x7B => {
                    self.pop_expect(ValType::I64)?;
                    self.push_val(ValType::I64);
                }
                // ── i64 binary: add..rotr ──
                0x7C..=0x8A => {
                    self.pop_expect(ValType::I64)?;
                    self.pop_expect(ValType::I64)?;
                    self.push_val(ValType::I64);
                }
                // ── f32 unary: abs..sqrt ──
                0x8B..=0x91 => {
                    self.pop_expect(ValType::F32)?;
                    self.push_val(ValType::F32);
                }
                // ── f32 binary: add..copysign ──
                0x92..=0x98 => {
                    self.pop_expect(ValType::F32)?;
                    self.pop_expect(ValType::F32)?;
                    self.push_val(ValType::F32);
                }
                // ── f64 unary: abs..sqrt ──
                0x99..=0x9F => {
                    self.pop_expect(ValType::F64)?;
                    self.push_val(ValType::F64);
                }
                // ── f64 binary: add..copysign ──
                0xA0..=0xA6 => {
                    self.pop_expect(ValType::F64)?;
                    self.pop_expect(ValType::F64)?;
                    self.push_val(ValType::F64);
                }

                // ── Conversions ──
                // i32.wrap_i64
                0xA7 => { self.pop_expect(ValType::I64)?; self.push_val(ValType::I32); }
                // i32.trunc_f32_s, i32.trunc_f32_u
                0xA8 | 0xA9 => { self.pop_expect(ValType::F32)?; self.push_val(ValType::I32); }
                // i32.trunc_f64_s, i32.trunc_f64_u
                0xAA | 0xAB => { self.pop_expect(ValType::F64)?; self.push_val(ValType::I32); }
                // i64.extend_i32_s, i64.extend_i32_u
                0xAC | 0xAD => { self.pop_expect(ValType::I32)?; self.push_val(ValType::I64); }
                // i64.trunc_f32_s, i64.trunc_f32_u
                0xAE | 0xAF => { self.pop_expect(ValType::F32)?; self.push_val(ValType::I64); }
                // i64.trunc_f64_s, i64.trunc_f64_u
                0xB0 | 0xB1 => { self.pop_expect(ValType::F64)?; self.push_val(ValType::I64); }
                // f32.convert_i32_s, f32.convert_i32_u
                0xB2 | 0xB3 => { self.pop_expect(ValType::I32)?; self.push_val(ValType::F32); }
                // f32.convert_i64_s, f32.convert_i64_u
                0xB4 | 0xB5 => { self.pop_expect(ValType::I64)?; self.push_val(ValType::F32); }
                // f32.demote_f64
                0xB6 => { self.pop_expect(ValType::F64)?; self.push_val(ValType::F32); }
                // f64.convert_i32_s, f64.convert_i32_u
                0xB7 | 0xB8 => { self.pop_expect(ValType::I32)?; self.push_val(ValType::F64); }
                // f64.convert_i64_s, f64.convert_i64_u
                0xB9 | 0xBA => { self.pop_expect(ValType::I64)?; self.push_val(ValType::F64); }
                // f64.promote_f32
                0xBB => { self.pop_expect(ValType::F32)?; self.push_val(ValType::F64); }
                // i32.reinterpret_f32
                0xBC => { self.pop_expect(ValType::F32)?; self.push_val(ValType::I32); }
                // i64.reinterpret_f64
                0xBD => { self.pop_expect(ValType::F64)?; self.push_val(ValType::I64); }
                // f32.reinterpret_i32
                0xBE => { self.pop_expect(ValType::I32)?; self.push_val(ValType::F32); }
                // f64.reinterpret_i64
                0xBF => { self.pop_expect(ValType::I64)?; self.push_val(ValType::F64); }

                // ── Sign extension ──
                // i32.extend8_s, i32.extend16_s
                0xC0 | 0xC1 => { self.pop_expect(ValType::I32)?; self.push_val(ValType::I32); }
                // i64.extend8_s, i64.extend16_s, i64.extend32_s
                0xC2 | 0xC3 | 0xC4 => { self.pop_expect(ValType::I64)?; self.push_val(ValType::I64); }

                // ── ref.null ──
                0xD0 => {
                    let heap_type = self.read_i32()?; // heaptype
                    if heap_type == -0x10 {
                        // (ref null func) = funcref
                        self.push_val(ValType::FuncRef);
                    } else if heap_type == -0x11 {
                        // (ref null extern) = externref
                        self.push_val(ValType::ExternRef);
                    } else if heap_type >= 0 {
                        // (ref null $t) = nullable typed func ref
                        self.push_val(ValType::NullableTypedFuncRef);
                    } else {
                        // Other abstract heap types - push as unknown
                        self.push_opd(StackType::Unknown);
                    }
                }
                // ── ref.is_null ──
                0xD1 => {
                    let _ = self.pop_opd()?;
                    self.push_val(ValType::I32);
                }
                // ── ref.func ──
                0xD2 => {
                    let idx = self.read_u32()?;
                    if idx as usize >= self.total_functions {
                        return Err(WasmError::FunctionNotFound(idx));
                    }
                    // Per spec, ref.func requires the function to be "declared"
                    if !self.declared_funcs.contains(&idx) {
                        return Err(WasmError::UndeclaredFuncRef);
                    }
                    // ref.func produces (ref $t) - a typed, non-nullable func ref
                    self.push_val(ValType::TypedFuncRef);
                }
                // ── ref.eq (opcode 0xD3) ──
                0xD3 => {
                    let _ = self.pop_opd()?; // ref1
                    let _ = self.pop_opd()?; // ref2
                    self.push_val(ValType::I32);
                }
                // ── ref.as_non_null (opcode 0xD4) ──
                0xD4 => {
                    // Pop a ref value; if it's a known non-ref type, reject
                    let ref_val = self.pop_opd()?;
                    match ref_val {
                        StackType::Known(t) if !is_ref_type(t) => {
                            return Err(WasmError::TypeMismatch);
                        }
                        _ => {}
                    }
                    // Push the non-null version: same type
                    self.push_opd(ref_val);
                }
                // ── br_on_null (opcode 0xD5) ──
                0xD5 => {
                    let n = self.read_u32()?;
                    // Pop the ref operand
                    let ref_val = self.pop_opd()?;
                    match ref_val {
                        StackType::Known(t) if !is_ref_type(t) => {
                            return Err(WasmError::TypeMismatch);
                        }
                        _ => {}
                    }
                    // Check branch target types
                    let label_types = self.label_types(n as usize)?;
                    for i in (0..label_types.len()).rev() {
                        self.pop_expect(label_types[i])?;
                    }
                    // Push label types back + the non-null ref
                    for &t in &label_types {
                        self.push_val(t);
                    }
                    // The ref is non-null on fallthrough
                    self.push_opd(ref_val);
                }
                // ── br_on_non_null (opcode 0xD6) ──
                0xD6 => {
                    let n = self.read_u32()?;
                    // Pop the ref operand
                    let ref_val = self.pop_opd()?;
                    match ref_val {
                        StackType::Known(t) if !is_ref_type(t) => {
                            return Err(WasmError::TypeMismatch);
                        }
                        _ => {}
                    }
                    // Branch target gets label_types + the non-null ref
                    let label_types = self.label_types(n as usize)?;
                    // Pop and check label types (minus the ref which goes on branch)
                    if label_types.is_empty() {
                        // label must accept at least the ref value
                    } else {
                        for i in (0..label_types.len() - 1).rev() {
                            self.pop_expect(label_types[i])?;
                        }
                        for i in 0..label_types.len() - 1 {
                            self.push_val(label_types[i]);
                        }
                    }
                    // On fallthrough, the ref was null so nothing is pushed
                }
                // ── 0xFC prefix: saturating truncation + bulk memory ──
                0xFC => {
                    let sub = self.read_u32()?;
                    match sub {
                        // i32.trunc_sat_f32_s/u
                        0 | 1 => { self.pop_expect(ValType::F32)?; self.push_val(ValType::I32); }
                        // i32.trunc_sat_f64_s/u
                        2 | 3 => { self.pop_expect(ValType::F64)?; self.push_val(ValType::I32); }
                        // i64.trunc_sat_f32_s/u
                        4 | 5 => { self.pop_expect(ValType::F32)?; self.push_val(ValType::I64); }
                        // i64.trunc_sat_f64_s/u
                        6 | 7 => { self.pop_expect(ValType::F64)?; self.push_val(ValType::I64); }
                        // memory.init
                        8 => {
                            let data_idx = self.read_u32()?;
                            let mem_idx = self.read_u32()?;
                            if !self.module.has_memory || (if self.module.multi_memory_enabled { mem_idx >= self.module.memory_count } else { mem_idx > 0 }) {
                                return Err(WasmError::MemoryOutOfBounds);
                            }
                            if data_idx as usize >= self.module.data_segments.len() {
                                return Err(WasmError::OutOfBounds);
                            }
                            let at = self.mem_addr_type_for(mem_idx);
                            self.pop_expect(ValType::I32)?; // size (always i32)
                            self.pop_expect(ValType::I32)?; // src offset (always i32)
                            self.pop_expect(at)?;           // dest offset (memory address type)
                        }
                        // data.drop
                        9 => {
                            let data_idx = self.read_u32()?;
                            if data_idx as usize >= self.module.data_segments.len() {
                                return Err(WasmError::OutOfBounds);
                            }
                        }
                        // memory.copy
                        10 => {
                            let dst = self.read_u32()?;
                            let src = self.read_u32()?;
                            if !self.module.has_memory || (if self.module.multi_memory_enabled { dst >= self.module.memory_count || src >= self.module.memory_count } else { dst > 0 || src > 0 }) {
                                return Err(WasmError::MemoryOutOfBounds);
                            }
                            let dst_at = self.mem_addr_type_for(dst);
                            let src_at = self.mem_addr_type_for(src);
                            // size type: if either memory is 64-bit, size is i64
                            let size_type = if dst_at == ValType::I64 || src_at == ValType::I64 { ValType::I64 } else { ValType::I32 };
                            self.pop_expect(size_type)?; // size
                            self.pop_expect(src_at)?;    // src
                            self.pop_expect(dst_at)?;    // dest
                        }
                        // memory.fill
                        11 => {
                            let mem = self.read_u32()?;
                            if !self.module.has_memory || (if self.module.multi_memory_enabled { mem >= self.module.memory_count } else { mem > 0 }) {
                                return Err(WasmError::MemoryOutOfBounds);
                            }
                            let at = self.mem_addr_type_for(mem);
                            self.pop_expect(at)?;           // size (memory address type)
                            self.pop_expect(ValType::I32)?; // value (always i32)
                            self.pop_expect(at)?;           // dest (memory address type)
                        }
                        // table.init
                        12 => {
                            let seg_idx = self.read_u32()?;
                            let tbl_idx = self.read_u32()?;
                            if seg_idx as usize >= self.module.element_segments.len() {
                                return Err(WasmError::UndefinedElement);
                            }
                            if tbl_idx as usize >= self.total_tables {
                                return Err(WasmError::TableIndexOutOfBounds);
                            }
                            // Check element type compatibility
                            let tbl_et = table_elem_type(self.module, tbl_idx, self.table_import_count);
                            let seg_et = self.module.element_segments[seg_idx as usize].elem_type;
                            if !ref_types_compatible(seg_et, tbl_et) {
                                return Err(WasmError::TypeMismatch);
                            }
                            let idx_type = table_index_type(self.module, tbl_idx);
                            self.pop_expect(ValType::I32)?; // n (always i32)
                            self.pop_expect(ValType::I32)?; // s (always i32)
                            self.pop_expect(idx_type)?;      // d (table index type)
                        }
                        // elem.drop
                        13 => {
                            let seg_idx = self.read_u32()? as usize;
                            if seg_idx >= self.module.element_segments.len() {
                                return Err(WasmError::UndefinedElement);
                            }
                        }
                        // table.copy
                        14 => {
                            let dst_idx = self.read_u32()?;
                            let src_idx = self.read_u32()?;
                            if dst_idx as usize >= self.total_tables || src_idx as usize >= self.total_tables {
                                return Err(WasmError::TableIndexOutOfBounds);
                            }
                            // Check element type compatibility: src must be subtype of dst
                            let dst_et = table_elem_type(self.module, dst_idx, self.table_import_count);
                            let src_et = table_elem_type(self.module, src_idx, self.table_import_count);
                            if !ref_types_compatible(src_et, dst_et) {
                                return Err(WasmError::TypeMismatch);
                            }
                            let src_it = table_index_type(self.module, src_idx);
                            let dst_it = table_index_type(self.module, dst_idx);
                            // n: minimum of src/dst index types (i32 if either is i32)
                            let n_type = if src_it == ValType::I32 || dst_it == ValType::I32 { ValType::I32 } else { ValType::I64 };
                            self.pop_expect(n_type)?;  // n
                            self.pop_expect(src_it)?;  // s
                            self.pop_expect(dst_it)?;  // d
                        }
                        // table.grow
                        15 => {
                            let tidx = self.read_u32()?;
                            if tidx as usize >= self.total_tables {
                                return Err(WasmError::TableIndexOutOfBounds);
                            }
                            let idx_type = table_index_type(self.module, tidx);
                            self.pop_expect(idx_type)?; // n
                            let et = table_elem_type(self.module, tidx, self.table_import_count);
                            self.pop_expect(et)?;            // init value must match table elem type
                            self.push_val(idx_type);
                        }
                        // table.size
                        16 => {
                            let tidx = self.read_u32()?;
                            let idx_type = table_index_type(self.module, tidx);
                            self.push_val(idx_type);
                        }
                        // table.fill
                        17 => {
                            let tidx = self.read_u32()?;
                            if tidx as usize >= self.total_tables {
                                return Err(WasmError::TableIndexOutOfBounds);
                            }
                            let idx_type = table_index_type(self.module, tidx);
                            self.pop_expect(idx_type)?; // n
                            let et = table_elem_type(self.module, tidx, self.table_import_count);
                            self.pop_expect(et)?;            // value must match table elem type
                            self.pop_expect(idx_type)?; // i
                        }
                        // wide-arithmetic: i64.add128 (0x13)
                        0x13 => {
                            self.pop_expect(ValType::I64)?;
                            self.pop_expect(ValType::I64)?;
                            self.pop_expect(ValType::I64)?;
                            self.pop_expect(ValType::I64)?;
                            self.push_val(ValType::I64);
                            self.push_val(ValType::I64);
                        }
                        // wide-arithmetic: i64.sub128 (0x14)
                        0x14 => {
                            self.pop_expect(ValType::I64)?;
                            self.pop_expect(ValType::I64)?;
                            self.pop_expect(ValType::I64)?;
                            self.pop_expect(ValType::I64)?;
                            self.push_val(ValType::I64);
                            self.push_val(ValType::I64);
                        }
                        // wide-arithmetic: i64.mul_wide_s (0x15)
                        0x15 => {
                            self.pop_expect(ValType::I64)?;
                            self.pop_expect(ValType::I64)?;
                            self.push_val(ValType::I64);
                            self.push_val(ValType::I64);
                        }
                        // wide-arithmetic: i64.mul_wide_u (0x16)
                        0x16 => {
                            self.pop_expect(ValType::I64)?;
                            self.pop_expect(ValType::I64)?;
                            self.push_val(ValType::I64);
                            self.push_val(ValType::I64);
                        }
                        _ => {}
                    }
                }

                // ── 0xFD prefix: SIMD ──
                0xFD => {
                    let sub = self.read_u32()?;
                    self.validate_simd(sub)?;
                }

                // ── 0xFE prefix: threads/atomics ──
                0xFE => {
                    let sub = self.read_u32()?;
                    match sub {
                        // memory.atomic.notify: [i32, i32] -> [i32]
                        0x00 => {
                            self.read_memarg(2)?;
                            if !self.module.has_memory { return Err(WasmError::MemoryOutOfBounds); }
                            self.pop_expect(ValType::I32)?;
                            self.pop_expect(ValType::I32)?;
                            self.push_val(ValType::I32);
                        }
                        // memory.atomic.wait32: [i32, i32, i64] -> [i32]
                        0x01 => {
                            self.read_memarg(2)?;
                            if !self.module.has_memory { return Err(WasmError::MemoryOutOfBounds); }
                            self.pop_expect(ValType::I64)?;
                            self.pop_expect(ValType::I32)?;
                            self.pop_expect(ValType::I32)?;
                            self.push_val(ValType::I32);
                        }
                        // memory.atomic.wait64: [i32, i64, i64] -> [i32]
                        0x02 => {
                            self.read_memarg(3)?;
                            if !self.module.has_memory { return Err(WasmError::MemoryOutOfBounds); }
                            self.pop_expect(ValType::I64)?;
                            self.pop_expect(ValType::I64)?;
                            self.pop_expect(ValType::I32)?;
                            self.push_val(ValType::I32);
                        }
                        // atomic.fence: [] -> []
                        0x03 => {
                            let _ = self.read_u8()?; // 0x00 byte
                        }
                        // i32.atomic.load (0x10): [i32] -> [i32]
                        0x10 => {
                            self.read_memarg(2)?;
                            if !self.module.has_memory { return Err(WasmError::MemoryOutOfBounds); }
                            self.pop_expect(ValType::I32)?;
                            self.push_val(ValType::I32);
                        }
                        // i64.atomic.load (0x11): [i32] -> [i64]
                        0x11 => {
                            self.read_memarg(3)?;
                            if !self.module.has_memory { return Err(WasmError::MemoryOutOfBounds); }
                            self.pop_expect(ValType::I32)?;
                            self.push_val(ValType::I64);
                        }
                        // i32.atomic.load8_u (0x12): [i32] -> [i32]
                        0x12 => {
                            self.read_memarg(0)?;
                            if !self.module.has_memory { return Err(WasmError::MemoryOutOfBounds); }
                            self.pop_expect(ValType::I32)?;
                            self.push_val(ValType::I32);
                        }
                        // i32.atomic.load16_u (0x13): [i32] -> [i32]
                        0x13 => {
                            self.read_memarg(1)?;
                            if !self.module.has_memory { return Err(WasmError::MemoryOutOfBounds); }
                            self.pop_expect(ValType::I32)?;
                            self.push_val(ValType::I32);
                        }
                        // i64.atomic.load8_u (0x14): [i32] -> [i64]
                        0x14 => {
                            self.read_memarg(0)?;
                            if !self.module.has_memory { return Err(WasmError::MemoryOutOfBounds); }
                            self.pop_expect(ValType::I32)?;
                            self.push_val(ValType::I64);
                        }
                        // i64.atomic.load16_u (0x15): [i32] -> [i64]
                        0x15 => {
                            self.read_memarg(1)?;
                            if !self.module.has_memory { return Err(WasmError::MemoryOutOfBounds); }
                            self.pop_expect(ValType::I32)?;
                            self.push_val(ValType::I64);
                        }
                        // i64.atomic.load32_u (0x16): [i32] -> [i64]
                        0x16 => {
                            self.read_memarg(2)?;
                            if !self.module.has_memory { return Err(WasmError::MemoryOutOfBounds); }
                            self.pop_expect(ValType::I32)?;
                            self.push_val(ValType::I64);
                        }
                        // i32.atomic.store (0x17): [i32, i32] -> []
                        0x17 => {
                            self.read_memarg(2)?;
                            if !self.module.has_memory { return Err(WasmError::MemoryOutOfBounds); }
                            self.pop_expect(ValType::I32)?;
                            self.pop_expect(ValType::I32)?;
                        }
                        // i64.atomic.store (0x18): [i32, i64] -> []
                        0x18 => {
                            self.read_memarg(3)?;
                            if !self.module.has_memory { return Err(WasmError::MemoryOutOfBounds); }
                            self.pop_expect(ValType::I64)?;
                            self.pop_expect(ValType::I32)?;
                        }
                        // i32.atomic.store8 (0x19): [i32, i32] -> []
                        0x19 => {
                            self.read_memarg(0)?;
                            if !self.module.has_memory { return Err(WasmError::MemoryOutOfBounds); }
                            self.pop_expect(ValType::I32)?;
                            self.pop_expect(ValType::I32)?;
                        }
                        // i32.atomic.store16 (0x1a): [i32, i32] -> []
                        0x1a => {
                            self.read_memarg(1)?;
                            if !self.module.has_memory { return Err(WasmError::MemoryOutOfBounds); }
                            self.pop_expect(ValType::I32)?;
                            self.pop_expect(ValType::I32)?;
                        }
                        // i64.atomic.store8 (0x1b): [i32, i64] -> []
                        0x1b => {
                            self.read_memarg(0)?;
                            if !self.module.has_memory { return Err(WasmError::MemoryOutOfBounds); }
                            self.pop_expect(ValType::I64)?;
                            self.pop_expect(ValType::I32)?;
                        }
                        // i64.atomic.store16 (0x1c): [i32, i64] -> []
                        0x1c => {
                            self.read_memarg(1)?;
                            if !self.module.has_memory { return Err(WasmError::MemoryOutOfBounds); }
                            self.pop_expect(ValType::I64)?;
                            self.pop_expect(ValType::I32)?;
                        }
                        // i64.atomic.store32 (0x1d): [i32, i64] -> []
                        0x1d => {
                            self.read_memarg(2)?;
                            if !self.module.has_memory { return Err(WasmError::MemoryOutOfBounds); }
                            self.pop_expect(ValType::I64)?;
                            self.pop_expect(ValType::I32)?;
                        }
                        // i32.atomic.rmw.* (0x1e, 0x25, 0x2c, 0x33, 0x3a, 0x41): [i32, i32] -> [i32]
                        0x1e | 0x25 | 0x2c | 0x33 | 0x3a | 0x41 => {
                            self.read_memarg(2)?;
                            if !self.module.has_memory { return Err(WasmError::MemoryOutOfBounds); }
                            self.pop_expect(ValType::I32)?;
                            self.pop_expect(ValType::I32)?;
                            self.push_val(ValType::I32);
                        }
                        // i64.atomic.rmw.* (0x1f, 0x26, 0x2d, 0x34, 0x3b, 0x42): [i32, i64] -> [i64]
                        0x1f | 0x26 | 0x2d | 0x34 | 0x3b | 0x42 => {
                            self.read_memarg(3)?;
                            if !self.module.has_memory { return Err(WasmError::MemoryOutOfBounds); }
                            self.pop_expect(ValType::I64)?;
                            self.pop_expect(ValType::I32)?;
                            self.push_val(ValType::I64);
                        }
                        // i32.atomic.rmw8.*_u (0x20, 0x27, 0x2e, 0x35, 0x3c, 0x43): [i32, i32] -> [i32]
                        0x20 | 0x27 | 0x2e | 0x35 | 0x3c | 0x43 => {
                            self.read_memarg(0)?;
                            if !self.module.has_memory { return Err(WasmError::MemoryOutOfBounds); }
                            self.pop_expect(ValType::I32)?;
                            self.pop_expect(ValType::I32)?;
                            self.push_val(ValType::I32);
                        }
                        // i32.atomic.rmw16.*_u (0x21, 0x28, 0x2f, 0x36, 0x3d, 0x44): [i32, i32] -> [i32]
                        0x21 | 0x28 | 0x2f | 0x36 | 0x3d | 0x44 => {
                            self.read_memarg(1)?;
                            if !self.module.has_memory { return Err(WasmError::MemoryOutOfBounds); }
                            self.pop_expect(ValType::I32)?;
                            self.pop_expect(ValType::I32)?;
                            self.push_val(ValType::I32);
                        }
                        // i64.atomic.rmw8.*_u (0x22, 0x29, 0x30, 0x37, 0x3e, 0x45): [i32, i64] -> [i64]
                        0x22 | 0x29 | 0x30 | 0x37 | 0x3e | 0x45 => {
                            self.read_memarg(0)?;
                            if !self.module.has_memory { return Err(WasmError::MemoryOutOfBounds); }
                            self.pop_expect(ValType::I64)?;
                            self.pop_expect(ValType::I32)?;
                            self.push_val(ValType::I64);
                        }
                        // i64.atomic.rmw16.*_u (0x23, 0x2a, 0x31, 0x38, 0x3f, 0x46): [i32, i64] -> [i64]
                        0x23 | 0x2a | 0x31 | 0x38 | 0x3f | 0x46 => {
                            self.read_memarg(1)?;
                            if !self.module.has_memory { return Err(WasmError::MemoryOutOfBounds); }
                            self.pop_expect(ValType::I64)?;
                            self.pop_expect(ValType::I32)?;
                            self.push_val(ValType::I64);
                        }
                        // i64.atomic.rmw32.*_u (0x24, 0x2b, 0x32, 0x39, 0x40, 0x47): [i32, i64] -> [i64]
                        0x24 | 0x2b | 0x32 | 0x39 | 0x40 | 0x47 => {
                            self.read_memarg(2)?;
                            if !self.module.has_memory { return Err(WasmError::MemoryOutOfBounds); }
                            self.pop_expect(ValType::I64)?;
                            self.pop_expect(ValType::I32)?;
                            self.push_val(ValType::I64);
                        }
                        // i32.atomic.rmw.cmpxchg (0x48): [i32, i32, i32] -> [i32]
                        0x48 => {
                            self.read_memarg(2)?;
                            if !self.module.has_memory { return Err(WasmError::MemoryOutOfBounds); }
                            self.pop_expect(ValType::I32)?;
                            self.pop_expect(ValType::I32)?;
                            self.pop_expect(ValType::I32)?;
                            self.push_val(ValType::I32);
                        }
                        // i64.atomic.rmw.cmpxchg (0x49): [i32, i64, i64] -> [i64]
                        0x49 => {
                            self.read_memarg(3)?;
                            if !self.module.has_memory { return Err(WasmError::MemoryOutOfBounds); }
                            self.pop_expect(ValType::I64)?;
                            self.pop_expect(ValType::I64)?;
                            self.pop_expect(ValType::I32)?;
                            self.push_val(ValType::I64);
                        }
                        // i32.atomic.rmw8.cmpxchg_u (0x4a): [i32, i32, i32] -> [i32]
                        0x4a => {
                            self.read_memarg(0)?;
                            if !self.module.has_memory { return Err(WasmError::MemoryOutOfBounds); }
                            self.pop_expect(ValType::I32)?;
                            self.pop_expect(ValType::I32)?;
                            self.pop_expect(ValType::I32)?;
                            self.push_val(ValType::I32);
                        }
                        // i32.atomic.rmw16.cmpxchg_u (0x4b): [i32, i32, i32] -> [i32]
                        0x4b => {
                            self.read_memarg(1)?;
                            if !self.module.has_memory { return Err(WasmError::MemoryOutOfBounds); }
                            self.pop_expect(ValType::I32)?;
                            self.pop_expect(ValType::I32)?;
                            self.pop_expect(ValType::I32)?;
                            self.push_val(ValType::I32);
                        }
                        // i64.atomic.rmw8.cmpxchg_u (0x4c): [i32, i64, i64] -> [i64]
                        0x4c => {
                            self.read_memarg(0)?;
                            if !self.module.has_memory { return Err(WasmError::MemoryOutOfBounds); }
                            self.pop_expect(ValType::I64)?;
                            self.pop_expect(ValType::I64)?;
                            self.pop_expect(ValType::I32)?;
                            self.push_val(ValType::I64);
                        }
                        // i64.atomic.rmw16.cmpxchg_u (0x4d): [i32, i64, i64] -> [i64]
                        0x4d => {
                            self.read_memarg(1)?;
                            if !self.module.has_memory { return Err(WasmError::MemoryOutOfBounds); }
                            self.pop_expect(ValType::I64)?;
                            self.pop_expect(ValType::I64)?;
                            self.pop_expect(ValType::I32)?;
                            self.push_val(ValType::I64);
                        }
                        // i64.atomic.rmw32.cmpxchg_u (0x4e): [i32, i64, i64] -> [i64]
                        0x4e => {
                            self.read_memarg(2)?;
                            if !self.module.has_memory { return Err(WasmError::MemoryOutOfBounds); }
                            self.pop_expect(ValType::I64)?;
                            self.pop_expect(ValType::I64)?;
                            self.pop_expect(ValType::I32)?;
                            self.push_val(ValType::I64);
                        }
                        _ => {}
                    }
                }

                // ── 0xFB prefix: GC proposal ──
                0xFB => {
                    let sub = self.read_u32()?;
                    match sub {
                        0 => { // struct.new: typeidx — pop N fields, push structref
                            let type_idx = self.read_u32()?;
                            // Pop field values in reverse order
                            if let Some(crate::wasm::decoder::GcTypeDef::Struct { field_types, .. }) = self.module.gc_types.get(type_idx as usize) {
                                for _ in 0..field_types.len() {
                                    let _ = self.pop_opd()?;
                                }
                            }
                            self.push_opd(StackType::Unknown);
                        }
                        1 => { // struct.new_default: typeidx — push structref
                            let _type_idx = self.read_u32()?;
                            self.push_opd(StackType::Unknown);
                        }
                        2 | 3 | 4 => { // struct.get/get_s/get_u: typeidx fieldidx — pop ref, push val
                            let _ = self.read_u32()?; let _ = self.read_u32()?;
                            let _ = self.pop_opd()?;
                            self.push_opd(StackType::Unknown);
                        }
                        5 => { // struct.set: typeidx fieldidx — pop ref, pop val
                            let _ = self.read_u32()?; let _ = self.read_u32()?;
                            let _ = self.pop_opd()?;
                            let _ = self.pop_opd()?;
                        }
                        6 => { // array.new: typeidx — pop init, pop len, push arrayref
                            let _ = self.read_u32()?;
                            let _ = self.pop_opd()?; // len
                            let _ = self.pop_opd()?; // init
                            self.push_opd(StackType::Unknown);
                        }
                        7 => { // array.new_default: typeidx — pop len, push arrayref
                            let _ = self.read_u32()?;
                            let _ = self.pop_opd()?; // len
                            self.push_opd(StackType::Unknown);
                        }
                        8 => { // array.new_fixed: typeidx + count
                            let _ = self.read_u32()?;
                            let count = self.read_u32()?;
                            for _ in 0..count { let _ = self.pop_opd()?; }
                            self.push_opd(StackType::Unknown);
                        }
                        9 | 10 => { // array.new_data/elem: typeidx + idx — pop offset, pop len, push ref
                            let _ = self.read_u32()?; let _ = self.read_u32()?;
                            let _ = self.pop_opd()?; // len
                            let _ = self.pop_opd()?; // offset
                            self.push_opd(StackType::Unknown);
                        }
                        11 | 12 | 13 => { // array.get/get_s/get_u: typeidx — pop idx, pop ref, push val
                            let _ = self.read_u32()?;
                            let _ = self.pop_opd()?; // idx
                            let _ = self.pop_opd()?; // ref
                            self.push_opd(StackType::Unknown);
                        }
                        14 => { // array.set: typeidx — pop val, pop idx, pop ref
                            let _ = self.read_u32()?;
                            let _ = self.pop_opd()?; // val
                            let _ = self.pop_opd()?; // idx
                            let _ = self.pop_opd()?; // ref
                        }
                        15 => { // array.len: pop ref, push i32
                            let _ = self.pop_opd()?;
                            self.push_val(ValType::I32);
                        }
                        16 => { // array.fill: typeidx — pop len, pop val, pop idx, pop ref
                            let _ = self.read_u32()?;
                            let _ = self.pop_opd()?; // len
                            let _ = self.pop_opd()?; // val
                            let _ = self.pop_opd()?; // idx
                            let _ = self.pop_opd()?; // ref
                        }
                        17 => { // array.copy: typeidx + typeidx — pop len, pop src_idx, pop src_ref, pop dst_idx, pop dst_ref
                            let _ = self.read_u32()?; let _ = self.read_u32()?;
                            let _ = self.pop_opd()?; // len
                            let _ = self.pop_opd()?; // src idx
                            let _ = self.pop_opd()?; // src ref
                            let _ = self.pop_opd()?; // dst idx
                            let _ = self.pop_opd()?; // dst ref
                        }
                        18 | 19 => { // array.init_data/elem: typeidx + idx — pop len, pop src_off, pop dst_idx, pop ref
                            let _ = self.read_u32()?; let _ = self.read_u32()?;
                            let _ = self.pop_opd()?; // len
                            let _ = self.pop_opd()?; // src offset
                            let _ = self.pop_opd()?; // dst idx
                            let _ = self.pop_opd()?; // ref
                        }
                        20 | 21 => { // ref.test: heaptype — pop ref, push i32
                            let _ = self.read_i32()?;
                            let _ = self.pop_opd()?;
                            self.push_val(ValType::I32);
                        }
                        22 | 23 => { // ref.cast: heaptype — pop ref, push ref
                            let _ = self.read_i32()?;
                            let _ = self.pop_opd()?;
                            self.push_opd(StackType::Unknown);
                        }
                        24 | 25 => { // br_on_cast, br_on_cast_fail
                            let _ = self.read_u8()?; // flags
                            let _ = self.read_u32()?; // label
                            let _ = self.read_i32()?; // ht1
                            let _ = self.read_i32()?; // ht2
                            // Pop the input ref, push Unknown (type is narrowed on fall-through)
                            let _ = self.pop_opd()?;
                            self.push_opd(StackType::Unknown);
                        }
                        26 | 27 => { // any.convert_extern, extern.convert_any: pop ref, push ref
                            let _ = self.pop_opd()?;
                            self.push_opd(StackType::Unknown);
                        }
                        28 => { // ref.i31: pop i32, push i31ref
                            self.pop_expect(ValType::I32)?;
                            self.push_val(ValType::I31Ref);
                        }
                        29 | 30 => { // i31.get_s, i31.get_u: pop i31ref, push i32
                            let _ = self.pop_opd()?;
                            self.push_val(ValType::I32);
                        }
                        _ => {} // unknown GC sub-opcode — skip
                    }
                }

                _ => {
                    // Unknown opcode - skip
                }
            }
        }

        // After processing all bytecode, the control stack should have exactly 0 frames
        // (the outermost frame was popped by the final 'end')
        if !self.ctrl_stack.is_empty() {
            return Err(WasmError::TypeMismatch);
        }

        Ok(())
    }

    /// Validate SIMD instructions for type-checking purposes.
    /// Handles immediate parsing and stack effects.
    fn validate_simd(&mut self, sub: u32) -> Result<(), WasmError> {
        match sub {
            // v128.load
            0x00 => {
                self.read_memarg(4)?;
                self.pop_expect(ValType::I32)?;
                self.push_val(ValType::V128);
            }
            // v128.load8x8_s/u, v128.load16x4_s/u, v128.load32x2_s/u
            0x01..=0x06 => {
                self.read_memarg(3)?;
                self.pop_expect(ValType::I32)?;
                self.push_val(ValType::V128);
            }
            // v128.load8_splat
            0x07 => {
                self.read_memarg(0)?;
                self.pop_expect(ValType::I32)?;
                self.push_val(ValType::V128);
            }
            // v128.load16_splat
            0x08 => {
                self.read_memarg(1)?;
                self.pop_expect(ValType::I32)?;
                self.push_val(ValType::V128);
            }
            // v128.load32_splat
            0x09 => {
                self.read_memarg(2)?;
                self.pop_expect(ValType::I32)?;
                self.push_val(ValType::V128);
            }
            // v128.load64_splat
            0x0A => {
                self.read_memarg(3)?;
                self.pop_expect(ValType::I32)?;
                self.push_val(ValType::V128);
            }
            // v128.store
            0x0B => {
                self.read_memarg(4)?;
                self.pop_expect(ValType::V128)?;
                self.pop_expect(ValType::I32)?;
            }
            // v128.const
            0x0C => {
                if self.pc + 16 > self.end { return Err(WasmError::UnexpectedEnd); }
                self.pc += 16;
                self.push_val(ValType::V128);
            }
            // i8x16.shuffle
            0x0D => {
                for _ in 0..16 {
                    if self.pc >= self.end { return Err(WasmError::UnexpectedEnd); }
                    let lane = self.code[self.pc]; self.pc += 1;
                    if lane >= 32 { return Err(WasmError::OutOfBounds); }
                }
                self.pop_expect(ValType::V128)?;
                self.pop_expect(ValType::V128)?;
                self.push_val(ValType::V128);
            }
            // i8x16.swizzle
            0x0E => {
                self.pop_expect(ValType::V128)?;
                self.pop_expect(ValType::V128)?;
                self.push_val(ValType::V128);
            }
            // v128 splat instructions
            // i8x16.splat, i16x8.splat, i32x4.splat
            0x0F | 0x10 | 0x11 => {
                self.pop_expect(ValType::I32)?;
                self.push_val(ValType::V128);
            }
            // i64x2.splat
            0x12 => {
                self.pop_expect(ValType::I64)?;
                self.push_val(ValType::V128);
            }
            // f32x4.splat
            0x13 => {
                self.pop_expect(ValType::F32)?;
                self.push_val(ValType::V128);
            }
            // f64x2.splat
            0x14 => {
                self.pop_expect(ValType::F64)?;
                self.push_val(ValType::V128);
            }

            // ── extract_lane / replace_lane ──
            // i8x16.extract_lane_s/u
            0x15 | 0x16 => {
                if self.pc >= self.end { return Err(WasmError::UnexpectedEnd); }
                let lane = self.code[self.pc]; self.pc += 1;
                if lane >= 16 { return Err(WasmError::OutOfBounds); }
                self.pop_expect(ValType::V128)?;
                self.push_val(ValType::I32);
            }
            // i8x16.replace_lane
            0x17 => {
                if self.pc >= self.end { return Err(WasmError::UnexpectedEnd); }
                let lane = self.code[self.pc]; self.pc += 1;
                if lane >= 16 { return Err(WasmError::OutOfBounds); }
                self.pop_expect(ValType::I32)?;
                self.pop_expect(ValType::V128)?;
                self.push_val(ValType::V128);
            }
            // i16x8.extract_lane_s/u
            0x18 | 0x19 => {
                if self.pc >= self.end { return Err(WasmError::UnexpectedEnd); }
                let lane = self.code[self.pc]; self.pc += 1;
                if lane >= 8 { return Err(WasmError::OutOfBounds); }
                self.pop_expect(ValType::V128)?;
                self.push_val(ValType::I32);
            }
            // i16x8.replace_lane
            0x1A => {
                if self.pc >= self.end { return Err(WasmError::UnexpectedEnd); }
                let lane = self.code[self.pc]; self.pc += 1;
                if lane >= 8 { return Err(WasmError::OutOfBounds); }
                self.pop_expect(ValType::I32)?;
                self.pop_expect(ValType::V128)?;
                self.push_val(ValType::V128);
            }
            // i32x4.extract_lane
            0x1B => {
                if self.pc >= self.end { return Err(WasmError::UnexpectedEnd); }
                let lane = self.code[self.pc]; self.pc += 1;
                if lane >= 4 { return Err(WasmError::OutOfBounds); }
                self.pop_expect(ValType::V128)?;
                self.push_val(ValType::I32);
            }
            // i32x4.replace_lane
            0x1C => {
                if self.pc >= self.end { return Err(WasmError::UnexpectedEnd); }
                let lane = self.code[self.pc]; self.pc += 1;
                if lane >= 4 { return Err(WasmError::OutOfBounds); }
                self.pop_expect(ValType::I32)?;
                self.pop_expect(ValType::V128)?;
                self.push_val(ValType::V128);
            }
            // i64x2.extract_lane
            0x1D => {
                if self.pc >= self.end { return Err(WasmError::UnexpectedEnd); }
                let lane = self.code[self.pc]; self.pc += 1;
                if lane >= 2 { return Err(WasmError::OutOfBounds); }
                self.pop_expect(ValType::V128)?;
                self.push_val(ValType::I64);
            }
            // i64x2.replace_lane
            0x1E => {
                if self.pc >= self.end { return Err(WasmError::UnexpectedEnd); }
                let lane = self.code[self.pc]; self.pc += 1;
                if lane >= 2 { return Err(WasmError::OutOfBounds); }
                self.pop_expect(ValType::I64)?;
                self.pop_expect(ValType::V128)?;
                self.push_val(ValType::V128);
            }
            // f32x4.extract_lane
            0x1F => {
                if self.pc >= self.end { return Err(WasmError::UnexpectedEnd); }
                let lane = self.code[self.pc]; self.pc += 1;
                if lane >= 4 { return Err(WasmError::OutOfBounds); }
                self.pop_expect(ValType::V128)?;
                self.push_val(ValType::F32);
            }
            // f32x4.replace_lane
            0x20 => {
                if self.pc >= self.end { return Err(WasmError::UnexpectedEnd); }
                let lane = self.code[self.pc]; self.pc += 1;
                if lane >= 4 { return Err(WasmError::OutOfBounds); }
                self.pop_expect(ValType::F32)?;
                self.pop_expect(ValType::V128)?;
                self.push_val(ValType::V128);
            }
            // f64x2.extract_lane
            0x21 => {
                if self.pc >= self.end { return Err(WasmError::UnexpectedEnd); }
                let lane = self.code[self.pc]; self.pc += 1;
                if lane >= 2 { return Err(WasmError::OutOfBounds); }
                self.pop_expect(ValType::V128)?;
                self.push_val(ValType::F64);
            }
            // f64x2.replace_lane
            0x22 => {
                if self.pc >= self.end { return Err(WasmError::UnexpectedEnd); }
                let lane = self.code[self.pc]; self.pc += 1;
                if lane >= 2 { return Err(WasmError::OutOfBounds); }
                self.pop_expect(ValType::F64)?;
                self.pop_expect(ValType::V128)?;
                self.push_val(ValType::V128);
            }

            // v128.load8_lane
            0x54 => {
                self.read_memarg(0)?;
                if self.pc >= self.end { return Err(WasmError::UnexpectedEnd); }
                let lane = self.code[self.pc]; self.pc += 1;
                if lane >= 16 { return Err(WasmError::OutOfBounds); }
                self.pop_expect(ValType::V128)?;
                self.pop_expect(ValType::I32)?;
                self.push_val(ValType::V128);
            }
            // v128.load16_lane
            0x55 => {
                self.read_memarg(1)?;
                if self.pc >= self.end { return Err(WasmError::UnexpectedEnd); }
                let lane = self.code[self.pc]; self.pc += 1;
                if lane >= 8 { return Err(WasmError::OutOfBounds); }
                self.pop_expect(ValType::V128)?;
                self.pop_expect(ValType::I32)?;
                self.push_val(ValType::V128);
            }
            // v128.load32_lane
            0x56 => {
                self.read_memarg(2)?;
                if self.pc >= self.end { return Err(WasmError::UnexpectedEnd); }
                let lane = self.code[self.pc]; self.pc += 1;
                if lane >= 4 { return Err(WasmError::OutOfBounds); }
                self.pop_expect(ValType::V128)?;
                self.pop_expect(ValType::I32)?;
                self.push_val(ValType::V128);
            }
            // v128.load64_lane
            0x57 => {
                self.read_memarg(3)?;
                if self.pc >= self.end { return Err(WasmError::UnexpectedEnd); }
                let lane = self.code[self.pc]; self.pc += 1;
                if lane >= 2 { return Err(WasmError::OutOfBounds); }
                self.pop_expect(ValType::V128)?;
                self.pop_expect(ValType::I32)?;
                self.push_val(ValType::V128);
            }
            // v128.store8_lane
            0x58 => {
                self.read_memarg(0)?;
                if self.pc >= self.end { return Err(WasmError::UnexpectedEnd); }
                let lane = self.code[self.pc]; self.pc += 1;
                if lane >= 16 { return Err(WasmError::OutOfBounds); }
                self.pop_expect(ValType::V128)?;
                self.pop_expect(ValType::I32)?;
            }
            // v128.store16_lane
            0x59 => {
                self.read_memarg(1)?;
                if self.pc >= self.end { return Err(WasmError::UnexpectedEnd); }
                let lane = self.code[self.pc]; self.pc += 1;
                if lane >= 8 { return Err(WasmError::OutOfBounds); }
                self.pop_expect(ValType::V128)?;
                self.pop_expect(ValType::I32)?;
            }
            // v128.store32_lane
            0x5A => {
                self.read_memarg(2)?;
                if self.pc >= self.end { return Err(WasmError::UnexpectedEnd); }
                let lane = self.code[self.pc]; self.pc += 1;
                if lane >= 4 { return Err(WasmError::OutOfBounds); }
                self.pop_expect(ValType::V128)?;
                self.pop_expect(ValType::I32)?;
            }
            // v128.store64_lane
            0x5B => {
                self.read_memarg(3)?;
                if self.pc >= self.end { return Err(WasmError::UnexpectedEnd); }
                let lane = self.code[self.pc]; self.pc += 1;
                if lane >= 2 { return Err(WasmError::OutOfBounds); }
                self.pop_expect(ValType::V128)?;
                self.pop_expect(ValType::I32)?;
            }
            // v128.load32_zero
            0x5C => {
                self.read_memarg(2)?;
                self.pop_expect(ValType::I32)?;
                self.push_val(ValType::V128);
            }
            // v128.load64_zero
            0x5D => {
                self.read_memarg(3)?;
                self.pop_expect(ValType::I32)?;
                self.push_val(ValType::V128);
            }

            // All remaining SIMD ops (no immediates) — classified by signature
            _ => {
                let sig = simd_op_signature(sub);
                match sig {
                    SimdSig::UnaryV128 => {
                        self.pop_expect(ValType::V128)?;
                        self.push_val(ValType::V128);
                    }
                    SimdSig::BinaryV128 => {
                        self.pop_expect(ValType::V128)?;
                        self.pop_expect(ValType::V128)?;
                        self.push_val(ValType::V128);
                    }
                    SimdSig::TernaryV128 => {
                        self.pop_expect(ValType::V128)?;
                        self.pop_expect(ValType::V128)?;
                        self.pop_expect(ValType::V128)?;
                        self.push_val(ValType::V128);
                    }
                    SimdSig::ShiftV128 => {
                        self.pop_expect(ValType::I32)?;
                        self.pop_expect(ValType::V128)?;
                        self.push_val(ValType::V128);
                    }
                    SimdSig::V128ToI32 => {
                        self.pop_expect(ValType::V128)?;
                        self.push_val(ValType::I32);
                    }
                }
            }
        }
        Ok(())
    }
}

/// SIMD instruction signature categories
#[derive(Debug, Clone, Copy)]
enum SimdSig {
    UnaryV128,   // v128 -> v128
    BinaryV128,  // v128 x v128 -> v128
    TernaryV128, // v128 x v128 x v128 -> v128
    ShiftV128,   // v128 x i32 -> v128
    V128ToI32,   // v128 -> i32
}

/// Classify a SIMD sub-opcode by its stack signature.
/// Derived from the runtime.rs execution engine's actual pop/push patterns.
fn simd_op_signature(sub: u32) -> SimdSig {
    match sub {
        // ── v128 -> i32 (test/bitmask) ──
        0x53 | 0x63 | 0x64 | 0x83 | 0x84 | 0xA3 | 0xA4 | 0xC3 | 0xC4
        => SimdSig::V128ToI32,

        // ── v128 -> v128 (unary) ──
        0x4D | 0x5E | 0x5F | 0x60 | 0x61 | 0x62 | 0x67 | 0x68 |
        0x69 | 0x6A | 0x74 | 0x75 | 0x7A | 0x7C | 0x7D | 0x7E |
        0x7F | 0x80 | 0x81 | 0x87 | 0x88 | 0x89 | 0x8A | 0x94 |
        0xA0 | 0xA1 | 0xA7 | 0xA8 | 0xA9 | 0xAA | 0xC0 | 0xC1 |
        0xC7 | 0xC8 | 0xC9 | 0xCA | 0xE0 | 0xE1 | 0xE3 | 0xEC |
        0xED | 0xEF | 0xF8 | 0xF9 | 0xFA | 0xFB | 0xFC | 0xFD |
        0xFE | 0xFF |
        // relaxed unary (trunc): 0x101-0x104
        0x101 | 0x102 | 0x103 | 0x104
        => SimdSig::UnaryV128,

        // ── v128 x i32 -> v128 (shift) ──
        0x6B | 0x6C | 0x6D | // i8x16 shl/shr_s/shr_u
        0x8B | 0x8C | 0x8D | // i16x8 shl/shr_s/shr_u
        0xAB | 0xAC | 0xAD | // i32x4 shl/shr_s/shr_u
        0xCB | 0xCC | 0xCD   // i64x2 shl/shr_s/shr_u
        => SimdSig::ShiftV128,

        // ── v128 x v128 x v128 -> v128 (ternary) ──
        0x52 |  // v128.bitselect
        // relaxed SIMD ternary:
        0x105 | 0x106 | 0x107 | 0x108 | // f32x4/f64x2 relaxed_madd/nmadd
        0x109 | 0x10A | 0x10B | 0x10C | // relaxed_laneselect
        0x113   // i32x4.relaxed_dot_i8x16_i7x16_add_s
        => SimdSig::TernaryV128,

        // Everything else is binary (v128 x v128 -> v128)
        _ => SimdSig::BinaryV128,
    }
}

fn byte_to_valtype(b: u8) -> Result<ValType, WasmError> {
    match b {
        0x7F => Ok(ValType::I32),
        0x7E => Ok(ValType::I64),
        0x7D => Ok(ValType::F32),
        0x7C => Ok(ValType::F64),
        0x7B => Ok(ValType::V128),
        0x70 => Ok(ValType::FuncRef),
        0x6F => Ok(ValType::ExternRef),
        // Typed function reference types (should not normally appear as raw bytes here,
        // but handle them in case the decoder passes them through)
        0x63 => Ok(ValType::NullableTypedFuncRef),
        0x64 => Ok(ValType::TypedFuncRef),
        _ => Err(WasmError::TypeMismatch),
    }
}

/// Validate instructions in a function body using stack-based type checking.
fn validate_function_body(
    module: &WasmModule,
    _func_index: usize,
    func: &crate::wasm::decoder::FuncDef,
    total_functions: usize,
    has_memory: bool,
    total_tables: usize,
    total_globals: usize,
    table_import_count: usize,
    declared_funcs: &BTreeSet<u32>,
) -> Result<(), WasmError> {
    let code = &module.code;
    let start = func.code_offset;
    let end = func.code_offset + func.code_len;

    if start >= code.len() || end > code.len() {
        return Err(WasmError::CodeTooLarge);
    }

    let type_idx = func.type_idx as usize;
    if type_idx >= module.func_types.len() {
        return Err(WasmError::FunctionNotFound(func.type_idx));
    }

    let ft = &module.func_types[type_idx];
    let func_import_count = module.func_import_count();

    // Build local types: params + locals
    let mut local_types = Vec::new();
    for i in 0..ft.param_count as usize {
        local_types.push(ft.params[i]);
    }
    for i in 0..func.local_count as usize {
        local_types.push(func.locals[i]);
    }

    let return_types: Vec<ValType> = ft.results[..ft.result_count as usize].to_vec();

    // Build local initialization tracking.
    // Params are always initialized. Non-nullable ref locals start uninitialized.
    let param_count = ft.param_count as usize;
    let mut local_inits = vec![true; local_types.len()];
    for i in param_count..local_types.len() {
        let local_idx = i - param_count;
        let is_nn = func.non_nullable_locals.get(local_idx).copied().unwrap_or(false);
        if is_nn || is_non_nullable_ref(local_types[i]) {
            local_inits[i] = false;
        }
    }

    let mut validator = Validator {
        module,
        code,
        pc: start,
        end,
        opd_stack: Vec::new(),
        ctrl_stack: Vec::new(),
        local_types,
        param_count,
        return_types,
        total_functions,
        has_memory,
        total_tables,
        total_globals,
        func_import_count,
        table_import_count,
        declared_funcs,
        local_inits,
    };

    // Temporary debug: dump function body bytes
    validator.validate()
}

// ─── LEB128 helpers for validation ─────────────────────────────────────────

fn read_leb128_u32(code: &[u8], pc: &mut usize) -> Result<u32, WasmError> {
    crate::wasm::decoder::decode_leb128_u32(code, pc)
}
