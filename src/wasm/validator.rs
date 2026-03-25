//! WASM module validator.
//!
//! Performs structural and instruction-level validation of a decoded WASM module,
//! including stack-based type checking per the WebAssembly specification.

#[path = "validator/subtype.rs"]
pub mod subtype;
#[path = "validator/func.rs"]
mod func;

pub use subtype::types_equivalent_in_module;

use subtype::*;
use func::validate_function_body;
use crate::wasm::decoder::{ElemMode, ExportKind, ImportKind, WasmModule};
use crate::wasm::types::{ValType, WasmError, MAX_MEMORY_PAGES};
use alloc::collections::BTreeSet;
use alloc::string::String;

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

    // Validate memory limits (per-memory)
    if module.memories.is_empty() {
        // Fallback: use module-wide fields for backward compat
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
    } else {
        for mdef in &module.memories {
            if mdef.is_memory64 {
                // memory64: still validate min <= max, but skip 32-bit page limit
                if mdef.has_max && mdef.min_pages > mdef.max_pages {
                    return Err(WasmError::MemoryOutOfBounds);
                }
                continue;
            }
            if mdef.min_pages as u64 > MAX_MEMORY_PAGES as u64 {
                return Err(WasmError::MemoryOutOfBounds);
            }
            if mdef.has_max {
                if mdef.min_pages > mdef.max_pages {
                    return Err(WasmError::MemoryOutOfBounds);
                }
                if mdef.max_pages as u64 > MAX_MEMORY_PAGES as u64 {
                    return Err(WasmError::MemoryOutOfBounds);
                }
            }
        }
    }

    // Validate subtype declarations
    validate_subtypes(module)?;

    // Validate table limits and non-nullable ref types
    for table in &module.tables {
        if let Some(max) = table.max {
            if table.min > max {
                return Err(WasmError::TableIndexOutOfBounds);
            }
        }
        // Non-nullable ref types require an init expression
        if table.is_non_nullable && table.init_expr_bytes.is_none() {
            return Err(WasmError::TypeMismatch);
        }
        // Validate table init expression type compatibility
        if let Some(ref expr_bytes) = table.init_expr_bytes {
            let info = crate::wasm::decoder::scan_init_expr_info(expr_bytes, 0);
            if info.stack_depth != 1 {
                return Err(WasmError::TypeMismatch);
            }
            // Check init expr doesn't reference module-defined globals (only imports allowed)
            if let Some(ref_idx) = info.global_ref {
                let global_import_count_local = count_global_imports(module);
                if ref_idx as usize >= global_import_count_local {
                    return Err(WasmError::GlobalIndexOutOfBounds);
                }
            }
            // Validate init expr result type matches table element type
            if let Some(init_type) = info.result_type {
                if !is_ref_type(init_type) && is_ref_type(table.elem_type) {
                    // Non-ref init for ref table
                    return Err(WasmError::TypeMismatch);
                }
                // Check type compatibility: init must be subtype of table elem type
                if init_type != table.elem_type && !val_is_subtype(init_type, table.elem_type) {
                    return Err(WasmError::TypeMismatch);
                }
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
        // Validate no non-constant instructions in init expression
        if global.has_non_const {
            return Err(WasmError::ConstExprRequired);
        }
        // Validate global init expression type matches declared type
        // Skip for GC globals with complex init expressions (struct.new, array.new, etc.)
        if let Some(expr_type) = global.init_expr_type {
            if expr_type != global.val_type && !global.has_non_const {
                if !is_ref_compatible(expr_type, global.val_type) {
                    if !module.gc_enabled || !val_is_subtype(expr_type, global.val_type) {
                        return Err(WasmError::TypeMismatch);
                    }
                }
            }
        } else if global.init_global_ref.is_some() {
            if let Some(ref_idx) = global.init_global_ref {
                let ref_type = get_imported_global_type(module, ref_idx);
                if let Some(rt) = ref_type {
                    if rt != global.val_type && !is_ref_compatible(rt, global.val_type) {
                        if !module.gc_enabled || !val_is_subtype(rt, global.val_type) {
                            return Err(WasmError::TypeMismatch);
                        }
                    }
                }
            }
        }
        // GC: when global is (ref $t) and init result is a funcref (ref.func $f),
        // check that func type is a subtype of global type.
        // Only when init_expr_type indicates funcref (ref.func is the result, not an argument to array.new).
        if module.gc_enabled {
            if let (Some(global_ht), Some(func_idx)) = (global.heap_type, global.init_func_ref) {
                let init_is_funcref = matches!(global.init_expr_type,
                    Some(ValType::FuncRef) | Some(ValType::TypedFuncRef) |
                    Some(ValType::NullableTypedFuncRef) | Some(ValType::NonNullableFuncRef));
                if global_ht >= 0 && init_is_funcref {
                    let global_type_idx = global_ht as u32;
                    let fti = if (func_idx as usize) < func_import_count {
                        module.func_import_type(func_idx)
                    } else {
                        module.functions.get(func_idx as usize - func_import_count).map(|f| f.type_idx)
                    };
                    if let Some(fti) = fti {
                        if !is_type_index_subtype(fti, global_type_idx, module) {
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
        let is_func_elem = matches!(seg.elem_type, ValType::FuncRef | ValType::TypedFuncRef | ValType::NonNullableFuncRef | ValType::NullableTypedFuncRef);
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
        let is_func_elem = matches!(seg.elem_type, ValType::FuncRef | ValType::TypedFuncRef | ValType::NonNullableFuncRef | ValType::NullableTypedFuncRef);
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
