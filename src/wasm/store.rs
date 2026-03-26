//! Cross-instance state sharing: import injection, memory/global synchronization.
//!
//! These functions apply pre-resolved import values to a WasmModule, handling
//! global prepending, memory size upgrades, and table size upgrades. The
//! embedder is responsible for resolving import values from the instance
//! registry before calling these functions.

use alloc::vec::Vec;
use crate::wasm::decoder::{GlobalDef, ImportKind, WasmModule};
use crate::wasm::instance::{bytes_to_string, exported_memory_index, exported_table_index};
use crate::wasm::linker::decode_valtype_byte;
use crate::wasm::types::{ValType, Value};

/// A resolved global import: val_type, mutability, and the resolved value.
pub struct ResolvedGlobal {
    pub val_type: ValType,
    pub mutable: bool,
    pub value: Value,
}

/// Prepend resolved imported globals to a module's global list, then
/// re-evaluate init expressions for module-defined globals that reference
/// imported globals via `global.get`.
///
/// Returns `Err(message)` on type mismatch.
pub fn apply_imported_globals(
    module: &mut WasmModule,
    resolved: Vec<ResolvedGlobal>,
) -> Result<(), &'static str> {
    if resolved.is_empty() {
        return Ok(());
    }
    let num_imported = resolved.len();
    let mut globals: Vec<GlobalDef> = resolved
        .into_iter()
        .map(|rg| GlobalDef {
            val_type: rg.val_type,
            mutable: rg.mutable,
            init_value: rg.value,
            init_global_ref: None,
            init_func_ref: None,
            init_expr_type: Some(rg.val_type),
            init_expr_stack_depth: 1,
            init_expr_bytes: Vec::new(),
            heap_type: None,
            has_non_const: false,
        })
        .collect();
    globals.extend(module.globals.iter().cloned());
    module.globals = globals;

    // Re-evaluate init expressions for module-defined globals that reference
    // imported globals. At decode time, global.get returns 0 as a placeholder.
    // Now that imported globals have their actual values, add the reference value.
    for i in num_imported..module.globals.len() {
        if let Some(ref_idx) = module.globals[i].init_global_ref {
            if (ref_idx as usize) < i {
                let ref_val = module.globals[ref_idx as usize].init_value;
                let init = &mut module.globals[i].init_value;
                match (ref_val, *init) {
                    (Value::I32(r), Value::I32(v)) => *init = Value::I32(v.wrapping_add(r)),
                    (Value::I64(r), Value::I64(v)) => *init = Value::I64(v.wrapping_add(r)),
                    (Value::F32(r), Value::F32(v)) => *init = Value::F32(v + r),
                    (Value::F64(r), Value::F64(v)) => *init = Value::F64(v + r),
                    (val, _) => *init = val,
                }
                // Clear the ref so the runtime doesn't re-process
                module.globals[i].init_global_ref = None;
            }
        }
    }
    Ok(())
}

/// A resolved memory source: the actual size (min pages) and optional max.
pub struct ResolvedMemory {
    /// Index of this memory in the importing module's memory list.
    pub mem_idx: usize,
    /// The actual number of pages available from the exporter.
    pub actual_min_pages: u32,
    /// The max pages constraint from the exporter, if any.
    pub actual_max_pages: Option<u32>,
}

/// Update a module's memory definitions to reflect the actual sizes of imported
/// memories. Call this after resolving all memory imports.
pub fn apply_imported_memories(module: &mut WasmModule, resolved: &[ResolvedMemory]) {
    for rm in resolved {
        let mem_idx = rm.mem_idx;
        let actual_min_pages = rm.actual_min_pages;
        let actual_max_pages = rm.actual_max_pages;

        // Update module-wide fields for memory 0 (backward compat)
        if mem_idx == 0 {
            if module.memory_min_pages < actual_min_pages {
                module.memory_min_pages = actual_min_pages;
            }
            if let Some(actual_max) = actual_max_pages {
                if module.has_memory_max {
                    if module.memory_max_pages > actual_max {
                        module.memory_max_pages = actual_max;
                    }
                } else {
                    module.has_memory_max = true;
                    module.memory_max_pages = actual_max;
                }
            }
        }

        // Update the per-memory MemoryDef
        if mem_idx < module.memories.len() {
            if module.memories[mem_idx].min_pages < actual_min_pages {
                module.memories[mem_idx].min_pages = actual_min_pages;
            }
            if let Some(actual_max) = actual_max_pages {
                if module.memories[mem_idx].has_max {
                    if module.memories[mem_idx].max_pages > actual_max {
                        module.memories[mem_idx].max_pages = actual_max;
                    }
                } else {
                    module.memories[mem_idx].has_max = true;
                    module.memories[mem_idx].max_pages = actual_max;
                }
            }
        }
    }
}

/// A resolved table source: index and actual size.
pub struct ResolvedTable {
    /// Index of this table in the importing module's table list.
    pub table_idx: usize,
    /// The actual number of entries in the exporter's table.
    pub actual_min: u32,
}

/// Update a module's table definitions to reflect the actual sizes of imported
/// tables. Call this after resolving all table imports.
pub fn apply_imported_tables(module: &mut WasmModule, resolved: &[ResolvedTable]) {
    for rt in resolved {
        if rt.table_idx < module.tables.len() && module.tables[rt.table_idx].min < rt.actual_min {
            module.tables[rt.table_idx].min = rt.actual_min;
        }
    }
}

/// Re-evaluate element/data segment offsets that reference globals.
/// After applying imported globals, the globals have actual values, so we can
/// re-evaluate extended-const offset expressions that use global.get.
pub fn fixup_segment_offsets(module: &mut WasmModule, original_bytes: &[u8]) {
    // Build global init values for the evaluator
    let global_values: Vec<Value> = module.globals.iter().map(|g| g.init_value).collect();

    // Re-evaluate element segment offsets
    use crate::wasm::decoder::ElemMode;
    for seg in &mut module.element_segments {
        if seg.mode != ElemMode::Active {
            continue;
        }
        // Only re-evaluate if the offset expression references a global
        if seg.offset_expr_info.global_ref.is_none() {
            continue;
        }
        let (start, end) = seg.offset_expr_range;
        if start == 0 && end == 0 {
            continue; // no saved byte range
        }
        if end <= original_bytes.len() {
            let mut pos = start;
            if let Ok(val) = crate::wasm::decoder::eval_init_expr_with_globals(original_bytes, &mut pos, &global_values) {
                seg.offset = match val {
                    Value::I32(v) => v as u32,
                    Value::I64(v) => v as u32,
                    _ => seg.offset,
                };
            }
        }
    }

    // Re-evaluate data segment offsets
    for seg in &mut module.data_segments {
        if !seg.is_active {
            continue;
        }
        if seg.offset_expr_info.global_ref.is_none() {
            continue;
        }
        let (start, end) = seg.offset_expr_range;
        if start == 0 && end == 0 {
            continue;
        }
        if end <= original_bytes.len() {
            let mut pos = start;
            if let Ok(val) = crate::wasm::decoder::eval_init_expr_with_globals(original_bytes, &mut pos, &global_values) {
                seg.offset = match val {
                    Value::I32(v) => v as u32,
                    Value::I64(v) => v as u32,
                    _ => seg.offset,
                };
            }
        }
    }
}

/// Collect the global import info from a module: (val_type_byte, mutable, module_name, field_name).
/// This is a helper for embedders to know what globals need resolving.
pub fn collect_global_imports(module: &WasmModule) -> Vec<(u8, bool, &[u8], &[u8])> {
    let mut result = Vec::new();
    for import in &module.imports {
        if let ImportKind::Global(val_type_byte, mutable, _) = import.kind {
            let mod_name = module.get_name(import.module_name_offset, import.module_name_len);
            let fld_name = module.get_name(import.field_name_offset, import.field_name_len);
            result.push((val_type_byte, mutable, mod_name, fld_name));
        }
    }
    result
}

/// Collect memory import info: (mem_idx, module_name, field_name).
pub fn collect_memory_imports(module: &WasmModule) -> Vec<(usize, &[u8], &[u8])> {
    let mut result = Vec::new();
    let mut mem_idx = 0usize;
    for import in &module.imports {
        if matches!(import.kind, ImportKind::Memory) {
            let mod_name = module.get_name(import.module_name_offset, import.module_name_len);
            let fld_name = module.get_name(import.field_name_offset, import.field_name_len);
            result.push((mem_idx, mod_name, fld_name));
            mem_idx += 1;
        }
    }
    result
}

/// Collect table import info: (table_idx, module_name, field_name).
pub fn collect_table_imports(module: &WasmModule) -> Vec<(usize, &[u8], &[u8])> {
    let mut result = Vec::new();
    let mut tbl_idx = 0usize;
    for import in &module.imports {
        if matches!(import.kind, ImportKind::Table(_)) {
            let mod_name = module.get_name(import.module_name_offset, import.module_name_len);
            let fld_name = module.get_name(import.field_name_offset, import.field_name_len);
            result.push((tbl_idx, mod_name, fld_name));
            tbl_idx += 1;
        }
    }
    result
}

/// Synchronize a mutable global from source to destination.
/// `src_globals` is the source instance's globals array.
/// `dst_globals` is the destination instance's globals array.
pub fn sync_global(src_globals: &[Value], src_idx: usize, dst_globals: &mut [Value], dst_idx: usize) {
    if let Some(&val) = src_globals.get(src_idx) {
        if let Some(slot) = dst_globals.get_mut(dst_idx) {
            *slot = val;
        }
    }
}

/// Synchronize memory content from src to dst, growing dst if needed.
pub fn sync_memory(
    src_mem: &[u8], src_size: usize,
    dst_mem: &mut Vec<u8>, dst_size: &mut usize,
) {
    if src_size > *dst_size {
        dst_mem.resize(src_size, 0);
        dst_mem[..src_size].copy_from_slice(&src_mem[..src_size]);
        *dst_size = src_size;
    } else if *dst_size > src_size {
        // dst is larger, no sync needed from this direction
    } else if src_size == *dst_size && src_size > 0 {
        dst_mem[..src_size].copy_from_slice(&src_mem[..src_size]);
    }
}
