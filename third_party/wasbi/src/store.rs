//! Cross-instance state sharing: import injection, memory/global synchronization.
//!
//! These functions apply pre-resolved import values to a WasmModule, handling
//! global prepending, memory size upgrades, and table size upgrades. The
//! embedder is responsible for resolving import values from the instance
//! registry before calling these functions.
//!
//! The [`Store`] struct provides a higher-level API for multi-module
//! instantiation and cross-module call dispatch, managing a collection of
//! instances and their shared state.

use crate::decoder::{GlobalDef, ImportKind, WasmModule};
use crate::engine::Engine;
use crate::instance_utils;
use crate::linker::{ExternVal, Linker};
use crate::linker_utils;
use crate::runtime::{ExecResult, WasmInstance};
use crate::types::{ValType, Value, WasmError};
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

// ─── Existing free functions (kept as-is) ────────────────────────────────────

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
    use crate::decoder::ElemMode;
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
            if let Ok(val) = crate::decoder::eval_init_expr_with_globals(
                original_bytes,
                &mut pos,
                &global_values,
            ) {
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
            if let Ok(val) = crate::decoder::eval_init_expr_with_globals(
                original_bytes,
                &mut pos,
                &global_values,
            ) {
                seg.offset = match val {
                    Value::I32(v) => v as u32,
                    Value::I64(v) => v as u32,
                    _ => seg.offset,
                };
            }
        }
    }

    // Re-evaluate element segment item expressions that reference globals
    // (e.g., funcref elements initialized with global.get)
    for seg in &mut module.element_segments {
        if seg.item_expr_bytes.is_empty() {
            continue;
        }
        for (i, item_bytes) in seg.item_expr_bytes.iter().enumerate() {
            if i >= seg.func_indices.len() {
                break;
            }
            // Check if this item references a global
            let item_info = seg.item_expr_infos.get(i);
            let refs_global = item_info.is_some_and(|info| info.global_ref.is_some());
            if !refs_global {
                continue;
            }
            let mut pos = 0;
            if let Ok(val) =
                crate::decoder::eval_init_expr_with_globals(item_bytes, &mut pos, &global_values)
            {
                seg.func_indices[i] = match val {
                    Value::I32(v) => v as u32,
                    Value::NullRef => u32::MAX,
                    _ => seg.func_indices[i],
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
pub fn sync_global(
    src_globals: &[Value],
    src_idx: usize,
    dst_globals: &mut [Value],
    dst_idx: usize,
) {
    if let Some(&val) = src_globals.get(src_idx) {
        if let Some(slot) = dst_globals.get_mut(dst_idx) {
            *slot = val;
        }
    }
}

/// Synchronize memory content from src to dst, growing dst if needed.
pub fn sync_memory(src_mem: &[u8], src_size: usize, dst_mem: &mut Vec<u8>, dst_size: &mut usize) {
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

// ─── Store struct (Steps 3-6) ────────────────────────────────────────────────

/// Tracks a shared memory link between two instances.
struct MemoryShare {
    importer_idx: usize,
    importer_mem: usize,
    exporter_idx: usize,
    exporter_mem: usize,
}

/// Tracks a shared mutable global link between two instances.
struct GlobalShare {
    importer_idx: usize,
    importer_global: usize,
    exporter_idx: usize,
    exporter_global: usize,
}

/// A multi-module store managing instances, linking, and cross-module dispatch.
///
/// The `Store` owns a collection of [`WasmInstance`]s and a [`Linker`], and
/// provides methods to instantiate modules with automatic import resolution,
/// call functions with cross-module dispatch, and synchronize shared state.
pub struct Store {
    engine: Engine,
    instances: Vec<WasmInstance>,
    names: BTreeMap<String, usize>,
    linker: Linker,
    memory_shares: Vec<MemoryShare>,
    global_shares: Vec<GlobalShare>,
}

impl Store {
    /// Create a new empty store with the given engine.
    pub fn new(engine: Engine) -> Self {
        Self {
            engine,
            instances: Vec::new(),
            names: BTreeMap::new(),
            linker: Linker::new(),
            memory_shares: Vec::new(),
            global_shares: Vec::new(),
        }
    }

    /// Get the linker for registering host functions and externs.
    pub fn linker(&mut self) -> &mut Linker {
        &mut self.linker
    }

    /// Get a shared reference to the linker.
    pub fn linker_ref(&self) -> &Linker {
        &self.linker
    }

    /// Instantiate a module, resolving imports from registered instances.
    ///
    /// If `name` is provided, the instance and its exports are registered under
    /// that name for future import resolution.
    ///
    /// Returns the instance index on success.
    pub fn instantiate(
        &mut self,
        mut module: WasmModule,
        name: Option<&str>,
    ) -> Result<usize, WasmError> {
        // Save original bytes for fixup_segment_offsets
        // Use the full WASM binary (not just code section) because
        // offset_expr_range positions reference the full binary.
        let original_bytes = if module.get_original_bytes().is_empty() {
            module.get_code().to_vec()
        } else {
            module.get_original_bytes().to_vec()
        };

        // 0. Validate imports before modifying the module.
        self.validate_imports_with_runtime(&module)?;

        // 1. Collect and resolve global imports (owned copies to avoid borrow conflicts)
        let global_import_info: Vec<(u8, bool, String, String)> = {
            let raw = collect_global_imports(&module);
            raw.into_iter()
                .map(|(vt, m, mn, fn_)| {
                    (
                        vt,
                        m,
                        String::from(core::str::from_utf8(mn).unwrap_or("")),
                        String::from(core::str::from_utf8(fn_).unwrap_or("")),
                    )
                })
                .collect()
        };

        let mut resolved_globals = Vec::new();
        for (val_type_byte, mutable, mod_name, fld_name) in &global_import_info {
            if let Some(ext) = self.linker.resolve_str(mod_name, fld_name) {
                if let ExternVal::Global(src_idx, global_idx) = ext {
                    if let Some(src_inst) = self.instances.get(*src_idx) {
                        let src_module = &src_inst.module;
                        let src_globals_defs = src_module.get_globals();
                        let val = src_inst
                            .get_global(*global_idx as usize)
                            .unwrap_or(Value::I32(0));
                        let val_type =
                            if let Some(gdef) = src_globals_defs.get(*global_idx as usize) {
                                gdef.val_type
                            } else {
                                linker_utils::decode_valtype_byte(*val_type_byte)
                                    .unwrap_or(ValType::I32)
                            };
                        resolved_globals.push(ResolvedGlobal {
                            val_type,
                            mutable: *mutable,
                            value: val,
                        });
                    }
                }
            } else {
                // No extern found — use a zero-initialized placeholder
                let val_type =
                    linker_utils::decode_valtype_byte(*val_type_byte).unwrap_or(ValType::I32);
                resolved_globals.push(ResolvedGlobal {
                    val_type,
                    mutable: *mutable,
                    value: Value::default_for(val_type),
                });
            }
        }

        // 2. Apply imported globals
        if apply_imported_globals(&mut module, resolved_globals).is_err() {
            return Err(WasmError::TypeMismatch);
        }

        // 3. Fixup funcref globals (global.get references in init exprs)
        // Already handled by apply_imported_globals above.

        // 4. Fixup segment offsets (includes re-evaluating element item expressions
        //    that reference globals)
        fixup_segment_offsets(&mut module, &original_bytes);

        // 4b. Translate funcref values in element segments that came from imported globals.
        // After fixup_segment_offsets, element items that used global.get on an imported
        // funcref global will have function indices from the source module's space.
        // We need to copy those function bodies into this module.
        {
            let num_imported_globals = global_import_info.len();
            // Collect all (seg_idx, item_idx, src_idx, func_idx) that need translation
            let mut translations: Vec<(usize, usize, usize, u32)> = Vec::new();
            for (seg_idx, seg) in module.get_element_segments().iter().enumerate() {
                for (i, item_info) in seg.item_expr_infos.iter().enumerate() {
                    if i >= seg.func_indices.len() {
                        break;
                    }
                    if let Some(global_ref) = item_info.global_ref {
                        if (global_ref as usize) < num_imported_globals {
                            let func_idx = seg.func_indices[i];
                            if func_idx == u32::MAX {
                                continue;
                            }
                            let (_, _, mod_name, fld_name) =
                                &global_import_info[global_ref as usize];
                            if let Some(ext) = self.linker.resolve_str(mod_name, fld_name) {
                                if let ExternVal::Global(src_idx, _) = ext {
                                    translations.push((seg_idx, i, *src_idx, func_idx));
                                }
                            }
                        }
                    }
                }
            }
            for (seg_idx, item_idx, src_idx, func_idx) in translations {
                let src_mod = &self.instances[src_idx].module;
                let new_idx =
                    instance_utils::copy_function_from_module(&mut module, src_mod, func_idx);
                if seg_idx < module.element_segments.len()
                    && item_idx < module.element_segments[seg_idx].func_indices.len()
                {
                    module.element_segments[seg_idx].func_indices[item_idx] = new_idx;
                    // Update the item expression bytes to use ref.func with the
                    // new function index, so eval_gc_elem_exprs produces the
                    // correct value when it re-evaluates.
                    if item_idx < module.element_segments[seg_idx].item_expr_bytes.len() {
                        let mut new_bytes = Vec::new();
                        new_bytes.push(0xD2); // ref.func
                                              // LEB128-encode the function index
                        let mut v = new_idx;
                        loop {
                            let byte = (v & 0x7F) as u8;
                            v >>= 7;
                            if v == 0 {
                                new_bytes.push(byte);
                                break;
                            }
                            new_bytes.push(byte | 0x80);
                        }
                        new_bytes.push(0x0B); // end
                        module.element_segments[seg_idx].item_expr_bytes[item_idx] = new_bytes;
                    }
                }
            }
        }

        // 5. Resolve memory imports (owned copies)
        let memory_import_info: Vec<(usize, String, String)> = {
            let raw = collect_memory_imports(&module);
            raw.into_iter()
                .map(|(idx, mn, fn_)| {
                    (
                        idx,
                        String::from(core::str::from_utf8(mn).unwrap_or("")),
                        String::from(core::str::from_utf8(fn_).unwrap_or("")),
                    )
                })
                .collect()
        };

        let mut resolved_memories = Vec::new();
        let mut memory_sources: Vec<(usize, usize)> = Vec::new(); // (src_idx, src_mem_idx)
        for (mem_idx, mod_name, fld_name) in &memory_import_info {
            if let Some(ExternVal::Memory(src_idx, src_mem_idx)) =
                self.linker.resolve_str(mod_name, fld_name)
            {
                let src_idx = *src_idx;
                let src_mem_idx = *src_mem_idx as usize;
                if let Some(src_inst) = self.instances.get(src_idx) {
                    let src_mem_defs = src_inst.module.get_memories();
                    let actual_pages = src_inst
                        .get_memory_size(src_mem_idx)
                        .map(|sz| (sz / 65536) as u32)
                        .unwrap_or(0);
                    let actual_max = src_mem_defs.get(src_mem_idx).and_then(|m| {
                        if m.has_max {
                            Some(m.max_pages)
                        } else {
                            None
                        }
                    });
                    resolved_memories.push(ResolvedMemory {
                        mem_idx: *mem_idx,
                        actual_min_pages: actual_pages,
                        actual_max_pages: actual_max,
                    });
                    memory_sources.push((src_idx, src_mem_idx));
                }
            }
        }
        apply_imported_memories(&mut module, &resolved_memories);

        // 6. Resolve table imports (owned copies)
        let table_import_info: Vec<(usize, String, String)> = {
            let raw = collect_table_imports(&module);
            raw.into_iter()
                .map(|(idx, mn, fn_)| {
                    (
                        idx,
                        String::from(core::str::from_utf8(mn).unwrap_or("")),
                        String::from(core::str::from_utf8(fn_).unwrap_or("")),
                    )
                })
                .collect()
        };

        let mut resolved_tables = Vec::new();
        let mut table_sources: Vec<(usize, usize)> = Vec::new();
        for (tbl_idx, mod_name, fld_name) in &table_import_info {
            if let Some(ExternVal::Table(src_idx, src_tbl_idx)) =
                self.linker.resolve_str(mod_name, fld_name)
            {
                let src_idx = *src_idx;
                let src_tbl_idx = *src_tbl_idx as usize;
                if let Some(src_inst) = self.instances.get(src_idx) {
                    let actual_min = src_inst
                        .get_table(src_tbl_idx)
                        .map(|t| t.len() as u32)
                        .unwrap_or(0);
                    resolved_tables.push(ResolvedTable {
                        table_idx: *tbl_idx,
                        actual_min,
                    });
                    table_sources.push((src_idx, src_tbl_idx));
                }
            }
        }
        apply_imported_tables(&mut module, &resolved_tables);

        // 7. (Validation done in step 0 above.)

        // Save data/element segment info for partial application on failure.
        let data_segs: Vec<_> = module
            .get_data_segments()
            .iter()
            .map(|seg| {
                (
                    seg.is_active,
                    seg.memory_idx,
                    seg.offset,
                    seg.data_offset,
                    seg.data_len,
                )
            })
            .collect();
        let code_copy = module.get_code().to_vec();
        let elem_segs: Vec<_> = module
            .get_element_segments()
            .iter()
            .map(|seg| {
                (
                    seg.mode,
                    seg.table_idx,
                    seg.offset,
                    seg.func_indices.clone(),
                )
            })
            .collect();
        // Save function definitions for cross-module resolution on failure
        let saved_functions = module.functions.clone();
        let saved_func_types = module.func_types.clone();
        let saved_import_count = module.func_import_count();
        let saved_imports = module.imports.clone();
        let saved_names = module.get_names().to_vec();

        // 8. Create the WasmInstance
        let instance = match WasmInstance::with_config(module, self.engine.config()) {
            Ok(inst) => inst,
            Err(err) => {
                // On instantiation failure (e.g., OOB data/element segments),
                // apply partial segments to shared memory/tables before returning.
                self.apply_partial_segments_on_failure_v2(
                    &data_segs,
                    &code_copy,
                    &elem_segs,
                    &memory_sources,
                    &table_sources,
                    &memory_import_info,
                    &table_import_info,
                    &saved_functions,
                    &saved_func_types,
                    saved_import_count,
                    &saved_imports,
                    &saved_names,
                );
                return Err(err);
            }
        };
        let new_idx = self.instances.len();
        self.instances.push(instance);

        // 9. Copy memory data from exporters
        for (i, &(src_idx, src_mem_idx)) in memory_sources.iter().enumerate() {
            let imp_mem_idx = if i < memory_import_info.len() {
                memory_import_info[i].0
            } else {
                i
            };
            // Use split borrows to access src and dst simultaneously
            if src_idx < new_idx {
                let (left, right) = self.instances.split_at_mut(new_idx);
                let src = &left[src_idx];
                let dst = &mut right[0];

                if let (Some(src_mem), Some(src_size)) = (
                    src.get_memory(src_mem_idx),
                    src.get_memory_size(src_mem_idx),
                ) {
                    let dst_size_ref = dst.get_memory_size(imp_mem_idx).unwrap_or(0);
                    if let Some(dst_mem) = dst.get_memory_mut(imp_mem_idx) {
                        if src_size > 0 {
                            if dst_mem.len() < src_size {
                                dst_mem.resize(src_size, 0);
                            }
                            let copy_len = src_size.min(src_mem.len()).min(dst_mem.len());
                            dst_mem[..copy_len].copy_from_slice(&src_mem[..copy_len]);
                            if dst_size_ref < src_size {
                                dst.set_memory_size(imp_mem_idx, src_size);
                            }
                        }
                    }
                }

                // Re-apply importer's active data segments for this memory
                {
                    let dst = &mut self.instances[new_idx];
                    let segs: Vec<(usize, usize, usize)> = dst
                        .module
                        .get_data_segments()
                        .iter()
                        .filter(|seg| seg.is_active && seg.memory_idx as usize == imp_mem_idx)
                        .map(|seg| (seg.offset as usize, seg.data_offset, seg.data_len))
                        .collect();
                    let dst_size = dst.get_memory_size(imp_mem_idx).unwrap_or(0);
                    for (dst_start, data_off, data_len) in segs {
                        if dst_start.saturating_add(data_len) <= dst_size
                            && data_off.saturating_add(data_len) <= dst.module.get_code().len()
                        {
                            let code_bytes =
                                dst.module.get_code()[data_off..data_off + data_len].to_vec();
                            if let Some(dst_mem) = dst.get_memory_mut(imp_mem_idx) {
                                dst_mem[dst_start..dst_start + data_len]
                                    .copy_from_slice(&code_bytes);
                            }
                        }
                    }
                }

                // Copy back to exporter so both share the same state
                if src_idx < new_idx {
                    let (left, right) = self.instances.split_at_mut(new_idx);
                    let src = &mut left[src_idx];
                    let dst = &right[0];
                    let imp_size = dst.get_memory_size(imp_mem_idx).unwrap_or(0);
                    let exp_size = src.get_memory_size(src_mem_idx).unwrap_or(0);
                    let max_size = imp_size.max(exp_size);
                    if max_size > 0 {
                        if let Some(src_mem) = src.get_memory_mut(src_mem_idx) {
                            if src_mem.len() < max_size {
                                src_mem.resize(max_size, 0);
                            }
                            if let Some(imp_mem) = dst.get_memory(imp_mem_idx) {
                                let copy_len = max_size.min(imp_mem.len()).min(src_mem.len());
                                src_mem[..copy_len].copy_from_slice(&imp_mem[..copy_len]);
                            }
                            src.set_memory_size(src_mem_idx, max_size);
                        }
                    }
                }

                // Track memory share
                self.memory_shares.push(MemoryShare {
                    importer_idx: new_idx,
                    importer_mem: imp_mem_idx,
                    exporter_idx: src_idx,
                    exporter_mem: src_mem_idx,
                });
            }
        }

        // Copy table data from exporters with cross-module function index translation
        for (i, &(src_idx, src_tbl_idx)) in table_sources.iter().enumerate() {
            let imp_tbl_idx = if i < table_import_info.len() {
                table_import_info[i].0
            } else {
                i
            };
            if src_idx < new_idx {
                // 1. Read the exporter's table entries
                let src_data: Vec<Option<u32>> = {
                    let src = &self.instances[src_idx];
                    src.get_table(src_tbl_idx)
                        .map(|t| t.to_vec())
                        .unwrap_or_default()
                };

                // 2. Translate each exporter function index → importer's space
                let mut translated = Vec::with_capacity(src_data.len());
                for entry in &src_data {
                    match entry {
                        Some(func_idx) => {
                            let new_idx_val =
                                self.resolve_cross_module_function(src_idx, *func_idx, new_idx);
                            translated.push(Some(new_idx_val));
                        }
                        None => translated.push(None),
                    }
                }

                // 3. Write translated table to importer
                {
                    let dst = &mut self.instances[new_idx];
                    if let Some(dst_table) = dst.get_table_mut(imp_tbl_idx) {
                        if dst_table.len() < translated.len() {
                            dst_table.resize(translated.len(), None);
                        }
                        for (j, val) in translated.iter().enumerate() {
                            if j < dst_table.len() {
                                dst_table[j] = *val;
                            }
                        }
                    }
                }

                // 4. Re-apply importer's active element segments for this table
                {
                    let dst = &mut self.instances[new_idx];
                    let segs: Vec<(usize, Vec<u32>)> = {
                        use crate::decoder::ElemMode;
                        dst.module
                            .get_element_segments()
                            .iter()
                            .filter(|s| {
                                s.mode == ElemMode::Active && s.table_idx as usize == imp_tbl_idx
                            })
                            .map(|s| (s.offset as usize, s.func_indices.clone()))
                            .collect()
                    };
                    for (offset, func_indices) in &segs {
                        if let Some(tbl) = dst.get_table_mut(imp_tbl_idx) {
                            for (j, &fi) in func_indices.iter().enumerate() {
                                let pos = offset + j;
                                if pos < tbl.len() {
                                    tbl[pos] = if fi == u32::MAX { None } else { Some(fi) };
                                }
                            }
                        }
                    }
                }

                // 5. Copy back to exporter: translate importer's element positions
                //    to exporter's function index space
                {
                    let imp_table: Vec<Option<u32>> = self.instances[new_idx]
                        .get_table(imp_tbl_idx)
                        .map(|t| t.to_vec())
                        .unwrap_or_default();

                    // Collect positions that the importer's element segments wrote to
                    let mut importer_positions = alloc::collections::BTreeSet::new();
                    {
                        use crate::decoder::ElemMode;
                        let dst = &self.instances[new_idx];
                        for seg in dst.module.get_element_segments().iter() {
                            if seg.mode == ElemMode::Active && seg.table_idx as usize == imp_tbl_idx
                            {
                                let off = seg.offset as usize;
                                for j in 0..seg.func_indices.len() {
                                    importer_positions.insert(off + j);
                                }
                            }
                        }
                    }

                    // Translate importer positions back to exporter's space
                    let mut exp_table: Vec<Option<u32>> = self.instances[src_idx]
                        .get_table(src_tbl_idx)
                        .map(|t| t.to_vec())
                        .unwrap_or_default();

                    if exp_table.len() < imp_table.len() {
                        exp_table.resize(imp_table.len(), None);
                    }

                    for &pos in &importer_positions {
                        if pos < imp_table.len() {
                            match imp_table[pos] {
                                Some(func_idx) => {
                                    let resolved = self
                                        .resolve_cross_module_function(new_idx, func_idx, src_idx);
                                    exp_table[pos] = Some(resolved);
                                }
                                None => {
                                    exp_table[pos] = None;
                                }
                            }
                        }
                    }

                    // Write back to exporter
                    if let Some(tbl) = self.instances[src_idx].get_table_mut(src_tbl_idx) {
                        let copy_len = exp_table.len().min(tbl.len());
                        tbl[..copy_len].copy_from_slice(&exp_table[..copy_len]);
                        if exp_table.len() > tbl.len() {
                            tbl.resize(exp_table.len(), None);
                            tbl[copy_len..].copy_from_slice(&exp_table[copy_len..]);
                        }
                    }
                }
            }
        }

        // 9b. Set up table aliases when multiple imports resolve to the same source table
        {
            let mut seen: Vec<(usize, usize, usize)> = Vec::new(); // (src_idx, src_tbl_idx, imp_tbl_idx)
            for (i, &(src_idx, src_tbl_idx)) in table_sources.iter().enumerate() {
                let imp_tbl_idx = if i < table_import_info.len() {
                    table_import_info[i].0
                } else {
                    i
                };
                // Check if we already have an import pointing to the same source table
                if let Some((_, _, first_imp_idx)) = seen
                    .iter()
                    .find(|(si, sti, _)| *si == src_idx && *sti == src_tbl_idx)
                {
                    // Alias this table to the first one
                    if let Some(inst) = self.instances.get_mut(new_idx) {
                        let aliases = inst.table_aliases_mut();
                        if imp_tbl_idx < aliases.len() {
                            aliases[imp_tbl_idx] = Some(*first_imp_idx);
                        }
                    }
                } else {
                    seen.push((src_idx, src_tbl_idx, imp_tbl_idx));
                }
            }
        }

        // 9c. Set up global aliases for duplicate global imports
        {
            let mut seen: Vec<(usize, usize, usize)> = Vec::new();
            for (i, (_, _, mod_name, fld_name)) in global_import_info.iter().enumerate() {
                if let Some(ExternVal::Global(src_idx, global_idx)) =
                    self.linker.resolve_str(mod_name, fld_name)
                {
                    if let Some((_, _, first_imp_idx)) = seen
                        .iter()
                        .find(|(si, sgi, _)| *si == *src_idx && *sgi == *global_idx as usize)
                    {
                        if let Some(inst) = self.instances.get_mut(new_idx) {
                            let aliases = inst.global_aliases_mut();
                            if i < aliases.len() {
                                aliases[i] = Some(*first_imp_idx);
                            }
                        }
                    } else {
                        seen.push((*src_idx, *global_idx as usize, i));
                    }
                }
            }
        }

        // 9d. Set up memory aliases for duplicate memory imports
        // After aliasing, merge data from aliased memories into the target
        {
            let mut seen: Vec<(usize, usize, usize)> = Vec::new();
            for (i, &(src_idx, src_mem_idx)) in memory_sources.iter().enumerate() {
                let imp_mem_idx = if i < memory_import_info.len() {
                    memory_import_info[i].0
                } else {
                    i
                };
                if let Some((_, _, first_imp_idx)) = seen
                    .iter()
                    .find(|(si, smi, _)| *si == src_idx && *smi == src_mem_idx)
                {
                    let first_imp_idx = *first_imp_idx;
                    // Before aliasing, copy any data from this memory to the first one
                    // (data segments may have written to this memory)
                    if let Some(inst) = self.instances.get_mut(new_idx) {
                        let this_size = inst.get_memory_size(imp_mem_idx).unwrap_or(0);
                        if this_size > 0 {
                            let first_size = inst.get_memory_size(first_imp_idx).unwrap_or(0);
                            // Copy non-zero bytes from this memory to the first one
                            let this_data: Vec<u8> = inst
                                .get_memory(imp_mem_idx)
                                .map(|m| m[..this_size].to_vec())
                                .unwrap_or_default();
                            if let Some(first_mem) = inst.get_memory_mut(first_imp_idx) {
                                if first_mem.len() < this_size {
                                    first_mem.resize(this_size, 0);
                                }
                                // Merge: only copy non-zero bytes (data segments write)
                                for (j, &b) in this_data.iter().enumerate() {
                                    if b != 0 && j < first_mem.len() {
                                        first_mem[j] = b;
                                    }
                                }
                            }
                            // Also update the first memory's size if needed
                            if this_size > first_size {
                                inst.set_memory_size(first_imp_idx, this_size);
                            }
                        }
                        let aliases = inst.memory_aliases_mut();
                        if imp_mem_idx < aliases.len() {
                            aliases[imp_mem_idx] = Some(first_imp_idx);
                        }
                    }
                } else {
                    seen.push((src_idx, src_mem_idx, imp_mem_idx));
                }
            }
        }

        // 10. Track global shares for mutable imported globals
        for (i, (_, mutable, mod_name, fld_name)) in global_import_info.iter().enumerate() {
            if !mutable {
                continue;
            }
            if let Some(ExternVal::Global(src_idx, global_idx)) =
                self.linker.resolve_str(mod_name, fld_name)
            {
                self.global_shares.push(GlobalShare {
                    importer_idx: new_idx,
                    importer_global: i,
                    exporter_idx: *src_idx,
                    exporter_global: *global_idx as usize,
                });
            }
        }

        // 11. Run start function
        {
            let inst = &mut self.instances[new_idx];
            let start_result = inst.run_start();
            match start_result {
                ExecResult::Ok | ExecResult::Returned(_) => {}
                ExecResult::HostCall(func_idx, ref args, arg_count) => {
                    // Handle host calls during start
                    let result = self.dispatch_host_call_loop(new_idx, func_idx, args, arg_count);
                    match result {
                        ExecResult::Ok | ExecResult::Returned(_) => {}
                        ExecResult::Trap(e) => return Err(e),
                        _ => {}
                    }
                }
                ExecResult::Trap(e) => return Err(e),
                ExecResult::OutOfFuel => return Err(WasmError::OutOfFuel),
                ExecResult::Exception(tag, vals) => {
                    let _ = (tag, vals);
                    return Err(WasmError::UncaughtException);
                }
            }
        }

        // 12. Register instance + exports in linker
        if let Some(n) = name {
            // Get module ref before registering to avoid borrow issues
            let module_ref = &self.instances[new_idx].module;
            // Collect export info
            let mut export_info = Vec::new();
            for export in module_ref.get_exports() {
                let field_name =
                    core::str::from_utf8(module_ref.get_name(export.name_offset, export.name_len))
                        .unwrap_or("");
                export_info.push((String::from(field_name), export.kind));
            }
            self.names.insert(String::from(n), new_idx);
            // Register exports
            for (field_name, kind) in export_info {
                let val = match kind {
                    crate::decoder::ExportKind::Func(idx) => ExternVal::Func(new_idx, idx),
                    crate::decoder::ExportKind::Global(idx) => ExternVal::Global(new_idx, idx),
                    crate::decoder::ExportKind::Memory(idx) => ExternVal::Memory(new_idx, idx),
                    crate::decoder::ExportKind::Table(idx) => ExternVal::Table(new_idx, idx),
                    crate::decoder::ExportKind::Tag(idx) => ExternVal::Tag(new_idx, idx),
                };
                self.linker.define(n, &field_name, val);
            }
        }

        Ok(new_idx)
    }

    /// Register an existing instance under a name.
    pub fn register(&mut self, name: &str, idx: usize) {
        if idx < self.instances.len() {
            self.names.insert(String::from(name), idx);
            // Register all exports
            let module_ref = &self.instances[idx].module;
            let mut export_info = Vec::new();
            for export in module_ref.get_exports() {
                let field_name =
                    core::str::from_utf8(module_ref.get_name(export.name_offset, export.name_len))
                        .unwrap_or("");
                export_info.push((String::from(field_name), export.kind));
            }
            for (field_name, kind) in export_info {
                let val = match kind {
                    crate::decoder::ExportKind::Func(fi) => ExternVal::Func(idx, fi),
                    crate::decoder::ExportKind::Global(gi) => ExternVal::Global(idx, gi),
                    crate::decoder::ExportKind::Memory(mi) => ExternVal::Memory(idx, mi),
                    crate::decoder::ExportKind::Table(ti) => ExternVal::Table(idx, ti),
                    crate::decoder::ExportKind::Tag(tgi) => ExternVal::Tag(idx, tgi),
                };
                self.linker.define(name, &field_name, val);
            }
        }
    }

    /// Get a reference to an instance by index.
    pub fn instance(&self, idx: usize) -> Option<&WasmInstance> {
        self.instances.get(idx)
    }

    /// Get a mutable reference to an instance by index.
    pub fn instance_mut(&mut self, idx: usize) -> Option<&mut WasmInstance> {
        self.instances.get_mut(idx)
    }

    /// Look up an instance index by name.
    pub fn lookup(&self, name: &str) -> Option<usize> {
        self.names.get(name).copied()
    }

    /// Apply partial data/element segments from a failed module instantiation
    /// to shared (exporter) memories and tables.
    /// Uses pre-saved segment info since the module has been consumed.
    fn apply_partial_segments_on_failure_v2(
        &mut self,
        data_segs: &[(bool, u32, u32, usize, usize)], // (is_active, mem_idx, offset, data_offset, data_len)
        code: &[u8],                                  // module code bytes for data content
        elem_segs: &[(crate::decoder::ElemMode, u32, u32, Vec<u32>)], // (mode, table_idx, offset, func_indices)
        memory_sources: &[(usize, usize)],
        table_sources: &[(usize, usize)],
        memory_import_info: &[(usize, String, String)],
        table_import_info: &[(usize, String, String)],
        saved_functions: &[crate::decoder::FuncDef],
        saved_func_types: &[crate::decoder::FuncTypeDef],
        saved_import_count: usize,
        saved_imports: &[crate::decoder::ImportDef],
        saved_names: &[u8],
    ) {
        // Apply partial data segments to exporter memories
        for &(is_active, mem_idx, offset, data_off, data_len) in data_segs {
            if !is_active {
                continue;
            }
            let imp_mem_idx = mem_idx as usize;
            let source = memory_sources
                .iter()
                .zip(memory_import_info.iter())
                .find(|(&(_, _), (idx, _, _))| *idx == imp_mem_idx);
            if let Some((&(src_idx, src_mem_idx), _)) = source {
                if let Some(src_inst) = self.instances.get_mut(src_idx) {
                    let mem_size = src_inst.get_memory_size(src_mem_idx).unwrap_or(0);
                    let dst_start = offset as usize;
                    if dst_start.saturating_add(data_len) > mem_size {
                        break; // OOB: stop at first failing segment
                    }
                    if data_off.saturating_add(data_len) <= code.len() {
                        if let Some(mem) = src_inst.get_memory_mut(src_mem_idx) {
                            mem[dst_start..dst_start + data_len]
                                .copy_from_slice(&code[data_off..data_off + data_len]);
                        }
                    }
                }
            } else {
                // Non-shared memory: check if OOB to know when to stop
                let dst_start = offset as usize;
                if dst_start.saturating_add(data_len) > 65536 * 65536 {
                    break;
                }
            }
        }

        // Apply partial element segments to exporter tables with function
        // index translation (copy function bodies from the failed module
        // into the exporter module).
        use crate::decoder::ElemMode;
        for (mode, table_idx, offset, func_indices) in elem_segs {
            if *mode != ElemMode::Active {
                continue;
            }
            let imp_tbl_idx = *table_idx as usize;
            let source = table_sources
                .iter()
                .zip(table_import_info.iter())
                .find(|(&(_, _), (idx, _, _))| *idx == imp_tbl_idx);
            if let Some((&(src_idx, src_tbl_idx), _)) = source {
                let tbl_len = self
                    .instances
                    .get(src_idx)
                    .and_then(|inst| inst.get_table(src_tbl_idx).map(|t| t.len()))
                    .unwrap_or(0);
                let off = *offset as usize;
                let count = func_indices.len();
                if off.saturating_add(count) > tbl_len {
                    break; // OOB: stop
                }

                // Translate each function index from failed module's space
                // to the exporter's space
                let mut translated = Vec::with_capacity(count);
                for &fi in func_indices {
                    if fi == u32::MAX {
                        translated.push(None);
                    } else {
                        let resolved = Self::resolve_failed_module_func(
                            &mut self.instances[src_idx].module,
                            fi,
                            saved_functions,
                            saved_func_types,
                            saved_import_count,
                            saved_imports,
                            saved_names,
                            code,
                        );
                        translated.push(Some(resolved));
                    }
                }

                if let Some(tbl) = self.instances[src_idx].get_table_mut(src_tbl_idx) {
                    for (i, val) in translated.iter().enumerate() {
                        tbl[off + i] = *val;
                    }
                }
            }
        }
    }

    /// Resolve a function index from a failed (non-existent) module's space
    /// into a destination module's space by copying the function body.
    fn resolve_failed_module_func(
        dst_module: &mut WasmModule,
        func_idx: u32,
        saved_functions: &[crate::decoder::FuncDef],
        saved_func_types: &[crate::decoder::FuncTypeDef],
        saved_import_count: usize,
        saved_imports: &[crate::decoder::ImportDef],
        saved_names: &[u8],
        code: &[u8],
    ) -> u32 {
        if (func_idx as usize) < saved_import_count {
            // The function is an import in the failed module. Try to find it in dst.
            let mut func_seen = 0u32;
            for imp in saved_imports {
                if let ImportKind::Func(_) = imp.kind {
                    if func_seen == func_idx {
                        // Try to find this export in dst_module
                        let end = imp
                            .field_name_offset
                            .saturating_add(imp.field_name_len)
                            .min(saved_names.len());
                        let start = imp.field_name_offset.min(end);
                        let fld_name_bytes = &saved_names[start..end];
                        if let Some(dst_func_idx) = dst_module.find_export_func(fld_name_bytes) {
                            return dst_func_idx;
                        }
                        return func_idx;
                    }
                    func_seen += 1;
                }
            }
            return func_idx;
        }

        // Local function: copy the function body into dst_module
        let local_idx = (func_idx as usize) - saved_import_count;
        if local_idx >= saved_functions.len() {
            return func_idx;
        }

        let src_func = &saved_functions[local_idx];
        let source_ft = if (src_func.type_idx as usize) < saved_func_types.len() {
            saved_func_types[src_func.type_idx as usize].clone()
        } else {
            crate::decoder::FuncTypeDef::empty()
        };

        let host_type_idx = instance_utils::find_or_add_func_type(dst_module, &source_ft);
        let host_code_offset = dst_module.code.len();
        let code_start = src_func.code_offset;
        let code_len = src_func.code_len;
        if code_start + code_len <= code.len() {
            dst_module
                .code
                .extend_from_slice(&code[code_start..code_start + code_len]);
        }
        dst_module.functions.push(crate::decoder::FuncDef {
            type_idx: host_type_idx,
            code_offset: host_code_offset,
            code_len,
            local_count: src_func.local_count,
            locals: src_func.locals,
            non_nullable_locals: Vec::new(),
        });

        dst_module.func_import_count() as u32 + (dst_module.functions.len() as u32 - 1)
    }

    /// Validate imports using actual runtime sizes for memory and table bounds.
    ///
    /// Unlike `Linker::validate_imports` which only checks module declarations,
    /// this method accounts for runtime growth (e.g., memory.grow).
    fn validate_imports_with_runtime(&self, module: &WasmModule) -> Result<(), WasmError> {
        let mut mem_import_idx = 0usize;
        let mut table_import_idx = 0usize;
        for import in module.get_imports() {
            let mod_name = module.get_name(import.module_name_offset, import.module_name_len);
            let fld_name = module.get_name(import.field_name_offset, import.field_name_len);

            let ext = match self.linker.resolve(mod_name, fld_name) {
                Some(e) => e,
                None => return Err(WasmError::ImportNotFound(0)),
            };

            match (&import.kind, ext) {
                (ImportKind::Func(type_idx), ExternVal::Host(_)) => {
                    let _ = type_idx;
                }
                (ImportKind::Func(type_idx), ExternVal::Func(src_idx, src_func_idx)) => {
                    if let Some(src_inst) = self.instances.get(*src_idx) {
                        let src_module = &src_inst.module;
                        if let Some(src_type_idx) =
                            crate::instance_utils::function_type_idx(src_module, *src_func_idx)
                        {
                            // When both modules have sub_type info (GC-enabled),
                            // use rec-group-aware type equivalence/subtyping.
                            let has_sub_types =
                                !module.sub_types.is_empty() && !src_module.sub_types.is_empty();
                            let compatible = if has_sub_types {
                                linker_utils::cross_module_type_subtype(
                                    src_module,
                                    src_type_idx,
                                    module,
                                    *type_idx,
                                )
                            } else {
                                linker_utils::func_types_match(
                                    &module.get_func_types()[*type_idx as usize],
                                    &src_module.get_func_types()[src_type_idx as usize],
                                ) || linker_utils::cross_module_type_subtype(
                                    src_module,
                                    src_type_idx,
                                    module,
                                    *type_idx,
                                )
                            };
                            if !compatible {
                                return Err(WasmError::TypeMismatch);
                            }
                        }
                    }
                }
                (
                    ImportKind::Global(val_type_byte, mutable, heap_type),
                    ExternVal::Global(src_idx, global_idx),
                ) => {
                    if let Some(src_inst) = self.instances.get(*src_idx) {
                        let src_module = &src_inst.module;
                        if let Some(src_global) = src_module.get_globals().get(*global_idx as usize)
                        {
                            let import_val_type = linker_utils::decode_valtype_byte(*val_type_byte)
                                .unwrap_or(crate::types::ValType::I32);
                            // Check mutability first
                            if src_global.mutable != *mutable {
                                return Err(WasmError::TypeMismatch);
                            }
                            // Direct type match for numeric types
                            if import_val_type != src_global.val_type {
                                // Try ref-type compatibility check
                                if !linker_utils::global_types_compatible(
                                    import_val_type,
                                    *val_type_byte,
                                    *heap_type,
                                    src_global.val_type,
                                    src_global.heap_type,
                                    *mutable,
                                ) {
                                    return Err(WasmError::TypeMismatch);
                                }
                            }
                        }
                    }
                }
                (ImportKind::Memory, ExternVal::Memory(src_idx, mem_idx)) => {
                    if let Some(src_inst) = self.instances.get(*src_idx) {
                        let src_module = &src_inst.module;
                        let src_mems = src_module.get_memories();
                        let imp_mems = module.get_memories();
                        if let (Some(src_mem), Some(imp_mem)) = (
                            src_mems.get(*mem_idx as usize),
                            imp_mems.get(mem_import_idx),
                        ) {
                            // Check shared flag
                            if imp_mem.is_shared != src_mem.is_shared {
                                return Err(WasmError::TypeMismatch);
                            }
                            // Check memory64 flag
                            if imp_mem.is_memory64 != src_mem.is_memory64 {
                                return Err(WasmError::TypeMismatch);
                            }
                            // Check page_size
                            if imp_mem.page_size_log2 != src_mem.page_size_log2 {
                                return Err(WasmError::TypeMismatch);
                            }
                            // Check min pages using ACTUAL runtime size
                            let page_size = match src_mem.page_size_log2 {
                                Some(log2) => 1usize << log2,
                                None => 65536,
                            };
                            let actual_pages = src_inst
                                .get_memory_size(*mem_idx as usize)
                                .map(|sz| {
                                    if page_size > 0 {
                                        (sz / page_size) as u32
                                    } else {
                                        0
                                    }
                                })
                                .unwrap_or(src_mem.min_pages);
                            let available_min = actual_pages.max(src_mem.min_pages);
                            if available_min < imp_mem.min_pages {
                                return Err(WasmError::TypeMismatch);
                            }
                            // Check max pages
                            if imp_mem.has_max
                                && (!src_mem.has_max || src_mem.max_pages > imp_mem.max_pages)
                            {
                                return Err(WasmError::TypeMismatch);
                            }
                        }
                    }
                    mem_import_idx += 1;
                }
                (ImportKind::Table(elem_type), ExternVal::Table(src_idx, table_idx)) => {
                    if let Some(src_inst) = self.instances.get(*src_idx) {
                        let src_module = &src_inst.module;
                        let src_tables = src_module.get_tables();
                        if let Some(src_table) = src_tables.get(*table_idx as usize) {
                            // Table element types must match exactly (tables are mutable,
                            // so both covariance and contravariance apply → invariance).
                            if *elem_type != src_table.elem_type {
                                return Err(WasmError::TypeMismatch);
                            }
                            let imp_tables = module.get_tables();
                            if let Some(imp_table) = imp_tables.get(table_import_idx) {
                                if imp_table.is_table64 != src_table.is_table64 {
                                    return Err(WasmError::TypeMismatch);
                                }
                                // Use actual runtime table size
                                let actual_min = src_inst
                                    .get_table(*table_idx as usize)
                                    .map(|t| t.len() as u32)
                                    .unwrap_or(src_table.min);
                                let available_min = actual_min.max(src_table.min);
                                if available_min < imp_table.min {
                                    return Err(WasmError::TypeMismatch);
                                }
                                if let Some(imp_max) = imp_table.max {
                                    match src_table.max {
                                        Some(src_max) if src_max <= imp_max => {}
                                        _ => {
                                            return Err(WasmError::TypeMismatch);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    table_import_idx += 1;
                }
                (ImportKind::Tag(imp_type_idx), ExternVal::Tag(src_idx, tag_idx)) => {
                    // Validate tag type compatibility
                    if let Some(src_inst) = self.instances.get(*src_idx) {
                        let src_module = &src_inst.module;
                        let src_tag_types = src_module.get_tag_types();
                        if let Some(&src_type_idx) = src_tag_types.get(*tag_idx as usize) {
                            // Use rec-group-aware type equivalence when available
                            let has_sub_types =
                                !module.sub_types.is_empty() && !src_module.sub_types.is_empty();
                            let compatible = if has_sub_types {
                                // Tags require exact type match (not subtyping)
                                linker_utils::type_indices_equivalent(
                                    src_module,
                                    src_type_idx,
                                    module,
                                    *imp_type_idx,
                                )
                            } else {
                                let imp_types = module.get_func_types();
                                let src_types = src_module.get_func_types();
                                match (
                                    imp_types.get(*imp_type_idx as usize),
                                    src_types.get(src_type_idx as usize),
                                ) {
                                    (Some(imp_ft), Some(src_ft)) => {
                                        linker_utils::func_types_match(imp_ft, src_ft)
                                    }
                                    _ => false,
                                }
                            };
                            if !compatible {
                                return Err(WasmError::TypeMismatch);
                            }
                        }
                    }
                }
                _ => return Err(WasmError::TypeMismatch),
            }
        }
        Ok(())
    }

    /// Call a function on an instance with automatic sync and cross-module dispatch.
    pub fn call(&mut self, idx: usize, func_name: &str, args: &[Value]) -> ExecResult {
        // Find the function index
        let func_idx = {
            let inst = match self.instances.get(idx) {
                Some(i) => i,
                None => return ExecResult::Trap(WasmError::FunctionNotFound(0)),
            };
            match inst.module.find_export_func(func_name.as_bytes()) {
                Some(fi) => fi,
                None => return ExecResult::Trap(WasmError::FunctionNotFound(0)),
            }
        };

        // 1. Sync imported globals into this instance
        self.sync_imported_globals(idx);

        // 2. Reset stack and call the function
        self.instances[idx].reset_stack_ptr();
        let result = self.instances[idx].call_func(func_idx, args);

        // 3. Handle host calls and cross-module calls in a loop
        let result = match result {
            ExecResult::HostCall(hc_func_idx, ref hc_args, hc_count) => {
                self.dispatch_host_call_loop(idx, hc_func_idx, hc_args, hc_count)
            }
            other => other,
        };

        // 4. Sync globals back
        self.sync_globals_back(idx);

        // 5. Sync shared memory
        self.sync_shared_memory();

        result
    }

    /// Read an exported global value, syncing shared globals first.
    pub fn get_global(&mut self, idx: usize, name: &str) -> Option<Value> {
        // Sync imported globals so we read the latest value from exporters
        self.sync_imported_globals(idx);
        let inst = self.instances.get(idx)?;
        let global_idx = instance_utils::exported_global_index(&inst.module, name)?;
        inst.get_global(global_idx as usize)
    }

    /// Debug: get the last instantiated module's element segment func_indices (for testing).
    #[cfg(feature = "spec-test-internals")]
    pub fn debug_last_elem_func_indices(
        &self,
        idx: usize,
    ) -> Option<alloc::vec::Vec<alloc::vec::Vec<u32>>> {
        let inst = self.instances.get(idx)?;
        Some(
            inst.module
                .element_segments
                .iter()
                .map(|seg| seg.func_indices.clone())
                .collect(),
        )
    }

    /// Get a reference to the engine.
    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    /// Get the number of instances in the store.
    pub fn instance_count(&self) -> usize {
        self.instances.len()
    }

    // ── Internal dispatch ────────────────────────────────────────────────

    /// Handle a HostCall result, dispatching to host functions or cross-module
    /// WASM calls, and resuming the caller in a loop until completion.
    fn dispatch_host_call_loop(
        &mut self,
        caller_idx: usize,
        func_idx: u32,
        args: &[Value; crate::types::MAX_PARAMS],
        arg_count: u8,
    ) -> ExecResult {
        let mut current_func_idx = func_idx;
        let mut current_args_buf = *args;
        let mut current_count = arg_count;

        loop {
            let call_args = &current_args_buf[..current_count as usize];

            // Resolve the import to see if it's a host func or cross-module WASM func
            let resolution = self.resolve_import(caller_idx, current_func_idx);

            match resolution {
                Some(ImportResolution::Host(binding_idx)) => {
                    // Dispatch to host function
                    let result = self.linker.dispatch_host(
                        &mut self.instances[caller_idx],
                        binding_idx,
                        call_args,
                    );
                    match result {
                        Ok(ret) => {
                            let resumed = self.instances[caller_idx].resume(ret);
                            match resumed {
                                ExecResult::Ok => {
                                    if self.instances[caller_idx].is_finished() {
                                        return ExecResult::Ok;
                                    }
                                    // Need to continue running
                                    let run_result = self.instances[caller_idx].run();
                                    match run_result {
                                        ExecResult::HostCall(f, ref a, c) => {
                                            current_func_idx = f;
                                            current_args_buf = *a;
                                            current_count = c;
                                            continue;
                                        }
                                        other => return other,
                                    }
                                }
                                ExecResult::HostCall(f, ref a, c) => {
                                    current_func_idx = f;
                                    current_args_buf = *a;
                                    current_count = c;
                                    continue;
                                }
                                other => return other,
                            }
                        }
                        Err(e) => return ExecResult::Trap(e),
                    }
                }
                Some(ImportResolution::Wasm(target_idx, target_func_idx)) => {
                    // Cross-module call: sync globals, call target, sync back
                    self.sync_globals_back(caller_idx);
                    self.sync_shared_memory();
                    self.sync_imported_globals(target_idx);

                    let target_result =
                        self.instances[target_idx].call_func(target_func_idx, call_args);

                    // Handle host calls from the target module
                    let target_result = match target_result {
                        ExecResult::HostCall(f, ref a, c) => {
                            self.dispatch_host_call_loop(target_idx, f, a, c)
                        }
                        other => other,
                    };

                    self.sync_globals_back(target_idx);
                    self.sync_shared_memory();
                    self.sync_imported_globals(caller_idx);

                    // Extract return value or exception
                    let ret_val = match target_result {
                        ExecResult::Ok => None,
                        ExecResult::Returned(v) => Some(v),
                        ExecResult::Trap(e) => return ExecResult::Trap(e),
                        ExecResult::OutOfFuel => return ExecResult::OutOfFuel,
                        ExecResult::Exception(tag, vals) => {
                            // Translate the tag index from target's space to caller's space
                            // and resume the caller with the exception so its try/catch
                            // blocks can handle it.
                            let caller_tag = self.translate_tag(target_idx, tag, caller_idx);
                            let resumed =
                                self.instances[caller_idx].resume_with_exception(caller_tag, vals);
                            match resumed {
                                ExecResult::Ok => {
                                    if self.instances[caller_idx].is_finished() {
                                        return ExecResult::Ok;
                                    }
                                    let run_result = self.instances[caller_idx].run();
                                    match run_result {
                                        ExecResult::HostCall(f, ref a, c) => {
                                            current_func_idx = f;
                                            current_args_buf = *a;
                                            current_count = c;
                                            continue;
                                        }
                                        other => return other,
                                    }
                                }
                                ExecResult::HostCall(f, ref a, c) => {
                                    current_func_idx = f;
                                    current_args_buf = *a;
                                    current_count = c;
                                    continue;
                                }
                                other => return other,
                            }
                        }
                        ExecResult::HostCall(_, _, _) => {
                            // Should not happen after dispatch_host_call_loop
                            return ExecResult::Trap(WasmError::ImportNotFound(target_func_idx));
                        }
                    };

                    // Resume caller with return value
                    let resumed = self.instances[caller_idx].resume(ret_val);
                    match resumed {
                        ExecResult::Ok => {
                            if self.instances[caller_idx].is_finished() {
                                return ExecResult::Ok;
                            }
                            let run_result = self.instances[caller_idx].run();
                            match run_result {
                                ExecResult::HostCall(f, ref a, c) => {
                                    current_func_idx = f;
                                    current_args_buf = *a;
                                    current_count = c;
                                    continue;
                                }
                                other => return other,
                            }
                        }
                        ExecResult::HostCall(f, ref a, c) => {
                            current_func_idx = f;
                            current_args_buf = *a;
                            current_count = c;
                            continue;
                        }
                        other => return other,
                    }
                }
                None => {
                    // Try the old dispatch_raw path (direct linker binding lookup)
                    let result = self.linker.dispatch_raw(
                        &mut self.instances[caller_idx],
                        current_func_idx,
                        call_args,
                    );
                    match result {
                        Ok(ret) => {
                            let resumed = self.instances[caller_idx].resume(ret);
                            match resumed {
                                ExecResult::Ok => {
                                    if self.instances[caller_idx].is_finished() {
                                        return ExecResult::Ok;
                                    }
                                    let run_result = self.instances[caller_idx].run();
                                    match run_result {
                                        ExecResult::HostCall(f, ref a, c) => {
                                            current_func_idx = f;
                                            current_args_buf = *a;
                                            current_count = c;
                                            continue;
                                        }
                                        other => return other,
                                    }
                                }
                                ExecResult::HostCall(f, ref a, c) => {
                                    current_func_idx = f;
                                    current_args_buf = *a;
                                    current_count = c;
                                    continue;
                                }
                                other => return other,
                            }
                        }
                        Err(e) => return ExecResult::Trap(e),
                    }
                }
            }
        }
    }

    /// Translate a tag index from source instance's space to destination instance's space.
    ///
    /// Finds the exported identity of the tag in the source, then looks for a matching
    /// import or local tag in the destination.
    fn translate_tag(&self, src_idx: usize, src_tag: u32, dst_idx: usize) -> u32 {
        // Get the source tag's identity: (module_name, field_name) for exported tags
        let src_inst = match self.instances.get(src_idx) {
            Some(i) => i,
            None => return src_tag,
        };

        // Find which export (if any) corresponds to this tag in the source
        let mut src_export_name: Option<&[u8]> = None;
        for exp in &src_inst.module.exports {
            if let crate::decoder::ExportKind::Tag(idx) = exp.kind {
                if idx == src_tag {
                    src_export_name = Some(src_inst.module.get_name(exp.name_offset, exp.name_len));
                    break;
                }
            }
        }

        // Check if the source tag is itself an import
        let mut src_import_identity: Option<(&[u8], &[u8])> = None;
        {
            let mut tag_seen = 0u32;
            for imp in &src_inst.module.imports {
                if let ImportKind::Tag(_) = imp.kind {
                    if tag_seen == src_tag {
                        let mod_name = src_inst
                            .module
                            .get_name(imp.module_name_offset, imp.module_name_len);
                        let fld_name = src_inst
                            .module
                            .get_name(imp.field_name_offset, imp.field_name_len);
                        src_import_identity = Some((mod_name, fld_name));
                        break;
                    }
                    tag_seen += 1;
                }
            }
        }

        // Now look in the destination for a matching tag
        let dst_inst = match self.instances.get(dst_idx) {
            Some(i) => i,
            None => return src_tag,
        };

        // Check destination's tag imports
        let mut tag_seen = 0u32;
        for imp in &dst_inst.module.imports {
            if let ImportKind::Tag(_) = imp.kind {
                let mod_name = dst_inst
                    .module
                    .get_name(imp.module_name_offset, imp.module_name_len);
                let fld_name = dst_inst
                    .module
                    .get_name(imp.field_name_offset, imp.field_name_len);

                // Check if this import resolves to the same tag
                if let Some(ext) = self.linker.resolve(mod_name, fld_name) {
                    if let ExternVal::Tag(ext_idx, ext_tag) = ext {
                        if *ext_idx == src_idx && *ext_tag == src_tag {
                            return tag_seen;
                        }
                        // Also check transitively: if the src tag was an import
                        if let Some((src_mod, src_fld)) = src_import_identity {
                            if let Some(src_ext) = self.linker.resolve(src_mod, src_fld) {
                                if let ExternVal::Tag(src_ext_idx, src_ext_tag) = src_ext {
                                    if *ext_idx == *src_ext_idx && *ext_tag == *src_ext_tag {
                                        return tag_seen;
                                    }
                                }
                            }
                        }
                    }
                }
                tag_seen += 1;
            }
        }

        // If the source tag has a registered name, look it up as an export name
        // in the linker to find it in the destination
        if let Some(export_name) = src_export_name {
            // Check all registered module names to find one that maps to src_idx
            for ((mod_name, fld_name), val) in self.linker.externs_iter() {
                if let ExternVal::Tag(idx, tag_idx) = val {
                    if *idx == src_idx && *tag_idx == src_tag {
                        // Found the extern for this tag. Now check if dst imports
                        // from the same (mod_name, fld_name)
                        let mut dt_seen = 0u32;
                        for dst_imp in &dst_inst.module.imports {
                            if let ImportKind::Tag(_) = dst_imp.kind {
                                let dm = dst_inst
                                    .module
                                    .get_name(dst_imp.module_name_offset, dst_imp.module_name_len);
                                let df = dst_inst
                                    .module
                                    .get_name(dst_imp.field_name_offset, dst_imp.field_name_len);
                                if dm == mod_name.as_bytes() && df == fld_name.as_bytes() {
                                    return dt_seen;
                                }
                                dt_seen += 1;
                            }
                        }
                    }
                }
            }
            let _ = export_name;
        }

        // Fallback: return a sentinel value that won't match any catch clause.
        // Using u32::MAX ensures the exception propagates to catch_all.
        u32::MAX
    }

    /// Resolve a function import to either a host binding or a cross-module WASM function.
    fn resolve_import(&self, instance_idx: usize, func_idx: u32) -> Option<ImportResolution> {
        let inst = self.instances.get(instance_idx)?;
        let imp = instance_utils::nth_function_import(&inst.module, func_idx)?;
        let mod_name = inst
            .module
            .get_name(imp.module_name_offset, imp.module_name_len);
        let fld_name = inst
            .module
            .get_name(imp.field_name_offset, imp.field_name_len);

        let ext = self.linker.resolve(mod_name, fld_name)?;
        match ext {
            ExternVal::Host(binding_idx) => Some(ImportResolution::Host(*binding_idx)),
            ExternVal::Func(target_idx, target_func_idx) => {
                Some(ImportResolution::Wasm(*target_idx, *target_func_idx))
            }
            _ => None,
        }
    }

    // ── Sync methods ─────────────────────────────────────────────────────

    /// Synchronize shared memory between all linked instances.
    fn sync_shared_memory(&mut self) {
        for i in 0..self.memory_shares.len() {
            let share = &self.memory_shares[i];
            let imp_idx = share.importer_idx;
            let imp_mem = share.importer_mem;
            let exp_idx = share.exporter_idx;
            let exp_mem = share.exporter_mem;

            if imp_idx == exp_idx {
                continue;
            }

            // Determine which has the larger memory and sync to the other
            let (smaller, larger) = if imp_idx < exp_idx {
                let (left, right) = self.instances.split_at_mut(exp_idx);
                (&mut left[imp_idx], &mut right[0])
            } else {
                let (left, right) = self.instances.split_at_mut(imp_idx);
                (&mut right[0], &mut left[exp_idx])
            };

            // smaller is the one at the lower index, larger at the higher
            let (src, src_mem_idx, dst, dst_mem_idx) = if imp_idx < exp_idx {
                // smaller = importer, larger = exporter
                // Sync exporter -> importer (exporter is the source of truth)
                (larger, exp_mem, smaller, imp_mem)
            } else {
                // smaller = exporter, larger = importer
                (smaller, exp_mem, larger, imp_mem)
            };

            let src_size = src.get_memory_size(src_mem_idx).unwrap_or(0);
            let dst_size = dst.get_memory_size(dst_mem_idx).unwrap_or(0);
            let max_size = src_size.max(dst_size);

            if max_size > 0 {
                if let (Some(src_mem_data), Some(dst_mem_data)) =
                    (src.get_memory(src_mem_idx), dst.get_memory_mut(dst_mem_idx))
                {
                    if dst_mem_data.len() < max_size {
                        dst_mem_data.resize(max_size, 0);
                    }
                    let copy_len = src_size.min(src_mem_data.len()).min(dst_mem_data.len());
                    if copy_len > 0 {
                        dst_mem_data[..copy_len].copy_from_slice(&src_mem_data[..copy_len]);
                    }
                    dst.set_memory_size(dst_mem_idx, max_size);
                }
            }
        }
    }

    /// Sync imported (shared) globals into the given instance from their exporters.
    fn sync_imported_globals(&mut self, idx: usize) {
        for i in 0..self.global_shares.len() {
            let share = &self.global_shares[i];
            if share.importer_idx != idx {
                continue;
            }
            let exp_idx = share.exporter_idx;
            let exp_global = share.exporter_global;
            let imp_global = share.importer_global;

            if exp_idx == idx {
                continue;
            }

            // Read value from exporter, write to importer
            let val = self.instances[exp_idx]
                .get_global(exp_global)
                .unwrap_or(Value::I32(0));
            self.instances[idx].set_global(imp_global, val);
        }
    }

    /// Sync globals from the given instance back to their exporters.
    fn sync_globals_back(&mut self, idx: usize) {
        for i in 0..self.global_shares.len() {
            let share = &self.global_shares[i];
            if share.importer_idx != idx {
                continue;
            }
            let exp_idx = share.exporter_idx;
            let exp_global = share.exporter_global;
            let imp_global = share.importer_global;

            if exp_idx == idx {
                continue;
            }

            // Read value from importer, write to exporter
            let val = self.instances[idx]
                .get_global(imp_global)
                .unwrap_or(Value::I32(0));
            self.instances[exp_idx].set_global(exp_global, val);
        }
    }

    /// Resolve a function index from `src_idx` instance's index space into
    /// `dst_idx` instance's index space by copying the function body.
    ///
    /// For local functions in the source: copies the function body into the
    /// destination module and returns the new function index.
    ///
    /// For imported functions in the source: follows the import chain to find
    /// the actual function, then copies it.
    fn resolve_cross_module_function(
        &mut self,
        src_idx: usize,
        src_func_idx: u32,
        dst_idx: usize,
    ) -> u32 {
        let src_inst = match self.instances.get(src_idx) {
            Some(i) => i,
            None => return src_func_idx,
        };
        let src_mod = &src_inst.module;
        let src_import_count = src_mod.func_import_count();

        if (src_func_idx as usize) < src_import_count {
            // Source function is an import — resolve through the import chain.
            let imp = match instance_utils::nth_function_import(src_mod, src_func_idx) {
                Some(i) => i,
                None => return src_func_idx,
            };
            let mod_name = src_mod.get_name(imp.module_name_offset, imp.module_name_len);
            let fld_name = src_mod.get_name(imp.field_name_offset, imp.field_name_len);

            // Look up the extern
            let ext = match self.linker.resolve(mod_name, fld_name) {
                Some(e) => e.clone(),
                None => return src_func_idx,
            };

            match ext {
                ExternVal::Func(target_idx, target_func_idx) => {
                    if target_idx == dst_idx {
                        // The function comes from the destination itself
                        return target_func_idx;
                    }
                    // Recursively resolve from the target module
                    return self.resolve_cross_module_function(
                        target_idx,
                        target_func_idx,
                        dst_idx,
                    );
                }
                ExternVal::Host(_) => {
                    // Host function — find a matching import in dst
                    let dst_mod = &self.instances[dst_idx].module;
                    let mut seen = 0u32;
                    for dst_imp in &dst_mod.imports {
                        if let ImportKind::Func(_) = dst_imp.kind {
                            let dm = dst_mod
                                .get_name(dst_imp.module_name_offset, dst_imp.module_name_len);
                            let df =
                                dst_mod.get_name(dst_imp.field_name_offset, dst_imp.field_name_len);
                            if dm == mod_name && df == fld_name {
                                return seen;
                            }
                            seen += 1;
                        }
                    }
                    return src_func_idx;
                }
                _ => return src_func_idx,
            }
        }

        // Local function in source — copy the function body into dst.
        // Need to work with split borrows to access both src and dst modules.
        let src_mod = &self.instances[src_idx].module;
        let local_idx = (src_func_idx as usize) - src_import_count;
        if local_idx >= src_mod.functions.len() {
            return src_func_idx;
        }

        // Check if we already have this function in the destination
        // (avoid duplicating the same function body multiple times)
        let src_func = &src_mod.functions[local_idx];
        let src_type_idx = src_func.type_idx;
        let source_ft = if (src_type_idx as usize) < src_mod.func_types.len() {
            src_mod.func_types[src_type_idx as usize].clone()
        } else {
            crate::decoder::FuncTypeDef::empty()
        };
        let code_start = src_func.code_offset;
        let code_len = src_func.code_len;
        let src_code = if code_start + code_len <= src_mod.code.len() {
            src_mod.code[code_start..code_start + code_len].to_vec()
        } else {
            Vec::new()
        };
        let local_count = src_func.local_count;
        let locals = src_func.locals;

        // Now write into dst
        let dst_mod = &mut self.instances[dst_idx].module;
        let host_type_idx = instance_utils::find_or_add_func_type(dst_mod, &source_ft);
        let host_code_offset = dst_mod.code.len();
        dst_mod.code.extend_from_slice(&src_code);
        dst_mod.functions.push(crate::decoder::FuncDef {
            type_idx: host_type_idx,
            code_offset: host_code_offset,
            code_len,
            local_count,
            locals,
            non_nullable_locals: Vec::new(),
        });

        dst_mod.func_import_count() as u32 + (dst_mod.functions.len() as u32 - 1)
    }
}

/// Internal result of resolving an import.
enum ImportResolution {
    /// Host function binding index.
    Host(usize),
    /// Cross-module WASM function: (instance_idx, func_idx).
    Wasm(usize, u32),
}
