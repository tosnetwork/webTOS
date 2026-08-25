//! High-level module representation.
//!
//! A [`Module`] wraps a decoded and validated WASM binary, ready for
//! instantiation.

use crate::config::Config;
#[cfg(not(feature = "gc"))]
use crate::decoder::GcTypeDef;
use crate::decoder::{self, ExportKind, ImportKind, WasmModule};
use crate::engine::Engine;
use crate::instance_utils::{exported_global_index, exported_memory_index, exported_table_index};
#[cfg(any(not(feature = "exceptions"), not(feature = "gc")))]
use crate::types::ValType;
use crate::types::WasmError;
use crate::validator;

/// A decoded and validated WebAssembly module.
///
/// Created via [`Module::new`], which performs both decoding and validation
/// in a single step.
pub struct Module {
    inner: WasmModule,
}

impl Module {
    /// Decode and validate a WASM binary.
    pub fn new(engine: &Engine, bytes: &[u8]) -> Result<Self, WasmError> {
        let module = decoder::decode(bytes)?;
        validator::validate(&module)?;
        enforce_feature_support(&module)?;
        enforce_config_limits(&module, engine.config())?;
        Ok(Self { inner: module })
    }

    /// Look up an exported function by name, returning its function index.
    pub fn export_func(&self, name: &str) -> Option<u32> {
        self.inner.find_export_func(name.as_bytes())
    }

    /// Look up an exported global by name, returning its global index.
    pub fn export_global(&self, name: &str) -> Option<u32> {
        exported_global_index(&self.inner, name)
    }

    /// Look up an exported memory by name, returning its memory index.
    pub fn export_memory(&self, name: &str) -> Option<u32> {
        exported_memory_index(&self.inner, name)
    }

    /// Look up an exported table by name, returning its table index.
    pub fn export_table(&self, name: &str) -> Option<u32> {
        exported_table_index(&self.inner, name)
    }

    /// List all exported function names and their indices.
    pub fn exported_funcs(&self) -> alloc::vec::Vec<(&[u8], u32)> {
        let mut result = alloc::vec::Vec::new();
        for export in &self.inner.exports {
            if let ExportKind::Func(idx) = export.kind {
                let name = self.inner.get_name(export.name_offset, export.name_len);
                result.push((name, idx));
            }
        }
        result
    }

    /// Return the number of imports in the module.
    pub fn import_count(&self) -> usize {
        self.inner.imports.len()
    }

    /// Return the number of exports in the module.
    pub fn export_count(&self) -> usize {
        self.inner.exports.len()
    }

    /// Return the number of local function definitions in the module.
    pub fn function_count(&self) -> usize {
        self.inner.functions.len()
    }

    /// Return the number of tables in the module.
    pub fn table_count(&self) -> usize {
        self.inner.tables.len()
    }

    /// Return the number of memories in the module.
    pub fn memory_count(&self) -> usize {
        self.inner.memories.len()
    }

    /// Return the number of globals, including imported globals.
    pub fn global_count(&self) -> usize {
        self.inner.globals.len() + count_global_imports(&self.inner)
    }

    /// Return the number of data segments in the module.
    pub fn data_segment_count(&self) -> usize {
        self.inner.data_segments.len()
    }

    /// Return the number of element segments in the module.
    pub fn element_segment_count(&self) -> usize {
        self.inner.element_segments.len()
    }

    /// Consume the `Module` and return the underlying `WasmModule`.
    pub(crate) fn into_inner(self) -> WasmModule {
        self.inner
    }
}

fn enforce_config_limits(module: &WasmModule, config: &Config) -> Result<(), WasmError> {
    if module.functions.len() > config.max_functions {
        return Err(WasmError::LimitExceeded("max_functions"));
    }
    if module.imports.len() > config.max_imports {
        return Err(WasmError::LimitExceeded("max_imports"));
    }
    if module.exports.len() > config.max_exports {
        return Err(WasmError::LimitExceeded("max_exports"));
    }
    if module.data_segments.len() > config.max_data_segments {
        return Err(WasmError::LimitExceeded("max_data_segments"));
    }
    if module.element_segments.len() > config.max_element_segments {
        return Err(WasmError::LimitExceeded("max_element_segments"));
    }

    let global_count = module.globals.len() + count_global_imports(module);
    if global_count > config.max_globals {
        return Err(WasmError::LimitExceeded("max_globals"));
    }

    let code_size = module
        .functions
        .iter()
        .fold(0usize, |acc, func| acc.saturating_add(func.code_len));
    if code_size > config.max_code_size {
        return Err(WasmError::CodeTooLarge);
    }

    for func in &module.functions {
        let param_count = module
            .func_types
            .get(func.type_idx as usize)
            .map(|ft| ft.param_count as usize)
            .unwrap_or(0);
        let total_locals = param_count.saturating_add(func.local_count as usize);
        if total_locals > config.max_locals {
            return Err(WasmError::LimitExceeded("max_locals"));
        }
    }

    for memory in &module.memories {
        if memory.min_pages as usize > config.max_memory_pages {
            return Err(WasmError::LimitExceeded("max_memory_pages"));
        }
        if memory.has_max && memory.max_pages as usize > config.max_memory_pages {
            return Err(WasmError::LimitExceeded("max_memory_pages"));
        }
    }

    if module.memories.is_empty() && module.has_memory {
        if module.memory_min_pages as usize > config.max_memory_pages {
            return Err(WasmError::LimitExceeded("max_memory_pages"));
        }
        if module.has_memory_max && module.memory_max_pages as usize > config.max_memory_pages {
            return Err(WasmError::LimitExceeded("max_memory_pages"));
        }
    }

    for table in &module.tables {
        if table.min as usize > config.max_table_size {
            return Err(WasmError::LimitExceeded("max_table_size"));
        }
        if let Some(max) = table.max {
            if max as usize > config.max_table_size {
                return Err(WasmError::LimitExceeded("max_table_size"));
            }
        }
    }

    Ok(())
}

fn enforce_feature_support(module: &WasmModule) -> Result<(), WasmError> {
    let _ = module;

    #[cfg(not(feature = "memory64"))]
    if module.memories.iter().any(|memory| memory.is_memory64) || module.is_memory64 {
        return Err(WasmError::UnsupportedProposal);
    }

    #[cfg(not(feature = "threads"))]
    if module.memories.iter().any(|memory| memory.is_shared) {
        return Err(WasmError::UnsupportedProposal);
    }

    #[cfg(not(feature = "exceptions"))]
    if module_uses_exception_handling(module) {
        return Err(WasmError::UnsupportedProposal);
    }

    #[cfg(not(feature = "gc"))]
    if module_uses_gc_proposal(module) {
        return Err(WasmError::UnsupportedProposal);
    }

    Ok(())
}

fn count_global_imports(module: &WasmModule) -> usize {
    module
        .imports
        .iter()
        .filter(|import| matches!(import.kind, ImportKind::Global(..)))
        .count()
}

#[cfg(not(feature = "exceptions"))]
fn module_uses_exception_handling(module: &WasmModule) -> bool {
    if !module.tag_types.is_empty() {
        return true;
    }

    if module
        .imports
        .iter()
        .any(|import| matches!(import.kind, ImportKind::Tag(_)))
    {
        return true;
    }

    if module
        .exports
        .iter()
        .any(|export| matches!(export.kind, ExportKind::Tag(_)))
    {
        return true;
    }

    module_uses_val_type(module, uses_exception_ref_type)
}

#[cfg(not(feature = "gc"))]
fn module_uses_gc_proposal(module: &WasmModule) -> bool {
    if module.has_self_ref_types || module.implicit_rec_enabled {
        return true;
    }

    if module
        .gc_types
        .iter()
        .any(|ty| !matches!(ty, GcTypeDef::Func))
    {
        return true;
    }

    module_uses_val_type(module, uses_gc_ref_type)
}

#[cfg(any(not(feature = "exceptions"), not(feature = "gc")))]
fn module_uses_val_type(module: &WasmModule, predicate: impl Fn(ValType) -> bool + Copy) -> bool {
    if module.func_types.iter().any(|func_type| {
        func_type.params[..func_type.param_count as usize]
            .iter()
            .copied()
            .any(predicate)
            || func_type.results[..func_type.result_count as usize]
                .iter()
                .copied()
                .any(predicate)
    }) {
        return true;
    }

    if module.functions.iter().any(|func| {
        func.locals[..func.local_count as usize]
            .iter()
            .copied()
            .any(predicate)
    }) {
        return true;
    }

    if module
        .globals
        .iter()
        .any(|global| predicate(global.val_type))
    {
        return true;
    }

    if module.tables.iter().any(|table| predicate(table.elem_type)) {
        return true;
    }

    false
}

#[cfg(not(feature = "exceptions"))]
fn uses_exception_ref_type(val_type: ValType) -> bool {
    matches!(val_type, ValType::ExnRef)
}

#[cfg(not(feature = "gc"))]
fn uses_gc_ref_type(val_type: ValType) -> bool {
    matches!(
        val_type,
        ValType::AnyRef
            | ValType::NullableAnyRef
            | ValType::NullableEqRef
            | ValType::I31Ref
            | ValType::StructRef
            | ValType::NullableStructRef
            | ValType::ArrayRef
            | ValType::NullableArrayRef
            | ValType::NoneRef
    )
}
