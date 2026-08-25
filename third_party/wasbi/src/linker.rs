//! Host function registration and import linking.
//!
//! The [`Linker`] allows embedders to register host functions by
//! (module, field) name. When an [`Instance`](crate::instance::Instance) encounters a
//! [`HostCall`](crate::runtime::ExecResult::HostCall), the linker resolves and
//! dispatches the call automatically.
//!
//! The linker also supports multi-module linking via [`ExternVal`] entries:
//! WASM function, global, memory, table, and tag exports from one module can
//! be registered and resolved as imports in another.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use crate::decoder::{ExportKind, ImportKind, WasmModule};
use crate::linker_utils;
use crate::runtime::{ExecResult, WasmInstance};
use crate::types::{Value, WasmError};

/// Narrow host-side view into the running instance during an import call.
///
/// The type parameter `T` is the user data stored alongside the instance.
/// When `T` is `()` (the default), the caller provides only instance access.
pub struct Caller<'a, T = ()> {
    instance: &'a mut WasmInstance,
    data: *mut T,
}

impl<'a, T> Caller<'a, T> {
    /// Create a caller with a typed data pointer.
    fn new_with_data(instance: &'a mut WasmInstance, data: &'a mut T) -> Self {
        Self {
            instance,
            data: data as *mut T,
        }
    }

    /// Access the user data.
    pub fn data(&self) -> &T {
        // SAFETY: The pointer is valid for the lifetime 'a, guaranteed by the
        // caller of `new_with_data` or by the `func_wrap` type-erasure that
        // reconstructs the reference from a pointer whose lifetime is tied to
        // the dispatch call.
        unsafe { &*self.data }
    }

    /// Mutably access the user data.
    pub fn data_mut(&mut self) -> &mut T {
        // SAFETY: Same as `data()` — the pointer is valid and exclusively
        // borrowed for 'a.
        unsafe { &mut *self.data }
    }

    /// Read the remaining fuel budget.
    pub fn fuel(&self) -> u64 {
        self.instance.get_fuel()
    }

    /// Replace the remaining fuel budget.
    pub fn set_fuel(&mut self, fuel: u64) {
        self.instance.set_fuel(fuel);
    }

    /// Whether execution has finished.
    pub fn is_finished(&self) -> bool {
        self.instance.is_finished()
    }

    /// Mark the instance as finished.
    pub fn set_finished(&mut self, finished: bool) {
        self.instance.set_finished(finished);
    }

    /// Read a linear memory as a slice.
    pub fn memory(&self, idx: usize) -> Option<&[u8]> {
        self.instance
            .get_memory(idx)
            .map(|memory| memory.as_slice())
    }

    /// Mutably borrow a linear memory as a slice.
    pub fn memory_mut(&mut self, idx: usize) -> Option<&mut [u8]> {
        self.instance
            .get_memory_mut(idx)
            .map(|memory| memory.as_mut_slice())
    }

    /// Read the current byte length of a linear memory.
    pub fn memory_size(&self, idx: usize) -> Option<usize> {
        self.instance.get_memory_size(idx)
    }

    /// Read a global value.
    pub fn global(&self, idx: usize) -> Option<Value> {
        self.instance.get_global(idx)
    }

    /// Update a global value.
    pub fn set_global(&mut self, idx: usize, value: Value) {
        self.instance.set_global(idx, value);
    }

    /// Read a table as a slice.
    pub fn table(&self, idx: usize) -> Option<&[Option<u32>]> {
        self.instance.get_table(idx).map(|table| table.as_slice())
    }
}

/// Type-erased host function.
///
/// The raw `*mut u8` carries a pointer to the user data whose concrete type
/// was captured when the closure was registered via [`Linker::func_wrap`].
type ErasedHostFn =
    Box<dyn Fn(&mut WasmInstance, *mut u8, &[Value]) -> Result<Option<Value>, WasmError>>;

/// An external value that can satisfy a WASM import.
#[derive(Clone)]
pub enum ExternVal {
    /// A host function closure (index into Linker's bindings vec).
    Host(usize),
    /// A WASM function: (instance_idx in Store, func_idx).
    Func(usize, u32),
    /// A global: (instance_idx, global_idx).
    Global(usize, u32),
    /// A memory: (instance_idx, mem_idx).
    Memory(usize, u32),
    /// A table: (instance_idx, table_idx).
    Table(usize, u32),
    /// A tag: (instance_idx, tag_idx).
    Tag(usize, u32),
}

/// Registers host functions and resolves WASM imports.
///
/// # Example
///
/// ```
/// use wasbi::prelude::*;
/// use wasbi::linker::Linker;
///
/// let mut linker = Linker::new();
/// linker.func_wrap("env", "add", |_caller: Caller<'_, ()>, args: &[Value]| {
///     let a = args[0].as_i32();
///     let b = args[1].as_i32();
///     Ok(Some(Value::I32(a + b)))
/// });
/// ```
pub struct Linker {
    bindings: Vec<Binding>,
    externs: BTreeMap<(String, String), ExternVal>,
}

struct Binding {
    module_name: String,
    field_name: String,
    func: ErasedHostFn,
}

impl Linker {
    /// Create an empty linker.
    pub fn new() -> Self {
        Self {
            bindings: Vec::new(),
            externs: BTreeMap::new(),
        }
    }

    /// Register a host function under the given module and field name.
    ///
    /// The closure receives a [`Caller<'_, T>`] that gives access to the
    /// running instance **and** the user data of type `T`. When dispatching,
    /// the caller must pass a `&mut T` via [`dispatch_raw_with_data`] (or
    /// [`dispatch_host_with_data`]). The non-`_with_data` dispatch methods
    /// pass `&mut ()`, which is correct when `T = ()`.
    ///
    /// Returns `&mut Self` for fluent chaining.
    pub fn func_wrap<T: 'static>(
        &mut self,
        module_name: &str,
        field_name: &str,
        func: impl for<'a> Fn(Caller<'a, T>, &[Value]) -> Result<Option<Value>, WasmError> + 'static,
    ) -> &mut Self {
        let erased: ErasedHostFn = Box::new(move |inst, data_ptr, args| {
            // SAFETY: The concrete type behind `data_ptr` is `T`, guaranteed
            // by the matching `dispatch_*_with_data::<T>` call. The reference
            // is valid for the duration of the closure invocation.
            let data: &mut T = unsafe { &mut *(data_ptr as *mut T) };
            let caller = Caller::new_with_data(inst, data);
            func(caller, args)
        });
        let idx = self.bindings.len();
        self.bindings.push(Binding {
            module_name: String::from(module_name),
            field_name: String::from(field_name),
            func: erased,
        });
        // Also register in externs so resolve() can find host functions.
        self.externs.insert(
            (String::from(module_name), String::from(field_name)),
            ExternVal::Host(idx),
        );
        self
    }

    /// Define an extern value (WASM export or host function).
    pub fn define(&mut self, module_name: &str, field_name: &str, val: ExternVal) -> &mut Self {
        self.externs
            .insert((String::from(module_name), String::from(field_name)), val);
        self
    }

    /// Register all exports from a WasmModule instance in the Store.
    ///
    /// `name` is the module name under which exports are registered.
    /// `instance_idx` is the index of the instance in the Store's instance list.
    /// `module` is the WasmModule whose exports describe what is available.
    pub fn register_instance(&mut self, name: &str, instance_idx: usize, module: &WasmModule) {
        for export in module.get_exports() {
            let field_name =
                core::str::from_utf8(module.get_name(export.name_offset, export.name_len))
                    .unwrap_or("");
            let val = match export.kind {
                ExportKind::Func(idx) => ExternVal::Func(instance_idx, idx),
                ExportKind::Global(idx) => ExternVal::Global(instance_idx, idx),
                ExportKind::Memory(idx) => ExternVal::Memory(instance_idx, idx),
                ExportKind::Table(idx) => ExternVal::Table(instance_idx, idx),
                ExportKind::Tag(idx) => ExternVal::Tag(instance_idx, idx),
            };
            self.externs
                .insert((String::from(name), String::from(field_name)), val);
        }
    }

    /// Re-register all externs from module `from` under name `to`.
    pub fn alias_module(&mut self, from: &str, to: &str) {
        let entries: Vec<(String, ExternVal)> = self
            .externs
            .iter()
            .filter(|((m, _), _)| m == from)
            .map(|((_, f), v)| (f.clone(), v.clone()))
            .collect();
        for (field, val) in entries {
            self.externs.insert((String::from(to), field), val);
        }
    }

    /// Look up an extern by (module, field) name (byte slices).
    pub fn resolve(&self, module_name: &[u8], field_name: &[u8]) -> Option<&ExternVal> {
        let m = core::str::from_utf8(module_name).ok()?;
        let f = core::str::from_utf8(field_name).ok()?;
        self.resolve_str(m, f)
    }

    /// Iterate over all registered extern values.
    pub fn externs_iter(&self) -> impl Iterator<Item = (&(String, String), &ExternVal)> {
        self.externs.iter()
    }

    /// Look up an extern by (module, field) name (string slices).
    pub fn resolve_str(&self, module_name: &str, field_name: &str) -> Option<&ExternVal> {
        // We need to search by borrowed key. BTreeMap with owned keys requires
        // constructing owned keys for lookup unfortunately.
        self.externs
            .get(&(String::from(module_name), String::from(field_name)))
    }

    /// Validate all imports of a module can be satisfied by registered externs.
    pub fn validate_imports(
        &self,
        module: &WasmModule,
        instances: &[WasmInstance],
    ) -> Result<(), WasmError> {
        for import in module.get_imports() {
            let mod_name = module.get_name(import.module_name_offset, import.module_name_len);
            let fld_name = module.get_name(import.field_name_offset, import.field_name_len);

            let ext = match self.resolve(mod_name, fld_name) {
                Some(e) => e,
                None => {
                    // Check if there is a host binding that matches
                    let has_binding = self.bindings.iter().any(|b| {
                        b.module_name.as_bytes() == mod_name && b.field_name.as_bytes() == fld_name
                    });
                    if has_binding {
                        // Host bindings are valid for Func imports
                        if matches!(import.kind, ImportKind::Func(_)) {
                            continue;
                        }
                    }
                    return Err(WasmError::ImportNotFound(0));
                }
            };

            match (&import.kind, ext) {
                (ImportKind::Func(type_idx), ExternVal::Host(_)) => {
                    // Host functions are always considered compatible (validated at call time)
                    let _ = type_idx;
                }
                (ImportKind::Func(type_idx), ExternVal::Func(src_idx, src_func_idx)) => {
                    // Check type compatibility
                    if let Some(src_inst) = instances.get(*src_idx) {
                        let src_module = &src_inst.module;
                        if let Some(src_type_idx) =
                            crate::instance_utils::function_type_idx(src_module, *src_func_idx)
                        {
                            if !linker_utils::func_types_match(
                                &module.get_func_types()[*type_idx as usize],
                                &src_module.get_func_types()[src_type_idx as usize],
                            ) && !linker_utils::cross_module_type_subtype(
                                src_module,
                                src_type_idx,
                                module,
                                *type_idx,
                            ) {
                                return Err(WasmError::TypeMismatch);
                            }
                        }
                    }
                }
                (
                    ImportKind::Global(val_type_byte, mutable, heap_type),
                    ExternVal::Global(src_idx, global_idx),
                ) => {
                    if let Some(src_inst) = instances.get(*src_idx) {
                        let src_module = &src_inst.module;
                        let src_globals = src_module.get_globals();
                        if let Some(src_global) = src_globals.get(*global_idx as usize) {
                            let import_val_type = linker_utils::decode_valtype_byte(*val_type_byte)
                                .unwrap_or(crate::types::ValType::I32);
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
                (ImportKind::Memory, ExternVal::Memory(src_idx, mem_idx)) => {
                    if let Some(src_inst) = instances.get(*src_idx) {
                        let src_module = &src_inst.module;
                        let src_mems = src_module.get_memories();
                        if let Some(src_mem) = src_mems.get(*mem_idx as usize) {
                            // Check that the importing module's memory defs are compatible
                            // The first memory import maps to mem index 0 in the importer
                            let imp_mems = module.get_memories();
                            if let Some(imp_mem) = imp_mems.first() {
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
                                // Check min pages: export must have >= import's min
                                if src_mem.min_pages < imp_mem.min_pages {
                                    return Err(WasmError::TypeMismatch);
                                }
                                // Check max pages: if import has max, export must also
                                // have max and export max <= import max
                                if imp_mem.has_max
                                    && (!src_mem.has_max || src_mem.max_pages > imp_mem.max_pages)
                                {
                                    return Err(WasmError::TypeMismatch);
                                }
                            }
                        }
                    }
                }
                (ImportKind::Table(elem_type), ExternVal::Table(src_idx, table_idx)) => {
                    if let Some(src_inst) = instances.get(*src_idx) {
                        let src_module = &src_inst.module;
                        let src_tables = src_module.get_tables();
                        if let Some(src_table) = src_tables.get(*table_idx as usize) {
                            // Check element type compatibility
                            if !linker_utils::ref_types_compatible(*elem_type, src_table.elem_type)
                            {
                                return Err(WasmError::TypeMismatch);
                            }
                            // Check table64 flag
                            let imp_tables = module.get_tables();
                            if let Some(imp_table) = imp_tables.first() {
                                if imp_table.is_table64 != src_table.is_table64 {
                                    return Err(WasmError::TypeMismatch);
                                }
                                // Check min: export must have >= import's min
                                if src_table.min < imp_table.min {
                                    return Err(WasmError::TypeMismatch);
                                }
                                // Check max: if import has max, export must have max <= import max
                                if let Some(imp_max) = imp_table.max {
                                    match src_table.max {
                                        Some(src_max) if src_max <= imp_max => {}
                                        _ => return Err(WasmError::TypeMismatch),
                                    }
                                }
                            }
                        }
                    }
                }
                (ImportKind::Tag(_), ExternVal::Tag(_, _)) => {
                    // Tag imports: type validation would need cross-module check
                    // Accept for now (tags are matched by structure at throw/catch time)
                }
                _ => {
                    // Kind mismatch (e.g., Func import but Global extern)
                    return Err(WasmError::TypeMismatch);
                }
            }
        }
        Ok(())
    }

    /// Resolve a host call by looking up the import's (module, field) name
    /// in the registered bindings, passing typed user data to the closure.
    ///
    /// `func_idx` is the WASM function index of the imported function.
    pub fn dispatch_with_data<T>(
        &self,
        instance: &mut crate::instance::Instance,
        data: &mut T,
        func_idx: u32,
        args: &[Value],
    ) -> Result<Option<Value>, WasmError> {
        self.dispatch_raw_with_data(instance.as_inner_mut(), data, func_idx, args)
    }

    /// Resolve a host call (convenience for `T = ()`).
    pub fn dispatch(
        &self,
        instance: &mut crate::instance::Instance,
        func_idx: u32,
        args: &[Value],
    ) -> Result<Option<Value>, WasmError> {
        self.dispatch_raw(instance.as_inner_mut(), func_idx, args)
    }

    /// Dispatch a host call directly on a WasmInstance with typed user data.
    pub(crate) fn dispatch_raw_with_data<T>(
        &self,
        instance: &mut WasmInstance,
        data: &mut T,
        func_idx: u32,
        args: &[Value],
    ) -> Result<Option<Value>, WasmError> {
        // Find the import entry for this function index.
        let mut seen = 0u32;
        let mut found = None;
        for imp in &instance.module.imports {
            if let ImportKind::Func(_) = imp.kind {
                if seen == func_idx {
                    found = Some(imp);
                    break;
                }
                seen = seen.saturating_add(1);
            }
        }

        let imp = match found {
            Some(imp) => imp,
            None => return Err(WasmError::ImportNotFound(func_idx)),
        };

        let mod_name = instance
            .module
            .get_name(imp.module_name_offset, imp.module_name_len);
        let field_name = instance
            .module
            .get_name(imp.field_name_offset, imp.field_name_len);

        let data_ptr = data as *mut T as *mut u8;

        for binding in &self.bindings {
            if binding.module_name.as_bytes() == mod_name
                && binding.field_name.as_bytes() == field_name
            {
                return (binding.func)(instance, data_ptr, args);
            }
        }

        Err(WasmError::ImportNotFound(func_idx))
    }

    /// Dispatch a host call directly on a WasmInstance (convenience for `T = ()`).
    pub(crate) fn dispatch_raw(
        &self,
        instance: &mut WasmInstance,
        func_idx: u32,
        args: &[Value],
    ) -> Result<Option<Value>, WasmError> {
        self.dispatch_raw_with_data(instance, &mut (), func_idx, args)
    }

    /// Dispatch a host call by binding index with typed user data.
    pub(crate) fn dispatch_host_with_data<T>(
        &self,
        instance: &mut WasmInstance,
        data: &mut T,
        binding_idx: usize,
        args: &[Value],
    ) -> Result<Option<Value>, WasmError> {
        let data_ptr = data as *mut T as *mut u8;
        if let Some(binding) = self.bindings.get(binding_idx) {
            (binding.func)(instance, data_ptr, args)
        } else {
            Err(WasmError::ImportNotFound(binding_idx as u32))
        }
    }

    /// Dispatch a host call by binding index (convenience for `T = ()`).
    pub(crate) fn dispatch_host(
        &self,
        instance: &mut WasmInstance,
        binding_idx: usize,
        args: &[Value],
    ) -> Result<Option<Value>, WasmError> {
        self.dispatch_host_with_data(instance, &mut (), binding_idx, args)
    }
}

impl Default for Linker {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::instance::Instance {
    /// Run to completion, automatically dispatching host calls via the linker.
    ///
    /// This is a convenience method that wraps the run/resume loop.
    /// For each `HostCall`, the linker resolves the import and calls the
    /// registered host function. Uses `T = ()` (no user data).
    pub fn run_with_linker(&mut self, linker: &Linker) -> ExecResult {
        self.run_with_linker_data(linker, &mut ())
    }

    /// Run to completion with typed user data, automatically dispatching host
    /// calls via the linker.
    ///
    /// Each host function receives a [`Caller<'_, T>`] with access to `data`.
    pub fn run_with_linker_data<T>(&mut self, linker: &Linker, data: &mut T) -> ExecResult {
        loop {
            let result = self.run();
            match result {
                ExecResult::HostCall(func_idx, ref args, arg_count) => {
                    let args = &args[..arg_count as usize];
                    match linker.dispatch_raw_with_data(self.as_inner_mut(), data, func_idx, args) {
                        Ok(ret) => {
                            let resumed = self.resume(ret);
                            match resumed {
                                ExecResult::Ok => {
                                    if self.is_finished() {
                                        return ExecResult::Ok;
                                    }
                                    // continue loop
                                }
                                other => return other,
                            }
                        }
                        Err(e) => return ExecResult::Trap(e),
                    }
                }
                other => return other,
            }
        }
    }
}
