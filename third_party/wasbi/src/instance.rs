//! High-level instance representation.
//!
//! An [`Instance`] wraps a running WASM instance, providing a clean API
//! for calling functions, accessing memory/globals, and managing fuel.

use alloc::vec::Vec;

use crate::engine::Engine;
use crate::module::Module;
use crate::runtime::{ExecResult, WasmInstance};
use crate::types::{Value, WasmError};

/// A resumable call handle that captures execution state after a [`ExecResult::HostCall`].
///
/// When a call (or resumed call) yields a host import, this handle preserves
/// the import index and arguments so the embedder can inspect them, perform
/// async work, and later resume execution via [`Instance::resume_call`].
#[derive(Debug)]
pub struct ResumableCall {
    /// The import index that triggered the host call.
    pub host_import_idx: u32,
    /// The arguments passed to the host function.
    pub host_args: Vec<Value>,
}

/// A running WebAssembly instance.
///
/// Created from a [`Module`] and an [`Engine`]. Provides typed accessors
/// for memory, globals, tables, and fuel management.
pub struct Instance {
    inner: WasmInstance,
}

impl Instance {
    /// Instantiate a module with the engine's configuration.
    pub fn new(module: Module, engine: &Engine) -> Result<Self, WasmError> {
        let inner = WasmInstance::with_config(module.into_inner(), engine.config())?;
        Ok(Self { inner })
    }

    // ── Execution ───────────────────────────────────────────────────────

    /// Call an exported function by name.
    pub fn call(&mut self, name: &str, args: &[Value]) -> ExecResult {
        let func_idx = match self.inner.module.find_export_func(name.as_bytes()) {
            Some(idx) => idx,
            None => return ExecResult::Trap(WasmError::FunctionNotFound(0)),
        };
        self.inner.call_func(func_idx, args)
    }

    /// Call a function by its raw index.
    pub fn call_by_index(&mut self, func_idx: u32, args: &[Value]) -> ExecResult {
        self.inner.call_func(func_idx, args)
    }

    /// Run the module's start function, if one exists.
    pub fn run_start(&mut self) -> ExecResult {
        self.inner.run_start()
    }

    /// Continue execution until completion, fuel exhaustion, or host call.
    pub fn run(&mut self) -> ExecResult {
        self.inner.run()
    }

    /// Resume execution after a host call returned a value.
    pub fn resume(&mut self, return_value: Option<Value>) -> ExecResult {
        self.inner.resume(return_value)
    }

    /// Resume execution after a host call raised an exception.
    pub fn resume_with_exception(&mut self, tag_idx: u32, values: Vec<Value>) -> ExecResult {
        self.inner.resume_with_exception(tag_idx, values)
    }

    // ── Fuel ────────────────────────────────────────────────────────────

    /// Get the remaining fuel budget.
    pub fn fuel(&self) -> u64 {
        self.inner.fuel_state.fuel
    }

    /// Set the fuel budget.
    pub fn set_fuel(&mut self, fuel: u64) {
        self.inner.fuel_state.fuel = fuel;
    }

    /// Check whether execution has finished.
    pub fn is_finished(&self) -> bool {
        self.inner.fuel_state.finished
    }

    // ── Memory ──────────────────────────────────────────────────────────

    /// Get a shared reference to a linear memory by index.
    pub fn memory(&self, idx: usize) -> Option<&[u8]> {
        let mem = self.inner.memory_store.memories.get(idx)?;
        let size = self
            .inner
            .memory_store
            .memory_sizes
            .get(idx)
            .copied()
            .unwrap_or(mem.len());
        Some(&mem[..size])
    }

    /// Get a mutable reference to a linear memory by index.
    pub fn memory_mut(&mut self, idx: usize) -> Option<&mut [u8]> {
        let size = self.inner.memory_store.memory_sizes.get(idx).copied()?;
        let mem = self.inner.memory_store.memories.get_mut(idx)?;
        Some(&mut mem[..size])
    }

    /// Get the size of a linear memory in bytes.
    pub fn memory_size(&self, idx: usize) -> Option<usize> {
        self.inner.memory_store.memory_sizes.get(idx).copied()
    }

    /// Grow a linear memory by `delta` pages. Returns the old size in pages,
    /// or `u32::MAX` on failure.
    ///
    /// This mirrors the semantics of the `memory.grow` WASM instruction.
    pub fn memory_grow(&mut self, idx: usize, delta: u32) -> u32 {
        use crate::types::limits::{MAX_MEMORY_PAGES, WASM_PAGE_SIZE};

        let page_size = if idx < self.inner.module.memories.len() {
            if let Some(log2) = self.inner.module.memories[idx].page_size_log2 {
                1usize << log2
            } else {
                WASM_PAGE_SIZE
            }
        } else {
            WASM_PAGE_SIZE
        };

        let msz = match self.inner.memory_store.memory_sizes.get(idx).copied() {
            Some(s) => s,
            None => return u32::MAX,
        };

        let old_pages = (msz / page_size) as u32;
        let new_pages = old_pages.saturating_add(delta);

        // Compute effective max pages
        let config_max = if page_size == 0 {
            0
        } else {
            (self.inner.max_memory_pages * WASM_PAGE_SIZE) / page_size
        };
        let module_max = if idx < self.inner.module.memories.len()
            && self.inner.module.memories[idx].max_pages != u32::MAX
        {
            self.inner.module.memories[idx].max_pages as usize
        } else if self.inner.module.has_memory_max
            && idx == 0
            && self.inner.module.memory_max_pages != u32::MAX
        {
            self.inner.module.memory_max_pages as usize
        } else {
            let max_bytes = MAX_MEMORY_PAGES * WASM_PAGE_SIZE;
            max_bytes / page_size
        };
        let effective_max = module_max.min(config_max);

        if new_pages as usize > effective_max {
            return u32::MAX;
        }

        // Charge fuel
        let extra = self
            .inner
            .fuel_state
            .fuel_costs
            .memory_grow_cost(delta as u64);
        if !self.inner.fuel_state.consume_extra(extra) {
            return u32::MAX;
        }

        let new_size = (new_pages as usize).saturating_mul(page_size);
        if idx < self.inner.memory_store.memories.len() {
            self.inner.memory_store.memories[idx].resize(new_size, 0);
            self.inner.memory_store.memory_sizes[idx] = new_size;
        }

        old_pages
    }

    // ── Globals ─────────────────────────────────────────────────────────

    /// Read a global value by index.
    pub fn global(&self, idx: usize) -> Option<Value> {
        self.inner.global_store.globals.get(idx).copied()
    }

    /// Write a global value by index.
    pub fn set_global(&mut self, idx: usize, val: Value) {
        if let Some(g) = self.inner.global_store.globals.get_mut(idx) {
            *g = val;
        }
    }

    // ── Tables ──────────────────────────────────────────────────────────

    /// Get a shared reference to a table by index.
    pub fn table(&self, idx: usize) -> Option<&[Option<u32>]> {
        self.inner.table_store.tables.get(idx).map(|t| t.as_slice())
    }

    // ── Internal access ─────────────────────────────────────────────────

    // ── Resumable calls ──────────────────────────────────────────────────

    /// Start a call that can be resumed after host calls.
    ///
    /// Returns `Ok(result)` when execution completes without a host call,
    /// or `Err(handle)` with a [`ResumableCall`] when a host import is
    /// invoked and the embedder must supply a return value via
    /// [`resume_call`](Self::resume_call).
    pub fn call_resumable(
        &mut self,
        name: &str,
        args: &[Value],
    ) -> Result<ExecResult, ResumableCall> {
        Self::wrap_host_call(self.call(name, args))
    }

    /// Resume a suspended resumable call after the host has computed a
    /// return value.
    ///
    /// The `_handle` is consumed to enforce single-use semantics. Returns
    /// `Ok(result)` on completion or `Err(handle)` if another host call is
    /// encountered.
    pub fn resume_call(
        &mut self,
        _handle: ResumableCall,
        return_value: Option<Value>,
    ) -> Result<ExecResult, ResumableCall> {
        Self::wrap_host_call(self.resume(return_value))
    }

    /// Shared helper: convert a `HostCall` result into `Err(ResumableCall)`.
    fn wrap_host_call(result: ExecResult) -> Result<ExecResult, ResumableCall> {
        match result {
            ExecResult::HostCall(idx, args_arr, count) => {
                let host_args: Vec<Value> = args_arr[..count as usize].to_vec();
                Err(ResumableCall {
                    host_import_idx: idx,
                    host_args,
                })
            }
            other => Ok(other),
        }
    }

    // ── Export lookup ───────────────────────────────────────────────────

    /// Look up an exported function by name, returning its function index.
    pub fn export_func(&self, name: &str) -> Option<u32> {
        self.inner.module.find_export_func(name.as_bytes())
    }

    /// Look up an exported global by name, returning its global index.
    pub fn export_global(&self, name: &str) -> Option<u32> {
        crate::instance_utils::exported_global_index(&self.inner.module, name)
    }

    /// Look up an exported memory by name, returning its memory index.
    pub fn export_memory(&self, name: &str) -> Option<u32> {
        crate::instance_utils::exported_memory_index(&self.inner.module, name)
    }

    /// Look up an exported table by name, returning its table index.
    pub fn export_table(&self, name: &str) -> Option<u32> {
        crate::instance_utils::exported_table_index(&self.inner.module, name)
    }

    // ── Internal access ─────────────────────────────────────────────────

    /// Mutably borrow the underlying `WasmInstance`.
    pub(crate) fn as_inner_mut(&mut self) -> &mut WasmInstance {
        &mut self.inner
    }
}
