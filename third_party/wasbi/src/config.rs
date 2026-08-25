//! Engine configuration.

use crate::fuel::FuelCosts;
use crate::types::{
    RuntimeClass, DEFAULT_RUNTIME_CLASS, MAX_CALL_DEPTH, MAX_CODE_SIZE, MAX_DATA_SEGMENTS,
    MAX_ELEMENT_SEGMENTS, MAX_EXPORTS, MAX_FUNCTIONS, MAX_GLOBALS, MAX_IMPORTS, MAX_LOCALS,
    MAX_MEMORY_PAGES, MAX_STACK, MAX_TABLE_SIZE,
};

/// Configuration for a wasbi [`Engine`](crate::engine::Engine).
///
/// All limits default to the values in [`types::limits`](crate::types).
#[derive(Debug, Clone)]
pub struct Config {
    /// Maximum number of function definitions per module.
    pub max_functions: usize,
    /// Maximum number of locals per function.
    pub max_locals: usize,
    /// Maximum operand stack depth.
    pub max_stack: usize,
    /// Maximum linear memory size in pages.
    pub max_memory_pages: usize,
    /// Maximum number of imports per module.
    pub max_imports: usize,
    /// Maximum number of exports per module.
    pub max_exports: usize,
    /// Maximum code section size in bytes.
    pub max_code_size: usize,
    /// Maximum call stack depth.
    pub max_call_depth: usize,
    /// Maximum table size in elements.
    pub max_table_size: usize,
    /// Maximum number of globals per module.
    pub max_globals: usize,
    /// Maximum number of data segments per module.
    pub max_data_segments: usize,
    /// Maximum number of element segments per module.
    pub max_element_segments: usize,
    /// Initial fuel budget for execution.
    pub fuel: u64,
    /// Runtime class controlling which WASM features are allowed.
    pub runtime_class: RuntimeClass,
    /// Fuel cost model for metered execution.
    pub fuel_costs: FuelCosts,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_functions: MAX_FUNCTIONS,
            max_locals: MAX_LOCALS,
            max_stack: MAX_STACK,
            max_memory_pages: MAX_MEMORY_PAGES,
            max_imports: MAX_IMPORTS,
            max_exports: MAX_EXPORTS,
            max_code_size: MAX_CODE_SIZE,
            max_call_depth: MAX_CALL_DEPTH,
            max_table_size: MAX_TABLE_SIZE,
            max_globals: MAX_GLOBALS,
            max_data_segments: MAX_DATA_SEGMENTS,
            max_element_segments: MAX_ELEMENT_SEGMENTS,
            fuel: 1_000_000,
            runtime_class: DEFAULT_RUNTIME_CLASS,
            fuel_costs: FuelCosts::default(),
        }
    }
}
