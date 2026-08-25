//! Component structs that break WasmInstance's monolithic state into narrower
//! subsystems: memories, tables, globals, GC heap, and fuel/control state.

use super::GcObject;
use crate::types::Value;
use alloc::vec::Vec;

// ─── Linear memory storage ─────────────────────────────────────────────────

/// Linear memory storage.
pub(crate) struct MemoryStore {
    pub(crate) memories: Vec<Vec<u8>>,
    pub(crate) memory_sizes: Vec<usize>,
    pub(crate) memory_aliases: Vec<Option<usize>>,
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self {
            memories: Vec::new(),
            memory_sizes: Vec::new(),
            memory_aliases: Vec::new(),
        }
    }
}

// ─── Table storage ──────────────────────────────────────────────────────────

/// Table storage.
pub(crate) struct TableStore {
    pub(crate) tables: Vec<Vec<Option<u32>>>,
    pub(crate) table_aliases: Vec<Option<usize>>,
    pub(crate) dropped_elems: Vec<bool>,
}

impl Default for TableStore {
    fn default() -> Self {
        Self {
            tables: Vec::new(),
            table_aliases: Vec::new(),
            dropped_elems: Vec::new(),
        }
    }
}

// ─── Global variable storage ────────────────────────────────────────────────

/// Global variable storage.
pub(crate) struct GlobalStore {
    pub(crate) globals: Vec<Value>,
    pub(crate) global_aliases: Vec<Option<usize>>,
}

impl Default for GlobalStore {
    fn default() -> Self {
        Self {
            globals: Vec::new(),
            global_aliases: Vec::new(),
        }
    }
}

// ─── GC heap and related state ──────────────────────────────────────────────

/// GC heap and related state.
pub(crate) struct GcStore {
    pub(crate) gc_heap: Vec<GcObject>,
    pub(crate) elem_gc_values: Vec<Vec<Value>>,
}

impl Default for GcStore {
    fn default() -> Self {
        Self {
            gc_heap: Vec::new(),
            elem_gc_values: Vec::new(),
        }
    }
}

// ─── Execution fuel and control state ───────────────────────────────────────

/// Execution fuel and control state.
pub(crate) struct FuelState {
    pub(crate) fuel: u64,
    pub(crate) finished: bool,
    pub(crate) fuel_costs: crate::fuel::FuelCosts,
}

impl Default for FuelState {
    fn default() -> Self {
        Self {
            fuel: 0,
            finished: false,
            fuel_costs: crate::fuel::FuelCosts::default(),
        }
    }
}

impl FuelState {
    /// Create a new fuel state with the given budget and cost model.
    pub(crate) fn new(fuel: u64, fuel_costs: crate::fuel::FuelCosts) -> Self {
        Self {
            fuel,
            finished: false,
            fuel_costs,
        }
    }

    /// Consume fuel for a basic instruction. Returns false if out of fuel.
    pub(crate) fn consume(&mut self) -> bool {
        if self.fuel < self.fuel_costs.base {
            return false;
        }
        self.fuel -= self.fuel_costs.base;
        true
    }

    /// Consume a variable amount of fuel. Returns false if out of fuel.
    pub(crate) fn consume_extra(&mut self, amount: u64) -> bool {
        if amount == 0 {
            return true;
        }
        if self.fuel < amount {
            return false;
        }
        self.fuel -= amount;
        true
    }
}
