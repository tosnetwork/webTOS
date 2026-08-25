//! Fuel cost model for metered execution.
//!
//! The [`FuelCosts`] struct defines how much fuel each category of
//! WebAssembly instruction consumes. All costs are deterministic
//! constants — the same module always consumes the same fuel.

/// Fuel costs for different instruction categories.
///
/// # Default Costs
///
/// | Category | Cost |
/// |----------|------|
/// | Base (arithmetic, stack, control) | 1 |
/// | Function call | 2 |
/// | SIMD instruction | 1 |
/// | GC allocation | 3 + 1/element |
/// | Bulk memory (copy/fill/init) | 1 + len/64 |
/// | Bulk table (copy/fill/init) | 1 + 1/element |
/// | Memory grow | 1 + 1/page |
#[derive(Debug, Clone)]
pub struct FuelCosts {
    /// Cost per basic instruction (arithmetic, stack, local, control flow).
    pub base: u64,
    /// Cost per function call (call, call_indirect, call_ref).
    pub call: u64,
    /// Cost per SIMD instruction (0xFD prefix).
    pub simd: u64,
    /// Base cost per GC heap allocation (struct.new, array.new).
    pub gc_alloc: u64,
    /// Additional cost per element for GC operations (array.copy, array.fill).
    pub gc_per_element: u64,
    /// Divisor for bulk memory cost: `base + len / bytes_per_fuel`.
    pub bytes_per_fuel: u64,
    /// Additional cost per element for bulk table operations.
    pub table_per_element: u64,
    /// Additional cost per page for memory.grow.
    pub memory_grow_per_page: u64,
}

impl Default for FuelCosts {
    fn default() -> Self {
        Self {
            base: 1,
            call: 2,
            simd: 1,
            gc_alloc: 3,
            gc_per_element: 1,
            bytes_per_fuel: 64,
            table_per_element: 1,
            memory_grow_per_page: 1,
        }
    }
}

impl FuelCosts {
    /// Uniform cost model: every operation costs 1 fuel, no dynamic costs.
    ///
    /// This matches the original wasbi behavior before dynamic fuel was
    /// introduced.
    pub fn uniform() -> Self {
        Self {
            base: 1,
            call: 1,
            simd: 1,
            gc_alloc: 1,
            gc_per_element: 0,
            bytes_per_fuel: u64::MAX,
            table_per_element: 0,
            memory_grow_per_page: 0,
        }
    }

    /// Calculate fuel for a bulk memory operation (memory.copy, memory.fill, memory.init).
    pub fn bulk_memory_cost(&self, len: u64) -> u64 {
        len / self.bytes_per_fuel
    }

    /// Calculate fuel for a bulk table operation (table.copy, table.fill, table.init).
    pub fn bulk_table_cost(&self, count: u64) -> u64 {
        count.saturating_mul(self.table_per_element)
    }

    /// Calculate fuel for memory.grow.
    pub fn memory_grow_cost(&self, pages: u64) -> u64 {
        pages.saturating_mul(self.memory_grow_per_page)
    }

    /// Calculate fuel for a GC allocation or bulk GC operation.
    pub fn gc_cost(&self, element_count: u64) -> u64 {
        self.gc_alloc
            .saturating_add(element_count.saturating_mul(self.gc_per_element))
            .saturating_sub(self.base) // base already charged by step()
    }

    /// Extra fuel for a call instruction (beyond the base already charged).
    pub fn call_extra(&self) -> u64 {
        self.call.saturating_sub(self.base)
    }

    /// Extra fuel for a SIMD instruction (beyond the base already charged).
    pub fn simd_extra(&self) -> u64 {
        self.simd.saturating_sub(self.base)
    }
}
