//! GC heap object definitions.

use alloc::vec::Vec;
use crate::wasm::types::Value;

/// A GC heap-allocated object (struct or array).
#[derive(Debug, Clone)]
pub enum GcObject {
    Struct { type_idx: u32, fields: Vec<Value> },
    Array { type_idx: u32, elements: Vec<Value> },
    /// Internalized extern (from any.convert_extern): wraps an externref into the any hierarchy
    Internalized { value: Value },
    /// Externalized any (from extern.convert_any): wraps an anyref into the extern hierarchy
    Externalized { value: Value },
}

impl GcObject {
    pub fn type_idx(&self) -> u32 {
        match self {
            GcObject::Struct { type_idx, .. } => *type_idx,
            GcObject::Array { type_idx, .. } => *type_idx,
            GcObject::Internalized { .. } | GcObject::Externalized { .. } => u32::MAX,
        }
    }
}
