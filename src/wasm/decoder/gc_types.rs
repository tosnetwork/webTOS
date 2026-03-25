//! GC-proposal type definitions: StorageType, GcTypeDef, SubTypeInfo.

use alloc::vec::Vec;
use crate::wasm::types::ValType;

/// Storage type for struct fields and array elements (GC proposal).
/// Packed types i8/i16 are narrower than full value types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageType {
    I8,
    I16,
    Val(ValType),
    /// A concrete ref type with a tracked heap type index.
    /// Used to distinguish (ref $a) from (ref $b) in validation.
    RefType(ValType, u32),
}

impl StorageType {
    /// Get the full ValType for this storage type (packed -> I32).
    pub fn unpack(self) -> ValType {
        match self {
            StorageType::I8 | StorageType::I16 => ValType::I32,
            StorageType::Val(vt) => vt,
            StorageType::RefType(vt, _) => vt,
        }
    }
}

/// GC type definition — parallel to func_types, indexed by the same type index.
#[derive(Debug, Clone)]
pub enum GcTypeDef {
    /// Regular function type (delegates to func_types entry).
    Func,
    /// Struct type with field types and mutabilities.
    Struct {
        field_types: Vec<StorageType>,
        field_muts: Vec<bool>,
    },
    /// Array type with element type and mutability.
    Array {
        elem_type: StorageType,
        elem_mutable: bool,
    },
}

/// Subtype info: for each type index, which type index is its supertype (if any).
#[derive(Debug, Clone, Copy, Default)]
pub struct SubTypeInfo {
    pub supertype: Option<u32>,
    pub is_final: bool,
    /// The starting type index of the rec group this type belongs to.
    pub rec_group_start: u32,
    /// The number of types in the rec group this type belongs to.
    pub rec_group_size: u32,
}
