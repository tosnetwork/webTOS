//! Newtype index wrappers for type-safe WASM index spaces.
//!
//! These prevent accidental confusion between different index kinds
//! (e.g., using a function index where a type index is expected).

/// Macro to define a newtype wrapper around `u32` for WASM indices.
macro_rules! define_index {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[repr(transparent)]
        pub struct $name(pub u32);

        impl $name {
            /// Create a new index.
            pub const fn new(val: u32) -> Self { Self(val) }
            /// Get the raw `u32` value.
            pub const fn raw(self) -> u32 { self.0 }
            /// Convert to `usize` for array indexing.
            pub const fn as_usize(self) -> usize { self.0 as usize }
        }

        impl From<u32> for $name {
            fn from(val: u32) -> Self { Self(val) }
        }

        impl From<$name> for u32 {
            fn from(idx: $name) -> u32 { idx.0 }
        }
    };
}

define_index!(
    /// Index into the function index space (imports + local functions).
    FuncIdx
);

define_index!(
    /// Index into the type section (function signatures).
    TypeIdx
);

define_index!(
    /// Index into the global index space.
    GlobalIdx
);

define_index!(
    /// Index into the table index space.
    TableIdx
);

define_index!(
    /// Index into the memory index space.
    MemIdx
);

define_index!(
    /// Index into the local variable space within a function.
    LocalIdx
);

define_index!(
    /// Index into the label/block stack for branch targets.
    LabelIdx
);

define_index!(
    /// Index into the tag index space (exception handling).
    TagIdx
);

define_index!(
    /// Index into the data segment space.
    DataIdx
);

define_index!(
    /// Index into the element segment space.
    ElemIdx
);
