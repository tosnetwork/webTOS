//! # Wasbi — A lightweight WebAssembly interpreter
//!
//! ## Stable API
//!
//! The following modules form the stable public API:
//! - [`config`] — Engine configuration
//! - [`engine`] — Shared execution engine
//! - [`module`] — Decoded and validated WASM modules
//! - [`instance`] — Running WASM instances
//! - [`linker`] — Host function registration (includes re-exported linker utilities)
//! - [`prelude`] — Convenience re-exports
//!
//! ## Advanced APIs
//!
//! The following modules are public for advanced integrations and tooling:
//! - [`decoder`] — Low-level binary decoder
//! - [`validator`] — Low-level validator
//! - [`types`] — Value types, error types, index types
//!
//! Additional low-level engine internals are available only behind the hidden
//! `spec-test-internals` feature for the in-repository spec runner.

#![no_std]
// Allow indexing loops in the interpreter — the patterns are intentional
// and converting to iterators would reduce clarity in the bytecode dispatch.
#![allow(clippy::needless_range_loop)]
#![allow(clippy::suspicious_else_formatting)]
#![allow(clippy::collapsible_else_if)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::field_reassign_with_default)]
#![allow(clippy::vec_init_then_push)]
#![allow(clippy::if_same_then_else)]
#![allow(clippy::nonminimal_bool)]
#![allow(clippy::manual_memcpy)]
#![allow(clippy::empty_line_after_doc_comments)]
#![allow(clippy::large_enum_variant)]
#![allow(clippy::possible_missing_else)]
#![allow(clippy::overly_complex_bool_expr)]
#![allow(clippy::derivable_impls)]
#![allow(clippy::collapsible_match)]
extern crate alloc;

// ── Public API layer ────────────────────────────────────────────────────
pub mod config;
pub mod engine;
pub mod fuel;
pub mod instance;
pub mod linker;
pub mod module;
pub mod types;

// ── Advanced and internal engine modules ────────────────────────────────
pub mod decoder;
#[allow(dead_code)]
pub(crate) mod instance_utils;
#[allow(dead_code)]
pub(crate) mod linker_utils;
#[allow(dead_code)]
pub(crate) mod runtime;
#[allow(dead_code)]
pub(crate) mod store;
pub mod validator;

/// Hidden internal re-exports for the in-repository spec runner.
///
/// This surface is intentionally excluded from the default public API and may
/// change without notice. External embedders should prefer [`module`],
/// [`instance`], and [`linker`].
#[cfg(feature = "spec-test-internals")]
#[doc(hidden)]
pub mod internal {
    pub mod instance {
        pub use crate::instance_utils::*;
    }

    pub mod linker {
        pub use crate::linker_utils::*;
    }

    pub mod runtime {
        pub use crate::runtime::*;
    }

    pub mod store {
        pub use crate::store::*;
    }
}

/// Convenience re-exports for the most commonly used types.
pub mod prelude {
    pub use crate::config::Config;
    pub use crate::engine::Engine;
    pub use crate::fuel::FuelCosts;
    pub use crate::instance::{Instance, ResumableCall};
    pub use crate::linker::{Caller, Linker};
    pub use crate::module::Module;
    pub use crate::runtime::ExecResult;
    pub use crate::types::{FuncIdx, GlobalIdx, MemIdx, TableIdx, TypeIdx};
    pub use crate::types::{RuntimeClass, ValType, Value, WasmError};
}
