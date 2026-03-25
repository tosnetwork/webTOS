//! WASM binary format types for the ATOS minimal interpreter.
//!
//! Small tables use fixed-size arrays; large buffers (code, memory)
//! are heap-allocated via `Vec`.

#[path = "types/values.rs"]
pub mod values;
#[path = "types/error.rs"]
pub mod error;
#[path = "types/limits.rs"]
pub mod limits;
#[path = "types/opcode.rs"]
pub mod opcode;

pub use values::*;
pub use error::*;
pub use limits::*;
pub use opcode::*;
