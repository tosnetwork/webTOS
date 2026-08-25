//! WASM binary format types for the wasbi interpreter.
//!
//! Small tables use fixed-size arrays; large buffers (code, memory)
//! are heap-allocated via `Vec`.

#[path = "types/error.rs"]
pub mod error;
#[path = "types/index.rs"]
pub mod index;
#[path = "types/limits.rs"]
pub mod limits;
#[path = "types/opcode.rs"]
pub mod opcode;
#[path = "types/values.rs"]
pub mod values;

pub use error::*;
pub use index::*;
pub use limits::*;
pub use opcode::*;
pub use values::*;
