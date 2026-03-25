// The wasm engine is consumed both by the kernel binary and by host-side tools
// such as the spec runner. That split leaves a number of legitimate library
// entry points unused in the kernel build, so keep dead-code noise scoped to
// this subsystem instead of masking warnings crate-wide.
#[allow(dead_code, unused_imports)]
pub mod types;
#[allow(dead_code)]
pub mod decoder;
#[allow(dead_code)]
pub mod validator;
#[allow(dead_code)]
pub mod runtime;
pub mod host;
