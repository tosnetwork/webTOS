//! Resource limits and RuntimeClass definition.

/// Per-agent execution class controlling which WASM features are allowed.
///
/// Default is **BestEffort** (most permissive) — agents opt IN to stricter
/// modes when they need verifiability, not opt OUT of features they need.
///
/// - **BestEffort** (default): full features — floats, SIMD, threads (future).
///   No replay or proof guarantees. Suitable for general agents, AI inference,
///   data processing, tool agents, and any workload that just needs to run.
/// - **ReplayGrade**: floats and SIMD allowed, no threads.
///   Execution is reproducible on the same hardware but not formally provable.
/// - **ProofGrade**: strict determinism — no floats, no SIMD, no threads.
///   Execution can be replayed and independently verified. Produces
///   cryptographically meaningful ExecutionReceipts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RuntimeClass {
    BestEffort = 0,
    ReplayGrade = 1,
    ProofGrade = 2,
}

/// Default runtime class for new agents — most permissive.
/// Agents that need verifiability explicitly request ProofGrade.
pub const DEFAULT_RUNTIME_CLASS: RuntimeClass = RuntimeClass::BestEffort;

// Engine limits
pub const MAX_FUNCTIONS: usize = 10_000;
pub const MAX_LOCALS: usize = 4096;
pub const MAX_STACK: usize = 65_536;           // ~1 MB of Value cells
pub const MAX_MEMORY_PAGES: usize = 65_536;    // 4 GiB max (WASM spec limit, gated by agent mem_quota)
pub const WASM_PAGE_SIZE: usize = 65_536;      // Standard WASM page size (64 KiB)
pub const MAX_IMPORTS: usize = 10_000;
pub const MAX_EXPORTS: usize = 10_000;
pub const MAX_CODE_SIZE: usize = 10_485_760;   // 10 MB max code
pub const MAX_CALL_DEPTH: usize = 1_000;
pub const MAX_PARAMS: usize = 128;
pub const MAX_RESULTS: usize = 128;
pub const MAX_NAME_BYTES: usize = 1_024;
pub const MAX_BLOCK_DEPTH: usize = 10_000;
pub const MAX_GLOBALS: usize = 1_000;
pub const MAX_TABLE_SIZE: usize = 65_536;
pub const MAX_DATA_SEGMENTS: usize = 1_000;
pub const MAX_ELEMENT_SEGMENTS: usize = 1_000;
pub const MAX_BR_TABLE_SIZE: usize = 4_096;
