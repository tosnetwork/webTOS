# Changelog

## 0.1.0 (2026-03-26)

Initial release.

- Initial standalone `no_std` crate release
- Public API: `Engine`, `Config`, `Module`, `Instance`, `Linker`
- Full WebAssembly MVP + multi-value, bulk-memory, reference-types, SIMD, GC, exception handling, memory64, multi-memory, typed function references, tail calls
- RuntimeClass tiers: BestEffort, ReplayGrade, ProofGrade
- Fuel-based execution metering
- Error classification via `WasmError::layer()`
- 444/444 official spec test files passing (78,346 assertions)
- Zero `unsafe`, zero `unwrap`, zero panics in production code
