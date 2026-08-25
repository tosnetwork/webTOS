# Versioning and Compatibility

## Semantic Versioning

Wasbi follows [Semantic Versioning 2.0.0](https://semver.org/).

- **Patch** (0.1.x): Bug fixes, documentation improvements, performance improvements
- **Minor** (0.x.0): New features, new API additions (backward compatible)
- **Major** (x.0.0): Breaking API changes

## What Counts as a Breaking Change

The following are breaking changes that require a major version bump:

- Removing or renaming a public type, function, or method
- Changing the signature of a public function
- Changing the behavior of WasmError variants (adding/removing/renaming)
- Changing the semantics of RuntimeClass tiers
- Removing a Cargo feature

The following are NOT breaking changes:

- Adding new public types, functions, or methods
- Adding new WasmError variants
- Adding new Cargo features
- Adding new fields to Config (with Default)
- Performance improvements
- Bug fixes that correct behavior to match the WebAssembly spec
- Changes to `pub(crate)` internal APIs

## Minimum Supported Rust Version (MSRV)

The current MSRV is Rust 1.75.0 (stable).

MSRV bumps are treated as minor version changes, not patch changes.

## Supported Targets

- `x86_64-unknown-linux-gnu` (primary)
- Any target supporting `no_std` + `alloc`
- ATOS kernel integration target

## Feature Stability

All default features (`simd`, `gc`, `exceptions`, `threads`, `memory64`)
are considered stable. Disabling a feature may reduce functionality but
should not break compilation of code that does not use the feature.
