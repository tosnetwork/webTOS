# Vendored: wasbi (core crate)

- Upstream: https://gitlab.com/atos-im/wasbi
- Commit: `dcd858844f9e9570ba289c76a6adb9a86d7b240e`
- License: MIT (see `LICENSE`)

wasbi is the no_std WebAssembly interpreter used by the kernel's Wasm agent
runtime (`src/wasm/`, `src/agents/wasm_agent.rs`). It is vendored so the
kernel build does not depend on any external repository; the root
`Cargo.toml` references it by path.

## Subset

Only the core interpreter crate is vendored: `src/`, `tests/`, `benches/`,
`docs/`, and the crate manifest. Not vendored (still in the upstream
repository): the ecosystem crates (`crates/`: c-api, cli, compat, wasi,
wat), the spec-test harness (`tools/wasm-spec-test`), and fuzz targets.

## Local patches

1. `Cargo.toml`: the `[workspace]` table was reduced to an empty marker so
   the crate stands alone (the upstream members are not vendored).

When updating this vendor copy, re-apply the patch and rebuild the kernel
(`cargo build` at the repository root).

## History note

The kernel previously pinned `github.com/tosnetwork/wasbi` at
`5df1c118...`, whose history is not part of the GitLab repository. This
vendor copy supersedes that pin.
