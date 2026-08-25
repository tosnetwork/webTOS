# Vendored: icicle-emu (subset)

- Upstream: https://github.com/icicle-emu/icicle-emu
- Commit: `2b47d30920a67c19c01df929284d005153417dc9`
- License: MIT OR Apache-2.0 (see `LICENCE-MIT`, `LICENCE-APACHE`)

## Subset

Only the CPU-emulation core is vendored: `icicle-cpu`, `icicle-mem`, and the
`sleigh/` crates (`pcode`, `sleigh-parse`, `sleigh-compile`,
`sleigh-runtime`). The JIT (`icicle-jit`), Linux userspace environment
(`icicle-linux`), VM front end (`icicle-vm`), and fuzzing/GDB tooling are not
vendored; webTOS provides its own interpreter loop and Linux environment in
`crates/x64-engine`.

## Local patches

1. `Cargo.toml` (workspace): `ahash` switched to
   `default-features = false, features = ["std", "compile-time-rng"]`.
   Removes the `getrandom` dependency so the crates build for
   `wasm32-unknown-unknown`, and makes hash seeding deterministic.
2. `icicle-cpu/src/lifter/mod.rs`: sentinel `UNKNOWN_BLOCK` changed from
   `0xbadbadbadbad` to `usize::MAX - 0xbad` so it fits a 32-bit `usize`.
3. `icicle-cpu/src/exec/const_eval.rs`: `shift_left`/`shift_right` calls use
   fully qualified `BitVecExt::` syntax to silence the
   `unstable_name_collisions` future-incompatibility warning.

When updating this vendor copy, re-apply both patches and rerun the
`x64-engine` test suite for native and `wasm32-unknown-unknown` targets.
