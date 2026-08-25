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
4. `icicle-mem/src/mmu.rs`: added `Mmu::clear_code_cache`, which drops the
   `executed` flags and `IN_CODE_CACHE` permission bits so the VM can
   recover from self-modifying-code faults by flushing lifted blocks and
   retrying the write (data sharing a page range with executed code, e.g.
   OpenSSL initialization, hits this).

When updating this vendor copy, re-apply the patches and rerun the
`x64-engine` and `linux-compat` test suites for native and
`wasm32-unknown-unknown` targets.

## Known issues

- On `wasm32-unknown-unknown`, building the interpreter at `opt-level = 3`
  miscompiles instruction semantics (BusyBox `ls` enters an endless loop
  that is correct at `opt-level = 2`, in native builds, and with
  `debug-assertions` enabled). The `crates/` workspace pins its release
  profile to `opt-level = 2`; do not raise it without re-running the wasm
  workload harness (`web/test_node.mjs`).
