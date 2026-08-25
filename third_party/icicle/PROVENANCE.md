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
4. `icicle-cpu/src/elf.rs`: debug-info loading is best-effort — errors
   (e.g. compressed DWARF sections in Go binaries) are logged and ignored
   instead of failing the load.
5. `icicle-mem/src/mmu.rs`: added `Mmu::clear_code_cache`, which drops the
   `executed` flags and `IN_CODE_CACHE` permission bits so the VM can
   recover from self-modifying-code faults by flushing lifted blocks and
   retrying the write (data sharing a page range with executed code, e.g.
   OpenSSL initialization, hits this).
6. `sleigh/sleigh-parse/src/{lexer.rs,parser.rs}`: emit a synthetic
   end-of-line token at a source's boundary (a new `Lexer.emitted_boundary_line`
   flag drives it in `Parser::lexer_next`). A SLEIGH source, or an included
   file, may end without a trailing newline; directives and constructors
   expect a line terminator, so the file boundary now supplies one. Without
   this, compiling a recent Ghidra x86 language set fails on
   `cmpccxadd.sinc`, which ends with `@endif` and no newline. Enables
   compiling newer specifications; the AVX-512 spec upgrade itself is not
   yet applied (it changes the execution semantics of existing instructions
   and needs an execution-differential pass first).

When updating this vendor copy, re-apply the patches and rerun the
`x64-engine` and `linux-compat` test suites for native and
`wasm32-unknown-unknown` targets.

## Known issues

- The x86 SLEIGH lifter mis-decodes the length of at least one instruction
  reached during glibc's `init_cpu_features` when CPUID advertises a
  max-basic-leaf above 1 (so leaf 2+ cache/topology descriptors are
  walked). The symptom is a later fetch landing mid-instruction and
  faulting. CPUID leaf handling in `icicle-cpu/src/exec/helpers.rs` is
  therefore left at the upstream default (max basic leaf 1). Raising it
  (needed for Node.js/V8, milestone 7) requires closing the decode gap
  first, ideally with a differential-decode harness.


- On `wasm32-unknown-unknown`, building the interpreter at `opt-level = 3`
  miscompiles instruction semantics (BusyBox `ls` enters an endless loop
  that is correct at `opt-level = 2`, in native builds, and with
  `debug-assertions` enabled). The `crates/` workspace pins its release
  profile to `opt-level = 2`; do not raise it without re-running the wasm
  workload harness (`web/test_node.mjs`).
