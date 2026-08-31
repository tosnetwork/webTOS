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
   `wasm32-unknown-unknown`. The seed is fixed within one compiled binary, but
   `const-random` chooses a new value on each rebuild unless
   `CONST_RANDOM_SEED` is set; the release builder sets it explicitly so the
   wasm itself is reproducible.
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

7. `sleigh/sleigh-runtime/src/lifter.rs`: `resolve_export` forwards an
   `Export::Value` sub-table operand as-is (`resolve_operand`) instead of
   resolving it to a value (`resolve_value`). When a constructor exports a
   sub-table whose own export is a RAM reference — e.g. a newer Ghidra x86
   set wraps short conditional jumps as `jccRel8: rel8 is rel8 { export
   rel8; }`, where `rel8` exports `*[ram]:8` — the nested export must
   forward the reference. Resolving to a value emitted a load, so `goto`
   landed on the *bytes stored at* the target rather than the target,
   producing a pointer-shaped garbage jump (the "PageFault to a huge
   address" symptom). Verified with `exec_diff`: the `JNZ rel8` divergence
   between the old and a newer spec disappears. Only exercised by specs that
   use the nested-export form; the vendored fork spec does not, so this is
   inert until an AVX-512-capable spec is adopted.

8. `icicle-cpu/src/exec/helpers.rs`: added p-code-op helpers the spec leaves
   as opaque `pcodeop`s but that real workloads (Node/V8, OpenSSL, TLS
   clients, Rust std) issue directly, so without them they trap as
   unimplemented: the AES-NI round primitives (`aesenc`, `aesenclast`,
   `aesdec`, `aesdeclast`, `aesimc`, `aeskeygenassist`), `pshufb`, `psadbw`,
   and scalar `roundsd`/`roundss`. All are verified against the native x86-64
   intrinsics by `x64-engine/examples/sse_probe.rs`. Note: `roundsd`/`roundss`
   round to nearest-ties-even unconditionally — icicle's p-code carries only
   two operands, so the instruction's imm8 rounding-mode is dropped during
   lifting; the IEEE/MXCSR default is used.

9. `icicle-cpu/src/exec/helpers.rs`: the pre-M9 CPUID profile advertised an SSE/SSE2/SSE3
   baseline. `cpuid_basic_info` reports max-basic-leaf 1 (was 0) so software
   reads leaf 1 at all — V8 aborts (`Check failed: cpu.has_sse2()`) otherwise;
   leaf 1 EDX gains the SSE2 baseline (`FeatureInformationEdx`) and ECX keeps
   SSE3/AES-NI. At that stage AVX/AVX-512 remained unadvertised. Item 11
   records the later M9 profile that supersedes this baseline.

10. `icicle-mem/src/physical.rs`: raised `MAX_PAGES` from 50,000 (~195 MiB of
    guest physical memory) to 262,144 (1 GiB). Pages are allocated lazily, so
    this reserves nothing up front; it is a runaway-allocation backstop. Large
    statically linked agent binaries exceed the old limit at load time — the
    ~246 MiB Codex musl build needs ~63,000 pages for its segments alone,
    before any runtime heap.

11. M9 adds the versioned `webtos-x86_64-icelake-simdutf-v1` userspace
    execution profile. `icicle-cpu/src/exec/x86_profile.rs` is the single
    CPUID/XCR0/xstate component authority; `helpers.rs` implements standard
    FXSAVE/FXRSTOR and XSAVE/XRSTOR plus the published VEX/AVX2/EVEX p-code
    operations; the x86 language files bind complete XMM/YMM/ZMM aliases,
    masking, upper-lane clearing, and precise memory forms. The profile
    publishes AVX, AVX2, BMI1/BMI2, AVX-512F/CD/BW/VL/VBMI2/VPOPCNTDQ and
    deliberately omits AVX-512DQ. VAES and VPCLMULQDQ remain reachable through
    the separately published AES-NI/PCLMULQDQ bits and are included in the
    native oracle. The generic lifter also rejects the x86-64 EVEX reserved
    combination `z=1, aaa=000` before generated SLEIGH semantics can execute
    it as an unmasked operation; ptrace verifies SIGILL and the restart RIP.
    CPUID.15H/16H and extended leaf 0x80000007 publish the virtual engine's
    explicit 1 GHz invariant-TSC contract, and RDTSC/RDTSCP include the same
    suspension offset as the Linux monotonic clock.
    The p-code core also gains a width-aware `IntCountTrailingZeroes` operation
    (`tzcount` in SLEIGH, Wasm `ctz` in the JIT); BMI1 `TZCNT` uses it instead
    of a data-dependent 16/32/64-iteration p-code loop. This preserves the
    native result and flags while avoiding pathological bitmap-scan overhead
    in the pinned JavaScript runtime.
    The execution contract is gated by
    `x64-engine/tests/native_oracle.rs`, the xstate tests, and the portable
    native/interpreter/JIT/browser fingerprint; see
    `docs/M9_ICE_LAKE_EXECUTION_PARITY.md`.

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
