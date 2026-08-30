# Vendored: Ghidra x86 SLEIGH language definitions

- Upstream: https://github.com/NationalSecurityAgency/ghidra
- Commit: `6b502aab73ff22397f3f1fb5d6dcf42822464ccb` (2026-08-24)
- License: Apache-2.0 (see `LICENSE`)
- Contents: `Ghidra/Processors/x86/data/languages/` only.

The `x64-engine` crate compiles `languages/x86.ldefs` (language id
`x86:LE:64:default`) at startup; this takes roughly 120 ms.

## Why upstream NSA, not the icicle-emu fork

An earlier revision vendored the icicle-emu fork of Ghidra (commit
`50230050…`) because the fork's older `sleigh-compile` could not parse the
current NSA specifications. That fork does not lift the AVX-512 family, which
Node.js/V8 and glibc's ifunc resolvers reach. This revision upgrades to the
NSA master language set (which does define AVX-512 in `avx512.sinc` /
`avx512_manual.sinc` / `gfni.sinc`) and re-applies, on top of it, the small
set of fork patches that the vendored icicle interpreter's helper ABI depends
on. A parser fix in the vendored `sleigh-parse` (see
`third_party/icicle/PROVENANCE.md`, patch #6) lets the compiler ingest this
newer set.

Verification: a dynamic execution-differential harness
(`crates/linux-compat/examples/exec_diff_dyn.rs`) runs a dynamically linked
glibc binary through the fork spec and this patched master spec in lockstep;
after the patches below they agree instruction-for-instruction for >3,000,000
instructions (to process exit). At that pre-M9 revision, a decode diff against
iced-x86 showed zero gaps on glibc and a 0.0049% residual on Node. M9 replaces
that historical SSE-only boundary with the validated profile described below.

## Local patches (re-applied from the icicle-emu fork)

The NSA master spec expresses several instructions in a form the vendored
icicle interpreter cannot execute (opaque `pcodeop`s with no helper, or forms
whose result is consumed differently than icicle's helpers produce it). Each
is replaced with the icicle fork's equivalent construct:

1. `ia.sinc` **CPUID**: the master form is `tmpptr = cpuid(EAX); EAX =
   *tmpptr` (a pointer the helper does not populate). Replaced with the fork's
   `local tmp:16; tmp = cpuid_*(EAX, ECX); EAX = tmp[0,32]; …`, matching the
   icicle helper that writes four dwords into a 16-byte varnode. Without this,
   glibc's `init_cpu_features` reads a null pointer.
2. `ia.sinc` **XGETBV**: the master form calls an `xinuse()` pcodeop icicle
   has no helper for (returns 0, zeroing `XCR0`). Replaced with the fork's
   direct `EDX:EAX = XCR0` read.
3. `ia.sinc` **SYSCALL**: `R11 = rflags` reads a packed flags register icicle
   does not maintain (it tracks individual flag varnodes). Replaced with the
   fork's `packflags(R11)`.
4. `ia.sinc` **FXSAVE/FXRSTOR** (`_fxsave`/`_fxrstor`): master declares these
   as opaque `pcodeop`s (no helper → illegal instruction when glibc's
   `_dl_runtime_resolve_fxsave` runs). Replaced with the fork's inlined macros
   that actually store/load the x87+SSE area.

These are semantics-preserving relative to the fork spec that milestones 1–6
were validated against. See `third_party/icicle/PROVENANCE.md` patch #7 for a
companion lifter fix (nested `export` sub-tables) that the newer spec's
short-jump encoding requires.

## M9 local execution patches

M9 repairs the VEX/AVX2/EVEX rules used by the versioned
`webtos-x86_64-icelake-simdutf-v1` profile. The local changes bind complete
XMM/YMM/ZMM aliases, implement upper-lane clearing, mask merge/zero behavior,
compressed and VSIB addressing, masked memory fault suppression, and lower
wide operations into width-safe slices or registered helpers. The inherited
VAES and VPCLMULQDQ rules were also changed to clear the complete ZMM alias;
the native oracle caught the previous stale high 256 bits.

These changes are not accepted by decode coverage alone. The authoritative
gates are `crates/x64-engine/tests/native_oracle.rs`, the xstate suites,
`crates/x64-engine/examples/feature_coverage.rs`, and the portable
native/interpreter/JIT/browser fingerprint. See
`docs/M9_ICE_LAKE_EXECUTION_PARITY.md` for the exact contract and evidence.

## Current feature boundary

The public profile advertises AVX, AVX2, BMI1/BMI2, AVX-512F/CD/BW/VL/VBMI2/
VPOPCNTDQ and the separately published AES-NI/PCLMULQDQ VEX forms. It
deliberately does not advertise AVX-512DQ, XOP, or another extension merely
because the language files decode it. The coverage ledger fails if an opaque
operation becomes reachable behind a published bit without a registered
helper.
