# Milestone 9: Ice Lake Execution Parity

- **Status:** ISA implementation and browser acceptance are complete; the
  final live Claude task remains blocked at the client/API lifecycle boundary
- **Relationship to M7:** follow-on ISA coverage. M7 could use the conservative
  SSE/Westmere route, but M9's own final acceptance requires the pinned Claude
  Code workload to complete under the published Ice Lake profile
- **Primary target:** the profile satisfies the pinned simdutf `icelake`
  selector through normal runtime detection, and the pinned Claude Code/Bun
  workload completes a real interactive task without a dispatch override

## Why this is a separate milestone

Before M9, webTOS advertised a conservative SSE CPU profile. The upgraded
Ghidra specification could decode VEX and EVEX encodings and represented YMM,
ZMM, and opmask registers, but decode coverage was not execution correctness.
M9 closes that gap as one coherent architecture: the versioned
`webtos-x86_64-icelake-simdutf-v1` profile now publishes only the AVX-family
features whose p-code semantics, extended state, faults, and OS-visible
save/restore behavior are covered by the native authority and portable replay.

The pre-M9 baseline was not fully self-consistent even before AVX was added:
CPUID.1 advertised XSAVE while CPUID.0 reported a maximum basic leaf of 1,
XCR0 reset to zero, leaf 0x0d and XSAVE/XRSTOR had no execution helper, and the
Linux signal frame did not transfer guest-visible fp/xstate. The completed
profile derives CPUID.0d and serialization from the same xstate table, starts
with XCR0 `0xe7`, faults invalid XGETBV/XSETBV use, and transfers the standard
Linux xstate image through `rt_sigframe` and `rt_sigreturn`.

The starting implementation also had a CPUID register-order defect: feature
masks intended for ECX and EDX were exchanged at the Rust/SLEIGH tuple
boundary, including extended-leaf SYSCALL and LONG_MODE bits. The typed
`CpuidResult { eax, ebx, ecx, edx }` adapter and all-register golden tests now
prevent this class of defect.

The distinction is observable in the pinned Claude Code 2.1.247 fixture
(`sha256:5fb321bf417ffc5cd4e3f36e7c9c7e029bf47aaa36d5621db979fcc5e6eabe15`).
With normal dispatch, simdutf did not select an accelerated implementation
under the pre-M9 virtual CPU profile. Forcing
`SIMDUTF_FORCE_IMPLEMENTATION=westmere` gets past that dispatch failure and is
useful for diagnosing M7, but it is not a CPU implementation. Forcing
`SIMDUTF_FORCE_IMPLEMENTATION=icelake` selects the Ice Lake object and reaches
an execution failure after 142,435,521 retired guest instructions:

```text
RIP 0x399b8e2: 62 f2 7d 48 58 0d 54 67 c5 fc
               vpbroadcastd zmm1, DWORD PTR [rip-0x33a98ac]
RIP 0x399b8f0: 62 f3 75 48 25 06 f8
               vpternlogd zmm0, zmm1, ZMMWORD PTR [rsi], 0xf8
```

Both encodings decode. Their generated semantics call opaque p-code operations
that have no registered execution helper, so the VM converts
`UnimplementedOp` into its guest-visible `IllegalInstruction` exit. The failure
occurred before the previously observed simdutf path loop and proved that
selecting the Ice Lake implementation activated broad AVX-512 code in
Bun/JavaScriptCore, not one isolated UTF routine. M9 therefore treats CPUID,
extended state, instruction execution, Linux signal state, and the native
oracle as one milestone.

## Non-negotiable rule

No AVX, AVX2, or AVX-512 CPUID feature bit may be enabled merely because the
corresponding instructions decode or one workload reaches a later point. A bit
may be advertised only after:

1. its architectural prerequisites and XCR0 state are coherent;
2. every instruction family implied by the advertised profile is either
   implemented and differentially gated or excluded by a narrower truthful
   profile;
3. XSAVE/XRSTOR and Linux signal delivery preserve the enabled state; and
4. the strict native, browser, and workload matrices pass without an
   implementation-forcing environment variable.

Every new gate must be demonstrated red against the behavior it is intended to
catch before its fix is accepted.

## Architectural contract

### CPUID and XCR0

Define one named, versioned virtual CPU profile instead of scattering feature
constants through the CPUID helper. Every basic leaf and subleaf through the
advertised maximum must return the profile's documented result without an
`IllegalInstruction`; intercepted but unsupported leaves cannot become p-code
traps. The profile must provide mutually consistent results for at least:

- CPUID leaves 0, 1, 7, and 0x0d, including valid maximum leaf/subleaf values;
- CPUID leaves 0x15, 0x16, and 0x80000007 publishing one coherent 1 GHz
  invariant-TSC contract, plus the matching Ice Lake Server family/model;
- XSAVE, OSXSAVE, AVX, AVX2, BMI1/BMI2, and the exact AVX-512 dependency closure
  required by the chosen Ice Lake profile;
- the state-component sizes, offsets, and capabilities reported by leaf 0x0d;
- XGETBV for XCR0, with x87, XMM, YMM, opmask, ZMM_Hi256, and Hi16_ZMM state
  enabled coherently; and
- rejection of invalid XCR0 combinations rather than silently accepting them.

Leaf 7 EAX must be the actual maximum supported subleaf, not a sentinel such as
`u32::MAX`. Leaf 0x0d must be derived from the same component-layout table used
by XSAVE/XRSTOR so enumeration and serialization cannot drift.

XCR0 is initialized by the virtual execution profile. Userspace may inspect
XCR0 with XGETBV only for a valid selector; invalid selectors must fault.
XSETBV must retain its architectural privilege behavior rather than becoming a
guest-controlled feature switch.

The milestone emulates a truthful userspace execution profile, not Ice Lake
cache topology, branch prediction, or physical-core performance. Its virtual
timing contract is intentionally simple and explicit: one invariant-TSC tick
per nanosecond, advanced across host suspension together with
`CLOCK_MONOTONIC`.

### Runtime thread and clock substrate

The ISA profile cannot be validated with a runtime that silently takes a
different operating-system path. The pinned Bun/Claude image reads
`/sys/devices/system/cpu/online` before creating its GC helpers and uses Linux
`clone3`. The Linux layer therefore exposes one stable four-logical-CPU
contract through sysfs and `sched_getaffinity`, and decodes `struct clone_args`
versions 0-2 into the same `CloneSpec` used by legacy `clone`. Future non-zero
fields and unsupported PID-fd, explicit-PID, and cgroup authorities fail
closed. Logical CPUs are deterministically time-sliced by the single execution
engine; the topology controls bounded runtime helper provisioning, not host
parallelism.

Realtime, monotonic, process-CPU, and thread-CPU clocks are separate domains.
Only realtime clocks carry the epoch, only realtime/monotonic clocks include a
host suspension gap, and CPU clocks count retired work. RDTSC/RDTSCP use the
same global invariant offset as monotonic time. This prevents a runtime from
interpreting a browser pause as CPU consumed or calibrating two contradictory
clocks.

### YMM, ZMM, and opmask state

The register model must preserve:

- the aliasing between XMM, YMM, and ZMM views;
- all 32 ZMM registers available in 64-bit EVEX encodings;
- VEX/EVEX upper-lane zeroing versus legacy SSE preservation;
- K0-K7 widths and the special unmasked meaning of K0 where the ISA specifies
  it;
- merge masking, zero masking, and destination preservation at each element
  width; and
- MXCSR-controlled rounding and exception state, including embedded rounding
  and suppress-all-exceptions forms where advertised.

The raw register store and SLEIGH aliases can represent wide state in 128-bit
slices. The unsafe boundary is generic dynamic/helper access: it currently
preserves only the low 128 bits of a 256-bit input and yields no useful 512-bit
input, while additional p-code arguments pass through a single `u128` slot. A
naive whole-ZMM helper can therefore observe a third vector operand as zero.
M9-C must either make this ABI explicitly width-safe or keep wide operations
lowered into slices; silent truncation is forbidden.

Interpreter correctness is the first gate. The JIT may initially bail to the
interpreter for wide operations, but it must produce identical architectural
state when coverage is added.

### EVEX execution

Decode success is only the input to this work. Execution gates must cover:

- register and memory forms at 128-, 256-, and 512-bit vector lengths;
- EVEX register extension, tuple types, compressed displacement, broadcast,
  and immediate handling;
- masked loads and stores, including masked-off fault suppression and
  cross-page behavior;
- arithmetic, logical, compare, conversion, shuffle, permute, compress,
  expand, gather, and scatter families required by the advertised profile;
- defined RFLAGS and MXCSR effects, NaNs, signed zero, overflow, saturation,
  and integer-indefinite results; and
- precise illegal-instruction and memory-fault class, address, and resume PC.

The two instructions at the first Claude/Bun failure (`vpbroadcastd` and
`vpternlogd`) are mandatory canaries, not sufficient completion evidence.
For the first implementation tranche, broadcast can be lowered directly into
32-bit lanes and ternary logic into 128-bit chunks, avoiding an unsafe
whole-ZMM helper. The ternary corpus covers all 256 immediates; for the observed
`0xf8` case, each result bit is `old_destination | (source1 & source2)`.

EVEX operand validation is independent of those semantics. The generated
GPR-source `vpbroadcastd` rule currently omits its `r32` input, so register and
memory broadcast forms require separate decode gates even after the observed
memory-source canary executes.

### XSAVE, XRSTOR, and Linux state transfer

First make FXSAVE/FXRSTOR and their 64-bit forms architecturally correct; the
current inline legacy form explicitly does not use the architectural layout,
and the 64-bit forms are opaque unregistered operations. Then implement the
standard-format XSAVE state image needed by userspace for the enabled XCR0
components. Compacted and supervisor forms remain unadvertised unless
implemented separately. Tests must cover:

- CPUID leaf 0x0d layout against the bytes written by XSAVE;
- XSAVE/XRSTOR round trips with independently seeded legacy, YMM, opmask, and
  ZMM state;
- requested-feature masks, initialized-state behavior, alignment, page
  crossings, and faults; and
- a real x86-64 Linux `rt_sigframe` whose guest-visible `ucontext_t`, signal
  mask, fpstate, and aligned xstate area can be inspected and lawfully modified
  by the handler before `rt_sigreturn`; and
- signal delivery and `rt_sigreturn` preserving the full enabled vector state.

Advertising XSAVE while returning an incomplete state image is a correctness
failure even when the current workload does not inspect the omitted bytes.

## Native bit-for-bit differential authority

An x86-64 Linux hardware runner is the execution authority. The existing
`sse_probe` pattern is a starting point, but M9 needs a data-driven probe that
executes raw instruction bytes natively and in the interpreter from the same
seeded state. The preferred native mechanism is a ptrace-supervised child:
install GPR and `NT_X86_XSTATE` state, single-step exactly one raw instruction,
then read registers, xstate, memory, and signal/fault metadata without a signal
handler or compiler-generated prologue clobbering the result.

For every case, compare:

- instruction length and next RIP;
- GPRs and architecturally defined RFLAGS;
- XMM/YMM/ZMM0-31, K0-K7, and MXCSR;
- touched memory bytes; and
- exception or fault class, fault address, and restart RIP.

Undefined and implementation-dependent result bits must be represented by an
explicit per-case comparison mask; the harness must never hide a mismatch by
globally ignoring a register or flag. Corpus inputs combine edge cases,
deterministic pseudo-random values, register/memory aliases, every mask pattern,
each vector length, page-boundary operands, and invalid encodings. The
normalized core-corpus result is pinned in the oracle source as a versioned
digest. Its reproducibility context records CPU identity, microcode, kernel,
compiler/assembler versions, source bytes, deterministic input construction,
and the per-instruction comparison mask. Specialized approximation and fault
cases remain named executable gates rather than being folded into a misleading
bitwise digest.

Architecturally approximate operations are tested against their specified
error bounds unless the oracle is the exact microarchitecture whose result is
being claimed. “Bit for bit” applies to architecturally deterministic state; it
must not turn one processor's permitted approximation into a false ISA rule.

The hardware job must fail closed when the required feature set is absent. A
skipped native oracle is not a pass. Browser CI replays the committed oracle
corpus and must agree across Chromium, Firefox, and WebKit instruction for
instruction.

The recorded x86-64 fixture host is a Xeon Platinum 8455C (Sapphire Rapids),
not Ice Lake. It is a valid feature-superset execution authority for the
architecturally deterministic instructions in this userspace profile, and the
evidence labels it accurately. It is not used as an Ice Lake CPUID, cache,
timing, approximation, or microarchitecture authority. An actual Ice Lake
capture is required only before making one of those model-specific claims;
none is part of M9. Architecturally approximate operations are instead held to
their specified error bounds and special-value behavior.

The published evidence bundle contains the normalized environment and CPUID
capture, XCR0/XSAVE layout, versioned corpus plus digest, native and emulator
results, advertised-feature coverage, zero-skip summary, and exact commands.
The native oracle is run twice and normalized outputs must be byte-identical
before the emulator comparison is trusted.

## Parallel work packages

Each package should be a reviewable PR with its own red-before-green gate.
Feature publication remains last so packages can land without changing the
default workload dispatch.

| Package | Scope | Can proceed with | Exit evidence |
|---|---|---|---|
| M9-A | Add a typed CPUID-result adapter; fix basic and extended register ordering; clear the unsupported XSAVE claim | M9-I | Golden tests compare EAX/EBX/ECX/EDX for every current leaf and go red on the present swap |
| M9-B | Define a total, named virtual profile and feature dependency graph while keeping AVX-family bits off | M9-A, M9-I | Every leaf/subleaf through the advertised maxima returns a valid documented result |
| M9-C | Validate XMM/YMM/ZMM aliases and K0-K7; make dynamic/helper wide access fail closed or width-safe; define reset and upper-lane rules | M9-I | Seed/read/write/alias/upper-zeroing and multi-input sentinel tests cover every slice of all 32 vector and eight mask registers |
| M9-D | Add immutable xstate policy, initialized XCR0, validated XGETBV, and user-mode XSETBV faulting | M9-B, M9-C | Valid and invalid selector/state/privilege tests match the architectural contract |
| M9-E | Make FXSAVE/FXRSTOR and their 64-bit forms architectural | M9-C, M9-I | Defined legacy fp/SSE image bytes and fault behavior match native cases |
| M9-F | Implement standard XSAVE/XRSTOR and derive CPUID leaf 0x0d from the same component table | M9-D, M9-E | Independently seeded state components round-trip and native-layout bytes match |
| M9-G | Implement guest-visible x86-64 `rt_sigframe` for GPRs, mask, altstack, and legacy fp/SSE state | M9-E | A handler reads and edits context; validated sigreturn applies lawful edits |
| M9-H | Extend Linux signal frames to YMM, opmask, and ZMM xstate | M9-F, M9-G | Handler clobber/edit/preserve tests match Linux UAPI layout and behavior |
| M9-I | Build the raw-byte native oracle, comparison schema, one-instruction reproducers, and portable replay runner | none | Deliberately corrupted GPR, mask, xstate, memory, and fault metadata all fail |
| M9-J | Validate and repair VEX/AVX/AVX2 execution while feature publication remains off | M9-C, M9-I | Advertised-candidate corpus matches native state and faults |
| M9-K | Validate EVEX operands, masks, tuple addressing, and instruction-family semantics in parallel child packages | M9-C, M9-I | Includes the two Claude canaries plus systematic widths, masks, memory, and fault cases |
| M9-L | Close the feature-coverage ledger, enable the profile, and integrate JIT fallback, workloads, browsers, and evidence | M9-A-M9-K | No unvalidated opcode sits behind a bit; simdutf auto-selects `icelake`; all release gates pass |

During implementation, parallel changes did not edit shared feature constants
opportunistically. Packages added semantics and tests while the public profile
remained conservative; M9-L alone enabled the completed profile by default.

## Implementation record

All work packages are implemented on `feat/m9-ice-lake-parity`. The public
profile was enabled only after the state-transfer and execution authorities
were green.

| Package | Result | Authoritative gate |
|---|---|---|
| M9-A/B | Complete | `cpuid.rs` compares complete register tuples, finite leaf boundaries, the xstate-derived leaf 0x0d, and the exact simdutf Ice Lake selector prerequisites. |
| M9-C | Complete | `wide_state.rs` covers all ZMM slices, K registers, aliases, and upper-lane behavior without transporting a YMM/ZMM through a `u128` helper argument. |
| M9-D | Complete | `xstate_policy.rs` covers XCR0 `0xe7`, invalid selectors, and user-mode XSETBV faulting without mutation. |
| M9-E/F | Complete | `fxsave.rs` and `xsave.rs` cover standard layouts, requested masks, init state, complete round trips, reserved bytes, MXCSR, alignment, and precise page-crossing faults. |
| M9-G/H | Complete | `signal_context.rs` compiles a real Linux handler that inspects and edits GPRs and the complete standard xstate image, then verifies the lawful edits after `rt_sigreturn`. |
| M9-I | Complete | `native_oracle.rs` uses ptrace GPR and `NT_X86_XSTATE` authority, derives an explicit undefined-flags mask for each instruction, runs every normalized native case twice, and detects deliberately corrupted GPR, mask, xstate, memory, and fault results. The core authority digest is `bee2b17f0b247fde`; `m9_icelake_oracle.elf` is the portable replay. |
| M9-J/K | Complete | The native corpus covers VEX/AVX2 and the published EVEX families across widths, masks, register/memory forms, VSIB gather/scatter, special floating-point classes, page boundaries, and partial-fault restart state. BMI1 `TZCNT` lowers to the width-aware p-code `IntCountTrailingZeroes` operation, so JavaScript-runtime bitmap scans use one interpreter/wasm `ctz` instead of a data-dependent p-code loop. |
| M9-L | Complete | `feature_coverage` reports 789 published-profile mnemonics, including BMI1/BMI2 and VEX AES/PCLMUL, and zero reachable opaque operations without helpers. Interpreter and JIT produce the same portable result; browser replay uses the same digest-pinned ELF. The Linux contract exposes four coherent logical CPUs, a 1 GHz invariant TSC, separate thread/process CPU clocks, deterministic preemption, and the Bun-safe `sched_setscheduler` subset. |

The portable corpus is intentionally smaller than the ptrace corpus. The
ptrace suite is the per-instruction hardware comparison authority; the static
ELF composes representative operations from every published extension and
provides a deterministic cross-engine replay fingerprint. Treating the latter
as a replacement for the former would weaken the gate.

### Recorded authority and portable artifact

The 2026-08-30 native authority is Linux 6.8.0 x86-64 on a GenuineIntel Xeon
Platinum 8455C (family 6, model 143, stepping 8, microcode `0x2b000661`). The
toolchain is Rust `1.100.0-nightly (e7769602a 2026-08-24)`, GCC 15.2.0, and GNU
binutils 2.38. The host advertises every feature required by the corpus; an
absent feature fails the tests rather than becoming a skip.

The normalized ptrace core-corpus output is pinned as:

```text
M9_NATIVE_FNV1A64=bee2b17f0b247fde
```

The digest covers each instruction's raw bytes, normalized GPRs and defined
RFLAGS, explicit RFLAGS comparison mask, profile-defined xstate bytes, touched
memory, and fault signal/address. Every case is executed twice before it may
contribute to the digest.

The portable artifact is reproducible with:

```sh
gcc -nostdlib -static -Wl,--build-id=none -march=icelake-server \
  -o test_data/m9_icelake_oracle.elf test_data/m9_icelake_oracle.S
```

Its SHA-256 is
`94e367834d46c0ebb18d8ef0a30399b9dd3edecd4b9b49a3c2524c4f4dcad7c9` and
its native output is:

```text
M9_ORACLE_FNV1A64=0a7c58fd00cdfc14
```

That output commits AVX/AVX2, BMI1/BMI2, VEX AES/PCLMUL with complete ZMM
upper-lane clearing, and the selected AVX-512 feature closure. Both interpreter
and JIT replays must match the native text exactly.

The final browser matrix used `web/webtos_web.wasm` SHA-256
`4795c298ead472433d07f7b34664ec5cb0ab5509d9d8eca35ae133738373870d`.
Chromium 151.0.7922.34 and Firefox 153.0 passed 47/47 checks; WebKit 26.5
passed 38/38 applicable checks and reported eight explicit OPFS capability
skips. The M9 interpreter and JIT replays each retired 2,485 instructions in
every engine with identical fingerprints. The OPFS skips do not apply to the
M9 replay and are not counted as ISA passes.

The pinned Claude Code 2.1.247 input is SHA-256
`5fb321bf417ffc5cd4e3f36e7c9c7e029bf47aaa36d5621db979fcc5e6eabe15`.
Its version gate retired 171,923,284 identical instructions in Chromium,
Firefox, and WebKit. The separate live-task gate uses the same WASM and binary,
scoped host credentials, an API-only network allowlist, and no simdutf forcing
variable.

## Acceptance gates

M9 is complete only when all of the following hold:

- CPUID and XGETBV expose the versioned profile without contradictions.
- Native differential coverage is complete for every instruction family
  implied by the advertised feature bits, including defined faults and state.
- XSAVE/XRSTOR and signal delivery preserve every enabled user-state component.
- The strict x86-64 Linux suites pass with `WEBTOS_REQUIRE_FIXTURES=1` and no
  M9-relevant skip. Explicitly ignored rewrite and optional measurement tests
  are outside the M9 gate and are reported as such rather than counted as
  passes.
- Interpreter and JIT modes produce the same architectural traces; unsupported
  wide JIT operations take an explicit interpreter fallback.
- The oracle corpus passes in Chromium, Firefox, and WebKit with identical
  instruction fingerprints.
- The decoder corpus no longer exempts VEX/EVEX encodings covered by the
  profile.
- The pinned Node, Codex, OpenFox, and Claude Code compatibility profiles do not
  regress.
- The pinned simdutf selector gate reports `icelake` from the guest-visible
  CPUID/XGETBV tuple, and Claude Code completes a real interactive TUI task
  under the same profile with no `SIMDUTF_FORCE_IMPLEMENTATION` variable.
- The milestone publishes correctness and performance evidence separately;
  no speedup is required for correctness completion.

## Out of scope

- Exact physical Ice Lake timing, cache hierarchy, branch prediction, power
  behavior, or frequency scaling beyond the documented virtual invariant-TSC
  contract.
- Privileged instructions, kernel boot, devices, SGX, and other platform
  facilities not required by the Linux userspace execution contract.
- Enabling an extension merely to satisfy a library's name check.
- Requiring M7 to adopt the Ice Lake profile; its conservative SSE/Westmere
  route remains valid independently of M9.

## Implementation and evidence anchors

- `third_party/icicle/icicle-cpu/src/exec/x86_profile.rs`: the named CPUID and
  xstate contract, including the shared standard component table.
- `third_party/icicle/icicle-cpu/src/exec/helpers.rs`: CPUID, FXSAVE/FXRSTOR,
  XSAVE/XRSTOR, VEX/AVX2/EVEX execution helpers, precise memory access, and
  standard xstate serialization.
- `third_party/ghidra-x86/languages/{ia,bmi1,avx,avx2,avx512}.sinc`: the repaired
  instruction lowering and explicit feature annotations consumed by the
  coverage ledger.
- `third_party/icicle/sleigh/pcode`, `sleigh-compile`, and
  `icicle-cpu/src/exec/{interpreter,const_eval}.rs`: the width-aware trailing-
  zero p-code primitive shared by SLEIGH, constant evaluation, the interpreter,
  and the wasm JIT.
- `crates/x64-engine/tests/{cpuid,wide_state,xstate_policy,fxsave,xsave}.rs`:
  coherent profile and state-transfer gates.
- `crates/x64-engine/tests/native_oracle.rs`: ptrace-supervised, twice-stable
  native execution authority with exact per-case comparison.
- `crates/x64-engine/examples/feature_coverage.rs`: fail-closed mapping from
  published feature bits to reachable p-code operations and registered
  helpers.
- `crates/linux-compat/tests/signal_context.rs`: compiled guest-visible Linux
  signal-context and complete xstate round trip.
- `crates/linux-compat/tests/{process,suspend}.rs`: `clone3`, virtual CPU
  topology, deterministic preemption, clock-domain, suspension, and
  invariant-TSC gates used by the live runtime.
- `test_data/m9_icelake_oracle.{S,elf}` and
  `crates/linux-compat/tests/m9_oracle.rs`: digest-pinned native/interpreter/JIT
  portable replay, also executed by `web/test_browsers.mjs`.
- `web/probe_claude_tui.mjs`: real Claude TUI task gate with scoped credentials,
  API-only network authority, a real Edit operation, clean exit, and final file
  verification.

## Normative references

Implementation PRs must name the document revision used by their generated
cases. The initial authorities are:

- [Intel 64 and IA-32 Architectures Software Developer's Manuals](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html),
  especially Volume 1's AVX-512 detection and XSAVE-state chapters, Volume 2's
  instruction definitions, and the CPUID leaf definitions; and
- [Linux x86 userspace XSTATE documentation](https://www.kernel.org/doc/html/latest/arch/x86/xstate.html)
  plus the matching kernel UAPI signal-context definitions for the fixture
  host kernel.

The native machine is the result oracle, but it does not replace the manuals:
undefined outputs, feature prerequisites, and exception rules must come from a
recorded specification revision rather than being inferred from one CPU.
