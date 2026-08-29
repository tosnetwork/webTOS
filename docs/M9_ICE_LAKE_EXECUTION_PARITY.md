# Milestone 9: Ice Lake Execution Parity

- **Status:** proposed, not started
- **Relationship to M7:** follow-on ISA coverage; it is not required to close
  the Claude Code TUI gate
- **Primary target:** the pinned Claude Code/Bun workload selects simdutf's
  `icelake` implementation through normal runtime detection and completes a
  real interactive task without an environment override

## Why this is a separate milestone

webTOS currently advertises a conservative SSE CPU profile. The upgraded
Ghidra specification can decode VEX and EVEX encodings, and it defines YMM,
ZMM, and opmask registers, but decode coverage is not execution correctness.
The AVX and AVX-512 feature bits remain clear because their p-code semantics,
extended state, and OS-visible save/restore behavior have not been validated as
one coherent architecture.

The existing baseline is not fully self-consistent even before AVX is added:
CPUID.1 advertises XSAVE while CPUID.0 reports a maximum basic leaf of 1, XCR0
resets to zero, the leaf 0x0d and XSAVE/XRSTOR user operations have no execution
helper, and the Linux signal frame does not transfer guest-visible fp/xstate.
M9-A must first make the conservative profile truthful. A temporary removal of
an unsupported bit is preferable to preserving a false capability claim.

There is also a confirmed CPUID.1 register-order defect: the Rust helper writes
its intended ECX mask into tuple slice 8 and EDX mask into slice 12, while the
SLEIGH instruction maps those slices to RDX and RCX respectively. Existing
tests observe only selected bits whose positions happen to collide across the
two masks. The same hand-encoded ordering puts the extended leaf 0x80000001
SYSCALL and LONG_MODE bits in RCX instead of EDX. M9-A's first red gate must
compare all four output registers for every supported leaf and catch these
swaps before any new feature is considered. The implementation should route
all leaves through one typed `CpuidResult { eax, ebx, ecx, edx }` adapter so
individual helpers cannot re-invent the SLEIGH tuple layout.

The distinction is observable in the pinned Claude Code 2.1.247 fixture
(`sha256:5fb321bf417ffc5cd4e3f36e7c9c7e029bf47aaa36d5621db979fcc5e6eabe15`).
With normal dispatch, simdutf does not select an accelerated implementation
under the current virtual CPU profile. Forcing
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
occurs before the previously observed simdutf path loop and proves that
selecting the Ice Lake implementation activates broad AVX-512 code in
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
cache topology, timing, frequency, or a marketing model number.

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
each vector length, page-boundary operands, and invalid encodings. Native
results are stored as versioned evidence with CPU identity, microcode, kernel,
compiler/assembler versions, source bytes, input state, comparison mask, and
result digest.

Architecturally approximate operations are tested against their specified
error bounds unless the oracle is the exact microarchitecture whose result is
being claimed. “Bit for bit” applies to architecturally deterministic state; it
must not turn one processor's permitted approximation into a false ISA rule.

The hardware job must fail closed when the required feature set is absent. A
skipped native oracle is not a pass. Browser CI replays the committed oracle
corpus and must agree across Chromium, Firefox, and WebKit instruction for
instruction.

The currently available x86-64 fixture host is a Xeon Platinum 8455C
(Sapphire Rapids), not Ice Lake. It can serve as a feature-superset semantic
oracle for deterministic instructions, but it is not an Ice Lake CPUID or
microarchitecture authority. M9-A must obtain and record an actual Ice Lake
profile capture; any hardware job run elsewhere must label itself accurately.

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
| M9-I | Build the raw-byte native oracle, comparison schema, minimizer, and portable replay runner | none | Deliberately corrupted result, mask, state, memory, and fault metadata all fail |
| M9-J | Validate and repair VEX/AVX/AVX2 execution while feature publication remains off | M9-C, M9-I | Advertised-candidate corpus matches native state and faults |
| M9-K | Validate EVEX operands, masks, tuple addressing, and instruction-family semantics in parallel child packages | M9-C, M9-I | Includes the two Claude canaries plus systematic widths, masks, memory, and fault cases |
| M9-L | Close the feature-coverage ledger, enable the profile, and integrate JIT fallback, workloads, browsers, and evidence | M9-A-M9-K | No unvalidated opcode sits behind a bit; simdutf auto-selects `icelake`; all release gates pass |

Parallel changes must not edit shared feature constants opportunistically.
Packages add semantics and tests while the public profile remains conservative;
M9-L is the only package that enables the completed profile by default.

## Acceptance gates

M9 is complete only when all of the following hold:

- CPUID and XGETBV expose the versioned profile without contradictions.
- Native differential coverage is complete for every instruction family
  implied by the advertised feature bits, including defined faults and state.
- XSAVE/XRSTOR and signal delivery preserve every enabled user-state component.
- The strict x86-64 Linux suites pass with `WEBTOS_REQUIRE_FIXTURES=1` and no
  skip.
- Interpreter and JIT modes produce the same architectural traces; unsupported
  wide JIT operations take an explicit interpreter fallback.
- The oracle corpus passes in Chromium, Firefox, and WebKit with identical
  instruction fingerprints.
- The decoder corpus no longer exempts VEX/EVEX encodings covered by the
  profile.
- The pinned Node, Codex, OpenFox, and Claude Code compatibility profiles do not
  regress.
- Claude Code completes a real interactive TUI task with simdutf reporting
  `icelake`, selected through normal detection, with no
  `SIMDUTF_FORCE_IMPLEMENTATION` variable.
- The milestone publishes correctness and performance evidence separately;
  no speedup is required for correctness completion.

## Out of scope

- Exact Ice Lake timing, cache hierarchy, branch prediction, power behavior,
  or RDTSC wall-clock behavior.
- Privileged instructions, kernel boot, devices, SGX, and other platform
  facilities not required by the Linux userspace execution contract.
- Enabling an extension merely to satisfy a library's name check.
- Requiring M9 to close the M7 Claude TUI gate; the conservative SSE/Westmere
  route remains the shorter M7 correctness path.

## Starting evidence and code anchors

- `third_party/icicle/icicle-cpu/src/exec/helpers.rs`: current CPUID maximum
  basic leaf, the currently inconsistent XSAVE claim, and conservative feature
  constants.
- `third_party/ghidra-x86/languages/ia.sinc`: XCR0, XMM/YMM/ZMM aliases,
  K0-K7, XGETBV/XSETBV, the unimplemented CPUID.0d user operation, and opaque
  XSAVE/XRSTOR p-code operations.
- `third_party/ghidra-x86/languages/avx512.sinc`: generated EVEX decode and
  semantics requiring validation, including opaque canary operations and the
  GPR-source broadcast rule whose input is currently missing.
- `third_party/ghidra-x86/PROVENANCE.md`: the explicit warning that AVX-512
  decode exists while execution semantics are not validated.
- `crates/x64-engine/examples/sse_probe.rs`: native-intrinsic differential
  precedent.
- `crates/x64-engine/examples/exec_diff.rs`: current instruction-step state
  comparison precedent; it compares only GPRs and must not be mistaken for the
  M9 native oracle.
- `crates/x64-engine/tests/decode_diff.rs`: current VEX/EVEX exemptions that
  the advertised profile must remove.
- `third_party/icicle/icicle-cpu/src/regs.rs`: dynamic register accesses that
  currently truncate or reject values wider than 128 bits.
- `third_party/icicle/sleigh/sleigh-runtime/src/lifter.rs` and
  `third_party/icicle/icicle-cpu/src/exec/interpreter.rs`: additional p-code
  arguments and the `u128` helper-argument slot that cannot transport a whole
  YMM/ZMM operand.
- `crates/linux-compat/src/syscall.rs`: current signal delivery uses a fixed
  zeroed ucontext area and restores private saved state rather than transferring
  guest-visible fp/xstate.
- `docs/workloads/node.md`: current workload-level AVX/AVX-512 limitation.

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
