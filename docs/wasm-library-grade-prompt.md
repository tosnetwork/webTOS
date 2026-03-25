# WASM Library-Grade Refactor Prompt

Use the following prompt with Claude Code to upgrade the ATOS self-built WASM implementation toward library-grade quality comparable to `wasmi`, while preserving the custom engine architecture.

```text
You are a senior Rust and WebAssembly runtime engineer. Upgrade the ATOS custom wasm implementation from a "large prototype that works" to something much closer to wasmi in library-grade quality.

Workspace:
- Main project: /home/tomi/atos
- WASM engine code: /home/tomi/atos/src/wasm
- Spec runner: /home/tomi/atos/tools/wasm-spec-test
- Reference implementation: /tmp/wasmi_compare_20260325d1
  If /tmp/wasmi_compare_20260325d1 does not exist, then look at ~/wasmi. You may study its module boundaries, error model, and engineering discipline, but do not copy code directly and do not replace our engine with wasmi.

Important constraints:
- Keep our self-built decoder / validator / executor path.
- Do not replace the production implementation with wasmi / wasmparser / wasmtime.
- You may use wasmparser / wasmi / wasmtime only as test-only, fuzz-only, or oracle-only dependencies for validation and differential testing.
- Do not hide bugs with catch_unwind or similar panic-masking techniques. Fix the real invariant and bounds issues.
- Preserve the current RuntimeClass semantics: BestEffort / ReplayGrade / ProofGrade.
- Do not revert unrelated user changes. The worktree may be dirty.
- Use incremental refactoring with verification after each step. Do not attempt a single giant rewrite first.

Current status and known issues:
- The current WASM implementation is concentrated in a few large files:
  - src/wasm/runtime.rs is very large, roughly 5.4k LOC
  - src/wasm/validator.rs is very large, roughly 3.5k LOC
  - src/wasm/decoder.rs is very large, roughly 2.6k LOC
- Recent official spec-runner baseline:
  - 414/444 .wast files passing
  - 78058/78307 assertions passing
  - 82 skipped
  - 2 panic cases remain
- Known high-priority issues:
  1. Panic / bounds / invariant fragility
     - Validator locals path has direct indexing fragility, around src/wasm/validator.rs where local_types.push(func.locals[i]) occurs
     - Some SIMD paths can still panic under official testsuite inputs, around src/wasm/runtime.rs in i16x8/i32x4 related operations
  2. Ref type and subtyping modeling is too coarse
     - src/wasm/types.rs
     - src/wasm/decoder.rs
     - src/wasm/validator.rs
  3. Table init and init-expr validation / instantiation are not strict enough
     - src/wasm/validator.rs
     - src/wasm/runtime.rs
  4. Legacy exception handling and delegate semantics have gaps
     - src/wasm/runtime.rs
  5. Runner and host ABI limitations are mixed together with engine limitations
     - tools/wasm-spec-test/README.md
     - tools/wasm-spec-test/src/runner.rs

The goal is not only to pass more tests. The goal is to improve:
1. Correctness
2. Robustness
3. Architecture
4. Testability
5. Maintainability

Execute the work in the following order:

Phase 1: Baseline and plan
- Read /home/tomi/atos/src/wasm and /home/tomi/atos/tools/wasm-spec-test first.
- Compare the current structure against /tmp/wasmi_compare_20260325d1, especially module boundaries, error handling, and testing strategy.
- Before changing code, produce a short but concrete plan that includes:
  - Current architecture problems
  - P0 / P1 / P2 priorities
  - Which files you will modify first, and why

Phase 2: P0 hardening, mandatory first
Treat "no external wasm input should be able to panic the engine" as a hard requirement. Focus on:
- Parse / validate / instantiate / execute code paths with unchecked indexing, unwrap, expect, or implicit assumptions driven by input
- Fixed-size locals / params / stacks and other brittle boundaries
- Replacing panic scenarios with explicit WasmError / Trap / ValidationError results
- Adding bounds checks to every input-dependent array or slice access
- Fixing the known testsuite panic cases
- Ensuring malformed / invalid / boundary-case modules return structured errors instead of crashing

Requirements:
- Any remaining unwrap / panic / unsafe must be for a truly internal, proven invariant and must be documented with a short explanation
- If the invariant is not clearly proven, do not keep it

Phase 3: P1 semantic correctness
Close the highest-impact spec gaps, especially:
- Ref types, nullable references, abstract heap types, typed refs, nofunc, noextern, none, and related modeling
- Subtyping, assignability, and validation logic
- Table init-expr type checking and table initialization behavior
- Legacy exception handling semantics, especially delegate / catch / rethrow behavior
- Separate runner limitations from engine limitations so host-runner issues are not misclassified as engine bugs

Phase 4: P2 architecture refactor
Split the large monolithic files into cleaner modules. Follow wasmi's separation ideas, but keep our own implementation strategy.

Suggested direction:
- src/wasm/module/*
  - module data structures
  - imports / exports
  - init expressions
  - type definitions
- src/wasm/decode/*
  - binary reader
  - section parsing
  - reftype / valtype decoding
- src/wasm/validate/*
  - validator
  - control stack / operand stack
  - subtype rules
  - limits / invariants
- src/wasm/exec/*
  - executor
  - call frames
  - block frames
  - trap handling
- src/wasm/store/* or src/wasm/instance/*
  - instance
  - globals
  - memories
  - tables
  - refs / gc heap
- src/wasm/error.rs
  - unified error model

Architecture goals:
- Reduce the size and responsibility concentration of runtime.rs, validator.rs, and decoder.rs
- Make the boundaries between module representation, validation, instantiation, and execution explicit
- Isolate table / memory / global / ref / exception logic into narrower modules
- Add concise invariant comments where they materially help reviewability

Phase 5: P3 library-grade testing and engineering
Add the missing engineering layers expected from a library-grade runtime:
- Unit tests and integration tests for parse / validate / instantiate / execute behavior
- Regression tests for every bug fixed in this effort
- Fuzz targets for:
  - parser / decoder
  - validator
  - execution
  - differential behavior against wasmi or wasmtime if practical
- A before/after spec-runner comparison
- If failures remain, classify them explicitly as:
  - engine bug
  - runner limitation
  - unsupported proposal
  - flaky or infra issue

Required deliverables:
1. Real code changes, not only recommendations
2. A short design document, for example docs/wasm-library-grade-plan.md
3. New or updated tests
4. Validation commands that were run, with result summaries
5. A remaining-issues list with next steps

Acceptance criteria:
- Main input paths no longer panic on malformed, invalid, or boundary-case wasm
- Official spec-runner results are better than the current baseline, or at minimum all panic cases are eliminated
- The code structure is materially easier to maintain than before
- Engine bugs and runner bugs are classified more clearly
- Every high-priority issue fixed in this effort has test coverage
- If the full P1 / P2 / P3 scope does not fit in one pass, complete the largest safe increment and leave a clear TODO and failure classification document

Working style:
- Read code before editing
- Run the most relevant tests after each logical batch of changes
- Prioritize highest-ROI fixes first: panic elimination, bounds hardening, ref types, table init, and exception handling
- At the end, report:
  - what changed
  - why it changed
  - which issues are solved
  - which issues remain
  - what should be done next

Start now. First print your phased plan, then implement it directly. Do not stop at analysis only.
```

