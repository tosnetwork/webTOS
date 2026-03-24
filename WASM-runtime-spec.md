# ATOS WASM Runtime Specification

**Version:** 2.0 (Per-Agent RuntimeClass)
**Status:** Implementation Reference
**Companion to:** Yellow Paper §24.3.1

> This document is the normative specification for the ATOS WASM runtime. The yellow paper provides architectural context and roadmap; this document provides the complete opcode support matrix, runtime class policy, host function ABI, limits, and implementation contract.

---

## Table of Contents

- [1. Overview](#1-overview)
- [2. Runtime Class Model](#2-runtime-class-model)
- [3. Value Types](#3-value-types)
- [4. Module Format and Sections](#4-module-format-and-sections)
- [5. Instruction Set](#5-instruction-set)
- [6. Memory Model](#6-memory-model)
- [7. Function Calls and Control Flow](#7-function-calls-and-control-flow)
- [8. Host Functions (ATOS Syscall Bridge)](#8-host-functions-atos-syscall-bridge)
- [9. Fuel Metering](#9-fuel-metering)
- [10. Instance Lifecycle](#10-instance-lifecycle)
- [11. Agent Loading Path](#11-agent-loading-path)
- [12. Implementation Limits](#12-implementation-limits)
- [13. Error Types](#13-error-types)
- [14. SDK (atos-wasm-sdk)](#14-sdk-atos-wasm-sdk)
- [15. Differences from Standard WASM MVP](#15-differences-from-standard-wasm-mvp)
- [16. Future Extensions](#16-future-extensions)
- [Appendix A. Source File Map](#appendix-a-source-file-map)

---

## 1. Overview

The ATOS WASM runtime is the primary sandboxed execution backend for ATOS agents. It provides portable execution with fine-grained memory safety and fuel-based metering.

WASM is an `AgentRuntime` (unlike eBPF-lite, which is the policy layer). WASM agents are scheduled by the kernel, communicate via mailboxes, and consume energy budgets — they are first-class agents.

**Design goals:**

- **Per-agent determinism policy** via RuntimeClass — agents choose their trust level
- Fuel-bounded execution mapped to ATOS energy accounting
- Sandboxed memory (linear memory, bounds-checked on every access)
- Syscall bridging via host function imports (not direct kernel calls)
- Interpreter-only in Stage-2/3 (no JIT)

**Why WASM for ATOS:**

The yellowpaper §25.2.4 states: *"Full instruction-level determinism is only guaranteed for WASM agents (fuel-counted). Native agents have deterministic scheduling order but may produce different results per tick depending on CPU microarchitecture."* For maximum replay and proof guarantees, production agents should prefer WASM with ProofGrade RuntimeClass.

`[IMPL: ✅ ~4,661 lines across 6 kernel modules + agent_loader + SDK crate]`

---

## 2. Runtime Class Model

ATOS does **not** impose a single determinism policy on all agents. Different agents have different needs — a settlement agent must be provably deterministic, while an AI inference agent needs floating-point. The RuntimeClass system resolves this.

### 2.1 RuntimeClass enum

```rust
pub enum RuntimeClass {
    ProofGrade   = 0,  // strict determinism — no floats, no SIMD, no threads
    ReplayGrade  = 1,  // relaxed — floats + SIMD allowed, no threads
    BestEffort   = 2,  // full features — everything allowed (threads future)
}
```

RuntimeClass is a **per-instance** property of `WasmInstance`, not a global compile-time flag. The same WASM module can be loaded under different classes by different agents.

### 2.2 Feature matrix

| Feature | ProofGrade | ReplayGrade | BestEffort |
|---------|-----------|-------------|------------|
| Integer ops (i32/i64) | ✅ | ✅ | ✅ |
| Floating-point (f32/f64) | ❌ trap | ✅ | ✅ |
| SIMD (v128) | ❌ trap | ❌ trap | ❌ trap (future: ✅) |
| Threads / atomics | ❌ trap | ❌ trap | ❌ trap (future: ✅) |
| Deterministic replay | ✅ full | ⚠️ same-hardware only | ❌ |
| ExecutionReceipt / proof | ✅ | ❌ | ❌ |
| Fuel metering | ✅ | ✅ | ✅ |

### 2.3 When to use each class

| Class | Use for | Example agents |
|-------|---------|---------------|
| **ProofGrade** | Anything that needs third-party verification | Settlement, billing, state transitions, capability decisions |
| **ReplayGrade** | Computation that needs floats but not formal proof | AI inference, data analysis, image processing, scientific compute |
| **BestEffort** | Utility work with no verification requirement | Web crawlers, API callers, log processors, tool agents |

### 2.4 How it works

```
Agent A (ProofGrade):  WASM with integer-only — verifiable receipt
Agent B (ReplayGrade): WASM with f32/f64   — AI inference
Agent C (ProofGrade):  validates B's output  — "amount <= balance?"

A and C produce receipts. B does the heavy computation.
All three communicate via mailbox on the same kernel.
```

### 2.5 Why ProofGrade disables floats

IEEE 754 floating-point can produce different results across platforms:
- NaN bit patterns vary by CPU
- x87 vs SSE vs ARM VFP have subtle rounding differences
- `f32.nearest` and `f32.min/max` have NaN propagation edge cases

For ProofGrade agents, these differences would make replay verification fail. ReplayGrade agents accept this risk because their output is validated at the business logic level (by a ProofGrade agent), not at the bit level.

### 2.6 Why SIMD and Threads are currently disabled for all classes

- **SIMD** (0xFD prefix): implementation pending; will be enabled for ReplayGrade/BestEffort in a future stage
- **Threads** (0xFE prefix): shared memory and atomics make execution order-dependent on CPU scheduling; will be enabled for BestEffort only

### 2.7 Determinism guarantees by runtime

| Runtime | ProofGrade | ReplayGrade | BestEffort |
|---------|-----------|-------------|------------|
| WASM | **Full** — instruction-level deterministic | **Partial** — floats may vary across CPUs | **None** — best-effort execution |
| Native (x86_64) | N/A (native is always partial) | Partial — scheduling deterministic | Partial |
| eBPF-lite | **Full** — verified, bounded | N/A | N/A |

`[IMPL: ✅ types.rs RuntimeClass enum; runtime.rs per-instance check; agent_loader.rs passes class through]`

---

## 3. Value Types

### 3.1 Supported types

| Type | Size | ProofGrade | ReplayGrade | BestEffort |
|------|------|-----------|-------------|------------|
| `i32` | 32-bit signed integer | ✅ | ✅ | ✅ |
| `i64` | 64-bit signed integer | ✅ | ✅ | ✅ |
| `f32` | 32-bit IEEE 754 float | ❌ trap | ✅ | ✅ |
| `f64` | 64-bit IEEE 754 float | ❌ trap | ✅ | ✅ |

### 3.2 Value representation

```text
Value {
    I32(i32),
    I64(i64),
    F32(f32),
    F64(f64),
}
```

All four variants are always present in the enum. The decoder always accepts F32/F64 types. Enforcement is at **runtime** based on the instance's RuntimeClass.

`[IMPL: ✅ types.rs ValType enum + Value enum]`

---

## 4. Module Format and Sections

### 4.1 Binary format

Standard WASM binary format:

```text
Bytes 0-3:   magic    = 0x00 0x61 0x73 0x6D  (\0asm)
Bytes 4-7:   version  = 0x01 0x00 0x00 0x00  (version 1)
Bytes 8+:    sections (variable length, LEB128 encoded)
```

### 4.2 Supported sections

All 12 standard WASM sections are parsed:

| ID | Section | Description | Status |
|----|---------|-------------|--------|
| 1 | Type | Function type signatures | ✅ |
| 2 | Import | Imported functions and globals | ✅ |
| 3 | Function | Function declarations (type indices) | ✅ |
| 4 | Table | Indirect call tables (funcref) | ✅ |
| 5 | Memory | Linear memory limits (min/max pages) | ✅ |
| 6 | Global | Global variables with init expressions | ✅ |
| 7 | Export | Exported functions/tables/memory/globals | ✅ |
| 8 | Start | Optional start function (auto-invoked) | ✅ |
| 9 | Element | Table initialization segments | ✅ (active + passive + declarative) |
| 10 | Code | Function bodies (locals + bytecode) | ✅ |
| 11 | Data | Memory initialization segments | ✅ (active + passive) |
| 12 | DataCount | Data segment count (bulk memory proposal) | ✅ |

Module decoding is **RuntimeClass-agnostic** — the decoder always parses all types and opcodes. The RuntimeClass restriction is enforced at execution time only.

Unknown sections are safely skipped.

### 4.3 Module structures

```text
FuncTypeDef {
    param_count:  u8
    params:       [ValType; MAX_PARAMS]     // up to 8
    result_count: u8
    results:      [ValType; MAX_RESULTS]    // up to 4
}

FuncDef {
    type_idx:     u32        // index into func_types
    code_offset:  usize      // start of bytecode in module.code
    code_len:     usize
    local_count:  u16        // params + declared locals
    locals:       [ValType; MAX_LOCALS]     // up to 32
}

ImportDef {
    module_name_offset: usize
    module_name_len:    usize
    field_name_offset:  usize
    field_name_len:     usize
    kind:               ImportKind   // Func(type_idx) or Global(valtype, mutable)
}

ExportDef {
    name_offset: usize
    name_len:    usize
    kind:        ExportKind  // Func(idx), Table(idx), Memory(idx), Global(idx)
}

GlobalDef {
    val_type:   ValType
    mutable:    bool
    init_value: Value       // evaluated from init expression
}
```

### 4.4 Function index space

The WASM function index space counts only **function imports**, not global/table/memory imports:

```text
function index 0 .. N-1  = imported functions (from module.imports where kind = Func)
function index N .. N+M-1 = local functions (from module.functions)
```

`func_import_count()` returns N. `func_import_type(idx)` returns the type index of the idx-th function import by scanning the import list.

### 4.5 Init expression support

Init expressions (used in globals, data offsets, element offsets) support:

| Opcode | Description |
|--------|-------------|
| `i32.const` (0x41) | 32-bit integer constant |
| `i64.const` (0x42) | 64-bit integer constant |
| `f32.const` (0x43) | 32-bit float constant (always parsed) |
| `f64.const` (0x44) | 64-bit float constant (always parsed) |
| `global.get` (0x23) | Reference another global's value |
| `end` (0x0B) | Terminator |

### 4.6 LEB128 encoding

All section sizes, counts, and instruction immediates use LEB128 variable-length encoding:

- `decode_leb128_u32` — unsigned 32-bit (up to 5 bytes)
- `decode_leb128_i32` — signed 32-bit (up to 5 bytes)
- `decode_leb128_i64` — signed 64-bit (up to 10 bytes)

`[IMPL: ✅ decoder.rs — all 12 sections, LEB128, module structure, func_import_count/type]`

---

## 5. Instruction Set

### 5.1 Summary

| Category | Opcodes | ProofGrade | ReplayGrade/BestEffort |
|----------|---------|-----------|----------------------|
| Control flow | 14 | ✅ | ✅ |
| Parametric | 2 | ✅ | ✅ |
| Variable access | 7 | ✅ | ✅ |
| Memory load/store (integer) | 26 | ✅ | ✅ |
| Memory load/store (float) | 4 | ❌ FloatsDisabled | ✅ |
| Memory management | 2 | ✅ | ✅ |
| Constants (integer) | 2 | ✅ | ✅ |
| Constants (float) | 2 | ❌ FloatsDisabled | ✅ |
| i32 comparison | 11 | ✅ | ✅ |
| i64 comparison | 11 | ✅ | ✅ |
| f32/f64 comparison | 12 | ❌ FloatsDisabled | ✅ |
| i32 arithmetic | 18 | ✅ | ✅ |
| i64 arithmetic | 18 | ✅ | ✅ |
| f32 arithmetic | 14 | ❌ FloatsDisabled | ✅ |
| f64 arithmetic | 14 | ❌ FloatsDisabled | ✅ |
| Integer conversions | 3 | ✅ | ✅ |
| Float conversions | 22 | ❌ FloatsDisabled | ✅ |
| Sign extension | 5 | ✅ | ✅ |
| Saturating trunc (0xFC 0-7) | 8 | ❌ FloatsDisabled | ✅ |
| Bulk memory (0xFC 8-17) | 10 | ✅ | ✅ |
| SIMD (0xFD prefix) | — | ❌ UnsupportedProposal | ❌ UnsupportedProposal |
| Threads (0xFE prefix) | — | ❌ UnsupportedProposal | ❌ UnsupportedProposal |
| **Total defined** | **203** | **134 active / 69 disabled** | **196 active / 7 disabled** |

### 5.2 Control flow opcodes

| Hex | Opcode | Operands | Description |
|-----|--------|----------|-------------|
| `0x00` | `unreachable` | — | Trap immediately |
| `0x01` | `nop` | — | No operation |
| `0x02` | `block` | blocktype | Begin structured block |
| `0x03` | `loop` | blocktype | Begin loop (branch target = start) |
| `0x04` | `if` | blocktype | Conditional block; pops i32 condition |
| `0x05` | `else` | — | Else clause of if block |
| `0x0B` | `end` | — | Terminate block/if/loop/function |
| `0x0C` | `br` | label_idx | Unconditional branch to enclosing label |
| `0x0D` | `br_if` | label_idx | Conditional branch; pops i32 condition |
| `0x0E` | `br_table` | vec(label), default | Table-driven branch (up to 256 labels) |
| `0x0F` | `return` | — | Return from current function |
| `0x10` | `call` | func_idx | Direct function call |
| `0x11` | `call_indirect` | type_idx, table_idx | Indirect call via table with type check |
| `0x12` | `return_call` | func_idx | Tail call (reuses frame) |
| `0x13` | `return_call_indirect` | type_idx, table_idx | Tail call via table |

### 5.3 Parametric opcodes

| Hex | Opcode | Description |
|-----|--------|-------------|
| `0x1A` | `drop` | Discard top-of-stack value |
| `0x1B` | `select` | Pop condition (i32), select between two same-typed values |

`select` validates that both operands have the same type; traps `TypeMismatch` if they differ.

### 5.4 Variable access opcodes

| Hex | Opcode | Description |
|-----|--------|-------------|
| `0x20` | `local.get` | Push local variable onto stack |
| `0x21` | `local.set` | Pop value into local variable |
| `0x22` | `local.tee` | Set local variable, keep value on stack |
| `0x23` | `global.get` | Push global variable onto stack |
| `0x24` | `global.set` | Pop value into mutable global (traps if immutable) |
| `0x25` | `table.get` | Read table element (returns -1 for null) |
| `0x26` | `table.set` | Write table element |

### 5.5 Memory opcodes — integer loads

| Hex | Opcode | Width | Extension |
|-----|--------|-------|-----------|
| `0x28` | `i32.load` | 4 bytes | — |
| `0x29` | `i64.load` | 8 bytes | — |
| `0x2C` | `i32.load8_s` | 1 byte | sign-extend to i32 |
| `0x2D` | `i32.load8_u` | 1 byte | zero-extend to i32 |
| `0x2E` | `i32.load16_s` | 2 bytes | sign-extend to i32 |
| `0x2F` | `i32.load16_u` | 2 bytes | zero-extend to i32 |
| `0x30` | `i64.load8_s` | 1 byte | sign-extend to i64 |
| `0x31` | `i64.load8_u` | 1 byte | zero-extend to i64 |
| `0x32` | `i64.load16_s` | 2 bytes | sign-extend to i64 |
| `0x33` | `i64.load16_u` | 2 bytes | zero-extend to i64 |
| `0x34` | `i64.load32_s` | 4 bytes | sign-extend to i64 |
| `0x35` | `i64.load32_u` | 4 bytes | zero-extend to i64 |

All loads: address = `pop_i32() as u32 + immediate_offset`, using `checked_add` to prevent overflow.

### 5.6 Memory opcodes — integer stores

| Hex | Opcode | Width |
|-----|--------|-------|
| `0x36` | `i32.store` | 4 bytes |
| `0x37` | `i64.store` | 8 bytes |
| `0x3A` | `i32.store8` | 1 byte (low 8 bits) |
| `0x3B` | `i32.store16` | 2 bytes (low 16 bits) |
| `0x3C` | `i64.store8` | 1 byte |
| `0x3D` | `i64.store16` | 2 bytes |
| `0x3E` | `i64.store32` | 4 bytes (low 32 bits) |

### 5.7 Memory opcodes — float loads/stores

| Hex | Opcode | ProofGrade | ReplayGrade/BestEffort |
|-----|--------|-----------|----------------------|
| `0x2A` | `f32.load` | ❌ FloatsDisabled | ✅ |
| `0x2B` | `f64.load` | ❌ FloatsDisabled | ✅ |
| `0x38` | `f32.store` | ❌ FloatsDisabled | ✅ |
| `0x39` | `f64.store` | ❌ FloatsDisabled | ✅ |

### 5.8 Memory management

| Hex | Opcode | Description |
|-----|--------|-------------|
| `0x3F` | `memory.size` | Push current memory size in pages (i32) |
| `0x40` | `memory.grow` | Pop delta pages (i32), grow memory; push old size or -1 on failure |

`memory.grow` checks: module's declared max pages AND global `MAX_MEMORY_PAGES` (16).

### 5.9 Constants

| Hex | Opcode | ProofGrade | ReplayGrade/BestEffort |
|-----|--------|-----------|----------------------|
| `0x41` | `i32.const` | ✅ | ✅ |
| `0x42` | `i64.const` | ✅ | ✅ |
| `0x43` | `f32.const` | ❌ FloatsDisabled | ✅ |
| `0x44` | `f64.const` | ❌ FloatsDisabled | ✅ |

### 5.10 i32 comparison and arithmetic

| Hex | Opcode | Semantics |
|-----|--------|-----------|
| `0x45` | `i32.eqz` | `a == 0` → i32(1 or 0) |
| `0x46` | `i32.eq` | `a == b` |
| `0x47` | `i32.ne` | `a != b` |
| `0x48` | `i32.lt_s` | signed `a < b` |
| `0x49` | `i32.lt_u` | unsigned `a < b` |
| `0x4A` | `i32.gt_s` | signed `a > b` |
| `0x4B` | `i32.gt_u` | unsigned `a > b` |
| `0x4C` | `i32.le_s` | signed `a <= b` |
| `0x4D` | `i32.le_u` | unsigned `a <= b` |
| `0x4E` | `i32.ge_s` | signed `a >= b` |
| `0x4F` | `i32.ge_u` | unsigned `a >= b` |
| `0x67` | `i32.clz` | count leading zeros |
| `0x68` | `i32.ctz` | count trailing zeros |
| `0x69` | `i32.popcnt` | population count |
| `0x6A` | `i32.add` | wrapping add |
| `0x6B` | `i32.sub` | wrapping sub |
| `0x6C` | `i32.mul` | wrapping mul |
| `0x6D` | `i32.div_s` | signed division (traps: div-by-zero, IntegerOverflow on MIN/-1) |
| `0x6E` | `i32.div_u` | unsigned division (traps: div-by-zero) |
| `0x6F` | `i32.rem_s` | signed remainder (traps: div-by-zero; MIN%-1 = 0) |
| `0x70` | `i32.rem_u` | unsigned remainder (traps: div-by-zero) |
| `0x71` | `i32.and` | bitwise AND |
| `0x72` | `i32.or` | bitwise OR |
| `0x73` | `i32.xor` | bitwise XOR |
| `0x74` | `i32.shl` | shift left (amount masked & 31) |
| `0x75` | `i32.shr_s` | arithmetic shift right |
| `0x76` | `i32.shr_u` | logical shift right |
| `0x77` | `i32.rotl` | rotate left |
| `0x78` | `i32.rotr` | rotate right |

### 5.11 i64 comparison and arithmetic

Same operations as i32 but for 64-bit values, opcodes `0x50`–`0x5A` (comparison) and `0x79`–`0x8A` (arithmetic). Shift amounts masked with `& 63`.

### 5.12 Float operations (ReplayGrade/BestEffort only)

All float opcodes (`0x5B`–`0x66`, `0x8B`–`0xA6`, `0xA8`–`0xBF`, `0xFC sub 0-7`) are **fully implemented** with:

- **Quiet NaN conversion**: ceil, floor, trunc, sqrt convert signaling NaN to quiet NaN
- **NaN propagation**: min/max use `lhs + rhs` to propagate NaN with payload preservation
- **Precise trunc boundaries**: use exact float constants matching wasmi spec (e.g., `-2147483904.0_f32` for f32→i32)
- **IEEE 754 nearest-even**: uses `libm::rintf`/`libm::rint`

In ProofGrade mode, all these opcodes trap with `FloatsDisabled`.

### 5.13 Integer type conversions

| Hex | Opcode | Description |
|-----|--------|-------------|
| `0xA7` | `i32.wrap_i64` | Truncate i64 to i32 (low 32 bits) |
| `0xAC` | `i64.extend_i32_s` | Sign-extend i32 to i64 |
| `0xAD` | `i64.extend_i32_u` | Zero-extend i32 to i64 |

### 5.14 Sign extension

| Hex | Opcode | Description |
|-----|--------|-------------|
| `0xC0` | `i32.extend8_s` | Sign-extend 8-bit to i32 |
| `0xC1` | `i32.extend16_s` | Sign-extend 16-bit to i32 |
| `0xC2` | `i64.extend8_s` | Sign-extend 8-bit to i64 |
| `0xC3` | `i64.extend16_s` | Sign-extend 16-bit to i64 |
| `0xC4` | `i64.extend32_s` | Sign-extend 32-bit to i64 |

### 5.15 Bulk memory and table operations (0xFC prefix)

| Sub-opcode | Opcode | Description | Status |
|------------|--------|-------------|--------|
| 0-7 | `i32/i64.trunc_sat_f32/f64_s/u` | Saturating float-to-int (no trap on NaN/overflow) | ProofGrade: ❌; others: ✅ |
| 8 | `memory.init` | Copy from data segment to memory | ✅ all classes |
| 9 | `data.drop` | Mark data segment as dropped | ✅ all classes |
| 10 | `memory.copy` | Copy memory region (memmove semantics) | ✅ all classes |
| 11 | `memory.fill` | Fill memory with byte value | ✅ all classes |
| 12 | `table.init` | Copy from element segment to table | ✅ all classes |
| 13 | `elem.drop` | Mark element segment as dropped | ✅ all classes |
| 14 | `table.copy` | Copy table region | ✅ all classes |
| 15 | `table.grow` | Grow table size | ✅ all classes |
| 16 | `table.size` | Get table element count | ✅ all classes |
| 17 | `table.fill` | Fill table with value | ✅ all classes |

### 5.16 Unsupported proposals

| Prefix | Proposal | Status | Planned |
|--------|----------|--------|---------|
| `0xFD` | SIMD (v128) | ❌ `UnsupportedProposal` | ReplayGrade/BestEffort in future stage |
| `0xFE` | Threads / Atomics | ❌ `UnsupportedProposal` | BestEffort only in future stage |

`[IMPL: ✅ runtime.rs — 203 opcodes defined, per-instance RuntimeClass check on all float ops]`

---

## 6. Memory Model

### 6.1 Linear memory

- Single linear memory per instance (WASM MVP)
- Page size: **65,536 bytes** (64 KiB) per WASM standard
- Initial size: `memory_min_pages × 65,536` bytes
- Maximum: `min(module_max_pages, MAX_MEMORY_PAGES)` pages
- Hard limit: **MAX_MEMORY_PAGES = 65,536** → **4 GiB** (WASM spec maximum, actual usage gated by agent `mem_quota`)

### 6.2 Memory access

- All loads/stores are **bounds-checked** before access
- Address computation: `base(i32) + offset(u32)`, using `checked_add` to prevent overflow
- Out-of-bounds access returns `WasmError::MemoryOutOfBounds`
- Alignment hints in the binary format are parsed but **not enforced** (unaligned access is permitted)

### 6.3 Memory growth

`memory.grow(delta_pages)`:
- Returns old memory size in pages on success
- Returns -1 (as i32) on failure
- Fails if growth would exceed module's declared maximum or `MAX_MEMORY_PAGES`
- New pages are zero-initialized

### 6.4 Data segments

- **Active segments** (flags 0, 2): copied to memory at instantiation with an offset expression
- **Passive segments** (flag 1): available for `memory.init`, not applied at instantiation
- Bounds-checked: source data must fit within module.code, destination must fit within memory

`[IMPL: ✅ runtime.rs — WasmInstance.memory as Vec<u8>, bounds-checked loads/stores with checked_add]`

---

## 7. Function Calls and Control Flow

### 7.1 Call stack

```text
CallFrame {
    func_idx:     u32      // function being executed
    return_pc:    usize    // resume point in caller
    code_offset:  usize    // start of function bytecode
    code_end:     usize    // end of function bytecode
    local_base:   usize    // index into locals array
    local_count:  usize    // params + declared locals
    stack_base:   usize    // operand stack depth at entry
    result_count: u8       // number of return values
}
```

- Maximum call depth: **1,000 frames** (`MAX_CALL_DEPTH`)
- Maximum total locals across all frames: **65,536** (`MAX_TOTAL_LOCALS`)

### 7.2 Call mechanisms

| Mechanism | Opcode | Description |
|-----------|--------|-------------|
| Direct call | `call` (0x10) | Call by function index (import or local) |
| Indirect call | `call_indirect` (0x11) | Call via table lookup; validates type signature |
| Tail call | `return_call` (0x12) | Pop current frame, enter new function |
| Tail call indirect | `return_call_indirect` (0x13) | Tail call via table |
| Import call | — | Returns `ExecResult::HostCall`, caller handles |

Import calls **pause** execution and return control to the kernel. The kernel dispatches the host function, then resumes the WASM instance with `resume(return_value)`.

### 7.3 Block stack

```text
BlockFrame {
    start_pc:     usize    // branch target for Loop
    end_pc:       usize    // branch target for Block/If
    stack_base:   usize    // stack depth at block entry
    result_count: u8
    is_loop:      bool     // changes branch target behavior
}
```

- Maximum block nesting: **1,000** (`MAX_BLOCK_DEPTH`)
- `br N` branches to the Nth enclosing label (0 = innermost)
- For `block`/`if`: branch goes to `end` (forward)
- For `loop`: branch goes to `start` (backward — loop re-entry)

### 7.4 If/Else handling

- `if` pops an i32 condition
- Two-pass scan: first finds else/end boundary, then finds true end of if/else/end structure
- If condition ≠ 0: execute then-body; `else` opcode skips to true end
- If condition = 0: skip to `else` (or `end` if no else)
- Block `end_pc` always points to the true end of the entire if/else/end structure

### 7.5 Indirect call table

- Element type: `funcref` only (WASM MVP)
- Maximum table size: **65,536 entries** (`MAX_TABLE_SIZE`, WASM spec limit)
- Populated from element segments at instantiation
- `call_indirect` validates the function type signature using `func_import_type()` for imports and `functions[].type_idx` for local functions; traps with `IndirectCallTypeMismatch` on mismatch
- Null table entries (uninitialized) trap with `UndefinedElement`

`[IMPL: ✅ runtime.rs — CallFrame, BlockFrame, call/call_indirect/return_call, br/br_if/br_table, two-pass if/else]`

---

## 8. Host Functions (ATOS Syscall Bridge)

WASM agents invoke ATOS syscalls by importing host functions from the `"atos"` module. The runtime bridges these to kernel syscalls.

### 8.1 Host function table

| Import name | Signature | Return | Description |
|-------------|-----------|--------|-------------|
| `sys_yield` | `() → (i32)` | 0 (success) | Yield current timeslice |
| `sys_send` | `(mailbox_id: i32, ptr: i32, len: i32) → (i32)` | 0 (success) | Send message to mailbox |
| `sys_recv` | `(mailbox_id: i32, ptr: i32, capacity: i32) → (i32)` | 0 (success) | Receive message from mailbox (blocking) |
| `sys_exit` | `(code: i32) → ()` | — | Terminate agent; sets `instance.finished = true` |
| `sys_energy_get` | `() → (i64)` | remaining fuel | Query remaining energy budget |
| `log` | `(ptr: i32, len: i32) → ()` | — | Log message bytes to serial output |

### 8.2 Memory safety

All host functions that accept memory pointers (`ptr`, `len`) perform bounds validation:

```text
end = ptr.checked_add(len)    // overflow check
if end > instance.memory_size → MemoryOutOfBounds
```

### 8.3 Host call protocol

1. WASM `call` instruction references an import function index
2. Runtime finds the N-th function import by scanning (not direct array index)
3. Returns `ExecResult::HostCall(func_idx, args, arg_count)`
4. Kernel calls `host::handle_host_call(instance, func_idx, args, arg_count)`
5. Host function executes (may invoke kernel syscall)
6. Returns `Ok(Some(return_value))` or `Ok(None)` for void
7. Kernel calls `instance.resume(return_value)` to continue WASM execution

### 8.4 Unknown imports

If a WASM module imports a function not in the table above, `handle_host_call` returns `WasmError::ImportNotFound`.

`[IMPL: ✅ host.rs — 6 host functions, resolve_import via func_import scan, handle_host_call()]`

---

## 9. Fuel Metering

### 9.1 Cost model

Every instruction executed costs **1 fuel unit**. Fuel is decremented in `step()` before opcode dispatch.

```text
1 WASM instruction = 1 fuel = 1 ATOS energy unit
```

This applies identically across all RuntimeClasses — ProofGrade, ReplayGrade, and BestEffort agents all consume fuel at the same rate.

### 9.2 Exhaustion behavior

When fuel reaches 0:
1. `step()` returns `ExecResult::OutOfFuel`
2. The agent's energy budget is considered exhausted
3. The kernel moves the agent to `Suspended` state and emits `BUDGET_EXHAUSTED`

### 9.3 Fuel query

WASM agents can check remaining fuel via the `sys_energy_get` host function, which returns `instance.fuel as i64`.

`[IMPL: ✅ runtime.rs — fuel: u64, decremented per step(), OutOfFuel result]`

---

## 10. Instance Lifecycle

### 10.1 Creation

```text
WasmInstance::new(module, fuel)                          // default: ProofGrade
WasmInstance::with_class(module, fuel, runtime_class)    // explicit class
```

Initializes:
- Linear memory to `memory_min_pages × WASM_PAGE_SIZE` bytes (zeroed)
- Globals from module global definitions (init expressions evaluated)
- Table from element segments (active segments applied)
- Active data segments copied to memory (passive segments skipped)
- Stack, locals, call stack — all empty
- PC = 0, fuel = given value, finished = false
- **runtime_class** = given value (defaults to `ProofGrade`)

### 10.2 Execution

```text
instance.run_start()           // run module start function (if present)
instance.call_func(idx, args)  // call exported function
instance.run()                 // execute until completion/pause
instance.resume(value)         // resume after host call
```

### 10.3 Execution results

| Result | Meaning |
|--------|---------|
| `ExecResult::Ok` | One instruction executed; call `step()` again |
| `ExecResult::Returned(Value)` | Function returned a value; execution complete |
| `ExecResult::OutOfFuel` | Fuel exhausted; agent suspended |
| `ExecResult::Trap(WasmError)` | Runtime error; agent faulted |
| `ExecResult::HostCall(idx, args, count)` | Paused for host function dispatch |

### 10.4 Entry point convention

The agent loader searches for an entry point in this priority order:

1. `"run"` — ATOS convention (preferred for SDK agents)
2. `"_start"` — WASI / standard WASM convention
3. `"main"` — C/Rust convention

The first one found is used. This allows standard `rustc --target wasm32-unknown-unknown` compiled programs to run without requiring the ATOS SDK.

`[IMPL: ✅ runtime.rs — WasmInstance with runtime_class, ExecResult, call_func/resume/run/run_start]`

---

## 11. Agent Loading Path

Per yellowpaper §24.2.3.1:

### 11.1 sys_spawn_image ABI (syscall 22)

```text
sys_spawn_image(
    a1 = image_ptr,
    a2 = image_len,
    a3 = runtime_kind[7:0] | runtime_class[15:8],
    a4 = energy_budget,
    a5 = mem_quota
) → agent_id or error

runtime_kind:  0 = Native (ELF64), 1 = WASM
runtime_class: 0 = ProofGrade, 1 = ReplayGrade, 2 = BestEffort
```

### 11.2 Loading flow

```text
1. wasm::decoder::decode(image_bytes) → WasmModule  (class-agnostic)
2. Validate: module must export an entry point ("run", "_start", or "main")
3. Store WasmModule + RuntimeClass in kernel tables (indexed by agent_id)
4. Create kernel-mode agent with wasm_runner_entry as entry point
5. wasm_runner_entry:
   a. Retrieve module and runtime_class from tables
   b. Create WasmInstance::with_class(module, fuel, runtime_class)
   c. Run start function (if present)
   d. Call entry point ("run" or "_start" or "main", first found)
   e. Loop: dispatch host calls, resume, until completion/trap/fuel
```

`[IMPL: ✅ agent_loader.rs — spawn_from_image_with_class, WASM_RUNTIME_CLASSES table]`

---

## 12. Implementation Limits

Limits are aligned with [wasmi](https://github.com/wasmi-labs/wasmi) defaults. Actual memory usage is gated by the agent's `mem_quota`.

| Constant | Value | wasmi default | Description |
|----------|-------|-------------|-------------|
| `MAX_FUNCTIONS` | 10,000 | 10,000 | Total functions (imports + local) |
| `MAX_IMPORTS` | 10,000 | — | Maximum imported functions/globals |
| `MAX_EXPORTS` | 10,000 | — | Maximum exported items |
| `MAX_LOCALS` | 128 | — | Locals per function (params + declared) |
| `MAX_PARAMS` | 32 | 32 | Parameters per function type |
| `MAX_RESULTS` | 32 | 32 | Return values per function type |
| `MAX_STACK` | 65,536 | ~1 MB | Operand stack depth (values) |
| `MAX_TOTAL_LOCALS` | 65,536 | — | Total locals across all call frames |
| `MAX_CALL_DEPTH` | 1,000 | 1,000 | Maximum nested function calls |
| `MAX_BLOCK_DEPTH` | 1,000 | — | Maximum nested blocks/loops/ifs |
| `MAX_MEMORY_PAGES` | 65,536 | unlimited | 4 GiB max (WASM spec limit, gated by agent mem_quota) |
| `WASM_PAGE_SIZE` | 65,536 | 65,536 | Bytes per memory page (64 KiB) |
| `MAX_CODE_SIZE` | 10,485,760 | unlimited | Maximum bytecode size (10 MiB) |
| `MAX_GLOBALS` | 1,000 | 1,000 | Maximum global variables |
| `MAX_TABLE_SIZE` | 65,536 | unlimited | Maximum indirect call table entries |
| `MAX_DATA_SEGMENTS` | 1,000 | 1,000 | Maximum data segments |
| `MAX_ELEMENT_SEGMENTS` | 1,000 | 1,000 | Maximum element segments |
| `MAX_BR_TABLE_SIZE` | 4,096 | — | Maximum br_table labels |
| `MAX_NAME_BYTES` | 1,024 | — | Name buffer for imports/exports |

`[IMPL: ✅ types.rs — all constants]`

---

## 13. Error Types

| Error | Trigger |
|-------|---------|
| `InvalidMagic` | WASM magic bytes mismatch |
| `UnsupportedVersion` | WASM version ≠ 1 |
| `InvalidSection` | Malformed section data |
| `InvalidOpcode(u8)` | Unknown opcode byte |
| `StackOverflow` | Operand stack exceeds MAX_STACK |
| `StackUnderflow` | Pop from empty stack |
| `TypeMismatch` | Value type incompatibility (e.g., select with mismatched types) |
| `OutOfBounds` | Index out of range |
| `DivisionByZero` | Integer div/rem by zero |
| `UnreachableExecuted` | `unreachable` instruction reached |
| `ImportNotFound(u32)` | Unknown host function |
| `FunctionNotFound(u32)` | Invalid function index |
| `TooManyFunctions` | Exceeds MAX_FUNCTIONS |
| `TooManyImports` | Exceeds MAX_IMPORTS |
| `CodeTooLarge` | Exceeds MAX_CODE_SIZE |
| `InvalidLEB128` | Malformed variable-length integer |
| `OutOfFuel` | Fuel budget exhausted |
| `MemoryOutOfBounds` | Memory access outside linear memory or address overflow |
| `CallStackOverflow` | Exceeds MAX_CALL_DEPTH |
| `InvalidBlockType` | Invalid block signature |
| `BranchDepthExceeded` | Exceeds MAX_BLOCK_DEPTH |
| `UnexpectedEnd` | Unexpected end of bytecode |
| `IntegerOverflow` | Integer division overflow (MIN/-1) or float→int out of range |
| `FloatsDisabled` | Float opcode executed in ProofGrade mode |
| `UndefinedElement` | Table entry not initialized |
| `IndirectCallTypeMismatch` | call_indirect type signature mismatch |
| `ImmutableGlobal` | Write to immutable global |
| `GlobalIndexOutOfBounds` | Global index out of range |
| `UnsupportedProposal` | SIMD (0xFD) or Threads (0xFE) prefix |
| `TableIndexOutOfBounds` | Table index out of range |

`[IMPL: ✅ types.rs WasmError enum — 30 variants]`

---

## 14. SDK (atos-wasm-sdk)

The `atos-wasm-sdk` Rust crate provides **optional** safe wrappers for writing WASM agents. The SDK is not required — any `no_std` Rust program compiled with `rustc --target wasm32-unknown-unknown` that exports `run`, `_start`, or `main` can run on ATOS directly. The SDK simply makes it more convenient to interact with ATOS host functions.

### 14.1 Usage

```rust
#![no_std]
#![no_main]
use atos_wasm_sdk::*;

#[no_mangle]
pub extern "C" fn run() {
    log_str("Hello from WASM agent!");
    let msg = b"hello";
    send(3, msg);
    loop { atos_yield(); }
}
```

Compile with: `cargo build --target wasm32-unknown-unknown --release`

Deploy with RuntimeClass: `sys_spawn_image(wasm_bytes, len, 1 | (1 << 8), energy, quota)` — this creates a ReplayGrade WASM agent that can use floats.

### 14.2 API

| Function | Signature | Description |
|----------|-----------|-------------|
| `atos_yield()` | `() → i32` | Yield timeslice |
| `send(mailbox_id, payload)` | `(u16, &[u8]) → i32` | Send message |
| `recv(mailbox_id, buf)` | `(u16, &mut [u8]) → i32` | Receive message |
| `exit(code)` | `(i32) → !` | Terminate agent |
| `energy_remaining()` | `() → i64` | Query remaining fuel |
| `log_str(s)` | `(&str) → ()` | Log string to serial |
| `log_bytes(b)` | `(&[u8]) → ()` | Log raw bytes |

### 14.3 Host import declarations

The SDK declares imports using `#[link(wasm_import_module = "atos")]`:

```rust
extern "C" {
    fn host_sys_yield() -> i32;
    fn host_sys_send(mailbox_id: i32, ptr: i32, len: i32) -> i32;
    fn host_sys_recv(mailbox_id: i32, ptr: i32, capacity: i32) -> i32;
    fn host_sys_exit(code: i32);
    fn host_sys_energy_get() -> i64;
    fn host_log(ptr: i32, len: i32);
}
```

`[IMPL: ✅ sdk/atos-wasm-sdk/src/lib.rs + examples/hello.rs]`

---

## 15. Differences from Standard WASM MVP

### 15.1 Feature availability by RuntimeClass

| Feature | Standard WASM | ProofGrade | ReplayGrade | BestEffort |
|---------|--------------|-----------|-------------|------------|
| Floating-point (f32/f64) | ✅ | ❌ | ✅ | ✅ |
| SIMD (128-bit vectors) | ✅ (proposal) | ❌ | ❌ (future) | ❌ (future) |
| Threads / atomics | ✅ (proposal) | ❌ | ❌ | ❌ (future) |
| Multi-memory | ✅ (proposal) | ❌ | ❌ | ❌ |
| Reference types (externref) | ✅ (proposal) | ❌ | ❌ | ❌ |

### 15.2 Limits (aligned with wasmi defaults)

ATOS limits are aligned with [wasmi](https://github.com/wasmi-labs/wasmi) to ensure compatibility with standard WASM toolchain output. Actual resource usage is controlled per-agent by `mem_quota` and `energy_budget`.

| Resource | Standard WASM | ATOS | wasmi |
|----------|--------------|------|-------|
| Max memory | 4 GiB (65,536 pages) | **4 GiB** (65,536 pages) | unlimited (by Store) |
| Max functions | Unlimited | **10,000** | 10,000 |
| Max code size | Unlimited | **10 MiB** | unlimited |
| Max call depth | Unlimited | **1,000** | 1,000 |
| Max locals per function | Unlimited | **128** | — |
| Max stack depth | Unlimited | **65,536 values** | ~1 MB |
| Max params per function | Unlimited | **32** | 32 |
| Max results per function | Unlimited | **32** | 32 |
| Max globals | Unlimited | **1,000** | 1,000 |
| Max data segments | Unlimited | **1,000** | 1,000 |
| Max element segments | Unlimited | **1,000** | 1,000 |

### 15.3 Extensions beyond MVP

| Feature | Standard MVP | ATOS | Source |
|---------|-------------|------|--------|
| Sign extension ops | Post-MVP proposal | ✅ | Useful for integer conversions |
| Tail calls | Post-MVP proposal | ✅ | Useful for agent loop patterns |
| Bulk memory ops | Post-MVP proposal | ✅ | memory.copy/fill/init, data.drop |
| Table operations | Post-MVP proposal | ✅ | table.grow/size/fill/copy/init |
| Saturating trunc | Post-MVP proposal | ✅ (ReplayGrade+) | Safe float→int without trap |

### 15.4 Behavioral differences

| Behavior | Standard WASM | ATOS |
|----------|--------------|------|
| Division by zero | Trap | Trap (same) |
| Integer overflow on div | Trap (i32.div_s MIN/-1) | Trap with `IntegerOverflow` (same) |
| Memory alignment | Hint only, not enforced | Hint only, not enforced (same) |
| Memory out-of-bounds | Trap | Trap (same) |
| Address overflow | Trap | Trap with `MemoryOutOfBounds` via `checked_add` |
| Fuel metering | Not part of spec | **1 fuel per instruction** |
| Host function pausing | Not part of spec | Returns `HostCall`, kernel dispatches |
| Float determinism | Platform-dependent NaN | ProofGrade: disabled; ReplayGrade: quiet NaN canonicalization |

`[IMPL: ✅ All differences are by design, not by omission]`

---

## 16. Future Extensions

Per Yellow Paper §24.3.1, §25.2, and §27:

### 16.1 Stage-3+

| Enhancement | Description | Status |
|-------------|-------------|--------|
| Instruction-class-weighted fuel | Different cost per opcode class (load=2, call=5, etc.) | Planned |
| Memory quota enforcement | `memory.grow` gated by agent's `memory_quota` | Planned |
| Checkpoint/snapshot | Serialize WasmInstance state for checkpoint/restore | Planned |
| JIT compilation | Optional JIT for ReplayGrade/BestEffort agents | Planned (Stage-3+) |
| SIMD for ReplayGrade | Enable 0xFD prefix for non-proof workloads | Planned |
| Threads for BestEffort | Enable 0xFE prefix for tool agents | Planned |

### 16.2 Host function extensions (recommended)

| Host function | Purpose | Priority |
|---------------|---------|----------|
| `sys_state_get` | Read from agent's state keyspace | High |
| `sys_state_put` | Write to agent's state keyspace | High |
| `sys_spawn` | Spawn child agent from WASM | Medium |
| `sys_cap_query` | Query own capabilities | Medium |
| `sys_time_get` | Read deterministic tick counter | Medium |

### 16.3 Limit increases

All limits have been raised to support standard compiler output (see §12). No further increases are currently planned.

---

## Appendix A. Source File Map

| File | Lines | Description |
|------|-------|-------------|
| `src/wasm/mod.rs` | ~5 | Module declaration |
| `src/wasm/types.rs` | ~581 | RuntimeClass, value types, 203 opcodes, 30 error variants, all limits |
| `src/wasm/decoder.rs` | ~931 | Binary format parser, 12 section decoders, func_import_count/type, LEB128 |
| `src/wasm/validator.rs` | ~58 | Basic structural validation |
| `src/wasm/runtime.rs` | ~2,228 | Stack machine interpreter, per-instance RuntimeClass, all opcode handlers |
| `src/wasm/host.rs` | ~177 | Host function resolver (N-th func import scan), 6 syscall bridges |
| `src/agents/wasm_agent.rs` | ~209 | Demo WASM agent with hand-crafted binary |
| `src/agent_loader.rs` | ~472 | Agent loading: spawn_from_image_with_class, multi-entry-point support |
| `sdk/atos-wasm-sdk/src/lib.rs` | ~92 | Agent SDK (optional): safe host function wrappers |
