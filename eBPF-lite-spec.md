# ATOS eBPF-lite Specification

**Version:** 2.0 (Stage-3)
**Status:** Implementation Complete
**Companion to:** Yellow Paper §24.3.2

> This document is the normative specification for the ATOS eBPF-lite policy runtime. The yellow paper provides architectural context and roadmap; this document provides the complete ABI, instruction set, and implementation contract.

---

## Table of Contents

- [1. Overview](#1-overview)
- [2. Instruction Encoding](#2-instruction-encoding)
- [3. Register Convention](#3-register-convention)
- [4. Instruction Set](#4-instruction-set)
- [5. Memory Model](#5-memory-model)
- [6. Helper Functions](#6-helper-functions)
- [7. Maps](#7-maps)
- [8. Attachment Points and Context Structures](#8-attachment-points-and-context-structures)
- [9. Action Codes](#9-action-codes)
- [10. Static Verifier Rules](#10-static-verifier-rules)
- [11. Runtime Execution Semantics](#11-runtime-execution-semantics)
- [12. Program Management (policyd Protocol)](#12-program-management-policyd-protocol)
- [13. AEBF Binary Format](#13-aebf-binary-format)
- [14. SDK Assembly Syntax](#14-sdk-assembly-syntax)
- [15. Implementation Constants](#15-implementation-constants)
- [16. Error Types](#16-error-types)
- [17. Differences from Standard Linux eBPF](#17-differences-from-standard-linux-ebpf)
- [18. Future Extensions](#18-future-extensions)
- [Appendix A. Source File Map](#appendix-a-source-file-map)

---

## 1. Overview

eBPF-lite is the policy execution layer of ATOS. It is a restricted bytecode runtime for policy enforcement, event filtering, and validation rules. It runs **inside the kernel**, not in user mode.

eBPF-lite is **not** an `AgentRuntime` (§24.3.0). It is kernel-resident and attachment-driven rather than agent-scheduled. It follows bounded-lifecycle principles: every program is statically verified for termination before loading, and every execution is bounded by an instruction counter.

**Design goals:**

- Verifiable, bounded, low-cost rule enforcement at kernel-defined attachment points
- No unbounded loops, no direct kernel memory access
- Deterministic for a given verified bytecode image, input context, and helper results
- Bytecode encoding compatible with standard Linux eBPF (subset)

`[IMPL: ✅ ~1,750 lines across 6 kernel modules + integration files + SDK toolchain]`

---

## 2. Instruction Encoding

All instructions are **8 bytes** each, using the standard Linux eBPF encoding:

```text
Byte   Field     Type    Description
─────────────────────────────────────────────
0      opcode    u8      Operation and class
1      regs      u8      dst:4 (low nibble) | src:4 (high nibble)
2-3    off       i16     Signed offset (branch displacement, memory offset)
4-7    imm       i32     Signed immediate value
```

`[IMPL: ✅ types.rs — Insn struct, #[repr(C)]]`

### 2.1 Opcode bit fields

```text
Bit 7  6  5  4  3  2  1  0
    └──────┘  │  └──────┘
    operation src  class
    (4 bits)  bit  (3 bits)
```

| Mask | Field | Applies to | Values |
|------|-------|-----------|--------|
| `opcode & 0x07` | Instruction class | All | See §2.2 |
| `opcode & 0xF0` | Operation within class | All | See §4 |
| `opcode & 0x08` | Source operand (K/X) | **ALU, ALU64, JMP only** | `0x00` = immediate (K), `0x08` = register (X) |
| `opcode & 0x18` | Memory size | **LD, LDX, ST, STX only** | See §4.4 |

> **Important:** Bit 3 (`0x08`) serves different purposes depending on the instruction class. For ALU/ALU64/JMP classes, it selects between immediate (K) and register (X) source operand. For LD/LDX/ST/STX classes, bit 3 is part of the 2-bit size field (`opcode & 0x18`), not a source selector. LDX/STX always use a register operand; ST always uses an immediate.

### 2.2 Instruction classes

| Value | Name | Description | Status |
|-------|------|-------------|--------|
| `0x00` | `BPF_LD` | Load (legacy/special) | Defined, not implemented |
| `0x01` | `BPF_LDX` | Load from memory | ✅ |
| `0x02` | `BPF_ST` | Store immediate to memory | ✅ |
| `0x03` | `BPF_STX` | Store register to memory | ✅ |
| `0x04` | `BPF_ALU` | 32-bit arithmetic | ✅ |
| `0x05` | `BPF_JMP` | 64-bit jumps + call + exit | ✅ |
| `0x06` | — | Reserved (JMP32 in Linux) | Not implemented |
| `0x07` | `BPF_ALU64` | 64-bit arithmetic | ✅ |

### 2.3 Register encoding

The `regs` byte packs two 4-bit register indices:

```text
regs = (src << 4) | dst

dst = regs & 0x0F
src = (regs >> 4) & 0x0F
```

`[IMPL: ✅ Insn::dst() and Insn::src() methods]`

---

## 3. Register Convention

| Register | Purpose | Writable | After `call` | Notes |
|----------|---------|----------|-------------|-------|
| `r0` | Return value | Yes | Set to result | Function result; program exit value |
| `r1` | Argument 1 / context pointer | Yes | **Preserved** | Set to context pointer on entry |
| `r2` | Argument 2 | Yes | **Preserved** | Helper function arg |
| `r3` | Argument 3 | Yes | **Preserved** | Helper function arg |
| `r4` | Argument 4 | Yes | **Preserved** | Helper function arg |
| `r5` | Argument 5 | Yes | **Preserved** | Helper function arg |
| `r6`–`r9` | General purpose / callee-saved | Yes | Preserved | |
| `r10` | Frame pointer | **Read-only** | Preserved | Points to stack top; enforced by verifier |

> **Difference from standard eBPF:** In Linux eBPF, r1–r5 are **caller-saved** (clobbered after `call`). In ATOS eBPF-lite, r1–r5 are **preserved** across helper calls — only r0 is modified. This means programs that rely on r1–r5 values after a `call` will work on ATOS but may fail on Linux eBPF. Portable programs should treat r1–r5 as clobbered after `call` and save values to r6–r9 or the stack beforehand.

### 3.1 Entry state

On program execution start:

```text
r0       = 0
r1       = context pointer (kernel-provided, attach-point-specific)
r2–r9    = 0
r10      = stack_base + STACK_SIZE (frame pointer, top of stack)
PC       = 0
insn_count = 0
```

`[IMPL: ✅ runtime.rs EbpfVm::execute()]`

---

## 4. Instruction Set

### 4.1 ALU64 — 64-bit arithmetic (class `0x07`)

| Op code | Mnemonic | Hex (imm) | Hex (reg) | Semantics |
|---------|----------|-----------|-----------|-----------|
| `BPF_ADD` | `add` | `0x07` | `0x0F` | `dst += src` (wrapping) |
| `BPF_SUB` | `sub` | `0x17` | `0x1F` | `dst -= src` (wrapping) |
| `BPF_MUL` | `mul` | `0x27` | `0x2F` | `dst *= src` (wrapping) |
| `BPF_DIV` | `div` | `0x37` | `0x3F` | `dst /= src` (unsigned; error if src=0) |
| `BPF_OR` | `or` | `0x47` | `0x4F` | `dst \|= src` |
| `BPF_AND` | `and` | `0x57` | `0x5F` | `dst &= src` |
| `BPF_LSH` | `lsh` | `0x67` | `0x6F` | `dst <<= (src & 63)` |
| `BPF_RSH` | `rsh` | `0x77` | `0x7F` | `dst >>= (src & 63)` (logical) |
| `BPF_NEG` | `neg` | `0x87` | — | `dst = -dst` (two's complement) |
| `BPF_MOD` | `mod` | `0x97` | `0x9F` | `dst %= src` (unsigned; error if src=0) |
| `BPF_XOR` | `xor` | `0xA7` | `0xAF` | `dst ^= src` |
| `BPF_MOV` | `mov` | `0xB7` | `0xBF` | `dst = src` |

**Immediate handling:** 32-bit `imm` is sign-extended to 64-bit (`imm as i64 as u64`).

**Shift masking:** Shift amount is masked with `& 63` to prevent undefined behavior.

`[IMPL: ✅ runtime.rs exec_alu64() — all 12 operations]`

### 4.2 ALU32 — 32-bit arithmetic (class `0x04`)

Same operations as ALU64, with these differences:

- Operands are truncated to 32-bit before computation
- Result is **zero-extended** to 64-bit: `result = (result32 as u32) as u64`
- Shift amount masked with `& 31`

| Op code | Hex (imm) | Hex (reg) |
|---------|-----------|-----------|
| `BPF_ADD` | `0x04` | `0x0C` |
| `BPF_SUB` | `0x14` | `0x1C` |
| `BPF_MUL` | `0x24` | `0x2C` |
| `BPF_DIV` | `0x34` | `0x3C` |
| `BPF_OR` | `0x44` | `0x4C` |
| `BPF_AND` | `0x54` | `0x5C` |
| `BPF_LSH` | `0x64` | `0x6C` |
| `BPF_RSH` | `0x74` | `0x7C` |
| `BPF_NEG` | `0x84` | — |
| `BPF_MOD` | `0x94` | `0x9C` |
| `BPF_XOR` | `0xA4` | `0xAC` |
| `BPF_MOV` | `0xB4` | `0xBC` |

`[IMPL: ✅ runtime.rs exec_alu32() — all 12 operations, zero-extend verified]`

### 4.3 JMP — jumps, calls, and exit (class `0x05`)

| Op code | Mnemonic | Hex (imm) | Hex (reg) | Semantics |
|---------|----------|-----------|-----------|-----------|
| `BPF_JA` | `ja` | `0x05` | — | Unconditional: `PC += off` |
| `BPF_JEQ` | `jeq` | `0x15` | `0x1D` | `if dst == src: PC += off` |
| `BPF_JGT` | `jgt` | `0x25` | `0x2D` | `if dst > src: PC += off` (unsigned) |
| `BPF_JGE` | `jge` | `0x35` | `0x3D` | `if dst >= src: PC += off` (unsigned) |
| `BPF_JSET` | `jset` | `0x45` | `0x4D` | `if (dst & src) != 0: PC += off` |
| `BPF_JNE` | `jne` | `0x55` | `0x5D` | `if dst != src: PC += off` |
| `BPF_JLT` | `jlt` | `0xA5` | `0xAD` | `if dst < src: PC += off` (unsigned) |
| `BPF_JLE` | `jle` | `0xB5` | `0xBD` | `if dst <= src: PC += off` (unsigned) |
| `BPF_CALL` | `call` | `0x85` | — | Call helper `imm` (r1–r5 args, r0 result) |
| `BPF_EXIT` | `exit` | `0x95` | — | Terminate program, return `r0` |

**Branch target calculation:**

```text
if branch taken:
    PC = PC + off       (main loop then adds +1)
else:
    PC unchanged        (main loop adds +1, falls through)
```

Effective target address: `PC + 1 + off` from the perspective of the program counter before execution.

**All comparisons are unsigned.** Signed comparisons (`JSGT`, `JSGE`, `JSLT`, `JSLE`) are not implemented (see §17).

`[IMPL: ✅ runtime.rs exec_jmp() — all 10 operations]`

### 4.4 LDX — memory load (class `0x01`)

Syntax: `dst = *(size *)(src + off)`

| Size code | Mnemonic | Hex | Load width |
|-----------|----------|-----|------------|
| `BPF_B` (`0x10`) | `ldxb` | `0x71` | 8-bit, zero-extended |
| `BPF_H` (`0x08`) | `ldxh` | `0x69` | 16-bit, zero-extended |
| `BPF_W` (`0x00`) | `ldxw` | `0x61` | 32-bit, zero-extended |
| `BPF_DW` (`0x18`) | `ldxdw` | `0x79` | 64-bit |

Opcode formula: `BPF_LDX | BPF_MEM | size_code` where `BPF_MEM = 0x60`.

**Address computation:** `addr = regs[src] as i64 + off as i64` (signed addition, wraps).

**Alignment:** Unaligned reads are permitted (`read_unaligned`).

**Access control:** Stack and context (any non-null address) reads are permitted. See §5 for details.

`[IMPL: ✅ runtime.rs exec_ldx() — all 4 sizes]`

### 4.5 STX — register store (class `0x03`)

Syntax: `*(size *)(dst + off) = src`

| Size code | Mnemonic | Hex | Store width |
|-----------|----------|-----|-------------|
| `BPF_B` (`0x10`) | `stxb` | `0x73` | 8-bit |
| `BPF_H` (`0x08`) | `stxh` | `0x6B` | 16-bit |
| `BPF_W` (`0x00`) | `stxw` | `0x63` | 32-bit |
| `BPF_DW` (`0x18`) | `stxdw` | `0x7B` | 64-bit |

**Access control:** Only stack writes are permitted. See §5.

`[IMPL: ✅ runtime.rs exec_stx() — all 4 sizes]`

### 4.6 ST — immediate store (class `0x02`)

Syntax: `*(size *)(dst + off) = imm`

| Size code | Mnemonic | Hex | Store width |
|-----------|----------|-----|-------------|
| `BPF_B` (`0x10`) | — | `0x72` | 8-bit |
| `BPF_H` (`0x08`) | — | `0x6A` | 16-bit |
| `BPF_W` (`0x00`) | — | `0x62` | 32-bit |
| `BPF_DW` (`0x18`) | — | `0x7A` | 64-bit |

The immediate is sign-extended from i32 to u64 before storing.

`[IMPL: ✅ runtime.rs exec_st() — all 4 sizes]`

---

## 5. Memory Model

### 5.1 Stack

Each program execution has a private 512-byte stack.

```text
stack_base                         stack_base + 512
    │                                      │
    ▼                                      ▼
    ┌──────────────────────────────────────┐
    │            512 bytes                 │
    └──────────────────────────────────────┘
                                           ▲
                                         r10 (frame pointer)
```

- `r10` points to `stack_base + STACK_SIZE` (one past the end, x86_64 convention)
- Stack grows downward: `r10 - 8` is the first usable 8-byte slot
- Stack is zero-initialized on each execution

### 5.2 Access control

| Region | Read (LDX) | Write (STX/ST) | How accessed |
|--------|------------|----------------|--------------|
| Stack `[stack_base, stack_base+512)` | ✅ | ✅ | `r10 - offset` |
| Context (via r1) | ✅ | ❌ | `r1 + field_offset` |
| Map value pointers | ✅ (read only) | ❌ (use `map_update` helper) | Pointer returned by `map_lookup` |
| Kernel memory | ❌ | ❌ | N/A |

**Write safety:** `check_write()` restricts all writes to the stack region. Any write outside `[stack_base, stack_base+512)` returns `EbpfError::OutOfBounds`.

**Read safety:** `check_read()` permits reads from the stack region and from any non-null address. This is a Stage-2 simplification — the verifier ensures program safety, and context pointers are kernel-allocated with known layouts. A production implementation should use per-region memory maps.

`[IMPL: ✅ runtime.rs check_read() / check_write(); ⚠️ read check is permissive by design in Stage-2]`

### 5.3 Alignment

Unaligned memory access is permitted for all sizes. The runtime uses `read_unaligned` / `write_unaligned` for 16-bit, 32-bit, and 64-bit operations.

---

## 6. Helper Functions

Helper functions provide eBPF programs with access to kernel services. They are invoked via the `call` instruction with the helper ID in the `imm` field. Arguments are passed in `r1`–`r5`, and the return value is placed in `r0`.

| ID | Name | Signature | Return | Status |
|----|------|-----------|--------|--------|
| 1 | `map_lookup` | `r1=map_id, r2=key_ptr, r3=key_len` | `r0` = value pointer, or 0 if not found | ✅ |
| 2 | `map_update` | `r1=map_id, r2=key_ptr, r3=key_len, r4=val_ptr, r5=val_len` | `r0` = 0 (success) or 1 (error) | ✅ |
| 3 | `map_delete` | `r1=map_id, r2=key_ptr, r3=key_len` | `r0` = 0 (success) or 1 (not found) | ✅ |
| 4 | `get_agent_id` | (none) | `r0` = current agent ID | ✅ |
| 5 | `get_energy` | (none) | `r0` = agent's remaining energy budget | ✅ |
| 6 | `emit_event` | `r1=event_code` | `r0` = 0 | ✅ |
| 7 | `get_tick` | (none) | `r0` = system timer tick count | ✅ |
| 8 | `get_mailbox_pressure` | `r1=mailbox_id` | `r0` = fill count (0–16) | ✅ |
| 9 | `get_agent_parent` | `r1=agent_id` | `r0` = parent ID (0xFFFF if none) | ✅ |
| 10 | `get_capability_count` | `r1=agent_id` | `r0` = capability count | ✅ |
| 11 | `increment_counter` | `r1=map_id, r2=key_ptr, r3=key_len` | `r0` = 0 (success) or 1 (error) | ✅ |
| 12 | `read_gauge` | `r1=map_id, r2=key_ptr, r3=key_len` | `r0` = u64 value (0 if not found) | ✅ |
| 13 | `map_persist` | `r1=map_id` | `r0` = 0 (success) or 1 (error) | ✅ |
| 14 | `map_restore` | `r1=map_id` | `r0` = 0 (success) or 1 (error) | ✅ |

### 6.1 Helper details

**`map_lookup` (ID 1):** Returns a raw pointer to the value bytes in the map entry. The pointer is valid for the duration of the program execution. Returns 0 (null) if the key is not found or the map does not exist. Key length must not exceed `MAX_KEY_SIZE` (8 bytes).

**`map_update` (ID 2):** Inserts or updates an entry. If the key exists, the value is overwritten in place. If the key does not exist, a new entry is created. Returns 1 if the map is full, the key exceeds `MAX_KEY_SIZE`, or the value exceeds `MAX_VALUE_SIZE`.

**`map_delete` (ID 3):** Removes an entry by key. Returns 0 if the entry was found and deleted, 1 if not found.

**`get_agent_id` (ID 4):** Returns the ID of the agent whose operation triggered the eBPF program (the currently scheduled agent).

**`get_energy` (ID 5):** Returns the triggering agent's remaining energy budget. Returns 0 if the agent is not found.

**`emit_event` (ID 6):** Emits a `Custom` audit event with the given event code via the kernel event subsystem (`event::emit`). The event is recorded in both the serial log and the in-kernel ring buffer. Always returns 0.

**`get_tick` (ID 7):** Returns the current PIT timer tick count (100 Hz resolution in Stage-1/2).

**`get_mailbox_pressure` (ID 8):** Returns the current fill count of the specified mailbox (0 to `MAX_MAILBOX_CAPACITY`=16). Returns 0 if the mailbox does not exist.

**`get_agent_parent` (ID 9):** Returns the parent agent ID for the given agent. Returns `0xFFFF` if the agent has no parent or does not exist.

**`get_capability_count` (ID 10):** Returns the number of capabilities held by the given agent. Returns 0 if the agent does not exist.

**`increment_counter` (ID 11):** Reads a `u64` value from the map at the given key, increments by 1, writes back. If not found, inserts with value 1. Returns 0 on success, 1 on error.

**`read_gauge` (ID 12):** Reads a `u64` value from the map at the given key. Returns 0 if not found.

**`map_persist` (ID 13):** Serializes all entries of the specified map to the calling agent's keyspace via the state subsystem. Returns 0 on success, 1 on failure.

**`map_restore` (ID 14):** Deserializes map entries from the calling agent's keyspace, overwriting current map contents. Returns 0 on success, 1 on failure.

**Invalid helper IDs** return `EbpfError::InvalidHelper`.

`[IMPL: ✅ runtime.rs call_helper() — all 14 helpers fully wired]`

---

## 7. Maps

Maps are shared key-value data structures for communication between eBPF programs and the kernel.

### 7.1 Limits

| Parameter | Value | Constant |
|-----------|-------|----------|
| Maximum maps | 8 | `MAX_MAPS` |
| Maximum entries per map | 64 | `MAX_MAP_ENTRIES` |
| Maximum key size | 8 bytes | `MAX_KEY_SIZE` |
| Maximum value size | 64 bytes | `MAX_VALUE_SIZE` |

### 7.2 Entry structure

```text
MapEntry {
    key:       [u8; 8]     // key data (MAX_KEY_SIZE)
    value:     [u8; 64]    // value data (MAX_VALUE_SIZE)
    key_len:   usize       // actual key length
    value_len: usize       // actual value length
    occupied:  bool        // entry is in use
}
```

### 7.3 Map types

Two map types are supported:

| Type | Enum | Lookup | Key semantics |
|------|------|--------|---------------|
| **Hash** | `MapType::Hash` | Linear scan, O(n) | Exact byte match |
| **Array** | `MapType::Array` | Direct index, O(1) | Key is little-endian `u32` index (must be ≥ 4 bytes) |

**Hash map operations:**
- `lookup(key)` — linear scan, exact key match; O(n)
- `update(key, value)` — scan for existing key or first empty slot; O(n)
- `delete(key)` — scan for key, mark unoccupied; O(n)

**Array map operations:**
- `lookup(key)` — interpret key as `u32` index, direct access; O(1)
- `update(key, value)` — direct write at index; O(1)
- `delete(key)` — clear entry at index; O(1)

### 7.4 Kernel API

| Function | Signature | Description |
|----------|-----------|-------------|
| `create_map` | `(id: u32) -> Result<(), EbpfError>` | Allocate a new hash map |
| `create_map_typed` | `(id: u32, map_type: MapType) -> Result<(), EbpfError>` | Allocate a map with specified type |
| `get_map` | `(id: u32) -> Option<&EbpfMap>` | Immutable reference by ID |
| `get_map_mut` | `(id: u32) -> Option<&mut EbpfMap>` | Mutable reference by ID |
| `persist_map` | `(map_id: u32, keyspace: u16) -> u32` | Serialize map to agent's keyspace |
| `restore_map` | `(map_id: u32, keyspace: u16) -> u32` | Deserialize map from agent's keyspace |

**SMP safety:** Slot creation/deletion is protected by `MAPS_SLOT_LOCK: SpinLock<()>`. Map data access (`get_map`/`get_map_mut`) uses direct `static mut` access, safe because eBPF execution is serialized by the `PROGRAMS` SpinLock in `attach.rs`.

**Persistence:** Maps can be persisted to the state subsystem via `map_persist` (helper 13) and restored via `map_restore` (helper 14). Entries are serialized to the calling agent's keyspace. Maps are **not** auto-persistent — persistence is explicit.

`[IMPL: ✅ maps.rs — Hash + Array map types, SMP-safe slot lock, persist/restore via state.rs]`

---

## 8. Attachment Points and Context Structures

### 8.1 Attachment points

eBPF programs are attached to kernel event hooks. When the event occurs, all programs attached at that point are executed.

| Attach Point | Argument | Description | Wired in syscall path |
|-------------|----------|-------------|----------------------|
| `SyscallEntry(syscall_num)` | `u64` | Before syscall execution | ❌ Defined only |
| `SyscallExit(syscall_num)` | `u64` | After syscall execution | ❌ Defined only |
| `MailboxSend(mailbox_id)` | `u16` | Before message send | ✅ `syscall.rs:122` |
| `MailboxRecv(mailbox_id)` | `u16` | Before message receive | ❌ Defined only |
| `AgentSpawn` | — | Before agent creation | ❌ Defined only |
| `TimerTick` | — | On timer interrupt | ❌ Defined only |

`[IMPL: ✅ attach.rs AttachPoint enum; ✅ all 6 points wired; SpinLock-protected with priority-sorted execution]`

### 8.2 Context structures

Each attachment point passes a typed context structure to the program via `r1`. Programs read context fields using `ldxb/ldxh/ldxw/ldxdw` instructions with `r1` as the base pointer.

#### MailboxContext (for `MailboxSend` / `MailboxRecv`)

```text
Offset  Size  Field            Type
──────────────────────────────────────
0       2     sender_id        u16
2       2     target_mailbox   u16
4       2     payload_len      u16
```

Total size: 6 bytes.

`[IMPL: ✅ attach.rs MailboxContext — #[repr(C)]]`

#### SyscallContext (for `SyscallEntry` / `SyscallExit`)

```text
Offset  Size  Field            Type
──────────────────────────────────────
0       2     agent_id         u16
2       6     (padding)        —
8       8     syscall_num      u64
16      8     arg0             u64
24      8     arg1             u64
32      8     arg2             u64
```

Total size: 40 bytes.

`[IMPL: ✅ attach.rs SyscallContext — #[repr(C)]]`

#### SpawnContext (for `AgentSpawn`)

```text
Offset  Size  Field            Type
──────────────────────────────────────
0       2     parent_id        u16
2       6     (padding)        —
8       8     energy_quota     u64
16      4     mem_quota        u32
20      4     (tail padding)   —        (struct aligned to 8 bytes)
```

Total size: 24 bytes (aligned to largest member `u64`, 8-byte boundary).

`[IMPL: ✅ attach.rs SpawnContext — #[repr(C)]]`

#### TimerTick

No typed context structure is defined for `TimerTick`. The `ctx` argument is the raw tick count (`u64`) from `arch::x86_64::timer::get_ticks()`, passed directly to `run_at()`. Programs access it via `r1`. The hook runs in `sched::timer_tick()` after energy charging and before preemptive rescheduling; its action code is ignored (observational only).

> **Note:** Padding depends on Rust's `#[repr(C)]` layout rules. Programs should use field offsets from this table, not assume packed layout.

### 8.3 Program table

| Parameter | Value |
|-----------|-------|
| Maximum attached programs | 16 (`MAX_ATTACHED`) |
| Default execution instruction limit | 10,000 (`DEFAULT_MAX_INSNS`) |

Programs are stored in a global static array of `Option<AttachedProgram>`. Each entry holds:

```text
AttachedProgram {
    program:      [Insn; MAX_INSNS]   // copied instruction array
    len:          usize               // actual instruction count
    attach_point: AttachPoint         // where this program runs
    active:       bool                // whether program is active
}
```

The `active` flag is set to `true` on `attach()` and checked by `run_at()`. `detach()` sets it to `false` and then removes the entry (`Option` set to `None`).

### 8.4 Multi-program execution

When multiple programs are attached at the same point, `run_at()` executes them sequentially and merges results using **most-restrictive-wins**:

```text
Deny > Log > Allow
```

- If any program returns `Deny`, execution **short-circuits immediately** — remaining programs are not executed and the final action is `Deny`
- If a program errors during execution, execution **short-circuits immediately** with `Deny`
- If no program returns `Deny` but any returns `Log`, the final action is `Log`
- If all programs return `Allow`, the final action is `Allow`

`[IMPL: ✅ attach.rs run_at() — sequential execution with priority merge]`

---

## 9. Action Codes

Programs return an action code in `r0` to indicate their policy decision.

| Value | Name | Meaning |
|-------|------|---------|
| `0` | `Allow` | Permit the operation |
| `1` | `Deny` | Block the operation (returns `E_NO_CAP` to caller) |
| `2` | `Log` | Permit but emit additional audit event |

Any value other than 0 or 2 is treated as `Deny` (default-deny for unknown codes).

`[IMPL: ✅ types.rs Action enum + Action::from_u64()]`

---

## 10. Static Verifier Rules

All programs must pass static verification before loading. The verifier is a single-pass linear scan.

### 10.1 Rule table

| # | Rule | Rejection reason |
|---|------|-----------------|
| 1 | Program must be non-empty | `ProgramTooLarge` |
| 2 | Program must not exceed `MAX_INSNS` (256) instructions | `ProgramTooLarge` |
| 3 | Last instruction must be `BPF_JMP \| BPF_EXIT` | `"last instruction must be BPF_EXIT"` |
| 4 | All jump targets must be in bounds `[0, len)` | `"jump target out of bounds"` |
| 5 | **No backward jumps:** target must be `> pc` | `"backward jump detected (no loops allowed)"` |
| 6 | All register indices must be in `[0, 10]` | `InvalidRegister` |
| 7 | `r10` must never appear as a write destination (ALU/ALU64/LDX dst) | `"r10 (frame pointer) is read-only"` |
| 8 | All opcodes must belong to a recognized class and operation | `InvalidOpcode` |

### 10.2 Loop policy

**No loops of any kind are permitted.** The verifier enforces a simplified DAG (directed acyclic graph) check by rejecting all backward jumps (`target_pc <= current_pc`). This guarantees termination statically without path simulation.

This is more restrictive than Linux eBPF, which allows bounded loops (kernel 5.3+) via path-based complexity analysis. ATOS chooses simplicity and absolute termination guarantees over expressiveness.

### 10.3 What the verifier does NOT check

- Helper ID validity (checked at runtime)
- Memory access bounds (checked at runtime)
- Register liveness / initialization (not tracked)
- Division by zero (checked at runtime)

`[IMPL: ✅ verifier.rs verify() — single-pass, all 8 rules]`

---

## 11. Runtime Execution Semantics

### 11.1 Execution loop

```text
1. Initialize: r0-r9 = 0, r1 = ctx, r10 = frame_ptr, PC = 0, insn_count = 0
2. Loop:
   a. If PC >= program.len() → error OutOfBounds
   b. If insn_count >= max_insns → error MaxInstructionsExceeded
   c. insn_count += 1
   d. Fetch insn = program[PC]
   e. Decode class = opcode & 0x07
   f. Execute instruction (may modify regs, PC, memory)
   g. If instruction was BPF_EXIT → return r0
   h. PC += 1
   i. Go to step 2
```

### 11.2 Arithmetic semantics

- **Wrapping:** ADD, SUB, MUL use wrapping arithmetic (no overflow error)
- **Division by zero:** DIV and MOD return `EbpfError::DivisionByZero`, which **terminates the program** and defaults the action to Deny. This differs from standard Linux eBPF, where DIV by 0 silently returns 0 and MOD by 0 returns the dividend unchanged (see §17.4).
- **Sign extension:** Immediates are sign-extended from i32 to i64, then reinterpreted as u64
- **Shift masking:** 64-bit shifts mask amount with `& 63`; 32-bit shifts with `& 31`
- **NEG:** Two's complement negation: `dst = -(dst as i64) as u64`
- **ALU32 zero-extend:** 32-bit results are zero-extended to 64-bit

### 11.3 Instruction budget

Each `execute()` call has an instruction budget (default 10,000). Every instruction executed increments the counter. If the counter reaches the budget, execution halts with `MaxInstructionsExceeded`. This provides a second layer of termination guarantee beyond the verifier's no-backward-jump rule.

### 11.4 Energy accounting

eBPF-lite execution is charged against the **system energy pool**, not individual agent budgets. This is because eBPF runs as kernel policy, not as agent code.

`[IMPL: ✅ runtime.rs execute() — full execution loop with all semantics above]`

---

## 12. Program Management (policyd Protocol)

The `policyd` system agent manages eBPF program lifecycle via mailbox messages.

### 12.1 Message format

#### OP_ATTACH (0x01) — Load and attach a program

```text
Byte   Field                  Type
────────────────────────────────────────
0      opcode = 0x01          u8
1      attach_type            u8       (0=SyscallEntry, 1=SyscallExit,
                                        2=MailboxSend, 3=MailboxRecv,
                                        4=AgentSpawn, 5=TimerTick)
2-3    attach_target          u16 LE   (syscall num or mailbox ID)
4      priority               u8       (lower = higher priority, default 128)
5-6    prog_len               u16 LE   (total bytecode size in bytes)
7..    bytecode               [u8]     (8-byte aligned instructions)
```

Instruction count is derived: `insn_count = prog_len / 8`.

Maximum: 1024 instructions = 8,192 bytes of bytecode. A single message can carry up to **31 instructions** (7 header bytes + 31 × 8 = 255 bytes). For larger programs, use OP_ATTACH_CHUNK (0x04).

#### OP_DETACH (0x02) — Remove a program

```text
Byte   Field                  Type
────────────────────────────────────────
0      opcode = 0x02          u8
1-2    program_index          u16 LE   (index returned by attach)
```

#### OP_LIST (0x03) — List attached programs

```text
Byte   Field                  Type
────────────────────────────────────────
0      opcode = 0x03          u8
```

Response: policyd iterates attached programs via `for_each_attached()` and outputs each entry's slot index, attach point, priority, and instruction count to the serial log.

#### OP_ATTACH_CHUNK (0x04) — Multi-message program loading

For programs larger than a single mailbox message (> 31 instructions).

```text
First chunk:  [op=0x04, flags=0x01, attach_type, attach_target:u16, priority, total_len:u16, bytecode...]
Continuation: [op=0x04, flags=0x00, bytecode...]
Last chunk:   [op=0x04, flags=0x02, bytecode...]  (triggers attach)
```

Flags: bit 0 = first chunk (has header), bit 1 = last chunk (triggers attach). Chunks are accumulated in a static 8192-byte buffer.

#### OP_REPLACE (0x05) — Hot-replace program bytecode

```text
Byte   Field                  Type
────────────────────────────────────────
0      opcode = 0x05          u8
1-2    program_index          u16 LE   (index of program to replace)
3-4    prog_len               u16 LE   (new bytecode size in bytes)
5..    bytecode               [u8]
```

Replaces the bytecode of an existing program. The attach point and priority are preserved. The new program is verified before replacement.

### 12.2 Capability requirement

Loading, unloading, and replacing eBPF programs requires the `CAP_POLICY_LOAD` capability (`CapType::PolicyLoad = 7`). Policyd checks `agent_has_cap(msg.sender_id, CapType::PolicyLoad, 0)` before processing OP_ATTACH, OP_ATTACH_CHUNK, OP_DETACH, and OP_REPLACE. OP_LIST does not require the capability.

`[IMPL: ✅ agents/policyd.rs — ATTACH/DETACH/LIST/ATTACH_CHUNK/REPLACE with CAP_POLICY_LOAD; ✅ capability.rs PolicyLoad=7]`

---

## 13. AEBF Binary Format

The SDK compiles `.ebpf` text assembly into `.bin` files using the **AEBF** (ATOS eBPF) binary format. This is a simple, non-ELF format with an 8-byte header followed by raw instructions.

### 13.1 Layout

```text
Offset  Size   Field
──────────────────────────────────────
0       4      magic = "AEBF" (0x41 0x45 0x42 0x46)
4       1      version = 1
5       2      insn_count (u16, little-endian)
7       1      padding (0x00)
8       N×8    instructions, each 8 bytes (little-endian encoding)
```

Each instruction is encoded as:

```text
Byte 0:    opcode (u8)
Byte 1:    regs   (u8, dst:4 | src:4)
Byte 2-3:  off    (i16, little-endian)
Byte 4-7:  imm    (i32, little-endian)
```

### 13.2 Validation on read

- Magic must be exactly `"AEBF"`
- Version must be `1` (future versions may extend the header)
- `insn_count` determines how many 8-byte instruction records follow the header

`[IMPL: ✅ sdk/atos-ebpf-sdk/src/binary.rs — write_binary() / read_binary()]`

---

## 14. SDK Assembly Syntax

The `atos-ebpf-sdk` provides a text assembler (`atos-ebpf compile`) for writing eBPF-lite programs. Source files use the `.ebpf` extension by convention.

### 14.1 General syntax

```text
; This is a comment
mnemonic  operand1, operand2     ; inline comment
```

**Line structure:**

- Each non-empty, non-comment line is one instruction
- Lines starting with `;` are comments (the entire line is ignored)
- Anything after the first `;` on a line is an inline comment and is stripped before parsing
- Empty lines and whitespace-only lines are ignored
- The first whitespace-delimited token is the mnemonic; the remainder is the operand string

**Mnemonics:**

- Case-insensitive: `MOV`, `mov`, `Mov` are all accepted
- Must be one of the recognized mnemonics listed in §14.2–14.4; unknown mnemonics produce an error

**Operand separators:**

- Multiple operands are separated by **commas** (`,`)
- Whitespace around commas is optional and stripped: `add r0,1` and `add r0, 1` are equivalent
- Two-operand instructions (ALU, memory) expect exactly 2 comma-separated operands
- Three-operand instructions (conditional jumps) expect exactly 3 comma-separated operands
- Zero-operand instructions (`exit`) and one-operand instructions (`neg rD`, `ja +off`, `call N`) have no commas

**Registers:**

- Named `r0` through `r10` (or `R0` through `R10`)
- Register index must be in range 0–10; `r11` and above produce an error
- The assembler determines whether an operand is a register or immediate by checking if it starts with `r` or `R`

**Immediate values:**

- Three numeric formats:
  - Decimal: `42`, `-7`, `0`
  - Hexadecimal: `0x1234`, `0xFF`, `0XAB` (prefix `0x` or `0X`)
  - Binary: `0b1010`, `0B1100` (prefix `0b` or `0B`)
- May be negative (prefix `-`): `-0x10` = `-16`
- Immediates for ALU/JMP operands must fit in **i32** range (`-2147483648` to `2147483647`)

**Jump offsets:**

- Jump offsets are specified as signed integers in **i16** range (`-32768` to `32767`)
- The `+` prefix is **optional**: `ja +3` and `ja 3` are equivalent
- Negative offsets use `-`: `ja -2` (though the verifier will reject backward jumps)
- Offsets represent the displacement from the *next* instruction: effective target = `current_pc + 1 + offset`

**Memory references:**

- Enclosed in square brackets: `[rN+offset]` or `[rN-offset]`
- Three accepted forms:
  - `[r1+8]` — positive offset
  - `[r1-4]` — negative offset
  - `[r1]` — no offset (implicitly `+0`)
- The offset is parsed as a signed i16 (`-32768` to `32767`)
- Whitespace is not allowed inside the brackets

**Error reporting:**

- All assembler errors include the **line number** and a descriptive message
- Format: `line N: <description>`
- Examples:
  - `line 3: unknown mnemonic 'nop'`
  - `line 7: expected register like r0-r10, got 'x1'`
  - `line 12: immediate 3000000000 does not fit in i32`
  - `line 15: jump offset 40000 does not fit in i16`
  - `line 20: expected [rN+off], got 'r1+8'`

### 14.2 ALU instructions

```text
mov  rD, imm          ; rD = sign_extend(imm)
mov  rD, rS           ; rD = rS
add  rD, imm/rS       ; rD += operand
sub  rD, imm/rS       ; rD -= operand
mul  rD, imm/rS       ; rD *= operand
div  rD, imm/rS       ; rD /= operand
mod  rD, imm/rS       ; rD %= operand
and  rD, imm/rS       ; rD &= operand
or   rD, imm/rS       ; rD |= operand
xor  rD, imm/rS       ; rD ^= operand
lsh  rD, imm/rS       ; rD <<= operand
rsh  rD, imm/rS       ; rD >>= operand
neg  rD               ; rD = -rD
```

All ALU mnemonics generate **64-bit ALU64** instructions (class `0x07`). The assembler does not support 32-bit ALU mnemonics. The disassembler outputs 32-bit ALU instructions with a `32` suffix (e.g., `add32`, `mov32`), but these suffixed forms cannot be used as assembler input.

The assembler auto-detects the operand type: if the second operand starts with `r`/`R`, it generates a register-source instruction (BPF_X); otherwise it parses the operand as an immediate (BPF_K).

### 14.3 Jump instructions

```text
ja   +offset                    ; unconditional jump (offset only, no register)
jeq  rD, imm/rS, +offset       ; jump if equal
jne  rD, imm/rS, +offset       ; jump if not equal
jgt  rD, imm/rS, +offset       ; jump if greater (unsigned)
jge  rD, imm/rS, +offset       ; jump if greater or equal (unsigned)
jlt  rD, imm/rS, +offset       ; jump if less (unsigned)
jle  rD, imm/rS, +offset       ; jump if less or equal (unsigned)
jset rD, imm/rS, +offset       ; jump if bit set
call helper_id                  ; call helper function (helper_id is an immediate)
exit                            ; return r0 (no operands)
```

For conditional jumps, the second operand follows the same auto-detection rule as ALU: `r`/`R` prefix → register, otherwise → immediate.

### 14.4 Memory instructions

```text
ldxb  rD, [rS+offset]          ; load  8-bit   (zero-extended to 64-bit)
ldxh  rD, [rS+offset]          ; load 16-bit   (zero-extended to 64-bit)
ldxw  rD, [rS+offset]          ; load 32-bit   (zero-extended to 64-bit)
ldxdw rD, [rS+offset]          ; load 64-bit
stxb  [rD+offset], rS          ; store  8-bit
stxh  [rD+offset], rS          ; store 16-bit
stxw  [rD+offset], rS          ; store 32-bit
stxdw [rD+offset], rS          ; store 64-bit
```

Memory reference forms: `[r1+8]`, `[r1-4]`, `[r1]` (see §14.1 for details).

> **Note:** There are no assembler mnemonics for immediate-store instructions (ST class, §4.6). The runtime supports ST instructions, but they can only be generated programmatically (e.g., via policyd or direct bytecode construction), not through the text assembler.

### 14.5 Example: allow all sends

```text
; Allow-all policy — always returns ALLOW (0)
mov r0, 0
exit
```

### 14.6 Example: deny sends to a specific agent

```text
; Deny sends from agent 4 to this mailbox
; Context: r1 -> MailboxContext { sender_id: u16, target_mailbox: u16, payload_len: u16 }
ldxh r2, [r1+0]          ; 0: r2 = sender_id
jeq  r2, 4, +2           ; 1: if sender == 4 → PC 4 (deny)
mov  r0, 0               ; 2: allow
exit                     ; 3:
mov  r0, 1               ; 4: deny
exit                     ; 5:
```

### 14.7 Example: rate-limit via map counter

This example demonstrates map usage for counting sends per agent. It uses `map_update` (helper 2) to increment a counter stored in map 0. If the counter exceeds 100, the send is denied.

> **Implementation note:** `check_write()` restricts writes to the stack region only. Writing directly to a `map_lookup` pointer via `stxdw [r0+0], r7` would fail with `OutOfBounds`. Therefore, counter updates must go through `map_update` (helper 2), not through direct pointer writes.

```text
; Rate-limit sends per agent using map 0
; Deny if agent has sent more than 100 messages
; Total: 28 instructions (fits in single mailbox message)
;
; PC  Instruction
mov  r6, r1              ; 0:  save context pointer
call 4                   ; 1:  r0 = get_agent_id()
stxdw [r10-8], r0        ; 2:  store agent_id on stack as key

mov  r1, 0               ; 3:  map_id = 0
mov  r2, r10             ; 4:
add  r2, -8              ; 5:  r2 = &key (on stack)
mov  r3, 8               ; 6:  key_len = 8
call 1                   ; 7:  r0 = map_lookup(0, &key, 8)

jeq  r0, 0, +5           ; 8:  if not found → PC 14 (insert count=1)
ldxdw r7, [r0+0]         ; 9:  r7 = current count (read from map pointer — allowed)
add  r7, 1               ; 10: increment
jgt  r7, 100, +14        ; 11: if count > 100 → PC 26 (deny)
stxdw [r10-16], r7       ; 12: write new count to stack
ja   +2                  ; 13: → PC 16 (common map_update path)

; Insert new entry with count = 1
mov  r7, 1               ; 14:
stxdw [r10-16], r7       ; 15: value = 1 on stack

; Common path: call map_update with value on stack
mov  r1, 0               ; 16: map_id
mov  r2, r10             ; 17:
add  r2, -8              ; 18: key_ptr
mov  r3, 8               ; 19: key_len
mov  r4, r10             ; 20:
add  r4, -16             ; 21: val_ptr (count on stack)
mov  r5, 8               ; 22: val_len
call 2                   ; 23: map_update(0, &key, 8, &val, 8)
mov  r0, 0               ; 24: allow
exit                     ; 25:

; Deny — rate limit exceeded
mov  r0, 1               ; 26:
exit                     ; 27:
```

`[IMPL: ✅ sdk/atos-ebpf-sdk/src/assembler.rs — full text assembler]`

---

## 15. Implementation Constants

| Constant | Value | Location | Description |
|----------|-------|----------|-------------|
| `NUM_REGS` | 11 | `types.rs` | Register count (r0–r10) |
| `MAX_INSNS` | 1024 | `types.rs` | Maximum program size (instructions) |
| `STACK_SIZE` | 512 | `types.rs` | Per-execution stack (bytes) |
| `DEFAULT_MAX_INSNS` | 10,000 | `attach.rs` | Runtime instruction budget |
| `MAX_ATTACHED` | 16 | `attach.rs` | Maximum attached programs |
| `MAX_MAPS` | 8 | `maps.rs` | Global map table size |
| `MAX_MAP_ENTRIES` | 64 | `maps.rs` | Entries per map |
| `MAX_KEY_SIZE` | 8 | `maps.rs` | Maximum key size (bytes) |
| `MAX_VALUE_SIZE` | 64 | `maps.rs` | Maximum value size (bytes) |

---

## 16. Error Types

| Error | Trigger |
|-------|---------|
| `InvalidProgram` | Bytecode parsing failed |
| `ProgramTooLarge` | Program empty or exceeds 1024 instructions |
| `InvalidOpcode(u8)` | Unknown opcode encountered during verification or execution |
| `InvalidRegister(u8)` | Register index >= 11 |
| `DivisionByZero` | DIV or MOD with src = 0 |
| `OutOfBounds` | PC exceeds program length; memory access outside permitted region |
| `InvalidHelper(u32)` | Unknown helper function ID |
| `VerificationFailed(&str)` | Static verifier rejected program (with reason) |
| `MaxInstructionsExceeded` | Execution instruction counter reached budget |
| `MapFull` | All 64 entries in use during `map_update` |
| `KeyTooLarge` | Key exceeds 8 bytes |
| `ValueTooLarge` | Value exceeds 64 bytes |
| `NoFreeSlot` | No free slot in map table or program table |

`[IMPL: ✅ types.rs EbpfError enum]`

---

## 17. Differences from Standard Linux eBPF

### 17.1 Missing opcodes

| Feature | Linux eBPF | ATOS eBPF-lite | Impact |
|---------|-----------|----------------|--------|
| `ARSH` (arithmetic right shift) | ✅ | ✅ | — |
| `JSGT/JSGE/JSLT/JSLE` (signed jumps) | ✅ | ✅ | — |
| `JMP32` class (0x06) | ✅ | ❌ | No 32-bit branch optimization |
| `BPF_LD_IMM64` (64-bit immediate load) | ✅ | ✅ | — |
| `BPF_LD_ABS / BPF_LD_IND` | ✅ | ❌ | Packet direct access (N/A for ATOS) |
| `BPF_ATOMIC` (XADD, XCHG, CMPXCHG) | ✅ | ❌ | No atomic operations (single-core) |
| `BPF_END` (byte swap LE/BE) | ✅ | ❌ | No endian conversion |

### 17.2 Verifier differences

| Aspect | Linux eBPF | ATOS eBPF-lite |
|--------|-----------|----------------|
| Loop support | Bounded loops (5.3+) via path simulation | **No loops at all** (no backward jumps) |
| Max instructions | 1,000,000 | **1024** |
| Verification method | Path-based symbolic execution | Single-pass linear scan |
| Register tracking | Full type + range tracking per path | Index bounds check only |
| BTF/CO-RE | ✅ | ❌ |
| BPF-to-BPF calls | ✅ (4.16+) | ❌ |
| Tail calls | ✅ | ❌ |

### 17.3 Runtime differences

| Aspect | Linux eBPF | ATOS eBPF-lite |
|--------|-----------|----------------|
| Helper functions | 200+ | 14 |
| Map types | 30+ | 2 (hash + array) |
| Program types | 30+ (XDP, tc, kprobe, etc.) | 6 attachment points |
| JIT compilation | ✅ | ❌ (interpreter only) |
| Ring buffer output | ✅ (`bpf_ringbuf_*`) | ❌ |
| Per-CPU maps | ✅ | ❌ (single-core) |
| Pinning (bpffs) | ✅ | ❌ |

### 17.4 Semantic differences (same opcodes, different behavior)

These differences are more subtle than missing opcodes — the bytecode is identical, but the runtime behavior differs:

| Behavior | Standard Linux eBPF | ATOS eBPF-lite | Risk |
|----------|-------------------|----------------|------|
| **DIV by 0 (64-bit)** | `dst = 0` (silent) | `EbpfError::DivisionByZero` (terminates program) | Program that relies on div-by-zero returning 0 will be terminated on ATOS |
| **MOD by 0 (64-bit)** | `dst = dst` (returns dividend) | `EbpfError::DivisionByZero` (terminates program) | Same — ATOS treats all zero-divisor cases as fatal |
| **DIV by 0 (32-bit)** | `dst = 0` | `EbpfError::DivisionByZero` | Same |
| **MOD by 0 (32-bit)** | `dst = dst` | `EbpfError::DivisionByZero` | Same |
| **r1–r5 after `call`** | Clobbered (caller-saved) | **Preserved** | Programs using r1–r5 after call work on ATOS but break on Linux |

The division-by-zero difference is a deliberate ATOS design choice: in a policy engine, silent corruption (returning 0 for a division) is worse than explicit failure. A program that divides by a potentially-zero value should guard with a `jeq` check before the `div`/`mod` instruction.

### 17.5 Design rationale

ATOS eBPF-lite intentionally does not aim for Linux eBPF compatibility. It borrows the bytecode encoding format for toolchain familiarity, but the runtime semantics serve a different purpose: **agent policy enforcement** rather than network/tracing programmability. The restricted feature set reflects ATOS's priorities of verifiable termination, minimal kernel complexity, and deterministic execution.

---

## 18. Extensions (all implemented)

All enhancements from Yellow Paper §25.2.7 and gap analysis have been implemented.

### 18.1 Stage-3 (Yellow Paper §25.2.7)

| Enhancement | Description | Status |
|-------------|-------------|--------|
| All attachment points wired | SyscallEntry/Exit, MailboxSend/Recv, AgentSpawn, TimerTick | ✅ Done |
| Program chaining with priority | `AttachedProgram.priority: u8`, insertion sort in `run_at()` | ✅ Done |
| Persistent maps | `map_persist` (ID 13) / `map_restore` (ID 14) via state subsystem | ✅ Done |
| Metrics helpers | `increment_counter` (ID 11), `read_gauge` (ID 12) | ✅ Done |
| Hot-reload | `replace(index, new_program)` + OP_REPLACE (0x05) protocol | ✅ Done |

### 18.2 Opcode extensions

| Extension | Description | Status |
|-----------|-------------|--------|
| `BPF_LD_IMM64` | Two-instruction 64-bit immediate load (opcode 0x18) | ✅ Done |
| `JSGT/JSGE/JSLT/JSLE` | Signed comparison jumps (opcodes 0x65/0x6D/0x75/0x7D/0xC5/0xCD/0xD5/0xDD) | ✅ Done |
| `ARSH` | Arithmetic right shift, ALU64 (0xC7) and ALU32 (0xC4) | ✅ Done |

### 18.3 Helper extensions

| Helper | ID | Purpose | Status |
|--------|----|---------|--------|
| `emit_event` | 6 | Emit audit event to kernel event subsystem | ✅ Done |
| `get_mailbox_pressure` | 8 | Read mailbox fill level (0–16) | ✅ Done |
| `get_agent_parent` | 9 | Read parent agent ID | ✅ Done |
| `get_capability_count` | 10 | Read agent's capability count | ✅ Done |
| `increment_counter` | 11 | Atomic u64 counter increment in map | ✅ Done |
| `read_gauge` | 12 | Read u64 gauge value from map | ✅ Done |
| `map_persist` | 13 | Serialize map to agent keyspace | ✅ Done |
| `map_restore` | 14 | Restore map from agent keyspace | ✅ Done |
| `drop_message` | — | Silently drop at MailboxRecv | ✅ Covered by `Action::Deny` |

### 18.4 Infrastructure extensions

| Extension | Description | Status |
|-----------|-------------|--------|
| SMP safety (PROGRAMS) | `SpinLock<[Option<AttachedProgram>; 16]>` in attach.rs | ✅ Done |
| SMP safety (MAPS) | `MAPS_SLOT_LOCK: SpinLock<()>` for slot creation; data access serialized by PROGRAMS lock | ✅ Done |
| Array map type | `MapType::Array` with O(1) indexed access via u32 key | ✅ Done |
| Multi-message loading | OP_ATTACH_CHUNK (0x04) with chunked accumulation buffer | ✅ Done |
| Instruction limit increase | MAX_INSNS: 256 → 1024 | ✅ Done |

---

## Appendix A. Source File Map

| File | Lines | Description |
|------|-------|-------------|
| `src/ebpf/mod.rs` | ~10 | Module declaration |
| `src/ebpf/types.rs` | ~138 | Instruction encoding, opcodes (incl. ARSH, signed jumps), 14 helper IDs, constants |
| `src/ebpf/runtime.rs` | ~548 | VM interpreter, ALU/JMP/MEM/LD_IMM64 execution, 14 helper dispatchers |
| `src/ebpf/verifier.rs` | ~164 | Static verification (8 rules + LD_IMM64 skip_next, signed jumps) |
| `src/ebpf/attach.rs` | ~205 | SpinLock-protected program table, priority sort, `run_at()`, `replace()`, `for_each_attached()` |
| `src/ebpf/maps.rs` | ~383 | Hash + Array map types, SMP-safe slot lock, persist/restore via state.rs |
| `src/agents/policyd.rs` | ~303 | policyd: ATTACH/DETACH/LIST/ATTACH_CHUNK/REPLACE with CAP_POLICY_LOAD |
| `src/syscall.rs` | ~857 | Syscall dispatcher with eBPF hooks at all 6 attachment points |
| `src/sched.rs` | (line 413) | TimerTick eBPF hook in `timer_tick()` |
| `src/capability.rs` | ~350 | Capability model including `PolicyLoad = 7` |
| `src/event.rs` | ~240 | Audit subsystem including `EbpfPolicy = 22` event type |
| `src/init.rs` | (lines 502–566) | Boot-time eBPF test programs |
| `sdk/atos-ebpf-sdk/src/assembler.rs` | ~300 | Text-to-bytecode assembler |
| `sdk/atos-ebpf-sdk/src/verifier.rs` | ~130 | Offline verifier (mirrors kernel) |
| `sdk/atos-ebpf-sdk/src/disasm.rs` | ~100 | Bytecode disassembler |
| `sdk/atos-ebpf-sdk/src/binary.rs` | ~80 | Binary serialization format |
