# Wasmi WASM Engine Integration — Porting Plan

**Status:** Design Document
**Companion to:** Yellow Paper §27, ATOS Runtime Architecture

> This document describes how to replace ATOS's self-built WASM interpreter with [wasmi](https://github.com/wasmi-labs/wasmi), a production-ready, audited, `#![no_std]` WebAssembly interpreter designed for embedded and constrained environments. Unlike the Ristretto JVM port (which requires significant virtualization work), wasmi is a near-drop-in replacement — it already supports everything ATOS needs out of the box.

---

## 1. Why Replace the Self-Built Interpreter

| | ATOS Self-Built | wasmi v2.0 |
|---|---|---|
| WASM spec compliance | Partial (MVP + some proposals) | **100% spec testsuite** |
| Security audits | None | **Audited twice** (SRLabs/Parity 2023, Runtime Verification/Stellar 2024) |
| `#![no_std]` support | N/A (lives in kernel) | **Native `#![no_std]` + alloc** |
| Fuel metering | Custom implementation | **Built-in, configurable `FuelCosts` trait** |
| WASM proposals | Limited | **13 proposals fully supported** (SIMD, tail-calls, multi-memory, memory64, etc.) |
| Execution model | Stack-based interpreter | **Register-based IR** (80-100% faster than stack-based) |
| Host function API | Ad-hoc `handle_host_call()` | **Type-safe `Linker<T>` + `Store<T>` API** |
| Resource limiting | None | **`ResourceLimiter` trait** for memory/table/instance growth control |
| Maintenance | We maintain every opcode | **Community-maintained, actively developed** |
| Code maturity | ~2,000 lines, prototype quality | Production-grade, used by Parity/Stellar/others |

The self-built interpreter was valuable for prototyping the ATOS architecture. For production, wasmi provides spec compliance, security guarantees, and ongoing maintenance that we cannot match alone.

## 2. Why wasmi is an Ideal Fit

wasmi was explicitly designed for the exact use case ATOS needs:

> "Wasmi was designed with the above embedding scenarios in mind. It is specifically designed for use in resource-constrained, embedded, or otherwise specialized environments."
> — wasmi documentation

**Key properties that align with ATOS:**

1. **`#![no_std]`** — All core crates (`wasmi`, `wasmi_core`, `wasmi_ir`, `wasmi_collections`) declare `#![no_std]` at line 1. Only requires `alloc` (Vec, Box, Arc).

2. **Built-in fuel metering** — `FuelCosts` trait with configurable per-instruction costs. Maps directly to ATOS energy budgets. No need to build our own.

3. **Deterministic execution** — `LazyTranslation` compilation mode: validates eagerly, compiles lazily, ensures deterministic behavior. Perfect for ProofGrade replay.

4. **Resumable execution** — wasmi supports suspending and resuming execution at host function boundaries. Enables cooperative scheduling with ATOS.

5. **Type-safe host integration** — `Linker<T>` provides compile-time-checked host function bindings. `Store<T>` carries per-instance state. Far safer than our current raw pointer approach.

6. **Resource control** — `ResourceLimiter` trait lets ATOS cap memory growth, table sizes, and instance counts per agent. Maps to agent memory quotas.

## 3. Architecture

```
┌──────────────────────────────────────────────┐
│              .wasm binary                    │
├──────────────────────────────────────────────┤
│          wasmi Engine (no_std)               │
│   parse → validate → compile to wasmi IR     │
│   register-based interpreter + fuel meter    │
├──────────────────────────────────────────────┤
│       ATOS Host Bindings (Linker<T>)         │
│   sys_yield | sys_send | sys_recv | log      │
│   sys_exit  | sys_energy_get | ...           │
├──────────────────────────────────────────────┤
│       ATOS Native Agent Runtime              │
│   allocator (sys_mmap) | entry point         │
├──────────────────────────────────────────────┤
│             ATOS Kernel                      │
│   sched | mailbox | capability | energy      │
└──────────────────────────────────────────────┘
```

The wasmi engine runs as a **native ATOS agent** (Ring-3 x86_64). It is not embedded in the kernel. From the kernel's perspective, it is just another agent — with a mailbox, capabilities, and an energy budget. The agent happens to contain a WASM interpreter that executes user-submitted `.wasm` modules.

## 4. Integration Design

### 4.1 Dependency Configuration

```toml
[dependencies]
wasmi = { version = "2.0.0-beta.2", default-features = false }
```

This gives us:
- WASM parsing and validation (wasmparser, no_std mode)
- Register-based interpreter with fuel metering
- `Linker<T>` / `Store<T>` / `Module` / `Instance` API
- No filesystem, no networking, no threads — just pure computation

### 4.2 Host State Type

```rust
/// Per-instance ATOS state, carried in wasmi's Store<T>.
struct AtosHostState {
    agent_id: AgentId,
    mailbox_id: MailboxId,
    energy_budget: u64,
    finished: bool,
}
```

### 4.3 Host Function Bindings

Replace the current ad-hoc `handle_host_call()` with wasmi's type-safe `Linker`:

```rust
fn register_atos_host_functions(linker: &mut Linker<AtosHostState>) {
    // sys_yield() -> i32
    linker.func_wrap("atos", "sys_yield", |caller: Caller<'_, AtosHostState>| -> i32 {
        syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0) as i32
    }).unwrap();

    // sys_send(mailbox_id: i32, ptr: i32, len: i32) -> i32
    linker.func_wrap("atos", "sys_send",
        |caller: Caller<'_, AtosHostState>, mailbox: i32, ptr: i32, len: i32| -> i32 {
            let memory = caller.get_export("memory").unwrap().into_memory().unwrap();
            let data = &memory.data(&caller)[ptr as usize..(ptr + len) as usize];
            syscall::syscall(SYS_SEND, mailbox as u64, data.as_ptr() as u64, len as u64, 0, 0) as i32
        }
    ).unwrap();

    // sys_recv(mailbox_id: i32, ptr: i32, capacity: i32) -> i32
    linker.func_wrap("atos", "sys_recv",
        |mut caller: Caller<'_, AtosHostState>, mailbox: i32, ptr: i32, cap: i32| -> i32 {
            let memory = caller.get_export("memory").unwrap().into_memory().unwrap();
            let buf = &mut memory.data_mut(&mut caller)[ptr as usize..(ptr + cap) as usize];
            syscall::syscall(SYS_RECV, mailbox as u64, buf.as_mut_ptr() as u64, cap as u64, 0, 0) as i32
        }
    ).unwrap();

    // sys_exit(code: i32)
    linker.func_wrap("atos", "sys_exit",
        |mut caller: Caller<'_, AtosHostState>, code: i32| {
            caller.data_mut().finished = true;
            syscall::syscall(SYS_EXIT, code as u64, 0, 0, 0, 0);
        }
    ).unwrap();

    // sys_energy_get() -> i64
    linker.func_wrap("atos", "sys_energy_get",
        |caller: Caller<'_, AtosHostState>| -> i64 {
            syscall::syscall(SYS_ENERGY_GET, 0, 0, 0, 0, 0)
        }
    ).unwrap();

    // log(ptr: i32, len: i32)
    linker.func_wrap("atos", "log",
        |caller: Caller<'_, AtosHostState>, ptr: i32, len: i32| {
            let memory = caller.get_export("memory").unwrap().into_memory().unwrap();
            let data = &memory.data(&caller)[ptr as usize..(ptr + len) as usize];
            // Write to serial via kernel log
            serial_print_bytes(data);
        }
    ).unwrap();
}
```

This is a direct replacement of the current `src/wasm/host.rs` — same functions, same signatures, but type-safe and using wasmi's proper API instead of raw pointer manipulation.

### 4.4 Fuel ↔ Energy Bridge

wasmi's fuel system maps directly to ATOS energy:

```rust
// Configure engine with fuel metering
let mut config = Config::default();
config.consume_fuel(true);

let engine = Engine::new(&config);
let mut store = Store::new(&engine, AtosHostState { ... });

// Set initial fuel from agent's energy budget
store.set_fuel(agent_energy_budget);

// After execution, sync remaining fuel back to agent energy
let remaining = store.get_fuel().unwrap();
update_agent_energy(agent_id, remaining);
```

wasmi's default fuel cost is **1 fuel per instruction**. This can be customized via `FuelCostsProvider` to assign different costs to different instruction classes (e.g., SIMD operations cost more).

### 4.5 Resource Limiting

```rust
struct AtosResourceLimiter {
    mem_quota_pages: u32,  // from agent's memory quota
}

impl ResourceLimiter for AtosResourceLimiter {
    fn memory_growing(&mut self, current: usize, desired: usize, max: Option<usize>) -> Result<bool, MemoryError> {
        let pages = desired / 65536;
        Ok(pages <= self.mem_quota_pages as usize)
    }

    fn table_growing(&mut self, current: u32, desired: u32, max: Option<u32>) -> Result<bool, TableError> {
        Ok(desired <= 65536)  // MAX_TABLE_ENTRIES
    }
}

store.limiter(|state| &mut state.resource_limiter);
```

### 4.6 RuntimeClass Enforcement

| RuntimeClass | wasmi Configuration |
|-------------|-------------------|
| **BestEffort** | All features enabled, lazy compilation |
| **ReplayGrade** | `LazyTranslation` mode (deterministic), no threads |
| **ProofGrade** | `LazyTranslation`, no floats (reject modules with f32/f64 via custom validator), no SIMD |

ProofGrade float restriction can be enforced by scanning the module's type section and code section during loading — reject any module that uses `f32` or `f64` value types.

## 5. Migration Path

### Phase 1: Parallel Integration

Add wasmi as an alternative WASM backend alongside the existing self-built interpreter. Both coexist behind a runtime selection flag.

**Changes:**
1. Add `wasmi` dependency to `Cargo.toml` (default-features = false)
2. Create `src/wasm_wasmi/` module with wasmi-based agent runner
3. In `agent_loader.rs`, route WASM loading to wasmi backend
4. Implement all 6 host functions via `Linker<AtosHostState>`
5. Wire fuel metering to agent energy budget

**Test:** Existing WASM test agent (hello world, send/recv) runs identically on both backends.

### Phase 2: Feature Parity Validation

Verify that wasmi passes all tests the self-built interpreter handles, plus additional spec compliance.

**Changes:**
1. Run WASM spec testsuite against wasmi backend on ATOS
2. Validate RuntimeClass enforcement (BestEffort/ReplayGrade/ProofGrade)
3. Verify fuel accounting matches expected energy consumption
4. Test resource limiting (memory growth, table growth)

### Phase 3: Replace and Remove

Once wasmi backend is validated, remove the self-built interpreter.

**Changes:**
1. Remove `src/wasm/runtime.rs`, `src/wasm/decoder.rs`, `src/wasm/validator.rs`
2. Keep `src/wasm/types.rs` (RuntimeClass enum, shared types)
3. Update `agent_loader.rs` to use wasmi exclusively
4. Update `src/agents/wasm_agent.rs` boot-time test to use wasmi
5. Update eBPF-lite spec and yellowpaper references

**Result:** ~2,000 lines of self-built WASM interpreter replaced by a battle-tested, audited library.

## 6. What We Keep vs. What wasmi Replaces

| Component | Keep | Replace |
|-----------|------|---------|
| `src/wasm/host.rs` (host function definitions) | Rewrite using `Linker<T>` API | Old raw-pointer dispatch |
| `src/wasm/types.rs` (RuntimeClass, WasmModule) | Keep RuntimeClass; adapt WasmModule | — |
| `src/wasm/runtime.rs` (interpreter loop) | — | **wasmi engine** |
| `src/wasm/decoder.rs` (WASM parser) | — | **wasmparser** (wasmi dependency) |
| `src/wasm/validator.rs` (validation) | — | **wasmparser validation** |
| `src/agent_loader.rs` (spawn_wasm_with_class) | Adapt to wasmi API | — |
| `src/agents/wasm_agent.rs` (boot test) | Adapt to wasmi API | — |
| `sdk/atos-wasm-sdk` (user SDK) | **No changes** (same import names) | — |
| Existing `.wasm` binaries | **No changes** (wasmi is spec-compliant) | — |

The user-facing SDK (`atos-wasm-sdk`) and all existing `.wasm` binaries require **zero changes**. The host function import names (`atos.sys_yield`, `atos.sys_send`, etc.) stay the same — only the implementation behind them changes.

## 7. Comparison: Self-Built vs. wasmi vs. Ristretto

| Aspect | Self-built WASM | wasmi | Ristretto JVM |
|--------|----------------|-------|---------------|
| Target bytecode | WASM | WASM | Java |
| `#![no_std]` | N/A (kernel) | **Yes, native** | No (needs porting) |
| Porting effort | Already done | **Minimal** (~200 lines glue) | Significant (virtualization layer) |
| Spec compliance | Partial | **100%** | N/A (Java spec) |
| Fuel metering | Custom | **Built-in** | N/A (timer-tick only) |
| Host API | Raw pointers | **Type-safe Linker** | Syscall bridge |
| Maintenance | Us | **Community** | Community + us |
| Security audit | None | **Twice audited** | None |

## 8. Risk Assessment

| Risk | Mitigation |
|------|-----------|
| wasmi binary size too large for agent | wasmi with no_std + LTO is compact (~200-400 KB); ATOS allows 4 MB agent images |
| Performance regression | wasmi v2.0 register-based IR is 80-100% faster than stack-based interpreters; likely faster than our self-built |
| API stability | wasmi 2.0 is a major release with stable API; pinned version in Cargo.toml |
| Upstream abandonment | MIT/Apache-2.0 license; we can fork if needed; codebase is well-documented |

## 9. Allocator Requirement

wasmi requires `alloc` (Vec, Box, Arc). ATOS native agents need a heap allocator. Two options:

1. **Use ATOS `sys_mmap`** — implement a simple bump or free-list allocator on top of `sys_mmap` pages. The `atos-sdk` can provide this as `#[global_allocator]`.

2. **Use a no_std allocator crate** — `linked_list_allocator` or `buddy_system_allocator` initialized with a pre-allocated memory region from `sys_mmap`.

This is the same requirement as Ristretto and any non-trivial native agent. It is a one-time infrastructure investment, not specific to wasmi.

## 10. Relationship to Ristretto

wasmi and Ristretto follow the same porting pattern but at different difficulty levels:

```
wasmi:      #![no_std] ✅  →  add Linker host bindings  →  done
Ristretto:  #![no_std] ❌  →  add cfg(atos) + virtualization layer  →  much more work
```

Both become native ATOS agents. Both benefit from timer-tick energy metering. wasmi additionally uses its built-in fuel metering for instruction-level accounting (useful for ProofGrade). The two engines can coexist:

| Runtime | Engine | Bytecode |
|---------|--------|----------|
| WASM | wasmi (native agent) | .wasm files |
| Java | Ristretto (native agent) | .jar / .class files |
| eBPF-lite | Self-built (kernel) | eBPF bytecode |
| Native | Direct execution | ELF64 binaries |
