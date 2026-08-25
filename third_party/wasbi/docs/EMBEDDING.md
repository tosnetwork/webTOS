# Embedding Guide

How to use wasbi as a WebAssembly interpreter in your Rust application.

## Adding wasbi as a dependency

```toml
[dependencies]
wasbi = { path = "../wasbi" }
# or, once published:
# wasbi = "0.1"
```

Wasbi is `no_std` with an `alloc` dependency. It works in bare-metal,
kernel, and hosted environments.

## Loading a module

```rust
use wasbi::prelude::*;

let engine = Engine::default();
let wasm_bytes: &[u8] = include_bytes!("my_module.wasm");
let module = Module::new(&engine, wasm_bytes)
    .expect("decode + validate failed");
```

`Module::new` decodes the binary and validates it in a single step.
Validation errors are returned as `WasmError` variants such as
`InvalidMagic`, `UnsupportedVersion`, or `TypeMismatch`.

## Instantiation

```rust
let mut instance = Instance::new(module, &engine)
    .expect("instantiation failed");
```

Instantiation allocates memories, tables, and globals, and evaluates
data/element segment initializers. It does **not** run the start
function automatically -- call `instance.run_start()` if needed.

## Calling exported functions

```rust
let result = instance.call("add", &[Value::I32(2), Value::I32(3)]);
match result {
    ExecResult::Returned(val) => {
        assert_eq!(val.as_i32(), 5);
    }
    ExecResult::Ok => {
        // Function returned with no value.
    }
    ExecResult::Trap(err) => {
        panic!("trap: {:?}", err);
    }
    ExecResult::OutOfFuel => {
        panic!("fuel exhausted");
    }
    // ...
    _ => {}
}
```

You can also call by raw function index:

```rust
let result = instance.call_by_index(0, &[Value::I64(42)]);
```

## Registering host functions with Linker

The `Linker` lets you provide host-side implementations for WASM imports.

```rust
use wasbi::linker::Linker;
use wasbi::runtime::WasmInstance;

let mut linker = Linker::new();
linker.func_wrap("env", "log", |_inst: &mut WasmInstance, args: &[Value]| {
    let msg_ptr = args[0].as_i32() as usize;
    let msg_len = args[1].as_i32() as usize;
    // Access instance memory to read the string, etc.
    Ok(None) // no return value
});

linker.func_wrap("env", "add", |_inst: &mut WasmInstance, args: &[Value]| {
    let a = args[0].as_i32();
    let b = args[1].as_i32();
    Ok(Some(Value::I32(a + b)))
});
```

Host functions receive `&mut WasmInstance` for direct memory access and
the arguments popped from the WASM operand stack. Return `Ok(Some(val))`
to push a return value, `Ok(None)` for void, or `Err(WasmError::...)` to
trap.

## Handling HostCall results (the resume loop)

When a WASM module calls an imported function, execution pauses and
returns `ExecResult::HostCall`. You must dispatch the call and resume:

```rust
use wasbi::linker::Linker;

fn run_to_completion(
    instance: &mut Instance,
    linker: &Linker,
    func_name: &str,
    args: &[Value],
) -> ExecResult {
    let mut result = instance.call(func_name, args);
    loop {
        match result {
            ExecResult::HostCall(func_idx, host_args, arg_count) => {
                let args_slice = &host_args[..arg_count as usize];
                match linker.dispatch(instance.as_inner_mut(), func_idx, args_slice) {
                    Ok(ret_val) => {
                        result = instance.resume(ret_val);
                    }
                    Err(err) => {
                        return ExecResult::Trap(err);
                    }
                }
            }
            // Terminal states: return as-is.
            other => return other,
        }
    }
}
```

> **Note**: `instance.as_inner_mut()` exposes the underlying `WasmInstance`
> for linker dispatch. This is the standard embedding pattern.

## Fuel metering

Wasbi charges one unit of fuel per WASM instruction. When fuel reaches
zero, execution suspends with `ExecResult::OutOfFuel`.

### Setting fuel via Config

```rust
use wasbi::config::Config;

let mut config = Config::default(); // fuel defaults to 1_000_000
config.fuel = 10_000_000;

let engine = Engine::new(config);
```

### Runtime fuel management

```rust
// Check remaining fuel.
let remaining = instance.fuel();

// Top up fuel (e.g., between calls).
instance.set_fuel(5_000_000);

// Handle exhaustion.
let result = instance.call("work", &[]);
if matches!(result, ExecResult::OutOfFuel) {
    instance.set_fuel(1_000_000);
    let result = instance.run(); // resume where it left off
    // ...
}
```

## Error handling

All errors flow through `WasmError`, which covers four layers:

| Layer           | Example variants                               |
|-----------------|-------------------------------------------------|
| Decode          | `InvalidMagic`, `InvalidLEB128`, `UnexpectedEnd`|
| Validation      | `TypeMismatch`, `DuplicateExport`, `ImmutableGlobal` |
| Instantiation   | `ImportNotFound(idx)`, `FunctionNotFound(idx)`  |
| Runtime trap    | `StackOverflow`, `DivisionByZero`, `Unreachable`|

`Module::new` returns decode and validation errors. `Instance::new`
returns instantiation errors. `instance.call` returns runtime traps
wrapped in `ExecResult::Trap(WasmError)`.

```rust
match Module::new(&engine, bad_bytes) {
    Err(WasmError::InvalidMagic) => { /* not a WASM file */ }
    Err(WasmError::TypeMismatch) => { /* validation failure */ }
    Err(e) => { /* other error */ }
    Ok(_) => {}
}
```

## Memory access

Linear memory is exposed as byte slices:

```rust
// Read memory 0.
if let Some(mem) = instance.memory(0) {
    let first_page = &mem[..65536];
    // ...
}

// Write to memory 0.
if let Some(mem) = instance.memory_mut(0) {
    mem[0x100..0x104].copy_from_slice(&42u32.to_le_bytes());
}

// Query memory size in bytes.
let size = instance.memory_size(0).unwrap_or(0);
```

## RuntimeClass selection

Wasbi supports three runtime classes that control which WASM features
are permitted at validation time:

| Class         | Floats | SIMD | Threads | Use case               |
|---------------|--------|------|---------|------------------------|
| `BestEffort`  | yes    | yes  | yes     | General execution      |
| `ReplayGrade` | yes    | yes  | no      | Deterministic replay   |
| `ProofGrade`  | no     | no   | no      | Formal verification    |

```rust
use wasbi::config::Config;
use wasbi::types::RuntimeClass;

let mut config = Config::default();
config.runtime_class = RuntimeClass::ProofGrade;

let engine = Engine::new(config);
// Modules using floats or SIMD will be rejected at validation time.
```

`ProofGrade` is the strictest tier: it rejects floating-point, SIMD, and
thread instructions, ensuring fully deterministic execution suitable for
on-chain proof verification.
