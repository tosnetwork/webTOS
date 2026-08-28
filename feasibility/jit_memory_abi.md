# JIT memory ABI: how a translated block reaches guest memory

A translated block runs as a wasm function over the register space (imported
as memory `env.regs`). Guest memory is a different thing entirely — paged,
permissioned, and able to fault — and a wasm function cannot reproduce the
MMU. So Load/Store are delegated to host imports that call the *same* memory
code the interpreter calls, which makes them bit-exact for free and leaves the
wasm responsible only for orchestration and the fault unwind.

This is the softmmu-callback shape qemu-wasm uses (learned, not copied — it is
GPL). It is deliberately narrow for now: **RAM space only, little-endian
only** (this engine is x86-64, `is_big_endian() == false`). A `Load`/`Store`
on any other space, or a size other than 1/2/4/8, bails the whole block to the
interpreter — the space id is known at translate time from `Op::Load(id)`, so
this is a compile-time decision, not a runtime one.

## Imports (declared only when a block actually loads or stores)

- `env.load(addr: i64, dst_off: i32, size: i32) -> (ok: i32)` — reads `size`
  bytes at `addr` through the host MMU (`mem.read::<N>(addr, perm::READ)`) and,
  on success, writes them straight into `env.regs` at `dst_off`. Little-endian
  makes that a memcpy, identical to the interpreter's `write_var`. On an MMU
  error it sets `cpu.exception` to `from_load_error(err)` with value `addr`
  (exactly the interpreter's path) and returns 0.
- `env.store(addr: i64, value: i64, size: i32) -> (ok: i32)` — writes the low
  `size` bytes of `value` (little-endian) at `addr`
  (`mem.write::<N>(addr, .., perm::WRITE)`). Passing the value on the stack (not
  a register offset) is what lets a *constant* store operand work. On error it
  sets `cpu.exception` to `from_store_error(err)` / `addr` and returns 0.
- `env.fault(index: i32)` — records the index of the instruction that faulted,
  so the host can return `Some(index)` exactly like `interpret_block_unchecked`.

## Per-op emission (index i in the block)

    Load:   push addr(i64); i32.const dst_off; i32.const size; call load
            if ok == 0 { i32.const i; call fault; return }
    Store:  push addr(i64); push value(i64); i32.const size; call store
            if ok == 0 { i32.const i; call fault; return }

`run()` stays `[] -> []`. A block that completes calls `fault` never; a block
that faults at instruction i has, byte for byte, applied instructions 0..i and
not i, set the same exception, and reported i — a perfect substitute for the
interpreter stopping mid-block.

## The gate

Two VMs built the same way (so the MMU config is identical, and faults match
by construction). A case may map a guest region and seed it in both. The block
is run through the interpreter on one VM and through the emitted wasm on the
other — the wasm's Load/Store imports backed by the second VM's real MMU — and
the gate compares the full register space, the guest region, the resume index
(`None` vs `Some(i)`), and `cpu.exception`. Fault cases (unmapped address) are
included, and every new arm is proven to make the gate fail before it passes.

## Not yet, and why it is safe to defer

`InstructionMarker` is still emitted as nothing. In a real block it updates PC
and decrements fuel, and can raise `InstructionLimit` mid-block — so once the
JIT is wired into execution over real (marker-bearing) blocks, the marker must
decrement fuel and write PC, or a block that should stop on the fuel limit
would run to completion and a fault's PC would be stale. The gate blocks here
carry no markers, so the straight-line ops stay correct without it; handling
it belongs to the execution-wiring step, tracked there.

## Update: the host ABI grew a `raise`, and coverage is now complete

The memory ABI generalised into a four-import **host ABI**, declared together
whenever a block needs the host (`block_needs_host`): `load` (0), `store` (1),
`fault` (2), and now `raise` (3) — `raise(code, value, index)` sets a given
exception (re-canonicalised through `from_u32`, as the interpreter does) and
records where the block stopped. `run` follows the imports at function 4.

`raise` lets three more things translate without ever letting wasm trap:

- **The four integer divisions.** The interpreter raises `DivisionException`
  and writes nothing on a zero divisor (and, for the signed ops, on the
  `INT_MIN / -1` overflow). The emitted code guards exactly those inputs — the
  only ones wasm's `div`/`rem` would trap on — and raises before dividing;
  otherwise it divides on the safe path. Sub-word operands are sign- or
  zero-extended so a 1/2-byte divide is exact, and the overflow guard compares
  against the varnode-width `INT_MIN`, not the wasm type's.
- **`Exception`** (dynamic code/value from its inputs) and **`Invalid`**
  (InvalidInstruction), each a `raise` + stop.

With the conversions (`IntToFloat`/`UintToFloat` via the signed/unsigned wasm
converts, `FloatToFloat` via promote/demote/identity, `FloatToInt` via the
*saturating* truncation that matches Rust's saturating `as`), the translator
now covers every p-code op whose semantics wasm can reproduce. The gate holds
the division/exception ops through the same two-VM host harness as memory
(comparing registers, resume index, and `cpu.exception`), and the conversions
through the register harness with the NaN-aware float comparison. Three canaries
confirm the new arms: mis-coding the raised exception reddens the division-fault
cases on the exception, swapping div for rem reddens the value, and an unsigned
convert on a signed input reddens the sign.

### What still bails, and why it is correct

- **`FloatRound`.** Round-half-away-from-zero (Rust `f64::round`) has no wasm
  op — `nearest` is half-to-even — and the naive `trunc(x + copysign(0.5, x))`
  is wrong at the tie just below ½. It stays interpreted.
- **Non-computational ops.** `Branch`/`PcodeBranch`/`PcodeLabel` are resolved
  into block structure at lift time and never appear in an executed stream (the
  interpreter itself panics on them); `MultiEqual`/`Indirect` are SSA
  placeholders, never executed; `PcodeOp`/`Hook`/`HookIf`/`Arg`/`TracerLoad`/
  `TracerStore` are escapes into arbitrary host state and instrumentation, not
  pure computation. A block containing any of them bails whole, which is
  correct — the interpreter is the floor.
- **Widths with no wasm type:** the 80-bit x87 extended format (size 10) and
  the size-2 half floats, and `FloatToInt` into an i16.
