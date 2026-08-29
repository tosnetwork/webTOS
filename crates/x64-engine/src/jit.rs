//! p-code block → WebAssembly translation (the JIT's front half).
//!
//! A hot block is translated once to a wasm function that executes its p-code
//! straight through, and the browser runs that function at near-native speed
//! instead of the interpreter simulating each op. This module emits the wasm;
//! the host instantiates it and dispatches to it. `feasibility/` measured why
//! this is worth doing (~490x on the table for compute) and proved the
//! mechanism; this is the real thing.
//!
//! ## The register space
//!
//! p-code operates on varnodes — typed storage slots with an id, an offset,
//! and a size. The interpreter keeps them in one flat byte array (`Regs`,
//! 0x20000 bytes). The emitted wasm imports that array as linear memory and
//! reads and writes the *same* byte offsets, so JIT'd code and interpreted
//! code see the same registers. [`var_offset`] must therefore match the
//! interpreter's `Regs::var_offset` exactly, which the gate checks by
//! comparing the whole register space bit for bit after a block runs both
//! ways.
//!
//! ## Tiered by construction
//!
//! [`translate_block`] returns `None` the moment it meets an op it cannot
//! translate. That block stays interpreted; only fully-translatable blocks
//! become wasm. The JIT never has to be complete to be correct — it only ever
//! compiles what it fully understands, and the interpreter is the floor.
//!
//! ## For the op handlers
//!
//! Each p-code op is handled in [`translate_instruction`]. A handler emits
//! wasm that computes the op's result and stores it to the output varnode,
//! using the shared helpers below so every handler addresses the register
//! space the same way:
//!
//! - [`emit_store_addr`] pushes the output's byte address (wasm `store` wants
//!   the address underneath the value, so this comes first).
//! - [`emit_load`] pushes an operand — a varnode loaded from memory, or a
//!   constant — as the wasm type for its size.
//! - [`emit_store`] stores the value on top of the stack to the output.
//!
//! So a binary op is: store-addr(out), load(a), load(b), the wasm op,
//! store(out). `IntAdd` below is the worked reference; the rest follow it.

use icicle_cpu::lifter::{Block as LiftedBlock, BlockExit, Target};
use pcode::{Op, Value, VarNode};
use wasm_encoder::{
    BlockType, CodeSection, EntityType, ExportKind, ExportSection, Function, FunctionSection,
    Instruction, MemArg, MemoryType, Module, TypeSection, ValType,
};

/// Function indices of the four host imports, in the order [`translate_block`]
/// declares them. Imported functions occupy the low end of the function index
/// space, so these are fixed; the emitted `run` function follows them. They are
/// declared only for a block that needs the host (see [`block_needs_host`]); a
/// self-contained register-to-register block imports none of them and its `run`
/// is function 0.
///
/// `load`/`store` reach guest memory; `fault` records where a memory access
/// stopped the block (the memory import has already set the exception);
/// `raise` sets a given exception and records where the block stopped, for the
/// division guards and the `Exception`/`Invalid` ops.
const IMPORT_LOAD: u32 = 0;
const IMPORT_STORE: u32 = 1;
const IMPORT_FAULT: u32 = 2;
const IMPORT_RAISE: u32 = 3;

/// Local index of `run`'s single parameter, `regs_base` — the byte offset of
/// the register file within the host's memory, added to every varnode address
/// (see [`reg_arg`]). Passing it as a parameter (rather than an imported global)
/// lets the host supply the base per call, so the same compiled block works
/// wherever the register file sits — offset 0 for a dedicated register memory,
/// or the live pointer into the engine's memory in the browser.
const REGS_BASE_PARAM: u32 = 0;

/// Local index of `run`'s second parameter, `tlb_base` — the byte offset of
/// icicle's live translation cache ([`icicle_mem::tlb::TranslationCache`])
/// within the host's memory. The inline softmmu fast path reads the TLB and the
/// resolved guest page directly from that memory, calling the host only on a
/// miss or a fault. Passing it as a parameter (like `regs_base`) lets the host
/// supply the live pointer per call — `cpu.mem.tlb_ptr()` in the browser, where
/// the TLB and the guest pages both live in the same linear memory the compiled
/// block imports as `env.regs`.
const TLB_BASE_PARAM: u32 = 1;

/// The scratch locals the inline memory fast path uses, by index. They differ
/// between a per-block `run` (params `regs_base`, `tlb_base`) and a region `run`
/// (params `regs_base`, `tlb_base`, `max_iters`, then the iteration counter), so
/// the layout is passed in rather than hard-coded.
///
/// - `addr`: the guest address, zero-extended to `i64`.
/// - `entry`: the byte offset of the addressed TLB entry (`i32`).
/// - `data`: the host linear-memory offset of the addressed guest byte (`i32`).
/// - `wide`: the first of [`WIDE_SCRATCH`] consecutive `i64` locals the 128-bit
///   cross-lane ops (multiply, shifts) use to snapshot their operands before
///   they overwrite an output that aliases an input.
#[derive(Clone, Copy)]
pub struct FastLocals {
    addr: u32,
    entry: u32,
    data: u32,
    wide: u32,
}

/// The count of `i64` scratch locals reserved for the 128-bit cross-lane ops:
/// four to snapshot the two operands' lanes, plus one temporary.
const WIDE_SCRATCH: u32 = 6;

/// Fast-path scratch locals for a per-block `run` — params are `regs_base` (0)
/// and `tlb_base` (1), so the scratch locals begin at 2, and the wide scratch
/// after the three memory-fast-path locals.
const BLOCK_FAST: FastLocals = FastLocals {
    addr: 2,
    entry: 3,
    data: 4,
    wide: 5,
};

/// Fast-path scratch locals for a region `run` — params are `regs_base` (0),
/// `tlb_base` (1), `max_iters` (2), then the iteration counter local (3), so the
/// scratch locals begin at 4.
const REGION_FAST: FastLocals = FastLocals {
    addr: 4,
    entry: 5,
    data: 6,
    wide: 7,
};

const TRACE_STATE_LOCAL: u32 = 4;
const TRACE_FAST: FastLocals = FastLocals {
    addr: 5,
    entry: 6,
    data: 7,
    wide: 8,
};
pub(crate) const TRACE_RESUME_BITS: u32 = 8;

/// The mask of permission bits the fast path requires per byte: `READ | INIT`
/// for a load, `WRITE | INIT` for a store (`READ=0b10`, `WRITE=0b100`,
/// `INIT=0b1`). Requiring `INIT` too is what keeps the fast path correct whether
/// or not `track_uninitialized` is on — an uninitialized or unmapped-perm byte
/// fails the mask and falls to the host, which raises the exact exception. INIT
/// is only ever set on a byte that also went through a MAP-setting path, so the
/// mask needs no separate MAP check.
const PERM_READ_INIT: u64 = 0b0000_0011;
const PERM_WRITE_INIT: u64 = 0b0000_0101;

/// The TLB tag mask, `addr & 0xFFFF_FFFF_FFC0_0000` — the address with its low
/// 22 bits (page offset + TLB index) cleared. Mirrors
/// `icicle_mem::tlb::TLBEntry::tag_mask()`.
const TLB_TAG_MASK: i64 = 0xFFFF_FFFF_FFC0_0000u64 as i64;

/// Byte offset of the WRITE half of the translation cache within it: the READ
/// array is `[TLBEntry; 1024]` at offset 0, so the WRITE array begins at
/// `1024 * 16`. Mirrors the `#[repr(C)]` layout of
/// `icicle_mem::tlb::TranslationCache`.
const TLB_WRITE_ARRAY_OFFSET: u64 = 1024 * 16;

/// Byte offset of the permission bytes within a `PageData` (`#[repr(C)]`:
/// `data: [u8; 4096]` then `perm: [u8; 4096]`).
const PAGE_PERM_OFFSET: u64 = 4096;

/// The per-byte permission mask replicated across the `n` low bytes of a word,
/// for the single masked compare the fast path uses (e.g. `n = 8` → the mask in
/// every byte of an `i64`).
fn perm_mask_word(byte: u64, n: u8) -> u64 {
    let mut m = 0u64;
    for i in 0..n {
        m |= byte << (8 * i as u64);
    }
    m
}

/// The exception codes the division guards raise. These mirror
/// `icicle_cpu::ExceptionCode` discriminants; the `raise` import re-canonicalises
/// through `from_u32`, so a value here need only match the interpreter's.
const EXC_DIVISION: u32 = 0x0103;
const EXC_INVALID_INSTRUCTION: u32 = 0x1001;

/// Whether the block needs the host imports.
///
/// Guest memory (`Load`/`Store`), the divisions (which raise on a zero or
/// `INT_MIN/-1` divisor), and the `Exception`/`Invalid` ops all cross into the
/// host. A block with none of them stays a self-contained register-to-register
/// function with no imported calls.
pub fn block_needs_host(block: &pcode::Block) -> bool {
    block.instructions.iter().any(|inst| {
        matches!(
            inst.op,
            Op::Load(_)
                | Op::Store(_)
                | Op::IntDiv
                | Op::IntSignedDiv
                | Op::IntRem
                | Op::IntSignedRem
                | Op::Exception
                | Op::Invalid
        )
    })
}

/// The register space is 0x20000 bytes — two 64 KiB wasm pages.
pub const REG_SPACE_BYTES: u32 = 0x20000;
const REG_PAGES: u64 = (REG_SPACE_BYTES as u64).div_ceil(65536);

/// The byte offset of a varnode in the register space.
///
/// This mirrors `icicle_cpu::Regs::var_offset` exactly. It has to: the wasm
/// this module emits reads and writes these offsets, and the interpreter reads
/// and writes the same array. The gate compares the whole space after a block
/// runs both ways, so a mismatch here fails loudly rather than silently
/// corrupting a register.
pub fn var_offset(var: VarNode) -> u32 {
    const REG_OFFSET: i32 = 0x200 * 16;
    (REG_OFFSET + var.id as i32 * 16 + var.offset as i32) as u32
}

/// The wasm value type a varnode of this byte size is computed in.
///
/// 1, 2, and 4-byte varnodes are computed in `i32`; 8-byte in `i64`. Wider
/// sizes — 10-byte x87, 16-byte SIMD — have no direct wasm type and are not
/// handled here; a block using them bails to the interpreter.
pub fn wasm_ty(size: u8) -> Option<ValType> {
    match size {
        1 | 2 | 4 => Some(ValType::I32),
        8 => Some(ValType::I64),
        _ => None,
    }
}

/// Whether the two operands and the output of a same-width op are all a size
/// this JIT handles. A convenience for handlers whose inputs and output share
/// a width (the arithmetic and logic ops).
pub fn same_width(out: VarNode, a: Value, b: Value) -> Option<u8> {
    let size = out.size;
    wasm_ty(size)?;
    if a.size() != size || b.size() != size {
        return None;
    }
    Some(size)
}

/// A `MemArg` addressing a varnode: the register-space byte offset goes in the
/// static offset immediate, and the dynamic address is `regs_base` (pushed by
/// [`emit_regs_base`]), so the effective address is `regs_base + var_offset`.
/// That is what lets a block run against the register file wherever it sits in
/// the host's memory — offset 0 in the gate's dedicated memory, or deep inside
/// the engine's memory in the browser.
fn reg_arg(var: VarNode) -> MemArg {
    MemArg {
        offset: var_offset(var) as u64,
        align: 0,
        memory_index: 0,
    }
}

/// Pushes `regs_base`, the dynamic part of every register address. It is `run`'s
/// parameter, so the host supplies the base on each call (0 for a dedicated
/// register memory).
fn emit_regs_base(f: &mut Function) {
    f.instruction(&Instruction::LocalGet(REGS_BASE_PARAM));
}

/// Pushes the base address for a following `store` to a varnode. Wasm `store`
/// consumes `[address, value]`, address first, which is why this is emitted
/// before the value is computed; the varnode's offset rides the store's
/// immediate (see [`reg_arg`]).
pub fn emit_store_addr(f: &mut Function) {
    emit_regs_base(f);
}

/// Pushes an operand onto the wasm stack in the wasm type for `size`.
///
/// A constant becomes an `iN.const`. A varnode becomes a load from the
/// register space at its offset — zero-extended for the sub-word sizes, since
/// a varnode's bytes are its value and the high bits of the wasm register are
/// not part of it. Returns `None` for a size this JIT does not handle.
pub fn emit_load(f: &mut Function, value: Value, size: u8) -> Option<()> {
    let ty = wasm_ty(size)?;
    match value {
        Value::Const(c, _) => match ty {
            ValType::I32 => f.instruction(&Instruction::I32Const(c as i32)),
            ValType::I64 => f.instruction(&Instruction::I64Const(c as i64)),
            _ => return None,
        },
        Value::Var(var) => {
            emit_regs_base(f);
            let arg = reg_arg(var);
            match size {
                1 => f.instruction(&Instruction::I32Load8U(arg)),
                2 => f.instruction(&Instruction::I32Load16U(arg)),
                4 => f.instruction(&Instruction::I32Load(arg)),
                8 => f.instruction(&Instruction::I64Load(arg)),
                _ => return None,
            }
        }
    };
    Some(())
}

/// Stores the value on top of the stack to `out`, given the base address
/// `emit_store_addr` pushed underneath it. Sub-word sizes store only their low
/// bytes; the varnode's offset rides the store's immediate.
pub fn emit_store(f: &mut Function, out: VarNode) -> Option<()> {
    wasm_ty(out.size)?;
    let arg = reg_arg(out);
    match out.size {
        1 => f.instruction(&Instruction::I32Store8(arg)),
        2 => f.instruction(&Instruction::I32Store16(arg)),
        4 => f.instruction(&Instruction::I32Store(arg)),
        8 => f.instruction(&Instruction::I64Store(arg)),
        _ => return None,
    };
    Some(())
}

/// Pushes an operand as an `i64`, zero-extended from its own width. A memory
/// address or a store value is passed to the host import this way: loaded at
/// its size, then widened, so the import receives a full 64-bit value. Returns
/// `None` for a size this JIT does not handle.
fn emit_zext_i64(f: &mut Function, v: Value) -> Option<()> {
    let size = v.size();
    emit_load(f, v, size)?;
    if !matches!(wasm_ty(size)?, ValType::I64) {
        f.instruction(&Instruction::I64ExtendI32U);
    }
    Some(())
}

/// Pushes an operand as an `i32`, matching the interpreter's `zxt::<u32>()`: the
/// value zero-extended, or — for an 8-byte operand — truncated to its low 32
/// bits. Used for an exception code.
fn emit_zext_i32(f: &mut Function, v: Value) -> Option<()> {
    let size = v.size();
    emit_load(f, v, size)?;
    if matches!(wasm_ty(size)?, ValType::I64) {
        f.instruction(&Instruction::I32WrapI64);
    }
    Some(())
}

/// Pushes an operand sign-extended to its wasm type: `i32` for widths 1/2/4
/// (with an explicit sign extension for the sub-word widths, since [`emit_load`]
/// zero-extends), `i64` for width 8. The signed divisions and the signed
/// int-to-float conversion read their operands this way.
fn emit_signed(f: &mut Function, v: Value, size: u8) -> Option<()> {
    match size {
        1 => {
            emit_load(f, v, 1)?;
            f.instruction(&Instruction::I32Extend8S);
        }
        2 => {
            emit_load(f, v, 2)?;
            f.instruction(&Instruction::I32Extend16S);
        }
        4 => emit_load(f, v, 4)?,
        8 => emit_load(f, v, 8)?,
        _ => return None,
    }
    Some(())
}

/// Pushes an operand sign-extended to a full `i64`, whatever its byte width.
/// Used for the low lane of a 128-bit sign-extend and its sign fill.
fn emit_sext_i64(f: &mut Function, v: Value, size: u8) -> Option<()> {
    emit_signed(f, v, size)?;
    if size < 8 {
        f.instruction(&Instruction::I64ExtendI32S);
    }
    Some(())
}

/// The two 8-byte lane offsets of a 128-bit varnode. The move/widen/logic ops
/// that dominate vectorised code are per-lane, so they are emitted as two
/// independent `i64` operations on the low and high halves — no wasm SIMD. The
/// register file lays a 16-byte varnode out contiguously, so lane `off` is the
/// varnode sliced at `off` for 8 bytes, matching the interpreter, which reads
/// and writes a 128-bit value as its two little-endian `u64` halves.
const WIDE_LANES: [u8; 2] = [0, 8];

/// out = a `<op>` b, a 128-bit same-width binary op done as two `i64` lanes.
/// `op` emits the `i64` instruction once the two lane operands are on the stack.
fn emit_wide_binop(
    f: &mut Function,
    out: VarNode,
    a: Value,
    b: Value,
    op: impl Fn(&mut Function),
) -> Option<()> {
    if out.size != 16 || a.size() != 16 || b.size() != 16 {
        return None;
    }
    for off in WIDE_LANES {
        emit_store_addr(f);
        emit_load(f, a.slice(off, 8), 8)?;
        emit_load(f, b.slice(off, 8), 8)?;
        op(f);
        emit_store(f, out.slice(off, 8))?;
    }
    Some(())
}

/// out = `<op>` a, a 128-bit unary op (a move, or a not) done as two `i64`
/// lanes. `op` transforms each loaded lane before it is stored; for a plain
/// copy it does nothing.
fn emit_wide_unary(
    f: &mut Function,
    out: VarNode,
    a: Value,
    op: impl Fn(&mut Function),
) -> Option<()> {
    if out.size != 16 || a.size() != 16 {
        return None;
    }
    for off in WIDE_LANES {
        emit_store_addr(f);
        emit_load(f, a.slice(off, 8), 8)?;
        op(f);
        emit_store(f, out.slice(off, 8))?;
    }
    Some(())
}

/// Low 32 bits, as an `i64` mask.
const LO32_MASK: i64 = 0xffff_ffff;

/// Pushes the high 64 bits of the 128-bit product `x * y` (both `u64`, read from
/// the given locals) onto the stack. Wasm has no widening multiply, so this is
/// the schoolbook sum over 32-bit halves: with `xl/xh`, `yl/yh` the low/high
/// halves, the cross term `(xl*yl >> 32) + (xl*yh & lo) + (xh*yl & lo)` carries
/// into `xh*yh + (xl*yh >> 32) + (xh*yl >> 32)`. `t` is a scratch `i64` local.
fn emit_mulhi_u64(f: &mut Function, x: u32, y: u32, t: u32) {
    let get = |f: &mut Function, l: u32| {
        f.instruction(&Instruction::LocalGet(l));
    };
    let lo = |f: &mut Function| {
        f.instruction(&Instruction::I64Const(LO32_MASK));
        f.instruction(&Instruction::I64And);
    };
    let hi = |f: &mut Function| {
        f.instruction(&Instruction::I64Const(32));
        f.instruction(&Instruction::I64ShrU);
    };
    // cross = (xl*yl >> 32) + (xl*yh & lo) + (xh*yl & lo)
    get(f, x);
    lo(f);
    get(f, y);
    lo(f);
    f.instruction(&Instruction::I64Mul);
    hi(f);
    get(f, x);
    lo(f);
    get(f, y);
    hi(f);
    f.instruction(&Instruction::I64Mul);
    lo(f);
    f.instruction(&Instruction::I64Add);
    get(f, x);
    hi(f);
    get(f, y);
    lo(f);
    f.instruction(&Instruction::I64Mul);
    lo(f);
    f.instruction(&Instruction::I64Add);
    f.instruction(&Instruction::LocalSet(t));
    // mulhi = xh*yh + (xl*yh >> 32) + (xh*yl >> 32) + (cross >> 32)
    get(f, x);
    hi(f);
    get(f, y);
    hi(f);
    f.instruction(&Instruction::I64Mul);
    get(f, x);
    lo(f);
    get(f, y);
    hi(f);
    f.instruction(&Instruction::I64Mul);
    hi(f);
    f.instruction(&Instruction::I64Add);
    get(f, x);
    hi(f);
    get(f, y);
    lo(f);
    f.instruction(&Instruction::I64Mul);
    hi(f);
    f.instruction(&Instruction::I64Add);
    get(f, t);
    hi(f);
    f.instruction(&Instruction::I64Add);
}

/// out = (a * b) mod 2^128, a 128-bit multiply as two `i64` lanes:
///   lo = a_lo * b_lo,
///   hi = mulhi_u64(a_lo, b_lo) + a_lo*b_hi + a_hi*b_lo   (all mod 2^64).
/// Operands are snapshotted into locals first so an output that aliases an input
/// is safe.
fn emit_wide_mul(
    f: &mut Function,
    out: VarNode,
    a: Value,
    b: Value,
    fast: FastLocals,
) -> Option<()> {
    if out.size != 16 || a.size() != 16 || b.size() != 16 {
        return None;
    }
    let (al, ah, bl, bh, t) = (
        fast.wide,
        fast.wide + 1,
        fast.wide + 2,
        fast.wide + 3,
        fast.wide + 4,
    );
    emit_load(f, a.slice(0, 8), 8)?;
    f.instruction(&Instruction::LocalSet(al));
    emit_load(f, a.slice(8, 8), 8)?;
    f.instruction(&Instruction::LocalSet(ah));
    emit_load(f, b.slice(0, 8), 8)?;
    f.instruction(&Instruction::LocalSet(bl));
    emit_load(f, b.slice(8, 8), 8)?;
    f.instruction(&Instruction::LocalSet(bh));

    // Low lane: a_lo * b_lo (wraps).
    emit_store_addr(f);
    f.instruction(&Instruction::LocalGet(al));
    f.instruction(&Instruction::LocalGet(bl));
    f.instruction(&Instruction::I64Mul);
    emit_store(f, out.slice(0, 8))?;

    // High lane: mulhi(a_lo, b_lo) + a_lo*b_hi + a_hi*b_lo.
    emit_store_addr(f);
    emit_mulhi_u64(f, al, bl, t);
    f.instruction(&Instruction::LocalGet(al));
    f.instruction(&Instruction::LocalGet(bh));
    f.instruction(&Instruction::I64Mul);
    f.instruction(&Instruction::I64Add);
    f.instruction(&Instruction::LocalGet(ah));
    f.instruction(&Instruction::LocalGet(bl));
    f.instruction(&Instruction::I64Mul);
    f.instruction(&Instruction::I64Add);
    emit_store(f, out.slice(8, 8))
}

/// Which 128-bit shift to emit.
#[derive(Clone, Copy)]
enum WideShift {
    /// `IntLeft`: `y >= 128 ? 0 : x << y`.
    Left,
    /// `IntRight`: `y >= 128 ? 0 : x >>u y` (logical).
    RightU,
    /// `IntSignedRight`: `x >>u min(y, 127)`. At width 16 the interpreter reads
    /// `x` as `sxt()` (a no-op — the value is already 128 bits) into a `u128` and
    /// shifts it *logically*, so this is a logical right shift with the count
    /// clamped to 127; the clamp is the only difference from `RightU`.
    RightS,
}

/// out = a `<shift>` b, a 128-bit shift by the count in `b`, as two `i64` lanes.
///
/// A lane shift by `s = shift & 63` moves bits within a lane; the bits crossing
/// the lane boundary are `lo >> (64 - s)` (left) or `hi << (64 - s)` (right),
/// which we form as `(v >> 1) >> (63 - s)` / `(v << 1) << (63 - s)` so `s == 0`
/// gives 0 rather than tripping wasm's shift-count masking. A shift of 64..127
/// moves one lane whole into the other; 128+ (logical only) is zero; the
/// arithmetic shift clamps the count to 127 and fills with the sign bit. All
/// cases are selected on the count at run time.
fn emit_wide_shift(
    f: &mut Function,
    out: VarNode,
    a: Value,
    b: Value,
    mode: WideShift,
    fast: FastLocals,
) -> Option<()> {
    if out.size != 16 || a.size() != 16 {
        return None;
    }
    wasm_ty(b.size())?;
    let (al, ah, s, y, tmp) = (
        fast.wide,
        fast.wide + 1,
        fast.wide + 2,
        fast.wide + 3,
        fast.wide + 4,
    );
    let get = |f: &mut Function, l: u32| {
        f.instruction(&Instruction::LocalGet(l));
    };
    let konst = |f: &mut Function, c: i64| {
        f.instruction(&Instruction::I64Const(c));
    };

    // Snapshot the operand lanes (the output may alias the input).
    emit_load(f, a.slice(0, 8), 8)?;
    f.instruction(&Instruction::LocalSet(al));
    emit_load(f, a.slice(8, 8), 8)?;
    f.instruction(&Instruction::LocalSet(ah));

    // y = the count as i64; the arithmetic shift clamps it to 127.
    emit_shift_count_u32(f, b)?;
    f.instruction(&Instruction::I64ExtendI32U);
    if let WideShift::RightS = mode {
        f.instruction(&Instruction::LocalSet(tmp));
        get(f, tmp);
        konst(f, 127);
        get(f, tmp);
        konst(f, 127);
        f.instruction(&Instruction::I64LtU);
        f.instruction(&Instruction::Select);
    }
    f.instruction(&Instruction::LocalSet(y));
    // s = y & 63.
    get(f, y);
    konst(f, 63);
    f.instruction(&Instruction::I64And);
    f.instruction(&Instruction::LocalSet(s));

    // `lo_lt64 = (a_lo >>u s) | (a_hi << (64 - s))`, the low lane for a right
    // shift by s < 64; `hi_lt64 = (a_hi << s) | (a_lo >> (64 - s))`, the high
    // lane for a left shift by s < 64. Emitted where needed below.
    let carry_up = |f: &mut Function| {
        // a_lo >> (64 - s) as (a_lo >> 1) >> (63 - s).
        get(f, al);
        konst(f, 1);
        f.instruction(&Instruction::I64ShrU);
        konst(f, 63);
        get(f, s);
        f.instruction(&Instruction::I64Sub);
        f.instruction(&Instruction::I64ShrU);
    };
    let carry_down = |f: &mut Function| {
        // a_hi << (64 - s) as (a_hi << 1) << (63 - s).
        get(f, ah);
        konst(f, 1);
        f.instruction(&Instruction::I64Shl);
        konst(f, 63);
        get(f, s);
        f.instruction(&Instruction::I64Sub);
        f.instruction(&Instruction::I64Shl);
    };

    match mode {
        WideShift::Left => {
            // Low lane: (y < 64) ? a_lo << s : 0.
            emit_store_addr(f);
            get(f, al);
            get(f, s);
            f.instruction(&Instruction::I64Shl);
            konst(f, 0);
            get(f, y);
            konst(f, 64);
            f.instruction(&Instruction::I64LtU);
            f.instruction(&Instruction::Select);
            emit_store(f, out.slice(0, 8))?;
            // High lane: (y<64) ? (a_hi<<s)|carry_up : (y<128) ? a_lo<<s : 0.
            emit_store_addr(f);
            get(f, ah);
            get(f, s);
            f.instruction(&Instruction::I64Shl);
            carry_up(f);
            f.instruction(&Instruction::I64Or);
            get(f, al);
            get(f, s);
            f.instruction(&Instruction::I64Shl);
            konst(f, 0);
            get(f, y);
            konst(f, 128);
            f.instruction(&Instruction::I64LtU);
            f.instruction(&Instruction::Select);
            get(f, y);
            konst(f, 64);
            f.instruction(&Instruction::I64LtU);
            f.instruction(&Instruction::Select);
            emit_store(f, out.slice(8, 8))
        }
        // Logical right shift. `RightS` reaches here too: its count was clamped
        // to 127 above, so the `y >= 128 ? 0` case simply never fires.
        WideShift::RightU | WideShift::RightS => {
            // High lane: (y < 64) ? a_hi >>u s : 0.
            emit_store_addr(f);
            get(f, ah);
            get(f, s);
            f.instruction(&Instruction::I64ShrU);
            konst(f, 0);
            get(f, y);
            konst(f, 64);
            f.instruction(&Instruction::I64LtU);
            f.instruction(&Instruction::Select);
            emit_store(f, out.slice(8, 8))?;
            // Low lane: (y<64) ? (a_lo>>u s)|carry_down : (y<128) ? a_hi>>u s : 0.
            emit_store_addr(f);
            get(f, al);
            get(f, s);
            f.instruction(&Instruction::I64ShrU);
            carry_down(f);
            f.instruction(&Instruction::I64Or);
            get(f, ah);
            get(f, s);
            f.instruction(&Instruction::I64ShrU);
            konst(f, 0);
            get(f, y);
            konst(f, 128);
            f.instruction(&Instruction::I64LtU);
            f.instruction(&Instruction::Select);
            get(f, y);
            konst(f, 64);
            f.instruction(&Instruction::I64LtU);
            f.instruction(&Instruction::Select);
            emit_store(f, out.slice(0, 8))
        }
    }
}

/// The `iN.eqz` for an operand of this width (i64 at width 8, i32 otherwise).
fn int_eqz(size: u8) -> Instruction<'static> {
    match size {
        8 => Instruction::I64Eqz,
        _ => Instruction::I32Eqz,
    }
}

/// The `iN.eq` for an operand of this width.
fn int_eq(size: u8) -> Instruction<'static> {
    match size {
        8 => Instruction::I64Eq,
        _ => Instruction::I32Eq,
    }
}

/// An `iN.const` of this width. Sub-word widths compute in i32, so their
/// constants are i32; width 8 is i64.
fn int_const(size: u8, value: i64) -> Instruction<'static> {
    match size {
        8 => Instruction::I64Const(value),
        _ => Instruction::I32Const(value as i32),
    }
}

/// The signed minimum at a varnode width, as an i64 (widened for the i32 path,
/// where it still compares equal after sign extension).
fn int_min(size: u8) -> i64 {
    match size {
        1 => i8::MIN as i64,
        2 => i16::MIN as i64,
        4 => i32::MIN as i64,
        _ => i64::MIN,
    }
}

/// Emits the fault check that follows a memory import: the import left an `ok`
/// flag on the stack, and if it is zero the access faulted. On a fault the
/// block stops exactly where the interpreter would — it reports the faulting
/// instruction's index (the import has already set the exception) and returns,
/// leaving every earlier instruction's effects in place and this one's undone.
///
/// `region_iter` distinguishes the two kinds of `run` this feeds. For a
/// per-block `run() -> ()` it is `None` and the emitter returns nothing. For a
/// region `run(..) -> i64` it is `Some(iter_local)`: the completed-iteration
/// counter is pushed just before the `return`, so a mid-loop fault reports how
/// many whole iterations retired (the fault happens before `iter` is
/// incremented, so `iter` is exactly the count of fully-completed iterations).
fn emit_fault_check(f: &mut Function, index: u32, region_iter: Option<u32>) {
    f.instruction(&Instruction::I32Eqz);
    f.instruction(&Instruction::If(BlockType::Empty));
    f.instruction(&Instruction::I32Const(index as i32));
    f.instruction(&Instruction::Call(IMPORT_FAULT));
    if let Some(iter) = region_iter {
        f.instruction(&Instruction::LocalGet(iter));
    }
    f.instruction(&Instruction::Return);
    f.instruction(&Instruction::End);
}

/// Emits a raise of a constant-coded exception and a `return`: sets
/// `code`/`value` and records that the block stopped at `index`, exactly as the
/// interpreter does when `exception()` is followed by the block driver seeing a
/// pending exception. Used by the division guards and `Invalid`.
///
/// `region_iter` works as in [`emit_fault_check`]: `Some(iter_local)` pushes the
/// completed-iteration count before the `return` of a region `run`.
fn emit_raise_const(f: &mut Function, code: u32, value: i64, index: u32, region_iter: Option<u32>) {
    f.instruction(&Instruction::I32Const(code as i32));
    f.instruction(&Instruction::I64Const(value));
    f.instruction(&Instruction::I32Const(index as i32));
    f.instruction(&Instruction::Call(IMPORT_RAISE));
    if let Some(iter) = region_iter {
        f.instruction(&Instruction::LocalGet(iter));
    }
    f.instruction(&Instruction::Return);
}

/// Pushes a float operand: the varnode's (or constant's) bits loaded as an
/// integer, then reinterpreted as `f32`/`f64`. Going through [`emit_load`] means
/// a constant immediate and a register both work, and the register bytes are
/// the IEEE bits already, so the reinterpret is free. Only the two wasm float
/// widths, 4 and 8, are handled.
fn emit_float_operand(f: &mut Function, v: Value, size: u8) -> Option<()> {
    match size {
        4 => {
            emit_load(f, v, 4)?;
            f.instruction(&Instruction::F32ReinterpretI32);
        }
        8 => {
            emit_load(f, v, 8)?;
            f.instruction(&Instruction::F64ReinterpretI64);
        }
        _ => return None,
    }
    Some(())
}

/// Stores the float on top of the stack to `out`, given the base address
/// underneath it, writing its IEEE bits. The output width picks `f32`/`f64`.
fn emit_float_store(f: &mut Function, out: VarNode) -> Option<()> {
    let arg = reg_arg(out);
    match out.size {
        4 => f.instruction(&Instruction::F32Store(arg)),
        8 => f.instruction(&Instruction::F64Store(arg)),
        _ => return None,
    };
    Some(())
}

/// A `MemArg` for a raw byte-offset access into the host memory (not the
/// register file): `offset` rides the load/store immediate, natural alignment
/// unconstrained (`align = 0`) since guest pages and the TLB are read at
/// whatever alignment the address lands on.
fn raw_arg(offset: u64) -> MemArg {
    MemArg {
        offset,
        align: 0,
        memory_index: 0,
    }
}

/// Emits the inline softmmu fast path for a scalar guest Load or Store of `n` ∈
/// {1,2,4,8} bytes, with the existing host call as the fall-back `slow` path.
///
/// The common case — a resident, permissioned, single-page access — is done
/// entirely in wasm by reading icicle's live TLB (at `tlb_base`) and the
/// resolved guest page directly from the host memory, so no host callback and no
/// wasm→JS→wasm crossing happens. Anything the fast path is not certain it can
/// handle falls to `slow` (the unchanged `env.load`/`env.store` call), which is
/// always correct and also fills the TLB for next time. The guards, in order:
///
/// 1. Cross-page: `(addr & 0xfff) + n > 4096` ⇒ slow. A single TLB entry and a
///    single page only cover one page; a straddling access needs two.
/// 2. Tag: the TLB entry at `index(addr)` (the READ array for a load, the WRITE
///    array for a store) must have `tag == addr & TLB_TAG_MASK`. An invalid
///    entry holds `u64::MAX`, whose low 22 bits are set, so it never matches a
///    real address's tag — a flushed (invalidated) entry always falls to slow,
///    which is what makes reading the *live* TLB coherent after a remap.
/// 3. Permissions: every one of the `n` permission bytes must have `READ|INIT`
///    (load) / `WRITE|INIT` (store) set, tested as one masked compare.
///
/// When all guards pass, the `n` bytes are moved directly between the guest page
/// and the register file (load) or the register/const operand and the guest page
/// (store), little-endian, matching the host callback's effect exactly. No fault
/// is possible on the taken fast path.
///
/// The address is resolved once into `fast.addr`; `slow` re-derives it the same
/// way the pre-fast-path code did, so the fall-back is byte-identical to the
/// proven host path. The whole thing is wrapped in two nested empty blocks so a
/// guard `br_if`s to the slow path (depth 0) and the taken fast path `br`s past
/// it (depth 1).
#[allow(clippy::too_many_arguments)]
fn emit_mem_fastpath(
    f: &mut Function,
    is_store: bool,
    addr: Value,
    n: u8,
    load_out: Option<VarNode>,
    store_val: Option<Value>,
    fast: FastLocals,
    slow: impl FnOnce(&mut Function) -> Option<()>,
) -> Option<()> {
    if !matches!(n, 1 | 2 | 4 | 8) {
        return None;
    }
    let tlb_off = if is_store { TLB_WRITE_ARRAY_OFFSET } else { 0 };
    let perm_byte = if is_store {
        PERM_WRITE_INIT
    } else {
        PERM_READ_INIT
    };
    let mask = perm_mask_word(perm_byte, n);

    // block $done { block $slow { <fast attempt>; br $done } ; <slow> }
    f.instruction(&Instruction::Block(BlockType::Empty)); // $done
    f.instruction(&Instruction::Block(BlockType::Empty)); // $slow

    // fast.addr = zext_i64(addr)
    emit_zext_i64(f, addr)?;
    f.instruction(&Instruction::LocalSet(fast.addr));

    // Cross-page guard: (addr & 0xfff) + n > 4096 -> $slow
    f.instruction(&Instruction::LocalGet(fast.addr));
    f.instruction(&Instruction::I32WrapI64);
    f.instruction(&Instruction::I32Const(0xfff));
    f.instruction(&Instruction::I32And);
    f.instruction(&Instruction::I32Const(n as i32));
    f.instruction(&Instruction::I32Add);
    f.instruction(&Instruction::I32Const(4096));
    f.instruction(&Instruction::I32GtU);
    f.instruction(&Instruction::BrIf(0));

    // fast.entry = tlb_base + index(addr) * 16 ; index = (addr >> 12) & 0x3ff
    f.instruction(&Instruction::LocalGet(TLB_BASE_PARAM));
    f.instruction(&Instruction::LocalGet(fast.addr));
    f.instruction(&Instruction::I64Const(12));
    f.instruction(&Instruction::I64ShrU);
    f.instruction(&Instruction::I32WrapI64);
    f.instruction(&Instruction::I32Const(0x3ff));
    f.instruction(&Instruction::I32And);
    f.instruction(&Instruction::I32Const(16));
    f.instruction(&Instruction::I32Mul);
    f.instruction(&Instruction::I32Add);
    f.instruction(&Instruction::LocalSet(fast.entry));

    // Tag guard: entry.tag (at tlb_off) != (addr & TLB_TAG_MASK) -> $slow
    f.instruction(&Instruction::LocalGet(fast.entry));
    f.instruction(&Instruction::I64Load(raw_arg(tlb_off)));
    f.instruction(&Instruction::LocalGet(fast.addr));
    f.instruction(&Instruction::I64Const(TLB_TAG_MASK));
    f.instruction(&Instruction::I64And);
    f.instruction(&Instruction::I64Ne);
    f.instruction(&Instruction::BrIf(0));

    // fast.data = wrap_i64(addr + entry.guest_to_host_offset)  (the data byte).
    // guest_to_host_offset is the second u64 of the entry, at tlb_off + 8.
    f.instruction(&Instruction::LocalGet(fast.addr));
    f.instruction(&Instruction::LocalGet(fast.entry));
    f.instruction(&Instruction::I64Load(raw_arg(tlb_off + 8)));
    f.instruction(&Instruction::I64Add);
    f.instruction(&Instruction::I32WrapI64);
    f.instruction(&Instruction::LocalSet(fast.data));

    // Permission guard: the n perm bytes at fast.data + PAGE_PERM_OFFSET must
    // all carry the required bits. One masked compare: (perm & mask) != mask.
    f.instruction(&Instruction::LocalGet(fast.data));
    match n {
        1 => f.instruction(&Instruction::I32Load8U(raw_arg(PAGE_PERM_OFFSET))),
        2 => f.instruction(&Instruction::I32Load16U(raw_arg(PAGE_PERM_OFFSET))),
        4 => f.instruction(&Instruction::I32Load(raw_arg(PAGE_PERM_OFFSET))),
        _ => f.instruction(&Instruction::I64Load(raw_arg(PAGE_PERM_OFFSET))),
    };
    if n == 8 {
        f.instruction(&Instruction::I64Const(mask as i64));
        f.instruction(&Instruction::I64And);
        f.instruction(&Instruction::I64Const(mask as i64));
        f.instruction(&Instruction::I64Ne);
    } else {
        f.instruction(&Instruction::I32Const(mask as i32));
        f.instruction(&Instruction::I32And);
        f.instruction(&Instruction::I32Const(mask as i32));
        f.instruction(&Instruction::I32Ne);
    }
    f.instruction(&Instruction::BrIf(0));

    // Fast path taken: move the n bytes directly, no fault possible.
    if is_store {
        let val = store_val?;
        f.instruction(&Instruction::LocalGet(fast.data));
        emit_load(f, val, n)?;
        match n {
            1 => f.instruction(&Instruction::I32Store8(raw_arg(0))),
            2 => f.instruction(&Instruction::I32Store16(raw_arg(0))),
            4 => f.instruction(&Instruction::I32Store(raw_arg(0))),
            _ => f.instruction(&Instruction::I64Store(raw_arg(0))),
        };
    } else {
        let out = load_out?;
        // Store into the register file: [regs_base, value] then iN.store.
        f.instruction(&Instruction::LocalGet(REGS_BASE_PARAM));
        f.instruction(&Instruction::LocalGet(fast.data));
        match n {
            1 => f.instruction(&Instruction::I32Load8U(raw_arg(0))),
            2 => f.instruction(&Instruction::I32Load16U(raw_arg(0))),
            4 => f.instruction(&Instruction::I32Load(raw_arg(0))),
            _ => f.instruction(&Instruction::I64Load(raw_arg(0))),
        };
        match n {
            1 => f.instruction(&Instruction::I32Store8(reg_arg(out))),
            2 => f.instruction(&Instruction::I32Store16(reg_arg(out))),
            4 => f.instruction(&Instruction::I32Store(reg_arg(out))),
            _ => f.instruction(&Instruction::I64Store(reg_arg(out))),
        };
    }
    f.instruction(&Instruction::Br(1)); // skip the slow path

    f.instruction(&Instruction::End); // end $slow

    // Slow path: the unchanged host call (which also fills the TLB) plus its
    // fault check.
    slow(f)?;

    f.instruction(&Instruction::End); // end $done
    Some(())
}

/// Translates one p-code instruction into wasm appended to `f`, or returns
/// `None` if the op (or a size it uses) is not handled — which bails the whole
/// block to the interpreter.
///
/// This is the dispatch the op handlers plug into. `IntAdd` is the worked
/// reference; each remaining integer op is one arm here, mostly a single wasm
/// binary instruction between the shared load/store helpers.
///
/// `region_iter` selects how a host op stops the emitted `run` on a fault: it is
/// `None` in a per-block `run() -> ()` (the fault emitters return nothing), and
/// `Some(iter_local)` in a region `run(..) -> i64` (they push the
/// completed-iteration counter before returning it). It threads straight through
/// to [`emit_fault_check`]/[`emit_raise_const`] and the inline `Exception` stop.
/// Pushes the p-code shift count as an `i32` holding the interpreter's
/// `read_dynamic(b).zxt::<u32>()`: the count zero-extended, and — for an 8-byte
/// count — truncated to its low 32 bits (`i32.wrap_i64`), which is what a
/// `u128 -> u32` zxt does. Used for the width comparison, and (after widening)
/// as the shift amount itself. A count wider than 8 bytes bails.
fn emit_shift_count_u32(f: &mut Function, b: Value) -> Option<()> {
    match b.size() {
        1 | 2 | 4 => emit_load(f, b, b.size())?,
        8 => {
            emit_load(f, b, 8)?;
            f.instruction(&Instruction::I32WrapI64);
        }
        _ => return None,
    }
    Some(())
}

pub fn translate_instruction(
    f: &mut Function,
    inst: &pcode::Instruction,
    index: u32,
    has_host: bool,
    region_iter: Option<u32>,
    fast: FastLocals,
) -> Option<()> {
    let out = inst.output;
    let [a, b] = inst.inputs.get();

    match inst.op {
        // Metadata: marks an instruction boundary. No machine effect; the
        // interpreter uses it for the instruction count, which the block
        // driver accounts for separately. Emit nothing.
        Op::InstructionMarker => Some(()),

        // The reference. out = a + b, all one width.
        //   store-addr(out); load(a); load(b); iN.add; store(out)
        Op::IntAdd => {
            let size = same_width(out, a, b)?;
            emit_store_addr(f);
            emit_load(f, a, size)?;
            emit_load(f, b, size)?;
            match size {
                8 => f.instruction(&Instruction::I64Add),
                _ => f.instruction(&Instruction::I32Add),
            };
            emit_store(f, out)
        }

        // out = a - b, all one width. Wasm sub wraps, matching wrapping_sub.
        Op::IntSub => {
            let size = same_width(out, a, b)?;
            emit_store_addr(f);
            emit_load(f, a, size)?;
            emit_load(f, b, size)?;
            match size {
                8 => f.instruction(&Instruction::I64Sub),
                _ => f.instruction(&Instruction::I32Sub),
            };
            emit_store(f, out)
        }

        // out = a ^ b, all one width.
        Op::IntXor => {
            if out.size == 16 {
                return emit_wide_binop(f, out, a, b, |f| {
                    f.instruction(&Instruction::I64Xor);
                });
            }
            let size = same_width(out, a, b)?;
            emit_store_addr(f);
            emit_load(f, a, size)?;
            emit_load(f, b, size)?;
            match size {
                8 => f.instruction(&Instruction::I64Xor),
                _ => f.instruction(&Instruction::I32Xor),
            };
            emit_store(f, out)
        }

        // out = a | b, all one width.
        Op::IntOr => {
            if out.size == 16 {
                return emit_wide_binop(f, out, a, b, |f| {
                    f.instruction(&Instruction::I64Or);
                });
            }
            let size = same_width(out, a, b)?;
            emit_store_addr(f);
            emit_load(f, a, size)?;
            emit_load(f, b, size)?;
            match size {
                8 => f.instruction(&Instruction::I64Or),
                _ => f.instruction(&Instruction::I32Or),
            };
            emit_store(f, out)
        }

        // out = a & b, all one width.
        Op::IntAnd => {
            if out.size == 16 {
                return emit_wide_binop(f, out, a, b, |f| {
                    f.instruction(&Instruction::I64And);
                });
            }
            let size = same_width(out, a, b)?;
            emit_store_addr(f);
            emit_load(f, a, size)?;
            emit_load(f, b, size)?;
            match size {
                8 => f.instruction(&Instruction::I64And),
                _ => f.instruction(&Instruction::I32And),
            };
            emit_store(f, out)
        }

        // out = a * b, all one width. Wasm mul wraps, matching wrapping_mul; the
        // store keeps only the low `size` bytes.
        Op::IntMul => {
            if out.size == 16 {
                return emit_wide_mul(f, out, a, b, fast);
            }
            let size = same_width(out, a, b)?;
            emit_store_addr(f);
            emit_load(f, a, size)?;
            emit_load(f, b, size)?;
            match size {
                8 => f.instruction(&Instruction::I64Mul),
                _ => f.instruction(&Instruction::I32Mul),
            };
            emit_store(f, out)
        }

        // out = !a. Wasm has no bitwise-not, so xor with all-ones. The store
        // truncates, so setting the high wasm bits for a sub-word `a` is
        // harmless.
        Op::IntNot => {
            if out.size == 16 {
                return emit_wide_unary(f, out, a, |f| {
                    f.instruction(&Instruction::I64Const(-1));
                    f.instruction(&Instruction::I64Xor);
                });
            }
            let size = out.size;
            let ty = wasm_ty(size)?;
            if a.size() != size {
                return None;
            }
            emit_store_addr(f);
            emit_load(f, a, size)?;
            match ty {
                ValType::I64 => {
                    f.instruction(&Instruction::I64Const(-1));
                    f.instruction(&Instruction::I64Xor);
                }
                _ => {
                    f.instruction(&Instruction::I32Const(-1));
                    f.instruction(&Instruction::I32Xor);
                }
            };
            emit_store(f, out)
        }

        // out = -a = 0 - a, matching wrapping_neg. Wasm sub wraps; the store
        // keeps only the low `size` bytes.
        Op::IntNegate => {
            let size = out.size;
            let ty = wasm_ty(size)?;
            if a.size() != size {
                return None;
            }
            emit_store_addr(f);
            match ty {
                ValType::I64 => f.instruction(&Instruction::I64Const(0)),
                _ => f.instruction(&Instruction::I32Const(0)),
            };
            emit_load(f, a, size)?;
            match ty {
                ValType::I64 => f.instruction(&Instruction::I64Sub),
                _ => f.instruction(&Instruction::I32Sub),
            };
            emit_store(f, out)
        }

        // Logical shifts. The interpreter computes `if y >= width { 0 } else
        // { x <shift> y }`, where `width` is the *output* bit width and `y` is
        // the count. Wasm shifts instead mask the count modulo the wasm type
        // width (32 or 64), so an out-of-range count would wrap rather than
        // zero. We reproduce the interpreter by computing the in-range shift and
        // selecting zero when `y >= width`. `a` must match the output width; the
        // count may be any handled size.
        Op::IntLeft | Op::IntRight => {
            if out.size == 16 {
                let mode = match inst.op {
                    Op::IntLeft => WideShift::Left,
                    _ => WideShift::RightU,
                };
                return emit_wide_shift(f, out, a, b, mode, fast);
            }
            let size = out.size;
            let ty = wasm_ty(size)?;
            if a.size() != size {
                return None;
            }
            wasm_ty(b.size())?;
            let width = size as i32 * 8;

            emit_store_addr(f);
            // In-range result: x << y (or x >> y). The count is `y` in the value
            // type; masking is a no-op here because `select` discards this value
            // unless y < width.
            emit_load(f, a, size)?;
            emit_shift_count_u32(f, b)?;
            let left = matches!(inst.op, Op::IntLeft);
            match (left, ty) {
                (true, ValType::I64) => {
                    f.instruction(&Instruction::I64ExtendI32U);
                    f.instruction(&Instruction::I64Shl);
                }
                (false, ValType::I64) => {
                    f.instruction(&Instruction::I64ExtendI32U);
                    f.instruction(&Instruction::I64ShrU);
                }
                (true, _) => {
                    f.instruction(&Instruction::I32Shl);
                }
                (false, _) => {
                    f.instruction(&Instruction::I32ShrU);
                }
            }
            // Zero alternative.
            match ty {
                ValType::I64 => f.instruction(&Instruction::I64Const(0)),
                _ => f.instruction(&Instruction::I32Const(0)),
            };
            // Condition: y < width. select keeps the shifted value when true,
            // zero otherwise.
            emit_shift_count_u32(f, b)?;
            f.instruction(&Instruction::I32Const(width));
            f.instruction(&Instruction::I32LtU);
            f.instruction(&Instruction::Select);
            emit_store(f, out)
        }

        // Arithmetic (sign-propagating) shift right. The interpreter clamps the
        // count to `width - 1` and sign-extends `a` before shifting, so an
        // out-of-range count fills the result with the sign bit. Wasm `shr_s`
        // sign-propagates but masks the count, so we clamp explicitly and
        // sign-extend a sub-word `a` up to its wasm type first.
        Op::IntSignedRight => {
            if out.size == 16 {
                return emit_wide_shift(f, out, a, b, WideShift::RightS, fast);
            }
            let size = out.size;
            let ty = wasm_ty(size)?;
            if a.size() != size {
                return None;
            }
            wasm_ty(b.size())?;
            let clamp = size as i32 * 8 - 1;

            emit_store_addr(f);
            // Value, sign-extended to the wasm type (4/8-byte loads already fill
            // the type; 1/2-byte loads are zero-extended and need fixing up).
            emit_load(f, a, size)?;
            match size {
                1 => {
                    f.instruction(&Instruction::I32Extend8S);
                }
                2 => {
                    f.instruction(&Instruction::I32Extend16S);
                }
                _ => {}
            }
            // Count = min(y, width - 1) as i32: select y when y < width-1 else
            // width-1.
            emit_shift_count_u32(f, b)?;
            f.instruction(&Instruction::I32Const(clamp));
            emit_shift_count_u32(f, b)?;
            f.instruction(&Instruction::I32Const(clamp));
            f.instruction(&Instruction::I32LtU);
            f.instruction(&Instruction::Select);
            match ty {
                ValType::I64 => {
                    f.instruction(&Instruction::I64ExtendI32U);
                    f.instruction(&Instruction::I64ShrS);
                }
                _ => {
                    f.instruction(&Instruction::I32ShrS);
                }
            }
            emit_store(f, out)
        }

        // Rotates. The interpreter rotates at the value's native width, so wasm
        // `rotl`/`rotr` only match for the 4- and 8-byte types (whose native
        // width equals the wasm type width); 1- and 2-byte rotates would use the
        // wrong modulus and bail.
        Op::IntRotateLeft | Op::IntRotateRight => {
            let size = same_width(out, a, b)?;
            let left = matches!(inst.op, Op::IntRotateLeft);
            let op = match (left, size) {
                (true, 4) => Instruction::I32Rotl,
                (true, 8) => Instruction::I64Rotl,
                (false, 4) => Instruction::I32Rotr,
                (false, 8) => Instruction::I64Rotr,
                _ => return None,
            };
            emit_store_addr(f);
            emit_load(f, a, size)?;
            emit_load(f, b, size)?;
            f.instruction(&op);
            emit_store(f, out)
        }

        // --- Comparisons -----------------------------------------------------
        //
        // Both inputs are `size` bytes and equal width; the output is exactly
        // one byte holding 0 or 1 (the interpreter writes `<Op>::eval(a, b) as
        // u8`). A wasm `iN.*` comparison yields an `i32` 0/1 regardless of
        // operand width — including the `i64.*` forms — so the result stores
        // straight to the 1-byte output via `emit_store` (`i32.store8`).
        //
        // Equality and the unsigned relations compare the operands as loaded:
        // `emit_load` zero-extends the sub-word sizes, and unsigned/equality
        // comparisons of equally zero-extended values agree with the sub-word
        // comparison. The signed relations must instead sign-extend each
        // sub-word operand into its wasm register first, since a byte 0xff is
        // -1 as `i8` but 255 as a zero-extended `i32`.
        Op::IntEqual => {
            let size = a.size();
            if b.size() != size || out.size != 1 {
                return None;
            }
            wasm_ty(size)?;
            emit_store_addr(f);
            emit_load(f, a, size)?;
            emit_load(f, b, size)?;
            match size {
                8 => f.instruction(&Instruction::I64Eq),
                _ => f.instruction(&Instruction::I32Eq),
            };
            emit_store(f, out)
        }

        Op::IntNotEqual => {
            let size = a.size();
            if b.size() != size || out.size != 1 {
                return None;
            }
            wasm_ty(size)?;
            emit_store_addr(f);
            emit_load(f, a, size)?;
            emit_load(f, b, size)?;
            match size {
                8 => f.instruction(&Instruction::I64Ne),
                _ => f.instruction(&Instruction::I32Ne),
            };
            emit_store(f, out)
        }

        Op::IntLess => {
            let size = a.size();
            if b.size() != size || out.size != 1 {
                return None;
            }
            wasm_ty(size)?;
            emit_store_addr(f);
            emit_load(f, a, size)?;
            emit_load(f, b, size)?;
            match size {
                8 => f.instruction(&Instruction::I64LtU),
                _ => f.instruction(&Instruction::I32LtU),
            };
            emit_store(f, out)
        }

        Op::IntLessEqual => {
            let size = a.size();
            if b.size() != size || out.size != 1 {
                return None;
            }
            wasm_ty(size)?;
            emit_store_addr(f);
            emit_load(f, a, size)?;
            emit_load(f, b, size)?;
            match size {
                8 => f.instruction(&Instruction::I64LeU),
                _ => f.instruction(&Instruction::I32LeU),
            };
            emit_store(f, out)
        }

        Op::IntSignedLess => {
            let size = a.size();
            if b.size() != size || out.size != 1 {
                return None;
            }
            wasm_ty(size)?;
            emit_store_addr(f);
            emit_load(f, a, size)?;
            match size {
                1 => f.instruction(&Instruction::I32Extend8S),
                2 => f.instruction(&Instruction::I32Extend16S),
                _ => f,
            };
            emit_load(f, b, size)?;
            match size {
                1 => f.instruction(&Instruction::I32Extend8S),
                2 => f.instruction(&Instruction::I32Extend16S),
                _ => f,
            };
            match size {
                8 => f.instruction(&Instruction::I64LtS),
                _ => f.instruction(&Instruction::I32LtS),
            };
            emit_store(f, out)
        }

        Op::IntSignedLessEqual => {
            let size = a.size();
            if b.size() != size || out.size != 1 {
                return None;
            }
            wasm_ty(size)?;
            emit_store_addr(f);
            emit_load(f, a, size)?;
            match size {
                1 => f.instruction(&Instruction::I32Extend8S),
                2 => f.instruction(&Instruction::I32Extend16S),
                _ => f,
            };
            emit_load(f, b, size)?;
            match size {
                1 => f.instruction(&Instruction::I32Extend8S),
                2 => f.instruction(&Instruction::I32Extend16S),
                _ => f,
            };
            match size {
                8 => f.instruction(&Instruction::I64LeS),
                _ => f.instruction(&Instruction::I32LeS),
            };
            emit_store(f, out)
        }

        // --- Booleans --------------------------------------------------------
        //
        // 1-byte operands and a 1-byte output. The interpreter evaluates each
        // as a bitwise op on the raw bytes followed by `!= 0` (e.g. BoolAnd is
        // `a & b != 0`), so the emitted code mirrors that exactly: the bitwise
        // wasm op, then `i32.ne 0` to normalise to 0/1. Doing the `!= 0` rather
        // than storing the raw bitwise result matters when an operand is not a
        // strict 0/1 boolean. BoolNot is `a == 0`, which is `i32.eqz`.
        Op::BoolAnd => {
            if a.size() != 1 || b.size() != 1 || out.size != 1 {
                return None;
            }
            emit_store_addr(f);
            emit_load(f, a, 1)?;
            emit_load(f, b, 1)?;
            f.instruction(&Instruction::I32And);
            f.instruction(&Instruction::I32Const(0));
            f.instruction(&Instruction::I32Ne);
            emit_store(f, out)
        }

        Op::BoolOr => {
            if a.size() != 1 || b.size() != 1 || out.size != 1 {
                return None;
            }
            emit_store_addr(f);
            emit_load(f, a, 1)?;
            emit_load(f, b, 1)?;
            f.instruction(&Instruction::I32Or);
            f.instruction(&Instruction::I32Const(0));
            f.instruction(&Instruction::I32Ne);
            emit_store(f, out)
        }

        Op::BoolXor => {
            if a.size() != 1 || b.size() != 1 || out.size != 1 {
                return None;
            }
            emit_store_addr(f);
            emit_load(f, a, 1)?;
            emit_load(f, b, 1)?;
            f.instruction(&Instruction::I32Xor);
            f.instruction(&Instruction::I32Const(0));
            f.instruction(&Instruction::I32Ne);
            emit_store(f, out)
        }

        Op::BoolNot => {
            if a.size() != 1 || out.size != 1 {
                return None;
            }
            emit_store_addr(f);
            emit_load(f, a, 1)?;
            f.instruction(&Instruction::I32Eqz);
            emit_store(f, out)
        }

        // --- Move / resize ---------------------------------------------------

        // out = a, same width. A load then a store of the same size.
        Op::Copy => {
            if out.size == 16 {
                return emit_wide_unary(f, out, a, |_| {});
            }
            let size = out.size;
            if a.size() != size {
                return None;
            }
            wasm_ty(size)?;
            emit_store_addr(f);
            emit_load(f, a, size)?;
            emit_store(f, out)
        }

        // out = zero-extend(a), out wider than a. `emit_load` already
        // zero-extends a sub-word load into its `i32`, so for an `i32` output
        // the value stores directly (the high output bytes are already zero).
        // Only widening the `i32`-typed load to an `i64` output needs an
        // explicit `i64.extend_i32_u`.
        Op::ZeroExtend => {
            // 128-bit output: the low lane is the zero-extended input, the high
            // lane is zero (the SSE "move-and-zero-upper" idiom).
            if out.size == 16 && matches!(a.size(), 1 | 2 | 4 | 8) {
                emit_store_addr(f);
                emit_zext_i64(f, a)?;
                emit_store(f, out.slice(0, 8))?;
                emit_store_addr(f);
                f.instruction(&Instruction::I64Const(0));
                emit_store(f, out.slice(8, 8))?;
                return Some(());
            }
            let in_size = a.size();
            let out_size = out.size;
            let in_ty = wasm_ty(in_size)?;
            let out_ty = wasm_ty(out_size)?;
            if out_size < in_size {
                return None;
            }
            emit_store_addr(f);
            emit_load(f, a, in_size)?;
            match (in_ty, out_ty) {
                (ValType::I32, ValType::I32) => {}
                (ValType::I32, ValType::I64) => {
                    f.instruction(&Instruction::I64ExtendI32U);
                }
                (ValType::I64, ValType::I64) => {}
                _ => return None,
            }
            emit_store(f, out)
        }

        // out = sign-extend(a), out strictly wider than a. The sub-word load is
        // zero-extended, so sign-extension is explicit: `i32.extend8_s` /
        // `i32.extend16_s` fill the sign within an `i32`, and `i64.extend_i32_s`
        // widens a sign-filled `i32` to an `i64` output.
        Op::SignExtend => {
            // 128-bit output: the low lane is the sign-extended input as an
            // i64, the high lane is that i64's sign (an arithmetic shift by 63,
            // giving all-zero or all-one bytes).
            if out.size == 16 && matches!(a.size(), 1 | 2 | 4 | 8) {
                emit_store_addr(f);
                emit_sext_i64(f, a, a.size())?;
                emit_store(f, out.slice(0, 8))?;
                emit_store_addr(f);
                emit_sext_i64(f, a, a.size())?;
                f.instruction(&Instruction::I64Const(63));
                f.instruction(&Instruction::I64ShrS);
                emit_store(f, out.slice(8, 8))?;
                return Some(());
            }
            let in_size = a.size();
            let out_size = out.size;
            wasm_ty(in_size)?;
            wasm_ty(out_size)?;
            if out_size <= in_size {
                return None;
            }
            emit_store_addr(f);
            emit_load(f, a, in_size)?;
            match out_size {
                1 | 2 | 4 => match in_size {
                    1 => {
                        f.instruction(&Instruction::I32Extend8S);
                    }
                    2 => {
                        f.instruction(&Instruction::I32Extend16S);
                    }
                    _ => return None,
                },
                8 => match in_size {
                    1 => {
                        f.instruction(&Instruction::I32Extend8S);
                        f.instruction(&Instruction::I64ExtendI32S);
                    }
                    2 => {
                        f.instruction(&Instruction::I32Extend16S);
                        f.instruction(&Instruction::I64ExtendI32S);
                    }
                    4 => {
                        f.instruction(&Instruction::I64ExtendI32S);
                    }
                    _ => return None,
                },
                _ => return None,
            }
            emit_store(f, out)
        }

        // out = a's bytes starting at byte `offset`, truncated to out.size
        // (the interpreter reaches this as a copy of `a.slice(offset,
        // out.size)`). Load a whole, shift right by offset*8, then the store
        // truncates to the output width. Only the in-bounds case is emitted;
        // a slice reaching past `a` (which would zero-fill high bytes) bails.
        Op::Subpiece(offset) => {
            let in_size = a.size();
            let out_size = out.size;
            let in_ty = wasm_ty(in_size)?;
            wasm_ty(out_size)?;
            let offset = offset as u64;
            if offset + out_size as u64 > in_size as u64 {
                return None;
            }
            emit_store_addr(f);
            emit_load(f, a, in_size)?;
            if offset > 0 {
                match in_ty {
                    ValType::I64 => {
                        f.instruction(&Instruction::I64Const((offset * 8) as i64));
                        f.instruction(&Instruction::I64ShrU);
                    }
                    _ => {
                        f.instruction(&Instruction::I32Const((offset * 8) as i32));
                        f.instruction(&Instruction::I32ShrU);
                    }
                }
            }
            // Reconcile the input's wasm type with the output store's type: an
            // i64 value feeding an i32-typed (<=4 byte) output must be wrapped.
            if in_ty == ValType::I64 && out_size <= 4 {
                f.instruction(&Instruction::I32WrapI64);
            }
            emit_store(f, out)
        }

        // Flags. Each writes a 1-byte boolean to `out` from two W-wide inputs
        // (interpreter: `cmp_op!`). Output must be size 1; inputs share width W
        // in {1,2,4,8}. Size 16 bails via `wasm_ty`.
        //
        // IntCarry: unsigned add carry-out, `a.checked_add(b).is_none()`, i.e.
        // the width-W sum wraps. Compute (a+b), mask to W bits (for the sub-word
        // i32 sizes; identity at 4 and unneeded at 8), then `sum <u a`.
        Op::IntCarry => {
            if out.size != 1 || b.size() != a.size() {
                return None;
            }
            let size = a.size();
            let ty = wasm_ty(size)?;
            emit_store_addr(f);
            emit_load(f, a, size)?;
            emit_load(f, b, size)?;
            match ty {
                ValType::I64 => {
                    f.instruction(&Instruction::I64Add);
                    emit_load(f, a, size)?;
                    f.instruction(&Instruction::I64LtU);
                }
                _ => {
                    f.instruction(&Instruction::I32Add);
                    if size != 4 {
                        let mask = ((1u32 << (size as u32 * 8)) - 1) as i32;
                        f.instruction(&Instruction::I32Const(mask));
                        f.instruction(&Instruction::I32And);
                    }
                    emit_load(f, a, size)?;
                    f.instruction(&Instruction::I32LtU);
                }
            }
            emit_store(f, out)
        }

        // IntSignedCarry: signed add overflow,
        // `a.to_signed().checked_add(b.to_signed()).is_none()`. Overflow iff the
        // operands share a sign and the sum's sign differs:
        //   ((a ^ sum) & (b ^ sum) & signbit) != 0,  sum = a + b (width W).
        // The final `& signbit` isolates bit W*8-1, so `sum` needs no masking —
        // higher stray bits from the i32 add fall outside the mask.
        Op::IntSignedCarry => {
            if out.size != 1 || b.size() != a.size() {
                return None;
            }
            let size = a.size();
            let ty = wasm_ty(size)?;
            let is64 = matches!(ty, ValType::I64);
            emit_store_addr(f);
            // a ^ sum
            emit_load(f, a, size)?;
            emit_load(f, a, size)?;
            emit_load(f, b, size)?;
            f.instruction(if is64 {
                &Instruction::I64Add
            } else {
                &Instruction::I32Add
            });
            f.instruction(if is64 {
                &Instruction::I64Xor
            } else {
                &Instruction::I32Xor
            });
            // b ^ sum
            emit_load(f, b, size)?;
            emit_load(f, a, size)?;
            emit_load(f, b, size)?;
            f.instruction(if is64 {
                &Instruction::I64Add
            } else {
                &Instruction::I32Add
            });
            f.instruction(if is64 {
                &Instruction::I64Xor
            } else {
                &Instruction::I32Xor
            });
            f.instruction(if is64 {
                &Instruction::I64And
            } else {
                &Instruction::I32And
            });
            if is64 {
                f.instruction(&Instruction::I64Const(1i64 << 63));
                f.instruction(&Instruction::I64And);
                f.instruction(&Instruction::I64Const(0));
                f.instruction(&Instruction::I64Ne);
            } else {
                let signbit = (1u32 << (size as u32 * 8 - 1)) as i32;
                f.instruction(&Instruction::I32Const(signbit));
                f.instruction(&Instruction::I32And);
                f.instruction(&Instruction::I32Const(0));
                f.instruction(&Instruction::I32Ne);
            }
            emit_store(f, out)
        }

        // IntSignedBorrow: signed subtract overflow,
        // `a.to_signed().checked_sub(b.to_signed()).is_none()`. Overflow iff the
        // operands differ in sign and the difference's sign differs from a's:
        //   ((a ^ b) & (a ^ diff) & signbit) != 0,  diff = a - b (width W).
        Op::IntSignedBorrow => {
            if out.size != 1 || b.size() != a.size() {
                return None;
            }
            let size = a.size();
            let ty = wasm_ty(size)?;
            let is64 = matches!(ty, ValType::I64);
            emit_store_addr(f);
            // a ^ b
            emit_load(f, a, size)?;
            emit_load(f, b, size)?;
            f.instruction(if is64 {
                &Instruction::I64Xor
            } else {
                &Instruction::I32Xor
            });
            // a ^ diff
            emit_load(f, a, size)?;
            emit_load(f, a, size)?;
            emit_load(f, b, size)?;
            f.instruction(if is64 {
                &Instruction::I64Sub
            } else {
                &Instruction::I32Sub
            });
            f.instruction(if is64 {
                &Instruction::I64Xor
            } else {
                &Instruction::I32Xor
            });
            f.instruction(if is64 {
                &Instruction::I64And
            } else {
                &Instruction::I32And
            });
            if is64 {
                f.instruction(&Instruction::I64Const(1i64 << 63));
                f.instruction(&Instruction::I64And);
                f.instruction(&Instruction::I64Const(0));
                f.instruction(&Instruction::I64Ne);
            } else {
                let signbit = (1u32 << (size as u32 * 8 - 1)) as i32;
                f.instruction(&Instruction::I32Const(signbit));
                f.instruction(&Instruction::I32And);
                f.instruction(&Instruction::I32Const(0));
                f.instruction(&Instruction::I32Ne);
            }
            emit_store(f, out)
        }

        // Bit counts (interpreter: `write_trunc(out, read::<uW>(a).count_ones())`
        // / `.leading_zeros()`). The count is computed over the *input* width and
        // truncated into `out` (any handled size); the count is at most 64, so it
        // always fits in one byte and the truncation is lossless.
        //
        // IntCountOnes: popcount over the input width. Zero-extended sub-word
        // loads carry only their low bits, so a 32-bit popcnt is exact for sizes
        // 1/2/4; size 8 uses the 64-bit popcnt.
        Op::IntCountOnes => {
            if b.size() != 0 {
                return None;
            }
            let in_size = a.size();
            let in_ty = wasm_ty(in_size)?;
            let out_ty = wasm_ty(out.size)?;
            emit_store_addr(f);
            emit_load(f, a, in_size)?;
            match in_ty {
                ValType::I64 => {
                    f.instruction(&Instruction::I64Popcnt);
                    f.instruction(&Instruction::I32WrapI64);
                }
                _ => {
                    f.instruction(&Instruction::I32Popcnt);
                }
            }
            if matches!(out_ty, ValType::I64) {
                f.instruction(&Instruction::I64ExtendI32U);
            }
            emit_store(f, out)
        }

        // IntCountLeadingZeroes: leading zeros counted within the input width, not
        // in 32/64 bits. wasm `clz` counts in the full register width, so a
        // sub-word i32 load (zero-extended) over-counts by the padding bits —
        // subtract 32 - W*8 to recover the width-W count. Size 8's i64 clz already
        // counts in 64 bits, and size 4 needs no adjustment.
        Op::IntCountLeadingZeroes => {
            if b.size() != 0 {
                return None;
            }
            let in_size = a.size();
            let in_ty = wasm_ty(in_size)?;
            let out_ty = wasm_ty(out.size)?;
            emit_store_addr(f);
            emit_load(f, a, in_size)?;
            match in_ty {
                ValType::I64 => {
                    f.instruction(&Instruction::I64Clz);
                    f.instruction(&Instruction::I32WrapI64);
                }
                _ => {
                    f.instruction(&Instruction::I32Clz);
                    let adjust = 32 - (in_size as i32 * 8);
                    if adjust != 0 {
                        f.instruction(&Instruction::I32Const(adjust));
                        f.instruction(&Instruction::I32Sub);
                    }
                }
            }
            if matches!(out_ty, ValType::I64) {
                f.instruction(&Instruction::I64ExtendI32U);
            }
            emit_store(f, out)
        }

        // out = cond != 0 ? a : b, a conditional move. `cond` is the 1-byte
        // varnode named by the op; the interpreter reads it as u8 and copies
        // whichever input into `out`. Wasm's `select` is exactly this — it
        // pops [first, second, cond] and yields `first` when cond != 0 — so a
        // is pushed first (chosen when cond != 0), then b, then the loaded
        // condition byte. Inputs and output share `out`'s width.
        Op::Select(cond_var) => {
            let size = out.size;
            wasm_ty(size)?;
            if a.size() != size || b.size() != size {
                return None;
            }
            emit_store_addr(f);
            emit_load(f, a, size)?;
            emit_load(f, b, size)?;
            emit_load(f, Value::Var(VarNode::new(cond_var, 1)), 1)?;
            f.instruction(&Instruction::Select);
            emit_store(f, out)
        }

        // Float arithmetic: out = a <op> b, all one IEEE width (4 or 8). The
        // operands are reinterpreted from their bits, the wasm float op runs,
        // and the result's bits are stored. NaN payloads may differ between a
        // native interpreter build and wasm, but a wasm interpreter build (the
        // real target) computes these with the same wasm ops, so they agree
        // there; the gate compares NaN-aware for exactly this reason.
        Op::FloatAdd | Op::FloatSub | Op::FloatMul | Op::FloatDiv => {
            let size = out.size;
            if !matches!(size, 4 | 8) || a.size() != size || b.size() != size {
                return None;
            }
            emit_store_addr(f);
            emit_float_operand(f, a, size)?;
            emit_float_operand(f, b, size)?;
            f.instruction(&match (inst.op, size) {
                (Op::FloatAdd, 4) => Instruction::F32Add,
                (Op::FloatAdd, _) => Instruction::F64Add,
                (Op::FloatSub, 4) => Instruction::F32Sub,
                (Op::FloatSub, _) => Instruction::F64Sub,
                (Op::FloatMul, 4) => Instruction::F32Mul,
                (Op::FloatMul, _) => Instruction::F64Mul,
                (Op::FloatDiv, 4) => Instruction::F32Div,
                (_, _) => Instruction::F64Div,
            });
            emit_float_store(f, out)
        }

        // Float unary: out = <op> a, same IEEE width. FloatRound is *not* here
        // — the interpreter's round is half-away-from-zero (Rust `f64::round`)
        // while wasm `nearest` is half-to-even, so it bails to the interpreter.
        Op::FloatNegate | Op::FloatAbs | Op::FloatSqrt | Op::FloatCeil | Op::FloatFloor => {
            let size = out.size;
            if !matches!(size, 4 | 8) || a.size() != size {
                return None;
            }
            emit_store_addr(f);
            emit_float_operand(f, a, size)?;
            f.instruction(&match (inst.op, size) {
                (Op::FloatNegate, 4) => Instruction::F32Neg,
                (Op::FloatNegate, _) => Instruction::F64Neg,
                (Op::FloatAbs, 4) => Instruction::F32Abs,
                (Op::FloatAbs, _) => Instruction::F64Abs,
                (Op::FloatSqrt, 4) => Instruction::F32Sqrt,
                (Op::FloatSqrt, _) => Instruction::F64Sqrt,
                (Op::FloatCeil, 4) => Instruction::F32Ceil,
                (Op::FloatCeil, _) => Instruction::F64Ceil,
                (Op::FloatFloor, 4) => Instruction::F32Floor,
                (_, _) => Instruction::F64Floor,
            });
            emit_float_store(f, out)
        }

        // Float comparison: out (1 byte) = a <cmp> b. IEEE comparison already
        // yields the interpreter's booleans, including every NaN case (all
        // false but not-equal), so the i32 result stores straight into the
        // 1-byte output.
        Op::FloatEqual | Op::FloatNotEqual | Op::FloatLess | Op::FloatLessEqual => {
            let size = a.size();
            if out.size != 1 || !matches!(size, 4 | 8) || b.size() != size {
                return None;
            }
            emit_store_addr(f);
            emit_float_operand(f, a, size)?;
            emit_float_operand(f, b, size)?;
            f.instruction(&match (inst.op, size) {
                (Op::FloatEqual, 4) => Instruction::F32Eq,
                (Op::FloatEqual, _) => Instruction::F64Eq,
                (Op::FloatNotEqual, 4) => Instruction::F32Ne,
                (Op::FloatNotEqual, _) => Instruction::F64Ne,
                (Op::FloatLess, 4) => Instruction::F32Lt,
                (Op::FloatLess, _) => Instruction::F64Lt,
                (Op::FloatLessEqual, 4) => Instruction::F32Le,
                (_, _) => Instruction::F64Le,
            });
            emit_store(f, out)
        }

        // out (1 byte) = a is NaN. A value is NaN iff it does not equal itself,
        // so the operand is loaded twice and compared not-equal — matching the
        // interpreter's `is_nan`.
        Op::FloatIsNan => {
            let size = a.size();
            if out.size != 1 || !matches!(size, 4 | 8) {
                return None;
            }
            emit_store_addr(f);
            emit_float_operand(f, a, size)?;
            emit_float_operand(f, a, size)?;
            f.instruction(&match size {
                4 => Instruction::F32Ne,
                _ => Instruction::F64Ne,
            });
            emit_store(f, out)
        }

        // out = *addr, a guest-memory load. The address is input 0; the host
        // import reads `out.size` bytes through the real MMU and writes them
        // into the register space at `out`'s offset (little-endian makes that a
        // memcpy, identical to the interpreter's write). Only RAM and sizes
        // 1/2/4/8 are handled; anything else bails. On a fault the import has
        // set the exception and returns 0, and the block stops here.
        Op::Load(id) => {
            if !has_host || id != pcode::RAM_SPACE || !matches!(out.size, 1 | 2 | 4 | 8 | 16) {
                return None;
            }
            // A 128-bit load is two 8-byte loads, low half at addr and high at
            // addr + 8 — exactly how the interpreter reads a 16-byte value.
            if out.size == 16 {
                for off in WIDE_LANES {
                    emit_zext_i64(f, a)?;
                    if off != 0 {
                        f.instruction(&Instruction::I64Const(off as i64));
                        f.instruction(&Instruction::I64Add);
                    }
                    f.instruction(&Instruction::I32Const(var_offset(out.slice(off, 8)) as i32));
                    f.instruction(&Instruction::I32Const(8));
                    f.instruction(&Instruction::Call(IMPORT_LOAD));
                    emit_fault_check(f, index, region_iter);
                }
                return Some(());
            }
            // Inline softmmu fast path with the host `env.load` as the
            // fall-back; see [`emit_mem_fastpath`].
            emit_mem_fastpath(f, false, a, out.size, Some(out), None, fast, |f| {
                emit_zext_i64(f, a)?;
                f.instruction(&Instruction::I32Const(var_offset(out) as i32));
                f.instruction(&Instruction::I32Const(out.size as i32));
                f.instruction(&Instruction::Call(IMPORT_LOAD));
                emit_fault_check(f, index, region_iter);
                Some(())
            })
        }

        // *addr = value, a guest-memory store. Address is input 0, value is
        // input 1, and the store width is the value's size. The value is passed
        // to the import on the stack (not by register offset) so a constant
        // operand works. Same RAM-only, size-1/2/4/8, fault-stops-here contract
        // as Load.
        Op::Store(id) => {
            if !has_host || id != pcode::RAM_SPACE || !matches!(b.size(), 1 | 2 | 4 | 8 | 16) {
                return None;
            }
            // A 128-bit store is two 8-byte stores, low half at addr and high at
            // addr + 8 — matching the interpreter, so a fault on the high half
            // after the low half is written leaves the same partial effect.
            if b.size() == 16 {
                for off in WIDE_LANES {
                    emit_zext_i64(f, a)?;
                    if off != 0 {
                        f.instruction(&Instruction::I64Const(off as i64));
                        f.instruction(&Instruction::I64Add);
                    }
                    emit_zext_i64(f, b.slice(off, 8))?;
                    f.instruction(&Instruction::I32Const(8));
                    f.instruction(&Instruction::Call(IMPORT_STORE));
                    emit_fault_check(f, index, region_iter);
                }
                return Some(());
            }
            // Inline softmmu fast path with the host `env.store` as the
            // fall-back; see [`emit_mem_fastpath`].
            emit_mem_fastpath(f, true, a, b.size(), None, Some(b), fast, |f| {
                emit_zext_i64(f, a)?;
                emit_zext_i64(f, b)?;
                f.instruction(&Instruction::I32Const(b.size() as i32));
                f.instruction(&Instruction::Call(IMPORT_STORE));
                emit_fault_check(f, index, region_iter);
                Some(())
            })
        }

        // Unsigned division/remainder. The interpreter raises
        // DivisionException and writes nothing when the divisor is zero, so the
        // emitted code guards that first — the only input on which wasm's
        // div_u/rem_u would trap — then divides on the safe path.
        Op::IntDiv | Op::IntRem => {
            if !has_host {
                return None;
            }
            let size = same_width(out, a, b)?;
            emit_load(f, b, size)?;
            f.instruction(&int_eqz(size));
            f.instruction(&Instruction::If(BlockType::Empty));
            emit_raise_const(f, EXC_DIVISION, 0, index, region_iter);
            f.instruction(&Instruction::End);

            emit_store_addr(f);
            emit_load(f, a, size)?;
            emit_load(f, b, size)?;
            f.instruction(&match (inst.op, size) {
                (Op::IntDiv, 8) => Instruction::I64DivU,
                (Op::IntDiv, _) => Instruction::I32DivU,
                (Op::IntRem, 8) => Instruction::I64RemU,
                (_, _) => Instruction::I32RemU,
            });
            emit_store(f, out)
        }

        // Signed division/remainder. The interpreter raises on a zero divisor
        // and on the one signed overflow, INT_MIN / -1 (checked at the varnode
        // width, where wasm would either trap at 4/8 or silently not overflow
        // at 1/2). Both guards come first; operands are sign-extended so a
        // sub-word divide is exact.
        Op::IntSignedDiv | Op::IntSignedRem => {
            if !has_host {
                return None;
            }
            let size = same_width(out, a, b)?;
            let is64 = size == 8;

            // Guard 1: divisor is zero.
            emit_load(f, b, size)?;
            f.instruction(&int_eqz(size));
            f.instruction(&Instruction::If(BlockType::Empty));
            emit_raise_const(f, EXC_DIVISION, 0, index, region_iter);
            f.instruction(&Instruction::End);

            // Guard 2: dividend is the width's INT_MIN and divisor is -1.
            emit_signed(f, a, size)?;
            f.instruction(&int_const(size, int_min(size)));
            f.instruction(&int_eq(size));
            emit_signed(f, b, size)?;
            f.instruction(&int_const(size, -1));
            f.instruction(&int_eq(size));
            f.instruction(&Instruction::I32And);
            f.instruction(&Instruction::If(BlockType::Empty));
            emit_raise_const(f, EXC_DIVISION, 0, index, region_iter);
            f.instruction(&Instruction::End);

            emit_store_addr(f);
            emit_signed(f, a, size)?;
            emit_signed(f, b, size)?;
            f.instruction(&match (inst.op, is64) {
                (Op::IntSignedDiv, true) => Instruction::I64DivS,
                (Op::IntSignedDiv, false) => Instruction::I32DivS,
                (Op::IntSignedRem, true) => Instruction::I64RemS,
                (_, _) => Instruction::I32RemS,
            });
            emit_store(f, out)
        }

        // Signed integer -> float. The source is sign-extended to i32 (widths
        // 1/2/4) or i64 (width 8); the wasm convert rounds to nearest-even, as
        // the interpreter's `as f32`/`as f64` does. Output 10 (x87) bails.
        Op::IntToFloat => {
            let in_size = a.size();
            if !matches!(out.size, 4 | 8) || !matches!(in_size, 1 | 2 | 4 | 8) {
                return None;
            }
            emit_store_addr(f);
            emit_signed(f, a, in_size)?;
            f.instruction(&match (in_size == 8, out.size) {
                (false, 4) => Instruction::F32ConvertI32S,
                (false, _) => Instruction::F64ConvertI32S,
                (true, 4) => Instruction::F32ConvertI64S,
                (true, _) => Instruction::F64ConvertI64S,
            });
            emit_float_store(f, out)
        }

        // Unsigned integer -> float. Like IntToFloat but zero-extended (which
        // is what `emit_load` already produces).
        Op::UintToFloat => {
            let in_size = a.size();
            if !matches!(out.size, 4 | 8) || !matches!(in_size, 1 | 2 | 4 | 8) {
                return None;
            }
            emit_store_addr(f);
            emit_load(f, a, in_size)?;
            f.instruction(&match (in_size == 8, out.size) {
                (false, 4) => Instruction::F32ConvertI32U,
                (false, _) => Instruction::F64ConvertI32U,
                (true, 4) => Instruction::F32ConvertI64U,
                (true, _) => Instruction::F64ConvertI64U,
            });
            emit_float_store(f, out)
        }

        // float -> float between the two wasm widths. Promote (4->8) and demote
        // (8->4) map to the wasm ops; same-width is the interpreter's exact
        // bit round-trip, i.e. a plain copy of the bits. Any half (2) or x87
        // (10) width bails.
        Op::FloatToFloat => {
            let in_size = a.size();
            match (in_size, out.size) {
                (4, 4) | (8, 8) => {
                    emit_store_addr(f);
                    emit_load(f, a, in_size)?;
                    emit_store(f, out)
                }
                (4, 8) => {
                    emit_store_addr(f);
                    emit_float_operand(f, a, 4)?;
                    f.instruction(&Instruction::F64PromoteF32);
                    emit_float_store(f, out)
                }
                (8, 4) => {
                    emit_store_addr(f);
                    emit_float_operand(f, a, 8)?;
                    f.instruction(&Instruction::F32DemoteF64);
                    emit_float_store(f, out)
                }
                _ => None,
            }
        }

        // float -> signed integer, truncating toward zero and saturating (NaN
        // -> 0, out-of-range -> the clamped extreme). wasm's saturating
        // truncation matches the interpreter's saturating `as iN` exactly.
        // Output 2 (i16) has no wasm saturating form and bails.
        Op::FloatToInt => {
            let in_size = a.size();
            if !matches!(in_size, 4 | 8) || !matches!(out.size, 4 | 8) {
                return None;
            }
            emit_store_addr(f);
            emit_float_operand(f, a, in_size)?;
            f.instruction(&match (in_size, out.size) {
                (4, 4) => Instruction::I32TruncSatF32S,
                (8, 4) => Instruction::I32TruncSatF64S,
                (4, _) => Instruction::I64TruncSatF32S,
                (_, _) => Instruction::I64TruncSatF64S,
            });
            emit_store(f, out)
        }

        // Raise a dynamic exception: code from input 0, value from input 1,
        // then stop. The `raise` import re-canonicalises the code through
        // `from_u32`, matching `exception(from_u32(a), b)`.
        Op::Exception => {
            if !has_host {
                return None;
            }
            emit_zext_i32(f, a)?;
            emit_zext_i64(f, b)?;
            f.instruction(&Instruction::I32Const(index as i32));
            f.instruction(&Instruction::Call(IMPORT_RAISE));
            if let Some(iter) = region_iter {
                f.instruction(&Instruction::LocalGet(iter));
            }
            f.instruction(&Instruction::Return);
            Some(())
        }

        // An invalid instruction raises InvalidInstruction (value 0) and stops.
        Op::Invalid => {
            if !has_host {
                return None;
            }
            emit_raise_const(f, EXC_INVALID_INSTRUCTION, 0, index, region_iter);
            Some(())
        }

        // Everything above translates fully. What remains bails to the
        // interpreter and is correct there: FloatRound (the interpreter rounds
        // half away from zero, wasm `nearest` rounds half to even); the 80-bit
        // x87 width and the size-2 half floats (no wasm type); and the
        // helper/hook/tracer/SSA ops (PcodeOp, Hook, Arg, MultiEqual, ...),
        // which are escapes into arbitrary host state, not pure computation.
        _ => None,
    }
}

/// Translates a whole p-code block to a wasm module whose exported `run`
/// executes it against the register space (imported as memory `env.regs`), or
/// returns `None` if any instruction is unhandled.
///
/// A block that reaches guest memory also imports three host functions —
/// `env.load`, `env.store`, `env.fault` — described in `feasibility/`; a block
/// that does not imports only the register memory. Either way the module is
/// self-contained bytes ready for `WebAssembly.instantiate`; the host supplies
/// the register memory (and, for a memory-using block, the imports) and calls
/// `run`.
pub fn translate_block(block: &pcode::Block) -> Option<Vec<u8>> {
    let has_host = block_needs_host(block);

    // Scratch locals: the inline memory fast path's i64 address and two i32 host
    // offsets, then WIDE_SCRATCH i64 locals for the 128-bit cross-lane ops; see
    // [`FastLocals`] / [`BLOCK_FAST`]. Unused locals are harmless.
    let mut body = Function::new([
        (1, ValType::I64),
        (2, ValType::I32),
        (WIDE_SCRATCH, ValType::I64),
    ]);
    for (i, inst) in block.instructions.iter().enumerate() {
        // Per-block `run` returns nothing, so a fault emits a bare `return`.
        translate_instruction(&mut body, inst, i as u32, has_host, None, BLOCK_FAST)?;
    }
    body.instruction(&Instruction::End);

    let mut module = Module::new();

    // Type 0 is always `run(regs_base: i32, tlb_base: i32)`. The host-import
    // signatures follow it and exist only when the block uses them.
    let mut types = TypeSection::new();
    types.ty().function([ValType::I32, ValType::I32], []); // 0: run(regs_base, tlb_base)
    if has_host {
        types
            .ty()
            .function([ValType::I64, ValType::I32, ValType::I32], [ValType::I32]); // 1: load
        types
            .ty()
            .function([ValType::I64, ValType::I64, ValType::I32], [ValType::I32]); // 2: store
        types.ty().function([ValType::I32], []); // 3: fault
        types
            .ty()
            .function([ValType::I32, ValType::I64, ValType::I32], []); // 4: raise(code, value, index)
    }
    module.section(&types);

    // Import the register space as memory, so JIT'd code and the interpreter
    // share it. The host binds `env.regs` to the real register bytes. The
    // function imports, when present, are declared in the order the
    // `IMPORT_*` indices expect (memory imports do not occupy the function
    // index space, so `load`/`store`/`fault`/`raise` are 0/1/2/3).
    let mut imports = wasm_encoder::ImportSection::new();
    imports.import(
        "env",
        "regs",
        EntityType::Memory(MemoryType {
            minimum: REG_PAGES,
            maximum: None,
            memory64: false,
            shared: false,
            page_size_log2: None,
        }),
    );
    if has_host {
        imports.import("env", "load", EntityType::Function(1));
        imports.import("env", "store", EntityType::Function(2));
        imports.import("env", "fault", EntityType::Function(3));
        imports.import("env", "raise", EntityType::Function(4));
    }
    module.section(&imports);

    // `run` is type 0. Its function index is 0 when there are no function
    // imports, or 4 when the four host imports precede it.
    let run_index = if has_host { 4 } else { 0 };

    let mut funcs = FunctionSection::new();
    funcs.function(0);
    module.section(&funcs);

    let mut exports = ExportSection::new();
    exports.export("run", ExportKind::Func, run_index);
    module.section(&exports);

    let mut code = CodeSection::new();
    code.function(&body);
    module.section(&code);

    Some(module.finish())
}

/// Local index of a region `run`'s third parameter, `max_iters` — the cap on
/// how many loop iterations one call may execute (the fuel budget divided by the
/// block's instruction count). It follows `regs_base` (0) and `tlb_base` (1).
const REGION_MAX_ITERS_PARAM: u32 = 2;

/// Local index of a region's iteration counter, an `i64` declared after the
/// three parameters.
const REGION_ITER_LOCAL: u32 = 3;

/// Translates a register-only self-loop block into a wasm *region* function.
///
/// A self-loop is a block whose structured exit branches back to its own start.
/// `cond` says how it loops: `Some(v)` is a conditional branch that stays in the
/// loop while the branch condition varnode `v` reads non-zero; `None` is an
/// unconditional jump back to the start (an infinite spin — `hlt`/`jmp $` — that
/// only a fuel slice ends). Where [`translate_block`] emits one straight-line
/// pass and the host re-dispatches once per iteration, this emits an internal
/// wasm `loop`, so N iterations are one call:
///
/// ```text
/// run(regs_base: i32, max_iters: i64) -> i64      ; returns iterations executed
///   loop
///     <block body>                                ; the per-instruction emitters
///     iter += 1
///     if iter < max_iters [ && cond-byte != 0 ] { continue }   ; else exit
///   end
///   return iter
/// ```
///
/// The count `iter` includes the terminal iteration whose branch went false
/// (that block execution ran in full, exactly as the interpreter would run it),
/// so the host charges `iter * num_instructions` fuel and the register file
/// holds the post-iteration state — from which the host's `block_exit` reads the
/// live condition and goes to the loop target or the fallthrough itself. The
/// combined `iter < max_iters` guard means a run that hits the budget exits with
/// `iter == max_iters` (the loop still live) and one that the condition ends
/// exits with `iter < max_iters`; either way the register file, not `iter`,
/// decides where control goes next.
///
/// Host self-loops are supported: a body that reaches guest memory (the
/// memcpy/hash/scan loops that dominate real workloads), divides, or raises
/// declares the same four function imports [`translate_block`] uses, and a
/// mid-loop fault stops the region exactly where the interpreter would. Because
/// the region's `run` returns the iteration count, a fault pushes that count
/// before returning (see [`emit_fault_check`]), so the host learns BOTH how many
/// whole iterations retired and — via the reported index — where the partial
/// iteration stopped. A register-only self-loop declares no function imports and
/// its `run` is function 0, byte-for-byte as before.
///
/// Returns `None` if a conditional `cond` is not a variable (a constant
/// condition is a [`pcode`] `Jump`, never a `Branch`), or if any instruction
/// does not translate.
pub fn translate_region(block: &pcode::Block, cond: Option<Value>) -> Option<Vec<u8>> {
    let has_host = block_needs_host(block);
    let cond_var = match cond {
        Some(Value::Var(v)) => Some(v),
        Some(Value::Const(..)) => return None,
        None => None,
    };

    // Locals after the three params: the i64 iteration counter (index 3), the
    // three inline-fast-path scratch locals (an i64 address and two i32 host
    // offsets, indices 4/5/6), then WIDE_SCRATCH i64 locals for the 128-bit
    // cross-lane ops; see [`FastLocals`] / [`REGION_FAST`].
    let mut body = Function::new([
        (1, ValType::I64),
        (1, ValType::I64),
        (2, ValType::I32),
        (WIDE_SCRATCH, ValType::I64),
    ]);
    body.instruction(&Instruction::Loop(BlockType::Empty));
    for (i, inst) in block.instructions.iter().enumerate() {
        // A host op that faults stops the region by returning the current
        // iteration count (`REGION_ITER_LOCAL`), so the host can reproduce the
        // interpreter's mid-loop stop; a register-only body emits no such
        // `return` and its loop is the only control flow.
        translate_instruction(
            &mut body,
            inst,
            i as u32,
            has_host,
            Some(REGION_ITER_LOCAL),
            REGION_FAST,
        )?;
    }
    // iter += 1
    body.instruction(&Instruction::LocalGet(REGION_ITER_LOCAL));
    body.instruction(&Instruction::I64Const(1));
    body.instruction(&Instruction::I64Add);
    body.instruction(&Instruction::LocalSet(REGION_ITER_LOCAL));
    // Continue while iter < max_iters (the budget) ...
    body.instruction(&Instruction::LocalGet(REGION_ITER_LOCAL));
    body.instruction(&Instruction::LocalGet(REGION_MAX_ITERS_PARAM));
    body.instruction(&Instruction::I64LtU);
    // ... and, for a conditional self-loop, while the branch condition byte is
    // non-zero (matching the interpreter's `read::<u8>(cond) != 0`). Normalise
    // the byte to 0/1 so a value like 2 does not clear a bit under `and`.
    if let Some(v) = cond_var {
        emit_load(&mut body, Value::Var(v), 1)?;
        body.instruction(&Instruction::I32Const(0));
        body.instruction(&Instruction::I32Ne);
        body.instruction(&Instruction::I32And);
    }
    body.instruction(&Instruction::BrIf(0));
    // Fell through: the budget is spent, or the condition went false.
    body.instruction(&Instruction::End); // end loop
    body.instruction(&Instruction::LocalGet(REGION_ITER_LOCAL));
    body.instruction(&Instruction::End); // end function

    let mut module = Module::new();

    // Type 0 is always the region `run(regs_base, tlb_base, max_iters) ->
    // iters`. The host-import signatures follow it and exist only when the block
    // uses them, declared exactly as `translate_block` does so `IMPORT_LOAD/
    // STORE/FAULT/RAISE` (0/1/2/3) stay valid.
    let mut types = TypeSection::new();
    types
        .ty()
        .function([ValType::I32, ValType::I32, ValType::I64], [ValType::I64]); // 0: run(regs_base, tlb_base, max_iters) -> iters
    if has_host {
        types
            .ty()
            .function([ValType::I64, ValType::I32, ValType::I32], [ValType::I32]); // 1: load
        types
            .ty()
            .function([ValType::I64, ValType::I64, ValType::I32], [ValType::I32]); // 2: store
        types.ty().function([ValType::I32], []); // 3: fault
        types
            .ty()
            .function([ValType::I32, ValType::I64, ValType::I32], []); // 4: raise(code, value, index)
    }
    module.section(&types);

    // Import the register memory; a host region also imports the four functions
    // in the order the `IMPORT_*` indices expect (memory imports do not occupy
    // the function index space, so `load`/`store`/`fault`/`raise` are 0/1/2/3).
    let mut imports = wasm_encoder::ImportSection::new();
    imports.import(
        "env",
        "regs",
        EntityType::Memory(MemoryType {
            minimum: REG_PAGES,
            maximum: None,
            memory64: false,
            shared: false,
            page_size_log2: None,
        }),
    );
    if has_host {
        imports.import("env", "load", EntityType::Function(1));
        imports.import("env", "store", EntityType::Function(2));
        imports.import("env", "fault", EntityType::Function(3));
        imports.import("env", "raise", EntityType::Function(4));
    }
    module.section(&imports);

    // `run` is type 0. Its function index is 0 when there are no function
    // imports, or 4 when the four host imports precede it.
    let run_index = if has_host { 4 } else { 0 };

    let mut funcs = FunctionSection::new();
    funcs.function(0);
    module.section(&funcs);

    let mut exports = ExportSection::new();
    exports.export("run", ExportKind::Func, run_index);
    module.section(&exports);

    let mut code = CodeSection::new();
    code.function(&body);
    module.section(&code);

    Some(module.finish())
}

#[derive(Clone, Copy, Debug)]
pub struct TraceResume {
    pub block_id: usize,
    pub addr: u64,
}

pub struct TraceTranslation {
    pub bytes: Vec<u8>,
    pub resumes: Vec<TraceResume>,
    /// Global fault index -> (arena block id, p-code index in that block).
    pub fault_sites: Vec<(usize, usize)>,
}

/// Compiles a bounded multi-block CFG as a wasm state-machine loop. Internal
/// edges select the next state without returning to Rust/JS; static side exits
/// return a compact resume code. The high bits of a successful return are the
/// exact guest instructions retired, so unlike a single-block region, blocks
/// of different sizes preserve fuel and icount exactly.
pub fn translate_trace(
    blocks: &[LiftedBlock],
    order: &[usize],
    pc: VarNode,
) -> Option<TraceTranslation> {
    if order.len() < 2 || order.len() > 8 || pc.size != 8 {
        return None;
    }
    let states: std::collections::HashMap<usize, u32> = order
        .iter()
        .enumerate()
        .map(|(state, &block)| (block, state as u32))
        .collect();
    if states.len() != order.len() {
        return None;
    }
    if order.iter().any(|&id| id >= blocks.len()) {
        return None;
    }
    let has_host = order.iter().any(|&id| block_needs_host(&blocks[id].pcode));
    let mut resumes = Vec::<TraceResume>::new();
    let mut fault_sites = Vec::new();
    for &id in order {
        let block = blocks.get(id)?;
        if block.has_breakpoint() || block.num_instructions == 0 {
            return None;
        }
        fault_sites.extend((0..block.pcode.instructions.len()).map(|index| (id, index)));
    }

    let mut body = Function::new([
        (1, ValType::I64),
        (1, ValType::I32),
        (1, ValType::I64),
        (2, ValType::I32),
        (WIDE_SCRATCH, ValType::I64),
    ]);
    body.instruction(&Instruction::Loop(BlockType::Empty));
    let mut global_index = 0_u32;

    for (state, &id) in order.iter().enumerate() {
        let block = blocks.get(id)?;
        body.instruction(&Instruction::LocalGet(TRACE_STATE_LOCAL));
        body.instruction(&Instruction::I32Const(state as i32));
        body.instruction(&Instruction::I32Eq);
        body.instruction(&Instruction::If(BlockType::Empty));

        // Keep the architectural PC on the state about to run, including a
        // budget return before its first instruction.
        emit_store_addr(&mut body);
        body.instruction(&Instruction::I64Const(block.start as i64));
        emit_store(&mut body, pc)?;

        // Do not enter a block that does not fit the remaining fuel.
        body.instruction(&Instruction::LocalGet(REGION_ITER_LOCAL));
        body.instruction(&Instruction::I64Const(block.num_instructions as i64));
        body.instruction(&Instruction::I64Add);
        body.instruction(&Instruction::LocalGet(REGION_MAX_ITERS_PARAM));
        body.instruction(&Instruction::I64GtU);
        body.instruction(&Instruction::If(BlockType::Empty));
        let resume = trace_resume(&mut resumes, id, block.start)?;
        emit_trace_return(&mut body, resume);
        body.instruction(&Instruction::End);

        for inst in &block.pcode.instructions {
            translate_instruction(
                &mut body,
                inst,
                global_index,
                has_host,
                Some(REGION_ITER_LOCAL),
                TRACE_FAST,
            )?;
            global_index += 1;
        }
        body.instruction(&Instruction::LocalGet(REGION_ITER_LOCAL));
        body.instruction(&Instruction::I64Const(block.num_instructions as i64));
        body.instruction(&Instruction::I64Add);
        body.instruction(&Instruction::LocalSet(REGION_ITER_LOCAL));

        match block.exit {
            BlockExit::Jump { target } => {
                emit_trace_target(&mut body, target, blocks, &states, &mut resumes, pc, 1)?
            }
            BlockExit::Branch {
                cond,
                target,
                fallthrough,
            } => {
                emit_load(&mut body, cond, cond.size())?;
                match wasm_ty(cond.size())? {
                    ValType::I32 => {
                        body.instruction(&Instruction::I32Const(0));
                        body.instruction(&Instruction::I32Ne);
                    }
                    ValType::I64 => {
                        body.instruction(&Instruction::I64Const(0));
                        body.instruction(&Instruction::I64Ne);
                    }
                    _ => return None,
                }
                body.instruction(&Instruction::If(BlockType::Empty));
                emit_trace_target(&mut body, target, blocks, &states, &mut resumes, pc, 2)?;
                body.instruction(&Instruction::Else);
                emit_trace_target(&mut body, fallthrough, blocks, &states, &mut resumes, pc, 2)?;
                body.instruction(&Instruction::End);
            }
            _ => return None,
        }
        body.instruction(&Instruction::End);
    }
    // An invalid state cannot execute guest code. Return the retired count;
    // the selector/compiler pair never emits such a state.
    body.instruction(&Instruction::LocalGet(REGION_ITER_LOCAL));
    body.instruction(&Instruction::I64Const(TRACE_RESUME_BITS as i64));
    body.instruction(&Instruction::I64Shl);
    body.instruction(&Instruction::Return);
    body.instruction(&Instruction::End); // loop
    body.instruction(&Instruction::I64Const(0));
    body.instruction(&Instruction::End); // function

    let bytes = finish_region_module(body, has_host);
    Some(TraceTranslation {
        bytes,
        resumes,
        fault_sites,
    })
}

fn trace_resume(resumes: &mut Vec<TraceResume>, block_id: usize, addr: u64) -> Option<u32> {
    if let Some(index) = resumes
        .iter()
        .position(|resume| resume.block_id == block_id && resume.addr == addr)
    {
        return Some(index as u32);
    }
    if resumes.len() >= (1 << TRACE_RESUME_BITS) {
        return None;
    }
    resumes.push(TraceResume { block_id, addr });
    Some((resumes.len() - 1) as u32)
}

fn target_resume(target: Target, blocks: &[LiftedBlock]) -> Option<(usize, u64)> {
    match target {
        Target::Internal(id) => Some((id, blocks.get(id)?.start)),
        Target::External(Value::Const(addr, _)) => Some((usize::MAX, addr)),
        _ => None,
    }
}

fn emit_trace_return(body: &mut Function, resume: u32) {
    body.instruction(&Instruction::LocalGet(REGION_ITER_LOCAL));
    body.instruction(&Instruction::I64Const(TRACE_RESUME_BITS as i64));
    body.instruction(&Instruction::I64Shl);
    body.instruction(&Instruction::I64Const(resume as i64));
    body.instruction(&Instruction::I64Or);
    body.instruction(&Instruction::Return);
}

fn emit_trace_target(
    body: &mut Function,
    target: Target,
    blocks: &[LiftedBlock],
    states: &std::collections::HashMap<usize, u32>,
    resumes: &mut Vec<TraceResume>,
    pc: VarNode,
    loop_depth: u32,
) -> Option<()> {
    let internal_state = match target {
        Target::Internal(id) => states.get(&id).copied(),
        Target::External(Value::Const(addr, _)) => states.iter().find_map(|(&id, &state)| {
            (blocks.get(id).map(|block| block.start) == Some(addr)).then_some(state)
        }),
        _ => None,
    };
    if let Some(state) = internal_state {
        body.instruction(&Instruction::I32Const(state as i32));
        body.instruction(&Instruction::LocalSet(TRACE_STATE_LOCAL));
        body.instruction(&Instruction::Br(loop_depth));
        return Some(());
    }
    let (block_id, addr) = target_resume(target, blocks)?;
    emit_store_addr(body);
    body.instruction(&Instruction::I64Const(addr as i64));
    emit_store(body, pc)?;
    let resume = trace_resume(resumes, block_id, addr)?;
    emit_trace_return(body, resume);
    Some(())
}

fn finish_region_module(body: Function, has_host: bool) -> Vec<u8> {
    let mut module = Module::new();
    let mut types = TypeSection::new();
    types
        .ty()
        .function([ValType::I32, ValType::I32, ValType::I64], [ValType::I64]);
    if has_host {
        types
            .ty()
            .function([ValType::I64, ValType::I32, ValType::I32], [ValType::I32]);
        types
            .ty()
            .function([ValType::I64, ValType::I64, ValType::I32], [ValType::I32]);
        types.ty().function([ValType::I32], []);
        types
            .ty()
            .function([ValType::I32, ValType::I64, ValType::I32], []);
    }
    module.section(&types);
    let mut imports = wasm_encoder::ImportSection::new();
    imports.import(
        "env",
        "regs",
        EntityType::Memory(MemoryType {
            minimum: REG_PAGES,
            maximum: None,
            memory64: false,
            shared: false,
            page_size_log2: None,
        }),
    );
    if has_host {
        imports.import("env", "load", EntityType::Function(1));
        imports.import("env", "store", EntityType::Function(2));
        imports.import("env", "fault", EntityType::Function(3));
        imports.import("env", "raise", EntityType::Function(4));
    }
    module.section(&imports);
    let mut funcs = FunctionSection::new();
    funcs.function(0);
    module.section(&funcs);
    let mut exports = ExportSection::new();
    exports.export("run", ExportKind::Func, if has_host { 4 } else { 0 });
    module.section(&exports);
    let mut code = CodeSection::new();
    code.function(&body);
    module.section(&code);
    module.finish()
}

/// The outcome of running a compiled block through a [`JitBackend`].
pub enum JitOutcome {
    /// Ran to completion; the register file is updated and control falls
    /// through to the block's exit, exactly as after the interpreter runs the
    /// whole block.
    Completed,
    /// Faulted at this instruction index — a memory fault or a raised
    /// exception. The backend has already set the exception, so this is the
    /// interpreter's `Some(index)` early return reached a second way.
    Faulted(u32),
    /// The backend declined or could not run the block; fall back to the
    /// interpreter for this entry.
    Unavailable,
}

/// The outcome of running a compiled self-loop region (see
/// [`translate_region`]) through a [`JitBackend`].
pub enum RegionOutcome {
    /// The loop body ran `iters` full iterations against the register file,
    /// which now holds the post-iteration state. `iters` is the iteration
    /// budget when the budget was spent (the loop is still live), or fewer when
    /// the branch condition went false (the loop has exited). Either way the
    /// host charges `iters * num_instructions` fuel and lets its own
    /// `block_exit` read the live condition to pick the next block.
    Ran(u64),
    /// A host op faulted partway through, after `iters` fully completed
    /// iterations, at pcode instruction `index`. The counter is not yet
    /// incremented at the fault, so `iters` is exactly the count of whole
    /// iterations that retired; the backend has already set the exception, as
    /// for a per-block [`JitOutcome::Faulted`]. The host charges
    /// `iters * num_instructions` for the completed iterations, then the guest
    /// instructions of the partial faulting iteration up to `index`, and resumes
    /// the interpreter at `index`. Only a host region can fault; a register-only
    /// one never does.
    Faulted(u64, u32),
    /// The backend declined or could not run the region; fall back to the
    /// per-block path (always correct) for this entry.
    Unavailable,
}

/// A host that compiles translated blocks and runs them.
///
/// [`translate_block`] produces the wasm; a backend turns those bytes into
/// something callable — the browser's WebAssembly engine, or wasmi in a native
/// test — and runs it against the register file. The backend owns how the
/// register file is made visible to the compiled code: shared with the host's
/// own memory in the browser (no copy), copied in and out for a native runtime.
pub trait JitBackend {
    /// Compiles block bytes to an opaque handle, or `None` if it declines (a
    /// module too large to compile synchronously, say). A `None` is cached as a
    /// permanent bail for that block.
    fn compile(&mut self, bytes: &[u8]) -> Option<u32>;

    /// Runs the compiled block `handle` against `cpu`.
    ///
    /// The block reads and writes `cpu.regs` (the register file), and — for a
    /// block that touches guest memory, divides, or raises — its host callbacks
    /// go through `cpu.mem` and set `cpu.exception`, exactly as the interpreter
    /// would. The backend owns how the register file reaches the compiled code:
    /// shared with the host's memory in the browser, copied in and out for a
    /// native runtime.
    fn call(&mut self, handle: u32, cpu: &mut icicle_cpu::Cpu) -> JitOutcome;

    /// Runs a compiled self-loop region `handle` against `cpu` for up to
    /// `max_iters` iterations, returning how many the loop body executed.
    ///
    /// The region is a [`translate_region`] function: `run(regs_base,
    /// max_iters) -> iters`. `max_iters` bounds the run to the fuel budget, so
    /// the region never retires more than the interpreter would in one slice.
    /// A backend that does not support regions returns
    /// [`RegionOutcome::Unavailable`], and the host falls back to the per-block
    /// path.
    fn call_region(
        &mut self,
        handle: u32,
        cpu: &mut icicle_cpu::Cpu,
        max_iters: u64,
    ) -> RegionOutcome;

    /// Drops the compiled code for `handle`, freeing whatever the runtime spent
    /// on it (a wasm module and instance). The host calls this when it evicts a
    /// block under the code budget, or wholesale when it flushes the code cache;
    /// after it, the host never calls `handle` again (it re-earns compilation
    /// from scratch). A handle already dropped or never issued is ignored.
    fn evict(&mut self, handle: u32);
}

/// Where a block first fails to translate, for the coverage diagnostic. `width`
/// is the largest of the output and input byte sizes at that instruction, so a
/// 16-byte SIMD or i128 op reads as width 16.
pub struct Bail {
    pub op: String,
    pub width: u8,
}

/// The first instruction in `block` that [`translate_instruction`] cannot
/// handle, or `None` if the whole block translates. Used to attribute why a hot
/// block bailed, so coverage work can be aimed at what actually executes.
pub fn first_bail(block: &pcode::Block) -> Option<Bail> {
    let has_host = block_needs_host(block);
    for (i, inst) in block.instructions.iter().enumerate() {
        let mut scratch = Function::new([
            (1, ValType::I64),
            (2, ValType::I32),
            (WIDE_SCRATCH, ValType::I64),
        ]);
        if translate_instruction(&mut scratch, inst, i as u32, has_host, None, BLOCK_FAST).is_none()
        {
            let out = inst.output.size;
            let in_max = inst
                .inputs
                .get()
                .iter()
                .map(|v| v.size())
                .max()
                .unwrap_or(0);
            let dbg = format!("{:?}", inst.op);
            let op = dbg.split('(').next().unwrap_or(&dbg).to_string();
            return Some(Bail {
                op,
                width: out.max(in_max),
            });
        }
    }
    None
}
