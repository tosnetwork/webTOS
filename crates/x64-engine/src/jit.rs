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

use pcode::{Op, Value, VarNode};
use wasm_encoder::{
    BlockType, CodeSection, EntityType, ExportKind, ExportSection, Function, FunctionSection,
    Instruction, MemArg, MemoryType, Module, TypeSection, ValType,
};

/// Function indices of the three memory imports, in the order
/// [`translate_block`] declares them. Imported functions occupy the low end of
/// the function index space, so these are fixed; the emitted `run` function
/// follows them. They are declared only for a block that actually loads or
/// stores (see [`block_needs_mem`]); a block without memory ops imports none of
/// them and its `run` is function 0.
const IMPORT_LOAD: u32 = 0;
const IMPORT_STORE: u32 = 1;
const IMPORT_FAULT: u32 = 2;

/// Whether the block reaches guest memory, and so needs the memory imports.
///
/// Only `Load`/`Store` do. A block with none of them stays a self-contained
/// register-to-register function with no imported host calls.
fn block_needs_mem(block: &pcode::Block) -> bool {
    block
        .instructions
        .iter()
        .any(|inst| matches!(inst.op, Op::Load(_) | Op::Store(_)))
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

/// Pushes the byte address of `out` in the register space, so a following
/// `store` writes there. Wasm `store` consumes `[address, value]`, address
/// first, which is why this is emitted before the value is computed.
pub fn emit_store_addr(f: &mut Function, out: VarNode) {
    f.instruction(&Instruction::I32Const(var_offset(out) as i32));
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
            let addr = var_offset(var);
            f.instruction(&Instruction::I32Const(addr as i32));
            let arg = MemArg {
                offset: 0,
                align: 0,
                memory_index: 0,
            };
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

/// Stores the value on top of the stack to `out`, given the address `emit_store_addr`
/// pushed underneath it. Sub-word sizes store only their low bytes.
pub fn emit_store(f: &mut Function, out: VarNode) -> Option<()> {
    wasm_ty(out.size)?;
    let arg = MemArg {
        offset: 0,
        align: 0,
        memory_index: 0,
    };
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

/// Emits the fault check that follows a memory import: the import left an `ok`
/// flag on the stack, and if it is zero the access faulted. On a fault the
/// block stops exactly where the interpreter would — it reports the faulting
/// instruction's index (the import has already set the exception) and returns,
/// leaving every earlier instruction's effects in place and this one's undone.
fn emit_fault_check(f: &mut Function, index: u32) {
    f.instruction(&Instruction::I32Eqz);
    f.instruction(&Instruction::If(BlockType::Empty));
    f.instruction(&Instruction::I32Const(index as i32));
    f.instruction(&Instruction::Call(IMPORT_FAULT));
    f.instruction(&Instruction::Return);
    f.instruction(&Instruction::End);
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

/// Stores the float on top of the stack to the address underneath it, writing
/// its IEEE bits. The output width picks `f32`/`f64`.
fn emit_float_store(f: &mut Function, size: u8) -> Option<()> {
    let arg = MemArg {
        offset: 0,
        align: 0,
        memory_index: 0,
    };
    match size {
        4 => f.instruction(&Instruction::F32Store(arg)),
        8 => f.instruction(&Instruction::F64Store(arg)),
        _ => return None,
    };
    Some(())
}

/// Translates one p-code instruction into wasm appended to `f`, or returns
/// `None` if the op (or a size it uses) is not handled — which bails the whole
/// block to the interpreter.
///
/// This is the dispatch the op handlers plug into. `IntAdd` is the worked
/// reference; each remaining integer op is one arm here, mostly a single wasm
/// binary instruction between the shared load/store helpers.
pub fn translate_instruction(
    f: &mut Function,
    inst: &pcode::Instruction,
    index: u32,
    has_mem: bool,
) -> Option<()> {
    let out = inst.output;
    let [a, b] = inst.inputs.get();

    // Pushes the p-code shift count as an `i32` holding the interpreter's
    // `read_dynamic(b).zxt::<u32>()`: the count zero-extended, and — for an
    // 8-byte count — truncated to its low 32 bits (`i32.wrap_i64`), which is
    // what a `u128 -> u32` zxt does. Used for the width comparison, and (after
    // widening) as the shift amount itself.
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

    match inst.op {
        // Metadata: marks an instruction boundary. No machine effect; the
        // interpreter uses it for the instruction count, which the block
        // driver accounts for separately. Emit nothing.
        Op::InstructionMarker => Some(()),

        // The reference. out = a + b, all one width.
        //   store-addr(out); load(a); load(b); iN.add; store(out)
        Op::IntAdd => {
            let size = same_width(out, a, b)?;
            emit_store_addr(f, out);
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
            emit_store_addr(f, out);
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
            let size = same_width(out, a, b)?;
            emit_store_addr(f, out);
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
            let size = same_width(out, a, b)?;
            emit_store_addr(f, out);
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
            let size = same_width(out, a, b)?;
            emit_store_addr(f, out);
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
            let size = same_width(out, a, b)?;
            emit_store_addr(f, out);
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
            let size = out.size;
            let ty = wasm_ty(size)?;
            if a.size() != size {
                return None;
            }
            emit_store_addr(f, out);
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
            emit_store_addr(f, out);
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
            let size = out.size;
            let ty = wasm_ty(size)?;
            if a.size() != size {
                return None;
            }
            wasm_ty(b.size())?;
            let width = size as i32 * 8;

            emit_store_addr(f, out);
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
            let size = out.size;
            let ty = wasm_ty(size)?;
            if a.size() != size {
                return None;
            }
            wasm_ty(b.size())?;
            let clamp = size as i32 * 8 - 1;

            emit_store_addr(f, out);
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
            emit_store_addr(f, out);
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
            emit_store_addr(f, out);
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
            emit_store_addr(f, out);
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
            emit_store_addr(f, out);
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
            emit_store_addr(f, out);
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
            emit_store_addr(f, out);
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
            emit_store_addr(f, out);
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
            emit_store_addr(f, out);
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
            emit_store_addr(f, out);
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
            emit_store_addr(f, out);
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
            emit_store_addr(f, out);
            emit_load(f, a, 1)?;
            f.instruction(&Instruction::I32Eqz);
            emit_store(f, out)
        }

        // --- Move / resize ---------------------------------------------------

        // out = a, same width. A load then a store of the same size.
        Op::Copy => {
            let size = out.size;
            if a.size() != size {
                return None;
            }
            wasm_ty(size)?;
            emit_store_addr(f, out);
            emit_load(f, a, size)?;
            emit_store(f, out)
        }

        // out = zero-extend(a), out wider than a. `emit_load` already
        // zero-extends a sub-word load into its `i32`, so for an `i32` output
        // the value stores directly (the high output bytes are already zero).
        // Only widening the `i32`-typed load to an `i64` output needs an
        // explicit `i64.extend_i32_u`.
        Op::ZeroExtend => {
            let in_size = a.size();
            let out_size = out.size;
            let in_ty = wasm_ty(in_size)?;
            let out_ty = wasm_ty(out_size)?;
            if out_size < in_size {
                return None;
            }
            emit_store_addr(f, out);
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
            let in_size = a.size();
            let out_size = out.size;
            wasm_ty(in_size)?;
            wasm_ty(out_size)?;
            if out_size <= in_size {
                return None;
            }
            emit_store_addr(f, out);
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
            emit_store_addr(f, out);
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
            emit_store_addr(f, out);
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
            emit_store_addr(f, out);
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
            emit_store_addr(f, out);
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
            emit_store_addr(f, out);
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
            emit_store_addr(f, out);
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
            emit_store_addr(f, out);
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
            emit_store_addr(f, out);
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
            emit_float_store(f, size)
        }

        // Float unary: out = <op> a, same IEEE width. FloatRound is *not* here
        // — the interpreter's round is half-away-from-zero (Rust `f64::round`)
        // while wasm `nearest` is half-to-even, so it bails to the interpreter.
        Op::FloatNegate | Op::FloatAbs | Op::FloatSqrt | Op::FloatCeil | Op::FloatFloor => {
            let size = out.size;
            if !matches!(size, 4 | 8) || a.size() != size {
                return None;
            }
            emit_store_addr(f, out);
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
            emit_float_store(f, size)
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
            emit_store_addr(f, out);
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
            emit_store_addr(f, out);
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
            if !has_mem || id != pcode::RAM_SPACE || !matches!(out.size, 1 | 2 | 4 | 8) {
                return None;
            }
            emit_zext_i64(f, a)?;
            f.instruction(&Instruction::I32Const(var_offset(out) as i32));
            f.instruction(&Instruction::I32Const(out.size as i32));
            f.instruction(&Instruction::Call(IMPORT_LOAD));
            emit_fault_check(f, index);
            Some(())
        }

        // *addr = value, a guest-memory store. Address is input 0, value is
        // input 1, and the store width is the value's size. The value is passed
        // to the import on the stack (not by register offset) so a constant
        // operand works. Same RAM-only, size-1/2/4/8, fault-stops-here contract
        // as Load.
        Op::Store(id) => {
            if !has_mem || id != pcode::RAM_SPACE || !matches!(b.size(), 1 | 2 | 4 | 8) {
                return None;
            }
            emit_zext_i64(f, a)?;
            emit_zext_i64(f, b)?;
            f.instruction(&Instruction::I32Const(b.size() as i32));
            f.instruction(&Instruction::Call(IMPORT_STORE));
            emit_fault_check(f, index);
            Some(())
        }

        // Everything above translates fully; anything else bails the block to
        // the interpreter. That deliberately includes the four division ops
        // (IntDiv/IntSignedDiv/IntRem/IntSignedRem): the interpreter raises an
        // exception and writes nothing on a zero (or signed INT_MIN/-1)
        // divisor, whereas wasm's div/rem trap on exactly those inputs —
        // behaviour a compile-time handler can't reconcile, so they stay
        // interpreted.
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
    let has_mem = block_needs_mem(block);

    let mut body = Function::new([]);
    for (i, inst) in block.instructions.iter().enumerate() {
        translate_instruction(&mut body, inst, i as u32, has_mem)?;
    }
    body.instruction(&Instruction::End);

    let mut module = Module::new();

    // Type 0 is always `run`: [] -> []. The memory-import signatures follow it
    // and exist only when the block uses them.
    let mut types = TypeSection::new();
    types.ty().function([], []); // 0: run
    if has_mem {
        types
            .ty()
            .function([ValType::I64, ValType::I32, ValType::I32], [ValType::I32]); // 1: load
        types
            .ty()
            .function([ValType::I64, ValType::I64, ValType::I32], [ValType::I32]); // 2: store
        types.ty().function([ValType::I32], []); // 3: fault
    }
    module.section(&types);

    // Import the register space as memory, so JIT'd code and the interpreter
    // share it. The host binds `env.regs` to the real register bytes. The
    // function imports, when present, are declared in the order the
    // `IMPORT_*` indices expect (memory imports do not occupy the function
    // index space, so `load`/`store`/`fault` are 0/1/2).
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
    if has_mem {
        imports.import("env", "load", EntityType::Function(1));
        imports.import("env", "store", EntityType::Function(2));
        imports.import("env", "fault", EntityType::Function(3));
    }
    module.section(&imports);

    // `run` is type 0. Its function index is 0 when there are no function
    // imports, or 3 when the three memory imports precede it.
    let run_index = if has_mem { 3 } else { 0 };

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
