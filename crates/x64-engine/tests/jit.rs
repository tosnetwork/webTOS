//! The JIT gate: a p-code block translated to wasm must produce the
//! interpreter's register state, bit for bit.
//!
//! This is the block-level form of the trace-suite gate, and the standard
//! every op handler is held to. It runs a block two ways — through the real
//! interpreter, and through the wasm the JIT emits, executed by wasmi over a
//! copy of the same initial register bytes — and compares the whole register
//! space. If a handler emits wasm that computes even one byte differently, the
//! comparison fails and names the block.
//!
//! `IntAdd` is the worked reference. Each op slice adds its ops to
//! `translate_instruction` and a case to `CASES` below; the gate then holds
//! them all to the interpreter.

use std::path::PathBuf;

use pcode::{Op, VarNode};
use x64_engine::build::{build_x64_vm, EngineConfig};
use x64_engine::jit::{translate_block, REG_SPACE_BYTES};

fn ldef_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../third_party/ghidra-x86/languages/x86.ldefs")
}

/// One gate case: a name, the register seeds (varnode → value), and the block
/// to run. The block is built from p-code instructions; the seeds are written
/// into both the interpreter and the wasm's memory before it runs.
struct Case {
    name: &'static str,
    seeds: Vec<(VarNode, u64)>,
    block: pcode::Block,
}

/// A register-space varnode of `size` bytes at slot `id`.
fn reg(id: i16, size: u8) -> VarNode {
    VarNode::new(id, size)
}

/// A one-instruction case for a two-input op: `o = op(a, b)`, seeding `a` and
/// `b`.
fn two(name: &'static str, o: VarNode, op: Op, a: VarNode, av: u64, b: VarNode, bv: u64) -> Case {
    let mut block = pcode::Block::new();
    block.push((o, op, a, b));
    Case {
        name,
        seeds: vec![(a, av), (b, bv)],
        block,
    }
}

/// A one-instruction case for a one-input op: `o = op(a)`, seeding `a`.
fn one(name: &'static str, o: VarNode, op: Op, a: VarNode, av: u64) -> Case {
    let mut block = pcode::Block::new();
    block.push((o, op, a));
    Case {
        name,
        seeds: vec![(a, av)],
        block,
    }
}

fn cases() -> Vec<Case> {
    let mut out = Vec::new();

    // The reference: out(1) = a(2) + b(3), 4 bytes, with a carry across the
    // wrap so a wrong width would show.
    {
        let (o, a, b) = (reg(1, 4), reg(2, 4), reg(3, 4));
        let mut block = pcode::Block::new();
        block.push((o, Op::IntAdd, a, b));
        out.push(Case {
            name: "IntAdd u32 with wraparound",
            seeds: vec![(a, 0xffff_fff0), (b, 0x20)],
            block,
        });
    }

    // IntAdd on 8 bytes, to exercise the i64 path.
    {
        let (o, a, b) = (reg(1, 8), reg(2, 8), reg(3, 8));
        let mut block = pcode::Block::new();
        block.push((o, Op::IntAdd, a, b));
        out.push(Case {
            name: "IntAdd u64",
            seeds: vec![(a, 0x1_0000_0000), (b, 0xff)],
            block,
        });
    }

    // A one-instruction block: out(1,size) = a(2,size) <op> b(3,size).
    let binary = |name, op, size, av: u64, bv: u64| {
        let (o, a, b) = (reg(1, size), reg(2, size), reg(3, size));
        let mut block = pcode::Block::new();
        block.push((o, op, a, b));
        Case {
            name,
            seeds: vec![(a, av), (b, bv)],
            block,
        }
    };
    // A one-instruction unary block: out(1,size) = <op> a(2,size).
    let unary = |name, op, size, av: u64| {
        let (o, a) = (reg(1, size), reg(2, size));
        let mut block = pcode::Block::new();
        block.push((o, op, a));
        Case {
            name,
            seeds: vec![(a, av)],
            block,
        }
    };
    // A one-instruction shift block: out(1,size) = a(2,size) <shift> count(3,csize).
    // The value and the count can be different widths.
    let shift = |name, op, size: u8, csize: u8, av: u64, count: u64| {
        let (o, a, c) = (reg(1, size), reg(2, size), reg(3, csize));
        let mut block = pcode::Block::new();
        block.push((o, op, a, c));
        Case {
            name,
            seeds: vec![(a, av), (c, count)],
            block,
        }
    };

    // IntSub: a borrow across zero, both widths.
    out.push(binary("IntSub u32 with borrow", Op::IntSub, 4, 0x10, 0x20));
    out.push(binary(
        "IntSub u64 with borrow",
        Op::IntSub,
        8,
        0x1,
        0x1_0000_0000,
    ));
    // IntXor / IntOr / IntAnd: overlapping bit patterns.
    out.push(binary(
        "IntXor u32",
        Op::IntXor,
        4,
        0xf0f0_ff00,
        0x0ff0_0ff0,
    ));
    out.push(binary(
        "IntXor u64",
        Op::IntXor,
        8,
        0xdead_beef_0000_ffff,
        0x0000_ffff_dead_beef,
    ));
    out.push(binary("IntOr u32", Op::IntOr, 4, 0xf0f0_0000, 0x0000_0f0f));
    out.push(binary(
        "IntAnd u32",
        Op::IntAnd,
        4,
        0xff00_ff00,
        0x0ff0_0ff0,
    ));
    out.push(binary(
        "IntAnd u64",
        Op::IntAnd,
        8,
        0xffff_ffff_ffff_ffff,
        0x0123_4567_89ab_cdef,
    ));
    // IntMul: a product that overflows the width, so a wrong width shows.
    out.push(binary(
        "IntMul u32 with overflow",
        Op::IntMul,
        4,
        0x1000_0001,
        0x20,
    ));
    out.push(binary(
        "IntMul u64 with overflow",
        Op::IntMul,
        8,
        0x1_0000_0001,
        0x20,
    ));

    // IntNot: complement; the size-1 case checks the store truncates.
    out.push(unary("IntNot u32", Op::IntNot, 4, 0x0f0f_a5a5));
    out.push(unary("IntNot u8", Op::IntNot, 1, 0xa5));
    out.push(unary("IntNot u64", Op::IntNot, 8, 0x0123_4567_89ab_cdef));
    // IntNegate: wrapping negate, including the sub-word wrap and negate-of-zero.
    out.push(unary("IntNegate u32", Op::IntNegate, 4, 0x0000_0001));
    out.push(unary("IntNegate u32 of zero", Op::IntNegate, 4, 0x0));
    out.push(unary("IntNegate u8", Op::IntNegate, 1, 0x01));
    out.push(unary("IntNegate u64", Op::IntNegate, 8, 0x1));

    // IntLeft: in-range, exactly at the width (→0), and past it (→0).
    out.push(shift("IntLeft u32 by 4", Op::IntLeft, 4, 1, 0x1234_5678, 4));
    out.push(shift("IntLeft u32 by 31", Op::IntLeft, 4, 1, 0x1, 31));
    out.push(shift(
        "IntLeft u32 by 32 is zero",
        Op::IntLeft,
        4,
        1,
        0xffff_ffff,
        32,
    ));
    out.push(shift(
        "IntLeft u32 by 40 is zero",
        Op::IntLeft,
        4,
        1,
        0xffff_ffff,
        40,
    ));
    out.push(shift("IntLeft u8 by 4", Op::IntLeft, 1, 1, 0xf3, 4));
    out.push(shift("IntLeft u64 by 40", Op::IntLeft, 8, 1, 0x1, 40));
    out.push(shift(
        "IntLeft u64 by 64 is zero",
        Op::IntLeft,
        8,
        1,
        0xffff_ffff_ffff_ffff,
        64,
    ));
    // A wide (8-byte) count whose low 32 bits are in range, to exercise the wrap.
    out.push(shift(
        "IntLeft u32 wide count low32=4",
        Op::IntLeft,
        4,
        8,
        0x1,
        0x1_0000_0004,
    ));

    // IntRight (logical): in-range and past the width.
    out.push(shift(
        "IntRight u32 by 4",
        Op::IntRight,
        4,
        1,
        0x8000_0000,
        4,
    ));
    out.push(shift(
        "IntRight u32 by 32 is zero",
        Op::IntRight,
        4,
        1,
        0xffff_ffff,
        32,
    ));
    out.push(shift("IntRight u8 by 3", Op::IntRight, 1, 1, 0xf0, 3));
    out.push(shift(
        "IntRight u64 by 4",
        Op::IntRight,
        8,
        1,
        0x8000_0000_0000_0000,
        4,
    ));

    // IntSignedRight (arithmetic): high bit set so the sign propagates; a count
    // past the width clamps to width-1 and fills the result with the sign.
    out.push(shift(
        "IntSignedRight u32 neg by 4",
        Op::IntSignedRight,
        4,
        1,
        0x8000_0000,
        4,
    ));
    out.push(shift(
        "IntSignedRight u32 pos by 4",
        Op::IntSignedRight,
        4,
        1,
        0x7000_0000,
        4,
    ));
    out.push(shift(
        "IntSignedRight u32 neg by 40",
        Op::IntSignedRight,
        4,
        1,
        0x8000_0000,
        40,
    ));
    out.push(shift(
        "IntSignedRight u8 neg by 2",
        Op::IntSignedRight,
        1,
        1,
        0x80,
        2,
    ));
    out.push(shift(
        "IntSignedRight u16 neg by 3",
        Op::IntSignedRight,
        2,
        1,
        0x8001,
        3,
    ));
    out.push(shift(
        "IntSignedRight u64 neg by 8",
        Op::IntSignedRight,
        8,
        1,
        0x8000_0000_0000_0000,
        8,
    ));
    out.push(shift(
        "IntSignedRight u64 neg by 100",
        Op::IntSignedRight,
        8,
        1,
        0x8000_0000_0000_0000,
        100,
    ));

    // Rotates: a count in range and one past the width (masked modulo width).
    out.push(binary(
        "IntRotateLeft u32 by 4",
        Op::IntRotateLeft,
        4,
        0x1234_5678,
        4,
    ));
    out.push(binary(
        "IntRotateLeft u32 by 36 wraps",
        Op::IntRotateLeft,
        4,
        0x1234_5678,
        36,
    ));
    out.push(binary(
        "IntRotateLeft u64 by 8",
        Op::IntRotateLeft,
        8,
        0x0123_4567_89ab_cdef,
        8,
    ));
    out.push(binary(
        "IntRotateRight u32 by 4",
        Op::IntRotateRight,
        4,
        0x1234_5678,
        4,
    ));
    out.push(binary(
        "IntRotateRight u32 by 68 wraps",
        Op::IntRotateRight,
        4,
        0x1234_5678,
        68,
    ));
    out.push(binary(
        "IntRotateRight u64 by 8",
        Op::IntRotateRight,
        8,
        0x0123_4567_89ab_cdef,
        8,
    ));

    // --- Comparisons: 1-byte 0/1 output ------------------------------------
    // The output is reg(1,1); inputs are equal-width. Cases cover a<b, a==b,
    // a>b, and — crucially — inputs whose high bit is set, where the signed
    // and unsigned relations disagree, so a wrong signedness is caught.
    let cmp_out = reg(1, 1);

    // IntEqual / IntNotEqual: equal and unequal, and an i64 case.
    out.push(two(
        "IntEqual u32 equal",
        cmp_out,
        Op::IntEqual,
        reg(2, 4),
        0x1234_5678,
        reg(3, 4),
        0x1234_5678,
    ));
    out.push(two(
        "IntEqual u32 unequal",
        cmp_out,
        Op::IntEqual,
        reg(2, 4),
        1,
        reg(3, 4),
        2,
    ));
    out.push(two(
        "IntNotEqual u8 unequal",
        cmp_out,
        Op::IntNotEqual,
        reg(2, 1),
        0x10,
        reg(3, 1),
        0x20,
    ));
    out.push(two(
        "IntNotEqual u64 equal",
        cmp_out,
        Op::IntNotEqual,
        reg(2, 8),
        0x1_0000_0000,
        reg(3, 8),
        0x1_0000_0000,
    ));

    // IntLess (unsigned): a high-bit input is a large unsigned value.
    out.push(two(
        "IntLess u32 high-bit unsigned",
        cmp_out,
        Op::IntLess,
        reg(2, 4),
        0x8000_0000,
        reg(3, 4),
        0x0000_0001,
    ));
    out.push(two(
        "IntLess u8 a<b",
        cmp_out,
        Op::IntLess,
        reg(2, 1),
        0x10,
        reg(3, 1),
        0x20,
    ));

    // IntSignedLess: same high-bit seeds as unsigned, where the answers differ
    // (0x8000_0000 is negative, so signed-less-than 1 is true), plus a sub-word
    // negative that only comes out right if the byte is sign-extended.
    out.push(two(
        "IntSignedLess u32 high-bit signed",
        cmp_out,
        Op::IntSignedLess,
        reg(2, 4),
        0x8000_0000,
        reg(3, 4),
        0x0000_0001,
    ));
    out.push(two(
        "IntSignedLess u8 negative",
        cmp_out,
        Op::IntSignedLess,
        reg(2, 1),
        0xff, // -1
        reg(3, 1),
        0x01, // 1
    ));
    out.push(two(
        "IntSignedLess u16 negative",
        cmp_out,
        Op::IntSignedLess,
        reg(2, 2),
        0x8000, // -32768
        reg(3, 2),
        0x0000,
    ));
    out.push(two(
        "IntSignedLess u64 negative",
        cmp_out,
        Op::IntSignedLess,
        reg(2, 8),
        0xffff_ffff_ffff_ffff, // -1
        reg(3, 8),
        0x0000_0000_0000_0000,
    ));

    // IntLessEqual (unsigned): equality boundary and a high-bit case.
    out.push(two(
        "IntLessEqual u32 equal",
        cmp_out,
        Op::IntLessEqual,
        reg(2, 4),
        5,
        reg(3, 4),
        5,
    ));
    out.push(two(
        "IntLessEqual u32 high-bit unsigned",
        cmp_out,
        Op::IntLessEqual,
        reg(2, 4),
        0x8000_0000,
        reg(3, 4),
        0x0000_0001,
    ));

    // IntSignedLessEqual: equal negatives, a sub-word negative boundary, i64.
    out.push(two(
        "IntSignedLessEqual u16 equal negatives",
        cmp_out,
        Op::IntSignedLessEqual,
        reg(2, 2),
        0xffff,
        reg(3, 2),
        0xffff,
    ));
    out.push(two(
        "IntSignedLessEqual u16 high-bit signed",
        cmp_out,
        Op::IntSignedLessEqual,
        reg(2, 2),
        0x8000, // -32768
        reg(3, 2),
        0x0000,
    ));
    out.push(two(
        "IntSignedLessEqual u64 min",
        cmp_out,
        Op::IntSignedLessEqual,
        reg(2, 8),
        0x8000_0000_0000_0000, // i64::MIN
        reg(3, 8),
        0x0000_0000_0000_0000,
    ));

    // --- Booleans: 1-byte operands and output ------------------------------
    // Seeds include non-strict-boolean bytes (values other than 0/1) so the
    // "bitwise op then != 0" semantics are distinguished from storing the raw
    // bitwise result or from a logical combination of the operands' truth.
    let bool_out = reg(1, 1);
    out.push(two(
        "BoolAnd 1&1",
        bool_out,
        Op::BoolAnd,
        reg(2, 1),
        1,
        reg(3, 1),
        1,
    ));
    out.push(two(
        "BoolAnd 1&2 disjoint",
        bool_out,
        Op::BoolAnd,
        reg(2, 1),
        1,
        reg(3, 1),
        2,
    ));
    out.push(two(
        "BoolAnd 3&1 overlap",
        bool_out,
        Op::BoolAnd,
        reg(2, 1),
        3,
        reg(3, 1),
        1,
    ));
    out.push(two(
        "BoolOr 0|0",
        bool_out,
        Op::BoolOr,
        reg(2, 1),
        0,
        reg(3, 1),
        0,
    ));
    out.push(two(
        "BoolOr 0|2",
        bool_out,
        Op::BoolOr,
        reg(2, 1),
        0,
        reg(3, 1),
        2,
    ));
    out.push(two(
        "BoolXor 3^1 nonzero",
        bool_out,
        Op::BoolXor,
        reg(2, 1),
        3,
        reg(3, 1),
        1,
    ));
    out.push(two(
        "BoolXor 1^1 zero",
        bool_out,
        Op::BoolXor,
        reg(2, 1),
        1,
        reg(3, 1),
        1,
    ));
    out.push(one("BoolNot 0", bool_out, Op::BoolNot, reg(2, 1), 0));
    out.push(one("BoolNot 5", bool_out, Op::BoolNot, reg(2, 1), 5));

    // --- Copy: same width in and out ---------------------------------------
    out.push(one("Copy u8", reg(1, 1), Op::Copy, reg(2, 1), 0xa5));
    out.push(one("Copy u16", reg(1, 2), Op::Copy, reg(2, 2), 0xbeef));
    out.push(one("Copy u32", reg(1, 4), Op::Copy, reg(2, 4), 0xdead_beef));
    out.push(one(
        "Copy u64",
        reg(1, 8),
        Op::Copy,
        reg(2, 8),
        0x1122_3344_5566_7788,
    ));

    // --- ZeroExtend: wider output, high bits must be zero -------------------
    // High-bit-set inputs distinguish zero- from sign-extension.
    out.push(one(
        "ZeroExtend 1->2",
        reg(1, 2),
        Op::ZeroExtend,
        reg(2, 1),
        0xff,
    ));
    out.push(one(
        "ZeroExtend 1->4",
        reg(1, 4),
        Op::ZeroExtend,
        reg(2, 1),
        0xff,
    ));
    out.push(one(
        "ZeroExtend 2->4",
        reg(1, 4),
        Op::ZeroExtend,
        reg(2, 2),
        0x8080,
    ));
    out.push(one(
        "ZeroExtend 1->8",
        reg(1, 8),
        Op::ZeroExtend,
        reg(2, 1),
        0xff,
    ));
    out.push(one(
        "ZeroExtend 2->8",
        reg(1, 8),
        Op::ZeroExtend,
        reg(2, 2),
        0x8000,
    ));
    out.push(one(
        "ZeroExtend 4->8",
        reg(1, 8),
        Op::ZeroExtend,
        reg(2, 4),
        0x8000_0000,
    ));

    // --- SignExtend: wider output, high bits copy the sign -----------------
    out.push(one(
        "SignExtend 1->2",
        reg(1, 2),
        Op::SignExtend,
        reg(2, 1),
        0xff,
    ));
    out.push(one(
        "SignExtend 1->4",
        reg(1, 4),
        Op::SignExtend,
        reg(2, 1),
        0x80,
    ));
    out.push(one(
        "SignExtend 2->4",
        reg(1, 4),
        Op::SignExtend,
        reg(2, 2),
        0x8001,
    ));
    out.push(one(
        "SignExtend 1->8",
        reg(1, 8),
        Op::SignExtend,
        reg(2, 1),
        0xff,
    ));
    out.push(one(
        "SignExtend 2->8",
        reg(1, 8),
        Op::SignExtend,
        reg(2, 2),
        0x8000,
    ));
    out.push(one(
        "SignExtend 4->8",
        reg(1, 8),
        Op::SignExtend,
        reg(2, 4),
        0x8000_0000,
    ));
    // A positive input must not gain spurious high bits.
    out.push(one(
        "SignExtend 1->8 positive",
        reg(1, 8),
        Op::SignExtend,
        reg(2, 1),
        0x7f,
    ));

    // A flag/unary op case: out(1) written from inputs of width `size`.
    // Helper closure to cut repetition for the single-block cases below.
    let mut push_binflag = |name: &'static str, op: Op, size: u8, av: u64, bv: u64| {
        let (o, a, b) = (reg(1, 1), reg(2, size), reg(3, size));
        let mut block = pcode::Block::new();
        block.push((o, op, a, b));
        out.push(Case {
            name,
            seeds: vec![(a, av), (b, bv)],
            block,
        });
    };

    // --- IntCarry: unsigned add carry-out (1 iff the width-W sum wraps). ---
    // Sub-word widths, exercising the mask path.
    push_binflag("IntCarry u8 carry", Op::IntCarry, 1, 0xff, 0x01);
    push_binflag("IntCarry u8 no carry", Op::IntCarry, 1, 0x7f, 0x01);
    push_binflag("IntCarry u16 carry", Op::IntCarry, 2, 0xffff, 0x01);
    push_binflag("IntCarry u16 no carry", Op::IntCarry, 2, 0x00ff, 0x01);
    // Width-boundary carry at 4 and 8 (the i32/i64 wrap paths, no mask).
    push_binflag("IntCarry u32 carry", Op::IntCarry, 4, 0xffff_ffff, 0x01);
    push_binflag("IntCarry u32 no carry", Op::IntCarry, 4, 0xffff_fffe, 0x01);
    push_binflag(
        "IntCarry u64 carry",
        Op::IntCarry,
        8,
        0xffff_ffff_ffff_ffff,
        0x01,
    );
    push_binflag(
        "IntCarry u64 no carry",
        Op::IntCarry,
        8,
        0x0fff_ffff_ffff_ffff,
        0x01,
    );

    // --- IntSignedCarry: signed add overflow. ---
    // 8-bit: 127 + 1 overflows to -128; -128 + -1 underflows; benign case does not.
    push_binflag(
        "IntSignedCarry i8 pos overflow",
        Op::IntSignedCarry,
        1,
        0x7f,
        0x01,
    );
    push_binflag(
        "IntSignedCarry i8 neg overflow",
        Op::IntSignedCarry,
        1,
        0x80,
        0xff,
    );
    push_binflag(
        "IntSignedCarry i8 no overflow",
        Op::IntSignedCarry,
        1,
        0x7f,
        0xff,
    );
    // 16/32/64-bit at INT_MAX + 1.
    push_binflag(
        "IntSignedCarry i16 overflow",
        Op::IntSignedCarry,
        2,
        0x7fff,
        0x0001,
    );
    push_binflag(
        "IntSignedCarry i32 overflow",
        Op::IntSignedCarry,
        4,
        0x7fff_ffff,
        0x0000_0001,
    );
    push_binflag(
        "IntSignedCarry i32 no overflow",
        Op::IntSignedCarry,
        4,
        0x7fff_ffff,
        0xffff_ffff,
    );
    push_binflag(
        "IntSignedCarry i64 overflow",
        Op::IntSignedCarry,
        8,
        0x7fff_ffff_ffff_ffff,
        0x0000_0000_0000_0001,
    );
    push_binflag(
        "IntSignedCarry i64 neg overflow",
        Op::IntSignedCarry,
        8,
        0x8000_0000_0000_0000,
        0xffff_ffff_ffff_ffff,
    );

    // --- IntSignedBorrow: signed subtract overflow. ---
    // 8-bit: 127 - (-1) = 128 overflows; -128 - 1 underflows; same-sign does not.
    push_binflag(
        "IntSignedBorrow i8 pos overflow",
        Op::IntSignedBorrow,
        1,
        0x7f,
        0xff,
    );
    push_binflag(
        "IntSignedBorrow i8 neg overflow",
        Op::IntSignedBorrow,
        1,
        0x80,
        0x01,
    );
    push_binflag(
        "IntSignedBorrow i8 no overflow",
        Op::IntSignedBorrow,
        1,
        0x7f,
        0x01,
    );
    push_binflag(
        "IntSignedBorrow i16 overflow",
        Op::IntSignedBorrow,
        2,
        0x7fff,
        0xffff,
    );
    push_binflag(
        "IntSignedBorrow i32 overflow",
        Op::IntSignedBorrow,
        4,
        0x8000_0000,
        0x0000_0001,
    );
    push_binflag(
        "IntSignedBorrow i32 no overflow",
        Op::IntSignedBorrow,
        4,
        0x0000_0005,
        0x0000_0003,
    );
    push_binflag(
        "IntSignedBorrow i64 overflow",
        Op::IntSignedBorrow,
        8,
        0x7fff_ffff_ffff_ffff,
        0xffff_ffff_ffff_ffff,
    );

    // --- IntCountOnes: popcount over the input width, truncated into out. ---
    // out and input share width here; count fits in a byte at every width.
    for (name, size, val) in [
        ("IntCountOnes u8 zero", 1u8, 0x00u64),
        ("IntCountOnes u8 all-ones", 1, 0xff),
        ("IntCountOnes u8 mixed", 1, 0xa5),
        ("IntCountOnes u16 mixed", 2, 0xf00f),
        ("IntCountOnes u32 all-ones", 4, 0xffff_ffff),
        ("IntCountOnes u32 mixed", 4, 0xdead_beef),
        ("IntCountOnes u64 all-ones", 8, 0xffff_ffff_ffff_ffff),
        ("IntCountOnes u64 mixed", 8, 0x0123_4567_89ab_cdef),
    ] {
        let (o, a) = (reg(1, size), reg(2, size));
        let mut block = pcode::Block::new();
        block.push((o, Op::IntCountOnes, a, pcode::Value::invalid()));
        out.push(Case {
            name,
            seeds: vec![(a, val)],
            block,
        });
    }
    // Popcount of a size-8 input written into a size-1 output (truncation path).
    {
        let (o, a) = (reg(1, 1), reg(2, 8));
        let mut block = pcode::Block::new();
        block.push((o, Op::IntCountOnes, a, pcode::Value::invalid()));
        out.push(Case {
            name: "IntCountOnes u64 into u8 out",
            seeds: vec![(a, 0xffff_ffff_ffff_ffff)],
            block,
        });
    }

    // --- IntCountLeadingZeroes: clz within the input width. ---
    for (name, size, val) in [
        ("IntClz u16 zero", 2u8, 0x0000u64),
        ("IntClz u16 one", 2, 0x0001),
        ("IntClz u16 high bit", 2, 0x8000),
        ("IntClz u32 zero", 4, 0x0000_0000),
        ("IntClz u32 one", 4, 0x0000_0001),
        ("IntClz u32 high bit", 4, 0x8000_0000),
        ("IntClz u64 zero", 8, 0x0000_0000_0000_0000),
        ("IntClz u64 one", 8, 0x0000_0000_0000_0001),
        ("IntClz u64 high bit", 8, 0x8000_0000_0000_0000),
        ("IntClz u8 zero", 1, 0x00),
        ("IntClz u8 high bit", 1, 0x80),
    ] {
        let (o, a) = (reg(1, size), reg(2, size));
        let mut block = pcode::Block::new();
        block.push((o, Op::IntCountLeadingZeroes, a, pcode::Value::invalid()));
        out.push(Case {
            name,
            seeds: vec![(a, val)],
            block,
        });
    }
    // clz of a size-8 input written into a size-8 output where the count needs
    // the i64-extend store path — value 0 gives count 64.
    {
        let (o, a) = (reg(1, 8), reg(2, 8));
        let mut block = pcode::Block::new();
        block.push((o, Op::IntCountLeadingZeroes, a, pcode::Value::invalid()));
        out.push(Case {
            name: "IntClz u64 zero -> 64",
            seeds: vec![(a, 0)],
            block,
        });
    }

    // Select (conditional move): out = cond != 0 ? a : b. The condition is a
    // separate 1-byte varnode named by the op. One case per branch, so a wrong
    // operand order or a dropped condition load shows immediately.
    {
        let (o, a, b, cond) = (reg(1, 4), reg(2, 4), reg(3, 4), reg(4, 1));
        let mut block = pcode::Block::new();
        block.push((o, Op::Select(cond.id), a, b));
        out.push(Case {
            name: "Select cond != 0 picks a",
            seeds: vec![(a, 0xaaaa_aaaa), (b, 0x5555_5555), (cond, 1)],
            block,
        });
    }
    {
        let (o, a, b, cond) = (reg(1, 8), reg(2, 8), reg(3, 8), reg(4, 1));
        let mut block = pcode::Block::new();
        block.push((o, Op::Select(cond.id), a, b));
        out.push(Case {
            name: "Select cond == 0 picks b (u64)",
            seeds: vec![
                (a, 0xaaaa_aaaa_aaaa_aaaa),
                (b, 0x5555_5555_5555_5555),
                (cond, 0),
            ],
            block,
        });
    }

    out
}

/// Runs a block through the interpreter, returning the full register space.
fn interpret(case: &Case) -> Vec<u8> {
    let mut vm = build_x64_vm(&ldef_path(), &EngineConfig::default()).expect("build vm");
    vm.cpu.regs.fill(0);
    // Seed by writing each varnode's little-endian bytes at its offset — the
    // same way the wasm memory is seeded, so the two runs start identical.
    for &(var, value) in &case.seeds {
        let off = x64_engine::jit::var_offset(var) as usize;
        let n = var.size as usize;
        vm.cpu.regs.as_bytes_mut()[off..off + n].copy_from_slice(&value.to_le_bytes()[..n]);
    }
    // Safety: the block is well-formed p-code built above.
    unsafe {
        vm.cpu.interpret_block_unchecked(&case.block, 0);
    }
    vm.cpu.regs.as_bytes().to_vec()
}

/// Runs the JIT'd wasm for a block through wasmi over the same seeds,
/// returning the full register space, or None if the block did not translate.
fn jit(case: &Case) -> Option<Vec<u8>> {
    let bytes = translate_block(&case.block)?;

    let engine = wasmi::Engine::default();
    let module = wasmi::Module::new(&engine, &bytes[..]).expect("emitted wasm is valid");
    let mut store = wasmi::Store::new(&engine, ());
    let mem_ty = wasmi::MemoryType::new(REG_SPACE_BYTES / 65536, None);
    let memory = wasmi::Memory::new(&mut store, mem_ty).expect("memory");

    // Seed the register space the same way the interpreter was seeded, by
    // writing each varnode's little-endian bytes at its offset.
    let mut regs = vec![0u8; REG_SPACE_BYTES as usize];
    for &(var, value) in &case.seeds {
        let off = x64_engine::jit::var_offset(var) as usize;
        let n = var.size as usize;
        regs[off..off + n].copy_from_slice(&value.to_le_bytes()[..n]);
    }
    memory.write(&mut store, 0, &regs).expect("seed memory");

    let mut linker = wasmi::Linker::new(&engine);
    linker.define("env", "regs", memory).expect("define memory");
    let instance = linker
        .instantiate(&mut store, &module)
        .expect("instantiate")
        .start(&mut store)
        .expect("start");
    let run = instance
        .get_typed_func::<(), ()>(&store, "run")
        .expect("run export");
    run.call(&mut store, ()).expect("run");

    let mut out = vec![0u8; REG_SPACE_BYTES as usize];
    memory.read(&store, 0, &mut out).expect("read memory");
    Some(out)
}

#[test]
fn translated_blocks_match_the_interpreter() {
    let mut failures = Vec::new();
    let mut ran = 0;
    for case in cases() {
        let Some(jit_regs) = jit(&case) else {
            // A case that does not translate is a hole in the JIT, not a pass:
            // every case here is built from ops the JIT is meant to handle.
            failures.push(format!("{}: did not translate", case.name));
            continue;
        };
        let interp_regs = interpret(&case);
        ran += 1;
        if let Some(offset) = first_difference(&interp_regs, &jit_regs) {
            failures.push(format!(
                "{}: diverged at register byte {offset:#x} (interp {:#04x}, jit {:#04x})",
                case.name, interp_regs[offset], jit_regs[offset]
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of the gated blocks diverged from the interpreter:\n  {}",
        failures.len(),
        failures.join("\n  ")
    );
    assert!(ran > 0, "no cases ran");
}

fn first_difference(a: &[u8], b: &[u8]) -> Option<usize> {
    a.iter().zip(b).position(|(x, y)| x != y)
}

/// Subpiece is verified on its own because the interpreter never executes a
/// raw `Op::Subpiece` — the lifter lowers it to a copy of `a.slice(offset,
/// out.size)`, and the interpreter's op table panics on the raw form. So the
/// JIT's `Op::Subpiece` is held to the interpreter running that exact lowered
/// equivalent over the same seed: two blocks, same result, compared byte for
/// byte across the whole register space.
#[test]
fn subpiece_matches_lowered_copy() {
    // (name, in_size, out_size, offset, seed). Every slice is in-bounds
    // (offset + out_size <= in_size); offsets are nonzero where it matters so
    // the byte shift is exercised, not just a low-slice.
    let specs: &[(&str, u8, u8, u8, u64)] = &[
        ("Subpiece u64[0..2]", 8, 2, 0, 0x1122_3344_5566_7788),
        ("Subpiece u64[2..6]", 8, 4, 2, 0x1122_3344_5566_7788),
        ("Subpiece u64[4..8]", 8, 4, 4, 0x1122_3344_5566_7788),
        ("Subpiece u64[6..8]", 8, 2, 6, 0xdead_beef_cafe_babe),
        ("Subpiece u64[7..8]", 8, 1, 7, 0xdead_beef_cafe_babe),
        ("Subpiece u32[1..2]", 4, 1, 1, 0xaabb_ccdd),
        ("Subpiece u32[3..4]", 4, 1, 3, 0xaabb_ccdd),
        ("Subpiece u32[2..4]", 4, 2, 2, 0x8000_00ff),
        ("Subpiece u16[1..2]", 2, 1, 1, 0x80ff),
    ];

    let mut failures = Vec::new();
    for &(name, in_size, out_size, offset, seed) in specs {
        let a = reg(2, in_size);
        let o = reg(1, out_size);

        // JIT runs the raw Subpiece.
        let mut jit_block = pcode::Block::new();
        jit_block.push((o, Op::Subpiece(offset), a));
        let jit_case = Case {
            name,
            seeds: vec![(a, seed)],
            block: jit_block,
        };

        // Interpreter runs the equivalent copy of the slice.
        let mut ref_block = pcode::Block::new();
        ref_block.push((o, Op::Copy, a.slice(offset, out_size)));
        let ref_case = Case {
            name,
            seeds: vec![(a, seed)],
            block: ref_block,
        };

        let Some(jit_regs) = jit(&jit_case) else {
            failures.push(format!("{name}: did not translate"));
            continue;
        };
        let interp_regs = interpret(&ref_case);
        if let Some(offset) = first_difference(&interp_regs, &jit_regs) {
            failures.push(format!(
                "{name}: diverged at register byte {offset:#x} (interp {:#04x}, jit {:#04x})",
                interp_regs[offset], jit_regs[offset]
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} Subpiece blocks diverged from the interpreter:\n  {}",
        failures.len(),
        failures.join("\n  ")
    );
}

// ---------------------------------------------------------------------------
// Guest-memory ops (Load/Store).
//
// These cross the wasm/host boundary, so they need a richer harness than the
// register-only gate above. The emitted `run` calls three host imports
// (`env.load`, `env.store`, `env.fault`); the load/store imports go through a
// real MMU on a second VM built exactly like the interpreter's, so a fault
// faults identically by construction. The gate compares the full register
// space, the guest region, the resume index (`None` vs the faulting
// instruction), and `cpu.exception` — everything the interpreter's mid-block
// stop produces.

use icicle_cpu::mem::{perm, Mapping};
use pcode::{Inputs, RAM_SPACE};

/// The state the memory imports act on: a VM providing the real MMU (guest
/// memory and the exception it sets on a fault), the register memory the load
/// import writes into, and the index a fault reported.
struct JitHost {
    vm: x64_engine::InterpVm,
    regs: Option<wasmi::Memory>,
    fault: Option<u32>,
}

/// A guest-memory gate case.
struct MemCase {
    name: &'static str,
    seeds: Vec<(VarNode, u64)>,
    block: pcode::Block,
    /// A region mapped read+write in both VMs and seeded with these bytes
    /// before the run; `None` maps nothing, so any access faults. The same
    /// bytes are compared back after the run.
    region: Option<(u64, Vec<u8>)>,
}

/// What a run produced, for the interpreter and the JIT to be compared on.
struct MemOut {
    regs: Vec<u8>,
    guest: Vec<u8>,
    fault: Option<usize>,
    exc: (u32, u64),
}

/// Maps a region read+write and seeds it, the same way in either VM's MMU.
fn map_region(mem: &mut icicle_cpu::mem::Mmu, base: u64, bytes: &[u8]) {
    let len = ((bytes.len() as u64 + 0xfff) / 0x1000).max(1) * 0x1000;
    mem.map_memory_len(
        base,
        len,
        Mapping {
            perm: perm::READ | perm::WRITE,
            value: 0,
        },
    );
    // Bypass the permission check for seeding; the mapping already carries RW.
    mem.write_bytes(base, bytes, perm::NONE)
        .expect("seed guest");
}

fn seed_regs_bytes(seeds: &[(VarNode, u64)]) -> Vec<u8> {
    let mut regs = vec![0u8; REG_SPACE_BYTES as usize];
    for &(var, value) in seeds {
        let off = x64_engine::jit::var_offset(var) as usize;
        let n = var.size as usize;
        regs[off..off + n].copy_from_slice(&value.to_le_bytes()[..n]);
    }
    regs
}

fn mem_interpret(case: &MemCase) -> MemOut {
    let mut vm = build_x64_vm(&ldef_path(), &EngineConfig::default()).expect("build vm");
    vm.cpu.regs.fill(0);
    if let Some((base, bytes)) = &case.region {
        map_region(&mut vm.cpu.mem, *base, bytes);
    }
    for &(var, value) in &case.seeds {
        let off = x64_engine::jit::var_offset(var) as usize;
        let n = var.size as usize;
        vm.cpu.regs.as_bytes_mut()[off..off + n].copy_from_slice(&value.to_le_bytes()[..n]);
    }
    // Safety: the block is well-formed p-code built below.
    let fault = unsafe { vm.cpu.interpret_block_unchecked(&case.block, 0) };
    let regs = vm.cpu.regs.as_bytes().to_vec();
    let guest = match &case.region {
        Some((base, bytes)) => {
            let mut buf = vec![0u8; bytes.len()];
            vm.cpu
                .mem
                .read_bytes(*base, &mut buf, perm::NONE)
                .expect("read guest");
            buf
        }
        None => vec![],
    };
    MemOut {
        regs,
        guest,
        fault,
        exc: (vm.cpu.exception.code, vm.cpu.exception.value),
    }
}

fn mem_jit(case: &MemCase) -> Option<MemOut> {
    let bytes = translate_block(&case.block)?;
    let engine = wasmi::Engine::default();
    let module = wasmi::Module::new(&engine, &bytes[..]).expect("emitted wasm is valid");

    let mut vm = build_x64_vm(&ldef_path(), &EngineConfig::default()).expect("build vm");
    vm.cpu.regs.fill(0);
    if let Some((base, region)) = &case.region {
        map_region(&mut vm.cpu.mem, *base, region);
    }

    let mut store = wasmi::Store::new(
        &engine,
        JitHost {
            vm,
            regs: None,
            fault: None,
        },
    );
    let mem_ty = wasmi::MemoryType::new(REG_SPACE_BYTES / 65536, None);
    let memory = wasmi::Memory::new(&mut store, mem_ty).expect("memory");
    store.data_mut().regs = Some(memory);
    memory
        .write(&mut store, 0, &seed_regs_bytes(&case.seeds))
        .expect("seed memory");

    let mut linker = wasmi::Linker::new(&engine);
    linker.define("env", "regs", memory).expect("define memory");

    // load(addr, dst_off, size) -> ok: read `size` bytes through the MMU and,
    // on success, write them into the register space at dst_off (little-endian
    // makes this a memcpy). On a fault, set the same exception the interpreter
    // would and return 0.
    linker
        .func_wrap(
            "env",
            "load",
            |mut caller: wasmi::Caller<JitHost>, addr: i64, dst_off: i32, size: i32| -> i32 {
                let addr = addr as u64;
                let res = {
                    let mem = &mut caller.data_mut().vm.cpu.mem;
                    match size {
                        1 => mem.read::<1>(addr, perm::READ).map(|b| b.to_vec()),
                        2 => mem.read::<2>(addr, perm::READ).map(|b| b.to_vec()),
                        4 => mem.read::<4>(addr, perm::READ).map(|b| b.to_vec()),
                        8 => mem.read::<8>(addr, perm::READ).map(|b| b.to_vec()),
                        _ => return 0,
                    }
                };
                match res {
                    Ok(loaded) => {
                        let regs = caller.data().regs.expect("regs");
                        regs.write(&mut caller, dst_off as usize, &loaded)
                            .expect("write regs");
                        1
                    }
                    Err(e) => {
                        let code = x64_engine::ExceptionCode::from_load_error(e) as u32;
                        let cpu = &mut caller.data_mut().vm.cpu;
                        cpu.exception.code = code;
                        cpu.exception.value = addr;
                        0
                    }
                }
            },
        )
        .expect("define load");

    // store(addr, value, size) -> ok: write the low `size` bytes of value
    // (little-endian) through the MMU.
    linker
        .func_wrap(
            "env",
            "store",
            |mut caller: wasmi::Caller<JitHost>, addr: i64, value: i64, size: i32| -> i32 {
                let addr = addr as u64;
                let v = value as u64;
                let cpu = &mut caller.data_mut().vm.cpu;
                let res = match size {
                    1 => cpu
                        .mem
                        .write::<1>(addr, (v as u8).to_le_bytes(), perm::WRITE),
                    2 => cpu
                        .mem
                        .write::<2>(addr, (v as u16).to_le_bytes(), perm::WRITE),
                    4 => cpu
                        .mem
                        .write::<4>(addr, (v as u32).to_le_bytes(), perm::WRITE),
                    8 => cpu.mem.write::<8>(addr, v.to_le_bytes(), perm::WRITE),
                    _ => return 0,
                };
                match res {
                    Ok(()) => 1,
                    Err(e) => {
                        let code = x64_engine::ExceptionCode::from_store_error(e) as u32;
                        cpu.exception.code = code;
                        cpu.exception.value = addr;
                        0
                    }
                }
            },
        )
        .expect("define store");

    linker
        .func_wrap(
            "env",
            "fault",
            |mut caller: wasmi::Caller<JitHost>, index: i32| {
                caller.data_mut().fault = Some(index as u32);
            },
        )
        .expect("define fault");

    let instance = linker
        .instantiate(&mut store, &module)
        .expect("instantiate")
        .start(&mut store)
        .expect("start");
    let run = instance
        .get_typed_func::<(), ()>(&store, "run")
        .expect("run export");
    run.call(&mut store, ()).expect("run");

    let mut regs = vec![0u8; REG_SPACE_BYTES as usize];
    memory.read(&store, 0, &mut regs).expect("read memory");
    let fault = store.data().fault.map(|i| i as usize);
    let exc = {
        let e = &store.data().vm.cpu.exception;
        (e.code, e.value)
    };
    let guest = match &case.region {
        Some((base, region)) => {
            let mut buf = vec![0u8; region.len()];
            store
                .data_mut()
                .vm
                .cpu
                .mem
                .read_bytes(*base, &mut buf, perm::NONE)
                .expect("read guest");
            buf
        }
        None => vec![],
    };
    Some(MemOut {
        regs,
        guest,
        fault,
        exc,
    })
}

/// A register-space varnode holding a memory address or a value operand.
fn v(id: i16, size: u8) -> VarNode {
    VarNode::new(id, size)
}

fn mem_cases() -> Vec<MemCase> {
    const BASE: u64 = 0x1_0000;
    let seed16: Vec<u8> = (0..16u8).map(|i| 0x11u8.wrapping_mul(i + 1)).collect();
    let mut cases = Vec::new();

    // Loads of each width, at nonzero offsets so the address arithmetic shows.
    for &(name, off, size) in &[
        ("Load u64", 0u64, 8u8),
        ("Load u32 at +4", 4, 4),
        ("Load u16 at +1", 1, 2),
        ("Load u8 at +7", 7, 1),
    ] {
        let (out, addr) = (v(1, size), v(5, 8));
        let mut block = pcode::Block::new();
        block.push((out, Op::Load(RAM_SPACE), addr));
        cases.push(MemCase {
            name,
            seeds: vec![(addr, BASE + off)],
            block,
            region: Some((BASE, seed16.clone())),
        });
    }

    // Load from an unmapped address: both sides fault ReadUnmapped at index 0,
    // leave the destination untouched, and set exception value = addr.
    {
        let (out, addr) = (v(1, 4), v(5, 8));
        let mut block = pcode::Block::new();
        block.push((out, Op::Load(RAM_SPACE), addr));
        cases.push(MemCase {
            name: "Load fault (unmapped)",
            seeds: vec![(out, 0xdead_beef), (addr, 0x9_0000)],
            block,
            region: None,
        });
    }

    // Stores of each width, including a constant operand (only reachable
    // because the value is passed on the stack, not by register offset).
    {
        let (addr, val) = (v(5, 8), v(6, 8));
        let mut block = pcode::Block::new();
        block.push((Op::Store(RAM_SPACE), Inputs::new(addr, val)));
        cases.push(MemCase {
            name: "Store u64",
            seeds: vec![(addr, BASE), (val, 0xcafe_f00d_1234_5678)],
            block,
            region: Some((BASE, vec![0u8; 32])),
        });
    }
    {
        let (addr, val) = (v(5, 8), v(6, 4));
        let mut block = pcode::Block::new();
        block.push((Op::Store(RAM_SPACE), Inputs::new(addr, val)));
        cases.push(MemCase {
            name: "Store u32 at +8",
            seeds: vec![(addr, BASE + 8), (val, 0xaabb_ccdd)],
            block,
            region: Some((BASE, vec![0xffu8; 32])),
        });
    }
    {
        let addr = v(5, 8);
        let mut block = pcode::Block::new();
        block.push((
            Op::Store(RAM_SPACE),
            Inputs::new(addr, pcode::Value::Const(0x00ff, 2)),
        ));
        cases.push(MemCase {
            name: "Store const u16",
            seeds: vec![(addr, BASE + 3)],
            block,
            region: Some((BASE, vec![0u8; 32])),
        });
    }
    {
        let (addr, val) = (v(5, 8), v(6, 4));
        let mut block = pcode::Block::new();
        block.push((Op::Store(RAM_SPACE), Inputs::new(addr, val)));
        cases.push(MemCase {
            name: "Store fault (unmapped)",
            seeds: vec![(addr, 0x9_0000), (val, 0x1234_5678)],
            block,
            region: None,
        });
    }

    // Load, transform, store back: a realistic straight-line sequence that
    // both reads and writes guest memory in one translated block.
    {
        let (tmp, addr) = (v(1, 8), v(5, 8));
        let mut block = pcode::Block::new();
        block.push((tmp, Op::Load(RAM_SPACE), addr));
        block.push((tmp, Op::IntAdd, tmp, pcode::Value::Const(0x1111_1111, 8)));
        block.push((Op::Store(RAM_SPACE), Inputs::new(addr, tmp)));
        cases.push(MemCase {
            name: "Load, add, store back",
            seeds: vec![(addr, BASE)],
            block,
            region: Some((BASE, seed16.clone())),
        });
    }

    // A fault partway through a block: the first op applies, the second (a
    // load from unmapped memory) faults. Both sides must apply instruction 0,
    // not instruction 1, and report the fault at index 1.
    {
        let (r1, r2, r3) = (v(1, 4), v(2, 4), v(3, 4));
        let (out, addr) = (v(4, 4), v(5, 8));
        let mut block = pcode::Block::new();
        block.push((r1, Op::IntAdd, r2, r3));
        block.push((out, Op::Load(RAM_SPACE), addr));
        cases.push(MemCase {
            name: "Fault at index 1 after an applied add",
            seeds: vec![
                (r2, 0x1000),
                (r3, 0x0337),
                (out, 0x4242_4242),
                (addr, 0x9_0000),
            ],
            block,
            region: None,
        });
    }

    cases
}

#[test]
fn memory_ops_match_the_interpreter() {
    let mut failures = Vec::new();
    let mut ran = 0;
    for case in mem_cases() {
        let Some(j) = mem_jit(&case) else {
            failures.push(format!("{}: did not translate", case.name));
            continue;
        };
        let i = mem_interpret(&case);
        ran += 1;
        if let Some(off) = first_difference(&i.regs, &j.regs) {
            failures.push(format!(
                "{}: registers diverged at byte {off:#x} (interp {:#04x}, jit {:#04x})",
                case.name, i.regs[off], j.regs[off]
            ));
        }
        if i.guest != j.guest {
            failures.push(format!(
                "{}: guest memory diverged (interp {:02x?}, jit {:02x?})",
                case.name, i.guest, j.guest
            ));
        }
        if i.fault != j.fault {
            failures.push(format!(
                "{}: resume index diverged (interp {:?}, jit {:?})",
                case.name, i.fault, j.fault
            ));
        }
        if i.exc != j.exc {
            failures.push(format!(
                "{}: exception diverged (interp {:#06x}/{:#x}, jit {:#06x}/{:#x})",
                case.name, i.exc.0, i.exc.1, j.exc.0, j.exc.1
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} memory blocks diverged from the interpreter:\n  {}",
        failures.len(),
        failures.join("\n  ")
    );
    assert!(ran > 0, "no cases ran");
}
