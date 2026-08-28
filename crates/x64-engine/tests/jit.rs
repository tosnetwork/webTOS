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

    // 128-bit (16-byte) move/widen/logic ops, done as two 8-byte lanes. Inputs
    // are seeded through their 8-byte slices (the seed value is a u64). The two
    // lanes carry different patterns so a lane mix-up or a dropped high lane
    // shows.
    let (o16, a16, b16) = (reg(1, 16), reg(2, 16), reg(3, 16));
    let (alo, ahi) = (a16.slice(0, 8), a16.slice(8, 8));
    let (blo, bhi) = (b16.slice(0, 8), b16.slice(8, 8));
    let seed16 = || {
        vec![
            (alo, 0x0f0f_f0f0_dead_beef_u64),
            (ahi, 0x1122_3344_5566_7788),
            (blo, 0xffff_0000_ffff_0000),
            (bhi, 0x00ff_00ff_00ff_00ff),
        ]
    };
    for (name, op) in [
        ("IntXor u128", Op::IntXor),
        ("IntOr u128", Op::IntOr),
        ("IntAnd u128", Op::IntAnd),
    ] {
        let mut block = pcode::Block::new();
        block.push((o16, op, a16, b16));
        out.push(Case {
            name,
            seeds: seed16(),
            block,
        });
    }
    {
        let mut block = pcode::Block::new();
        block.push((o16, Op::Copy, a16));
        out.push(Case {
            name: "Copy u128",
            seeds: seed16(),
            block,
        });
    }
    {
        let mut block = pcode::Block::new();
        block.push((o16, Op::IntNot, a16));
        out.push(Case {
            name: "IntNot u128",
            seeds: seed16(),
            block,
        });
    }
    // 128-bit multiply: the low lane is a plain product, the high lane needs the
    // schoolbook mulhi plus the a_lo*b_hi + a_hi*b_lo cross terms, so values with
    // both lanes set and a carry into the high lane catch a wrong mulhi or a
    // dropped term.
    for (name, alo_v, ahi_v, blo_v, bhi_v) in [
        // (2^64-1)^2: lo = 1, hi = 0xffff_ffff_ffff_fffe — a full mulhi carry.
        ("IntMul u128 all-ones squared", u64::MAX, 0, u64::MAX, 0),
        (
            "IntMul u128 both lanes",
            0x0f0f_f0f0_dead_beef,
            0x1122_3344_5566_7788,
            0xffff_0000_ffff_0000,
            0x00ff_00ff_00ff_00ff,
        ),
        // A product that overflows 128 bits, so truncation shows.
        (
            "IntMul u128 overflow",
            0xdead_beef_cafe_babe,
            0x8000_0000_0000_0000,
            0x2,
            0x1,
        ),
    ] {
        let mut block = pcode::Block::new();
        block.push((o16, Op::IntMul, a16, b16));
        out.push(Case {
            name,
            seeds: vec![(alo, alo_v), (ahi, ahi_v), (blo, blo_v), (bhi, bhi_v)],
            block,
        });
    }
    // 128-bit multiply in place: the output aliases an input, so a naive lane
    // store would corrupt an operand the high lane still needs.
    {
        let mut block = pcode::Block::new();
        block.push((a16, Op::IntMul, a16, b16));
        out.push(Case {
            name: "IntMul u128 in place",
            seeds: seed16(),
            block,
        });
    }
    // ZeroExtend/SignExtend a sub-16 input to 16 bytes; the input's top bit is
    // set so the sign fill of SignExtend is exercised (0xff high lane).
    for (name, op, in_size, av) in [
        ("ZeroExtend u32->u128", Op::ZeroExtend, 4u8, 0x8000_00ff_u64),
        (
            "ZeroExtend u64->u128",
            Op::ZeroExtend,
            8,
            0xdead_beef_8000_0001,
        ),
        ("SignExtend u32->u128", Op::SignExtend, 4, 0x8000_00ff),
        ("SignExtend u8->u128", Op::SignExtend, 1, 0xf3),
        (
            "SignExtend u64->u128",
            Op::SignExtend,
            8,
            0x8000_0000_0000_0001,
        ),
    ] {
        let a = reg(2, in_size);
        let mut block = pcode::Block::new();
        block.push((o16, op, a));
        out.push(Case {
            name,
            seeds: vec![(a, av)],
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
        .get_typed_func::<(i32, i32), ()>(&store, "run")
        .expect("run export");
    // Register-only blocks: tlb_base is unused, so 0.
    run.call(&mut store, (0, 0)).expect("run");

    let mut out = vec![0u8; REG_SPACE_BYTES as usize];
    memory.read(&store, 0, &mut out).expect("read memory");
    Some(out)
}

/// Runs a register-only block with the register file placed at `base` bytes
/// into a larger memory, supplying `env.regs_base = base`. This is the browser's
/// case, where the register file sits deep inside the engine's memory rather
/// than at offset 0. Returns the register window `[base, base + REG_SPACE)`.
fn jit_at_base(case: &Case, base: u32) -> Vec<u8> {
    let bytes = translate_block(&case.block).expect("translates");
    let engine = wasmi::Engine::default();
    let module = wasmi::Module::new(&engine, &bytes[..]).expect("valid wasm");
    let mut store = wasmi::Store::new(&engine, ());

    let total = base + REG_SPACE_BYTES;
    let pages = total.div_ceil(65536);
    let memory = wasmi::Memory::new(&mut store, wasmi::MemoryType::new(pages, None)).expect("mem");

    // Seed each varnode at base + its offset.
    let mut regs = vec![0u8; REG_SPACE_BYTES as usize];
    for &(var, value) in &case.seeds {
        let off = x64_engine::jit::var_offset(var) as usize;
        let n = var.size as usize;
        regs[off..off + n].copy_from_slice(&value.to_le_bytes()[..n]);
    }
    memory
        .write(&mut store, base as usize, &regs)
        .expect("seed");

    let mut linker = wasmi::Linker::new(&engine);
    linker.define("env", "regs", memory).expect("define memory");
    let instance = linker
        .instantiate(&mut store, &module)
        .expect("instantiate")
        .start(&mut store)
        .expect("start");
    let run = instance
        .get_typed_func::<(i32, i32), ()>(&store, "run")
        .expect("run export");
    // Register-only blocks: tlb_base is unused, so 0.
    run.call(&mut store, (base as i32, 0)).expect("run");

    let mut out = vec![0u8; REG_SPACE_BYTES as usize];
    memory.read(&store, base as usize, &mut out).expect("read");
    out
}

#[test]
fn translated_blocks_run_at_a_nonzero_base() {
    // A base that is not page-aligned relative to the register offsets, to catch
    // an address computed with the wrong term.
    let base = 0x4_1230;
    let mut failures = Vec::new();
    for case in cases() {
        let interp = interpret(&case);
        let jit = jit_at_base(&case, base);
        if let Some(off) = first_difference(&interp, &jit) {
            failures.push(format!(
                "{}: diverged at register byte {off:#x} (interp {:#04x}, jit {:#04x})",
                case.name, interp[off], jit[off]
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "blocks run at base {base:#x} diverged from the interpreter:\n  {}",
        failures.join("\n  ")
    );
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

/// Bytes of an `icicle_mem::tlb::TranslationCache` image: two `[TLBEntry; 1024]`
/// arrays (read then write), 16 bytes each. Placed after the register file in
/// the wasm memory so the inline fast path can read it at `tlb_base`.
const TLB_BYTES: u32 = 2 * 1024 * 16;

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
    // The memory holds the register file, then an all-invalid TLB image so the
    // inline memory fast path always misses and defers to the host callbacks —
    // this harness is the slow-path reference (the fast path is exercised warm by
    // the `fastmem` gate below). `tlb_base` points at that TLB region; filling it
    // with 0xFF makes every tag `u64::MAX` (invalid), so the tag guard never
    // matches and the page math (which could read out of bounds) never runs.
    let tlb_base = REG_SPACE_BYTES;
    let total = REG_SPACE_BYTES + TLB_BYTES;
    let mem_ty = wasmi::MemoryType::new(total.div_ceil(65536), None);
    let memory = wasmi::Memory::new(&mut store, mem_ty).expect("memory");
    store.data_mut().regs = Some(memory);
    memory
        .write(&mut store, 0, &seed_regs_bytes(&case.seeds))
        .expect("seed memory");
    memory
        .write(
            &mut store,
            tlb_base as usize,
            &vec![0xffu8; TLB_BYTES as usize],
        )
        .expect("invalidate tlb");

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

    // raise(code, value, index): set the exception (re-canonicalised through
    // from_u32, as the interpreter does) and record the resume index.
    linker
        .func_wrap(
            "env",
            "raise",
            |mut caller: wasmi::Caller<JitHost>, code: i32, value: i64, index: i32| {
                let host = caller.data_mut();
                host.vm.cpu.exception.code =
                    x64_engine::ExceptionCode::from_u32(code as u32) as u32;
                host.vm.cpu.exception.value = value as u64;
                host.fault = Some(index as u32);
            },
        )
        .expect("define raise");

    let instance = linker
        .instantiate(&mut store, &module)
        .expect("instantiate")
        .start(&mut store)
        .expect("start");
    let run = instance
        .get_typed_func::<(i32, i32), ()>(&store, "run")
        .expect("run export");
    run.call(&mut store, (0, tlb_base as i32)).expect("run");

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

    // Division: normal quotients/remainders across widths and signedness, plus
    // the two cases the interpreter raises on — a zero divisor and the signed
    // INT_MIN / -1 overflow. The output is seeded with a sentinel so a fault
    // that must write nothing shows if it wrongly writes.
    for &(name, op, size, av, bv) in &[
        ("IntDiv u32", Op::IntDiv, 4u8, 100u64, 7u64),
        ("IntRem u32", Op::IntRem, 4, 100, 7),
        ("IntDiv u8", Op::IntDiv, 1, 200, 7),
        ("IntDiv u64", Op::IntDiv, 8, 0x1_0000_0003, 2),
        (
            "IntSignedDiv i32",
            Op::IntSignedDiv,
            4,
            (-100i32) as u32 as u64,
            7,
        ),
        (
            "IntSignedRem i32",
            Op::IntSignedRem,
            4,
            (-100i32) as u32 as u64,
            7,
        ),
        (
            "IntSignedDiv i8",
            Op::IntSignedDiv,
            1,
            (-100i8) as u8 as u64,
            7,
        ),
        (
            "IntSignedDiv i64 neg",
            Op::IntSignedDiv,
            8,
            (-1000i64) as u64,
            3,
        ),
    ] {
        let (o, a, b) = (v(1, size), v(5, size), v(6, size));
        let mut block = pcode::Block::new();
        block.push((o, op, a, b));
        cases.push(MemCase {
            name,
            seeds: vec![(o, 0xdead_beef_dead_beef), (a, av), (b, bv)],
            block,
            region: None,
        });
    }
    for &(name, op, size, av, bv) in &[
        ("IntDiv by zero", Op::IntDiv, 4u8, 100u64, 0u64),
        ("IntRem by zero u64", Op::IntRem, 8, 100, 0),
        (
            "IntSignedDiv INT_MIN/-1",
            Op::IntSignedDiv,
            4,
            i32::MIN as u32 as u64,
            (-1i32) as u32 as u64,
        ),
        (
            "IntSignedRem INT_MIN/-1",
            Op::IntSignedRem,
            8,
            i64::MIN as u64,
            (-1i64) as u64,
        ),
        (
            "IntSignedDiv i8 INT_MIN/-1",
            Op::IntSignedDiv,
            1,
            i8::MIN as u8 as u64,
            (-1i8) as u8 as u64,
        ),
    ] {
        let (o, a, b) = (v(1, size), v(5, size), v(6, size));
        let mut block = pcode::Block::new();
        block.push((o, op, a, b));
        cases.push(MemCase {
            name,
            seeds: vec![(o, 0xdead_beef_dead_beef), (a, av), (b, bv)],
            block,
            region: None,
        });
    }

    // Exception raises a dynamic code/value and stops; Invalid raises
    // InvalidInstruction. Both are compared on the resume index and the
    // exception the interpreter sets.
    {
        let mut block = pcode::Block::new();
        block.push((Op::Exception, (0x1001u32, 0x1234u64)));
        cases.push(MemCase {
            name: "Exception op",
            seeds: vec![],
            block,
            region: None,
        });
    }
    {
        let mut block = pcode::Block::new();
        block.push(Op::Invalid);
        cases.push(MemCase {
            name: "Invalid op",
            seeds: vec![],
            block,
            region: None,
        });
    }

    // 128-bit load/store (movdqa-shaped): each is two 8-byte guest accesses,
    // low half at addr and high at addr + 8, matching the interpreter.
    {
        let (out, addr) = (v(1, 16), v(5, 8));
        let mut block = pcode::Block::new();
        block.push((out, Op::Load(RAM_SPACE), addr));
        cases.push(MemCase {
            name: "Load u128",
            seeds: vec![(addr, BASE)],
            block,
            region: Some((BASE, seed16.clone())),
        });
    }
    {
        let (addr, val) = (v(5, 8), v(6, 16));
        let mut block = pcode::Block::new();
        block.push((Op::Store(RAM_SPACE), Inputs::new(addr, val)));
        cases.push(MemCase {
            name: "Store u128",
            seeds: vec![
                (addr, BASE),
                (val.slice(0, 8), 0xdead_beef_cafe_babe),
                (val.slice(8, 8), 0x0011_2233_4455_6677),
            ],
            block,
            region: Some((BASE, vec![0u8; 32])),
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

// ---------------------------------------------------------------------------
// Float ops (sizes 4 and 8).
//
// These are register-only, so they reuse `jit()`/`interpret()` above. The one
// difference is the comparison: a NaN *result* can carry a different payload
// under a native interpreter build (Rust f64) than under wasm, even though a
// wasm interpreter build — the real target — computes them with the same wasm
// ops and agrees bit for bit. So the output slot of a float-producing op is
// compared NaN-aware (both-NaN is a match); everything else, including every
// boolean result, is compared exactly.

/// A float gate case: like the register cases, plus which varnode is the
/// output and whether that output is itself a float (so a NaN there is
/// compared leniently) rather than a boolean (compared exactly).
struct FloatCase {
    name: &'static str,
    seeds: Vec<(VarNode, u64)>,
    block: pcode::Block,
    out: VarNode,
    out_is_float: bool,
}

fn f32b(x: f32) -> u64 {
    x.to_bits() as u64
}
fn f64b(x: f64) -> u64 {
    x.to_bits()
}

fn is_nan_bits(bytes: &[u8], size: u8) -> bool {
    match size {
        4 => f32::from_bits(u32::from_le_bytes(bytes.try_into().unwrap())).is_nan(),
        8 => f64::from_bits(u64::from_le_bytes(bytes.try_into().unwrap())).is_nan(),
        _ => false,
    }
}

/// `None` if the two register spaces match (NaN-aware within a float output
/// slot), else a description of the first divergence.
fn float_diff(interp: &[u8], jit: &[u8], case: &FloatCase) -> Option<String> {
    let off = x64_engine::jit::var_offset(case.out) as usize;
    let n = case.out.size as usize;
    for i in 0..interp.len() {
        if (off..off + n).contains(&i) {
            continue;
        }
        if interp[i] != jit[i] {
            return Some(format!(
                "byte {i:#x}: interp {:#04x} jit {:#04x}",
                interp[i], jit[i]
            ));
        }
    }
    let (ib, jb) = (&interp[off..off + n], &jit[off..off + n]);
    if ib == jb {
        return None;
    }
    if case.out_is_float && is_nan_bits(ib, case.out.size) && is_nan_bits(jb, case.out.size) {
        return None;
    }
    Some(format!("output slot: interp {ib:02x?} jit {jb:02x?}"))
}

fn float_cases() -> Vec<FloatCase> {
    let mut out = Vec::new();

    let binary = |name, op, size, av: u64, bv: u64, out_is_float| {
        let (o, a, b) = (
            reg(1, if out_is_float { size } else { 1 }),
            reg(2, size),
            reg(3, size),
        );
        let mut block = pcode::Block::new();
        block.push((o, op, a, b));
        FloatCase {
            name,
            seeds: vec![(a, av), (b, bv)],
            block,
            out: o,
            out_is_float,
        }
    };
    let unary = |name, op, size, av: u64, out_is_float| {
        let (o, a) = (reg(1, if out_is_float { size } else { 1 }), reg(2, size));
        let mut block = pcode::Block::new();
        block.push((o, op, a));
        FloatCase {
            name,
            seeds: vec![(a, av)],
            block,
            out: o,
            out_is_float,
        }
    };

    // Arithmetic on finite operands: exact results.
    out.push(binary(
        "FloatAdd f64",
        Op::FloatAdd,
        8,
        f64b(1.5),
        f64b(2.25),
        true,
    ));
    out.push(binary(
        "FloatAdd f32",
        Op::FloatAdd,
        4,
        f32b(1.5),
        f32b(2.25),
        true,
    ));
    out.push(binary(
        "FloatSub f64",
        Op::FloatSub,
        8,
        f64b(10.0),
        f64b(3.5),
        true,
    ));
    out.push(binary(
        "FloatMul f64",
        Op::FloatMul,
        8,
        f64b(2.5),
        f64b(4.0),
        true,
    ));
    out.push(binary(
        "FloatMul f32",
        Op::FloatMul,
        4,
        f32b(2.5),
        f32b(4.0),
        true,
    ));
    out.push(binary(
        "FloatDiv f64",
        Op::FloatDiv,
        8,
        f64b(7.0),
        f64b(2.0),
        true,
    ));
    out.push(binary(
        "FloatDiv f32",
        Op::FloatDiv,
        4,
        f32b(7.0),
        f32b(2.0),
        true,
    ));

    // Arithmetic producing NaN: compared NaN-aware.
    out.push(binary(
        "FloatDiv 0/0 f64",
        Op::FloatDiv,
        8,
        f64b(0.0),
        f64b(0.0),
        true,
    ));
    out.push(binary(
        "FloatAdd inf+-inf f64",
        Op::FloatAdd,
        8,
        f64b(f64::INFINITY),
        f64b(f64::NEG_INFINITY),
        true,
    ));
    out.push(binary(
        "FloatMul 0*inf f32",
        Op::FloatMul,
        4,
        f32b(0.0),
        f32b(f32::INFINITY),
        true,
    ));

    // Unary on finite operands.
    out.push(unary(
        "FloatNegate f64",
        Op::FloatNegate,
        8,
        f64b(3.0),
        true,
    ));
    out.push(unary(
        "FloatNegate f32",
        Op::FloatNegate,
        4,
        f32b(-3.0),
        true,
    ));
    out.push(unary("FloatAbs f64", Op::FloatAbs, 8, f64b(-3.5), true));
    out.push(unary("FloatSqrt f64", Op::FloatSqrt, 8, f64b(2.0), true));
    out.push(unary("FloatSqrt f32", Op::FloatSqrt, 4, f32b(4.0), true));
    out.push(unary("FloatCeil f64 +", Op::FloatCeil, 8, f64b(2.3), true));
    out.push(unary("FloatCeil f64 -", Op::FloatCeil, 8, f64b(-2.3), true));
    out.push(unary(
        "FloatFloor f64 +",
        Op::FloatFloor,
        8,
        f64b(2.7),
        true,
    ));
    out.push(unary(
        "FloatFloor f32 -",
        Op::FloatFloor,
        4,
        f32b(-2.3),
        true,
    ));
    // Unary producing NaN.
    out.push(unary(
        "FloatSqrt -1 f64",
        Op::FloatSqrt,
        8,
        f64b(-1.0),
        true,
    ));

    // Comparisons: boolean output, exact.
    out.push(binary(
        "FloatEqual eq f64",
        Op::FloatEqual,
        8,
        f64b(2.0),
        f64b(2.0),
        false,
    ));
    out.push(binary(
        "FloatEqual ne f64",
        Op::FloatEqual,
        8,
        f64b(2.0),
        f64b(3.0),
        false,
    ));
    out.push(binary(
        "FloatNotEqual f64",
        Op::FloatNotEqual,
        8,
        f64b(1.0),
        f64b(2.0),
        false,
    ));
    out.push(binary(
        "FloatLess lt f64",
        Op::FloatLess,
        8,
        f64b(1.0),
        f64b(2.0),
        false,
    ));
    out.push(binary(
        "FloatLess ge f64",
        Op::FloatLess,
        8,
        f64b(2.0),
        f64b(1.0),
        false,
    ));
    out.push(binary(
        "FloatLessEqual f64",
        Op::FloatLessEqual,
        8,
        f64b(2.0),
        f64b(2.0),
        false,
    ));
    out.push(binary(
        "FloatLess f32",
        Op::FloatLess,
        4,
        f32b(1.0),
        f32b(2.0),
        false,
    ));
    // NaN comparisons: all false but not-equal.
    out.push(binary(
        "FloatEqual NaN f64",
        Op::FloatEqual,
        8,
        f64b(f64::NAN),
        f64b(2.0),
        false,
    ));
    out.push(binary(
        "FloatNotEqual NaN f64",
        Op::FloatNotEqual,
        8,
        f64b(f64::NAN),
        f64b(2.0),
        false,
    ));
    out.push(binary(
        "FloatLess NaN f64",
        Op::FloatLess,
        8,
        f64b(f64::NAN),
        f64b(2.0),
        false,
    ));

    // IsNan: boolean output.
    out.push(unary(
        "FloatIsNan NaN f64",
        Op::FloatIsNan,
        8,
        f64b(f64::NAN),
        false,
    ));
    out.push(unary(
        "FloatIsNan finite f64",
        Op::FloatIsNan,
        8,
        f64b(1.0),
        false,
    ));
    out.push(unary(
        "FloatIsNan NaN f32",
        Op::FloatIsNan,
        4,
        f32b(f32::NAN),
        false,
    ));

    // Conversions: input width and output width differ, so these are built
    // explicitly rather than through the same-width closures.
    let conv = |name, op, in_size: u8, out_size: u8, av: u64, out_is_float| {
        let (o, a) = (reg(1, out_size), reg(2, in_size));
        let mut block = pcode::Block::new();
        block.push((o, op, a));
        FloatCase {
            name,
            seeds: vec![(a, av)],
            block,
            out: o,
            out_is_float,
        }
    };

    // Signed int -> float.
    out.push(conv(
        "IntToFloat i32->f64",
        Op::IntToFloat,
        4,
        8,
        (-5i32) as u32 as u64,
        true,
    ));
    out.push(conv(
        "IntToFloat i32->f32",
        Op::IntToFloat,
        4,
        4,
        (-5i32) as u32 as u64,
        true,
    ));
    out.push(conv(
        "IntToFloat i8->f64",
        Op::IntToFloat,
        1,
        8,
        (-3i8) as u8 as u64,
        true,
    ));
    out.push(conv(
        "IntToFloat i64->f64",
        Op::IntToFloat,
        8,
        8,
        (-1_000_000i64) as u64,
        true,
    ));
    out.push(conv(
        "IntToFloat i64->f32 round",
        Op::IntToFloat,
        8,
        4,
        0x0020_0000_0000_0001,
        true,
    ));
    // Unsigned int -> float.
    out.push(conv(
        "UintToFloat u32->f64",
        Op::UintToFloat,
        4,
        8,
        4_000_000_000,
        true,
    ));
    out.push(conv(
        "UintToFloat u64->f64 round",
        Op::UintToFloat,
        8,
        8,
        u64::MAX,
        true,
    ));
    out.push(conv(
        "UintToFloat u8->f32",
        Op::UintToFloat,
        1,
        4,
        200,
        true,
    ));
    // float -> float: promote, demote, identity.
    out.push(conv(
        "FloatToFloat f32->f64",
        Op::FloatToFloat,
        4,
        8,
        f32b(1.5),
        true,
    ));
    out.push(conv(
        "FloatToFloat f64->f32",
        Op::FloatToFloat,
        8,
        4,
        f64b(0.1),
        true,
    ));
    out.push(conv(
        "FloatToFloat f32->f32",
        Op::FloatToFloat,
        4,
        4,
        f32b(-2.5),
        true,
    ));
    out.push(conv(
        "FloatToFloat f64->f64",
        Op::FloatToFloat,
        8,
        8,
        f64b(1e100),
        true,
    ));
    // float -> signed int (saturating, exact integer output).
    out.push(conv(
        "FloatToInt f64->i32",
        Op::FloatToInt,
        8,
        4,
        f64b(3.7),
        false,
    ));
    out.push(conv(
        "FloatToInt f64->i32 neg",
        Op::FloatToInt,
        8,
        4,
        f64b(-3.7),
        false,
    ));
    out.push(conv(
        "FloatToInt f64->i32 saturate",
        Op::FloatToInt,
        8,
        4,
        f64b(1e30),
        false,
    ));
    out.push(conv(
        "FloatToInt NaN->i32",
        Op::FloatToInt,
        8,
        4,
        f64b(f64::NAN),
        false,
    ));
    out.push(conv(
        "FloatToInt f32->i64",
        Op::FloatToInt,
        4,
        8,
        f32b(3.7),
        false,
    ));
    out.push(conv(
        "FloatToInt f64->i64 saturate",
        Op::FloatToInt,
        8,
        8,
        f64b(1e300),
        false,
    ));

    out
}

#[test]
fn float_ops_match_the_interpreter() {
    let mut failures = Vec::new();
    let mut ran = 0;
    for case in float_cases() {
        // Reuse the register-only harness: float ops touch no guest memory.
        let reg_case = Case {
            name: case.name,
            seeds: case.seeds.clone(),
            block: clone_block(&case.block),
        };
        let Some(jit_regs) = jit(&reg_case) else {
            failures.push(format!("{}: did not translate", case.name));
            continue;
        };
        let interp_regs = interpret(&reg_case);
        ran += 1;
        if let Some(why) = float_diff(&interp_regs, &jit_regs, &case) {
            failures.push(format!("{}: {why}", case.name));
        }
    }
    assert!(
        failures.is_empty(),
        "{} float blocks diverged from the interpreter:\n  {}",
        failures.len(),
        failures.join("\n  ")
    );
    assert!(ran > 0, "no cases ran");
}

/// A shallow clone of a block's instructions, so a `FloatCase` can be run
/// through the register-only `Case` harness without moving its block.
fn clone_block(block: &pcode::Block) -> pcode::Block {
    let mut out = pcode::Block::new();
    for inst in &block.instructions {
        out.instructions.push(*inst);
    }
    out
}

// ---------------------------------------------------------------------------
// Inline softmmu fast-path gate (`fastmem`).
//
// The whole risk of the fast path is silent corruption: it reads icicle's live
// TLB and the resolved guest page directly, in wasm, and only a *wrong* fast
// path — a bad tag compare, a bad permission mask, a stale mapping — would
// diverge from the host callback while still producing a plausible answer. So
// this gate is brutal about it.
//
// The browser shares one linear memory, so the compiled block reads the *same*
// TLB and pages the engine writes; the Node gates (`web/test_jit_run.mjs`
// memory scan, region-compiled) exercise that literal wiring against the real
// interpreter. This native harness reproduces that single-memory model so the
// *emitted fast-path wasm* can be held to the interpreter here too: one wasm
// memory holds the register file, then a TLB image, then a pool of guest-page
// images. The load/store host callbacks route through a real `Cpu` (so faults
// are the engine's real faults) and, on success, mirror the touched page into
// the pool and fill the in-wasm TLB — exactly as `Mmu::read`/`write` fill the
// live TLB in the browser. A host-call counter proves the fast path actually
// fires: once a page is warm, re-running the block calls the host zero more
// times.
//
// What each test proves:
//   - hit + counter: a warm access is served inline and matches the
//     interpreter, and the host is not called again (so it is not silently
//     always-slow).
//   - cross-page: an 8-byte straddling access always defers to the host and
//     matches.
//   - coherence: after the mapping changes and the (live) TLB entry is
//     invalidated — as icicle does on unmap/mprotect — the next access does NOT
//     use the stale translation; it faults exactly as the interpreter does.
//   - permission: when the resolved page's perm bytes lose a required bit, the
//     fast path defers and the host raises the exact fault.
// Breaking the tag compare reddens the coherence test; dropping INIT from the
// perm mask reddens the permission test (the discrimination checks in the task
// report).

/// Byte offset of the TLB image within the fast-path harness memory (right after
/// the register file).
const FASTMEM_TLB_BASE: u32 = REG_SPACE_BYTES;
/// Byte offset of the guest-page image pool (after the TLB image).
const FASTMEM_POOL_BASE: u32 = REG_SPACE_BYTES + TLB_BYTES;
/// Bytes per page image: `data[4096]` then `perm[4096]`, matching `PageData`.
const FASTMEM_PAGE_IMG: u32 = 8192;
/// Page-image slots the pool holds (the gate's blocks touch only a few pages).
const FASTMEM_MAX_SLOTS: u32 = 8;
/// The TLB tag mask (`addr & 0xFFFF_FFFF_FFC0_0000`).
const FASTMEM_TAG_MASK: u64 = 0xFFFF_FFFF_FFC0_0000;

/// State the fast-path harness callbacks act on: a real VM (guest memory and the
/// exception a fault sets), the wasm memory the register file / TLB / page pool
/// live in, the resume index a fault reports, the page→slot table, and the count
/// of host callbacks (which stops growing once the fast path is warm).
struct FastHost {
    vm: x64_engine::InterpVm,
    memory: Option<wasmi::Memory>,
    fault: Option<u32>,
    pages: Vec<(u64, u32)>,
    next_slot: u32,
    host_calls: u64,
}

/// Mirrors the resident guest page containing `page_addr` (data + perm) into its
/// pool slot and fills the in-wasm TLB entry so a subsequent access to it is
/// served inline — the harness's stand-in for `Mmu::read`/`write` caching a
/// translation. A store re-mirrors the page (which now carries the write and its
/// `INIT` bits) and fills the WRITE array; a load fills the READ array.
fn fastmem_ensure_page(caller: &mut wasmi::Caller<FastHost>, page_addr: u64, is_write: bool) {
    // Find or allocate the slot for this page.
    let slot = {
        let host = caller.data_mut();
        match host.pages.iter().find(|(pa, _)| *pa == page_addr) {
            Some((_, s)) => *s,
            None => {
                let s = host.next_slot;
                assert!(s < FASTMEM_MAX_SLOTS, "fastmem page pool exhausted");
                host.next_slot += 1;
                host.pages.push((page_addr, s));
                s
            }
        }
    };

    // Copy the resident page's data+perm out of the real MMU.
    let mut buf = [0u8; FASTMEM_PAGE_IMG as usize];
    {
        let mem = &mut caller.data_mut().vm.cpu.mem;
        if let Some(idx) = mem.get_physical_index(page_addr) {
            let pd = mem.get_physical(idx).data();
            buf[..4096].copy_from_slice(&pd.data);
            buf[4096..].copy_from_slice(&pd.perm);
        }
    }
    let memory = caller.data().memory.expect("memory");
    let slot_off = FASTMEM_POOL_BASE as usize + slot as usize * FASTMEM_PAGE_IMG as usize;
    memory
        .write(&mut *caller, slot_off, &buf)
        .expect("mirror page");

    // Fill the TLB entry: tag = page tag, guest_to_host_offset = image base -
    // page base, so `addr + g2h` lands on the addressed byte in the image.
    let index = ((page_addr >> 12) & 0x3ff) as usize;
    let tag = page_addr & FASTMEM_TAG_MASK;
    let g2h = (slot_off as u64).wrapping_sub(page_addr);
    let array = if is_write { 0x4000 } else { 0 };
    let entry_off = FASTMEM_TLB_BASE as usize + array + index * 16;
    let mut entry = [0u8; 16];
    entry[..8].copy_from_slice(&tag.to_le_bytes());
    entry[8..].copy_from_slice(&g2h.to_le_bytes());
    memory
        .write(&mut *caller, entry_off, &entry)
        .expect("tlb entry");
}

/// The fast-path harness: one wasm memory (register file + TLB + page pool) plus
/// a real VM the callbacks route through. Built around one translated block that
/// it runs repeatedly, warming the TLB after the first run.
struct FastRunner {
    store: wasmi::Store<FastHost>,
    memory: wasmi::Memory,
    run: wasmi::TypedFunc<(i32, i32), ()>,
}

impl FastRunner {
    /// Builds the harness for `block`, mapping and seeding `region` (base, bytes)
    /// in the VM and seeding the register file. Returns `None` if the block does
    /// not translate.
    fn new(
        block: &pcode::Block,
        seeds: &[(VarNode, u64)],
        region: &[(u64, Vec<u8>)],
    ) -> Option<Self> {
        let bytes = translate_block(block)?;
        let engine = wasmi::Engine::default();
        let module = wasmi::Module::new(&engine, &bytes[..]).expect("emitted wasm is valid");

        let mut vm = build_x64_vm(&ldef_path(), &EngineConfig::default()).expect("build vm");
        vm.cpu.regs.fill(0);
        for (base, data) in region {
            map_region(&mut vm.cpu.mem, *base, data);
        }

        let mut store = wasmi::Store::new(
            &engine,
            FastHost {
                vm,
                memory: None,
                fault: None,
                pages: Vec::new(),
                next_slot: 0,
                host_calls: 0,
            },
        );
        let total = FASTMEM_POOL_BASE + FASTMEM_MAX_SLOTS * FASTMEM_PAGE_IMG;
        let mem_ty = wasmi::MemoryType::new(total.div_ceil(65536), None);
        let memory = wasmi::Memory::new(&mut store, mem_ty).expect("memory");
        store.data_mut().memory = Some(memory);
        // Seed the register file; start the TLB all-invalid (0xFF tags).
        memory
            .write(&mut store, 0, &seed_regs_bytes(seeds))
            .expect("seed regs");
        memory
            .write(
                &mut store,
                FASTMEM_TLB_BASE as usize,
                &vec![0xffu8; TLB_BYTES as usize],
            )
            .expect("invalidate tlb");

        let mut linker = wasmi::Linker::new(&engine);
        linker.define("env", "regs", memory).expect("define memory");
        linker
            .func_wrap(
                "env",
                "load",
                |mut caller: wasmi::Caller<FastHost>, addr: i64, dst_off: i32, size: i32| -> i32 {
                    caller.data_mut().host_calls += 1;
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
                            fastmem_ensure_page(&mut caller, addr & !0xfff, false);
                            let regs = caller.data().memory.expect("memory");
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
        linker
            .func_wrap(
                "env",
                "store",
                |mut caller: wasmi::Caller<FastHost>, addr: i64, value: i64, size: i32| -> i32 {
                    caller.data_mut().host_calls += 1;
                    let addr = addr as u64;
                    let v = value as u64;
                    let res = {
                        let mem = &mut caller.data_mut().vm.cpu.mem;
                        match size {
                            1 => mem.write::<1>(addr, (v as u8).to_le_bytes(), perm::WRITE),
                            2 => mem.write::<2>(addr, (v as u16).to_le_bytes(), perm::WRITE),
                            4 => mem.write::<4>(addr, (v as u32).to_le_bytes(), perm::WRITE),
                            8 => mem.write::<8>(addr, v.to_le_bytes(), perm::WRITE),
                            _ => return 0,
                        }
                    };
                    match res {
                        Ok(()) => {
                            fastmem_ensure_page(&mut caller, addr & !0xfff, true);
                            1
                        }
                        Err(e) => {
                            let code = x64_engine::ExceptionCode::from_store_error(e) as u32;
                            let cpu = &mut caller.data_mut().vm.cpu;
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
                |mut caller: wasmi::Caller<FastHost>, index: i32| {
                    caller.data_mut().fault = Some(index as u32);
                },
            )
            .expect("define fault");
        linker
            .func_wrap(
                "env",
                "raise",
                |mut caller: wasmi::Caller<FastHost>, code: i32, value: i64, index: i32| {
                    let cpu = &mut caller.data_mut().vm.cpu;
                    cpu.exception.code = x64_engine::ExceptionCode::from_u32(code as u32) as u32;
                    cpu.exception.value = value as u64;
                    caller.data_mut().fault = Some(index as u32);
                },
            )
            .expect("define raise");

        let instance = linker
            .instantiate(&mut store, &module)
            .expect("instantiate")
            .start(&mut store)
            .expect("start");
        let run = instance
            .get_typed_func::<(i32, i32), ()>(&store, "run")
            .expect("run export");

        Some(Self { store, memory, run })
    }

    /// Runs the block once against the shared memory. Returns how many host
    /// callbacks it made and the fault index it stopped at, if any.
    fn run_once(&mut self) -> (u64, Option<u32>) {
        self.store.data_mut().fault = None;
        let before = self.store.data().host_calls;
        self.run
            .call(&mut self.store, (0, FASTMEM_TLB_BASE as i32))
            .expect("run");
        let calls = self.store.data().host_calls - before;
        (calls, self.store.data().fault)
    }

    fn mem(&mut self) -> &mut icicle_cpu::mem::Mmu {
        &mut self.store.data_mut().vm.cpu.mem
    }

    fn exception(&self) -> (u32, u64) {
        let e = &self.store.data().vm.cpu.exception;
        (e.code, e.value)
    }

    /// Reads back the register file window `[0, REG_SPACE)`.
    fn regs(&self) -> Vec<u8> {
        let mut out = vec![0u8; REG_SPACE_BYTES as usize];
        self.memory
            .read(&self.store, 0, &mut out)
            .expect("read regs");
        out
    }

    /// Flushes each mirrored page's data back into the real MMU (so a fast-path
    /// store, which wrote only the image, is reflected), then reads the region.
    fn guest(&mut self, base: u64, len: usize) -> Vec<u8> {
        let pages: Vec<(u64, u32)> = self.store.data().pages.clone();
        for (page_addr, slot) in pages {
            let mut data = vec![0u8; 4096];
            let off = FASTMEM_POOL_BASE as usize + slot as usize * FASTMEM_PAGE_IMG as usize;
            self.memory
                .read(&self.store, off, &mut data)
                .expect("read image");
            // Best-effort: an unmapped page (coherence test) cannot be written.
            let _ = self
                .store
                .data_mut()
                .vm
                .cpu
                .mem
                .write_bytes(page_addr, &data, perm::NONE);
        }
        let mut buf = vec![0u8; len];
        self.store
            .data_mut()
            .vm
            .cpu
            .mem
            .read_bytes(base, &mut buf, perm::NONE)
            .expect("read guest");
        buf
    }

    /// Marks a warm TLB entry invalid (as icicle's flush does on unmap/mprotect),
    /// in both arrays, so the fast path can no longer use its stale translation.
    fn invalidate_tlb(&mut self, addr: u64) {
        let index = ((addr >> 12) & 0x3ff) as usize;
        for array in [0usize, 0x4000] {
            let off = FASTMEM_TLB_BASE as usize + array + index * 16;
            self.memory
                .write(&mut self.store, off, &[0xffu8; 16])
                .expect("invalidate tlb");
        }
    }

    /// ANDs the perm bytes of the mirrored page for `addr` over `len` with
    /// `keep`, to simulate a permission change on an already-resident page (the
    /// TLB entry stays valid; only the page's perms change).
    fn clear_mirror_perm(&mut self, addr: u64, len: usize, keep: u8) {
        let page_addr = addr & !0xfff;
        let slot = self
            .store
            .data()
            .pages
            .iter()
            .find(|(pa, _)| *pa == page_addr)
            .map(|(_, s)| *s)
            .expect("page mirrored");
        let page_off = (addr & 0xfff) as usize;
        let base = FASTMEM_POOL_BASE as usize + slot as usize * FASTMEM_PAGE_IMG as usize + 4096;
        let mut perm = vec![0u8; len];
        self.memory
            .read(&self.store, base + page_off, &mut perm)
            .expect("read perm");
        for p in &mut perm {
            *p &= keep;
        }
        self.memory
            .write(&mut self.store, base + page_off, &perm)
            .expect("write perm");
    }
}

/// A parallel interpreter reference: the same block over the same seeds/region,
/// run one execution at a time so a test can apply the same mapping change to it
/// and the JIT harness between runs.
struct InterpRef {
    vm: x64_engine::InterpVm,
    block: pcode::Block,
}

impl InterpRef {
    fn new(block: &pcode::Block, seeds: &[(VarNode, u64)], region: &[(u64, Vec<u8>)]) -> Self {
        let mut vm = build_x64_vm(&ldef_path(), &EngineConfig::default()).expect("build vm");
        vm.cpu.regs.fill(0);
        for (base, data) in region {
            map_region(&mut vm.cpu.mem, *base, data);
        }
        for &(var, value) in seeds {
            let off = x64_engine::jit::var_offset(var) as usize;
            let n = var.size as usize;
            vm.cpu.regs.as_bytes_mut()[off..off + n].copy_from_slice(&value.to_le_bytes()[..n]);
        }
        Self {
            vm,
            block: clone_block(block),
        }
    }

    fn run_once(&mut self) -> Option<usize> {
        // Safety: the block is well-formed p-code built by the test.
        unsafe { self.vm.cpu.interpret_block_unchecked(&self.block, 0) }
    }

    fn mem(&mut self) -> &mut icicle_cpu::mem::Mmu {
        &mut self.vm.cpu.mem
    }

    fn exception(&self) -> (u32, u64) {
        (self.vm.cpu.exception.code, self.vm.cpu.exception.value)
    }

    fn regs(&self) -> Vec<u8> {
        self.vm.cpu.regs.as_bytes().to_vec()
    }

    fn guest(&mut self, base: u64, len: usize) -> Vec<u8> {
        let mut buf = vec![0u8; len];
        self.vm
            .cpu
            .mem
            .read_bytes(base, &mut buf, perm::NONE)
            .expect("read guest");
        buf
    }
}

/// Asserts the JIT-with-fast-path state (regs, guest bytes, fault, exception)
/// equals the interpreter's after the same execution.
fn fastmem_assert_same(
    label: &str,
    interp: &mut InterpRef,
    jit: &mut FastRunner,
    ifault: Option<usize>,
    jfault: Option<u32>,
    base: u64,
    len: usize,
) {
    assert_eq!(
        ifault,
        jfault.map(|i| i as usize),
        "{label}: fault index diverged (interp {ifault:?}, jit {jfault:?})"
    );
    assert_eq!(
        interp.exception(),
        jit.exception(),
        "{label}: exception diverged"
    );
    assert_eq!(interp.regs(), jit.regs(), "{label}: register file diverged");
    if len > 0 {
        assert_eq!(
            interp.guest(base, len),
            jit.guest(base, len),
            "{label}: guest memory diverged"
        );
    }
}

/// A single-Load block: `out(size) = *addr`, address in varnode 5.
fn load_block(size: u8) -> (pcode::Block, VarNode, VarNode) {
    let (out, addr) = (v(1, size), v(5, 8));
    let mut block = pcode::Block::new();
    block.push((out, Op::Load(RAM_SPACE), addr));
    (block, out, addr)
}

/// A single-Store block: `*addr = val(size)`, address in 5, value in 6.
fn store_block(size: u8) -> (pcode::Block, VarNode, VarNode) {
    let (addr, val) = (v(5, 8), v(6, size));
    let mut block = pcode::Block::new();
    block.push((Op::Store(RAM_SPACE), Inputs::new(addr, val)));
    (block, addr, val)
}

#[test]
fn fastmem_load_hit_matches_and_warms() {
    // A warm load of each width is served inline (no host call on the second
    // run) and matches the interpreter.
    const BASE: u64 = 0x1_0000;
    let seed: Vec<u8> = (0..64u8)
        .map(|i| i.wrapping_mul(7).wrapping_add(3))
        .collect();
    for size in [1u8, 2, 4, 8] {
        let off = 16u64; // aligned for every width
        let (block, _out, addr) = load_block(size);
        let seeds = vec![(addr, BASE + off)];
        let region = vec![(BASE, seed.clone())];

        let mut interp = InterpRef::new(&block, &seeds, &region);
        let mut jit = FastRunner::new(&block, &seeds, &region).expect("translates");

        // First run warms the TLB (a host call), second must be pure fast path.
        let i1 = interp.run_once();
        let (c1, f1) = jit.run_once();
        fastmem_assert_same(
            &format!("load u{} run1", size * 8),
            &mut interp,
            &mut jit,
            i1,
            f1,
            BASE,
            seed.len(),
        );
        assert!(
            c1 > 0,
            "load u{}: first run should miss and call the host",
            size * 8
        );

        let i2 = interp.run_once();
        let (c2, f2) = jit.run_once();
        fastmem_assert_same(
            &format!("load u{} run2", size * 8),
            &mut interp,
            &mut jit,
            i2,
            f2,
            BASE,
            seed.len(),
        );
        assert_eq!(
            c2,
            0,
            "load u{}: warm run still called the host {c2}x — the fast path did not fire",
            size * 8
        );
    }
}

#[test]
fn fastmem_store_hit_matches_and_warms() {
    // A warm store of each width writes through inline (no host call once warm)
    // and the written-back memory matches the interpreter.
    const BASE: u64 = 0x1_0000;
    for (size, val) in [
        (1u8, 0xa5u64),
        (2, 0xbeef),
        (4, 0xdead_beef),
        (8, 0xcafe_f00d_1234_5678),
    ] {
        let off = 24u64;
        let (block, addr, valv) = store_block(size);
        let seeds = vec![(addr, BASE + off), (valv, val)];
        let region = vec![(BASE, vec![0u8; 64])];

        let mut interp = InterpRef::new(&block, &seeds, &region);
        let mut jit = FastRunner::new(&block, &seeds, &region).expect("translates");

        let i1 = interp.run_once();
        let (c1, f1) = jit.run_once();
        fastmem_assert_same(
            &format!("store u{} run1", size * 8),
            &mut interp,
            &mut jit,
            i1,
            f1,
            BASE,
            64,
        );
        assert!(c1 > 0, "store u{}: first run should miss", size * 8);

        let i2 = interp.run_once();
        let (c2, f2) = jit.run_once();
        fastmem_assert_same(
            &format!("store u{} run2", size * 8),
            &mut interp,
            &mut jit,
            i2,
            f2,
            BASE,
            64,
        );
        assert_eq!(
            c2,
            0,
            "store u{}: warm run still called the host — fast path did not fire",
            size * 8
        );
    }
}

#[test]
fn fastmem_cross_page_load_always_defers() {
    // An 8-byte load straddling a page boundary must always take the slow path
    // (the cross-page guard), even after neighbouring accesses warm the TLB, and
    // must still match the interpreter (which reads it byte by byte).
    const BASE: u64 = 0x1_0000; // two pages: [0x10000, 0x12000)
    let bytes: Vec<u8> = (0..0x2000u32).map(|i| (i as u8).wrapping_mul(3)).collect();
    let straddle = 0x1_1000 - 4; // [0x10ffc, 0x11004): crosses the 0x11000 boundary
    let (block, _out, addr) = load_block(8);
    let seeds = vec![(addr, straddle)];
    let region = vec![(BASE, bytes.clone())];

    let mut interp = InterpRef::new(&block, &seeds, &region);
    let mut jit = FastRunner::new(&block, &seeds, &region).expect("translates");

    for run in 0..2 {
        let i = interp.run_once();
        let (c, f) = jit.run_once();
        fastmem_assert_same(
            &format!("cross-page run{run}"),
            &mut interp,
            &mut jit,
            i,
            f,
            BASE,
            bytes.len(),
        );
        assert!(
            c > 0,
            "cross-page run{run}: a straddling load must defer to the host every time"
        );
    }
}

#[test]
fn fastmem_coherence_after_unmap() {
    // Warm a page through the fast path, then unmap it (and invalidate the TLB
    // entry, as icicle's flush does). The next access must NOT use the stale
    // translation: it faults exactly as the interpreter does. This is the
    // correctness crux — breaking the tag compare reddens it.
    const BASE: u64 = 0x1_0000;
    let seed: Vec<u8> = (0..64u8).collect();
    let (block, _out, addr) = load_block(8);
    let seeds = vec![(addr, BASE)];
    let region = vec![(BASE, seed.clone())];

    let mut interp = InterpRef::new(&block, &seeds, &region);
    let mut jit = FastRunner::new(&block, &seeds, &region).expect("translates");

    // Warm.
    let i1 = interp.run_once();
    let (c1, f1) = jit.run_once();
    fastmem_assert_same(
        "coherence warm",
        &mut interp,
        &mut jit,
        i1,
        f1,
        BASE,
        seed.len(),
    );
    assert!(c1 > 0, "coherence: first run should warm the TLB");
    let (c2, _) = jit.run_once();
    let _ = interp.run_once();
    assert_eq!(c2, 0, "coherence: page should be warm before the unmap");

    // Unmap in both; icicle flushes the live TLB, which the harness mirrors by
    // invalidating the entry the JIT reads.
    interp.mem().unmap_memory_len(BASE, 0x1000);
    jit.mem().unmap_memory_len(BASE, 0x1000);
    jit.invalidate_tlb(BASE);

    let i3 = interp.run_once();
    let (c3, f3) = jit.run_once();
    fastmem_assert_same(
        "coherence after unmap",
        &mut interp,
        &mut jit,
        i3,
        f3,
        BASE,
        0,
    );
    assert!(f3.is_some(), "coherence: the access after unmap must fault");
    assert!(c3 > 0, "coherence: the faulting access must reach the host");
}

#[test]
fn fastmem_tlb_index_aliasing() {
    // Two pages that map to the SAME TLB index (their addresses differ by a
    // multiple of the index span, 0x40_0000). A block loads from both: the first
    // load warms the shared index with page A's translation, the second must NOT
    // reuse it for page B — the tag differs, so it misses and reads B. This is
    // exactly what the tag compare exists for; accepting any tag makes the second
    // load resolve through A's translation and diverge (a wrong address, here out
    // of bounds), so breaking the tag compare reddens this test.
    let a_base = 0x10_0000u64; // index (0x100000 >> 12) & 0x3ff = 0x100
    let b_base = 0x10_0000u64 + 0x40_0000; // 0x500000, index 0x100 as well
    assert_eq!(
        (a_base >> 12) & 0x3ff,
        (b_base >> 12) & 0x3ff,
        "same TLB index"
    );
    let region = vec![(a_base, vec![0x11u8; 4096]), (b_base, vec![0x22u8; 4096])];

    let (oa, ob) = (v(1, 1), v(2, 1));
    let (aa, ab) = (v(5, 8), v(6, 8));
    let mut block = pcode::Block::new();
    block.push((oa, Op::Load(RAM_SPACE), aa));
    block.push((ob, Op::Load(RAM_SPACE), ab));
    let seeds = vec![(aa, a_base), (ab, b_base)];

    let mut interp = InterpRef::new(&block, &seeds, &region);
    let mut jit = FastRunner::new(&block, &seeds, &region).expect("translates");
    // Two runs, so the second sees both indices warm and the aliasing is live.
    for run in 0..2 {
        let i = interp.run_once();
        let (_c, f) = jit.run_once();
        fastmem_assert_same(
            &format!("aliasing run{run}"),
            &mut interp,
            &mut jit,
            i,
            f,
            0,
            0,
        );
    }
    // The second load must have read page B (0x22), not page A (0x11).
    assert_eq!(
        jit.regs()[x64_engine::jit::var_offset(ob) as usize],
        0x22,
        "aliasing: the second load must read page B, not A's stale translation"
    );
}

#[test]
fn fastmem_permission_fault_after_mprotect() {
    // Warm a readable page, then drop READ from its perms (mprotect) — updating
    // the resident page's perm bytes but leaving the TLB entry valid. The fast
    // path's permission guard must reject it and defer to the host, which raises
    // the exact ReadViolation the interpreter does. Dropping INIT from the perm
    // mask reddens this.
    const BASE: u64 = 0x1_0000;
    let seed: Vec<u8> = (0..64u8).collect();
    let (block, _out, addr) = load_block(8);
    let seeds = vec![(addr, BASE)];
    let region = vec![(BASE, seed.clone())];

    let mut interp = InterpRef::new(&block, &seeds, &region);
    let mut jit = FastRunner::new(&block, &seeds, &region).expect("translates");

    let i1 = interp.run_once();
    let (c1, f1) = jit.run_once();
    fastmem_assert_same("perm warm", &mut interp, &mut jit, i1, f1, BASE, seed.len());
    assert!(c1 > 0);
    let (c2, _) = jit.run_once();
    let _ = interp.run_once();
    assert_eq!(c2, 0, "perm: page should be warm before the mprotect");

    // mprotect to write-only (no READ) in both. The TLB entry stays valid; only
    // the resident page's perms change, so the fast path's perm guard is what
    // must catch it.
    interp
        .mem()
        .update_perm(BASE, 0x1000, perm::WRITE)
        .expect("mprotect");
    jit.mem()
        .update_perm(BASE, 0x1000, perm::WRITE)
        .expect("mprotect");
    jit.clear_mirror_perm(BASE, 8, !perm::READ);

    let i3 = interp.run_once();
    let (c3, f3) = jit.run_once();
    fastmem_assert_same(
        "perm after mprotect",
        &mut interp,
        &mut jit,
        i3,
        f3,
        BASE,
        0,
    );
    assert!(f3.is_some(), "perm: the read of a no-read page must fault");
    assert!(c3 > 0, "perm: the faulting access must defer to the host");
    assert_eq!(
        jit.exception().0,
        x64_engine::ExceptionCode::from_load_error(icicle_cpu::mem::MemError::ReadViolation) as u32,
        "perm: expected a ReadViolation"
    );
}

/// A deterministic splitmix64 stream, so a failure names the exact inputs and
/// reproduces.
struct SplitMix(u64);
impl SplitMix {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}

/// 128-bit multiply against the interpreter over many random inputs, including
/// the in-place form, so a wrong mulhi, a dropped cross term, or an aliasing bug
/// shows on some seed.
#[test]
fn wide_multiply_matches_the_interpreter_on_random_inputs() {
    let (o16, a16, b16) = (reg(1, 16), reg(2, 16), reg(3, 16));
    let (alo, ahi) = (a16.slice(0, 8), a16.slice(8, 8));
    let (blo, bhi) = (b16.slice(0, 8), b16.slice(8, 8));
    let mut rng = SplitMix(0x1234_5678_9abc_def0);
    for i in 0..256 {
        let (av0, av1, bv0, bv1) = (rng.next(), rng.next(), rng.next(), rng.next());
        // Alternate the plain and in-place (output aliases `a`) forms.
        let dst = if i % 2 == 0 { o16 } else { a16 };
        let mut block = pcode::Block::new();
        block.push((dst, Op::IntMul, a16, b16));
        let case = Case {
            name: "IntMul u128 random",
            seeds: vec![(alo, av0), (ahi, av1), (blo, bv0), (bhi, bv1)],
            block,
        };
        let interp = interpret(&case);
        let jitted = jit(&case).expect("IntMul u128 must translate");
        assert_eq!(
            interp,
            jitted,
            "IntMul u128 diverged: a={av1:016x}{av0:016x} b={bv1:016x}{bv0:016x} (in_place={})",
            i % 2 == 1
        );
    }
}

/// 128-bit shifts (left, logical right, arithmetic right) against the
/// interpreter across the boundary counts (0, 63, 64, 65, 127, 128, ...) and
/// random values/counts, including the in-place form.
#[test]
fn wide_shift_matches_the_interpreter() {
    let (o16, a16, cnt) = (reg(1, 16), reg(2, 16), reg(4, 4));
    let (alo, ahi) = (a16.slice(0, 8), a16.slice(8, 8));

    let run = |op: Op, dst: VarNode, av0: u64, av1: u64, c: u64| -> (Vec<u8>, Vec<u8>) {
        let mut block = pcode::Block::new();
        block.push((dst, op, a16, cnt));
        let case = Case {
            name: "wide shift",
            seeds: vec![(alo, av0), (ahi, av1), (cnt, c)],
            block,
        };
        (interpret(&case), jit(&case).expect("wide shift translates"))
    };

    let boundaries = [
        0u64, 1, 31, 32, 33, 63, 64, 65, 95, 96, 127, 128, 129, 191, 192, 255, 256, 1000,
    ];
    let mut rng = SplitMix(0xdead_beef_1234_5678);
    for (name, op) in [
        ("IntLeft u128", Op::IntLeft),
        ("IntRight u128", Op::IntRight),
        ("IntSignedRight u128", Op::IntSignedRight),
    ] {
        // A value with the sign bit set, so the arithmetic shift's sign fill shows.
        for &c in &boundaries {
            for &(av0, av1) in &[
                (0x8000_0000_0000_0001u64, 0xfedc_ba98_7654_3210u64),
                (0x0, 0x8000_0000_0000_0000),
                (u64::MAX, u64::MAX),
                (0x1, 0x0),
            ] {
                for dst in [o16, a16] {
                    let (interp, jitted) = run(op, dst, av0, av1, c);
                    assert_eq!(
                        interp,
                        jitted,
                        "{name} diverged: a={av1:016x}{av0:016x} count={c} in_place={}",
                        dst == a16
                    );
                }
            }
        }
        for i in 0..128 {
            let (av0, av1) = (rng.next(), rng.next());
            let c = rng.next() % 300;
            let dst = if i % 2 == 0 { o16 } else { a16 };
            let (interp, jitted) = run(op, dst, av0, av1, c);
            assert_eq!(
                interp,
                jitted,
                "{name} diverged (random): a={av1:016x}{av0:016x} count={c} in_place={}",
                i % 2 == 1
            );
        }
    }
}
