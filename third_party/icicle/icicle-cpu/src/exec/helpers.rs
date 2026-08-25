use pcode::{Value, VarNode};

use crate::{Cpu, ExceptionCode, ValueSource};

pub type PcodeOpHelper = fn(&mut Cpu, VarNode, [Value; 2]);

pub fn unknown_operation(cpu: &mut Cpu, _: VarNode, _: [Value; 2]) {
    cpu.exception.code = ExceptionCode::UnimplementedOp as u32;
}

pub const HELPERS: &[(&str, PcodeOpHelper)] = &[
    ("count_leading_zeros", count_leading_zeros),
    ("count_leading_zeroes", count_leading_zeros),
    ("countLeadingZeros", count_leading_zeros),
    ("count_leading_ones", count_leading_ones),
    ("countLeadingOnes", count_leading_ones),
    ("bcd_add", bcd_add),
    ("UnsignedSaturate", unsigned_saturate),
    ("UnsignedDoesSaturate", unsigned_does_saturate),
    ("SignedSaturate", signed_saturate),
    ("SignedDoesSaturate", signed_does_saturate),
    ("setISAMode", set_isa_mode),
];

fn set_isa_mode(_cpu: &mut Cpu, _: VarNode, _: [Value; 2]) {
    // Icicle checks for ISA mode switches on every block so does not need this function to be
    // called explicitly.
}

fn enable_interrupts(_cpu: &mut Cpu, _: VarNode, _: [Value; 2]) {
    // @todo
}

fn disable_interrupts(_cpu: &mut Cpu, _: VarNode, _: [Value; 2]) {
    // @todo
}

fn count_leading_zeros(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
    let input = args[0];
    let result = match args[0].size() {
        1 => cpu.read::<u8>(input).leading_zeros(),
        2 => cpu.read::<u16>(input).leading_zeros(),
        4 => cpu.read::<u32>(input).leading_zeros(),
        8 => cpu.read::<u64>(input).leading_zeros(),
        16 => cpu.read::<u128>(input).leading_zeros(),
        size => {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = size as u64;
            return;
        }
    };
    cpu.write_trunc(dst, result);
}

fn count_leading_ones(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
    let input = args[0];
    let result = match args[0].size() {
        1 => cpu.read::<u8>(input).leading_ones(),
        2 => cpu.read::<u16>(input).leading_ones(),
        4 => cpu.read::<u32>(input).leading_ones(),
        8 => cpu.read::<u64>(input).leading_ones(),
        16 => cpu.read::<u128>(input).leading_ones(),
        size => {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = size as u64;
            return;
        }
    };
    cpu.write_trunc(dst, result);
}

fn bcd_add(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
    let size = dst.size;

    if args[0].size() != size || args[1].size() != size {
        cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
        cpu.exception.value = args[0].size() as u64;
        return;
    }

    match size {
        1 => {
            let a = cpu.read::<u8>(args[0]);
            let b = cpu.read::<u8>(args[1]);
            let result = bcd_add8(a, b);
            cpu.write_var(dst, result);
        }
        2 => {
            let a = cpu.read::<u16>(args[0]);
            let b = cpu.read::<u16>(args[1]);
            let result = bcd_add16(a, b);
            cpu.write_var(dst, result);
        }
        _ => {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = args[0].size() as u64;
        }
    }
}

fn bcd_add8(a: u8, b: u8) -> u8 {
    let mut result = 0;
    let mut carry = 0;
    for digit in 0..2 {
        let (result_digit, next_carry) =
            bcd_add_digit((a >> (4 * digit)) & 0xF, (b >> (4 * digit)) & 0xF, carry);
        carry = next_carry;
        result |= result_digit << (4 * digit);
    }
    result
}

fn bcd_add16(a: u16, b: u16) -> u16 {
    let mut result = 0;
    let mut carry = 0;
    for digit in 0..4 {
        let (result_digit, next_carry) = bcd_add_digit(
            ((a >> (4 * digit)) & 0xF) as u8,
            ((b >> (4 * digit)) & 0xF) as u8,
            carry,
        );
        carry = next_carry;
        result |= (result_digit as u16) << (4 * digit);
    }

    result
}

fn bcd_add_digit(a: u8, b: u8, carry: u8) -> (u8, u8) {
    match a + b + carry {
        x if x < 10 => (x, 0),
        x => (x % 10, 1),
    }
}

fn unsigned_saturate_impl(value: i64, bits: u32) -> (i64, bool) {
    let max: i64 = (1 << bits) - 1;
    if value < 0 {
        (0, true)
    }
    else if value > max {
        (max, true)
    }
    else {
        (value, false)
    }
}

fn unsigned_saturate(cpu: &mut Cpu, dst: pcode::VarNode, args: [Value; 2]) {
    let bits: u32 = cpu.read_dynamic(args[1]).zxt();
    // Some uses of `UnsignedSaturate` in SLEIGH do nothing because the bits have already been
    // truncated. Here we try to detect bugs in the spec by returning an error if the result would
    // never change.
    if bits >= (args[0].size() as u32 * 8) || bits >= 64 {
        cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
        cpu.exception.value = args[0].size() as u64;
        return;
    }

    let value: i64 = cpu.read_dynamic(args[0]).sxt();
    let (value, _) = unsigned_saturate_impl(value, bits);
    cpu.write_trunc(dst, value as u64);
}

fn unsigned_does_saturate(cpu: &mut Cpu, dst: pcode::VarNode, args: [Value; 2]) {
    let bits: u32 = cpu.read_dynamic(args[1]).zxt();
    if bits >= (args[0].size() as u32 * 8) || bits >= 64 {
        cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
        cpu.exception.value = args[0].size() as u64;
        return;
    }

    let value: i64 = cpu.read_dynamic(args[0]).sxt();
    let (_, saturates) = unsigned_saturate_impl(value, bits);
    cpu.write_var::<u8>(dst, saturates as u8);
}

fn signed_saturate_impl(value: i64, bits: u32) -> (i64, bool) {
    let max = (1 << (bits - 1)) - 1;
    let min = -(1 << (bits - 1));
    if value < min {
        (min, true)
    }
    else if value > max {
        (max, true)
    }
    else {
        (value, false)
    }
}

fn signed_saturate(cpu: &mut Cpu, dst: pcode::VarNode, args: [Value; 2]) {
    let bits: u32 = cpu.read_dynamic(args[1]).zxt();
    if bits >= (args[0].size() as u32 * 8) || bits >= 64 {
        cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
        cpu.exception.value = args[0].size() as u64;
        return;
    }

    let value: i64 = cpu.read_dynamic(args[0]).sxt();
    let (value, _) = signed_saturate_impl(value, bits);
    cpu.write_trunc(dst, value as u64);
}

fn signed_does_saturate(cpu: &mut Cpu, dst: pcode::VarNode, args: [Value; 2]) {
    let bits: u32 = cpu.read_dynamic(args[1]).zxt();
    if bits >= (args[0].size() as u32 * 8) || bits >= 64 {
        cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
        cpu.exception.value = args[0].size() as u64;
        return;
    }
    let value: i64 = cpu.read_dynamic(args[0]).sxt();
    let (_, saturates) = unsigned_saturate_impl(value, bits);
    cpu.write_var::<u8>(dst, saturates as u8);
}

#[allow(unused)]
fn saturating_sub(cpu: &mut Cpu, dst: pcode::VarNode, args: [Value; 2]) {
    let size = dst.size;

    if args[0].size() != size || args[1].size() != size {
        cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
        cpu.exception.value = args[0].size() as u64;
        return;
    }

    match size {
        1 => {
            let a = cpu.read::<u8>(args[0]);
            let b = cpu.read::<u8>(args[1]);
            cpu.write_var(dst, a.saturating_sub(b))
        }
        2 => {
            let a = cpu.read::<u16>(args[0]);
            let b = cpu.read::<u16>(args[1]);
            cpu.write_var(dst, a.saturating_sub(b))
        }
        4 => {
            let a = cpu.read::<u32>(args[0]);
            let b = cpu.read::<u32>(args[1]);
            cpu.write_var(dst, a.saturating_sub(b))
        }
        8 => {
            let a = cpu.read::<u64>(args[0]);
            let b = cpu.read::<u64>(args[1]);
            cpu.write_var(dst, a.saturating_sub(b))
        }
        _ => {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = args[0].size() as u64;
        }
    }
}

pub mod x86 {
    use super::*;

    pub const HELPERS: &[(&str, PcodeOpHelper)] = &[
        ("rdtsc", rdtsc),
        ("cpuid_basic_info", cpuid_basic_info),
        ("cpuid_Version_info", cpuid_version_info),
        ("cpuid_Extended_Feature_Enumeration_info", cpuid_extended_feature_enumeration_info),
        ("cpuid", cpuid),
        ("movmskpd", movmskpd),
        ("pinsrw", pinsrw), // Note: implemented in SLEIGH in Ghidra 10.3.
        ("pshuflw", pshuflw),
        ("pshufhw", pshufhw),
        ("shufpd", shufpd), // Note: implemented in SLEIGH in Ghidra 10.3.
        ("pmaddwd", pmaddwd),
        ("psadbw", psadbw),
        ("pshufb", pshufb),
        ("roundsd", roundsd),
        ("roundss", roundss),
        // AES-NI (SSE form). Node/V8 and OpenSSL issue these unconditionally.
        ("aesenc", aesenc),
        ("aesenclast", aesenclast),
        ("aesdec", aesdec),
        ("aesdeclast", aesdeclast),
        ("aesimc", aesimc),
        ("aeskeygenassist", aeskeygenassist),
        ("in", in_io),
        ("out", out_io),
        ("LOCK", lock),
        ("UNLOCK", unlock),
        // Legacy float operations
        ("fsin", fsin),
        ("fcos", fcos),
        ("fptan", fptan),
        ("f2xm1", f2xm1),
        ("fscale", fscale),
    ];

    fn rdtsc(cpu: &mut Cpu, dst: VarNode, _: [Value; 2]) {
        cpu.write_var(dst, 0_u64);
    }

    // Basic processor information
    fn cpuid_basic_info(cpu: &mut Cpu, dst: VarNode, _: [Value; 2]) {
        if dst.size != 16 {
            tracing::warn!(
                "Using unpatched SLEIGH specification, CPUID instruction will behave incorrectly"
            );
            return;
        }
        tracing::debug!("cpuid(BASIC_INFO)");
        // Maximum basic leaf. Must be at least 1 so software (e.g. V8) reads
        // leaf 1 and sees the SSE2 feature bit; kept at 1 so the unimplemented
        // cache/topology leaves (2..6) are never queried.
        const MAX_BASIC_LEAF: u32 = 1;
        if true {
            // Pretend to be an Intel CPU
            cpu.write_var(dst.slice(0, 4), MAX_BASIC_LEAF);
            cpu.write_var(dst.slice(4, 4), u32::from_le_bytes(*b"Genu"));
            cpu.write_var(dst.slice(8, 4), u32::from_le_bytes(*b"ineI"));
            cpu.write_var(dst.slice(12, 4), u32::from_le_bytes(*b"ntel"));
        }
        else {
            cpu.write_var(dst.slice(0, 4), MAX_BASIC_LEAF);
            cpu.write_var(dst.slice(4, 4), u32::from_le_bytes(*b"Icic"));
            cpu.write_var(dst.slice(8, 4), u32::from_le_bytes(*b"leCo"));
            cpu.write_var(dst.slice(12, 4), u32::from_le_bytes(*b"reVm"));
        }
    }

    // Processor info and feature bits
    fn cpuid_version_info(cpu: &mut Cpu, dst: VarNode, _: [Value; 2]) {
        if dst.size != 16 {
            tracing::warn!(
                "Using unpatched SLEIGH specification, CPUID instruction will behave incorrectly"
            );
            return;
        }
        tracing::debug!("cpuid(VERSION_INFO)");
        // Copied from `Coffee Lake` microarchitecture
        let extended_family = 0x0;
        let family = 0x6;
        let extended_model = 0x9;
        let model = 0xe;

        let eax: u32 =
            (extended_family << 20) | (extended_model << 16) | (family << 8) | (model << 4);

        use cpuid::FeatureInformationEcx as Feature;

        // Advertise SSE/SSE2/SSE3 and AES-NI, but deliberately not AVX or
        // AVX-512: those encodings decode but their p-code semantics are not
        // all validated, so userspace stays on the SSE paths. `avx`,
        // `osxsave`, and `f16c` are left clear. SSE4 is also left clear (a
        // Rust guest otherwise reaches inline `roundsd`, whose imm8 rounding
        // mode icicle's two-operand p-code cannot carry). AES-NI *is*
        // advertised: its round primitives have helpers, and a guest TLS
        // client's hardware-AES path (which also uses `pshufb`) works.
        let ecx: u32 = (Feature::sse3
            | Feature::tm2
            | Feature::pdcm
            | Feature::popcnt
            | Feature::tsc_deadline
            | Feature::aesni
            | Feature::xsave)
            .bits();

        // EDX baseline for an SSE2-capable CPU. V8 aborts at startup unless
        // SSE2 is present (`Check failed: cpu.has_sse2()`).
        use cpuid::FeatureInformationEdx as FeatureEdx;
        let edx: u32 = (FeatureEdx::fpu
            | FeatureEdx::vme
            | FeatureEdx::de
            | FeatureEdx::tsc
            | FeatureEdx::msr
            | FeatureEdx::pae
            | FeatureEdx::cx8
            | FeatureEdx::sep
            | FeatureEdx::cmov
            | FeatureEdx::clfsh
            | FeatureEdx::mmx
            | FeatureEdx::fxsr
            | FeatureEdx::sse
            | FeatureEdx::sse2)
            .bits();

        cpu.write_var(dst.slice(0, 4), eax);
        cpu.write_var(dst.slice(4, 4), 0_u32);
        cpu.write_var(dst.slice(8, 4), ecx);
        cpu.write_var(dst.slice(12, 4), edx);
    }

    // Return structured extended feature enumeration info leaf
    fn cpuid_extended_feature_enumeration_info(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 16 {
            tracing::warn!(
                "Using unpatched SLEIGH specification, CPUID instruction will behave incorrectly"
            );
            return;
        }
        let count: u32 = cpu.read(args[1]);
        tracing::debug!("cpuid(EXTENDED_FEATURE_ENUMERATION_INFO, {:#0x})", count);

        match count {
            // Returns extended feature flags in EBX, ECX, and EDX
            0x0 => {
                cpu.write_var(dst.slice(0, 4), u32::MAX);
                cpu.write_var(dst.slice(4, 4), cpuid::EXTENDED_FEATURES_EBX);
                cpu.write_var(dst.slice(8, 4), cpuid::EXTENDED_FEATURES_EDX);
                cpu.write_var(dst.slice(12, 4), cpuid::EXTENDED_FEATURES_ECX);
            }

            // Returns extended feature flags in EAX
            0x1 => {
                // We don't support AVX-512 BFLOAT16 operations
                cpu.write_var(dst.slice(0, 4), 0_u32);
                cpu.write_var(dst.slice(4, 4), 0_u32);
                cpu.write_var(dst.slice(8, 4), 0_u32);
                cpu.write_var(dst.slice(12, 4), 0_u32);
            }
            _ => {
                cpu.write_var(dst.slice(0, 4), 0_u32);
                cpu.write_var(dst.slice(4, 4), 0_u32);
                cpu.write_var(dst.slice(8, 4), 0_u32);
                cpu.write_var(dst.slice(12, 4), 0_u32);
            }
        }
    }

    fn cpuid(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 16 {
            tracing::warn!(
                "Using unpatched SLEIGH specification, CPUID instruction will behave incorrectly"
            );
            return;
        }
        let index: u32 = cpu.read(args[0]);
        let count: u32 = cpu.read(args[1]);
        tracing::debug!("cpuid({:#0x}, {:#0x})", index, count);
        match index {
            // Hypervisor
            0x4000_0000 => {
                cpu.write_var(dst.slice(0, 4), 0_u32);
                cpu.write_var(dst.slice(4, 4), 0_u32);
                cpu.write_var(dst.slice(8, 4), 0_u32);
                cpu.write_var(dst.slice(12, 4), 0_u32);
            }

            // Get Highest Extended Function Implemented
            0x8000_0000 => {
                cpu.write_var(dst.slice(0, 4), 0_u32);
                cpu.write_var(dst.slice(4, 4), 0_u32);
                cpu.write_var(dst.slice(8, 4), 0_u32);
                cpu.write_var(dst.slice(12, 4), 0_u32);
            }
            unknown => {
                tracing::warn!("Unknown CPUID index: {:0x}", unknown);
                cpu.exception.code = ExceptionCode::UnknownCpuID as u32;
                cpu.exception.value = unknown as u64;
            }
        }
    }

    /// Extract Packed Double-Precision Floating-Point Sign Mask
    fn movmskpd(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let src = cpu.read::<u128>(args[1]);
        let result = ((src >> 63) & 0b01) as u32 | ((src >> 126) & 0b10) as u32;

        // workaround SLEIGH bug? should zero extend to 64-bits
        cpu.write_var(VarNode::new(dst.id, 8), result as u64);
    }

    /// Insert word
    #[allow(unused)]
    fn pinsrw(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        // The byte offset to insert the word at
        let offset = 2 * (cpu.args[0] as u64).min(7);
        let src: u64 = cpu.read_dynamic(args[1]).zxt();

        cpu.write_var(dst.slice(offset as u8, 2), src as u16);
    }

    /// Shuffle packed low words
    fn pshuflw(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let src = cpu.read::<u64>(args[1].slice(0, 8));
        let count = cpu.args[0] as u64;

        // Shuffle low bits
        for offset in 0..4 {
            let shift = (count >> (offset * 2) & 0b11) * 16;
            let value = (src >> shift) & 0xffff;
            cpu.write_var(dst.slice(offset * 2, 2), value as u16);
        }

        // Copy high bits
        let src_hi = cpu.read::<u64>(args[1].slice(8, 8));
        cpu.write_var(dst.slice(8, 8), src_hi)
    }

    /// Shuffle packed high words
    fn pshufhw(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let src = cpu.read::<u64>(args[1].slice(8, 8));
        let count = cpu.args[0] as u64;

        // Copy low bits
        let src_low = cpu.read::<u64>(args[1].slice(0, 8));
        cpu.write_var(dst.slice(0, 8), src_low);

        // Shuffle high bits
        for offset in 0..4 {
            let shift = (count >> (offset * 2) & 0b11) * 16;
            let value = (src >> shift) & 0xffff;
            cpu.write_var(dst.slice(8 + offset * 2, 2), value as u16);
        }
    }

    /// Packed interleave shuffle
    #[allow(unused)]
    fn shufpd(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let index = cpu.args[0] as u64;

        let a = if index & 0b01 == 0 { 0 } else { 8 };
        let b = if index & 0b10 == 0 { 0 } else { 8 };

        let lo = cpu.read::<u64>(args[0].slice(a, 8));
        let hi = cpu.read::<u64>(args[1].slice(b, 8));

        cpu.write_var(dst.slice(0, 8), lo);
        cpu.write_var(dst.slice(8, 8), hi);
    }

    // Multiply and Add Packed Integers
    fn pmaddwd(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        for i in (0..dst.size).step_by(std::mem::size_of::<u32>()) {
            let lo = cpu.read::<i16>(args[0].slice(i, 2)) as i32
                * cpu.read::<i16>(args[1].slice(i, 2)) as i32;

            let hi = cpu.read::<i16>(args[0].slice(i + 2, 2)) as i32
                * cpu.read::<i16>(args[1].slice(i + 2, 2)) as i32;

            cpu.write_var(dst.slice(i, 4), lo.wrapping_add(hi));
        }
    }

    fn roundsd(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        // Scalar round of the low f64 of args[1], with the upper 64 bits taken
        // from args[0]. The SLEIGH pcodeop drops the imm8 rounding mode (only
        // two operands survive icicle's p-code), so round to nearest, ties to
        // even — the IEEE default and the MXCSR default that `imm8` bit 2
        // selects.
        let upper = cpu.read::<u128>(args[0]);
        let value = f64::from_bits(cpu.read::<u64>(args[1].slice(0, 8)));
        let rounded = value.round_ties_even().to_bits();
        cpu.write_var(dst, (upper & !0xffff_ffff_ffff_ffffu128) | rounded as u128);
    }

    fn roundss(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let upper = cpu.read::<u128>(args[0]);
        let value = f32::from_bits(cpu.read::<u32>(args[1].slice(0, 4)));
        let rounded = value.round_ties_even().to_bits();
        cpu.write_var(dst, (upper & !0xffff_ffffu128) | rounded as u128);
    }

    fn pshufb(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        // Byte shuffle: for each byte, a control byte with the high bit set
        // yields zero, otherwise it selects a source byte by its low nibble
        // (within the same 128-bit lane; only 16-byte operands are used here).
        let src: [u8; 16] = cpu.read::<u128>(args[0]).to_le_bytes();
        let ctrl: [u8; 16] = cpu.read::<u128>(args[1]).to_le_bytes();
        let mut out = [0u8; 16];
        for i in 0..16 {
            let c = ctrl[i];
            out[i] = if c & 0x80 != 0 { 0 } else { src[(c & 0x0f) as usize] };
        }
        cpu.write_var(dst, u128::from_le_bytes(out));
    }

    fn psadbw(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        // Sum of absolute byte differences, per 64-bit lane, result in the
        // low 16 bits of each lane.
        for lane in (0..dst.size).step_by(8) {
            let mut sum: u16 = 0;
            for i in 0..8 {
                let a = cpu.read::<u8>(args[0].slice(lane + i, 1));
                let b = cpu.read::<u8>(args[1].slice(lane + i, 1));
                sum += (a as i16 - b as i16).unsigned_abs();
            }
            cpu.write_var::<u64>(dst.slice(lane, 8), sum as u64);
        }
    }

    // --- AES-NI ---------------------------------------------------------
    // Software implementations of the AES round primitives. Node/V8 and
    // OpenSSL emit these directly; the SLEIGH spec leaves them as opaque
    // pcodeops, so without these helpers they trap as unimplemented.

    #[rustfmt::skip]
    const AES_SBOX: [u8; 256] = [
        0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
        0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
        0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
        0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
        0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
        0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
        0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
        0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
        0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
        0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
        0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
        0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
        0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
        0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
        0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
        0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
    ];

    fn aes_inv_sbox() -> [u8; 256] {
        let mut inv = [0u8; 256];
        let mut i = 0;
        while i < 256 {
            inv[AES_SBOX[i] as usize] = i as u8;
            i += 1;
        }
        inv
    }

    /// GF(2^8) multiply (AES polynomial 0x11b).
    fn gmul(mut a: u8, mut b: u8) -> u8 {
        let mut p = 0u8;
        for _ in 0..8 {
            if b & 1 != 0 {
                p ^= a;
            }
            let hi = a & 0x80;
            a <<= 1;
            if hi != 0 {
                a ^= 0x1b;
            }
            b >>= 1;
        }
        p
    }

    fn aes_sub_bytes(s: &mut [u8; 16], sbox: &[u8; 256]) {
        for b in s.iter_mut() {
            *b = sbox[*b as usize];
        }
    }

    /// ShiftRows on a column-major state: out[c*4+r] = in[((c+r)%4)*4 + r].
    /// `dir` = 1 for forward, 3 for inverse (shift the opposite way).
    fn aes_shift_rows(s: &[u8; 16], dir: usize) -> [u8; 16] {
        let mut out = [0u8; 16];
        for c in 0..4 {
            for r in 0..4 {
                out[c * 4 + r] = s[(((c + r * dir) % 4) * 4) + r];
            }
        }
        out
    }

    fn aes_mix_columns(s: &[u8; 16], coeffs: [u8; 4]) -> [u8; 16] {
        let mut out = [0u8; 16];
        for c in 0..4 {
            let s0 = s[c * 4];
            let s1 = s[c * 4 + 1];
            let s2 = s[c * 4 + 2];
            let s3 = s[c * 4 + 3];
            let [m0, m1, m2, m3] = coeffs;
            out[c * 4] = gmul(s0, m0) ^ gmul(s1, m1) ^ gmul(s2, m2) ^ gmul(s3, m3);
            out[c * 4 + 1] = gmul(s0, m3) ^ gmul(s1, m0) ^ gmul(s2, m1) ^ gmul(s3, m2);
            out[c * 4 + 2] = gmul(s0, m2) ^ gmul(s1, m3) ^ gmul(s2, m0) ^ gmul(s3, m1);
            out[c * 4 + 3] = gmul(s0, m1) ^ gmul(s1, m2) ^ gmul(s2, m3) ^ gmul(s3, m0);
        }
        out
    }

    fn read_xmm(cpu: &mut Cpu, v: Value) -> [u8; 16] {
        cpu.read::<u128>(v).to_le_bytes()
    }

    fn write_xmm(cpu: &mut Cpu, dst: VarNode, s: [u8; 16]) {
        cpu.write_var(dst, u128::from_le_bytes(s));
    }

    fn aesenc(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let state = read_xmm(cpu, args[0]);
        let key = read_xmm(cpu, args[1]);
        let mut t = aes_shift_rows(&state, 1);
        aes_sub_bytes(&mut t, &AES_SBOX);
        let mut t = aes_mix_columns(&t, [2, 3, 1, 1]);
        for i in 0..16 {
            t[i] ^= key[i];
        }
        write_xmm(cpu, dst, t);
    }

    fn aesenclast(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let state = read_xmm(cpu, args[0]);
        let key = read_xmm(cpu, args[1]);
        let mut t = aes_shift_rows(&state, 1);
        aes_sub_bytes(&mut t, &AES_SBOX);
        for i in 0..16 {
            t[i] ^= key[i];
        }
        write_xmm(cpu, dst, t);
    }

    fn aesdec(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let state = read_xmm(cpu, args[0]);
        let key = read_xmm(cpu, args[1]);
        let inv = aes_inv_sbox();
        let mut t = aes_shift_rows(&state, 3);
        aes_sub_bytes(&mut t, &inv);
        let mut t = aes_mix_columns(&t, [14, 11, 13, 9]);
        for i in 0..16 {
            t[i] ^= key[i];
        }
        write_xmm(cpu, dst, t);
    }

    fn aesdeclast(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let state = read_xmm(cpu, args[0]);
        let key = read_xmm(cpu, args[1]);
        let inv = aes_inv_sbox();
        let mut t = aes_shift_rows(&state, 3);
        aes_sub_bytes(&mut t, &inv);
        for i in 0..16 {
            t[i] ^= key[i];
        }
        write_xmm(cpu, dst, t);
    }

    fn aesimc(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let x = read_xmm(cpu, args[0]);
        let t = aes_mix_columns(&x, [14, 11, 13, 9]);
        write_xmm(cpu, dst, t);
    }

    fn aeskeygenassist(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let x = read_xmm(cpu, args[0]);
        let rcon = cpu.read::<u8>(args[1]);
        let sub_word = |w: [u8; 4]| -> [u8; 4] {
            [
                AES_SBOX[w[0] as usize],
                AES_SBOX[w[1] as usize],
                AES_SBOX[w[2] as usize],
                AES_SBOX[w[3] as usize],
            ]
        };
        // RotWord: [b0,b1,b2,b3] -> [b1,b2,b3,b0].
        let rot = |w: [u8; 4]| -> [u8; 4] { [w[1], w[2], w[3], w[0]] };
        let x1 = [x[4], x[5], x[6], x[7]];
        let x3 = [x[12], x[13], x[14], x[15]];
        let s1 = sub_word(x1);
        let s3 = sub_word(x3);
        let mut r1 = rot(s1);
        r1[0] ^= rcon;
        let mut r3 = rot(s3);
        r3[0] ^= rcon;
        let mut out = [0u8; 16];
        out[0..4].copy_from_slice(&s1);
        out[4..8].copy_from_slice(&r1);
        out[8..12].copy_from_slice(&s3);
        out[12..16].copy_from_slice(&r3);
        write_xmm(cpu, dst, out);
    }

    fn in_io(cpu: &mut Cpu, dst: VarNode, _: [Value; 2]) {
        cpu.write_trunc(dst, 0_u32);
    }
    fn out_io(_: &mut Cpu, _: VarNode, _: [Value; 2]) {}
    fn lock(_: &mut Cpu, _: VarNode, _: [Value; 2]) {}
    fn unlock(_: &mut Cpu, _: VarNode, _: [Value; 2]) {}

    /// Compute the approximate of the sine of the source operand and store it in the destination
    fn fsin(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        // Input is an 80-bit floating point number, but we treat it as a f64.
        let x = f64::from_bits(cpu.read::<u64>(args[0].slice(0, 8)));
        let result = x.sin();
        cpu.write_var(dst.truncate(8), result.to_bits());
    }

    /// Compute the approximate of the cosine of the source operand and store it in the destination
    fn fcos(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        // Input is an 80-bit floating point number, but we treat it as a f64.
        let x = f64::from_bits(cpu.read::<u64>(args[0].truncate(8)));
        let result = x.cos();
        cpu.write_var(dst.truncate(8), result.to_bits());
    }

    /// Compute the approximate of the tangent of the source operand and store it in the destination
    fn fptan(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        // Input is an 80-bit floating point number, but we treat it as a f64.
        let x = f64::from_bits(cpu.read::<u64>(args[0].truncate(8)));
        let result = x.tan();
        cpu.write_var(dst.truncate(8), result.to_bits());
    }

    /// Compute ST0 = 2^(ST0) - 1
    fn f2xm1(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        // Input is an 80-bit floating point number, but we treat it as a f64.
        let st0 = f64::from_bits(cpu.read::<u64>(args[0].truncate(8)));
        let result = st0.exp2() - 1.0;
        cpu.write_var(dst.truncate(8), result.to_bits());
    }

    /// Compute ST0 = ST0 * 2^(trunc(ST1))
    fn fscale(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        // Input is an 80-bit floating point number, but we treat it as a f64.
        let st0 = f64::from_bits(cpu.read::<u64>(args[0].truncate(8)));
        let st1 = f64::from_bits(cpu.read::<u64>(args[1].truncate(8)));
        let result = st0 * st1.trunc().exp2();
        cpu.write_var(dst.truncate(8), result.to_bits());
    }

    pub mod cpuid {
        #![allow(non_upper_case_globals)]

        use bitflags::bitflags;

        bitflags! {
            pub struct FeatureInformationEcx: u32 {
                const sse3         = 1 << 0;
                const pclmulqdq    = 1 << 1;
                const dtes64       = 1 << 2;
                const monitor      = 1 << 3;
                const ds_cpl       = 1 << 4;
                const vmx          = 1 << 5;
                const smx          = 1 << 6;
                const eist         = 1 << 7;
                const tm2          = 1 << 8;
                const ssse3        = 1 << 9;
                const cnxt_id      = 1 << 10;
                const sdbg         = 1 << 11;
                const fma          = 1 << 12;
                const cmpxchg16b   = 1 << 13;
                const xtpr         = 1 << 14;
                const pdcm         = 1 << 15;
                const _reserved    = 1 << 16;
                const pcid         = 1 << 17;
                const dca          = 1 << 18;
                const sse4_1       = 1 << 19;
                const sse4_2       = 1 << 20;
                const x2apic       = 1 << 21;
                const movbe        = 1 << 22;
                const popcnt       = 1 << 23;
                const tsc_deadline = 1 << 24;
                const aesni        = 1 << 25;
                const xsave        = 1 << 26;
                const osxsave      = 1 << 27;
                const avx          = 1 << 28;
                const f16c         = 1 << 29;
                const rdrand       = 1 << 30;
                const _unused      = 1 << 31;
            }
        }

        bitflags! {
            pub struct FeatureInformationEdx: u32 {
                const fpu   = 1 << 0;
                const vme   = 1 << 1;
                const de    = 1 << 2;
                const pse   = 1 << 3;
                const tsc   = 1 << 4;
                const msr   = 1 << 5;
                const pae   = 1 << 6;
                const mce   = 1 << 7;
                const cx8   = 1 << 8;
                const apic  = 1 << 9;
                const sep   = 1 << 11;
                const mtrr  = 1 << 12;
                const pge   = 1 << 13;
                const mca   = 1 << 14;
                const cmov  = 1 << 15;
                const pat   = 1 << 16;
                const pse36 = 1 << 17;
                const clfsh = 1 << 19;
                const mmx   = 1 << 23;
                const fxsr  = 1 << 24;
                const sse   = 1 << 25;
                const sse2  = 1 << 26;
            }
        }

        bitflags! {
            pub struct ExtendedFeaturesEbx: u32 {
                const fsgsbase   = 1 << 0;
                const tscadjust  = 1 << 1;
                const sgx        = 1 << 2;
                const bmi1       = 1 << 3;
                const hle        = 1 << 4;
                const avx2       = 1 << 5;
                const _invalid0  = 1 << 6;
                const smep       = 1 << 7;
                const bmi2       = 1 << 8;
                const erms       = 1 << 9;
                const invpcid    = 1 << 10;
                const rtm        = 1 << 11;
                const pqm        = 1 << 12;
                const _invalid1  = 1 << 13;
                const mpx        = 1 << 14;
                const pqe        = 1 << 15;
                const avx512f    = 1 << 16;
                const avx512dq   = 1 << 17;
                const rdseed     = 1 << 18;
                const adx        = 1 << 19;
                const smap       = 1 << 20;
                const avx512ifma = 1 << 21;
                const pcommit    = 1 << 22;
                const clflushopt = 1 << 23;
                const clwb       = 1 << 24;
                const intel_pt   = 1 << 25;
                const avx512pf   = 1 << 26;
                const avx512er   = 1 << 27;
                const avx412cd   = 1 << 28;
                const sha        = 1 << 29;
                const avx512bw   = 1 << 30;
                const avx512vl   = 1 << 31;
            }
        }

        pub const EXTENDED_FEATURES_EBX: u32 = 0;
        pub const EXTENDED_FEATURES_ECX: u32 = 0;
        pub const EXTENDED_FEATURES_EDX: u32 = 0;
    }
}

pub mod aarch64 {
    use super::*;

    pub const HELPERS: &[(&str, PcodeOpHelper)] = &[
        ("NEON_cmeq", neon_cmeq),
        ("NEON_uminv", neon_uminv),
        ("NEON_sminv", neon_sminv),
        ("NEON_umaxv", neon_umaxv),
        ("NEON_smaxv", neon_smaxv),
    ];

    //
    // NEON implementations
    // @todo: implement these in pcode
    //

    fn neon_cmeq(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let size = cpu.args[0] as u8;
        if size == 0 {
            // This only occurs as a result of a SLEIGH bug.
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = 0;
            return;
        }

        let a = args[0];
        let b = args[1];
        for i in (0..a.size()).step_by(size as usize) {
            let a: u64 = cpu.read_dynamic(a.slice(i, size)).zxt();
            let b: u64 = cpu.read_dynamic(b.slice(i, size)).zxt();
            cpu.write_trunc(dst.slice(i, size), if a == b { u64::MAX } else { 0 })
        }
    }

    fn neon_uminv(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let value = args[0];
        let size = cpu.read::<u8>(args[1]);

        let mut min = u64::MAX;
        for i in (0..value.size()).step_by(size as usize) {
            let a: u64 = cpu.read_dynamic(value.slice(i, size)).zxt();
            min = u64::min(min, a);
        }
        cpu.write_trunc(dst, min);
    }

    fn neon_sminv(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let value = args[0];
        let size = cpu.read::<u8>(args[1]);

        let mut min = i64::MAX;
        for i in (0..value.size()).step_by(size as usize) {
            let a: u64 = cpu.read_dynamic(value.slice(i, size)).sxt();
            min = i64::min(min, a as i64);
        }
        cpu.write_trunc(dst, min as u64);
    }

    fn neon_umaxv(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let value = args[0];
        let size = cpu.read::<u8>(args[1]);

        let mut max = u64::MIN;
        for i in (0..value.size()).step_by(size as usize) {
            let a = cpu.read_dynamic(value.slice(i, size)).zxt();
            max = u64::max(max, a);
        }
        cpu.write_trunc(dst, max);
    }

    fn neon_smaxv(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let value = args[0];
        let size = cpu.read::<u8>(args[1]);

        let mut max = i64::MIN;
        for i in (0..value.size()).step_by(size as usize) {
            let a: u64 = cpu.read_dynamic(value.slice(i, size)).sxt();
            max = i64::max(max, a as i64);
        }
        cpu.write_trunc(dst, max as u64);
    }
}

pub mod arm {
    use super::*;

    pub const HELPERS: &[(&str, PcodeOpHelper)] = &[
        ("enableIRQinterrupts", enable_interrupts),
        ("disableIRQinterrupts", disable_interrupts),
        ("coprocessor_movefromRt", coprocessor_move_from_rt),
        ("coprocessor_movefromRt2", coprocessor_move_from_rt2),
        // NEON
        ("VectorCompareEqual", vector_compare_equal),
        ("VectorPairwiseAdd", vector_pairwise_add),
        ("VectorAdd", vector_add),
        ("VectorSub", vector_sub),
        ("vrev", vrev),
        ("VectorCopyNarrow", vector_copy_narrow),
        ("FixedToFP", fpu_fixed_to_fp),
    ];

    /// The vector ops in SLEIGH are used for both widening and regular vector ops. We only support
    /// the regular vector ops for now, so this helper checks that the arguments are well-formed for
    /// regular vector ops avoiding a crash.
    ///
    /// Most of these are probably better implemented in SLEIGH directly.
    fn ensure_matching_vector_args(
        cpu: &mut Cpu,
        dst: VarNode,
        args: [Value; 2],
        esize: u8,
    ) -> bool {
        if esize == 0 || dst.size % esize != 0 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = esize as u64;
            return false;
        }
        if args[0].size() != dst.size || args[1].size() != dst.size {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = dst.size as u64;
            return false;
        }
        true
    }

    fn vector_compare_equal(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if !ensure_matching_vector_args(cpu, dst, args, cpu.args[0] as u8) {
            return;
        }

        let esize = cpu.args[0] as u8;
        for i in 0..(dst.size / esize) {
            let a: u64 = cpu.read_dynamic(args[0].slice(i * esize, esize)).zxt();
            let b: u64 = cpu.read_dynamic(args[1].slice(i * esize, esize)).zxt();
            cpu.write_trunc(dst.slice(i * esize, esize), if a == b { u64::MAX } else { 0 });
        }
    }

    // Note: SLEIGH uses this for both widening and non-widening vector adds, but we only implement
    // the non-widening version for now.
    //
    //  [a, b] + [c, d] = [a + c, b + d]
    fn vector_add(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        // `esize` in sleigh is encoded as bytes.
        let esize = cpu.args[0] as u8;
        let is_signed = cpu.args[1] == 0;

        if esize == 0 || dst.size % esize != 0 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = esize as u64;
            return;
        }

        let src0_size = args[0].size();
        let src1_size = args[1].size();

        let extract_lane = |cpu: &mut Cpu, value: Value, lane: u8| -> u64 {
            let x = value.slice(lane * esize, esize);
            match is_signed {
                true => cpu.read_dynamic(x).sxt(),
                false => cpu.read_dynamic(x).zxt(),
            }
        };
        let insert_lane = |cpu: &mut Cpu, dst: VarNode, lane: u8, element: u64| {
            cpu.write_trunc(dst.slice(lane * esize, esize), element);
        };

        // Same-width add (e.g. vadd.i*)
        if src0_size == dst.size && src1_size == dst.size {
            for i in 0..(dst.size / esize) {
                let a = extract_lane(cpu, args[0], i);
                let b = extract_lane(cpu, args[1], i);
                insert_lane(cpu, dst, i, a.wrapping_add(b));
            }
        }
        else {
            // Widening adds (vaddl / vaddw), not currently supported
            cpu.exception.code = ExceptionCode::UnimplementedOp as u32;
            cpu.exception.value = cpu.read_pc();
        }
    }

    // [a, b] - [c, d] = [a - c, b - d]
    fn vector_sub(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if !ensure_matching_vector_args(cpu, dst, args, cpu.args[0] as u8) {
            return;
        }

        let esize = cpu.args[0] as u8;
        for i in 0..(dst.size / esize) {
            let a: u64 = cpu.read_dynamic(args[0].slice(i * esize, esize)).zxt();
            let b: u64 = cpu.read_dynamic(args[1].slice(i * esize, esize)).zxt();
            cpu.write_trunc(dst.slice(i * esize, esize), a.wrapping_sub(b));
        }
    }

    // [a, b][c, d] = [a + b, c + d]
    fn vector_pairwise_add(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let esize = cpu.args[0] as u8;

        let dst_low = dst.slice(0, dst.size / 2);
        for i in 0..(dst_low.size / esize) {
            let a: u64 = cpu.read_dynamic(args[0].slice((i * 2) * esize, esize)).zxt();
            let b: u64 = cpu.read_dynamic(args[0].slice(((i * 2) + 1) * esize, esize)).zxt();
            cpu.write_trunc(dst_low.slice(i * esize, esize), a.wrapping_add(b));
        }
        let dst_high = dst.slice(dst.size / 2, dst.size / 2);
        for i in 0..(dst_high.size / esize) {
            let a: u64 = cpu.read_dynamic(args[1].slice((i * 2) * esize, esize)).zxt();
            let b: u64 = cpu.read_dynamic(args[1].slice(((i * 2) + 1) * esize, esize)).zxt();
            cpu.write_trunc(dst_high.slice(i * esize, esize), a.wrapping_add(b));
        }
    }

    fn vrev(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let esize: u8 = cpu.read_dynamic(args[1]).zxt();
        for i in 0..(dst.size / esize) {
            let a: u64 = cpu.read_dynamic(args[0].slice(i * esize, esize)).zxt();
            cpu.write_trunc(dst.slice(dst.size - (i + 1) * esize, esize), a);
        }
    }

    /// Copy the lower bits of a quadword vector to a doubleword vector.
    /// arg[0] = source, arg[1] = element size
    ///
    /// e.g., for element size = 4:
    /// arg[0] [a:u32, b:32, c:u32, d:u32], dst=[a:u16, b:u16, c:u16, d:u16]
    fn vector_copy_narrow(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let src = args[0];
        let esize = cpu.read::<u8>(args[1]);
        let dst_esize = esize / 2;
        for i in 0..(src.size() / esize) {
            let value: u64 = cpu.read_dynamic(src.slice(i * esize, esize)).zxt();
            cpu.write_trunc(dst.slice(i * dst_esize, dst_esize), value);
        }
    }

    fn coprocessor_move_from_rt(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let coproc = cpu.read::<u32>(args[0]);
        let opc1 = cpu.read::<u32>(args[1]);
        let crm = cpu.args[0] as u32;
        let result = coprocessor_read(cpu, coproc, opc1, crm) as u32;
        cpu.write_var(dst, result);
    }

    fn coprocessor_move_from_rt2(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let coproc = cpu.read::<u32>(args[0]);
        let opc1 = cpu.read::<u32>(args[1]);
        let crm = cpu.args[0] as u32;
        let result = (coprocessor_read(cpu, coproc, opc1, crm) >> 32) as u32;
        cpu.write_var(dst, result);
    }

    fn coprocessor_read(cpu: &mut Cpu, coproc: u32, opc1: u32, crm: u32) -> u64 {
        /// Virtual count register
        const CNTVCT: (u32, u32, u32) = (0b1111, 0b1110, 0b0001);

        match (coproc, crm, opc1) {
            CNTVCT => cpu.icount(),
            _ => {
                tracing::debug!("Unknown MSR: coproc=p{coproc}, opc1={opc1}, crm=c{crm}");
                cpu.exception.code = ExceptionCode::UnimplementedOp as u32;
                0
            }
        }
    }

    // Pseudocode from https://developer.arm.com/documentation/ddi0597/2023-09/Shared-Pseudocode/shared-functions-float
    //
    // SLEIGH signature: FixedToFP(fp, M, N, fbits, unsigned, rounding)
    fn fpu_fixed_to_fp(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let m = cpu.read::<u32>(args[1]);
        let n = cpu.args[0];
        let fbits = cpu.args[1];
        let is_unsigned = cpu.args[2] != 0;
        let rounding = cpu.args[3];

        assert!(m == 16 || m == 32, "fixed-point size must be 16 or 32 bits");
        assert!(n == 32 || n == 64, "floating-point size must be 32 or 64 bits");
        assert!(fbits <= u128::from(m), "fractional bits must fit in the fixed-point value");
        assert!(rounding == 0, "only the default ARM rounding mode is implemented");

        // Read the source register at its native VarNode size, then truncate to
        // the fixed-point width `m`.
        let raw: u64 = cpu.read_dynamic(args[0]).zxt();
        let value: i64 = match (is_unsigned, m) {
            (false, 16) => (raw as i16).into(),
            (false, 32) => (raw as i32).into(),
            (true, 16) => (raw as u16).into(),
            (true, 32) => (raw as u32).into(),
            _ => unreachable!(),
        };

        // Scaling by a power of two is exact, so convert-then-divide rounds
        // once, matching the single FPRound in the ARM pseudocode.
        let scale = (1u64 << fbits) as f64;
        match n {
            32 => cpu.write_trunc(dst, (value as f32 / scale as f32).to_bits()),
            64 => cpu.write_trunc(dst, (value as f64 / scale).to_bits()),
            _ => unreachable!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bcd_add16() {
        assert_eq!(bcd_add16(0x0001, 0x0009), 0x0010);
        assert_eq!(bcd_add16(0x0001, 0x0019), 0x0020);
        assert_eq!(bcd_add16(0x0001, 0x0099), 0x0100);
        assert_eq!(bcd_add16(0x0001, 0x0199), 0x0200);
        assert_eq!(bcd_add16(0x0001, 0x0999), 0x1000);

        assert_eq!(bcd_add16(0x1234, 0x1234), 0x2468);
        assert_eq!(bcd_add16(0x0555, 0x5555), 0x6110);
    }

    /// Regression test: `fpu_fixed_to_fp` used to read the source register
    /// based on `n` (float output size) rather than the VarNode's actual size.
    /// When the source VarNode was 8 bytes but `n == 32`, the read panicked
    /// with "read/write to invalid VarNode: … of size: 4".
    #[test]
    fn test_fpu_fixed_to_fp_8byte_varnode_n32() {
        let arch = crate::Arch::none();
        let mut cpu = crate::Cpu::new_boxed(arch);

        // Source register "a" (8 bytes) and destination register "b" (8 bytes).
        let reg_a = cpu.arch.sleigh.get_varnode("a").unwrap();
        let reg_b = cpu.arch.sleigh.get_varnode("b").unwrap();

        // Write a fixed-point value into the 8-byte source register.
        // Using 0x0001_0000 which represents 1.0 with 16 fractional bits.
        cpu.write_var::<u64>(reg_a, 0x0001_0000);

        // args[1] = m (fixed-point size in bits); pass via a const Value.
        let m_value = pcode::Value::Const(32, 4);
        let src_value = pcode::Value::Var(reg_a);

        // cpu.args: [0]=n (float size), [1]=fbits, [2]=unsigned flag (0 = signed), [3]=rounding
        cpu.args[0] = 32; // n = 32-bit float output
        cpu.args[1] = 16; // fbits = 16 fractional bits
        cpu.args[2] = 0; // signed
        cpu.args[3] = 0; // default rounding

        // Call through the public HELPERS table (same path as the interpreter).
        let helper = arm::HELPERS.iter().find(|(name, _)| *name == "FixedToFP").unwrap().1;
        // This panicked before the fix because the 8-byte VarNode was read as i32.
        helper(&mut cpu, reg_b, [src_value, m_value]);

        // Result should be 1.0f32 written into the lower bytes of reg_b.
        let result: u64 = cpu.read_var(reg_b);
        let float_val = f32::from_bits(result as u32);
        assert!((float_val - 1.0).abs() < f32::EPSILON, "expected 1.0, got {float_val}");
    }

    /// `fbits == 32` is encodable (`vcvt.f32.s32 d0, d0, #32`: fbits = 64 - imm6)
    /// and is the boundary case for the scale-factor shift.
    #[test]
    fn test_fpu_fixed_to_fp_fbits_32() {
        let arch = crate::Arch::none();
        let mut cpu = crate::Cpu::new_boxed(arch);

        let reg_a = cpu.arch.sleigh.get_varnode("a").unwrap();
        let reg_b = cpu.arch.sleigh.get_varnode("b").unwrap();

        // 0x8000_0000 as a signed 32-bit fixed-point value with 32 fractional
        // bits represents -2^31 / 2^32 = -0.5.
        cpu.write_var::<u64>(reg_a, 0x8000_0000);

        let m_value = pcode::Value::Const(32, 4);
        let src_value = pcode::Value::Var(reg_a);

        cpu.args[0] = 32; // n = 32-bit float output
        cpu.args[1] = 32; // fbits = 32 fractional bits
        cpu.args[2] = 0; // signed
        cpu.args[3] = 0; // default rounding

        let helper = arm::HELPERS.iter().find(|(name, _)| *name == "FixedToFP").unwrap().1;
        helper(&mut cpu, reg_b, [src_value, m_value]);

        let result: u64 = cpu.read_var(reg_b);
        let float_val = f32::from_bits(result as u32);
        assert!((float_val + 0.5).abs() < f32::EPSILON, "expected -0.5, got {float_val}");
    }
}
