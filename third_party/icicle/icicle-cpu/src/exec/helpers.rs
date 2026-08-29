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
        ("rdtscp", rdtscp),
        ("cpuid_basic_info", cpuid_basic_info),
        ("cpuid_Version_info", cpuid_version_info),
        ("cpuid_Extended_Feature_Enumeration_info", cpuid_extended_feature_enumeration_info),
        ("cpuid", cpuid),
        ("movmskpd", movmskpd),
        ("movmskps", movmskps),
        ("pinsrw", pinsrw), // Note: implemented in SLEIGH in Ghidra 10.3.
        ("pshuflw", pshuflw),
        ("pshufhw", pshufhw),
        ("shufpd", shufpd), // Note: implemented in SLEIGH in Ghidra 10.3.
        ("pmaddwd", pmaddwd),
        ("psadbw", psadbw),
        ("pshufb", pshufb),
        ("roundsd", roundsd),
        ("roundss", roundss),
        ("pmulhuw", pmulhuw),
        ("pmulhw", pmulhw),
        ("pmulld", pmulld),
        ("packsswb", packsswb),
        ("packuswb", packuswb),
        ("packssdw", packssdw),
        ("packusdw", packusdw),
        ("pavgb", pavgb),
        ("pavgw", pavgw),
        ("punpcklqdq", punpcklqdq),
        ("pabsb", pabsb),
        ("pabsw", pabsw),
        ("pabsd", pabsd),
        ("psllw", psllw),
        ("psraw", psraw),
        ("divpd", divpd),
        ("divps", divps),
        ("maxpd", maxpd),
        ("maxps", maxps),
        ("minpd", minpd),
        ("minps", minps),
        ("sqrtpd", sqrtpd),
        ("sqrtps", sqrtps),
        // SSE4.1 / SSSE3 ops the spec leaves opaque. Compilers targeting the
        // x86-64-v2 baseline emit these unconditionally, without a CPUID
        // check, so static binaries hit them even when CPUID stays quiet.
        ("pblendw", pblendw),
        ("pblendvb", pblendvb),
        ("blendvps", blendvps),
        ("blendvpd", blendvpd),
        ("pmovzxbw", pmovzxbw),
        ("pmovzxbd", pmovzxbd),
        ("pmovzxbq", pmovzxbq),
        ("pmovzxwd", pmovzxwd),
        ("pmovzxwq", pmovzxwq),
        ("pmovzxdq", pmovzxdq),
        ("pmovsxbw", pmovsxbw),
        ("pmovsxbd", pmovsxbd),
        ("pmovsxbq", pmovsxbq),
        ("pmovsxwd", pmovsxwd),
        ("pmovsxwq", pmovsxwq),
        ("pmovsxdq", pmovsxdq),
        ("pmuldq", pmuldq),
        ("pmulhrsw", pmulhrsw),
        ("pmaddubsw", pmaddubsw),
        ("psignb", psignb),
        ("psignw", psignw),
        ("psignd", psignd),
        ("phaddw", phaddw),
        ("phaddd", phaddd),
        ("phaddsw", phaddsw),
        ("phsubw", phsubw),
        ("phsubd", phsubd),
        ("phsubsw", phsubsw),
        ("phminposuw", phminposuw),
        ("insertps", insertps),
        ("extractps", extractps),
        ("roundps", roundps),
        ("roundpd", roundpd),
        // MMX/SSE2 saturating packed arithmetic (also opaque in the spec).
        ("paddsb", paddsb),
        ("paddsw", paddsw),
        ("paddusb", paddusb),
        ("paddusw", paddusw),
        ("psubsb", psubsb),
        ("psubsw", psubsw),
        ("psubusb", psubusb),
        ("psubusw", psubusw),
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
        ("fprem", fprem),
        ("fprem1", fprem1),
        ("fist_round", fist_round),
        ("f2xm1", f2xm1),
        ("fscale", fscale),
    ];

    fn rdtsc(cpu: &mut Cpu, dst: VarNode, _: [Value; 2]) {
        // One retired instruction is one cycle, matching the guest clock's
        // one-instruction-one-nanosecond model (an invariant 1 GHz TSC). The
        // counter must advance: code that spin-waits on `rdtsc` deltas (timer
        // calibration, backoff loops) never terminates on a constant TSC.
        cpu.write_var(dst, cpu.icount());
    }

    // The SLEIGH spec calls `rdtscp()` with no output, so the helper writes
    // the architectural results itself: EDX:EAX = TSC, ECX = IA32_TSC_AUX
    // (0: single processor), each as a full 64-bit register write, which
    // zeroes the upper halves exactly as 32-bit destinations do on x86-64.
    fn rdtscp(cpu: &mut Cpu, _: VarNode, _: [Value; 2]) {
        let tsc = cpu.icount();
        for (name, value) in [("RAX", tsc & 0xffff_ffff), ("RDX", tsc >> 32), ("RCX", 0)] {
            if let Some(var) = cpu.arch.sleigh.get_varnode(name) {
                cpu.write_var(var, value);
            }
        }
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

        // Advertise SSE/SSE2/SSE3, AES-NI, and PCLMULQDQ, but deliberately not
        // AVX or AVX-512: those encodings decode but their p-code semantics are
        // not all validated, so userspace stays on the SSE paths. `avx`,
        // `osxsave`, and `f16c` are left clear. AES-NI and PCLMULQDQ *are*
        // advertised: their primitives are supported here (the AES round ops
        // as helpers, PCLMULQDQ as an inlined SLEIGH macro, both verified
        // against the native intrinsics), so a TLS client can use the
        // hardware AES-GCM (AES-NI + carryless-multiply GHASH) SSE path
        // instead of a software fallback. AVX-only fused GCM stays off.
        //
        // SSE4 is left clear as a conservative choice, not a proven blocker
        // (advertising it currently passes every test, Node included). SSE4.1/
        // 4.2 add ~50 instructions — most notably the SSE4.2 string ops
        // (`pcmpistri`/`pcmpestri`, used by glibc strlen/strchr) and packed
        // rounds — that have no helpers here; keeping the bit clear avoids
        // opting feature-detecting code onto those unvalidated paths, and onto
        // more uses of `roundsd`/`roundss`, whose imm8 rounding mode icicle's
        // two-operand p-code drops (so those helpers can only round to
        // nearest — a silent approximation for floor/ceil/trunc).
        let ecx: u32 = (Feature::sse3
            | Feature::pclmulqdq
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

            // Highest extended function implemented. Reporting none is not a
            // position a 64-bit processor can hold: every x86-64 part answers
            // leaf 0x8000_0001, and programs read it without asking first.
            0x8000_0000 => {
                cpu.write_var(dst.slice(0, 4), 0x8000_0001_u32);
                cpu.write_var(dst.slice(4, 4), 0_u32);
                cpu.write_var(dst.slice(8, 4), 0_u32);
                cpu.write_var(dst.slice(12, 4), 0_u32);
            }

            // Extended processor info. Only what this engine actually
            // implements is advertised: long mode and `syscall`. Claiming a
            // feature that is not there is how a guest takes a path that then
            // executes something unimplemented.
            0x8000_0001 => {
                const SYSCALL: u32 = 1 << 11;
                const LONG_MODE: u32 = 1 << 29;
                cpu.write_var(dst.slice(0, 4), 0_u32);
                cpu.write_var(dst.slice(4, 4), 0_u32);
                cpu.write_var(dst.slice(8, 4), 0_u32);
                cpu.write_var(dst.slice(12, 4), SYSCALL | LONG_MODE);
            }

            // Anything else reads as zero. `CPUID` does not fault on real
            // hardware — an unimplemented leaf returns zeros — so raising an
            // exception turns a feature probe the guest is entitled to make
            // into a crash.
            unknown => {
                tracing::debug!("CPUID leaf {unknown:#x} answered with zeros");
                cpu.write_var(dst.slice(0, 4), 0_u32);
                cpu.write_var(dst.slice(4, 4), 0_u32);
                cpu.write_var(dst.slice(8, 4), 0_u32);
                cpu.write_var(dst.slice(12, 4), 0_u32);
            }
        }
    }

    /// Extract Packed Double-Precision Floating-Point Sign Mask
    fn movmskpd(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let Some(src) = xmm_bytes(cpu, args[1]) else {
            return;
        };
        let src = u128::from_le_bytes(src);
        let result = ((src >> 63) & 0b01) as u32 | ((src >> 126) & 0b10) as u32;

        // workaround SLEIGH bug? should zero extend to 64-bits
        cpu.write_var(VarNode::new(dst.id, 8), result as u64);
    }

    /// Extract the sign bit of each of the four packed single-precision floats
    /// into the low four bits of the destination register.
    fn movmskps(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let Some(src) = xmm_bytes(cpu, args[1]) else {
            return;
        };
        let src = u128::from_le_bytes(src);
        let result = ((src >> 31) & 0b0001) as u32
            | ((src >> 62) & 0b0010) as u32
            | ((src >> 93) & 0b0100) as u32
            | ((src >> 124) & 0b1000) as u32;
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
        // from args[0]. The imm8 rounding mode is the pcodeop's third input,
        // delivered via `cpu.args` (as the packed forms already read it): bit
        // 2 selects MXCSR rounding, which this machine keeps at the default
        // (nearest-even); bits 1:0 give the explicit mode. `Math.floor`,
        // `ceil`, and `trunc` all compile to this instruction, so rounding
        // every mode to nearest silently corrupts any program that indexes
        // with a floored value.
        let Some(upper) = xmm_bytes(cpu, args[0]) else {
            return;
        };
        // The scalar operand is a lane of a vector register, so a
        // narrower one has no lane to take.
        if args[1].size() < 8 {
            cpu.exception.code = ExceptionCode::UnimplementedOp as u32;
            return;
        }
        let imm = cpu.args[0] as u8;
        let mode = if imm & 4 != 0 { 0 } else { imm & 3 };
        let upper = u128::from_le_bytes(upper);
        let value = f64::from_bits(cpu.read::<u64>(args[1].slice(0, 8)));
        let rounded = match mode {
            0 => value.round_ties_even(),
            1 => value.floor(),
            2 => value.ceil(),
            _ => value.trunc(),
        }
        .to_bits();
        write_xmm(cpu, dst, ((upper & !0xffff_ffff_ffff_ffffu128) | rounded as u128).to_le_bytes());
    }

    fn roundss(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        // The f32 sibling of `roundsd`; same imm8-via-`cpu.args` contract.
        let Some(upper) = xmm_bytes(cpu, args[0]) else {
            return;
        };
        // The scalar operand is a lane of a vector register, so a
        // narrower one has no lane to take.
        if args[1].size() < 4 {
            cpu.exception.code = ExceptionCode::UnimplementedOp as u32;
            return;
        }
        let imm = cpu.args[0] as u8;
        let mode = if imm & 4 != 0 { 0 } else { imm & 3 };
        let upper = u128::from_le_bytes(upper);
        let value = f32::from_bits(cpu.read::<u32>(args[1].slice(0, 4)));
        let rounded = match mode {
            0 => value.round_ties_even(),
            1 => value.floor(),
            2 => value.ceil(),
            _ => value.trunc(),
        }
        .to_bits();
        write_xmm(cpu, dst, ((upper & !0xffff_ffffu128) | rounded as u128).to_le_bytes());
    }

    fn pshufb(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        // Byte shuffle: for each byte, a control byte with the high bit set
        // yields zero, otherwise it selects a source byte by its low nibble
        // (within the same 128-bit lane; only 16-byte operands are used here).
        let (Some(src), Some(ctrl)) = (xmm_bytes(cpu, args[0]), xmm_bytes(cpu, args[1])) else {
            return;
        };
        let mut out = [0u8; 16];
        for i in 0..16 {
            let c = ctrl[i];
            out[i] = if c & 0x80 != 0 { 0 } else { src[(c & 0x0f) as usize] };
        }
        write_xmm(cpu, dst, out);
    }

    // --- Packed-integer SIMD ops the spec leaves as opaque pcodeops -------
    // Verified against the native intrinsics in x64-engine/examples/sse_probe.

    /// The 128-bit operand these helpers are written for.
    ///
    /// The same opcodes have 64-bit MMX forms, which a guest can execute —
    /// nothing stops it mapping a page executable and jumping into one. A
    /// helper written for one width cannot answer for the other, and reading
    /// a register at a size it does not have is not an available answer: say
    /// the operation is unimplemented, the way an unknown one is.
    fn xmm_bytes(cpu: &mut Cpu, v: Value) -> Option<[u8; 16]> {
        if v.size() != 16 {
            cpu.exception.code = ExceptionCode::UnimplementedOp as u32;
            cpu.exception.value = v.size() as u64;
            return None;
        }
        Some(cpu.read::<u128>(v).to_le_bytes())
    }


    fn pmulhuw(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let (Some(a), Some(b)) = (xmm_bytes(cpu, args[0]), xmm_bytes(cpu, args[1])) else {
            return;
        };
        let mut out = [0u8; 16];
        for i in 0..8 {
            let x = u16::from_le_bytes([a[2 * i], a[2 * i + 1]]) as u32;
            let y = u16::from_le_bytes([b[2 * i], b[2 * i + 1]]) as u32;
            out[2 * i..2 * i + 2].copy_from_slice(&(((x * y) >> 16) as u16).to_le_bytes());
        }
        write_xmm(cpu, dst, out);
    }

    fn pmulhw(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let (Some(a), Some(b)) = (xmm_bytes(cpu, args[0]), xmm_bytes(cpu, args[1])) else {
            return;
        };
        let mut out = [0u8; 16];
        for i in 0..8 {
            let x = i16::from_le_bytes([a[2 * i], a[2 * i + 1]]) as i32;
            let y = i16::from_le_bytes([b[2 * i], b[2 * i + 1]]) as i32;
            out[2 * i..2 * i + 2].copy_from_slice(&(((x * y) >> 16) as i16).to_le_bytes());
        }
        write_xmm(cpu, dst, out);
    }

    fn pmulld(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let (Some(a), Some(b)) = (xmm_bytes(cpu, args[0]), xmm_bytes(cpu, args[1])) else {
            return;
        };
        let mut out = [0u8; 16];
        for i in 0..4 {
            let x = u32::from_le_bytes(a[4 * i..4 * i + 4].try_into().unwrap());
            let y = u32::from_le_bytes(b[4 * i..4 * i + 4].try_into().unwrap());
            out[4 * i..4 * i + 4].copy_from_slice(&x.wrapping_mul(y).to_le_bytes());
        }
        write_xmm(cpu, dst, out);
    }

    fn pack_words(cpu: &mut Cpu, dst: VarNode, args: [Value; 2], signed: bool) {
        let (Some(a), Some(b)) = (xmm_bytes(cpu, args[0]), xmm_bytes(cpu, args[1])) else {
            return;
        };
        let mut out = [0u8; 16];
        for (half, src) in [a, b].into_iter().enumerate() {
            for i in 0..8 {
                let w = i16::from_le_bytes([src[2 * i], src[2 * i + 1]]) as i32;
                out[half * 8 + i] = if signed {
                    w.clamp(-128, 127) as i8 as u8
                } else {
                    w.clamp(0, 255) as u8
                };
            }
        }
        write_xmm(cpu, dst, out);
    }

    fn packsswb(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        pack_words(cpu, dst, args, true);
    }
    fn packuswb(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        pack_words(cpu, dst, args, false);
    }

    fn pack_dwords(cpu: &mut Cpu, dst: VarNode, args: [Value; 2], signed: bool) {
        let (Some(a), Some(b)) = (xmm_bytes(cpu, args[0]), xmm_bytes(cpu, args[1])) else {
            return;
        };
        let mut out = [0u8; 16];
        for (half, src) in [a, b].into_iter().enumerate() {
            for i in 0..4 {
                let d = i32::from_le_bytes(src[4 * i..4 * i + 4].try_into().unwrap());
                let w = if signed {
                    d.clamp(-32768, 32767) as i16 as u16
                } else {
                    d.clamp(0, 65535) as u16
                };
                out[half * 8 + 2 * i..half * 8 + 2 * i + 2].copy_from_slice(&w.to_le_bytes());
            }
        }
        write_xmm(cpu, dst, out);
    }

    fn packssdw(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        pack_dwords(cpu, dst, args, true);
    }
    fn packusdw(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        pack_dwords(cpu, dst, args, false);
    }

    /// Shift count for a packed-shift pcodeop: the low bits of the second
    /// operand (an imm8, m64, or xmm). Saturated so callers can treat any
    /// count past the element width as a full shift-out.
    fn simd_shift_count(cpu: &mut Cpu, v: Value) -> u32 {
        let raw: u128 = match v.size() {
            16 => cpu.read::<u128>(v),
            _ => {
                let x: u64 = cpu.read_dynamic(v).zxt();
                x as u128
            }
        };
        raw.min(255) as u32
    }

    fn psllw(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let count = simd_shift_count(cpu, args[1]);
        for i in (0..dst.size).step_by(2) {
            let w: u16 = cpu.read(args[0].slice(i, 2));
            let r = if count >= 16 { 0 } else { w << count };
            cpu.write_var(dst.slice(i, 2), r);
        }
    }

    fn psraw(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let count = simd_shift_count(cpu, args[1]);
        for i in (0..dst.size).step_by(2) {
            let w = cpu.read::<u16>(args[0].slice(i, 2)) as i16;
            let r = if count >= 16 {
                (w >> 15) as u16
            } else {
                (w >> count) as u16
            };
            cpu.write_var(dst.slice(i, 2), r);
        }
    }

    // pavg* are invoked element-wise by the spec (one call per lane).
    fn pavgb(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let a: u8 = cpu.read(args[0]);
        let b: u8 = cpu.read(args[1]);
        cpu.write_var(dst, ((a as u16 + b as u16 + 1) >> 1) as u8);
    }

    fn pavgw(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let a: u16 = cpu.read(args[0]);
        let b: u16 = cpu.read(args[1]);
        cpu.write_var(dst, ((a as u32 + b as u32 + 1) >> 1) as u16);
    }

    fn punpcklqdq(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let (Some(a), Some(b)) = (xmm_bytes(cpu, args[0]), xmm_bytes(cpu, args[1])) else {
            return;
        };
        let mut out = [0u8; 16];
        out[0..8].copy_from_slice(&a[0..8]);
        out[8..16].copy_from_slice(&b[0..8]);
        write_xmm(cpu, dst, out);
    }

    /// pabs* take the source in the second operand; the first is the (unused)
    /// destination register the pcodeop is written with.
    fn pabsb(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let Some(s) = xmm_bytes(cpu, args[1]) else {
            return;
        };
        let out: [u8; 16] = std::array::from_fn(|i| (s[i] as i8).unsigned_abs());
        write_xmm(cpu, dst, out);
    }
    fn pabsw(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let Some(s) = xmm_bytes(cpu, args[1]) else {
            return;
        };
        let mut out = [0u8; 16];
        for i in 0..8 {
            let w = i16::from_le_bytes([s[2 * i], s[2 * i + 1]]).unsigned_abs();
            out[2 * i..2 * i + 2].copy_from_slice(&w.to_le_bytes());
        }
        write_xmm(cpu, dst, out);
    }
    fn pabsd(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let Some(s) = xmm_bytes(cpu, args[1]) else {
            return;
        };
        let mut out = [0u8; 16];
        for i in 0..4 {
            let d = i32::from_le_bytes(s[4 * i..4 * i + 4].try_into().unwrap()).unsigned_abs();
            out[4 * i..4 * i + 4].copy_from_slice(&d.to_le_bytes());
        }
        write_xmm(cpu, dst, out);
    }

    // --- Packed floating-point SIMD ops (whole-register pcodeops) ---------
    // SSE max/min return the second operand on unordered/equal, matching
    // `(a OP b) ? a : b`.

    fn f64x2_binop(cpu: &mut Cpu, dst: VarNode, args: [Value; 2], f: fn(f64, f64) -> f64) {
        let Some(a) = xmm_bytes(cpu, args[0]) else {
            return;
        };
        let Some(b) = xmm_bytes(cpu, args[1]) else {
            return;
        };
        let mut out = [0u8; 16];
        for i in 0..2 {
            let x = f64::from_bits(u64::from_le_bytes(a[8 * i..8 * i + 8].try_into().unwrap()));
            let y = f64::from_bits(u64::from_le_bytes(b[8 * i..8 * i + 8].try_into().unwrap()));
            out[8 * i..8 * i + 8].copy_from_slice(&f(x, y).to_bits().to_le_bytes());
        }
        write_xmm(cpu, dst, out);
    }

    fn f32x4_binop(cpu: &mut Cpu, dst: VarNode, args: [Value; 2], f: fn(f32, f32) -> f32) {
        let Some(a) = xmm_bytes(cpu, args[0]) else {
            return;
        };
        let Some(b) = xmm_bytes(cpu, args[1]) else {
            return;
        };
        let mut out = [0u8; 16];
        for i in 0..4 {
            let x = f32::from_bits(u32::from_le_bytes(a[4 * i..4 * i + 4].try_into().unwrap()));
            let y = f32::from_bits(u32::from_le_bytes(b[4 * i..4 * i + 4].try_into().unwrap()));
            out[4 * i..4 * i + 4].copy_from_slice(&f(x, y).to_bits().to_le_bytes());
        }
        write_xmm(cpu, dst, out);
    }

    fn divpd(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        f64x2_binop(cpu, dst, args, |x, y| x / y);
    }
    fn divps(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        f32x4_binop(cpu, dst, args, |x, y| x / y);
    }
    fn maxpd(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        f64x2_binop(cpu, dst, args, |x, y| if x > y { x } else { y });
    }
    fn maxps(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        f32x4_binop(cpu, dst, args, |x, y| if x > y { x } else { y });
    }
    fn minpd(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        f64x2_binop(cpu, dst, args, |x, y| if x < y { x } else { y });
    }
    fn minps(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        f32x4_binop(cpu, dst, args, |x, y| if x < y { x } else { y });
    }

    // sqrt takes its source in the second operand (like pabs).
    fn sqrtpd(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        f64x2_binop(cpu, dst, [args[1], args[1]], |x, _| x.sqrt());
    }
    fn sqrtps(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        f32x4_binop(cpu, dst, [args[1], args[1]], |x, _| x.sqrt());
    }

    // --- SSE4.1 / SSSE3 -------------------------------------------------

    fn pblendw(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        // Third operand (imm8) arrives via the pcode arg slot.
        let (Some(a), Some(b)) = (xmm_bytes(cpu, args[0]), xmm_bytes(cpu, args[1])) else {
            return;
        };
        let mask = cpu.args[0] as u8;
        let mut out = [0u8; 16];
        for i in 0..8 {
            let src = if mask >> i & 1 == 0 { &a } else { &b };
            out[2 * i..2 * i + 2].copy_from_slice(&src[2 * i..2 * i + 2]);
        }
        write_xmm(cpu, dst, out);
    }

    fn pblendvb(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        // Third operand (the implicit XMM0 mask) arrives via the arg slot.
        let (Some(a), Some(b)) = (xmm_bytes(cpu, args[0]), xmm_bytes(cpu, args[1])) else {
            return;
        };
        let mask = cpu.args[0].to_le_bytes();
        let mut out = [0u8; 16];
        for i in 0..16 {
            out[i] = if mask[i] & 0x80 != 0 { b[i] } else { a[i] };
        }
        write_xmm(cpu, dst, out);
    }

    fn blendv_lanes(cpu: &mut Cpu, dst: VarNode, args: [Value; 2], lane: usize) {
        let (Some(a), Some(b)) = (xmm_bytes(cpu, args[0]), xmm_bytes(cpu, args[1])) else {
            return;
        };
        let mask = cpu.args[0].to_le_bytes();
        let mut out = [0u8; 16];
        for i in (0..16).step_by(lane) {
            let take_b = mask[i + lane - 1] & 0x80 != 0; // sign bit of the lane
            let src = if take_b { &b } else { &a };
            out[i..i + lane].copy_from_slice(&src[i..i + lane]);
        }
        write_xmm(cpu, dst, out);
    }

    fn blendvps(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        blendv_lanes(cpu, dst, args, 4);
    }

    fn blendvpd(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        blendv_lanes(cpu, dst, args, 8);
    }

    /// Packed move-with-extend: widen `count` elements of `from` bytes each
    /// to `16 / count` bytes, zero- or sign-extending. The source operand
    /// may be a narrow memory value, so only the needed low bytes are read.
    fn pmov_extend(
        cpu: &mut Cpu,
        dst: VarNode,
        src: Value,
        from: usize,
        count: usize,
        signed: bool,
    ) {
        let need = (from * count).min(src.size() as usize);
        let mut src_bytes = [0u8; 16];
        for (i, slot) in src_bytes.iter_mut().enumerate().take(need) {
            *slot = cpu.read::<u8>(src.slice(i as u8, 1));
        }
        let to = 16 / count;
        let mut out = [0u8; 16];
        for i in 0..count {
            let chunk = &src_bytes[from * i..from * i + from];
            let fill = if signed && chunk[from - 1] & 0x80 != 0 { 0xff } else { 0 };
            let lane = &mut out[to * i..to * i + to];
            lane.fill(fill);
            lane[..from].copy_from_slice(chunk);
        }
        write_xmm(cpu, dst, out);
    }

    fn pmovzxbw(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        pmov_extend(cpu, dst, args[1], 1, 8, false);
    }
    fn pmovzxbd(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        pmov_extend(cpu, dst, args[1], 1, 4, false);
    }
    fn pmovzxbq(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        pmov_extend(cpu, dst, args[1], 1, 2, false);
    }
    fn pmovzxwd(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        pmov_extend(cpu, dst, args[1], 2, 4, false);
    }
    fn pmovzxwq(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        pmov_extend(cpu, dst, args[1], 2, 2, false);
    }
    fn pmovzxdq(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        pmov_extend(cpu, dst, args[1], 4, 2, false);
    }
    fn pmovsxbw(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        pmov_extend(cpu, dst, args[1], 1, 8, true);
    }
    fn pmovsxbd(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        pmov_extend(cpu, dst, args[1], 1, 4, true);
    }
    fn pmovsxbq(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        pmov_extend(cpu, dst, args[1], 1, 2, true);
    }
    fn pmovsxwd(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        pmov_extend(cpu, dst, args[1], 2, 4, true);
    }
    fn pmovsxwq(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        pmov_extend(cpu, dst, args[1], 2, 2, true);
    }
    fn pmovsxdq(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        pmov_extend(cpu, dst, args[1], 4, 2, true);
    }

    fn pmuldq(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        // Signed multiply of dwords 0 and 2 into two 64-bit products.
        let (Some(a), Some(b)) = (xmm_bytes(cpu, args[0]), xmm_bytes(cpu, args[1])) else {
            return;
        };
        let mut out = [0u8; 16];
        for i in 0..2 {
            let x = i32::from_le_bytes(a[8 * i..8 * i + 4].try_into().unwrap()) as i64;
            let y = i32::from_le_bytes(b[8 * i..8 * i + 4].try_into().unwrap()) as i64;
            out[8 * i..8 * i + 8].copy_from_slice(&x.wrapping_mul(y).to_le_bytes());
        }
        write_xmm(cpu, dst, out);
    }

    fn pmulhrsw(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let (Some(a), Some(b)) = (xmm_bytes(cpu, args[0]), xmm_bytes(cpu, args[1])) else {
            return;
        };
        let mut out = [0u8; 16];
        for i in 0..8 {
            let x = i16::from_le_bytes([a[2 * i], a[2 * i + 1]]) as i32;
            let y = i16::from_le_bytes([b[2 * i], b[2 * i + 1]]) as i32;
            let r = ((x * y >> 14) + 1) >> 1;
            out[2 * i..2 * i + 2].copy_from_slice(&(r as i16).to_le_bytes());
        }
        write_xmm(cpu, dst, out);
    }

    fn pmaddubsw(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        // Unsigned bytes of a times signed bytes of b, adjacent pairs
        // summed with signed saturation.
        let (Some(a), Some(b)) = (xmm_bytes(cpu, args[0]), xmm_bytes(cpu, args[1])) else {
            return;
        };
        let mut out = [0u8; 16];
        for i in 0..8 {
            let lo = a[2 * i] as i32 * (b[2 * i] as i8) as i32;
            let hi = a[2 * i + 1] as i32 * (b[2 * i + 1] as i8) as i32;
            let sum = (lo + hi).clamp(i16::MIN as i32, i16::MAX as i32) as i16;
            out[2 * i..2 * i + 2].copy_from_slice(&sum.to_le_bytes());
        }
        write_xmm(cpu, dst, out);
    }

    /// Reads a signed `lane`-byte element starting at `bytes[at]`.
    fn lane_i64(bytes: &[u8; 16], at: usize, lane: usize) -> i64 {
        let mut w = [0u8; 8];
        w[..lane].copy_from_slice(&bytes[at..at + lane]);
        if bytes[at + lane - 1] & 0x80 != 0 {
            w[lane..].fill(0xff);
        }
        i64::from_le_bytes(w)
    }

    fn psign_lanes(cpu: &mut Cpu, dst: VarNode, args: [Value; 2], lane: usize) {
        let size = (dst.size as usize).min(16);
        let read = |cpu: &mut Cpu, v: Value| {
            let mut bytes = [0u8; 16];
            for (i, slot) in bytes.iter_mut().enumerate().take(size) {
                *slot = cpu.read::<u8>(v.slice(i as u8, 1));
            }
            bytes
        };
        let (a, b) = (read(cpu, args[0]), read(cpu, args[1]));
        let mut out = [0u8; 16];
        for i in (0..size).step_by(lane) {
            let mut x = lane_i64(&a, i, lane);
            if b[i..i + lane].iter().all(|&v| v == 0) {
                x = 0;
            } else if b[i + lane - 1] & 0x80 != 0 {
                x = x.wrapping_neg();
            }
            out[i..i + lane].copy_from_slice(&x.to_le_bytes()[..lane]);
        }
        for (off, byte) in out[..size].iter().enumerate() {
            cpu.write_var::<u8>(dst.slice(off as u8, 1), *byte);
        }
    }

    fn psignb(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        psign_lanes(cpu, dst, args, 1);
    }
    fn psignw(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        psign_lanes(cpu, dst, args, 2);
    }
    fn psignd(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        psign_lanes(cpu, dst, args, 4);
    }

    /// Horizontal add/sub over `lane`-byte signed elements of the operand
    /// pair, with optional saturation (word lanes only). Handles both the
    /// 8-byte MMX and 16-byte XMM forms via the destination size.
    fn phop_lanes(
        cpu: &mut Cpu,
        dst: VarNode,
        args: [Value; 2],
        lane: usize,
        sub: bool,
        saturate: bool,
    ) {
        let size = (dst.size as usize).min(16);
        let read = |cpu: &mut Cpu, v: Value| {
            let mut bytes = [0u8; 16];
            for (i, slot) in bytes.iter_mut().enumerate().take(size) {
                *slot = cpu.read::<u8>(v.slice(i as u8, 1));
            }
            bytes
        };
        let (a, b) = (read(cpu, args[0]), read(cpu, args[1]));
        let lanes = size / lane;
        let mut out = [0u8; 16];
        for i in 0..lanes {
            // First half of the results pairs up a; second half pairs up b.
            let (src, base) = if i < lanes / 2 { (&a, 2 * i) } else { (&b, 2 * (i - lanes / 2)) };
            let x = lane_i64(src, lane * base, lane);
            let y = lane_i64(src, lane * (base + 1), lane);
            let mut r = if sub { x - y } else { x + y };
            if saturate {
                r = r.clamp(i16::MIN as i64, i16::MAX as i64);
            }
            out[lane * i..lane * i + lane].copy_from_slice(&r.to_le_bytes()[..lane]);
        }
        for (off, byte) in out[..size].iter().enumerate() {
            cpu.write_var::<u8>(dst.slice(off as u8, 1), *byte);
        }
    }

    fn phaddw(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        phop_lanes(cpu, dst, args, 2, false, false);
    }
    fn phaddd(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        phop_lanes(cpu, dst, args, 4, false, false);
    }
    fn phaddsw(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        phop_lanes(cpu, dst, args, 2, false, true);
    }
    fn phsubw(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        phop_lanes(cpu, dst, args, 2, true, false);
    }
    fn phsubd(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        phop_lanes(cpu, dst, args, 4, true, false);
    }
    fn phsubsw(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        phop_lanes(cpu, dst, args, 2, true, true);
    }

    fn phminposuw(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        // Single-operand op: the source is the only input.
        let Some(src) = xmm_bytes(cpu, args[0]) else {
            return;
        };
        let mut best = (u16::MAX, 0u16);
        for i in 0..8 {
            let w = u16::from_le_bytes([src[2 * i], src[2 * i + 1]]);
            if w < best.0 {
                best = (w, i as u16);
            }
        }
        cpu.write_var(dst, best.0 as u128 | (best.1 as u128) << 16);
    }

    fn insertps(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let Some(a) = xmm_bytes(cpu, args[0]) else {
            return;
        };
        let imm = cpu.args[0] as u8;
        // Register source: dword selected by bits 7:6; memory source: the
        // 32-bit value itself.
        let src = if args[1].size() >= 16 {
            let Some(b) = xmm_bytes(cpu, args[1]) else {
            return;
        };
            let idx = (imm >> 6 & 3) as usize;
            u32::from_le_bytes(b[4 * idx..4 * idx + 4].try_into().unwrap())
        } else {
            cpu.read::<u32>(args[1].slice(0, 4))
        };
        let mut out = a;
        let dst_idx = (imm >> 4 & 3) as usize;
        out[4 * dst_idx..4 * dst_idx + 4].copy_from_slice(&src.to_le_bytes());
        for i in 0..4 {
            if imm >> i & 1 != 0 {
                out[4 * i..4 * i + 4].fill(0);
            }
        }
        write_xmm(cpu, dst, out);
    }

    fn extractps(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        // dst is a 4- or 8-byte GPR/memory location; zero-extended dword.
        let Some(src) = xmm_bytes(cpu, args[0]) else {
            return;
        };
        let imm = cpu.read::<u64>(args[1]) as u8;
        let idx = (imm & 3) as usize;
        let value = u32::from_le_bytes(src[4 * idx..4 * idx + 4].try_into().unwrap());
        match dst.size {
            8 => cpu.write_var(dst, value as u64),
            _ => cpu.write_var(dst, value),
        }
    }

    fn roundp_lanes(cpu: &mut Cpu, dst: VarNode, args: [Value; 2], double: bool) {
        let Some(b) = xmm_bytes(cpu, args[1]) else {
            return;
        };
        // Bit 2 selects MXCSR rounding, which this machine keeps at the
        // default (nearest-even); bits 1:0 give the explicit mode.
        let imm = cpu.args[0] as u8;
        let mode = if imm & 4 != 0 { 0 } else { imm & 3 };
        let round64 = |v: f64| -> f64 {
            match mode {
                0 => v.round_ties_even(),
                1 => v.floor(),
                2 => v.ceil(),
                _ => v.trunc(),
            }
        };
        let mut out = [0u8; 16];
        if double {
            for i in 0..2 {
                let v =
                    f64::from_bits(u64::from_le_bytes(b[8 * i..8 * i + 8].try_into().unwrap()));
                out[8 * i..8 * i + 8].copy_from_slice(&round64(v).to_bits().to_le_bytes());
            }
        } else {
            for i in 0..4 {
                let v =
                    f32::from_bits(u32::from_le_bytes(b[4 * i..4 * i + 4].try_into().unwrap()));
                let r = round64(v as f64) as f32;
                out[4 * i..4 * i + 4].copy_from_slice(&r.to_bits().to_le_bytes());
            }
        }
        write_xmm(cpu, dst, out);
    }

    fn roundps(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        roundp_lanes(cpu, dst, args, false);
    }

    fn roundpd(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        roundp_lanes(cpu, dst, args, true);
    }

    /// Saturating packed add/sub over `lane`-byte elements (1 or 2 bytes),
    /// signed or unsigned. Handles both the 8-byte MMX and 16-byte XMM
    /// forms via the destination size.
    fn satop_lanes(
        cpu: &mut Cpu,
        dst: VarNode,
        args: [Value; 2],
        lane: usize,
        signed: bool,
        sub: bool,
    ) {
        let size = (dst.size as usize).min(16);
        let read = |cpu: &mut Cpu, v: Value| {
            let mut bytes = [0u8; 16];
            for (i, slot) in bytes.iter_mut().enumerate().take(size) {
                *slot = cpu.read::<u8>(v.slice(i as u8, 1));
            }
            bytes
        };
        let (a, b) = (read(cpu, args[0]), read(cpu, args[1]));
        let mut out = [0u8; 16];
        for i in (0..size).step_by(lane) {
            let (x, y) = if signed {
                (lane_i64(&a, i, lane), lane_i64(&b, i, lane))
            } else {
                let mut w = [0u8; 8];
                w[..lane].copy_from_slice(&a[i..i + lane]);
                let x = i64::from_le_bytes(w);
                w = [0u8; 8];
                w[..lane].copy_from_slice(&b[i..i + lane]);
                (x, i64::from_le_bytes(w))
            };
            let r = if sub { x - y } else { x + y };
            let (lo, hi) = match (signed, lane) {
                (true, 1) => (i8::MIN as i64, i8::MAX as i64),
                (true, _) => (i16::MIN as i64, i16::MAX as i64),
                (false, 1) => (0, u8::MAX as i64),
                (false, _) => (0, u16::MAX as i64),
            };
            let r = r.clamp(lo, hi);
            out[i..i + lane].copy_from_slice(&r.to_le_bytes()[..lane]);
        }
        for (off, byte) in out[..size].iter().enumerate() {
            cpu.write_var::<u8>(dst.slice(off as u8, 1), *byte);
        }
    }

    fn paddsb(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        satop_lanes(cpu, dst, args, 1, true, false);
    }
    fn paddsw(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        satop_lanes(cpu, dst, args, 2, true, false);
    }
    fn paddusb(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        satop_lanes(cpu, dst, args, 1, false, false);
    }
    fn paddusw(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        satop_lanes(cpu, dst, args, 2, false, false);
    }
    fn psubsb(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        satop_lanes(cpu, dst, args, 1, true, true);
    }
    fn psubsw(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        satop_lanes(cpu, dst, args, 2, true, true);
    }
    fn psubusb(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        satop_lanes(cpu, dst, args, 1, false, true);
    }
    fn psubusw(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        satop_lanes(cpu, dst, args, 2, false, true);
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

    /// The destination side of the same assumption `xmm_bytes` guards on the
    /// way in: a 128-bit result has nowhere to go in a narrower register.
    fn write_xmm(cpu: &mut Cpu, dst: VarNode, s: [u8; 16]) {
        if dst.size != 16 {
            cpu.exception.code = ExceptionCode::UnimplementedOp as u32;
            cpu.exception.value = dst.size as u64;
            return;
        }
        cpu.write_var(dst, u128::from_le_bytes(s));
    }

    fn aesenc(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let Some(state) = xmm_bytes(cpu, args[0]) else {
            return;
        };
        let Some(key) = xmm_bytes(cpu, args[1]) else {
            return;
        };
        let mut t = aes_shift_rows(&state, 1);
        aes_sub_bytes(&mut t, &AES_SBOX);
        let mut t = aes_mix_columns(&t, [2, 3, 1, 1]);
        for i in 0..16 {
            t[i] ^= key[i];
        }
        write_xmm(cpu, dst, t);
    }

    fn aesenclast(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let Some(state) = xmm_bytes(cpu, args[0]) else {
            return;
        };
        let Some(key) = xmm_bytes(cpu, args[1]) else {
            return;
        };
        let mut t = aes_shift_rows(&state, 1);
        aes_sub_bytes(&mut t, &AES_SBOX);
        for i in 0..16 {
            t[i] ^= key[i];
        }
        write_xmm(cpu, dst, t);
    }

    fn aesdec(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let Some(state) = xmm_bytes(cpu, args[0]) else {
            return;
        };
        let Some(key) = xmm_bytes(cpu, args[1]) else {
            return;
        };
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
        let Some(state) = xmm_bytes(cpu, args[0]) else {
            return;
        };
        let Some(key) = xmm_bytes(cpu, args[1]) else {
            return;
        };
        let inv = aes_inv_sbox();
        let mut t = aes_shift_rows(&state, 3);
        aes_sub_bytes(&mut t, &inv);
        for i in 0..16 {
            t[i] ^= key[i];
        }
        write_xmm(cpu, dst, t);
    }

    fn aesimc(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let Some(x) = xmm_bytes(cpu, args[0]) else {
            return;
        };
        let t = aes_mix_columns(&x, [14, 11, 13, 9]);
        write_xmm(cpu, dst, t);
    }

    fn aeskeygenassist(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let Some(x) = xmm_bytes(cpu, args[0]) else {
            return;
        };
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
    /// Reads an x87 operand: 80-bit extended, or a narrower float spilled
    /// to memory.
    fn x87_read(cpu: &mut Cpu, v: Value) -> f64 {
        match v.size() {
            10 => crate::exec::interpreter::f80_to_f64(cpu.read::<[u8; 10]>(v)),
            8 => f64::from_bits(cpu.read::<u64>(v)),
            _ => f32::from_bits(cpu.read::<u32>(v.slice(0, 4))) as f64,
        }
    }

    /// Writes an x87 result in the destination's own width.
    fn x87_write(cpu: &mut Cpu, dst: VarNode, value: f64) {
        match dst.size {
            10 => cpu.write_var(dst, crate::exec::interpreter::f64_to_f80(value)),
            8 => cpu.write_var(dst, value.to_bits()),
            _ => cpu.write_var(dst, (value as f32).to_bits()),
        }
    }

    fn fsin(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let x = x87_read(cpu, args[0]);
        x87_write(cpu, dst, x.sin());
    }

    /// Compute the approximate of the cosine of the source operand and store it in the destination
    fn fcos(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let x = x87_read(cpu, args[0]);
        x87_write(cpu, dst, x.cos());
    }

    /// Compute the approximate of the tangent of the source operand and store it in the destination
    fn fptan(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let x = x87_read(cpu, args[0]);
        x87_write(cpu, dst, x.tan());
    }

    /// `fist`/`fistp`: converts ST0 to an integer honoring the rounding
    /// control field of the FPU control word (second operand, via the arg
    /// slot): 0 nearest-even, 1 down, 2 up, 3 truncate.
    fn fist_round(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        use crate::exec::interpreter::softfp80::{self, RoundMode};
        let x = softfp80::parse(cpu.read::<[u8; 10]>(args[0]));
        let rc = match args[1].size() {
            2 => (cpu.read::<u16>(args[1]) >> 10) & 3,
            _ => (cpu.args[0] as u16 >> 10) & 3,
        };
        let mode = match rc {
            0 => RoundMode::NearestTiesEven,
            1 => RoundMode::Floor,
            2 => RoundMode::Ceil,
            _ => RoundMode::Trunc,
        };
        let v = softfp80::to_i128(softfp80::round_int(x, mode));
        match dst.size {
            2 => cpu.write_var(dst, v as i16),
            4 => cpu.write_var(dst, v as i32),
            _ => cpu.write_var(dst, v as i64),
        }
    }

    /// x87 partial remainder (truncating quotient, C2 cleared by the spec).
    fn fprem(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let (a, b) = (x87_read(cpu, args[0]), x87_read(cpu, args[1]));
        x87_write(cpu, dst, a % b);
    }

    /// x87 IEEE remainder (round-to-nearest quotient).
    fn fprem1(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let (a, b) = (x87_read(cpu, args[0]), x87_read(cpu, args[1]));
        let q = (a / b).round_ties_even();
        x87_write(cpu, dst, a - q * b);
    }

    /// Compute ST0 = 2^(ST0) - 1
    fn f2xm1(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let st0 = x87_read(cpu, args[0]);
        x87_write(cpu, dst, st0.exp2() - 1.0);
    }

    /// Compute ST0 = ST0 * 2^(trunc(ST1))
    fn fscale(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let st0 = x87_read(cpu, args[0]);
        let st1 = x87_read(cpu, args[1]);
        x87_write(cpu, dst, st0 * (2f64).powi(st1.trunc().clamp(-2000.0, 2000.0) as i32));
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
