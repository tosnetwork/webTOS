use pcode::{Value, VarNode};

use crate::{Cpu, ExceptionCode, ValueSource};

#[path = "x86_profile.rs"]
mod x86_profile;

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
        ("cpuid_Processor_Extended_States_info", cpuid_xstate_info),
        ("cpuid", cpuid),
        ("xgetbv", xgetbv),
        ("xsetbv", xsetbv),
        ("webtos_fxsave", fxsave),
        ("webtos_fxsave64", fxsave64),
        ("webtos_fxrstor", fxrstor),
        ("webtos_fxrstor64", fxrstor64),
        ("xsave", xsave),
        ("xsave64", xsave64),
        ("xrstor", xrstor),
        ("xrstor64", xrstor64),
        ("vpbroadcastd_avx512vl", vpbroadcastd_128),
        ("vpbroadcastd_avx512f", vpbroadcastd_128),
        ("vpternlogd_avx512vl", vpternlog_128),
        ("vpternlogd_avx512f", vpternlog_128),
        ("vpternlogq_avx512vl", vpternlog_128),
        ("vpternlogq_avx512f", vpternlog_128),
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
        // Generated AVX-family specifications leave several packed integer
        // operations opaque. These helpers are width-generic: they walk the
        // p-code Value in architectural lanes, so YMM/ZMM operands never pass
        // through a truncating whole-value u128 read.
        ("vpsubq_avx", packed_sub_q),
        ("vpsubq_avx2", packed_sub_q),
        ("vpsubq_avx512vl", packed_sub_q),
        ("vpsubq_avx512f", packed_sub_q),
        ("vpaddd_avx512vl", packed_add_d),
        ("vpaddd_avx512f", packed_add_d),
        ("vpcmpd_avx512vl", packed_compare_d_signed),
        ("vpcmpd_avx512f", packed_compare_d_signed),
        ("vpshufb_avx", pshufb),
        ("vpshufb_avx2", pshufb),
        ("vpshufb_avx512vl", pshufb),
        ("vpshufb_avx512bw", pshufb),
        ("webtos_vpmovmskb_128", packed_movemask_b),
        ("webtos_vpermd_lane_128", packed_permute_d_lane),
        ("webtos_vpermq_lane_128", packed_permute_q_lane),
        ("webtos_vpermd_256_chunk", packed_permute_d_256_chunk),
        ("webtos_vpermd_512_chunk", packed_permute_d_512_chunk),
        ("webtos_vpermq_256_chunk", packed_permute_q_256_chunk),
        ("webtos_vpcompressd_128_chunk", packed_compress_d_128_chunk),
        ("webtos_vpcompressd_256_chunk", packed_compress_d_256_chunk),
        ("webtos_vpcompressd_512_chunk", packed_compress_d_512_chunk),
        ("webtos_vpcompressd_mem_128", packed_compress_d_mem_128),
        ("webtos_vpcompressd_mem_256", packed_compress_d_mem_256),
        ("webtos_vpcompressd_mem_512", packed_compress_d_mem_512),
        ("webtos_vpexpandd_128_chunk", packed_expand_d_128_chunk),
        ("webtos_vpexpandd_256_chunk", packed_expand_d_256_chunk),
        ("webtos_vpexpandd_512_chunk", packed_expand_d_512_chunk),
        ("webtos_vpcompact_128_chunk", packed_compact_128_chunk),
        ("webtos_vpcompact_256_chunk", packed_compact_256_chunk),
        ("webtos_vpcompact_512_chunk", packed_compact_512_chunk),
        ("webtos_vpcompress_mem_128", packed_compress_mem_128),
        ("webtos_vpcompress_mem_256", packed_compress_mem_256),
        ("webtos_vpcompress_mem_512", packed_compress_mem_512),
        ("webtos_vpexpand_mem_128", packed_expand_mem_128),
        ("webtos_vpexpand_mem_256", packed_expand_mem_256),
        ("webtos_vpexpand_mem_512", packed_expand_mem_512),
        ("webtos_masked_load_128", masked_load_128),
        ("webtos_masked_store_128", masked_store_128),
        ("webtos_masked_store_256", masked_store_256),
        ("webtos_masked_store_512", masked_store_512),
        ("webtos_vptestm_128", packed_test_mask_128),
        ("webtos_vptestm_512", packed_test_mask_512),
        ("webtos_vptestm_mem_128", packed_test_mask_mem_128),
        ("webtos_vptestm_mem_256", packed_test_mask_mem_256),
        ("webtos_vptestm_mem_512", packed_test_mask_mem_512),
        ("webtos_vpopcnt_128", packed_popcount_128),
        ("webtos_vpopcnt_mem_128", packed_popcount_mem_128),
        ("webtos_vpmultishift_masked_128", packed_multishift_masked_128),
        ("webtos_vpmultishift_mem_128", packed_multishift_mem_128),
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

    fn packed_sub_q(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size == 0
            || dst.size > 64
            || dst.size % 8 != 0
            || args[0].size() != dst.size
            || args[1].size() != dst.size
        {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        for offset in (0..dst.size).step_by(8) {
            let left = cpu.read::<u64>(args[0].slice(offset, 8));
            let right = cpu.read::<u64>(args[1].slice(offset, 8));
            cpu.write_var(dst.slice(offset, 8), left.wrapping_sub(right));
        }
    }

    fn packed_add_d(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size == 0
            || dst.size > 16
            || dst.size % 4 != 0
            || args[0].size() != dst.size
            || args[1].size() != dst.size
        {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        for offset in (0..dst.size).step_by(4) {
            let left = cpu.read::<u32>(args[0].slice(offset, 4));
            let right = cpu.read::<u32>(args[1].slice(offset, 4));
            cpu.write_var(dst.slice(offset, 4), left.wrapping_add(right));
        }
    }

    fn packed_compare_d_signed(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 1 || args[0].size() != 16 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let predicate = cpu.args[0] as u8 & 7;
        let mut mask = 0_u8;
        for lane in 0..4_u8 {
            let left = cpu.read::<i32>(args[0].slice(lane * 4, 4));
            let right = cpu.read::<i32>(args[1].slice(lane * 4, 4));
            let matches = match predicate {
                0 => left == right,
                1 => left < right,
                2 => left <= right,
                3 => false,
                4 => left != right,
                5 => left >= right,
                6 => left > right,
                7 => true,
                _ => unreachable!(),
            };
            mask |= u8::from(matches) << lane;
        }
        cpu.write_var(dst, mask);
    }

    fn packed_movemask_b(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 2 || args[0].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let bytes = cpu.read::<u128>(args[0]).to_le_bytes();
        let mut mask = 0_u16;
        for (index, byte) in bytes.into_iter().enumerate() {
            mask |= u16::from(byte >> 7) << index;
        }
        cpu.write_var(dst, mask);
    }

    fn packed_permute_d_lane(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 4 || args[0].size() != 4 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let lane = (cpu.read::<u32>(args[0]) & 3) as u8;
        let value = cpu.read::<u32>(args[1].slice(lane * 4, 4));
        cpu.write_var(dst, value);
    }

    fn packed_permute_q_lane(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 8 || args[0].size() != 1 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let lane = cpu.read::<u8>(args[0]) & 1;
        let value = cpu.read::<u64>(args[1].slice(lane * 8, 8));
        cpu.write_var(dst, value);
    }

    fn packed_permute_d_chunk(
        cpu: &mut Cpu,
        dst: VarNode,
        indexes: Value,
        sources: [u128; 4],
        lane_mask: u32,
    ) {
        if dst.size != 16 || indexes.size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let indexes = cpu.read::<u128>(indexes).to_le_bytes();
        let sources = sources.map(u128::to_le_bytes);
        for output_lane in 0..4_u8 {
            let start = usize::from(output_lane) * 4;
            let index =
                u32::from_le_bytes(indexes[start..start + 4].try_into().unwrap()) & lane_mask;
            let chunk = (index / 4) as usize;
            let lane = (index % 4) as usize;
            let value =
                u32::from_le_bytes(sources[chunk][lane * 4..lane * 4 + 4].try_into().unwrap());
            cpu.write_var(dst.slice(output_lane * 4, 4), value);
        }
    }

    fn packed_permute_d_256_chunk(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(args[1].size());
            return;
        }
        packed_permute_d_chunk(
            cpu,
            dst,
            args[0],
            [cpu.read::<u128>(args[1]), cpu.args[0], 0, 0],
            7,
        );
    }

    fn packed_permute_d_512_chunk(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(args[1].size());
            return;
        }
        packed_permute_d_chunk(
            cpu,
            dst,
            args[0],
            [cpu.read::<u128>(args[1]), cpu.args[0], cpu.args[1], cpu.args[2]],
            15,
        );
    }

    fn packed_permute_q_256_chunk(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 16 || args[0].size() != 16 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let sources =
            [cpu.read::<u128>(args[0]).to_le_bytes(), cpu.read::<u128>(args[1]).to_le_bytes()];
        let immediate = cpu.args[0] as u8;
        let output_pair = (cpu.args[1] as u8) & 1;
        for lane_in_pair in 0..2_u8 {
            let output_lane = output_pair * 2 + lane_in_pair;
            let source_lane = (immediate >> (output_lane * 2)) & 3;
            let source_chunk = usize::from(source_lane / 2);
            let lane_in_chunk = usize::from(source_lane % 2);
            let value = u64::from_le_bytes(
                sources[source_chunk][lane_in_chunk * 8..lane_in_chunk * 8 + 8].try_into().unwrap(),
            );
            cpu.write_var(dst.slice(lane_in_pair * 8, 8), value);
        }
    }

    fn packed_compact_d_chunk(
        cpu: &mut Cpu,
        dst: VarNode,
        sources: [u128; 4],
        lane_count: usize,
        old_destination: u128,
        mask: u64,
        output_chunk: usize,
        expand: bool,
    ) {
        if dst.size != 16 || !matches!(lane_count, 4 | 8 | 16) || output_chunk * 4 >= lane_count {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }

        let source_bytes = sources.map(u128::to_le_bytes);
        let old_bytes = old_destination.to_le_bytes();
        let read_source_lane = |lane: usize| {
            let chunk = lane / 4;
            let offset = (lane % 4) * 4;
            u32::from_le_bytes(source_bytes[chunk][offset..offset + 4].try_into().unwrap())
        };

        let mut packed = [0_u32; 16];
        let mut packed_len = 0;
        if !expand {
            for source_lane in 0..lane_count {
                if mask & (1_u64 << source_lane) != 0 {
                    packed[packed_len] = read_source_lane(source_lane);
                    packed_len += 1;
                }
            }
        }

        for lane_in_chunk in 0..4 {
            let destination_lane = output_chunk * 4 + lane_in_chunk;
            let old_offset = lane_in_chunk * 4;
            let old = u32::from_le_bytes(old_bytes[old_offset..old_offset + 4].try_into().unwrap());
            let value = if expand {
                if mask & (1_u64 << destination_lane) == 0 {
                    old
                }
                else {
                    let packed_index = (mask & ((1_u64 << destination_lane) - 1)).count_ones();
                    read_source_lane(packed_index as usize)
                }
            }
            else if destination_lane < packed_len {
                packed[destination_lane]
            }
            else {
                old
            };
            cpu.write_var(dst.slice((lane_in_chunk * 4) as u8, 4), value);
        }
    }

    fn packed_compress_d_128_chunk(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_compact_d_chunk(
            cpu,
            dst,
            [cpu.read::<u128>(args[0]), 0, 0, 0],
            4,
            cpu.read::<u128>(args[1]),
            cpu.args[0] as u64,
            cpu.args[1] as usize,
            false,
        );
    }

    fn packed_compress_d_256_chunk(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_compact_d_chunk(
            cpu,
            dst,
            [cpu.read::<u128>(args[0]), cpu.read::<u128>(args[1]), 0, 0],
            8,
            cpu.args[0],
            cpu.args[1] as u64,
            cpu.args[2] as usize,
            false,
        );
    }

    fn packed_compress_d_512_chunk(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_compact_d_chunk(
            cpu,
            dst,
            [cpu.read::<u128>(args[0]), cpu.read::<u128>(args[1]), cpu.args[0], cpu.args[1]],
            16,
            cpu.args[2],
            cpu.args[3] as u64,
            cpu.args[4] as usize,
            false,
        );
    }

    fn packed_compress_d_memory(
        cpu: &mut Cpu,
        address: u64,
        sources: [u128; 4],
        lane_count: usize,
        mask: u64,
    ) {
        let source_bytes = sources.map(u128::to_le_bytes);
        let mut packed = [0_u32; 16];
        let mut packed_len = 0;
        for source_lane in 0..lane_count {
            if mask & (1_u64 << source_lane) == 0 {
                continue;
            }
            let chunk = source_lane / 4;
            let offset = (source_lane % 4) * 4;
            packed[packed_len] =
                u32::from_le_bytes(source_bytes[chunk][offset..offset + 4].try_into().unwrap());
            packed_len += 1;
        }

        // Native VPCOMPRESSD memory writes are fault-atomic. Preflight every
        // selected dword before the first mutation, and report the end of the
        // first failing element as Linux exposes it through si_addr.
        for output_lane in 0..packed_len {
            let Some(element_start) = address.checked_add((output_lane * 4) as u64)
            else {
                cpu.exception.code = ExceptionCode::AddressOverflow as u32;
                cpu.exception.value = u64::MAX;
                return;
            };
            for byte in 0..4_u64 {
                let Some(current) = element_start.checked_add(byte)
                else {
                    cpu.exception.code = ExceptionCode::AddressOverflow as u32;
                    cpu.exception.value = u64::MAX;
                    return;
                };
                if let Err(error) =
                    icicle_mem::perm::check(cpu.mem.get_perm(current), icicle_mem::perm::WRITE)
                {
                    cpu.exception.code = ExceptionCode::from_store_error(error) as u32;
                    cpu.exception.value = element_start.saturating_add(3);
                    return;
                }
            }
        }

        for (output_lane, value) in packed[..packed_len].iter().copied().enumerate() {
            let element_start = address + (output_lane * 4) as u64;
            if let Err(error) =
                cpu.mem.write::<4>(element_start, value.to_le_bytes(), icicle_mem::perm::WRITE)
            {
                cpu.exception.code = ExceptionCode::from_store_error(error) as u32;
                cpu.exception.value = element_start.saturating_add(3);
                return;
            }
        }
    }

    fn packed_compress_d_mem_128(cpu: &mut Cpu, _: VarNode, args: [Value; 2]) {
        if args[0].size() != 8 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(args[1].size());
            return;
        }
        packed_compress_d_memory(
            cpu,
            cpu.read::<u64>(args[0]),
            [cpu.read::<u128>(args[1]), 0, 0, 0],
            4,
            cpu.args[0] as u64,
        );
    }

    fn packed_compress_d_mem_256(cpu: &mut Cpu, _: VarNode, args: [Value; 2]) {
        if args[0].size() != 8 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(args[1].size());
            return;
        }
        packed_compress_d_memory(
            cpu,
            cpu.read::<u64>(args[0]),
            [cpu.read::<u128>(args[1]), cpu.args[0], 0, 0],
            8,
            cpu.args[1] as u64,
        );
    }

    fn packed_compress_d_mem_512(cpu: &mut Cpu, _: VarNode, args: [Value; 2]) {
        if args[0].size() != 8 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(args[1].size());
            return;
        }
        packed_compress_d_memory(
            cpu,
            cpu.read::<u64>(args[0]),
            [cpu.read::<u128>(args[1]), cpu.args[0], cpu.args[1], cpu.args[2]],
            16,
            cpu.args[3] as u64,
        );
    }

    fn packed_expand_d_128_chunk(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_compact_d_chunk(
            cpu,
            dst,
            [cpu.read::<u128>(args[0]), 0, 0, 0],
            4,
            cpu.read::<u128>(args[1]),
            cpu.args[0] as u64,
            cpu.args[1] as usize,
            true,
        );
    }

    fn packed_expand_d_256_chunk(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_compact_d_chunk(
            cpu,
            dst,
            [cpu.read::<u128>(args[0]), cpu.read::<u128>(args[1]), 0, 0],
            8,
            cpu.args[0],
            cpu.args[1] as u64,
            cpu.args[2] as usize,
            true,
        );
    }

    fn packed_expand_d_512_chunk(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_compact_d_chunk(
            cpu,
            dst,
            [cpu.read::<u128>(args[0]), cpu.read::<u128>(args[1]), cpu.args[0], cpu.args[1]],
            16,
            cpu.args[2],
            cpu.args[3] as u64,
            cpu.args[4] as usize,
            true,
        );
    }

    fn packed_compact_chunk(
        cpu: &mut Cpu,
        dst: VarNode,
        sources: [u128; 4],
        vector_size: usize,
        old_destination: u128,
        mask: u64,
        output_chunk: usize,
        element_size: usize,
        expand: bool,
    ) {
        if dst.size != 16
            || !matches!(vector_size, 16 | 32 | 64)
            || !matches!(element_size, 1 | 2 | 4 | 8)
            || vector_size % element_size != 0
            || output_chunk >= vector_size / 16
        {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = vector_size as u64;
            return;
        }

        let source = sources.map(u128::to_le_bytes);
        let mut output = old_destination.to_le_bytes();
        let lane_count = vector_size / element_size;
        let lanes_per_chunk = 16 / element_size;
        let mut packed = [0_u8; 64];
        let mut packed_len = 0;
        if !expand {
            for source_lane in 0..lane_count {
                if mask & (1_u64 << source_lane) == 0 {
                    continue;
                }
                let source_offset = source_lane * element_size;
                let packed_offset = packed_len * element_size;
                for byte in 0..element_size {
                    let source_byte = source_offset + byte;
                    packed[packed_offset + byte] = source[source_byte / 16][source_byte % 16];
                }
                packed_len += 1;
            }
        }

        for lane_in_chunk in 0..lanes_per_chunk {
            let destination_lane = output_chunk * lanes_per_chunk + lane_in_chunk;
            let source_lane = if expand {
                if mask & (1_u64 << destination_lane) == 0 {
                    continue;
                }
                (mask & ((1_u64 << destination_lane) - 1)).count_ones() as usize
            }
            else {
                if destination_lane >= packed_len {
                    continue;
                }
                destination_lane
            };
            let output_offset = lane_in_chunk * element_size;
            let source_offset = source_lane * element_size;
            for byte in 0..element_size {
                output[output_offset + byte] = if expand {
                    let source_byte = source_offset + byte;
                    source[source_byte / 16][source_byte % 16]
                }
                else {
                    packed[source_offset + byte]
                };
            }
        }
        cpu.write_var(dst, u128::from_le_bytes(output));
    }

    fn packed_compact_128_chunk(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if args[0].size() != 16 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(args[0].size());
            return;
        }
        packed_compact_chunk(
            cpu,
            dst,
            [cpu.read::<u128>(args[0]), 0, 0, 0],
            16,
            cpu.read::<u128>(args[1]),
            cpu.args[0] as u64,
            cpu.args[1] as usize,
            cpu.args[2] as usize,
            cpu.args[3] != 0,
        );
    }

    fn packed_compact_256_chunk(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if args[0].size() != 16 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(args[0].size());
            return;
        }
        packed_compact_chunk(
            cpu,
            dst,
            [cpu.read::<u128>(args[0]), cpu.read::<u128>(args[1]), 0, 0],
            32,
            cpu.args[0],
            cpu.args[1] as u64,
            cpu.args[2] as usize,
            cpu.args[3] as usize,
            cpu.args[4] != 0,
        );
    }

    fn packed_compact_512_chunk(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if args[0].size() != 16 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(args[0].size());
            return;
        }
        packed_compact_chunk(
            cpu,
            dst,
            [cpu.read::<u128>(args[0]), cpu.read::<u128>(args[1]), cpu.args[0], cpu.args[1]],
            64,
            cpu.args[2],
            cpu.args[3] as u64,
            cpu.args[4] as usize,
            cpu.args[5] as usize,
            cpu.args[6] != 0,
        );
    }

    fn packed_compress_memory(
        cpu: &mut Cpu,
        address: u64,
        sources: [u128; 4],
        vector_size: usize,
        mask: u64,
        element_size: usize,
    ) {
        if !matches!(vector_size, 16 | 32 | 64)
            || !matches!(element_size, 1 | 2 | 4 | 8)
            || vector_size % element_size != 0
        {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = vector_size as u64;
            return;
        }
        let source = sources.map(u128::to_le_bytes);
        let lane_count = vector_size / element_size;
        let mut packed = [0_u8; 64];
        let mut packed_len = 0;
        for source_lane in 0..lane_count {
            if mask & (1_u64 << source_lane) == 0 {
                continue;
            }
            for byte in 0..element_size {
                let source_byte = source_lane * element_size + byte;
                packed[packed_len * element_size + byte] =
                    source[source_byte / 16][source_byte % 16];
            }
            packed_len += 1;
        }

        // Compact stores are fault-atomic. Probe the complete selected output
        // before exposing the first byte, matching native restart behavior.
        for output_lane in 0..packed_len {
            let Some(element_start) = address.checked_add((output_lane * element_size) as u64)
            else {
                cpu.exception.code = ExceptionCode::AddressOverflow as u32;
                cpu.exception.value = u64::MAX;
                return;
            };
            for byte in 0..element_size {
                let Some(current) = element_start.checked_add(byte as u64)
                else {
                    cpu.exception.code = ExceptionCode::AddressOverflow as u32;
                    cpu.exception.value = u64::MAX;
                    return;
                };
                if let Err(error) =
                    icicle_mem::perm::check(cpu.mem.get_perm(current), icicle_mem::perm::WRITE)
                {
                    cpu.exception.code = ExceptionCode::from_store_error(error) as u32;
                    cpu.exception.value = element_start.saturating_add((element_size - 1) as u64);
                    return;
                }
            }
        }
        for byte in 0..packed_len * element_size {
            let current = address + byte as u64;
            if let Err(error) = cpu.mem.write::<1>(current, [packed[byte]], icicle_mem::perm::WRITE)
            {
                cpu.exception.code = ExceptionCode::from_store_error(error) as u32;
                cpu.exception.value = current;
                return;
            }
        }
    }

    fn packed_compress_mem_128(cpu: &mut Cpu, _: VarNode, args: [Value; 2]) {
        if args[0].size() != 8 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(args[1].size());
            return;
        }
        packed_compress_memory(
            cpu,
            cpu.read::<u64>(args[0]),
            [cpu.read::<u128>(args[1]), 0, 0, 0],
            16,
            cpu.args[0] as u64,
            cpu.args[1] as usize,
        );
    }

    fn packed_compress_mem_256(cpu: &mut Cpu, _: VarNode, args: [Value; 2]) {
        if args[0].size() != 8 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(args[1].size());
            return;
        }
        packed_compress_memory(
            cpu,
            cpu.read::<u64>(args[0]),
            [cpu.read::<u128>(args[1]), cpu.args[0], 0, 0],
            32,
            cpu.args[1] as u64,
            cpu.args[2] as usize,
        );
    }

    fn packed_compress_mem_512(cpu: &mut Cpu, _: VarNode, args: [Value; 2]) {
        if args[0].size() != 8 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(args[1].size());
            return;
        }
        packed_compress_memory(
            cpu,
            cpu.read::<u64>(args[0]),
            [cpu.read::<u128>(args[1]), cpu.args[0], cpu.args[1], cpu.args[2]],
            64,
            cpu.args[3] as u64,
            cpu.args[4] as usize,
        );
    }

    fn packed_expand_memory_chunk(
        cpu: &mut Cpu,
        dst: VarNode,
        address: u64,
        old_destination: u128,
        vector_size: usize,
        mask: u64,
        output_chunk: usize,
        element_size: usize,
    ) {
        if dst.size != 16
            || !matches!(vector_size, 16 | 32 | 64)
            || !matches!(element_size, 1 | 2 | 4 | 8)
            || vector_size % element_size != 0
            || output_chunk >= vector_size / 16
        {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = vector_size as u64;
            return;
        }
        let lanes_per_chunk = 16 / element_size;
        let mut output = old_destination.to_le_bytes();
        for lane_in_chunk in 0..lanes_per_chunk {
            let destination_lane = output_chunk * lanes_per_chunk + lane_in_chunk;
            if mask & (1_u64 << destination_lane) == 0 {
                continue;
            }
            let packed_lane = (mask & ((1_u64 << destination_lane) - 1)).count_ones() as usize;
            for byte in 0..element_size {
                let Some(current) = address.checked_add((packed_lane * element_size + byte) as u64)
                else {
                    cpu.exception.code = ExceptionCode::AddressOverflow as u32;
                    cpu.exception.value = u64::MAX;
                    return;
                };
                match cpu.mem.read::<1>(current, icicle_mem::perm::READ) {
                    Ok(value) => output[lane_in_chunk * element_size + byte] = value[0],
                    Err(error) => {
                        cpu.exception.code = ExceptionCode::from_load_error(error) as u32;
                        cpu.exception.value = current;
                        return;
                    }
                }
            }
        }
        cpu.write_var(dst, u128::from_le_bytes(output));
    }

    fn packed_expand_mem_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if args[0].size() != 8 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(args[1].size());
            return;
        }
        packed_expand_memory_chunk(
            cpu,
            dst,
            cpu.read::<u64>(args[0]),
            cpu.read::<u128>(args[1]),
            16,
            cpu.args[0] as u64,
            cpu.args[1] as usize,
            cpu.args[2] as usize,
        );
    }

    fn packed_expand_mem_256(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if args[0].size() != 8 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(args[1].size());
            return;
        }
        packed_expand_memory_chunk(
            cpu,
            dst,
            cpu.read::<u64>(args[0]),
            cpu.read::<u128>(args[1]),
            32,
            cpu.args[0] as u64,
            cpu.args[1] as usize,
            cpu.args[2] as usize,
        );
    }

    fn packed_expand_mem_512(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if args[0].size() != 8 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(args[1].size());
            return;
        }
        packed_expand_memory_chunk(
            cpu,
            dst,
            cpu.read::<u64>(args[0]),
            cpu.read::<u128>(args[1]),
            64,
            cpu.args[0] as u64,
            cpu.args[1] as usize,
            cpu.args[2] as usize,
        );
    }

    fn masked_memory_shape(cpu: &mut Cpu, element_size: usize, chunks: usize) -> Option<usize> {
        if !matches!(element_size, 1 | 2 | 4 | 8) || !(1..=4).contains(&chunks) {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = element_size as u64;
            return None;
        }
        Some(chunks * 16 / element_size)
    }

    /// Reads one 128-bit chunk of an EVEX masked vector load.
    ///
    /// The address operand is deliberately not materialized by SLEIGH. Only
    /// selected elements are touched, so an unmapped page containing solely
    /// masked-off lanes cannot fault. The destination is committed only after
    /// every selected byte in the chunk has been read successfully.
    fn masked_load_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 16 || args[0].size() != 8 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let address = cpu.read::<u64>(args[0]);
        let mut output = cpu.read::<u128>(args[1]).to_le_bytes();
        let mask = cpu.args[0] as u64;
        let element_size = cpu.args[1] as usize;
        let chunk = cpu.args[2] as usize;
        let Some(_) = masked_memory_shape(cpu, element_size, chunk + 1)
        else {
            return;
        };
        if chunk >= 4 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = chunk as u64;
            return;
        }
        let lanes_per_chunk = 16 / element_size;
        for lane in 0..lanes_per_chunk {
            let global_lane = chunk * lanes_per_chunk + lane;
            if mask & (1_u64 << global_lane) == 0 {
                continue;
            }
            for byte in 0..element_size {
                let offset = chunk * 16 + lane * element_size + byte;
                let Some(current) = address.checked_add(offset as u64)
                else {
                    cpu.exception.code = ExceptionCode::AddressOverflow as u32;
                    cpu.exception.value = u64::MAX;
                    return;
                };
                match cpu.mem.read::<1>(current, icicle_mem::perm::READ) {
                    Ok(value) => output[lane * element_size + byte] = value[0],
                    Err(error) => {
                        cpu.exception.code = ExceptionCode::from_load_error(error) as u32;
                        cpu.exception.value = current;
                        return;
                    }
                }
            }
        }
        cpu.write_var(dst, u128::from_le_bytes(output));
    }

    fn masked_store(
        cpu: &mut Cpu,
        address: u64,
        chunks: [u128; 4],
        chunk_count: usize,
        mask: u64,
        element_size: usize,
    ) {
        let Some(lane_count) = masked_memory_shape(cpu, element_size, chunk_count)
        else {
            return;
        };
        let source = chunks.map(u128::to_le_bytes);

        // Ordinary masked vector stores are restartable as one instruction.
        // Preflight every selected byte so a late page fault cannot expose a
        // partially committed vector store in the guest memory image.
        for lane in 0..lane_count {
            if mask & (1_u64 << lane) == 0 {
                continue;
            }
            for byte in 0..element_size {
                let offset = lane * element_size + byte;
                let Some(current) = address.checked_add(offset as u64)
                else {
                    cpu.exception.code = ExceptionCode::AddressOverflow as u32;
                    cpu.exception.value = u64::MAX;
                    return;
                };
                if let Err(error) =
                    icicle_mem::perm::check(cpu.mem.get_perm(current), icicle_mem::perm::WRITE)
                {
                    cpu.exception.code = ExceptionCode::from_store_error(error) as u32;
                    cpu.exception.value = current;
                    return;
                }
            }
        }

        for lane in 0..lane_count {
            if mask & (1_u64 << lane) == 0 {
                continue;
            }
            for byte in 0..element_size {
                let offset = lane * element_size + byte;
                let current = address + offset as u64;
                let value = source[offset / 16][offset % 16];
                if let Err(error) = cpu.mem.write::<1>(current, [value], icicle_mem::perm::WRITE) {
                    cpu.exception.code = ExceptionCode::from_store_error(error) as u32;
                    cpu.exception.value = current;
                    return;
                }
            }
        }
    }

    fn masked_store_128(cpu: &mut Cpu, _: VarNode, args: [Value; 2]) {
        if args[0].size() != 8 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(args[1].size());
            return;
        }
        masked_store(
            cpu,
            cpu.read::<u64>(args[0]),
            [cpu.read::<u128>(args[1]), 0, 0, 0],
            1,
            cpu.args[0] as u64,
            cpu.args[1] as usize,
        );
    }

    fn masked_store_256(cpu: &mut Cpu, _: VarNode, args: [Value; 2]) {
        if args[0].size() != 8 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(args[1].size());
            return;
        }
        masked_store(
            cpu,
            cpu.read::<u64>(args[0]),
            [cpu.read::<u128>(args[1]), cpu.args[0], 0, 0],
            2,
            cpu.args[1] as u64,
            cpu.args[2] as usize,
        );
    }

    fn masked_store_512(cpu: &mut Cpu, _: VarNode, args: [Value; 2]) {
        if args[0].size() != 8 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(args[1].size());
            return;
        }
        masked_store(
            cpu,
            cpu.read::<u64>(args[0]),
            [cpu.read::<u128>(args[1]), cpu.args[0], cpu.args[1], cpu.args[2]],
            4,
            cpu.args[3] as u64,
            cpu.args[4] as usize,
        );
    }

    fn packed_test_mask_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if !(1..=2).contains(&dst.size) || args[0].size() != 16 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let element_size = cpu.args[0] as usize;
        if !matches!(element_size, 1 | 2 | 4 | 8) {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = element_size as u64;
            return;
        }
        let result_size = (16 / element_size + 7) / 8;
        if usize::from(dst.size) < result_size {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let invert_result = cpu.args[1] != 0;
        let left = cpu.read::<u128>(args[0]).to_le_bytes();
        let right = cpu.read::<u128>(args[1]).to_le_bytes();
        let mut result = 0_u16;
        for lane in 0..16 / element_size {
            let start = lane * element_size;
            let any = (0..element_size).any(|byte| left[start + byte] & right[start + byte] != 0);
            result |= u16::from(any ^ invert_result) << lane;
        }
        cpu.write_trunc(dst, result);
    }

    fn packed_test_mask_512(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if !(1..=8).contains(&dst.size) || args[0].size() != 16 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let element_size = cpu.args[6] as usize;
        if !matches!(element_size, 1 | 2 | 4 | 8) {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = element_size as u64;
            return;
        }
        let result_size = (64 / element_size + 7) / 8;
        if usize::from(dst.size) < result_size {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let invert_result = cpu.args[7] != 0;
        let left = [cpu.read::<u128>(args[0]), cpu.read::<u128>(args[1]), cpu.args[0], cpu.args[1]]
            .map(u128::to_le_bytes);
        let right = [cpu.args[2], cpu.args[3], cpu.args[4], cpu.args[5]].map(u128::to_le_bytes);
        let lane_count = 64 / element_size;
        let mut result = 0_u64;
        for lane in 0..lane_count {
            let start = lane * element_size;
            let any = (0..element_size).any(|byte| {
                let offset = start + byte;
                let lhs = left[offset / 16][offset % 16];
                lhs & right[offset / 16][offset % 16] != 0
            });
            result |= u64::from(any ^ invert_result) << lane;
        }
        cpu.write_trunc(dst, result);
    }

    fn packed_test_mask_memory(
        cpu: &mut Cpu,
        dst: VarNode,
        address: u64,
        sources: [u128; 4],
        vector_size: usize,
        mask: u64,
        element_size: usize,
        invert_result: bool,
        broadcast: bool,
    ) {
        if !matches!(vector_size, 16 | 32 | 64)
            || !matches!(element_size, 1 | 2 | 4 | 8)
            || vector_size % element_size != 0
        {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = vector_size as u64;
            return;
        }
        let lane_count = vector_size / element_size;
        let result_size = (lane_count + 7) / 8;
        if usize::from(dst.size) < result_size || dst.size > 8 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }

        let sources = sources.map(u128::to_le_bytes);
        let mut result = 0_u64;
        for lane in 0..lane_count {
            if mask & (1_u64 << lane) == 0 {
                continue;
            }
            let memory_offset = if broadcast { 0 } else { lane * element_size };
            let source_offset = lane * element_size;
            let mut any = false;
            for byte in 0..element_size {
                let Some(current) = address.checked_add((memory_offset + byte) as u64)
                else {
                    cpu.exception.code = ExceptionCode::AddressOverflow as u32;
                    cpu.exception.value = u64::MAX;
                    return;
                };
                let memory = match cpu.mem.read::<1>(current, icicle_mem::perm::READ) {
                    Ok(value) => value[0],
                    Err(error) => {
                        cpu.exception.code = ExceptionCode::from_load_error(error) as u32;
                        cpu.exception.value = current;
                        return;
                    }
                };
                let source_byte = source_offset + byte;
                let source = sources[source_byte / 16][source_byte % 16];
                any |= source & memory != 0;
            }
            result |= u64::from(any ^ invert_result) << lane;
        }
        cpu.write_trunc(dst, result);
    }

    fn packed_test_mask_mem_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if args[0].size() != 8 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(args[1].size());
            return;
        }
        packed_test_mask_memory(
            cpu,
            dst,
            cpu.read::<u64>(args[0]),
            [cpu.read::<u128>(args[1]), 0, 0, 0],
            16,
            cpu.args[0] as u64,
            cpu.args[1] as usize,
            cpu.args[2] != 0,
            cpu.args[3] != 0,
        );
    }

    fn packed_test_mask_mem_256(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if args[0].size() != 8 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(args[1].size());
            return;
        }
        packed_test_mask_memory(
            cpu,
            dst,
            cpu.read::<u64>(args[0]),
            [cpu.read::<u128>(args[1]), cpu.args[0], 0, 0],
            32,
            cpu.args[1] as u64,
            cpu.args[2] as usize,
            cpu.args[3] != 0,
            cpu.args[4] != 0,
        );
    }

    fn packed_test_mask_mem_512(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if args[0].size() != 8 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(args[1].size());
            return;
        }
        packed_test_mask_memory(
            cpu,
            dst,
            cpu.read::<u64>(args[0]),
            [cpu.read::<u128>(args[1]), cpu.args[0], cpu.args[1], cpu.args[2]],
            64,
            cpu.args[3] as u64,
            cpu.args[4] as usize,
            cpu.args[5] != 0,
            cpu.args[6] != 0,
        );
    }

    fn packed_popcount_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 16 || args[0].size() != 16 || args[1].size() != 1 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let element_size = cpu.read::<u8>(args[1]) as usize;
        if !matches!(element_size, 1 | 2 | 4 | 8) {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = element_size as u64;
            return;
        }
        let source = cpu.read::<u128>(args[0]).to_le_bytes();
        let mut output = [0_u8; 16];
        for lane in 0..16 / element_size {
            let start = lane * element_size;
            let count: u64 = source[start..start + element_size]
                .iter()
                .map(|byte| u64::from(byte.count_ones()))
                .sum();
            output[start..start + element_size]
                .copy_from_slice(&count.to_le_bytes()[..element_size]);
        }
        cpu.write_var(dst, u128::from_le_bytes(output));
    }

    fn packed_popcount_mem_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 16 || args[0].size() != 8 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let address = cpu.read::<u64>(args[0]);
        let mask = cpu.args[0] as u64;
        let element_size = cpu.args[1] as usize;
        let chunk = cpu.args[2] as usize;
        let broadcast = cpu.args[3] != 0;
        if !matches!(element_size, 1 | 2 | 4 | 8) || chunk >= 4 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = element_size as u64;
            return;
        }
        let lanes_per_chunk = 16 / element_size;
        let mut output = cpu.read::<u128>(args[1]).to_le_bytes();
        for lane_in_chunk in 0..lanes_per_chunk {
            let global_lane = chunk * lanes_per_chunk + lane_in_chunk;
            if mask & (1_u64 << global_lane) == 0 {
                continue;
            }
            let source_offset = if broadcast { 0 } else { global_lane * element_size };
            let mut count = 0_u64;
            for byte in 0..element_size {
                let Some(current) = address.checked_add((source_offset + byte) as u64)
                else {
                    cpu.exception.code = ExceptionCode::AddressOverflow as u32;
                    cpu.exception.value = u64::MAX;
                    return;
                };
                match cpu.mem.read::<1>(current, icicle_mem::perm::READ) {
                    Ok(value) => count += u64::from(value[0].count_ones()),
                    Err(error) => {
                        cpu.exception.code = ExceptionCode::from_load_error(error) as u32;
                        cpu.exception.value = current;
                        return;
                    }
                }
            }
            let output_offset = lane_in_chunk * element_size;
            output[output_offset..output_offset + element_size]
                .copy_from_slice(&count.to_le_bytes()[..element_size]);
        }
        cpu.write_var(dst, u128::from_le_bytes(output));
    }

    fn packed_multishift_masked_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 16 || args[0].size() != 16 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let control = cpu.read::<u128>(args[0]).to_le_bytes();
        let data = cpu.read::<u128>(args[1]).to_le_bytes();
        let mut output = cpu.args[0].to_le_bytes();
        let mask = cpu.args[1] as u64;
        let chunk = cpu.args[2] as usize;
        if chunk >= 4 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = chunk as u64;
            return;
        }
        for group in 0..2 {
            let qword = u64::from_le_bytes(data[group * 8..group * 8 + 8].try_into().unwrap());
            for byte in 0..8 {
                let lane_in_chunk = group * 8 + byte;
                let global_lane = chunk * 16 + lane_in_chunk;
                if mask & (1_u64 << global_lane) != 0 {
                    output[lane_in_chunk] =
                        qword.rotate_right(u32::from(control[lane_in_chunk] & 63)) as u8;
                }
            }
        }
        cpu.write_var(dst, u128::from_le_bytes(output));
    }

    fn packed_multishift_mem_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 16 || args[0].size() != 8 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let address = cpu.read::<u64>(args[0]);
        let control = cpu.read::<u128>(args[1]).to_le_bytes();
        let mut output = cpu.args[0].to_le_bytes();
        let mask = cpu.args[1] as u64;
        let chunk = cpu.args[2] as usize;
        let broadcast = cpu.args[3] != 0;
        if chunk >= 4 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = chunk as u64;
            return;
        }
        for group_in_chunk in 0..2 {
            let global_group = chunk * 2 + group_in_chunk;
            let source_offset = if broadcast { 0 } else { global_group * 8 };
            let mut qword_bytes = [0_u8; 8];
            for (byte, output_byte) in qword_bytes.iter_mut().enumerate() {
                let Some(current) = address.checked_add((source_offset + byte) as u64)
                else {
                    cpu.exception.code = ExceptionCode::AddressOverflow as u32;
                    cpu.exception.value = u64::MAX;
                    return;
                };
                match cpu.mem.read::<1>(current, icicle_mem::perm::READ) {
                    Ok(value) => *output_byte = value[0],
                    Err(error) => {
                        cpu.exception.code = ExceptionCode::from_load_error(error) as u32;
                        cpu.exception.value = current;
                        return;
                    }
                }
            }
            let qword = u64::from_le_bytes(qword_bytes);
            for byte in 0..8 {
                let global_lane = global_group * 8 + byte;
                if mask & (1_u64 << global_lane) == 0 {
                    continue;
                }
                let lane_in_chunk = group_in_chunk * 8 + byte;
                output[lane_in_chunk] =
                    qword.rotate_right(u32::from(control[lane_in_chunk] & 63)) as u8;
            }
        }
        cpu.write_var(dst, u128::from_le_bytes(output));
    }

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

    impl x86_profile::CpuidResult {
        fn write(self, cpu: &mut Cpu, dst: VarNode) {
            if dst.size != 16 {
                tracing::warn!(
                    "Using unpatched SLEIGH specification, CPUID instruction will behave incorrectly"
                );
                return;
            }

            cpu.write_var(dst.slice(0, 4), self.eax);
            cpu.write_var(dst.slice(4, 4), self.ebx);
            cpu.write_var(dst.slice(8, 4), self.edx);
            cpu.write_var(dst.slice(12, 4), self.ecx);
        }
    }

    // Basic processor information
    fn cpuid_basic_info(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        cpuid_leaf(cpu, dst, 0, args[1]);
    }

    // Processor info and feature bits
    fn cpuid_version_info(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        cpuid_leaf(cpu, dst, 1, args[1]);
    }

    // Return structured extended feature enumeration info leaf
    fn cpuid_extended_feature_enumeration_info(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        cpuid_leaf(cpu, dst, 7, args[1]);
    }

    fn cpuid_xstate_info(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        cpuid_leaf(cpu, dst, 0x0d, args[1]);
    }

    fn cpuid(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let leaf = cpu.read(args[0]);
        cpuid_leaf(cpu, dst, leaf, args[1]);
    }

    fn cpuid_leaf(cpu: &mut Cpu, dst: VarNode, leaf: u32, subleaf: Value) {
        let subleaf = cpu.read(subleaf);
        tracing::debug!("cpuid({leaf:#x}, {subleaf:#x}) profile={}", x86_profile::PROFILE_NAME);
        x86_profile::cpuid(leaf, subleaf).write(cpu, dst);
    }

    pub const INITIAL_XCR0: u64 = x86_profile::INITIAL_XCR0;
    pub const STANDARD_XSTATE_SIZE: usize = x86_profile::XSAVE_AREA_SIZE as usize;

    fn xgetbv(cpu: &mut Cpu, _: VarNode, args: [Value; 2]) {
        let selector: u32 = cpu.read(args[0]);
        if selector != 0 {
            cpu.exception.code = ExceptionCode::GeneralProtection as u32;
            cpu.exception.value = 0;
            return;
        }

        for (name, value) in [("RAX", INITIAL_XCR0 & 0xffff_ffff), ("RDX", INITIAL_XCR0 >> 32)] {
            if let Some(var) = cpu.arch.sleigh.get_varnode(name) {
                cpu.write_var(var, value);
            }
        }
    }

    fn xsetbv(cpu: &mut Cpu, _: VarNode, _: [Value; 2]) {
        // XSETBV is privileged.  The virtual userspace profile is immutable;
        // a guest cannot turn unimplemented state components into features.
        cpu.exception.code = ExceptionCode::GeneralProtection as u32;
        cpu.exception.value = 0;
    }

    const MXCSR_MASK: u32 = 0x0000_ffff;

    fn fxsave(cpu: &mut Cpu, _: VarNode, args: [Value; 2]) {
        fxsave_impl(cpu, args[0], false);
    }

    fn fxsave64(cpu: &mut Cpu, _: VarNode, args: [Value; 2]) {
        fxsave_impl(cpu, args[0], true);
    }

    fn fxrstor(cpu: &mut Cpu, _: VarNode, args: [Value; 2]) {
        fxrstor_impl(cpu, args[0], false);
    }

    fn fxrstor64(cpu: &mut Cpu, _: VarNode, args: [Value; 2]) {
        fxrstor_impl(cpu, args[0], true);
    }

    fn xsave(cpu: &mut Cpu, _: VarNode, args: [Value; 2]) {
        xsave_impl(cpu, args[0], false);
    }

    fn xsave64(cpu: &mut Cpu, _: VarNode, args: [Value; 2]) {
        xsave_impl(cpu, args[0], true);
    }

    fn xrstor(cpu: &mut Cpu, _: VarNode, args: [Value; 2]) {
        xrstor_impl(cpu, args[0], false);
    }

    fn xrstor64(cpu: &mut Cpu, _: VarNode, args: [Value; 2]) {
        xrstor_impl(cpu, args[0], true);
    }

    /// One 128-bit slice of EVEX VPBROADCASTD. Wide constructors invoke this
    /// helper once per slice so no YMM/ZMM value crosses the u128 helper ABI.
    fn vpbroadcastd_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 16 || args[0].size() < 4 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let lane = u128::from(cpu.read::<u32>(args[0].slice(0, 4)));
        cpu.write_var(dst, lane | lane << 32 | lane << 64 | lane << 96);
    }

    /// One 128-bit slice of VPTERNLOGD/Q. The truth-table operation is bitwise,
    /// so dword and qword forms share the same implementation. Source 2 and
    /// imm8 are the third and fourth p-codeop arguments and are width-safe
    /// because each vector operand has already been lowered to 128 bits.
    fn vpternlog_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 16 || args[0].size() != 16 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let destination = cpu.read::<u128>(args[0]);
        let source1 = cpu.read::<u128>(args[1]);
        let source2 = cpu.args[0];
        let table = cpu.args[1] as u8;
        let mut result = 0_u128;
        for index in 0..8 {
            if table & (1 << index) == 0 {
                continue;
            }
            let d = if index & 4 != 0 { destination } else { !destination };
            let a = if index & 2 != 0 { source1 } else { !source1 };
            let b = if index & 1 != 0 { source2 } else { !source2 };
            result |= d & a & b;
        }
        cpu.write_var(dst, result);
    }

    fn named_reg(cpu: &mut Cpu, name: &str) -> Option<VarNode> {
        match cpu.arch.sleigh.get_varnode(name) {
            Some(var) => Some(var),
            None => {
                cpu.exception.code = ExceptionCode::InternalError as u32;
                cpu.exception.value = 0;
                None
            }
        }
    }

    fn read_named<R: crate::RegValue>(cpu: &mut Cpu, name: &str) -> Option<R> {
        let var = named_reg(cpu, name)?;
        Some(cpu.read_var(var))
    }

    fn write_named<R: crate::RegValue>(cpu: &mut Cpu, name: &str, value: R) -> Option<()> {
        let var = named_reg(cpu, name)?;
        cpu.write_var(var, value);
        Some(())
    }

    fn named_slice(cpu: &mut Cpu, name: &str, offset: u8, size: u8) -> Option<VarNode> {
        match cpu.arch.sleigh.get_reg(name).and_then(|reg| reg.slice_var(offset, size)) {
            Some(var) => Some(var),
            None => {
                cpu.exception.code = ExceptionCode::InternalError as u32;
                cpu.exception.value = 0;
                None
            }
        }
    }

    fn fx_address(cpu: &mut Cpu, value: Value) -> Option<u64> {
        let address = cpu.read(value);
        if address & 0xf != 0 {
            cpu.exception.code = ExceptionCode::GeneralProtection as u32;
            cpu.exception.value = 0;
            return None;
        }
        Some(address)
    }

    fn xsave_address(cpu: &mut Cpu, value: Value) -> Option<u64> {
        let address: u64 = cpu.read(value);
        if address & 0x3f != 0 {
            cpu.exception.code = ExceptionCode::GeneralProtection as u32;
            cpu.exception.value = 0;
            return None;
        }
        Some(address)
    }

    fn xstate_request(cpu: &mut Cpu) -> Option<u64> {
        let eax = read_named::<u64>(cpu, "RAX")? & 0xffff_ffff;
        let edx = read_named::<u64>(cpu, "RDX")? & 0xffff_ffff;
        Some(((edx << 32) | eax) & INITIAL_XCR0)
    }

    fn write_guest(cpu: &mut Cpu, address: u64, bytes: &[u8]) -> Option<()> {
        // The MMU's bulk API reports only the error class after a potentially
        // partial access. XSAVE-family faults must identify the first failing
        // linear byte, so walk the small architectural image explicitly.
        for (offset, byte) in bytes.iter().copied().enumerate() {
            let Some(current) = address.checked_add(offset as u64)
            else {
                cpu.exception.code = ExceptionCode::AddressOverflow as u32;
                cpu.exception.value = u64::MAX;
                return None;
            };
            if let Err(error) = cpu.mem.write::<1>(current, [byte], icicle_mem::perm::WRITE) {
                cpu.exception.code = ExceptionCode::from_store_error(error) as u32;
                cpu.exception.value = current;
                return None;
            }
        }
        Some(())
    }

    fn read_guest(cpu: &mut Cpu, address: u64, bytes: &mut [u8]) -> Option<()> {
        for (offset, byte) in bytes.iter_mut().enumerate() {
            let Some(current) = address.checked_add(offset as u64)
            else {
                cpu.exception.code = ExceptionCode::AddressOverflow as u32;
                cpu.exception.value = u64::MAX;
                return None;
            };
            match cpu.mem.read::<1>(current, icicle_mem::perm::READ) {
                Ok(value) => *byte = value[0],
                Err(error) => {
                    cpu.exception.code = ExceptionCode::from_load_error(error) as u32;
                    cpu.exception.value = current;
                    return None;
                }
            }
        }
        Some(())
    }

    fn abridged_tag_word(full: u16) -> u8 {
        let mut abridged = 0_u8;
        for index in 0..8 {
            if (full >> (index * 2)) & 0b11 != 0b11 {
                abridged |= 1 << index;
            }
        }
        abridged
    }

    fn expanded_tag_word(abridged: u8, image: &[u8; 512]) -> u16 {
        let mut full = 0_u16;
        for index in 0..8 {
            let tag = if abridged & (1 << index) == 0 {
                0b11
            }
            else {
                let slot = 32 + index * 16;
                let significand = u64::from_le_bytes(image[slot..slot + 8].try_into().unwrap());
                let exponent =
                    u16::from_le_bytes(image[slot + 8..slot + 10].try_into().unwrap()) & 0x7fff;
                if exponent == 0 && significand == 0 {
                    0b01
                }
                else if exponent == 0 || exponent == 0x7fff || significand >> 63 == 0 {
                    0b10
                }
                else {
                    0b00
                }
            };
            full |= tag << (index * 2);
        }
        full
    }

    fn build_fx_image(cpu: &mut Cpu, mode64: bool) -> Option<[u8; 512]> {
        let mut image = [0_u8; 512];

        let fcw = read_named::<u16>(cpu, "FPUControlWord")?;
        let fsw = read_named::<u16>(cpu, "FPUStatusWord")?;
        let ftw = read_named::<u16>(cpu, "FPUTagWord")?;
        let fop = read_named::<u16>(cpu, "FPULastInstructionOpcode")?;
        let fip = read_named::<u64>(cpu, "FPUInstructionPointer")?;
        let fdp = read_named::<u64>(cpu, "FPUDataPointer")?;
        let fcs = read_named::<u16>(cpu, "FPUPointerSelector")?;
        let fds = read_named::<u16>(cpu, "FPUDataSelector")?;
        let mxcsr = read_named::<u32>(cpu, "MXCSR")?;

        image[0..2].copy_from_slice(&fcw.to_le_bytes());
        image[2..4].copy_from_slice(&fsw.to_le_bytes());
        image[4] = abridged_tag_word(ftw);
        image[6..8].copy_from_slice(&(fop & 0x07ff).to_le_bytes());
        if mode64 {
            image[8..16].copy_from_slice(&fip.to_le_bytes());
            image[16..24].copy_from_slice(&fdp.to_le_bytes());
        }
        else {
            image[8..12].copy_from_slice(&(fip as u32).to_le_bytes());
            image[12..14].copy_from_slice(&fcs.to_le_bytes());
            image[16..20].copy_from_slice(&(fdp as u32).to_le_bytes());
            image[20..22].copy_from_slice(&fds.to_le_bytes());
        }
        image[24..28].copy_from_slice(&mxcsr.to_le_bytes());
        image[28..32].copy_from_slice(&MXCSR_MASK.to_le_bytes());

        for index in 0..8 {
            let value = read_named::<[u8; 10]>(cpu, &format!("ST{index}"))?;
            let offset = 32 + index * 16;
            image[offset..offset + 10].copy_from_slice(&value);
        }
        for index in 0..16 {
            let value = read_named::<[u8; 16]>(cpu, &format!("XMM{index}"))?;
            let offset = 160 + index * 16;
            image[offset..offset + 16].copy_from_slice(&value);
        }
        Some(image)
    }

    fn fxsave_impl(cpu: &mut Cpu, address: Value, mode64: bool) {
        let Some(address) = fx_address(cpu, address)
        else {
            return;
        };
        let Some(image) = build_fx_image(cpu, mode64)
        else {
            return;
        };
        write_guest(cpu, address, &image);
    }

    fn validate_mxcsr(cpu: &mut Cpu, image: &[u8; 512]) -> Option<u32> {
        let mxcsr = u32::from_le_bytes(image[24..28].try_into().unwrap());
        if mxcsr & !MXCSR_MASK != 0 {
            cpu.exception.code = ExceptionCode::GeneralProtection as u32;
            cpu.exception.value = 0;
            return None;
        }
        Some(mxcsr)
    }

    fn restore_x87(cpu: &mut Cpu, image: &[u8; 512], mode64: bool) -> Option<()> {
        let fcw = u16::from_le_bytes(image[0..2].try_into().unwrap());
        let fsw = u16::from_le_bytes(image[2..4].try_into().unwrap());
        let ftw = expanded_tag_word(image[4], &image);
        let fop = u16::from_le_bytes(image[6..8].try_into().unwrap()) & 0x07ff;
        let (fip, fdp, fcs, fds) = if mode64 {
            (
                u64::from_le_bytes(image[8..16].try_into().unwrap()),
                u64::from_le_bytes(image[16..24].try_into().unwrap()),
                0,
                0,
            )
        }
        else {
            (
                u32::from_le_bytes(image[8..12].try_into().unwrap()) as u64,
                u32::from_le_bytes(image[16..20].try_into().unwrap()) as u64,
                u16::from_le_bytes(image[12..14].try_into().unwrap()),
                u16::from_le_bytes(image[20..22].try_into().unwrap()),
            )
        };

        write_named(cpu, "FPUControlWord", fcw)?;
        write_named(cpu, "FPUStatusWord", fsw)?;
        write_named(cpu, "FPUTagWord", ftw)?;
        write_named(cpu, "FPULastInstructionOpcode", fop)?;
        write_named(cpu, "FPUInstructionPointer", fip)?;
        write_named(cpu, "FPUDataPointer", fdp)?;
        write_named(cpu, "FPUPointerSelector", fcs)?;
        write_named(cpu, "FPUDataSelector", fds)?;

        for index in 0..8 {
            let offset = 32 + index * 16;
            let value: [u8; 10] = image[offset..offset + 10].try_into().unwrap();
            write_named(cpu, &format!("ST{index}"), value)?;
        }
        Some(())
    }

    fn initialize_x87(cpu: &mut Cpu) -> Option<()> {
        write_named(cpu, "FPUControlWord", 0x037f_u16)?;
        write_named(cpu, "FPUStatusWord", 0_u16)?;
        write_named(cpu, "FPUTagWord", 0xffff_u16)?;
        write_named(cpu, "FPULastInstructionOpcode", 0_u16)?;
        write_named(cpu, "FPUInstructionPointer", 0_u64)?;
        write_named(cpu, "FPUDataPointer", 0_u64)?;
        write_named(cpu, "FPUPointerSelector", 0_u16)?;
        write_named(cpu, "FPUDataSelector", 0_u16)?;
        for index in 0..8 {
            write_named(cpu, &format!("ST{index}"), [0_u8; 10])?;
        }
        Some(())
    }

    fn restore_sse(cpu: &mut Cpu, image: &[u8; 512]) -> Option<()> {
        for index in 0..16 {
            let offset = 160 + index * 16;
            let value: [u8; 16] = image[offset..offset + 16].try_into().unwrap();
            write_named(cpu, &format!("XMM{index}"), value)?;
        }
        Some(())
    }

    fn initialize_sse(cpu: &mut Cpu) -> Option<()> {
        for index in 0..16 {
            write_named(cpu, &format!("XMM{index}"), [0_u8; 16])?;
        }
        Some(())
    }

    fn fxrstor_impl(cpu: &mut Cpu, address: Value, mode64: bool) {
        let Some(address) = fx_address(cpu, address)
        else {
            return;
        };
        let mut image = [0_u8; 512];
        if read_guest(cpu, address, &mut image).is_none() {
            return;
        }
        let Some(mxcsr) = validate_mxcsr(cpu, &image)
        else {
            return;
        };
        if restore_x87(cpu, &image, mode64).is_none()
            || write_named(cpu, "MXCSR", mxcsr).is_none()
            || restore_sse(cpu, &image).is_none()
        {
            return;
        }
    }

    fn xstate_in_use(cpu: &mut Cpu) -> Option<u64> {
        // Host-driven state transfer (notably Linux signal delivery) can run
        // while the CPU still carries the syscall exception that entered the
        // host. Only a new helper failure is relevant here.
        let exception_before = cpu.exception.code;
        let mut in_use = 0_u64;
        if read_named::<u16>(cpu, "FPUControlWord")? != 0x037f
            || read_named::<u16>(cpu, "FPUStatusWord")? != 0
            || read_named::<u16>(cpu, "FPUTagWord")? != 0xffff
            || read_named::<u16>(cpu, "FPULastInstructionOpcode")? != 0
            || read_named::<u64>(cpu, "FPUInstructionPointer")? != 0
            || read_named::<u64>(cpu, "FPUDataPointer")? != 0
            || read_named::<u16>(cpu, "FPUPointerSelector")? != 0
            || read_named::<u16>(cpu, "FPUDataSelector")? != 0
            || (0..8).any(|index| {
                read_named::<[u8; 10]>(cpu, &format!("ST{index}"))
                    .is_some_and(|value| value != [0; 10])
            })
        {
            in_use |= 1 << 0;
        }
        if (0..16).any(|index| {
            read_named::<[u8; 16]>(cpu, &format!("XMM{index}"))
                .is_some_and(|value| value != [0; 16])
        }) {
            in_use |= 1 << 1;
        }
        if (0..16).any(|index| {
            named_slice(cpu, &format!("ZMM{index}"), 16, 16)
                .is_some_and(|var| cpu.read_var::<[u8; 16]>(var) != [0; 16])
        }) {
            in_use |= 1 << 2;
        }
        if (0..8).any(|index| {
            read_named::<u64>(cpu, &format!("K{index}")).is_some_and(|value| value != 0)
        }) {
            in_use |= 1 << 5;
        }
        if (0..16).any(|index| {
            (0..2).any(|lane| {
                named_slice(cpu, &format!("ZMM{index}"), 32 + lane * 16, 16)
                    .is_some_and(|var| cpu.read_var::<[u8; 16]>(var) != [0; 16])
            })
        }) {
            in_use |= 1 << 6;
        }
        if (16..32).any(|index| {
            (0..4).any(|lane| {
                named_slice(cpu, &format!("ZMM{index}"), lane * 16, 16)
                    .is_some_and(|var| cpu.read_var::<[u8; 16]>(var) != [0; 16])
            })
        }) {
            in_use |= 1 << 7;
        }
        if cpu.exception.code == exception_before { Some(in_use) } else { None }
    }

    /// Serialize the complete standard-format user xstate image used by the
    /// Linux x86-64 signal ABI. The layout is the same table exposed through
    /// CPUID leaf 0x0d and consumed by XSAVE/XRSTOR.
    pub fn standard_xstate_image(cpu: &mut Cpu, mode64: bool) -> Option<Vec<u8>> {
        let legacy = build_fx_image(cpu, mode64)?;
        let present = xstate_in_use(cpu)? & INITIAL_XCR0;
        let mut image = vec![0_u8; STANDARD_XSTATE_SIZE];
        image[..legacy.len()].copy_from_slice(&legacy);
        image[512..520].copy_from_slice(&present.to_le_bytes());

        for index in 0..16 {
            let ymm = named_slice(cpu, &format!("ZMM{index}"), 16, 16)?;
            image[576 + index * 16..576 + (index + 1) * 16]
                .copy_from_slice(&cpu.read_var::<[u8; 16]>(ymm));
            for lane in 0..2 {
                let zmm = named_slice(cpu, &format!("ZMM{index}"), 32 + lane * 16, 16)?;
                let start = 1152 + index * 32 + usize::from(lane) * 16;
                image[start..start + 16].copy_from_slice(&cpu.read_var::<[u8; 16]>(zmm));
            }
        }
        for index in 0..8 {
            let value = read_named::<u64>(cpu, &format!("K{index}"))?;
            let start = 1088 + index * 8;
            image[start..start + 8].copy_from_slice(&value.to_le_bytes());
        }
        for index in 16..32 {
            for lane in 0..4 {
                let zmm = named_slice(cpu, &format!("ZMM{index}"), lane * 16, 16)?;
                let start = 1664 + (index - 16) * 64 + usize::from(lane) * 16;
                image[start..start + 16].copy_from_slice(&cpu.read_var::<[u8; 16]>(zmm));
            }
        }
        Some(image)
    }

    fn save_x87_component(cpu: &mut Cpu, address: u64, image: &[u8; 512]) -> Option<()> {
        write_guest(cpu, address, &image[..24])?;
        for index in 0..8 {
            let offset = 32 + index * 16;
            write_guest(cpu, address + offset as u64, &image[offset..offset + 10])?;
        }
        Some(())
    }

    fn save_sse_component(cpu: &mut Cpu, address: u64, image: &[u8; 512]) -> Option<()> {
        for index in 0..16 {
            let offset = 160 + index * 16;
            write_guest(cpu, address + offset as u64, &image[offset..offset + 16])?;
        }
        Some(())
    }

    fn xsave_impl(cpu: &mut Cpu, address: Value, mode64: bool) {
        let Some(address) = xsave_address(cpu, address)
        else {
            return;
        };
        let Some(requested) = xstate_request(cpu)
        else {
            return;
        };
        let Some(legacy) = build_fx_image(cpu, mode64)
        else {
            return;
        };
        let Some(in_use) = xstate_in_use(cpu)
        else {
            return;
        };

        // XSAVE updates only XSTATE_BV in the header. Bits for components not
        // selected by RFBM and every reserved header byte remain untouched.
        let header_address = address + u64::from(x86_profile::XSAVE_LEGACY_SIZE);
        let mut old_bv = [0_u8; 8];
        if read_guest(cpu, header_address, &mut old_bv).is_none() {
            return;
        }
        let old_bv = u64::from_le_bytes(old_bv);
        let updated_bv = (old_bv & !requested) | (in_use & requested);
        if write_guest(cpu, header_address, &updated_bv.to_le_bytes()).is_none() {
            return;
        }

        if requested & (1 << 0) != 0 && save_x87_component(cpu, address, &legacy).is_none() {
            return;
        }
        // MXCSR and MXCSR_MASK are saved when either SSE or AVX is requested.
        if requested & ((1 << 1) | (1 << 2)) != 0
            && write_guest(cpu, address + 24, &legacy[24..32]).is_none()
        {
            return;
        }
        if requested & (1 << 1) != 0 && save_sse_component(cpu, address, &legacy).is_none() {
            return;
        }
        if requested & (1 << 2) != 0 {
            for index in 0..16 {
                let Some(var) = named_slice(cpu, &format!("ZMM{index}"), 16, 16)
                else {
                    return;
                };
                let value = cpu.read_var::<[u8; 16]>(var);
                if write_guest(cpu, address + 576 + index * 16, &value).is_none() {
                    return;
                }
            }
        }
        if requested & (1 << 5) != 0 {
            for index in 0..8 {
                let Some(value) = read_named::<u64>(cpu, &format!("K{index}"))
                else {
                    return;
                };
                if write_guest(cpu, address + 1088 + index * 8, &value.to_le_bytes()).is_none() {
                    return;
                }
            }
        }
        if requested & (1 << 6) != 0 {
            for index in 0..16 {
                for lane in 0..2 {
                    let Some(var) = named_slice(cpu, &format!("ZMM{index}"), 32 + lane * 16, 16)
                    else {
                        return;
                    };
                    let value = cpu.read_var::<[u8; 16]>(var);
                    if write_guest(cpu, address + 1152 + index * 32 + u64::from(lane) * 16, &value)
                        .is_none()
                    {
                        return;
                    }
                }
            }
        }
        if requested & (1 << 7) != 0 {
            for index in 16..32 {
                for lane in 0..4 {
                    let Some(var) = named_slice(cpu, &format!("ZMM{index}"), lane * 16, 16)
                    else {
                        return;
                    };
                    let value = cpu.read_var::<[u8; 16]>(var);
                    if write_guest(
                        cpu,
                        address + 1664 + (index - 16) * 64 + u64::from(lane) * 16,
                        &value,
                    )
                    .is_none()
                    {
                        return;
                    }
                }
            }
        }
    }

    fn read_x87_component(cpu: &mut Cpu, address: u64, image: &mut [u8; 512]) -> Option<()> {
        read_guest(cpu, address, &mut image[..24])?;
        for index in 0..8 {
            let offset = 32 + index * 16;
            read_guest(cpu, address + offset as u64, &mut image[offset..offset + 10])?;
        }
        Some(())
    }

    fn read_sse_component(cpu: &mut Cpu, address: u64, image: &mut [u8; 512]) -> Option<()> {
        for index in 0..16 {
            let offset = 160 + index * 16;
            read_guest(cpu, address + offset as u64, &mut image[offset..offset + 16])?;
        }
        Some(())
    }

    fn validate_xstate_header(cpu: &mut Cpu, header: &[u8]) -> Option<u64> {
        let present = u64::from_le_bytes(header[0..8].try_into().unwrap());
        if present & !INITIAL_XCR0 != 0 || header[8..].iter().any(|byte| *byte != 0) {
            cpu.exception.code = ExceptionCode::GeneralProtection as u32;
            cpu.exception.value = 0;
            return None;
        }
        Some(present)
    }

    fn apply_xstate_components(
        cpu: &mut Cpu,
        requested: u64,
        present: u64,
        legacy: &[u8; 512],
        extended: &[u8],
        mode64: bool,
    ) -> Option<()> {
        if requested & (1 << 0) != 0 {
            if present & (1 << 0) != 0 {
                restore_x87(cpu, legacy, mode64)?;
            }
            else {
                initialize_x87(cpu)?;
            }
        }
        if requested & ((1 << 1) | (1 << 2)) != 0 {
            let mxcsr = u32::from_le_bytes(legacy[24..28].try_into().unwrap());
            write_named(cpu, "MXCSR", mxcsr)?;
        }
        if requested & (1 << 1) != 0 {
            if present & (1 << 1) != 0 {
                restore_sse(cpu, legacy)?;
            }
            else {
                initialize_sse(cpu)?;
            }
        }
        for index in 0..16 {
            if requested & (1 << 2) != 0 {
                let start = 576 + index * 16;
                let value: [u8; 16] = if present & (1 << 2) != 0 {
                    extended[start..start + 16].try_into().unwrap()
                }
                else {
                    [0; 16]
                };
                let var = named_slice(cpu, &format!("ZMM{index}"), 16, 16)?;
                cpu.write_var(var, value);
            }
            if requested & (1 << 6) != 0 {
                for lane in 0..2 {
                    let start = 1152 + index * 32 + lane as usize * 16;
                    let value: [u8; 16] = if present & (1 << 6) != 0 {
                        extended[start..start + 16].try_into().unwrap()
                    }
                    else {
                        [0; 16]
                    };
                    let var = named_slice(cpu, &format!("ZMM{index}"), 32 + lane * 16, 16)?;
                    cpu.write_var(var, value);
                }
            }
        }
        if requested & (1 << 5) != 0 {
            for index in 0..8 {
                let start = 1088 + index * 8;
                let value = if present & (1 << 5) != 0 {
                    u64::from_le_bytes(extended[start..start + 8].try_into().unwrap())
                }
                else {
                    0
                };
                write_named(cpu, &format!("K{index}"), value)?;
            }
        }
        if requested & (1 << 7) != 0 {
            for index in 16..32 {
                for lane in 0..4 {
                    let start = 1664 + (index - 16) as usize * 64 + lane as usize * 16;
                    let value: [u8; 16] = if present & (1 << 7) != 0 {
                        extended[start..start + 16].try_into().unwrap()
                    }
                    else {
                        [0; 16]
                    };
                    let var = named_slice(cpu, &format!("ZMM{index}"), lane * 16, 16)?;
                    cpu.write_var(var, value);
                }
            }
        }
        Some(())
    }

    /// Validate and restore a complete standard-format user xstate image.
    /// The caller must stage the bytes before calling so malformed input or a
    /// guest-memory fault cannot partially update architectural state.
    pub fn restore_standard_xstate_image(cpu: &mut Cpu, image: &[u8], mode64: bool) -> Option<()> {
        if image.len() != STANDARD_XSTATE_SIZE {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = image.len() as u64;
            return None;
        }
        let present = validate_xstate_header(cpu, &image[512..576])?;
        let legacy: &[u8; 512] = image[..512].try_into().unwrap();
        validate_mxcsr(cpu, legacy)?;
        apply_xstate_components(cpu, INITIAL_XCR0, present, legacy, image, mode64)
    }

    fn xrstor_impl(cpu: &mut Cpu, address: Value, mode64: bool) {
        let Some(address) = xsave_address(cpu, address)
        else {
            return;
        };
        let Some(requested) = xstate_request(cpu)
        else {
            return;
        };
        let mut header = [0_u8; x86_profile::XSAVE_HEADER_SIZE as usize];
        if read_guest(cpu, address + u64::from(x86_profile::XSAVE_LEGACY_SIZE), &mut header)
            .is_none()
        {
            return;
        }
        let Some(present) = validate_xstate_header(cpu, &header)
        else {
            return;
        };

        // Stage every requested, present component before mutating registers.
        // A memory fault therefore leaves the architectural register file at
        // the restart RIP unchanged.
        let mut legacy = [0_u8; 512];
        if requested & ((1 << 1) | (1 << 2)) != 0 {
            if read_guest(cpu, address + 24, &mut legacy[24..28]).is_none() {
                return;
            }
            if validate_mxcsr(cpu, &legacy).is_none() {
                return;
            }
        }
        if requested & (1 << 0) != 0
            && present & (1 << 0) != 0
            && read_x87_component(cpu, address, &mut legacy).is_none()
        {
            return;
        }
        if requested & (1 << 1) != 0
            && present & (1 << 1) != 0
            && read_sse_component(cpu, address, &mut legacy).is_none()
        {
            return;
        }

        let mut extended = vec![0_u8; x86_profile::XSAVE_AREA_SIZE as usize];
        for component in x86_profile::XSTATE_COMPONENTS {
            let bit = 1_u64 << component.bit;
            if requested & bit == 0 || present & bit == 0 {
                continue;
            }
            let start = component.offset as usize;
            let end = start + component.size as usize;
            if read_guest(cpu, address + u64::from(component.offset), &mut extended[start..end])
                .is_none()
            {
                return;
            }
        }

        apply_xstate_components(cpu, requested, present, &legacy, &extended, mode64);
    }

    /// Extract Packed Double-Precision Floating-Point Sign Mask
    fn movmskpd(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let Some(src) = xmm_bytes(cpu, args[1])
        else {
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
        let Some(src) = xmm_bytes(cpu, args[1])
        else {
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
        let Some(upper) = xmm_bytes(cpu, args[0])
        else {
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
        let Some(upper) = xmm_bytes(cpu, args[0])
        else {
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
        let (Some(src), Some(ctrl)) = (xmm_bytes(cpu, args[0]), xmm_bytes(cpu, args[1]))
        else {
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
        let (Some(a), Some(b)) = (xmm_bytes(cpu, args[0]), xmm_bytes(cpu, args[1]))
        else {
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
        let (Some(a), Some(b)) = (xmm_bytes(cpu, args[0]), xmm_bytes(cpu, args[1]))
        else {
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
        let (Some(a), Some(b)) = (xmm_bytes(cpu, args[0]), xmm_bytes(cpu, args[1]))
        else {
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
        let (Some(a), Some(b)) = (xmm_bytes(cpu, args[0]), xmm_bytes(cpu, args[1]))
        else {
            return;
        };
        let mut out = [0u8; 16];
        for (half, src) in [a, b].into_iter().enumerate() {
            for i in 0..8 {
                let w = i16::from_le_bytes([src[2 * i], src[2 * i + 1]]) as i32;
                out[half * 8 + i] =
                    if signed { w.clamp(-128, 127) as i8 as u8 } else { w.clamp(0, 255) as u8 };
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
        let (Some(a), Some(b)) = (xmm_bytes(cpu, args[0]), xmm_bytes(cpu, args[1]))
        else {
            return;
        };
        let mut out = [0u8; 16];
        for (half, src) in [a, b].into_iter().enumerate() {
            for i in 0..4 {
                let d = i32::from_le_bytes(src[4 * i..4 * i + 4].try_into().unwrap());
                let w = if signed {
                    d.clamp(-32768, 32767) as i16 as u16
                }
                else {
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
            let r = if count >= 16 { (w >> 15) as u16 } else { (w >> count) as u16 };
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
        let (Some(a), Some(b)) = (xmm_bytes(cpu, args[0]), xmm_bytes(cpu, args[1]))
        else {
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
        let Some(s) = xmm_bytes(cpu, args[1])
        else {
            return;
        };
        let out: [u8; 16] = std::array::from_fn(|i| (s[i] as i8).unsigned_abs());
        write_xmm(cpu, dst, out);
    }
    fn pabsw(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let Some(s) = xmm_bytes(cpu, args[1])
        else {
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
        let Some(s) = xmm_bytes(cpu, args[1])
        else {
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
        let Some(a) = xmm_bytes(cpu, args[0])
        else {
            return;
        };
        let Some(b) = xmm_bytes(cpu, args[1])
        else {
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
        let Some(a) = xmm_bytes(cpu, args[0])
        else {
            return;
        };
        let Some(b) = xmm_bytes(cpu, args[1])
        else {
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
        let (Some(a), Some(b)) = (xmm_bytes(cpu, args[0]), xmm_bytes(cpu, args[1]))
        else {
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
        let (Some(a), Some(b)) = (xmm_bytes(cpu, args[0]), xmm_bytes(cpu, args[1]))
        else {
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
        let (Some(a), Some(b)) = (xmm_bytes(cpu, args[0]), xmm_bytes(cpu, args[1]))
        else {
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
        let (Some(a), Some(b)) = (xmm_bytes(cpu, args[0]), xmm_bytes(cpu, args[1]))
        else {
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
        let (Some(a), Some(b)) = (xmm_bytes(cpu, args[0]), xmm_bytes(cpu, args[1]))
        else {
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
        let (Some(a), Some(b)) = (xmm_bytes(cpu, args[0]), xmm_bytes(cpu, args[1]))
        else {
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
            }
            else if b[i + lane - 1] & 0x80 != 0 {
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
        let Some(src) = xmm_bytes(cpu, args[0])
        else {
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
        let Some(a) = xmm_bytes(cpu, args[0])
        else {
            return;
        };
        let imm = cpu.args[0] as u8;
        // Register source: dword selected by bits 7:6; memory source: the
        // 32-bit value itself.
        let src = if args[1].size() >= 16 {
            let Some(b) = xmm_bytes(cpu, args[1])
            else {
                return;
            };
            let idx = (imm >> 6 & 3) as usize;
            u32::from_le_bytes(b[4 * idx..4 * idx + 4].try_into().unwrap())
        }
        else {
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
        let Some(src) = xmm_bytes(cpu, args[0])
        else {
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
        let Some(b) = xmm_bytes(cpu, args[1])
        else {
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
                let v = f64::from_bits(u64::from_le_bytes(b[8 * i..8 * i + 8].try_into().unwrap()));
                out[8 * i..8 * i + 8].copy_from_slice(&round64(v).to_bits().to_le_bytes());
            }
        }
        else {
            for i in 0..4 {
                let v = f32::from_bits(u32::from_le_bytes(b[4 * i..4 * i + 4].try_into().unwrap()));
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
            }
            else {
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
        let Some(state) = xmm_bytes(cpu, args[0])
        else {
            return;
        };
        let Some(key) = xmm_bytes(cpu, args[1])
        else {
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
        let Some(state) = xmm_bytes(cpu, args[0])
        else {
            return;
        };
        let Some(key) = xmm_bytes(cpu, args[1])
        else {
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
        let Some(state) = xmm_bytes(cpu, args[0])
        else {
            return;
        };
        let Some(key) = xmm_bytes(cpu, args[1])
        else {
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
        let Some(state) = xmm_bytes(cpu, args[0])
        else {
            return;
        };
        let Some(key) = xmm_bytes(cpu, args[1])
        else {
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
        let Some(x) = xmm_bytes(cpu, args[0])
        else {
            return;
        };
        let t = aes_mix_columns(&x, [14, 11, 13, 9]);
        write_xmm(cpu, dst, t);
    }

    fn aeskeygenassist(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let Some(x) = xmm_bytes(cpu, args[0])
        else {
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
