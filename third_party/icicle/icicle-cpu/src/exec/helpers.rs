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
        ("cpuid_cache_tlb_info", cpuid),
        ("cpuid_serial_info", cpuid),
        ("cpuid_Deterministic_Cache_Parameters_info", cpuid),
        ("cpuid_MONITOR_MWAIT_Features_info", cpuid),
        ("cpuid_Thermal_Power_Management_info", cpuid),
        ("cpuid_Extended_Feature_Enumeration_info", cpuid_extended_feature_enumeration_info),
        ("cpuid_Direct_Cache_Access_info", cpuid),
        ("cpuid_Architectural_Performance_Monitoring_info", cpuid),
        ("cpuid_Extended_Topology_info", cpuid),
        ("cpuid_Processor_Extended_States_info", cpuid_xstate_info),
        ("cpuid_Quality_of_Service_info", cpuid),
        ("cpuid_brand_part1_info", cpuid),
        ("cpuid_brand_part2_info", cpuid),
        ("cpuid_brand_part3_info", cpuid),
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
        ("vpbroadcastb_avx512vl", vpbroadcastb_128),
        ("vpbroadcastb_avx512bw", vpbroadcastb_128),
        ("vpbroadcastw_avx512vl", vpbroadcastw_128),
        ("vpbroadcastw_avx512bw", vpbroadcastw_128),
        ("vpbroadcastq_avx512vl", vpbroadcastq_128),
        ("vpbroadcastq_avx512f", vpbroadcastq_128),
        ("vbroadcastss_avx512vl", vpbroadcastd_128),
        ("vbroadcastss_avx512f", vpbroadcastd_128),
        ("vbroadcastsd_avx512vl", vpbroadcastq_128),
        ("vbroadcastsd_avx512f", vpbroadcastq_128),
        ("vbroadcastf32x4_avx512vl", copy_128),
        ("vbroadcastf32x4_avx512f", copy_128),
        ("vbroadcasti32x4_avx512vl", copy_128),
        ("vbroadcasti32x4_avx512f", copy_128),
        ("vaddpd_avx512vl", addpd_masked),
        ("vaddpd_avx512f", addpd_masked),
        ("vaddps_avx512vl", addps_masked),
        ("vaddps_avx512f", addps_masked),
        ("vaddsubpd_avx", addsubpd),
        ("vaddsubps_avx", addsubps),
        ("vdivpd_avx", divpd),
        ("vdivpd_avx512vl", divpd_masked),
        ("vdivpd_avx512f", divpd_masked),
        ("vdivps_avx", divps),
        ("vdivps_avx512vl", divps_masked),
        ("vdivps_avx512f", divps_masked),
        ("vmaxpd_avx", maxpd),
        ("vmaxpd_avx512vl", maxpd_masked),
        ("vmaxpd_avx512f", maxpd_masked),
        ("vmaxps_avx", maxps),
        ("vmaxps_avx512vl", maxps_masked),
        ("vmaxps_avx512f", maxps_masked),
        ("vmaxsd_avx", maxsd),
        ("vmaxss_avx", maxss),
        ("vmaxsd_avx512f", maxsd_masked),
        ("vmaxss_avx512f", maxss_masked),
        ("vminpd_avx", minpd),
        ("vminpd_avx512vl", minpd_masked),
        ("vminpd_avx512f", minpd_masked),
        ("vminps_avx", minps),
        ("vminps_avx512vl", minps_masked),
        ("vminps_avx512f", minps_masked),
        ("vminsd_avx", minsd),
        ("vminss_avx", minss),
        ("vminsd_avx512f", minsd_masked),
        ("vminss_avx512f", minss_masked),
        ("vaddsd_avx512f", addsd_masked),
        ("vaddss_avx512f", addss_masked),
        ("vdivsd_avx512f", divsd_masked),
        ("vdivss_avx512f", divss_masked),
        ("vmulsd_avx512f", mulsd_masked),
        ("vmulss_avx512f", mulss_masked),
        ("vsubsd_avx512f", subsd_masked),
        ("vsubss_avx512f", subss_masked),
        ("vmulpd_avx512vl", mulpd_masked),
        ("vmulpd_avx512f", mulpd_masked),
        ("vmulps_avx512vl", mulps_masked),
        ("vmulps_avx512f", mulps_masked),
        ("vsqrtpd_avx", vector_sqrtpd),
        ("vsqrtpd_avx512vl", vector_sqrtpd_masked),
        ("vsqrtpd_avx512f", vector_sqrtpd_masked),
        ("vsqrtps_avx", vector_sqrtps),
        ("vsqrtps_avx512vl", vector_sqrtps_masked),
        ("vsqrtps_avx512f", vector_sqrtps_masked),
        ("vsubpd_avx", subpd),
        ("vsubpd_avx512vl", subpd_masked),
        ("vsubpd_avx512f", subpd_masked),
        ("vsubps_avx", subps),
        ("vsubps_avx512vl", subps_masked),
        ("vsubps_avx512f", subps_masked),
        ("vunpckhpd_avx", packed_unpack_high_q_128),
        ("vunpckhpd_avx512vl", packed_unpack_high_q_128),
        ("vunpckhpd_avx512f", packed_unpack_high_q_128),
        ("vunpcklpd_avx", punpcklqdq),
        ("vunpcklpd_avx512vl", punpcklqdq),
        ("vunpcklpd_avx512f", punpcklqdq),
        ("vunpckhps_avx", packed_unpack_high_d_128),
        ("vunpckhps_avx512vl", packed_unpack_high_d_128),
        ("vunpckhps_avx512f", packed_unpack_high_d_128),
        ("vunpcklps_avx", packed_unpack_low_d_128),
        ("vunpcklps_avx512vl", packed_unpack_low_d_128),
        ("vunpcklps_avx512f", packed_unpack_low_d_128),
        ("vblendpd_avx", packed_blend_pd_indexed),
        ("vblendps_avx", packed_blend_ps_indexed),
        ("vblendvpd_avx", blendvpd),
        ("vblendvps_avx", blendvps),
        ("vblendmpd_avx512vl", copy_second_128),
        ("vblendmpd_avx512f", copy_second_128),
        ("vblendmps_avx512vl", copy_second_128),
        ("vblendmps_avx512f", copy_second_128),
        ("vmovddup_avx512vl", packed_move_ddup_128),
        ("vmovddup_avx512f", packed_move_ddup_128),
        ("vmovshdup_avx", packed_move_shdup_128),
        ("vmovshdup_avx512vl", packed_move_shdup_128),
        ("vmovshdup_avx512f", packed_move_shdup_128),
        ("vmovsldup_avx", packed_move_sldup_128),
        ("vmovsldup_avx512vl", packed_move_sldup_128),
        ("vmovsldup_avx512f", packed_move_sldup_128),
        ("vmovntdqa_avx", copy_128),
        ("vmovntdqa_avx2", copy_128),
        ("vmovntdqa_avx512vl", copy_128),
        ("vmovntdqa_avx512f", copy_128),
        ("vlddqu_avx", copy_128),
        ("vmovntpd_avx", copy_128),
        ("vmovntpd_avx512vl", copy_128),
        ("vmovntpd_avx512f", copy_128),
        ("vmovntps_avx", copy_128),
        ("vmovntps_avx512vl", copy_128),
        ("vmovntps_avx512f", copy_128),
        ("vextractps_avx", extractps),
        ("vextractps_avx512f", extractps),
        ("vinsertps_avx", insertps),
        ("vinsertps_avx512f", insertps),
        ("vmovmskpd_avx", vmovmskpd),
        ("vmovmskps_avx", vmovmskps),
        ("webtos_vmovmskpd_256", vmovmskpd_256),
        ("webtos_vmovmskps_256", vmovmskps_256),
        ("vmovhlps_avx", vmovhlps),
        ("vmovhpd_avx", vmov_high64),
        ("vmovhpd_avx512f", vmov_high64),
        ("vmovhps_avx", vmov_high64),
        ("vmovhps_avx512f", vmov_high64),
        ("vmovlhps_avx", vmovlhps),
        ("vmovlhps_avx512f", vmovlhps),
        ("vmovlpd_avx", vmov_low64),
        ("vmovlpd_avx512f", vmov_low64),
        ("vmovlps_avx", vmov_low64),
        ("vmovlps_avx512f", vmov_low64),
        ("vpermilpd_avx", vpermilpd),
        ("vpermilpd_avx512vl", vpermilpd),
        ("vpermilpd_avx512f", vpermilpd),
        ("vpermilps_avx", vpermilps),
        ("vpermilps_avx512vl", vpermilps),
        ("vpermilps_avx512f", vpermilps),
        ("vroundpd_avx", roundpd),
        ("vroundps_avx", roundps),
        ("vroundsd_avx", roundsd),
        ("vroundss_avx", roundss),
        ("vrcpps_avx", reciprocal_ps),
        ("vrcpss_avx", reciprocal_ss),
        ("vrsqrtps_avx", reciprocal_sqrt_ps),
        ("vrsqrtss_avx", reciprocal_sqrt_ss),
        ("vmpsadbw_avx", packed_mpsadbw_128),
        ("vmpsadbw_avx2", packed_mpsadbw_128),
        ("vdppd_avx", dotpd),
        ("vdpps_avx", dotps),
        ("vcmppd_avx", compare_pd),
        ("vcmpps_avx", compare_ps),
        ("vcmpsd_avx", compare_sd),
        ("vcmpss_avx", compare_ss),
        ("webtos_vcmppd_mask_128", compare_pd_mask_128),
        ("webtos_vcmpps_mask_128", compare_ps_mask_128),
        ("webtos_vcmpsd_mask", compare_sd_mask),
        ("webtos_vcmpss_mask", compare_ss_mask),
        ("vcvtdq2pd_avx", convert_i32_to_f64_128),
        ("vcvtdq2ps_avx", convert_i32_to_f32_128),
        ("vcvtps2dq_avx", convert_f32_to_i32_128),
        ("vcvtps2pd_avx", convert_f32_to_f64_128),
        ("vcvtdq2pd_avx512vl", convert_i32_to_f64_128),
        ("vcvtdq2pd_avx512f", convert_i32_to_f64_128),
        ("vcvtdq2ps_avx512vl", convert_i32_to_f32_128),
        ("vcvtdq2ps_avx512f", convert_i32_to_f32_128),
        ("vcvtpd2dq_avx512vl", convert_f64_to_i32),
        ("vcvtpd2dq_avx512f", convert_f64_to_i32),
        ("vcvtpd2ps_avx512vl", convert_f64_pair_to_f32),
        ("vcvtpd2ps_avx512f", convert_f64_pair_to_f32),
        ("vcvtpd2udq_avx512vl", convert_f64_to_u32),
        ("vcvtpd2udq_avx512f", convert_f64_to_u32),
        ("vcvtph2ps_avx512vl", convert_f16_to_f32),
        ("vcvtph2ps_avx512f", convert_f16_to_f32),
        ("vcvtps2dq_avx512vl", convert_f32_to_i32_128),
        ("vcvtps2dq_avx512f", convert_f32_to_i32_128),
        ("vcvtps2pd_avx512vl", convert_f32_to_f64_128),
        ("vcvtps2pd_avx512f", convert_f32_to_f64_128),
        ("vcvtps2ph_avx512vl", convert_f32_to_f16),
        ("vcvtps2ph_avx512f", convert_f32_to_f16),
        ("vcvtps2udq_avx512vl", convert_f32_to_u32),
        ("vcvtps2udq_avx512f", convert_f32_to_u32),
        ("vcvtsd2si_avx512f", convert_scalar_f64_to_i),
        ("vcvtsd2ss_avx512f", convert_scalar_f64_to_f32),
        ("vcvtsd2usi_avx512f", convert_scalar_f64_to_u),
        ("vcvtsi2sd_avx512f", convert_scalar_i_to_f64),
        ("vcvtsi2ss_avx512f", convert_scalar_i_to_f32),
        ("vcvtss2sd_avx512f", convert_scalar_f32_to_f64),
        ("vcvtss2si_avx512f", convert_scalar_f32_to_i),
        ("vcvtss2usi_avx512f", convert_scalar_f32_to_u),
        ("vcvttpd2dq_avx512vl", truncate_f64_to_i32),
        ("vcvttpd2dq_avx512f", truncate_f64_to_i32),
        ("vcvttpd2udq_avx512vl", truncate_f64_to_u32),
        ("vcvttpd2udq_avx512f", truncate_f64_to_u32),
        ("vcvttps2dq_avx512vl", truncate_f32_to_i32),
        ("vcvttps2dq_avx512f", truncate_f32_to_i32),
        ("vcvttps2udq_avx512vl", truncate_f32_to_u32),
        ("vcvttps2udq_avx512f", truncate_f32_to_u32),
        ("vcvttsd2si_avx512f", truncate_scalar_f64_to_i),
        ("vcvttsd2usi_avx512f", truncate_scalar_f64_to_u),
        ("vcvttss2si_avx512f", truncate_scalar_f32_to_i),
        ("vcvttss2usi_avx512f", truncate_scalar_f32_to_u),
        ("vcvtudq2pd_avx512vl", convert_u32_to_f64),
        ("vcvtudq2pd_avx512f", convert_u32_to_f64),
        ("vcvtudq2ps_avx512vl", convert_u32_to_f32),
        ("vcvtudq2ps_avx512f", convert_u32_to_f32),
        ("vcvtusi2sd_avx512f", convert_scalar_u_to_f64),
        ("vcvtusi2ss_avx512f", convert_scalar_u_to_f32),
        ("vgatherdpd", vex_vsib_gather),
        ("vgatherdps", vex_vsib_gather),
        ("vgatherqpd", vex_vsib_gather),
        ("vgatherqps", vex_vsib_gather),
        ("vpgatherdd", vex_vsib_gather),
        ("vpgatherdq", vex_vsib_gather),
        ("vpgatherqd", vex_vsib_gather),
        ("vpgatherqq", vex_vsib_gather),
        ("vgatherdpd_avx512vl", vsib_gather),
        ("vgatherdpd_avx512f", vsib_gather),
        ("vgatherdps_avx512vl", vsib_gather),
        ("vgatherdps_avx512f", vsib_gather),
        ("vgatherqpd_avx512vl", vsib_gather),
        ("vgatherqpd_avx512f", vsib_gather),
        ("vgatherqps_avx512vl", vsib_gather),
        ("vgatherqps_avx512f", vsib_gather),
        ("vpgatherdd_avx512vl", vsib_gather),
        ("vpgatherdd_avx512f", vsib_gather),
        ("vpgatherdq_avx512vl", vsib_gather),
        ("vpgatherdq_avx512f", vsib_gather),
        ("vpgatherqd_avx512vl", vsib_gather),
        ("vpgatherqd_avx512f", vsib_gather),
        ("vpgatherqq_avx512vl", vsib_gather),
        ("vpgatherqq_avx512f", vsib_gather),
        ("vpscatterdd_avx512vl", vsib_scatter),
        ("vpscatterdd_avx512f", vsib_scatter),
        ("vpscatterdq_avx512vl", vsib_scatter),
        ("vpscatterdq_avx512f", vsib_scatter),
        ("vpscatterqd_avx512vl", vsib_scatter),
        ("vpscatterqd_avx512f", vsib_scatter),
        ("vpscatterqq_avx512vl", vsib_scatter),
        ("vpscatterqq_avx512f", vsib_scatter),
        ("vscatterdpd_avx512vl", vsib_scatter),
        ("vscatterdpd_avx512f", vsib_scatter),
        ("vscatterdps_avx512vl", vsib_scatter),
        ("vscatterdps_avx512f", vsib_scatter),
        ("vscatterqpd_avx512vl", vsib_scatter),
        ("vscatterqpd_avx512f", vsib_scatter),
        ("vscatterqps_avx512vl", vsib_scatter),
        ("vscatterqps_avx512f", vsib_scatter),
        ("vfixupimmpd_avx512vl", fixup_pd),
        ("vfixupimmpd_avx512f", fixup_pd),
        ("vfixupimmps_avx512vl", fixup_ps),
        ("vfixupimmps_avx512f", fixup_ps),
        ("vfixupimmsd_avx512f", fixup_sd),
        ("vfixupimmss_avx512f", fixup_ss),
        ("vgetexppd_avx512vl", getexp_pd),
        ("vgetexppd_avx512f", getexp_pd),
        ("vgetexpps_avx512vl", getexp_ps),
        ("vgetexpps_avx512f", getexp_ps),
        ("vgetexpsd_avx512f", getexp_sd),
        ("vgetexpss_avx512f", getexp_ss),
        ("vgetmantpd_avx512vl", getmant_pd),
        ("vgetmantpd_avx512f", getmant_pd),
        ("vgetmantps_avx512vl", getmant_ps),
        ("vgetmantps_avx512f", getmant_ps),
        ("vgetmantsd_avx512f", getmant_sd),
        ("vgetmantss_avx512f", getmant_ss),
        ("vrcp14pd_avx512vl", rcp14_pd),
        ("vrcp14pd_avx512f", rcp14_pd),
        ("vrcp14ps_avx512vl", rcp14_ps),
        ("vrcp14ps_avx512f", rcp14_ps),
        ("vrcp14sd_avx512f", rcp14_sd),
        ("vrcp14ss_avx512f", rcp14_ss),
        ("vrndscalepd_avx512vl", rndscale_pd),
        ("vrndscalepd_avx512f", rndscale_pd),
        ("vrndscaleps_avx512vl", rndscale_ps),
        ("vrndscaleps_avx512f", rndscale_ps),
        ("vrndscalesd_avx512f", rndscale_sd),
        ("vrndscaless_avx512f", rndscale_ss),
        ("vrsqrt14pd_avx512vl", rsqrt14_pd),
        ("vrsqrt14pd_avx512f", rsqrt14_pd),
        ("vrsqrt14ps_avx512vl", rsqrt14_ps),
        ("vrsqrt14ps_avx512f", rsqrt14_ps),
        ("vrsqrt14sd_avx512f", rsqrt14_sd),
        ("vrsqrt14ss_avx512f", rsqrt14_ss),
        ("vscalefpd_avx512vl", scalef_pd),
        ("vscalefpd_avx512f", scalef_pd),
        ("vscalefps_avx512vl", scalef_ps),
        ("vscalefps_avx512f", scalef_ps),
        ("vscalefsd_avx512f", scalef_sd),
        ("vscalefss_avx512f", scalef_ss),
        ("webtos_cvtpd2dq_pair", convert_f64_pair_to_i32),
        ("webtos_cvtpd2ps_pair", convert_f64_pair_to_f32),
        ("vmaskmovdqu_avx", maskmovdqu),
        ("vhaddps_avx", haddps),
        ("vhsubpd_avx", hsubpd),
        ("vhsubps_avx", hsubps),
        ("vldmxcsr_avx", vldmxcsr),
        ("vstmxcsr_avx", vstmxcsr),
        ("vshufpd_avx", packed_shuffle_pd_indexed),
        ("vshufpd_avx512vl", packed_shuffle_pd_indexed),
        ("vshufpd_avx512f", packed_shuffle_pd_indexed),
        ("vshufps_avx", packed_shuffle_ps_128),
        ("vshufps_avx512vl", packed_shuffle_ps_128),
        ("vshufps_avx512f", packed_shuffle_ps_128),
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
        ("vpsllw_avx", psllw),
        ("vpsllw_avx2", psllw),
        ("vpsllw_avx512vl", psllw),
        ("vpsllw_avx512bw", psllw),
        ("vpsrlw_avx", packed_shift_right_w),
        ("vpsrlw_avx2", packed_shift_right_w),
        ("vpsrlw_avx512vl", packed_shift_right_w),
        ("vpsrlw_avx512bw", packed_shift_right_w),
        ("vpsrld_avx", packed_shift_right_d),
        ("vpsrld_avx2", packed_shift_right_d),
        ("vpsrld_avx512vl", packed_shift_right_d),
        ("vpsrld_avx512f", packed_shift_right_d),
        ("vpsllq_avx", packed_shift_left_q),
        ("vpsllq_avx2", packed_shift_left_q),
        ("vpsllq_avx512vl", packed_shift_left_q),
        ("vpsllq_avx512f", packed_shift_left_q),
        ("vpslld_avx", packed_shift_left_d),
        ("vpslld_avx2", packed_shift_left_d),
        ("vpslld_avx512vl", packed_shift_left_d),
        ("vpslld_avx512f", packed_shift_left_d),
        ("vpsrldq_avx", packed_shift_right_lane_bytes),
        ("vpsrldq_avx2", packed_shift_right_lane_bytes),
        ("vpsrldq_avx512vl", packed_shift_right_lane_bytes),
        ("vpsrldq_avx512bw", packed_shift_right_lane_bytes),
        ("vpslldq_avx", packed_shift_left_lane_bytes),
        ("vpslldq_avx2", packed_shift_left_lane_bytes),
        ("vpslldq_avx512vl", packed_shift_left_lane_bytes),
        ("vpslldq_avx512bw", packed_shift_left_lane_bytes),
        ("pcmpistri", packed_compare_implicit_index),
        ("vpcmpistri_avx", packed_compare_implicit_index),
        ("pcmpistrm", packed_compare_implicit_mask),
        ("vpcmpistrm_avx", packed_compare_implicit_mask),
        ("pcmpestri", packed_compare_explicit_index),
        ("vpcmpestri_avx", packed_compare_explicit_index),
        ("pcmpestrm", packed_compare_explicit_mask),
        ("vpcmpestrm_avx", packed_compare_explicit_mask),
        ("vpsllvd_avx2", packed_shift_left_variable_d),
        ("vpsllvd_avx512vl", packed_shift_left_variable_d),
        ("vpsllvd_avx512f", packed_shift_left_variable_d),
        ("vpsrlvd_avx2", packed_shift_right_variable_d),
        ("vpsrlvd_avx512vl", packed_shift_right_variable_d),
        ("vpsrlvd_avx512f", packed_shift_right_variable_d),
        ("vpsllvq_avx2", packed_shift_left_variable_q_128),
        ("vpsllvq_avx512vl", packed_shift_left_variable_q_128),
        ("vpsllvq_avx512f", packed_shift_left_variable_q_128),
        ("vpsllvw_avx512vl", packed_shift_left_variable_w_128),
        ("vpsllvw_avx512bw", packed_shift_left_variable_w_128),
        ("vpsrlvq_avx2", packed_shift_right_variable_q_128),
        ("vpsrlvq_avx512vl", packed_shift_right_variable_q_128),
        ("vpsrlvq_avx512f", packed_shift_right_variable_q_128),
        ("vpsrlvw_avx512vl", packed_shift_right_variable_w_128),
        ("vpsrlvw_avx512bw", packed_shift_right_variable_w_128),
        ("vpsravd_avx2", packed_shift_right_arithmetic_variable_d_128),
        ("vpsravd_avx512vl", packed_shift_right_arithmetic_variable_d_128),
        ("vpsravd_avx512f", packed_shift_right_arithmetic_variable_d_128),
        ("vpsravq_avx512vl", packed_shift_right_arithmetic_variable_q_128),
        ("vpsravq_avx512f", packed_shift_right_arithmetic_variable_q_128),
        ("vpsravw_avx512vl", packed_shift_right_arithmetic_variable_w_128),
        ("vpsravw_avx512bw", packed_shift_right_arithmetic_variable_w_128),
        ("vpsrad_avx", packed_shift_right_arithmetic_d_128),
        ("vpsrad_avx2", packed_shift_right_arithmetic_d_128),
        ("vpsrad_avx512vl", packed_shift_right_arithmetic_d_128),
        ("vpsrad_avx512f", packed_shift_right_arithmetic_d_128),
        ("vpsraq_avx512vl", packed_shift_right_arithmetic_q_128),
        ("vpsraq_avx512f", packed_shift_right_arithmetic_q_128),
        ("vpsraw_avx", psraw),
        ("vpsraw_avx2", psraw),
        ("vpsraw_avx512vl", psraw),
        ("vpsraw_avx512bw", psraw),
        ("vprold_avx512vl", packed_rotate_left_d_128),
        ("vprold_avx512f", packed_rotate_left_d_128),
        ("vprolvd_avx512vl", packed_rotate_left_d_128),
        ("vprolvd_avx512f", packed_rotate_left_d_128),
        ("vprolq_avx512vl", packed_rotate_left_q_128),
        ("vprolq_avx512f", packed_rotate_left_q_128),
        ("vprolvq_avx512vl", packed_rotate_left_q_128),
        ("vprolvq_avx512f", packed_rotate_left_q_128),
        ("vprord_avx512vl", packed_rotate_right_d_128),
        ("vprord_avx512f", packed_rotate_right_d_128),
        ("vprorvd_avx512vl", packed_rotate_right_d_128),
        ("vprorvd_avx512f", packed_rotate_right_d_128),
        ("vprorq_avx512vl", packed_rotate_right_q_128),
        ("vprorq_avx512f", packed_rotate_right_q_128),
        ("vprorvq_avx512vl", packed_rotate_right_q_128),
        ("vprorvq_avx512f", packed_rotate_right_q_128),
        ("vplzcntd_avx512vl", packed_leading_zeros_d_128),
        ("vplzcntd_avx512cd", packed_leading_zeros_d_128),
        ("vplzcntq_avx512vl", packed_leading_zeros_q_128),
        ("vplzcntq_avx512cd", packed_leading_zeros_q_128),
        ("webtos_vpconflictd_128_chunk", packed_conflict_d_128_chunk),
        ("webtos_vpconflictd_256_chunk", packed_conflict_d_256_chunk),
        ("webtos_vpconflictd_512_chunk", packed_conflict_d_512_chunk),
        ("webtos_vpconflictq_128_chunk", packed_conflict_q_128_chunk),
        ("webtos_vpconflictq_256_chunk", packed_conflict_q_256_chunk),
        ("webtos_vpconflictq_512_chunk", packed_conflict_q_512_chunk),
        ("webtos_vpshiftvd_mem_128", packed_shift_variable_d_mem_128),
        ("vpabsb_avx", packed_abs_b),
        ("vpabsb_avx2", packed_abs_b),
        ("vpabsb_avx512vl", packed_abs_b),
        ("vpabsb_avx512bw", packed_abs_b),
        ("vpabsw_avx", packed_abs_w),
        ("vpabsw_avx2", packed_abs_w),
        ("vpabsw_avx512vl", packed_abs_w),
        ("vpabsw_avx512bw", packed_abs_w),
        ("vpabsd_avx", packed_abs_d),
        ("vpabsd_avx2", packed_abs_d),
        ("vpabsd_avx512vl", packed_abs_d),
        ("vpabsd_avx512f", packed_abs_d),
        ("vpabsq_avx512vl", packed_abs_q),
        ("vpabsq_avx512f", packed_abs_q),
        ("vpaddw_avx512vl", packed_add_w_128),
        ("vpaddw_avx512bw", packed_add_w_128),
        ("vpaddb_avx", packed_add_b),
        ("vpaddb_avx2", packed_add_b),
        ("vpaddb_avx512vl", packed_add_b),
        ("vpaddb_avx512bw", packed_add_b),
        ("webtos_vpaddb_128", packed_add_b),
        ("webtos_vpaddq_128", packed_add_q_128),
        ("webtos_vpsadbw_128", packed_sum_absolute_differences_b_128),
        ("webtos_vextract128_256", packed_extract_128_256),
        ("webtos_vextract128_512", packed_extract_128_512),
        ("vpsubb_avx", packed_sub_b_128),
        ("vpsubb_avx2", packed_sub_b_128),
        ("vpsubb_avx512vl", packed_sub_b_128),
        ("vpsubb_avx512bw", packed_sub_b_128),
        ("vpsubw_avx", packed_sub_w),
        ("vpsubw_avx2", packed_sub_w),
        ("vpsubw_avx512vl", packed_sub_w),
        ("vpsubw_avx512bw", packed_sub_w),
        ("vpaddusb_avx", paddusb),
        ("vpaddusb_avx2", paddusb),
        ("vpaddusb_avx512vl", paddusb),
        ("vpaddusb_avx512bw", paddusb),
        ("vpaddsb_avx", paddsb),
        ("vpaddsb_avx2", paddsb),
        ("vpaddsb_avx512vl", paddsb),
        ("vpaddsb_avx512bw", paddsb),
        ("vpaddsw_avx", paddsw),
        ("vpaddsw_avx2", paddsw),
        ("vpaddsw_avx512vl", paddsw),
        ("vpaddsw_avx512bw", paddsw),
        ("vpaddusw_avx", paddusw),
        ("vpaddusw_avx2", paddusw),
        ("vpaddusw_avx512vl", paddusw),
        ("vpaddusw_avx512bw", paddusw),
        ("vpmulhuw_avx", pmulhuw),
        ("vpmulhuw_avx2", pmulhuw),
        ("vpmulhuw_avx512vl", pmulhuw),
        ("vpmulhuw_avx512bw", pmulhuw),
        ("vpmullw_avx", packed_mul_low_w_128),
        ("vpmullw_avx2", packed_mul_low_w_128),
        ("vpmullw_avx512vl", packed_mul_low_w_128),
        ("vpmullw_avx512bw", packed_mul_low_w_128),
        ("vpunpcklwd_avx", packed_unpack_low_w_128),
        ("vpunpcklwd_avx2", packed_unpack_low_w_128),
        ("vpunpcklwd_avx512vl", packed_unpack_low_w_128),
        ("vpunpcklwd_avx512bw", packed_unpack_low_w_128),
        ("vpunpckhwd_avx", packed_unpack_high_w_128),
        ("vpunpckhwd_avx2", packed_unpack_high_w_128),
        ("vpunpckhwd_avx512vl", packed_unpack_high_w_128),
        ("vpunpckhwd_avx512bw", packed_unpack_high_w_128),
        ("vpunpcklqdq_avx", punpcklqdq),
        ("vpunpcklqdq_avx2", punpcklqdq),
        ("vpunpcklqdq_avx512vl", punpcklqdq),
        ("vpunpcklqdq_avx512f", punpcklqdq),
        ("vpunpckhqdq_avx", packed_unpack_high_q_128),
        ("vpunpckhqdq_avx2", packed_unpack_high_q_128),
        ("vpunpckhqdq_avx512vl", packed_unpack_high_q_128),
        ("vpunpckhqdq_avx512f", packed_unpack_high_q_128),
        ("vpshufd_avx", packed_shuffle_d_128),
        ("vpshufd_avx2", packed_shuffle_d_128),
        ("vpshufd_avx512vl", packed_shuffle_d_128),
        ("vpshufd_avx512f", packed_shuffle_d_128),
        ("vpsubusb_avx", psubusb),
        ("vpsubusb_avx2", psubusb),
        ("vpsubusb_avx512vl", psubusb),
        ("vpsubusb_avx512bw", psubusb),
        ("vpsubusw_avx", psubusw),
        ("vpsubusw_avx2", psubusw),
        ("vpsubusw_avx512vl", psubusw),
        ("vpsubusw_avx512bw", psubusw),
        ("vpmovzxbw_avx", pmovzxbw_single),
        ("vpmovzxbw_avx2", pmovzxbw_single),
        ("vpmovzxbw_avx512vl", pmovzxbw_single),
        ("vpmovzxbw_avx512bw", pmovzxbw_single),
        ("vpmovwb_avx512vl", packed_narrow_w_to_b_128),
        ("vpmovwb_avx512bw", packed_narrow_w_to_b_128),
        ("vpmovdb_avx512vl", narrow_dword_to_byte),
        ("vpmovdb_avx512f", narrow_dword_to_byte),
        ("vpmovsdb_avx512vl", narrow_signed_dword_to_byte),
        ("vpmovsdb_avx512f", narrow_signed_dword_to_byte),
        ("vpmovusdb_avx512vl", narrow_unsigned_dword_to_byte),
        ("vpmovusdb_avx512f", narrow_unsigned_dword_to_byte),
        ("vpmovdw_avx512vl", narrow_dword_to_word),
        ("vpmovdw_avx512f", narrow_dword_to_word),
        ("vpmovsdw_avx512vl", narrow_signed_dword_to_word),
        ("vpmovsdw_avx512f", narrow_signed_dword_to_word),
        ("vpmovusdw_avx512vl", narrow_unsigned_dword_to_word),
        ("vpmovusdw_avx512f", narrow_unsigned_dword_to_word),
        ("vpmovqb_avx512vl", narrow_qword_to_byte),
        ("vpmovqb_avx512f", narrow_qword_to_byte),
        ("vpmovsqb_avx512vl", narrow_signed_qword_to_byte),
        ("vpmovsqb_avx512f", narrow_signed_qword_to_byte),
        ("vpmovusqb_avx512vl", narrow_unsigned_qword_to_byte),
        ("vpmovusqb_avx512f", narrow_unsigned_qword_to_byte),
        ("vpmovqw_avx512vl", narrow_qword_to_word),
        ("vpmovqw_avx512f", narrow_qword_to_word),
        ("vpmovsqw_avx512vl", narrow_signed_qword_to_word),
        ("vpmovsqw_avx512f", narrow_signed_qword_to_word),
        ("vpmovusqw_avx512vl", narrow_unsigned_qword_to_word),
        ("vpmovusqw_avx512f", narrow_unsigned_qword_to_word),
        ("vpmovqd_avx512vl", narrow_qword_to_dword),
        ("vpmovqd_avx512f", narrow_qword_to_dword),
        ("vpmovsqd_avx512vl", narrow_signed_qword_to_dword),
        ("vpmovsqd_avx512f", narrow_signed_qword_to_dword),
        ("vpmovusqd_avx512vl", narrow_unsigned_qword_to_dword),
        ("vpmovusqd_avx512f", narrow_unsigned_qword_to_dword),
        ("vpmovswb_avx512vl", narrow_signed_word_to_byte),
        ("vpmovswb_avx512bw", narrow_signed_word_to_byte),
        ("vpmovuswb_avx512vl", narrow_unsigned_word_to_byte),
        ("vpmovuswb_avx512bw", narrow_unsigned_word_to_byte),
        ("vpmovzxwd_avx", pmovzxwd_single),
        ("vpmovzxwd_avx2", pmovzxwd_single),
        ("vpmovzxwd_avx512vl", pmovzxwd_single),
        ("vpmovzxwd_avx512f", pmovzxwd_single),
        ("vpmovzxbd_avx", pmovzxbd_single),
        ("vpmovzxbd_avx2", pmovzxbd_single),
        ("vpmovzxbd_avx512vl", pmovzxbd_single),
        ("vpmovzxbd_avx512f", pmovzxbd_single),
        ("vpmovzxbq_avx", packed_move_zxbq_128_indexed),
        ("vpmovzxbq_avx2", packed_move_zxbq_128_indexed),
        ("vpmovzxbq_avx512vl", packed_move_zxbq_128_indexed),
        ("vpmovzxbq_avx512f", packed_move_zxbq_128_indexed),
        ("vpmovzxwq_avx", packed_move_zxwq_128_indexed),
        ("vpmovzxwq_avx2", packed_move_zxwq_128_indexed),
        ("vpmovzxwq_avx512vl", packed_move_zxwq_128_indexed),
        ("vpmovzxwq_avx512f", packed_move_zxwq_128_indexed),
        ("webtos_vpmovzxbd_mem_128_chunk", packed_move_zxbd_mem_128_chunk),
        ("vpmovzxdq_avx", pmovzxdq_single),
        ("vpmovzxdq_avx2", pmovzxdq_single),
        ("vpmovzxdq_avx512vl", pmovzxdq_single),
        ("vpmovzxdq_avx512f", pmovzxdq_single),
        ("vpmaxud_avx", packed_max_unsigned_d_128),
        ("vpmaxud_avx2", packed_max_unsigned_d_128),
        ("vpmaxud_avx512vl", packed_max_unsigned_d_128),
        ("vpmaxud_avx512f", packed_max_unsigned_d_128),
        ("vpmaxsb_avx", packed_max_signed_b_128),
        ("vpmaxsb_avx2", packed_max_signed_b_128),
        ("vpmaxsb_avx512vl", packed_max_signed_b_128),
        ("vpmaxsb_avx512bw", packed_max_signed_b_128),
        ("vpmaxsw_avx", packed_max_signed_w_128),
        ("vpmaxsw_avx2", packed_max_signed_w_128),
        ("vpmaxsw_avx512vl", packed_max_signed_w_128),
        ("vpmaxsw_avx512bw", packed_max_signed_w_128),
        ("vpmaxsd_avx", packed_max_signed_d_128),
        ("vpmaxsd_avx2", packed_max_signed_d_128),
        ("vpmaxsd_avx512vl", packed_max_signed_d_128),
        ("vpmaxsd_avx512f", packed_max_signed_d_128),
        ("vpmaxsq_avx512vl", packed_max_signed_q_128),
        ("vpmaxsq_avx512f", packed_max_signed_q_128),
        ("vpmaxub_avx", packed_max_unsigned_b_128),
        ("vpmaxub_avx2", packed_max_unsigned_b_128),
        ("vpmaxub_avx512vl", packed_max_unsigned_b_128),
        ("vpmaxub_avx512bw", packed_max_unsigned_b_128),
        ("vpmaxuw_avx", packed_max_unsigned_w_128),
        ("vpmaxuw_avx2", packed_max_unsigned_w_128),
        ("vpmaxuw_avx512vl", packed_max_unsigned_w_128),
        ("vpmaxuw_avx512bw", packed_max_unsigned_w_128),
        ("vpmaxuq_avx512vl", packed_max_unsigned_q_128),
        ("vpmaxuq_avx512f", packed_max_unsigned_q_128),
        ("vpminub_avx", packed_min_unsigned_b_128),
        ("vpminub_avx2", packed_min_unsigned_b_128),
        ("vpminub_avx512vl", packed_min_unsigned_b_128),
        ("vpminub_avx512bw", packed_min_unsigned_b_128),
        ("vpavgb_avx", packed_average_unsigned_b_128),
        ("vpavgb_avx2", packed_average_unsigned_b_128),
        ("vpavgb_avx512vl", packed_average_unsigned_b_128),
        ("vpavgb_avx512bw", packed_average_unsigned_b_128),
        ("vpavgw_avx", packed_average_unsigned_w_128),
        ("vpavgw_avx2", packed_average_unsigned_w_128),
        ("vpavgw_avx512vl", packed_average_unsigned_w_128),
        ("vpavgw_avx512bw", packed_average_unsigned_w_128),
        ("vpcmpgtb_avx", packed_compare_greater_b_128),
        ("vpcmpgtb_avx2", packed_compare_greater_b_128),
        ("vpcmpgtd_avx", packed_compare_greater_d_128),
        ("vpcmpgtd_avx2", packed_compare_greater_d_128),
        ("vpcmpgtd_avx512vl", packed_compare_d_signed),
        ("vpcmpgtd_avx512f", packed_compare_d_signed),
        ("vpcmpgtb_avx512vl", packed_compare_b_signed),
        ("vpcmpgtb_avx512bw", packed_compare_b_signed),
        ("vpcmpeqb_avx", packed_compare_equal_b_128),
        ("vpcmpeqb_avx2", packed_compare_equal_b_128),
        ("vpcmpeqd_avx", packed_compare_equal_d_128),
        ("vpcmpeqd_avx2", packed_compare_equal_d_128),
        ("vpackusdw_avx", packusdw),
        ("vpackusdw_avx2", packusdw),
        ("vpackusdw_avx512vl", packusdw),
        ("vpackusdw_avx512bw", packusdw),
        ("vpmovsxbw_avx", pmovsxbw_single),
        ("vpmovsxbw_avx2", pmovsxbw_single),
        ("vpmovsxbw_avx512vl", pmovsxbw_single),
        ("vpmovsxbw_avx512bw", pmovsxbw_single),
        ("vpmovsxbd_avx", packed_move_sxbd_128_indexed),
        ("vpmovsxbd_avx2", packed_move_sxbd_128_indexed),
        ("vpmovsxbd_avx512vl", packed_move_sxbd_128_indexed),
        ("vpmovsxbd_avx512f", packed_move_sxbd_128_indexed),
        ("vpmovsxbq_avx", packed_move_sxbq_128_indexed),
        ("vpmovsxbq_avx2", packed_move_sxbq_128_indexed),
        ("vpmovsxbq_avx512vl", packed_move_sxbq_128_indexed),
        ("vpmovsxbq_avx512f", packed_move_sxbq_128_indexed),
        ("vpmovsxwq_avx", packed_move_sxwq_128_indexed),
        ("vpmovsxwq_avx2", packed_move_sxwq_128_indexed),
        ("vpmovsxwq_avx512vl", packed_move_sxwq_128_indexed),
        ("vpmovsxwq_avx512f", packed_move_sxwq_128_indexed),
        ("vpmovsxwd_avx", pmovsxwd_single),
        ("vpmovsxwd_avx2", pmovsxwd_single),
        ("vpmovsxwd_avx512vl", pmovsxwd_single),
        ("vpmovsxwd_avx512f", pmovsxwd_single),
        ("vpmovsxdq_avx", pmovsxdq_single),
        ("vpmovsxdq_avx2", pmovsxdq_single),
        ("vpmovsxdq_avx512vl", pmovsxdq_single),
        ("vpmovsxdq_avx512f", pmovsxdq_single),
        ("vpackuswb_avx", packuswb),
        ("vpackuswb_avx2", packuswb),
        ("vpackuswb_avx512vl", packuswb),
        ("vpackuswb_avx512bw", packuswb),
        ("vpsubsb_avx", psubsb),
        ("vpsubsb_avx2", psubsb),
        ("vpsubsb_avx512vl", psubsb),
        ("vpsubsb_avx512bw", psubsb),
        ("vpsubsw_avx", psubsw),
        ("vpsubsw_avx2", psubsw),
        ("vpsubsw_avx512vl", psubsw),
        ("vpsubsw_avx512bw", psubsw),
        ("vpminuw_avx", packed_min_unsigned_w_128),
        ("vpminuw_avx2", packed_min_unsigned_w_128),
        ("vpminuw_avx512vl", packed_min_unsigned_w_128),
        ("vpminuw_avx512bw", packed_min_unsigned_w_128),
        ("vpminsb_avx", packed_min_signed_b_128),
        ("vpminsb_avx2", packed_min_signed_b_128),
        ("vpminsb_avx512vl", packed_min_signed_b_128),
        ("vpminsb_avx512bw", packed_min_signed_b_128),
        ("vpminsw_avx", packed_min_signed_w_128),
        ("vpminsw_avx2", packed_min_signed_w_128),
        ("vpminsw_avx512vl", packed_min_signed_w_128),
        ("vpminsw_avx512bw", packed_min_signed_w_128),
        ("vpminsd_avx", packed_min_signed_d_128),
        ("vpminsd_avx2", packed_min_signed_d_128),
        ("vpminsd_avx512vl", packed_min_signed_d_128),
        ("vpminsd_avx512f", packed_min_signed_d_128),
        ("vpminsq_avx512vl", packed_min_signed_q_128),
        ("vpminsq_avx512f", packed_min_signed_q_128),
        ("vpminud_avx", packed_min_unsigned_d_128),
        ("vpminud_avx2", packed_min_unsigned_d_128),
        ("vpminud_avx512vl", packed_min_unsigned_d_128),
        ("vpminud_avx512f", packed_min_unsigned_d_128),
        ("vpminuq_avx512vl", packed_min_unsigned_q_128),
        ("vpminuq_avx512f", packed_min_unsigned_q_128),
        ("vpackssdw_avx", packssdw),
        ("vpackssdw_avx2", packssdw),
        ("vpackssdw_avx512vl", packssdw),
        ("vpackssdw_avx512bw", packssdw),
        ("vpacksswb_avx", packsswb),
        ("vpacksswb_avx2", packsswb),
        ("vpacksswb_avx512vl", packsswb),
        ("vpacksswb_avx512bw", packsswb),
        ("vpmulld_avx", pmulld),
        ("vpmulld_avx2", pmulld),
        ("vpmulld_avx512vl", pmulld),
        ("vpmulld_avx512f", pmulld),
        ("vpmulhw_avx", pmulhw),
        ("vpmulhw_avx2", pmulhw),
        ("vpmulhw_avx512vl", pmulhw),
        ("vpmulhw_avx512bw", pmulhw),
        ("vpmulhuw_avx", pmulhuw),
        ("vpmulhuw_avx2", pmulhuw),
        ("vpmulhuw_avx512vl", pmulhuw),
        ("vpmulhuw_avx512bw", pmulhuw),
        ("vpmuldq_avx", pmuldq),
        ("vpmuldq_avx2", pmuldq),
        ("vpmuldq_avx512vl", pmuldq),
        ("vpmuldq_avx512f", pmuldq),
        ("vpmuludq_avx", packed_mul_unsigned_dq_128),
        ("vpmuludq_avx2", packed_mul_unsigned_dq_128),
        ("vpmuludq_avx512vl", packed_mul_unsigned_dq_128),
        ("vpmuludq_avx512f", packed_mul_unsigned_dq_128),
        ("vpmulhrsw_avx", pmulhrsw),
        ("vpmulhrsw_avx2", pmulhrsw),
        ("vpmulhrsw_avx512vl", pmulhrsw),
        ("vpmulhrsw_avx512bw", pmulhrsw),
        ("vpsignb_avx", psignb),
        ("vpsignb_avx2", psignb),
        ("vpsignw_avx", psignw),
        ("vpsignw_avx2", psignw),
        ("vpsignd_avx", psignd),
        ("vpsignd_avx2", psignd),
        ("vpandn_avx", packed_and_not_128),
        ("vpandn_avx2", packed_and_not_128),
        ("vpcmpgtw_avx", packed_compare_greater_w_128),
        ("vpcmpgtw_avx2", packed_compare_greater_w_128),
        ("vpcmpgtw_avx512vl", packed_compare_w_signed),
        ("vpcmpgtw_avx512bw", packed_compare_w_signed),
        ("vpcmpgtq_avx", packed_compare_greater_q_128),
        ("vpcmpgtq_avx2", packed_compare_greater_q_128),
        ("vpcmpgtq_avx512vl", packed_compare_q_signed),
        ("vpcmpgtq_avx512f", packed_compare_q_signed),
        ("vpshufhw_avx", packed_shuffle_high_w_128),
        ("vpshufhw_avx2", packed_shuffle_high_w_128),
        ("vpshufhw_avx512vl", packed_shuffle_high_w_128),
        ("vpshufhw_avx512bw", packed_shuffle_high_w_128),
        ("vpshuflw_avx", packed_shuffle_low_w_128),
        ("vpshuflw_avx2", packed_shuffle_low_w_128),
        ("vpshuflw_avx512vl", packed_shuffle_low_w_128),
        ("vpshuflw_avx512bw", packed_shuffle_low_w_128),
        ("vpunpckhbw_avx", packed_unpack_high_b_128),
        ("vpunpckhbw_avx2", packed_unpack_high_b_128),
        ("vpunpckhbw_avx512vl", packed_unpack_high_b_128),
        ("vpunpckhbw_avx512bw", packed_unpack_high_b_128),
        ("vpunpcklbw_avx", packed_unpack_low_b_128),
        ("vpunpcklbw_avx2", packed_unpack_low_b_128),
        ("vpunpcklbw_avx512vl", packed_unpack_low_b_128),
        ("vpunpcklbw_avx512bw", packed_unpack_low_b_128),
        ("vpunpckhdq_avx", packed_unpack_high_d_128),
        ("vpunpckhdq_avx2", packed_unpack_high_d_128),
        ("vpunpckhdq_avx512vl", packed_unpack_high_d_128),
        ("vpunpckhdq_avx512f", packed_unpack_high_d_128),
        ("vpunpckldq_avx", packed_unpack_low_d_128),
        ("vpunpckldq_avx2", packed_unpack_low_d_128),
        ("vpunpckldq_avx512vl", packed_unpack_low_d_128),
        ("vpunpckldq_avx512f", packed_unpack_low_d_128),
        ("vphaddw_avx", phaddw),
        ("vphaddw_avx2", phaddw),
        ("vphaddd_avx", phaddd),
        ("vphaddd_avx2", phaddd),
        ("vphaddsw_avx", phaddsw),
        ("vphaddsw_avx2", phaddsw),
        ("vphsubw_avx", phsubw),
        ("vphsubw_avx2", phsubw),
        ("vphsubd_avx", phsubd),
        ("vphsubd_avx2", phsubd),
        ("vphsubsw_avx", phsubsw),
        ("vphsubsw_avx2", phsubsw),
        ("vphminposuw_avx", phminposuw),
        ("vpblendd_avx2", packed_blend_d_128),
        ("vpinsrb_avx", packed_insert_b_128),
        ("vpinsrb_avx512bw", packed_insert_b_128),
        ("vpinsrw_avx512bw", packed_insert_w_128),
        ("vpcmpeqw_avx", packed_compare_equal_w_128),
        ("vpcmpeqw_avx2", packed_compare_equal_w_128),
        ("vpsrlq_avx", packed_shift_right_q_128),
        ("vpsrlq_avx2", packed_shift_right_q_128),
        ("vpsrlq_avx512vl", packed_shift_right_q_128),
        ("vpsrlq_avx512f", packed_shift_right_q_128),
        ("vpblendvb_avx", pblendvb),
        ("vpblendvb_avx2", pblendvb),
        ("vpblendw_avx", pblendw),
        ("vpblendw_avx2", pblendw),
        ("vpinsrw_avx", packed_insert_w_128),
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
        ("vpsubd_avx", packed_sub_d),
        ("vpsubd_avx2", packed_sub_d),
        ("vpsubd_avx512vl", packed_sub_d),
        ("vpsubd_avx512f", packed_sub_d),
        ("vpaddd_avx512vl", packed_add_d),
        ("vpaddd_avx512f", packed_add_d),
        ("vpcmpb_avx512vl", packed_compare_b_signed),
        ("vpcmpb_avx512bw", packed_compare_b_signed),
        ("vpcmpub_avx512vl", packed_compare_b_unsigned),
        ("vpcmpub_avx512bw", packed_compare_b_unsigned),
        ("vpcmpw_avx512vl", packed_compare_w_signed),
        ("vpcmpw_avx512bw", packed_compare_w_signed),
        ("vpcmpuw_avx512vl", packed_compare_w_unsigned),
        ("vpcmpuw_avx512bw", packed_compare_w_unsigned),
        ("vpcmpd_avx512vl", packed_compare_d_signed),
        ("vpcmpd_avx512f", packed_compare_d_signed),
        ("vpcmpud_avx512vl", packed_compare_d_unsigned),
        ("vpcmpud_avx512f", packed_compare_d_unsigned),
        ("vpcmpq_avx512vl", packed_compare_q_signed),
        ("vpcmpq_avx512f", packed_compare_q_signed),
        ("vpcmpuq_avx512vl", packed_compare_q_unsigned),
        ("vpcmpuq_avx512f", packed_compare_q_unsigned),
        ("vpcmpeqb_avx512vl", packed_compare_b_unsigned),
        ("vpcmpeqb_avx512bw", packed_compare_b_unsigned),
        ("vpcmpeqw_avx512vl", packed_compare_w_unsigned),
        ("vpcmpeqw_avx512bw", packed_compare_w_unsigned),
        ("vpcmpeqd_avx512vl", packed_compare_d_unsigned),
        ("vpcmpeqd_avx512f", packed_compare_d_unsigned),
        ("vpcmpeqq_avx512vl", packed_compare_q_unsigned),
        ("vpcmpeqq_avx512f", packed_compare_q_unsigned),
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
        ("webtos_vpermb_128_chunk", packed_permute_b_128_chunk),
        ("webtos_vpermb_256_chunk", packed_permute_b_256_chunk),
        ("webtos_vpermb_512_chunk", packed_permute_b_512_chunk),
        ("webtos_vpermb_mem_128_chunk", packed_permute_b_mem_128_chunk),
        ("webtos_vpermb_mem_256_chunk", packed_permute_b_mem_256_chunk),
        ("webtos_vpermb_mem_512_chunk", packed_permute_b_mem_512_chunk),
        ("webtos_vperm2b_128_chunk", packed_permute2_b_128_chunk),
        ("webtos_vperm2b_256_chunk", packed_permute2_b_256_chunk),
        ("webtos_vperm2b_512_chunk", packed_permute2_b_512_chunk),
        ("webtos_vperm2b_mem_128_chunk", packed_permute2_b_mem_128_chunk),
        ("webtos_vperm2b_mem_256_chunk", packed_permute2_b_mem_256_chunk),
        ("webtos_vperm2b_mem_512_chunk", packed_permute2_b_mem_512_chunk),
        ("webtos_vperm2d_128_chunk", packed_permute2_d_128_chunk),
        ("webtos_vperm2d_256_chunk", packed_permute2_d_256_chunk),
        ("webtos_vperm2d_512_chunk", packed_permute2_d_512_chunk),
        ("webtos_vperm2q_128_chunk", packed_permute2_q_128_chunk),
        ("webtos_vperm2q_256_chunk", packed_permute2_q_256_chunk),
        ("webtos_vperm2q_512_chunk", packed_permute2_q_512_chunk),
        ("webtos_vperm2w_128_chunk", packed_permute2_w_128_chunk),
        ("webtos_vperm2w_256_chunk", packed_permute2_w_256_chunk),
        ("webtos_vperm2w_512_chunk", packed_permute2_w_512_chunk),
        ("webtos_vpalignr_128_chunk", packed_align_right_128_chunk),
        ("webtos_valignd_128_chunk", packed_align_d_128_chunk),
        ("webtos_valignd_256_chunk", packed_align_d_256_chunk),
        ("webtos_valignd_512_chunk", packed_align_d_512_chunk),
        ("webtos_valignq_128_chunk", packed_align_q_128_chunk),
        ("webtos_valignq_256_chunk", packed_align_q_256_chunk),
        ("webtos_valignq_512_chunk", packed_align_q_512_chunk),
        ("webtos_vshuffle128_256_chunk", packed_shuffle_128_256_chunk),
        ("webtos_vshuffle128_512_chunk", packed_shuffle_128_512_chunk),
        ("webtos_vinsert128_256_chunk", packed_insert_128_256_chunk),
        ("webtos_vinsert128_512_chunk", packed_insert_128_512_chunk),
        ("webtos_vinsert256_512_chunk", packed_insert_256_512_chunk),
        ("vpshldw_avx512_vbmi2", packed_shift_left_double_w),
        ("vpshldd_avx512_vbmi2", packed_shift_left_double_d),
        ("vpshldq_avx512_vbmi2", packed_shift_left_double_q),
        ("vpshrdw_avx512_vbmi2", packed_shift_right_double_w),
        ("vpshrdd_avx512_vbmi2", packed_shift_right_double_d),
        ("vpshrdq_avx512_vbmi2", packed_shift_right_double_q),
        ("webtos_vpshld_128", packed_shift_left_double_128),
        ("webtos_vpshrd_128", packed_shift_right_double_128),
        ("webtos_vpshldv_128", packed_shift_left_double_variable_128),
        ("webtos_vpshrdv_128", packed_shift_right_double_variable_128),
        ("webtos_apply_byte_mask_128", apply_byte_mask_128),
        ("webtos_apply_dword_mask_128", apply_dword_mask_128),
        ("webtos_vpmaddubsw_128", packed_maddubs_128),
        ("webtos_vpmaddwd_128", packed_maddwd_128),
        ("vpmaddubsw_avx", packed_maddubs_128),
        ("vpmaddwd_avx", packed_maddwd_128),
        ("webtos_vpmaddubsw_avx2_128", packed_maddubs_128),
        ("webtos_vpmaddwd_avx2_128", packed_maddwd_128),
        ("vdbpsadbw_avx512vl", packed_dbsad_bw),
        ("vdbpsadbw_avx512bw", packed_dbsad_bw),
        ("webtos_vdbpsadbw_128", packed_dbsad_bw),
        ("webtos_vpmovm2b_128", packed_mask_to_bytes_128),
        ("webtos_vpmovb2m_128", packed_bytes_to_mask_128),
        ("webtos_vpmovm2w_128", packed_mask_to_words_128),
        ("webtos_vpmovw2m_128", packed_words_to_mask_128),
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
        ("webtos_vmask_load_128", vector_sign_masked_load_128),
        ("webtos_vmask_store_128", vector_sign_masked_store_128),
        ("webtos_vmask_store_256", vector_sign_masked_store_256),
        ("webtos_masked_store_128", masked_store_128),
        ("webtos_masked_store_256", masked_store_256),
        ("webtos_masked_store_512", masked_store_512),
        ("webtos_aligned_masked_load_128", aligned_masked_load_128),
        ("webtos_aligned_masked_store_128", aligned_masked_store_128),
        ("webtos_aligned_masked_store_256", aligned_masked_store_256),
        ("webtos_aligned_masked_store_512", aligned_masked_store_512),
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

    /// EVEX fused multiply-add operations. They share one decoder-driven,
    /// strictly fused implementation; the frontend splits packed YMM/ZMM
    /// forms into independently masked 128-bit chunks.
    pub const FMA_HELPERS: &[(&str, PcodeOpHelper)] = &[
        ("vfmadd132pd_avx512f", packed_fma),
        ("vfmadd132pd_avx512vl", packed_fma),
        ("vfmadd132ps_avx512f", packed_fma),
        ("vfmadd132ps_avx512vl", packed_fma),
        ("vfmadd132sd_avx512f", packed_fma),
        ("vfmadd132ss_avx512f", packed_fma),
        ("vfmadd213pd_avx512f", packed_fma),
        ("vfmadd213pd_avx512vl", packed_fma),
        ("vfmadd213ps_avx512f", packed_fma),
        ("vfmadd213ps_avx512vl", packed_fma),
        ("vfmadd213sd_avx512f", packed_fma),
        ("vfmadd213ss_avx512f", packed_fma),
        ("vfmadd231pd_avx512f", packed_fma),
        ("vfmadd231pd_avx512vl", packed_fma),
        ("vfmadd231ps_avx512f", packed_fma),
        ("vfmadd231ps_avx512vl", packed_fma),
        ("vfmadd231sd_avx512f", packed_fma),
        ("vfmadd231ss_avx512f", packed_fma),
        ("vfmaddsub132pd_avx512f", packed_fma),
        ("vfmaddsub132pd_avx512vl", packed_fma),
        ("vfmaddsub132ps_avx512f", packed_fma),
        ("vfmaddsub132ps_avx512vl", packed_fma),
        ("vfmaddsub213pd_avx512f", packed_fma),
        ("vfmaddsub213pd_avx512vl", packed_fma),
        ("vfmaddsub213ps_avx512f", packed_fma),
        ("vfmaddsub213ps_avx512vl", packed_fma),
        ("vfmaddsub231pd_avx512f", packed_fma),
        ("vfmaddsub231pd_avx512vl", packed_fma),
        ("vfmaddsub231ps_avx512f", packed_fma),
        ("vfmaddsub231ps_avx512vl", packed_fma),
        ("vfmsub132pd_avx512f", packed_fma),
        ("vfmsub132pd_avx512vl", packed_fma),
        ("vfmsub132ps_avx512f", packed_fma),
        ("vfmsub132ps_avx512vl", packed_fma),
        ("vfmsub132sd_avx512f", packed_fma),
        ("vfmsub132ss_avx512f", packed_fma),
        ("vfmsub213pd_avx512f", packed_fma),
        ("vfmsub213pd_avx512vl", packed_fma),
        ("vfmsub213ps_avx512f", packed_fma),
        ("vfmsub213ps_avx512vl", packed_fma),
        ("vfmsub213sd_avx512f", packed_fma),
        ("vfmsub213ss_avx512f", packed_fma),
        ("vfmsub231pd_avx512f", packed_fma),
        ("vfmsub231pd_avx512vl", packed_fma),
        ("vfmsub231ps_avx512f", packed_fma),
        ("vfmsub231ps_avx512vl", packed_fma),
        ("vfmsub231sd_avx512f", packed_fma),
        ("vfmsub231ss_avx512f", packed_fma),
        ("vfmsubadd132pd_avx512f", packed_fma),
        ("vfmsubadd132pd_avx512vl", packed_fma),
        ("vfmsubadd132ps_avx512f", packed_fma),
        ("vfmsubadd132ps_avx512vl", packed_fma),
        ("vfmsubadd213pd_avx512f", packed_fma),
        ("vfmsubadd213pd_avx512vl", packed_fma),
        ("vfmsubadd213ps_avx512f", packed_fma),
        ("vfmsubadd213ps_avx512vl", packed_fma),
        ("vfmsubadd231pd_avx512f", packed_fma),
        ("vfmsubadd231pd_avx512vl", packed_fma),
        ("vfmsubadd231ps_avx512f", packed_fma),
        ("vfmsubadd231ps_avx512vl", packed_fma),
        ("vfnmadd132pd_avx512f", packed_fma),
        ("vfnmadd132pd_avx512vl", packed_fma),
        ("vfnmadd132ps_avx512vl", packed_fma),
        ("vfnmadd132sd_avx512f", packed_fma),
        ("vfnmadd132ss_avx512f", packed_fma),
        ("vfnmadd213pd_avx512f", packed_fma),
        ("vfnmadd213pd_avx512vl", packed_fma),
        ("vfnmadd213ps_avx512f", packed_fma),
        ("vfnmadd213ps_avx512vl", packed_fma),
        ("vfnmadd213sd_avx512f", packed_fma),
        ("vfnmadd213ss_avx512f", packed_fma),
        ("vfnmadd231pd_avx512f", packed_fma),
        ("vfnmadd231pd_avx512vl", packed_fma),
        ("vfnmadd231ps_avx512f", packed_fma),
        ("vfnmadd231ps_avx512vl", packed_fma),
        ("vfnmadd231sd_avx512f", packed_fma),
        ("vfnmadd231ss_avx512f", packed_fma),
        ("vfnmsub132pd_avx512f", packed_fma),
        ("vfnmsub132pd_avx512vl", packed_fma),
        ("vfnmsub132ps_avx512f", packed_fma),
        ("vfnmsub132ps_avx512vl", packed_fma),
        ("vfnmsub132sd_avx512f", packed_fma),
        ("vfnmsub132ss_avx512f", packed_fma),
        ("vfnmsub213pd_avx512f", packed_fma),
        ("vfnmsub213pd_avx512vl", packed_fma),
        ("vfnmsub213ps_avx512f", packed_fma),
        ("vfnmsub213ps_avx512vl", packed_fma),
        ("vfnmsub213sd_avx512f", packed_fma),
        ("vfnmsub213ss_avx512f", packed_fma),
        ("vfnmsub231pd_avx512f", packed_fma),
        ("vfnmsub231pd_avx512vl", packed_fma),
        ("vfnmsub231ps_avx512f", packed_fma),
        ("vfnmsub231ps_avx512vl", packed_fma),
        ("vfnmsub231sd_avx512f", packed_fma),
        ("vfnmsub231ss_avx512f", packed_fma),
    ];

    /// Narrowing operations need proportional source/result splitting when a
    /// 256- or 512-bit source crosses the runtime's u128 helper boundary.
    pub const NARROW_USER_OPS: &[(&str, u8)] = &[
        ("vcvtpd2dq_avx512vl", 2),
        ("vcvtpd2dq_avx512f", 2),
        ("vcvtpd2ps_avx512vl", 2),
        ("vcvtpd2ps_avx512f", 2),
        ("vcvtpd2udq_avx512vl", 2),
        ("vcvtpd2udq_avx512f", 2),
        ("vcvtps2ph_avx512vl", 2),
        ("vcvtps2ph_avx512f", 2),
        ("vcvttpd2dq_avx512vl", 2),
        ("vcvttpd2dq_avx512f", 2),
        ("vcvttpd2udq_avx512vl", 2),
        ("vcvttpd2udq_avx512f", 2),
        ("vpmovdb_avx512vl", 4),
        ("vpmovdb_avx512f", 4),
        ("vpmovsdb_avx512vl", 4),
        ("vpmovsdb_avx512f", 4),
        ("vpmovusdb_avx512vl", 4),
        ("vpmovusdb_avx512f", 4),
        ("vpmovdw_avx512vl", 2),
        ("vpmovdw_avx512f", 2),
        ("vpmovsdw_avx512vl", 2),
        ("vpmovsdw_avx512f", 2),
        ("vpmovusdw_avx512vl", 2),
        ("vpmovusdw_avx512f", 2),
        ("vpmovqb_avx512vl", 8),
        ("vpmovqb_avx512f", 8),
        ("vpmovsqb_avx512vl", 8),
        ("vpmovsqb_avx512f", 8),
        ("vpmovusqb_avx512vl", 8),
        ("vpmovusqb_avx512f", 8),
        ("vpmovqw_avx512vl", 4),
        ("vpmovqw_avx512f", 4),
        ("vpmovsqw_avx512vl", 4),
        ("vpmovsqw_avx512f", 4),
        ("vpmovusqw_avx512vl", 4),
        ("vpmovusqw_avx512f", 4),
        ("vpmovqd_avx512vl", 2),
        ("vpmovqd_avx512f", 2),
        ("vpmovsqd_avx512vl", 2),
        ("vpmovsqd_avx512f", 2),
        ("vpmovusqd_avx512vl", 2),
        ("vpmovusqd_avx512f", 2),
        ("vpmovswb_avx512vl", 2),
        ("vpmovswb_avx512bw", 2),
        ("vpmovuswb_avx512vl", 2),
        ("vpmovuswb_avx512bw", 2),
    ];

    pub const WIDEN_USER_OPS: &[(&str, u8)] = &[
        ("vcvtdq2pd_avx512vl", 2),
        ("vcvtdq2pd_avx512f", 2),
        ("vcvtph2ps_avx512vl", 2),
        ("vcvtph2ps_avx512f", 2),
        ("vcvtps2pd_avx512vl", 2),
        ("vcvtps2pd_avx512f", 2),
        ("vcvtudq2pd_avx512vl", 2),
        ("vcvtudq2pd_avx512f", 2),
    ];

    pub const SAME_WIDTH_CONVERSION_USER_OPS: &[&str] = &[
        "vcvtdq2ps_avx512vl",
        "vcvtdq2ps_avx512f",
        "vcvtps2dq_avx512vl",
        "vcvtps2dq_avx512f",
        "vcvtps2udq_avx512vl",
        "vcvtps2udq_avx512f",
        "vcvttps2dq_avx512vl",
        "vcvttps2dq_avx512f",
        "vcvttps2udq_avx512vl",
        "vcvttps2udq_avx512f",
        "vcvtudq2ps_avx512vl",
        "vcvtudq2ps_avx512f",
    ];

    /// Ice Lake floating-point operations whose packed forms are independent
    /// in every 128-bit chunk. Indexed splitting preserves the architectural
    /// opmask lane number across YMM/ZMM chunks.
    pub const EVEX_SPECIAL_FLOAT_USER_OPS: &[&str] = &[
        "vfixupimmpd_avx512vl",
        "vfixupimmpd_avx512f",
        "vfixupimmps_avx512vl",
        "vfixupimmps_avx512f",
        "vgetexppd_avx512vl",
        "vgetexppd_avx512f",
        "vgetexpps_avx512vl",
        "vgetexpps_avx512f",
        "vgetmantpd_avx512vl",
        "vgetmantpd_avx512f",
        "vgetmantps_avx512vl",
        "vgetmantps_avx512f",
        "vrcp14pd_avx512vl",
        "vrcp14pd_avx512f",
        "vrcp14ps_avx512vl",
        "vrcp14ps_avx512f",
        "vrndscalepd_avx512vl",
        "vrndscalepd_avx512f",
        "vrndscaleps_avx512vl",
        "vrndscaleps_avx512f",
        "vrsqrt14pd_avx512vl",
        "vrsqrt14pd_avx512f",
        "vrsqrt14ps_avx512vl",
        "vrsqrt14ps_avx512f",
        "vscalefpd_avx512vl",
        "vscalefpd_avx512f",
        "vscalefps_avx512vl",
        "vscalefps_avx512f",
    ];

    pub const EVEX_VSIB_GATHER_USER_OPS: &[&str] = &[
        "vgatherdpd_avx512vl",
        "vgatherdpd_avx512f",
        "vgatherdps_avx512vl",
        "vgatherdps_avx512f",
        "vgatherqpd_avx512vl",
        "vgatherqpd_avx512f",
        "vgatherqps_avx512vl",
        "vgatherqps_avx512f",
        "vpgatherdd_avx512vl",
        "vpgatherdd_avx512f",
        "vpgatherdq_avx512vl",
        "vpgatherdq_avx512f",
        "vpgatherqd_avx512vl",
        "vpgatherqd_avx512f",
        "vpgatherqq_avx512vl",
        "vpgatherqq_avx512f",
    ];

    pub const VEX_VSIB_GATHER_USER_OPS: &[&str] = &[
        "vgatherdpd",
        "vgatherdps",
        "vgatherqpd",
        "vgatherqps",
        "vpgatherdd",
        "vpgatherdq",
        "vpgatherqd",
        "vpgatherqq",
    ];

    /// Opaque operations that are independently lane-local in each 128-bit
    /// chunk. The x86 frontend uses this explicit allowlist to lower wide
    /// SLEIGH results without passing YMM/ZMM values through the u128 helper
    /// ABI. Cross-lane operations must never be added here.
    pub const LANE_LOCAL_128_USER_OPS: &[&str] = &[
        "vbroadcastss_avx512vl",
        "vbroadcastss_avx512f",
        "vbroadcastsd_avx512vl",
        "vbroadcastsd_avx512f",
        "vbroadcastf32x4_avx512vl",
        "vbroadcastf32x4_avx512f",
        "vbroadcasti32x4_avx512vl",
        "vbroadcasti32x4_avx512f",
        "vaddpd_avx512vl",
        "vaddpd_avx512f",
        "vaddps_avx512vl",
        "vaddps_avx512f",
        "vaddsubpd_avx",
        "vaddsubps_avx",
        "vblendmpd_avx512vl",
        "vblendmpd_avx512f",
        "vblendmps_avx512vl",
        "vblendmps_avx512f",
        "vdivpd_avx",
        "vdivpd_avx512vl",
        "vdivpd_avx512f",
        "vdivps_avx",
        "vdivps_avx512vl",
        "vdivps_avx512f",
        "vmaxpd_avx",
        "vmaxpd_avx512vl",
        "vmaxpd_avx512f",
        "vmaxps_avx",
        "vmaxps_avx512vl",
        "vmaxps_avx512f",
        "vminpd_avx",
        "vminpd_avx512vl",
        "vminpd_avx512f",
        "vminps_avx",
        "vminps_avx512vl",
        "vminps_avx512f",
        "vmulpd_avx512vl",
        "vmulpd_avx512f",
        "vmulps_avx512vl",
        "vmulps_avx512f",
        "vsqrtpd_avx",
        "vsqrtpd_avx512vl",
        "vsqrtpd_avx512f",
        "vsqrtps_avx",
        "vsqrtps_avx512vl",
        "vsqrtps_avx512f",
        "vsubpd_avx",
        "vsubpd_avx512vl",
        "vsubpd_avx512f",
        "vsubps_avx",
        "vsubps_avx512vl",
        "vsubps_avx512f",
        "vhaddps_avx",
        "vhsubpd_avx",
        "vhsubps_avx",
        "vroundpd_avx",
        "vroundps_avx",
        "vrcpps_avx",
        "vrsqrtps_avx",
        "vmpsadbw_avx",
        "vmpsadbw_avx2",
        "vdpps_avx",
        "vcmppd_avx",
        "vcmpps_avx",
        "vcvtdq2pd_avx",
        "vcvtdq2ps_avx",
        "vcvtps2dq_avx",
        "vcvtps2pd_avx",
        "vunpckhpd_avx",
        "vunpckhpd_avx512vl",
        "vunpckhpd_avx512f",
        "vunpcklpd_avx",
        "vunpcklpd_avx512vl",
        "vunpcklpd_avx512f",
        "vunpckhps_avx",
        "vunpckhps_avx512vl",
        "vunpckhps_avx512f",
        "vunpcklps_avx",
        "vunpcklps_avx512vl",
        "vunpcklps_avx512f",
        "vblendvpd_avx",
        "vblendvps_avx",
        "vmovddup_avx512vl",
        "vmovddup_avx512f",
        "vmovshdup_avx",
        "vmovshdup_avx512vl",
        "vmovshdup_avx512f",
        "vmovsldup_avx",
        "vmovsldup_avx512vl",
        "vmovsldup_avx512f",
        "vmovntdqa_avx",
        "vmovntdqa_avx2",
        "vmovntdqa_avx512vl",
        "vmovntdqa_avx512f",
        "vlddqu_avx",
        "vmovntpd_avx",
        "vmovntpd_avx512vl",
        "vmovntpd_avx512f",
        "vmovntps_avx",
        "vmovntps_avx512vl",
        "vmovntps_avx512f",
        "vpermilpd_avx",
        "vpermilpd_avx512vl",
        "vpermilpd_avx512f",
        "vpermilps_avx",
        "vpermilps_avx512vl",
        "vpermilps_avx512f",
        "vshufps_avx",
        "vshufps_avx512vl",
        "vshufps_avx512f",
        "vpmaxsb_avx",
        "vpmaxsb_avx2",
        "vpmaxsb_avx512vl",
        "vpmaxsb_avx512bw",
        "vpmaxsw_avx",
        "vpmaxsw_avx2",
        "vpmaxsw_avx512vl",
        "vpmaxsw_avx512bw",
        "vpmaxsd_avx",
        "vpmaxsd_avx2",
        "vpmaxsd_avx512vl",
        "vpmaxsd_avx512f",
        "vpmaxsq_avx512vl",
        "vpmaxsq_avx512f",
        "vpmaxub_avx",
        "vpmaxub_avx2",
        "vpmaxub_avx512vl",
        "vpmaxub_avx512bw",
        "vpmaxuw_avx",
        "vpmaxuw_avx2",
        "vpmaxuw_avx512vl",
        "vpmaxuw_avx512bw",
        "vpmaxuq_avx512vl",
        "vpmaxuq_avx512f",
        "vpminsb_avx",
        "vpminsb_avx2",
        "vpminsb_avx512vl",
        "vpminsb_avx512bw",
        "vpminsw_avx",
        "vpminsw_avx2",
        "vpminsw_avx512vl",
        "vpminsw_avx512bw",
        "vpminsd_avx",
        "vpminsd_avx2",
        "vpminsd_avx512vl",
        "vpminsd_avx512f",
        "vpminsq_avx512vl",
        "vpminsq_avx512f",
        "vpminud_avx",
        "vpminud_avx2",
        "vpminud_avx512vl",
        "vpminud_avx512f",
        "vpminuq_avx512vl",
        "vpminuq_avx512f",
        "vpackssdw_avx",
        "vpackssdw_avx2",
        "vpackssdw_avx512vl",
        "vpackssdw_avx512bw",
        "vpacksswb_avx",
        "vpacksswb_avx2",
        "vpacksswb_avx512vl",
        "vpacksswb_avx512bw",
        "vpmulld_avx",
        "vpmulld_avx2",
        "vpmulld_avx512vl",
        "vpmulld_avx512f",
        "vpmulhw_avx",
        "vpmulhw_avx2",
        "vpmulhw_avx512vl",
        "vpmulhw_avx512bw",
        "vpmulhuw_avx",
        "vpmulhuw_avx2",
        "vpmulhuw_avx512vl",
        "vpmulhuw_avx512bw",
        "vpmuldq_avx",
        "vpmuldq_avx2",
        "vpmuldq_avx512vl",
        "vpmuldq_avx512f",
        "vpmuludq_avx",
        "vpmuludq_avx2",
        "vpmuludq_avx512vl",
        "vpmuludq_avx512f",
        "vpmulhrsw_avx",
        "vpmulhrsw_avx2",
        "vpmulhrsw_avx512vl",
        "vpmulhrsw_avx512bw",
        "vpsignb_avx",
        "vpsignb_avx2",
        "vpsignw_avx",
        "vpsignw_avx2",
        "vpsignd_avx",
        "vpsignd_avx2",
        "vpandn_avx",
        "vpandn_avx2",
        "vpcmpgtw_avx",
        "vpcmpgtw_avx2",
        "vpcmpgtq_avx",
        "vpcmpgtq_avx2",
        "vpshufhw_avx",
        "vpshufhw_avx2",
        "vpshufhw_avx512vl",
        "vpshufhw_avx512bw",
        "vpshuflw_avx",
        "vpshuflw_avx2",
        "vpshuflw_avx512vl",
        "vpshuflw_avx512bw",
        "vpunpckhbw_avx",
        "vpunpckhbw_avx2",
        "vpunpckhbw_avx512vl",
        "vpunpckhbw_avx512bw",
        "vpunpcklbw_avx",
        "vpunpcklbw_avx2",
        "vpunpcklbw_avx512vl",
        "vpunpcklbw_avx512bw",
        "vpunpckhdq_avx",
        "vpunpckhdq_avx2",
        "vpunpckhdq_avx512vl",
        "vpunpckhdq_avx512f",
        "vpunpckldq_avx",
        "vpunpckldq_avx2",
        "vpunpckldq_avx512vl",
        "vpunpckldq_avx512f",
        "vphaddw_avx",
        "vphaddw_avx2",
        "vphaddd_avx",
        "vphaddd_avx2",
        "vphaddsw_avx",
        "vphaddsw_avx2",
        "vphsubw_avx",
        "vphsubw_avx2",
        "vphsubd_avx",
        "vphsubd_avx2",
        "vphsubsw_avx",
        "vphsubsw_avx2",
        "vpsllvq_avx2",
        "vpsllvq_avx512vl",
        "vpsllvq_avx512f",
        "vpsllvw_avx512vl",
        "vpsllvw_avx512bw",
        "vpsrlvq_avx2",
        "vpsrlvq_avx512vl",
        "vpsrlvq_avx512f",
        "vpsrlvw_avx512vl",
        "vpsrlvw_avx512bw",
        "vpsravd_avx2",
        "vpsravd_avx512vl",
        "vpsravd_avx512f",
        "vpsravq_avx512vl",
        "vpsravq_avx512f",
        "vpsravw_avx512vl",
        "vpsravw_avx512bw",
        "vpsrad_avx",
        "vpsrad_avx2",
        "vpsrad_avx512vl",
        "vpsrad_avx512f",
        "vpsraq_avx512vl",
        "vpsraq_avx512f",
        "vpsraw_avx",
        "vpsraw_avx2",
        "vpsraw_avx512vl",
        "vpsraw_avx512bw",
        "vprold_avx512vl",
        "vprold_avx512f",
        "vprolvd_avx512vl",
        "vprolvd_avx512f",
        "vprolq_avx512vl",
        "vprolq_avx512f",
        "vprolvq_avx512vl",
        "vprolvq_avx512f",
        "vprord_avx512vl",
        "vprord_avx512f",
        "vprorvd_avx512vl",
        "vprorvd_avx512f",
        "vprorq_avx512vl",
        "vprorq_avx512f",
        "vprorvq_avx512vl",
        "vprorvq_avx512f",
        "vplzcntd_avx512vl",
        "vplzcntd_avx512cd",
        "vplzcntq_avx512vl",
        "vplzcntq_avx512cd",
    ];

    /// Lane-local operations that need their architectural 128-bit chunk
    /// number in order to suppress floating-point exceptions in masked-off
    /// EVEX lanes before the destination merge is evaluated.
    pub const INDEXED_LANE_LOCAL_128_USER_OPS: &[&str] = &[
        "vaddpd_avx512vl",
        "vaddpd_avx512f",
        "vaddps_avx512vl",
        "vaddps_avx512f",
        "vdivpd_avx512vl",
        "vdivpd_avx512f",
        "vdivps_avx512vl",
        "vdivps_avx512f",
        "vmaxpd_avx512vl",
        "vmaxpd_avx512f",
        "vmaxps_avx512vl",
        "vmaxps_avx512f",
        "vminpd_avx512vl",
        "vminpd_avx512f",
        "vminps_avx512vl",
        "vminps_avx512f",
        "vmulpd_avx512vl",
        "vmulpd_avx512f",
        "vmulps_avx512vl",
        "vmulps_avx512f",
        "vsqrtpd_avx512vl",
        "vsqrtpd_avx512f",
        "vsqrtps_avx512vl",
        "vsqrtps_avx512f",
        "vsubpd_avx512vl",
        "vsubpd_avx512f",
        "vsubps_avx512vl",
        "vsubps_avx512f",
        "vblendpd_avx",
        "vblendps_avx",
        "vshufpd_avx",
        "vshufpd_avx512vl",
        "vshufpd_avx512f",
        "vpmovsxbd_avx",
        "vpmovsxbd_avx2",
        "vpmovsxbd_avx512vl",
        "vpmovsxbd_avx512f",
        "vpmovsxbq_avx",
        "vpmovsxbq_avx2",
        "vpmovsxbq_avx512vl",
        "vpmovsxbq_avx512f",
        "vpmovsxwq_avx",
        "vpmovsxwq_avx2",
        "vpmovsxwq_avx512vl",
        "vpmovsxwq_avx512f",
        "vpmovzxbq_avx",
        "vpmovzxbq_avx2",
        "vpmovzxbq_avx512vl",
        "vpmovzxbq_avx512f",
        "vpmovzxwq_avx",
        "vpmovzxwq_avx2",
        "vpmovzxwq_avx512vl",
        "vpmovzxwq_avx512f",
        "vmpsadbw_avx",
        "vmpsadbw_avx2",
        "vcvtdq2pd_avx",
        "vcvtps2pd_avx",
        "vpermilpd_avx",
        "vpermilpd_avx512vl",
        "vpermilpd_avx512f",
        "vpermilps_avx",
        "vpermilps_avx512vl",
        "vpermilps_avx512f",
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

    fn packed_sub_d(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size == 0
            || dst.size > 64
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
            cpu.write_var(dst.slice(offset, 4), left.wrapping_sub(right));
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

    fn packed_compare_128(
        cpu: &mut Cpu,
        dst: VarNode,
        args: [Value; 2],
        element_size: usize,
        signed: bool,
    ) {
        let lane_count = 16 / element_size;
        let result_size = lane_count.div_ceil(8);
        if usize::from(dst.size) != result_size
            || args[0].size() != 16
            || args[1].size() != 16
            || !matches!(element_size, 1 | 2 | 4 | 8)
        {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let predicate = cpu.args[0] as u8 & 7;
        let mut mask = 0_u16;
        for lane in 0..lane_count {
            let offset = (lane * element_size) as u8;
            let left: u128 = cpu.read_dynamic(args[0].slice(offset, element_size as u8)).zxt();
            let right: u128 = cpu.read_dynamic(args[1].slice(offset, element_size as u8)).zxt();
            let matches = if signed {
                let shift = 128 - element_size * 8;
                let left = ((left << shift) as i128) >> shift;
                let right = ((right << shift) as i128) >> shift;
                match predicate {
                    0 => left == right,
                    1 => left < right,
                    2 => left <= right,
                    3 => false,
                    4 => left != right,
                    5 => left >= right,
                    6 => left > right,
                    7 => true,
                    _ => unreachable!(),
                }
            }
            else {
                match predicate {
                    0 => left == right,
                    1 => left < right,
                    2 => left <= right,
                    3 => false,
                    4 => left != right,
                    5 => left >= right,
                    6 => left > right,
                    7 => true,
                    _ => unreachable!(),
                }
            };
            mask |= u16::from(matches) << lane;
        }
        cpu.write_trunc(dst, mask);
    }

    fn packed_compare_b_signed(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_compare_128(cpu, dst, args, 1, true);
    }

    fn packed_compare_b_unsigned(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_compare_128(cpu, dst, args, 1, false);
    }

    fn packed_compare_w_signed(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_compare_128(cpu, dst, args, 2, true);
    }

    fn packed_compare_w_unsigned(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_compare_128(cpu, dst, args, 2, false);
    }

    fn packed_compare_d_signed(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_compare_128(cpu, dst, args, 4, true);
    }

    fn packed_compare_d_unsigned(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_compare_128(cpu, dst, args, 4, false);
    }

    fn packed_compare_q_signed(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_compare_128(cpu, dst, args, 8, true);
    }

    fn packed_compare_q_unsigned(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_compare_128(cpu, dst, args, 8, false);
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

    fn packed_permute_b_chunk(
        cpu: &mut Cpu,
        dst: VarNode,
        indexes: Value,
        sources: [u128; 4],
        lane_count: usize,
    ) {
        if dst.size != 16 || indexes.size() != 16 || !lane_count.is_power_of_two() {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let indexes = cpu.read::<u128>(indexes).to_le_bytes();
        let sources = sources.map(u128::to_le_bytes);
        let mut output = [0_u8; 16];
        for (lane, index) in indexes.into_iter().enumerate() {
            let source_lane = usize::from(index) & (lane_count - 1);
            output[lane] = sources[source_lane / 16][source_lane % 16];
        }
        cpu.write_var(dst, u128::from_le_bytes(output));
    }

    fn packed_permute_b_128_chunk(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_permute_b_chunk(cpu, dst, args[0], [cpu.read::<u128>(args[1]), 0, 0, 0], 16);
    }

    fn packed_permute_b_256_chunk(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_permute_b_chunk(
            cpu,
            dst,
            args[0],
            [cpu.read::<u128>(args[1]), cpu.args[0], 0, 0],
            32,
        );
    }

    fn packed_permute_b_512_chunk(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_permute_b_chunk(
            cpu,
            dst,
            args[0],
            [cpu.read::<u128>(args[1]), cpu.args[0], cpu.args[1], cpu.args[2]],
            64,
        );
    }

    fn packed_permute_b_mem_chunk(
        cpu: &mut Cpu,
        dst: VarNode,
        address: Value,
        indexes: Value,
        lane_count: usize,
    ) {
        if address.size() != 8 || dst.size != 16 || indexes.size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let address = cpu.read::<u64>(address);
        let mut source = [0_u8; 64];
        for (offset, byte) in source[..lane_count].iter_mut().enumerate() {
            let Some(current) = address.checked_add(offset as u64)
            else {
                cpu.exception.code = ExceptionCode::AddressOverflow as u32;
                cpu.exception.value = u64::MAX;
                return;
            };
            match cpu.mem.read::<1>(current, icicle_mem::perm::READ) {
                Ok(value) => *byte = value[0],
                Err(error) => {
                    cpu.exception.code = ExceptionCode::from_load_error(error) as u32;
                    cpu.exception.value = current;
                    return;
                }
            }
        }
        let indexes = cpu.read::<u128>(indexes).to_le_bytes();
        let mut output = [0_u8; 16];
        for (lane, index) in indexes.into_iter().enumerate() {
            output[lane] = source[usize::from(index) & (lane_count - 1)];
        }
        cpu.write_var(dst, u128::from_le_bytes(output));
    }

    fn packed_permute_b_mem_128_chunk(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_permute_b_mem_chunk(cpu, dst, args[0], args[1], 16);
    }

    fn packed_permute_b_mem_256_chunk(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_permute_b_mem_chunk(cpu, dst, args[0], args[1], 32);
    }

    fn packed_permute_b_mem_512_chunk(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_permute_b_mem_chunk(cpu, dst, args[0], args[1], 64);
    }

    fn packed_permute2_b_chunk(
        cpu: &mut Cpu,
        dst: VarNode,
        indexes: Value,
        first: [u128; 4],
        second: [u128; 4],
        lane_count: usize,
    ) {
        if dst.size != 16 || indexes.size() != 16 || !lane_count.is_power_of_two() {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let indexes = cpu.read::<u128>(indexes).to_le_bytes();
        let first = first.map(u128::to_le_bytes);
        let second = second.map(u128::to_le_bytes);
        let mut output = [0_u8; 16];
        for (lane, index) in indexes.into_iter().enumerate() {
            let source_lane = usize::from(index) & (lane_count * 2 - 1);
            let (table, source_lane) = if source_lane < lane_count {
                (&first, source_lane)
            }
            else {
                (&second, source_lane - lane_count)
            };
            output[lane] = table[source_lane / 16][source_lane % 16];
        }
        cpu.write_var(dst, u128::from_le_bytes(output));
    }

    fn packed_permute2_b_128_chunk(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_permute2_b_chunk(
            cpu,
            dst,
            args[0],
            [cpu.read::<u128>(args[1]), 0, 0, 0],
            [cpu.args[0], 0, 0, 0],
            16,
        );
    }

    fn packed_permute2_b_256_chunk(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_permute2_b_chunk(
            cpu,
            dst,
            args[0],
            [cpu.read::<u128>(args[1]), cpu.args[0], 0, 0],
            [cpu.args[1], cpu.args[2], 0, 0],
            32,
        );
    }

    fn packed_permute2_b_512_chunk(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_permute2_b_chunk(
            cpu,
            dst,
            args[0],
            [cpu.read::<u128>(args[1]), cpu.args[0], cpu.args[1], cpu.args[2]],
            [cpu.args[3], cpu.args[4], cpu.args[5], cpu.args[6]],
            64,
        );
    }

    fn packed_permute2_b_mem_chunk(
        cpu: &mut Cpu,
        dst: VarNode,
        indexes: Value,
        first: [u128; 4],
        address: u64,
        lane_count: usize,
    ) {
        if dst.size != 16 || indexes.size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let mut second = [0_u8; 64];
        for (offset, byte) in second[..lane_count].iter_mut().enumerate() {
            let Some(current) = address.checked_add(offset as u64)
            else {
                cpu.exception.code = ExceptionCode::AddressOverflow as u32;
                cpu.exception.value = u64::MAX;
                return;
            };
            match cpu.mem.read::<1>(current, icicle_mem::perm::READ) {
                Ok(value) => *byte = value[0],
                Err(error) => {
                    cpu.exception.code = ExceptionCode::from_load_error(error) as u32;
                    cpu.exception.value = current;
                    return;
                }
            }
        }
        let indexes = cpu.read::<u128>(indexes).to_le_bytes();
        let first = first.map(u128::to_le_bytes);
        let mut output = [0_u8; 16];
        for (lane, index) in indexes.into_iter().enumerate() {
            let source_lane = usize::from(index) & (lane_count * 2 - 1);
            output[lane] = if source_lane < lane_count {
                first[source_lane / 16][source_lane % 16]
            }
            else {
                second[source_lane - lane_count]
            };
        }
        cpu.write_var(dst, u128::from_le_bytes(output));
    }

    fn packed_permute2_b_mem_128_chunk(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_permute2_b_mem_chunk(
            cpu,
            dst,
            args[0],
            [cpu.read::<u128>(args[1]), 0, 0, 0],
            cpu.args[0] as u64,
            16,
        );
    }

    fn packed_permute2_b_mem_256_chunk(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_permute2_b_mem_chunk(
            cpu,
            dst,
            args[0],
            [cpu.read::<u128>(args[1]), cpu.args[0], 0, 0],
            cpu.args[1] as u64,
            32,
        );
    }

    fn packed_permute2_b_mem_512_chunk(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_permute2_b_mem_chunk(
            cpu,
            dst,
            args[0],
            [cpu.read::<u128>(args[1]), cpu.args[0], cpu.args[1], cpu.args[2]],
            cpu.args[3] as u64,
            64,
        );
    }

    fn packed_permute2_elements_chunk(
        cpu: &mut Cpu,
        dst: VarNode,
        indexes: Value,
        first: [u128; 4],
        second: [u128; 4],
        lane_width: usize,
        lane_count: usize,
    ) {
        if dst.size != 16
            || indexes.size() != 16
            || !matches!(lane_width, 2 | 4 | 8)
            || !lane_count.is_power_of_two()
        {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }

        let indexes = cpu.read::<u128>(indexes).to_le_bytes();
        let first = first.map(u128::to_le_bytes);
        let second = second.map(u128::to_le_bytes);
        let mut output = [0_u8; 16];
        for lane in 0..16 / lane_width {
            let offset = lane * lane_width;
            let source_lane = match lane_width {
                2 => u16::from_le_bytes(indexes[offset..offset + 2].try_into().unwrap()) as usize,
                4 => u32::from_le_bytes(indexes[offset..offset + 4].try_into().unwrap()) as usize,
                8 => u64::from_le_bytes(indexes[offset..offset + 8].try_into().unwrap()) as usize,
                _ => unreachable!(),
            } & (lane_count * 2 - 1);
            let (table, source_lane) = if source_lane < lane_count {
                (&first, source_lane)
            }
            else {
                (&second, source_lane - lane_count)
            };
            let source_offset = source_lane * lane_width;
            let source_chunk = source_offset / 16;
            let source_chunk_offset = source_offset % 16;
            output[offset..offset + lane_width].copy_from_slice(
                &table[source_chunk][source_chunk_offset..source_chunk_offset + lane_width],
            );
        }
        cpu.write_var(dst, u128::from_le_bytes(output));
    }

    fn packed_permute2_d_128_chunk(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_permute2_elements_chunk(
            cpu,
            dst,
            args[0],
            [cpu.read::<u128>(args[1]), 0, 0, 0],
            [cpu.args[0], 0, 0, 0],
            4,
            4,
        );
    }

    fn packed_permute2_d_256_chunk(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_permute2_elements_chunk(
            cpu,
            dst,
            args[0],
            [cpu.read::<u128>(args[1]), cpu.args[0], 0, 0],
            [cpu.args[1], cpu.args[2], 0, 0],
            4,
            8,
        );
    }

    fn packed_permute2_d_512_chunk(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_permute2_elements_chunk(
            cpu,
            dst,
            args[0],
            [cpu.read::<u128>(args[1]), cpu.args[0], cpu.args[1], cpu.args[2]],
            [cpu.args[3], cpu.args[4], cpu.args[5], cpu.args[6]],
            4,
            16,
        );
    }

    fn packed_permute2_q_128_chunk(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_permute2_elements_chunk(
            cpu,
            dst,
            args[0],
            [cpu.read::<u128>(args[1]), 0, 0, 0],
            [cpu.args[0], 0, 0, 0],
            8,
            2,
        );
    }

    fn packed_permute2_q_256_chunk(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_permute2_elements_chunk(
            cpu,
            dst,
            args[0],
            [cpu.read::<u128>(args[1]), cpu.args[0], 0, 0],
            [cpu.args[1], cpu.args[2], 0, 0],
            8,
            4,
        );
    }

    fn packed_permute2_q_512_chunk(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_permute2_elements_chunk(
            cpu,
            dst,
            args[0],
            [cpu.read::<u128>(args[1]), cpu.args[0], cpu.args[1], cpu.args[2]],
            [cpu.args[3], cpu.args[4], cpu.args[5], cpu.args[6]],
            8,
            8,
        );
    }

    fn packed_permute2_w_128_chunk(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_permute2_elements_chunk(
            cpu,
            dst,
            args[0],
            [cpu.read::<u128>(args[1]), 0, 0, 0],
            [cpu.args[0], 0, 0, 0],
            2,
            8,
        );
    }

    fn packed_permute2_w_256_chunk(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_permute2_elements_chunk(
            cpu,
            dst,
            args[0],
            [cpu.read::<u128>(args[1]), cpu.args[0], 0, 0],
            [cpu.args[1], cpu.args[2], 0, 0],
            2,
            16,
        );
    }

    fn packed_permute2_w_512_chunk(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_permute2_elements_chunk(
            cpu,
            dst,
            args[0],
            [cpu.read::<u128>(args[1]), cpu.args[0], cpu.args[1], cpu.args[2]],
            [cpu.args[3], cpu.args[4], cpu.args[5], cpu.args[6]],
            2,
            32,
        );
    }

    fn packed_align_right_128_chunk(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 16 || args[0].size() != 16 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let upper = cpu.read::<u128>(args[0]).to_le_bytes();
        let lower = cpu.read::<u128>(args[1]).to_le_bytes();
        let shift = cpu.args[0] as usize;
        let mut output = [0_u8; 16];
        for (lane, byte) in output.iter_mut().enumerate() {
            let source = lane + shift;
            *byte = if source < 16 {
                lower[source]
            }
            else if source < 32 {
                upper[source - 16]
            }
            else {
                0
            };
        }
        cpu.write_var(dst, u128::from_le_bytes(output));
    }

    fn packed_align_elements_chunk(
        cpu: &mut Cpu,
        dst: VarNode,
        first: [u128; 4],
        second: [u128; 4],
        vector_size: usize,
        lane_bytes: usize,
        immediate: usize,
        output_chunk: usize,
    ) {
        if dst.size != 16
            || !matches!(vector_size, 16 | 32 | 64)
            || output_chunk >= vector_size / 16
        {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = vector_size as u64;
            return;
        }
        let lane_count = vector_size / lane_bytes;
        let source_start = immediate & (lane_count - 1);
        let first = first.map(u128::to_le_bytes);
        let second = second.map(u128::to_le_bytes);
        let mut output = [0_u8; 16];
        let lanes_per_chunk = 16 / lane_bytes;
        for lane_in_chunk in 0..lanes_per_chunk {
            let destination_lane = output_chunk * lanes_per_chunk + lane_in_chunk;
            let source_lane = source_start + destination_lane;
            let (source, source_lane) = if source_lane < lane_count {
                (&second, source_lane)
            }
            else {
                (&first, source_lane - lane_count)
            };
            let source_chunk = source_lane / lanes_per_chunk;
            let source_offset = (source_lane % lanes_per_chunk) * lane_bytes;
            let output_offset = lane_in_chunk * lane_bytes;
            output[output_offset..output_offset + lane_bytes]
                .copy_from_slice(&source[source_chunk][source_offset..source_offset + lane_bytes]);
        }
        cpu.write_var(dst, u128::from_le_bytes(output));
    }

    fn packed_align_d_128_chunk(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if args[0].size() != 16 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(args[0].size());
            return;
        }
        packed_align_elements_chunk(
            cpu,
            dst,
            [cpu.read::<u128>(args[0]), 0, 0, 0],
            [cpu.read::<u128>(args[1]), 0, 0, 0],
            16,
            4,
            cpu.args[0] as usize,
            0,
        );
    }

    fn packed_align_d_256_chunk(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if args[0].size() != 16 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(args[0].size());
            return;
        }
        packed_align_elements_chunk(
            cpu,
            dst,
            [cpu.read::<u128>(args[0]), cpu.read::<u128>(args[1]), 0, 0],
            [cpu.args[0], cpu.args[1], 0, 0],
            32,
            4,
            cpu.args[2] as usize,
            cpu.args[3] as usize,
        );
    }

    fn packed_align_d_512_chunk(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if args[0].size() != 16 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(args[0].size());
            return;
        }
        packed_align_elements_chunk(
            cpu,
            dst,
            [cpu.read::<u128>(args[0]), cpu.read::<u128>(args[1]), cpu.args[0], cpu.args[1]],
            [cpu.args[2], cpu.args[3], cpu.args[4], cpu.args[5]],
            64,
            4,
            cpu.args[6] as usize,
            cpu.args[7] as usize,
        );
    }

    fn packed_align_q_128_chunk(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if args[0].size() != 16 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(args[0].size());
            return;
        }
        packed_align_elements_chunk(
            cpu,
            dst,
            [cpu.read::<u128>(args[0]), 0, 0, 0],
            [cpu.read::<u128>(args[1]), 0, 0, 0],
            16,
            8,
            cpu.args[0] as usize,
            0,
        );
    }

    fn packed_align_q_256_chunk(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if args[0].size() != 16 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(args[0].size());
            return;
        }
        packed_align_elements_chunk(
            cpu,
            dst,
            [cpu.read::<u128>(args[0]), cpu.read::<u128>(args[1]), 0, 0],
            [cpu.args[0], cpu.args[1], 0, 0],
            32,
            8,
            cpu.args[2] as usize,
            cpu.args[3] as usize,
        );
    }

    fn packed_align_q_512_chunk(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if args[0].size() != 16 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(args[0].size());
            return;
        }
        packed_align_elements_chunk(
            cpu,
            dst,
            [cpu.read::<u128>(args[0]), cpu.read::<u128>(args[1]), cpu.args[0], cpu.args[1]],
            [cpu.args[2], cpu.args[3], cpu.args[4], cpu.args[5]],
            64,
            8,
            cpu.args[6] as usize,
            cpu.args[7] as usize,
        );
    }

    fn packed_shuffle_128_256_chunk(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 16 || args[0].size() != 16 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let first = [cpu.read::<u128>(args[0]), cpu.read::<u128>(args[1])];
        let second = [cpu.args[0], cpu.args[1]];
        let immediate = cpu.args[2] as usize;
        let output_chunk = cpu.args[3] as usize;
        let result = match output_chunk {
            0 => first[immediate & 1],
            1 => second[(immediate >> 1) & 1],
            _ => {
                cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
                cpu.exception.value = output_chunk as u64;
                return;
            }
        };
        cpu.write_var(dst, result);
    }

    fn packed_shuffle_128_512_chunk(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 16 || args[0].size() != 16 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let first =
            [cpu.read::<u128>(args[0]), cpu.read::<u128>(args[1]), cpu.args[0], cpu.args[1]];
        let second = [cpu.args[2], cpu.args[3], cpu.args[4], cpu.args[5]];
        let immediate = cpu.args[6] as usize;
        let output_chunk = cpu.args[7] as usize;
        if output_chunk >= 4 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = output_chunk as u64;
            return;
        }
        let source_chunk = (immediate >> (output_chunk * 2)) & 3;
        let source = if output_chunk < 2 { first } else { second };
        cpu.write_var(dst, source[source_chunk]);
    }

    fn packed_insert_128_256_chunk(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 16 || args[0].size() != 16 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let source = [cpu.read::<u128>(args[0]), cpu.read::<u128>(args[1])];
        let inserted = cpu.args[0];
        let selected_chunk = (cpu.args[1] & 1) as usize;
        let output_chunk = cpu.args[2] as usize;
        if output_chunk >= source.len() {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = output_chunk as u64;
            return;
        }
        let result = if output_chunk == selected_chunk { inserted } else { source[output_chunk] };
        cpu.write_var(dst, result);
    }

    fn packed_insert_128_512_chunk(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 16 || args[0].size() != 16 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let source =
            [cpu.read::<u128>(args[0]), cpu.read::<u128>(args[1]), cpu.args[0], cpu.args[1]];
        let inserted = cpu.args[2];
        let selected_chunk = (cpu.args[3] & 3) as usize;
        let output_chunk = cpu.args[4] as usize;
        if output_chunk >= source.len() {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = output_chunk as u64;
            return;
        }
        let result = if output_chunk == selected_chunk { inserted } else { source[output_chunk] };
        cpu.write_var(dst, result);
    }

    fn packed_insert_256_512_chunk(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 16 || args[0].size() != 16 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let source =
            [cpu.read::<u128>(args[0]), cpu.read::<u128>(args[1]), cpu.args[0], cpu.args[1]];
        let inserted = [cpu.args[2], cpu.args[3]];
        let selected_base = ((cpu.args[4] & 1) as usize) * 2;
        let output_chunk = cpu.args[5] as usize;
        if output_chunk >= source.len() {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = output_chunk as u64;
            return;
        }
        let result = if output_chunk == selected_base {
            inserted[0]
        }
        else if output_chunk == selected_base + 1 {
            inserted[1]
        }
        else {
            source[output_chunk]
        };
        cpu.write_var(dst, result);
    }

    fn packed_shift_double(
        cpu: &mut Cpu,
        dst: VarNode,
        args: [Value; 2],
        element_size: u8,
        left: bool,
    ) {
        if dst.size == 0
            || dst.size > 64
            || dst.size % element_size != 0
            || args[0].size() != dst.size
            || args[1].size() != dst.size
            || !matches!(element_size, 2 | 4 | 8)
        {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let element_bits = u32::from(element_size) * 8;
        let shift = (cpu.args[0] as u32) & (element_bits - 1);
        let element_mask = (1_u128 << element_bits) - 1;
        for offset in (0..dst.size).step_by(element_size as usize) {
            let first: u128 = cpu.read_dynamic(args[0].slice(offset, element_size)).zxt();
            let second: u128 = cpu.read_dynamic(args[1].slice(offset, element_size)).zxt();
            let result = if shift == 0 {
                first
            }
            else if left {
                ((first << shift) | (second >> (element_bits - shift))) & element_mask
            }
            else {
                ((first >> shift) | (second << (element_bits - shift))) & element_mask
            };
            match element_size {
                2 => cpu.write_var(dst.slice(offset, element_size), result as u16),
                4 => cpu.write_var(dst.slice(offset, element_size), result as u32),
                8 => cpu.write_var(dst.slice(offset, element_size), result as u64),
                _ => unreachable!(),
            }
        }
    }

    fn packed_shift_left_double_w(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_shift_double(cpu, dst, args, 2, true);
    }

    fn packed_shift_left_double_d(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_shift_double(cpu, dst, args, 4, true);
    }

    fn packed_shift_left_double_q(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_shift_double(cpu, dst, args, 8, true);
    }

    fn packed_shift_right_double_w(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_shift_double(cpu, dst, args, 2, false);
    }

    fn packed_shift_right_double_d(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_shift_double(cpu, dst, args, 4, false);
    }

    fn packed_shift_right_double_q(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_shift_double(cpu, dst, args, 8, false);
    }

    fn packed_shift_left_double_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_shift_double(cpu, dst, args, cpu.args[1] as u8, true);
    }

    fn packed_shift_right_double_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_shift_double(cpu, dst, args, cpu.args[1] as u8, false);
    }

    fn packed_shift_double_variable_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2], left: bool) {
        let element_size = cpu.args[1] as u8;
        if dst.size != 16
            || args[0].size() != 16
            || args[1].size() != 16
            || !matches!(element_size, 2 | 4 | 8)
        {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let first = cpu.read::<u128>(args[0]).to_le_bytes();
        let second = cpu.read::<u128>(args[1]).to_le_bytes();
        let counts = cpu.args[0].to_le_bytes();
        let element_bits = u32::from(element_size) * 8;
        let element_mask = (1_u128 << element_bits) - 1;
        let mut output = [0_u8; 16];
        for offset in (0..16).step_by(element_size as usize) {
            let mut first_lane = 0_u128;
            let mut second_lane = 0_u128;
            let mut count_lane = 0_u128;
            for byte in 0..element_size as usize {
                first_lane |= u128::from(first[offset + byte]) << (byte * 8);
                second_lane |= u128::from(second[offset + byte]) << (byte * 8);
                count_lane |= u128::from(counts[offset + byte]) << (byte * 8);
            }
            let shift = (count_lane as u32) & (element_bits - 1);
            let result = if shift == 0 {
                first_lane
            }
            else if left {
                ((first_lane << shift) | (second_lane >> (element_bits - shift))) & element_mask
            }
            else {
                ((first_lane >> shift) | (second_lane << (element_bits - shift))) & element_mask
            };
            for byte in 0..element_size as usize {
                output[offset + byte] = (result >> (byte * 8)) as u8;
            }
        }
        cpu.write_var(dst, u128::from_le_bytes(output));
    }

    fn packed_shift_left_double_variable_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_shift_double_variable_128(cpu, dst, args, true);
    }

    fn packed_shift_right_double_variable_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_shift_double_variable_128(cpu, dst, args, false);
    }

    fn apply_byte_mask_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 16 || args[0].size() != 16 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let result = cpu.read::<u128>(args[0]).to_le_bytes();
        let old_destination = cpu.read::<u128>(args[1]).to_le_bytes();
        let mask = cpu.args[0] as u64;
        let chunk = cpu.args[1] as usize;
        if chunk >= 4 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = chunk as u64;
            return;
        }
        let mut output = [0_u8; 16];
        for lane in 0..16 {
            let global_lane = chunk * 16 + lane;
            output[lane] = if mask & (1_u64 << global_lane) != 0 {
                result[lane]
            }
            else {
                old_destination[lane]
            };
        }
        cpu.write_var(dst, u128::from_le_bytes(output));
    }

    fn apply_dword_mask_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 16 || args[0].size() != 16 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let result = cpu.read::<u128>(args[0]).to_le_bytes();
        let old_destination = cpu.read::<u128>(args[1]).to_le_bytes();
        let mask = cpu.args[0] as u64;
        let chunk = cpu.args[1] as usize;
        if chunk >= 4 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = chunk as u64;
            return;
        }
        let mut output = [0_u8; 16];
        for lane in 0..4 {
            let range = lane * 4..lane * 4 + 4;
            let source =
                if mask & (1_u64 << (chunk * 4 + lane)) != 0 { &result } else { &old_destination };
            output[range.clone()].copy_from_slice(&source[range]);
        }
        cpu.write_var(dst, u128::from_le_bytes(output));
    }

    fn packed_maddubs_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 16 || args[0].size() != 16 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let unsigned = cpu.read::<u128>(args[0]).to_le_bytes();
        let signed = cpu.read::<u128>(args[1]).to_le_bytes();
        let mut output = [0_u8; 16];
        for lane in 0..8 {
            let offset = lane * 2;
            let sum = i32::from(unsigned[offset]) * i32::from(signed[offset] as i8)
                + i32::from(unsigned[offset + 1]) * i32::from(signed[offset + 1] as i8);
            output[offset..offset + 2].copy_from_slice(
                &(sum.clamp(i16::MIN.into(), i16::MAX.into()) as i16).to_le_bytes(),
            );
        }
        cpu.write_var(dst, u128::from_le_bytes(output));
    }

    fn packed_mpsadbw_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 16 || args[0].size() != 16 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let first = cpu.read::<u128>(args[0]).to_le_bytes();
        let second = cpu.read::<u128>(args[1]).to_le_bytes();
        let chunk = cpu.args[7] as usize;
        if chunk > 1 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = chunk as u64;
            return;
        }
        let control = ((cpu.args[0] >> (chunk * 3)) & 7) as usize;
        let first_base = ((control >> 2) & 1) * 4;
        let second_base = (control & 3) * 4;
        let mut output = [0_u8; 16];
        for lane in 0..8 {
            let mut sum = 0_u16;
            for byte in 0..4 {
                sum = sum.saturating_add(u16::from(
                    first[first_base + lane + byte].abs_diff(second[second_base + byte]),
                ));
            }
            output[lane * 2..lane * 2 + 2].copy_from_slice(&sum.to_le_bytes());
        }
        cpu.write_var(dst, u128::from_le_bytes(output));
    }

    fn packed_dbsad_bw(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if !matches!(dst.size, 16 | 32 | 64)
            || args[0].size() != dst.size
            || args[1].size() != dst.size
        {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let control = cpu.args[0] as usize;
        for chunk in (0..dst.size).step_by(16) {
            let first = cpu.read::<u128>(args[0].slice(chunk, 16)).to_le_bytes();
            let second = cpu.read::<u128>(args[1].slice(chunk, 16)).to_le_bytes();
            let mut selected = [0_u8; 16];
            for dword in 0..4 {
                let source = ((control >> (dword * 2)) & 3) * 4;
                selected[dword * 4..dword * 4 + 4].copy_from_slice(&second[source..source + 4]);
            }
            let mut output = [0_u8; 16];
            for half in 0..2 {
                for lane_in_half in 0..4 {
                    let mut sum = 0_u16;
                    for byte in 0..4 {
                        sum = sum.saturating_add(u16::from(
                            first[half * 8 + (lane_in_half / 2) * 4 + byte]
                                .abs_diff(selected[half * 8 + lane_in_half + byte]),
                        ));
                    }
                    let lane = half * 4 + lane_in_half;
                    output[lane * 2..lane * 2 + 2].copy_from_slice(&sum.to_le_bytes());
                }
            }
            cpu.write_var(dst.slice(chunk, 16), u128::from_le_bytes(output));
        }
    }

    fn packed_maddwd_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 16 || args[0].size() != 16 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let left = cpu.read::<u128>(args[0]).to_le_bytes();
        let right = cpu.read::<u128>(args[1]).to_le_bytes();
        let mut output = [0_u8; 16];
        for lane in 0..4 {
            let offset = lane * 4;
            let left0 = i16::from_le_bytes(left[offset..offset + 2].try_into().unwrap());
            let left1 = i16::from_le_bytes(left[offset + 2..offset + 4].try_into().unwrap());
            let right0 = i16::from_le_bytes(right[offset..offset + 2].try_into().unwrap());
            let right1 = i16::from_le_bytes(right[offset + 2..offset + 4].try_into().unwrap());
            let sum = i32::from(left0)
                .wrapping_mul(i32::from(right0))
                .wrapping_add(i32::from(left1).wrapping_mul(i32::from(right1)));
            output[offset..offset + 4].copy_from_slice(&sum.to_le_bytes());
        }
        cpu.write_var(dst, u128::from_le_bytes(output));
    }

    fn packed_mask_to_bytes_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 16 || args[0].size() != 8 || args[1].size() != 1 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let mask = cpu.read::<u64>(args[0]);
        let chunk = cpu.read::<u8>(args[1]) as usize;
        if chunk >= 4 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = chunk as u64;
            return;
        }
        let mut output = [0_u8; 16];
        for (lane, byte) in output.iter_mut().enumerate() {
            *byte = if mask & (1_u64 << (chunk * 16 + lane)) != 0 { 0xff } else { 0 };
        }
        cpu.write_var(dst, u128::from_le_bytes(output));
    }

    fn packed_bytes_to_mask_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 2 || args[0].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let bytes = cpu.read::<u128>(args[0]).to_le_bytes();
        let mut mask = 0_u16;
        for (lane, byte) in bytes.into_iter().enumerate() {
            mask |= u16::from(byte >> 7) << lane;
        }
        cpu.write_var(dst, mask);
    }

    fn packed_mask_to_words_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 16 || args[0].size() != 8 || args[1].size() != 1 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let mask = cpu.read::<u64>(args[0]);
        let chunk = cpu.read::<u8>(args[1]) as usize;
        if chunk >= 4 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = chunk as u64;
            return;
        }
        let mut output = [0_u8; 16];
        for lane in 0..8 {
            let word = if mask & (1_u64 << (chunk * 8 + lane)) != 0 { u16::MAX } else { 0 };
            output[lane * 2..lane * 2 + 2].copy_from_slice(&word.to_le_bytes());
        }
        cpu.write_var(dst, u128::from_le_bytes(output));
    }

    fn packed_words_to_mask_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 1 || args[0].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let bytes = cpu.read::<u128>(args[0]).to_le_bytes();
        let mut mask = 0_u8;
        for lane in 0..8 {
            mask |= ((bytes[lane * 2 + 1] >> 7) & 1) << lane;
        }
        cpu.write_var(dst, mask);
    }

    fn packed_conflict_chunk(
        cpu: &mut Cpu,
        dst: VarNode,
        sources: [u128; 4],
        vector_size: usize,
        element_size: usize,
        output_chunk: usize,
    ) {
        if dst.size != 16
            || !matches!(vector_size, 16 | 32 | 64)
            || !matches!(element_size, 4 | 8)
            || output_chunk >= vector_size / 16
        {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = vector_size as u64;
            return;
        }
        let source = sources.map(u128::to_le_bytes);
        let lane_count = vector_size / element_size;
        let lanes_per_chunk = 16 / element_size;
        let lane = |index: usize| {
            let offset = index * element_size;
            let mut bytes = [0_u8; 8];
            for byte in 0..element_size {
                bytes[byte] = source[(offset + byte) / 16][(offset + byte) % 16];
            }
            u64::from_le_bytes(bytes)
        };
        let mut output = [0_u8; 16];
        for local in 0..lanes_per_chunk {
            let current = output_chunk * lanes_per_chunk + local;
            let mut conflicts = 0_u64;
            for previous in 0..current.min(lane_count) {
                if lane(previous) == lane(current) {
                    conflicts |= 1_u64 << previous;
                }
            }
            output[local * element_size..(local + 1) * element_size]
                .copy_from_slice(&conflicts.to_le_bytes()[..element_size]);
        }
        cpu.write_var(dst, u128::from_le_bytes(output));
    }

    fn packed_conflict_d_128_chunk(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_conflict_chunk(cpu, dst, [cpu.read::<u128>(args[0]), 0, 0, 0], 16, 4, 0);
    }

    fn packed_conflict_d_256_chunk(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_conflict_chunk(
            cpu,
            dst,
            [cpu.read::<u128>(args[0]), cpu.read::<u128>(args[1]), 0, 0],
            32,
            4,
            cpu.args[0] as usize,
        );
    }

    fn packed_conflict_d_512_chunk(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_conflict_chunk(
            cpu,
            dst,
            [cpu.read::<u128>(args[0]), cpu.read::<u128>(args[1]), cpu.args[0], cpu.args[1]],
            64,
            4,
            cpu.args[2] as usize,
        );
    }

    fn packed_conflict_q_128_chunk(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_conflict_chunk(cpu, dst, [cpu.read::<u128>(args[0]), 0, 0, 0], 16, 8, 0);
    }

    fn packed_conflict_q_256_chunk(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_conflict_chunk(
            cpu,
            dst,
            [cpu.read::<u128>(args[0]), cpu.read::<u128>(args[1]), 0, 0],
            32,
            8,
            cpu.args[0] as usize,
        );
    }

    fn packed_conflict_q_512_chunk(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_conflict_chunk(
            cpu,
            dst,
            [cpu.read::<u128>(args[0]), cpu.read::<u128>(args[1]), cpu.args[0], cpu.args[1]],
            64,
            8,
            cpu.args[2] as usize,
        );
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

    fn vector_sign_mask(value: u128, element_size: usize) -> Option<u64> {
        if !matches!(element_size, 1 | 2 | 4 | 8) {
            return None;
        }
        let bytes = value.to_le_bytes();
        let mut mask = 0_u64;
        for lane in 0..16 / element_size {
            mask |= u64::from(bytes[(lane + 1) * element_size - 1] >> 7) << lane;
        }
        Some(mask)
    }

    fn vector_sign_masked_load_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 16 || args[0].size() != 8 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let element_size = cpu.args[0] as usize;
        let chunk = cpu.args[1] as usize;
        let Some(mask) = vector_sign_mask(cpu.read::<u128>(args[1]), element_size)
        else {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = element_size as u64;
            return;
        };
        let Some(address) = cpu.read::<u64>(args[0]).checked_add((chunk.saturating_mul(16)) as u64)
        else {
            cpu.exception.code = ExceptionCode::AddressOverflow as u32;
            cpu.exception.value = u64::MAX;
            return;
        };
        let mut output = [0_u8; 16];
        for lane in 0..16 / element_size {
            if mask & (1 << lane) == 0 {
                continue;
            }
            for byte in 0..element_size {
                let offset = lane * element_size + byte;
                let current = address + offset as u64;
                match cpu.mem.read::<1>(current, icicle_mem::perm::READ) {
                    Ok(value) => output[offset] = value[0],
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

    fn vector_sign_masked_store_128(cpu: &mut Cpu, _: VarNode, args: [Value; 2]) {
        if args[0].size() != 8 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(args[1].size());
            return;
        }
        let element_size = cpu.args[1] as usize;
        let Some(mask) = vector_sign_mask(cpu.read::<u128>(args[1]), element_size)
        else {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = element_size as u64;
            return;
        };
        masked_store(cpu, cpu.read::<u64>(args[0]), [cpu.args[0], 0, 0, 0], 1, mask, element_size);
    }

    fn vector_sign_masked_store_256(cpu: &mut Cpu, _: VarNode, args: [Value; 2]) {
        if args[0].size() != 8 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(args[1].size());
            return;
        }
        let element_size = cpu.args[3] as usize;
        let Some(low_mask) = vector_sign_mask(cpu.read::<u128>(args[1]), element_size)
        else {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = element_size as u64;
            return;
        };
        let Some(high_mask) = vector_sign_mask(cpu.args[0], element_size)
        else {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = element_size as u64;
            return;
        };
        let lanes_per_chunk = 16 / element_size;
        masked_store(
            cpu,
            cpu.read::<u64>(args[0]),
            [cpu.args[1], cpu.args[2], 0, 0],
            2,
            low_mask | (high_mask << lanes_per_chunk),
            element_size,
        );
    }

    fn maskmovdqu(cpu: &mut Cpu, _: VarNode, args: [Value; 2]) {
        if args[0].size() != 16 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(args[1].size());
            return;
        }
        let Some(address) = read_named::<u64>(cpu, "RDI")
        else {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = 0;
            return;
        };
        // MASKMOVDQU's non-temporal memory reference covers the full
        // 16-byte destination. Native hardware faults on an inaccessible
        // masked-off tail, so validate the complete span before writing the
        // selected bytes.
        for byte in 0..16_u64 {
            let Some(current) = address.checked_add(byte)
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
        let mask = vector_sign_mask(cpu.read::<u128>(args[1]), 1).unwrap_or(0);
        masked_store(cpu, address, [cpu.read::<u128>(args[0]), 0, 0, 0], 1, mask, 1);
    }

    fn aligned_vector_address(cpu: &mut Cpu, address: u64, mask: u64, width: usize) -> bool {
        if !matches!(width, 16 | 32 | 64) {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = width as u64;
            return false;
        }
        // EVEX masking suppresses the memory reference entirely when no lane
        // is selected. Otherwise VMOVDQA32/64 retains the architectural
        // vector-width alignment requirement.
        if mask != 0 && address & (width as u64 - 1) != 0 {
            cpu.exception.code = ExceptionCode::GeneralProtection as u32;
            cpu.exception.value = 0;
            return false;
        }
        true
    }

    fn aligned_masked_load_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if args[0].size() != 8 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(args[0].size());
            return;
        }
        let address = cpu.read::<u64>(args[0]);
        let mask = cpu.args[0] as u64;
        let width = cpu.args[3] as usize;
        if aligned_vector_address(cpu, address, mask, width) {
            masked_load_128(cpu, dst, args);
        }
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

    fn aligned_masked_store_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if args[0].size() != 8 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(args[0].size());
            return;
        }
        let address = cpu.read::<u64>(args[0]);
        let mask = cpu.args[0] as u64;
        if aligned_vector_address(cpu, address, mask, 16) {
            masked_store_128(cpu, dst, args);
        }
    }

    fn aligned_masked_store_256(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if args[0].size() != 8 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(args[0].size());
            return;
        }
        let address = cpu.read::<u64>(args[0]);
        let mask = cpu.args[1] as u64;
        if aligned_vector_address(cpu, address, mask, 32) {
            masked_store_256(cpu, dst, args);
        }
    }

    fn aligned_masked_store_512(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if args[0].size() != 8 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(args[0].size());
            return;
        }
        let address = cpu.read::<u64>(args[0]);
        let mask = cpu.args[3] as u64;
        if aligned_vector_address(cpu, address, mask, 64) {
            masked_store_512(cpu, dst, args);
        }
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
        cpu.write_var(dst, cpu.icount().saturating_add(cpu.time_offset));
    }

    // The SLEIGH spec calls `rdtscp()` with no output, so the helper writes
    // the architectural results itself: EDX:EAX = TSC, ECX = IA32_TSC_AUX
    // (0: single processor), each as a full 64-bit register write, which
    // zeroes the upper halves exactly as 32-bit destinations do on x86-64.
    fn rdtscp(cpu: &mut Cpu, _: VarNode, _: [Value; 2]) {
        let tsc = cpu.icount().saturating_add(cpu.time_offset);
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

    /// One 128-bit slice of an integer broadcast. The SLEIGH constructors
    /// lower every wide destination into slices so the helper ABI never has
    /// to transport a YMM or ZMM value.
    fn broadcast_integer_lane_128(cpu: &mut Cpu, dst: VarNode, source: Value, lane_bytes: usize) {
        if dst.size != 16 || usize::from(source.size()) < lane_bytes {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let lane = match lane_bytes {
            1 => u128::from(cpu.read::<u8>(source.slice(0, 1))),
            2 => u128::from(cpu.read::<u16>(source.slice(0, 2))),
            8 => u128::from(cpu.read::<u64>(source.slice(0, 8))),
            _ => unreachable!("broadcast helper has a fixed lane width"),
        };
        let lane_bits = lane_bytes * 8;
        let lane_mask = u128::MAX >> (128 - lane_bits);
        let mut output = 0_u128;
        for offset in (0..128).step_by(lane_bits) {
            output |= (lane & lane_mask) << offset;
        }
        cpu.write_var(dst, output);
    }

    fn vpbroadcastb_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        broadcast_integer_lane_128(cpu, dst, args[0], 1);
    }

    fn vpbroadcastw_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        broadcast_integer_lane_128(cpu, dst, args[0], 2);
    }

    fn vpbroadcastq_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        broadcast_integer_lane_128(cpu, dst, args[0], 8);
    }

    fn copy_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 16 || args[0].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let value = cpu.read::<u128>(args[0]);
        cpu.write_var(dst, value);
    }

    fn copy_second_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 16 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let value = cpu.read::<u128>(args[1]);
        cpu.write_var(dst, value);
    }

    #[derive(Clone, Copy)]
    struct PackedStringComparison {
        int_res2: u16,
        element_count: usize,
        left_terminated: bool,
        right_terminated: bool,
    }

    /// Intel SDM Vol. 2, "Imm8 Control Byte Operation for PCMPESTRI /
    /// PCMPESTRM / PCMPISTRI / PCMPISTRM". This is deliberately expressed as
    /// the two architectural intermediate results rather than as a libc-style
    /// string helper: invalid elements participate differently in each of the
    /// four aggregation modes, including positions beyond the end of a
    /// candidate in equal-ordered mode.
    fn compare_strings(
        cpu: &mut Cpu,
        left_value: Value,
        right_value: Value,
        control: u8,
        explicit_lengths: Option<(u32, u32)>,
    ) -> Option<PackedStringComparison> {
        if left_value.size() != 16 || right_value.size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(left_value.size());
            return None;
        }

        let left_bytes = cpu.read::<u128>(left_value).to_le_bytes();
        let right_bytes = cpu.read::<u128>(right_value).to_le_bytes();
        let words = control & 1 != 0;
        let signed = control & 2 != 0;
        let element_count = if words { 8 } else { 16 };
        let mut left = [0_i32; 16];
        let mut right = [0_i32; 16];
        for index in 0..element_count {
            if words {
                let offset = index * 2;
                let left_word = u16::from_le_bytes([left_bytes[offset], left_bytes[offset + 1]]);
                let right_word = u16::from_le_bytes([right_bytes[offset], right_bytes[offset + 1]]);
                left[index] =
                    if signed { i32::from(left_word as i16) } else { i32::from(left_word) };
                right[index] =
                    if signed { i32::from(right_word as i16) } else { i32::from(right_word) };
            }
            else {
                left[index] = if signed {
                    i32::from(left_bytes[index] as i8)
                }
                else {
                    i32::from(left_bytes[index])
                };
                right[index] = if signed {
                    i32::from(right_bytes[index] as i8)
                }
                else {
                    i32::from(right_bytes[index])
                };
            }
        }

        let (left_length, right_length) = match explicit_lengths {
            Some((left_length, right_length)) => (
                (left_length as i32).unsigned_abs().min(element_count as u32) as usize,
                (right_length as i32).unsigned_abs().min(element_count as u32) as usize,
            ),
            None => (
                left[..element_count]
                    .iter()
                    .position(|&element| element == 0)
                    .unwrap_or(element_count),
                right[..element_count]
                    .iter()
                    .position(|&element| element == 0)
                    .unwrap_or(element_count),
            ),
        };
        let aggregation = (control >> 2) & 3;

        let comparison = |left_index: usize, right_index: usize| {
            let left_valid = left_index < left_length;
            let right_valid = right_index < right_length && right_index < element_count;
            if !left_valid || !right_valid {
                return match aggregation {
                    0 | 1 => false,
                    2 => !left_valid && !right_valid,
                    3 => !left_valid,
                    _ => unreachable!(),
                };
            }
            match aggregation {
                0 | 2 | 3 => left[left_index] == right[right_index],
                1 if left_index & 1 == 0 => right[right_index] >= left[left_index],
                1 => right[right_index] <= left[left_index],
                _ => unreachable!(),
            }
        };

        let mut int_res1 = 0_u16;
        match aggregation {
            // Equal any: each output bit says whether the corresponding
            // right-hand element matched any valid member of the left set.
            0 => {
                for right_index in 0..element_count {
                    if (0..element_count).any(|left_index| comparison(left_index, right_index)) {
                        int_res1 |= 1 << right_index;
                    }
                }
            }
            // Ranges: consecutive left elements are inclusive lower/upper
            // bounds. Invalid pairs are forced false by the SDM table.
            1 => {
                for right_index in 0..element_count {
                    if (0..element_count).step_by(2).any(|left_index| {
                        comparison(left_index, right_index)
                            && comparison(left_index + 1, right_index)
                    }) {
                        int_res1 |= 1 << right_index;
                    }
                }
            }
            // Equal each compares elements at the same index.
            2 => {
                for index in 0..element_count {
                    if comparison(index, index) {
                        int_res1 |= 1 << index;
                    }
                }
            }
            // Equal ordered tests the left string at every possible starting
            // position in the right string. Out-of-register right positions
            // are invalid, so a still-valid left element forces failure.
            3 => {
                for right_start in 0..element_count {
                    if (0..element_count)
                        .all(|left_index| comparison(left_index, right_start + left_index))
                    {
                        int_res1 |= 1 << right_start;
                    }
                }
            }
            _ => unreachable!(),
        }

        let all_elements =
            if element_count == 16 { u16::MAX } else { (1_u16 << element_count) - 1 };
        let valid_right = if right_length == 16 { u16::MAX } else { (1_u16 << right_length) - 1 };
        let int_res2 = match (control >> 4) & 3 {
            0 | 2 => int_res1,
            1 => (!int_res1) & all_elements,
            3 => int_res1 ^ valid_right,
            _ => unreachable!(),
        };

        Some(PackedStringComparison {
            int_res2,
            element_count,
            left_terminated: left_length < element_count,
            right_terminated: right_length < element_count,
        })
    }

    fn write_packed_string_flags(cpu: &mut Cpu, comparison: PackedStringComparison) -> Option<()> {
        for (name, value) in [
            ("CF", comparison.int_res2 != 0),
            ("ZF", comparison.right_terminated),
            ("SF", comparison.left_terminated),
            ("OF", comparison.int_res2 & 1 != 0),
            ("AF", false),
            ("PF", false),
        ] {
            write_named(cpu, name, u8::from(value))?;
        }
        Some(())
    }

    fn packed_compare_implicit_index(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let Some(comparison) = compare_strings(cpu, args[0], args[1], cpu.args[0] as u8, None)
        else {
            return;
        };
        if write_packed_string_flags(cpu, comparison).is_none() {
            return;
        }
        let index = if comparison.int_res2 == 0 {
            comparison.element_count as u32
        }
        else if cpu.args[0] & 0x40 == 0 {
            comparison.int_res2.trailing_zeros()
        }
        else {
            u16::BITS - 1 - comparison.int_res2.leading_zeros()
        };
        cpu.write_trunc(dst, index);
    }

    fn packed_compare_implicit_mask(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let Some(comparison) = compare_strings(cpu, args[0], args[1], cpu.args[0] as u8, None)
        else {
            return;
        };
        if write_packed_string_flags(cpu, comparison).is_none() {
            return;
        }
        let result = if cpu.args[0] & 0x40 == 0 {
            u128::from(comparison.int_res2)
        }
        else {
            let lane_bits = if comparison.element_count == 16 { 8 } else { 16 };
            let lane_mask = (1_u128 << lane_bits) - 1;
            let mut expanded = 0_u128;
            for index in 0..comparison.element_count {
                if comparison.int_res2 & (1 << index) != 0 {
                    expanded |= lane_mask << (index * lane_bits);
                }
            }
            expanded
        };
        cpu.write_var(dst, result);
    }

    fn packed_compare_explicit_index(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let Some(comparison) = compare_strings(
            cpu,
            args[0],
            args[1],
            cpu.args[0] as u8,
            Some((cpu.args[1] as u32, cpu.args[2] as u32)),
        )
        else {
            return;
        };
        if write_packed_string_flags(cpu, comparison).is_none() {
            return;
        }
        let index = if comparison.int_res2 == 0 {
            comparison.element_count as u32
        }
        else if cpu.args[0] & 0x40 == 0 {
            comparison.int_res2.trailing_zeros()
        }
        else {
            u16::BITS - 1 - comparison.int_res2.leading_zeros()
        };
        cpu.write_trunc(dst, index);
    }

    fn packed_compare_explicit_mask(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let Some(comparison) = compare_strings(
            cpu,
            args[0],
            args[1],
            cpu.args[0] as u8,
            Some((cpu.args[1] as u32, cpu.args[2] as u32)),
        )
        else {
            return;
        };
        if write_packed_string_flags(cpu, comparison).is_none() {
            return;
        }
        let result = if cpu.args[0] & 0x40 == 0 {
            u128::from(comparison.int_res2)
        }
        else {
            let lane_bits = if comparison.element_count == 16 { 8 } else { 16 };
            let lane_mask = (1_u128 << lane_bits) - 1;
            let mut expanded = 0_u128;
            for index in 0..comparison.element_count {
                if comparison.int_res2 & (1 << index) != 0 {
                    expanded |= lane_mask << (index * lane_bits);
                }
            }
            expanded
        };
        cpu.write_var(dst, result);
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

    fn vector_movemask_value(cpu: &mut Cpu, source: Value, lane_size: u8) -> Option<u32> {
        if source.size() != 16 || source.size() % lane_size != 0 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(source.size());
            return None;
        }
        let mut result = 0_u32;
        for lane in 0..source.size() / lane_size {
            let sign_byte = source.slice(lane * lane_size + lane_size - 1, 1);
            result |= u32::from(cpu.read::<u8>(sign_byte) >> 7) << lane;
        }
        Some(result)
    }

    fn vmovmskpd(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if let Some(result) = vector_movemask_value(cpu, args[0], 8) {
            cpu.write_var(VarNode::new(dst.id, 8), u64::from(result));
        }
    }

    fn vmovmskps(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if let Some(result) = vector_movemask_value(cpu, args[0], 4) {
            cpu.write_var(VarNode::new(dst.id, 8), u64::from(result));
        }
    }

    fn vector_movemask_256(cpu: &mut Cpu, dst: VarNode, args: [Value; 2], lane_size: u8) {
        let Some(low) = vector_movemask_value(cpu, args[0], lane_size)
        else {
            return;
        };
        let Some(high) = vector_movemask_value(cpu, args[1], lane_size)
        else {
            return;
        };
        let lanes_per_chunk = 16 / u32::from(lane_size);
        cpu.write_var(VarNode::new(dst.id, 8), u64::from(low | (high << lanes_per_chunk)));
    }

    fn vmovmskpd_256(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        vector_movemask_256(cpu, dst, args, 8);
    }

    fn vmovmskps_256(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        vector_movemask_256(cpu, dst, args, 4);
    }

    fn vmovhlps(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 16 || args[0].size() != 16 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let low = cpu.read::<u64>(args[1].slice(8, 8));
        let high = cpu.read::<u64>(args[0].slice(8, 8));
        cpu.write_var(dst.slice(0, 8), low);
        cpu.write_var(dst.slice(8, 8), high);
    }

    fn vmovlhps(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 16 || args[0].size() != 16 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let low = cpu.read::<u64>(args[0].slice(0, 8));
        let high = cpu.read::<u64>(args[1].slice(0, 8));
        cpu.write_var(dst.slice(0, 8), low);
        cpu.write_var(dst.slice(8, 8), high);
    }

    fn vmov_high64(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        match dst.size {
            8 if args[0].size() == 16 => {
                cpu.write_var(dst, cpu.read::<u64>(args[0].slice(8, 8)));
            }
            16 if args[0].size() == 16 && args[1].size() == 8 => {
                let low = cpu.read::<u64>(args[0].slice(0, 8));
                let high = cpu.read::<u64>(args[1]);
                cpu.write_var(dst.slice(0, 8), low);
                cpu.write_var(dst.slice(8, 8), high);
            }
            _ => {
                cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
                cpu.exception.value = u64::from(dst.size);
            }
        }
    }

    fn vmov_low64(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        match dst.size {
            8 if args[0].size() == 16 => {
                cpu.write_var(dst, cpu.read::<u64>(args[0].slice(0, 8)));
            }
            16 if args[0].size() == 16 && args[1].size() == 8 => {
                let low = cpu.read::<u64>(args[1]);
                let high = cpu.read::<u64>(args[0].slice(8, 8));
                cpu.write_var(dst.slice(0, 8), low);
                cpu.write_var(dst.slice(8, 8), high);
            }
            _ => {
                cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
                cpu.exception.value = u64::from(dst.size);
            }
        }
    }

    fn vpermil(cpu: &mut Cpu, dst: VarNode, args: [Value; 2], lane_size: u8) {
        if dst.size != 16 || !matches!(lane_size, 4 | 8) {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let lanes = 16 / lane_size;
        if args[1].size() == 1 {
            if args[0].size() != 16 {
                cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
                cpu.exception.value = u64::from(args[0].size());
                return;
            }
            let immediate = cpu.read::<u8>(args[1]);
            let chunk = cpu.args[7] as u8;
            for lane in 0..lanes {
                let bits = if lane_size == 4 { 2 } else { 1 };
                let control_lane = chunk * lanes + lane;
                let source_lane = (immediate >> (control_lane * bits)) & ((1 << bits) - 1);
                let value: u64 =
                    cpu.read_dynamic(args[0].slice(source_lane * lane_size, lane_size)).zxt();
                cpu.write_trunc(dst.slice(lane * lane_size, lane_size), value);
            }
        }
        else {
            if args[0].size() != 16 || args[1].size() != 16 {
                cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
                cpu.exception.value = u64::from(args[1].size());
                return;
            }
            for lane in 0..lanes {
                let control: u64 =
                    cpu.read_dynamic(args[1].slice(lane * lane_size, lane_size)).zxt();
                let source_lane =
                    if lane_size == 4 { control as u8 & 3 } else { (control as u8 >> 1) & 1 };
                let value: u64 =
                    cpu.read_dynamic(args[0].slice(source_lane * lane_size, lane_size)).zxt();
                cpu.write_trunc(dst.slice(lane * lane_size, lane_size), value);
            }
        }
    }

    fn vpermilpd(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        vpermil(cpu, dst, args, 8);
    }

    fn vpermilps(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        vpermil(cpu, dst, args, 4);
    }

    fn vldmxcsr(cpu: &mut Cpu, _dst: VarNode, args: [Value; 2]) {
        let value = cpu.read::<u32>(args[0]);
        if value & !MXCSR_MASK != 0 {
            cpu.exception.code = ExceptionCode::GeneralProtection as u32;
            cpu.exception.value = 0;
            return;
        }
        let _ = write_named(cpu, "MXCSR", value);
    }

    fn vstmxcsr(cpu: &mut Cpu, dst: VarNode, _args: [Value; 2]) {
        if let Some(value) = read_named::<u32>(cpu, "MXCSR") {
            cpu.write_var(dst, value);
        }
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

    fn rounding_control(cpu: &mut Cpu, immediate: u8) -> (u8, bool, bool) {
        let mxcsr = read_named::<u32>(cpu, "MXCSR").unwrap_or(0x1f80);
        let mode = if immediate & 4 != 0 { ((mxcsr >> 13) & 3) as u8 } else { immediate & 3 };
        (mode, mxcsr & (1 << 6) != 0, immediate & 8 != 0)
    }

    fn round_f64_bits(bits: u64, mode: u8, denormals_are_zero: bool) -> (u64, u32) {
        let sign = bits & (1_u64 << 63);
        let exponent = bits & 0x7ff0_0000_0000_0000;
        let fraction = bits & 0x000f_ffff_ffff_ffff;
        if exponent == 0x7ff0_0000_0000_0000 {
            if fraction == 0 {
                return (bits, 0);
            }
            let signaling = bits & 0x0008_0000_0000_0000 == 0;
            return (bits | u64::from(signaling) * 0x0008_0000_0000_0000, u32::from(signaling));
        }
        let subnormal = exponent == 0 && fraction != 0;
        let effective = if subnormal && denormals_are_zero { sign } else { bits };
        let value = f64::from_bits(effective);
        let rounded = match mode {
            0 => value.round_ties_even(),
            1 => value.floor(),
            2 => value.ceil(),
            _ => value.trunc(),
        };
        let inexact = rounded != value;
        let flags = (u32::from(subnormal && !denormals_are_zero) << 1) | (u32::from(inexact) << 5);
        (rounded.to_bits(), flags)
    }

    fn round_f32_bits(bits: u32, mode: u8, denormals_are_zero: bool) -> (u32, u32) {
        let sign = bits & (1_u32 << 31);
        let exponent = bits & 0x7f80_0000;
        let fraction = bits & 0x007f_ffff;
        if exponent == 0x7f80_0000 {
            if fraction == 0 {
                return (bits, 0);
            }
            let signaling = bits & 0x0040_0000 == 0;
            return (bits | u32::from(signaling) * 0x0040_0000, u32::from(signaling));
        }
        let subnormal = exponent == 0 && fraction != 0;
        let effective = if subnormal && denormals_are_zero { sign } else { bits };
        let value = f32::from_bits(effective);
        let rounded = match mode {
            0 => value.round_ties_even(),
            1 => value.floor(),
            2 => value.ceil(),
            _ => value.trunc(),
        };
        let inexact = rounded != value;
        let flags = (u32::from(subnormal && !denormals_are_zero) << 1) | (u32::from(inexact) << 5);
        (rounded.to_bits(), flags)
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
        let (mode, daz, suppress_precision) = rounding_control(cpu, imm);
        let upper = u128::from_le_bytes(upper);
        let (rounded, mut flags) = round_f64_bits(cpu.read::<u64>(args[1].slice(0, 8)), mode, daz);
        if suppress_precision {
            flags &= !(1 << 5);
        }
        write_xmm(cpu, dst, ((upper & !0xffff_ffff_ffff_ffffu128) | rounded as u128).to_le_bytes());
        raise_mxcsr_flags(cpu, flags);
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
        let (mode, daz, suppress_precision) = rounding_control(cpu, imm);
        let upper = u128::from_le_bytes(upper);
        let (rounded, mut flags) = round_f32_bits(cpu.read::<u32>(args[1].slice(0, 4)), mode, daz);
        if suppress_precision {
            flags &= !(1 << 5);
        }
        write_xmm(cpu, dst, ((upper & !0xffff_ffffu128) | rounded as u128).to_le_bytes());
        raise_mxcsr_flags(cpu, flags);
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

    fn packed_mul_low_w_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 16 || args[0].size() != 16 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        for lane in 0..8_u8 {
            let offset = lane * 2;
            let left = cpu.read::<u16>(args[0].slice(offset, 2));
            let right = cpu.read::<u16>(args[1].slice(offset, 2));
            cpu.write_var(dst.slice(offset, 2), left.wrapping_mul(right));
        }
    }

    fn packed_unpack_w_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2], high: bool) {
        if dst.size != 16 || args[0].size() != 16 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let source_start = if high { 4_u8 } else { 0_u8 };
        for lane in 0..4_u8 {
            let source_offset = (source_start + lane) * 2;
            let destination_offset = lane * 4;
            let left = cpu.read::<u16>(args[0].slice(source_offset, 2));
            let right = cpu.read::<u16>(args[1].slice(source_offset, 2));
            cpu.write_var(dst.slice(destination_offset, 2), left);
            cpu.write_var(dst.slice(destination_offset + 2, 2), right);
        }
    }

    fn packed_unpack_low_w_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_unpack_w_128(cpu, dst, args, false);
    }

    fn packed_unpack_high_w_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_unpack_w_128(cpu, dst, args, true);
    }

    fn packed_unpack_lanes_128(
        cpu: &mut Cpu,
        dst: VarNode,
        args: [Value; 2],
        element_size: u8,
        high: bool,
    ) {
        if dst.size != 16
            || args[0].size() != 16
            || args[1].size() != 16
            || !matches!(element_size, 1 | 4)
        {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let lanes_per_half = 8 / element_size;
        let source_base = if high { 8 } else { 0 };
        for lane in 0..lanes_per_half {
            let source_offset = source_base + lane * element_size;
            let destination_offset = lane * element_size * 2;
            let left: u64 = cpu.read_dynamic(args[0].slice(source_offset, element_size)).zxt();
            let right: u64 = cpu.read_dynamic(args[1].slice(source_offset, element_size)).zxt();
            cpu.write_trunc(dst.slice(destination_offset, element_size), left);
            cpu.write_trunc(dst.slice(destination_offset + element_size, element_size), right);
        }
    }

    fn packed_unpack_high_b_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_unpack_lanes_128(cpu, dst, args, 1, true);
    }

    fn packed_unpack_low_b_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_unpack_lanes_128(cpu, dst, args, 1, false);
    }

    fn packed_unpack_high_d_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_unpack_lanes_128(cpu, dst, args, 4, true);
    }

    fn packed_unpack_low_d_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_unpack_lanes_128(cpu, dst, args, 4, false);
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
            // Packed shifts consume the low unsigned qword of an XMM count
            // operand; bits 127:64 do not participate in the count.
            16 => u128::from(cpu.read::<u64>(v.slice(0, 8))),
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

    fn packed_shift_right_w(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let count = simd_shift_count(cpu, args[1]);
        for i in (0..dst.size).step_by(2) {
            let word: u16 = cpu.read(args[0].slice(i, 2));
            cpu.write_var(dst.slice(i, 2), if count >= 16 { 0 } else { word >> count });
        }
    }

    fn packed_shift_right_q_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 16 || args[0].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let count = simd_shift_count(cpu, args[1]);
        for offset in [0_u8, 8] {
            let value = cpu.read::<u64>(args[0].slice(offset, 8));
            cpu.write_var(dst.slice(offset, 8), if count >= 64 { 0 } else { value >> count });
        }
    }

    fn packed_shift_right_d(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let count = simd_shift_count(cpu, args[1]);
        for i in (0..dst.size).step_by(4) {
            let dword: u32 = cpu.read(args[0].slice(i, 4));
            cpu.write_var(dst.slice(i, 4), if count >= 32 { 0 } else { dword >> count });
        }
    }

    fn packed_shift_left_d(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let count = simd_shift_count(cpu, args[1]);
        for i in (0..dst.size).step_by(4) {
            let dword: u32 = cpu.read(args[0].slice(i, 4));
            cpu.write_var(dst.slice(i, 4), if count >= 32 { 0 } else { dword << count });
        }
    }

    fn packed_shift_left_q(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != args[0].size() || dst.size % 8 != 0 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let count = simd_shift_count(cpu, args[1]);
        for offset in (0..dst.size).step_by(8) {
            let value = cpu.read::<u64>(args[0].slice(offset, 8));
            cpu.write_var(dst.slice(offset, 8), if count >= 64 { 0 } else { value << count });
        }
    }

    /// VPSRLDQ shifts each architectural 128-bit lane independently. Counts
    /// greater than 15 zero the complete lane rather than crossing a lane
    /// boundary.
    fn packed_shift_right_lane_bytes(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let count = simd_shift_count(cpu, args[1]).min(16) as u8;
        for lane in (0..dst.size).step_by(16) {
            for byte in 0_u8..16 {
                let value = if byte + count < 16 {
                    cpu.read::<u8>(args[0].slice(lane + byte + count, 1))
                }
                else {
                    0
                };
                cpu.write_var(dst.slice(lane + byte, 1), value);
            }
        }
    }

    fn packed_shift_left_lane_bytes(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 16 || args[0].size() != 16 || args[1].size() != 1 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let count = cpu.read::<u8>(args[1]);
        let result =
            if count >= 16 { 0 } else { cpu.read::<u128>(args[0]) << (u32::from(count) * 8) };
        cpu.write_var(dst, result);
    }

    fn packed_shift_variable_d(cpu: &mut Cpu, dst: VarNode, args: [Value; 2], left: bool) {
        for i in (0..dst.size).step_by(4) {
            let value: u32 = cpu.read(args[0].slice(i, 4));
            let count: u32 = cpu.read(args[1].slice(i, 4));
            let result = if count >= 32 {
                0
            }
            else if left {
                value << count
            }
            else {
                value >> count
            };
            cpu.write_var(dst.slice(i, 4), result);
        }
    }

    fn packed_shift_left_variable_d(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_shift_variable_d(cpu, dst, args, true);
    }

    fn packed_shift_right_variable_d(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_shift_variable_d(cpu, dst, args, false);
    }

    fn packed_shift_variable_128(
        cpu: &mut Cpu,
        dst: VarNode,
        args: [Value; 2],
        element_size: u8,
        direction: i8,
    ) {
        if dst.size != 16
            || args[0].size() != 16
            || args[1].size() != 16
            || !matches!(element_size, 2 | 4 | 8)
            || !matches!(direction, -1 | 0 | 1)
        {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let bits = u32::from(element_size) * 8;
        for offset in (0_u8..16).step_by(usize::from(element_size)) {
            let value: u64 = cpu.read_dynamic(args[0].slice(offset, element_size)).zxt();
            let count: u64 = cpu.read_dynamic(args[1].slice(offset, element_size)).zxt();
            let result = match direction {
                1 => {
                    if count >= u64::from(bits) {
                        0
                    }
                    else {
                        value << count
                    }
                }
                -1 => {
                    if count >= u64::from(bits) {
                        0
                    }
                    else {
                        value >> count
                    }
                }
                0 => {
                    let shift = 64 - bits;
                    let signed = ((value << shift) as i64) >> shift;
                    let count = count.min(u64::from(bits - 1)) as u32;
                    (signed >> count) as u64
                }
                _ => unreachable!(),
            };
            cpu.write_trunc(dst.slice(offset, element_size), result);
        }
    }

    fn packed_shift_left_variable_q_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_shift_variable_128(cpu, dst, args, 8, 1);
    }

    fn packed_shift_left_variable_w_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_shift_variable_128(cpu, dst, args, 2, 1);
    }

    fn packed_shift_right_variable_q_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_shift_variable_128(cpu, dst, args, 8, -1);
    }

    fn packed_shift_right_variable_w_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_shift_variable_128(cpu, dst, args, 2, -1);
    }

    fn packed_shift_right_arithmetic_variable_d_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_shift_variable_128(cpu, dst, args, 4, 0);
    }

    fn packed_shift_right_arithmetic_variable_q_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_shift_variable_128(cpu, dst, args, 8, 0);
    }

    fn packed_shift_right_arithmetic_variable_w_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_shift_variable_128(cpu, dst, args, 2, 0);
    }

    fn packed_shift_right_arithmetic_128(
        cpu: &mut Cpu,
        dst: VarNode,
        args: [Value; 2],
        element_size: u8,
    ) {
        if dst.size != 16 || args[0].size() != 16 || !matches!(element_size, 4 | 8) {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let bits = u32::from(element_size) * 8;
        let count = simd_shift_count(cpu, args[1]).min(bits - 1);
        for offset in (0_u8..16).step_by(usize::from(element_size)) {
            let value: u64 = cpu.read_dynamic(args[0].slice(offset, element_size)).zxt();
            let shift = 64 - bits;
            let signed = ((value << shift) as i64) >> shift;
            cpu.write_trunc(dst.slice(offset, element_size), (signed >> count) as u64);
        }
    }

    fn packed_shift_right_arithmetic_d_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_shift_right_arithmetic_128(cpu, dst, args, 4);
    }

    fn packed_shift_right_arithmetic_q_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_shift_right_arithmetic_128(cpu, dst, args, 8);
    }

    fn packed_rotate_128(
        cpu: &mut Cpu,
        dst: VarNode,
        args: [Value; 2],
        element_size: u8,
        left: bool,
    ) {
        if dst.size != 16
            || args[0].size() != 16
            || !matches!(args[1].size(), 1 | 16)
            || !matches!(element_size, 4 | 8)
        {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let bits = u32::from(element_size) * 8;
        let mask = if bits == 64 { u64::MAX } else { (1_u64 << bits) - 1 };
        for offset in (0_u8..16).step_by(usize::from(element_size)) {
            let value: u64 = cpu.read_dynamic(args[0].slice(offset, element_size)).zxt();
            let raw_count: u64 = if args[1].size() == 1 {
                u64::from(cpu.read::<u8>(args[1]))
            }
            else {
                cpu.read_dynamic(args[1].slice(offset, element_size)).zxt()
            };
            let count = (raw_count as u32) & (bits - 1);
            let result = if count == 0 {
                value
            }
            else if left {
                (value << count) | (value >> (bits - count))
            }
            else {
                (value >> count) | (value << (bits - count))
            };
            cpu.write_trunc(dst.slice(offset, element_size), result & mask);
        }
    }

    fn packed_rotate_left_d_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_rotate_128(cpu, dst, args, 4, true);
    }

    fn packed_rotate_left_q_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_rotate_128(cpu, dst, args, 8, true);
    }

    fn packed_rotate_right_d_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_rotate_128(cpu, dst, args, 4, false);
    }

    fn packed_rotate_right_q_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_rotate_128(cpu, dst, args, 8, false);
    }

    fn packed_leading_zeros_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2], element_size: u8) {
        if dst.size != 16 || args[0].size() != 16 || !matches!(element_size, 4 | 8) {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let unused_bits = 64 - u32::from(element_size) * 8;
        for offset in (0_u8..16).step_by(usize::from(element_size)) {
            let value: u64 = cpu.read_dynamic(args[0].slice(offset, element_size)).zxt();
            cpu.write_trunc(
                dst.slice(offset, element_size),
                u64::from(value.leading_zeros() - unused_bits),
            );
        }
    }

    fn packed_leading_zeros_d_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_leading_zeros_128(cpu, dst, args, 4);
    }

    fn packed_leading_zeros_q_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_leading_zeros_128(cpu, dst, args, 8);
    }

    /// Computes one 128-bit chunk of an EVEX variable dword shift whose
    /// count vector is in memory. SLEIGH passes the address rather than
    /// materializing the vector so inactive mask elements suppress faults.
    fn packed_shift_variable_d_mem_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 16 || args[0].size() != 8 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let address = cpu.read::<u64>(args[0]);
        let values = cpu.read::<u128>(args[1]).to_le_bytes();
        let mut output = cpu.args[0].to_le_bytes();
        let mask = cpu.args[1] as u64;
        let chunk = cpu.args[2] as usize;
        let left = cpu.args[3] != 0;
        let broadcast = cpu.args[4] != 0;
        if chunk >= 4 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = chunk as u64;
            return;
        }

        for lane in 0..4 {
            let global_lane = chunk * 4 + lane;
            if mask & (1_u64 << global_lane) == 0 {
                continue;
            }
            let source_offset = if broadcast { 0 } else { global_lane * 4 };
            let mut count_bytes = [0_u8; 4];
            for (byte, output_byte) in count_bytes.iter_mut().enumerate() {
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
            let count = u32::from_le_bytes(count_bytes);
            let start = lane * 4;
            let value = u32::from_le_bytes(values[start..start + 4].try_into().unwrap());
            let result = if count >= 32 {
                0
            }
            else if left {
                value << count
            }
            else {
                value >> count
            };
            output[start..start + 4].copy_from_slice(&result.to_le_bytes());
        }
        cpu.write_var(dst, u128::from_le_bytes(output));
    }

    fn packed_abs(cpu: &mut Cpu, dst: VarNode, source: Value, element_size: u8) {
        if dst.size == 0
            || dst.size > 64
            || dst.size != source.size()
            || dst.size % element_size != 0
            || !matches!(element_size, 1 | 2 | 4 | 8)
        {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        for offset in (0..dst.size).step_by(usize::from(element_size)) {
            let source = source.slice(offset, element_size);
            let destination = dst.slice(offset, element_size);
            match element_size {
                1 => cpu.write_var(destination, (cpu.read::<u8>(source) as i8).unsigned_abs()),
                2 => cpu.write_var(destination, (cpu.read::<u16>(source) as i16).unsigned_abs()),
                4 => cpu.write_var(destination, (cpu.read::<u32>(source) as i32).unsigned_abs()),
                8 => cpu.write_var(destination, (cpu.read::<u64>(source) as i64).unsigned_abs()),
                _ => unreachable!(),
            }
        }
    }

    fn packed_abs_b(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_abs(cpu, dst, args[0], 1);
    }

    fn packed_abs_w(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_abs(cpu, dst, args[0], 2);
    }

    fn packed_abs_d(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_abs(cpu, dst, args[0], 4);
    }

    fn packed_abs_q(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_abs(cpu, dst, args[0], 8);
    }

    fn packed_add_w_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 16 || args[0].size() != 16 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        for offset in (0_u8..16).step_by(2) {
            let lhs = cpu.read::<u16>(args[0].slice(offset, 2));
            let rhs = cpu.read::<u16>(args[1].slice(offset, 2));
            cpu.write_var(dst.slice(offset, 2), lhs.wrapping_add(rhs));
        }
    }

    fn packed_add_b(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if args[0].size() != dst.size || args[1].size() != dst.size {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        for offset in 0..dst.size {
            let lhs = cpu.read::<u8>(args[0].slice(offset, 1));
            let rhs = cpu.read::<u8>(args[1].slice(offset, 1));
            cpu.write_var(dst.slice(offset, 1), lhs.wrapping_add(rhs));
        }
    }

    fn packed_add_q_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 16 || args[0].size() != 16 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        for offset in [0_u8, 8] {
            let lhs = cpu.read::<u64>(args[0].slice(offset, 8));
            let rhs = cpu.read::<u64>(args[1].slice(offset, 8));
            cpu.write_var(dst.slice(offset, 8), lhs.wrapping_add(rhs));
        }
    }

    fn packed_sum_absolute_differences_b_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 16 || args[0].size() != 16 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        for group in 0_u8..2 {
            let mut sum = 0_u64;
            for lane in 0_u8..8 {
                let offset = group * 8 + lane;
                let lhs = cpu.read::<u8>(args[0].slice(offset, 1));
                let rhs = cpu.read::<u8>(args[1].slice(offset, 1));
                sum += u64::from(lhs.abs_diff(rhs));
            }
            cpu.write_var(dst.slice(group * 8, 8), sum);
        }
    }

    fn packed_extract_128_256(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 16 || args[0].size() != 16 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let source = [cpu.read::<u128>(args[0]), cpu.read::<u128>(args[1])];
        let value = source[cpu.args[0] as usize & 1];
        cpu.write_var(dst, value);
    }

    fn packed_extract_128_512(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 16 || args[0].size() != 16 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let source =
            [cpu.read::<u128>(args[0]), cpu.read::<u128>(args[1]), cpu.args[0], cpu.args[1]];
        let value = source[cpu.args[2] as usize & 3];
        cpu.write_var(dst, value);
    }

    fn packed_sub_b_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 16 || args[0].size() != 16 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        for offset in 0_u8..16 {
            let lhs = cpu.read::<u8>(args[0].slice(offset, 1));
            let rhs = cpu.read::<u8>(args[1].slice(offset, 1));
            cpu.write_var(dst.slice(offset, 1), lhs.wrapping_sub(rhs));
        }
    }

    fn packed_sub_w(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 16 || args[0].size() != 16 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        for offset in (0_u8..16).step_by(2) {
            let lhs = cpu.read::<u16>(args[0].slice(offset, 2));
            let rhs = cpu.read::<u16>(args[1].slice(offset, 2));
            cpu.write_var(dst.slice(offset, 2), lhs.wrapping_sub(rhs));
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

    fn packed_unpack_high_q_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 16 || args[0].size() != 16 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let left = cpu.read::<u64>(args[0].slice(8, 8));
        let right = cpu.read::<u64>(args[1].slice(8, 8));
        cpu.write_var(dst.slice(0, 8), left);
        cpu.write_var(dst.slice(8, 8), right);
    }

    fn packed_shuffle_d_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 16 || args[0].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let immediate = cpu.read::<u8>(args[1]);
        let source = cpu.read::<u128>(args[0]).to_le_bytes();
        let mut output = [0_u8; 16];
        for lane in 0..4 {
            let source_lane = usize::from((immediate >> (lane * 2)) & 0x3);
            output[lane * 4..lane * 4 + 4]
                .copy_from_slice(&source[source_lane * 4..source_lane * 4 + 4]);
        }
        cpu.write_var(dst, u128::from_le_bytes(output));
    }

    fn packed_shuffle_w_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2], high: bool) {
        if dst.size != 16 || args[0].size() != 16 || args[1].size() != 1 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let immediate = cpu.read::<u8>(args[1]);
        let source = cpu.read::<u128>(args[0]).to_le_bytes();
        let mut output = source;
        let base = usize::from(high) * 8;
        for lane in 0..4 {
            let source_lane = usize::from((immediate >> (lane * 2)) & 0x3);
            output[base + lane * 2..base + lane * 2 + 2]
                .copy_from_slice(&source[base + source_lane * 2..base + source_lane * 2 + 2]);
        }
        cpu.write_var(dst, u128::from_le_bytes(output));
    }

    fn packed_shuffle_high_w_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_shuffle_w_128(cpu, dst, args, true);
    }

    fn packed_shuffle_low_w_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_shuffle_w_128(cpu, dst, args, false);
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

    /// Execute host floating-point operations under the guest's MXCSR control
    /// and merge the resulting sticky exception flags back into the guest.
    /// All exceptions stay masked while the helper runs; architectural trap
    /// delivery is handled by the x86 frontend rather than leaking a host
    /// SIGFPE into the emulator process.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[allow(deprecated)]
    fn with_guest_mxcsr(cpu: &mut Cpu, operation: impl FnOnce(&mut Cpu)) {
        #[cfg(target_arch = "x86")]
        use std::arch::x86::{_mm_getcsr, _mm_setcsr};
        #[cfg(target_arch = "x86_64")]
        use std::arch::x86_64::{_mm_getcsr, _mm_setcsr};

        let Some(guest_mxcsr) = read_named::<u32>(cpu, "MXCSR")
        else {
            return;
        };
        let host_mxcsr = unsafe { _mm_getcsr() };
        // Clear sticky status and force every exception mask on, while
        // preserving guest rounding, DAZ and FTZ controls.
        unsafe { _mm_setcsr((guest_mxcsr & !0x3f) | 0x1f80) };
        operation(cpu);
        let status = unsafe { _mm_getcsr() } & 0x3f;
        unsafe { _mm_setcsr(host_mxcsr) };
        let _ = write_named(cpu, "MXCSR", guest_mxcsr | status);
    }

    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    fn with_guest_mxcsr(cpu: &mut Cpu, operation: impl FnOnce(&mut Cpu)) {
        operation(cpu);
    }

    fn packed_fma(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 16 || args[0].size() != 16 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let pc = cpu.read_pc();
        let Some(prefix_offset) = current_evex_prefix_offset(cpu)
        else {
            cpu.exception.code = ExceptionCode::UnimplementedOp as u32;
            return;
        };
        let Some(opcode) = read_instruction_byte(cpu, pc, prefix_offset + 4)
        else {
            cpu.exception.code = ExceptionCode::UnimplementedOp as u32;
            return;
        };
        let Some(p1) = read_instruction_byte(cpu, pc, prefix_offset + 2)
        else {
            cpu.exception.code = ExceptionCode::UnimplementedOp as u32;
            return;
        };
        let order = match opcode >> 4 {
            0x9 => 132,
            0xa => 213,
            0xb => 231,
            _ => {
                cpu.exception.code = ExceptionCode::UnimplementedOp as u32;
                cpu.exception.value = u64::from(opcode);
                return;
            }
        };
        let kind = opcode & 0x0f;
        if !matches!(kind, 0x6..=0xf) {
            cpu.exception.code = ExceptionCode::UnimplementedOp as u32;
            cpu.exception.value = u64::from(opcode);
            return;
        }
        let scalar = matches!(kind, 0x9 | 0xb | 0xd | 0xf);
        let lane_bytes = if p1 & 0x80 != 0 { 8 } else { 4 };
        let lane_count = if scalar { 1 } else { 16 / lane_bytes };
        let chunk = cpu.args[7] as usize;
        let mask = current_evex_mask(cpu);
        let old_destination = cpu.read::<u128>(args[0]).to_le_bytes();
        let second = cpu.read::<u128>(args[1]).to_le_bytes();
        let third = cpu.args[0].to_le_bytes();
        let mut output = if scalar { second } else { [0_u8; 16] };

        with_guest_mxcsr(cpu, |cpu| {
            for lane in 0..lane_count {
                if mask & (1_u64 << (chunk * (16 / lane_bytes) + lane)) == 0 {
                    continue;
                }
                let offset = lane * lane_bytes;
                if lane_bytes == 8 {
                    let destination = f64::from_bits(u64::from_le_bytes(
                        old_destination[offset..offset + 8].try_into().unwrap(),
                    ));
                    let source1 = f64::from_bits(u64::from_le_bytes(
                        second[offset..offset + 8].try_into().unwrap(),
                    ));
                    let source2 = f64::from_bits(u64::from_le_bytes(
                        third[offset..offset + 8].try_into().unwrap(),
                    ));
                    let (multiplicand, multiplier, addend) = match order {
                        132 => (destination, source2, source1),
                        213 => (source1, destination, source2),
                        231 => (source1, source2, destination),
                        _ => unreachable!(),
                    };
                    let subtract = match kind {
                        0x6 => (chunk * 2 + lane) % 2 == 0,
                        0x7 => (chunk * 2 + lane) % 2 != 0,
                        0xa | 0xb | 0xe | 0xf => true,
                        _ => false,
                    };
                    let negate_product = matches!(kind, 0xc..=0xf);
                    let a = if negate_product { -multiplicand } else { multiplicand };
                    let c = if subtract { -addend } else { addend };
                    output[offset..offset + 8]
                        .copy_from_slice(&a.mul_add(multiplier, c).to_bits().to_le_bytes());
                }
                else {
                    let destination = f32::from_bits(u32::from_le_bytes(
                        old_destination[offset..offset + 4].try_into().unwrap(),
                    ));
                    let source1 = f32::from_bits(u32::from_le_bytes(
                        second[offset..offset + 4].try_into().unwrap(),
                    ));
                    let source2 = f32::from_bits(u32::from_le_bytes(
                        third[offset..offset + 4].try_into().unwrap(),
                    ));
                    let (multiplicand, multiplier, addend) = match order {
                        132 => (destination, source2, source1),
                        213 => (source1, destination, source2),
                        231 => (source1, source2, destination),
                        _ => unreachable!(),
                    };
                    let subtract = match kind {
                        0x6 => (chunk * 4 + lane) % 2 == 0,
                        0x7 => (chunk * 4 + lane) % 2 != 0,
                        0xa | 0xb | 0xe | 0xf => true,
                        _ => false,
                    };
                    let negate_product = matches!(kind, 0xc..=0xf);
                    let a = if negate_product { -multiplicand } else { multiplicand };
                    let c = if subtract { -addend } else { addend };
                    let result = a.mul_add(multiplier, c);
                    output[offset..offset + 4].copy_from_slice(&result.to_bits().to_le_bytes());
                }
            }
            write_xmm(cpu, dst, output);
        });
    }

    fn f64x2_binop(cpu: &mut Cpu, dst: VarNode, args: [Value; 2], f: fn(f64, f64) -> f64) {
        f64x2_binop_masked(cpu, dst, args, u64::MAX, 0, f);
    }

    fn f64x2_binop_masked(
        cpu: &mut Cpu,
        dst: VarNode,
        args: [Value; 2],
        mask: u64,
        chunk: usize,
        f: fn(f64, f64) -> f64,
    ) {
        let Some(a) = xmm_bytes(cpu, args[0])
        else {
            return;
        };
        let Some(b) = xmm_bytes(cpu, args[1])
        else {
            return;
        };
        with_guest_mxcsr(cpu, |cpu| {
            let mut out = [0u8; 16];
            for i in 0..2 {
                if mask & (1 << (chunk * 2 + i)) == 0 {
                    continue;
                }
                let x = f64::from_bits(u64::from_le_bytes(a[8 * i..8 * i + 8].try_into().unwrap()));
                let y = f64::from_bits(u64::from_le_bytes(b[8 * i..8 * i + 8].try_into().unwrap()));
                out[8 * i..8 * i + 8].copy_from_slice(&f(x, y).to_bits().to_le_bytes());
            }
            write_xmm(cpu, dst, out);
        });
    }

    fn f32x4_binop(cpu: &mut Cpu, dst: VarNode, args: [Value; 2], f: fn(f32, f32) -> f32) {
        f32x4_binop_masked(cpu, dst, args, u64::MAX, 0, f);
    }

    fn f32x4_binop_masked(
        cpu: &mut Cpu,
        dst: VarNode,
        args: [Value; 2],
        mask: u64,
        chunk: usize,
        f: fn(f32, f32) -> f32,
    ) {
        let Some(a) = xmm_bytes(cpu, args[0])
        else {
            return;
        };
        let Some(b) = xmm_bytes(cpu, args[1])
        else {
            return;
        };
        with_guest_mxcsr(cpu, |cpu| {
            let mut out = [0u8; 16];
            for i in 0..4 {
                if mask & (1 << (chunk * 4 + i)) == 0 {
                    continue;
                }
                let x = f32::from_bits(u32::from_le_bytes(a[4 * i..4 * i + 4].try_into().unwrap()));
                let y = f32::from_bits(u32::from_le_bytes(b[4 * i..4 * i + 4].try_into().unwrap()));
                out[4 * i..4 * i + 4].copy_from_slice(&f(x, y).to_bits().to_le_bytes());
            }
            write_xmm(cpu, dst, out);
        });
    }

    fn current_evex_prefix_offset(cpu: &mut Cpu) -> Option<usize> {
        let pc = cpu.read_pc();
        for offset in 0..15 {
            match read_instruction_byte(cpu, pc, offset)? {
                0x62 => return Some(offset),
                0x67 | 0x64 | 0x65 | 0x2e | 0x3e | 0x26 | 0x36 => {}
                _ => return None,
            }
        }
        None
    }

    fn current_evex_mask(cpu: &mut Cpu) -> u64 {
        let Some(offset) = current_evex_prefix_offset(cpu)
        else {
            return u64::MAX;
        };
        let Some(p2) = read_instruction_byte(cpu, cpu.read_pc(), offset + 3)
        else {
            return u64::MAX;
        };
        let selector = p2 & 7;
        if selector == 0 {
            return u64::MAX;
        }
        read_named::<u64>(cpu, &format!("K{selector}")).unwrap_or(0)
    }

    fn current_evex_embedded_rounding(cpu: &mut Cpu) -> Option<u8> {
        let pc = cpu.read_pc();
        let offset = current_evex_prefix_offset(cpu)?;
        let p2 = read_instruction_byte(cpu, pc, offset + 3)?;
        let modrm = read_instruction_byte(cpu, pc, offset + 5)?;
        (p2 & 0x10 != 0 && modrm >> 6 == 3).then_some((p2 >> 5) & 3)
    }

    fn masked_binary_context(cpu: &mut Cpu) -> (u64, usize) {
        (current_evex_mask(cpu), cpu.args[7] as usize)
    }

    fn raise_mxcsr_flags(cpu: &mut Cpu, flags: u32) {
        if flags == 0 {
            return;
        }
        if let Some(mxcsr) = read_named::<u32>(cpu, "MXCSR") {
            let _ = write_named(cpu, "MXCSR", mxcsr | flags);
        }
    }

    fn packed_sqrt_is_invalid(
        cpu: &mut Cpu,
        source: Value,
        lane_bytes: usize,
        mask: u64,
        chunk: usize,
    ) -> bool {
        let lanes = 16 / lane_bytes;
        (0..lanes).any(|lane| {
            if mask & (1 << (chunk * lanes + lane)) == 0 {
                return false;
            }
            let offset = (lane * lane_bytes) as u8;
            match lane_bytes {
                4 => {
                    let bits = cpu.read::<u32>(source.slice(offset, 4));
                    let magnitude = bits & 0x7fff_ffff;
                    let negative_nonzero = bits >> 31 != 0 && magnitude != 0;
                    let signaling_nan = magnitude > 0x7f80_0000 && bits & 0x0040_0000 == 0;
                    negative_nonzero || signaling_nan
                }
                8 => {
                    let bits = cpu.read::<u64>(source.slice(offset, 8));
                    let magnitude = bits & 0x7fff_ffff_ffff_ffff;
                    let negative_nonzero = bits >> 63 != 0 && magnitude != 0;
                    let signaling_nan =
                        magnitude > 0x7ff0_0000_0000_0000 && bits & 0x0008_0000_0000_0000 == 0;
                    negative_nonzero || signaling_nan
                }
                _ => unreachable!("packed sqrt has a fixed IEEE lane width"),
            }
        })
    }

    fn divpd(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        f64x2_binop(cpu, dst, args, |x, y| x / y);
    }
    fn divpd_masked(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let (mask, chunk) = masked_binary_context(cpu);
        f64x2_binop_masked(cpu, dst, args, mask, chunk, |x, y| x / y);
    }
    fn divps(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        f32x4_binop(cpu, dst, args, |x, y| x / y);
    }
    fn divps_masked(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let (mask, chunk) = masked_binary_context(cpu);
        f32x4_binop_masked(cpu, dst, args, mask, chunk, |x, y| x / y);
    }
    fn addpd_masked(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let (mask, chunk) = masked_binary_context(cpu);
        f64x2_binop_masked(cpu, dst, args, mask, chunk, |x, y| x + y);
    }
    fn addps_masked(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let (mask, chunk) = masked_binary_context(cpu);
        f32x4_binop_masked(cpu, dst, args, mask, chunk, |x, y| x + y);
    }
    fn addsubpd(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let (Some(a), Some(b)) = (xmm_bytes(cpu, args[0]), xmm_bytes(cpu, args[1]))
        else {
            return;
        };
        with_guest_mxcsr(cpu, |cpu| {
            let mut out = [0_u8; 16];
            for lane in 0..2 {
                let offset = lane * 8;
                let x =
                    f64::from_bits(u64::from_le_bytes(a[offset..offset + 8].try_into().unwrap()));
                let y =
                    f64::from_bits(u64::from_le_bytes(b[offset..offset + 8].try_into().unwrap()));
                let result = if lane & 1 == 0 { x - y } else { x + y };
                out[offset..offset + 8].copy_from_slice(&result.to_bits().to_le_bytes());
            }
            write_xmm(cpu, dst, out);
        });
    }
    fn addsubps(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let (Some(a), Some(b)) = (xmm_bytes(cpu, args[0]), xmm_bytes(cpu, args[1]))
        else {
            return;
        };
        with_guest_mxcsr(cpu, |cpu| {
            let mut out = [0_u8; 16];
            for lane in 0..4 {
                let offset = lane * 4;
                let x =
                    f32::from_bits(u32::from_le_bytes(a[offset..offset + 4].try_into().unwrap()));
                let y =
                    f32::from_bits(u32::from_le_bytes(b[offset..offset + 4].try_into().unwrap()));
                let result = if lane & 1 == 0 { x - y } else { x + y };
                out[offset..offset + 4].copy_from_slice(&result.to_bits().to_le_bytes());
            }
            write_xmm(cpu, dst, out);
        });
    }

    fn horizontal_ps(cpu: &mut Cpu, dst: VarNode, args: [Value; 2], subtract: bool) {
        let (Some(a), Some(b)) = (xmm_bytes(cpu, args[0]), xmm_bytes(cpu, args[1]))
        else {
            return;
        };
        with_guest_mxcsr(cpu, |cpu| {
            let mut out = [0_u8; 16];
            for (pair, source) in [a, b].into_iter().enumerate() {
                for lane in 0..2 {
                    let source_offset = lane * 8;
                    let x = f32::from_bits(u32::from_le_bytes(
                        source[source_offset..source_offset + 4].try_into().unwrap(),
                    ));
                    let y = f32::from_bits(u32::from_le_bytes(
                        source[source_offset + 4..source_offset + 8].try_into().unwrap(),
                    ));
                    let result = if subtract { x - y } else { x + y };
                    let output_offset = (pair * 2 + lane) * 4;
                    out[output_offset..output_offset + 4]
                        .copy_from_slice(&result.to_bits().to_le_bytes());
                }
            }
            write_xmm(cpu, dst, out);
        });
    }

    fn haddps(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        horizontal_ps(cpu, dst, args, false);
    }

    fn hsubps(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        horizontal_ps(cpu, dst, args, true);
    }

    fn hsubpd(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let (Some(a), Some(b)) = (xmm_bytes(cpu, args[0]), xmm_bytes(cpu, args[1]))
        else {
            return;
        };
        with_guest_mxcsr(cpu, |cpu| {
            let mut out = [0_u8; 16];
            for (lane, source) in [a, b].into_iter().enumerate() {
                let x = f64::from_bits(u64::from_le_bytes(source[0..8].try_into().unwrap()));
                let y = f64::from_bits(u64::from_le_bytes(source[8..16].try_into().unwrap()));
                out[lane * 8..lane * 8 + 8].copy_from_slice(&(x - y).to_bits().to_le_bytes());
            }
            write_xmm(cpu, dst, out);
        });
    }

    #[inline(never)]
    fn strict_mul_f32(first: f32, second: f32) -> f32 {
        std::hint::black_box(first) * std::hint::black_box(second)
    }

    #[inline(never)]
    fn strict_add_f32(first: f32, second: f32) -> f32 {
        std::hint::black_box(first) + std::hint::black_box(second)
    }

    #[inline(never)]
    fn strict_mul_f64(first: f64, second: f64) -> f64 {
        std::hint::black_box(first) * std::hint::black_box(second)
    }

    #[inline(never)]
    fn strict_add_f64(first: f64, second: f64) -> f64 {
        std::hint::black_box(first) + std::hint::black_box(second)
    }

    fn dotpd(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let (Some(a), Some(b)) = (xmm_bytes(cpu, args[0]), xmm_bytes(cpu, args[1]))
        else {
            return;
        };
        let control = cpu.args[0] as u8;
        with_guest_mxcsr(cpu, |cpu| {
            let mut products = [0.0_f64; 2];
            for lane in 0..2 {
                if control & (1 << (lane + 4)) == 0 {
                    continue;
                }
                let offset = lane * 8;
                let first =
                    f64::from_bits(u64::from_le_bytes(a[offset..offset + 8].try_into().unwrap()));
                let second =
                    f64::from_bits(u64::from_le_bytes(b[offset..offset + 8].try_into().unwrap()));
                products[lane] = strict_mul_f64(first, second);
            }
            let sum = strict_add_f64(products[0], products[1]);
            let mut output = [0_u8; 16];
            for lane in 0..2 {
                if control & (1 << lane) != 0 {
                    output[lane * 8..lane * 8 + 8].copy_from_slice(&sum.to_bits().to_le_bytes());
                }
            }
            write_xmm(cpu, dst, output);
        });
    }

    fn dotps(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let (Some(a), Some(b)) = (xmm_bytes(cpu, args[0]), xmm_bytes(cpu, args[1]))
        else {
            return;
        };
        let control = cpu.args[0] as u8;
        with_guest_mxcsr(cpu, |cpu| {
            let mut products = [0.0_f32; 4];
            for lane in 0..4 {
                if control & (1 << (lane + 4)) == 0 {
                    continue;
                }
                let offset = lane * 4;
                let first =
                    f32::from_bits(u32::from_le_bytes(a[offset..offset + 4].try_into().unwrap()));
                let second =
                    f32::from_bits(u32::from_le_bytes(b[offset..offset + 4].try_into().unwrap()));
                products[lane] = strict_mul_f32(first, second);
            }
            let low = strict_add_f32(products[0], products[1]);
            let high = strict_add_f32(products[2], products[3]);
            let sum = strict_add_f32(low, high);
            let mut output = [0_u8; 16];
            for lane in 0..4 {
                if control & (1 << lane) != 0 {
                    output[lane * 4..lane * 4 + 4].copy_from_slice(&sum.to_bits().to_le_bytes());
                }
            }
            write_xmm(cpu, dst, output);
        });
    }

    fn compare_truth<T: PartialEq + PartialOrd>(
        first: T,
        second: T,
        unordered: bool,
        control: u8,
    ) -> bool {
        match control & 0xf {
            0 => !unordered && first == second,
            1 => !unordered && first < second,
            2 => !unordered && first <= second,
            3 => unordered,
            4 => unordered || first != second,
            5 => unordered || first >= second,
            6 => unordered || first > second,
            7 => !unordered,
            8 => unordered || first == second,
            9 => unordered || first < second,
            10 => unordered || first <= second,
            11 => false,
            12 => !unordered && first != second,
            13 => !unordered && first >= second,
            14 => !unordered && first > second,
            _ => true,
        }
    }

    fn signaling_compare_predicate(control: u8) -> bool {
        matches!(
            control & 0x1f,
            1 | 2 | 5 | 6 | 9 | 10 | 13 | 14 | 16 | 19 | 20 | 23 | 24 | 27 | 28 | 31
        )
    }

    fn f32_nan_kind(bits: u32) -> (bool, bool) {
        let nan = bits & 0x7f80_0000 == 0x7f80_0000 && bits & 0x007f_ffff != 0;
        (nan, nan && bits & 0x0040_0000 == 0)
    }

    fn f64_nan_kind(bits: u64) -> (bool, bool) {
        let nan = bits & 0x7ff0_0000_0000_0000 == 0x7ff0_0000_0000_0000
            && bits & 0x000f_ffff_ffff_ffff != 0;
        (nan, nan && bits & 0x0008_0000_0000_0000 == 0)
    }

    fn compare_pd_mask_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if args[0].size() != 16 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(args[1].size());
            return;
        }
        let control = cpu.args[0] as u8;
        let chunk = cpu.args[1] as usize;
        let active = current_evex_mask(cpu);
        let mut output = 0_u64;
        let mut invalid = false;
        for lane in 0..2_u8 {
            if active & (1 << (chunk * 2 + usize::from(lane))) == 0 {
                continue;
            }
            let offset = lane * 8;
            let first_bits = cpu.read::<u64>(args[0].slice(offset, 8));
            let second_bits = cpu.read::<u64>(args[1].slice(offset, 8));
            let (first_nan, first_signaling) = f64_nan_kind(first_bits);
            let (second_nan, second_signaling) = f64_nan_kind(second_bits);
            let unordered = first_nan || second_nan;
            invalid |= first_signaling
                || second_signaling
                || (unordered && signaling_compare_predicate(control));
            if compare_truth(
                f64::from_bits(first_bits),
                f64::from_bits(second_bits),
                unordered,
                control,
            ) {
                output |= 1 << lane;
            }
        }
        cpu.write_var(dst, output);
        raise_mxcsr_flags(cpu, u32::from(invalid));
    }

    fn compare_ps_mask_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if args[0].size() != 16 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(args[1].size());
            return;
        }
        let control = cpu.args[0] as u8;
        let chunk = cpu.args[1] as usize;
        let active = current_evex_mask(cpu);
        let mut output = 0_u64;
        let mut invalid = false;
        for lane in 0..4_u8 {
            if active & (1 << (chunk * 4 + usize::from(lane))) == 0 {
                continue;
            }
            let offset = lane * 4;
            let first_bits = cpu.read::<u32>(args[0].slice(offset, 4));
            let second_bits = cpu.read::<u32>(args[1].slice(offset, 4));
            let (first_nan, first_signaling) = f32_nan_kind(first_bits);
            let (second_nan, second_signaling) = f32_nan_kind(second_bits);
            let unordered = first_nan || second_nan;
            invalid |= first_signaling
                || second_signaling
                || (unordered && signaling_compare_predicate(control));
            if compare_truth(
                f32::from_bits(first_bits),
                f32::from_bits(second_bits),
                unordered,
                control,
            ) {
                output |= 1 << lane;
            }
        }
        cpu.write_var(dst, output);
        raise_mxcsr_flags(cpu, u32::from(invalid));
    }

    fn compare_sd_mask(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if args[0].size() < 8 || args[1].size() < 8 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(args[1].size());
            return;
        }
        if current_evex_mask(cpu) & 1 == 0 {
            cpu.write_var(dst, 0_u64);
            return;
        }
        let control = cpu.args[0] as u8;
        let first_bits = cpu.read::<u64>(args[0].slice(0, 8));
        let second_bits = cpu.read::<u64>(args[1].slice(0, 8));
        let (first_nan, first_signaling) = f64_nan_kind(first_bits);
        let (second_nan, second_signaling) = f64_nan_kind(second_bits);
        let unordered = first_nan || second_nan;
        let result = compare_truth(
            f64::from_bits(first_bits),
            f64::from_bits(second_bits),
            unordered,
            control,
        );
        cpu.write_var(dst, u64::from(result));
        let invalid = first_signaling
            || second_signaling
            || (unordered && signaling_compare_predicate(control));
        raise_mxcsr_flags(cpu, u32::from(invalid));
    }

    fn compare_ss_mask(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if args[0].size() < 4 || args[1].size() < 4 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(args[1].size());
            return;
        }
        if current_evex_mask(cpu) & 1 == 0 {
            cpu.write_var(dst, 0_u64);
            return;
        }
        let control = cpu.args[0] as u8;
        let first_bits = cpu.read::<u32>(args[0].slice(0, 4));
        let second_bits = cpu.read::<u32>(args[1].slice(0, 4));
        let (first_nan, first_signaling) = f32_nan_kind(first_bits);
        let (second_nan, second_signaling) = f32_nan_kind(second_bits);
        let unordered = first_nan || second_nan;
        let result = compare_truth(
            f32::from_bits(first_bits),
            f32::from_bits(second_bits),
            unordered,
            control,
        );
        cpu.write_var(dst, u64::from(result));
        let invalid = first_signaling
            || second_signaling
            || (unordered && signaling_compare_predicate(control));
        raise_mxcsr_flags(cpu, u32::from(invalid));
    }

    fn compare_pd(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let (Some(first), Some(second)) = (xmm_bytes(cpu, args[0]), xmm_bytes(cpu, args[1]))
        else {
            return;
        };
        let control = cpu.args[0] as u8;
        let mut output = [0_u8; 16];
        let mut invalid = false;
        for lane in 0..2 {
            let offset = lane * 8;
            let first_bits = u64::from_le_bytes(first[offset..offset + 8].try_into().unwrap());
            let second_bits = u64::from_le_bytes(second[offset..offset + 8].try_into().unwrap());
            let (first_nan, first_signaling) = f64_nan_kind(first_bits);
            let (second_nan, second_signaling) = f64_nan_kind(second_bits);
            let unordered = first_nan || second_nan;
            invalid |= first_signaling
                || second_signaling
                || (unordered && signaling_compare_predicate(control));
            if compare_truth(
                f64::from_bits(first_bits),
                f64::from_bits(second_bits),
                unordered,
                control,
            ) {
                output[offset..offset + 8].fill(0xff);
            }
        }
        write_xmm(cpu, dst, output);
        raise_mxcsr_flags(cpu, u32::from(invalid));
    }

    fn compare_ps(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let (Some(first), Some(second)) = (xmm_bytes(cpu, args[0]), xmm_bytes(cpu, args[1]))
        else {
            return;
        };
        let control = cpu.args[0] as u8;
        let mut output = [0_u8; 16];
        let mut invalid = false;
        for lane in 0..4 {
            let offset = lane * 4;
            let first_bits = u32::from_le_bytes(first[offset..offset + 4].try_into().unwrap());
            let second_bits = u32::from_le_bytes(second[offset..offset + 4].try_into().unwrap());
            let (first_nan, first_signaling) = f32_nan_kind(first_bits);
            let (second_nan, second_signaling) = f32_nan_kind(second_bits);
            let unordered = first_nan || second_nan;
            invalid |= first_signaling
                || second_signaling
                || (unordered && signaling_compare_predicate(control));
            if compare_truth(
                f32::from_bits(first_bits),
                f32::from_bits(second_bits),
                unordered,
                control,
            ) {
                output[offset..offset + 4].fill(0xff);
            }
        }
        write_xmm(cpu, dst, output);
        raise_mxcsr_flags(cpu, u32::from(invalid));
    }

    fn compare_sd(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 16 || args[0].size() != 16 || args[1].size() < 8 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(args[1].size());
            return;
        }
        let control = cpu.args[0] as u8;
        let first_bits = cpu.read::<u64>(args[0].slice(0, 8));
        let second_bits = cpu.read::<u64>(args[1].slice(0, 8));
        let (first_nan, first_signaling) = f64_nan_kind(first_bits);
        let (second_nan, second_signaling) = f64_nan_kind(second_bits);
        let unordered = first_nan || second_nan;
        let result = compare_truth(
            f64::from_bits(first_bits),
            f64::from_bits(second_bits),
            unordered,
            control,
        );
        let upper = cpu.read::<u128>(args[0]) & !u128::from(u64::MAX);
        cpu.write_var(dst, upper | u128::from(if result { u64::MAX } else { 0 }));
        let invalid = first_signaling
            || second_signaling
            || (unordered && signaling_compare_predicate(control));
        raise_mxcsr_flags(cpu, u32::from(invalid));
    }

    fn compare_ss(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 16 || args[0].size() != 16 || args[1].size() < 4 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(args[1].size());
            return;
        }
        let control = cpu.args[0] as u8;
        let first_bits = cpu.read::<u32>(args[0].slice(0, 4));
        let second_bits = cpu.read::<u32>(args[1].slice(0, 4));
        let (first_nan, first_signaling) = f32_nan_kind(first_bits);
        let (second_nan, second_signaling) = f32_nan_kind(second_bits);
        let unordered = first_nan || second_nan;
        let result = compare_truth(
            f32::from_bits(first_bits),
            f32::from_bits(second_bits),
            unordered,
            control,
        );
        let upper = cpu.read::<u128>(args[0]) & !u128::from(u32::MAX);
        cpu.write_var(dst, upper | u128::from(if result { u32::MAX } else { 0 }));
        let invalid = first_signaling
            || second_signaling
            || (unordered && signaling_compare_predicate(control));
        raise_mxcsr_flags(cpu, u32::from(invalid));
    }

    fn convert_i32_to_f64_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 16 || args[0].size() < 8 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(args[0].size());
            return;
        }
        let chunk = cpu.args[7] as u8;
        let source_offset = if args[0].size() == 8 { 0 } else { chunk.saturating_mul(8) };
        if source_offset.saturating_add(8) > args[0].size() {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(source_offset);
            return;
        }
        for lane in 0..2_u8 {
            let value = cpu.read::<i32>(args[0].slice(source_offset + lane * 4, 4));
            cpu.write_var(dst.slice(lane * 8, 8), (value as f64).to_bits());
        }
    }

    fn i32_to_f32_bits(value: i32, mode: u8) -> (u32, bool) {
        if value == 0 {
            return (0, false);
        }
        let negative = value < 0;
        let sign = u32::from(negative) << 31;
        let magnitude = value.unsigned_abs();
        let highest = 31 - magnitude.leading_zeros();
        if highest <= 23 {
            let significand = magnitude << (23 - highest);
            return (sign | ((highest + 127) << 23) | (significand & 0x007f_ffff), false);
        }
        let shift = highest - 23;
        let mut significand = magnitude >> shift;
        let remainder_mask = (1_u32 << shift) - 1;
        let remainder = magnitude & remainder_mask;
        let half = 1_u32 << (shift - 1);
        let increment = match mode {
            0 => remainder > half || (remainder == half && significand & 1 != 0),
            1 => negative && remainder != 0,
            2 => !negative && remainder != 0,
            _ => false,
        };
        let mut exponent = highest + 127;
        if increment {
            significand += 1;
            if significand == 1 << 24 {
                significand >>= 1;
                exponent += 1;
            }
        }
        (sign | (exponent << 23) | (significand & 0x007f_ffff), remainder != 0)
    }

    fn convert_i32_to_f32_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 16 || args[0].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(args[0].size());
            return;
        }
        let mxcsr = read_named::<u32>(cpu, "MXCSR").unwrap_or(0x1f80);
        let mode = ((mxcsr >> 13) & 3) as u8;
        let mut inexact = false;
        for lane in 0..4_u8 {
            let value = cpu.read::<i32>(args[0].slice(lane * 4, 4));
            let (bits, lane_inexact) = i32_to_f32_bits(value, mode);
            inexact |= lane_inexact;
            cpu.write_var(dst.slice(lane * 4, 4), bits);
        }
        raise_mxcsr_flags(cpu, u32::from(inexact) << 5);
    }

    fn convert_f32_to_i32_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 16 || args[0].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(args[0].size());
            return;
        }
        let mxcsr = read_named::<u32>(cpu, "MXCSR").unwrap_or(0x1f80);
        let mode = ((mxcsr >> 13) & 3) as u8;
        let daz = mxcsr & (1 << 6) != 0;
        let mut flags = 0_u32;
        for lane in 0..4_u8 {
            let bits = cpu.read::<u32>(args[0].slice(lane * 4, 4));
            let exponent = bits & 0x7f80_0000;
            let fraction = bits & 0x007f_ffff;
            let subnormal = exponent == 0 && fraction != 0;
            let effective = if subnormal && daz { bits & 0x8000_0000 } else { bits };
            let value = f64::from(f32::from_bits(effective));
            let rounded = match mode {
                0 => value.round_ties_even(),
                1 => value.floor(),
                2 => value.ceil(),
                _ => value.trunc(),
            };
            let invalid = !value.is_finite()
                || rounded < f64::from(i32::MIN)
                || rounded > f64::from(i32::MAX);
            let result = if invalid { i32::MIN } else { rounded as i32 };
            flags |= u32::from(invalid);
            if !invalid && rounded != value {
                flags |= 1 << 5;
            }
            if subnormal && !daz {
                flags |= 1 << 1;
            }
            cpu.write_var(dst.slice(lane * 4, 4), result);
        }
        raise_mxcsr_flags(cpu, flags);
    }

    fn convert_f64_pair_to_i32(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 8 || args[0].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let mxcsr = read_named::<u32>(cpu, "MXCSR").unwrap_or(0x1f80);
        let mode = ((mxcsr >> 13) & 3) as u8;
        let daz = mxcsr & (1 << 6) != 0;
        let mut flags = 0_u32;
        for lane in 0..2_u8 {
            let bits = cpu.read::<u64>(args[0].slice(lane * 8, 8));
            let exponent = bits & 0x7ff0_0000_0000_0000;
            let fraction = bits & 0x000f_ffff_ffff_ffff;
            let subnormal = exponent == 0 && fraction != 0;
            let effective = if subnormal && daz { bits & (1_u64 << 63) } else { bits };
            let value = f64::from_bits(effective);
            let rounded = match mode {
                0 => value.round_ties_even(),
                1 => value.floor(),
                2 => value.ceil(),
                _ => value.trunc(),
            };
            let invalid = !value.is_finite()
                || rounded < f64::from(i32::MIN)
                || rounded > f64::from(i32::MAX);
            let result = if invalid { i32::MIN } else { rounded as i32 };
            flags |= u32::from(invalid);
            if !invalid && rounded != value {
                flags |= 1 << 5;
            }
            if subnormal && !daz {
                flags |= 1 << 1;
            }
            cpu.write_var(dst.slice(lane * 4, 4), result);
        }
        raise_mxcsr_flags(cpu, flags);
    }

    fn round_shift_u64(value: u64, shift: u32, negative: bool, mode: u8) -> (u64, bool) {
        if shift == 0 {
            return (value, false);
        }

        let (truncated, remainder, greater_than_half, exactly_half) = if shift < 64 {
            let truncated = value >> shift;
            let remainder = value & ((1_u64 << shift) - 1);
            let half = 1_u64 << (shift - 1);
            (truncated, remainder, remainder > half, remainder == half)
        }
        else if shift == 64 {
            let half = 1_u64 << 63;
            (0, value, value > half, value == half)
        }
        else {
            (0, value, false, false)
        };
        let inexact = remainder != 0;
        let increment = match mode {
            0 => greater_than_half || (exactly_half && truncated & 1 != 0),
            1 => negative && inexact,
            2 => !negative && inexact,
            _ => false,
        };
        (truncated + u64::from(increment), inexact)
    }

    fn narrow_f64_bits(bits: u64, mode: u8, daz: bool, ftz: bool) -> (u32, u32) {
        let negative = bits >> 63 != 0;
        let sign = u32::from(negative) << 31;
        let raw_exponent = ((bits >> 52) & 0x7ff) as u32;
        let fraction = bits & 0x000f_ffff_ffff_ffff;

        if raw_exponent == 0x7ff {
            if fraction == 0 {
                return (sign | 0x7f80_0000, 0);
            }
            let signaling = fraction & 0x0008_0000_0000_0000 == 0;
            let mut payload = (fraction >> 29) as u32 & 0x007f_ffff;
            payload |= 0x0040_0000;
            return (sign | 0x7f80_0000 | payload, u32::from(signaling));
        }

        if raw_exponent == 0 && fraction == 0 {
            return (sign, 0);
        }

        let source_subnormal = raw_exponent == 0;
        if source_subnormal && daz {
            return (sign, 0);
        }
        let mut flags = u32::from(source_subnormal) << 1;
        let (significand, exponent): (u64, i32) = if source_subnormal {
            (fraction, -1022 - 52)
        }
        else {
            ((1_u64 << 52) | fraction, raw_exponent as i32 - 1023 - 52)
        };
        let highest = 63 - significand.leading_zeros();
        let unbiased = exponent + highest as i32;

        if unbiased >= -126 {
            let shift = highest.saturating_sub(23);
            let (mut rounded, inexact) = round_shift_u64(significand, shift, negative, mode);
            let mut result_exponent = unbiased;
            if rounded == 1 << 24 {
                rounded >>= 1;
                result_exponent += 1;
            }
            if result_exponent > 127 {
                let infinity = match mode {
                    0 => true,
                    1 => negative,
                    2 => !negative,
                    _ => false,
                };
                let magnitude = if infinity { 0x7f80_0000 } else { 0x7f7f_ffff };
                return (sign | magnitude, flags | (1 << 3) | (1 << 5));
            }
            if inexact {
                flags |= 1 << 5;
            }
            let result =
                sign | (((result_exponent + 127) as u32) << 23) | (rounded as u32 & 0x007f_ffff);
            return (result, flags);
        }

        // A binary32 subnormal stores value * 2^149 as its fraction.
        let shift = (-149 - exponent) as u32;
        let (rounded, inexact) = round_shift_u64(significand, shift, negative, mode);
        if rounded == 1 << 23 {
            if inexact {
                flags |= 1 << 5;
            }
            return (sign | 0x0080_0000, flags);
        }
        if inexact {
            flags |= (1 << 4) | (1 << 5);
        }
        if ftz && rounded != 0 {
            flags |= (1 << 4) | (1 << 5);
            return (sign, flags);
        }
        (sign | rounded as u32, flags)
    }

    fn convert_f64_pair_to_f32(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 8 || args[0].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let mxcsr = read_named::<u32>(cpu, "MXCSR").unwrap_or(0x1f80);
        let mode = ((mxcsr >> 13) & 3) as u8;
        let daz = mxcsr & (1 << 6) != 0;
        let ftz = mxcsr & (1 << 15) != 0;
        let mut flags = 0_u32;
        for lane in 0..2_u8 {
            let source = cpu.read::<u64>(args[0].slice(lane * 8, 8));
            let (result, lane_flags) = narrow_f64_bits(source, mode, daz, ftz);
            cpu.write_var(dst.slice(lane * 4, 4), result);
            flags |= lane_flags;
        }
        raise_mxcsr_flags(cpu, flags);
    }

    fn quiet_f32_nan(bits: u32) -> u32 {
        bits | 0x0040_0000
    }

    fn reciprocal_f32_bits(bits: u32) -> u32 {
        let magnitude = bits & 0x7fff_ffff;
        let sign = bits & 0x8000_0000;
        if magnitude > 0x7f80_0000 {
            return quiet_f32_nan(bits);
        }
        if magnitude == 0 || magnitude < 0x0080_0000 {
            return sign | 0x7f80_0000;
        }
        if magnitude == 0x7f80_0000 {
            return sign;
        }
        (1.0_f32 / f32::from_bits(bits)).to_bits()
    }

    fn reciprocal_sqrt_f32_bits(bits: u32) -> u32 {
        let magnitude = bits & 0x7fff_ffff;
        let sign = bits & 0x8000_0000;
        if magnitude > 0x7f80_0000 {
            return quiet_f32_nan(bits);
        }
        if magnitude == 0 || magnitude < 0x0080_0000 {
            return sign | 0x7f80_0000;
        }
        if sign != 0 {
            return 0xffc0_0000;
        }
        if magnitude == 0x7f80_0000 {
            return 0;
        }
        (1.0_f32 / f32::from_bits(bits).sqrt()).to_bits()
    }

    fn approximate_ps(cpu: &mut Cpu, dst: VarNode, source: Value, operation: fn(u32) -> u32) {
        if dst.size != 16 || source.size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(source.size());
            return;
        }
        for lane in 0..4_u8 {
            let bits = cpu.read::<u32>(source.slice(lane * 4, 4));
            cpu.write_var(dst.slice(lane * 4, 4), operation(bits));
        }
    }

    fn reciprocal_ps(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        approximate_ps(cpu, dst, args[0], reciprocal_f32_bits);
    }

    fn reciprocal_sqrt_ps(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        approximate_ps(cpu, dst, args[0], reciprocal_sqrt_f32_bits);
    }

    fn approximate_ss(cpu: &mut Cpu, dst: VarNode, args: [Value; 2], operation: fn(u32) -> u32) {
        if dst.size != 16 || args[0].size() != 16 || args[1].size() < 4 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(args[1].size());
            return;
        }
        let upper = cpu.read::<u128>(args[0]) & !u128::from(u32::MAX);
        let source = cpu.read::<u32>(args[1].slice(0, 4));
        cpu.write_var(dst, upper | u128::from(operation(source)));
    }

    fn reciprocal_ss(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        approximate_ss(cpu, dst, args, reciprocal_f32_bits);
    }

    fn reciprocal_sqrt_ss(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        approximate_ss(cpu, dst, args, reciprocal_sqrt_f32_bits);
    }

    fn widen_f32_bits(bits: u32, denormals_are_zero: bool) -> (u64, u32) {
        let sign = u64::from(bits >> 31) << 63;
        let exponent = bits & 0x7f80_0000;
        let fraction = bits & 0x007f_ffff;
        if exponent == 0x7f80_0000 {
            if fraction == 0 {
                return (sign | 0x7ff0_0000_0000_0000, 0);
            }
            let signaling = bits & 0x0040_0000 == 0;
            let payload = (u64::from(fraction) << 29) | (u64::from(signaling) << 51);
            return (sign | 0x7ff0_0000_0000_0000 | payload, u32::from(signaling));
        }
        let subnormal = exponent == 0 && fraction != 0;
        if subnormal && denormals_are_zero {
            return (sign, 0);
        }
        ((f32::from_bits(bits) as f64).to_bits(), u32::from(subnormal) << 1)
    }

    fn convert_f32_to_f64_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 16 || args[0].size() < 8 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(args[0].size());
            return;
        }
        let chunk = cpu.args[7] as u8;
        let source_offset = if args[0].size() == 8 { 0 } else { chunk.saturating_mul(8) };
        if source_offset.saturating_add(8) > args[0].size() {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(source_offset);
            return;
        }
        let mxcsr = read_named::<u32>(cpu, "MXCSR").unwrap_or(0x1f80);
        let daz = mxcsr & (1 << 6) != 0;
        let mut flags = 0_u32;
        for lane in 0..2_u8 {
            let bits = cpu.read::<u32>(args[0].slice(source_offset + lane * 4, 4));
            let (value, lane_flags) = widen_f32_bits(bits, daz);
            flags |= lane_flags;
            cpu.write_var(dst.slice(lane * 8, 8), value);
        }
        raise_mxcsr_flags(cpu, flags);
    }

    fn convert_float_to_integer(
        cpu: &mut Cpu,
        dst: VarNode,
        source: Value,
        source_lane_size: u8,
        destination_lane_size: u8,
        unsigned: bool,
        truncate: bool,
    ) {
        if !matches!(source_lane_size, 4 | 8)
            || !matches!(destination_lane_size, 4 | 8)
            || source.size() % source_lane_size != 0
        {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(source.size());
            return;
        }
        let lanes = source.size() / source_lane_size;
        if lanes * destination_lane_size > dst.size {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let mxcsr = read_named::<u32>(cpu, "MXCSR").unwrap_or(0x1f80);
        let embedded_rounding = current_evex_embedded_rounding(cpu);
        let mode =
            if truncate { 3 } else { embedded_rounding.unwrap_or(((mxcsr >> 13) & 3) as u8) };
        let daz = mxcsr & (1 << 6) != 0;
        let mut flags = 0_u32;
        let mask = current_evex_mask(cpu);
        let chunk = cpu.args[7] as u8;
        for lane in 0..lanes {
            if mask & (1_u64 << (usize::from(chunk) * usize::from(lanes) + usize::from(lane))) == 0
            {
                continue;
            }
            let lane_source = source.slice(lane * source_lane_size, source_lane_size);
            let (mut value, subnormal) = if source_lane_size == 8 {
                let bits = cpu.read::<u64>(lane_source);
                let subnormal =
                    bits & 0x7ff0_0000_0000_0000 == 0 && bits & 0x000f_ffff_ffff_ffff != 0;
                (f64::from_bits(bits), subnormal)
            }
            else {
                let bits = cpu.read::<u32>(lane_source);
                let subnormal = bits & 0x7f80_0000 == 0 && bits & 0x007f_ffff != 0;
                (f64::from(f32::from_bits(bits)), subnormal)
            };
            if subnormal {
                if daz {
                    value = value.copysign(0.0);
                }
                else {
                    flags |= 1 << 1;
                }
            }
            let rounded = match mode {
                0 => value.round_ties_even(),
                1 => value.floor(),
                2 => value.ceil(),
                _ => value.trunc(),
            };
            let bits = u32::from(destination_lane_size) * 8;
            let invalid = if unsigned {
                !value.is_finite() || rounded < 0.0 || rounded > (u64::MAX >> (64 - bits)) as f64
            }
            else {
                let minimum = -(1_i128 << (bits - 1)) as f64;
                let maximum = ((1_i128 << (bits - 1)) - 1) as f64;
                !value.is_finite() || rounded < minimum || rounded > maximum
            };
            let result = if invalid {
                flags |= 1;
                if unsigned { u64::MAX >> (64 - bits) } else { 1_u64 << (bits - 1) }
            }
            else {
                if rounded != value {
                    flags |= 1 << 5;
                }
                if unsigned { rounded as u64 } else { (rounded as i64) as u64 }
            };
            cpu.write_trunc(dst.slice(lane * destination_lane_size, destination_lane_size), result);
        }
        if embedded_rounding.is_none() {
            raise_mxcsr_flags(cpu, flags);
        }
    }

    fn convert_f64_to_i32(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        convert_float_to_integer(cpu, dst, args[0], 8, 4, false, false);
    }
    fn convert_f64_to_u32(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        convert_float_to_integer(cpu, dst, args[0], 8, 4, true, false);
    }
    fn convert_f32_to_u32(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        convert_float_to_integer(cpu, dst, args[0], 4, 4, true, false);
    }
    fn truncate_f64_to_i32(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        convert_float_to_integer(cpu, dst, args[0], 8, 4, false, true);
    }
    fn truncate_f64_to_u32(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        convert_float_to_integer(cpu, dst, args[0], 8, 4, true, true);
    }
    fn truncate_f32_to_i32(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        convert_float_to_integer(cpu, dst, args[0], 4, 4, false, true);
    }
    fn truncate_f32_to_u32(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        convert_float_to_integer(cpu, dst, args[0], 4, 4, true, true);
    }

    fn scalar_float_to_integer(
        cpu: &mut Cpu,
        dst: VarNode,
        source: Value,
        source_size: u8,
        unsigned: bool,
        truncate: bool,
    ) {
        cpu.args[7] = 0;
        convert_float_to_integer(
            cpu,
            dst,
            source.slice(0, source_size),
            source_size,
            dst.size,
            unsigned,
            truncate,
        );
    }
    fn convert_scalar_f64_to_i(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        scalar_float_to_integer(cpu, dst, args[0], 8, false, false);
    }
    fn convert_scalar_f64_to_u(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        scalar_float_to_integer(cpu, dst, args[0], 8, true, false);
    }
    fn convert_scalar_f32_to_i(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        scalar_float_to_integer(cpu, dst, args[0], 4, false, false);
    }
    fn convert_scalar_f32_to_u(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        scalar_float_to_integer(cpu, dst, args[0], 4, true, false);
    }
    fn truncate_scalar_f64_to_i(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        scalar_float_to_integer(cpu, dst, args[0], 8, false, true);
    }
    fn truncate_scalar_f64_to_u(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        scalar_float_to_integer(cpu, dst, args[0], 8, true, true);
    }
    fn truncate_scalar_f32_to_i(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        scalar_float_to_integer(cpu, dst, args[0], 4, false, true);
    }
    fn truncate_scalar_f32_to_u(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        scalar_float_to_integer(cpu, dst, args[0], 4, true, true);
    }

    fn convert_u32_to_f64(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 16 || args[0].size() < 8 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            return;
        }
        for lane in 0..2_u8 {
            let value = cpu.read::<u32>(args[0].slice(lane * 4, 4));
            cpu.write_var(dst.slice(lane * 8, 8), f64::from(value).to_bits());
        }
    }

    fn convert_u32_to_f32(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 16 || args[0].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            return;
        }
        let mxcsr = read_named::<u32>(cpu, "MXCSR").unwrap_or(0x1f80);
        let mode = ((mxcsr >> 13) & 3) as u8;
        let mask = current_evex_mask(cpu);
        let chunk = cpu.args[7] as usize;
        let mut inexact = false;
        for lane in 0..4_u8 {
            if mask & (1_u64 << (chunk * 4 + usize::from(lane))) == 0 {
                continue;
            }
            let value = cpu.read::<u32>(args[0].slice(lane * 4, 4));
            if value == 0 {
                cpu.write_var(dst.slice(lane * 4, 4), 0_u32);
                continue;
            }
            let highest = 31 - value.leading_zeros();
            let (significand, lane_inexact) = if highest <= 23 {
                (value << (23 - highest), false)
            }
            else {
                let shift = highest - 23;
                let truncated = value >> shift;
                let remainder = value & ((1_u32 << shift) - 1);
                let half = 1_u32 << (shift - 1);
                let increment = match mode {
                    0 => remainder > half || (remainder == half && truncated & 1 != 0),
                    2 => remainder != 0,
                    _ => false,
                };
                (truncated + u32::from(increment), remainder != 0)
            };
            let mut exponent = highest + 127;
            let mut significand = significand;
            if significand == 1 << 24 {
                significand >>= 1;
                exponent += 1;
            }
            cpu.write_var(dst.slice(lane * 4, 4), (exponent << 23) | (significand & 0x007f_ffff));
            inexact |= lane_inexact;
        }
        raise_mxcsr_flags(cpu, u32::from(inexact) << 5);
    }

    fn scalar_integer_to_float(
        cpu: &mut Cpu,
        dst: VarNode,
        args: [Value; 2],
        unsigned: bool,
        double: bool,
    ) {
        if dst.size != 16 || args[0].size() != 16 || !matches!(args[1].size(), 4 | 8) {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            return;
        }
        let merge = cpu.read::<u128>(args[0]);
        cpu.write_var(dst, merge);
        let raw: u64 = cpu.read_dynamic(args[1]).zxt();
        let value = if unsigned {
            if args[1].size() == 4 { f64::from(raw as u32) } else { raw as f64 }
        }
        else if args[1].size() == 4 {
            f64::from(raw as u32 as i32)
        }
        else {
            raw as i64 as f64
        };
        if double {
            cpu.write_var(dst.slice(0, 8), value.to_bits());
        }
        else {
            cpu.write_var(dst.slice(0, 4), (value as f32).to_bits());
        }
    }
    fn convert_scalar_i_to_f64(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        scalar_integer_to_float(cpu, dst, args, false, true);
    }
    fn convert_scalar_i_to_f32(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        scalar_integer_to_float(cpu, dst, args, false, false);
    }
    fn convert_scalar_u_to_f64(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        scalar_integer_to_float(cpu, dst, args, true, true);
    }
    fn convert_scalar_u_to_f32(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        scalar_integer_to_float(cpu, dst, args, true, false);
    }

    struct EvexVsib {
        destination_register: usize,
        index_register: usize,
        base_register: Option<usize>,
        displacement: i64,
        scale: u64,
        address32: bool,
        segment_base: u64,
        data_size: usize,
        index_size: usize,
        lane_count: usize,
        destination_size: usize,
        mask_register: usize,
    }

    fn read_instruction_byte(cpu: &mut Cpu, pc: u64, offset: usize) -> Option<u8> {
        let Some(address) = pc.checked_add(offset as u64)
        else {
            cpu.exception.code = ExceptionCode::AddressOverflow as u32;
            cpu.exception.value = u64::MAX;
            return None;
        };
        match cpu.mem.read::<1>(address, icicle_mem::perm::NONE) {
            Ok(value) => Some(value[0]),
            Err(error) => {
                cpu.exception.code = ExceptionCode::from_load_error(error) as u32;
                cpu.exception.value = address;
                None
            }
        }
    }

    fn decode_evex_vsib(cpu: &mut Cpu) -> Option<EvexVsib> {
        let pc = cpu.read_pc();
        let mut offset = 0_usize;
        let mut address32 = false;
        let mut segment_name = None;
        loop {
            if offset >= 15 {
                cpu.exception.code = ExceptionCode::InvalidInstruction as u32;
                cpu.exception.value = pc;
                return None;
            }
            match read_instruction_byte(cpu, pc, offset)? {
                0x67 => address32 = true,
                0x64 => segment_name = Some("FS_OFFSET"),
                0x65 => segment_name = Some("GS_OFFSET"),
                0x2e | 0x3e | 0x26 | 0x36 => {}
                _ => break,
            }
            offset += 1;
        }
        if read_instruction_byte(cpu, pc, offset)? != 0x62 || offset + 7 > 15 {
            cpu.exception.code = ExceptionCode::InvalidInstruction as u32;
            cpu.exception.value = pc;
            return None;
        }
        let p0 = read_instruction_byte(cpu, pc, offset + 1)?;
        let p1 = read_instruction_byte(cpu, pc, offset + 2)?;
        let p2 = read_instruction_byte(cpu, pc, offset + 3)?;
        let opcode = read_instruction_byte(cpu, pc, offset + 4)?;
        let modrm = read_instruction_byte(cpu, pc, offset + 5)?;
        let sib = read_instruction_byte(cpu, pc, offset + 6)?;
        let mode = modrm >> 6;
        if p0 & 0x0b != 0x02
            || p1 & 0x7c != 0x7c
            || p2 & 7 == 0
            || p2 & 0x90 != 0
            || mode == 3
            || modrm & 7 != 4
        {
            cpu.exception.code = ExceptionCode::InvalidInstruction as u32;
            cpu.exception.value = pc;
            return None;
        }
        let is_vsib_opcode = matches!(opcode, 0x90..=0x93 | 0xa0..=0xa3);
        if !is_vsib_opcode {
            cpu.exception.code = ExceptionCode::InvalidInstruction as u32;
            cpu.exception.value = u64::from(opcode);
            return None;
        }
        let vector_size = match (p2 >> 5) & 3 {
            0 => 16,
            1 => 32,
            2 => 64,
            _ => {
                cpu.exception.code = ExceptionCode::InvalidInstruction as u32;
                cpu.exception.value = pc;
                return None;
            }
        };
        let data_size = if p1 & 0x80 == 0 { 4 } else { 8 };
        let index_size = if opcode & 1 == 0 { 4 } else { 8 };
        let lane_count = vector_size / data_size.max(index_size);
        let destination_size = lane_count * data_size;
        let inverted = |byte: u8, bit: u8| usize::from(((byte >> bit) & 1) ^ 1);
        let destination_register =
            usize::from((modrm >> 3) & 7) + inverted(p0, 7) * 8 + inverted(p0, 4) * 16;
        let index_register =
            usize::from((sib >> 3) & 7) + inverted(p0, 6) * 8 + inverted(p2, 3) * 16;
        if destination_register == index_register {
            cpu.exception.code = ExceptionCode::InvalidInstruction as u32;
            cpu.exception.value = pc;
            return None;
        }
        let base_field = sib & 7;
        let base_register =
            (mode != 0 || base_field != 5).then_some(usize::from(base_field) + inverted(p0, 5) * 8);
        let displacement_offset = offset + 7;
        let displacement = match mode {
            0 if base_field == 5 => {
                if displacement_offset + 4 > 15 {
                    cpu.exception.code = ExceptionCode::InvalidInstruction as u32;
                    cpu.exception.value = pc;
                    return None;
                }
                let value = i32::from_le_bytes([
                    read_instruction_byte(cpu, pc, displacement_offset)?,
                    read_instruction_byte(cpu, pc, displacement_offset + 1)?,
                    read_instruction_byte(cpu, pc, displacement_offset + 2)?,
                    read_instruction_byte(cpu, pc, displacement_offset + 3)?,
                ]);
                i64::from(value)
            }
            1 => {
                if displacement_offset >= 15 {
                    cpu.exception.code = ExceptionCode::InvalidInstruction as u32;
                    cpu.exception.value = pc;
                    return None;
                }
                let value = i64::from(read_instruction_byte(cpu, pc, displacement_offset)? as i8)
                    * data_size as i64;
                value
            }
            2 => {
                if displacement_offset + 4 > 15 {
                    cpu.exception.code = ExceptionCode::InvalidInstruction as u32;
                    cpu.exception.value = pc;
                    return None;
                }
                let value = i32::from_le_bytes([
                    read_instruction_byte(cpu, pc, displacement_offset)?,
                    read_instruction_byte(cpu, pc, displacement_offset + 1)?,
                    read_instruction_byte(cpu, pc, displacement_offset + 2)?,
                    read_instruction_byte(cpu, pc, displacement_offset + 3)?,
                ]);
                i64::from(value)
            }
            _ => 0,
        };
        let segment_base = segment_name.and_then(|name| read_named::<u64>(cpu, name)).unwrap_or(0);
        Some(EvexVsib {
            destination_register,
            index_register,
            base_register,
            displacement,
            scale: 1_u64 << (sib >> 6),
            address32,
            segment_base,
            data_size,
            index_size,
            lane_count,
            destination_size,
            mask_register: usize::from(p2 & 7),
        })
    }

    fn decode_vex_vsib(cpu: &mut Cpu) -> Option<EvexVsib> {
        let pc = cpu.read_pc();
        let mut offset = 0_usize;
        let mut address32 = false;
        let mut segment_name = None;
        loop {
            if offset >= 15 {
                cpu.exception.code = ExceptionCode::InvalidInstruction as u32;
                cpu.exception.value = pc;
                return None;
            }
            match read_instruction_byte(cpu, pc, offset)? {
                0x67 => address32 = true,
                0x64 => segment_name = Some("FS_OFFSET"),
                0x65 => segment_name = Some("GS_OFFSET"),
                0x2e | 0x3e | 0x26 | 0x36 => {}
                _ => break,
            }
            offset += 1;
        }
        if read_instruction_byte(cpu, pc, offset)? != 0xc4 || offset + 6 > 15 {
            cpu.exception.code = ExceptionCode::InvalidInstruction as u32;
            cpu.exception.value = pc;
            return None;
        }
        let p0 = read_instruction_byte(cpu, pc, offset + 1)?;
        let p1 = read_instruction_byte(cpu, pc, offset + 2)?;
        let opcode = read_instruction_byte(cpu, pc, offset + 3)?;
        let modrm = read_instruction_byte(cpu, pc, offset + 4)?;
        let sib = read_instruction_byte(cpu, pc, offset + 5)?;
        let mode = modrm >> 6;
        if p0 & 0x1f != 2
            || p1 & 3 != 1
            || !matches!(opcode, 0x90..=0x93)
            || mode == 3
            || modrm & 7 != 4
        {
            cpu.exception.code = ExceptionCode::InvalidInstruction as u32;
            cpu.exception.value = pc;
            return None;
        }
        let vector_size = if p1 & 4 == 0 { 16 } else { 32 };
        let data_size = if p1 & 0x80 == 0 { 4 } else { 8 };
        let index_size = if opcode & 1 == 0 { 4 } else { 8 };
        let lane_count = vector_size / data_size.max(index_size);
        let destination_size = lane_count * data_size;
        let inverted = |byte: u8, bit: u8| usize::from(((byte >> bit) & 1) ^ 1);
        let destination_register = usize::from((modrm >> 3) & 7) + inverted(p0, 7) * 8;
        let index_register = usize::from((sib >> 3) & 7) + inverted(p0, 6) * 8;
        let mask_register = usize::from((p1 >> 3) & 0xf) ^ 0xf;
        if destination_register == index_register
            || destination_register == mask_register
            || index_register == mask_register
        {
            cpu.exception.code = ExceptionCode::InvalidInstruction as u32;
            cpu.exception.value = pc;
            return None;
        }
        let base_field = sib & 7;
        let base_register =
            (mode != 0 || base_field != 5).then_some(usize::from(base_field) + inverted(p0, 5) * 8);
        let displacement_offset = offset + 6;
        let displacement = match mode {
            0 if base_field == 5 => {
                if displacement_offset + 4 > 15 {
                    cpu.exception.code = ExceptionCode::InvalidInstruction as u32;
                    cpu.exception.value = pc;
                    return None;
                }
                i64::from(i32::from_le_bytes([
                    read_instruction_byte(cpu, pc, displacement_offset)?,
                    read_instruction_byte(cpu, pc, displacement_offset + 1)?,
                    read_instruction_byte(cpu, pc, displacement_offset + 2)?,
                    read_instruction_byte(cpu, pc, displacement_offset + 3)?,
                ]))
            }
            1 => {
                if displacement_offset >= 15 {
                    cpu.exception.code = ExceptionCode::InvalidInstruction as u32;
                    cpu.exception.value = pc;
                    return None;
                }
                i64::from(read_instruction_byte(cpu, pc, displacement_offset)? as i8)
            }
            2 => {
                if displacement_offset + 4 > 15 {
                    cpu.exception.code = ExceptionCode::InvalidInstruction as u32;
                    cpu.exception.value = pc;
                    return None;
                }
                i64::from(i32::from_le_bytes([
                    read_instruction_byte(cpu, pc, displacement_offset)?,
                    read_instruction_byte(cpu, pc, displacement_offset + 1)?,
                    read_instruction_byte(cpu, pc, displacement_offset + 2)?,
                    read_instruction_byte(cpu, pc, displacement_offset + 3)?,
                ]))
            }
            _ => 0,
        };
        let segment_base = segment_name.and_then(|name| read_named::<u64>(cpu, name)).unwrap_or(0);
        Some(EvexVsib {
            destination_register,
            index_register,
            base_register,
            displacement,
            scale: 1_u64 << (sib >> 6),
            address32,
            segment_base,
            data_size,
            index_size,
            lane_count,
            destination_size,
            mask_register,
        })
    }

    const GPR_NAMES: [&str; 16] = [
        "RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI", "R8", "R9", "R10", "R11", "R12",
        "R13", "R14", "R15",
    ];

    fn vsib_lane_address(cpu: &mut Cpu, decoded: &EvexVsib, lane: usize) -> Option<u64> {
        let index_var = named_slice(
            cpu,
            &format!("ZMM{}", decoded.index_register),
            (lane * decoded.index_size) as u8,
            decoded.index_size as u8,
        )?;
        let index = if decoded.index_size == 4 {
            i64::from(cpu.read_var::<u32>(index_var) as i32)
        }
        else {
            cpu.read_var::<u64>(index_var) as i64
        };
        let base = decoded
            .base_register
            .and_then(|register| read_named::<u64>(cpu, GPR_NAMES[register]))
            .unwrap_or(0);
        let indexed = (index as u64).wrapping_mul(decoded.scale);
        let address = if decoded.address32 {
            u64::from(
                (base as u32)
                    .wrapping_add(indexed as u32)
                    .wrapping_add(decoded.displacement as u32),
            )
        }
        else {
            base.wrapping_add(indexed).wrapping_add(decoded.displacement as u64)
        };
        Some(decoded.segment_base.wrapping_add(address))
    }

    fn vsib_gather(cpu: &mut Cpu, dst: VarNode, _: [Value; 2]) {
        let Some(decoded) = decode_evex_vsib(cpu)
        else {
            return;
        };
        let lanes_per_chunk = 16 / decoded.data_size;
        let chunk = if decoded.destination_size <= 16 { 0 } else { cpu.args[7] as usize };
        let destination_name = format!("ZMM{}", decoded.destination_register);
        let Some(destination_chunk) = named_slice(cpu, &destination_name, (chunk * 16) as u8, 16)
        else {
            return;
        };
        cpu.write_var(dst, cpu.read_var::<u128>(destination_chunk));
        let mask_name = format!("K{}", decoded.mask_register);
        let mut mask = read_named::<u64>(cpu, &mask_name).unwrap_or(0);
        for local_lane in 0..lanes_per_chunk {
            let lane = chunk * lanes_per_chunk + local_lane;
            if lane >= decoded.lane_count || mask & (1_u64 << lane) == 0 {
                continue;
            }
            let Some(address) = vsib_lane_address(cpu, &decoded, lane)
            else {
                return;
            };
            let mut bytes = [0_u8; 8];
            if read_guest(cpu, address, &mut bytes[..decoded.data_size]).is_none() {
                let _ = write_named(cpu, &mask_name, mask);
                return;
            }
            let offset = (local_lane * decoded.data_size) as u8;
            if decoded.data_size == 4 {
                let value = u32::from_le_bytes(bytes[..4].try_into().unwrap());
                cpu.write_var(dst.slice(offset, 4), value);
                if let Some(lane_var) = named_slice(cpu, &destination_name, (lane * 4) as u8, 4) {
                    cpu.write_var(lane_var, value);
                }
            }
            else {
                let value = u64::from_le_bytes(bytes);
                cpu.write_var(dst.slice(offset, 8), value);
                if let Some(lane_var) = named_slice(cpu, &destination_name, (lane * 8) as u8, 8) {
                    cpu.write_var(lane_var, value);
                }
            }
            mask &= !(1_u64 << lane);
        }
        if (chunk + 1) * lanes_per_chunk >= decoded.lane_count {
            mask = 0;
        }
        let _ = write_named(cpu, &mask_name, mask);
    }

    fn vex_vsib_gather(cpu: &mut Cpu, dst: VarNode, _: [Value; 2]) {
        let Some(decoded) = decode_vex_vsib(cpu)
        else {
            return;
        };
        let lanes_per_chunk = 16 / decoded.data_size;
        let chunk = if decoded.destination_size <= 16 { 0 } else { cpu.args[7] as usize };
        let destination_name = format!("ZMM{}", decoded.destination_register);
        let mask_name = format!("ZMM{}", decoded.mask_register);
        if chunk == 0 {
            for name in [&destination_name, &mask_name] {
                for byte in (decoded.destination_size..64).step_by(16) {
                    let Some(slice) = named_slice(cpu, name, byte as u8, 16)
                    else {
                        return;
                    };
                    cpu.write_var(slice, 0_u128);
                }
            }
            // AVX2 gather restart state canonicalizes every selected mask
            // element to all ones. Completed elements are then cleared one by
            // one, leaving a hardware-compatible retry mask after a fault.
            for lane in 0..decoded.lane_count {
                let Some(mask_lane) = named_slice(
                    cpu,
                    &mask_name,
                    (lane * decoded.data_size) as u8,
                    decoded.data_size as u8,
                )
                else {
                    return;
                };
                let active = if decoded.data_size == 4 {
                    cpu.read_var::<u32>(mask_lane) >> 31 != 0
                }
                else {
                    cpu.read_var::<u64>(mask_lane) >> 63 != 0
                };
                if active {
                    if decoded.data_size == 4 {
                        cpu.write_var(mask_lane, u32::MAX);
                    }
                    else {
                        cpu.write_var(mask_lane, u64::MAX);
                    }
                }
            }
        }
        let Some(destination_chunk) = named_slice(cpu, &destination_name, (chunk * 16) as u8, 16)
        else {
            return;
        };
        cpu.write_var(dst, cpu.read_var::<u128>(destination_chunk));
        for local_lane in 0..lanes_per_chunk {
            let lane = chunk * lanes_per_chunk + local_lane;
            if lane >= decoded.lane_count {
                continue;
            }
            let Some(mask_lane) = named_slice(
                cpu,
                &mask_name,
                (lane * decoded.data_size) as u8,
                decoded.data_size as u8,
            )
            else {
                return;
            };
            let active = if decoded.data_size == 4 {
                cpu.read_var::<u32>(mask_lane) >> 31 != 0
            }
            else {
                cpu.read_var::<u64>(mask_lane) >> 63 != 0
            };
            if !active {
                continue;
            }
            let Some(address) = vsib_lane_address(cpu, &decoded, lane)
            else {
                return;
            };
            let mut bytes = [0_u8; 8];
            if read_guest(cpu, address, &mut bytes[..decoded.data_size]).is_none() {
                return;
            }
            let output_offset = (local_lane * decoded.data_size) as u8;
            let destination_offset = (lane * decoded.data_size) as u8;
            if decoded.data_size == 4 {
                let value = u32::from_le_bytes(bytes[..4].try_into().unwrap());
                cpu.write_var(dst.slice(output_offset, 4), value);
                if let Some(lane_var) = named_slice(cpu, &destination_name, destination_offset, 4) {
                    cpu.write_var(lane_var, value);
                }
                cpu.write_var(mask_lane, 0_u32);
            }
            else {
                let value = u64::from_le_bytes(bytes);
                cpu.write_var(dst.slice(output_offset, 8), value);
                if let Some(lane_var) = named_slice(cpu, &destination_name, destination_offset, 8) {
                    cpu.write_var(lane_var, value);
                }
                cpu.write_var(mask_lane, 0_u64);
            }
        }
        if (chunk + 1) * lanes_per_chunk >= decoded.lane_count {
            for mask_chunk in 0..4 {
                let Some(slice) = named_slice(cpu, &mask_name, mask_chunk * 16, 16)
                else {
                    return;
                };
                cpu.write_var(slice, 0_u128);
            }
        }
    }

    fn vsib_scatter(cpu: &mut Cpu, _: VarNode, _: [Value; 2]) {
        let Some(decoded) = decode_evex_vsib(cpu)
        else {
            return;
        };
        let source_name = format!("ZMM{}", decoded.destination_register);
        let mask_name = format!("K{}", decoded.mask_register);
        let mut mask = read_named::<u64>(cpu, &mask_name).unwrap_or(0);
        for lane in 0..decoded.lane_count {
            if mask & (1_u64 << lane) == 0 {
                continue;
            }
            let Some(address) = vsib_lane_address(cpu, &decoded, lane)
            else {
                return;
            };
            let Some(source) = named_slice(
                cpu,
                &source_name,
                (lane * decoded.data_size) as u8,
                decoded.data_size as u8,
            )
            else {
                return;
            };
            let bytes = if decoded.data_size == 4 {
                cpu.read_var::<u32>(source).to_le_bytes().to_vec()
            }
            else {
                cpu.read_var::<u64>(source).to_le_bytes().to_vec()
            };
            if write_guest(cpu, address, &bytes).is_none() {
                let _ = write_named(cpu, &mask_name, mask);
                return;
            }
            mask &= !(1_u64 << lane);
        }
        let _ = write_named(cpu, &mask_name, 0_u64);
    }

    fn evex_lane_active(cpu: &mut Cpu, lane: usize, lanes_per_chunk: usize) -> bool {
        let chunk = cpu.args[7] as usize;
        current_evex_mask(cpu) & (1_u64 << (chunk * lanes_per_chunk + lane)) != 0
    }

    fn evex_scalar_lane_active(cpu: &mut Cpu) -> bool {
        current_evex_mask(cpu) & 1 != 0
    }

    fn getexp_f32(bits: u32) -> (u32, u32) {
        let exponent = (bits >> 23) & 0xff;
        let fraction = bits & 0x007f_ffff;
        match (exponent, fraction) {
            (0xff, 0) => (0x7f80_0000, 0),
            (0xff, _) => {
                let signaling = fraction & 0x0040_0000 == 0;
                (bits | 0x0040_0000, u32::from(signaling))
            }
            (0, 0) => (0xff80_0000, 0),
            (0, _) => {
                let unbiased = 31_i32 - fraction.leading_zeros() as i32 - 149;
                ((unbiased as f32).to_bits(), 1 << 1)
            }
            _ => (((exponent as i32 - 127) as f32).to_bits(), 0),
        }
    }

    fn getexp_f64(bits: u64) -> (u64, u32) {
        let exponent = (bits >> 52) & 0x7ff;
        let fraction = bits & 0x000f_ffff_ffff_ffff;
        match (exponent, fraction) {
            (0x7ff, 0) => (0x7ff0_0000_0000_0000, 0),
            (0x7ff, _) => {
                let signaling = fraction & 0x0008_0000_0000_0000 == 0;
                (bits | 0x0008_0000_0000_0000, u32::from(signaling))
            }
            (0, 0) => (0xfff0_0000_0000_0000, 0),
            (0, _) => {
                let unbiased = 63_i32 - fraction.leading_zeros() as i32 - 1074;
                ((unbiased as f64).to_bits(), 1 << 1)
            }
            _ => (((exponent as i32 - 1023) as f64).to_bits(), 0),
        }
    }

    fn getexp_packed(cpu: &mut Cpu, dst: VarNode, source: Value, double: bool) {
        let lane_bytes = if double { 8 } else { 4 };
        if dst.size != 16 || source.size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            return;
        }
        let lanes = 16 / lane_bytes;
        let mut flags = 0;
        for lane in 0..lanes {
            if !evex_lane_active(cpu, lane, lanes) {
                continue;
            }
            let offset = (lane * lane_bytes) as u8;
            if double {
                let (value, lane_flags) = getexp_f64(cpu.read::<u64>(source.slice(offset, 8)));
                cpu.write_var(dst.slice(offset, 8), value);
                flags |= lane_flags;
            }
            else {
                let (value, lane_flags) = getexp_f32(cpu.read::<u32>(source.slice(offset, 4)));
                cpu.write_var(dst.slice(offset, 4), value);
                flags |= lane_flags;
            }
        }
        raise_mxcsr_flags(cpu, flags);
    }

    fn getexp_pd(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        getexp_packed(cpu, dst, args[0], true);
    }
    fn getexp_ps(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        getexp_packed(cpu, dst, args[0], false);
    }
    fn getexp_sd(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        cpu.write_var(dst, cpu.read::<u128>(args[0]));
        if evex_scalar_lane_active(cpu) {
            let (value, flags) = getexp_f64(cpu.read::<u64>(args[1].slice(0, 8)));
            cpu.write_var(dst.slice(0, 8), value);
            raise_mxcsr_flags(cpu, flags);
        }
    }
    fn getexp_ss(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        cpu.write_var(dst, cpu.read::<u128>(args[0]));
        if evex_scalar_lane_active(cpu) {
            let (value, flags) = getexp_f32(cpu.read::<u32>(args[1].slice(0, 4)));
            cpu.write_var(dst.slice(0, 4), value);
            raise_mxcsr_flags(cpu, flags);
        }
    }

    fn quiet_nan_f32(bits: u32) -> (u32, u32) {
        (bits | 0x0040_0000, u32::from(bits & 0x0040_0000 == 0))
    }
    fn quiet_nan_f64(bits: u64) -> (u64, u32) {
        (bits | 0x0008_0000_0000_0000, u32::from(bits & 0x0008_0000_0000_0000 == 0))
    }

    fn getmant_f32(bits: u32, immediate: u8) -> (u32, u32) {
        let sign = bits & 0x8000_0000;
        let exponent = bits & 0x7f80_0000;
        let fraction = bits & 0x007f_ffff;
        if exponent == 0x7f80_0000 {
            if fraction != 0 {
                return quiet_nan_f32(bits);
            }
            if immediate & 0x0c == 0x08 && sign != 0 {
                return (0xffc0_0000, 1);
            }
            return (0x3f80_0000 | if immediate & 0x0c == 0 { sign } else { 0 }, 0);
        }
        if exponent == 0 && fraction == 0 {
            return (0x3f80_0000 | if immediate & 0x0c == 0x04 { 0 } else { sign }, 0);
        }
        if immediate & 0x0c == 0x08 && sign != 0 {
            return (0xffc0_0000, 1);
        }
        let (normalized_fraction, unbiased_exponent, flags) = if exponent == 0 {
            let highest = 31 - fraction.leading_zeros();
            let shift = 23 - highest;
            ((fraction << shift) & 0x007f_ffff, highest as i32 - 149, 1 << 1)
        }
        else {
            (fraction, ((exponent >> 23) as i32) - 127, 0)
        };
        let output_exponent = match immediate & 3 {
            0 => 127,
            1 if unbiased_exponent & 1 != 0 => 126,
            1 => 127,
            2 => 126,
            3 if normalized_fraction >= 0x0040_0000 => 126,
            3 => 127,
            _ => unreachable!(),
        };
        let output_sign = if immediate & 0x0c == 0 { sign } else { 0 };
        (output_sign | ((output_exponent as u32) << 23) | normalized_fraction, flags)
    }

    fn getmant_f64(bits: u64, immediate: u8) -> (u64, u32) {
        let sign = bits & 0x8000_0000_0000_0000;
        let exponent = bits & 0x7ff0_0000_0000_0000;
        let fraction = bits & 0x000f_ffff_ffff_ffff;
        if exponent == 0x7ff0_0000_0000_0000 {
            if fraction != 0 {
                return quiet_nan_f64(bits);
            }
            if immediate & 0x0c == 0x08 && sign != 0 {
                return (0xfff8_0000_0000_0000, 1);
            }
            return (0x3ff0_0000_0000_0000 | if immediate & 0x0c == 0 { sign } else { 0 }, 0);
        }
        if exponent == 0 && fraction == 0 {
            return (0x3ff0_0000_0000_0000 | if immediate & 0x0c == 0x04 { 0 } else { sign }, 0);
        }
        if immediate & 0x0c == 0x08 && sign != 0 {
            return (0xfff8_0000_0000_0000, 1);
        }
        let (normalized_fraction, unbiased_exponent, flags) = if exponent == 0 {
            let highest = 63 - fraction.leading_zeros();
            let shift = 52 - highest;
            ((fraction << shift) & 0x000f_ffff_ffff_ffff, highest as i32 - 1074, 1 << 1)
        }
        else {
            (fraction, ((exponent >> 52) as i32) - 1023, 0)
        };
        let output_exponent = match immediate & 3 {
            0 => 1023,
            1 if unbiased_exponent & 1 != 0 => 1022,
            1 => 1023,
            2 => 1022,
            3 if normalized_fraction >= 0x0008_0000_0000_0000 => 1022,
            3 => 1023,
            _ => unreachable!(),
        };
        let output_sign = if immediate & 0x0c == 0 { sign } else { 0 };
        (output_sign | ((output_exponent as u64) << 52) | normalized_fraction, flags)
    }

    fn getmant_packed(cpu: &mut Cpu, dst: VarNode, args: [Value; 2], double: bool) {
        let immediate = cpu.read::<u8>(args[1]);
        let lane_bytes = if double { 8 } else { 4 };
        let lanes = 16 / lane_bytes;
        let mut flags = 0;
        for lane in 0..lanes {
            if !evex_lane_active(cpu, lane, lanes) {
                continue;
            }
            let offset = (lane * lane_bytes) as u8;
            if double {
                let (value, lane_flags) =
                    getmant_f64(cpu.read::<u64>(args[0].slice(offset, 8)), immediate);
                cpu.write_var(dst.slice(offset, 8), value);
                flags |= lane_flags;
            }
            else {
                let (value, lane_flags) =
                    getmant_f32(cpu.read::<u32>(args[0].slice(offset, 4)), immediate);
                cpu.write_var(dst.slice(offset, 4), value);
                flags |= lane_flags;
            }
        }
        raise_mxcsr_flags(cpu, flags);
    }
    fn getmant_pd(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        getmant_packed(cpu, dst, args, true);
    }
    fn getmant_ps(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        getmant_packed(cpu, dst, args, false);
    }
    fn getmant_sd(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let immediate = cpu.args[0] as u8;
        cpu.write_var(dst, cpu.read::<u128>(args[0]));
        if evex_scalar_lane_active(cpu) {
            let (value, flags) = getmant_f64(cpu.read::<u64>(args[1].slice(0, 8)), immediate);
            cpu.write_var(dst.slice(0, 8), value);
            raise_mxcsr_flags(cpu, flags);
        }
    }
    fn getmant_ss(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let immediate = cpu.args[0] as u8;
        cpu.write_var(dst, cpu.read::<u128>(args[0]));
        if evex_scalar_lane_active(cpu) {
            let (value, flags) = getmant_f32(cpu.read::<u32>(args[1].slice(0, 4)), immediate);
            cpu.write_var(dst.slice(0, 4), value);
            raise_mxcsr_flags(cpu, flags);
        }
    }

    fn quantize_f32_14(value: f32) -> f32 {
        let bits = value.to_bits();
        if bits & 0x7f80_0000 == 0x7f80_0000 || bits & 0x7fff_ffff == 0 {
            return value;
        }
        f32::from_bits((bits.wrapping_add(1 << 8)) & !0x1ff)
    }

    fn quantize_f64_14(value: f64) -> f64 {
        let bits = value.to_bits();
        if bits & 0x7ff0_0000_0000_0000 == 0x7ff0_0000_0000_0000
            || bits & 0x7fff_ffff_ffff_ffff == 0
        {
            return value;
        }
        f64::from_bits((bits.wrapping_add(1 << 37)) & !((1_u64 << 38) - 1))
    }

    fn approximate_unary_packed(
        cpu: &mut Cpu,
        dst: VarNode,
        source: Value,
        double: bool,
        reciprocal_sqrt: bool,
    ) {
        let lane_bytes = if double { 8 } else { 4 };
        let lanes = 16 / lane_bytes;
        for lane in 0..lanes {
            if !evex_lane_active(cpu, lane, lanes) {
                continue;
            }
            let offset = (lane * lane_bytes) as u8;
            if double {
                let input = f64::from_bits(cpu.read::<u64>(source.slice(offset, 8)));
                let result = if reciprocal_sqrt { 1.0 / input.sqrt() } else { 1.0 / input };
                cpu.write_var(dst.slice(offset, 8), quantize_f64_14(result).to_bits());
            }
            else {
                let input = f32::from_bits(cpu.read::<u32>(source.slice(offset, 4)));
                let result = if reciprocal_sqrt { 1.0 / input.sqrt() } else { 1.0 / input };
                cpu.write_var(dst.slice(offset, 4), quantize_f32_14(result).to_bits());
            }
        }
    }

    fn rcp14_pd(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        approximate_unary_packed(cpu, dst, args[0], true, false);
    }
    fn rcp14_ps(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        approximate_unary_packed(cpu, dst, args[0], false, false);
    }
    fn rsqrt14_pd(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        approximate_unary_packed(cpu, dst, args[0], true, true);
    }
    fn rsqrt14_ps(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        approximate_unary_packed(cpu, dst, args[0], false, true);
    }

    fn approximate_unary_scalar(
        cpu: &mut Cpu,
        dst: VarNode,
        args: [Value; 2],
        double: bool,
        reciprocal_sqrt: bool,
    ) {
        cpu.write_var(dst, cpu.read::<u128>(args[0]));
        if !evex_scalar_lane_active(cpu) {
            return;
        }
        if double {
            let input = f64::from_bits(cpu.read::<u64>(args[1].slice(0, 8)));
            let result = if reciprocal_sqrt { 1.0 / input.sqrt() } else { 1.0 / input };
            cpu.write_var(dst.slice(0, 8), quantize_f64_14(result).to_bits());
        }
        else {
            let input = f32::from_bits(cpu.read::<u32>(args[1].slice(0, 4)));
            let result = if reciprocal_sqrt { 1.0 / input.sqrt() } else { 1.0 / input };
            cpu.write_var(dst.slice(0, 4), quantize_f32_14(result).to_bits());
        }
    }
    fn rcp14_sd(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        approximate_unary_scalar(cpu, dst, args, true, false);
    }
    fn rcp14_ss(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        approximate_unary_scalar(cpu, dst, args, false, false);
    }
    fn rsqrt14_sd(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        approximate_unary_scalar(cpu, dst, args, true, true);
    }
    fn rsqrt14_ss(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        approximate_unary_scalar(cpu, dst, args, false, true);
    }

    fn rndscale_f64(bits: u64, immediate: u8, mxcsr: u32) -> (u64, u32) {
        let exponent = bits & 0x7ff0_0000_0000_0000;
        let fraction = bits & 0x000f_ffff_ffff_ffff;
        if exponent == 0x7ff0_0000_0000_0000 && fraction != 0 {
            return quiet_nan_f64(bits);
        }
        let scale = i32::from(immediate >> 4);
        let mode = if immediate & 4 != 0 { ((mxcsr >> 13) & 3) as u8 } else { immediate & 3 };
        let daz = mxcsr & (1 << 6) != 0;
        let scaled = f64::from_bits(bits) * 2.0_f64.powi(scale);
        let (rounded, flags) = round_f64_bits(scaled.to_bits(), mode, daz);
        ((f64::from_bits(rounded) * 2.0_f64.powi(-scale)).to_bits(), flags & !(1 << 1))
    }
    fn rndscale_f32(bits: u32, immediate: u8, mxcsr: u32) -> (u32, u32) {
        let exponent = bits & 0x7f80_0000;
        let fraction = bits & 0x007f_ffff;
        if exponent == 0x7f80_0000 && fraction != 0 {
            return quiet_nan_f32(bits);
        }
        let scale = i32::from(immediate >> 4);
        let mode = if immediate & 4 != 0 { ((mxcsr >> 13) & 3) as u8 } else { immediate & 3 };
        let daz = mxcsr & (1 << 6) != 0;
        let scaled = f32::from_bits(bits) * 2.0_f32.powi(scale);
        let (rounded, flags) = round_f32_bits(scaled.to_bits(), mode, daz);
        ((f32::from_bits(rounded) * 2.0_f32.powi(-scale)).to_bits(), flags & !(1 << 1))
    }

    fn rndscale_packed(cpu: &mut Cpu, dst: VarNode, args: [Value; 2], double: bool) {
        let immediate = cpu.read::<u8>(args[1]);
        let mxcsr = read_named::<u32>(cpu, "MXCSR").unwrap_or(0x1f80);
        let lane_bytes = if double { 8 } else { 4 };
        let lanes = 16 / lane_bytes;
        let mut flags = 0;
        for lane in 0..lanes {
            if !evex_lane_active(cpu, lane, lanes) {
                continue;
            }
            let offset = (lane * lane_bytes) as u8;
            if double {
                let (value, lane_flags) =
                    rndscale_f64(cpu.read::<u64>(args[0].slice(offset, 8)), immediate, mxcsr);
                cpu.write_var(dst.slice(offset, 8), value);
                flags |= lane_flags;
            }
            else {
                let (value, lane_flags) =
                    rndscale_f32(cpu.read::<u32>(args[0].slice(offset, 4)), immediate, mxcsr);
                cpu.write_var(dst.slice(offset, 4), value);
                flags |= lane_flags;
            }
        }
        raise_mxcsr_flags(cpu, if immediate & 8 == 0 { flags } else { flags & !(1 << 5) });
    }
    fn rndscale_pd(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        rndscale_packed(cpu, dst, args, true);
    }
    fn rndscale_ps(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        rndscale_packed(cpu, dst, args, false);
    }
    fn rndscale_sd(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let immediate = cpu.args[0] as u8;
        let mxcsr = read_named::<u32>(cpu, "MXCSR").unwrap_or(0x1f80);
        cpu.write_var(dst, cpu.read::<u128>(args[0]));
        if evex_scalar_lane_active(cpu) {
            let (value, flags) =
                rndscale_f64(cpu.read::<u64>(args[1].slice(0, 8)), immediate, mxcsr);
            cpu.write_var(dst.slice(0, 8), value);
            raise_mxcsr_flags(cpu, if immediate & 8 == 0 { flags } else { flags & !(1 << 5) });
        }
    }
    fn rndscale_ss(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let immediate = cpu.args[0] as u8;
        let mxcsr = read_named::<u32>(cpu, "MXCSR").unwrap_or(0x1f80);
        cpu.write_var(dst, cpu.read::<u128>(args[0]));
        if evex_scalar_lane_active(cpu) {
            let (value, flags) =
                rndscale_f32(cpu.read::<u32>(args[1].slice(0, 4)), immediate, mxcsr);
            cpu.write_var(dst.slice(0, 4), value);
            raise_mxcsr_flags(cpu, if immediate & 8 == 0 { flags } else { flags & !(1 << 5) });
        }
    }

    fn scalef_f32(value_bits: u32, scale_bits: u32) -> (u32, u32) {
        let (value_nan, value_signaling) = f32_nan_kind(value_bits);
        if value_nan {
            return (value_bits | 0x0040_0000, u32::from(value_signaling));
        }
        let (scale_nan, scale_signaling) = f32_nan_kind(scale_bits);
        if scale_nan {
            return (scale_bits | 0x0040_0000, u32::from(scale_signaling));
        }
        let value_zero = value_bits & 0x7fff_ffff == 0;
        let value_infinite = value_bits & 0x7fff_ffff == 0x7f80_0000;
        let scale_positive_infinite = scale_bits == 0x7f80_0000;
        let scale_negative_infinite = scale_bits == 0xff80_0000;
        if (value_zero && scale_positive_infinite) || (value_infinite && scale_negative_infinite) {
            return (0xffc0_0000, 1);
        }
        let value = f32::from_bits(value_bits);
        let scale = f32::from_bits(scale_bits).floor();
        // SCALEF applies the (floored) source exponent before IEEE-754
        // rounding.  Clamping at the f32 result limits is incorrect: a large
        // finite significand can still produce a subnormal at -150, while an
        // exponent below that must continue toward signed zero.  f64 is wide
        // enough to evaluate every f32 result-relevant exponent exactly; the
        // wider bounds only avoid feeding an unbounded converted exponent to
        // powi.  Values beyond them already have the same f32 result and
        // exception class as the chosen endpoint.
        let exponent = scale.clamp(-512.0, 512.0) as i32;
        let exact = f64::from(value) * 2.0_f64.powi(exponent);
        let result = exact as f32;
        let mut flags = 0_u32;
        let value_subnormal = value_bits & 0x7f80_0000 == 0 && value_bits & 0x007f_ffff != 0;
        let scale_subnormal = scale_bits & 0x7f80_0000 == 0 && scale_bits & 0x007f_ffff != 0;
        if value_subnormal || scale_subnormal {
            flags |= 1 << 1;
        }
        if value.is_finite() && value != 0.0 {
            if result.is_infinite() {
                flags |= (1 << 3) | (1 << 5);
            }
            else if f64::from(result) != exact {
                flags |= 1 << 5;
                if result == 0.0 || result.is_subnormal() {
                    flags |= 1 << 4;
                }
            }
        }
        (result.to_bits(), flags)
    }

    fn scalef_f64(value_bits: u64, scale_bits: u64) -> (u64, u32) {
        let (value_nan, value_signaling) = f64_nan_kind(value_bits);
        if value_nan {
            return (value_bits | 0x0008_0000_0000_0000, u32::from(value_signaling));
        }
        let (scale_nan, scale_signaling) = f64_nan_kind(scale_bits);
        if scale_nan {
            return (scale_bits | 0x0008_0000_0000_0000, u32::from(scale_signaling));
        }
        let value_zero = value_bits & 0x7fff_ffff_ffff_ffff == 0;
        let value_infinite = value_bits & 0x7fff_ffff_ffff_ffff == 0x7ff0_0000_0000_0000;
        let scale_positive_infinite = scale_bits == 0x7ff0_0000_0000_0000;
        let scale_negative_infinite = scale_bits == 0xfff0_0000_0000_0000;
        if (value_zero && scale_positive_infinite) || (value_infinite && scale_negative_infinite) {
            return (0xfff8_0000_0000_0000, 1);
        }
        let value = f64::from_bits(value_bits);
        let scale = f64::from_bits(scale_bits).floor();
        let exponent = scale.clamp(-1075.0, 1024.0) as i32;
        let result = if exponent < -1022 {
            (value * 2.0_f64.powi(exponent + 1022)) * 2.0_f64.powi(-1022)
        }
        else if exponent > 1023 {
            (value * 2.0) * 2.0_f64.powi(1023)
        }
        else {
            value * 2.0_f64.powi(exponent)
        };
        let mut flags = 0_u32;
        let value_subnormal =
            value_bits & 0x7ff0_0000_0000_0000 == 0 && value_bits & 0x000f_ffff_ffff_ffff != 0;
        let scale_subnormal =
            scale_bits & 0x7ff0_0000_0000_0000 == 0 && scale_bits & 0x000f_ffff_ffff_ffff != 0;
        if value_subnormal || scale_subnormal {
            flags |= 1 << 1;
        }
        if value.is_finite() && value != 0.0 {
            if result.is_infinite() {
                flags |= (1 << 3) | (1 << 5);
            }
            else if result == 0.0 {
                flags |= (1 << 4) | (1 << 5);
            }
        }
        (result.to_bits(), flags)
    }

    fn scalef_packed(cpu: &mut Cpu, dst: VarNode, args: [Value; 2], double: bool) {
        let lane_bytes = if double { 8 } else { 4 };
        let lanes = 16 / lane_bytes;
        let mut flags = 0_u32;
        for lane in 0..lanes {
            if !evex_lane_active(cpu, lane, lanes) {
                continue;
            }
            let offset = (lane * lane_bytes) as u8;
            if double {
                let (result, lane_flags) = scalef_f64(
                    cpu.read::<u64>(args[0].slice(offset, 8)),
                    cpu.read::<u64>(args[1].slice(offset, 8)),
                );
                flags |= lane_flags;
                cpu.write_var(dst.slice(offset, 8), result);
            }
            else {
                let (result, lane_flags) = scalef_f32(
                    cpu.read::<u32>(args[0].slice(offset, 4)),
                    cpu.read::<u32>(args[1].slice(offset, 4)),
                );
                flags |= lane_flags;
                cpu.write_var(dst.slice(offset, 4), result);
            }
        }
        raise_mxcsr_flags(cpu, flags);
    }
    fn scalef_pd(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        scalef_packed(cpu, dst, args, true);
    }
    fn scalef_ps(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        scalef_packed(cpu, dst, args, false);
    }
    fn scalef_sd(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        cpu.write_var(dst, cpu.read::<u128>(args[0]));
        if evex_scalar_lane_active(cpu) {
            let (result, flags) = scalef_f64(
                cpu.read::<u64>(args[0].slice(0, 8)),
                cpu.read::<u64>(args[1].slice(0, 8)),
            );
            cpu.write_var(dst.slice(0, 8), result);
            raise_mxcsr_flags(cpu, flags);
        }
    }
    fn scalef_ss(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        cpu.write_var(dst, cpu.read::<u128>(args[0]));
        if evex_scalar_lane_active(cpu) {
            let (result, flags) = scalef_f32(
                cpu.read::<u32>(args[0].slice(0, 4)),
                cpu.read::<u32>(args[1].slice(0, 4)),
            );
            cpu.write_var(dst.slice(0, 4), result);
            raise_mxcsr_flags(cpu, flags);
        }
    }

    fn fixup_class_f32(bits: u32) -> usize {
        let exponent = bits & 0x7f80_0000;
        let fraction = bits & 0x007f_ffff;
        if exponent == 0x7f80_0000 && fraction != 0 {
            usize::from(fraction & 0x0040_0000 == 0)
        }
        else if bits & 0x7fff_ffff == 0 {
            2
        }
        else if bits == 0x3f80_0000 {
            3
        }
        else if bits == 0xff80_0000 {
            4
        }
        else if bits == 0x7f80_0000 {
            5
        }
        else if bits >> 31 != 0 {
            6
        }
        else {
            7
        }
    }
    fn fixup_class_f64(bits: u64) -> usize {
        let exponent = bits & 0x7ff0_0000_0000_0000;
        let fraction = bits & 0x000f_ffff_ffff_ffff;
        if exponent == 0x7ff0_0000_0000_0000 && fraction != 0 {
            usize::from(fraction & 0x0008_0000_0000_0000 == 0)
        }
        else if bits & 0x7fff_ffff_ffff_ffff == 0 {
            2
        }
        else if bits == 0x3ff0_0000_0000_0000 {
            3
        }
        else if bits == 0xfff0_0000_0000_0000 {
            4
        }
        else if bits == 0x7ff0_0000_0000_0000 {
            5
        }
        else if bits >> 63 != 0 {
            6
        }
        else {
            7
        }
    }
    fn fixup_action_f32(old: u32, source: u32, action: u8) -> u32 {
        match action & 0xf {
            0 => old,
            1 => source,
            2 => 0x7fc0_0000,
            3 => 0xffc0_0000,
            4 => 0xff80_0000,
            5 => 0x7f80_0000,
            6 => (source & 0x8000_0000) | 0x7f80_0000,
            7 => 0x8000_0000,
            8 => 0,
            9 => 0xbf80_0000,
            10 => 0x3f80_0000,
            11 => 0x3f00_0000,
            12 => 90.0_f32.to_bits(),
            13 => core::f32::consts::FRAC_PI_2.to_bits(),
            14 => 0x7f7f_ffff,
            _ => 0xff7f_ffff,
        }
    }
    fn fixup_action_f64(old: u64, source: u64, action: u8) -> u64 {
        match action & 0xf {
            0 => old,
            1 => source,
            2 => 0x7ff8_0000_0000_0000,
            3 => 0xfff8_0000_0000_0000,
            4 => 0xfff0_0000_0000_0000,
            5 => 0x7ff0_0000_0000_0000,
            6 => (source & 0x8000_0000_0000_0000) | 0x7ff0_0000_0000_0000,
            7 => 0x8000_0000_0000_0000,
            8 => 0,
            9 => 0xbff0_0000_0000_0000,
            10 => 0x3ff0_0000_0000_0000,
            11 => 0x3fe0_0000_0000_0000,
            12 => 90.0_f64.to_bits(),
            13 => core::f64::consts::FRAC_PI_2.to_bits(),
            14 => 0x7fef_ffff_ffff_ffff,
            _ => 0xffef_ffff_ffff_ffff,
        }
    }
    fn fixup_packed(cpu: &mut Cpu, dst: VarNode, args: [Value; 2], double: bool) {
        let control = cpu.args[0].to_le_bytes();
        let immediate = cpu.args[1] as u8;
        let lane_bytes = if double { 8 } else { 4 };
        let lanes = 16 / lane_bytes;
        let mut flags = 0;
        for lane in 0..lanes {
            if !evex_lane_active(cpu, lane, lanes) {
                continue;
            }
            let offset = (lane * lane_bytes) as u8;
            if double {
                let old = cpu.read::<u64>(args[0].slice(offset, 8));
                let source = cpu.read::<u64>(args[1].slice(offset, 8));
                let table = u64::from_le_bytes(control[lane * 8..lane * 8 + 8].try_into().unwrap());
                let class = fixup_class_f64(source);
                cpu.write_var(
                    dst.slice(offset, 8),
                    fixup_action_f64(old, source, ((table >> (class * 4)) & 0xf) as u8),
                );
                if immediate & (1 << class) != 0 {
                    flags |= if class == 2 { 1 << 2 } else { 1 };
                }
            }
            else {
                let old = cpu.read::<u32>(args[0].slice(offset, 4));
                let source = cpu.read::<u32>(args[1].slice(offset, 4));
                let table = u32::from_le_bytes(control[lane * 4..lane * 4 + 4].try_into().unwrap());
                let class = fixup_class_f32(source);
                cpu.write_var(
                    dst.slice(offset, 4),
                    fixup_action_f32(old, source, ((table >> (class * 4)) & 0xf) as u8),
                );
                if immediate & (1 << class) != 0 {
                    flags |= if class == 2 { 1 << 2 } else { 1 };
                }
            }
        }
        raise_mxcsr_flags(cpu, flags);
    }
    fn fixup_pd(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        fixup_packed(cpu, dst, args, true);
    }
    fn fixup_ps(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        fixup_packed(cpu, dst, args, false);
    }
    fn fixup_sd(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        cpu.write_var(dst, cpu.read::<u128>(args[1]));
        if current_evex_mask(cpu) & 1 == 0 {
            return;
        }
        let old = cpu.read::<u64>(args[0].slice(0, 8));
        let source = cpu.read::<u64>(args[1].slice(0, 8));
        let class = fixup_class_f64(source);
        let table = cpu.args[0] as u64;
        cpu.write_var(
            dst.slice(0, 8),
            fixup_action_f64(old, source, ((table >> (class * 4)) & 0xf) as u8),
        );
    }
    fn fixup_ss(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        cpu.write_var(dst, cpu.read::<u128>(args[1]));
        if current_evex_mask(cpu) & 1 == 0 {
            return;
        }
        let old = cpu.read::<u32>(args[0].slice(0, 4));
        let source = cpu.read::<u32>(args[1].slice(0, 4));
        let class = fixup_class_f32(source);
        let table = cpu.args[0] as u32;
        cpu.write_var(
            dst.slice(0, 4),
            fixup_action_f32(old, source, ((table >> (class * 4)) & 0xf) as u8),
        );
    }

    fn convert_scalar_f64_to_f32(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 16 || args[0].size() != 16 || args[1].size() < 8 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            return;
        }
        cpu.write_var(dst, cpu.read::<u128>(args[0]));
        if current_evex_mask(cpu) & 1 == 0 {
            return;
        }
        let source = cpu.read::<u64>(args[1].slice(0, 8));
        let mxcsr = read_named::<u32>(cpu, "MXCSR").unwrap_or(0x1f80);
        let (result, flags) = narrow_f64_bits(
            source,
            ((mxcsr >> 13) & 3) as u8,
            mxcsr & (1 << 6) != 0,
            mxcsr & (1 << 15) != 0,
        );
        cpu.write_var(dst.slice(0, 4), result);
        raise_mxcsr_flags(cpu, flags);
    }

    fn convert_scalar_f32_to_f64(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 16 || args[0].size() != 16 || args[1].size() < 4 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            return;
        }
        cpu.write_var(dst, cpu.read::<u128>(args[0]));
        if current_evex_mask(cpu) & 1 == 0 {
            return;
        }
        let bits = cpu.read::<u32>(args[1].slice(0, 4));
        let mxcsr = read_named::<u32>(cpu, "MXCSR").unwrap_or(0x1f80);
        let (result, flags) = widen_f32_bits(bits, mxcsr & (1 << 6) != 0);
        cpu.write_var(dst.slice(0, 8), result);
        raise_mxcsr_flags(cpu, flags);
    }

    fn half_to_f32_bits(bits: u16) -> (u32, u32) {
        let sign = u32::from(bits & 0x8000) << 16;
        let exponent = (bits >> 10) & 0x1f;
        let fraction = bits & 0x03ff;
        match (exponent, fraction) {
            (0, 0) => (sign, 0),
            (0, _) => {
                let leading = fraction.leading_zeros() - 6;
                let normalized = u32::from(fraction) << (leading + 1);
                let exponent = 127 - 15 - leading;
                (sign | (exponent << 23) | ((normalized & 0x03ff) << 13), 1 << 1)
            }
            (0x1f, 0) => (sign | 0x7f80_0000, 0),
            (0x1f, _) => {
                let signaling = fraction & 0x0200 == 0;
                (
                    sign | 0x7f80_0000 | (u32::from(fraction) << 13) | 0x0040_0000,
                    u32::from(signaling),
                )
            }
            _ => (sign | (u32::from(exponent + (127 - 15)) << 23) | (u32::from(fraction) << 13), 0),
        }
    }

    fn convert_f16_to_f32(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 16 || args[0].size() < 8 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            return;
        }
        let mut flags = 0;
        for lane in 0..4_u8 {
            let (bits, lane_flags) = half_to_f32_bits(cpu.read::<u16>(args[0].slice(lane * 2, 2)));
            cpu.write_var(dst.slice(lane * 4, 4), bits);
            flags |= lane_flags;
        }
        raise_mxcsr_flags(cpu, flags);
    }

    fn f32_to_half_bits(bits: u32, mode: u8) -> (u16, u32) {
        let sign = ((bits >> 16) & 0x8000) as u16;
        let exponent = ((bits >> 23) & 0xff) as i32;
        let fraction = bits & 0x007f_ffff;
        let source_flags = if exponent == 0 && fraction != 0 { 1 << 1 } else { 0 };
        if exponent == 0xff {
            if fraction == 0 {
                return (sign | 0x7c00, 0);
            }
            return (
                sign | 0x7c00 | ((fraction >> 13) as u16) | 0x0200,
                u32::from(fraction & 0x0040_0000 == 0),
            );
        }
        let value = f32::from_bits(bits);
        if value == 0.0 {
            return (sign, source_flags);
        }
        let negative = sign != 0;
        let unbiased = exponent - 127;
        let (mut significand, shift, half_exponent) = if unbiased >= -14 {
            ((1_u64 << 23) | u64::from(fraction), 13_u32, unbiased + 15)
        }
        else {
            ((1_u64 << 23) | u64::from(fraction), (-unbiased - 1) as u32, 0)
        };
        let (rounded, inexact) = round_shift_u64(significand, shift, negative, mode);
        significand = rounded;
        if half_exponent >= 31 || significand >= 0x800 && half_exponent == 30 {
            return (sign | 0x7c00, source_flags | (1 << 3) | (1 << 5));
        }
        let mut exponent_bits = half_exponent.max(0) as u16;
        if significand == 0x800 {
            exponent_bits += 1;
            significand = 0x400;
        }
        let result = sign | (exponent_bits << 10) | (significand as u16 & 0x03ff);
        let mut flags = source_flags;
        if inexact {
            flags |= 1 << 5;
            if exponent_bits == 0 {
                flags |= 1 << 4;
            }
        }
        (result, flags)
    }

    fn convert_f32_to_f16(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if args[0].size() != 16 || dst.size < 8 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            return;
        }
        let immediate = cpu.read::<u8>(args[1]);
        let mxcsr = read_named::<u32>(cpu, "MXCSR").unwrap_or(0x1f80);
        let mode = if immediate & 4 != 0 { ((mxcsr >> 13) & 3) as u8 } else { immediate & 3 };
        let mut flags = 0;
        for lane in 0..4_u8 {
            let (bits, lane_flags) =
                f32_to_half_bits(cpu.read::<u32>(args[0].slice(lane * 4, 4)), mode);
            cpu.write_var(dst.slice(lane * 2, 2), bits);
            flags |= lane_flags;
        }
        if immediate & 8 == 0 {
            raise_mxcsr_flags(cpu, flags);
        }
    }
    fn mulpd_masked(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let (mask, chunk) = masked_binary_context(cpu);
        f64x2_binop_masked(cpu, dst, args, mask, chunk, |x, y| x * y);
    }
    fn mulps_masked(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let (mask, chunk) = masked_binary_context(cpu);
        f32x4_binop_masked(cpu, dst, args, mask, chunk, |x, y| x * y);
    }
    fn subpd(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        f64x2_binop(cpu, dst, args, |x, y| x - y);
    }
    fn subpd_masked(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let (mask, chunk) = masked_binary_context(cpu);
        f64x2_binop_masked(cpu, dst, args, mask, chunk, |x, y| x - y);
    }
    fn subps(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        f32x4_binop(cpu, dst, args, |x, y| x - y);
    }
    fn subps_masked(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let (mask, chunk) = masked_binary_context(cpu);
        f32x4_binop_masked(cpu, dst, args, mask, chunk, |x, y| x - y);
    }
    fn maxpd(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        f64x2_binop(cpu, dst, args, |x, y| if x > y { x } else { y });
    }
    fn maxpd_masked(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let (mask, chunk) = masked_binary_context(cpu);
        f64x2_binop_masked(cpu, dst, args, mask, chunk, |x, y| if x > y { x } else { y });
    }
    fn maxps(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        f32x4_binop(cpu, dst, args, |x, y| if x > y { x } else { y });
    }
    fn maxps_masked(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let (mask, chunk) = masked_binary_context(cpu);
        f32x4_binop_masked(cpu, dst, args, mask, chunk, |x, y| if x > y { x } else { y });
    }
    fn minpd(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        f64x2_binop(cpu, dst, args, |x, y| if x < y { x } else { y });
    }
    fn minpd_masked(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let (mask, chunk) = masked_binary_context(cpu);
        f64x2_binop_masked(cpu, dst, args, mask, chunk, |x, y| if x < y { x } else { y });
    }
    fn minps(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        f32x4_binop(cpu, dst, args, |x, y| if x < y { x } else { y });
    }
    fn minps_masked(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let (mask, chunk) = masked_binary_context(cpu);
        f32x4_binop_masked(cpu, dst, args, mask, chunk, |x, y| if x < y { x } else { y });
    }

    fn scalar_f64_binop_masked(
        cpu: &mut Cpu,
        dst: VarNode,
        args: [Value; 2],
        operation: fn(f64, f64) -> f64,
    ) {
        if dst.size != 16 || args[0].size() != 16 || args[1].size() < 8 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(args[1].size());
            return;
        }
        let mut out = cpu.read::<u128>(args[0]).to_le_bytes();
        if current_evex_mask(cpu) & 1 != 0 {
            with_guest_mxcsr(cpu, |cpu| {
                let first = f64::from_bits(u64::from_le_bytes(out[0..8].try_into().unwrap()));
                let second = f64::from_bits(cpu.read::<u64>(args[1].slice(0, 8)));
                out[0..8].copy_from_slice(&operation(first, second).to_bits().to_le_bytes());
            });
        }
        write_xmm(cpu, dst, out);
    }

    fn scalar_f32_binop_masked(
        cpu: &mut Cpu,
        dst: VarNode,
        args: [Value; 2],
        operation: fn(f32, f32) -> f32,
    ) {
        if dst.size != 16 || args[0].size() != 16 || args[1].size() < 4 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(args[1].size());
            return;
        }
        let mut out = cpu.read::<u128>(args[0]).to_le_bytes();
        if current_evex_mask(cpu) & 1 != 0 {
            with_guest_mxcsr(cpu, |cpu| {
                let first = f32::from_bits(u32::from_le_bytes(out[0..4].try_into().unwrap()));
                let second = f32::from_bits(cpu.read::<u32>(args[1].slice(0, 4)));
                out[0..4].copy_from_slice(&operation(first, second).to_bits().to_le_bytes());
            });
        }
        write_xmm(cpu, dst, out);
    }

    fn addsd_masked(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        scalar_f64_binop_masked(cpu, dst, args, |x, y| x + y);
    }
    fn addss_masked(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        scalar_f32_binop_masked(cpu, dst, args, |x, y| x + y);
    }
    fn divsd_masked(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        scalar_f64_binop_masked(cpu, dst, args, |x, y| x / y);
    }
    fn divss_masked(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        scalar_f32_binop_masked(cpu, dst, args, |x, y| x / y);
    }
    fn mulsd_masked(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        scalar_f64_binop_masked(cpu, dst, args, |x, y| x * y);
    }
    fn mulss_masked(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        scalar_f32_binop_masked(cpu, dst, args, |x, y| x * y);
    }
    fn subsd_masked(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        scalar_f64_binop_masked(cpu, dst, args, |x, y| x - y);
    }
    fn subss_masked(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        scalar_f32_binop_masked(cpu, dst, args, |x, y| x - y);
    }

    fn scalar_minmax(cpu: &mut Cpu, dst: VarNode, args: [Value; 2], lane_bytes: u8, maximum: bool) {
        if dst.size != 16 || args[0].size() != 16 || args[1].size() < lane_bytes {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(args[1].size());
            return;
        }
        let mut out = cpu.read::<u128>(args[0]).to_le_bytes();
        with_guest_mxcsr(cpu, |cpu| match lane_bytes {
            4 => {
                let first = f32::from_bits(u32::from_le_bytes(out[0..4].try_into().unwrap()));
                let second = f32::from_bits(cpu.read::<u32>(args[1].slice(0, 4)));
                let result = if if maximum { first > second } else { first < second } {
                    first
                }
                else {
                    second
                };
                out[0..4].copy_from_slice(&result.to_bits().to_le_bytes());
                write_xmm(cpu, dst, out);
            }
            8 => {
                let first = f64::from_bits(u64::from_le_bytes(out[0..8].try_into().unwrap()));
                let second = f64::from_bits(cpu.read::<u64>(args[1].slice(0, 8)));
                let result = if if maximum { first > second } else { first < second } {
                    first
                }
                else {
                    second
                };
                out[0..8].copy_from_slice(&result.to_bits().to_le_bytes());
                write_xmm(cpu, dst, out);
            }
            _ => unreachable!("scalar min/max has a fixed IEEE lane width"),
        });
    }

    fn maxsd(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        scalar_minmax(cpu, dst, args, 8, true);
    }

    fn maxss(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        scalar_minmax(cpu, dst, args, 4, true);
    }

    fn minsd(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        scalar_minmax(cpu, dst, args, 8, false);
    }

    fn minss(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        scalar_minmax(cpu, dst, args, 4, false);
    }

    fn maxsd_masked(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        scalar_f64_binop_masked(cpu, dst, args, |x, y| if x > y { x } else { y });
    }
    fn maxss_masked(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        scalar_f32_binop_masked(cpu, dst, args, |x, y| if x > y { x } else { y });
    }
    fn minsd_masked(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        scalar_f64_binop_masked(cpu, dst, args, |x, y| if x < y { x } else { y });
    }
    fn minss_masked(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        scalar_f32_binop_masked(cpu, dst, args, |x, y| if x < y { x } else { y });
    }

    // sqrt takes its source in the second operand (like pabs).
    fn sqrtpd(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let invalid = packed_sqrt_is_invalid(cpu, args[1], 8, u64::MAX, 0);
        f64x2_binop(cpu, dst, [args[1], args[1]], |x, _| x.sqrt());
        raise_mxcsr_flags(cpu, u32::from(invalid));
    }
    fn sqrtps(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let invalid = packed_sqrt_is_invalid(cpu, args[1], 4, u64::MAX, 0);
        f32x4_binop(cpu, dst, [args[1], args[1]], |x, _| x.sqrt());
        raise_mxcsr_flags(cpu, u32::from(invalid));
    }

    fn vector_sqrtpd(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let invalid = packed_sqrt_is_invalid(cpu, args[0], 8, u64::MAX, 0);
        f64x2_binop(cpu, dst, [args[0], args[0]], |x, _| x.sqrt());
        raise_mxcsr_flags(cpu, u32::from(invalid));
    }

    fn vector_sqrtpd_masked(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let mask = current_evex_mask(cpu);
        let chunk = cpu.args[7] as usize;
        let invalid = packed_sqrt_is_invalid(cpu, args[0], 8, mask, chunk);
        f64x2_binop_masked(cpu, dst, [args[0], args[0]], mask, chunk, |x, _| x.sqrt());
        raise_mxcsr_flags(cpu, u32::from(invalid));
    }

    fn vector_sqrtps(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let invalid = packed_sqrt_is_invalid(cpu, args[0], 4, u64::MAX, 0);
        f32x4_binop(cpu, dst, [args[0], args[0]], |x, _| x.sqrt());
        raise_mxcsr_flags(cpu, u32::from(invalid));
    }

    fn vector_sqrtps_masked(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let mask = current_evex_mask(cpu);
        let chunk = cpu.args[7] as usize;
        let invalid = packed_sqrt_is_invalid(cpu, args[0], 4, mask, chunk);
        f32x4_binop_masked(cpu, dst, [args[0], args[0]], mask, chunk, |x, _| x.sqrt());
        raise_mxcsr_flags(cpu, u32::from(invalid));
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

    fn packed_blend_immediate_indexed(
        cpu: &mut Cpu,
        dst: VarNode,
        args: [Value; 2],
        lane_bytes: usize,
    ) {
        if dst.size != 16 || args[0].size() != 16 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let immediate = cpu.args[0] as u8;
        let chunk = cpu.args[7] as usize;
        let lanes = 16 / lane_bytes;
        for lane in 0..lanes {
            let source =
                if immediate & (1 << (chunk * lanes + lane)) == 0 { args[0] } else { args[1] };
            let offset = (lane * lane_bytes) as u8;
            let value: u128 = cpu.read_dynamic(source.slice(offset, lane_bytes as u8)).zxt();
            cpu.write_trunc(dst.slice(offset, lane_bytes as u8), value);
        }
    }

    fn packed_blend_pd_indexed(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_blend_immediate_indexed(cpu, dst, args, 8);
    }

    fn packed_blend_ps_indexed(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_blend_immediate_indexed(cpu, dst, args, 4);
    }

    fn packed_shuffle_pd_indexed(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 16 || args[0].size() != 16 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let control = (cpu.args[0] as u8) >> (cpu.args[7] as usize * 2);
        let left_lane = if control & 1 == 0 { 0 } else { 8 };
        let right_lane = if control & 2 == 0 { 0 } else { 8 };
        let left = cpu.read::<u64>(args[0].slice(left_lane, 8));
        let right = cpu.read::<u64>(args[1].slice(right_lane, 8));
        cpu.write_var(dst.slice(0, 8), left);
        cpu.write_var(dst.slice(8, 8), right);
    }

    fn packed_shuffle_ps_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 16 || args[0].size() != 16 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let control = cpu.args[0] as u8;
        for lane in 0..4_u8 {
            let source = if lane < 2 { args[0] } else { args[1] };
            let source_lane = (control >> (lane * 2)) & 3;
            let value = cpu.read::<u32>(source.slice(source_lane * 4, 4));
            cpu.write_var(dst.slice(lane * 4, 4), value);
        }
    }

    fn packed_move_ddup_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 16 || args[0].size() < 8 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let value = cpu.read::<u64>(args[0].slice(0, 8));
        cpu.write_var(dst.slice(0, 8), value);
        cpu.write_var(dst.slice(8, 8), value);
    }

    fn packed_move_dup_d_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2], high: bool) {
        if dst.size != 16 || args[0].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        for pair in 0..2_u8 {
            let source_lane = pair * 2 + u8::from(high);
            let value = cpu.read::<u32>(args[0].slice(source_lane * 4, 4));
            cpu.write_var(dst.slice(pair * 8, 4), value);
            cpu.write_var(dst.slice(pair * 8 + 4, 4), value);
        }
    }

    fn packed_move_shdup_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_move_dup_d_128(cpu, dst, args, true);
    }

    fn packed_move_sldup_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_move_dup_d_128(cpu, dst, args, false);
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

    fn packed_move_extend_128_indexed(
        cpu: &mut Cpu,
        dst: VarNode,
        source: Value,
        source_lane_size: u8,
        destination_lane_size: u8,
        signed: bool,
    ) {
        if dst.size != 16
            || source_lane_size == 0
            || destination_lane_size == 0
            || destination_lane_size < source_lane_size
            || 16 % destination_lane_size != 0
        {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let lanes = 16 / destination_lane_size;
        let chunk = cpu.args[7] as u8;
        let Some(source_start) =
            chunk.checked_mul(lanes).and_then(|lane| lane.checked_mul(source_lane_size))
        else {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = cpu.args[7] as u64;
            return;
        };
        let Some(source_end) = source_start.checked_add(lanes * source_lane_size)
        else {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(source.size());
            return;
        };
        if source_end > source.size() {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(source.size());
            return;
        }
        for lane in 0..lanes {
            let source = source.slice(source_start + lane * source_lane_size, source_lane_size);
            let raw: u64 = cpu.read_dynamic(source).zxt();
            let value = if signed {
                let shift = 64 - u32::from(source_lane_size) * 8;
                ((raw << shift) as i64 >> shift) as u64
            }
            else {
                raw
            };
            cpu.write_trunc(dst.slice(lane * destination_lane_size, destination_lane_size), value);
        }
    }

    fn packed_move_sxbd_128_indexed(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_move_extend_128_indexed(cpu, dst, args[0], 1, 4, true);
    }

    fn packed_move_sxbq_128_indexed(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_move_extend_128_indexed(cpu, dst, args[0], 1, 8, true);
    }

    fn packed_move_sxwq_128_indexed(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_move_extend_128_indexed(cpu, dst, args[0], 2, 8, true);
    }

    fn packed_move_zxbq_128_indexed(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_move_extend_128_indexed(cpu, dst, args[0], 1, 8, false);
    }

    fn packed_move_zxwq_128_indexed(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_move_extend_128_indexed(cpu, dst, args[0], 2, 8, false);
    }

    fn pmovzxbw(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        pmov_extend(cpu, dst, args[1], 1, 8, false);
    }
    fn pmovzxbw_single(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        pmov_extend(cpu, dst, args[0], 1, 8, false);
    }

    fn pmovzxwd_single(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        pmov_extend(cpu, dst, args[0], 2, 4, false);
    }

    fn packed_narrow_w_to_b_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 8 || args[0].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        for lane in 0..8_u8 {
            let value = cpu.read::<u16>(args[0].slice(lane * 2, 2)) as u8;
            cpu.write_var(dst.slice(lane, 1), value);
        }
    }

    #[derive(Clone, Copy)]
    enum PackedNarrowMode {
        Truncate,
        SignedSaturate,
        UnsignedSaturate,
    }

    fn packed_narrow_integer(
        cpu: &mut Cpu,
        dst: VarNode,
        source: Value,
        source_lane_size: u8,
        destination_lane_size: u8,
        mode: PackedNarrowMode,
    ) {
        if source_lane_size == 0
            || destination_lane_size == 0
            || source_lane_size > 8
            || destination_lane_size >= source_lane_size
            || source.size() % source_lane_size != 0
        {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(source.size());
            return;
        }
        let lanes = source.size() / source_lane_size;
        let meaningful_size = lanes * destination_lane_size;
        if meaningful_size > dst.size {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        for offset in 0..dst.size {
            cpu.write_var(dst.slice(offset, 1), 0_u8);
        }
        let source_bits = u32::from(source_lane_size) * 8;
        let destination_bits = u32::from(destination_lane_size) * 8;
        let signed_min = -(1_i128 << (destination_bits - 1));
        let signed_max = (1_i128 << (destination_bits - 1)) - 1;
        let unsigned_max = (1_i128 << destination_bits) - 1;
        for lane in 0..lanes {
            let raw: u64 =
                cpu.read_dynamic(source.slice(lane * source_lane_size, source_lane_size)).zxt();
            let shift = 64 - source_bits;
            let signed = ((raw << shift) as i64 >> shift) as i128;
            let result = match mode {
                PackedNarrowMode::Truncate => raw,
                PackedNarrowMode::SignedSaturate => signed.clamp(signed_min, signed_max) as u64,
                PackedNarrowMode::UnsignedSaturate => (raw as i128).min(unsigned_max) as u64,
            };
            cpu.write_trunc(dst.slice(lane * destination_lane_size, destination_lane_size), result);
        }
    }

    macro_rules! integer_narrow_helper {
        ($name:ident, $source:expr, $destination:expr, $mode:expr) => {
            fn $name(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
                packed_narrow_integer(cpu, dst, args[0], $source, $destination, $mode);
            }
        };
    }

    integer_narrow_helper!(narrow_dword_to_byte, 4, 1, PackedNarrowMode::Truncate);
    integer_narrow_helper!(narrow_signed_dword_to_byte, 4, 1, PackedNarrowMode::SignedSaturate);
    integer_narrow_helper!(narrow_unsigned_dword_to_byte, 4, 1, PackedNarrowMode::UnsignedSaturate);
    integer_narrow_helper!(narrow_dword_to_word, 4, 2, PackedNarrowMode::Truncate);
    integer_narrow_helper!(narrow_signed_dword_to_word, 4, 2, PackedNarrowMode::SignedSaturate);
    integer_narrow_helper!(narrow_unsigned_dword_to_word, 4, 2, PackedNarrowMode::UnsignedSaturate);
    integer_narrow_helper!(narrow_qword_to_byte, 8, 1, PackedNarrowMode::Truncate);
    integer_narrow_helper!(narrow_signed_qword_to_byte, 8, 1, PackedNarrowMode::SignedSaturate);
    integer_narrow_helper!(narrow_unsigned_qword_to_byte, 8, 1, PackedNarrowMode::UnsignedSaturate);
    integer_narrow_helper!(narrow_qword_to_word, 8, 2, PackedNarrowMode::Truncate);
    integer_narrow_helper!(narrow_signed_qword_to_word, 8, 2, PackedNarrowMode::SignedSaturate);
    integer_narrow_helper!(narrow_unsigned_qword_to_word, 8, 2, PackedNarrowMode::UnsignedSaturate);
    integer_narrow_helper!(narrow_qword_to_dword, 8, 4, PackedNarrowMode::Truncate);
    integer_narrow_helper!(narrow_signed_qword_to_dword, 8, 4, PackedNarrowMode::SignedSaturate);
    integer_narrow_helper!(
        narrow_unsigned_qword_to_dword,
        8,
        4,
        PackedNarrowMode::UnsignedSaturate
    );
    integer_narrow_helper!(narrow_signed_word_to_byte, 2, 1, PackedNarrowMode::SignedSaturate);
    integer_narrow_helper!(narrow_unsigned_word_to_byte, 2, 1, PackedNarrowMode::UnsignedSaturate);
    fn pmovzxbd(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        pmov_extend(cpu, dst, args[1], 1, 4, false);
    }
    fn pmovzxbd_single(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        pmov_extend(cpu, dst, args[0], 1, 4, false);
    }

    fn pmovzxdq_single(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        pmov_extend(cpu, dst, args[0], 4, 2, false);
    }

    fn packed_max_unsigned_d_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 16 || args[0].size() != 16 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        for lane in 0..4_u8 {
            let left = cpu.read::<u32>(args[0].slice(lane * 4, 4));
            let right = cpu.read::<u32>(args[1].slice(lane * 4, 4));
            cpu.write_var(dst.slice(lane * 4, 4), left.max(right));
        }
    }

    fn packed_minmax_128(
        cpu: &mut Cpu,
        dst: VarNode,
        args: [Value; 2],
        element_size: u8,
        signed: bool,
        maximum: bool,
    ) {
        if dst.size != 16
            || args[0].size() != 16
            || args[1].size() != 16
            || !matches!(element_size, 1 | 2 | 4 | 8)
        {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        for offset in (0_u8..16).step_by(usize::from(element_size)) {
            let left: u64 = cpu.read_dynamic(args[0].slice(offset, element_size)).zxt();
            let right: u64 = cpu.read_dynamic(args[1].slice(offset, element_size)).zxt();
            let choose_left = if signed {
                let shift = 64 - u32::from(element_size) * 8;
                let left = ((left << shift) as i64) >> shift;
                let right = ((right << shift) as i64) >> shift;
                if maximum { left >= right } else { left <= right }
            }
            else if maximum {
                left >= right
            }
            else {
                left <= right
            };
            cpu.write_trunc(
                dst.slice(offset, element_size),
                if choose_left { left } else { right },
            );
        }
    }

    macro_rules! minmax_helper {
        ($name:ident, $size:literal, $signed:literal, $maximum:literal) => {
            fn $name(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
                packed_minmax_128(cpu, dst, args, $size, $signed, $maximum);
            }
        };
    }

    minmax_helper!(packed_max_signed_b_128, 1, true, true);
    minmax_helper!(packed_max_signed_w_128, 2, true, true);
    minmax_helper!(packed_max_signed_d_128, 4, true, true);
    minmax_helper!(packed_max_signed_q_128, 8, true, true);
    minmax_helper!(packed_max_unsigned_b_128, 1, false, true);
    minmax_helper!(packed_max_unsigned_w_128, 2, false, true);
    minmax_helper!(packed_max_unsigned_q_128, 8, false, true);
    minmax_helper!(packed_min_signed_b_128, 1, true, false);
    minmax_helper!(packed_min_signed_w_128, 2, true, false);
    minmax_helper!(packed_min_signed_d_128, 4, true, false);
    minmax_helper!(packed_min_signed_q_128, 8, true, false);
    minmax_helper!(packed_min_unsigned_d_128, 4, false, false);
    minmax_helper!(packed_min_unsigned_q_128, 8, false, false);

    fn packed_min_unsigned_b_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 16 || args[0].size() != 16 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let left = cpu.read::<u128>(args[0]).to_le_bytes();
        let right = cpu.read::<u128>(args[1]).to_le_bytes();
        let mut output = [0_u8; 16];
        for lane in 0..16 {
            output[lane] = left[lane].min(right[lane]);
        }
        cpu.write_var(dst, u128::from_le_bytes(output));
    }

    fn packed_average_unsigned_b_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 16 || args[0].size() != 16 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        for lane in 0..16_u8 {
            let left = u16::from(cpu.read::<u8>(args[0].slice(lane, 1)));
            let right = u16::from(cpu.read::<u8>(args[1].slice(lane, 1)));
            cpu.write_var(dst.slice(lane, 1), ((left + right + 1) >> 1) as u8);
        }
    }

    fn packed_average_unsigned_w_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 16 || args[0].size() != 16 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        for offset in (0_u8..16).step_by(2) {
            let left = u32::from(cpu.read::<u16>(args[0].slice(offset, 2)));
            let right = u32::from(cpu.read::<u16>(args[1].slice(offset, 2)));
            cpu.write_var(dst.slice(offset, 2), ((left + right + 1) >> 1) as u16);
        }
    }

    fn packed_min_unsigned_w_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 16 || args[0].size() != 16 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        for lane in 0..8_u8 {
            let left = cpu.read::<u16>(args[0].slice(lane * 2, 2));
            let right = cpu.read::<u16>(args[1].slice(lane * 2, 2));
            cpu.write_var(dst.slice(lane * 2, 2), left.min(right));
        }
    }

    fn packed_compare_greater_b_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 16 || args[0].size() != 16 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let left = cpu.read::<u128>(args[0]).to_le_bytes();
        let right = cpu.read::<u128>(args[1]).to_le_bytes();
        let mut output = [0_u8; 16];
        for lane in 0..16 {
            output[lane] = if (left[lane] as i8) > (right[lane] as i8) { u8::MAX } else { 0 };
        }
        cpu.write_var(dst, u128::from_le_bytes(output));
    }

    fn packed_compare_greater_d_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 16 || args[0].size() != 16 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        for lane in 0..4_u8 {
            let offset = lane * 4;
            let left = cpu.read::<u32>(args[0].slice(offset, 4)) as i32;
            let right = cpu.read::<u32>(args[1].slice(offset, 4)) as i32;
            cpu.write_var(dst.slice(offset, 4), if left > right { u32::MAX } else { 0 });
        }
    }

    fn packed_compare_greater_w_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_compare_greater_lanes_128(cpu, dst, args, 2);
    }

    fn packed_compare_greater_q_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        packed_compare_greater_lanes_128(cpu, dst, args, 8);
    }

    fn packed_compare_greater_lanes_128(
        cpu: &mut Cpu,
        dst: VarNode,
        args: [Value; 2],
        element_size: u8,
    ) {
        if dst.size != 16
            || args[0].size() != 16
            || args[1].size() != 16
            || !matches!(element_size, 2 | 8)
        {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        for offset in (0_u8..16).step_by(usize::from(element_size)) {
            let left: u64 = cpu.read_dynamic(args[0].slice(offset, element_size)).zxt();
            let right: u64 = cpu.read_dynamic(args[1].slice(offset, element_size)).zxt();
            let shift = 64 - u32::from(element_size) * 8;
            let left = ((left << shift) as i64) >> shift;
            let right = ((right << shift) as i64) >> shift;
            let result = if left > right { u64::MAX } else { 0 };
            cpu.write_trunc(dst.slice(offset, element_size), result);
        }
    }

    fn packed_and_not_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 16 || args[0].size() != 16 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let left = cpu.read::<u128>(args[0]);
        let right = cpu.read::<u128>(args[1]);
        cpu.write_var(dst, !left & right);
    }

    fn packed_compare_equal_b_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 16 || args[0].size() != 16 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let left = cpu.read::<u128>(args[0]).to_le_bytes();
        let right = cpu.read::<u128>(args[1]).to_le_bytes();
        let mut output = [0_u8; 16];
        for lane in 0..16 {
            output[lane] = if left[lane] == right[lane] { u8::MAX } else { 0 };
        }
        cpu.write_var(dst, u128::from_le_bytes(output));
    }

    fn packed_compare_equal_d_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 16 || args[0].size() != 16 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        for lane in 0..4_u8 {
            let left = cpu.read::<u32>(args[0].slice(lane * 4, 4));
            let right = cpu.read::<u32>(args[1].slice(lane * 4, 4));
            cpu.write_var(dst.slice(lane * 4, 4), if left == right { u32::MAX } else { 0 });
        }
    }

    fn packed_compare_equal_w_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 16 || args[0].size() != 16 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        for lane in 0..8_u8 {
            let left = cpu.read::<u16>(args[0].slice(lane * 2, 2));
            let right = cpu.read::<u16>(args[1].slice(lane * 2, 2));
            cpu.write_var(dst.slice(lane * 2, 2), if left == right { u16::MAX } else { 0 });
        }
    }

    fn packed_insert_w_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 16 || args[0].size() != 16 || args[1].size() < 2 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let source = cpu.read::<u128>(args[0]).to_le_bytes();
        let mut output = source;
        let lane = cpu.args[0] as usize & 7;
        let value: u64 = cpu.read_dynamic(args[1]).zxt();
        output[lane * 2..lane * 2 + 2].copy_from_slice(&(value as u16).to_le_bytes());
        cpu.write_var(dst, u128::from_le_bytes(output));
    }

    fn packed_insert_b_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 16 || args[0].size() != 16 || args[1].size() < 1 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let mut output = cpu.read::<u128>(args[0]).to_le_bytes();
        let lane = cpu.args[0] as usize & 15;
        output[lane] = cpu.read::<u8>(args[1].slice(0, 1));
        cpu.write_var(dst, u128::from_le_bytes(output));
    }

    fn packed_blend_d_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 16 || args[0].size() != 16 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let immediate = cpu.args[0] as u8;
        for lane in 0..4_u8 {
            let source = if immediate & (1 << lane) == 0 { args[0] } else { args[1] };
            let value = cpu.read::<u32>(source.slice(lane * 4, 4));
            cpu.write_var(dst.slice(lane * 4, 4), value);
        }
    }

    fn packed_move_zxbd_mem_128_chunk(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 16 || args[0].size() != 8 || args[1].size() != 8 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        let address = cpu.read::<u64>(args[0]);
        let mask = cpu.read::<u64>(args[1]);
        let chunk = cpu.args[0] as usize;
        if chunk >= 4 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = chunk as u64;
            return;
        }
        let mut output = [0_u8; 16];
        for lane in 0..4 {
            let source_lane = chunk * 4 + lane;
            if mask & (1_u64 << source_lane) == 0 {
                continue;
            }
            let Some(current) = address.checked_add(source_lane as u64)
            else {
                cpu.exception.code = ExceptionCode::AddressOverflow as u32;
                cpu.exception.value = u64::MAX;
                return;
            };
            let value = match cpu.mem.read::<1>(current, icicle_mem::perm::READ) {
                Ok(value) => value[0],
                Err(error) => {
                    cpu.exception.code = ExceptionCode::from_load_error(error) as u32;
                    cpu.exception.value = current;
                    return;
                }
            };
            output[lane * 4] = value;
        }
        cpu.write_var(dst, u128::from_le_bytes(output));
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
    fn pmovsxbw_single(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        pmov_extend(cpu, dst, args[0], 1, 8, true);
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
    fn pmovsxwd_single(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        pmov_extend(cpu, dst, args[0], 2, 4, true);
    }
    fn pmovsxwq(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        pmov_extend(cpu, dst, args[1], 2, 2, true);
    }
    fn pmovsxdq(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        pmov_extend(cpu, dst, args[1], 4, 2, true);
    }
    fn pmovsxdq_single(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        pmov_extend(cpu, dst, args[0], 4, 2, true);
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

    fn packed_mul_unsigned_dq_128(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 16 || args[0].size() != 16 || args[1].size() != 16 {
            cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
            cpu.exception.value = u64::from(dst.size);
            return;
        }
        for offset in [0_u8, 8] {
            let left = u64::from(cpu.read::<u32>(args[0].slice(offset, 4)));
            let right = u64::from(cpu.read::<u32>(args[1].slice(offset, 4)));
            cpu.write_var(dst.slice(offset, 8), left * right);
        }
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
        let imm = cpu.args[0] as u8;
        let (mode, daz, suppress_precision) = rounding_control(cpu, imm);
        let mut out = [0u8; 16];
        let mut flags = 0_u32;
        if double {
            for i in 0..2 {
                let bits = u64::from_le_bytes(b[8 * i..8 * i + 8].try_into().unwrap());
                let (rounded, lane_flags) = round_f64_bits(bits, mode, daz);
                flags |= lane_flags;
                out[8 * i..8 * i + 8].copy_from_slice(&rounded.to_le_bytes());
            }
        }
        else {
            for i in 0..4 {
                let bits = u32::from_le_bytes(b[4 * i..4 * i + 4].try_into().unwrap());
                let (rounded, lane_flags) = round_f32_bits(bits, mode, daz);
                flags |= lane_flags;
                out[4 * i..4 * i + 4].copy_from_slice(&rounded.to_le_bytes());
            }
        }
        if suppress_precision {
            flags &= !(1 << 5);
        }
        write_xmm(cpu, dst, out);
        raise_mxcsr_flags(cpu, flags);
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
