//! SSE / AES-NI conformance probe.
//!
//! Executes a single instruction in the engine with controlled XMM inputs and
//! compares the result against the native x86-64 intrinsic (the host CPU is
//! the reference), over many random inputs. Covers the SSE2 integer ops and
//! the AES-NI / SSSE3 helpers that Node/V8 and TLS clients exercise. Exits
//! non-zero if any case diverges.

use std::path::PathBuf;

use icicle_cpu::{
    mem::{perm, Mapping},
    ValueSource,
};
use x64_engine::{build::build_x64_vm, EngineConfig, InterpVm, VmExit};

const CODE_ADDR: u64 = 0x1000;

struct Probe {
    vm: InterpVm,
}

impl Probe {
    fn new() -> Self {
        let ldef = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../third_party/ghidra-x86/languages/x86.ldefs");
        let mut config = EngineConfig::default();
        if std::env::var("NO_OPT").is_ok() {
            config.optimize_instructions = false;
            config.optimize_block = false;
        }
        let vm = build_x64_vm(&ldef, &config).expect("build engine");
        Self { vm }
    }

    /// Runs `code` (one instruction) with XMM1=b loaded into memory at
    /// DATA_ADDR and RAX=DATA_ADDR, XMM0=a; returns xmm0. For testing loads
    /// like `movdqu xmm0,[rax]` and memory-operand arithmetic.
    fn run_mem(&mut self, code: &[u8], a: u128, mem: u128) -> u128 {
        const DATA_ADDR: u64 = 0x2000;
        self.vm.cpu.mem.reset_virtual();
        self.vm.cpu.reset();
        self.vm.code.flush_code();
        self.vm.cpu.block_id = u64::MAX;
        self.vm.cpu.mem.map_memory_len(
            CODE_ADDR,
            0x1000,
            Mapping {
                perm: perm::ALL,
                value: 0,
            },
        );
        self.vm.cpu.mem.map_memory_len(
            DATA_ADDR,
            0x1000,
            Mapping {
                perm: perm::ALL,
                value: 0,
            },
        );
        self.vm
            .cpu
            .mem
            .write_bytes(CODE_ADDR, code, perm::NONE)
            .expect("code");
        self.vm
            .cpu
            .mem
            .write_bytes(DATA_ADDR, &mem.to_le_bytes(), perm::NONE)
            .expect("data");
        (self.vm.cpu.arch.on_boot)(&mut self.vm.cpu, CODE_ADDR);
        let xmm0 = self.vm.cpu.arch.sleigh.get_varnode("XMM0").expect("XMM0");
        let rax = self.vm.cpu.arch.sleigh.get_varnode("RAX").expect("RAX");
        self.vm.cpu.write_var(xmm0, a);
        self.vm.cpu.write_reg(rax, DATA_ADDR);
        let before = self.vm.cpu.icount;
        self.vm.icount_limit = self.vm.cpu.icount + 1;
        let exit = self.vm.run();
        assert!(
            self.vm.cpu.icount > before,
            "instruction did not execute: {exit:?}"
        );
        self.vm.cpu.read(xmm0.into())
    }

    /// Runs `code` (one instruction) with XMM0=a, XMM1=b; returns (xmm0, eax).
    fn run(&mut self, code: &[u8], a: u128, b: u128) -> (u128, u64) {
        self.vm.cpu.mem.reset_virtual();
        self.vm.cpu.reset();
        // Flush the lifted-block cache: every run maps code at the same
        // address, so a stale block would otherwise be reused.
        self.vm.code.flush_code();
        self.vm.cpu.block_id = u64::MAX;
        self.vm.cpu.mem.map_memory_len(
            CODE_ADDR,
            0x1000,
            Mapping {
                perm: perm::ALL,
                value: 0,
            },
        );
        self.vm
            .cpu
            .mem
            .write_bytes(CODE_ADDR, code, perm::NONE)
            .expect("write code");

        // on_boot resets the CPU, so set inputs *after* it.
        (self.vm.cpu.arch.on_boot)(&mut self.vm.cpu, CODE_ADDR);
        let xmm0 = self.vm.cpu.arch.sleigh.get_varnode("XMM0").expect("XMM0");
        let xmm1 = self.vm.cpu.arch.sleigh.get_varnode("XMM1").expect("XMM1");
        self.vm.cpu.write_var(xmm0, a);
        self.vm.cpu.write_var(xmm1, b);

        let before = self.vm.cpu.icount;
        self.vm.icount_limit = self.vm.cpu.icount + 1;
        let exit = self.vm.run();
        assert!(
            self.vm.cpu.icount > before,
            "instruction did not execute: {exit:?}"
        );
        if let VmExit::UnhandledException(e) = exit {
            // A fetch fault past the single instruction is expected; only a
            // decode/illegal failure matters.
            let _ = e;
        }

        let out_xmm0: u128 = self.vm.cpu.read(xmm0.into());
        let eax = self.vm.cpu.arch.sleigh.get_varnode("EAX").expect("EAX");
        let out_eax = self.vm.cpu.read_reg(eax);
        (out_xmm0, out_eax)
    }
}

/// A test case: name, instruction bytes, and a reference closure over the
/// two 16-byte inputs producing (expected_xmm0, expected_eax).
struct Case {
    name: &'static str,
    code: &'static [u8],
    xmm_out: bool, // result is in XMM0 (true) or EAX (false)
    reference: fn([u8; 16], [u8; 16]) -> u128,
}

#[inline]
unsafe fn load(b: [u8; 16]) -> std::arch::x86_64::__m128i {
    std::arch::x86_64::_mm_loadu_si128(b.as_ptr() as *const std::arch::x86_64::__m128i)
}

#[inline]
unsafe fn store(v: std::arch::x86_64::__m128i) -> u128 {
    let mut out = [0u8; 16];
    std::arch::x86_64::_mm_storeu_si128(out.as_mut_ptr() as *mut std::arch::x86_64::__m128i, v);
    u128::from_le_bytes(out)
}

fn main() {
    use std::arch::x86_64::*;
    // Deterministic pseudo-random inputs (no Math.random in this env anyway).
    let mut seed: u64 = 0x9e3779b97f4a7c15;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };

    let cases: &[Case] = &[
        Case {
            name: "pcmpeqb xmm0,xmm1 (66 0f 74 c1)",
            code: &[0x66, 0x0f, 0x74, 0xc1],
            xmm_out: true,
            reference: |a, b| unsafe {
                let r = _mm_cmpeq_epi8(
                    _mm_loadu_si128(a.as_ptr() as *const __m128i),
                    _mm_loadu_si128(b.as_ptr() as *const __m128i),
                );
                let mut out = [0u8; 16];
                _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, r);
                u128::from_le_bytes(out)
            },
        },
        Case {
            name: "pminub xmm0,xmm1 (66 0f da c1)",
            code: &[0x66, 0x0f, 0xda, 0xc1],
            xmm_out: true,
            reference: |a, b| unsafe {
                let r = _mm_min_epu8(
                    _mm_loadu_si128(a.as_ptr() as *const __m128i),
                    _mm_loadu_si128(b.as_ptr() as *const __m128i),
                );
                let mut out = [0u8; 16];
                _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, r);
                u128::from_le_bytes(out)
            },
        },
        Case {
            name: "psubb xmm0,xmm1 (66 0f f8 c1)",
            code: &[0x66, 0x0f, 0xf8, 0xc1],
            xmm_out: true,
            reference: |a, b| unsafe {
                let r = _mm_sub_epi8(
                    _mm_loadu_si128(a.as_ptr() as *const __m128i),
                    _mm_loadu_si128(b.as_ptr() as *const __m128i),
                );
                let mut out = [0u8; 16];
                _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, r);
                u128::from_le_bytes(out)
            },
        },
        Case {
            name: "pcmpeqd xmm0,xmm1 (66 0f 76 c1)",
            code: &[0x66, 0x0f, 0x76, 0xc1],
            xmm_out: true,
            reference: |a, b| unsafe {
                let r = _mm_cmpeq_epi32(
                    _mm_loadu_si128(a.as_ptr() as *const __m128i),
                    _mm_loadu_si128(b.as_ptr() as *const __m128i),
                );
                let mut out = [0u8; 16];
                _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, r);
                u128::from_le_bytes(out)
            },
        },
        Case {
            name: "pmovmskb eax,xmm0 (66 0f d7 c0)",
            code: &[0x66, 0x0f, 0xd7, 0xc0],
            xmm_out: false,
            reference: |a, _b| unsafe {
                let m = _mm_movemask_epi8(_mm_loadu_si128(a.as_ptr() as *const __m128i));
                (m as u32) as u128
            },
        },
        Case {
            name: "movmskps eax,xmm1 (0f 50 c1)",
            code: &[0x0f, 0x50, 0xc1],
            xmm_out: false,
            reference: |_a, b| unsafe {
                let m = _mm_movemask_ps(_mm_castsi128_ps(load(b)));
                (m as u32) as u128
            },
        },
        Case {
            name: "pcmpgtb xmm0,xmm1 (66 0f 64 c1)",
            code: &[0x66, 0x0f, 0x64, 0xc1],
            xmm_out: true,
            reference: |a, b| unsafe {
                let r = _mm_cmpgt_epi8(
                    _mm_loadu_si128(a.as_ptr() as *const __m128i),
                    _mm_loadu_si128(b.as_ptr() as *const __m128i),
                );
                let mut out = [0u8; 16];
                _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, r);
                u128::from_le_bytes(out)
            },
        },
        Case {
            name: "paddb xmm0,xmm1 (66 0f fc c1)",
            code: &[0x66, 0x0f, 0xfc, 0xc1],
            xmm_out: true,
            reference: |a, b| unsafe {
                let r = _mm_add_epi8(
                    _mm_loadu_si128(a.as_ptr() as *const __m128i),
                    _mm_loadu_si128(b.as_ptr() as *const __m128i),
                );
                let mut out = [0u8; 16];
                _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, r);
                u128::from_le_bytes(out)
            },
        },
        Case {
            name: "psadbw xmm0,xmm1 (66 0f f6 c1)",
            code: &[0x66, 0x0f, 0xf6, 0xc1],
            xmm_out: true,
            reference: |a, b| unsafe {
                let r = _mm_sad_epu8(
                    _mm_loadu_si128(a.as_ptr() as *const __m128i),
                    _mm_loadu_si128(b.as_ptr() as *const __m128i),
                );
                let mut out = [0u8; 16];
                _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, r);
                u128::from_le_bytes(out)
            },
        },
        Case {
            name: "pxor xmm0,xmm1 (66 0f ef c1)",
            code: &[0x66, 0x0f, 0xef, 0xc1],
            xmm_out: true,
            reference: |a, b| u128::from_le_bytes(a) ^ u128::from_le_bytes(b),
        },
        Case {
            name: "punpcklbw xmm0,xmm1 (66 0f 60 c1)",
            code: &[0x66, 0x0f, 0x60, 0xc1],
            xmm_out: true,
            reference: |a, b| unsafe {
                let r = _mm_unpacklo_epi8(
                    _mm_loadu_si128(a.as_ptr() as *const __m128i),
                    _mm_loadu_si128(b.as_ptr() as *const __m128i),
                );
                let mut out = [0u8; 16];
                _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, r);
                u128::from_le_bytes(out)
            },
        },
        Case {
            name: "pshufb xmm0,xmm1 (66 0f 38 00 c1)",
            code: &[0x66, 0x0f, 0x38, 0x00, 0xc1],
            xmm_out: true,
            reference: |a, b| unsafe { store(_mm_shuffle_epi8(load(a), load(b))) },
        },
        Case {
            name: "pmulhuw xmm0,xmm1 (66 0f e4 c1)",
            code: &[0x66, 0x0f, 0xe4, 0xc1],
            xmm_out: true,
            reference: |a, b| unsafe { store(_mm_mulhi_epu16(load(a), load(b))) },
        },
        Case {
            name: "pmulhw xmm0,xmm1 (66 0f e5 c1)",
            code: &[0x66, 0x0f, 0xe5, 0xc1],
            xmm_out: true,
            reference: |a, b| unsafe { store(_mm_mulhi_epi16(load(a), load(b))) },
        },
        Case {
            name: "pmulld xmm0,xmm1 (66 0f 38 40 c1)",
            code: &[0x66, 0x0f, 0x38, 0x40, 0xc1],
            xmm_out: true,
            reference: |a, b| unsafe { store(_mm_mullo_epi32(load(a), load(b))) },
        },
        Case {
            name: "packsswb xmm0,xmm1 (66 0f 63 c1)",
            code: &[0x66, 0x0f, 0x63, 0xc1],
            xmm_out: true,
            reference: |a, b| unsafe { store(_mm_packs_epi16(load(a), load(b))) },
        },
        Case {
            name: "packuswb xmm0,xmm1 (66 0f 67 c1)",
            code: &[0x66, 0x0f, 0x67, 0xc1],
            xmm_out: true,
            reference: |a, b| unsafe { store(_mm_packus_epi16(load(a), load(b))) },
        },
        Case {
            name: "packssdw xmm0,xmm1 (66 0f 6b c1)",
            code: &[0x66, 0x0f, 0x6b, 0xc1],
            xmm_out: true,
            reference: |a, b| unsafe { store(_mm_packs_epi32(load(a), load(b))) },
        },
        Case {
            name: "packusdw xmm0,xmm1 (66 0f 38 2b c1)",
            code: &[0x66, 0x0f, 0x38, 0x2b, 0xc1],
            xmm_out: true,
            reference: |a, b| unsafe { store(_mm_packus_epi32(load(a), load(b))) },
        },
        Case {
            name: "pavgb xmm0,xmm1 (66 0f e0 c1)",
            code: &[0x66, 0x0f, 0xe0, 0xc1],
            xmm_out: true,
            reference: |a, b| unsafe { store(_mm_avg_epu8(load(a), load(b))) },
        },
        Case {
            name: "pavgw xmm0,xmm1 (66 0f e3 c1)",
            code: &[0x66, 0x0f, 0xe3, 0xc1],
            xmm_out: true,
            reference: |a, b| unsafe { store(_mm_avg_epu16(load(a), load(b))) },
        },
        Case {
            name: "punpcklqdq xmm0,xmm1 (66 0f 6c c1)",
            code: &[0x66, 0x0f, 0x6c, 0xc1],
            xmm_out: true,
            reference: |a, b| unsafe { store(_mm_unpacklo_epi64(load(a), load(b))) },
        },
        Case {
            name: "pabsb xmm0,xmm1 (66 0f 38 1c c1)",
            code: &[0x66, 0x0f, 0x38, 0x1c, 0xc1],
            xmm_out: true,
            reference: |_a, b| unsafe { store(_mm_abs_epi8(load(b))) },
        },
        Case {
            name: "pabsw xmm0,xmm1 (66 0f 38 1d c1)",
            code: &[0x66, 0x0f, 0x38, 0x1d, 0xc1],
            xmm_out: true,
            reference: |_a, b| unsafe { store(_mm_abs_epi16(load(b))) },
        },
        Case {
            name: "pabsd xmm0,xmm1 (66 0f 38 1e c1)",
            code: &[0x66, 0x0f, 0x38, 0x1e, 0xc1],
            xmm_out: true,
            reference: |_a, b| unsafe { store(_mm_abs_epi32(load(b))) },
        },
        Case {
            name: "psllw xmm0,3 (66 0f 71 f0 03)",
            code: &[0x66, 0x0f, 0x71, 0xf0, 0x03],
            xmm_out: true,
            reference: |a, _b| unsafe { store(_mm_slli_epi16::<3>(load(a))) },
        },
        Case {
            name: "psraw xmm0,3 (66 0f 71 e0 03)",
            code: &[0x66, 0x0f, 0x71, 0xe0, 0x03],
            xmm_out: true,
            reference: |a, _b| unsafe { store(_mm_srai_epi16::<3>(load(a))) },
        },
        Case {
            name: "divpd xmm0,xmm1 (66 0f 5e c1)",
            code: &[0x66, 0x0f, 0x5e, 0xc1],
            xmm_out: true,
            reference: |a, b| unsafe {
                store(_mm_castpd_si128(_mm_div_pd(
                    _mm_castsi128_pd(load(a)),
                    _mm_castsi128_pd(load(b)),
                )))
            },
        },
        Case {
            name: "divps xmm0,xmm1 (0f 5e c1)",
            code: &[0x0f, 0x5e, 0xc1],
            xmm_out: true,
            reference: |a, b| unsafe {
                store(_mm_castps_si128(_mm_div_ps(
                    _mm_castsi128_ps(load(a)),
                    _mm_castsi128_ps(load(b)),
                )))
            },
        },
        Case {
            name: "maxpd xmm0,xmm1 (66 0f 5f c1)",
            code: &[0x66, 0x0f, 0x5f, 0xc1],
            xmm_out: true,
            reference: |a, b| unsafe {
                store(_mm_castpd_si128(_mm_max_pd(
                    _mm_castsi128_pd(load(a)),
                    _mm_castsi128_pd(load(b)),
                )))
            },
        },
        Case {
            name: "minpd xmm0,xmm1 (66 0f 5d c1)",
            code: &[0x66, 0x0f, 0x5d, 0xc1],
            xmm_out: true,
            reference: |a, b| unsafe {
                store(_mm_castpd_si128(_mm_min_pd(
                    _mm_castsi128_pd(load(a)),
                    _mm_castsi128_pd(load(b)),
                )))
            },
        },
        Case {
            name: "sqrtpd xmm0,xmm1 (66 0f 51 c1)",
            code: &[0x66, 0x0f, 0x51, 0xc1],
            xmm_out: true,
            reference: |_a, b| unsafe {
                store(_mm_castpd_si128(_mm_sqrt_pd(_mm_castsi128_pd(load(b)))))
            },
        },
        Case {
            name: "sqrtps xmm0,xmm1 (0f 51 c1)",
            code: &[0x0f, 0x51, 0xc1],
            xmm_out: true,
            reference: |_a, b| unsafe {
                store(_mm_castps_si128(_mm_sqrt_ps(_mm_castsi128_ps(load(b)))))
            },
        },
        Case {
            name: "aesenc xmm0,xmm1 (66 0f 38 dc c1)",
            code: &[0x66, 0x0f, 0x38, 0xdc, 0xc1],
            xmm_out: true,
            reference: |a, b| unsafe { store(_mm_aesenc_si128(load(a), load(b))) },
        },
        Case {
            name: "aesenclast xmm0,xmm1 (66 0f 38 dd c1)",
            code: &[0x66, 0x0f, 0x38, 0xdd, 0xc1],
            xmm_out: true,
            reference: |a, b| unsafe { store(_mm_aesenclast_si128(load(a), load(b))) },
        },
        Case {
            name: "aesdec xmm0,xmm1 (66 0f 38 de c1)",
            code: &[0x66, 0x0f, 0x38, 0xde, 0xc1],
            xmm_out: true,
            reference: |a, b| unsafe { store(_mm_aesdec_si128(load(a), load(b))) },
        },
        Case {
            name: "aesdeclast xmm0,xmm1 (66 0f 38 df c1)",
            code: &[0x66, 0x0f, 0x38, 0xdf, 0xc1],
            xmm_out: true,
            reference: |a, b| unsafe { store(_mm_aesdeclast_si128(load(a), load(b))) },
        },
        Case {
            // aesimc reads xmm1, writes xmm0.
            name: "aesimc xmm0,xmm1 (66 0f 38 db c1)",
            code: &[0x66, 0x0f, 0x38, 0xdb, 0xc1],
            xmm_out: true,
            reference: |_a, b| unsafe { store(_mm_aesimc_si128(load(b))) },
        },
        Case {
            // aeskeygenassist reads xmm1, imm8=1, writes xmm0.
            name: "aeskeygenassist xmm0,xmm1,1 (66 0f 3a df c1 01)",
            code: &[0x66, 0x0f, 0x3a, 0xdf, 0xc1, 0x01],
            xmm_out: true,
            reference: |_a, b| unsafe { store(_mm_aeskeygenassist_si128::<1>(load(b))) },
        },
        Case {
            name: "pblendw xmm0,xmm1,0xa5",
            code: &[0x66, 0x0f, 0x3a, 0x0e, 0xc1, 0xa5],
            xmm_out: true,
            reference: |a, b| unsafe {
                let (a, b) = (load(a), load(b));
                let _ = a;
                store(_mm_blend_epi16(a, b, 0xa5))
            },
        },
        Case {
            name: "pblendvb xmm0,xmm1 (mask=xmm0)",
            code: &[0x66, 0x0f, 0x38, 0x10, 0xc1],
            xmm_out: true,
            reference: |a, b| unsafe {
                let (a, b) = (load(a), load(b));
                let _ = a;
                store(_mm_blendv_epi8(a, b, a))
            },
        },
        Case {
            name: "blendvps xmm0,xmm1 (mask=xmm0)",
            code: &[0x66, 0x0f, 0x38, 0x14, 0xc1],
            xmm_out: true,
            reference: |a, b| unsafe {
                let (a, b) = (load(a), load(b));
                let _ = a;
                store(_mm_castps_si128(_mm_blendv_ps(_mm_castsi128_ps(a), _mm_castsi128_ps(b), _mm_castsi128_ps(a))))
            },
        },
        Case {
            name: "blendvpd xmm0,xmm1 (mask=xmm0)",
            code: &[0x66, 0x0f, 0x38, 0x15, 0xc1],
            xmm_out: true,
            reference: |a, b| unsafe {
                let (a, b) = (load(a), load(b));
                let _ = a;
                store(_mm_castpd_si128(_mm_blendv_pd(_mm_castsi128_pd(a), _mm_castsi128_pd(b), _mm_castsi128_pd(a))))
            },
        },
        Case {
            name: "pmovzxbw xmm0,xmm1",
            code: &[0x66, 0x0f, 0x38, 0x30, 0xc1],
            xmm_out: true,
            reference: |a, b| unsafe {
                let (a, b) = (load(a), load(b));
                let _ = a;
                store(_mm_cvtepu8_epi16(b))
            },
        },
        Case {
            name: "pmovzxbd xmm0,xmm1",
            code: &[0x66, 0x0f, 0x38, 0x31, 0xc1],
            xmm_out: true,
            reference: |a, b| unsafe {
                let (a, b) = (load(a), load(b));
                let _ = a;
                store(_mm_cvtepu8_epi32(b))
            },
        },
        Case {
            name: "pmovzxbq xmm0,xmm1",
            code: &[0x66, 0x0f, 0x38, 0x32, 0xc1],
            xmm_out: true,
            reference: |a, b| unsafe {
                let (a, b) = (load(a), load(b));
                let _ = a;
                store(_mm_cvtepu8_epi64(b))
            },
        },
        Case {
            name: "pmovzxwd xmm0,xmm1",
            code: &[0x66, 0x0f, 0x38, 0x33, 0xc1],
            xmm_out: true,
            reference: |a, b| unsafe {
                let (a, b) = (load(a), load(b));
                let _ = a;
                store(_mm_cvtepu16_epi32(b))
            },
        },
        Case {
            name: "pmovzxwq xmm0,xmm1",
            code: &[0x66, 0x0f, 0x38, 0x34, 0xc1],
            xmm_out: true,
            reference: |a, b| unsafe {
                let (a, b) = (load(a), load(b));
                let _ = a;
                store(_mm_cvtepu16_epi64(b))
            },
        },
        Case {
            name: "pmovzxdq xmm0,xmm1",
            code: &[0x66, 0x0f, 0x38, 0x35, 0xc1],
            xmm_out: true,
            reference: |a, b| unsafe {
                let (a, b) = (load(a), load(b));
                let _ = a;
                store(_mm_cvtepu32_epi64(b))
            },
        },
        Case {
            name: "pmovsxbw xmm0,xmm1",
            code: &[0x66, 0x0f, 0x38, 0x20, 0xc1],
            xmm_out: true,
            reference: |a, b| unsafe {
                let (a, b) = (load(a), load(b));
                let _ = a;
                store(_mm_cvtepi8_epi16(b))
            },
        },
        Case {
            name: "pmovsxbd xmm0,xmm1",
            code: &[0x66, 0x0f, 0x38, 0x21, 0xc1],
            xmm_out: true,
            reference: |a, b| unsafe {
                let (a, b) = (load(a), load(b));
                let _ = a;
                store(_mm_cvtepi8_epi32(b))
            },
        },
        Case {
            name: "pmovsxbq xmm0,xmm1",
            code: &[0x66, 0x0f, 0x38, 0x22, 0xc1],
            xmm_out: true,
            reference: |a, b| unsafe {
                let (a, b) = (load(a), load(b));
                let _ = a;
                store(_mm_cvtepi8_epi64(b))
            },
        },
        Case {
            name: "pmovsxwd xmm0,xmm1",
            code: &[0x66, 0x0f, 0x38, 0x23, 0xc1],
            xmm_out: true,
            reference: |a, b| unsafe {
                let (a, b) = (load(a), load(b));
                let _ = a;
                store(_mm_cvtepi16_epi32(b))
            },
        },
        Case {
            name: "pmovsxwq xmm0,xmm1",
            code: &[0x66, 0x0f, 0x38, 0x24, 0xc1],
            xmm_out: true,
            reference: |a, b| unsafe {
                let (a, b) = (load(a), load(b));
                let _ = a;
                store(_mm_cvtepi16_epi64(b))
            },
        },
        Case {
            name: "pmovsxdq xmm0,xmm1",
            code: &[0x66, 0x0f, 0x38, 0x25, 0xc1],
            xmm_out: true,
            reference: |a, b| unsafe {
                let (a, b) = (load(a), load(b));
                let _ = a;
                store(_mm_cvtepi32_epi64(b))
            },
        },
        Case {
            name: "pmuldq xmm0,xmm1",
            code: &[0x66, 0x0f, 0x38, 0x28, 0xc1],
            xmm_out: true,
            reference: |a, b| unsafe {
                let (a, b) = (load(a), load(b));
                let _ = a;
                store(_mm_mul_epi32(a, b))
            },
        },
        Case {
            name: "pmulhrsw xmm0,xmm1",
            code: &[0x66, 0x0f, 0x38, 0x0b, 0xc1],
            xmm_out: true,
            reference: |a, b| unsafe {
                let (a, b) = (load(a), load(b));
                let _ = a;
                store(_mm_mulhrs_epi16(a, b))
            },
        },
        Case {
            name: "pmaddubsw xmm0,xmm1",
            code: &[0x66, 0x0f, 0x38, 0x04, 0xc1],
            xmm_out: true,
            reference: |a, b| unsafe {
                let (a, b) = (load(a), load(b));
                let _ = a;
                store(_mm_maddubs_epi16(a, b))
            },
        },
        Case {
            name: "psignb xmm0,xmm1",
            code: &[0x66, 0x0f, 0x38, 0x08, 0xc1],
            xmm_out: true,
            reference: |a, b| unsafe {
                let (a, b) = (load(a), load(b));
                let _ = a;
                store(_mm_sign_epi8(a, b))
            },
        },
        Case {
            name: "psignw xmm0,xmm1",
            code: &[0x66, 0x0f, 0x38, 0x09, 0xc1],
            xmm_out: true,
            reference: |a, b| unsafe {
                let (a, b) = (load(a), load(b));
                let _ = a;
                store(_mm_sign_epi16(a, b))
            },
        },
        Case {
            name: "psignd xmm0,xmm1",
            code: &[0x66, 0x0f, 0x38, 0x0a, 0xc1],
            xmm_out: true,
            reference: |a, b| unsafe {
                let (a, b) = (load(a), load(b));
                let _ = a;
                store(_mm_sign_epi32(a, b))
            },
        },
        Case {
            name: "phaddw xmm0,xmm1",
            code: &[0x66, 0x0f, 0x38, 0x01, 0xc1],
            xmm_out: true,
            reference: |a, b| unsafe {
                let (a, b) = (load(a), load(b));
                let _ = a;
                store(_mm_hadd_epi16(a, b))
            },
        },
        Case {
            name: "phaddd xmm0,xmm1",
            code: &[0x66, 0x0f, 0x38, 0x02, 0xc1],
            xmm_out: true,
            reference: |a, b| unsafe {
                let (a, b) = (load(a), load(b));
                let _ = a;
                store(_mm_hadd_epi32(a, b))
            },
        },
        Case {
            name: "phaddsw xmm0,xmm1",
            code: &[0x66, 0x0f, 0x38, 0x03, 0xc1],
            xmm_out: true,
            reference: |a, b| unsafe {
                let (a, b) = (load(a), load(b));
                let _ = a;
                store(_mm_hadds_epi16(a, b))
            },
        },
        Case {
            name: "phsubw xmm0,xmm1",
            code: &[0x66, 0x0f, 0x38, 0x05, 0xc1],
            xmm_out: true,
            reference: |a, b| unsafe {
                let (a, b) = (load(a), load(b));
                let _ = a;
                store(_mm_hsub_epi16(a, b))
            },
        },
        Case {
            name: "phsubd xmm0,xmm1",
            code: &[0x66, 0x0f, 0x38, 0x06, 0xc1],
            xmm_out: true,
            reference: |a, b| unsafe {
                let (a, b) = (load(a), load(b));
                let _ = a;
                store(_mm_hsub_epi32(a, b))
            },
        },
        Case {
            name: "phsubsw xmm0,xmm1",
            code: &[0x66, 0x0f, 0x38, 0x07, 0xc1],
            xmm_out: true,
            reference: |a, b| unsafe {
                let (a, b) = (load(a), load(b));
                let _ = a;
                store(_mm_hsubs_epi16(a, b))
            },
        },
        Case {
            name: "phminposuw xmm0,xmm1",
            code: &[0x66, 0x0f, 0x38, 0x41, 0xc1],
            xmm_out: true,
            reference: |a, b| unsafe {
                let (a, b) = (load(a), load(b));
                let _ = a;
                store(_mm_minpos_epu16(b))
            },
        },
        Case {
            name: "insertps xmm0,xmm1,0x9c",
            code: &[0x66, 0x0f, 0x3a, 0x21, 0xc1, 0x9c],
            xmm_out: true,
            reference: |a, b| unsafe {
                let (a, b) = (load(a), load(b));
                let _ = a;
                store(_mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(a), _mm_castsi128_ps(b), 0x9c)))
            },
        },
        Case {
            name: "roundps xmm0,xmm1,1 (floor)",
            code: &[0x66, 0x0f, 0x3a, 0x08, 0xc1, 0x01],
            xmm_out: true,
            reference: |a, b| unsafe {
                let (a, b) = (load(a), load(b));
                let _ = a;
                store(_mm_castps_si128(_mm_round_ps(_mm_castsi128_ps(b), 0x1)))
            },
        },
        Case {
            name: "roundpd xmm0,xmm1,2 (ceil)",
            code: &[0x66, 0x0f, 0x3a, 0x09, 0xc1, 0x02],
            xmm_out: true,
            reference: |a, b| unsafe {
                let (a, b) = (load(a), load(b));
                let _ = a;
                store(_mm_castpd_si128(_mm_round_pd(_mm_castsi128_pd(b), 0x2)))
            },
        },
        Case {
            name: "paddsb xmm0,xmm1",
            code: &[0x66, 0x0f, 0xec, 0xc1],
            xmm_out: true,
            reference: |a, b| unsafe {
                let (a, b) = (load(a), load(b));
                let _ = a;
                store(_mm_adds_epi8(a, b))
            },
        },
        Case {
            name: "paddsw xmm0,xmm1",
            code: &[0x66, 0x0f, 0xed, 0xc1],
            xmm_out: true,
            reference: |a, b| unsafe {
                let (a, b) = (load(a), load(b));
                let _ = a;
                store(_mm_adds_epi16(a, b))
            },
        },
        Case {
            name: "paddusb xmm0,xmm1",
            code: &[0x66, 0x0f, 0xdc, 0xc1],
            xmm_out: true,
            reference: |a, b| unsafe {
                let (a, b) = (load(a), load(b));
                let _ = a;
                store(_mm_adds_epu8(a, b))
            },
        },
        Case {
            name: "paddusw xmm0,xmm1",
            code: &[0x66, 0x0f, 0xdd, 0xc1],
            xmm_out: true,
            reference: |a, b| unsafe {
                let (a, b) = (load(a), load(b));
                let _ = a;
                store(_mm_adds_epu16(a, b))
            },
        },
        Case {
            name: "psubsb xmm0,xmm1",
            code: &[0x66, 0x0f, 0xe8, 0xc1],
            xmm_out: true,
            reference: |a, b| unsafe {
                let (a, b) = (load(a), load(b));
                let _ = a;
                store(_mm_subs_epi8(a, b))
            },
        },
        Case {
            name: "psubsw xmm0,xmm1",
            code: &[0x66, 0x0f, 0xe9, 0xc1],
            xmm_out: true,
            reference: |a, b| unsafe {
                let (a, b) = (load(a), load(b));
                let _ = a;
                store(_mm_subs_epi16(a, b))
            },
        },
        Case {
            name: "psubusb xmm0,xmm1",
            code: &[0x66, 0x0f, 0xd8, 0xc1],
            xmm_out: true,
            reference: |a, b| unsafe {
                let (a, b) = (load(a), load(b));
                let _ = a;
                store(_mm_subs_epu8(a, b))
            },
        },
        Case {
            name: "psubusw xmm0,xmm1",
            code: &[0x66, 0x0f, 0xd9, 0xc1],
            xmm_out: true,
            reference: |a, b| unsafe {
                let (a, b) = (load(a), load(b));
                let _ = a;
                store(_mm_subs_epu16(a, b))
            },
        },
    ];

    let mut probe = Probe::new();

    // Diagnostic: CPUID leaf 1 EDX/ECX (V8 checks SSE2 = EDX bit 26).
    {
        probe.vm.cpu.mem.reset_virtual();
        probe.vm.cpu.reset();
        probe.vm.code.flush_code();
        probe.vm.cpu.block_id = u64::MAX;
        probe.vm.cpu.mem.map_memory_len(
            CODE_ADDR,
            0x1000,
            Mapping {
                perm: perm::ALL,
                value: 0,
            },
        );
        probe
            .vm
            .cpu
            .mem
            .write_bytes(CODE_ADDR, &[0x0f, 0xa2], perm::NONE)
            .expect("code");
        (probe.vm.cpu.arch.on_boot)(&mut probe.vm.cpu, CODE_ADDR);
        let rax = probe.vm.cpu.arch.sleigh.get_varnode("RAX").expect("RAX");
        let rcx = probe.vm.cpu.arch.sleigh.get_varnode("RCX").expect("RCX");
        let rdx = probe.vm.cpu.arch.sleigh.get_varnode("RDX").expect("RDX");
        probe.vm.cpu.write_reg(rax, 1);
        probe.vm.cpu.write_reg(rcx, 0);
        probe.vm.icount_limit = probe.vm.cpu.icount + 1;
        let _ = probe.vm.run();
        let edx = probe.vm.cpu.read_reg(rdx) as u32;
        let ecx = probe.vm.cpu.read_reg(rcx) as u32;
        println!(
            "diag cpuid.1: EDX={edx:#010x} (sse2 bit26={}) ECX={ecx:#010x}",
            (edx >> 26) & 1
        );
    }

    // Diagnostic: subtracting zero must leave the input unchanged, and the
    // decoded disassembly confirms the right constructor matched.
    {
        let a = 0x0102030405060708_090a0b0c0d0e0f10_u128;
        let (got, _) = probe.run(&[0x66, 0x0f, 0xf8, 0xc1], a, 0);
        println!("diag psubb(a,0): want={a:032x} got={got:032x}");
        let a2 = 0x11u128;
        let (got2, _) = probe.run(&[0x66, 0x0f, 0xf8, 0xc1], a2, 0x03);
        println!(
            "diag psubb(0x11,0x03) byte0: want=0e got={:02x}",
            got2 as u8
        );

        // movdqu xmm0,[rax] (f3 0f 6f 00) — unaligned load from memory.
        let mv = 0x0f0e0d0c0b0a0908_0706050403020100_u128;
        let gm = probe.run_mem(&[0xf3, 0x0f, 0x6f, 0x00], 0, mv);
        println!(
            "diag movdqu load: want={mv:032x} got={gm:032x} {}",
            if gm == mv { "OK" } else { "MISMATCH" }
        );

        // pcmpeqb xmm0,[rax] (66 0f 74 00) — memory-operand compare.
        let gm2 = probe.run_mem(&[0x66, 0x0f, 0x74, 0x00], mv, mv);
        println!(
            "diag pcmpeqb mem (equal): want=ff..ff got={gm2:032x} {}",
            if gm2 == u128::MAX { "OK" } else { "MISMATCH" }
        );
    }

    let iterations = 200;
    let mut failures = 0;
    for case in cases {
        let mut mismatches = 0;
        let mut first: Option<String> = None;
        for _ in 0..iterations {
            let a_bytes: [u8; 16] = std::array::from_fn(|_| next() as u8);
            let b_bytes: [u8; 16] = std::array::from_fn(|_| next() as u8);
            let a = u128::from_le_bytes(a_bytes);
            let b = u128::from_le_bytes(b_bytes);
            let (got_xmm, got_eax) = probe.run(case.code, a, b);
            let want = (case.reference)(a_bytes, b_bytes);
            let got = if case.xmm_out {
                got_xmm
            } else {
                got_eax as u128
            };
            if got != want {
                mismatches += 1;
                if first.is_none() {
                    first = Some(format!(
                        "a={a:032x} b={b:032x}\n    want={want:032x}\n    got ={got:032x}"
                    ));
                }
            }
        }
        if mismatches == 0 {
            println!("OK   {}", case.name);
        } else {
            failures += 1;
            println!("FAIL {} ({mismatches}/{iterations})", case.name);
            if let Some(f) = first {
                println!("    {f}");
            }
        }
    }
    std::process::exit(if failures == 0 { 0 } else { 1 });
}
