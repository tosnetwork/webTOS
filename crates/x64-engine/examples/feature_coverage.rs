//! Reports opaque p-code operations reachable through the AVX-family feature
//! bits published by the M9 virtual CPU profile but lacking an execution
//! helper. This is a development authority for closing M9-L; it deliberately
//! exits unsuccessfully while advertised semantics remain incomplete.

use std::collections::{BTreeMap, BTreeSet};

use iced_x86::{Code, CpuidFeature, EncodingKind};

const AVX: &str = include_str!("../../../third_party/ghidra-x86/languages/avx.sinc");
const AVX2: &str = include_str!("../../../third_party/ghidra-x86/languages/avx2.sinc");
const AVX2_MANUAL: &str =
    include_str!("../../../third_party/ghidra-x86/languages/avx2_manual.sinc");
const AVX512: &str = include_str!("../../../third_party/ghidra-x86/languages/avx512.sinc");
const AVX512_MANUAL: &str =
    include_str!("../../../third_party/ghidra-x86/languages/avx512_manual.sinc");
const IA: &str = include_str!("../../../third_party/ghidra-x86/languages/ia.sinc");
const HELPERS: &str = include_str!("../../../third_party/icicle/icicle-cpu/src/exec/helpers.rs");

fn is_published(feature: CpuidFeature) -> bool {
    matches!(
        feature,
        CpuidFeature::AES
            | CpuidFeature::PCLMULQDQ
            | CpuidFeature::BMI1
            | CpuidFeature::BMI2
            | CpuidFeature::AVX
            | CpuidFeature::AVX2
            | CpuidFeature::AVX512F
            | CpuidFeature::AVX512CD
            | CpuidFeature::AVX512BW
            | CpuidFeature::AVX512VL
            | CpuidFeature::AVX512_VBMI2
            | CpuidFeature::AVX512_VPOPCNTDQ
    )
}

fn is_architecture_baseline(feature: CpuidFeature) -> bool {
    matches!(
        feature,
        CpuidFeature::INTEL8086
            | CpuidFeature::INTEL186
            | CpuidFeature::INTEL286
            | CpuidFeature::INTEL386
            | CpuidFeature::INTEL486
            | CpuidFeature::X64
            | CpuidFeature::FPU
            | CpuidFeature::MMX
            | CpuidFeature::SSE
            | CpuidFeature::SSE2
            | CpuidFeature::SSE3
    )
}

fn pcodeops(source: &str) -> impl Iterator<Item = &str> {
    source.lines().filter_map(|line| {
        line.trim()
            .strip_prefix("define pcodeop ")
            .and_then(|rest| rest.strip_suffix(';'))
            .map(str::trim)
    })
}

fn operation_is_called(sources: &[&str], operation: &str) -> bool {
    sources.iter().any(|source| {
        source.match_indices(operation).any(|(offset, _)| {
            source[offset + operation.len()..]
                .trim_start()
                .starts_with('(')
        })
    })
}

fn registered_helpers() -> BTreeSet<&'static str> {
    HELPERS
        .lines()
        .filter_map(|line| {
            let rest = line.trim().strip_prefix("(\"")?;
            rest.split_once("\",").map(|(name, _)| name)
        })
        .collect()
}

fn operation_requirement(operation: &str) -> Option<(CpuidFeature, EncodingKind)> {
    let (feature, encoding) = if matches!(
        operation,
        "aesdec" | "aesdeclast" | "aesenc" | "aesenclast" | "aesimc" | "aeskeygenassist"
    ) {
        (CpuidFeature::AES, EncodingKind::VEX)
    } else if operation.ends_with("_avx512_vpopcntdq") {
        (CpuidFeature::AVX512_VPOPCNTDQ, EncodingKind::EVEX)
    } else if operation.ends_with("_avx512_vbmi2") {
        (CpuidFeature::AVX512_VBMI2, EncodingKind::EVEX)
    } else if operation.ends_with("_avx512vl") {
        (CpuidFeature::AVX512VL, EncodingKind::EVEX)
    } else if operation.ends_with("_avx512bw") {
        (CpuidFeature::AVX512BW, EncodingKind::EVEX)
    } else if operation.ends_with("_avx512cd") {
        (CpuidFeature::AVX512CD, EncodingKind::EVEX)
    } else if operation.ends_with("_avx512dq") {
        (CpuidFeature::AVX512DQ, EncodingKind::EVEX)
    } else if operation.ends_with("_avx512f") {
        (CpuidFeature::AVX512F, EncodingKind::EVEX)
    } else if matches!(
        operation,
        "vgatherdpd"
            | "vgatherdps"
            | "vgatherqpd"
            | "vgatherqps"
            | "vpgatherdd"
            | "vpgatherdq"
            | "vpgatherqd"
            | "vpgatherqq"
    ) || operation.ends_with("_avx2")
    {
        (CpuidFeature::AVX2, EncodingKind::VEX)
    } else if operation.ends_with("_avx") {
        (CpuidFeature::AVX, EncodingKind::VEX)
    } else {
        return None;
    };
    Some((feature, encoding))
}

fn main() {
    let mut published_codes =
        BTreeMap::<(String, EncodingKind), Vec<&'static [CpuidFeature]>>::new();
    for code in Code::values() {
        if !matches!(code.encoding(), EncodingKind::VEX | EncodingKind::EVEX) {
            continue;
        }
        let features = code.cpuid_features();
        if !features.iter().copied().any(is_published)
            || features
                .iter()
                .copied()
                .any(|feature| !is_published(feature) && !is_architecture_baseline(feature))
        {
            continue;
        }
        let mnemonic = format!("{:?}", code.mnemonic()).to_ascii_lowercase();
        published_codes
            .entry((mnemonic, code.encoding()))
            .or_default()
            .push(features);
    }

    let helpers = registered_helpers();
    let mut missing = BTreeMap::<&str, BTreeSet<String>>::new();
    let sources = [AVX, AVX2, AVX2_MANUAL, AVX512, AVX512_MANUAL, IA];
    for operation in sources.into_iter().flat_map(pcodeops) {
        if helpers.contains(operation) || !operation_is_called(&sources, operation) {
            continue;
        }
        let Some((required, encoding)) = operation_requirement(operation) else {
            continue;
        };
        let mnemonic = if matches!(required, CpuidFeature::AES) {
            format!("v{operation}")
        } else {
            operation.split('_').next().unwrap_or(operation).to_owned()
        };
        let Some(codes) = published_codes.get(&(mnemonic, encoding)) else {
            continue;
        };
        if codes.iter().any(|features| features.contains(&required)) {
            missing
                .entry(operation)
                .or_default()
                .insert(format!("{required:?}"));
        }
    }

    println!(
        "published_mnemonics={} opaque_ops_without_helpers={}",
        published_codes.len(),
        missing.len()
    );
    for (operation, features) in &missing {
        println!(
            "{operation}: {}",
            features.iter().cloned().collect::<Vec<_>>().join(",")
        );
    }
    if !missing.is_empty() {
        std::process::exit(1);
    }
}
