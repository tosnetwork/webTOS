//! The fixture checksum manifest, and the gate that keeps it honest.
//!
//! The suite runs against binary fixtures and reference traces checked into
//! `test_data/`. Git pins the bytes, but nothing said which files are the
//! ones the tests depend on or caught a fixture quietly changing out from
//! under a test — a regenerated ELF, a corrupted download, an edit to a trace
//! that should have moved deliberately. `FIXTURES.sha256` names each and its
//! digest, and this recomputes them.
//!
//! A change moves the manifest, the way a behavior change moves the traces;
//! regenerate deliberately:
//!
//!   cargo test -p linux-compat --test fixtures -- --ignored rewrite
//!
//! Only the executable fixtures and the reference traces are pinned — the
//! inputs a test actually runs, where a silent change is a silently wrong
//! test. Source files beside them are git's to track.

use std::collections::BTreeMap;
use std::path::PathBuf;

use linux_compat::digest::{hex, sha256};

fn test_data() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../test_data")
}

fn manifest_path() -> PathBuf {
    test_data().join("FIXTURES.sha256")
}

/// The relative paths under `test_data/` that the manifest pins: every `.elf`
/// and every reference trace. Discovered rather than listed, so a fixture
/// added tomorrow is pinned tomorrow — the gate then fails until the manifest
/// is regenerated, which is the deliberate step that records the new fixture.
fn pinned_files() -> Vec<String> {
    let root = test_data();
    let mut out = Vec::new();
    collect(&root, &root, &mut out);
    out.sort();
    out
}

fn collect(root: &std::path::Path, dir: &std::path::Path, out: &mut Vec<String>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            // The gitignored rootfs is not a pinned fixture; it is fetched.
            if path
                .file_name()
                .map(|n| n == "alpine-minirootfs")
                .unwrap_or(false)
            {
                continue;
            }
            collect(root, &path, out);
        } else {
            let name = path.to_string_lossy();
            let is_elf = name.ends_with(".elf");
            let is_trace = name.ends_with(".trace");
            if is_elf || is_trace {
                if let Ok(rel) = path.strip_prefix(root) {
                    out.push(rel.to_string_lossy().replace('\\', "/"));
                }
            }
        }
    }
}

fn recorded() -> BTreeMap<String, String> {
    let text = std::fs::read_to_string(manifest_path()).expect("FIXTURES.sha256");
    text.lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .filter_map(|l| {
            let (digest, name) = l.split_once("  ")?;
            Some((name.trim().to_string(), digest.trim().to_string()))
        })
        .collect()
}

fn actual() -> BTreeMap<String, String> {
    pinned_files()
        .into_iter()
        .map(|rel| {
            let bytes = std::fs::read(test_data().join(&rel)).expect("read fixture");
            (rel, hex(&sha256(&bytes)))
        })
        .collect()
}

#[test]
fn every_pinned_fixture_matches_its_recorded_digest() {
    let recorded = recorded();
    let actual = actual();
    assert!(!recorded.is_empty(), "the fixture manifest is empty");

    let mut drift = Vec::new();
    for (name, got) in &actual {
        match recorded.get(name) {
            None => drift.push(format!("{name}: present, not in the manifest")),
            Some(want) if want != got => {
                drift.push(format!("{name}: digest changed ({want} -> {got})"))
            }
            _ => {}
        }
    }
    for name in recorded.keys() {
        if !actual.contains_key(name) {
            drift.push(format!("{name}: in the manifest, no longer present"));
        }
    }
    assert!(
        drift.is_empty(),
        "the fixture manifest has drifted; if a fixture changed on purpose, \
         regenerate with `--ignored rewrite`:\n  {}",
        drift.join("\n  ")
    );
}

#[test]
#[ignore = "regenerates test_data/FIXTURES.sha256; run deliberately"]
fn rewrite() {
    let mut out = String::from(
        "# webTOS fixture checksums — the executable fixtures and reference traces\n\
         # the test suite runs against, pinned so a silent change is caught.\n\
         # Regenerate: cargo test -p linux-compat --test fixtures -- --ignored rewrite\n",
    );
    for (name, digest) in actual() {
        out.push_str(&format!("{digest}  {name}\n"));
    }
    std::fs::write(manifest_path(), out).expect("write FIXTURES.sha256");
    println!("[fixtures] wrote the manifest");
}
