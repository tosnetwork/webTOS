//! The specification fingerprint and the persisted-cache validation contract.
//!
//! Persisting the lift cache would skip re-lifting an image across sessions.
//! The reward is small — tiered lifting already skips the optimizer for cold
//! code, leaving about 0.43s of a 1.4s cold start, and only on a reload — but
//! the correctness question it raises is not small: p-code lifted under one
//! specification, executed under another, is silent wrong execution. The
//! fingerprint is what makes that checkable, and these gates are about the
//! fingerprint and the contract that refuses a cache it does not vouch for.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use linux_compat::digest::sha256;
use linux_compat::liftcache::LiftCacheHeader;
use linux_compat::Machine;
use x64_engine::EngineConfig;

fn ldef_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../third_party/ghidra-x86/languages/x86.ldefs")
}

#[test]
fn the_fingerprint_is_stable_across_builds_of_the_same_spec() {
    let a = Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("build a");
    let b = Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("build b");
    assert_eq!(
        a.spec_fingerprint(),
        b.spec_fingerprint(),
        "the same spec produced two different fingerprints; nothing keyed on \
         it could be trusted"
    );
    assert_ne!(
        a.spec_fingerprint(),
        [0; 32],
        "the fingerprint is all zeros, so it distinguishes nothing"
    );
}

#[test]
fn the_fingerprint_changes_when_the_spec_changes() {
    // Fingerprint the spec directory, then again with one grammar file's
    // bytes altered. A fingerprint that does not move is a fingerprint that
    // would let a cache from a different engine be used.
    let dir = ldef_path();
    let dir = dir.parent().expect("spec dir");
    let files = read_spec_files(dir);
    assert!(files.len() > 10, "expected a directory of spec files");

    let base = Machine::from_spec_files(files.clone(), &EngineConfig::default())
        .map(|m| m.spec_fingerprint());

    let mut changed = files.clone();
    // Touch a file the grammar actually includes. Adding a comment to any
    // .sinc changes what the directory hashes to.
    let (name, content) = changed
        .iter()
        .find(|(n, _)| n.ends_with(".sinc"))
        .map(|(n, c)| (n.clone(), c.clone()))
        .expect("a .sinc file");
    changed.insert(name, format!("{content}\n# spec fingerprint probe\n"));

    // from_spec_files may fail to compile a partial set; the fingerprint is
    // computed before compilation, so compare the fingerprints directly.
    let base_fp = fingerprint_via_files(&files);
    let changed_fp = fingerprint_via_files(&changed);
    assert_ne!(
        base_fp, changed_fp,
        "changing a spec file did not change the fingerprint"
    );
    // Sanity: the from_spec_files path agrees with the direct computation
    // when the spec is whole enough to build.
    if let Ok(fp) = base {
        assert_eq!(fp, base_fp, "the constructor and the helper disagree");
    }
}

#[test]
fn a_cache_from_another_spec_is_refused() {
    let engine = [0x11_u8; 32];
    let other = [0x22_u8; 32];
    let header = LiftCacheHeader::new(other, vec![sha256(b"an image")]);
    let bytes = header.serialize();

    let parsed = LiftCacheHeader::parse(&bytes).expect("round trips");
    assert_eq!(parsed, header, "the header did not survive serialization");
    let refused = parsed
        .validate_spec(&engine)
        .expect_err("a cache from another spec was accepted");
    assert!(
        refused.contains("was built under specification"),
        "the refusal did not say why: {refused}"
    );
    // The same cache under its own spec is fine.
    parsed
        .validate_spec(&other)
        .expect("its own spec was refused");
}

#[test]
fn a_cache_only_vouches_for_the_images_it_was_built_from() {
    let built = sha256(b"the image the cache holds");
    let other = sha256(b"a different image at the same path");
    let header = LiftCacheHeader::new([7; 32], vec![built]);
    assert!(
        header.covers_image(&built),
        "the cache does not cover its own image"
    );
    assert!(
        !header.covers_image(&other),
        "the cache vouched for bytes it was not built from"
    );
}

#[test]
fn a_truncated_or_forged_cache_is_refused_rather_than_read() {
    let header = LiftCacheHeader::new([9; 32], vec![sha256(b"x"), sha256(b"y")]);
    let full = header.serialize();

    // Every prefix short of the whole is truncated, and none may parse into
    // something usable — a half-read header is not a header with less in it.
    for cut in 0..full.len() {
        assert!(
            LiftCacheHeader::parse(&full[..cut]).is_err(),
            "a cache truncated to {cut} bytes parsed"
        );
    }
    // Wrong magic.
    let mut wrong = full.clone();
    wrong[0] ^= 0xff;
    assert!(
        LiftCacheHeader::parse(&wrong).is_err(),
        "a mis-magicked cache parsed"
    );
    // A count larger than the bytes can hold must not be believed.
    let mut lying = header.serialize();
    let count_at = 4 + 4 + 32;
    lying[count_at..count_at + 4].copy_from_slice(&1_000_000_u32.to_le_bytes());
    assert!(
        LiftCacheHeader::parse(&lying).is_err(),
        "a cache claiming a million images was believed"
    );
}

fn read_spec_files(dir: &Path) -> HashMap<String, String> {
    let mut files = HashMap::new();
    for entry in std::fs::read_dir(dir).expect("spec dir").flatten() {
        if let Ok(text) = std::fs::read_to_string(entry.path()) {
            files.insert(entry.file_name().to_string_lossy().into_owned(), text);
        }
    }
    files
}

/// Mirrors the fingerprint the constructor computes over in-memory files, so
/// the change test can compare two file sets without building an engine from
/// each.
fn fingerprint_via_files(files: &HashMap<String, String>) -> [u8; 32] {
    let mut names: Vec<&String> = files.keys().collect();
    names.sort();
    let mut all = Vec::new();
    for name in names {
        all.extend_from_slice(name.as_bytes());
        all.push(0);
        let content = &files[name];
        all.extend_from_slice(&(content.len() as u64).to_le_bytes());
        all.extend_from_slice(content.as_bytes());
    }
    sha256(&all)
}
