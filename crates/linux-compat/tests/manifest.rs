//! What a host is allowed to put in the guest.
//!
//! An image arrives in pieces over a network and is cached in browser storage
//! between sessions. TLS says something about the server that sent it and
//! nothing about a copy that has been in OPFS since last week. A manifest
//! commits to the content, and the commitment is checked before the guest
//! runs the bytes rather than when they arrive — a host that forgets to say
//! a stream finished cannot skip the check that way.

use std::path::PathBuf;

use linux_compat::digest::{hex, sha256};
use linux_compat::manifest::Manifest;
use linux_compat::Machine;
use x64_engine::EngineConfig;

fn ldef_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../third_party/ghidra-x86/languages/x86.ldefs")
}

fn image() -> Vec<u8> {
    std::fs::read(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../test_data/hello_linux.elf"))
        .expect("in-repo fixture")
}

fn fresh() -> Machine {
    Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build failed")
}

fn line(path: &str, bytes: &[u8]) -> String {
    format!("{} {} {path}\n", hex(&sha256(bytes)), bytes.len())
}

#[test]
fn an_image_that_matches_its_entry_runs() {
    let bytes = image();
    let mut machine = fresh();
    machine
        .set_manifest(Some(line("/bin/hello", &bytes).as_bytes()))
        .expect("manifest parses");
    machine
        .add_file(b"/bin/hello", bytes, 0o755)
        .expect("delivery refused a matching image");
    machine.set_args(vec![b"hello".to_vec()], vec![]);
    machine.load(b"/bin/hello").expect("load refused");
}

#[test]
fn an_image_whose_bytes_were_changed_does_not_run() {
    let bytes = image();
    // The manifest commits to the original; what arrives is one byte
    // different, deep inside — the shape of a substitution rather than of
    // corruption, which the loader would catch on its own.
    let manifest = line("/bin/hello", &bytes);
    let mut tampered = bytes.clone();
    let at = tampered.len() / 2;
    tampered[at] ^= 0x01;

    let mut machine = fresh();
    machine
        .set_manifest(Some(manifest.as_bytes()))
        .expect("manifest parses");
    let refused = machine
        .add_file(b"/bin/hello", tampered, 0o755)
        .expect_err("a changed image was delivered");
    assert!(
        refused.contains("manifest says"),
        "the refusal did not say what disagreed: {refused}"
    );
}

#[test]
fn an_image_the_manifest_does_not_name_does_not_run() {
    let bytes = image();
    let mut machine = fresh();
    machine
        .set_manifest(Some(line("/bin/hello", &bytes).as_bytes()))
        .expect("manifest parses");
    // A manifest is a list of what may be delivered. Something it does not
    // mention is how an extra image gets in, so it is refused rather than
    // waved through.
    let refused = machine
        .add_file(b"/bin/extra", bytes, 0o755)
        .expect_err("an unnamed image was delivered");
    assert!(
        refused.contains("not in the manifest"),
        "the refusal did not say why: {refused}"
    );
}

#[test]
fn a_streamed_image_is_judged_by_what_arrived_not_by_what_was_promised() {
    let bytes = image();
    let manifest = line("/bin/streamed", &bytes);

    // Delivered whole, in pieces: accepted, and it runs.
    let mut machine = fresh();
    machine
        .set_manifest(Some(manifest.as_bytes()))
        .expect("manifest parses");
    machine
        .create_file(b"/bin/streamed", bytes.len(), 0o755)
        .expect("create");
    for piece in bytes.chunks(1024) {
        machine
            .append_file(b"/bin/streamed", piece)
            .expect("append");
    }
    machine.set_args(vec![b"streamed".to_vec()], vec![]);
    machine
        .load(b"/bin/streamed")
        .expect("a whole stream was refused");

    // One piece altered: refused, at the moment before it would have run.
    let mut machine = fresh();
    machine
        .set_manifest(Some(manifest.as_bytes()))
        .expect("manifest parses");
    machine
        .create_file(b"/bin/streamed", bytes.len(), 0o755)
        .expect("create");
    for (i, piece) in bytes.chunks(1024).enumerate() {
        let mut piece = piece.to_vec();
        if i == 3 {
            piece[0] ^= 0x80;
        }
        machine
            .append_file(b"/bin/streamed", &piece)
            .expect("append");
    }
    machine.set_args(vec![b"streamed".to_vec()], vec![]);
    let refused = machine
        .load(b"/bin/streamed")
        .expect_err("a stream with an altered piece was loaded");
    assert!(
        refused.contains("manifest says"),
        "the refusal did not say what disagreed: {refused}"
    );
}

#[test]
fn a_stream_that_stops_early_does_not_run() {
    let bytes = image();
    let mut machine = fresh();
    machine
        .set_manifest(Some(line("/bin/truncated", &bytes).as_bytes()))
        .expect("manifest parses");
    machine
        .create_file(b"/bin/truncated", bytes.len(), 0o755)
        .expect("create");
    // A connection that dropped halfway leaves a file that is a valid prefix
    // of the right image. The size disagrees before the digest does.
    for piece in bytes[..bytes.len() / 2].chunks(1024) {
        machine
            .append_file(b"/bin/truncated", piece)
            .expect("append");
    }
    machine.set_args(vec![b"truncated".to_vec()], vec![]);
    let refused = machine
        .load(b"/bin/truncated")
        .expect_err("half an image was loaded");
    assert!(
        refused.contains("manifest says") && refused.contains("delivered"),
        "the refusal did not name the size: {refused}"
    );
}

#[test]
fn no_manifest_means_no_check() {
    // A host with nothing to verify against is not stopped from running.
    let mut machine = fresh();
    machine
        .add_file(b"/bin/hello", image(), 0o755)
        .expect("delivery refused without a manifest");
    machine.set_args(vec![b"hello".to_vec()], vec![]);
    machine.load(b"/bin/hello").expect("load refused");
}

#[test]
fn a_manifest_that_cannot_be_read_is_refused_rather_than_partly_believed() {
    for (text, why) in [
        (&b"not a manifest"[..], "shape"),
        (b"zz 1 /bin/x", "digest"),
        (
            b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 many /bin/x",
            "size",
        ),
        (
            b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 0 relative",
            "relative path",
        ),
        (b"# only a comment\n", "empty"),
    ] {
        let mut machine = fresh();
        machine
            .set_manifest(Some(text))
            .expect_err(&format!("a manifest with a bad {why} was accepted"));
    }
}

#[test]
fn one_path_named_twice_is_refused() {
    // Two entries for one path commit to two different things, and picking
    // either is a guess.
    let bytes = image();
    let doubled = format!("{}{}", line("/bin/hello", &bytes), line("/bin/hello", b"x"));
    let mut machine = fresh();
    let refused = machine
        .set_manifest(Some(doubled.as_bytes()))
        .expect_err("a manifest naming one path twice was accepted");
    assert!(refused.contains("named twice"), "{refused}");
}

#[test]
fn a_manifest_round_trips_through_its_text_form() {
    let bytes = image();
    let text = format!(
        "# a comment\n\n{}{}",
        line("/bin/hello", &bytes),
        line("/etc/config", b"{}\n")
    );
    let parsed = Manifest::parse(text.as_bytes()).expect("parses");
    assert_eq!(parsed.len(), 2);
    let again = Manifest::parse(parsed.to_text().as_bytes()).expect("re-parses");
    assert_eq!(again.len(), 2);
    for path in parsed.paths() {
        assert_eq!(
            parsed.get(path),
            again.get(path),
            "{} did not survive the round trip",
            String::from_utf8_lossy(path)
        );
    }
}
