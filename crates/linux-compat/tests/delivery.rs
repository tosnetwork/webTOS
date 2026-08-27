//! An image arrives as a call sequence, not as a blob: `create_file` reserves,
//! `append_file` fills, and the guest sees the result. The sequence comes from
//! the host, so it can be wrong in every way a sequence can — a piece for a
//! file that was never started, more pieces than the reservation expected, two
//! streams to one path, a path that is already something else.
//!
//! The property that matters most is what the guest can see. A reservation is
//! not content: a file half delivered must read as exactly the bytes that
//! arrived, never as the room made for the ones that did not.

use std::path::PathBuf;

use linux_compat::Machine;
use x64_engine::EngineConfig;

fn ldef_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../third_party/ghidra-x86/languages/x86.ldefs")
}

fn machine() -> Machine {
    Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build failed")
}

/// What the guest would read at `path`, via the same route a guest read takes.
fn contents(machine: &mut Machine, path: &[u8]) -> Option<Vec<u8>> {
    machine.env().vfs.read_file(path).map(<[u8]>::to_vec)
}

#[test]
fn a_half_delivered_image_reads_as_what_arrived_not_as_the_room_made_for_it() {
    let mut machine = machine();
    // Reserve a megabyte, deliver eleven bytes, stop.
    machine
        .create_file(b"/bin/partial", 1 << 20, 0o755)
        .expect("create");
    machine
        .append_file(b"/bin/partial", b"hello world")
        .expect("append");

    let seen = contents(&mut machine, b"/bin/partial").expect("the file exists");
    assert_eq!(
        seen,
        b"hello world",
        "a file that reserved a megabyte and received eleven bytes read as {} bytes; \
         the reservation is visible to the guest",
        seen.len()
    );
}

#[test]
fn pieces_for_a_file_nobody_started_are_refused() {
    let mut machine = machine();
    let err = machine
        .append_file(b"/bin/never-created", b"piece")
        .expect_err("appending to nothing should fail");
    assert!(
        err.contains("errno 2"),
        "expected ENOENT for a file that was never created, got {err}"
    );
    assert!(
        contents(&mut machine, b"/bin/never-created").is_none(),
        "a refused append created the file anyway"
    );
}

#[test]
fn more_pieces_than_the_reservation_expected_still_arrive_whole() {
    let mut machine = machine();
    machine
        .create_file(b"/bin/small", 4, 0o755)
        .expect("create");
    for piece in [&b"aaaa"[..], b"bbbb", b"cccc"] {
        machine
            .append_file(b"/bin/small", piece)
            .expect("a reservation is a hint, not a limit");
    }
    assert_eq!(
        contents(&mut machine, b"/bin/small").as_deref(),
        Some(&b"aaaabbbbcccc"[..]),
        "pieces past the reservation were lost or truncated"
    );
}

#[test]
fn a_second_stream_to_one_path_does_not_splice_itself_onto_the_first() {
    let mut machine = machine();
    machine
        .create_file(b"/bin/twice", 16, 0o755)
        .expect("first");
    machine
        .append_file(b"/bin/twice", b"first")
        .expect("first piece");
    // A host that starts over — a retried download, a reconnect — must get a
    // file holding the second delivery, not the two concatenated.
    machine
        .create_file(b"/bin/twice", 16, 0o755)
        .expect("second");
    machine
        .append_file(b"/bin/twice", b"second")
        .expect("second piece");
    assert_eq!(
        contents(&mut machine, b"/bin/twice").as_deref(),
        Some(&b"second"[..]),
        "restarting a delivery spliced it onto the abandoned one"
    );
}

#[test]
fn a_stream_aimed_at_a_directory_is_refused() {
    let mut machine = machine();
    machine
        .add_file(b"/bin/real/file", b"x".to_vec(), 0o644)
        .expect("seed a directory");
    machine
        .create_file(b"/bin/real", 8, 0o755)
        .expect_err("a directory is not a file to stream into");
    machine
        .append_file(b"/bin/real", b"piece")
        .expect_err("a directory is not a file to append to");
    machine
        .add_file(b"/bin/real", b"whole".to_vec(), 0o755)
        .expect_err("nor is it a file to write whole");
    assert_eq!(
        contents(&mut machine, b"/bin/real/file").as_deref(),
        Some(&b"x"[..]),
        "the refused stream damaged what was already there"
    );
}

#[test]
fn interleaved_streams_do_not_mix() {
    let mut machine = machine();
    machine.create_file(b"/bin/a", 8, 0o755).expect("create a");
    machine.create_file(b"/bin/b", 8, 0o755).expect("create b");
    for (path, piece) in [
        (&b"/bin/a"[..], &b"a1"[..]),
        (b"/bin/b", b"b1"),
        (b"/bin/a", b"a2"),
        (b"/bin/b", b"b2"),
    ] {
        machine.append_file(path, piece).expect("append");
    }
    assert_eq!(
        contents(&mut machine, b"/bin/a").as_deref(),
        Some(&b"a1a2"[..])
    );
    assert_eq!(
        contents(&mut machine, b"/bin/b").as_deref(),
        Some(&b"b1b2"[..])
    );
}

#[test]
fn a_reservation_too_large_for_the_host_is_refused_before_it_is_made() {
    let mut machine = machine();
    // Half the address space. The refusal has to come from asking whether the
    // room exists, not from taking it and falling over.
    let err = machine
        .create_file(b"/bin/enormous", usize::MAX / 2, 0o755)
        .expect_err("a reservation that cannot be served should be refused");
    assert!(
        err.contains("errno 12"),
        "expected ENOMEM for an unservable reservation, got {err}"
    );
    assert!(
        contents(&mut machine, b"/bin/enormous").is_none(),
        "a refused reservation left the file behind"
    );
}
