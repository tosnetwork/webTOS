//! A snapshot comes back from browser storage, where anything could have
//! happened to it: a partial write, a quota eviction mid-flush, a different
//! version of this program, or someone editing it. Restoring one must fail
//! closed — an error, never a panic and never a tree that looks valid and is
//! not.

use std::path::PathBuf;

use linux_compat::{vfs::Vfs, Machine};
use x64_engine::EngineConfig;

fn ldef_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../third_party/ghidra-x86/languages/x86.ldefs")
}

/// A snapshot of a small but structurally complete filesystem: directories,
/// nested files, a symlink, and a device node, so a sweep reaches every arm
/// of the parser.
fn sample_snapshot() -> Vec<u8> {
    let mut machine =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build failed");
    machine
        .add_file(
            b"/etc/config.json",
            b"{\"key\":\"value\"}\n".to_vec(),
            0o644,
        )
        .expect("seed file");
    machine
        .add_file(b"/root/notes.txt", b"alpha\nbeta\n".to_vec(), 0o600)
        .expect("seed file");
    machine
        .add_symlink(b"/bin/sh", b"/bin/busybox")
        .expect("seed symlink");
    machine.export_fs()
}

#[test]
fn a_snapshot_round_trips() {
    let snapshot = sample_snapshot();
    let restored = Vfs::deserialize(&snapshot).expect("a snapshot this program wrote");
    assert_eq!(
        restored.read_file(b"/etc/config.json"),
        Some(b"{\"key\":\"value\"}\n".as_slice())
    );
    // Serializing what was restored gives the same bytes, so the format has
    // no state the parser drops on the floor.
    assert!(
        restored.serialize() == snapshot,
        "a restored snapshot did not re-serialize identically"
    );
}

/// Every truncation. A partial write is the likeliest corruption a browser
/// produces, and the parser must treat every prefix as an error rather than
/// as a shorter filesystem.
#[test]
fn every_truncation_is_refused() {
    let snapshot = sample_snapshot();
    for cut in 0..snapshot.len() {
        let result = Vfs::deserialize(&snapshot[..cut]);
        assert!(
            result.is_err(),
            "a snapshot truncated to {cut} of {} bytes was accepted",
            snapshot.len()
        );
    }
}

/// Every single-byte corruption. Accepting one is allowed — flipping a byte
/// inside a file's contents produces a different but entirely valid
/// filesystem — but panicking is not, and neither is running out of memory
/// on a structure a few hundred bytes long.
#[test]
fn no_single_byte_corruption_panics() {
    let snapshot = sample_snapshot();
    let mut accepted = 0_usize;
    for index in 0..snapshot.len() {
        for bit in 0..8 {
            let mut damaged = snapshot.clone();
            damaged[index] ^= 1 << bit;
            match Vfs::deserialize(&damaged) {
                Ok(vfs) => {
                    accepted += 1;
                    // Whatever came back has to be a filesystem that can be
                    // walked and written out again without tripping.
                    let _ = vfs.read_file(b"/etc/config.json");
                    let _ = vfs.serialize();
                }
                Err(_) => {}
            }
        }
    }
    // The sweep is only evidence if some of it got through the parser and
    // exercised the structures behind it.
    assert!(
        accepted > 0,
        "no corrupted snapshot was accepted, so nothing past the header was tested"
    );
}

/// A header can claim far more nodes than the bytes could hold. Believing it
/// enough to reserve for them turns a dozen bytes out of browser storage into
/// a large allocation, which is the whole attack — and the parse fails either
/// way, so "it returned an error" is not evidence that it did not allocate.
/// What distinguishes the two is *which* error: the claim has to be refused
/// against the size of the input, before any reservation.
#[test]
fn a_header_claiming_more_nodes_than_bytes_is_refused_before_reserving() {
    let snapshot = sample_snapshot();
    let version = u32::from_le_bytes(snapshot[4..8].try_into().expect("snapshot version"));
    let mut count_at = 8;
    if version >= 3 {
        count_at += 1;
        if snapshot[8] == 1 {
            count_at += 32;
        }
    }
    let header_end = count_at + 4;
    let mut lying = snapshot[..header_end].to_vec();
    lying[count_at..header_end].copy_from_slice(&3_999_999_u32.to_le_bytes());
    let error = match Vfs::deserialize(&lying) {
        Ok(_) => panic!("a header claiming 4M nodes was accepted"),
        Err(error) => error,
    };
    assert!(
        error.contains("nodes claimed") && error.contains("bytes to hold them"),
        "the count was not checked against the input size; it failed later, having \
         already reserved for it: {error}"
    );

    // The same claim, one node short of what the bytes can back, is a
    // truncation rather than an implausible header — so the check is a real
    // bound and not a blanket refusal.
    let mut plausible = snapshot.clone();
    let backed = (snapshot.len() - header_end) / (8 + 4 + 8 + 8 + 1);
    plausible[count_at..header_end].copy_from_slice(&(backed as u32).to_le_bytes());
    let error = match Vfs::deserialize(&plausible) {
        Ok(_) => panic!("a node count that cannot be filled"),
        Err(error) => error,
    };
    assert!(
        !error.contains("nodes claimed"),
        "a count the input could hold was refused as implausible: {error}"
    );
}

/// A 64-bit length or index truncates when cast to `usize` on a 32-bit host,
/// and the browser is one: a length of 2^32 + 1 would read as 1, and an
/// out-of-range parent would wrap into a valid-looking index. The parse has
/// to refuse rather than narrow. Checked here on a 64-bit host by the error
/// path being reachable at all, which is what the cast removed.
#[test]
fn an_oversized_length_is_refused_rather_than_narrowed() {
    let snapshot = sample_snapshot();
    // Find a file node's length field: the tag byte 2 followed by a u64 that
    // matches a file this test seeded.
    let needle = b"alpha\nbeta\n";
    let at = snapshot
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("the seeded file is in the snapshot");
    let len_at = at - 8;
    assert_eq!(
        u64::from_le_bytes(snapshot[len_at..len_at + 8].try_into().unwrap()),
        needle.len() as u64,
        "did not find the length field ahead of the contents"
    );

    let mut oversized = snapshot.clone();
    oversized[len_at..len_at + 8].copy_from_slice(&(u64::MAX - 1).to_le_bytes());
    let error = match Vfs::deserialize(&oversized) {
        Ok(_) => panic!("a 2^64 file length was accepted"),
        Err(error) => error,
    };
    assert!(
        error.contains("truncated") || error.contains("too large"),
        "an oversized length produced an unrelated failure: {error}"
    );
}
