//! Content-addressed VFS foundation: immutable files name hashes, resident
//! storage is counted once, and snapshots retain authority without copying the
//! base payload into every session.

use linux_compat::{
    chunk::{ChunkedFile, ReadRange},
    digest::sha256,
    vfs::Vfs,
};

#[test]
fn chunked_inode_reads_verified_ranges_and_snapshots_without_base_bytes() {
    let first = vec![0x41; 4096];
    let second = vec![0x42; 31];
    let first_hash = sha256(&first);
    let second_hash = sha256(&second);
    let layout = ChunkedFile::new(4127, 4096, vec![first_hash, second_hash]).expect("layout");

    let mut vfs = Vfs::new();
    let node = vfs
        .add_chunked_file(b"/lib/runtime.so", layout, 0o555)
        .expect("chunked inode");
    assert_eq!(vfs.node(node).size(), 4127);
    assert_eq!(vfs.bytes(), 0, "logical size is not resident storage");
    assert_eq!(
        vfs.read_node_range(node, 4090, 20).expect("range"),
        ReadRange::Missing(first_hash)
    );

    vfs.put_chunk(first_hash, first.clone())
        .expect("first chunk");
    assert_eq!(
        vfs.read_node_range(node, 4090, 20).expect("range"),
        ReadRange::Missing(second_hash)
    );
    vfs.put_chunk(second_hash, second.clone())
        .expect("second chunk");
    assert_eq!(
        vfs.read_node_range(node, 4090, 20).expect("range"),
        ReadRange::Ready(vec![
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
            0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        ])
    );
    assert_eq!(vfs.bytes(), first.capacity() + second.capacity());

    let unbound = vfs.serialize();
    let error = match Vfs::deserialize(&unbound) {
        Ok(_) => panic!("a snapshot descriptor was accepted without image authority"),
        Err(error) => error,
    };
    assert_eq!(error, "chunked snapshot has no manifest root",);

    let root = sha256(b"canonical manifest bytes\n");
    vfs.set_manifest_root(Some(root));
    let snapshot = vfs.serialize();
    assert!(
        snapshot.len() < first.len(),
        "snapshot copied immutable base payload: {} bytes",
        snapshot.len()
    );
    let mut trailing = snapshot.clone();
    trailing.push(0);
    let error = match Vfs::deserialize(&trailing) {
        Ok(_) => panic!("snapshot trailing bytes were ignored"),
        Err(error) => error,
    };
    assert_eq!(error, "filesystem image has trailing bytes");
    let mut restored = Vfs::deserialize(&snapshot).expect("restore");
    assert_eq!(restored.manifest_root(), Some(root));
    assert_eq!(restored.bytes(), 0, "base cache is not session state");
    assert_eq!(
        restored.read_node_range(node, 0, 1).expect("range"),
        ReadRange::Missing(first_hash)
    );
    restored
        .put_chunk(first_hash, first)
        .expect("restore chunk");
    assert_eq!(
        restored.read_node_range(node, 0, 1).expect("range"),
        ReadRange::Ready(vec![0x41])
    );
}
