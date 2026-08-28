//! Known-answer tests for the digest.
//!
//! A hash implementation is either right or it is a random function, and the
//! only way to tell from the inside is to check it against answers computed
//! by someone else. These are the NIST vectors and a few lengths chosen to
//! land on the boundaries where a padding mistake lives: exactly one block,
//! one byte short of the length field, and one byte into it.

use linux_compat::digest::{from_hex, hex, sha256, Sha256};

#[test]
fn the_published_vectors_come_out_right() {
    for (input, want) in [
        (
            &b""[..],
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        (
            b"abc",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ),
        (
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        ),
    ] {
        assert_eq!(hex(&sha256(input)), want, "input {input:?}");
    }
}

#[test]
fn the_padding_boundaries_come_out_right() {
    // 55 bytes is the last length whose padding fits in one block; 56 is the
    // first that needs a second; 64 is exactly one block. A padding mistake
    // shows here and nowhere else.
    for (len, want) in [
        (
            55,
            "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318",
        ),
        (
            56,
            "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a",
        ),
        (
            64,
            "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb",
        ),
    ] {
        let input = vec![b'a'; len];
        assert_eq!(hex(&sha256(&input)), want, "{len} bytes of 'a'");
    }
}

#[test]
fn a_digest_taken_in_pieces_matches_one_taken_whole() {
    // This is how an image is actually hashed: as it arrives, in whatever
    // sizes the host chose. Splitting must not change the answer, and the
    // splits that matter are the ones that straddle a block.
    let data: Vec<u8> = (0..1000_u32).map(|i| (i % 251) as u8).collect();
    let whole = sha256(&data);
    for chunk in [1_usize, 7, 63, 64, 65, 127, 128, 333] {
        let mut hasher = Sha256::new();
        for piece in data.chunks(chunk) {
            hasher.update(piece);
        }
        assert_eq!(
            hasher.finish(),
            whole,
            "hashing in {chunk}-byte pieces gave a different answer"
        );
    }
}

#[test]
fn hex_round_trips_and_refuses_what_is_not_a_digest() {
    let digest = sha256(b"round trip");
    assert_eq!(from_hex(hex(&digest).as_bytes()), Some(digest));
    assert_eq!(from_hex(b"short"), None);
    assert_eq!(from_hex(&[b'z'; 64]), None, "non-hex accepted");
    assert_eq!(from_hex(&[b'0'; 63]), None, "wrong length accepted");
}
