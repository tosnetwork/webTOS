//! Minimal signing primitives for no_std bare-metal.
//! Uses a keyed hash (HMAC-FNV) as a placeholder for Ed25519.
//! Replace with real Ed25519 when a suitable no_std crate is integrated.

pub type SigningKey = [u8; 32];
pub type VerifyKey = [u8; 32];
pub type Signature = [u8; 64];

/// Generate a keypair (deterministic from seed for reproducibility).
pub fn generate_keypair(seed: &[u8; 32]) -> (SigningKey, VerifyKey) {
    let mut sk = [0u8; 32];
    let mut vk = [0u8; 32];
    // Derive signing key from seed
    let mut h: u64 = 0xcbf29ce484222325;
    for b in seed {
        h = h.wrapping_mul(0x100000001b3) ^ (*b as u64);
    }
    sk[0..8].copy_from_slice(&h.to_le_bytes());
    h = h.wrapping_mul(0x100000001b3) ^ 0xdeadbeef;
    sk[8..16].copy_from_slice(&h.to_le_bytes());
    h = h.wrapping_mul(0x100000001b3) ^ 0xcafebabe;
    sk[16..24].copy_from_slice(&h.to_le_bytes());
    h = h.wrapping_mul(0x100000001b3) ^ 0x12345678;
    sk[24..32].copy_from_slice(&h.to_le_bytes());
    // Derive verify key from signing key
    h = 0x6c62272e07bb0142;
    for b in &sk {
        h = h.wrapping_mul(0x100000001b3) ^ (*b as u64);
    }
    vk[0..8].copy_from_slice(&h.to_le_bytes());
    h = h.wrapping_mul(0x100000001b3) ^ 0xfeedface;
    vk[8..16].copy_from_slice(&h.to_le_bytes());
    h = h.wrapping_mul(0x100000001b3) ^ 0xbaadf00d;
    vk[16..24].copy_from_slice(&h.to_le_bytes());
    h = h.wrapping_mul(0x100000001b3) ^ 0xdeadc0de;
    vk[24..32].copy_from_slice(&h.to_le_bytes());
    (sk, vk)
}

/// Sign a message with a signing key.
pub fn sign(key: &SigningKey, message: &[u8]) -> Signature {
    let mut sig = [0u8; 64];
    // Keyed hash: H(key || message)
    let mut h: u64 = 0xcbf29ce484222325;
    for b in key {
        h = h.wrapping_mul(0x100000001b3) ^ (*b as u64);
    }
    for b in message {
        h = h.wrapping_mul(0x100000001b3) ^ (*b as u64);
    }
    sig[0..8].copy_from_slice(&h.to_le_bytes());
    // Second pass with different init
    h = 0x6c62272e07bb0142;
    for b in key {
        h = h.wrapping_mul(0x100000001b3) ^ (*b as u64);
    }
    for b in message {
        h = h.wrapping_mul(0x100000001b3) ^ (*b as u64);
    }
    sig[8..16].copy_from_slice(&h.to_le_bytes());
    // Fill remaining with cascaded hashes
    for i in 2..8 {
        h = h.wrapping_mul(0x100000001b3) ^ (i as u64);
        for b in key {
            h = h.wrapping_mul(0x100000001b3) ^ (*b as u64);
        }
        sig[i * 8..(i + 1) * 8].copy_from_slice(&h.to_le_bytes());
    }
    sig
}

/// Verify a signature.
pub fn verify(key: &VerifyKey, message: &[u8], sig: &Signature) -> bool {
    // Derive signing key from verify key (in real Ed25519 this is the reverse)
    // For our keyed-hash scheme, we re-derive the expected signature
    // This is a simplification -- real Ed25519 doesn't need the signing key to verify
    let mut sk = [0u8; 32];
    let mut h: u64 = 0x6c62272e07bb0142;
    for b in key {
        h = h.wrapping_mul(0x100000001b3) ^ (*b as u64);
    }
    sk[0..8].copy_from_slice(&h.to_le_bytes());
    for i in 1..4 {
        h = h.wrapping_mul(0x100000001b3) ^ (i as u64);
        sk[i * 8..(i + 1) * 8].copy_from_slice(&h.to_le_bytes());
    }
    let expected = sign(&sk, message);
    expected == *sig
}
