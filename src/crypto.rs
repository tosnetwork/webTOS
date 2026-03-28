//! Cryptographic primitives for ATOS.
//! Uses Ed25519 (via ed25519-dalek) with RDRAND hardware RNG.

extern crate alloc;

pub use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};

/// Hardware random number generator using x86_64 RDRAND instruction.
pub struct RdrandRng;

impl RdrandRng {
    pub fn new() -> Self { Self }

    fn rdrand64() -> u64 {
        let mut val: u64;
        unsafe {
            let mut ok: u8;
            core::arch::asm!(
                "rdrand {val}",
                "setc {ok}",
                val = out(reg) val,
                ok = out(reg_byte) ok,
            );
            if ok == 0 {
                // RDRAND failed, fallback to RDTSC
                let lo: u32;
                let hi: u32;
                core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi);
                val = ((hi as u64) << 32) | (lo as u64);
            }
        }
        val
    }
}

impl rand_core::RngCore for RdrandRng {
    fn next_u32(&mut self) -> u32 {
        Self::rdrand64() as u32
    }
    fn next_u64(&mut self) -> u64 {
        Self::rdrand64()
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut i = 0;
        while i < dest.len() {
            let val = Self::rdrand64();
            let bytes = val.to_le_bytes();
            let remaining = dest.len() - i;
            let to_copy = remaining.min(8);
            dest[i..i + to_copy].copy_from_slice(&bytes[..to_copy]);
            i += to_copy;
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl rand_core::CryptoRng for RdrandRng {}

/// Generate a new Ed25519 keypair using hardware RNG.
pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
    let mut rng = RdrandRng::new();
    let signing_key = SigningKey::generate(&mut rng);
    let verifying_key = signing_key.verifying_key();
    (signing_key, verifying_key)
}

/// Sign a message with an Ed25519 signing key.
pub fn sign(key: &SigningKey, message: &[u8]) -> Signature {
    key.sign(message)
}

/// Verify a signature with an Ed25519 verifying key.
pub fn verify(key: &VerifyingKey, message: &[u8], sig: &Signature) -> bool {
    key.verify(message, sig).is_ok()
}
