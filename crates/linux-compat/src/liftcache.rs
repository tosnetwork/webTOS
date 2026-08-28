//! The validation contract for a persisted lift cache.
//!
//! Lifting is the largest single cost of a cold start. Most of it — the
//! optimizer — is already skipped for cold code by tiered lifting, which runs
//! the optimizer only on blocks that prove hot; what remains to persist is the
//! cheap decode-and-build, about 0.43s of a 1.4s cold start, and only on a
//! *reload* of an image already seen. `docs/performance.md` has the numbers.
//!
//! That residual is small, and the thing it would persist — the engine's
//! internal p-code — is coupled to vendored representation and, executed under
//! the wrong specification, is silent wrong execution. So the body is not
//! serialized here. What is built is the part that makes persistence *safe*
//! and that a body serializer would have to sit behind: a header that keys the
//! cache to the specification it was lifted under and the images it covers,
//! and refuses anything that does not match. A cache is worse than useless if
//! it can be trusted when it should not be, and this is the piece that decides
//! that — so it is the piece worth building and gating first.

use crate::digest::{from_hex, hex};

const MAGIC: &[u8; 4] = b"WTLC";
/// The on-disk layout version. The body format the ROADMAP defers would bump
/// this; a reader that does not know a version refuses rather than guesses.
const FORMAT_VERSION: u32 = 1;

/// What a persisted lift cache commits to: the specification it was lifted
/// under, and the images it covers by content digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiftCacheHeader {
    pub spec_fingerprint: [u8; 32],
    /// The SHA-256 of each image the cache holds lifted blocks for. A cache
    /// is only valid for the exact bytes it was built from — the same
    /// content-addressing the in-process cache already does, made persistent.
    pub image_digests: Vec<[u8; 32]>,
}

impl LiftCacheHeader {
    pub fn new(spec_fingerprint: [u8; 32], image_digests: Vec<[u8; 32]>) -> Self {
        Self {
            spec_fingerprint,
            image_digests,
        }
    }

    /// Serializes the header. Binary, because it prefixes a binary body: a
    /// magic, a version, the spec fingerprint, then a count and the digests.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 4 + 32 + 4 + self.image_digests.len() * 32);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
        out.extend_from_slice(&self.spec_fingerprint);
        out.extend_from_slice(&(self.image_digests.len() as u32).to_le_bytes());
        for digest in &self.image_digests {
            out.extend_from_slice(digest);
        }
        out
    }

    /// Parses a header, refusing anything it cannot read rather than guessing
    /// past it. A truncated or mis-magicked cache is treated as absent, not as
    /// a cache with fewer entries.
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        let mut cursor = Cursor::new(bytes);
        if cursor.take(4)? != MAGIC {
            return Err("not a lift cache".into());
        }
        let version = cursor.u32()?;
        if version != FORMAT_VERSION {
            return Err(format!(
                "lift cache version {version}, this engine writes {FORMAT_VERSION}"
            ));
        }
        let mut spec_fingerprint = [0_u8; 32];
        spec_fingerprint.copy_from_slice(cursor.take(32)?);
        let count = cursor.u32()? as usize;
        // A count is a claim about how many digests follow. A cache that says
        // it has more than the bytes can hold is truncated, and reserving for
        // the claim rather than the bytes is how a bad length becomes a large
        // allocation.
        let remaining = cursor.remaining();
        if count.checked_mul(32).map(|n| n > remaining).unwrap_or(true) {
            return Err(format!(
                "lift cache claims {count} images but only {remaining} bytes follow"
            ));
        }
        let mut image_digests = Vec::with_capacity(count);
        for _ in 0..count {
            let mut digest = [0_u8; 32];
            digest.copy_from_slice(cursor.take(32)?);
            image_digests.push(digest);
        }
        Ok(Self {
            spec_fingerprint,
            image_digests,
        })
    }

    /// Whether this cache may be used with the given engine spec.
    ///
    /// This is the refusal that matters: p-code lifted under one spec is not
    /// valid under another, and executing it would be silent wrong execution
    /// rather than a crash. The fingerprint is what tells the two apart.
    pub fn validate_spec(&self, current: &[u8; 32]) -> Result<(), String> {
        if &self.spec_fingerprint != current {
            return Err(format!(
                "lift cache was built under specification {}, this engine is {}",
                hex(&self.spec_fingerprint),
                hex(current)
            ));
        }
        Ok(())
    }

    /// Whether the cache covers an image with the given content digest. A
    /// cache built from other bytes than the ones now present cannot vouch
    /// for them.
    pub fn covers_image(&self, digest: &[u8; 32]) -> bool {
        self.image_digests.contains(digest)
    }
}

/// A byte reader that refuses to read past the end, so a truncated cache
/// becomes an error rather than a panic.
struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self
            .at
            .checked_add(n)
            .filter(|&end| end <= self.bytes.len())
            .ok_or("lift cache is truncated")?;
        let slice = &self.bytes[self.at..end];
        self.at = end;
        Ok(slice)
    }

    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().expect("4 bytes"),
        ))
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.at
    }
}

/// The hex spec fingerprint, for a host that writes it beside a cache.
pub fn fingerprint_hex(fingerprint: &[u8; 32]) -> String {
    hex(fingerprint)
}

/// Parses a hex spec fingerprint a host stored.
pub fn fingerprint_from_hex(text: &[u8]) -> Option<[u8; 32]> {
    from_hex(text)
}
