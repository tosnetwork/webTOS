//! What a host is allowed to put in the guest, and what its bytes must be.
//!
//! An image arrives in pieces over a network and is cached in browser storage
//! between sessions. TLS says something about the server that sent it; it
//! says nothing about a copy that has been sitting in OPFS since last week,
//! nor about a piece that arrived from somewhere else. A manifest names each
//! image and commits to its content, and delivery refuses anything that does
//! not match.
//!
//! The signature over the manifest is not checked here, deliberately. A wrong
//! signature verifier fails open — it accepts what it should not, and nothing
//! says so — and a hand-rolled unaudited one in a security boundary is worse
//! than none. The platform has a vetted implementation: the host verifies the
//! manifest with `crypto.subtle` before installing it, and what reaches this
//! layer is already authenticated. This layer is only responsible for the
//! part a known-answer test can settle: that the bytes delivered are the
//! bytes the manifest names.
//!
//! The format is one entry per line, `<64 hex digits> <decimal size> <path>`,
//! with `#` comments and blank lines ignored. Text, because a host writes it
//! and a person reads it; and the digest first so a line is easy to check by
//! eye against `sha256sum`.

use std::collections::BTreeMap;

use crate::digest::{from_hex, hex};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub digest: [u8; 32],
    pub size: usize,
}

/// The images a host has committed to, by guest path.
#[derive(Debug, Clone, Default)]
pub struct Manifest {
    entries: BTreeMap<Vec<u8>, Entry>,
}

impl Manifest {
    /// Parses a manifest, refusing anything it cannot read rather than
    /// skipping the line. A manifest with a line nobody understood is not a
    /// manifest with one fewer entry — it is a manifest that does not say
    /// what someone thought it said.
    pub fn parse(text: &[u8]) -> Result<Self, String> {
        let mut entries = BTreeMap::new();
        for (number, line) in text.split(|&b| b == b'\n').enumerate() {
            let line = trim(line);
            if line.is_empty() || line[0] == b'#' {
                continue;
            }
            let mut fields = line.splitn(3, |&b| b == b' ');
            let (Some(digest), Some(size), Some(path)) =
                (fields.next(), fields.next(), fields.next())
            else {
                return Err(format!(
                    "manifest line {}: expected '<digest> <size> <path>'",
                    number + 1
                ));
            };
            let digest = from_hex(digest)
                .ok_or_else(|| format!("manifest line {}: not a sha-256 digest", number + 1))?;
            let size: usize = std::str::from_utf8(size)
                .ok()
                .and_then(|s| s.parse().ok())
                .ok_or_else(|| format!("manifest line {}: not a size", number + 1))?;
            let path = trim(path).to_vec();
            if path.is_empty() || path[0] != b'/' {
                return Err(format!(
                    "manifest line {}: path must be absolute",
                    number + 1
                ));
            }
            if entries
                .insert(path.clone(), Entry { digest, size })
                .is_some()
            {
                // Two entries for one path is a manifest that commits to two
                // different things, and picking either is a guess.
                return Err(format!(
                    "manifest line {}: {} is named twice",
                    number + 1,
                    String::from_utf8_lossy(&path)
                ));
            }
        }
        if entries.is_empty() {
            return Err("manifest names nothing".into());
        }
        Ok(Self { entries })
    }

    /// The text form, so a host can produce one from the images it has.
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        for (path, entry) in &self.entries {
            out.push_str(&hex(&entry.digest));
            out.push(' ');
            out.push_str(&entry.size.to_string());
            out.push(' ');
            out.push_str(&String::from_utf8_lossy(path));
            out.push('\n');
        }
        out
    }

    pub fn insert(&mut self, path: &[u8], digest: [u8; 32], size: usize) {
        self.entries.insert(path.to_vec(), Entry { digest, size });
    }

    pub fn get(&self, path: &[u8]) -> Option<&Entry> {
        self.entries.get(path)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn paths(&self) -> impl Iterator<Item = &Vec<u8>> {
        self.entries.keys()
    }

    /// Whether `path` is covered. A manifest is a list of what may be
    /// delivered, so an image it does not name is refused rather than waved
    /// through — otherwise adding a file nobody committed to is how an image
    /// gets in.
    pub fn covers(&self, path: &[u8]) -> bool {
        self.entries.contains_key(path)
    }

    /// Checks delivered bytes against what was committed, naming which of the
    /// two disagreed. The size is checked first because it is the cheaper
    /// answer and the more legible one.
    pub fn check(&self, path: &[u8], digest: &[u8; 32], size: usize) -> Result<(), String> {
        let name = String::from_utf8_lossy(path);
        let Some(entry) = self.entries.get(path) else {
            return Err(format!("{name} is not in the manifest"));
        };
        if entry.size != size {
            return Err(format!(
                "{name}: manifest says {} bytes, {size} delivered",
                entry.size
            ));
        }
        if &entry.digest != digest {
            return Err(format!(
                "{name}: manifest says {}, delivered {}",
                hex(&entry.digest),
                hex(digest)
            ));
        }
        Ok(())
    }
}

fn trim(line: &[u8]) -> &[u8] {
    let start = line
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(line.len());
    let end = line
        .iter()
        .rposition(|b| !b.is_ascii_whitespace())
        .map_or(start, |i| i + 1);
    &line[start..end]
}
