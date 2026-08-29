//! Canonical authority for an immutable, chunk-backed guest image.
//!
//! The host authenticates these exact bytes with platform cryptography. The
//! VM parses them again, hashes them as the image root, and installs only the
//! paths and chunk layouts they name. Paths and symlink targets are hex so the
//! line format is unambiguous for every Unix byte string.

use std::collections::BTreeSet;

use crate::{chunk::ChunkedFile, digest::sha256};

pub const HEADER: &str = "webtos-chunk-manifest 1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryKind {
    Dir,
    Symlink(Vec<u8>),
    File { file: ChunkedFile, legacy_fnv: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub path: Vec<u8>,
    pub mode: u32,
    pub mtime_sec: i64,
    pub kind: EntryKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkManifest {
    root: [u8; 32],
    entries: Vec<Entry>,
}

impl ChunkManifest {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.is_empty() || bytes.last() != Some(&b'\n') {
            return Err("chunk manifest must end with a newline".into());
        }
        let body = &bytes[..bytes.len() - 1];
        let mut lines = body.split(|byte| *byte == b'\n');
        if lines.next() != Some(HEADER.as_bytes()) {
            return Err(format!("chunk manifest must start with '{HEADER}'"));
        }
        let mut entries = Vec::new();
        let mut paths = BTreeSet::new();
        let mut previous: Option<Vec<u8>> = None;
        for (index, line) in lines.enumerate() {
            if line.is_empty() {
                return Err(format!(
                    "chunk manifest line {} is unexpectedly empty",
                    index + 2
                ));
            }
            let text = std::str::from_utf8(line)
                .map_err(|_| format!("chunk manifest line {} is not UTF-8", index + 2))?;
            let fields: Vec<&str> = text.split(' ').collect();
            let line_no = index + 2;
            let field = |at: usize| {
                fields
                    .get(at)
                    .copied()
                    .ok_or_else(|| format!("chunk manifest line {line_no} is truncated"))
            };
            let tag = field(0)?;
            let mode = parse_octal(field(1)?, line_no, "mode")?;
            let mtime_sec = field(2)?
                .parse::<i64>()
                .map_err(|_| format!("chunk manifest line {line_no} has an invalid mtime"))?;
            if mtime_sec.to_string() != field(2)? {
                return Err(format!(
                    "chunk manifest line {line_no} mtime is not canonical"
                ));
            }
            let path = decode_hex(field(3)?)
                .map_err(|why| format!("chunk manifest line {line_no} path: {why}"))?;
            if path.first() != Some(&b'/') || path.contains(&0) {
                return Err(format!(
                    "chunk manifest line {line_no} path must be absolute and NUL-free"
                ));
            }
            let noncanonical = path.len() > 1 && path.ends_with(b"/")
                || path.windows(2).any(|pair| pair == b"//")
                || path
                    .split(|byte| *byte == b'/')
                    .any(|part| part == b"." || part == b"..");
            if noncanonical {
                return Err(format!(
                    "chunk manifest line {line_no} path is not canonical"
                ));
            }
            if previous.as_ref().is_some_and(|before| before >= &path) {
                return Err(format!(
                    "chunk manifest line {line_no} paths are not strictly sorted"
                ));
            }
            previous = Some(path.clone());
            if !paths.insert(path.clone()) {
                return Err(format!(
                    "chunk manifest line {line_no} names {} twice",
                    path.escape_ascii()
                ));
            }
            let kind = match tag {
                "d" if fields.len() == 4 => EntryKind::Dir,
                "l" if fields.len() == 5 => {
                    let target = decode_hex(field(4)?)
                        .map_err(|why| format!("chunk manifest line {line_no} target: {why}"))?;
                    if target.is_empty() || target.contains(&0) {
                        return Err(format!(
                            "chunk manifest line {line_no} symlink target is empty or contains NUL"
                        ));
                    }
                    EntryKind::Symlink(target)
                }
                "f" if fields.len() == 8 => {
                    let size = field(4)?.parse::<u64>().map_err(|_| {
                        format!("chunk manifest line {line_no} has an invalid size")
                    })?;
                    let chunk_size = field(5)?.parse::<u32>().map_err(|_| {
                        format!("chunk manifest line {line_no} has an invalid chunk size")
                    })?;
                    if size.to_string() != field(4)? || chunk_size.to_string() != field(5)? {
                        return Err(format!(
                            "chunk manifest line {line_no} file layout is not canonical"
                        ));
                    }
                    let legacy_fnv = u64::from_str_radix(field(6)?, 16).map_err(|_| {
                        format!("chunk manifest line {line_no} has an invalid legacy FNV")
                    })?;
                    if field(6)?.len() != 16 {
                        return Err(format!(
                            "chunk manifest line {line_no} legacy FNV must be 16 hex digits"
                        ));
                    }
                    if !field(6)?
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
                    {
                        return Err(format!(
                            "chunk manifest line {line_no} legacy FNV must be lowercase hex"
                        ));
                    }
                    let hashes = if field(7)?.is_empty() {
                        Vec::new()
                    } else {
                        field(7)?
                            .split(',')
                            .map(|hash| {
                                let raw = decode_hex(hash).map_err(|why| {
                                    format!("chunk manifest line {line_no} hash: {why}")
                                })?;
                                raw.try_into().map_err(|_| {
                                    format!(
                                        "chunk manifest line {line_no} chunk hash is not SHA-256"
                                    )
                                })
                            })
                            .collect::<Result<Vec<_>, _>>()?
                    };
                    EntryKind::File {
                        file: ChunkedFile::new(size, chunk_size, hashes)?,
                        legacy_fnv,
                    }
                }
                _ => {
                    return Err(format!(
                        "chunk manifest line {line_no} has an unknown tag or field count"
                    ));
                }
            };
            entries.push(Entry {
                path,
                mode,
                mtime_sec,
                kind,
            });
        }
        if entries.is_empty() {
            return Err("chunk manifest names nothing".into());
        }
        let directories = entries
            .iter()
            .filter_map(|entry| {
                matches!(entry.kind, EntryKind::Dir).then_some(entry.path.as_slice())
            })
            .collect::<BTreeSet<_>>();
        for entry in &entries {
            if entry.path == b"/" {
                continue;
            }
            let slash = entry
                .path
                .iter()
                .rposition(|byte| *byte == b'/')
                .expect("absolute manifest path");
            let parent = if slash == 0 {
                b"/".as_slice()
            } else {
                &entry.path[..slash]
            };
            if parent != b"/" && !directories.contains(parent) {
                return Err(format!(
                    "chunk manifest does not name parent directory {} for {}",
                    parent.escape_ascii(),
                    entry.path.escape_ascii()
                ));
            }
        }
        Ok(Self {
            root: sha256(bytes),
            entries,
        })
    }

    pub fn root(&self) -> [u8; 32] {
        self.root
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    pub fn file(&self, path: &[u8]) -> Option<(&ChunkedFile, u64)> {
        self.entries.iter().find_map(|entry| {
            if entry.path != path {
                return None;
            }
            match &entry.kind {
                EntryKind::File { file, legacy_fnv } => Some((file, *legacy_fnv)),
                _ => None,
            }
        })
    }
}

fn parse_octal(text: &str, line: usize, name: &str) -> Result<u32, String> {
    let value = u32::from_str_radix(text, 8)
        .map_err(|_| format!("chunk manifest line {line} has an invalid {name}"))?;
    if value > 0o7777 {
        return Err(format!("chunk manifest line {line} has an invalid {name}"));
    }
    if format!("{value:o}") != text {
        return Err(format!(
            "chunk manifest line {line} has a noncanonical {name}"
        ));
    }
    Ok(value)
}

fn decode_hex(text: &str) -> Result<Vec<u8>, String> {
    if !text.len().is_multiple_of(2) {
        return Err("hex has odd length".into());
    }
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let digit = |byte| match byte {
                b'0'..=b'9' => Some(byte - b'0'),
                b'a'..=b'f' => Some(byte - b'a' + 10),
                _ => None,
            };
            let hi = digit(pair[0]).ok_or_else(|| "hex must be lowercase".to_string())?;
            let lo = digit(pair[1]).ok_or_else(|| "hex must be lowercase".to_string())?;
            Ok((hi << 4) | lo)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_manifest_pins_layout_and_root() {
        let hash = "00".repeat(32);
        let text = format!(
            "{HEADER}\nd 755 0 2f62696e\nf 755 1 2f62696e2f78 1 4096 cbf29ce484222325 {hash}\n"
        );
        let parsed = ChunkManifest::parse(text.as_bytes()).expect("manifest");
        assert_eq!(parsed.root(), sha256(text.as_bytes()));
        assert_eq!(parsed.file(b"/bin/x").expect("file").0.size, 1);
        assert!(ChunkManifest::parse(text.trim_end().as_bytes()).is_err());
        assert!(ChunkManifest::parse(format!("{text}\n").as_bytes()).is_err());
        assert!(ChunkManifest::parse(text.replace("d 755", "d 0755").as_bytes()).is_err());
        assert!(ChunkManifest::parse(text.replace("f 755 1", "f 755 +1").as_bytes()).is_err());
        assert!(
            ChunkManifest::parse(text.replace("d 755 0 2f62696e\n", "").as_bytes())
                .unwrap_err()
                .contains("does not name parent directory")
        );
    }
}
