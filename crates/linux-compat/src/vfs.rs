//! In-memory virtual filesystem.
//!
//! The whole tree lives in host memory: files the host preloads (the guest
//! image and its root filesystem) plus everything the guest creates at run
//! time. Directories, regular files, symlinks, and a few character devices
//! are supported. Node indexes are stable for the life of the VFS and double
//! as inode numbers.

use std::collections::BTreeMap;

use crate::abi;

pub const ROOT: usize = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dev {
    Null,
    Zero,
    Tty,
    Random,
    /// `/dev/ptmx`: opening it allocates a new pseudoterminal master.
    Ptmx,
}

#[derive(Debug, Clone)]
pub enum NodeKind {
    Dir(BTreeMap<Vec<u8>, usize>),
    File(Vec<u8>),
    Symlink(Vec<u8>),
    CharDev(Dev),
}

#[derive(Debug, Clone)]
pub struct Node {
    pub kind: NodeKind,
    pub mode: u32,
    pub nlink: u64,
    pub mtime_sec: i64,
    /// Parent directory (ROOT's parent is ROOT). Kept current on rename.
    pub parent: usize,
}

impl Node {
    pub fn file_type_bits(&self) -> u32 {
        match self.kind {
            NodeKind::Dir(_) => abi::S_IFDIR,
            NodeKind::File(_) => abi::S_IFREG,
            NodeKind::Symlink(_) => abi::S_IFLNK,
            NodeKind::CharDev(_) => abi::S_IFCHR,
        }
    }

    pub fn d_type(&self) -> u8 {
        match self.kind {
            NodeKind::Dir(_) => abi::DT_DIR,
            NodeKind::File(_) => abi::DT_REG,
            NodeKind::Symlink(_) => abi::DT_LNK,
            NodeKind::CharDev(_) => abi::DT_CHR,
        }
    }

    pub fn size(&self) -> u64 {
        match &self.kind {
            NodeKind::File(data) => data.len() as u64,
            NodeKind::Symlink(target) => target.len() as u64,
            NodeKind::Dir(entries) => entries.len() as u64,
            NodeKind::CharDev(_) => 0,
        }
    }
}

/// A resolved path: the parent directory node, the final component name, and
/// the target node if it exists.
pub struct Resolved {
    pub parent: usize,
    pub name: Vec<u8>,
    pub node: Option<usize>,
}

pub struct Vfs {
    pub(crate) nodes: Vec<Node>,
}

impl Vfs {
    pub fn new() -> Self {
        let mut vfs = Self {
            nodes: vec![Node {
                kind: NodeKind::Dir(BTreeMap::new()),
                mode: 0o755,
                nlink: 2,
                mtime_sec: 0,
                parent: ROOT,
            }],
        };
        // Standard skeleton every Linux userland expects.
        for dir in [
            "/bin", "/dev", "/dev/pts", "/etc", "/home", "/tmp", "/usr", "/usr/bin", "/var",
        ] {
            let _ = vfs.mkdir_p(dir.as_bytes());
        }
        for (path, dev) in [
            ("/dev/null", Dev::Null),
            ("/dev/zero", Dev::Zero),
            ("/dev/tty", Dev::Tty),
            ("/dev/urandom", Dev::Random),
            ("/dev/ptmx", Dev::Ptmx),
        ] {
            let _ = vfs.add_node(path.as_bytes(), NodeKind::CharDev(dev), 0o666);
        }
        vfs
    }

    pub fn node(&self, index: usize) -> &Node {
        &self.nodes[index]
    }

    pub fn node_mut(&mut self, index: usize) -> &mut Node {
        &mut self.nodes[index]
    }

    pub fn is_dir(&self, index: usize) -> bool {
        matches!(self.nodes[index].kind, NodeKind::Dir(_))
    }

    fn alloc(&mut self, node: Node) -> usize {
        self.nodes.push(node);
        self.nodes.len() - 1
    }

    /// Splits a path into components; `.` and empty segments are dropped,
    /// `..` is preserved for the walker.
    fn components(path: &[u8]) -> Vec<&[u8]> {
        path.split(|&b| b == b'/')
            .filter(|c| !c.is_empty() && *c != b".")
            .collect()
    }

    /// Walks `path` starting from `start` (ignored when the path is
    /// absolute). Follows symlinks in intermediate components, and in the
    /// final component when `follow_last` is set.
    pub fn resolve(&self, start: usize, path: &[u8], follow_last: bool) -> Result<Resolved, u64> {
        self.resolve_depth(start, path, follow_last, 0)
    }

    fn resolve_depth(
        &self,
        start: usize,
        path: &[u8],
        follow_last: bool,
        depth: u32,
    ) -> Result<Resolved, u64> {
        if depth > 8 {
            return Err(abi::ELOOP);
        }
        let mut current = if path.first() == Some(&b'/') {
            ROOT
        } else {
            start
        };
        let components = Self::components(path);

        if components.is_empty() {
            // "/" or "." — the node itself.
            return Ok(Resolved {
                parent: self.nodes[current].parent,
                name: b".".to_vec(),
                node: Some(current),
            });
        }

        for (i, component) in components.iter().enumerate() {
            let is_last = i + 1 == components.len();
            if *component == b".." {
                current = self.nodes[current].parent;
                if is_last {
                    return Ok(Resolved {
                        parent: self.nodes[current].parent,
                        name: b".".to_vec(),
                        node: Some(current),
                    });
                }
                continue;
            }

            let NodeKind::Dir(entries) = &self.nodes[current].kind else {
                return Err(abi::ENOTDIR);
            };
            let next = entries.get(*component).copied();

            if is_last {
                if follow_last {
                    if let Some(next_node) = next {
                        if let NodeKind::Symlink(target) = &self.nodes[next_node].kind {
                            let target = target.clone();
                            return self.resolve_depth(current, &target, true, depth + 1);
                        }
                    }
                }
                return Ok(Resolved {
                    parent: current,
                    name: component.to_vec(),
                    node: next,
                });
            }

            let Some(next) = next else {
                return Err(abi::ENOENT);
            };
            match &self.nodes[next].kind {
                NodeKind::Symlink(target) => {
                    let target = target.clone();
                    let resolved = self.resolve_depth(current, &target, true, depth + 1)?;
                    let Some(node) = resolved.node else {
                        return Err(abi::ENOENT);
                    };
                    if !self.is_dir(node) {
                        return Err(abi::ENOTDIR);
                    }
                    current = node;
                }
                NodeKind::Dir(_) => current = next,
                _ => return Err(abi::ENOTDIR),
            }
        }
        unreachable!("loop always returns on the last component");
    }

    /// Creates or replaces the node at `path`, creating parent directories.
    /// Host-side setup helper; guest-driven creation goes through `create`.
    pub fn add_node(&mut self, path: &[u8], kind: NodeKind, mode: u32) -> Result<usize, u64> {
        let parent_path_len = path.iter().rposition(|&b| b == b'/').unwrap_or(0);
        self.mkdir_p(&path[..parent_path_len])?;
        let resolved = self.resolve(ROOT, path, false)?;
        let nlink = if matches!(kind, NodeKind::Dir(_)) {
            2
        } else {
            1
        };
        let node = self.alloc(Node {
            kind,
            mode,
            nlink,
            mtime_sec: 0,
            parent: resolved.parent,
        });
        let NodeKind::Dir(entries) = &mut self.nodes[resolved.parent].kind else {
            return Err(abi::ENOTDIR);
        };
        entries.insert(resolved.name, node);
        Ok(node)
    }

    /// Creates the directory chain for `path` and returns its node.
    pub fn mkdir_p(&mut self, path: &[u8]) -> Result<usize, u64> {
        let mut current = ROOT;
        for component in Self::components(path) {
            if component == b".." {
                current = self.nodes[current].parent;
                continue;
            }
            let NodeKind::Dir(entries) = &self.nodes[current].kind else {
                return Err(abi::ENOTDIR);
            };
            if let Some(&next) = entries.get(component) {
                if !self.is_dir(next) {
                    return Err(abi::ENOTDIR);
                }
                current = next;
                continue;
            }
            let node = self.alloc(Node {
                kind: NodeKind::Dir(BTreeMap::new()),
                mode: 0o755,
                nlink: 2,
                mtime_sec: 0,
                parent: current,
            });
            let NodeKind::Dir(entries) = &mut self.nodes[current].kind else {
                return Err(abi::ENOTDIR);
            };
            entries.insert(component.to_vec(), node);
            current = node;
        }
        Ok(current)
    }

    /// Creates a new node under an already-resolved parent.
    pub fn create(
        &mut self,
        parent: usize,
        name: &[u8],
        kind: NodeKind,
        mode: u32,
    ) -> Result<usize, u64> {
        if name.is_empty() || name == b"." || name == b".." {
            return Err(abi::EEXIST);
        }
        let nlink = if matches!(kind, NodeKind::Dir(_)) {
            2
        } else {
            1
        };
        let node = self.alloc(Node {
            kind,
            mode,
            nlink,
            mtime_sec: 0,
            parent,
        });
        let NodeKind::Dir(entries) = &mut self.nodes[parent].kind else {
            return Err(abi::ENOTDIR);
        };
        if entries.contains_key(name) {
            return Err(abi::EEXIST);
        }
        entries.insert(name.to_vec(), node);
        Ok(node)
    }

    /// Adds a hard link: `parent/name` refers to the existing `node`.
    pub fn link(&mut self, parent: usize, name: &[u8], node: usize) -> Result<(), u64> {
        let NodeKind::Dir(entries) = &mut self.nodes[parent].kind else {
            return Err(abi::ENOTDIR);
        };
        if entries.contains_key(name) {
            return Err(abi::EEXIST);
        }
        entries.insert(name.to_vec(), node);
        self.nodes[node].nlink += 1;
        Ok(())
    }

    /// Removes the entry `name` from `parent`. `rmdir` selects directory
    /// semantics (must be empty) versus file semantics.
    pub fn unlink(&mut self, parent: usize, name: &[u8], rmdir: bool) -> Result<(), u64> {
        let NodeKind::Dir(entries) = &self.nodes[parent].kind else {
            return Err(abi::ENOTDIR);
        };
        let Some(&node) = entries.get(name) else {
            return Err(abi::ENOENT);
        };
        match &self.nodes[node].kind {
            NodeKind::Dir(children) => {
                if !rmdir {
                    return Err(abi::EISDIR);
                }
                if !children.is_empty() {
                    return Err(abi::ENOTEMPTY);
                }
            }
            _ if rmdir => return Err(abi::ENOTDIR),
            _ => {}
        }
        let NodeKind::Dir(entries) = &mut self.nodes[parent].kind else {
            return Err(abi::ENOTDIR);
        };
        entries.remove(name);
        Ok(())
    }

    /// Moves `old_parent/old_name` to `new_parent/new_name`, replacing an
    /// existing target file.
    pub fn rename(
        &mut self,
        old_parent: usize,
        old_name: &[u8],
        new_parent: usize,
        new_name: &[u8],
    ) -> Result<(), u64> {
        let NodeKind::Dir(entries) = &self.nodes[old_parent].kind else {
            return Err(abi::ENOTDIR);
        };
        let Some(&node) = entries.get(old_name) else {
            return Err(abi::ENOENT);
        };

        // Replacing a non-empty directory is not allowed.
        let NodeKind::Dir(new_entries) = &self.nodes[new_parent].kind else {
            return Err(abi::ENOTDIR);
        };
        if let Some(&existing) = new_entries.get(new_name) {
            if let NodeKind::Dir(children) = &self.nodes[existing].kind {
                if !children.is_empty() {
                    return Err(abi::ENOTEMPTY);
                }
            }
        }

        let NodeKind::Dir(entries) = &mut self.nodes[old_parent].kind else {
            return Err(abi::ENOTDIR);
        };
        entries.remove(old_name);
        let NodeKind::Dir(entries) = &mut self.nodes[new_parent].kind else {
            return Err(abi::ENOTDIR);
        };
        entries.insert(new_name.to_vec(), node);
        self.nodes[node].parent = new_parent;
        Ok(())
    }

    /// Directory listing including the synthetic `.` and `..` entries, in a
    /// stable order for deterministic `getdents64`.
    pub fn list(&self, dir: usize) -> Result<Vec<(Vec<u8>, usize)>, u64> {
        let NodeKind::Dir(entries) = &self.nodes[dir].kind else {
            return Err(abi::ENOTDIR);
        };
        let mut out = vec![
            (b".".to_vec(), dir),
            (b"..".to_vec(), self.nodes[dir].parent),
        ];
        out.extend(entries.iter().map(|(name, &node)| (name.clone(), node)));
        Ok(out)
    }

    /// Reconstructs an absolute path for `node` by climbing parent links.
    pub fn abs_path_of(&self, node: usize) -> Vec<u8> {
        if node == ROOT {
            return b"/".to_vec();
        }
        let mut segments: Vec<Vec<u8>> = Vec::new();
        let mut current = node;
        while current != ROOT && segments.len() < 256 {
            let parent = self.nodes[current].parent;
            if let NodeKind::Dir(entries) = &self.nodes[parent].kind {
                if let Some((name, _)) = entries.iter().find(|(_, &n)| n == current) {
                    segments.push(name.clone());
                }
            }
            current = parent;
        }
        let mut path = Vec::new();
        for segment in segments.iter().rev() {
            path.push(b'/');
            path.extend_from_slice(segment);
        }
        if path.is_empty() {
            path.push(b'/');
        }
        path
    }
}

impl Default for Vfs {
    fn default() -> Self {
        Self::new()
    }
}

// ── Whole-filesystem snapshots (browser reload persistence) ─────────────────

const SNAPSHOT_MAGIC: &[u8; 4] = b"WTFS";
const SNAPSHOT_VERSION: u32 = 1;

impl Vfs {
    /// Applies literal substitutions to every regular file's contents.
    /// Used for secret injection (`${name}` -> value) and its inverse
    /// (redaction before serialization).
    pub fn rewrite_files(&mut self, subs: &[(String, String)]) {
        if subs.is_empty() {
            return;
        }
        for node in &mut self.nodes {
            if let NodeKind::File(data) = &mut node.kind {
                let Ok(text) = std::str::from_utf8(data) else {
                    continue; // never touch binary files
                };
                let mut replaced = text.to_string();
                let mut changed = false;
                for (from, to) in subs {
                    if replaced.contains(from.as_str()) {
                        replaced = replaced.replace(from.as_str(), to);
                        changed = true;
                    }
                }
                if changed {
                    *data = replaced.into_bytes();
                }
            }
        }
    }

    /// Serializes the whole tree to a stable binary image (node indexes are
    /// preserved, so open guest state must not be carried across a
    /// restore — snapshots are taken between guest processes).
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4096);
        out.extend_from_slice(SNAPSHOT_MAGIC);
        out.extend_from_slice(&SNAPSHOT_VERSION.to_le_bytes());
        out.extend_from_slice(&(self.nodes.len() as u32).to_le_bytes());
        for node in &self.nodes {
            out.extend_from_slice(&(node.parent as u64).to_le_bytes());
            out.extend_from_slice(&node.mode.to_le_bytes());
            out.extend_from_slice(&node.nlink.to_le_bytes());
            out.extend_from_slice(&node.mtime_sec.to_le_bytes());
            match &node.kind {
                NodeKind::Dir(entries) => {
                    out.push(1);
                    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
                    for (name, &child) in entries {
                        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
                        out.extend_from_slice(name);
                        out.extend_from_slice(&(child as u64).to_le_bytes());
                    }
                }
                NodeKind::File(data) => {
                    out.push(2);
                    out.extend_from_slice(&(data.len() as u64).to_le_bytes());
                    out.extend_from_slice(data);
                }
                NodeKind::Symlink(target) => {
                    out.push(3);
                    out.extend_from_slice(&(target.len() as u16).to_le_bytes());
                    out.extend_from_slice(target);
                }
                NodeKind::CharDev(dev) => {
                    out.push(4);
                    out.push(match dev {
                        Dev::Null => 0,
                        Dev::Zero => 1,
                        Dev::Tty => 2,
                        Dev::Random => 3,
                        Dev::Ptmx => 5,
                    });
                }
            }
        }
        out
    }

    /// Restores a tree serialized by [`Vfs::serialize`].
    pub fn deserialize(bytes: &[u8]) -> Result<Self, String> {
        struct Reader<'a>(&'a [u8]);
        impl<'a> Reader<'a> {
            fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
                if self.0.len() < n {
                    return Err("truncated filesystem image".into());
                }
                let (head, rest) = self.0.split_at(n);
                self.0 = rest;
                Ok(head)
            }
            fn u8(&mut self) -> Result<u8, String> {
                Ok(self.take(1)?[0])
            }
            fn u16(&mut self) -> Result<u16, String> {
                Ok(u16::from_le_bytes(self.take(2)?.try_into().expect("size")))
            }
            fn u32(&mut self) -> Result<u32, String> {
                Ok(u32::from_le_bytes(self.take(4)?.try_into().expect("size")))
            }
            fn u64(&mut self) -> Result<u64, String> {
                Ok(u64::from_le_bytes(self.take(8)?.try_into().expect("size")))
            }
        }

        let mut r = Reader(bytes);
        if r.take(4)? != SNAPSHOT_MAGIC {
            return Err("not a filesystem image".into());
        }
        if r.u32()? != SNAPSHOT_VERSION {
            return Err("unsupported filesystem image version".into());
        }
        let count = r.u32()? as usize;
        if count == 0 || count > 4_000_000 {
            return Err("implausible filesystem image".into());
        }
        let mut nodes = Vec::with_capacity(count);
        for _ in 0..count {
            let parent = r.u64()? as usize;
            let mode = r.u32()?;
            let nlink = r.u64()?;
            let mtime_sec = i64::from_le_bytes(r.take(8)?.try_into().expect("size"));
            let kind = match r.u8()? {
                1 => {
                    let entries = r.u32()? as usize;
                    let mut map = BTreeMap::new();
                    for _ in 0..entries {
                        let len = r.u16()? as usize;
                        let name = r.take(len)?.to_vec();
                        let child = r.u64()? as usize;
                        if child >= count {
                            return Err("corrupt filesystem image: bad child index".into());
                        }
                        map.insert(name, child);
                    }
                    NodeKind::Dir(map)
                }
                2 => {
                    let len = r.u64()? as usize;
                    NodeKind::File(r.take(len)?.to_vec())
                }
                3 => {
                    let len = r.u16()? as usize;
                    NodeKind::Symlink(r.take(len)?.to_vec())
                }
                4 => NodeKind::CharDev(match r.u8()? {
                    0 => Dev::Null,
                    1 => Dev::Zero,
                    2 => Dev::Tty,
                    3 => Dev::Random,
                    5 => Dev::Ptmx,
                    other => return Err(format!("unknown device tag {other}")),
                }),
                other => return Err(format!("unknown node tag {other}")),
            };
            if parent >= count {
                return Err("corrupt filesystem image: bad parent index".into());
            }
            nodes.push(Node {
                kind,
                mode,
                nlink,
                mtime_sec,
                parent,
            });
        }
        Ok(Self { nodes })
    }
}
