//! In-memory virtual filesystem.
//!
//! The whole tree lives in host memory: files the host preloads (the guest
//! image and its root filesystem) plus everything the guest creates at run
//! time. Directories, regular files, symlinks, and a few character devices
//! are supported. Node indexes are stable for the life of the VFS and double
//! as inode numbers.

use std::collections::BTreeMap;

use crate::{
    abi,
    chunk::{ChunkStore, ChunkedFile, Hash, ReadRange},
};

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
    /// Immutable base-image file. Its logical bytes are named by hashes; only
    /// verified resident chunks occupy host memory.
    ChunkedFile(ChunkedFile),
    Symlink(Vec<u8>),
    CharDev(Dev),
}

impl NodeKind {
    /// Bytes this node's contents occupy, measured the way [`Vfs::bytes`]
    /// sums them. Directory entries and the node record itself are not
    /// counted: a filesystem's size is its data.
    fn data_len(&self) -> usize {
        match self {
            NodeKind::File(data) => data.capacity(),
            NodeKind::ChunkedFile(_) => 0,
            NodeKind::Symlink(target) => target.capacity(),
            NodeKind::Dir(_) | NodeKind::CharDev(_) => 0,
        }
    }
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
            NodeKind::File(_) | NodeKind::ChunkedFile(_) => abi::S_IFREG,
            NodeKind::Symlink(_) => abi::S_IFLNK,
            NodeKind::CharDev(_) => abi::S_IFCHR,
        }
    }

    pub fn d_type(&self) -> u8 {
        match self.kind {
            NodeKind::Dir(_) => abi::DT_DIR,
            NodeKind::File(_) | NodeKind::ChunkedFile(_) => abi::DT_REG,
            NodeKind::Symlink(_) => abi::DT_LNK,
            NodeKind::CharDev(_) => abi::DT_CHR,
        }
    }

    pub fn size(&self) -> u64 {
        match &self.kind {
            NodeKind::File(data) => data.len() as u64,
            NodeKind::ChunkedFile(file) => file.size,
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
    /// Verified immutable chunks shared by every chunk-backed inode.
    chunks: ChunkStore,
    /// Canonical immutable-image identity. Cached chunks are transport state
    /// and need not be embedded in a snapshot for this root to remain valid.
    manifest_root: Option<Hash>,
    /// Ceiling on [`Vfs::bytes`], or None for unbounded. See
    /// [`Vfs::set_storage_budget`].
    storage_budget: Option<usize>,
    /// Nodes whose last directory entry is gone. Their contents are still
    /// readable through any descriptor open at the time, so the bytes are
    /// released by [`Vfs::release_unreferenced`] once the host has
    /// established that nothing points at them any more.
    unlinked: Vec<usize>,
}

impl Vfs {
    pub fn new() -> Self {
        let mut vfs = Self {
            storage_budget: None,
            unlinked: Vec::new(),
            chunks: ChunkStore::default(),
            manifest_root: None,
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

    /// Installs an immutable file layout without making any payload resident.
    pub fn add_chunked_file(
        &mut self,
        path: &[u8],
        file: ChunkedFile,
        mode: u32,
    ) -> Result<usize, u64> {
        self.add_node(path, NodeKind::ChunkedFile(file), mode)
    }

    /// Adds one verified base-image chunk. Identical hashes are stored once.
    pub fn put_chunk(&mut self, expected: Hash, bytes: Vec<u8>) -> Result<(), String> {
        if !self.chunks.contains(&expected) {
            self.reserve(bytes.capacity())
                .map_err(|_| "chunk exceeds the storage budget".to_string())?;
        }
        self.chunks.insert(expected, bytes)
    }

    pub fn has_chunk(&self, hash: &Hash) -> bool {
        self.chunks.contains(hash)
    }

    pub fn chunk_bytes(&self) -> usize {
        self.chunks.bytes()
    }

    pub fn set_manifest_root(&mut self, root: Option<Hash>) {
        self.manifest_root = root;
    }

    pub fn manifest_root(&self) -> Option<Hash> {
        self.manifest_root
    }

    /// Clones namespace topology and immutable descriptors without cloning
    /// resident file or chunk payloads. Manifest installation uses this as a
    /// preflight transaction: every path conflict is discovered before the
    /// live filesystem is changed, even when the live tree holds a very large
    /// resident overlay.
    pub(crate) fn topology_only(&self) -> Self {
        let nodes = self
            .nodes
            .iter()
            .map(|node| Node {
                kind: match &node.kind {
                    NodeKind::Dir(entries) => NodeKind::Dir(entries.clone()),
                    NodeKind::File(_) => NodeKind::File(Vec::new()),
                    NodeKind::ChunkedFile(file) => NodeKind::ChunkedFile(file.clone()),
                    NodeKind::Symlink(target) => NodeKind::Symlink(target.clone()),
                    NodeKind::CharDev(dev) => NodeKind::CharDev(*dev),
                },
                mode: node.mode,
                nlink: node.nlink,
                mtime_sec: node.mtime_sec,
                parent: node.parent,
            })
            .collect();
        Self {
            nodes,
            chunks: ChunkStore::default(),
            manifest_root: self.manifest_root,
            storage_budget: None,
            unlinked: self.unlinked.clone(),
        }
    }

    pub(crate) fn read_chunked_range(
        &self,
        file: &ChunkedFile,
        offset: u64,
        len: usize,
    ) -> ReadRange {
        self.chunks.read_range(file, offset, len)
    }

    /// First authority needed before a legacy whole-file mutation can be
    /// applied. Callers request it and retry until materialization is ready.
    pub fn first_missing_file_chunk(&self, node: usize) -> Result<Option<Hash>, u64> {
        match &self.nodes.get(node).ok_or(abi::ENOENT)?.kind {
            NodeKind::File(_) => Ok(None),
            NodeKind::ChunkedFile(file) => Ok(self.chunks.first_missing(file)),
            NodeKind::Dir(_) => Err(abi::EISDIR),
            _ => Err(abi::EINVAL),
        }
    }

    /// Reads a regular-file range without silently materializing a chunked
    /// file. The first absent hash is returned to the page-in boundary.
    pub fn read_node_range(&self, node: usize, offset: u64, len: usize) -> Result<ReadRange, u64> {
        match &self.nodes.get(node).ok_or(abi::ENOENT)?.kind {
            NodeKind::File(data) => {
                let start = usize::try_from(offset)
                    .unwrap_or(usize::MAX)
                    .min(data.len());
                let end = start.saturating_add(len).min(data.len());
                Ok(ReadRange::Ready(data[start..end].to_vec()))
            }
            NodeKind::ChunkedFile(file) => Ok(self.chunks.read_range(file, offset, len)),
            NodeKind::Dir(_) => Err(abi::EISDIR),
            _ => Err(abi::EINVAL),
        }
    }

    /// Materializes a chunked inode only for legacy mutation/whole-file APIs.
    /// Missing authority is an error, never an eager transport fallback.
    pub fn materialize_file(&mut self, node: usize) -> Result<&mut Vec<u8>, u64> {
        let bytes = match &self.nodes.get(node).ok_or(abi::ENOENT)?.kind {
            NodeKind::File(_) => None,
            NodeKind::ChunkedFile(file) => match self.chunks.read_range(file, 0, usize::MAX) {
                ReadRange::Ready(bytes) => Some(bytes),
                ReadRange::Missing(_) => return Err(abi::EIO),
                ReadRange::Invalid(_) => return Err(abi::EIO),
            },
            NodeKind::Dir(_) => return Err(abi::EISDIR),
            _ => return Err(abi::EINVAL),
        };
        if let Some(bytes) = bytes {
            self.reserve(bytes.capacity())?;
            self.nodes[node].kind = NodeKind::File(bytes);
        }
        match &mut self.nodes[node].kind {
            NodeKind::File(data) => Ok(data),
            _ => unreachable!("regular file was materialized"),
        }
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
        // Linux: an empty pathname yields ENOENT (path resolution never treats
        // it as the base directory; AT_EMPTY_PATH callers branch before this).
        // Without the check, a corrupted or unfilled path string silently
        // resolves to the working directory and masks the corruption.
        if path.is_empty() {
            return Err(crate::abi::ENOENT);
        }
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
        if !matches!(kind, NodeKind::Dir(_)) && self.occupied_by_a_directory(path) {
            return Err(abi::EISDIR);
        }
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
        // Replacing a name drops the link the old node had under it. Without
        // this the old node stays in the arena, unreachable by path but not
        // gone: its bytes survive in memory, in the storage accounting, and
        // in every snapshot taken afterwards — so a file rewritten shorter
        // kept the tail of what it used to say, and a config rewritten
        // without a secret kept the secret.
        //
        // The link count is what decides, not the overwrite: a name is a
        // link, and the contents outlive the last one only for as long as a
        // descriptor opened before it still refers to them.
        if let Some(displaced) = entries.insert(resolved.name, node) {
            let old = &mut self.nodes[displaced];
            old.nlink = old.nlink.saturating_sub(1);
            if old.nlink == 0 && !self.unlinked.contains(&displaced) {
                self.unlinked.push(displaced);
            }
        }
        Ok(node)
    }

    /// Whether `path` already names a directory, which nothing may replace.
    ///
    /// Replacing a file is how a host restarts an interrupted delivery, so
    /// that stays allowed. Replacing a directory is not the same act: it
    /// discards everything underneath, and a host that aims an image at a
    /// path that turns out to be a directory — a mistake, or a path out of a
    /// manifest — would take the tree with it. The kernel answers `EISDIR`
    /// here and so does this.
    fn occupied_by_a_directory(&self, path: &[u8]) -> bool {
        self.resolve(ROOT, path, false)
            .ok()
            .and_then(|resolved| resolved.node)
            .is_some_and(|node| self.is_dir(node))
    }

    /// Creates an empty file at `path` with room reserved for `capacity`
    /// bytes, so a large image delivered in pieces does not repeatedly
    /// reallocate and briefly hold two copies of itself.
    pub fn create_file_with_capacity(
        &mut self,
        path: &[u8],
        capacity: usize,
        mode: u32,
    ) -> Result<usize, u64> {
        let mut data = Vec::new();
        data.try_reserve_exact(capacity).map_err(|_| abi::ENOMEM)?;
        self.add_node(path, NodeKind::File(data), mode)
    }

    /// Appends to the regular file at `path`. Paired with
    /// [`create_file_with_capacity`] this is how a host streams an image in
    /// without ever holding the whole thing twice.
    pub fn append_file(&mut self, path: &[u8], bytes: &[u8]) -> Result<(), u64> {
        let resolved = self.resolve(ROOT, path, true)?;
        let node = resolved.node.ok_or(abi::ENOENT)?;
        match &mut self.nodes[node].kind {
            NodeKind::File(data) => {
                data.try_reserve(bytes.len()).map_err(|_| abi::ENOMEM)?;
                data.extend_from_slice(bytes);
                Ok(())
            }
            _ => Err(abi::EISDIR),
        }
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
        // Charged before the node exists: a symlink whose target does not fit
        // must leave the tree exactly as it was.
        self.reserve(kind.data_len())?;
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
        // A name is a link. Losing the last one makes the file unreachable by
        // path but not yet dead: POSIX keeps the contents readable through a
        // descriptor opened before the unlink, which is how every "delete the
        // file and keep writing to it" idiom works.
        let node_ref = &mut self.nodes[node];
        node_ref.nlink = node_ref.nlink.saturating_sub(1);
        if node_ref.nlink == 0 && !self.unlinked.contains(&node) {
            self.unlinked.push(node);
        }
        Ok(())
    }

    /// Whether anything is waiting to be reclaimed, so the caller can skip
    /// walking every descriptor table in the common case.
    pub fn has_unlinked(&self) -> bool {
        !self.unlinked.is_empty()
    }

    /// Frees the contents of unlinked nodes that `referenced` does not name,
    /// returning the bytes released.
    ///
    /// The caller supplies the set because the filesystem cannot see
    /// descriptors: they live in process tables, and a node stays alive while
    /// any of them still points at it.
    ///
    /// The node itself is kept. Indices are how descriptors and directory
    /// entries name nodes, so removing one would renumber the rest; what is
    /// reclaimed is the data, which is all of it that has a size.
    pub fn release_unreferenced(&mut self, referenced: &std::collections::HashSet<usize>) -> usize {
        let mut freed = 0;
        let mut still_open = Vec::new();
        for node in std::mem::take(&mut self.unlinked) {
            if referenced.contains(&node) {
                still_open.push(node);
                continue;
            }
            if let Some(entry) = self.nodes.get_mut(node) {
                freed += entry.kind.data_len();
                entry.kind = NodeKind::File(Vec::new());
            }
        }
        self.unlinked = still_open;
        freed
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
        // Renaming onto an existing name replaces it, and the file that was
        // there loses its last link. This is the "write a temp file and move
        // it into place" idiom — the one an agent uses to edit a file — so
        // the replaced contents are exactly the previous version of something
        // someone cared about. Leaving the node behind keeps that version in
        // the arena and in every snapshot after it.
        if let Some(displaced) = entries.insert(new_name.to_vec(), node) {
            if displaced != node {
                let old = &mut self.nodes[displaced];
                old.nlink = old.nlink.saturating_sub(1);
                if old.nlink == 0 && !self.unlinked.contains(&displaced) {
                    self.unlinked.push(displaced);
                }
            }
        }
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

fn rewrite_bytes(data: &mut Vec<u8>, subs: &[(String, String)]) {
    let replacement = {
        let Ok(text) = std::str::from_utf8(data) else {
            return;
        };
        let mut out = text.to_string();
        let mut changed = false;
        for (from, to) in subs {
            if out.contains(from.as_str()) {
                out = out.replace(from.as_str(), to);
                changed = true;
            }
        }
        changed.then(|| out.into_bytes())
    };
    if let Some(replacement) = replacement {
        *data = replacement;
    }
}

impl Default for Vfs {
    fn default() -> Self {
        Self::new()
    }
}

// ── Whole-filesystem snapshots (browser reload persistence) ─────────────────

const SNAPSHOT_MAGIC: &[u8; 4] = b"WTFS";
const SNAPSHOT_VERSION: u32 = 3;

impl Vfs {
    /// Applies literal substitutions to every regular file's contents.
    /// Used for secret injection (`${name}` -> value) and its inverse
    /// (redaction before serialization).
    /// Bytes held in file contents and symlink targets. Directory entries and
    /// node records are not counted: a filesystem's size is its data, and
    /// that is the term an image moves.
    pub fn bytes(&self) -> usize {
        self.nodes
            .iter()
            .map(|node| node.kind.data_len())
            .sum::<usize>()
            .saturating_add(self.chunks.bytes())
    }

    /// Sets a ceiling on [`Vfs::bytes`], or clears it with None.
    ///
    /// This is the guest's disk, not the host's: the paths a guest can reach
    /// — creating a node, writing past the end of a file, extending one with
    /// `ftruncate` — are refused with `ENOSPC` once the tree is at the
    /// ceiling, which is what a real kernel returns for a full filesystem.
    /// The host's own preload paths ([`Vfs::add_node`],
    /// [`Vfs::create_file_with_capacity`], [`Vfs::append_file`]) are not
    /// refused, because what the host puts in is the host's decision and is
    /// already governed by the machine's memory budget — but the bytes they
    /// add do count against the ceiling, exactly as an image occupies space
    /// on a real disk. Size the budget above the image accordingly.
    ///
    /// What this bounds is total allocation over the machine's life, not
    /// live data. [`Vfs::unlink`] detaches a node from its directory but does
    /// not release its contents — node indexes are stable for the life of the
    /// VFS, and nothing yet decides when an unlinked file is past the last
    /// descriptor that could still read it — so deleting a file does not
    /// return its bytes to the budget. A guest that churns temporary files
    /// therefore approaches the ceiling even though nothing it can see is
    /// growing. The error is on the safe side (the budget refuses earlier
    /// than a real disk would, never later), but it means this is not yet a
    /// ceiling a long-running workload can live under.
    pub fn set_storage_budget(&mut self, bytes: Option<usize>) {
        self.storage_budget = bytes;
    }

    /// The ceiling on [`Vfs::bytes`], when one is set.
    pub fn storage_budget(&self) -> Option<usize> {
        self.storage_budget
    }

    /// Bytes the guest may still add, or None when no budget is set.
    pub fn storage_headroom(&self) -> Option<usize> {
        self.storage_budget
            .map(|budget| budget.saturating_sub(self.bytes()))
    }

    /// Refuses `growth` bytes with `ENOSPC` when they would not fit.
    ///
    /// Costs nothing when no budget is set. When one is, it re-sums the tree
    /// — one `usize` read per node, not per byte — which is the same
    /// recompute-on-demand shape the memory budget uses.
    ///
    /// What is charged is allocation, not written length: `growth` is the
    /// bytes being written, but the running total is capacity, the measure
    /// [`Vfs::bytes`] reports and the one the memory footprint uses. A file
    /// grown a chunk at a time doubles its buffer, so it can hold up to twice
    /// what has been written to it, and the guest reaches the ceiling with a
    /// smaller file than the number suggests. That is the truth about what
    /// the tab is holding — the same way a real filesystem charges whole
    /// blocks for a partly used one.
    ///
    /// Adding nothing always fits, whatever the total already is: an empty
    /// file and a directory cost the filesystem no bytes, so a full one is
    /// no reason to refuse them.
    pub fn reserve(&self, growth: usize) -> Result<(), u64> {
        if growth == 0 {
            return Ok(());
        }
        let Some(budget) = self.storage_budget else {
            return Ok(());
        };
        if self.bytes().saturating_add(growth) <= budget {
            return Ok(());
        }
        Err(abi::ENOSPC)
    }

    /// A file's contents, or None when the path is not a file.
    pub fn read_file(&self, path: &[u8]) -> Option<&[u8]> {
        let node = self.resolve(ROOT, path, true).ok()?.node?;
        match &self.nodes.get(node)?.kind {
            NodeKind::File(data) => Some(data),
            _ => None,
        }
    }

    /// Moves a file's contents out of the tree, returning them, or None when
    /// the path is not a file. Used to keep host-supplied images out of a
    /// snapshot: the bytes are moved, not copied, and moved back afterwards.
    pub fn take_file_contents(&mut self, path: &[u8]) -> Option<Vec<u8>> {
        let node = self.resolve(ROOT, path, true).ok()?.node?;
        match &mut self.nodes.get_mut(node)?.kind {
            NodeKind::File(data) => Some(std::mem::take(data)),
            _ => None,
        }
    }

    /// Puts contents taken by [`Vfs::take_file_contents`] back.
    pub fn put_file_contents(&mut self, path: &[u8], data: Vec<u8>) {
        let Ok(resolved) = self.resolve(ROOT, path, true) else {
            return;
        };
        let Some(node) = resolved.node.and_then(|n| self.nodes.get_mut(n)) else {
            return;
        };
        if let NodeKind::File(existing) = &mut node.kind {
            *existing = data;
        }
    }

    /// Applies substitutions to one file. Used to give a secret a scope:
    /// the value is written where the host says it belongs and nowhere else.
    pub fn rewrite_file(&mut self, path: &[u8], subs: &[(String, String)]) -> Result<(), u64> {
        let resolved = self.resolve(ROOT, path, true)?;
        let node = resolved.node.ok_or(abi::ENOENT)?;
        let data = self.materialize_file(node)?;
        rewrite_bytes(data, subs);
        Ok(())
    }

    pub fn rewrite_files(&mut self, subs: &[(String, String)]) -> Result<(), u64> {
        if subs.is_empty() {
            return Ok(());
        }
        let files: Vec<usize> = self
            .nodes
            .iter()
            .enumerate()
            .filter_map(|(index, node)| {
                matches!(node.kind, NodeKind::File(_) | NodeKind::ChunkedFile(_)).then_some(index)
            })
            .collect();
        for node in files {
            rewrite_bytes(self.materialize_file(node)?, subs);
        }
        Ok(())
    }

    /// Rewrites only files that are already mutable overlays. Immutable
    /// chunk descriptors cannot contain an injected secret: expanding one
    /// first promotes it to `File`, so snapshot redaction never needs to page
    /// untouched base files in.
    pub fn rewrite_resident_files(&mut self, subs: &[(String, String)]) {
        for node in &mut self.nodes {
            if let NodeKind::File(data) = &mut node.kind {
                rewrite_bytes(data, subs);
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
        match self.manifest_root {
            Some(root) => {
                out.push(1);
                out.extend_from_slice(&root);
            }
            None => out.push(0),
        }
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
                NodeKind::ChunkedFile(file) => {
                    // Base chunks are deliberately not serialized per session.
                    // Their hashes are the authority and the host cache can
                    // supply them again after restore.
                    out.push(5);
                    out.extend_from_slice(&file.size.to_le_bytes());
                    out.extend_from_slice(&file.chunk_size.to_le_bytes());
                    out.extend_from_slice(&(file.chunks.len() as u64).to_le_bytes());
                    for hash in &file.chunks {
                        out.extend_from_slice(hash);
                    }
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
        let version = r.u32()?;
        if !(1..=SNAPSHOT_VERSION).contains(&version) {
            return Err("unsupported filesystem image version".into());
        }
        let manifest_root = if version >= 3 {
            match r.u8()? {
                0 => None,
                1 => Some(r.take(32)?.try_into().expect("manifest root width")),
                _ => return Err("invalid snapshot manifest-root tag".into()),
            }
        } else {
            None
        };
        let count = r.u32()? as usize;
        if count == 0 || count > 4_000_000 {
            return Err("implausible filesystem image".into());
        }
        // The smallest a node can be on the wire: parent, mode, nlink, mtime,
        // and a kind tag. Reserving for a count the remaining bytes could not
        // possibly hold turns a dozen bytes out of browser storage into a
        // large allocation, so the claim is checked before it is believed.
        const MIN_NODE_BYTES: usize = 8 + 4 + 8 + 8 + 1;
        if count.saturating_mul(MIN_NODE_BYTES) > r.0.len() {
            return Err(format!(
                "implausible filesystem image: {count} nodes claimed, {} bytes to hold them",
                r.0.len()
            ));
        }
        let mut nodes = Vec::with_capacity(count);
        // `as usize` would truncate these on a 32-bit host, and the browser is
        // one: a length of 2^32 + 1 would read as 1, and an out-of-range
        // parent index would wrap into a valid-looking one. Refuse instead.
        fn index(value: u64) -> Result<usize, String> {
            usize::try_from(value).map_err(|_| "filesystem image too large for this host".into())
        }
        for _ in 0..count {
            let parent = index(r.u64()?)?;
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
                        let child = index(r.u64()?)?;
                        if child >= count {
                            return Err("corrupt filesystem image: bad child index".into());
                        }
                        map.insert(name, child);
                    }
                    NodeKind::Dir(map)
                }
                2 => {
                    let len = index(r.u64()?)?;
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
                5 if version >= 2 => {
                    let size = r.u64()?;
                    let chunk_size = r.u32()?;
                    let count = index(r.u64()?)?;
                    let hashes_len = count
                        .checked_mul(32)
                        .ok_or_else(|| "chunk hash table too large".to_string())?;
                    let hashes = r.take(hashes_len)?;
                    let chunks = hashes.as_chunks::<32>().0.to_vec();
                    NodeKind::ChunkedFile(ChunkedFile::new(size, chunk_size, chunks)?)
                }
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
        if !r.0.is_empty() {
            return Err("filesystem image has trailing bytes".into());
        }
        if manifest_root.is_none()
            && nodes
                .iter()
                .any(|node| matches!(node.kind, NodeKind::ChunkedFile(_)))
        {
            return Err("chunked snapshot has no manifest root".into());
        }
        Ok(Self {
            nodes,
            chunks: ChunkStore::default(),
            manifest_root,
            storage_budget: None,
            unlinked: Vec::new(),
        })
    }
}
