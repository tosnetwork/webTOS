//! File-system related Linux syscall implementations.
//!
//! Translates Linux file I/O syscalls into ATOS keyspace state operations.
//! Files are backed by the agent's private keyspace; pipes and sockets map
//! to ATOS mailbox IPC.

extern crate alloc;

use super::constants::*;
use super::state::{self, FdEntry, FdKind, MAX_FDS, MAX_PATH};
use sha2::{Digest, Sha256};

// ── Seek whence values ─────────────────────────────────────────────────────

const SEEK_SET: u32 = 0;
const SEEK_CUR: u32 = 1;
const SEEK_END: u32 = 2;

// ── fcntl commands ─────────────────────────────────────────────────────────

const F_DUPFD: u32 = 0;
const F_GETFD: u32 = 1;
const F_SETFD: u32 = 2;
const F_GETFL: u32 = 3;
const F_SETFL: u32 = 4;

// ── AT constants ───────────────────────────────────────────────────────────

const AT_FDCWD: i32 = -100;
const AT_EMPTY_PATH: u32 = 0x1000;

// ── Limits ─────────────────────────────────────────────────────────────────

const MAX_VALUE_SIZE: usize = 256;
const DT_CHR: u8 = 2;
const DT_DIR: u8 = 4;
const DT_REG: u8 = 8;
const DT_LNK: u8 = 10;
const MAX_DIRENTS_COLLECT: usize = 64;

// ── Helpers ────────────────────────────────────────────────────────────────

/// Hash a pathname to a deterministic u64 keyspace key using the first 8
/// bytes of its SHA-256 digest.
fn path_to_key(path: &[u8]) -> u64 {
    let hash = Sha256::digest(path);
    u64::from_le_bytes([
        hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
    ])
}

/// Read a null-terminated pathname from user memory (max `MAX_PATH` bytes).
/// Returns the byte count (excluding the null terminator), or 0 if the
/// pointer is null.
unsafe fn read_pathname(ptr: u64, buf: &mut [u8; MAX_PATH]) -> usize {
    if ptr == 0 {
        return 0;
    }
    let src = ptr as *const u8;
    let mut len = 0usize;
    while len < MAX_PATH {
        let byte = core::ptr::read(src.add(len));
        if byte == 0 {
            break;
        }
        buf[len] = byte;
        len += 1;
    }
    len
}

/// Normalize an absolute Linux path in-place style into `dst`.
///
/// This collapses repeated slashes plus `.` and `..` components so the VFS
/// behaves more like Linux for paths such as `/usr/bin/../lib/libc.so.6`.
fn normalize_absolute_path(src: &[u8], dst: &mut [u8; MAX_PATH]) -> usize {
    if src.is_empty() || src[0] != b'/' {
        let copy_len = src.len().min(MAX_PATH);
        dst[..copy_len].copy_from_slice(&src[..copy_len]);
        return copy_len;
    }

    let mut len = 1usize;
    dst[0] = b'/';
    let mut segment_ends = [0usize; 64];
    let mut segment_count = 0usize;
    let mut i = 1usize;

    while i < src.len() {
        while i < src.len() && src[i] == b'/' {
            i += 1;
        }
        if i >= src.len() {
            break;
        }

        let start = i;
        while i < src.len() && src[i] != b'/' {
            i += 1;
        }
        let segment = &src[start..i];

        if segment == b"." {
            continue;
        }
        if segment == b".." {
            if segment_count > 0 {
                segment_count -= 1;
                len = if segment_count == 0 {
                    1
                } else {
                    segment_ends[segment_count - 1]
                };
            }
            continue;
        }

        let needed = if len > 1 { 1 } else { 0 } + segment.len();
        if len + needed > MAX_PATH {
            break;
        }
        if len > 1 {
            dst[len] = b'/';
            len += 1;
        }
        dst[len..len + segment.len()].copy_from_slice(segment);
        len += segment.len();
        if segment_count < segment_ends.len() {
            segment_ends[segment_count] = len;
            segment_count += 1;
        }
    }

    len
}

fn normalized_path<'a>(raw: &'a [u8], scratch: &'a mut [u8; MAX_PATH]) -> &'a [u8] {
    if raw.first() == Some(&b'/') {
        let len = normalize_absolute_path(raw, scratch);
        &scratch[..len]
    } else {
        raw
    }
}

/// Copy bytes from a kernel buffer to user memory.
#[inline]
unsafe fn write_user_mem(dst: u64, src: &[u8]) {
    if !src.is_empty() {
        core::ptr::copy_nonoverlapping(src.as_ptr(), dst as *mut u8, src.len());
    }
}

/// Copy bytes from user memory into a kernel buffer.
#[inline]
unsafe fn read_user_mem(src: u64, dst: &mut [u8], len: usize) {
    if len > 0 {
        core::ptr::copy_nonoverlapping(src as *const u8, dst.as_mut_ptr(), len);
    }
}

/// Read file data from a keyspace at the given offset into user memory.
///
/// Handles both small values (≤256 bytes via state_get) and large files
/// stored via store_multi_segment. Returns the number of bytes copied.
fn read_file_data(keyspace: u16, key: u64, offset: usize, buf_ptr: u64, count: usize) -> usize {
    // Try small value first
    if let Some((value, value_len)) = crate::state::state_get(keyspace, key) {
        // Check if this looks like multi-segment metadata (6 bytes with valid header)
        if value_len == 6 {
            let total = u32::from_le_bytes([value[0], value[1], value[2], value[3]]) as usize;
            let seg_count = u16::from_le_bytes([value[4], value[5]]) as usize;
            if seg_count > 0 && total > 0 && total > MAX_VALUE_SIZE {
                // This is multi-segment metadata — load via multi-segment path
                return read_multi_segment_at(keyspace, key, offset, buf_ptr, count);
            }
        }
        // Plain small value
        if offset >= value_len {
            return 0;
        }
        let available = value_len - offset;
        let to_copy = count.min(available);
        unsafe {
            write_user_mem(buf_ptr, &value[offset..offset + to_copy]);
        }
        return to_copy;
    }
    0
}

/// Read from a multi-segment file at a given offset into user memory.
fn read_multi_segment_at(
    keyspace: u16,
    key: u64,
    offset: usize,
    buf_ptr: u64,
    count: usize,
) -> usize {
    let mut copied = 0usize;
    let mut scratch = [0u8; 4096];

    while copied < count {
        let chunk_len = (count - copied).min(scratch.len());
        let loaded = crate::state::load_file_range(
            keyspace,
            key,
            offset + copied,
            &mut scratch[..chunk_len],
        );
        if loaded == 0 {
            break;
        }
        unsafe {
            write_user_mem(buf_ptr + copied as u64, &scratch[..loaded]);
        }
        copied += loaded;
        if loaded < chunk_len {
            break;
        }
    }

    copied
}

#[inline]
fn stat_dev_for_keyspace(keyspace: u16) -> u64 {
    if keyspace == super::vfs::BASE_IMAGE_KEYSPACE {
        1
    } else {
        2 + keyspace as u64
    }
}

#[inline]
fn stat_ino_for_key(key: u64) -> u64 {
    if key == 0 {
        1
    } else {
        key
    }
}

fn base_image_namespace_has_entries(namespace: super::vfs::BaseImageNamespace) -> bool {
    let mut found = false;
    crate::state::iter_base_image_paths(|entry_ns, _| {
        if entry_ns == namespace {
            found = true;
            false
        } else {
            true
        }
    });
    found
}

fn base_image_directory_namespace(path: &[u8]) -> Option<(super::vfs::BaseImageNamespace, &[u8])> {
    if path == b"/lib" {
        return Some((super::vfs::BaseImageNamespace::Lib, b""));
    }
    if path == b"/lib64" {
        return Some((super::vfs::BaseImageNamespace::Lib, b""));
    }
    if path == b"/usr/lib" {
        return Some((super::vfs::BaseImageNamespace::Lib, b""));
    }
    if path == b"/usr/bin" {
        return Some((super::vfs::BaseImageNamespace::UsrBin, b""));
    }
    if path == b"/jdk" {
        return Some((super::vfs::BaseImageNamespace::Jdk, b""));
    }
    if path == b"/etc" {
        return Some((super::vfs::BaseImageNamespace::Etc, b""));
    }
    if path.len() > 5 && &path[..5] == b"/etc/" {
        return Some((super::vfs::BaseImageNamespace::Etc, &path[5..]));
    }
    if path.len() > 5 && &path[..5] == b"/lib/" {
        return Some((super::vfs::BaseImageNamespace::Lib, &path[5..]));
    }
    if path.len() > 7 && &path[..7] == b"/lib64/" {
        return Some((super::vfs::BaseImageNamespace::Lib, &path[7..]));
    }
    if path.len() > 9 && &path[..9] == b"/usr/lib/" {
        return Some((super::vfs::BaseImageNamespace::Lib, &path[9..]));
    }
    if path.len() > 9 && &path[..9] == b"/usr/bin/" {
        return Some((super::vfs::BaseImageNamespace::UsrBin, &path[9..]));
    }
    if path.len() > 5 && &path[..5] == b"/jdk/" {
        return Some((super::vfs::BaseImageNamespace::Jdk, &path[5..]));
    }
    None
}

fn base_image_directory_exists(path: &[u8]) -> bool {
    let Some((namespace, prefix)) = base_image_directory_namespace(path) else {
        return false;
    };

    let mut found = false;
    crate::state::iter_base_image_paths(|entry_ns, relative| {
        if entry_ns != namespace {
            return true;
        }

        match namespace {
            super::vfs::BaseImageNamespace::Etc => {
                if prefix.is_empty() {
                    found = true;
                    return false;
                }
                if relative.len() > prefix.len()
                    && &relative[..prefix.len()] == prefix
                    && relative[prefix.len()] == b'/'
                {
                    found = true;
                    return false;
                }
            }
            super::vfs::BaseImageNamespace::Lib
            | super::vfs::BaseImageNamespace::Jdk
            | super::vfs::BaseImageNamespace::UsrBin => {
                if prefix.is_empty() {
                    found = true;
                    return false;
                }
                if relative.len() > prefix.len()
                    && &relative[..prefix.len()] == prefix
                    && relative[prefix.len()] == b'/'
                {
                    found = true;
                    return false;
                }
            }
        }

        true
    });
    found
}

fn push_dir_entry(
    names: &mut [[u8; MAX_PATH]; MAX_DIRENTS_COLLECT],
    lens: &mut [u16; MAX_DIRENTS_COLLECT],
    dtypes: &mut [u8; MAX_DIRENTS_COLLECT],
    count: &mut usize,
    name: &[u8],
    d_type: u8,
) {
    if name.is_empty() || name.len() >= MAX_PATH || *count >= MAX_DIRENTS_COLLECT {
        return;
    }

    for i in 0..*count {
        if lens[i] as usize == name.len() && names[i][..name.len()] == name[..] {
            if d_type == DT_DIR {
                dtypes[i] = DT_DIR;
            }
            return;
        }
    }

    names[*count][..name.len()].copy_from_slice(name);
    lens[*count] = name.len() as u16;
    dtypes[*count] = d_type;
    *count += 1;
}

fn collect_base_image_children(
    dir_path: &[u8],
    names: &mut [[u8; MAX_PATH]; MAX_DIRENTS_COLLECT],
    lens: &mut [u16; MAX_DIRENTS_COLLECT],
    dtypes: &mut [u8; MAX_DIRENTS_COLLECT],
    count: &mut usize,
) {
    let Some((namespace, prefix)) = base_image_directory_namespace(dir_path) else {
        return;
    };

    crate::state::iter_base_image_paths(|entry_ns, relative| {
        if entry_ns != namespace {
            return true;
        }

        match namespace {
            super::vfs::BaseImageNamespace::Etc => {
                let remainder = if prefix.is_empty() {
                    relative
                } else {
                    if relative.len() <= prefix.len()
                        || &relative[..prefix.len()] != prefix
                        || relative[prefix.len()] != b'/'
                    {
                        return true;
                    }
                    &relative[prefix.len() + 1..]
                };

                if remainder.is_empty() {
                    return true;
                }

                if let Some(pos) = remainder.iter().position(|&b| b == b'/') {
                    push_dir_entry(names, lens, dtypes, count, &remainder[..pos], DT_DIR);
                } else {
                    push_dir_entry(names, lens, dtypes, count, remainder, DT_REG);
                }
            }
            super::vfs::BaseImageNamespace::Lib
            | super::vfs::BaseImageNamespace::Jdk
            | super::vfs::BaseImageNamespace::UsrBin => {
                let remainder = if prefix.is_empty() {
                    relative
                } else {
                    if relative.len() <= prefix.len()
                        || &relative[..prefix.len()] != prefix
                        || relative[prefix.len()] != b'/'
                    {
                        return true;
                    }
                    &relative[prefix.len() + 1..]
                };

                if remainder.is_empty() {
                    return true;
                }

                if let Some(pos) = remainder.iter().position(|&b| b == b'/') {
                    push_dir_entry(names, lens, dtypes, count, &remainder[..pos], DT_DIR);
                } else {
                    push_dir_entry(names, lens, dtypes, count, remainder, DT_REG);
                }
            }
        }

        true
    });
}

fn collect_directory_entries(
    dir_path: &[u8],
    names: &mut [[u8; MAX_PATH]; MAX_DIRENTS_COLLECT],
    lens: &mut [u16; MAX_DIRENTS_COLLECT],
    dtypes: &mut [u8; MAX_DIRENTS_COLLECT],
) -> usize {
    let mut count = 0usize;

    if dir_path == b"." || dir_path == b"/" {
        push_dir_entry(names, lens, dtypes, &mut count, b"app", DT_DIR);
        push_dir_entry(names, lens, dtypes, &mut count, b"bin", DT_DIR);
        push_dir_entry(names, lens, dtypes, &mut count, b"dev", DT_DIR);
        push_dir_entry(names, lens, dtypes, &mut count, b"etc", DT_DIR);
        push_dir_entry(names, lens, dtypes, &mut count, b"lib", DT_DIR);
        push_dir_entry(names, lens, dtypes, &mut count, b"lib64", DT_DIR);
        push_dir_entry(names, lens, dtypes, &mut count, b"proc", DT_DIR);
        push_dir_entry(names, lens, dtypes, &mut count, b"tmp", DT_DIR);
        push_dir_entry(names, lens, dtypes, &mut count, b"usr", DT_DIR);
        push_dir_entry(names, lens, dtypes, &mut count, b"var", DT_DIR);
        if base_image_namespace_has_entries(super::vfs::BaseImageNamespace::Jdk) {
            push_dir_entry(names, lens, dtypes, &mut count, b"jdk", DT_DIR);
        }
    } else if dir_path == b"/usr" {
        push_dir_entry(names, lens, dtypes, &mut count, b"bin", DT_DIR);
        push_dir_entry(names, lens, dtypes, &mut count, b"lib", DT_DIR);
    } else if dir_path == b"/var" {
        push_dir_entry(names, lens, dtypes, &mut count, b"run", DT_DIR);
    } else if dir_path == b"/proc" {
        push_dir_entry(names, lens, dtypes, &mut count, b"self", DT_DIR);
    } else if dir_path == b"/proc/self" {
        push_dir_entry(names, lens, dtypes, &mut count, b"exe", DT_LNK);
    } else if dir_path == b"/dev" {
        push_dir_entry(names, lens, dtypes, &mut count, b"null", DT_CHR);
        push_dir_entry(names, lens, dtypes, &mut count, b"random", DT_CHR);
        push_dir_entry(names, lens, dtypes, &mut count, b"urandom", DT_CHR);
    }

    collect_base_image_children(dir_path, names, lens, dtypes, &mut count);
    count
}

// ── sys_read ───────────────────────────────────────────────────────────────

/// Read from a file descriptor.
///
/// - **File** fd: reads from the agent's keyspace value at the current
///   offset and advances the offset.
/// - **Pipe / Socket** fd: dequeues one message from the associated
///   mailbox.
pub fn sys_read(agent_id: u16, fd: i32, buf_ptr: u64, count: u64) -> i64 {
    let st = match state::get_state_mut(agent_id) {
        Some(s) => s,
        None => return -EBADF,
    };

    let entry = match st.get_fd(fd) {
        Some(e) if e.active => e,
        _ => return -EBADF,
    };

    let kind = entry.kind;
    let key = entry.keyspace_key;
    let ks = entry.keyspace_id;
    let offset = entry.offset as usize;

    match kind {
        FdKind::File => {
            let to_copy = read_file_data(ks, key, offset, buf_ptr, count as usize);
            if to_copy > 0 {
                if let Some(e) = st.get_fd_mut(fd) {
                    e.offset += to_copy as u64;
                }
            }
            to_copy as i64
        }
        FdKind::Pipe | FdKind::Socket => {
            let mailbox_id = entry.mailbox_id;
            match crate::mailbox::recv_message(agent_id, mailbox_id) {
                Ok(msg) => {
                    let msg_len = msg.len as usize;
                    let to_copy = (count as usize).min(msg_len);
                    unsafe {
                        write_user_mem(buf_ptr, &msg.payload[..to_copy]);
                    }
                    to_copy as i64
                }
                Err(_) => 0, // no message available → EOF-like
            }
        }
        FdKind::Directory => -EISDIR,
        _ => -EINVAL,
    }
}

// ── sys_write ──────────────────────────────────────────────────────────────

/// Write to a file descriptor.
///
/// - fd 1 / 2 (stdout / stderr): bytes are printed to the serial console.
/// - **File** fd: the data is stored into the agent's keyspace.
/// - **Pipe / Socket** fd: the data is sent as a mailbox message.
pub fn sys_write(agent_id: u16, fd: i32, buf_ptr: u64, count: u64) -> i64 {
    let cnt = count as usize;
    if cnt == 0 {
        return 0;
    }

    // ── stdout / stderr → serial console ───────────────────────────────
    if fd == 1 || fd == 2 {
        // Read user data into a stack buffer and print via serial_print!
        let mut tmp = [0u8; 512];
        let to_read = cnt.min(tmp.len());
        unsafe {
            read_user_mem(buf_ptr, &mut tmp, to_read);
        }
        // Convert to a str-like slice and print; non-UTF-8 bytes are
        // replaced with '?' to keep the serial output clean.
        for &b in &tmp[..to_read] {
            if b == b'\n' {
                crate::serial_println!();
            } else if b.is_ascii() {
                crate::serial_print!("{}", b as char);
            } else {
                crate::serial_print!("?");
            }
        }
        return to_read as i64;
    }

    // ── Regular fd ─────────────────────────────────────────────────────
    let st = match state::get_state_mut(agent_id) {
        Some(s) => s,
        None => return -EBADF,
    };

    let entry = match st.get_fd(fd) {
        Some(e) if e.active => e,
        _ => return -EBADF,
    };

    let kind = entry.kind;
    let key = entry.keyspace_key;
    let ks = entry.keyspace_id;

    match kind {
        FdKind::File => {
            let to_write = cnt.min(MAX_VALUE_SIZE);
            let mut value = [0u8; MAX_VALUE_SIZE];
            unsafe {
                read_user_mem(buf_ptr, &mut value, to_write);
            }
            match crate::state::state_put(ks, key, &value[..to_write]) {
                Ok(()) => {
                    // Advance fd offset
                    if let Some(e) = st.get_fd_mut(fd) {
                        e.offset += to_write as u64;
                    }
                    to_write as i64
                }
                Err(_) => -ENOSPC,
            }
        }
        FdKind::Pipe | FdKind::Socket => {
            let mailbox_id = entry.mailbox_id;
            let to_send = cnt.min(crate::agent::MAX_MESSAGE_PAYLOAD);
            let mut payload = [0u8; crate::agent::MAX_MESSAGE_PAYLOAD];
            unsafe {
                read_user_mem(buf_ptr, &mut payload, to_send);
            }
            match crate::mailbox::send_message(agent_id, mailbox_id, &payload[..to_send]) {
                Ok(()) => to_send as i64,
                Err(_) => -EAGAIN,
            }
        }
        FdKind::Directory => -EISDIR,
        _ => -EINVAL,
    }
}

// ── sys_openat ─────────────────────────────────────────────────────────────

/// Open a file relative to a directory fd.
///
/// The pathname is read from user memory, hashed to a keyspace key via
/// SHA-256, and a new fd is allocated in the agent's fd table.
pub fn sys_openat(agent_id: u16, dirfd: i32, pathname_ptr: u64, flags: u32, mode: u32) -> i64 {
    let _ = dirfd; // AT_FDCWD or ignored; flat namespace in Stage-1
    let _ = mode; // permissions not enforced

    let mut path_buf = [0u8; MAX_PATH];
    let path_len = unsafe { read_pathname(pathname_ptr, &mut path_buf) };
    if path_len == 0 {
        return -ENOENT;
    }

    let mut norm_buf = [0u8; MAX_PATH];
    let path = normalized_path(&path_buf[..path_len], &mut norm_buf);
    let trace_python = super::state::trace_runtime_agent(agent_id);
    if trace_python {
        crate::serial_println!(
            "[PYDBG] openat-enter agent={} dirfd={} flags={:#x} mode={:#x} path={:?}",
            agent_id,
            dirfd,
            flags,
            mode,
            core::str::from_utf8(path).unwrap_or("?")
        );
    }

    // Special paths always succeed (e.g. /dev/null, /proc/*)
    let is_special = super::vfs::is_special_path(path).is_some();

    // Check if it's a directory open (for getdents64)
    let is_dir = (flags & O_DIRECTORY) != 0;
    let directory_target = is_directory_path(path);

    let (keyspace_id, key) = super::vfs::resolve_path(agent_id, path);

    if is_dir && !directory_target {
        let exists = crate::state::query_file_size(keyspace_id, key) > 0
            || crate::state::state_get(keyspace_id, key).is_some()
            || is_special;
        let ret = if exists { -ENOTDIR } else { -ENOENT };
        if trace_python {
            crate::serial_println!(
                "[PYDBG] openat-exit agent={} ret={} path={:?} ks={} key={:#x}",
                agent_id,
                ret,
                core::str::from_utf8(path).unwrap_or("?"),
                keyspace_id,
                key
            );
        }
        return ret;
    }

    // If not creating and not a special path and not a directory,
    // verify the file actually exists in the keyspace
    if (flags & O_CREAT) == 0 && !is_special && !directory_target {
        let size = crate::state::query_file_size(keyspace_id, key);
        if size == 0 {
            // Also check plain state_get for empty/small files
            if crate::state::state_get(keyspace_id, key).is_none() {
                if trace_python {
                    crate::serial_println!(
                        "[PYDBG] openat-exit agent={} ret={} path={:?} ks={} key={:#x}",
                        agent_id,
                        -ENOENT,
                        core::str::from_utf8(path).unwrap_or("?"),
                        keyspace_id,
                        key
                    );
                }
                return -ENOENT;
            }
        }
    }

    let st = match state::get_state_mut(agent_id) {
        Some(s) => s,
        None => return -EFAULT,
    };

    let fd_idx = match st.alloc_fd() {
        Some(idx) => idx,
        None => return -EMFILE,
    };

    if directory_target {
        let dir_handle = match st.alloc_directory_handle(path) {
            Some(id) => id,
            None => return -EMFILE,
        };
        st.fd_table[fd_idx] = Some(FdEntry {
            kind: FdKind::Directory,
            keyspace_key: dir_handle as u64,
            keyspace_id: 0,
            mailbox_id: 0,
            offset: 0,
            flags,
            active: true,
        });
    } else {
        st.fd_table[fd_idx] = Some(FdEntry {
            kind: FdKind::File,
            keyspace_key: key,
            keyspace_id,
            mailbox_id: 0,
            offset: 0,
            flags,
            active: true,
        });
    }

    if trace_python {
        crate::serial_println!(
            "[PYDBG] openat-exit agent={} fd={} path={:?} ks={} key={:#x} dir={}",
            agent_id,
            fd_idx,
            core::str::from_utf8(path).unwrap_or("?"),
            keyspace_id,
            key,
            directory_target
        );
    }

    fd_idx as i64
}

// ── sys_close ──────────────────────────────────────────────────────────────

/// Close a file descriptor.
pub fn sys_close(agent_id: u16, fd: i32) -> i64 {
    let st = match state::get_state_mut(agent_id) {
        Some(s) => s,
        None => return -EBADF,
    };
    if st.close_fd(fd) {
        0
    } else {
        -EBADF
    }
}

// ── sys_fstat ──────────────────────────────────────────────────────────────

/// Fill a Linux `struct stat` (x86_64, 144 bytes) for an open fd.
///
/// Layout offsets:
///   0: st_dev (u64), 8: st_ino (u64), 16: st_nlink (u64),
///   24: st_mode (u32), 28: st_uid (u32), 32: st_gid (u32),
///   36: pad (u32), 40: st_rdev (u64), 48: st_size (i64),
///   56: st_blksize (i64), 64: st_blocks (i64), 72..144: timestamps
pub fn sys_fstat(agent_id: u16, fd: i32, statbuf_ptr: u64) -> i64 {
    let st = match state::get_state(agent_id) {
        Some(s) => s,
        None => return -EBADF,
    };

    let entry = match st.get_fd(fd) {
        Some(e) if e.active => e,
        _ => return -EBADF,
    };

    if entry.kind == FdKind::Directory {
        fill_stat_buf_dir(statbuf_ptr);
        return 0;
    }

    let file_size: u64 = if entry.kind == FdKind::File {
        crate::state::query_file_size(entry.keyspace_id, entry.keyspace_key) as u64
    } else {
        0
    };

    fill_stat_buf(
        statbuf_ptr,
        file_size,
        stat_dev_for_keyspace(entry.keyspace_id),
        stat_ino_for_key(entry.keyspace_key),
    );
    0
}

/// Write a populated `struct stat` to user memory.
fn fill_stat_buf(ptr: u64, file_size: u64, st_dev: u64, st_ino: u64) {
    let mut buf = [0u8; 144];

    buf[0..8].copy_from_slice(&st_dev.to_le_bytes());
    buf[8..16].copy_from_slice(&st_ino.to_le_bytes());
    // st_nlink = 1
    buf[16..24].copy_from_slice(&1u64.to_le_bytes());
    // st_mode = S_IFREG | 0644 = 0o100644 = 0x81A4
    buf[24..28].copy_from_slice(&0x81A4u32.to_le_bytes());
    // st_uid = 1000
    buf[28..32].copy_from_slice(&1000u32.to_le_bytes());
    // st_gid = 1000
    buf[32..36].copy_from_slice(&1000u32.to_le_bytes());
    // st_size
    buf[48..56].copy_from_slice(&(file_size as i64).to_le_bytes());
    // st_blksize = 4096
    buf[56..64].copy_from_slice(&4096i64.to_le_bytes());
    // st_blocks = ceil(size / 512)
    let blocks = (file_size + 511) / 512;
    buf[64..72].copy_from_slice(&(blocks as i64).to_le_bytes());

    unsafe { write_user_mem(ptr, &buf) }
}

// ── sys_newfstatat ─────────────────────────────────────────────────────────

/// Stat a file by pathname relative to a directory fd.
///
/// With `AT_EMPTY_PATH` and a valid fd, behaves like `fstat`.
pub fn sys_newfstatat(
    agent_id: u16,
    dirfd: i32,
    pathname_ptr: u64,
    statbuf_ptr: u64,
    flags: u32,
) -> i64 {
    let trace_python = super::state::trace_runtime_agent(agent_id);
    // AT_EMPTY_PATH with a valid dirfd → delegate to fstat
    if (flags & AT_EMPTY_PATH) != 0 && dirfd >= 0 {
        let ret = sys_fstat(agent_id, dirfd, statbuf_ptr);
        if trace_python {
            crate::serial_println!(
                "[PYDBG] newfstatat-empty-path agent={} dirfd={} ret={}",
                agent_id,
                dirfd,
                ret
            );
        }
        return ret;
    }

    let _ = dirfd;

    let mut path_buf = [0u8; MAX_PATH];
    let path_len = unsafe { read_pathname(pathname_ptr, &mut path_buf) };
    if path_len == 0 {
        return -ENOENT;
    }

    let mut norm_buf = [0u8; MAX_PATH];
    let path = normalized_path(&path_buf[..path_len], &mut norm_buf);
    if trace_python {
        crate::serial_println!(
            "[PYDBG] newfstatat-enter agent={} dirfd={} flags={:#x} path={:?}",
            agent_id,
            dirfd,
            flags,
            core::str::from_utf8(path).unwrap_or("?")
        );
    }

    // Special paths always exist
    if super::vfs::is_special_path(path).is_some() {
        fill_stat_buf(statbuf_ptr, 0, 0x100, path_to_key(path));
        if trace_python {
            crate::serial_println!(
                "[PYDBG] newfstatat-exit agent={} ret=0 path={:?} special=true",
                agent_id,
                core::str::from_utf8(path).unwrap_or("?")
            );
        }
        return 0;
    }

    // Directory-like paths always succeed (return S_IFDIR)
    if is_directory_path(path) {
        fill_stat_buf_dir(statbuf_ptr);
        if trace_python {
            crate::serial_println!(
                "[PYDBG] newfstatat-exit agent={} ret=0 path={:?} dir=true",
                agent_id,
                core::str::from_utf8(path).unwrap_or("?")
            );
        }
        return 0;
    }

    let (ks, key) = super::vfs::resolve_path(agent_id, path);

    // Check existence: try query_file_size, then state_get for empty/small files
    let file_size = crate::state::query_file_size(ks, key);
    if file_size == 0 && crate::state::state_get(ks, key).is_none() {
        if trace_python {
            crate::serial_println!(
                "[PYDBG] newfstatat-exit agent={} ret={} path={:?} ks={} key={:#x}",
                agent_id,
                -ENOENT,
                core::str::from_utf8(path).unwrap_or("?"),
                ks,
                key
            );
        }
        return -ENOENT;
    }

    fill_stat_buf(
        statbuf_ptr,
        file_size as u64,
        stat_dev_for_keyspace(ks),
        stat_ino_for_key(key),
    );
    if trace_python {
        crate::serial_println!(
            "[PYDBG] newfstatat-exit agent={} ret=0 path={:?} size={} ks={} key={:#x}",
            agent_id,
            core::str::from_utf8(path).unwrap_or("?"),
            file_size,
            ks,
            key
        );
    }
    0
}

/// Check if a path is a known directory.
fn is_directory_path(path: &[u8]) -> bool {
    matches!(
        path,
        b"." | b"/"
            | b"/app"
            | b"/bin"
            | b"/dev"
            | b"/etc"
            | b"/lib"
            | b"/lib64"
            | b"/proc"
            | b"/proc/self"
            | b"/tmp"
            | b"/usr"
            | b"/usr/bin"
            | b"/usr/lib"
            | b"/var"
            | b"/var/run"
    ) || base_image_directory_exists(path)
}

/// Fill a stat buf with S_IFDIR mode.
fn fill_stat_buf_dir(ptr: u64) {
    let mut buf = [0u8; 144];
    // st_mode = S_IFDIR | 0755 = 0o40755 = 0x41ED
    buf[24..28].copy_from_slice(&0x41EDu32.to_le_bytes());
    // st_nlink = 2
    buf[16..24].copy_from_slice(&2u64.to_le_bytes());
    // st_uid = 1000
    buf[28..32].copy_from_slice(&1000u32.to_le_bytes());
    // st_gid = 1000
    buf[32..36].copy_from_slice(&1000u32.to_le_bytes());
    // st_blksize = 4096
    buf[56..64].copy_from_slice(&4096u64.to_le_bytes());
    unsafe { write_user_mem(ptr, &buf) }
}

// ── sys_lseek ──────────────────────────────────────────────────────────────

/// Reposition the read/write offset of an open fd.
pub fn sys_lseek(agent_id: u16, fd: i32, offset: i64, whence: u32) -> i64 {
    let st = match state::get_state_mut(agent_id) {
        Some(s) => s,
        None => return -EBADF,
    };

    let entry = match st.get_fd_mut(fd) {
        Some(e) if e.active => e,
        _ => return -EBADF,
    };

    if entry.kind != FdKind::File {
        if entry.kind == FdKind::Directory {
            return -EISDIR;
        }
        return -EINVAL; // cannot seek pipes/sockets
    }

    let file_size = crate::state::query_file_size(entry.keyspace_id, entry.keyspace_key) as u64;

    let new_offset: i64 = match whence {
        SEEK_SET => offset,
        SEEK_CUR => entry.offset as i64 + offset,
        SEEK_END => file_size as i64 + offset,
        _ => return -EINVAL,
    };

    if new_offset < 0 {
        return -EINVAL;
    }

    entry.offset = new_offset as u64;
    new_offset
}

// ── sys_pread64 ────────────────────────────────────────────────────────────

/// Read from a file at a given offset without modifying the fd offset.
pub fn sys_pread64(agent_id: u16, fd: i32, buf_ptr: u64, count: u64, offset: u64) -> i64 {
    let st = match state::get_state(agent_id) {
        Some(s) => s,
        None => return -EBADF,
    };

    let entry = match st.get_fd(fd) {
        Some(e) if e.active => e,
        _ => return -EBADF,
    };

    if entry.kind != FdKind::File {
        if entry.kind == FdKind::Directory {
            return -EISDIR;
        }
        return -EINVAL;
    }

    read_file_data(
        entry.keyspace_id,
        entry.keyspace_key,
        offset as usize,
        buf_ptr,
        count as usize,
    ) as i64
}

// ── sys_access ─────────────────────────────────────────────────────────────

/// Check user permissions for a file.
///
/// All files in the agent's keyspace are accessible in Stage-1.
/// Returns 0 if the key exists, `-ENOENT` otherwise.
pub fn sys_access(agent_id: u16, pathname_ptr: u64, mode: u32) -> i64 {
    let _ = mode; // all modes granted
    let trace_python = super::state::trace_runtime_agent(agent_id);

    let mut path_buf = [0u8; MAX_PATH];
    let path_len = unsafe { read_pathname(pathname_ptr, &mut path_buf) };
    if path_len == 0 {
        return -ENOENT;
    }
    let mut norm_buf = [0u8; MAX_PATH];
    let path = normalized_path(&path_buf[..path_len], &mut norm_buf);
    if trace_python {
        crate::serial_println!(
            "[PYDBG] access-enter agent={} mode={:#x} path={:?}",
            agent_id,
            mode,
            core::str::from_utf8(path).unwrap_or("?")
        );
    }

    // Special files always exist
    if super::vfs::is_special_path(path).is_some() {
        if trace_python {
            crate::serial_println!("[PYDBG] access-exit agent={} ret=0 special=true", agent_id);
        }
        return 0;
    }

    if is_directory_path(path) {
        if trace_python {
            crate::serial_println!("[PYDBG] access-exit agent={} ret=0 dir=true", agent_id);
        }
        return 0;
    }

    let (ks, key) = super::vfs::resolve_path(agent_id, path);
    let ret = if crate::state::query_file_size(ks, key) > 0
        || crate::state::state_get(ks, key).is_some()
    {
        0
    } else {
        -ENOENT
    };
    if trace_python {
        crate::serial_println!(
            "[PYDBG] access-exit agent={} ret={} path={:?} ks={} key={:#x}",
            agent_id,
            ret,
            core::str::from_utf8(path).unwrap_or("?"),
            ks,
            key
        );
    }
    ret
}

// ── sys_readlink ───────────────────────────────────────────────────────────

/// Read the target of a symbolic link.
///
/// `/proc/self/exe` is handled specially and returns `"/app/binary"`.
/// All other paths return `-EINVAL` (no real symlinks).
pub fn sys_readlink(agent_id: u16, pathname_ptr: u64, buf_ptr: u64, bufsiz: u64) -> i64 {
    let trace_python = super::state::trace_runtime_agent(agent_id);
    let mut path_buf = [0u8; MAX_PATH];
    let path_len = unsafe { read_pathname(pathname_ptr, &mut path_buf) };
    if path_len == 0 {
        return -ENOENT;
    }
    let mut norm_buf = [0u8; MAX_PATH];
    let path = normalized_path(&path_buf[..path_len], &mut norm_buf);
    if trace_python {
        crate::serial_println!(
            "[PYDBG] readlink-enter agent={} path={:?} bufsiz={}",
            agent_id,
            core::str::from_utf8(path).unwrap_or("?"),
            bufsiz
        );
    }

    const PROC_SELF_EXE: &[u8] = b"/proc/self/exe";
    if path == PROC_SELF_EXE {
        // Return the real exe_path from LinuxAgentState
        let result = match state::get_state(agent_id) {
            Some(s) if s.exe_path_len > 0 => &s.exe_path[..s.exe_path_len as usize],
            _ => b"/app/binary" as &[u8],
        };
        let to_copy = (bufsiz as usize).min(result.len());
        unsafe {
            write_user_mem(buf_ptr, &result[..to_copy]);
        }
        if trace_python {
            crate::serial_println!(
                "[PYDBG] readlink-exit agent={} ret={} path={:?}",
                agent_id,
                to_copy,
                core::str::from_utf8(path).unwrap_or("?")
            );
        }
        return to_copy as i64;
    }

    if trace_python {
        crate::serial_println!(
            "[PYDBG] readlink-exit agent={} ret={} path={:?}",
            agent_id,
            -EINVAL,
            core::str::from_utf8(path).unwrap_or("?")
        );
    }
    -EINVAL
}

// ── sys_readlinkat ────────────────────────────────────────────────────────

/// Read a symbolic link relative to a directory fd.
///
/// Delegates to sys_readlink for the actual path handling.
pub fn sys_readlinkat(
    agent_id: u16,
    dirfd: i32,
    pathname_ptr: u64,
    buf_ptr: u64,
    bufsiz: u64,
) -> i64 {
    let _ = dirfd; // AT_FDCWD or ignored
    sys_readlink(agent_id, pathname_ptr, buf_ptr, bufsiz)
}

// ── sys_statx ─────────────────────────────────────────────────────────────

/// statx — extended file status.
///
/// Linux `struct statx` is 256 bytes. We fill a minimal subset:
///   0: stx_mask (u32), 4: stx_blksize (u32), 8: stx_attributes (u64),
///   16: stx_nlink (u32), 20: stx_uid (u32), 24: stx_gid (u32),
///   28: stx_mode (u16), 40: stx_ino (u64), 48: stx_size (u64),
///   56: stx_blocks (u64)
pub fn sys_statx(
    agent_id: u16,
    dirfd: i32,
    pathname_ptr: u64,
    flags: u32,
    _mask: u32,
    statxbuf_ptr: u64,
) -> i64 {
    // AT_EMPTY_PATH with dirfd → fstat equivalent
    if (flags & AT_EMPTY_PATH) != 0 && dirfd >= 0 {
        let st = match state::get_state(agent_id) {
            Some(s) => s,
            None => return -EBADF,
        };
        let entry = match st.get_fd(dirfd) {
            Some(e) if e.active => e,
            _ => return -EBADF,
        };
        if entry.kind == FdKind::Directory {
            fill_statx_buf_dir(statxbuf_ptr);
            return 0;
        }
        let file_size = if entry.kind == FdKind::File {
            crate::state::query_file_size(entry.keyspace_id, entry.keyspace_key) as u64
        } else {
            0
        };
        fill_statx_buf(
            statxbuf_ptr,
            file_size,
            stat_dev_for_keyspace(entry.keyspace_id),
            stat_ino_for_key(entry.keyspace_key),
        );
        return 0;
    }

    let mut path_buf = [0u8; MAX_PATH];
    let path_len = unsafe { read_pathname(pathname_ptr, &mut path_buf) };
    if path_len == 0 {
        return -ENOENT;
    }

    let mut norm_buf = [0u8; MAX_PATH];
    let path = normalized_path(&path_buf[..path_len], &mut norm_buf);

    // Special paths always exist
    if super::vfs::is_special_path(path).is_some() {
        fill_statx_buf(statxbuf_ptr, 0, 0x100, path_to_key(path));
        return 0;
    }

    // Directory-like paths always succeed
    if is_directory_path(path) {
        fill_statx_buf_dir(statxbuf_ptr);
        return 0;
    }

    let (ks, key) = super::vfs::resolve_path(agent_id, path);
    let file_size = crate::state::query_file_size(ks, key);
    if file_size == 0 && crate::state::state_get(ks, key).is_none() {
        return -ENOENT;
    }
    fill_statx_buf(
        statxbuf_ptr,
        file_size as u64,
        stat_dev_for_keyspace(ks),
        stat_ino_for_key(key),
    );
    0
}

/// Write a `struct statx` for a directory.
fn fill_statx_buf_dir(ptr: u64) {
    let mut buf = [0u8; 256];
    buf[0..4].copy_from_slice(&0x07FFu32.to_le_bytes()); // stx_mask
    buf[4..8].copy_from_slice(&4096u32.to_le_bytes()); // stx_blksize
    buf[16..20].copy_from_slice(&2u32.to_le_bytes()); // stx_nlink
    buf[20..24].copy_from_slice(&1000u32.to_le_bytes()); // stx_uid
    buf[24..28].copy_from_slice(&1000u32.to_le_bytes()); // stx_gid
                                                         // stx_mode = S_IFDIR | 0755 = 0x41ED
    buf[28..30].copy_from_slice(&0x41EDu16.to_le_bytes());
    buf[40..48].copy_from_slice(&1u64.to_le_bytes()); // stx_ino
    unsafe { write_user_mem(ptr, &buf) }
}

/// Write a populated `struct statx` (256 bytes) to user memory.
fn fill_statx_buf(ptr: u64, file_size: u64, st_dev: u64, st_ino: u64) {
    let mut buf = [0u8; 256];

    // stx_mask = STATX_BASIC_STATS (0x07FF)
    buf[0..4].copy_from_slice(&0x07FFu32.to_le_bytes());
    // stx_blksize = 4096
    buf[4..8].copy_from_slice(&4096u32.to_le_bytes());
    // stx_nlink = 1
    buf[16..20].copy_from_slice(&1u32.to_le_bytes());
    // stx_uid = 1000
    buf[20..24].copy_from_slice(&1000u32.to_le_bytes());
    // stx_gid = 1000
    buf[24..28].copy_from_slice(&1000u32.to_le_bytes());
    // stx_mode = S_IFREG | 0644 = 0o100644 = 0x81A4
    buf[28..30].copy_from_slice(&0x81A4u16.to_le_bytes());
    buf[40..48].copy_from_slice(&st_ino.to_le_bytes());
    // stx_size
    buf[48..56].copy_from_slice(&file_size.to_le_bytes());
    // stx_blocks = ceil(size / 512)
    let blocks = (file_size + 511) / 512;
    buf[56..64].copy_from_slice(&blocks.to_le_bytes());
    // stx_dev_major/stx_dev_minor
    buf[136..140].copy_from_slice(&(st_dev as u32).to_le_bytes());
    buf[140..144].copy_from_slice(&0u32.to_le_bytes());

    unsafe { write_user_mem(ptr, &buf) }
}

// ── sys_getdents64 ─────────────────────────────────────────────────────────

/// Read directory entries.
///
/// Enumerates active entries in the agent's keyspace as `linux_dirent64`
/// structures.  Each key is rendered as a 16-character hex filename.
/// The fd offset tracks how many entries have already been returned so
/// that successive calls eventually yield 0 (end of directory).
pub fn sys_getdents64(agent_id: u16, fd: i32, dirp_ptr: u64, count: u64) -> i64 {
    let st = match state::get_state_mut(agent_id) {
        Some(s) => s,
        None => return -EBADF,
    };

    let entry = match st.get_fd(fd) {
        Some(e) if e.active => e,
        _ => return -EBADF,
    };

    if entry.kind != FdKind::Directory {
        return -ENOTDIR;
    }

    let dir_handle = match st.get_directory_handle(entry.keyspace_key as u16) {
        Some(handle) => *handle,
        None => return -EBADF,
    };

    let already_returned = entry.offset as usize;
    let buf_size = count as usize;

    let mut path = [0u8; MAX_PATH];
    let path_len = dir_handle.path_len as usize;
    path[..path_len].copy_from_slice(&dir_handle.path[..path_len]);

    let mut child_names = [[0u8; MAX_PATH]; MAX_DIRENTS_COLLECT];
    let mut child_lens = [0u16; MAX_DIRENTS_COLLECT];
    let mut child_dtypes = [0u8; MAX_DIRENTS_COLLECT];
    let child_count = collect_directory_entries(
        &path[..path_len],
        &mut child_names,
        &mut child_lens,
        &mut child_dtypes,
    );

    let mut names = [[0u8; MAX_PATH]; MAX_DIRENTS_COLLECT];
    let mut lens = [0u16; MAX_DIRENTS_COLLECT];
    let mut dtypes = [0u8; MAX_DIRENTS_COLLECT];
    let mut total_entries = 0usize;
    push_dir_entry(
        &mut names,
        &mut lens,
        &mut dtypes,
        &mut total_entries,
        b".",
        DT_DIR,
    );
    push_dir_entry(
        &mut names,
        &mut lens,
        &mut dtypes,
        &mut total_entries,
        b"..",
        DT_DIR,
    );
    for idx in 0..child_count {
        push_dir_entry(
            &mut names,
            &mut lens,
            &mut dtypes,
            &mut total_entries,
            &child_names[idx][..child_lens[idx] as usize],
            child_dtypes[idx],
        );
    }

    if already_returned >= total_entries {
        return 0;
    }

    let mut written = 0usize;
    let mut entries_emitted = 0usize;
    for idx in already_returned..total_entries {
        let name_len = lens[idx] as usize + 1;
        let reclen_raw = 8 + 8 + 2 + 1 + name_len;
        let reclen = (reclen_raw + 7) & !7;
        if written + reclen > buf_size {
            break;
        }

        let mut dirent = [0u8; MAX_PATH + 24];
        let ino = (idx as u64) + 1;
        dirent[0..8].copy_from_slice(&ino.to_le_bytes());
        dirent[8..16].copy_from_slice(&((idx + 1) as u64).to_le_bytes());
        dirent[16..18].copy_from_slice(&(reclen as u16).to_le_bytes());
        dirent[18] = dtypes[idx];
        let entry_len = lens[idx] as usize;
        dirent[19..19 + entry_len].copy_from_slice(&names[idx][..entry_len]);
        dirent[19 + entry_len] = 0;

        unsafe { write_user_mem(dirp_ptr + written as u64, &dirent[..reclen]) }
        written += reclen;
        entries_emitted += 1;
    }

    if let Some(e) = st.get_fd_mut(fd) {
        e.offset += entries_emitted as u64;
    }

    written as i64
}

// ── sys_fcntl ──────────────────────────────────────────────────────────────

/// File descriptor control operations.
///
/// Supports F_DUPFD, F_GETFD/F_SETFD, F_GETFL/F_SETFL.
pub fn sys_fcntl(agent_id: u16, fd: i32, cmd: u32, arg: u64) -> i64 {
    let st = match state::get_state_mut(agent_id) {
        Some(s) => s,
        None => return -EBADF,
    };

    match cmd {
        F_DUPFD => {
            let min_fd = arg as usize;
            let entry = match st.get_fd(fd) {
                Some(e) if e.active => *e,
                _ => return -EBADF,
            };
            for i in min_fd..MAX_FDS {
                if st.fd_table[i].is_none() {
                    let cloned = match clone_fd_entry(st, entry) {
                        Ok(e) => e,
                        Err(e) => return e,
                    };
                    st.fd_table[i] = Some(cloned);
                    return i as i64;
                }
            }
            -EMFILE
        }
        F_GETFD => match st.get_fd(fd) {
            Some(e) if e.active => {
                if (e.flags & O_CLOEXEC) != 0 {
                    1
                } else {
                    0
                }
            }
            _ => -EBADF,
        },
        F_SETFD => match st.get_fd_mut(fd) {
            Some(e) if e.active => {
                if (arg & 1) != 0 {
                    e.flags |= O_CLOEXEC;
                } else {
                    e.flags &= !O_CLOEXEC;
                }
                0
            }
            _ => -EBADF,
        },
        F_GETFL => match st.get_fd(fd) {
            Some(e) if e.active => e.flags as i64,
            _ => -EBADF,
        },
        F_SETFL => {
            match st.get_fd_mut(fd) {
                Some(e) if e.active => {
                    // Only O_NONBLOCK and O_APPEND are changeable at runtime
                    let changeable = O_NONBLOCK | O_APPEND;
                    e.flags = (e.flags & !changeable) | (arg as u32 & changeable);
                    0
                }
                _ => -EBADF,
            }
        }
        _ => -EINVAL,
    }
}

// ── sys_dup ────────────────────────────────────────────────────────────────

/// Duplicate a file descriptor, returning the lowest available fd.
pub fn sys_dup(agent_id: u16, oldfd: i32) -> i64 {
    let st = match state::get_state_mut(agent_id) {
        Some(s) => s,
        None => return -EBADF,
    };

    let entry = match st.get_fd(oldfd) {
        Some(e) if e.active => *e,
        _ => return -EBADF,
    };

    match st.alloc_fd() {
        Some(new_fd) => {
            let cloned = match clone_fd_entry(st, entry) {
                Ok(e) => e,
                Err(e) => return e,
            };
            st.fd_table[new_fd] = Some(cloned);
            new_fd as i64
        }
        None => -EMFILE,
    }
}

// ── sys_unlink ─────────────────────────────────────────────────────────────

/// Delete a file by removing its keyspace entry.
///
/// The pathname is hashed to a keyspace key and the corresponding entry
/// is marked inactive.  Returns 0 on success or `-ENOENT` if the key
/// did not exist.
pub fn sys_unlink(agent_id: u16, pathname_ptr: u64) -> i64 {
    let mut path_buf = [0u8; MAX_PATH];
    let path_len = unsafe { read_pathname(pathname_ptr, &mut path_buf) };
    if path_len == 0 {
        return -ENOENT;
    }

    let key = path_to_key(&path_buf[..path_len]);
    match crate::state::state_delete(agent_id, key) {
        Ok(()) => 0,
        Err(_) => -ENOENT,
    }
}

// ── sys_mkdir ──────────────────────────────────────────────────────────────

/// Create a directory.
///
/// Directories are virtual in Stage-1.  Always returns 0 (success).
pub fn sys_mkdir(agent_id: u16, pathname_ptr: u64, mode: u32) -> i64 {
    let _ = agent_id;
    let _ = mode;

    let mut path_buf = [0u8; MAX_PATH];
    let path_len = unsafe { read_pathname(pathname_ptr, &mut path_buf) };
    if path_len == 0 {
        return -ENOENT;
    }
    0
}

// ── sys_fchdir ─────────────────────────────────────────────────────────────

/// Change working directory via an open fd.
///
/// The fd must reference a directory handle.
pub fn sys_fchdir(agent_id: u16, fd: i32) -> i64 {
    let st = match state::get_state_mut(agent_id) {
        Some(s) => s,
        None => return -EBADF,
    };

    let entry = match st.get_fd(fd) {
        Some(e) if e.active => *e,
        _ => return -EBADF,
    };

    if entry.kind != FdKind::Directory {
        return -ENOTDIR;
    }

    let handle = match st.get_directory_handle(entry.keyspace_key as u16) {
        Some(h) => *h,
        None => return -EBADF,
    };

    let copy_len = handle.path_len as usize;
    st.cwd[..copy_len].copy_from_slice(&handle.path[..copy_len]);
    st.cwd_len = copy_len as u16;
    0
}

fn clone_fd_entry(st: &mut state::LinuxAgentState, entry: FdEntry) -> Result<FdEntry, i64> {
    if entry.kind != FdKind::Directory {
        return Ok(entry);
    }

    let Some(handle_id) = st.clone_directory_handle(entry.keyspace_key as u16) else {
        return Err(-EMFILE);
    };

    Ok(FdEntry {
        keyspace_key: handle_id as u64,
        ..entry
    })
}

// ── sys_getcwd ─────────────────────────────────────────────────────────────

/// Get the current working directory.
///
/// Copies the cwd from the agent's `LinuxAgentState` into the user buffer
/// and returns the buffer pointer (Linux convention).
pub fn sys_getcwd(agent_id: u16, buf_ptr: u64, size: u64) -> i64 {
    let st = match state::get_state(agent_id) {
        Some(s) => s,
        None => return -EFAULT,
    };

    let cwd_len = st.cwd_len as usize;
    // Need room for path + null terminator
    if size == 0 || (cwd_len + 1) > size as usize {
        return -EINVAL;
    }

    unsafe {
        write_user_mem(buf_ptr, &st.cwd[..cwd_len]);
        // Null terminator
        core::ptr::write((buf_ptr + cwd_len as u64) as *mut u8, 0);
    }
    buf_ptr as i64
}

// ── sys_flock ──────────────────────────────────────────────────────────────

/// Apply or remove an advisory lock on an open file.
///
/// No-op in Stage-1 (single agent, no contention).
pub fn sys_flock(agent_id: u16, fd: i32, operation: u32) -> i64 {
    let _ = operation;

    let st = match state::get_state(agent_id) {
        Some(s) => s,
        None => return -EBADF,
    };

    match st.get_fd(fd) {
        Some(e) if e.active => 0,
        _ => -EBADF,
    }
}

// ── sys_ftruncate ──────────────────────────────────────────────────────────

/// Truncate a file to a specified length.
///
/// If `length` is 0, stores an empty value.  Otherwise reads the current
/// value and truncates it.
pub fn sys_ftruncate(agent_id: u16, fd: i32, length: u64) -> i64 {
    let st = match state::get_state(agent_id) {
        Some(s) => s,
        None => return -EBADF,
    };

    let entry = match st.get_fd(fd) {
        Some(e) if e.active => e,
        _ => return -EBADF,
    };

    if entry.kind != FdKind::File {
        if entry.kind == FdKind::Directory {
            return -EISDIR;
        }
        return -EINVAL;
    }

    let key = entry.keyspace_key;
    let ks = entry.keyspace_id;

    if length == 0 {
        match crate::state::state_put(ks, key, &[]) {
            Ok(()) => 0,
            Err(_) => -ENOSPC,
        }
    } else {
        match crate::state::state_get(ks, key) {
            Some((value, value_len)) => {
                let new_len = (length as usize).min(value_len);
                match crate::state::state_put(ks, key, &value[..new_len]) {
                    Ok(()) => 0,
                    Err(_) => -ENOSPC,
                }
            }
            None => {
                // File doesn't exist; create zero-filled content.
                let zeros = [0u8; MAX_VALUE_SIZE];
                let new_len = (length as usize).min(MAX_VALUE_SIZE);
                match crate::state::state_put(ks, key, &zeros[..new_len]) {
                    Ok(()) => 0,
                    Err(_) => -ENOSPC,
                }
            }
        }
    }
}

// ── sys_ioctl ──────────────────────────────────────────────────────────────

/// Device I/O control.
///
/// Terminal ioctls return `-ENOTTY` so that `isatty()` reports false
/// and programs use non-interactive mode. TCGETS on any fd returns
/// ENOTTY (matching Linux behavior for non-terminals); CPython and
/// Java call ioctl(TCGETS) on regular file fds during startup.
/// All other ioctls on regular fds return `-EINVAL`.
pub fn sys_ioctl(agent_id: u16, fd: i32, cmd: u64, arg: u64) -> i64 {
    let _ = arg;

    const TCGETS: u64 = 0x5401;
    const TIOCGWINSZ: u64 = 0x5413;
    const ENOTTY: i64 = 25;

    // TCGETS on any fd returns ENOTTY — matches Linux behavior for non-terminals.
    // CPython and Java call ioctl(TCGETS) on regular file fds during startup.
    if cmd == TCGETS {
        return -ENOTTY;
    }

    // stdin / stdout / stderr → not a tty for window-size queries too
    if fd == 0 || fd == 1 || fd == 2 {
        if cmd == TIOCGWINSZ {
            return -ENOTTY;
        }
    }

    let st = match state::get_state(agent_id) {
        Some(s) => s,
        None => return -EBADF,
    };

    match st.get_fd(fd) {
        Some(e) if e.active => -EINVAL, // no ioctls for regular fds
        _ => -EBADF,
    }
}

// ── Preserved stubs from original file ─────────────────────────────────────
// These were in the original stub file and are kept for backward compatibility.

/// open(path, flags, mode) -> fd — delegates to sys_openat with AT_FDCWD
pub fn sys_open(agent_id: u16, path_ptr: u64, flags: u32, mode: u32) -> i64 {
    sys_openat(agent_id, AT_FDCWD, path_ptr, flags, mode)
}

/// stat(path, statbuf) -> 0 or error
pub fn sys_stat(agent_id: u16, path_ptr: u64, statbuf: u64) -> i64 {
    sys_newfstatat(agent_id, AT_FDCWD, path_ptr, statbuf, 0)
}

/// lstat(path, statbuf) -> 0 or error (no symlinks, same as stat)
pub fn sys_lstat(agent_id: u16, path_ptr: u64, statbuf: u64) -> i64 {
    sys_stat(agent_id, path_ptr, statbuf)
}

/// poll(fds, nfds, timeout) -> ready count
///
/// Checks fd readiness deterministically. Files are always ready,
/// sockets/pipes report writable, eventfds check counter > 0.
/// Iterates fds in ascending order for determinism.
pub fn sys_poll(agent_id: u16, fds: u64, nfds: u64, _timeout: i32) -> i64 {
    // struct pollfd { int fd; short events; short revents; } = 8 bytes
    const POLLFD_SIZE: u64 = 8;
    const POLLIN: i16 = 0x0001;
    const POLLOUT: i16 = 0x0004;
    const POLLNVAL: i16 = 0x0020;

    let st = match state::get_state(agent_id) {
        Some(s) => s,
        None => return -EINVAL,
    };

    let count = nfds.min(256) as usize;
    let mut ready: i64 = 0;

    for i in 0..count {
        let pfd_addr = fds + (i as u64) * POLLFD_SIZE;
        let fd = unsafe { core::ptr::read(pfd_addr as *const i32) };
        let events = unsafe { core::ptr::read((pfd_addr + 4) as *const i16) };

        let revents: i16 = match st.get_fd(fd) {
            Some(entry) if entry.active => {
                let mut r: i16 = 0;
                match entry.kind {
                    FdKind::File | FdKind::Directory => {
                        // Files are always ready for read and write
                        if events & POLLIN != 0 {
                            r |= POLLIN;
                        }
                        if events & POLLOUT != 0 {
                            r |= POLLOUT;
                        }
                    }
                    FdKind::Socket | FdKind::Pipe => {
                        if events & POLLOUT != 0 {
                            r |= POLLOUT;
                        }
                        if events & POLLIN != 0 {
                            if let Some(mb) = crate::mailbox::get_mailbox(entry.mailbox_id) {
                                if !mb.is_empty() {
                                    r |= POLLIN;
                                }
                            }
                        }
                    }
                    FdKind::EventFd => {
                        // Readable if counter > 0 (counter stored in keyspace_key)
                        if events & POLLIN != 0 && entry.keyspace_key > 0 {
                            r |= POLLIN;
                        }
                        if events & POLLOUT != 0 {
                            r |= POLLOUT;
                        }
                    }
                    FdKind::Epoll => {}
                }
                r
            }
            _ => POLLNVAL,
        };

        // Write revents back to user memory
        unsafe {
            core::ptr::write((pfd_addr + 6) as *mut i16, revents);
        }

        if revents != 0 {
            ready += 1;
        }
    }

    ready
}

/// pwrite64 stub
pub fn sys_pwrite64(agent_id: u16, fd: i32, buf_ptr: u64, count: u64, offset: u64) -> i64 {
    let st = match state::get_state(agent_id) {
        Some(s) => s,
        None => return -EBADF,
    };

    let entry = match st.get_fd(fd) {
        Some(e) if e.active => e,
        _ => return -EBADF,
    };

    if entry.kind != FdKind::File {
        if entry.kind == FdKind::Directory {
            return -EISDIR;
        }
        return -EINVAL;
    }

    // Read user data and store to keyspace (offset is informational;
    // keyspace values are treated as blobs).
    let _ = offset;
    let to_write = (count as usize).min(MAX_VALUE_SIZE);
    let mut value = [0u8; MAX_VALUE_SIZE];
    unsafe {
        read_user_mem(buf_ptr, &mut value, to_write);
    }
    match crate::state::state_put(entry.keyspace_id, entry.keyspace_key, &value[..to_write]) {
        Ok(()) => to_write as i64,
        Err(_) => -ENOSPC,
    }
}

/// readv — scatter-gather read
pub fn sys_readv(agent_id: u16, fd: i32, iov_ptr: u64, iovcnt: u64) -> i64 {
    let mut total: i64 = 0;
    for i in 0..iovcnt as usize {
        let iov_addr = iov_ptr + (i * 16) as u64;
        let base = unsafe { core::ptr::read(iov_addr as *const u64) };
        let len = unsafe { core::ptr::read((iov_addr + 8) as *const u64) };
        if len > 0 {
            let result = sys_read(agent_id, fd, base, len);
            if result < 0 {
                return if total > 0 { total } else { result };
            }
            total += result;
            if (result as u64) < len {
                break; // short read — don't continue to next iovec
            }
        }
    }
    total
}

/// writev — scatter-gather write
pub fn sys_writev(agent_id: u16, fd: i32, iov_ptr: u64, iovcnt: u64) -> i64 {
    let mut total: i64 = 0;
    for i in 0..iovcnt as usize {
        let iov_addr = iov_ptr + (i * 16) as u64;
        let base = unsafe { core::ptr::read(iov_addr as *const u64) };
        let len = unsafe { core::ptr::read((iov_addr + 8) as *const u64) };
        if len > 0 {
            let result = sys_write(agent_id, fd, base, len);
            if result < 0 {
                return if total > 0 { total } else { result };
            }
            total += result;
        }
    }
    total
}

/// pipe(pipefd[2]) -> 0 or error
pub fn sys_pipe(agent_id: u16, pipefd_ptr: u64) -> i64 {
    let st = match state::get_state_mut(agent_id) {
        Some(s) => s,
        None => return -EBADF,
    };

    let read_fd = match st.alloc_fd() {
        Some(f) => f,
        None => return -EMFILE,
    };
    st.fd_table[read_fd] = Some(FdEntry {
        kind: FdKind::Pipe,
        keyspace_key: 0,
        keyspace_id: 0,
        mailbox_id: agent_id,
        offset: 0,
        flags: O_RDONLY,
        active: true,
    });

    let write_fd = match st.alloc_fd() {
        Some(f) => f,
        None => {
            st.fd_table[read_fd] = None;
            return -EMFILE;
        }
    };
    st.fd_table[write_fd] = Some(FdEntry {
        kind: FdKind::Pipe,
        keyspace_key: 0,
        keyspace_id: 0,
        mailbox_id: agent_id,
        offset: 0,
        flags: O_WRONLY,
        active: true,
    });

    unsafe {
        let ptr = pipefd_ptr as *mut i32;
        core::ptr::write(ptr, read_fd as i32);
        core::ptr::write(ptr.add(1), write_fd as i32);
    }
    0
}

/// pipe2(pipefd, flags)
pub fn sys_pipe2(agent_id: u16, pipefd_ptr: u64, _flags: i32) -> i64 {
    sys_pipe(agent_id, pipefd_ptr)
}

/// select(nfds, readfds, writefds, exceptfds, timeout) -> ready count
///
/// Checks fd readiness deterministically for the fd_set bitmasks.
/// fd_set is a 128-byte (1024-bit) bitmask; we only check up to nfds.
pub fn sys_select(
    agent_id: u16,
    nfds: u64,
    readfds: u64,
    writefds: u64,
    _exceptfds: u64,
    _timeout: u64,
) -> i64 {
    let st = match state::get_state(agent_id) {
        Some(s) => s,
        None => return -EINVAL,
    };

    let max_fd = nfds.min(256) as i32;
    let mut ready: i64 = 0;

    // Helper: test bit in fd_set (128-byte bitmask)
    let test_bit = |set_ptr: u64, fd: i32| -> bool {
        if set_ptr == 0 {
            return false;
        }
        let byte_idx = (fd / 8) as u64;
        let bit_idx = (fd % 8) as u8;
        let byte_val = unsafe { core::ptr::read((set_ptr + byte_idx) as *const u8) };
        byte_val & (1 << bit_idx) != 0
    };

    // Helper: set bit in fd_set
    let set_bit = |set_ptr: u64, fd: i32| {
        if set_ptr == 0 {
            return;
        }
        let byte_idx = (fd / 8) as u64;
        let bit_idx = (fd % 8) as u8;
        unsafe {
            let ptr = (set_ptr + byte_idx) as *mut u8;
            *ptr |= 1 << bit_idx;
        }
    };

    // Helper: clear bit in fd_set
    let clear_bit = |set_ptr: u64, fd: i32| {
        if set_ptr == 0 {
            return;
        }
        let byte_idx = (fd / 8) as u64;
        let bit_idx = (fd % 8) as u8;
        unsafe {
            let ptr = (set_ptr + byte_idx) as *mut u8;
            *ptr &= !(1 << bit_idx);
        }
    };

    // First pass: clear all result bits
    for fd in 0..max_fd {
        if readfds != 0 {
            clear_bit(readfds, fd);
        }
        if writefds != 0 {
            clear_bit(writefds, fd);
        }
    }

    // Second pass: check readiness for each fd in ascending order (deterministic)
    for fd in 0..max_fd {
        let check_read = test_bit(readfds, fd) || (readfds != 0);
        let check_write = test_bit(writefds, fd) || (writefds != 0);

        if !check_read && !check_write {
            continue;
        }

        if let Some(entry) = st.get_fd(fd) {
            if !entry.active {
                continue;
            }

            let (can_read, can_write) = match entry.kind {
                FdKind::File | FdKind::Directory => (true, true),
                FdKind::Socket | FdKind::Pipe => {
                    let readable = crate::mailbox::get_mailbox(entry.mailbox_id)
                        .map(|mb| !mb.is_empty())
                        .unwrap_or(false);
                    (readable, true)
                }
                FdKind::EventFd => (entry.keyspace_key > 0, true),
                FdKind::Epoll => (false, false),
            };

            let mut marked = false;
            if can_read && readfds != 0 {
                set_bit(readfds, fd);
                marked = true;
            }
            if can_write && writefds != 0 {
                set_bit(writefds, fd);
                marked = true;
            }
            if marked {
                ready += 1;
            }
        }
    }

    ready
}

/// dup2(oldfd, newfd) -> newfd
pub fn sys_dup2(agent_id: u16, oldfd: i32, newfd: i32) -> i64 {
    if newfd < 0 || newfd as usize >= MAX_FDS {
        return -EBADF;
    }
    let st = match state::get_state_mut(agent_id) {
        Some(s) => s,
        None => return -EBADF,
    };
    let entry = match st.get_fd(oldfd) {
        Some(e) if e.active => *e,
        _ => return -EBADF,
    };
    st.close_fd(newfd);
    let cloned = match clone_fd_entry(st, entry) {
        Ok(e) => e,
        Err(e) => return e,
    };
    st.fd_table[newfd as usize] = Some(cloned);
    newfd as i64
}

/// fsync stub — always succeeds (keyspace is always "synced")
pub fn sys_fsync(agent_id: u16, fd: i32) -> i64 {
    let st = match state::get_state(agent_id) {
        Some(s) => s,
        None => return -EBADF,
    };
    match st.get_fd(fd) {
        Some(e) if e.active => 0,
        _ => -EBADF,
    }
}

/// chdir(path)
pub fn sys_chdir(agent_id: u16, path_ptr: u64) -> i64 {
    let mut path_buf = [0u8; MAX_PATH];
    let path_len = unsafe { read_pathname(path_ptr, &mut path_buf) };
    if path_len == 0 {
        return -ENOENT;
    }

    let mut norm_buf = [0u8; MAX_PATH];
    let path = normalized_path(&path_buf[..path_len], &mut norm_buf);

    if !is_directory_path(path) {
        return -ENOTDIR;
    }

    let st = match state::get_state_mut(agent_id) {
        Some(s) => s,
        None => return -EFAULT,
    };

    let copy_len = path.len().min(st.cwd.len());
    st.cwd[..copy_len].copy_from_slice(&path[..copy_len]);
    st.cwd_len = copy_len as u16;
    0
}
