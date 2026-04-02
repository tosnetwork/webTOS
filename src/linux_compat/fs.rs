//! File-system related Linux syscall implementations.
//!
//! Translates Linux file I/O syscalls into TOS keyspace state operations.
//! Files are backed by the agent's private keyspace; pipes and sockets map
//! to TOS mailbox IPC.

use alloc::vec::Vec;
use super::constants::*;
use super::state::{self, FdEntry, FdKind, LinuxAgentState, MAX_FDS, MAX_PATH};
use core::fmt::{self, Write};
use sha2::{Digest, Sha256};

// ── Seek whence values ─────────────────────────────────────────────────────

const SEEK_SET: u32 = 0;
const SEEK_CUR: u32 = 1;
const SEEK_END: u32 = 2;
const O_ACCMODE: u32 = 3;
const EFD_SEMAPHORE: u32 = 0x1;

// ── fcntl commands ─────────────────────────────────────────────────────────

const F_DUPFD: u32 = 0;
const F_DUPFD_CLOEXEC: u32 = 1030;
const F_GETFD: u32 = 1;
const F_SETFD: u32 = 2;
const F_GETFL: u32 = 3;
const F_SETFL: u32 = 4;

// ── AT constants ───────────────────────────────────────────────────────────

const AT_FDCWD: i32 = -100;
const AT_SYMLINK_NOFOLLOW: u32 = 0x100;
const AT_REMOVEDIR: u32 = 0x200;
const AT_EACCESS: u32 = 0x200;
const AT_EMPTY_PATH: u32 = 0x1000;
const RENAME_NOREPLACE: u32 = 0x1;
const RENAME_EXCHANGE: u32 = 0x2;
const RENAME_WHITEOUT: u32 = 0x4;

// ── Limits ─────────────────────────────────────────────────────────────────

const MAX_VALUE_SIZE: usize = 256;
const DT_CHR: u8 = 2;
const DT_DIR: u8 = 4;
const DT_REG: u8 = 8;
const DT_LNK: u8 = 10;
const MAX_DIRENT_NAME: usize = 128;
const MAX_DIRENTS_COLLECT: usize = 256;
const ESPIPE: i64 = 29;
const S_IFIFO: u32 = 0x1000;
const S_IFCHR: u32 = 0x2000;
const S_IFDIR: u32 = 0x4000;
const S_IFREG: u32 = 0x8000;
const S_IFSOCK: u32 = 0xC000;
const S_IFLNK: u32 = 0xA000;
const MODE_FIFO_0600: u32 = S_IFIFO | 0o600;
const MODE_DIR_0755: u32 = S_IFDIR | 0o755;
const MODE_REG_0644: u32 = S_IFREG | 0o644;
const MODE_CHR_0666: u32 = S_IFCHR | 0o666;
const MODE_LNK_0777: u32 = S_IFLNK | 0o777;
const MODE_SOCK_0777: u32 = S_IFSOCK | 0o777;
const TMPFS_MAGIC: u64 = 0x0102_1994;
const PROC_SUPER_MAGIC: u64 = 0x0000_9fa0;
const SYSFS_MAGIC: u64 = 0x6265_6572;
const DEVTMPFS_MAGIC: u64 = 0x0000_1373;
const EXT4_SUPER_MAGIC: u64 = 0x0000_ef53;
const PROC_SELF_CGROUP_CONTENT: &[u8] = b"0::/\n";
const PROC_MEMINFO_CONTENT: &[u8] = b"MemTotal:        524288 kB\nMemFree:         262144 kB\nMemAvailable:    262144 kB\nSwapTotal:            0 kB\nSwapFree:             0 kB\n";
const PROC_VERSION_SIGNATURE_CONTENT: &[u8] = b"Ubuntu 6.8.0-106.106~22.04.1-generic 6.8.12\n";
const SYS_CPU_ONLINE_CONTENT: &[u8] = b"0-0\n";
const SYS_CGROUP_LIMIT_CONTENT: &[u8] = b"max\n";

// ── Helpers ────────────────────────────────────────────────────────────────

fn agent_cr3(agent_id: u16) -> Option<u64> {
    crate::agent::get_agent(agent_id)
        .map(|agent| agent.context.cr3)
        .filter(|cr3| *cr3 != 0)
}

fn ensure_user_range_mapped(agent_id: u16, user_addr: u64, len: usize, write: bool) -> bool {
    let Some(cr3) = agent_cr3(agent_id) else {
        return false;
    };
    if len == 0 {
        return true;
    }

    let start = user_addr & !(crate::arch::x86_64::paging::PAGE_SIZE as u64 - 1);
    let end_addr = user_addr.saturating_add(len.saturating_sub(1) as u64);
    let end = end_addr & !(crate::arch::x86_64::paging::PAGE_SIZE as u64 - 1);
    let mut page = start;
    let fault_code = if write { 0x2 } else { 0x0 };

    loop {
        if crate::arch::x86_64::page_table::translate_user_vaddr(cr3, page).is_none()
            && !crate::linux_compat::memory::handle_user_page_fault(agent_id, page, fault_code)
        {
            return false;
        }
        if page == end {
            break;
        }
        page = page.saturating_add(crate::arch::x86_64::paging::PAGE_SIZE as u64);
    }

    true
}

fn copy_to_user(agent_id: u16, user_addr: u64, src: &[u8]) -> bool {
    let Some(cr3) = agent_cr3(agent_id) else {
        return false;
    };
    if !ensure_user_range_mapped(agent_id, user_addr, src.len(), true) {
        return false;
    }
    crate::arch::x86_64::page_table::copy_to_user(cr3, user_addr, src)
}

fn copy_from_user(agent_id: u16, user_addr: u64, dst: &mut [u8]) -> bool {
    let Some(cr3) = agent_cr3(agent_id) else {
        return false;
    };
    if !ensure_user_range_mapped(agent_id, user_addr, dst.len(), false) {
        return false;
    }
    crate::arch::x86_64::page_table::copy_from_user(cr3, user_addr, dst)
}

fn read_user_u64(agent_id: u16, user_addr: u64) -> Option<u64> {
    let mut bytes = [0u8; 8];
    copy_from_user(agent_id, user_addr, &mut bytes).then(|| u64::from_ne_bytes(bytes))
}

fn read_user_i32(agent_id: u16, user_addr: u64) -> Option<i32> {
    let mut bytes = [0u8; 4];
    copy_from_user(agent_id, user_addr, &mut bytes).then(|| i32::from_ne_bytes(bytes))
}

fn read_user_i16(agent_id: u16, user_addr: u64) -> Option<i16> {
    let mut bytes = [0u8; 2];
    copy_from_user(agent_id, user_addr, &mut bytes).then(|| i16::from_ne_bytes(bytes))
}

fn fd_access_mode(flags: u32) -> u32 {
    flags & O_ACCMODE
}

fn fd_allows_read(kind: FdKind, flags: u32) -> bool {
    match kind {
        FdKind::Directory => true,
        FdKind::File | FdKind::Pipe => fd_access_mode(flags) != O_WRONLY,
        FdKind::Socket | FdKind::EventFd | FdKind::TimerFd => true,
        FdKind::Epoll => false,
    }
}

fn fd_allows_write(kind: FdKind, flags: u32) -> bool {
    match kind {
        FdKind::Directory => false,
        FdKind::File | FdKind::Pipe => fd_access_mode(flags) != O_RDONLY,
        FdKind::Socket | FdKind::EventFd => true,
        FdKind::TimerFd => false,
        FdKind::Epoll => false,
    }
}

#[inline]
fn eventfd_handle(entry: &FdEntry) -> Option<u16> {
    (entry.kind == FdKind::EventFd).then_some(entry.keyspace_key as u16)
}

fn timerfd_handle(entry: &FdEntry) -> Option<u16> {
    (entry.kind == FdKind::TimerFd).then_some(entry.keyspace_key as u16)
}

/// Hash a pathname to a deterministic u64 keyspace key using the first 8
/// bytes of its SHA-256 digest.
fn path_to_key(path: &[u8]) -> u64 {
    let hash = Sha256::digest(path);
    u64::from_le_bytes([
        hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
    ])
}

/// Read a null-terminated pathname from user memory (max `MAX_PATH` bytes).
/// Returns the byte count (excluding the null terminator).
fn read_pathname(agent_id: u16, ptr: u64, buf: &mut [u8; MAX_PATH]) -> Result<usize, i64> {
    if ptr == 0 {
        return Err(-EFAULT);
    }
    let mut len = 0usize;
    let mut byte = [0u8; 1];
    while len < MAX_PATH {
        if !copy_from_user(agent_id, ptr + len as u64, &mut byte) {
            return Err(-EFAULT);
        }
        if byte[0] == 0 {
            break;
        }
        buf[len] = byte[0];
        len += 1;
    }
    Ok(len)
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

fn dirfd_base_path(agent_id: u16, dirfd: i32, dst: &mut [u8; MAX_PATH]) -> Result<usize, i64> {
    if dirfd == AT_FDCWD {
        let st = state::get_state(agent_id).ok_or(-EBADF)?;
        let cwd_len = st.cwd_len as usize;
        let copy_len = cwd_len.min(MAX_PATH);
        dst[..copy_len].copy_from_slice(&st.cwd[..copy_len]);
        return Ok(copy_len.max(1));
    }

    let st = state::get_files_state(agent_id).ok_or(-EBADF)?;
    let entry = match st.get_fd(dirfd) {
        Some(e) if e.active => *e,
        _ => return Err(-EBADF),
    };
    if entry.kind != FdKind::Directory {
        return Err(-ENOTDIR);
    }
    let handle = st
        .get_directory_handle(entry.keyspace_key as u16)
        .ok_or(-EBADF)?;
    let copy_len = (handle.path_len as usize).min(MAX_PATH);
    dst[..copy_len].copy_from_slice(&handle.path[..copy_len]);
    Ok(copy_len.max(1))
}

fn resolve_path_at<'a>(
    agent_id: u16,
    dirfd: i32,
    raw: &[u8],
    dst: &'a mut [u8; MAX_PATH],
) -> Result<&'a [u8], i64> {
    if raw.is_empty() {
        return Err(-ENOENT);
    }
    if raw[0] == b'/' {
        let len = normalize_absolute_path(raw, dst);
        return Ok(&dst[..len]);
    }

    let mut base = [0u8; MAX_PATH];
    let base_len = dirfd_base_path(agent_id, dirfd, &mut base)?;
    let mut combined = [0u8; MAX_PATH];
    let mut len = 0usize;

    let normalized_base_len = normalize_absolute_path(&base[..base_len], &mut combined);
    len = normalized_base_len;
    if len == 0 {
        combined[0] = b'/';
        len = 1;
    }

    if len > 1 && combined[len - 1] != b'/' {
        if len >= MAX_PATH {
            return Err(-EINVAL);
        }
        combined[len] = b'/';
        len += 1;
    }

    if len + raw.len() > MAX_PATH {
        return Err(-EINVAL);
    }
    combined[len..len + raw.len()].copy_from_slice(raw);
    len += raw.len();

    let norm_len = normalize_absolute_path(&combined[..len], dst);
    Ok(&dst[..norm_len])
}

/// Copy bytes from a kernel buffer to user memory.
#[inline]
fn write_user_mem(agent_id: u16, dst: u64, src: &[u8]) -> bool {
    src.is_empty() || copy_to_user(agent_id, dst, src)
}

/// Copy bytes from user memory into a kernel buffer.
#[inline]
fn read_user_mem(agent_id: u16, src: u64, dst: &mut [u8], len: usize) -> bool {
    len == 0 || copy_from_user(agent_id, src, &mut dst[..len])
}

/// Read file data from a keyspace at the given offset into user memory.
///
/// Handles both small values (≤256 bytes via state_get) and large files
/// stored via store_multi_segment. Returns the number of bytes copied.
fn read_file_data(
    agent_id: u16,
    keyspace: u16,
    key: u64,
    offset: usize,
    buf_ptr: u64,
    count: usize,
) -> Result<usize, i64> {
    if let Some(special) = special_file_for_key(key) {
        return read_special_file_data(agent_id, special, offset, buf_ptr, count);
    }

    // Embedded base-image files are stored as whole byte blobs in the kernel
    // image. Large ones synthesize a 6-byte size/count header for `state_get`,
    // but regular file I/O must expose the actual file contents, not that
    // storage metadata.
    if keyspace == super::vfs::BASE_IMAGE_KEYSPACE {
        if let Some(entry) = crate::base_image::find_by_key(key) {
            if offset >= entry.data.len() {
                return Ok(0);
            }
            let to_copy = count.min(entry.data.len() - offset);
            if !write_user_mem(agent_id, buf_ptr, &entry.data[offset..offset + to_copy]) {
                return Err(-EFAULT);
            }
            return Ok(to_copy);
        }
    }

    // Try small value first
    if let Some((value, value_len)) = crate::state::state_get(keyspace, key) {
        if crate::state::parse_multi_segment_header(keyspace, key, &value[..value_len], value_len)
            .is_some()
        {
            return read_multi_segment_at(agent_id, keyspace, key, offset, buf_ptr, count);
        }
        // Plain small value
        if offset >= value_len {
            return Ok(0);
        }
        let available = value_len - offset;
        let to_copy = count.min(available);
        if !write_user_mem(agent_id, buf_ptr, &value[offset..offset + to_copy]) {
            return Err(-EFAULT);
        }
        return Ok(to_copy);
    }
    Ok(0)
}

fn try_alloc_zeroed_vec(len: usize) -> Result<Vec<u8>, i64> {
    let mut data = Vec::new();
    data.try_reserve_exact(len).map_err(|_| -ENOMEM)?;
    data.resize(len, 0);
    Ok(data)
}

fn try_clone_vec(bytes: &[u8]) -> Result<Vec<u8>, i64> {
    let mut data = Vec::new();
    data.try_reserve_exact(bytes.len()).map_err(|_| -ENOMEM)?;
    data.extend_from_slice(bytes);
    Ok(data)
}

fn load_regular_file_data(keyspace: u16, key: u64) -> Result<Vec<u8>, i64> {
    if keyspace == super::vfs::BASE_IMAGE_KEYSPACE {
        if let Some(entry) = crate::base_image::find_by_key(key) {
            return try_clone_vec(entry.data);
        }
    }

    if let Some((value, value_len)) = crate::state::state_get(keyspace, key) {
        if crate::state::parse_multi_segment_header(keyspace, key, &value[..value_len], value_len)
            .is_none()
        {
            return try_clone_vec(&value[..value_len]);
        }
    }

    let size = crate::state::query_file_size(keyspace, key);
    if size == 0 {
        return Ok(Vec::new());
    }

    let mut data = match try_alloc_zeroed_vec(size) {
        Ok(data) => data,
        Err(err) => {
            let header = crate::state::state_get(keyspace, key)
                .map(|(buf, len)| {
                    let mut bytes = [0u8; 6];
                    let copy_len = len.min(bytes.len());
                    bytes[..copy_len].copy_from_slice(&buf[..copy_len]);
                    (len, bytes)
                })
                .unwrap_or((0, [0u8; 6]));
            crate::serial_println!(
                "[RTDBG] load-file-alloc-fail ks={} key={:#x} size={} value_len={} hdr=[{:#x},{:#x},{:#x},{:#x},{:#x},{:#x}] err={}",
                keyspace,
                key,
                size,
                header.0,
                header.1[0],
                header.1[1],
                header.1[2],
                header.1[3],
                header.1[4],
                header.1[5],
                err
            );
            return Err(err);
        }
    };
    let loaded = crate::state::load_file_range(keyspace, key, 0, &mut data);
    data.truncate(loaded);
    Ok(data)
}

fn store_regular_file_data(keyspace: u16, key: u64, data: &[u8]) -> Result<(), i64> {
    if data.len() <= MAX_VALUE_SIZE {
        crate::state::state_put(keyspace, key, data)
    } else {
        crate::state::store_multi_segment(keyspace, key, data)
    }
}

fn log_regular_file_store_failure(agent_id: u16, keyspace: u16, key: u64, data_len: usize, err: i64) {
    if state::trace_runtime_agent(agent_id) {
        let entry_count = crate::state::iter_entries(keyspace, |_, _| true);
        crate::serial_println!(
            "[RTDBG] file-store-fail agent={} ks={} key={:#x} len={} err={} entries={}",
            agent_id,
            keyspace,
            key,
            data_len,
            err,
            entry_count
        );
    }
}

fn write_regular_file_bytes(
    agent_id: u16,
    keyspace: u16,
    key: u64,
    current_offset: u64,
    flags: u32,
    incoming: &[u8],
) -> Result<(usize, u64), i64> {
    let count = incoming.len();
    let current_len = crate::state::query_file_size(keyspace, key).max(
        crate::state::state_get(keyspace, key)
            .map(|(_, len)| len)
            .unwrap_or(0),
    );
    let write_offset = if (flags & O_APPEND) != 0 {
        current_len
    } else {
        current_offset as usize
    };
    let write_end = write_offset.checked_add(count).ok_or(-EINVAL)?;

    if write_offset == current_len {
        let next_len = crate::state::append_file_data(keyspace, key, &incoming).map_err(|err| {
            if err == crate::agent::E_QUOTA_EXCEEDED {
                -ENOSPC
            } else {
                -ENOMEM
            }
        })?;
        return Ok((count, next_len as u64));
    }

    let mut file_data = load_regular_file_data(keyspace, key)?;

    if file_data.len() < write_end {
        file_data.resize(write_end, 0);
    }
    file_data[write_offset..write_end].copy_from_slice(&incoming);

    if let Err(err) = store_regular_file_data(keyspace, key, &file_data) {
        log_regular_file_store_failure(agent_id, keyspace, key, file_data.len(), err);
        return Err(-ENOSPC);
    }
    Ok((count, write_end as u64))
}

fn write_regular_file_data(
    agent_id: u16,
    keyspace: u16,
    key: u64,
    current_offset: u64,
    flags: u32,
    buf_ptr: u64,
    count: usize,
) -> Result<(usize, u64), i64> {
    const INLINE_WRITE_BUF: usize = 4096;

    if count <= INLINE_WRITE_BUF {
        let mut incoming = [0u8; INLINE_WRITE_BUF];
        if count > 0 && !read_user_mem(agent_id, buf_ptr, &mut incoming[..count], count) {
            return Err(-EFAULT);
        }
        return write_regular_file_bytes(
            agent_id,
            keyspace,
            key,
            current_offset,
            flags,
            &incoming[..count],
        );
    }

    let mut incoming = try_alloc_zeroed_vec(count)?;
    if count > 0 && !read_user_mem(agent_id, buf_ptr, &mut incoming, count) {
        return Err(-EFAULT);
    }

    write_regular_file_bytes(agent_id, keyspace, key, current_offset, flags, &incoming)
}

/// Read from a multi-segment file at a given offset into user memory.
fn read_multi_segment_at(
    agent_id: u16,
    keyspace: u16,
    key: u64,
    offset: usize,
    buf_ptr: u64,
    count: usize,
) -> Result<usize, i64> {
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
        if !write_user_mem(agent_id, buf_ptr + copied as u64, &scratch[..loaded]) {
            return Err(-EFAULT);
        }
        copied += loaded;
        if loaded < chunk_len {
            break;
        }
    }

    Ok(copied)
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

#[derive(Clone, Copy)]
struct LinuxStatMeta {
    st_dev: u64,
    st_ino: u64,
    st_mode: u32,
    st_nlink: u64,
    st_uid: u32,
    st_gid: u32,
    st_rdev: u64,
    st_size: u64,
    st_blksize: u64,
    st_blocks: u64,
}

fn agent_uid_gid(agent_id: u16) -> (u32, u32) {
    match state::get_state(agent_id) {
        Some(st) => (st.uid, st.gid),
        None => (1000, 1000),
    }
}

fn metadata_for_directory(agent_id: u16, ino: u64) -> LinuxStatMeta {
    let (uid, gid) = agent_uid_gid(agent_id);
    LinuxStatMeta {
        st_dev: 0x100,
        st_ino: ino,
        st_mode: MODE_DIR_0755,
        st_nlink: 2,
        st_uid: uid,
        st_gid: gid,
        st_rdev: 0,
        st_size: 0,
        st_blksize: 4096,
        st_blocks: 0,
    }
}

fn metadata_for_regular(agent_id: u16, file_size: u64, st_dev: u64, st_ino: u64) -> LinuxStatMeta {
    let (uid, gid) = agent_uid_gid(agent_id);
    LinuxStatMeta {
        st_dev,
        st_ino,
        st_mode: MODE_REG_0644,
        st_nlink: 1,
        st_uid: uid,
        st_gid: gid,
        st_rdev: 0,
        st_size: file_size,
        st_blksize: 4096,
        st_blocks: (file_size + 511) / 512,
    }
}

fn metadata_for_pipe(agent_id: u16, handle: u16) -> LinuxStatMeta {
    let (uid, gid) = agent_uid_gid(agent_id);
    LinuxStatMeta {
        st_dev: 0x103,
        st_ino: stat_ino_for_key(handle as u64),
        st_mode: MODE_FIFO_0600,
        st_nlink: 1,
        st_uid: uid,
        st_gid: gid,
        st_rdev: 0,
        st_size: 0,
        st_blksize: 4096,
        st_blocks: 0,
    }
}

fn metadata_for_socket(agent_id: u16, mailbox_id: u16) -> LinuxStatMeta {
    let (uid, gid) = agent_uid_gid(agent_id);
    LinuxStatMeta {
        st_dev: 0x104,
        st_ino: stat_ino_for_key(mailbox_id as u64),
        st_mode: MODE_SOCK_0777,
        st_nlink: 1,
        st_uid: uid,
        st_gid: gid,
        st_rdev: 0,
        st_size: 0,
        st_blksize: 4096,
        st_blocks: 0,
    }
}

fn metadata_for_eventfd(agent_id: u16, handle: u16) -> LinuxStatMeta {
    let (uid, gid) = agent_uid_gid(agent_id);
    LinuxStatMeta {
        st_dev: 0x105,
        st_ino: stat_ino_for_key(handle as u64),
        st_mode: 0o600,
        st_nlink: 1,
        st_uid: uid,
        st_gid: gid,
        st_rdev: 0,
        st_size: 0,
        st_blksize: 4096,
        st_blocks: 0,
    }
}

fn metadata_for_timerfd(agent_id: u16, handle: u16) -> LinuxStatMeta {
    let (uid, gid) = agent_uid_gid(agent_id);
    LinuxStatMeta {
        st_dev: 0x107,
        st_ino: stat_ino_for_key(handle as u64),
        st_mode: 0o600,
        st_nlink: 1,
        st_uid: uid,
        st_gid: gid,
        st_rdev: 0,
        st_size: 0,
        st_blksize: 4096,
        st_blocks: 0,
    }
}

fn metadata_for_special(agent_id: u16, special: super::vfs::SpecialFile) -> LinuxStatMeta {
    let (uid, gid) = agent_uid_gid(agent_id);
    match special {
        super::vfs::SpecialFile::Null => LinuxStatMeta {
            st_dev: 0x101,
            st_ino: 3,
            st_mode: MODE_CHR_0666,
            st_nlink: 1,
            st_uid: uid,
            st_gid: gid,
            st_rdev: 0x103,
            st_size: 0,
            st_blksize: 4096,
            st_blocks: 0,
        },
        super::vfs::SpecialFile::Urandom => LinuxStatMeta {
            st_dev: 0x101,
            st_ino: 9,
            st_mode: MODE_CHR_0666,
            st_nlink: 1,
            st_uid: uid,
            st_gid: gid,
            st_rdev: 0x109,
            st_size: 0,
            st_blksize: 4096,
            st_blocks: 0,
        },
        super::vfs::SpecialFile::ProcSelfMaps
        | super::vfs::SpecialFile::ProcSelfCgroup
        | super::vfs::SpecialFile::ProcMeminfo
        | super::vfs::SpecialFile::ProcVersionSignature
        | super::vfs::SpecialFile::SysCpuOnline
        | super::vfs::SpecialFile::SysCgroupMemoryMax
        | super::vfs::SpecialFile::SysCgroupMemoryHigh => LinuxStatMeta {
            st_dev: 0x102,
            st_ino: stat_ino_for_key(special_file_key(special)),
            st_mode: MODE_REG_0644,
            st_nlink: 1,
            st_uid: uid,
            st_gid: gid,
            st_rdev: 0,
            st_size: special_file_size(agent_id, special),
            st_blksize: 4096,
            st_blocks: 0,
        },
        super::vfs::SpecialFile::ProcSelfExe => {
            let target_len = match state::get_state(agent_id) {
                Some(st) if st.exe_path_len > 0 => st.exe_path_len as u64,
                _ => 11,
            };
            LinuxStatMeta {
                st_dev: 0x102,
                st_ino: path_to_key(b"/proc/self/exe"),
                st_mode: MODE_LNK_0777,
                st_nlink: 1,
                st_uid: uid,
                st_gid: gid,
                st_rdev: 0,
                st_size: target_len,
                st_blksize: 4096,
                st_blocks: 0,
            }
        }
    }
}

fn metadata_for_fd(agent_id: u16, entry: &FdEntry) -> LinuxStatMeta {
    if entry.kind == FdKind::Directory {
        return metadata_for_directory(agent_id, 1);
    }
    if let Some(special) = special_file_for_fd(entry) {
        return metadata_for_special(agent_id, special);
    }

    match entry.kind {
        FdKind::File => metadata_for_regular(
            agent_id,
            crate::state::query_file_size(entry.keyspace_id, entry.keyspace_key) as u64,
            stat_dev_for_keyspace(entry.keyspace_id),
            stat_ino_for_key(entry.keyspace_key),
        ),
        FdKind::Pipe => metadata_for_pipe(agent_id, entry.keyspace_key as u16),
        FdKind::Socket => metadata_for_socket(
            agent_id,
            if entry.keyspace_key == SOCKETPAIR_STREAM_MARKER {
                entry.keyspace_id
            } else {
                entry.mailbox_id
            },
        ),
        FdKind::EventFd => metadata_for_eventfd(agent_id, entry.keyspace_key as u16),
        FdKind::TimerFd => metadata_for_timerfd(agent_id, entry.keyspace_key as u16),
        FdKind::Epoll => metadata_for_regular(
            agent_id,
            0,
            0x106,
            stat_ino_for_key(entry.keyspace_key),
        ),
        FdKind::Directory => metadata_for_directory(agent_id, 1),
    }
}

fn copy_proc_self_exe_target<'a>(agent_id: u16, dst: &'a mut [u8; MAX_PATH]) -> &'a [u8] {
    let fallback = b"/app/binary";
    match state::get_state(agent_id) {
        Some(st) if st.exe_path_len > 0 => {
            let len = (st.exe_path_len as usize).min(MAX_PATH);
            dst[..len].copy_from_slice(&st.exe_path[..len]);
            &dst[..len]
        }
        _ => {
            dst[..fallback.len()].copy_from_slice(fallback);
            &dst[..fallback.len()]
        }
    }
}

fn metadata_for_regular_lookup(agent_id: u16, path: &[u8]) -> Result<LinuxStatMeta, i64> {
    let (ks, key) = super::vfs::resolve_path(agent_id, path);
    let file_size = crate::state::query_file_size(ks, key);
    if file_size == 0 && crate::state::state_get(ks, key).is_none() {
        return Err(-ENOENT);
    }
    Ok(metadata_for_regular(
        agent_id,
        file_size as u64,
        stat_dev_for_keyspace(ks),
        stat_ino_for_key(key),
    ))
}

fn metadata_for_proc_self_exe_target(agent_id: u16) -> LinuxStatMeta {
    let mut target_buf = [0u8; MAX_PATH];
    let target = copy_proc_self_exe_target(agent_id, &mut target_buf);

    if let Ok(meta) = metadata_for_regular_lookup(agent_id, target) {
        return meta;
    }

    metadata_for_regular(
        agent_id,
        0,
        stat_dev_for_keyspace(agent_id),
        stat_ino_for_key(path_to_key(target)),
    )
}

fn metadata_for_path(agent_id: u16, path: &[u8], flags: u32) -> Result<LinuxStatMeta, i64> {
    if let Some(special) = super::vfs::is_special_path(path) {
        if special == super::vfs::SpecialFile::ProcSelfExe
            && (flags & AT_SYMLINK_NOFOLLOW) == 0
        {
            return Ok(metadata_for_proc_self_exe_target(agent_id));
        }
        return Ok(metadata_for_special(agent_id, special));
    }

    if is_directory_path(agent_id, path) {
        return Ok(metadata_for_directory(agent_id, path_to_key(path)));
    }

    metadata_for_regular_lookup(agent_id, path)
}

#[inline]
fn path_is_same_or_child(path: &[u8], base: &[u8]) -> bool {
    path == base || (path.len() > base.len() && path.starts_with(base) && path[base.len()] == b'/')
}

fn renamed_path(old_base: &[u8], new_base: &[u8], path: &[u8]) -> Option<Vec<u8>> {
    if !path_is_same_or_child(path, old_base) {
        return None;
    }

    let suffix = if path == old_base {
        &[][..]
    } else {
        &path[old_base.len()..]
    };
    if new_base.len() + suffix.len() > MAX_PATH {
        return None;
    }

    let mut out = Vec::with_capacity(new_base.len() + suffix.len());
    out.extend_from_slice(new_base);
    out.extend_from_slice(suffix);
    Some(out)
}

#[derive(Clone, Copy)]
struct LinuxStatFsMeta {
    f_type: u64,
    f_bsize: u64,
    f_blocks: u64,
    f_bfree: u64,
    f_bavail: u64,
    f_files: u64,
    f_ffree: u64,
    f_fsid: u64,
    f_namelen: u64,
    f_frsize: u64,
    f_flags: u64,
}

fn fill_statfs_from_meta(agent_id: u16, ptr: u64, meta: LinuxStatFsMeta) -> bool {
    let mut buf = [0u8; 120];
    buf[0..8].copy_from_slice(&meta.f_type.to_le_bytes());
    buf[8..16].copy_from_slice(&meta.f_bsize.to_le_bytes());
    buf[16..24].copy_from_slice(&meta.f_blocks.to_le_bytes());
    buf[24..32].copy_from_slice(&meta.f_bfree.to_le_bytes());
    buf[32..40].copy_from_slice(&meta.f_bavail.to_le_bytes());
    buf[40..48].copy_from_slice(&meta.f_files.to_le_bytes());
    buf[48..56].copy_from_slice(&meta.f_ffree.to_le_bytes());
    buf[56..64].copy_from_slice(&meta.f_fsid.to_le_bytes());
    buf[64..72].copy_from_slice(&meta.f_namelen.to_le_bytes());
    buf[72..80].copy_from_slice(&meta.f_frsize.to_le_bytes());
    buf[80..88].copy_from_slice(&meta.f_flags.to_le_bytes());
    write_user_mem(agent_id, ptr, &buf)
}

fn statfs_for_magic(magic: u64, fsid: u64, read_only: bool) -> LinuxStatFsMeta {
    LinuxStatFsMeta {
        f_type: magic,
        f_bsize: 4096,
        f_blocks: 262_144,
        f_bfree: 131_072,
        f_bavail: 131_072,
        f_files: 131_072,
        f_ffree: 65_536,
        f_fsid: fsid,
        f_namelen: 255,
        f_frsize: 4096,
        f_flags: if read_only { 1 } else { 0 },
    }
}

fn statfs_for_special(special: super::vfs::SpecialFile) -> LinuxStatFsMeta {
    match special {
        super::vfs::SpecialFile::Null | super::vfs::SpecialFile::Urandom => {
            statfs_for_magic(DEVTMPFS_MAGIC, 0x6465_7600, false)
        }
        super::vfs::SpecialFile::ProcSelfExe
        | super::vfs::SpecialFile::ProcSelfMaps
        | super::vfs::SpecialFile::ProcSelfCgroup
        | super::vfs::SpecialFile::ProcMeminfo
        | super::vfs::SpecialFile::ProcVersionSignature => {
            statfs_for_magic(PROC_SUPER_MAGIC, 0x7072_6f63, true)
        }
        super::vfs::SpecialFile::SysCpuOnline
        | super::vfs::SpecialFile::SysCgroupMemoryMax
        | super::vfs::SpecialFile::SysCgroupMemoryHigh => {
            statfs_for_magic(SYSFS_MAGIC, 0x7379_7373, true)
        }
    }
}

fn statfs_for_path(agent_id: u16, path: &[u8]) -> Result<LinuxStatFsMeta, i64> {
    if let Some(special) = super::vfs::is_special_path(path) {
        return Ok(statfs_for_special(special));
    }

    if path.starts_with(b"/proc") {
        return Ok(statfs_for_magic(PROC_SUPER_MAGIC, 0x7072_6f63, true));
    }
    if path.starts_with(b"/sys") {
        return Ok(statfs_for_magic(SYSFS_MAGIC, 0x7379_7373, true));
    }
    if path.starts_with(b"/dev") {
        return Ok(statfs_for_magic(DEVTMPFS_MAGIC, 0x6465_7600, false));
    }
    if super::vfs::classify_base_image_path(path).is_some() {
        return Ok(statfs_for_magic(EXT4_SUPER_MAGIC, 0x6261_7365, true));
    }

    if is_directory_path(agent_id, path) {
        return Ok(statfs_for_magic(TMPFS_MAGIC, state::fs_owner(agent_id) as u64, false));
    }

    let (ks, key) = super::vfs::resolve_path(agent_id, path);
    if crate::state::query_file_size(ks, key) == 0 && crate::state::state_get(ks, key).is_none() {
        return Err(-ENOENT);
    }

    Ok(statfs_for_magic(
        if ks == super::vfs::BASE_IMAGE_KEYSPACE {
            EXT4_SUPER_MAGIC
        } else {
            TMPFS_MAGIC
        },
        ks as u64,
        ks == super::vfs::BASE_IMAGE_KEYSPACE,
    ))
}

fn statfs_for_fd(agent_id: u16, entry: &FdEntry) -> LinuxStatFsMeta {
    if let Some(special) = special_file_for_fd(entry) {
        return statfs_for_special(special);
    }

    match entry.kind {
        FdKind::Directory => {
            if let Some(st) = state::get_files_state(agent_id) {
                if let Some(handle) = st.get_directory_handle(entry.keyspace_key as u16) {
                    if let Ok(meta) =
                        statfs_for_path(agent_id, &handle.path[..handle.path_len as usize])
                    {
                        return meta;
                    }
                }
            }
            statfs_for_magic(TMPFS_MAGIC, state::fs_owner(agent_id) as u64, false)
        }
        FdKind::File => statfs_for_magic(
            if entry.keyspace_id == super::vfs::BASE_IMAGE_KEYSPACE {
                EXT4_SUPER_MAGIC
            } else {
                TMPFS_MAGIC
            },
            entry.keyspace_id as u64,
            entry.keyspace_id == super::vfs::BASE_IMAGE_KEYSPACE,
        ),
        FdKind::Pipe | FdKind::EventFd | FdKind::TimerFd => {
            statfs_for_magic(TMPFS_MAGIC, 0x7069_7065, false)
        }
        FdKind::Socket => statfs_for_magic(TMPFS_MAGIC, 0x736f_636b, false),
        FdKind::Epoll => statfs_for_magic(TMPFS_MAGIC, 0x6570_6f6c, false),
    }
}

fn resolve_open_path<'a>(
    agent_id: u16,
    path: &[u8],
    dst: &'a mut [u8; MAX_PATH],
) -> (&'a [u8], bool, bool) {
    if super::vfs::is_special_path(path) == Some(super::vfs::SpecialFile::ProcSelfExe) {
        return (copy_proc_self_exe_target(agent_id, dst), false, true);
    }
    let is_special = super::vfs::is_special_path(path).is_some();
    let len = path.len().min(MAX_PATH);
    dst[..len].copy_from_slice(&path[..len]);
    (&dst[..len], is_special, false)
}

fn special_file_for_fd(entry: &FdEntry) -> Option<super::vfs::SpecialFile> {
    if entry.kind != FdKind::File {
        return None;
    }
    special_file_for_key(entry.keyspace_key)
}

fn special_file_key(special: super::vfs::SpecialFile) -> u64 {
    match special {
        super::vfs::SpecialFile::Null => path_to_key(b"/dev/null"),
        super::vfs::SpecialFile::Urandom => path_to_key(b"/dev/urandom"),
        super::vfs::SpecialFile::ProcSelfExe => path_to_key(b"/proc/self/exe"),
        super::vfs::SpecialFile::ProcSelfMaps => path_to_key(b"/proc/self/maps"),
        super::vfs::SpecialFile::ProcSelfCgroup => path_to_key(b"/proc/self/cgroup"),
        super::vfs::SpecialFile::ProcMeminfo => path_to_key(b"/proc/meminfo"),
        super::vfs::SpecialFile::ProcVersionSignature => path_to_key(b"/proc/version_signature"),
        super::vfs::SpecialFile::SysCpuOnline => path_to_key(b"/sys/devices/system/cpu/online"),
        super::vfs::SpecialFile::SysCgroupMemoryMax => path_to_key(b"/sys/fs/cgroup/memory.max"),
        super::vfs::SpecialFile::SysCgroupMemoryHigh => {
            path_to_key(b"/sys/fs/cgroup/memory.high")
        }
    }
}

fn special_file_for_key(key: u64) -> Option<super::vfs::SpecialFile> {
    match key {
        k if k == path_to_key(b"/dev/null") => Some(super::vfs::SpecialFile::Null),
        k if k == path_to_key(b"/dev/urandom") || k == path_to_key(b"/dev/random") => {
            Some(super::vfs::SpecialFile::Urandom)
        }
        k if k == path_to_key(b"/proc/self/exe") => Some(super::vfs::SpecialFile::ProcSelfExe),
        k if k == path_to_key(b"/proc/self/maps") => Some(super::vfs::SpecialFile::ProcSelfMaps),
        k if k == path_to_key(b"/proc/self/cgroup") => {
            Some(super::vfs::SpecialFile::ProcSelfCgroup)
        }
        k if k == path_to_key(b"/proc/meminfo") => Some(super::vfs::SpecialFile::ProcMeminfo),
        k if k == path_to_key(b"/proc/version_signature") => {
            Some(super::vfs::SpecialFile::ProcVersionSignature)
        }
        k if k == path_to_key(b"/sys/devices/system/cpu/online") => {
            Some(super::vfs::SpecialFile::SysCpuOnline)
        }
        k if k == path_to_key(b"/sys/fs/cgroup/memory.max") => {
            Some(super::vfs::SpecialFile::SysCgroupMemoryMax)
        }
        k if k == path_to_key(b"/sys/fs/cgroup/memory.high") => {
            Some(super::vfs::SpecialFile::SysCgroupMemoryHigh)
        }
        _ => None,
    }
}

fn runtime_prng_fill(agent_id: u16, dst: &mut [u8]) -> bool {
    let Some(st) = state::get_state_mut(agent_id) else {
        return false;
    };

    let mut written = 0usize;
    while written < dst.len() {
        let mut hasher = Sha256::new();
        hasher.update(st.prng_state);
        hasher.update(st.prng_counter.to_le_bytes());
        let hash = hasher.finalize();
        st.prng_state.copy_from_slice(&hash);
        st.prng_counter += 1;

        let chunk = (dst.len() - written).min(hash.len());
        dst[written..written + chunk].copy_from_slice(&hash[..chunk]);
        written += chunk;
    }
    true
}

fn vm_state_for_agent(agent_id: u16) -> Option<&'static LinuxAgentState> {
    let owner = state::get_state(agent_id)
        .map(|st| {
            if st.vm_space_owner != 0 {
                st.vm_space_owner
            } else {
                agent_id
            }
        })
        .unwrap_or(agent_id);
    state::get_state(owner).or_else(|| state::get_state(agent_id))
}

struct FixedBuf<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl<'a> FixedBuf<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, len: 0 }
    }

    fn len(&self) -> usize {
        self.len
    }

    fn write_bytes(&mut self, bytes: &[u8]) -> fmt::Result {
        if self.len + bytes.len() > self.buf.len() {
            return Err(fmt::Error);
        }
        self.buf[self.len..self.len + bytes.len()].copy_from_slice(bytes);
        self.len += bytes.len();
        Ok(())
    }
}

impl Write for FixedBuf<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.write_bytes(s.as_bytes())
    }
}

fn copy_special_bytes(
    agent_id: u16,
    buf_ptr: u64,
    offset: usize,
    count: usize,
    bytes: &[u8],
) -> Result<usize, i64> {
    if offset >= bytes.len() {
        return Ok(0);
    }
    let to_copy = count.min(bytes.len() - offset);
    if !write_user_mem(agent_id, buf_ptr, &bytes[offset..offset + to_copy]) {
        return Err(-EFAULT);
    }
    Ok(to_copy)
}

fn special_static_bytes<'a>(
    agent_id: u16,
    special: super::vfs::SpecialFile,
    exe_buf: &'a mut [u8; MAX_PATH],
) -> Option<&'a [u8]> {
    match special {
        super::vfs::SpecialFile::ProcSelfExe => Some(copy_proc_self_exe_target(agent_id, exe_buf)),
        super::vfs::SpecialFile::ProcSelfCgroup => Some(PROC_SELF_CGROUP_CONTENT),
        super::vfs::SpecialFile::ProcMeminfo => Some(PROC_MEMINFO_CONTENT),
        super::vfs::SpecialFile::ProcVersionSignature => Some(PROC_VERSION_SIGNATURE_CONTENT),
        super::vfs::SpecialFile::SysCpuOnline => Some(SYS_CPU_ONLINE_CONTENT),
        super::vfs::SpecialFile::SysCgroupMemoryMax
        | super::vfs::SpecialFile::SysCgroupMemoryHigh => Some(SYS_CGROUP_LIMIT_CONTENT),
        _ => None,
    }
}

fn maps_path_for_vma<'a>(
    agent_id: u16,
    vma: &state::VmaEntry,
    exe_buf: &'a mut [u8; MAX_PATH],
) -> Option<&'a [u8]> {
    if vma.kind != state::VmaKind::File {
        return None;
    }

    if vma.keyspace_id == super::vfs::BASE_IMAGE_KEYSPACE {
        return crate::base_image::find_by_key(vma.keyspace_key).map(|entry| entry.path.as_bytes());
    }

    let exe_path = copy_proc_self_exe_target(agent_id, exe_buf);
    let (exe_ks, exe_key) = super::vfs::resolve_path(agent_id, exe_path);
    if vma.keyspace_id == exe_ks && vma.keyspace_key == exe_key {
        return Some(exe_path);
    }

    None
}

fn format_proc_self_maps_line(agent_id: u16, vma: &state::VmaEntry, line: &mut [u8]) -> usize {
    let read = if vma.prot & 0x1 != 0 { 'r' } else { '-' };
    let write = if vma.prot & 0x2 != 0 { 'w' } else { '-' };
    let exec = if vma.prot & 0x4 != 0 { 'x' } else { '-' };
    let share = if vma.flags & 0x01 != 0 { 's' } else { 'p' };
    let inode = if vma.kind == state::VmaKind::File {
        stat_ino_for_key(vma.keyspace_key)
    } else {
        0
    };

    let mut out = FixedBuf::new(line);
    let _ = write!(
        out,
        "{:016x}-{:016x} {}{}{}{} {:08x} 00:00 {}",
        vma.start,
        vma.end(),
        read,
        write,
        exec,
        share,
        vma.file_offset as u32,
        inode
    );

    let mut exe_buf = [0u8; MAX_PATH];
    if let Some(path) = maps_path_for_vma(agent_id, vma, &mut exe_buf) {
        let _ = out.write_bytes(b" ");
        let _ = out.write_bytes(path);
    }
    let _ = out.write_bytes(b"\n");
    out.len()
}

fn read_proc_self_maps(
    agent_id: u16,
    offset: usize,
    buf_ptr: u64,
    count: usize,
) -> Result<usize, i64> {
    let Some(vm_state) = vm_state_for_agent(agent_id) else {
        return Ok(0);
    };

    let mut total_offset = 0usize;
    let mut copied = 0usize;
    let mut previous_start = None;

    loop {
        let mut next_idx = None;
        let mut next_start = u64::MAX;
        for (idx, vma) in vm_state.vmas.iter().enumerate() {
            if !vma.active {
                continue;
            }
            if let Some(prev) = previous_start {
                if vma.start <= prev {
                    continue;
                }
            }
            if vma.start < next_start {
                next_start = vma.start;
                next_idx = Some(idx);
            }
        }

        let Some(idx) = next_idx else {
            break;
        };
        previous_start = Some(next_start);

        let mut line = [0u8; MAX_PATH + 128];
        let line_len = format_proc_self_maps_line(agent_id, &vm_state.vmas[idx], &mut line);
        if line_len == 0 {
            continue;
        }

        if offset < total_offset + line_len {
            let start_in_line = offset.saturating_sub(total_offset);
            let chunk = (count - copied).min(line_len - start_in_line);
            if chunk != 0 {
                if !write_user_mem(
                    agent_id,
                    buf_ptr + copied as u64,
                    &line[start_in_line..start_in_line + chunk],
                ) {
                    return Err(-EFAULT);
                }
                copied += chunk;
                if copied == count {
                    return Ok(copied);
                }
            }
        }

        total_offset += line_len;
    }

    Ok(copied)
}

fn special_file_size(agent_id: u16, special: super::vfs::SpecialFile) -> u64 {
    match special {
        super::vfs::SpecialFile::Null | super::vfs::SpecialFile::Urandom => 0,
        super::vfs::SpecialFile::ProcSelfMaps => 0,
        _ => {
            let mut exe_buf = [0u8; MAX_PATH];
            special_static_bytes(agent_id, special, &mut exe_buf)
                .map(|bytes| bytes.len() as u64)
                .unwrap_or(0)
        },
    }
}

fn read_special_file_data(
    agent_id: u16,
    special: super::vfs::SpecialFile,
    offset: usize,
    buf_ptr: u64,
    count: usize,
) -> Result<usize, i64> {
    match special {
        super::vfs::SpecialFile::Null => Ok(0),
        super::vfs::SpecialFile::Urandom => {
            let mut copied = 0usize;
            let mut scratch = [0u8; 256];
            while copied < count {
                let chunk_len = (count - copied).min(scratch.len());
                if !runtime_prng_fill(agent_id, &mut scratch[..chunk_len]) {
                    return Err(-EFAULT);
                }
                if !write_user_mem(agent_id, buf_ptr + copied as u64, &scratch[..chunk_len]) {
                    return Err(-EFAULT);
                }
                copied += chunk_len;
            }
            Ok(copied)
        }
        super::vfs::SpecialFile::ProcSelfMaps => read_proc_self_maps(agent_id, offset, buf_ptr, count),
        _ => {
            let mut exe_buf = [0u8; MAX_PATH];
            let Some(bytes) = special_static_bytes(agent_id, special, &mut exe_buf) else {
                return Ok(0);
            };
            copy_special_bytes(agent_id, buf_ptr, offset, count, bytes)
        }
    }
}

fn fill_stat_from_meta(agent_id: u16, ptr: u64, meta: LinuxStatMeta) -> bool {
    let mut buf = [0u8; 144];
    buf[0..8].copy_from_slice(&meta.st_dev.to_le_bytes());
    buf[8..16].copy_from_slice(&meta.st_ino.to_le_bytes());
    buf[16..24].copy_from_slice(&meta.st_nlink.to_le_bytes());
    buf[24..28].copy_from_slice(&meta.st_mode.to_le_bytes());
    buf[28..32].copy_from_slice(&meta.st_uid.to_le_bytes());
    buf[32..36].copy_from_slice(&meta.st_gid.to_le_bytes());
    buf[40..48].copy_from_slice(&meta.st_rdev.to_le_bytes());
    buf[48..56].copy_from_slice(&(meta.st_size as i64).to_le_bytes());
    buf[56..64].copy_from_slice(&(meta.st_blksize as i64).to_le_bytes());
    buf[64..72].copy_from_slice(&(meta.st_blocks as i64).to_le_bytes());
    write_user_mem(agent_id, ptr, &buf)
}

fn fill_statx_from_meta(agent_id: u16, ptr: u64, meta: LinuxStatMeta) -> bool {
    let mut buf = [0u8; 256];
    buf[0..4].copy_from_slice(&0x07FFu32.to_le_bytes());
    buf[4..8].copy_from_slice(&(meta.st_blksize as u32).to_le_bytes());
    buf[16..20].copy_from_slice(&(meta.st_nlink as u32).to_le_bytes());
    buf[20..24].copy_from_slice(&meta.st_uid.to_le_bytes());
    buf[24..28].copy_from_slice(&meta.st_gid.to_le_bytes());
    buf[28..30].copy_from_slice(&(meta.st_mode as u16).to_le_bytes());
    buf[40..48].copy_from_slice(&meta.st_ino.to_le_bytes());
    buf[48..56].copy_from_slice(&meta.st_size.to_le_bytes());
    buf[56..64].copy_from_slice(&meta.st_blocks.to_le_bytes());
    buf[136..140].copy_from_slice(&(meta.st_dev as u32).to_le_bytes());
    buf[140..144].copy_from_slice(&0u32.to_le_bytes());
    buf[144..148].copy_from_slice(&(meta.st_rdev as u32).to_le_bytes());
    buf[148..152].copy_from_slice(&0u32.to_le_bytes());
    write_user_mem(agent_id, ptr, &buf)
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

fn mutable_directory_exists(agent_id: u16, path: &[u8]) -> bool {
    matches!(state::lookup_mutable_path(agent_id, path), Some(true))
}

fn mutable_parent_exists(agent_id: u16, path: &[u8]) -> bool {
    if path == b"/" {
        return true;
    }

    let Some(last_slash) = path.iter().rposition(|&b| b == b'/') else {
        return false;
    };

    if last_slash == 0 {
        return true;
    }

    is_directory_path(agent_id, &path[..last_slash])
}

fn directory_has_children(agent_id: u16, path: &[u8]) -> bool {
    let mut child_names = [[0u8; MAX_DIRENT_NAME]; MAX_DIRENTS_COLLECT];
    let mut child_lens = [0u16; MAX_DIRENTS_COLLECT];
    let mut child_dtypes = [0u8; MAX_DIRENTS_COLLECT];
    collect_directory_entries(
        agent_id,
        path,
        &mut child_names,
        &mut child_lens,
        &mut child_dtypes,
    ) > 0
}

fn push_dir_entry(
    names: &mut [[u8; MAX_DIRENT_NAME]; MAX_DIRENTS_COLLECT],
    lens: &mut [u16; MAX_DIRENTS_COLLECT],
    dtypes: &mut [u8; MAX_DIRENTS_COLLECT],
    count: &mut usize,
    name: &[u8],
    d_type: u8,
) {
    if name.is_empty() || name.len() >= MAX_DIRENT_NAME || *count >= MAX_DIRENTS_COLLECT {
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
    names: &mut [[u8; MAX_DIRENT_NAME]; MAX_DIRENTS_COLLECT],
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

fn collect_mutable_children(
    agent_id: u16,
    dir_path: &[u8],
    names: &mut [[u8; MAX_DIRENT_NAME]; MAX_DIRENTS_COLLECT],
    lens: &mut [u16; MAX_DIRENTS_COLLECT],
    dtypes: &mut [u8; MAX_DIRENTS_COLLECT],
    count: &mut usize,
) {
    state::iter_mutable_paths(agent_id, |path, is_dir| {
        if path == dir_path || path.len() <= dir_path.len() {
            return true;
        }

        let remainder = if dir_path == b"/" {
            if path[0] != b'/' {
                return true;
            }
            &path[1..]
        } else {
            if &path[..dir_path.len()] != dir_path || path[dir_path.len()] != b'/' {
                return true;
            }
            &path[dir_path.len() + 1..]
        };

        if remainder.is_empty() {
            return true;
        }

        if let Some(pos) = remainder.iter().position(|&b| b == b'/') {
            push_dir_entry(names, lens, dtypes, count, &remainder[..pos], DT_DIR);
        } else {
            push_dir_entry(
                names,
                lens,
                dtypes,
                count,
                remainder,
                if is_dir { DT_DIR } else { DT_REG },
            );
        }
        true
    });
}

fn collect_directory_entries(
    agent_id: u16,
    dir_path: &[u8],
    names: &mut [[u8; MAX_DIRENT_NAME]; MAX_DIRENTS_COLLECT],
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
        push_dir_entry(names, lens, dtypes, &mut count, b"meminfo", DT_REG);
        push_dir_entry(names, lens, dtypes, &mut count, b"self", DT_DIR);
        push_dir_entry(names, lens, dtypes, &mut count, b"version_signature", DT_REG);
    } else if dir_path == b"/proc/self" {
        push_dir_entry(names, lens, dtypes, &mut count, b"cgroup", DT_REG);
        push_dir_entry(names, lens, dtypes, &mut count, b"exe", DT_LNK);
        push_dir_entry(names, lens, dtypes, &mut count, b"fd", DT_DIR);
        push_dir_entry(names, lens, dtypes, &mut count, b"maps", DT_REG);
    } else if dir_path == b"/proc/self/fd" {
        if let Some(st) = state::get_files_state(agent_id) {
            for fd in 0..MAX_FDS {
                if !matches!(st.fd_table[fd], Some(entry) if entry.active) {
                    continue;
                }
                let mut name = [0u8; 16];
                let mut n = fd;
                let mut digits = [0u8; 16];
                let mut digit_count = 0usize;
                if n == 0 {
                    digits[0] = b'0';
                    digit_count = 1;
                } else {
                    while n > 0 {
                        digits[digit_count] = b'0' + (n % 10) as u8;
                        digit_count += 1;
                        n /= 10;
                    }
                }
                for i in 0..digit_count {
                    name[i] = digits[digit_count - 1 - i];
                }
                push_dir_entry(names, lens, dtypes, &mut count, &name[..digit_count], DT_LNK);
            }
        }
    } else if dir_path == b"/dev" {
        push_dir_entry(names, lens, dtypes, &mut count, b"null", DT_CHR);
        push_dir_entry(names, lens, dtypes, &mut count, b"random", DT_CHR);
        push_dir_entry(names, lens, dtypes, &mut count, b"urandom", DT_CHR);
    } else if dir_path == b"/sys" {
        push_dir_entry(names, lens, dtypes, &mut count, b"devices", DT_DIR);
        push_dir_entry(names, lens, dtypes, &mut count, b"fs", DT_DIR);
    } else if dir_path == b"/sys/devices" {
        push_dir_entry(names, lens, dtypes, &mut count, b"system", DT_DIR);
    } else if dir_path == b"/sys/devices/system" {
        push_dir_entry(names, lens, dtypes, &mut count, b"cpu", DT_DIR);
    } else if dir_path == b"/sys/devices/system/cpu" {
        push_dir_entry(names, lens, dtypes, &mut count, b"online", DT_REG);
    } else if dir_path == b"/sys/fs" {
        push_dir_entry(names, lens, dtypes, &mut count, b"cgroup", DT_DIR);
    } else if dir_path == b"/sys/fs/cgroup" {
        push_dir_entry(names, lens, dtypes, &mut count, b"memory.high", DT_REG);
        push_dir_entry(names, lens, dtypes, &mut count, b"memory.max", DT_REG);
    }

    collect_base_image_children(dir_path, names, lens, dtypes, &mut count);
    collect_mutable_children(agent_id, dir_path, names, lens, dtypes, &mut count);
    count
}

// ── sys_read ───────────────────────────────────────────────────────────────

/// Read from a file descriptor.
///
/// - **File** fd: reads from the agent's keyspace value at the current
///   offset and advances the offset.
/// - **Pipe** fd: reads from a byte-stream pipe object.
/// - **Socket** fd: dequeues one message from the associated mailbox.
/// - **EventFd** fd: returns an 8-byte counter value.
pub fn sys_read(agent_id: u16, fd: i32, buf_ptr: u64, count: u64) -> i64 {
    let st = match state::get_files_state_mut(agent_id) {
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
    let flags = entry.flags;

    match kind {
        FdKind::File => {
            if !fd_allows_read(kind, flags) {
                return -EBADF;
            }
            let to_copy = match read_file_data(agent_id, ks, key, offset, buf_ptr, count as usize) {
                Ok(n) => n,
                Err(err) => return err,
            };
            if to_copy > 0 {
                if let Some(e) = st.get_fd_mut(fd) {
                    e.offset += to_copy as u64;
                }
            }
            to_copy as i64
        }
        FdKind::Pipe => {
            if !fd_allows_read(kind, flags) {
                return -EBADF;
            }
            let handle = entry.keyspace_key as u16;
            loop {
                let available = state::pipe_available(handle).unwrap_or(0);
                if available > 0 {
                    let mut total = 0usize;
                    let mut user_ptr = buf_ptr;
                    let mut remaining = (count as usize).min(available);
                    while remaining > 0 {
                        let chunk_len = remaining.min(512);
                        let mut chunk = [0u8; 512];
                        let Some(read_len) = state::pipe_read(handle, &mut chunk[..chunk_len]) else {
                            return -EBADF;
                        };
                        if read_len == 0 {
                            break;
                        }
                        if !write_user_mem(agent_id, user_ptr, &chunk[..read_len]) {
                            return if total > 0 { total as i64 } else { -EFAULT };
                        }
                        total += read_len;
                        user_ptr += read_len as u64;
                        remaining -= read_len;
                    }
                    if state::trace_runtime_agent(agent_id) {
                        crate::serial_println!(
                            "[RTDBG] pipe-read agent={} fd={} handle={} total={} requested={} available={}",
                            agent_id,
                            fd,
                            handle,
                            total,
                            count,
                            available
                        );
                    }
                    return total as i64;
                }

                if !state::pipe_has_writers(handle).unwrap_or(false) {
                    if state::trace_runtime_agent(agent_id) {
                        let (readers, writers, buffered) =
                            state::pipe_ref_counts(handle).unwrap_or((0, 0, 0));
                        crate::serial_println!(
                            "[RTDBG] pipe-read-eof agent={} fd={} handle={} readers={} writers={} buffered={}",
                            agent_id,
                            fd,
                            handle,
                            readers,
                            writers,
                            buffered
                        );
                    }
                    return 0;
                }
                if state::trace_runtime_agent(agent_id) {
                    let (readers, writers, buffered) =
                        state::pipe_ref_counts(handle).unwrap_or((0, 0, 0));
                    crate::serial_println!(
                        "[RTDBG] pipe-read-block agent={} fd={} handle={} readers={} writers={} buffered={} nonblock={}",
                        agent_id,
                        fd,
                        handle,
                        readers,
                        writers,
                        buffered,
                        (flags & O_NONBLOCK) != 0
                    );
                }
                if (flags & O_NONBLOCK) != 0 {
                    return -EAGAIN;
                }
                if crate::linux_compat::signal::has_unblocked_pending_signal(agent_id) {
                    return -EINTR;
                }

                state::add_blocked_pipe_reader(handle, agent_id);
                crate::sched::block_current(crate::agent::AgentStatus::BlockedRecv);

                if crate::linux_compat::signal::has_unblocked_pending_signal(agent_id) {
                    state::remove_blocked_pipe_reader(handle, agent_id);
                    return -EINTR;
                }
            }
        }
        FdKind::Socket => {
            if !fd_allows_read(kind, flags) {
                return -EBADF;
            }
            if entry.keyspace_key == SOCKETPAIR_STREAM_MARKER {
                let Some((read_handle, _write_handle)) = state::unix_stream_handles(entry.keyspace_id) else {
                    return -EBADF;
                };
                loop {
                    let available = state::pipe_available(read_handle).unwrap_or(0);
                    if available > 0 {
                        let mut total = 0usize;
                        let mut user_ptr = buf_ptr;
                        let mut remaining = (count as usize).min(available);
                        while remaining > 0 {
                            let chunk_len = remaining.min(512);
                            let mut chunk = [0u8; 512];
                            let Some(read_len) = state::pipe_read(read_handle, &mut chunk[..chunk_len]) else {
                                return -EBADF;
                            };
                            if read_len == 0 {
                                break;
                            }
                            if !write_user_mem(agent_id, user_ptr, &chunk[..read_len]) {
                                return if total > 0 { total as i64 } else { -EFAULT };
                            }
                            total += read_len;
                            user_ptr += read_len as u64;
                            remaining -= read_len;
                        }
                        if state::trace_runtime_agent(agent_id) {
                            crate::serial_println!(
                                "[RTDBG] socket-read agent={} fd={} handle={} total={} requested={} available={}",
                                agent_id,
                                fd,
                                read_handle,
                                total,
                                count,
                                available
                            );
                        }
                        return total as i64;
                    }

                    if !state::pipe_has_writers(read_handle).unwrap_or(false)
                        || (flags & super::network::FD_FLAG_SHUT_RD) != 0
                    {
                        return 0;
                    }
                    if (flags & O_NONBLOCK) != 0 {
                        return -EAGAIN;
                    }
                    if crate::linux_compat::signal::has_unblocked_pending_signal(agent_id) {
                        return -EINTR;
                    }

                    state::add_blocked_pipe_reader(read_handle, agent_id);
                    crate::sched::block_current(crate::agent::AgentStatus::BlockedRecv);

                    if crate::linux_compat::signal::has_unblocked_pending_signal(agent_id) {
                        state::remove_blocked_pipe_reader(read_handle, agent_id);
                        return -EINTR;
                    }
                }
            }
            let mailbox_id = entry.mailbox_id;
            loop {
                match crate::mailbox::recv_message_via_fd(agent_id, mailbox_id) {
                    Ok(msg) => {
                        let msg_len = msg.len as usize;
                        let to_copy = (count as usize).min(msg_len);
                        if !write_user_mem(agent_id, buf_ptr, &msg.payload[..to_copy]) {
                            return -EFAULT;
                        }
                        return to_copy as i64;
                    }
                    Err(_) => {
                        if !crate::mailbox::mailbox_has_writers(mailbox_id) {
                            return 0;
                        }
                        if (flags & O_NONBLOCK) != 0 {
                            return -EAGAIN;
                        }
                        if crate::linux_compat::signal::has_unblocked_pending_signal(agent_id) {
                            return -EINTR;
                        }

                        crate::mailbox::add_blocked_reader(mailbox_id, agent_id);
                        crate::sched::block_current(crate::agent::AgentStatus::BlockedRecv);

                        if crate::linux_compat::signal::has_unblocked_pending_signal(agent_id) {
                            return -EINTR;
                        }
                    }
                }
            }
        }
        FdKind::EventFd => {
            if !fd_allows_read(kind, flags) {
                return -EBADF;
            }
            if count < 8 {
                return -EINVAL;
            }

            let Some(handle) = eventfd_handle(entry) else {
                return -EBADF;
            };
            loop {
                let Some(counter) = state::eventfd_counter(handle) else {
                    return -EBADF;
                };
                if counter > 0 {
                    let value = if (flags & EFD_SEMAPHORE) != 0 {
                        1
                    } else {
                        counter
                    };
                    let next = if (flags & EFD_SEMAPHORE) != 0 {
                        counter - 1
                    } else {
                        0
                    };

                    if !write_user_mem(agent_id, buf_ptr, &value.to_ne_bytes()) {
                        return -EFAULT;
                    }
                    if !state::eventfd_set_counter(handle, next) {
                        return -EBADF;
                    }
                    if next > 0 {
                        state::wake_eventfd_readers(handle);
                    }
                    state::wake_eventfd_writers(handle);
                    if state::trace_runtime_agent(agent_id) {
                        crate::serial_println!(
                            "[RTDBG] eventfd-read agent={} fd={} handle={} value={} next={}",
                            agent_id,
                            fd,
                            handle,
                            value,
                            next
                        );
                    }
                    return 8;
                }

                if (flags & O_NONBLOCK) != 0 {
                    return -EAGAIN;
                }
                if crate::linux_compat::signal::has_unblocked_pending_signal(agent_id) {
                    return -EINTR;
                }

                state::add_blocked_eventfd_reader(handle, agent_id);
                crate::sched::block_current(crate::agent::AgentStatus::BlockedRecv);

                if crate::linux_compat::signal::has_unblocked_pending_signal(agent_id) {
                    state::remove_blocked_eventfd_reader(handle, agent_id);
                    return -EINTR;
                }
            }
        }
        FdKind::TimerFd => {
            if !fd_allows_read(kind, flags) {
                return -EBADF;
            }
            if count < 8 {
                return -EINVAL;
            }

            let Some(handle) = timerfd_handle(entry) else {
                return -EBADF;
            };
            loop {
                if let Some(expirations) = state::timerfd_take_expirations(handle) {
                    if !write_user_mem(agent_id, buf_ptr, &expirations.to_ne_bytes()) {
                        return -EFAULT;
                    }
                    return 8;
                }

                if (flags & O_NONBLOCK) != 0 {
                    return -EAGAIN;
                }
                if crate::linux_compat::signal::has_unblocked_pending_signal(agent_id) {
                    return -EINTR;
                }

                state::add_blocked_timerfd_reader(handle, agent_id);
                crate::sched::block_current(crate::agent::AgentStatus::BlockedRecv);

                if crate::linux_compat::signal::has_unblocked_pending_signal(agent_id) {
                    state::remove_blocked_timerfd_reader(handle, agent_id);
                    return -EINTR;
                }
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
/// - **Pipe** fd: the data is appended to a byte-stream pipe object.
/// - **Socket** fd: the data is sent as a mailbox message.
/// - **EventFd** fd: adds an 8-byte value to the counter.
pub fn sys_write(agent_id: u16, fd: i32, buf_ptr: u64, count: u64) -> i64 {
    let cnt = count as usize;
    if cnt == 0 {
        return 0;
    }

    // ── Regular fd ─────────────────────────────────────────────────────
    let st = match state::get_files_state_mut(agent_id) {
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
    let flags = entry.flags;

    // The default inherited stdout/stderr console is represented as the
    // synthetic file entry with key 0. Honor dup/dup2 redirection by checking
    // the fd table first instead of special-casing numeric fd 1/2.
    if kind == FdKind::File && key == 0 && entry.mailbox_id == 0 {
        if !fd_allows_write(kind, flags) {
            return -EBADF;
        }
        let mut tmp = [0u8; 512];
        let to_read = cnt.min(tmp.len());
        if !read_user_mem(agent_id, buf_ptr, &mut tmp, to_read) {
            return -EFAULT;
        }
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

    match kind {
        FdKind::File => {
            if !fd_allows_write(kind, flags) {
                return -EBADF;
            }
            match write_regular_file_data(agent_id, ks, key, entry.offset, flags, buf_ptr, cnt) {
                Ok((written, next_offset)) => {
                    if let Some(e) = st.get_fd_mut(fd) {
                        e.offset = next_offset;
                    }
                    written as i64
                }
                Err(err) => err,
            }
        }
        FdKind::Pipe => {
            if !fd_allows_write(kind, flags) {
                return -EBADF;
            }
            let handle = entry.keyspace_key as u16;
            let mut total = 0usize;
            let mut user_ptr = buf_ptr;

            loop {
                if !state::pipe_has_readers(handle).unwrap_or(false) {
                    return if total > 0 { total as i64 } else { -EPIPE };
                }

                let available = state::pipe_available(handle).unwrap_or(0);
                let free = state::PIPE_BUFFER_SIZE.saturating_sub(available);
                if free > 0 {
                    let chunk_len = cnt.saturating_sub(total).min(free).min(512);
                    let mut chunk = [0u8; 512];
                    if !read_user_mem(agent_id, user_ptr, &mut chunk, chunk_len) {
                        return if total > 0 { total as i64 } else { -EFAULT };
                    }
                    let Some(written) = state::pipe_write(handle, &chunk[..chunk_len]) else {
                        return if total > 0 { total as i64 } else { -EBADF };
                    };
                    if written == 0 {
                        return if total > 0 { total as i64 } else { -EAGAIN };
                    }
                    total += written;
                    user_ptr += written as u64;
                    if state::trace_runtime_agent(agent_id) {
                        crate::serial_println!(
                            "[RTDBG] pipe-write agent={} fd={} handle={} wrote={} total={} requested={} free={}",
                            agent_id,
                            fd,
                            handle,
                            written,
                            total,
                            count,
                            free
                        );
                    }
                    if total >= cnt || written < chunk_len {
                        return total as i64;
                    }
                    continue;
                }

                if (flags & O_NONBLOCK) != 0 {
                    return if total > 0 { total as i64 } else { -EAGAIN };
                }
                if crate::linux_compat::signal::has_unblocked_pending_signal(agent_id) {
                    return if total > 0 { total as i64 } else { -EINTR };
                }

                state::add_blocked_pipe_writer(handle, agent_id);
                crate::sched::block_current(crate::agent::AgentStatus::BlockedSend);

                if crate::linux_compat::signal::has_unblocked_pending_signal(agent_id) {
                    state::remove_blocked_pipe_writer(handle, agent_id);
                    return if total > 0 { total as i64 } else { -EINTR };
                }
            }
        }
        FdKind::Socket => {
            if !fd_allows_write(kind, flags) {
                return -EBADF;
            }
            if entry.keyspace_key == SOCKETPAIR_STREAM_MARKER {
                if (flags & super::network::FD_FLAG_SHUT_WR) != 0 {
                    return -EPIPE;
                }
                let Some((_read_handle, write_handle)) = state::unix_stream_handles(entry.keyspace_id) else {
                    return -EBADF;
                };
                let mut total = 0usize;
                let mut user_ptr = buf_ptr;
                loop {
                    if !state::pipe_has_readers(write_handle).unwrap_or(false) {
                        return if total > 0 { total as i64 } else { -EPIPE };
                    }

                    let available = state::pipe_available(write_handle).unwrap_or(0);
                    let free = state::PIPE_BUFFER_SIZE.saturating_sub(available);
                    if free > 0 {
                        let chunk_len = cnt.saturating_sub(total).min(free).min(512);
                        let mut chunk = [0u8; 512];
                        if !read_user_mem(agent_id, user_ptr, &mut chunk, chunk_len) {
                            return if total > 0 { total as i64 } else { -EFAULT };
                        }
                        let Some(written) = state::pipe_write(write_handle, &chunk[..chunk_len]) else {
                            return if total > 0 { total as i64 } else { -EBADF };
                        };
                        if written == 0 {
                            return if total > 0 { total as i64 } else { -EAGAIN };
                        }
                        total += written;
                        user_ptr += written as u64;
                        if state::trace_runtime_agent(agent_id) {
                            crate::serial_println!(
                                "[RTDBG] socket-write agent={} fd={} handle={} wrote={} total={} requested={} free={}",
                                agent_id,
                                fd,
                                write_handle,
                                written,
                                total,
                                count,
                                free
                            );
                        }
                        if total >= cnt || written < chunk_len {
                            return total as i64;
                        }
                        continue;
                    }

                    if (flags & O_NONBLOCK) != 0 {
                        return if total > 0 { total as i64 } else { -EAGAIN };
                    }
                    if crate::linux_compat::signal::has_unblocked_pending_signal(agent_id) {
                        return if total > 0 { total as i64 } else { -EINTR };
                    }

                    state::add_blocked_pipe_writer(write_handle, agent_id);
                    crate::sched::block_current(crate::agent::AgentStatus::BlockedSend);

                    if crate::linux_compat::signal::has_unblocked_pending_signal(agent_id) {
                        state::remove_blocked_pipe_writer(write_handle, agent_id);
                        return if total > 0 { total as i64 } else { -EINTR };
                    }
                }
            }
            let mailbox_id = if entry.keyspace_id != 0 {
                entry.keyspace_id
            } else {
                entry.mailbox_id
            };
            let to_send = cnt.min(crate::agent::MAX_MESSAGE_PAYLOAD);
            let mut payload = [0u8; crate::agent::MAX_MESSAGE_PAYLOAD];
            if !read_user_mem(agent_id, buf_ptr, &mut payload, to_send) {
                return -EFAULT;
            }
            match crate::mailbox::send_message_via_fd(agent_id, mailbox_id, &payload[..to_send]) {
                Ok(()) => to_send as i64,
                Err(_) => -EAGAIN,
            }
        }
        FdKind::EventFd => {
            if !fd_allows_write(kind, flags) {
                return -EBADF;
            }
            if count < 8 {
                return -EINVAL;
            }

            let mut value_bytes = [0u8; 8];
            if !read_user_mem(agent_id, buf_ptr, &mut value_bytes, 8) {
                return -EFAULT;
            }
            let value = u64::from_ne_bytes(value_bytes);
            if value == u64::MAX {
                return -EINVAL;
            }

            let Some(handle) = eventfd_handle(entry) else {
                return -EBADF;
            };
            loop {
                let Some(counter) = state::eventfd_counter(handle) else {
                    return -EBADF;
                };
                let Some(next) = counter.checked_add(value) else {
                    if (flags & O_NONBLOCK) != 0 {
                        return -EAGAIN;
                    }
                    if crate::linux_compat::signal::has_unblocked_pending_signal(agent_id) {
                        return -EINTR;
                    }
                    state::add_blocked_eventfd_writer(handle, agent_id);
                    crate::sched::block_current(crate::agent::AgentStatus::BlockedSend);
                    if crate::linux_compat::signal::has_unblocked_pending_signal(agent_id) {
                        state::remove_blocked_eventfd_writer(handle, agent_id);
                        return -EINTR;
                    }
                    continue;
                };
                if next == u64::MAX {
                    if (flags & O_NONBLOCK) != 0 {
                        return -EAGAIN;
                    }
                    if crate::linux_compat::signal::has_unblocked_pending_signal(agent_id) {
                        return -EINTR;
                    }
                    state::add_blocked_eventfd_writer(handle, agent_id);
                    crate::sched::block_current(crate::agent::AgentStatus::BlockedSend);
                    if crate::linux_compat::signal::has_unblocked_pending_signal(agent_id) {
                        state::remove_blocked_eventfd_writer(handle, agent_id);
                        return -EINTR;
                    }
                    continue;
                }

                if !state::eventfd_set_counter(handle, next) {
                    return -EBADF;
                }
                state::wake_eventfd_readers(handle);
                if state::trace_runtime_agent(agent_id) {
                    crate::serial_println!(
                        "[RTDBG] eventfd-write agent={} fd={} handle={} value={} next={}",
                        agent_id,
                        fd,
                        handle,
                        value,
                        next
                    );
                }
                return 8;
            }
        }
        FdKind::TimerFd => -EINVAL,
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
    let _ = mode; // permissions not enforced

    let mut path_buf = [0u8; MAX_PATH];
    let path_len = match read_pathname(agent_id, pathname_ptr, &mut path_buf) {
        Ok(len) => len,
        Err(err) => return err,
    };
    if path_len == 0 {
        return -ENOENT;
    }

    let mut norm_buf = [0u8; MAX_PATH];
    let path = match resolve_path_at(agent_id, dirfd, &path_buf[..path_len], &mut norm_buf) {
        Ok(path) => path,
        Err(err) => return err,
    };
    let trace_python = super::state::trace_runtime_agent(agent_id);
    let mut open_path_buf = [0u8; MAX_PATH];
    let (open_path, is_special, synthetic_ok) = resolve_open_path(agent_id, path, &mut open_path_buf);
    if trace_python {
        crate::serial_println!(
            "[PYDBG] openat-enter agent={} dirfd={} flags={:#x} mode={:#x} path={:?}",
            agent_id,
            dirfd,
            flags,
            mode,
            core::str::from_utf8(open_path).unwrap_or("?")
        );
    }

    // Check if it's a directory open (for getdents64)
    let is_dir = (flags & O_DIRECTORY) != 0;
    let directory_target = is_directory_path(agent_id, open_path);

    let (keyspace_id, key) = super::vfs::resolve_path(agent_id, open_path);
    let existed = directory_target
        || is_special
        || crate::state::query_file_size(keyspace_id, key) > 0
        || crate::state::state_get(keyspace_id, key).is_some();

    if is_dir && !directory_target {
        let ret = if existed { -ENOTDIR } else { -ENOENT };
        if trace_python {
            crate::serial_println!(
                "[PYDBG] openat-exit agent={} ret={} path={:?} ks={} key={:#x}",
                agent_id,
                ret,
                core::str::from_utf8(open_path).unwrap_or("?"),
                keyspace_id,
                key
            );
        }
        return ret;
    }

    if (flags & (O_CREAT | O_EXCL)) == (O_CREAT | O_EXCL) && existed && !directory_target {
        return -EEXIST;
    }

    // If not creating and not a special path and not a directory,
    // verify the file actually exists in the keyspace
    if (flags & O_CREAT) != 0 && !directory_target && !mutable_parent_exists(agent_id, open_path) {
        if trace_python {
            crate::serial_println!(
                "[PYDBG] openat-exit agent={} ret={} path={:?} ks={} key={:#x}",
                agent_id,
                -ENOENT,
                core::str::from_utf8(open_path).unwrap_or("?"),
                keyspace_id,
                key
            );
        }
        return -ENOENT;
    }

    if (flags & O_CREAT) == 0 && !is_special && !directory_target {
        let size = crate::state::query_file_size(keyspace_id, key);
        if size == 0 {
            // Also check plain state_get for empty/small files
            if crate::state::state_get(keyspace_id, key).is_none() && !synthetic_ok {
                if trace_python {
                    crate::serial_println!(
                        "[PYDBG] openat-exit agent={} ret={} path={:?} ks={} key={:#x}",
                        agent_id,
                        -ENOENT,
                        core::str::from_utf8(open_path).unwrap_or("?"),
                        keyspace_id,
                        key
                    );
                }
                return -ENOENT;
            }
        }
    }

    let st = match state::get_files_state_mut(agent_id) {
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

    if !directory_target && !is_special && (flags & O_CREAT) != 0 && !existed {
        if let Err(err) = store_regular_file_data(keyspace_id, key, &[]) {
            log_regular_file_store_failure(agent_id, keyspace_id, key, 0, err);
            let _ = st.close_fd(fd_idx as i32);
            return -ENOSPC;
        }
    }

    if !directory_target && !is_special && (flags & O_TRUNC) != 0 && fd_access_mode(flags) != O_RDONLY
    {
        if let Err(err) = store_regular_file_data(keyspace_id, key, &[]) {
            log_regular_file_store_failure(agent_id, keyspace_id, key, 0, err);
            let _ = st.close_fd(fd_idx as i32);
            return -ENOSPC;
        }
    }

    if !directory_target
        && !is_special
        && keyspace_id != super::vfs::BASE_IMAGE_KEYSPACE
        && (flags & O_CREAT) != 0
        && !state::record_mutable_path(agent_id, open_path, false)
    {
        let _ = st.close_fd(fd_idx as i32);
        return -ENOSPC;
    }

    if trace_python {
        crate::serial_println!(
            "[PYDBG] openat-exit agent={} fd={} path={:?} ks={} key={:#x} dir={}",
            agent_id,
            fd_idx,
            core::str::from_utf8(open_path).unwrap_or("?"),
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
    let st = match state::get_files_state_mut(agent_id) {
        Some(s) => s,
        None => return -EBADF,
    };
    let pipe_info = st
        .get_fd(fd)
        .filter(|entry| entry.kind == FdKind::Pipe)
        .map(|entry| (entry.keyspace_key as u16, entry.flags & O_ACCMODE));
    if st.close_fd(fd) {
        if let Some((handle, access)) = pipe_info {
            if state::trace_runtime_agent(agent_id) {
                let (readers, writers, buffered) =
                    state::pipe_ref_counts(handle).unwrap_or((0, 0, 0));
                crate::serial_println!(
                    "[RTDBG] pipe-close agent={} fd={} handle={} access={} readers={} writers={} buffered={}",
                    agent_id,
                    fd,
                    handle,
                    access,
                    readers,
                    writers,
                    buffered
                );
            }
        }
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
    let st = match state::get_files_state(agent_id) {
        Some(s) => s,
        None => return -EBADF,
    };

    let entry = match st.get_fd(fd) {
        Some(e) if e.active => e,
        _ => return -EBADF,
    };

    let meta = metadata_for_fd(agent_id, entry);

    if !fill_stat_from_meta(agent_id, statbuf_ptr, meta) {
        return -EFAULT;
    }
    0
}

/// Write a populated `struct stat` to user memory.
fn fill_stat_buf(ptr: u64, file_size: u64, st_dev: u64, st_ino: u64) {
    let _ = (ptr, file_size, st_dev, st_ino);
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

    let mut path_buf = [0u8; MAX_PATH];
    let path_len = match read_pathname(agent_id, pathname_ptr, &mut path_buf) {
        Ok(len) => len,
        Err(err) => return err,
    };
    if path_len == 0 {
        return -ENOENT;
    }

    let mut norm_buf = [0u8; MAX_PATH];
    let path = match resolve_path_at(agent_id, dirfd, &path_buf[..path_len], &mut norm_buf) {
        Ok(path) => path,
        Err(err) => return err,
    };
    if trace_python {
        crate::serial_println!(
            "[PYDBG] newfstatat-enter agent={} dirfd={} flags={:#x} path={:?}",
            agent_id,
            dirfd,
            flags,
            core::str::from_utf8(path).unwrap_or("?")
        );
    }

    match metadata_for_path(agent_id, path, flags) {
        Ok(meta) => {
            if !fill_stat_from_meta(agent_id, statbuf_ptr, meta) {
                return -EFAULT;
            }
            if trace_python {
                crate::serial_println!(
                    "[PYDBG] newfstatat-exit agent={} ret=0 path={:?} mode={:#o} ino={:#x}",
                    agent_id,
                    core::str::from_utf8(path).unwrap_or("?"),
                    meta.st_mode,
                    meta.st_ino
                );
            }
            0
        }
        Err(err) => {
            if trace_python {
                crate::serial_println!(
                    "[PYDBG] newfstatat-exit agent={} ret={} path={:?}",
                    agent_id,
                    err,
                    core::str::from_utf8(path).unwrap_or("?")
                );
            }
            err
        }
    }
}

/// Check if a path is a known directory.
fn is_directory_path(agent_id: u16, path: &[u8]) -> bool {
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
            | b"/proc/self/fd"
            | b"/sys"
            | b"/sys/devices"
            | b"/sys/devices/system"
            | b"/sys/devices/system/cpu"
            | b"/sys/fs"
            | b"/sys/fs/cgroup"
            | b"/tmp"
            | b"/usr"
            | b"/usr/bin"
            | b"/usr/lib"
            | b"/var"
            | b"/var/run"
    ) || base_image_directory_exists(path)
        || mutable_directory_exists(agent_id, path)
}

/// Fill a stat buf with S_IFDIR mode.
fn fill_stat_buf_dir(ptr: u64) {
    let _ = ptr;
}

// ── sys_lseek ──────────────────────────────────────────────────────────────

/// Reposition the read/write offset of an open fd.
pub fn sys_lseek(agent_id: u16, fd: i32, offset: i64, whence: u32) -> i64 {
    let st = match state::get_files_state_mut(agent_id) {
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
        if entry.kind == FdKind::Pipe || entry.kind == FdKind::Socket {
            return -ESPIPE;
        }
        return -EINVAL;
    }

    let file_size = crate::state::query_file_size(entry.keyspace_id, entry.keyspace_key) as u64;
    let file_size = if let Some(special) = special_file_for_fd(entry) {
        special_file_size(agent_id, special)
    } else {
        file_size
    };

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
    let st = match state::get_files_state(agent_id) {
        Some(s) => s,
        None => return -EBADF,
    };

    let entry = match st.get_fd(fd) {
        Some(e) if e.active => e,
        _ => return -EBADF,
    };

    if !fd_allows_read(entry.kind, entry.flags) {
        return -EBADF;
    }

    if entry.kind != FdKind::File {
        if entry.kind == FdKind::Directory {
            return -EISDIR;
        }
        return -EINVAL;
    }

    match read_file_data(
        agent_id,
        entry.keyspace_id,
        entry.keyspace_key,
        offset as usize,
        buf_ptr,
        count as usize,
    ) {
        Ok(n) => n as i64,
        Err(err) => err,
    }
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
    let path_len = match read_pathname(agent_id, pathname_ptr, &mut path_buf) {
        Ok(len) => len,
        Err(err) => return err,
    };
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

    if is_directory_path(agent_id, path) {
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

fn access_path_at(agent_id: u16, dirfd: i32, path: &[u8], mode: u32, flags: u32) -> i64 {
    let _ = mode; // permissions are not modeled yet
    let unsupported = flags & !(AT_SYMLINK_NOFOLLOW | AT_EACCESS | AT_EMPTY_PATH);
    if unsupported != 0 {
        return -EINVAL;
    }

    if path.is_empty() {
        if (flags & AT_EMPTY_PATH) == 0 {
            return -ENOENT;
        }
        if dirfd == AT_FDCWD {
            return 0;
        }
        let Some(st) = state::get_files_state(agent_id) else {
            return -EBADF;
        };
        return match st.get_fd(dirfd) {
            Some(entry) if entry.active => 0,
            _ => -EBADF,
        };
    }

    if super::vfs::is_special_path(path).is_some() || is_directory_path(agent_id, path) {
        return 0;
    }

    match metadata_for_path(agent_id, path, flags) {
        Ok(_) => 0,
        Err(err) => err,
    }
}

pub fn sys_faccessat(agent_id: u16, dirfd: i32, pathname_ptr: u64, mode: u32) -> i64 {
    let mut path_buf = [0u8; MAX_PATH];
    let path_len = match read_pathname(agent_id, pathname_ptr, &mut path_buf) {
        Ok(len) => len,
        Err(err) => return err,
    };

    let mut norm_buf = [0u8; MAX_PATH];
    let path = if path_len == 0 {
        &[][..]
    } else {
        match resolve_path_at(agent_id, dirfd, &path_buf[..path_len], &mut norm_buf) {
            Ok(path) => path,
            Err(err) => return err,
        }
    };

    access_path_at(agent_id, dirfd, path, mode, 0)
}

pub fn sys_faccessat2(
    agent_id: u16,
    dirfd: i32,
    pathname_ptr: u64,
    mode: u32,
    flags: u32,
) -> i64 {
    let mut path_buf = [0u8; MAX_PATH];
    let path_len = match read_pathname(agent_id, pathname_ptr, &mut path_buf) {
        Ok(len) => len,
        Err(err) => return err,
    };

    let mut norm_buf = [0u8; MAX_PATH];
    let path = if path_len == 0 {
        &[][..]
    } else {
        match resolve_path_at(agent_id, dirfd, &path_buf[..path_len], &mut norm_buf) {
            Ok(path) => path,
            Err(err) => return err,
        }
    };

    access_path_at(agent_id, dirfd, path, mode, flags)
}

// ── sys_readlink ───────────────────────────────────────────────────────────

/// Read the target of a symbolic link.
///
/// `/proc/self/exe` is handled specially and returns `"/app/binary"`.
/// All other paths return `-EINVAL` (no real symlinks).
fn readlink_path(agent_id: u16, path: &[u8], buf_ptr: u64, bufsiz: u64) -> i64 {
    let trace_python = super::state::trace_runtime_agent(agent_id);
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
        let result = match state::get_state(agent_id) {
            Some(s) if s.exe_path_len > 0 => &s.exe_path[..s.exe_path_len as usize],
            _ => b"/app/binary" as &[u8],
        };
        let to_copy = (bufsiz as usize).min(result.len());
        if !write_user_mem(agent_id, buf_ptr, &result[..to_copy]) {
            return -EFAULT;
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

    let ret = match metadata_for_path(agent_id, path, AT_SYMLINK_NOFOLLOW) {
        Ok(_) => -EINVAL,
        Err(err) => err,
    };

    if trace_python {
        crate::serial_println!(
            "[PYDBG] readlink-exit agent={} ret={} path={:?}",
            agent_id,
            ret,
            core::str::from_utf8(path).unwrap_or("?")
        );
    }
    ret
}

pub fn sys_readlink(agent_id: u16, pathname_ptr: u64, buf_ptr: u64, bufsiz: u64) -> i64 {
    let mut path_buf = [0u8; MAX_PATH];
    let path_len = match read_pathname(agent_id, pathname_ptr, &mut path_buf) {
        Ok(len) => len,
        Err(err) => return err,
    };
    if path_len == 0 {
        return -ENOENT;
    }
    let mut norm_buf = [0u8; MAX_PATH];
    let path = normalized_path(&path_buf[..path_len], &mut norm_buf);
    readlink_path(agent_id, path, buf_ptr, bufsiz)
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
    let mut path_buf = [0u8; MAX_PATH];
    let path_len = match read_pathname(agent_id, pathname_ptr, &mut path_buf) {
        Ok(len) => len,
        Err(err) => return err,
    };
    if path_len == 0 {
        return -ENOENT;
    }

    let mut norm_buf = [0u8; MAX_PATH];
    let path = match resolve_path_at(agent_id, dirfd, &path_buf[..path_len], &mut norm_buf) {
        Ok(path) => path,
        Err(err) => return err,
    };

    readlink_path(agent_id, path, buf_ptr, bufsiz)
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
        let meta = metadata_for_fd(agent_id, entry);
        if !fill_statx_from_meta(agent_id, statxbuf_ptr, meta) {
            return -EFAULT;
        }
        return 0;
    }

    let mut path_buf = [0u8; MAX_PATH];
    let path_len = match read_pathname(agent_id, pathname_ptr, &mut path_buf) {
        Ok(len) => len,
        Err(err) => return err,
    };
    if path_len == 0 {
        return -ENOENT;
    }

    let mut norm_buf = [0u8; MAX_PATH];
    let path = match resolve_path_at(agent_id, dirfd, &path_buf[..path_len], &mut norm_buf) {
        Ok(path) => path,
        Err(err) => return err,
    };

    match metadata_for_path(agent_id, path, flags) {
        Ok(meta) => {
            if !fill_statx_from_meta(agent_id, statxbuf_ptr, meta) {
                return -EFAULT;
            }
            0
        }
        Err(err) => err,
    }
}

/// Write a `struct statx` for a directory.
fn fill_statx_buf_dir(ptr: u64) {
    let _ = ptr;
}

/// Write a populated `struct statx` (256 bytes) to user memory.
fn fill_statx_buf(ptr: u64, file_size: u64, st_dev: u64, st_ino: u64) {
    let _ = (ptr, file_size, st_dev, st_ino);
}

// ── sys_statfs / sys_fstatfs ──────────────────────────────────────────────

pub fn sys_statfs(agent_id: u16, pathname_ptr: u64, statfs_ptr: u64) -> i64 {
    let mut path_buf = [0u8; MAX_PATH];
    let path_len = match read_pathname(agent_id, pathname_ptr, &mut path_buf) {
        Ok(len) => len,
        Err(err) => return err,
    };
    if path_len == 0 {
        return -ENOENT;
    }

    let mut norm_buf = [0u8; MAX_PATH];
    let path = match resolve_path_at(agent_id, AT_FDCWD, &path_buf[..path_len], &mut norm_buf) {
        Ok(path) => path,
        Err(err) => return err,
    };

    let meta = match statfs_for_path(agent_id, path) {
        Ok(meta) => meta,
        Err(err) => return err,
    };

    if !fill_statfs_from_meta(agent_id, statfs_ptr, meta) {
        return -EFAULT;
    }
    0
}

pub fn sys_fstatfs(agent_id: u16, fd: i32, statfs_ptr: u64) -> i64 {
    let st = match state::get_files_state(agent_id) {
        Some(s) => s,
        None => return -EBADF,
    };
    let entry = match st.get_fd(fd) {
        Some(e) if e.active => e,
        _ => return -EBADF,
    };
    let meta = statfs_for_fd(agent_id, entry);
    if !fill_statfs_from_meta(agent_id, statfs_ptr, meta) {
        return -EFAULT;
    }
    0
}

// ── sys_getdents64 ─────────────────────────────────────────────────────────

/// Read directory entries.
///
/// Enumerates active entries in the agent's keyspace as `linux_dirent64`
/// structures.  Each key is rendered as a 16-character hex filename.
/// The fd offset tracks how many entries have already been returned so
/// that successive calls eventually yield 0 (end of directory).
pub fn sys_getdents64(agent_id: u16, fd: i32, dirp_ptr: u64, count: u64) -> i64 {
    let st = match state::get_files_state_mut(agent_id) {
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

    let mut child_names = [[0u8; MAX_DIRENT_NAME]; MAX_DIRENTS_COLLECT];
    let mut child_lens = [0u16; MAX_DIRENTS_COLLECT];
    let mut child_dtypes = [0u8; MAX_DIRENTS_COLLECT];
    let child_count = collect_directory_entries(
        agent_id,
        &path[..path_len],
        &mut child_names,
        &mut child_lens,
        &mut child_dtypes,
    );

    let mut names = [[0u8; MAX_DIRENT_NAME]; MAX_DIRENTS_COLLECT];
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

        if !write_user_mem(agent_id, dirp_ptr + written as u64, &dirent[..reclen]) {
            return -EFAULT;
        }
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
/// Supports F_DUPFD/F_DUPFD_CLOEXEC, F_GETFD/F_SETFD, F_GETFL/F_SETFL.
pub fn sys_fcntl(agent_id: u16, fd: i32, cmd: u32, arg: u64) -> i64 {
    let st = match state::get_files_state_mut(agent_id) {
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
        F_DUPFD_CLOEXEC => {
            let min_fd = arg as usize;
            let entry = match st.get_fd(fd) {
                Some(e) if e.active => *e,
                _ => return -EBADF,
            };
            for i in min_fd..MAX_FDS {
                if st.fd_table[i].is_none() {
                    let cloned = match clone_fd_entry_with_cloexec(st, entry, true) {
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
    let st = match state::get_files_state_mut(agent_id) {
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

/// Duplicate a file descriptor to a specific slot.
///
/// Linux clears the close-on-exec flag on the duplicated descriptor unless
/// O_CLOEXEC is explicitly requested via dup3.
pub fn sys_dup3(agent_id: u16, oldfd: i32, newfd: i32, flags: u32) -> i64 {
    if oldfd == newfd {
        return -EINVAL;
    }
    if flags & !O_CLOEXEC != 0 {
        return -EINVAL;
    }
    if newfd < 0 || newfd as usize >= MAX_FDS {
        return -EBADF;
    }

    let st = match state::get_files_state_mut(agent_id) {
        Some(s) => s,
        None => return -EBADF,
    };
    let entry = match st.get_fd(oldfd) {
        Some(e) if e.active => *e,
        _ => return -EBADF,
    };

    st.close_fd(newfd);
    let cloned = match clone_fd_entry_with_cloexec(st, entry, (flags & O_CLOEXEC) != 0) {
        Ok(e) => e,
        Err(e) => return e,
    };
    st.fd_table[newfd as usize] = Some(cloned);
    newfd as i64
}

// ── sys_unlink ─────────────────────────────────────────────────────────────

/// Delete a file by removing its keyspace entry.
///
/// The pathname is hashed to a keyspace key and the corresponding entry
/// is marked inactive.  Returns 0 on success or `-ENOENT` if the key
/// did not exist.
fn rename_regular_file(agent_id: u16, old_path: &[u8], new_path: &[u8]) -> i64 {
    let (old_ks, old_key) = super::vfs::resolve_path(agent_id, old_path);
    if crate::state::query_file_size(old_ks, old_key) == 0
        && crate::state::state_get(old_ks, old_key).is_none()
    {
        return -ENOENT;
    }

    let data = match load_regular_file_data(old_ks, old_key) {
        Ok(data) => data,
        Err(err) if err == -ENOMEM => return -ENOMEM,
        Err(_) => return -EFAULT,
    };
    let (new_ks, new_key) = super::vfs::resolve_path(agent_id, new_path);
    if let Err(err) = store_regular_file_data(new_ks, new_key, &data) {
        log_regular_file_store_failure(agent_id, new_ks, new_key, data.len(), err);
        return -ENOSPC;
    }

    let _ = crate::state::state_delete(old_ks, old_key);
    state::remove_mutable_path(agent_id, old_path);
    let _ = state::record_mutable_path(agent_id, new_path, false);
    0
}

fn rename_directory_tree(agent_id: u16, old_path: &[u8], new_path: &[u8]) -> i64 {
    let mut entries: Vec<(Vec<u8>, bool)> = Vec::new();
    state::iter_mutable_paths(agent_id, |path, is_dir| {
        if path_is_same_or_child(path, old_path) {
            entries.push((path.to_vec(), is_dir));
        }
        true
    });

    if entries.is_empty() {
        return -ENOENT;
    }

    let mut files_to_copy: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    let mut new_entries: Vec<(Vec<u8>, bool)> = Vec::new();

    for (path, is_dir) in &entries {
        let Some(new_entry_path) = renamed_path(old_path, new_path, path) else {
            return -EINVAL;
        };
        if *is_dir {
            new_entries.push((new_entry_path, true));
        } else {
            files_to_copy.push((path.clone(), new_entry_path.clone()));
            new_entries.push((new_entry_path, false));
        }
    }

    for (old_file, new_file) in &files_to_copy {
        let (old_ks, old_key) = super::vfs::resolve_path(agent_id, old_file);
        let data = match load_regular_file_data(old_ks, old_key) {
            Ok(data) => data,
            Err(err) if err == -ENOMEM => return -ENOMEM,
            Err(_) => return -EFAULT,
        };
        let (new_ks, new_key) = super::vfs::resolve_path(agent_id, new_file);
        if let Err(err) = store_regular_file_data(new_ks, new_key, &data) {
            log_regular_file_store_failure(agent_id, new_ks, new_key, data.len(), err);
            return -ENOSPC;
        }
    }

    for (old_file, _) in &files_to_copy {
        let (old_ks, old_key) = super::vfs::resolve_path(agent_id, old_file);
        let _ = crate::state::state_delete(old_ks, old_key);
    }

    for (old_entry, _) in &entries {
        state::remove_mutable_path(agent_id, old_entry);
    }
    for (new_entry, is_dir) in &new_entries {
        if !state::record_mutable_path(agent_id, new_entry, *is_dir) {
            return -ENOSPC;
        }
    }

    0
}

pub fn sys_renameat2(
    agent_id: u16,
    olddirfd: i32,
    oldpath_ptr: u64,
    newdirfd: i32,
    newpath_ptr: u64,
    flags: u32,
) -> i64 {
    if flags & (RENAME_NOREPLACE | RENAME_EXCHANGE | RENAME_WHITEOUT) != 0 {
        return -EINVAL;
    }

    let mut old_buf = [0u8; MAX_PATH];
    let old_len = match read_pathname(agent_id, oldpath_ptr, &mut old_buf) {
        Ok(len) => len,
        Err(err) => return err,
    };
    if old_len == 0 {
        return -ENOENT;
    }

    let mut new_buf = [0u8; MAX_PATH];
    let new_len = match read_pathname(agent_id, newpath_ptr, &mut new_buf) {
        Ok(len) => len,
        Err(err) => return err,
    };
    if new_len == 0 {
        return -ENOENT;
    }

    let mut old_norm = [0u8; MAX_PATH];
    let old_path = match resolve_path_at(agent_id, olddirfd, &old_buf[..old_len], &mut old_norm) {
        Ok(path) => path,
        Err(err) => return err,
    };
    let mut new_norm = [0u8; MAX_PATH];
    let new_path = match resolve_path_at(agent_id, newdirfd, &new_buf[..new_len], &mut new_norm) {
        Ok(path) => path,
        Err(err) => return err,
    };

    if old_path == new_path {
        return 0;
    }

    if super::vfs::classify_base_image_path(old_path).is_some()
        || super::vfs::classify_base_image_path(new_path).is_some()
        || super::vfs::is_special_path(old_path).is_some()
        || super::vfs::is_special_path(new_path).is_some()
    {
        return -EROFS;
    }

    if !mutable_parent_exists(agent_id, new_path) {
        return -ENOENT;
    }

    let old_is_dir = matches!(state::lookup_mutable_path(agent_id, old_path), Some(true));
    if old_is_dir && path_is_same_or_child(new_path, old_path) {
        return -EINVAL;
    }
    let old_exists = if old_is_dir {
        true
    } else {
        let (old_ks, old_key) = super::vfs::resolve_path(agent_id, old_path);
        crate::state::query_file_size(old_ks, old_key) > 0 || crate::state::state_get(old_ks, old_key).is_some()
    };
    if !old_exists {
        return -ENOENT;
    }

    let new_is_dir = is_directory_path(agent_id, new_path);
    if old_is_dir && new_is_dir {
        if state::lookup_mutable_path(agent_id, new_path).is_some() {
            return -EEXIST;
        }
    } else if old_is_dir && !new_is_dir {
        let (new_ks, new_key) = super::vfs::resolve_path(agent_id, new_path);
        if crate::state::query_file_size(new_ks, new_key) > 0 || crate::state::state_get(new_ks, new_key).is_some() {
            return -ENOTDIR;
        }
    } else if !old_is_dir && new_is_dir {
        return -EISDIR;
    }

    if old_is_dir {
        return rename_directory_tree(agent_id, old_path, new_path);
    }

    rename_regular_file(agent_id, old_path, new_path)
}

pub fn sys_renameat(
    agent_id: u16,
    olddirfd: i32,
    oldpath_ptr: u64,
    newdirfd: i32,
    newpath_ptr: u64,
) -> i64 {
    sys_renameat2(agent_id, olddirfd, oldpath_ptr, newdirfd, newpath_ptr, 0)
}

pub fn sys_rename(agent_id: u16, oldpath_ptr: u64, newpath_ptr: u64) -> i64 {
    sys_renameat2(agent_id, AT_FDCWD, oldpath_ptr, AT_FDCWD, newpath_ptr, 0)
}

pub fn sys_unlink(agent_id: u16, pathname_ptr: u64) -> i64 {
    let mut path_buf = [0u8; MAX_PATH];
    let path_len = match read_pathname(agent_id, pathname_ptr, &mut path_buf) {
        Ok(len) => len,
        Err(err) => return err,
    };
    if path_len == 0 {
        return -ENOENT;
    }

    let mut norm_buf = [0u8; MAX_PATH];
    let path = match resolve_path_at(agent_id, AT_FDCWD, &path_buf[..path_len], &mut norm_buf) {
        Ok(path) => path,
        Err(err) => return err,
    };

    let (ks, key) = super::vfs::resolve_path(agent_id, path);
    match crate::state::state_delete(ks, key) {
        Ok(()) => {
            state::remove_mutable_path(agent_id, path);
            0
        }
        Err(_) => -ENOENT,
    }
}

pub fn sys_unlinkat(agent_id: u16, dirfd: i32, pathname_ptr: u64, flags: u32) -> i64 {
    let mut path_buf = [0u8; MAX_PATH];
    let path_len = match read_pathname(agent_id, pathname_ptr, &mut path_buf) {
        Ok(len) => len,
        Err(err) => return err,
    };
    if path_len == 0 {
        return -ENOENT;
    }

    let mut norm_buf = [0u8; MAX_PATH];
    let path = match resolve_path_at(agent_id, dirfd, &path_buf[..path_len], &mut norm_buf) {
        Ok(path) => path,
        Err(err) => return err,
    };

    if super::vfs::classify_base_image_path(path).is_some()
        || super::vfs::is_special_path(path).is_some()
    {
        return -EROFS;
    }

    let is_dir = is_directory_path(agent_id, path);
    if (flags & AT_REMOVEDIR) != 0 {
        if !is_dir {
            return -ENOTDIR;
        }
        if directory_has_children(agent_id, path) {
            return -ENOTEMPTY;
        }
        state::remove_mutable_path(agent_id, path);
        return 0;
    }

    if is_dir {
        return -EISDIR;
    }

    let (ks, key) = super::vfs::resolve_path(agent_id, path);
    match crate::state::state_delete(ks, key) {
        Ok(()) => {
            state::remove_mutable_path(agent_id, path);
            0
        }
        Err(_) => -ENOENT,
    }
}

pub fn sys_rmdir(agent_id: u16, pathname_ptr: u64) -> i64 {
    sys_unlinkat(agent_id, AT_FDCWD, pathname_ptr, AT_REMOVEDIR)
}

// ── sys_mkdir ──────────────────────────────────────────────────────────────

/// Create a directory.
///
pub fn sys_mkdir(agent_id: u16, pathname_ptr: u64, mode: u32) -> i64 {
    let _ = mode;

    let mut path_buf = [0u8; MAX_PATH];
    let path_len = match read_pathname(agent_id, pathname_ptr, &mut path_buf) {
        Ok(len) => len,
        Err(err) => return err,
    };
    if path_len == 0 {
        return -ENOENT;
    }

    let mut norm_buf = [0u8; MAX_PATH];
    let path = match resolve_path_at(agent_id, AT_FDCWD, &path_buf[..path_len], &mut norm_buf) {
        Ok(path) => path,
        Err(err) => return err,
    };

    if super::vfs::classify_base_image_path(path).is_some()
        || super::vfs::is_special_path(path).is_some()
    {
        return -EROFS;
    }

    if is_directory_path(agent_id, path) {
        return -EEXIST;
    }

    if !mutable_parent_exists(agent_id, path) {
        return -ENOENT;
    }

    if state::record_mutable_path(agent_id, path, true) {
        0
    } else {
        -ENOSPC
    }
}

// ── sys_fchdir ─────────────────────────────────────────────────────────────

/// Change working directory via an open fd.
///
/// The fd must reference a directory handle.
pub fn sys_fchdir(agent_id: u16, fd: i32) -> i64 {
    let st = match state::get_files_state(agent_id) {
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

    let Some(st) = state::get_state_mut(agent_id) else {
        return -EBADF;
    };

    let copy_len = handle.path_len as usize;
    st.cwd[..copy_len].copy_from_slice(&handle.path[..copy_len]);
    st.cwd_len = copy_len as u16;
    0
}

fn clone_fd_entry_with_cloexec(
    st: &mut state::LinuxAgentState,
    entry: FdEntry,
    cloexec: bool,
) -> Result<FdEntry, i64> {
    if entry.kind == FdKind::Directory {
        let Some(handle_id) = st.clone_directory_handle(entry.keyspace_key as u16) else {
            return Err(-EMFILE);
        };

        return Ok(FdEntry {
            keyspace_key: handle_id as u64,
            flags: (entry.flags & !O_CLOEXEC) | if cloexec { O_CLOEXEC } else { 0 },
            ..entry
        });
    }

    state::retain_fd_resources(&entry);
    Ok(FdEntry {
        flags: (entry.flags & !O_CLOEXEC) | if cloexec { O_CLOEXEC } else { 0 },
        ..entry
    })
}

fn clone_fd_entry(st: &mut state::LinuxAgentState, entry: FdEntry) -> Result<FdEntry, i64> {
    clone_fd_entry_with_cloexec(st, entry, false)
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

    if !write_user_mem(agent_id, buf_ptr, &st.cwd[..cwd_len])
        || !write_user_mem(agent_id, buf_ptr + cwd_len as u64, &[0])
    {
        return -EFAULT;
    }
    buf_ptr as i64
}

// ── sys_flock ──────────────────────────────────────────────────────────────

/// Apply or remove an advisory lock on an open file.
///
/// No-op in Stage-1 (single agent, no contention).
pub fn sys_flock(agent_id: u16, fd: i32, operation: u32) -> i64 {
    let _ = operation;

    let st = match state::get_files_state(agent_id) {
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
    let st = match state::get_files_state(agent_id) {
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
    let new_len = length as usize;
    let mut file_data = match load_regular_file_data(ks, key) {
        Ok(data) => data,
        Err(err) if err == -ENOMEM => return -ENOMEM,
        Err(_) => return -EFAULT,
    };
    if file_data.len() > new_len {
        file_data.truncate(new_len);
    } else if file_data.len() < new_len {
        file_data.resize(new_len, 0);
    }

    match store_regular_file_data(ks, key, &file_data) {
        Ok(()) => 0,
        Err(err) => {
            log_regular_file_store_failure(agent_id, ks, key, file_data.len(), err);
            -ENOSPC
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
    const TCGETS: u64 = 0x5401;
    const TIOCGWINSZ: u64 = 0x5413;
    const FIONREAD: u64 = 0x541B;
    const FIONBIO: u64 = 0x5421;
    const FIOCLEX: u64 = 0x5451;
    const FIONCLEX: u64 = 0x5450;
    const ENOTTY: i64 = 25;

    let st = match state::get_files_state_mut(agent_id) {
        Some(s) => s,
        None => return -EBADF,
    };

    let entry = match st.get_fd_mut(fd) {
        Some(e) if e.active => e,
        _ => return -EBADF,
    };

    match cmd {
        // Non-terminal fds report ENOTTY for tty-style probes.
        TCGETS | TIOCGWINSZ => -ENOTTY,
        FIOCLEX => {
            entry.flags |= O_CLOEXEC;
            0
        }
        FIONCLEX => {
            entry.flags &= !O_CLOEXEC;
            0
        }
        FIONBIO => {
            if arg == 0 {
                return -EFAULT;
            }
            let mut buf = [0u8; 4];
            let len = buf.len();
            if !read_user_mem(agent_id, arg, &mut buf, len) {
                return -EFAULT;
            }
            let enabled = i32::from_ne_bytes(buf) != 0;
            if enabled {
                entry.flags |= O_NONBLOCK;
            } else {
                entry.flags &= !O_NONBLOCK;
            }
            0
        }
        FIONREAD => {
            if arg == 0 {
                return -EFAULT;
            }
            let available = match entry.kind {
                FdKind::File => {
                    let file_size =
                        crate::state::query_file_size(entry.keyspace_id, entry.keyspace_key) as u64;
                    file_size.saturating_sub(entry.offset).min(i32::MAX as u64) as i32
                }
                FdKind::Pipe => state::pipe_available(entry.keyspace_key as u16)
                    .unwrap_or(0)
                    .min(i32::MAX as usize) as i32,
                FdKind::Socket => {
                    if entry.keyspace_key == SOCKETPAIR_STREAM_MARKER {
                        let Some((read_handle, _write_handle)) =
                            state::unix_stream_handles(entry.keyspace_id)
                        else {
                            return -EBADF;
                        };
                        state::pipe_available(read_handle)
                            .unwrap_or(0)
                            .min(i32::MAX as usize) as i32
                    } else {
                        match crate::mailbox::get_mailbox(entry.mailbox_id) {
                            Some(mb) if !mb.is_empty() => match &mb.buffer[mb.read_pos] {
                                Some(msg) => msg.len as i32,
                                None => 0,
                            },
                            _ => 0,
                        }
                    }
                }
                FdKind::EventFd => {
                    if eventfd_handle(entry)
                        .and_then(state::eventfd_counter)
                        .map(|counter| counter > 0)
                        .unwrap_or(false)
                    {
                        8
                    } else {
                        0
                    }
                }
                FdKind::TimerFd => {
                    if timerfd_handle(entry)
                        .map(state::timerfd_read_ready)
                        .unwrap_or(false)
                    {
                        8
                    } else {
                        0
                    }
                }
                FdKind::Directory | FdKind::Epoll => 0,
            };
            if !write_user_mem(agent_id, arg, &available.to_ne_bytes()) {
                return -EFAULT;
            }
            0
        }
        _ => -EINVAL,
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

/// lstat(path, statbuf) -> 0 or error
pub fn sys_lstat(agent_id: u16, path_ptr: u64, statbuf: u64) -> i64 {
    sys_newfstatat(agent_id, AT_FDCWD, path_ptr, statbuf, AT_SYMLINK_NOFOLLOW)
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

    let st = match state::get_files_state(agent_id) {
        Some(s) => s,
        None => return -EINVAL,
    };

    let count = nfds.min(256) as usize;
    let mut ready: i64 = 0;

    for i in 0..count {
        let pfd_addr = fds + (i as u64) * POLLFD_SIZE;
        let Some(fd) = read_user_i32(agent_id, pfd_addr) else {
            return -EFAULT;
        };
        let Some(events) = read_user_i16(agent_id, pfd_addr + 4) else {
            return -EFAULT;
        };

        let revents: i16 = match st.get_fd(fd) {
            Some(entry) if entry.active => {
                let mut r: i16 = 0;
                match entry.kind {
                    FdKind::File | FdKind::Directory => {
                        if events & POLLIN != 0 && fd_allows_read(entry.kind, entry.flags) {
                            r |= POLLIN;
                        }
                        if events & POLLOUT != 0 && fd_allows_write(entry.kind, entry.flags) {
                            r |= POLLOUT;
                        }
                    }
                    FdKind::Pipe => {
                        if events & POLLOUT != 0
                            && fd_allows_write(entry.kind, entry.flags)
                            && state::pipe_write_ready(entry.keyspace_key as u16)
                        {
                            r |= POLLOUT;
                        }
                        if events & POLLIN != 0 && fd_allows_read(entry.kind, entry.flags) {
                            if state::pipe_read_ready(entry.keyspace_key as u16) {
                                r |= POLLIN;
                            }
                        }
                    }
                    FdKind::Socket => {
                        if events & POLLOUT != 0 && fd_allows_write(entry.kind, entry.flags) {
                            r |= POLLOUT;
                        }
                        if events & POLLIN != 0 && fd_allows_read(entry.kind, entry.flags) {
                            if crate::mailbox::mailbox_fd_read_ready(entry.mailbox_id) {
                                r |= POLLIN;
                            }
                        }
                    }
                    FdKind::EventFd => {
                        if events & POLLIN != 0
                            && eventfd_handle(entry)
                                .map(state::eventfd_read_ready)
                                .unwrap_or(false)
                        {
                            r |= POLLIN;
                        }
                        if events & POLLOUT != 0
                            && eventfd_handle(entry)
                                .map(state::eventfd_write_ready)
                                .unwrap_or(false)
                        {
                            r |= POLLOUT;
                        }
                    }
                    FdKind::TimerFd => {
                        if events & POLLIN != 0
                            && timerfd_handle(entry)
                                .map(state::timerfd_read_ready)
                                .unwrap_or(false)
                        {
                            r |= POLLIN;
                        }
                    }
                    FdKind::Epoll => {}
                }
                r
            }
            _ => POLLNVAL,
        };

        // Write revents back to user memory
        if !write_user_mem(agent_id, pfd_addr + 6, &revents.to_ne_bytes()) {
            return -EFAULT;
        }

        if revents != 0 {
            ready += 1;
        }
    }

    ready
}

/// pwrite64 stub
pub fn sys_pwrite64(agent_id: u16, fd: i32, buf_ptr: u64, count: u64, offset: u64) -> i64 {
    let st = match state::get_files_state(agent_id) {
        Some(s) => s,
        None => return -EBADF,
    };

    let entry = match st.get_fd(fd) {
        Some(e) if e.active => e,
        _ => return -EBADF,
    };

    if !fd_allows_write(entry.kind, entry.flags) {
        return -EBADF;
    }

    if entry.kind != FdKind::File {
        if entry.kind == FdKind::Directory {
            return -EISDIR;
        }
        return -EINVAL;
    }

    match write_regular_file_data(
        agent_id,
        entry.keyspace_id,
        entry.keyspace_key,
        offset,
        entry.flags & !O_APPEND,
        buf_ptr,
        count as usize,
    ) {
        Ok((written, _)) => written as i64,
        Err(err) => err,
    }
}

/// readv — scatter-gather read
pub fn sys_readv(agent_id: u16, fd: i32, iov_ptr: u64, iovcnt: u64) -> i64 {
    let mut total: i64 = 0;
    for i in 0..iovcnt as usize {
        let iov_addr = iov_ptr + (i * 16) as u64;
        let Some(base) = read_user_u64(agent_id, iov_addr) else {
            return if total > 0 { total } else { -EFAULT };
        };
        let Some(len) = read_user_u64(agent_id, iov_addr + 8) else {
            return if total > 0 { total } else { -EFAULT };
        };
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
        let Some(base) = read_user_u64(agent_id, iov_addr) else {
            return if total > 0 { total } else { -EFAULT };
        };
        let Some(len) = read_user_u64(agent_id, iov_addr + 8) else {
            return if total > 0 { total } else { -EFAULT };
        };
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
    if pipefd_ptr == 0 {
        return -EFAULT;
    }

    let pipe_handle = match state::alloc_pipe() {
        Some(handle) => handle,
        None => return -ENOSPC,
    };

    let st = match state::get_files_state_mut(agent_id) {
        Some(s) => s,
        None => return -EBADF,
    };

    let read_fd = match st.alloc_fd() {
        Some(f) => f,
        None => return -EMFILE,
    };
    st.fd_table[read_fd] = Some(FdEntry {
        kind: FdKind::Pipe,
        keyspace_key: pipe_handle as u64,
        keyspace_id: 0,
        mailbox_id: 0,
        offset: 0,
        flags: O_RDONLY,
        active: true,
    });
    if let Some(entry) = st.fd_table[read_fd].as_ref() {
        state::retain_fd_resources(entry);
    }

    let write_fd = match st.alloc_fd() {
        Some(f) => f,
        None => {
            st.close_fd(read_fd as i32);
            return -EMFILE;
        }
    };
    st.fd_table[write_fd] = Some(FdEntry {
        kind: FdKind::Pipe,
        keyspace_key: pipe_handle as u64,
        keyspace_id: 0,
        mailbox_id: 0,
        offset: 0,
        flags: O_WRONLY,
        active: true,
    });
    if let Some(entry) = st.fd_table[write_fd].as_ref() {
        state::retain_fd_resources(entry);
    }

    let mut pipefd_bytes = [0u8; 8];
    pipefd_bytes[0..4].copy_from_slice(&(read_fd as i32).to_ne_bytes());
    pipefd_bytes[4..8].copy_from_slice(&(write_fd as i32).to_ne_bytes());
    if !write_user_mem(agent_id, pipefd_ptr, &pipefd_bytes) {
        st.close_fd(read_fd as i32);
        st.close_fd(write_fd as i32);
        return -EFAULT;
    }
    if state::trace_runtime_agent(agent_id) {
        crate::serial_println!(
            "[RTDBG] pipe agent={} handle={} read_fd={} write_fd={}",
            agent_id,
            pipe_handle,
            read_fd,
            write_fd
        );
    }
    0
}

/// pipe2(pipefd, flags)
pub fn sys_pipe2(agent_id: u16, pipefd_ptr: u64, flags: i32) -> i64 {
    let flags = flags as u32;
    let supported = O_CLOEXEC | O_NONBLOCK;
    if flags & !supported != 0 {
        return -EINVAL;
    }

    let ret = sys_pipe(agent_id, pipefd_ptr);
    if ret < 0 {
        return ret;
    }

    let Some(read_fd) = read_user_i32(agent_id, pipefd_ptr) else {
        return -EFAULT;
    };
    let Some(write_fd) = read_user_i32(agent_id, pipefd_ptr + 4) else {
        return -EFAULT;
    };
    let Some(st) = state::get_files_state_mut(agent_id) else {
        return -EBADF;
    };
    if let Some(entry) = st.get_fd_mut(read_fd) {
        entry.flags |= flags;
    }
    if let Some(entry) = st.get_fd_mut(write_fd) {
        entry.flags |= flags;
    }
    0
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
    let st = match state::get_files_state(agent_id) {
        Some(s) => s,
        None => return -EINVAL,
    };

    let max_fd = nfds.min(256) as i32;
    let mut ready: i64 = 0;
    let set_len = ((max_fd.max(0) as usize) + 7) / 8;
    let mut read_in = [0u8; 32];
    let mut write_in = [0u8; 32];
    let mut read_out = [0u8; 32];
    let mut write_out = [0u8; 32];

    if readfds != 0 && !copy_from_user(agent_id, readfds, &mut read_in[..set_len]) {
        return -EFAULT;
    }
    if writefds != 0 && !copy_from_user(agent_id, writefds, &mut write_in[..set_len]) {
        return -EFAULT;
    }

    let test_bit = |set: &[u8], fd: i32| -> bool {
        let byte_idx = (fd / 8) as usize;
        let bit_idx = (fd % 8) as u8;
        set.get(byte_idx)
            .map(|byte| (*byte & (1 << bit_idx)) != 0)
            .unwrap_or(false)
    };

    let set_bit = |set: &mut [u8], fd: i32| {
        let byte_idx = (fd / 8) as usize;
        let bit_idx = (fd % 8) as u8;
        if let Some(byte) = set.get_mut(byte_idx) {
            *byte |= 1 << bit_idx;
        }
    };

    // Second pass: check readiness for each fd in ascending order (deterministic)
    for fd in 0..max_fd {
        let check_read = readfds != 0 && test_bit(&read_in[..set_len], fd);
        let check_write = writefds != 0 && test_bit(&write_in[..set_len], fd);

        if !check_read && !check_write {
            continue;
        }

        if let Some(entry) = st.get_fd(fd) {
            if !entry.active {
                continue;
            }

            let (can_read, can_write) = match entry.kind {
                FdKind::File | FdKind::Directory => (
                    fd_allows_read(entry.kind, entry.flags),
                    fd_allows_write(entry.kind, entry.flags),
                ),
                FdKind::Pipe => (
                    fd_allows_read(entry.kind, entry.flags)
                        && state::pipe_read_ready(entry.keyspace_key as u16),
                    fd_allows_write(entry.kind, entry.flags)
                        && state::pipe_write_ready(entry.keyspace_key as u16),
                ),
                FdKind::Socket => {
                    if entry.keyspace_key == SOCKETPAIR_STREAM_MARKER {
                        match state::unix_stream_handles(entry.keyspace_id) {
                            Some((read_handle, write_handle)) => (
                                fd_allows_read(entry.kind, entry.flags)
                                    && state::pipe_read_ready(read_handle),
                                fd_allows_write(entry.kind, entry.flags)
                                    && state::pipe_write_ready(write_handle),
                            ),
                            None => (false, false),
                        }
                    } else {
                        let readable = fd_allows_read(entry.kind, entry.flags)
                            && crate::mailbox::mailbox_fd_read_ready(entry.mailbox_id);
                        (readable, fd_allows_write(entry.kind, entry.flags))
                    }
                }
                FdKind::EventFd => (
                    eventfd_handle(entry)
                        .map(state::eventfd_read_ready)
                        .unwrap_or(false),
                    eventfd_handle(entry)
                        .map(state::eventfd_write_ready)
                        .unwrap_or(false),
                ),
                FdKind::TimerFd => (
                    timerfd_handle(entry)
                        .map(state::timerfd_read_ready)
                        .unwrap_or(false),
                    false,
                ),
                FdKind::Epoll => (false, false),
            };

            let mut marked = false;
            if can_read && check_read {
                set_bit(&mut read_out[..set_len], fd);
                marked = true;
            }
            if can_write && check_write {
                set_bit(&mut write_out[..set_len], fd);
                marked = true;
            }
            if marked {
                ready += 1;
            }
        }
    }

    if readfds != 0 && !write_user_mem(agent_id, readfds, &read_out[..set_len]) {
        return -EFAULT;
    }
    if writefds != 0 && !write_user_mem(agent_id, writefds, &write_out[..set_len]) {
        return -EFAULT;
    }

    ready
}

/// dup2(oldfd, newfd) -> newfd
pub fn sys_dup2(agent_id: u16, oldfd: i32, newfd: i32) -> i64 {
    if oldfd == newfd {
        let st = match state::get_files_state(agent_id) {
            Some(s) => s,
            None => return -EBADF,
        };
        return match st.get_fd(oldfd) {
            Some(e) if e.active => newfd as i64,
            _ => -EBADF,
        };
    }
    if newfd < 0 || newfd as usize >= MAX_FDS {
        return -EBADF;
    }
    let st = match state::get_files_state_mut(agent_id) {
        Some(s) => s,
        None => return -EBADF,
    };
    let entry = match st.get_fd(oldfd) {
        Some(e) if e.active => *e,
        _ => return -EBADF,
    };
    st.close_fd(newfd);
    let cloned = match clone_fd_entry_with_cloexec(st, entry, false) {
        Ok(e) => e,
        Err(e) => return e,
    };
    st.fd_table[newfd as usize] = Some(cloned);
    newfd as i64
}

pub fn sys_fsync(agent_id: u16, fd: i32) -> i64 {
    let st = match state::get_files_state(agent_id) {
        Some(s) => s,
        None => return -EBADF,
    };
    let entry = match st.get_fd(fd) {
        Some(e) if e.active => *e,
        _ => return -EBADF,
    };
    match entry.kind {
        FdKind::File | FdKind::Directory => {
            if entry.keyspace_id != super::vfs::BASE_IMAGE_KEYSPACE {
                crate::persist::save_state_to_disk();
            }
            0
        }
        FdKind::Pipe | FdKind::Socket | FdKind::Epoll | FdKind::EventFd | FdKind::TimerFd => {
            -EINVAL
        }
    }
}

pub fn sys_fdatasync(agent_id: u16, fd: i32) -> i64 {
    sys_fsync(agent_id, fd)
}

pub fn sys_sync() -> i64 {
    crate::persist::save_state_to_disk();
    0
}

pub fn sys_syncfs(agent_id: u16, fd: i32) -> i64 {
    sys_fsync(agent_id, fd)
}

/// chdir(path)
pub fn sys_chdir(agent_id: u16, path_ptr: u64) -> i64 {
    let mut path_buf = [0u8; MAX_PATH];
    let path_len = match read_pathname(agent_id, path_ptr, &mut path_buf) {
        Ok(len) => len,
        Err(err) => return err,
    };
    if path_len == 0 {
        return -ENOENT;
    }

    let mut norm_buf = [0u8; MAX_PATH];
    let path = match resolve_path_at(agent_id, AT_FDCWD, &path_buf[..path_len], &mut norm_buf) {
        Ok(path) => path,
        Err(err) => return err,
    };

    if !is_directory_path(agent_id, path) {
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
