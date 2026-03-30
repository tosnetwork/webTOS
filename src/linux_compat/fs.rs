//! File-system related Linux syscall implementations.
//!
//! Translates Linux file I/O syscalls into ATOS keyspace state operations.
//! Files are backed by the agent's private keyspace; pipes and sockets map
//! to ATOS mailbox IPC.

use super::constants::*;
use super::state::{self, FdEntry, FdKind, MAX_FDS};
use sha2::{Sha256, Digest};

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

const MAX_PATH: usize = 256;
const MAX_VALUE_SIZE: usize = 256;

// ── Helpers ────────────────────────────────────────────────────────────────

/// Hash a pathname to a deterministic u64 keyspace key using the first 8
/// bytes of its SHA-256 digest.
fn path_to_key(path: &[u8]) -> u64 {
    let hash = Sha256::digest(path);
    u64::from_le_bytes([
        hash[0], hash[1], hash[2], hash[3],
        hash[4], hash[5], hash[6], hash[7],
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
    let offset = entry.offset as usize;

    match kind {
        FdKind::File => {
            match crate::state::state_get(agent_id, key) {
                Some((value, value_len)) => {
                    if offset >= value_len {
                        return 0; // EOF
                    }
                    let available = value_len - offset;
                    let to_copy = (count as usize).min(available);
                    unsafe {
                        write_user_mem(buf_ptr, &value[offset..offset + to_copy]);
                    }
                    // Advance fd offset
                    if let Some(e) = st.get_fd_mut(fd) {
                        e.offset += to_copy as u64;
                    }
                    to_copy as i64
                }
                None => 0, // file empty / never written → EOF
            }
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

    match kind {
        FdKind::File => {
            let to_write = cnt.min(MAX_VALUE_SIZE);
            let mut value = [0u8; MAX_VALUE_SIZE];
            unsafe {
                read_user_mem(buf_ptr, &mut value, to_write);
            }
            match crate::state::state_put(agent_id, key, &value[..to_write]) {
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
    let _ = mode;  // permissions not enforced

    let mut path_buf = [0u8; MAX_PATH];
    let path_len = unsafe { read_pathname(pathname_ptr, &mut path_buf) };
    if path_len == 0 {
        return -ENOENT;
    }

    let key = path_to_key(&path_buf[..path_len]);

    let st = match state::get_state_mut(agent_id) {
        Some(s) => s,
        None => return -EFAULT,
    };

    let fd_idx = match st.alloc_fd() {
        Some(idx) => idx,
        None => return -EMFILE,
    };

    st.fd_table[fd_idx] = Some(FdEntry {
        kind: FdKind::File,
        keyspace_key: key,
        mailbox_id: 0,
        offset: 0,
        flags,
        active: true,
    });

    fd_idx as i64
}

// ── sys_close ──────────────────────────────────────────────────────────────

/// Close a file descriptor.
pub fn sys_close(agent_id: u16, fd: i32) -> i64 {
    let st = match state::get_state_mut(agent_id) {
        Some(s) => s,
        None => return -EBADF,
    };
    if st.close_fd(fd) { 0 } else { -EBADF }
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

    let file_size: u64 = if entry.kind == FdKind::File {
        match crate::state::state_get(agent_id, entry.keyspace_key) {
            Some((_val, len)) => len as u64,
            None => 0,
        }
    } else {
        0
    };

    fill_stat_buf(statbuf_ptr, file_size);
    0
}

/// Write a populated `struct stat` to user memory.
fn fill_stat_buf(ptr: u64, file_size: u64) {
    let mut buf = [0u8; 144];

    // st_dev = 1
    buf[0..8].copy_from_slice(&1u64.to_le_bytes());
    // st_ino = 1
    buf[8..16].copy_from_slice(&1u64.to_le_bytes());
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
    // AT_EMPTY_PATH with a valid dirfd → delegate to fstat
    if (flags & AT_EMPTY_PATH) != 0 && dirfd >= 0 {
        return sys_fstat(agent_id, dirfd, statbuf_ptr);
    }

    let _ = dirfd;

    let mut path_buf = [0u8; MAX_PATH];
    let path_len = unsafe { read_pathname(pathname_ptr, &mut path_buf) };
    if path_len == 0 {
        return -ENOENT;
    }

    let key = path_to_key(&path_buf[..path_len]);
    let file_size: u64 = match crate::state::state_get(agent_id, key) {
        Some((_val, len)) => len as u64,
        None => 0, // report size 0 for non-existent files
    };

    fill_stat_buf(statbuf_ptr, file_size);
    0
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
        return -EINVAL; // cannot seek pipes/sockets
    }

    let file_size: u64 = match crate::state::state_get(agent_id, entry.keyspace_key) {
        Some((_val, len)) => len as u64,
        None => 0,
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
    let st = match state::get_state(agent_id) {
        Some(s) => s,
        None => return -EBADF,
    };

    let entry = match st.get_fd(fd) {
        Some(e) if e.active => e,
        _ => return -EBADF,
    };

    if entry.kind != FdKind::File {
        return -EINVAL;
    }

    match crate::state::state_get(agent_id, entry.keyspace_key) {
        Some((value, value_len)) => {
            let off = offset as usize;
            if off >= value_len {
                return 0; // EOF
            }
            let available = value_len - off;
            let to_copy = (count as usize).min(available);
            unsafe {
                write_user_mem(buf_ptr, &value[off..off + to_copy]);
            }
            to_copy as i64
        }
        None => 0,
    }
}

// ── sys_access ─────────────────────────────────────────────────────────────

/// Check user permissions for a file.
///
/// All files in the agent's keyspace are accessible in Stage-1.
/// Returns 0 if the key exists, `-ENOENT` otherwise.
pub fn sys_access(agent_id: u16, pathname_ptr: u64, mode: u32) -> i64 {
    let _ = mode; // all modes granted

    let mut path_buf = [0u8; MAX_PATH];
    let path_len = unsafe { read_pathname(pathname_ptr, &mut path_buf) };
    if path_len == 0 {
        return -ENOENT;
    }

    let key = path_to_key(&path_buf[..path_len]);
    match crate::state::get(agent_id, key) {
        Some(_) => 0,
        None => -ENOENT,
    }
}

// ── sys_readlink ───────────────────────────────────────────────────────────

/// Read the target of a symbolic link.
///
/// `/proc/self/exe` is handled specially and returns `"/app/binary"`.
/// All other paths return `-EINVAL` (no real symlinks).
pub fn sys_readlink(agent_id: u16, pathname_ptr: u64, buf_ptr: u64, bufsiz: u64) -> i64 {
    let _ = agent_id;

    let mut path_buf = [0u8; MAX_PATH];
    let path_len = unsafe { read_pathname(pathname_ptr, &mut path_buf) };
    if path_len == 0 {
        return -ENOENT;
    }

    const PROC_SELF_EXE: &[u8] = b"/proc/self/exe";
    if path_len == PROC_SELF_EXE.len() && path_buf[..path_len] == *PROC_SELF_EXE {
        const RESULT: &[u8] = b"/app/binary";
        let to_copy = (bufsiz as usize).min(RESULT.len());
        unsafe {
            write_user_mem(buf_ptr, &RESULT[..to_copy]);
        }
        return to_copy as i64;
    }

    -EINVAL
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

    let already_returned = entry.offset as usize;
    let buf_size = count as usize;

    // Collect keys from the keyspace, skipping already-returned entries.
    // We use a fixed-size buffer to avoid allocation.
    const MAX_COLLECT: usize = 64;
    let mut keys: [u64; MAX_COLLECT] = [0u64; MAX_COLLECT];
    let mut key_count: usize = 0;
    let mut visited: usize = 0;

    crate::state::iter_entries(agent_id, |key, _value| {
        if visited >= already_returned && key_count < MAX_COLLECT {
            keys[key_count] = key;
            key_count += 1;
        }
        visited += 1;
        true
    });

    if key_count == 0 {
        // If this is the very first call, return a "." entry so programs
        // don't see a completely empty directory.
        if already_returned == 0 {
            // Build a minimal "." dirent64
            // d_ino(8) + d_off(8) + d_reclen(2) + d_type(1) + d_name(".\0") = 21
            // Align to 8 bytes → 24
            const DOT_RECLEN: u16 = 24;
            if buf_size < DOT_RECLEN as usize {
                return -EINVAL;
            }
            let mut buf = [0u8; 24];
            // d_ino = 1
            buf[0..8].copy_from_slice(&1u64.to_le_bytes());
            // d_off = 1 (offset to next)
            buf[8..16].copy_from_slice(&1u64.to_le_bytes());
            // d_reclen
            buf[16..18].copy_from_slice(&DOT_RECLEN.to_le_bytes());
            // d_type = DT_DIR = 4
            buf[18] = 4;
            // d_name = "."
            buf[19] = b'.';
            buf[20] = 0;
            unsafe { write_user_mem(dirp_ptr, &buf) }
            // Advance offset so next call returns 0
            if let Some(e) = st.get_fd_mut(fd) {
                e.offset = 1;
            }
            return DOT_RECLEN as i64;
        }
        return 0;
    }

    // Write dirent64 entries into the user buffer.
    let mut written: usize = 0;
    let mut entries_emitted: usize = 0;

    for idx in 0..key_count {
        // Render the key as a 16-char hex filename
        let key = keys[idx];
        let key_bytes = key.to_le_bytes();
        let mut name = [0u8; 17]; // 16 hex chars + null
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for j in 0..8 {
            name[j * 2] = HEX[(key_bytes[j] >> 4) as usize];
            name[j * 2 + 1] = HEX[(key_bytes[j] & 0xf) as usize];
        }
        name[16] = 0;

        // d_ino(8) + d_off(8) + d_reclen(2) + d_type(1) + d_name(17) = 36
        // Align to 8 bytes → 40
        let name_len = 17usize; // includes null terminator
        let reclen_raw = 8 + 8 + 2 + 1 + name_len;
        let reclen = (reclen_raw + 7) & !7; // align to 8

        if written + reclen > buf_size {
            break;
        }

        let mut dirent = [0u8; 40];
        // d_ino = key (use the key itself as inode number)
        dirent[0..8].copy_from_slice(&key.to_le_bytes());
        // d_off = offset to next entry
        let next_off = (already_returned + entries_emitted + 1) as u64;
        dirent[8..16].copy_from_slice(&next_off.to_le_bytes());
        // d_reclen
        dirent[16..18].copy_from_slice(&(reclen as u16).to_le_bytes());
        // d_type = DT_REG = 8
        dirent[18] = 8;
        // d_name
        dirent[19..19 + name_len].copy_from_slice(&name[..name_len]);

        unsafe { write_user_mem(dirp_ptr + written as u64, &dirent[..reclen]) }
        written += reclen;
        entries_emitted += 1;
    }

    // Advance the fd offset so the next call skips these entries
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
                    st.fd_table[i] = Some(entry);
                    return i as i64;
                }
            }
            -EMFILE
        }
        F_GETFD => {
            match st.get_fd(fd) {
                Some(e) if e.active => {
                    if (e.flags & O_CLOEXEC) != 0 { 1 } else { 0 }
                }
                _ => -EBADF,
            }
        }
        F_SETFD => {
            match st.get_fd_mut(fd) {
                Some(e) if e.active => {
                    if (arg & 1) != 0 {
                        e.flags |= O_CLOEXEC;
                    } else {
                        e.flags &= !O_CLOEXEC;
                    }
                    0
                }
                _ => -EBADF,
            }
        }
        F_GETFL => {
            match st.get_fd(fd) {
                Some(e) if e.active => e.flags as i64,
                _ => -EBADF,
            }
        }
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
            st.fd_table[new_fd] = Some(entry);
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
/// Validates the fd exists but is otherwise a no-op in Stage-1.
pub fn sys_fchdir(agent_id: u16, fd: i32) -> i64 {
    let st = match state::get_state(agent_id) {
        Some(s) => s,
        None => return -EBADF,
    };

    match st.get_fd(fd) {
        Some(e) if e.active => 0,
        _ => -EBADF,
    }
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
        return -EINVAL;
    }

    let key = entry.keyspace_key;

    if length == 0 {
        match crate::state::state_put(agent_id, key, &[]) {
            Ok(()) => 0,
            Err(_) => -ENOSPC,
        }
    } else {
        match crate::state::state_get(agent_id, key) {
            Some((value, value_len)) => {
                let new_len = (length as usize).min(value_len);
                match crate::state::state_put(agent_id, key, &value[..new_len]) {
                    Ok(()) => 0,
                    Err(_) => -ENOSPC,
                }
            }
            None => {
                // File doesn't exist; create zero-filled content.
                let zeros = [0u8; MAX_VALUE_SIZE];
                let new_len = (length as usize).min(MAX_VALUE_SIZE);
                match crate::state::state_put(agent_id, key, &zeros[..new_len]) {
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
/// Terminal ioctls on stdin/stdout/stderr return `-ENOTTY` so that
/// `isatty()` reports false and programs use non-interactive mode.
/// All other ioctls on regular fds return `-EINVAL`.
pub fn sys_ioctl(agent_id: u16, fd: i32, cmd: u64, arg: u64) -> i64 {
    let _ = arg;

    const TCGETS: u64 = 0x5401;
    const TIOCGWINSZ: u64 = 0x5413;
    const ENOTTY: i64 = 25;

    // stdin / stdout / stderr → not a tty
    if fd == 0 || fd == 1 || fd == 2 {
        if cmd == TCGETS || cmd == TIOCGWINSZ {
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
pub fn sys_poll(_agent_id: u16, _fds: u64, _nfds: u64, _timeout: i32) -> i64 {
    0 // no fds ready
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
    match crate::state::state_put(agent_id, entry.keyspace_key, &value[..to_write]) {
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
        None => return -ENOSYS,
    };

    let read_fd = match st.alloc_fd() {
        Some(f) => f,
        None => return -EMFILE,
    };
    st.fd_table[read_fd] = Some(FdEntry {
        kind: FdKind::Pipe,
        keyspace_key: 0,
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

/// select stub
pub fn sys_select(
    _agent_id: u16,
    _nfds: u64,
    _readfds: u64,
    _writefds: u64,
    _exceptfds: u64,
    _timeout: u64,
) -> i64 {
    0 // no fds ready
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
    st.fd_table[newfd as usize] = Some(entry);
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

    let st = match state::get_state_mut(agent_id) {
        Some(s) => s,
        None => return -EFAULT,
    };

    let copy_len = path_len.min(st.cwd.len());
    st.cwd[..copy_len].copy_from_slice(&path_buf[..copy_len]);
    st.cwd_len = copy_len as u8;
    0
}
