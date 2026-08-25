//! Linux x86-64 ABI: syscall numbers, errno values, flags, and the on-disk
//! struct encodings the guest expects.
//!
//! Syscall numbers match the kernel's `arch/x86/entry/syscalls/syscall_64.tbl`
//! (the native webTOS substrate keeps the same table in
//! `src/linux_compat/constants.rs`).

#![allow(dead_code)]

// ── Syscall numbers ─────────────────────────────────────────────────────────
pub const SYS_READ: u64 = 0;
pub const SYS_WRITE: u64 = 1;
pub const SYS_OPEN: u64 = 2;
pub const SYS_CLOSE: u64 = 3;
pub const SYS_STAT: u64 = 4;
pub const SYS_FSTAT: u64 = 5;
pub const SYS_LSTAT: u64 = 6;
pub const SYS_POLL: u64 = 7;
pub const SYS_LSEEK: u64 = 8;
pub const SYS_MMAP: u64 = 9;
pub const SYS_MPROTECT: u64 = 10;
pub const SYS_MUNMAP: u64 = 11;
pub const SYS_BRK: u64 = 12;
pub const SYS_MADVISE: u64 = 28;
pub const SYS_RT_SIGACTION: u64 = 13;
pub const SYS_RT_SIGPROCMASK: u64 = 14;
pub const SYS_RT_SIGRETURN: u64 = 15;
pub const SYS_IOCTL: u64 = 16;
pub const SYS_PREAD64: u64 = 17;
pub const SYS_PWRITE64: u64 = 18;
pub const SYS_READV: u64 = 19;
pub const SYS_WRITEV: u64 = 20;
pub const SYS_ACCESS: u64 = 21;
pub const SYS_PIPE: u64 = 22;
pub const SYS_DUP: u64 = 32;
pub const SYS_DUP2: u64 = 33;
pub const SYS_DUP3: u64 = 292;
pub const SYS_SCHED_YIELD: u64 = 24;
pub const SYS_SELECT: u64 = 23;
pub const SYS_NANOSLEEP: u64 = 35;
pub const SYS_SENDFILE: u64 = 40;
pub const SYS_SOCKET: u64 = 41;
pub const SYS_CONNECT: u64 = 42;
pub const SYS_ACCEPT: u64 = 43;
pub const SYS_SENDTO: u64 = 44;
pub const SYS_RECVFROM: u64 = 45;
pub const SYS_SENDMSG: u64 = 46;
pub const SYS_RECVMSG: u64 = 47;
pub const SYS_SHUTDOWN: u64 = 48;
pub const SYS_BIND: u64 = 49;
pub const SYS_LISTEN: u64 = 50;
pub const SYS_GETSOCKNAME: u64 = 51;
pub const SYS_GETPEERNAME: u64 = 52;
pub const SYS_SOCKETPAIR: u64 = 53;
pub const SYS_SETSOCKOPT: u64 = 54;
pub const SYS_GETSOCKOPT: u64 = 55;
pub const SYS_GETPID: u64 = 39;
pub const SYS_CLONE: u64 = 56;
pub const SYS_FORK: u64 = 57;
pub const SYS_VFORK: u64 = 58;
pub const SYS_EXECVE: u64 = 59;
pub const SYS_EXIT: u64 = 60;
pub const SYS_WAIT4: u64 = 61;
pub const SYS_KILL: u64 = 62;
pub const SYS_UNAME: u64 = 63;
pub const SYS_FCNTL: u64 = 72;
pub const SYS_FSYNC: u64 = 74;
pub const SYS_GETDENTS: u64 = 78;
pub const SYS_GETCWD: u64 = 79;
pub const SYS_CHDIR: u64 = 80;
pub const SYS_FCHDIR: u64 = 81;
pub const SYS_RENAME: u64 = 82;
pub const SYS_MKDIR: u64 = 83;
pub const SYS_RMDIR: u64 = 84;
pub const SYS_CREAT: u64 = 85;
pub const SYS_LINK: u64 = 86;
pub const SYS_UNLINK: u64 = 87;
pub const SYS_SYMLINK: u64 = 88;
pub const SYS_READLINK: u64 = 89;
pub const SYS_CHMOD: u64 = 90;
pub const SYS_FCHMOD: u64 = 91;
pub const SYS_CHOWN: u64 = 92;
pub const SYS_UMASK: u64 = 95;
pub const SYS_GETTIMEOFDAY: u64 = 96;
pub const SYS_GETUID: u64 = 102;
pub const SYS_GETGID: u64 = 104;
pub const SYS_GETEUID: u64 = 107;
pub const SYS_GETEGID: u64 = 108;
pub const SYS_GETPPID: u64 = 110;
pub const SYS_GETPGRP: u64 = 111;
pub const SYS_SETSID: u64 = 112;
pub const SYS_GETGROUPS: u64 = 115;
pub const SYS_GETPGID: u64 = 121;
pub const SYS_SIGALTSTACK: u64 = 131;
pub const SYS_ARCH_PRCTL: u64 = 158;
pub const SYS_SETRLIMIT: u64 = 160;
pub const SYS_SYNC: u64 = 162;
pub const SYS_GETTID: u64 = 186;
pub const SYS_TIME: u64 = 201;
pub const SYS_FUTEX: u64 = 202;
pub const SYS_EPOLL_CREATE: u64 = 213;
pub const SYS_SCHED_GETAFFINITY: u64 = 204;
pub const SYS_GETDENTS64: u64 = 217;
pub const SYS_SET_TID_ADDRESS: u64 = 218;
pub const SYS_CLOCK_GETTIME: u64 = 228;
pub const SYS_CLOCK_GETRES: u64 = 229;
pub const SYS_CLOCK_NANOSLEEP: u64 = 230;
pub const SYS_EXIT_GROUP: u64 = 231;
pub const SYS_EPOLL_WAIT: u64 = 232;
pub const SYS_EPOLL_CTL: u64 = 233;
pub const SYS_TGKILL: u64 = 234;
pub const SYS_OPENAT: u64 = 257;
pub const SYS_MKDIRAT: u64 = 258;
pub const SYS_FCHOWNAT: u64 = 260;
pub const SYS_NEWFSTATAT: u64 = 262;
pub const SYS_UNLINKAT: u64 = 263;
pub const SYS_RENAMEAT: u64 = 264;
pub const SYS_LINKAT: u64 = 265;
pub const SYS_SYMLINKAT: u64 = 266;
pub const SYS_READLINKAT: u64 = 267;
pub const SYS_FCHMODAT: u64 = 268;
pub const SYS_FACCESSAT: u64 = 269;
pub const SYS_PSELECT6: u64 = 270;
pub const SYS_PPOLL: u64 = 271;
pub const SYS_SET_ROBUST_LIST: u64 = 273;
pub const SYS_UTIMENSAT: u64 = 280;
pub const SYS_EPOLL_PWAIT: u64 = 281;
pub const SYS_TIMERFD_CREATE: u64 = 283;
pub const SYS_EVENTFD: u64 = 284;
pub const SYS_TIMERFD_SETTIME: u64 = 286;
pub const SYS_TIMERFD_GETTIME: u64 = 287;
pub const SYS_ACCEPT4: u64 = 288;
pub const SYS_EVENTFD2: u64 = 290;
pub const SYS_EPOLL_CREATE1: u64 = 291;
pub const SYS_PIPE2: u64 = 293;
pub const SYS_PRLIMIT64: u64 = 302;
pub const SYS_GETRANDOM: u64 = 318;
pub const SYS_STATX: u64 = 332;
pub const SYS_RSEQ: u64 = 334;
pub const SYS_FACCESSAT2: u64 = 439;

// ── Errno ───────────────────────────────────────────────────────────────────
pub const EPERM: u64 = 1;
pub const ENOENT: u64 = 2;
pub const ESRCH: u64 = 3;
pub const EINTR: u64 = 4;
pub const E2BIG: u64 = 7;
pub const ENOEXEC: u64 = 8;
pub const EIO: u64 = 5;
pub const EBADF: u64 = 9;
pub const ECHILD: u64 = 10;
pub const EAGAIN: u64 = 11;
pub const ENOMEM: u64 = 12;
pub const EACCES: u64 = 13;
pub const EFAULT: u64 = 14;
pub const EEXIST: u64 = 17;
pub const EPIPE: u64 = 32;
pub const ENOTDIR: u64 = 20;
pub const EISDIR: u64 = 21;
pub const EINVAL: u64 = 22;
pub const EMFILE: u64 = 24;
pub const ENOTTY: u64 = 25;
pub const ESPIPE: u64 = 29;
pub const ERANGE: u64 = 34;
pub const ENOSYS: u64 = 38;
pub const ENOTEMPTY: u64 = 39;
pub const ELOOP: u64 = 40;
pub const EDESTADDRREQ: u64 = 89;
pub const EPROTONOSUPPORT: u64 = 93;
pub const EOPNOTSUPP: u64 = 95;
pub const EAFNOSUPPORT: u64 = 97;
pub const EADDRINUSE: u64 = 98;
pub const ENETUNREACH: u64 = 101;
pub const ECONNRESET: u64 = 104;
pub const ENOTSOCK: u64 = 88;
pub const ENOTCONN: u64 = 107;
pub const ETIMEDOUT: u64 = 110;
pub const ECONNREFUSED: u64 = 111;

/// Encodes `-errno` in the register-return convention.
pub const fn neg(errno: u64) -> u64 {
    errno.wrapping_neg()
}

// ── open(2) flags ───────────────────────────────────────────────────────────
pub const O_ACCMODE: u64 = 0o3;
pub const O_RDONLY: u64 = 0o0;
pub const O_WRONLY: u64 = 0o1;
pub const O_RDWR: u64 = 0o2;
pub const O_CREAT: u64 = 0o100;
pub const O_EXCL: u64 = 0o200;
pub const O_TRUNC: u64 = 0o1000;
pub const O_APPEND: u64 = 0o2000;
pub const O_NONBLOCK: u64 = 0o4000;
pub const O_DIRECTORY: u64 = 0o200000;
pub const O_NOFOLLOW: u64 = 0o400000;
pub const O_CLOEXEC: u64 = 0o2000000;

pub const AT_FDCWD: u64 = (-100_i64) as u64;
pub const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
pub const AT_REMOVEDIR: u64 = 0x200;
pub const AT_EMPTY_PATH: u64 = 0x1000;

// ── lseek(2) ────────────────────────────────────────────────────────────────
pub const SEEK_SET: u64 = 0;
pub const SEEK_CUR: u64 = 1;
pub const SEEK_END: u64 = 2;

// ── fcntl(2) ────────────────────────────────────────────────────────────────
pub const F_DUPFD: u64 = 0;
pub const F_GETFD: u64 = 1;
pub const F_SETFD: u64 = 2;
pub const F_GETFL: u64 = 3;
pub const F_SETFL: u64 = 4;
pub const F_DUPFD_CLOEXEC: u64 = 1030;
pub const FD_CLOEXEC: u64 = 1;

// ── ioctl(2) ────────────────────────────────────────────────────────────────
pub const TCGETS: u64 = 0x5401;
pub const TCSETS: u64 = 0x5402;
pub const TCSETSW: u64 = 0x5403;
pub const TIOCGWINSZ: u64 = 0x5413;
pub const TIOCSWINSZ: u64 = 0x5414;
pub const TIOCGPGRP: u64 = 0x540F;
pub const TIOCSPGRP: u64 = 0x5410;

// ── mmap(2) ─────────────────────────────────────────────────────────────────
pub const PROT_READ: u64 = 0x1;
pub const PROT_WRITE: u64 = 0x2;
pub const PROT_EXEC: u64 = 0x4;
pub const MAP_SHARED: u64 = 0x01;
pub const MAP_PRIVATE: u64 = 0x02;
pub const MAP_FIXED: u64 = 0x10;
pub const MAP_ANONYMOUS: u64 = 0x20;

// ── arch_prctl(2) ───────────────────────────────────────────────────────────
pub const ARCH_SET_FS: u64 = 0x1002;
pub const ARCH_GET_FS: u64 = 0x1003;

// ── File modes ──────────────────────────────────────────────────────────────
pub const S_IFMT: u32 = 0o170000;
pub const S_IFDIR: u32 = 0o040000;
pub const S_IFCHR: u32 = 0o020000;
pub const S_IFIFO: u32 = 0o010000;
pub const S_IFREG: u32 = 0o100000;
pub const S_IFLNK: u32 = 0o120000;

// ── dirent64 d_type ─────────────────────────────────────────────────────────
pub const DT_UNKNOWN: u8 = 0;
pub const DT_DIR: u8 = 4;
pub const DT_REG: u8 = 8;
pub const DT_LNK: u8 = 10;
pub const DT_CHR: u8 = 2;

/// Fields written by `stat`-family syscalls, encoded to the x86-64
/// `struct stat` layout (144 bytes).
#[derive(Debug, Clone, Copy, Default)]
pub struct Stat {
    pub dev: u64,
    pub ino: u64,
    pub nlink: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub rdev: u64,
    pub size: i64,
    pub blksize: i64,
    pub blocks: i64,
    pub atime_sec: i64,
    pub atime_nsec: i64,
    pub mtime_sec: i64,
    pub mtime_nsec: i64,
    pub ctime_sec: i64,
    pub ctime_nsec: i64,
}

impl Stat {
    pub fn encode(&self) -> [u8; 144] {
        let mut out = [0_u8; 144];
        let mut put =
            |offset: usize, bytes: &[u8]| out[offset..offset + bytes.len()].copy_from_slice(bytes);
        put(0, &self.dev.to_le_bytes());
        put(8, &self.ino.to_le_bytes());
        put(16, &self.nlink.to_le_bytes());
        put(24, &self.mode.to_le_bytes());
        put(28, &self.uid.to_le_bytes());
        put(32, &self.gid.to_le_bytes());
        // 4 bytes padding at 36
        put(40, &self.rdev.to_le_bytes());
        put(48, &self.size.to_le_bytes());
        put(56, &self.blksize.to_le_bytes());
        put(64, &self.blocks.to_le_bytes());
        put(72, &self.atime_sec.to_le_bytes());
        put(80, &self.atime_nsec.to_le_bytes());
        put(88, &self.mtime_sec.to_le_bytes());
        put(96, &self.mtime_nsec.to_le_bytes());
        put(104, &self.ctime_sec.to_le_bytes());
        put(112, &self.ctime_nsec.to_le_bytes());
        // 3 reserved u64 at 120..144
        out
    }
}

/// Encodes one `linux_dirent64` record; returns None if it does not fit in
/// `remaining` bytes.
pub fn encode_dirent64(
    ino: u64,
    next_off: u64,
    d_type: u8,
    name: &[u8],
    remaining: usize,
) -> Option<Vec<u8>> {
    // header (19 bytes) + name + NUL, rounded up to 8.
    let reclen = (19 + name.len() + 1 + 7) & !7;
    if reclen > remaining {
        return None;
    }
    let mut rec = vec![0_u8; reclen];
    rec[0..8].copy_from_slice(&ino.to_le_bytes());
    rec[8..16].copy_from_slice(&next_off.to_le_bytes());
    rec[16..18].copy_from_slice(&(reclen as u16).to_le_bytes());
    rec[18] = d_type;
    rec[19..19 + name.len()].copy_from_slice(name);
    Some(rec)
}
