//! Linux x86_64 syscall number constants.
//!
//! These match the Linux kernel's arch/x86/entry/syscalls/syscall_64.tbl.

// ── File I/O ────────────────────────────────────────────────────────────────
pub const SYS_READ: u64 = 0;
pub const SYS_WRITE: u64 = 1;
pub const SYS_OPEN: u64 = 2;
pub const SYS_CLOSE: u64 = 3;
pub const SYS_STAT: u64 = 4;
pub const SYS_FSTAT: u64 = 5;
pub const SYS_LSTAT: u64 = 6;
pub const SYS_POLL: u64 = 7;
pub const SYS_LSEEK: u64 = 8;

// ── Memory management ───────────────────────────────────────────────────────
pub const SYS_MMAP: u64 = 9;
pub const SYS_MPROTECT: u64 = 10;
pub const SYS_MUNMAP: u64 = 11;
pub const SYS_BRK: u64 = 12;

// ── Signals ─────────────────────────────────────────────────────────────────
pub const SYS_RT_SIGACTION: u64 = 13;
pub const SYS_RT_SIGPROCMASK: u64 = 14;
pub const SYS_RT_SIGRETURN: u64 = 15;
pub const SYS_RT_SIGPENDING: u64 = 127;

// Marker for local AF_UNIX/socketpair byte-stream endpoints.
pub const LOCAL_INET_LISTENER_MARKER: u64 = 0xFFFF_FFFC;
pub const LOCAL_INET_STREAM_MARKER: u64 = 0xFFFF_FFFD;
pub const SOCKETPAIR_STREAM_MARKER: u64 = 0xFFFF_FFFE;
pub const SOCKET_FD_FLAG_LISTENING: u32 = 0x0100_0000;
pub const SOCKET_FD_FLAG_SHUT_RD: u32 = 0x0200_0000;
pub const SOCKET_FD_FLAG_SHUT_WR: u32 = 0x0400_0000;
pub const SOCKET_FD_FLAG_REUSEADDR: u32 = 0x0800_0000;
pub const SOCKET_FD_FLAG_REUSEPORT: u32 = 0x1000_0000;
pub const SOCKET_FD_FLAG_KEEPALIVE: u32 = 0x2000_0000;
pub const SOCKET_FD_FLAG_NODELAY: u32 = 0x4000_0000;

// ── I/O control ─────────────────────────────────────────────────────────────
pub const SYS_IOCTL: u64 = 16;
pub const SYS_PREAD64: u64 = 17;
pub const SYS_PWRITE64: u64 = 18;
pub const SYS_READV: u64 = 19;
pub const SYS_WRITEV: u64 = 20;
pub const SYS_ACCESS: u64 = 21;
pub const SYS_PIPE: u64 = 22;
pub const SYS_SELECT: u64 = 23;

// ── Scheduling ──────────────────────────────────────────────────────────────
pub const SYS_SCHED_YIELD: u64 = 24;
pub const SYS_MREMAP: u64 = 25;

// ── Memory sync ─────────────────────────────────────────────────────────────
pub const SYS_MSYNC: u64 = 26;
pub const SYS_MADVISE: u64 = 28;

// ── Duplicate FD ────────────────────────────────────────────────────────────
pub const SYS_DUP: u64 = 32;
pub const SYS_DUP2: u64 = 33;

// ── Timer/alarm ─────────────────────────────────────────────────────────────
pub const SYS_NANOSLEEP: u64 = 35;
pub const SYS_GETITIMER: u64 = 36;
pub const SYS_ALARM: u64 = 37;
pub const SYS_SETITIMER: u64 = 38;

// ── Process identity ────────────────────────────────────────────────────────
pub const SYS_GETPID: u64 = 39;
pub const SYS_TIME: u64 = 201;

// ── Networking ──────────────────────────────────────────────────────────────
pub const SYS_SOCKET: u64 = 41;
pub const SYS_CONNECT: u64 = 42;
pub const SYS_ACCEPT: u64 = 43;
pub const SYS_ACCEPT4: u64 = 288;
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

// ── Process control ─────────────────────────────────────────────────────────
pub const SYS_CLONE: u64 = 56;
pub const SYS_FORK: u64 = 57;
pub const SYS_VFORK: u64 = 58;
pub const SYS_EXECVE: u64 = 59;
pub const SYS_EXIT: u64 = 60;
pub const SYS_WAIT4: u64 = 61;
pub const SYS_WAITID: u64 = 247;
pub const SYS_KILL: u64 = 62;
pub const SYS_UNAME: u64 = 63;

// ── File control ────────────────────────────────────────────────────────────
pub const SYS_FCNTL: u64 = 72;
pub const SYS_FLOCK: u64 = 73;
pub const SYS_FSYNC: u64 = 74;
pub const SYS_FDATASYNC: u64 = 75;
pub const SYS_UMASK: u64 = 95;
pub const SYS_GETCWD: u64 = 79;
pub const SYS_CHDIR: u64 = 80;
pub const SYS_FCHDIR: u64 = 81;
pub const SYS_RENAME: u64 = 82;
pub const SYS_MKDIR: u64 = 83;
pub const SYS_RMDIR: u64 = 84;
pub const SYS_READLINK: u64 = 89;

// ── Identity ────────────────────────────────────────────────────────────────
pub const SYS_GETUID: u64 = 102;
pub const SYS_GETGID: u64 = 104;
pub const SYS_GETEUID: u64 = 107;
pub const SYS_GETEGID: u64 = 108;
pub const SYS_SETPGID: u64 = 109;
pub const SYS_GETPPID: u64 = 110;
pub const SYS_SETSID: u64 = 112;
pub const SYS_GETPGID: u64 = 121;
pub const SYS_GETSID: u64 = 124;
pub const SYS_GETGROUPS: u64 = 115;
pub const SYS_SETGROUPS: u64 = 116;

// ── Architecture ────────────────────────────────────────────────────────────
pub const SYS_ARCH_PRCTL: u64 = 158;
pub const SYS_SYNC: u64 = 162;

// ── Futex ───────────────────────────────────────────────────────────────────
pub const SYS_FUTEX: u64 = 202;

// ── Epoll ───────────────────────────────────────────────────────────────────
pub const SYS_EPOLL_CREATE: u64 = 213;
pub const SYS_GETDENTS64: u64 = 217;
pub const SYS_SET_TID_ADDRESS: u64 = 218;
pub const SYS_FADVISE64: u64 = 221;

// ── Time ────────────────────────────────────────────────────────────────────
pub const SYS_CLOCK_GETTIME: u64 = 228;
pub const SYS_CLOCK_GETRES: u64 = 229;
pub const SYS_EXIT_GROUP: u64 = 231;
pub const SYS_EPOLL_WAIT: u64 = 232;
pub const SYS_EPOLL_CTL: u64 = 233;
pub const SYS_TGKILL: u64 = 234;

// ── Robust futex / TLS ─────────────────────────────────────────────────────
pub const SYS_SET_ROBUST_LIST: u64 = 273;
pub const SYS_GET_ROBUST_LIST: u64 = 274;

// ── Eventfd / pipe2 / epoll_create1 ─────────────────────────────────────────
pub const SYS_EVENTFD2: u64 = 290;
pub const SYS_EPOLL_CREATE1: u64 = 291;
pub const SYS_DUP3: u64 = 292;
pub const SYS_PIPE2: u64 = 293;

// ── System info / process ───────────────────────────────────────────────────
pub const SYS_GETRUSAGE: u64 = 98;
pub const SYS_SYSINFO: u64 = 99;
pub const SYS_GETTIMEOFDAY: u64 = 96;
pub const SYS_CAPGET: u64 = 125;
pub const SYS_SIGALTSTACK: u64 = 131;
pub const SYS_STATFS: u64 = 137;
pub const SYS_FSTATFS: u64 = 138;
pub const SYS_SCHED_SETPARAM: u64 = 142;
pub const SYS_SCHED_GETPARAM: u64 = 143;
pub const SYS_SCHED_SETSCHEDULER: u64 = 144;
pub const SYS_SCHED_GETSCHEDULER: u64 = 145;
pub const SYS_PRCTL: u64 = 157;
pub const SYS_GETTID: u64 = 186;
pub const SYS_SCHED_GETAFFINITY: u64 = 204;
pub const SYS_GETCPU: u64 = 309;

// ── Misc ────────────────────────────────────────────────────────────────────
pub const SYS_FTRUNCATE: u64 = 77;
pub const SYS_UNLINK: u64 = 87;
pub const SYS_OPENAT: u64 = 257;
pub const SYS_MKDIRAT: u64 = 258;
pub const SYS_UNLINKAT: u64 = 263;
pub const SYS_NEWFSTATAT: u64 = 262;
pub const SYS_RENAMEAT: u64 = 264;
pub const SYS_SYMLINKAT: u64 = 266;
pub const SYS_CLOCK_NANOSLEEP: u64 = 230;
pub const SYS_READLINKAT: u64 = 267;
pub const SYS_FACCESSAT: u64 = 269;
pub const SYS_EPOLL_PWAIT: u64 = 281;
pub const SYS_TIMERFD_CREATE: u64 = 283;
pub const SYS_TIMERFD_SETTIME: u64 = 286;
pub const SYS_TIMERFD_GETTIME: u64 = 287;
pub const SYS_PRLIMIT64: u64 = 302;
pub const SYS_SYNCFS: u64 = 306;
pub const SYS_RENAMEAT2: u64 = 316;
pub const SYS_GETRANDOM: u64 = 318;
pub const SYS_MEMBARRIER: u64 = 324;
pub const SYS_STATX: u64 = 332;
pub const SYS_UTIMENSAT: u64 = 280;
pub const SYS_RSEQ: u64 = 334;
pub const SYS_IO_URING_SETUP: u64 = 425;
pub const SYS_IO_URING_ENTER: u64 = 426;
pub const SYS_CLONE3: u64 = 435;
pub const SYS_FACCESSAT2: u64 = 439;

// ── Linux errno values ──────────────────────────────────────────────────────
pub const EPERM: i64 = 1;
pub const ENOENT: i64 = 2;
pub const ESRCH: i64 = 3;
pub const EINTR: i64 = 4;
pub const EIO: i64 = 5;
pub const E2BIG: i64 = 7;
pub const ENOEXEC: i64 = 8;
pub const EBADF: i64 = 9;
pub const EAGAIN: i64 = 11;
pub const ENOMEM: i64 = 12;
pub const EACCES: i64 = 13;
pub const EFAULT: i64 = 14;
pub const EEXIST: i64 = 17;
pub const ENOTDIR: i64 = 20;
pub const EISDIR: i64 = 21;
pub const EINVAL: i64 = 22;
pub const EMFILE: i64 = 24;
pub const EROFS: i64 = 30;
pub const EPIPE: i64 = 32;
pub const ENOTEMPTY: i64 = 39;
pub const ELOOP: i64 = 40;
pub const ENOSPC: i64 = 28;
pub const ENOSYS: i64 = 38;
pub const ECHILD: i64 = 10;
pub const ENOTSOCK: i64 = 88;
pub const EAFNOSUPPORT: i64 = 97;
pub const EADDRINUSE: i64 = 98;
pub const ETIMEDOUT: i64 = 110;

// ── O_* flags ───────────────────────────────────────────────────────────────
pub const O_RDONLY: u32 = 0;
pub const O_WRONLY: u32 = 1;
pub const O_RDWR: u32 = 2;
pub const O_CREAT: u32 = 0o100;
pub const O_EXCL: u32 = 0o200;
pub const O_TRUNC: u32 = 0o1000;
pub const O_APPEND: u32 = 0o2000;
pub const O_NONBLOCK: u32 = 0o4000;
pub const O_CLOEXEC: u32 = 0o2000000;
pub const O_DIRECTORY: u32 = 0o200000;

// ── arch_prctl sub-commands ─────────────────────────────────────────────────
pub const ARCH_SET_GS: u64 = 0x1001;
pub const ARCH_SET_FS: u64 = 0x1002;
pub const ARCH_GET_FS: u64 = 0x1003;
pub const ARCH_GET_GS: u64 = 0x1004;
