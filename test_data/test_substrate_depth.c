/*
 * test_substrate_depth.c — Verify deeper Linux substrate semantics
 *
 * Build:
 *   gcc -nostdlib -static -Os -s -Wl,-Ttext=0x40000000 \
 *     -o test_substrate_depth.elf test_substrate_depth.c
 */

typedef unsigned long u64;
typedef long i64;
typedef unsigned int u32;
typedef unsigned short u16;

#define SYS_WRITE 1
#define SYS_READ 0
#define SYS_CLOSE 3
#define SYS_MMAP 9
#define SYS_RT_SIGACTION 13
#define SYS_MREMAP 25
#define SYS_MSYNC 26
#define SYS_MUNMAP 11
#define SYS_NANOSLEEP 35
#define SYS_FSYNC 74
#define SYS_FDATASYNC 75
#define SYS_GETITIMER 36
#define SYS_SETITIMER 38
#define SYS_ALARM 37
#define SYS_GETPID 39
#define SYS_SOCKET 41
#define SYS_CONNECT 42
#define SYS_ACCEPT4 288
#define SYS_SETSOCKOPT 54
#define SYS_GETSOCKOPT 55
#define SYS_FORK 57
#define SYS_WAIT4 61
#define SYS_KILL 62
#define SYS_BIND 49
#define SYS_LISTEN 50
#define SYS_GETSOCKNAME 51
#define SYS_SETPGID 109
#define SYS_SETSID 112
#define SYS_GETPGID 121
#define SYS_GETSID 124
#define SYS_TIMERFD_CREATE 283
#define SYS_TIMERFD_SETTIME 286
#define SYS_TIMERFD_GETTIME 287
#define SYS_SYNC 162
#define SYS_GETCPU 309
#define SYS_MEMBARRIER 324
#define SYS_RSEQ 334
#define SYS_OPENAT 257
#define SYS_NEWFSTATAT 262
#define SYS_READLINKAT 267
#define SYS_SYNCFS 306
#define SYS_EXIT 60

#define PROT_READ 0x1
#define PROT_WRITE 0x2
#define MAP_SHARED 0x01
#define MAP_PRIVATE 0x02
#define MAP_ANONYMOUS 0x20

#define MS_ASYNC 0x1
#define MS_INVALIDATE 0x2
#define MS_SYNC 0x4

#define AT_FDCWD (-100)
#define AT_SYMLINK_NOFOLLOW 0x100
#define O_RDWR 2
#define O_NONBLOCK 0x800
#define O_CREAT 0x40
#define O_TRUNC 0x200

#define MREMAP_MAYMOVE 0x1
#define MREMAP_FIXED 0x2

#define EFAULT 14
#define EINVAL 22
#define ENOMEM 12
#define EPERM 1
#define EAGAIN 11

#define MODE_S_IFMT 0170000
#define MODE_S_IFREG 0100000
#define MODE_S_IFLNK 0120000

#define SIGALRM 14
#define SIG_IGN 1UL
#define SIGSET_BYTES 8

#define MEMBARRIER_CMD_QUERY 0
#define MEMBARRIER_CMD_GLOBAL (1u << 0)
#define MEMBARRIER_CMD_GLOBAL_EXPEDITED (1u << 1)
#define MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED (1u << 2)
#define MEMBARRIER_CMD_PRIVATE_EXPEDITED (1u << 3)
#define MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED (1u << 4)
#define MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE (1u << 5)
#define MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE (1u << 6)
#define MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ (1u << 7)
#define MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ (1u << 8)
#define MEMBARRIER_CMD_FLAG_CPU (1u << 0)
#define MEMBARRIER_SUPPORTED_MASK (MEMBARRIER_CMD_GLOBAL | \
                                   MEMBARRIER_CMD_GLOBAL_EXPEDITED | \
                                   MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED | \
                                   MEMBARRIER_CMD_PRIVATE_EXPEDITED | \
                                   MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED | \
                                   MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE | \
                                   MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE | \
                                   MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ | \
                                   MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ)

#define CLOCK_MONOTONIC 1
#define TFD_TIMER_ABSTIME 1
#define AF_INET 2
#define SOCK_STREAM 1
#define SOL_SOCKET 1
#define SOL_TCP 6
#define SO_REUSEADDR 2
#define SO_ERROR 4
#define SO_SNDBUF 7
#define SO_RCVBUF 8
#define SO_KEEPALIVE 9
#define SO_REUSEPORT 15
#define SO_ACCEPTCONN 30
#define TCP_NODELAY 1

struct sockaddr_in {
    u16 sin_family;
    u16 sin_port;
    u32 sin_addr;
    unsigned char sin_zero[8];
};

struct kernel_sigaction {
    u64 handler;
    u64 flags;
    u64 restorer;
    u64 mask;
};

struct timespec {
    i64 tv_sec;
    i64 tv_nsec;
};

struct timeval {
    i64 tv_sec;
    i64 tv_usec;
};

struct itimerval {
    struct timeval it_interval;
    struct timeval it_value;
};

struct itimerspec {
    struct timespec it_interval;
    struct timespec it_value;
};

struct rseq_area {
    u32 cpu_id_start;
    int cpu_id;
    u64 rseq_cs;
    u32 flags;
    u32 pad[3];
};

static i64 sys_call6(u64 nr, u64 a1, u64 a2, u64 a3, u64 a4, u64 a5, u64 a6) {
    i64 ret;
    register u64 r10 __asm__("r10") = a4;
    register u64 r8 __asm__("r8") = a5;
    register u64 r9 __asm__("r9") = a6;
    __asm__ volatile(
        "syscall"
        : "=a"(ret)
        : "a"(nr), "D"(a1), "S"(a2), "d"(a3), "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory");
    return ret;
}

static i64 sys_write(int fd, const void *buf, u64 count) {
    return sys_call6(SYS_WRITE, (u64)fd, (u64)buf, count, 0, 0, 0);
}

static i64 sys_read(int fd, void *buf, u64 count) {
    return sys_call6(SYS_READ, (u64)fd, (u64)buf, count, 0, 0, 0);
}

static i64 sys_close(int fd) {
    return sys_call6(SYS_CLOSE, (u64)fd, 0, 0, 0, 0, 0);
}

static void *sys_mmap(void *addr, u64 len, u64 prot, u64 flags, i64 fd, u64 off) {
    return (void *)sys_call6(SYS_MMAP, (u64)addr, len, prot, flags, (u64)fd, off);
}

static i64 sys_rt_sigaction(int signum, const struct kernel_sigaction *act) {
    return sys_call6(SYS_RT_SIGACTION, (u64)(u32)signum, (u64)act, 0, SIGSET_BYTES, 0, 0);
}

static void *sys_mremap(void *old_addr, u64 old_sz, u64 new_sz, u64 flags, void *new_addr) {
    return (void *)sys_call6(
        SYS_MREMAP,
        (u64)old_addr,
        old_sz,
        new_sz,
        flags,
        (u64)new_addr,
        0
    );
}

static i64 sys_munmap(void *addr, u64 len) {
    return sys_call6(SYS_MUNMAP, (u64)addr, len, 0, 0, 0, 0);
}

static i64 sys_msync(void *addr, u64 len, u64 flags) {
    return sys_call6(SYS_MSYNC, (u64)addr, len, flags, 0, 0, 0);
}

static i64 sys_nanosleep(const struct timespec *req, struct timespec *rem) {
    return sys_call6(SYS_NANOSLEEP, (u64)req, (u64)rem, 0, 0, 0, 0);
}

static i64 sys_fsync(int fd) {
    return sys_call6(SYS_FSYNC, (u64)fd, 0, 0, 0, 0, 0);
}

static i64 sys_fdatasync(int fd) {
    return sys_call6(SYS_FDATASYNC, (u64)fd, 0, 0, 0, 0, 0);
}

static i64 sys_sync(void) {
    return sys_call6(SYS_SYNC, 0, 0, 0, 0, 0, 0);
}

static i64 sys_syncfs(int fd) {
    return sys_call6(SYS_SYNCFS, (u64)fd, 0, 0, 0, 0, 0);
}

static i64 sys_openat(int dirfd, const char *path, int flags, int mode) {
    return sys_call6(
        SYS_OPENAT,
        (u64)(long)dirfd,
        (u64)path,
        (u64)(u32)flags,
        (u64)(u32)mode,
        0,
        0
    );
}

static i64 sys_newfstatat(int dirfd, const char *path, void *statbuf, int flags) {
    return sys_call6(
        SYS_NEWFSTATAT,
        (u64)(long)dirfd,
        (u64)path,
        (u64)statbuf,
        (u64)(u32)flags,
        0,
        0
    );
}

static i64 sys_readlinkat(int dirfd, const char *path, char *buf, u64 bufsiz) {
    return sys_call6(
        SYS_READLINKAT,
        (u64)(long)dirfd,
        (u64)path,
        (u64)buf,
        bufsiz,
        0,
        0
    );
}

static i64 sys_getitimer(int which, struct itimerval *curr) {
    return sys_call6(SYS_GETITIMER, (u64)(u32)which, (u64)curr, 0, 0, 0, 0);
}

static i64 sys_setitimer(int which, const struct itimerval *newv, struct itimerval *oldv) {
    return sys_call6(SYS_SETITIMER, (u64)(u32)which, (u64)newv, (u64)oldv, 0, 0, 0);
}

static i64 sys_alarm(u32 seconds) {
    return sys_call6(SYS_ALARM, (u64)seconds, 0, 0, 0, 0, 0);
}

static i64 sys_getpid(void) {
    return sys_call6(SYS_GETPID, 0, 0, 0, 0, 0, 0);
}

static i64 sys_socket(int domain, int type, int protocol) {
    return sys_call6(SYS_SOCKET, (u64)(u32)domain, (u64)(u32)type, (u64)(u32)protocol, 0, 0, 0);
}

static i64 sys_connect(int fd, const struct sockaddr_in *addr, u32 len) {
    return sys_call6(SYS_CONNECT, (u64)(u32)fd, (u64)addr, (u64)len, 0, 0, 0);
}

static i64 sys_bind(int fd, const struct sockaddr_in *addr, u32 len) {
    return sys_call6(SYS_BIND, (u64)(u32)fd, (u64)addr, (u64)len, 0, 0, 0);
}

static i64 sys_listen(int fd, int backlog) {
    return sys_call6(SYS_LISTEN, (u64)(u32)fd, (u64)(u32)backlog, 0, 0, 0, 0);
}

static i64 sys_accept4(int fd, struct sockaddr_in *addr, u32 *addrlen, int flags) {
    return sys_call6(SYS_ACCEPT4, (u64)(u32)fd, (u64)addr, (u64)addrlen, (u64)(u32)flags, 0, 0);
}

static i64 sys_getsockname(int fd, struct sockaddr_in *addr, u32 *addrlen) {
    return sys_call6(SYS_GETSOCKNAME, (u64)(u32)fd, (u64)addr, (u64)addrlen, 0, 0, 0);
}

static i64 sys_setsockopt(int fd, int level, int optname, const void *optval, u32 optlen) {
    return sys_call6(
        SYS_SETSOCKOPT,
        (u64)(u32)fd,
        (u64)(u32)level,
        (u64)(u32)optname,
        (u64)optval,
        (u64)optlen,
        0
    );
}

static i64 sys_getsockopt(int fd, int level, int optname, void *optval, u32 *optlen) {
    return sys_call6(
        SYS_GETSOCKOPT,
        (u64)(u32)fd,
        (u64)(u32)level,
        (u64)(u32)optname,
        (u64)optval,
        (u64)optlen,
        0
    );
}

static i64 sys_fork(void) {
    return sys_call6(SYS_FORK, 0, 0, 0, 0, 0, 0);
}

static i64 sys_wait4(i64 pid, u32 *status) {
    return sys_call6(SYS_WAIT4, (u64)pid, (u64)status, 0, 0, 0, 0);
}

static i64 sys_kill(i64 pid, int sig) {
    return sys_call6(SYS_KILL, (u64)pid, (u64)(u32)sig, 0, 0, 0, 0);
}

static i64 sys_setpgid(i64 pid, i64 pgid) {
    return sys_call6(SYS_SETPGID, (u64)pid, (u64)pgid, 0, 0, 0, 0);
}

static i64 sys_setsid(void) {
    return sys_call6(SYS_SETSID, 0, 0, 0, 0, 0, 0);
}

static i64 sys_getpgid(i64 pid) {
    return sys_call6(SYS_GETPGID, (u64)pid, 0, 0, 0, 0, 0);
}

static i64 sys_getsid(i64 pid) {
    return sys_call6(SYS_GETSID, (u64)pid, 0, 0, 0, 0, 0);
}

static i64 sys_timerfd_create(int clockid, int flags) {
    return sys_call6(SYS_TIMERFD_CREATE, (u64)(u32)clockid, (u64)(u32)flags, 0, 0, 0, 0);
}

static i64 sys_timerfd_settime(int fd, int flags, const struct itimerspec *newv, struct itimerspec *oldv) {
    return sys_call6(SYS_TIMERFD_SETTIME, (u64)(u32)fd, (u64)(u32)flags, (u64)newv, (u64)oldv, 0, 0);
}

static i64 sys_timerfd_gettime(int fd, struct itimerspec *curr) {
    return sys_call6(SYS_TIMERFD_GETTIME, (u64)(u32)fd, (u64)curr, 0, 0, 0, 0);
}

static i64 sys_getcpu(u32 *cpu, u32 *node) {
    return sys_call6(SYS_GETCPU, (u64)cpu, (u64)node, 0, 0, 0, 0);
}

static i64 sys_membarrier(u32 cmd, u32 flags, u32 cpu_id) {
    return sys_call6(SYS_MEMBARRIER, (u64)cmd, (u64)flags, (u64)cpu_id, 0, 0, 0);
}

static i64 sys_rseq(struct rseq_area *rseq, u32 len, u32 flags, u32 sig) {
    return sys_call6(SYS_RSEQ, (u64)rseq, (u64)len, (u64)flags, (u64)sig, 0, 0);
}

static u16 bswap16(u16 value) {
    return (u16)((value << 8) | (value >> 8));
}

static void sys_exit(int code) {
    __asm__ volatile(
        "syscall"
        :
        : "a"(SYS_EXIT), "D"((u64)code)
        : "rcx", "r11", "memory");
    __builtin_unreachable();
}

static void print(const char *s) {
    u64 len = 0;
    while (s[len]) len++;
    sys_write(1, s, len);
}

static int pass_count = 0;
static int fail_count = 0;

static void check(const char *name, int cond) {
    if (cond) {
        print("  [PASS] ");
        pass_count++;
    } else {
        print("  [FAIL] ");
        fail_count++;
    }
    print(name);
    print("\n");
}

static int bytes_eq(const char *a, const char *b, int len) {
    int i;
    for (i = 0; i < len; i++) {
        if ((unsigned char)a[i] != (unsigned char)b[i]) {
            return 0;
        }
    }
    return 1;
}

void _start(void) {
    struct kernel_sigaction ign_alrm;
    struct itimerval cur;
    struct itimerval oldv;
    struct itimerval newv;
    struct timespec sleep_req;
    char *region;
    char *guard;
    char *moved;
    char *src;
    char *fixed_dst;
    static char file_path[] = "/tmp/substrate_depth.bin";
    char first_byte = 0;
    char page_buf[4096];
    unsigned char statbuf[256];
    char proc_fd_path[32];
    char link_buf[256];
    struct rseq_area rseq;
    u32 wstatus = 0;
    struct itimerspec timer_new;
    struct itimerspec timer_old;
    struct itimerspec timer_cur;
    u64 expirations = 0;
    u32 cpu = 99;
    u32 node = 99;
    int fd;
    int tfd;
    i64 pid;
    char *shared_map;
    int i;

    print("=== TOS substrate depth smoke ===\n");

    ign_alrm.handler = SIG_IGN;
    ign_alrm.flags = 0;
    ign_alrm.restorer = 0;
    ign_alrm.mask = 0;
    check("ignore SIGALRM", sys_rt_sigaction(SIGALRM, &ign_alrm) == 0);

    check("getitimer(NULL) -> EFAULT", sys_getitimer(0, (struct itimerval *)0) == -EFAULT);
    check("setitimer(bad which) -> EINVAL", sys_setitimer(9, (struct itimerval *)0, (struct itimerval *)0) == -EINVAL);
    check("getcpu() reports cpu0/node0", sys_getcpu(&cpu, &node) == 0 && cpu == 0 && node == 0);
    check("getpgid(self) returns active group", sys_getpgid(0) > 0 && sys_getpgid(sys_getpid()) == sys_getpgid(0));
    check("getsid(self) returns active session", sys_getsid(0) > 0 && sys_getsid(sys_getpid()) == sys_getsid(0));
    pid = sys_fork();
    check("fork for setsid", pid >= 0);
    if (pid == 0) {
        i64 child_pid = sys_getpid();
        check("child setsid", sys_setsid() == child_pid);
        check("child getsid after setsid", sys_getsid(0) == child_pid);
        check("child getpgid after setsid", sys_getpgid(0) == child_pid);
        check("child setpgid on session leader -> EPERM", sys_setpgid(0, 0) == -EPERM);
        sys_exit(fail_count == 0 ? 0 : 1);
    } else if (pid > 0) {
        wstatus = 0;
        check("wait4 setsid child", sys_wait4(pid, &wstatus) == pid && wstatus == 0);
    }
    pid = sys_fork();
    check("fork for process group", pid >= 0);
    if (pid == 0) {
        i64 child_pid = sys_getpid();
        sleep_req.tv_sec = 0;
        sleep_req.tv_nsec = 40000000;
        check("child setpgid self", sys_setpgid(0, 0) == 0);
        check("child getpgid self", sys_getpgid(0) == child_pid);
        check("child getsid inherited", sys_getsid(0) > 0);
        check("child setsid after setpgid -> EPERM", sys_setsid() == -EPERM);
        sys_nanosleep(&sleep_req, (struct timespec *)0);
        sys_exit(fail_count == 0 ? 0 : 1);
    } else if (pid > 0) {
        sleep_req.tv_sec = 0;
        sleep_req.tv_nsec = 10000000;
        sys_nanosleep(&sleep_req, (struct timespec *)0);
        check("kill(-pgid, 0) finds child group", sys_kill(-pid, 0) == 0);
        wstatus = 0;
        check("wait4(-pgid) reaps child", sys_wait4(-pid, &wstatus) == pid && wstatus == 0);
    }
    check("membarrier(query bad flags) -> EINVAL", sys_membarrier(MEMBARRIER_CMD_QUERY, 1, 0) == -EINVAL);
    check("membarrier(query)", sys_membarrier(MEMBARRIER_CMD_QUERY, 0, 0) == (i64)MEMBARRIER_SUPPORTED_MASK);
    check("membarrier(private expedited before register) -> EPERM",
          sys_membarrier(MEMBARRIER_CMD_PRIVATE_EXPEDITED, 0, 0) == -EPERM);
    check("membarrier(register private expedited)",
          sys_membarrier(MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED, 0, 0) == 0);
    check("membarrier(private expedited)", sys_membarrier(MEMBARRIER_CMD_PRIVATE_EXPEDITED, 0, 0) == 0);
    check("membarrier(register private sync_core)",
          sys_membarrier(MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE, 0, 0) == 0);
    check("membarrier(private sync_core)",
          sys_membarrier(MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE, 0, 0) == 0);
    check("membarrier(register global expedited)",
          sys_membarrier(MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED, 0, 0) == 0);
    check("membarrier(global expedited)", sys_membarrier(MEMBARRIER_CMD_GLOBAL_EXPEDITED, 0, 0) == 0);
    check("membarrier(register private rseq)",
          sys_membarrier(MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ, 0, 0) == 0);
    check("membarrier(private rseq)", sys_membarrier(MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ, 0, 0) == 0);
    check("membarrier(private rseq cpu0)",
          sys_membarrier(MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ, MEMBARRIER_CMD_FLAG_CPU, 0) == 0);
    check("membarrier(private rseq bad cpu) -> EINVAL",
          sys_membarrier(MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ, MEMBARRIER_CMD_FLAG_CPU, 1) == -EINVAL);
    check("rseq(NULL) -> EFAULT", sys_rseq((struct rseq_area *)0, 32, 0, 0x53053053u) == -EFAULT);
    check("rseq(bad len) -> EINVAL", sys_rseq(&rseq, 24, 0, 0x53053053u) == -EINVAL);
    check("rseq(bad flags) -> EINVAL", sys_rseq(&rseq, 32, 2, 0x53053053u) == -EINVAL);
    rseq.cpu_id_start = 77;
    rseq.cpu_id = 77;
    rseq.rseq_cs = 0xdeadbeefULL;
    rseq.flags = 0;
    check("rseq(register)", sys_rseq(&rseq, 32, 0, 0x53053053u) == 0);
    check("rseq(register) writes cpu ids", rseq.cpu_id_start == 0 && rseq.cpu_id == 0 && rseq.rseq_cs == 0);
    rseq.rseq_cs = 0x1234ULL;
    check("rseq(unregister wrong sig) -> EINVAL", sys_rseq(&rseq, 32, 1, 0x53053054u) == -EINVAL);
    check("rseq(unregister)", sys_rseq(&rseq, 32, 1, 0x53053053u) == 0);
    check("rseq(unregister) clears state", rseq.cpu_id_start == 0 && rseq.cpu_id == -1 && rseq.rseq_cs == 0);

    newv.it_interval.tv_sec = 0;
    newv.it_interval.tv_usec = 0;
    newv.it_value.tv_sec = 0;
    newv.it_value.tv_usec = 20000;
    oldv.it_interval.tv_sec = 11;
    oldv.it_interval.tv_usec = 11;
    oldv.it_value.tv_sec = 11;
    oldv.it_value.tv_usec = 11;

    check("setitimer(one-shot 20ms)", sys_setitimer(0, &newv, &oldv) == 0);
    check("setitimer old timer initially zero", oldv.it_interval.tv_sec == 0 && oldv.it_interval.tv_usec == 0 &&
                                              oldv.it_value.tv_sec == 0 && oldv.it_value.tv_usec == 0);
    check("getitimer reports active timer", sys_getitimer(0, &cur) == 0 &&
                                            (cur.it_value.tv_sec > 0 || cur.it_value.tv_usec > 0));

    sleep_req.tv_sec = 0;
    sleep_req.tv_nsec = 40000000;
    check("nanosleep(40ms)", sys_nanosleep(&sleep_req, (struct timespec *)0) == 0);
    check("getitimer expires after sleep", sys_getitimer(0, &cur) == 0 &&
                                           cur.it_value.tv_sec == 0 && cur.it_value.tv_usec == 0);

    check("alarm(1) arms timer", sys_alarm(1) == 0);
    check("alarm(0) returns remaining seconds", sys_alarm(0) >= 1);
    check("timerfd_create(monotonic|nonblock)", (tfd = (int)sys_timerfd_create(CLOCK_MONOTONIC, O_NONBLOCK)) >= 0);
    check("timerfd_gettime(NULL) -> EFAULT", sys_timerfd_gettime(tfd, (struct itimerspec *)0) == -EFAULT);
    timer_new.it_interval.tv_sec = 0;
    timer_new.it_interval.tv_nsec = 0;
    timer_new.it_value.tv_sec = 0;
    timer_new.it_value.tv_nsec = 20000000;
    timer_old.it_interval.tv_sec = 7;
    timer_old.it_interval.tv_nsec = 7;
    timer_old.it_value.tv_sec = 7;
    timer_old.it_value.tv_nsec = 7;
    check("timerfd_settime(20ms)", sys_timerfd_settime(tfd, 0, &timer_new, &timer_old) == 0);
    check("timerfd_settime old timer initially zero",
          timer_old.it_interval.tv_sec == 0 && timer_old.it_interval.tv_nsec == 0 &&
          timer_old.it_value.tv_sec == 0 && timer_old.it_value.tv_nsec == 0);
    check("timerfd_gettime reports active timer",
          sys_timerfd_gettime(tfd, &timer_cur) == 0 &&
          (timer_cur.it_value.tv_sec > 0 || timer_cur.it_value.tv_nsec > 0));
    expirations = 0;
    check("timerfd read before expiry -> EAGAIN", sys_read(tfd, &expirations, 8) == -EAGAIN);
    sleep_req.tv_sec = 0;
    sleep_req.tv_nsec = 30000000;
    check("nanosleep(30ms) for timerfd", sys_nanosleep(&sleep_req, (struct timespec *)0) == 0);
    expirations = 0;
    check("timerfd read after expiry", sys_read(tfd, &expirations, 8) == 8 && expirations == 1);
    check("timerfd read drains expirations", sys_read(tfd, &expirations, 8) == -EAGAIN);
    timer_new.it_interval.tv_sec = 0;
    timer_new.it_interval.tv_nsec = 10000000;
    timer_new.it_value.tv_sec = 0;
    timer_new.it_value.tv_nsec = 10000000;
    check("timerfd_settime(periodic 10ms)", sys_timerfd_settime(tfd, 0, &timer_new, &timer_old) == 0);
    sleep_req.tv_sec = 0;
    sleep_req.tv_nsec = 35000000;
    check("nanosleep(35ms) periodic timerfd", sys_nanosleep(&sleep_req, (struct timespec *)0) == 0);
    expirations = 0;
    check("timerfd periodic read", sys_read(tfd, &expirations, 8) == 8 && expirations >= 2);
    check("timerfd_settime(bad flags) -> EINVAL",
          sys_timerfd_settime(tfd, TFD_TIMER_ABSTIME << 1, &timer_new, &timer_old) == -EINVAL);
    check("close timerfd", sys_close(tfd) == 0);

    {
        int listen_fd = (int)sys_socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in addr = {0};
        struct sockaddr_in bound = {0};
        struct sockaddr_in accepted_peer = {0};
        u32 addrlen = sizeof(bound);
        u32 peer_len = sizeof(accepted_peer);
        int client_fd;
        int accepted_fd;
        char payload[4] = {0};
        u32 sockopt_len;
        int sockopt_val;
        int enabled = 1;

        addr.sin_family = AF_INET;
        addr.sin_port = 0;
        addr.sin_addr = 0x0100007f; /* 127.0.0.1 in network-byte-order bytes */

        check("loopback socket(listener)", listen_fd >= 0);
        if (listen_fd >= 0) {
            check("loopback setsockopt(reuseaddr)",
                  sys_setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &enabled, 4) == 0);
            check("loopback setsockopt(reuseport)",
                  sys_setsockopt(listen_fd, SOL_SOCKET, SO_REUSEPORT, &enabled, 4) == 0);
            check("loopback setsockopt(keepalive)",
                  sys_setsockopt(listen_fd, SOL_SOCKET, SO_KEEPALIVE, &enabled, 4) == 0);
            sockopt_len = 4;
            sockopt_val = 0;
            check("loopback getsockopt(reuseaddr)",
                  sys_getsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &sockopt_val, &sockopt_len) == 0 &&
                  sockopt_len == 4 &&
                  sockopt_val == 1);
            check("loopback bind(127.0.0.1:0)",
                  sys_bind(listen_fd, &addr, sizeof(addr)) == 0);
            check("loopback listen", sys_listen(listen_fd, 4) == 0);
            sockopt_len = 4;
            sockopt_val = 0;
            check("loopback getsockopt(acceptconn)",
                  sys_getsockopt(listen_fd, SOL_SOCKET, SO_ACCEPTCONN, &sockopt_val, &sockopt_len) == 0 &&
                  sockopt_len == 4 &&
                  sockopt_val == 1);
            sockopt_len = 4;
            sockopt_val = 0;
            check("loopback getsockopt(keepalive)",
                  sys_getsockopt(listen_fd, SOL_SOCKET, SO_KEEPALIVE, &sockopt_val, &sockopt_len) == 0 &&
                  sockopt_len == 4 &&
                  sockopt_val == 1);
            sockopt_len = 4;
            sockopt_val = 0;
            check("loopback getsockopt(sndbuf)",
                  sys_getsockopt(listen_fd, SOL_SOCKET, SO_SNDBUF, &sockopt_val, &sockopt_len) == 0 &&
                  sockopt_len == 4 &&
                  sockopt_val > 0);
            check("loopback getsockname",
                  sys_getsockname(listen_fd, &bound, &addrlen) == 0 &&
                  bound.sin_family == AF_INET &&
                  bswap16(bound.sin_port) != 0);

            client_fd = (int)sys_socket(AF_INET, SOCK_STREAM, 0);
            check("loopback socket(client)", client_fd >= 0);
            if (client_fd >= 0) {
                check("loopback setsockopt(tcp_nodelay)",
                      sys_setsockopt(client_fd, SOL_TCP, TCP_NODELAY, &enabled, 4) == 0);
                sockopt_len = 4;
                sockopt_val = 0;
                check("loopback getsockopt(tcp_nodelay)",
                      sys_getsockopt(client_fd, SOL_TCP, TCP_NODELAY, &sockopt_val, &sockopt_len) == 0 &&
                      sockopt_len == 4 &&
                      sockopt_val == 1);
                sockopt_len = 4;
                sockopt_val = -1;
                check("loopback getsockopt(so_error)",
                      sys_getsockopt(client_fd, SOL_SOCKET, SO_ERROR, &sockopt_val, &sockopt_len) == 0 &&
                      sockopt_len == 4 &&
                      sockopt_val == 0);
                sockopt_len = 4;
                sockopt_val = 0;
                check("loopback getsockopt(rcvbuf)",
                      sys_getsockopt(client_fd, SOL_SOCKET, SO_RCVBUF, &sockopt_val, &sockopt_len) == 0 &&
                      sockopt_len == 4 &&
                      sockopt_val > 0);
                addr.sin_port = bound.sin_port;
                check("loopback connect", sys_connect(client_fd, &addr, sizeof(addr)) == 0);
                accepted_fd = (int)sys_accept4(listen_fd, &accepted_peer, &peer_len, 0);
                check("loopback accept4", accepted_fd >= 0);
                if (accepted_fd >= 0) {
                    check("loopback client->server write", sys_write(client_fd, "ping", 4) == 4);
                    check("loopback server read", sys_read(accepted_fd, payload, 4) == 4 &&
                                                      payload[0] == 'p' &&
                                                      payload[1] == 'i' &&
                                                      payload[2] == 'n' &&
                                                      payload[3] == 'g');
                    check("loopback server->client write", sys_write(accepted_fd, "pong", 4) == 4);
                    payload[0] = payload[1] = payload[2] = payload[3] = 0;
                    check("loopback client read", sys_read(client_fd, payload, 4) == 4 &&
                                                       payload[0] == 'p' &&
                                                       payload[1] == 'o' &&
                                                       payload[2] == 'n' &&
                                                       payload[3] == 'g');
                    check("loopback close accepted", sys_close(accepted_fd) == 0);
                }
                check("loopback close client", sys_close(client_fd) == 0);
            }
            check("loopback close listener", sys_close(listen_fd) == 0);
        }
    }
    check("msync(hole) -> ENOMEM", sys_msync((void *)0x50000000, 4096, MS_SYNC) == -ENOMEM);
    check("msync(bad flags) -> EINVAL", sys_msync((void *)0x50000000, 4096, MS_SYNC | MS_ASYNC) == -EINVAL);

    region = (char *)sys_mmap((void *)0, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    check("mmap(2 pages)", (i64)region > 0);
    if ((i64)region <= 0) {
        print("=== Results: fatal mmap failure ===\n");
        sys_exit(1);
    }

    region[0] = 'A';
    region[4096] = 'B';
    check("mremap shrink keeps same base", sys_mremap(region, 8192, 4096, 0, (void *)0) == region);
    check("mremap shrink preserves contents", region[0] == 'A');

    guard = (char *)sys_mmap((void *)0, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    check("mmap guard after shrink", (i64)guard > 0);
    moved = (char *)sys_mremap(region, 4096, 12288, MREMAP_MAYMOVE, (void *)0);
    check("mremap maymove succeeds", (i64)moved > 0);
    check("mremap maymove relocates mapping", moved != region);
    check("mremap maymove preserves contents", moved[0] == 'A');
    check("munmap guard", sys_munmap(guard, 8192) == 0);
    check("munmap moved mapping", sys_munmap(moved, 12288) == 0);

    src = (char *)sys_mmap((void *)0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    fixed_dst = (char *)sys_mmap((void *)0, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    check("mmap fixed-src", (i64)src > 0);
    check("mmap fixed-dst", (i64)fixed_dst > 0);
    if ((i64)src > 0 && (i64)fixed_dst > 0) {
        src[0] = 'Z';
        check(
            "mremap fixed move replaces target",
            sys_mremap(src, 4096, 8192, MREMAP_MAYMOVE | MREMAP_FIXED, fixed_dst) == fixed_dst
        );
        check("mremap fixed preserves contents", fixed_dst[0] == 'Z');
        check("munmap fixed-dst", sys_munmap(fixed_dst, 8192) == 0);
    }

    for (i = 0; i < (int)sizeof(page_buf); i++) {
        page_buf[i] = 'a';
    }
    fd = (int)sys_openat(AT_FDCWD, file_path, O_CREAT | O_RDWR | O_TRUNC, 0644);
    check("open backing file", fd >= 0);
    if (fd >= 0) {
        check("seed backing file", sys_write(fd, page_buf, sizeof(page_buf)) == (i64)sizeof(page_buf));
        check("fsync(file) succeeds", sys_fsync(fd) == 0);
        check("fdatasync(file) succeeds", sys_fdatasync(fd) == 0);
        check("syncfs(file) succeeds", sys_syncfs(fd) == 0);
        check("sync() succeeds", sys_sync() == 0);
        shared_map = (char *)sys_mmap((void *)0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        check("mmap shared file", (i64)shared_map > 0);
        if ((i64)shared_map > 0) {
            shared_map[0] = 'M';
            check("msync(shared file) succeeds", sys_msync(shared_map, 4096, MS_SYNC) == 0);
            check("munmap shared file", sys_munmap(shared_map, 4096) == 0);
        }
        check("close mapped file", sys_close(fd) == 0);
        fd = (int)sys_openat(AT_FDCWD, file_path, O_RDWR, 0);
        check("reopen backing file", fd >= 0);
        if (fd >= 0) {
            check("read synced byte", sys_read(fd, &first_byte, 1) == 1);
            check("shared file writeback visible", first_byte == 'M');
            {
                int proc_len = 0;
                int tmp_fd = fd;
                i64 link_len;
                proc_fd_path[proc_len++] = '/';
                proc_fd_path[proc_len++] = 'p';
                proc_fd_path[proc_len++] = 'r';
                proc_fd_path[proc_len++] = 'o';
                proc_fd_path[proc_len++] = 'c';
                proc_fd_path[proc_len++] = '/';
                proc_fd_path[proc_len++] = 's';
                proc_fd_path[proc_len++] = 'e';
                proc_fd_path[proc_len++] = 'l';
                proc_fd_path[proc_len++] = 'f';
                proc_fd_path[proc_len++] = '/';
                proc_fd_path[proc_len++] = 'f';
                proc_fd_path[proc_len++] = 'd';
                proc_fd_path[proc_len++] = '/';
                if (tmp_fd >= 100) {
                    proc_fd_path[proc_len++] = (char)('0' + (tmp_fd / 100));
                    proc_fd_path[proc_len++] = (char)('0' + ((tmp_fd / 10) % 10));
                } else if (tmp_fd >= 10) {
                    proc_fd_path[proc_len++] = (char)('0' + (tmp_fd / 10));
                }
                proc_fd_path[proc_len++] = (char)('0' + (tmp_fd % 10));
                proc_fd_path[proc_len] = 0;

                link_len = sys_readlinkat(AT_FDCWD, proc_fd_path, link_buf, sizeof(link_buf));
                check("readlink /proc/self/fd/<fd>", link_len == (i64)(sizeof(file_path) - 1));
                if (link_len == (i64)(sizeof(file_path) - 1)) {
                    check(
                        "/proc/self/fd target matches path",
                        bytes_eq(link_buf, file_path, (int)(sizeof(file_path) - 1))
                    );
                }

                check(
                    "lstat /proc/self/fd/<fd>",
                    sys_newfstatat(AT_FDCWD, proc_fd_path, statbuf, AT_SYMLINK_NOFOLLOW) == 0
                );
                if (sys_newfstatat(AT_FDCWD, proc_fd_path, statbuf, AT_SYMLINK_NOFOLLOW) == 0) {
                    check(
                        "/proc/self/fd/<fd> reports symlink",
                        ((*(u16 *)&statbuf[24]) & MODE_S_IFMT) == MODE_S_IFLNK
                    );
                }
                check(
                    "stat /proc/self/fd/<fd> follows target",
                    sys_newfstatat(AT_FDCWD, proc_fd_path, statbuf, 0) == 0
                );
                if (sys_newfstatat(AT_FDCWD, proc_fd_path, statbuf, 0) == 0) {
                    check(
                        "/proc/self/fd/<fd> follow reports regular file",
                        ((*(u16 *)&statbuf[24]) & MODE_S_IFMT) == MODE_S_IFREG
                    );
                }
            }
            check("close reopened file", sys_close(fd) == 0);
        }
    }

    print("=== Results: ");
    {
        char buf[32];
        int idx = 0;
        int value = pass_count;
        char tmp[16];
        int t = 0;
        if (value == 0) tmp[t++] = '0';
        while (value > 0) {
            tmp[t++] = (char)('0' + (value % 10));
            value /= 10;
        }
        while (t > 0) buf[idx++] = tmp[--t];
        buf[idx++] = ' ';
        buf[idx++] = 'p';
        buf[idx++] = 'a';
        buf[idx++] = 's';
        buf[idx++] = 's';
        buf[idx++] = 'e';
        buf[idx++] = 'd';
        buf[idx++] = ',';
        buf[idx++] = ' ';
        value = fail_count;
        t = 0;
        if (value == 0) tmp[t++] = '0';
        while (value > 0) {
            tmp[t++] = (char)('0' + (value % 10));
            value /= 10;
        }
        while (t > 0) buf[idx++] = tmp[--t];
        buf[idx++] = ' ';
        buf[idx++] = 'f';
        buf[idx++] = 'a';
        buf[idx++] = 'i';
        buf[idx++] = 'l';
        buf[idx++] = 'e';
        buf[idx++] = 'd';
        buf[idx++] = '\n';
        sys_write(1, buf, (u64)idx);
    }

    sys_exit(fail_count == 0 ? 0 : 1);
}
