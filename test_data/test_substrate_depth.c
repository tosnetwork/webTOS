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
#define SYS_TIMERFD_CREATE 283
#define SYS_TIMERFD_SETTIME 286
#define SYS_TIMERFD_GETTIME 287
#define SYS_SYNC 162
#define SYS_GETCPU 309
#define SYS_MEMBARRIER 324
#define SYS_RSEQ 334
#define SYS_OPENAT 257
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

static i64 sys_getitimer(int which, struct itimerval *curr) {
    return sys_call6(SYS_GETITIMER, (u64)(u32)which, (u64)curr, 0, 0, 0, 0);
}

static i64 sys_setitimer(int which, const struct itimerval *newv, struct itimerval *oldv) {
    return sys_call6(SYS_SETITIMER, (u64)(u32)which, (u64)newv, (u64)oldv, 0, 0, 0);
}

static i64 sys_alarm(u32 seconds) {
    return sys_call6(SYS_ALARM, (u64)seconds, 0, 0, 0, 0, 0);
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
    struct rseq_area rseq;
    struct itimerspec timer_new;
    struct itimerspec timer_old;
    struct itimerspec timer_cur;
    u64 expirations = 0;
    u32 cpu = 99;
    u32 node = 99;
    int fd;
    int tfd;
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
