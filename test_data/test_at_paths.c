/*
 * test_at_paths.c — Verify relative *at path semantics
 *
 * Build:
 *   gcc -nostdlib -static -Wl,-Ttext=0x40000000 -o test_at_paths.elf test_at_paths.c
 */

typedef unsigned long u64;
typedef long i64;
typedef unsigned int u32;

#define SYS_WRITE 1
#define SYS_CLOSE 3
#define SYS_LSTAT 6
#define SYS_EXIT 60
#define SYS_OPENAT 257
#define SYS_NEWFSTATAT 262
#define SYS_READLINKAT 267
#define SYS_STATX 332
#define SYS_FSTAT 5

#define AT_FDCWD (-100)
#define AT_SYMLINK_NOFOLLOW 0x100
#define O_RDONLY 0
#define O_DIRECTORY 0x10000
#define S_IFMT 0170000
#define S_IFDIR 0040000
#define S_IFREG 0100000
#define S_IFCHR 0020000
#define S_IFLNK 0120000

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

static i64 sys_openat(int dirfd, const char *path, int flags, u32 mode) {
    return sys_call6(SYS_OPENAT, (u64)(long)dirfd, (u64)path, (u64)(u32)flags, mode, 0, 0);
}

static i64 sys_fstat(int fd, void *st) {
    return sys_call6(SYS_FSTAT, (u64)fd, (u64)st, 0, 0, 0, 0);
}

static i64 sys_close(int fd) {
    return sys_call6(SYS_CLOSE, (u64)fd, 0, 0, 0, 0, 0);
}

static i64 sys_lstat(const char *path, void *st) {
    return sys_call6(SYS_LSTAT, (u64)path, (u64)st, 0, 0, 0, 0);
}

static i64 sys_readlinkat(int dirfd, const char *path, char *buf, u64 bufsiz) {
    return sys_call6(SYS_READLINKAT, (u64)(long)dirfd, (u64)path, (u64)buf, bufsiz, 0, 0);
}

static i64 sys_newfstatat(int dirfd, const char *path, void *st, int flags) {
    return sys_call6(SYS_NEWFSTATAT, (u64)(long)dirfd, (u64)path, (u64)st, (u64)(u32)flags, 0, 0);
}

static i64 sys_statx(int dirfd, const char *path, int flags, u32 mask, void *stx) {
    return sys_call6(SYS_STATX, (u64)(long)dirfd, (u64)path, (u64)(u32)flags, mask, (u64)stx, 0);
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

static int streq(const char *a, const char *b) {
    u64 i = 0;
    while (a[i] && b[i]) {
        if (a[i] != b[i]) return 0;
        i++;
    }
    return a[i] == 0 && b[i] == 0;
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
    static char proc_self[] = "/proc/self";
    static char exe_name[] = "exe";
    static char usr_bin[] = "/usr/bin";
    static char hello_name[] = "hello_dynamic";
    static char dev_null[] = "/dev/null";
    static char expected_exe[] = "/app/test_at_paths";
    char link_buf[128];
    unsigned char stat_buf[144];
    unsigned char statx_buf[256];
    i64 stat_ret = -1;

    print("=== ATOS *at path test ===\n");

    i64 procfd = sys_openat(AT_FDCWD, proc_self, O_RDONLY | O_DIRECTORY, 0);
    check("openat(/proc/self, O_DIRECTORY)", procfd >= 0);

    i64 link_len = -1;
    if (procfd >= 0) {
        link_len = sys_readlinkat((int)procfd, exe_name, link_buf, sizeof(link_buf) - 1);
        if (link_len > 0) {
            link_buf[link_len] = 0;
        }
    }
    check("readlinkat(procfd, \"exe\")", link_len > 0);
    check("readlinkat relative target matches", link_len > 0 && streq(link_buf, expected_exe));

    i64 exe_fd = -1;
    if (procfd >= 0) {
        exe_fd = sys_openat((int)procfd, exe_name, O_RDONLY, 0);
    }
    check("openat(procfd, \"exe\")", exe_fd >= 0);
    if (exe_fd >= 0) {
        stat_ret = sys_fstat((int)exe_fd, stat_buf);
    } else {
        stat_ret = -1;
    }
    check("fstat(openat(procfd, \"exe\"))", stat_ret == 0);
    {
        u32 st_mode = *(u32 *)(stat_buf + 24);
        check("fstat(openat(procfd, \"exe\")) is regular", stat_ret == 0 && (st_mode & S_IFMT) == S_IFREG);
    }

    if (procfd >= 0) {
        stat_ret = sys_newfstatat((int)procfd, exe_name, stat_buf, 0);
    }
    check("newfstatat(procfd, \"exe\")", stat_ret == 0);
    {
        u32 st_mode = *(u32 *)(stat_buf + 24);
        check("newfstatat(procfd, \"exe\") follows to regular", stat_ret == 0 && (st_mode & S_IFMT) == S_IFREG);
    }

    stat_ret = -1;
    if (procfd >= 0) {
        stat_ret = sys_newfstatat((int)procfd, exe_name, stat_buf, AT_SYMLINK_NOFOLLOW);
    }
    check("newfstatat(procfd, \"exe\", AT_SYMLINK_NOFOLLOW)", stat_ret == 0);
    {
        u32 st_mode = *(u32 *)(stat_buf + 24);
        check("newfstatat(..., AT_SYMLINK_NOFOLLOW) is symlink", stat_ret == 0 && (st_mode & S_IFMT) == S_IFLNK);
    }

    stat_ret = sys_lstat(proc_self, stat_buf);
    check("lstat(\"/proc/self\")", stat_ret == 0);
    {
        u32 st_mode = *(u32 *)(stat_buf + 24);
        check("lstat(\"/proc/self\") is directory", stat_ret == 0 && (st_mode & S_IFMT) == S_IFDIR);
    }

    stat_ret = sys_lstat("/proc/self/exe", stat_buf);
    check("lstat(\"/proc/self/exe\")", stat_ret == 0);
    {
        u32 st_mode = *(u32 *)(stat_buf + 24);
        check("lstat(\"/proc/self/exe\") is symlink", stat_ret == 0 && (st_mode & S_IFMT) == S_IFLNK);
    }

    i64 binfd = sys_openat(AT_FDCWD, usr_bin, O_RDONLY | O_DIRECTORY, 0);
    check("openat(/usr/bin, O_DIRECTORY)", binfd >= 0);

    i64 hello_fd = -1;
    if (binfd >= 0) {
        hello_fd = sys_openat((int)binfd, hello_name, O_RDONLY, 0);
    }
    check("openat(binfd, \"hello_dynamic\")", hello_fd >= 0);

    i64 statx_ret = -1;
    if (binfd >= 0) {
        statx_ret = sys_statx((int)binfd, hello_name, 0, 0, statx_buf);
    }
    check("statx(binfd, \"hello_dynamic\")", statx_ret == 0);

    u64 statx_size = *(u64 *)(statx_buf + 48);
    check("statx size > 0", statx_ret == 0 && statx_size > 0);
    {
        u32 stx_mode = *(unsigned short *)(statx_buf + 28);
        check("statx(binfd, \"hello_dynamic\") is regular", statx_ret == 0 && (stx_mode & S_IFMT) == S_IFREG);
    }

    statx_ret = sys_statx(AT_FDCWD, dev_null, 0, 0, statx_buf);
    check("statx(/dev/null)", statx_ret == 0);
    {
        u32 stx_mode = *(unsigned short *)(statx_buf + 28);
        check("statx(/dev/null) is char device", statx_ret == 0 && (stx_mode & S_IFMT) == S_IFCHR);
    }

    if (hello_fd >= 0) sys_close((int)hello_fd);
    if (exe_fd >= 0) sys_close((int)exe_fd);
    if (binfd >= 0) sys_close((int)binfd);
    if (procfd >= 0) sys_close((int)procfd);

    print("\n=== Results: ");
    if (pass_count >= 10) {
        char tens = '0' + (pass_count / 10);
        sys_write(1, &tens, 1);
    }
    {
        char ones = '0' + (pass_count % 10);
        sys_write(1, &ones, 1);
    }
    print(" passed, ");
    {
        char digit = '0' + fail_count;
        sys_write(1, &digit, 1);
    }
    print(" failed ===\n");

    sys_exit(fail_count);
}
