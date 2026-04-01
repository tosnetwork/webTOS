/*
 * test_ioctl_smoke.c — Verify Linux runtime-facing ioctl semantics
 *
 * Build:
 *   gcc -nostdlib -static -Wl,-Ttext=0x40000000 -o test_ioctl_smoke.elf test_ioctl_smoke.c
 */

typedef unsigned long u64;
typedef long i64;
typedef unsigned int u32;

#define SYS_READ 0
#define SYS_WRITE 1
#define SYS_CLOSE 3
#define SYS_FSTAT 5
#define SYS_IOCTL 16
#define SYS_LSEEK 8
#define SYS_FCNTL 72
#define SYS_DUP 32
#define SYS_DUP2 33
#define SYS_DUP3 292
#define SYS_EXIT 60
#define SYS_OPENAT 257
#define SYS_PIPE 22

#define AT_FDCWD (-100)
#define O_RDONLY 0
#define O_NONBLOCK 0x800
#define O_CLOEXEC 0x80000
#define F_DUPFD 0
#define F_GETFD 1
#define F_GETFL 3
#define F_DUPFD_CLOEXEC 1030
#define TCGETS 0x5401
#define TIOCGWINSZ 0x5413
#define FIONREAD 0x541B
#define FIONBIO 0x5421
#define FIONCLEX 0x5450
#define FIOCLEX 0x5451
#define ENOTTY 25
#define ESPIPE 29
#define SEEK_CUR 1
#define S_IFMT 0170000
#define S_IFIFO 0010000

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

static i64 sys_close(int fd) {
    return sys_call6(SYS_CLOSE, (u64)fd, 0, 0, 0, 0, 0);
}

static i64 sys_fstat(int fd, void *st) {
    return sys_call6(SYS_FSTAT, (u64)fd, (u64)st, 0, 0, 0, 0);
}

static i64 sys_ioctl(int fd, u64 cmd, void *arg) {
    return sys_call6(SYS_IOCTL, (u64)fd, cmd, (u64)arg, 0, 0, 0);
}

static i64 sys_lseek(int fd, i64 offset, u32 whence) {
    return sys_call6(SYS_LSEEK, (u64)fd, (u64)offset, (u64)whence, 0, 0, 0);
}

static i64 sys_fcntl(int fd, int cmd, u64 arg) {
    return sys_call6(SYS_FCNTL, (u64)fd, (u64)(u32)cmd, arg, 0, 0, 0);
}

static i64 sys_pipe(int *pipefd) {
    return sys_call6(SYS_PIPE, (u64)pipefd, 0, 0, 0, 0, 0);
}

static i64 sys_dup(int fd) {
    return sys_call6(SYS_DUP, (u64)fd, 0, 0, 0, 0, 0);
}

static i64 sys_dup2(int oldfd, int newfd) {
    return sys_call6(SYS_DUP2, (u64)oldfd, (u64)newfd, 0, 0, 0, 0);
}

static i64 sys_dup3(int oldfd, int newfd, u32 flags) {
    return sys_call6(SYS_DUP3, (u64)oldfd, (u64)newfd, (u64)flags, 0, 0, 0);
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
    static char hello_path[] = "/usr/bin/hello_dynamic";
    static char abc[] = "abc";
    int pipefd[2] = {-1, -1};
    unsigned char one = 1;
    int value = -1;
    unsigned char stat_buf[144];
    u32 st_mode = 0;

    print("=== ATOS ioctl smoke test ===\n");

    i64 fd = sys_openat(AT_FDCWD, hello_path, O_RDONLY, 0);
    check("openat(/usr/bin/hello_dynamic)", fd >= 0);
    check("ioctl(TCGETS) -> ENOTTY", fd >= 0 && sys_ioctl((int)fd, TCGETS, 0) == -ENOTTY);
    check(
        "ioctl(TIOCGWINSZ) -> ENOTTY",
        fd >= 0 && sys_ioctl((int)fd, TIOCGWINSZ, 0) == -ENOTTY
    );

    if (fd >= 0) {
        check("ioctl(FIOCLEX)", sys_ioctl((int)fd, FIOCLEX, 0) == 0);
        check("fcntl(F_GETFD) sees cloexec", sys_fcntl((int)fd, F_GETFD, 0) == 1);
        {
            i64 dupfd = sys_dup((int)fd);
            check("dup() clears cloexec", dupfd >= 0 && sys_fcntl((int)dupfd, F_GETFD, 0) == 0);
            if (dupfd >= 0) sys_close((int)dupfd);
        }
        {
            i64 dupfd = sys_fcntl((int)fd, F_DUPFD, 20);
            check(
                "fcntl(F_DUPFD) clears cloexec",
                dupfd >= 0 && sys_fcntl((int)dupfd, F_GETFD, 0) == 0
            );
            if (dupfd >= 0) sys_close((int)dupfd);
        }
        {
            i64 dupfd = sys_fcntl((int)fd, F_DUPFD_CLOEXEC, 20);
            check(
                "fcntl(F_DUPFD_CLOEXEC) sets cloexec",
                dupfd >= 0 && sys_fcntl((int)dupfd, F_GETFD, 0) == 1
            );
            if (dupfd >= 0) sys_close((int)dupfd);
        }
        {
            i64 dupfd = sys_dup2((int)fd, 30);
            check("dup2() clears cloexec", dupfd == 30 && sys_fcntl(30, F_GETFD, 0) == 0);
            if (dupfd >= 0) sys_close((int)dupfd);
        }
        {
            i64 dupfd = sys_dup3((int)fd, 31, O_CLOEXEC);
            check("dup3(O_CLOEXEC) sets cloexec", dupfd == 31 && sys_fcntl(31, F_GETFD, 0) == 1);
            if (dupfd >= 0) sys_close((int)dupfd);
        }
        check("ioctl(FIONCLEX)", sys_ioctl((int)fd, FIONCLEX, 0) == 0);
        check("fcntl(F_GETFD) sees cloexec cleared", sys_fcntl((int)fd, F_GETFD, 0) == 0);
    }

    check("pipe()", sys_pipe(pipefd) == 0);
    if (pipefd[0] >= 0) {
        check("ioctl(FIONBIO)", sys_ioctl(pipefd[0], FIONBIO, &one) == 0);
        check("fcntl(F_GETFL) sees O_NONBLOCK", (sys_fcntl(pipefd[0], F_GETFL, 0) & O_NONBLOCK) != 0);
        value = -1;
        check("ioctl(FIONREAD) empty pipe", sys_ioctl(pipefd[0], FIONREAD, &value) == 0 && value == 0);
        check("write(pipefd[1], \"abc\", 3)", sys_write(pipefd[1], abc, 3) == 3);
        value = -1;
        check("ioctl(FIONREAD) pending bytes", sys_ioctl(pipefd[0], FIONREAD, &value) == 0 && value == 3);
        for (u64 i = 0; i < sizeof(stat_buf); i++) stat_buf[i] = 0;
        check("fstat(pipefd[0])", sys_fstat(pipefd[0], stat_buf) == 0);
        st_mode = *(u32 *)&stat_buf[24];
        check("fstat(pipefd[0]) is fifo", (st_mode & S_IFMT) == S_IFIFO);
        check("lseek(pipefd[0]) -> ESPIPE", sys_lseek(pipefd[0], 0, SEEK_CUR) == -ESPIPE);
    }

    if (fd >= 0) sys_close((int)fd);
    if (pipefd[0] >= 0) sys_close(pipefd[0]);
    if (pipefd[1] >= 0) sys_close(pipefd[1]);

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
