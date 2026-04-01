/*
 * test_mux_smoke.c — Verify Linux pipe/readv/writev/poll/select semantics
 *
 * Build:
 *   gcc -nostdlib -static -Wl,-Ttext=0x40000000 -o test_mux_smoke.elf test_mux_smoke.c
 */

typedef unsigned long u64;
typedef long i64;
typedef unsigned int u32;

#define SYS_READ 0
#define SYS_WRITE 1
#define SYS_CLOSE 3
#define SYS_POLL 7
#define SYS_READV 19
#define SYS_WRITEV 20
#define SYS_PIPE 22
#define SYS_SELECT 23
#define SYS_FCNTL 72
#define SYS_EPOLL_WAIT 232
#define SYS_EPOLL_CTL 233
#define SYS_EXIT 60
#define SYS_EPOLL_CREATE1 291
#define SYS_PIPE2 293

#define O_RDONLY 0
#define O_WRONLY 1
#define O_NONBLOCK 0x800
#define O_CLOEXEC 0x80000

#define F_GETFD 1
#define F_GETFL 3

#define POLLIN 0x0001
#define POLLOUT 0x0004

#define EBADF 9
#define EFAULT 14
#define EINVAL 22

struct iovec {
    void *iov_base;
    u64 iov_len;
};

struct pollfd {
    int fd;
    short events;
    short revents;
};

struct epoll_event {
    u32 events;
    u64 data;
} __attribute__((packed));

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

static i64 sys_read(int fd, void *buf, u64 count) {
    return sys_call6(SYS_READ, (u64)fd, (u64)buf, count, 0, 0, 0);
}

static i64 sys_write(int fd, const void *buf, u64 count) {
    return sys_call6(SYS_WRITE, (u64)fd, (u64)buf, count, 0, 0, 0);
}

static i64 sys_close(int fd) {
    return sys_call6(SYS_CLOSE, (u64)fd, 0, 0, 0, 0, 0);
}

static i64 sys_poll(struct pollfd *fds, u64 nfds, int timeout) {
    return sys_call6(SYS_POLL, (u64)fds, nfds, (u64)(u32)timeout, 0, 0, 0);
}

static i64 sys_readv(int fd, struct iovec *iov, int iovcnt) {
    return sys_call6(SYS_READV, (u64)fd, (u64)iov, (u64)(u32)iovcnt, 0, 0, 0);
}

static i64 sys_writev(int fd, const struct iovec *iov, int iovcnt) {
    return sys_call6(SYS_WRITEV, (u64)fd, (u64)iov, (u64)(u32)iovcnt, 0, 0, 0);
}

static i64 sys_pipe(int *pipefd) {
    return sys_call6(SYS_PIPE, (u64)pipefd, 0, 0, 0, 0, 0);
}

static i64 sys_pipe2(int *pipefd, int flags) {
    return sys_call6(SYS_PIPE2, (u64)pipefd, (u64)(u32)flags, 0, 0, 0, 0);
}

static i64 sys_select(int nfds, void *readfds, void *writefds, void *exceptfds, void *timeout) {
    return sys_call6(
        SYS_SELECT,
        (u64)(u32)nfds,
        (u64)readfds,
        (u64)writefds,
        (u64)exceptfds,
        (u64)timeout,
        0
    );
}

static i64 sys_fcntl(int fd, int cmd, u64 arg) {
    return sys_call6(SYS_FCNTL, (u64)fd, (u64)(u32)cmd, arg, 0, 0, 0);
}

static i64 sys_epoll_create1(int flags) {
    return sys_call6(SYS_EPOLL_CREATE1, (u64)(u32)flags, 0, 0, 0, 0, 0);
}

static i64 sys_epoll_ctl(int epfd, int op, int fd, void *event) {
    return sys_call6(SYS_EPOLL_CTL, (u64)epfd, (u64)(u32)op, (u64)fd, (u64)event, 0, 0);
}

static i64 sys_epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout) {
    return sys_call6(SYS_EPOLL_WAIT, (u64)epfd, (u64)events, (u64)(u32)maxevents, (u64)(u32)timeout, 0, 0);
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

static int memeq(const char *a, const char *b, u64 len) {
    u64 i;
    for (i = 0; i < len; i++) {
        if (a[i] != b[i]) return 0;
    }
    return 1;
}

static void fd_zero(unsigned char *set) {
    u64 i;
    for (i = 0; i < 32; i++) set[i] = 0;
}

static void fd_set_bit(unsigned char *set, int fd) {
    set[(u32)fd / 8] |= (unsigned char)(1u << ((u32)fd & 7));
}

static int fd_is_set(const unsigned char *set, int fd) {
    return (set[(u32)fd / 8] & (unsigned char)(1u << ((u32)fd & 7))) != 0;
}

void _start(void) {
    int pipefd[2] = {-1, -1};
    struct pollfd pfds[2];
    struct epoll_event evbuf[2];
    struct iovec iov[2];
    char msg0[] = "ab";
    char msg1[] = "cd";
    char buf0[2] = {0, 0};
    char buf1[2] = {0, 0};
    char dummy[2] = {0, 0};
    unsigned char readfds[32];
    unsigned char writefds[32];
    int epfd = -1;

    enum { EPOLL_CTL_ADD = 1 };

    print("=== ATOS mux smoke test ===\n");

    check("pipe(NULL) -> EFAULT", sys_pipe((int *)0) == -EFAULT);
    check("pipe2(unsupported flags) -> EINVAL", sys_pipe2(pipefd, 0x4) == -EINVAL);
    check("poll(NULL, 1, 0) -> EFAULT", sys_poll((struct pollfd *)0, 1, 0) == -EFAULT);
    check("epoll_wait(NULL, 1, 0) -> EFAULT", sys_epoll_wait(0, (struct epoll_event *)0, 1, 0) == -EFAULT);

    check("pipe2(O_CLOEXEC|O_NONBLOCK)", sys_pipe2(pipefd, O_CLOEXEC | O_NONBLOCK) == 0);
    check("pipe2 fds valid", pipefd[0] >= 0 && pipefd[1] >= 0);
    check("pipe2 read fd cloexec", sys_fcntl(pipefd[0], F_GETFD, 0) == 1);
    check("pipe2 write fd cloexec", sys_fcntl(pipefd[1], F_GETFD, 0) == 1);
    check(
        "pipe2 read fd nonblock",
        (sys_fcntl(pipefd[0], F_GETFL, 0) & O_NONBLOCK) != 0
    );
    check(
        "pipe2 write fd nonblock",
        (sys_fcntl(pipefd[1], F_GETFL, 0) & O_NONBLOCK) != 0
    );

    check("read(write_end) -> EBADF", sys_read(pipefd[1], dummy, sizeof(dummy)) == -EBADF);
    check("write(read_end) -> EBADF", sys_write(pipefd[0], msg0, 1) == -EBADF);
    check("readv(NULL iov) -> EFAULT", sys_readv(pipefd[0], (struct iovec *)0, 1) == -EFAULT);
    check("writev(NULL iov) -> EFAULT", sys_writev(pipefd[1], (struct iovec *)0, 1) == -EFAULT);

    iov[0].iov_base = msg0;
    iov[0].iov_len = 2;
    iov[1].iov_base = msg1;
    iov[1].iov_len = 2;
    check("writev(pipe write end)", sys_writev(pipefd[1], iov, 2) == 4);

    pfds[0].fd = pipefd[0];
    pfds[0].events = POLLIN | POLLOUT;
    pfds[0].revents = 0;
    check("poll(read end) -> readable only", sys_poll(&pfds[0], 1, 0) == 1 && pfds[0].revents == POLLIN);

    pfds[1].fd = pipefd[1];
    pfds[1].events = POLLIN | POLLOUT;
    pfds[1].revents = 0;
    check(
        "poll(write end) -> writable only",
        sys_poll(&pfds[1], 1, 0) == 1 && pfds[1].revents == POLLOUT
    );

    fd_zero(readfds);
    fd_zero(writefds);
    fd_set_bit(readfds, pipefd[0]);
    fd_set_bit(writefds, pipefd[1]);
    check(
        "select(read end, write end)",
        sys_select(pipefd[1] + 1, readfds, writefds, 0, 0) == 2 &&
            fd_is_set(readfds, pipefd[0]) &&
            !fd_is_set(readfds, pipefd[1]) &&
            fd_is_set(writefds, pipefd[1]) &&
            !fd_is_set(writefds, pipefd[0])
    );

    iov[0].iov_base = buf0;
    iov[0].iov_len = 2;
    iov[1].iov_base = buf1;
    iov[1].iov_len = 2;
    check("readv(pipe read end)", sys_readv(pipefd[0], iov, 2) == 4);
    check("readv payload segment 0", memeq(buf0, "ab", 2));
    check("readv payload segment 1", memeq(buf1, "cd", 2));

    pfds[0].fd = pipefd[0];
    pfds[0].events = POLLIN;
    pfds[0].revents = 7;
    check("poll(read end empty) -> 0", sys_poll(&pfds[0], 1, 0) == 0 && pfds[0].revents == 0);

    fd_zero(readfds);
    fd_set_bit(readfds, pipefd[0]);
    check(
        "select(read end empty) -> 0 and clears bit",
        sys_select(pipefd[0] + 1, readfds, 0, 0, 0) == 0 && !fd_is_set(readfds, pipefd[0])
    );

    epfd = (int)sys_epoll_create1(0);
    check("epoll_create1(0)", epfd >= 0);
    if (epfd >= 0) {
        evbuf[0].events = POLLIN;
        evbuf[0].data = (u64)pipefd[0];
        check("epoll_ctl(ADD, read end)", sys_epoll_ctl(epfd, EPOLL_CTL_ADD, pipefd[0], &evbuf[0]) == 0);
        check("epoll_wait(empty read end) -> 0", sys_epoll_wait(epfd, evbuf, 1, 0) == 0);
        check("write(pipefd[1], \"ab\", 2)", sys_write(pipefd[1], msg0, 2) == 2);
        evbuf[0].events = 0;
        evbuf[0].data = 0;
        check(
            "epoll_wait(readable read end)",
            sys_epoll_wait(epfd, evbuf, 1, 0) == 1 &&
                evbuf[0].events == POLLIN &&
                evbuf[0].data == (u64)pipefd[0]
        );
        check("drain read end after epoll", sys_read(pipefd[0], dummy, 2) == 2);
    }

    if (epfd >= 0) sys_close(epfd);
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
        char tens = '0' + ((fail_count / 10) % 10);
        char ones = '0' + (fail_count % 10);
        if (fail_count >= 10) sys_write(1, &tens, 1);
        sys_write(1, &ones, 1);
    }
    print(" failed ===\n");

    sys_exit(fail_count);
}
