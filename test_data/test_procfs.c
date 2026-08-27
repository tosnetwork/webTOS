/*
 * test_procfs.c — the few /proc files a language runtime cannot start without
 *
 * `/proc/self/maps` is the one that matters: Bun aborts at startup when it is
 * missing, and every debugger reads it. The others are the same machine state
 * in the shapes procfs uses.
 *
 * Build:
 *   gcc -nostdlib -static -Wl,-Ttext=0x40000000 -o test_procfs.elf test_procfs.c
 */

typedef unsigned long u64;
typedef long i64;

#define SYS_READ 0
#define SYS_WRITE 1
#define SYS_CLOSE 3
#define SYS_EXIT 60
#define SYS_OPENAT 257
#define AT_FDCWD (-100)
#define O_RDONLY 0

static i64 sys3(i64 n, i64 a, i64 b, i64 c) {
    i64 r;
    __asm__ volatile("syscall" : "=a"(r) : "a"(n), "D"(a), "S"(b), "d"(c)
                     : "rcx", "r11", "memory");
    return r;
}
static i64 sys4(i64 n, i64 a, i64 b, i64 c, i64 d) {
    register i64 r10 __asm__("r10") = d;
    i64 r;
    __asm__ volatile("syscall" : "=a"(r) : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10)
                     : "rcx", "r11", "memory");
    return r;
}
static void out(const char *s) {
    const char *p = s;
    while (*p) p++;
    sys3(SYS_WRITE, 1, (i64)s, p - s);
}

static char buf[8192];

/* Reads a file and reports its first line, so the test sees the shape the
   guest sees rather than what the host thinks it wrote. */
static void show(const char *path) {
    out(path);
    out(": ");
    i64 fd = sys4(SYS_OPENAT, AT_FDCWD, (i64)path, O_RDONLY, 0);
    if (fd < 0) {
        out("MISSING\n");
        return;
    }
    i64 n = sys3(SYS_READ, fd, (i64)buf, sizeof buf - 1);
    sys3(SYS_CLOSE, fd, 0, 0);
    if (n <= 0) {
        out("EMPTY\n");
        return;
    }
    buf[n] = 0;
    for (i64 i = 0; i < n; i++) {
        if (buf[i] == '\n') { buf[i] = 0; break; }
    }
    out(buf);
    out("\n");
}

void _start(void) {
    show("/proc/self/maps");
    show("/proc/self/statm");
    show("/proc/self/cmdline");
    show("/proc/meminfo");
    sys3(SYS_EXIT, 0, 0, 0);
}
