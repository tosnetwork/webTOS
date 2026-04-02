/*
 * test_large_file_lifecycle.c — Verify large-file create/truncate/unlink cleanup
 *
 * Build:
 *   gcc -nostdlib -static -Os -s -Wl,-Ttext=0x40000000 \
 *     -o test_large_file_lifecycle.elf test_large_file_lifecycle.c
 */

typedef unsigned long u64;
typedef long i64;
typedef unsigned int u32;

#define SYS_WRITE 1
#define SYS_CLOSE 3
#define SYS_FTRUNCATE 77
#define SYS_OPENAT 257
#define SYS_UNLINKAT 263
#define SYS_EXIT 60

#define AT_FDCWD (-100)

#define O_RDONLY 0
#define O_RDWR 2
#define O_CREAT 0x40
#define O_TRUNC 0x200

#define ENOENT 2

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

static i64 sys_close(int fd) {
    return sys_call6(SYS_CLOSE, (u64)fd, 0, 0, 0, 0, 0);
}

static i64 sys_ftruncate(int fd, u64 length) {
    return sys_call6(SYS_FTRUNCATE, (u64)fd, length, 0, 0, 0, 0);
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

static i64 sys_unlinkat(int dirfd, const char *path, int flags) {
    return sys_call6(SYS_UNLINKAT, (u64)(long)dirfd, (u64)path, (u64)(u32)flags, 0, 0, 0);
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

static void print_num(i64 n) {
    char buf[32];
    int i = 0;
    unsigned long v;
    if (n == 0) {
        sys_write(1, "0", 1);
        return;
    }
    if (n < 0) {
        sys_write(1, "-", 1);
        v = (unsigned long)(-n);
    } else {
        v = (unsigned long)n;
    }
    while (v > 0) {
        buf[i++] = '0' + (v % 10);
        v /= 10;
    }
    while (i > 0) {
        char ch = buf[--i];
        sys_write(1, &ch, 1);
    }
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

static void check_eq_i64(const char *name, i64 got, i64 want) {
    if (got == want) {
        print("  [PASS] ");
        pass_count++;
        print(name);
        print("\n");
        return;
    }

    print("  [FAIL] ");
    fail_count++;
    print(name);
    print(" got=");
    print_num(got);
    print(" want=");
    print_num(want);
    print("\n");
}

static i64 write_large_file(int fd, const char *chunk, u64 chunk_size, int repeats) {
    int i;
    for (i = 0; i < repeats; i++) {
        i64 ret = sys_write(fd, chunk, chunk_size);
        if (ret != (i64)chunk_size) {
            return ret;
        }
    }
    return (i64)(chunk_size * (u64)repeats);
}

void _start(void) {
    static char path[] = "/tmp/large_lifecycle.bin";
    char chunk[4096];
    int iter;

    for (iter = 0; iter < (int)sizeof(chunk); iter++) {
        chunk[iter] = (char)('A' + (iter & 15));
    }

    print("=== TOS large-file lifecycle smoke ===\n");

    for (iter = 0; iter < 24; iter++) {
        int fd = (int)sys_openat(AT_FDCWD, path, O_CREAT | O_RDWR | O_TRUNC, 0644);
        check("open large file", fd >= 0);
        if (fd < 0) break;

        check_eq_i64(
            "write multi-segment payload",
            write_large_file(fd, chunk, sizeof(chunk), 80),
            327680
        );
        check("ftruncate to small file", sys_ftruncate(fd, 96) == 0);
        check("close small file", sys_close(fd) == 0);

        fd = (int)sys_openat(AT_FDCWD, path, O_RDWR | O_TRUNC, 0644);
        check("reopen with O_TRUNC", fd >= 0);
        if (fd < 0) break;

        check_eq_i64(
            "rewrite multi-segment payload",
            write_large_file(fd, chunk, sizeof(chunk), 80),
            327680
        );
        check("close rewritten file", sys_close(fd) == 0);
        check("unlink rewritten file", sys_unlinkat(AT_FDCWD, path, 0) == 0);
        check("reopen after unlink -> ENOENT", sys_openat(AT_FDCWD, path, O_RDONLY, 0) == -ENOENT);
    }

    print("=== Results: ");
    print_num(pass_count);
    print(" passed, ");
    print_num(fail_count);
    print(" failed ===\n");
    sys_exit(fail_count == 0 ? 0 : 1);
}
