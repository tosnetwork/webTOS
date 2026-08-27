/*
 * test_size_narrowing.c — guest sizes that do not fit a 32-bit `usize`
 *
 * `usize` is 32 bits in a browser, so a guest value cast with `as usize`
 * silently keeps its low half. A 4 GiB `ftruncate` became a truncate to zero,
 * and a write at offset 2^32 landed on top of the first bytes of the file.
 * Real Linux honours both (the file becomes sparse and the head is intact);
 * a tab cannot hold 4 GiB, so refusing is the only correct answer — what is
 * never correct is doing something smaller and reporting success.
 *
 * Build:
 *   gcc -nostdlib -static -Wl,-Ttext=0x40000000 -o test_size_narrowing.elf \
 *       test_size_narrowing.c
 */

typedef unsigned long u64;
typedef long i64;

#define SYS_READ 0
#define SYS_WRITE 1
#define SYS_CLOSE 3
#define SYS_LSEEK 8
#define SYS_FTRUNCATE 77
#define SYS_EXIT 60
#define SYS_OPENAT 257

#define AT_FDCWD (-100)
#define O_RDWR 2
#define O_CREAT 0100
#define O_TRUNC 01000
#define SEEK_SET 0
#define SEEK_END 2

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

static void num(i64 v) {
    char buf[24];
    int i = 23;
    int neg = v < 0;
    u64 u = neg ? (u64)(-v) : (u64)v;
    buf[i--] = 0;
    if (u == 0) buf[i--] = '0';
    while (u) { buf[i--] = '0' + (char)(u % 10); u /= 10; }
    if (neg) buf[i--] = '-';
    sys3(SYS_WRITE, 1, (i64)&buf[i + 1], 23 - (i + 1));
}

void _start(void) {
    i64 fd = sys4(SYS_OPENAT, AT_FDCWD, (i64) "/tmp/narrow",
                  O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) sys3(SYS_EXIT, 1, 0, 0);

    const char head[] = "keep-me";
    sys3(SYS_WRITE, fd, (i64)head, 7);

    i64 four_gib = 1LL << 32;
    i64 t = sys3(SYS_FTRUNCATE, fd, four_gib, 0);
    i64 size = sys3(SYS_LSEEK, fd, 0, SEEK_END);

    sys3(SYS_LSEEK, fd, four_gib, SEEK_SET);
    i64 w = sys3(SYS_WRITE, fd, (i64) "X", 1);

    /* A read far past the end must report end-of-file, not wrap to the
       start and hand back the beginning of the file. */
    char far[8];
    for (int i = 0; i < 8; i++) far[i] = 0;
    sys3(SYS_LSEEK, fd, four_gib, SEEK_SET);
    i64 rfar = sys3(SYS_READ, fd, (i64)far, 7);

    char buf[8];
    sys3(SYS_LSEEK, fd, 0, SEEK_SET);
    i64 r = sys3(SYS_READ, fd, (i64)buf, 7);
    buf[r > 0 ? r : 0] = 0;

    out("truncate="); num(t);
    out(" size="); num(size);
    out(" write="); num(w);
    out(" far_read="); num(rfar);
    out(" head="); out(buf);
    out("\n");

    sys3(SYS_CLOSE, fd, 0, 0);
    sys3(SYS_EXIT, 0, 0, 0);
}
