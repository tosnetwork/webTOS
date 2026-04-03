typedef unsigned long u64;
typedef long i64;

static i64 sys_write(int fd, const void *buf, u64 count) {
    i64 ret;
    __asm__ volatile(
        "syscall"
        : "=a"(ret)
        : "a"(1), "D"((u64)fd), "S"((u64)buf), "d"(count)
        : "rcx", "r11", "memory");
    return ret;
}

static i64 sys_getpid(void) {
    i64 ret;
    __asm__ volatile(
        "syscall"
        : "=a"(ret)
        : "a"(39)
        : "rcx", "r11", "memory");
    return ret;
}

static void sys_exit(int code) {
    __asm__ volatile(
        "syscall"
        :
        : "a"(60), "D"((u64)code)
        : "rcx", "r11", "memory");
    __builtin_unreachable();
}

static void write_str(const char *s) {
    u64 len = 0;
    while (s[len]) {
        len++;
    }
    sys_write(1, s, len);
}

static void write_num(i64 n) {
    char buf[32];
    int i = 0;
    unsigned long v = (unsigned long)(n < 0 ? -n : n);
    if (n < 0) {
        sys_write(1, "-", 1);
    }
    if (v == 0) {
        sys_write(1, "0", 1);
        return;
    }
    while (v > 0) {
        buf[i++] = (char)('0' + (v % 10));
        v /= 10;
    }
    while (i > 0) {
        char ch = buf[--i];
        sys_write(1, &ch, 1);
    }
}

void _start(void) {
    write_str("  PID CMD\n");
    write_num(sys_getpid());
    write_str(" ps\n");
    sys_exit(0);
}
