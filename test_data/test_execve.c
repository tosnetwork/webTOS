/*
 * test_execve.c — Verify execve() can launch a base-image executable.
 *
 * Build:
 *   gcc -nostdlib -static -Wl,-Ttext=0x40000000 -o test_execve.elf test_execve.c
 *
 * This binary performs a raw Linux x86_64 execve syscall:
 *   execve("/usr/bin/hello_dynamic", argv, envp)
 *
 * Success is observed when the dynamically-linked target starts and prints
 * its argv/envp lines. If execve returns, the test prints the error code.
 */

typedef unsigned long u64;
typedef long i64;

static i64 sys_write(int fd, const void *buf, u64 count) {
    i64 ret;
    __asm__ volatile(
        "syscall"
        : "=a"(ret)
        : "a"(1), "D"((u64)fd), "S"((u64)buf), "d"(count)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static i64 sys_execve(const char *path, char *const argv[], char *const envp[]) {
    i64 ret;
    __asm__ volatile(
        "syscall"
        : "=a"(ret)
        : "a"(59), "D"((u64)path), "S"((u64)argv), "d"((u64)envp)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static void sys_exit(int code) {
    __asm__ volatile(
        "syscall"
        :
        : "a"(60), "D"((u64)code)
        : "rcx", "r11", "memory"
    );
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

void _start(void) {
    static char path[] = "/usr/bin/hello_dynamic";
    static char arg1[] = "--via-execve";
    static char env0[] = "EXECVE_SMOKE=1";
    static char *argv[] = { path, arg1, 0 };
    static char *envp[] = { env0, 0 };

    print("[EXECVE] launching /usr/bin/hello_dynamic\n");
    i64 ret = sys_execve(path, argv, envp);
    print("[EXECVE] execve returned ");
    print_num(ret);
    print("\n");
    sys_exit(1);
}
