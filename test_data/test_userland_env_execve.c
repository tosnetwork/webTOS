/*
 * test_userland_env_execve.c — Minimal Linux userland environment smoke.
 *
 * Build:
 *   gcc -nostdlib -static -Os -s -Wl,-Ttext=0x40000000 \
 *     -o test_userland_env_execve.elf test_userland_env_execve.c
 *
 * Runs:
 *   execve("/usr/bin/env",
 *          ["env", "-i", "PATH=/bin:/usr/bin", "TOS_PROBE=ok",
 *           "/bin/sh", "/usr/lib/tos-tests/shell_env_probe.sh"], envp)
 */

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

static i64 sys_execve(const char *path, char *const argv[], char *const envp[]) {
    i64 ret;
    __asm__ volatile(
        "syscall"
        : "=a"(ret)
        : "a"(59), "D"((u64)path), "S"((u64)argv), "d"((u64)envp)
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

static void print(const char *s) {
    u64 len = 0;
    while (s[len]) {
        len++;
    }
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
        buf[i++] = (char)('0' + (v % 10));
        v /= 10;
    }
    while (i > 0) {
        char ch = buf[--i];
        sys_write(1, &ch, 1);
    }
}

void _start(void) {
    static char path[] = "/usr/bin/env";
    static char arg1[] = "-i";
    static char arg2[] = "PATH=/bin:/usr/bin";
    static char arg3[] = "TOS_PROBE=ok";
    static char arg4[] = "/bin/sh";
    static char arg5[] = "/usr/lib/tos-tests/shell_env_probe.sh";
    static char env0[] = "LANG=C";
    static char *argv[] = {path, arg1, arg2, arg3, arg4, arg5, 0};
    static char *envp[] = {env0, 0};

    print("[USERLAND] launching /usr/bin/env -> /bin/sh smoke\n");
    i64 ret = sys_execve(path, argv, envp);
    print("[USERLAND] env execve returned ");
    print_num(ret);
    print("\n");
    sys_exit(1);
}
