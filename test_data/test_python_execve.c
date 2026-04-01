/*
 * test_python_execve.c — Smoke test for host-installed Python in base image.
 *
 * Build:
 *   gcc -nostdlib -static -Os -s -Wl,-Ttext=0x40000000 -o test_python_execve.elf test_python_execve.c
 *
 * This binary performs:
 *   execve("/usr/bin/python3", ["python3", "-c", "print(1)"], envp)
 *
 * Success is observed if Python prints "1" and exits cleanly.
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
    static char path[] = "/usr/bin/python3";
    static char arg1[] = "-c";
    static char arg2[] = "print(1)";
    static char env0[] = "PYTHONHOME=/usr";
    static char env1[] = "PYTHONDONTWRITEBYTECODE=1";
    static char env2[] = "PYTHONNOUSERSITE=1";
    static char env3[] = "LANG=C";
    static char *argv[] = { path, arg1, arg2, 0 };
    static char *envp[] = { env0, env1, env2, env3, 0 };

    print("[PYTHON] launching /usr/bin/python3 -c print(1)\n");
    i64 ret = sys_execve(path, argv, envp);
    print("[PYTHON] execve returned ");
    print_num(ret);
    print("\n");
    sys_exit(1);
}
