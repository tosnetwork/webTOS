/*
 * test_node_child_execve.c — Child-process smoke for Node.js.
 *
 * Build:
 *   gcc -nostdlib -static -Os -s -Wl,-Ttext=0x40000000 -o test_node_child_execve.elf test_node_child_execve.c
 *
 * Runs:
 *   execve("/usr/bin/node", ["node", "--max-old-space-size=8", "/usr/lib/tos-tests/node_child_smoke.js"], envp)
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
    static char path[] = "/usr/bin/node";
    static char arg1[] = "--max-old-space-size=8";
    static char arg2[] = "/usr/lib/tos-tests/node_child_smoke.js";
    static char env0[] = "LANG=C";
    static char *argv[] = {path, arg1, arg2, 0};
    static char *envp[] = {env0, 0};

    print("[NODE] launching node child-process smoke\n");
    i64 ret = sys_execve(path, argv, envp);
    print("[NODE] child execve returned ");
    print_num(ret);
    print("\n");
    sys_exit(1);
}
