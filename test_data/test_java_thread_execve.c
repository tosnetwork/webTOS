/*
 * test_java_thread_execve.c — Multi-threaded stress smoke for OpenJDK.
 *
 * Build:
 *   gcc -nostdlib -static -Os -s -Wl,-Ttext=0x40000000 -o test_java_thread_execve.elf test_java_thread_execve.c
 *
 * Runs:
 *   execve("/usr/lib/jvm/java-11-openjdk-amd64/bin/java",
 *          ["java", "-Xshare:off", "-XX:-UsePerfData", "-cp",
 *           "/usr/lib/tos-tests", "JavaThreadSmoke"], envp)
 */

typedef unsigned long size_t;

static long sys_write(int fd, const void *buf, size_t len) {
    long ret;
    __asm__ volatile(
        "syscall"
        : "=a"(ret)
        : "a"(1), "D"(fd), "S"(buf), "d"(len)
        : "rcx", "r11", "memory");
    return ret;
}

static long sys_execve(const char *path, char *const argv[], char *const envp[]) {
    long ret;
    __asm__ volatile(
        "syscall"
        : "=a"(ret)
        : "a"(59), "D"(path), "S"(argv), "d"(envp)
        : "rcx", "r11", "memory");
    return ret;
}

static void sys_exit(int code) {
    __asm__ volatile(
        "syscall"
        :
        : "a"(60), "D"(code)
        : "rcx", "r11", "memory");
    __builtin_unreachable();
}

static size_t strlen_(const char *s) {
    size_t n = 0;
    while (s[n]) {
        n++;
    }
    return n;
}

static void print(const char *s) {
    sys_write(1, s, strlen_(s));
}

static void print_num(long x) {
    char buf[32];
    int i = 0;
    if (x == 0) {
        sys_write(1, "0", 1);
        return;
    }
    if (x < 0) {
        sys_write(1, "-", 1);
        x = -x;
    }
    while (x > 0) {
        buf[i++] = (char)('0' + (x % 10));
        x /= 10;
    }
    while (i-- > 0) {
        sys_write(1, &buf[i], 1);
    }
}

void _start(void) {
    static char path[] = "/usr/lib/jvm/java-11-openjdk-amd64/bin/java";
    static char arg0[] = "java";
    static char arg1[] = "-Xshare:off";
    static char arg2[] = "-XX:-UsePerfData";
    static char arg3[] = "-cp";
    static char arg4[] = "/usr/lib/tos-tests";
    static char arg5[] = "JavaThreadSmoke";
    static char env0[] = "JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64";
    static char env1[] = "LANG=C";
    static char env2[] = "LC_ALL=C";
    static char env3[] = "TZ=UTC0";
    static char env4[] = "HOME=/";
    static char *argv[] = {arg0, arg1, arg2, arg3, arg4, arg5, 0};
    static char *envp[] = {env0, env1, env2, env3, env4, 0};

    print("[JAVA] launching java thread smoke\n");
    long ret = sys_execve(path, argv, envp);
    print("[JAVA] thread execve returned ");
    print_num(ret);
    print("\n");
    sys_exit(1);
}
