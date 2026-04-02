/*
 * test_java_jtreg_execve.c — Launch a first-pass OpenJDK 11 jtreg subset.
 *
 * Build:
 *   gcc -nostdlib -static -Os -s -Wl,-Ttext=0x40000000 \
 *     -o test_java_jtreg_execve.elf test_java_jtreg_execve.c
 *
 * The first guest-side bring-up deliberately uses otherVM instead of agentVM.
 * jtreg's agentVM pool uses socket-based VM management, and TOS does not yet
 * provide a Linux-like localhost socket stack for that path.
 *
 * The first in-guest smoke intentionally avoids java.net for now. The current
 * TOS runtime does not yet provide Linux-like NIC/DNS behavior inside the
 * guest, and URL construction tests trigger resolver traffic that can stall
 * jtreg bring-up before the summary is emitted.
 *
 * Success is observed from jtreg's summary in the serial log.
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
    register long r10 __asm__("r10") = 0;
    register long r8 __asm__("r8") = 0;
    register long r9 __asm__("r9") = 0;
    __asm__ volatile(
        "syscall"
        : "=a"(ret)
        : "a"(59), "D"(path), "S"(argv), "d"(envp), "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory");
    return ret;
}

static void sys_exit(int code) {
    __asm__ volatile(
        "syscall"
        :
        : "a"(60), "D"(code)
        : "rcx", "r11", "memory");
    for (;;)
        ;
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
    int neg = 0;
    if (x == 0) {
        sys_write(1, "0", 1);
        return;
    }
    if (x < 0) {
        neg = 1;
        x = -x;
    }
    while (x > 0 && i < (int)sizeof(buf)) {
        buf[i++] = '0' + (x % 10);
        x /= 10;
    }
    if (neg) {
        buf[i++] = '-';
    }
    while (i-- > 0) {
        sys_write(1, &buf[i], 1);
    }
}

void _start(void) {
    static char path[] = "/usr/lib/jvm/java-11-openjdk-amd64/bin/java";
    static char arg0[] = "java";
    static char arg1[] = "-jar";
    static char arg2[] = "/jdk/jtreg/lib/jtreg.jar";
    static char arg3[] = "-jdk:/usr/lib/jvm/java-11-openjdk-amd64";
    static char arg4[] = "-javaoptions:-Xshare:off";
    static char arg5[] = "-javaoptions:-XX:-UsePerfData";
    static char arg6[] = "-vmoption:-Xint";
    static char arg7[] = "-vmoption:-XX:-UseCompiler";
    static char arg8[] = "-javacoption:-J-Xint";
    static char arg9[] = "-javacoption:-J-XX:-UseCompiler";
    static char arg10[] = "-nojit";
    static char arg11[] = "-othervm";
    static char arg12[] = "-a";
    static char arg13[] = "-noshell";
    static char arg14[] = "-verbose:error,fail,summary";
    static char arg15[] = "-ignore:quiet";
    static char arg16[] = "-timeoutFactor:4";
    static char arg17[] = "-w:/tmp/JTwork";
    static char arg18[] = "-r:/tmp/JTreport";
    static char arg19[] = "/jdk/test/jdk/java/lang/String/Chars.java";
    static char arg20[] = "/jdk/test/jdk/java/io/File/IsAbsolute.java";
    static char arg21[] = "/jdk/test/jdk/java/nio/file/DirectoryStream/Basic.java";
    static char arg22[] = "/jdk/test/jdk/java/nio/file/Path/Misc.java";
    static char arg23[] = "/jdk/test/jdk/java/util/Base64/Base64GetEncoderTest.java";
    static char arg24[] = "/jdk/test/jdk/java/util/concurrent/TimeUnit/Basic.java";
    static char arg25[] = "/jdk/test/jdk/java/util/zip/ZipEntry/Constructor.java";
    static char env0[] = "JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64";
    static char env1[] = "LANG=C";
    static char env2[] = "LC_ALL=C";
    static char env3[] = "TZ=UTC0";
    static char env4[] = "HOME=/";
    /*
     * Force all helper JVMs that jtreg spawns down the interpreted path.
     * The remaining guest-side bring-up failure is HotSpot crashing in the
     * compiler interface during the bootClasses javac step.
     */
    static char env5[] = "JAVA_TOOL_OPTIONS=-Xint -XX:-UseCompiler -Xshare:off -XX:-UsePerfData";
    static char *argv[] = {
        arg0,  arg1,  arg2,  arg3,  arg4,  arg5,  arg6,  arg7,
        arg8,  arg9,  arg10, arg11, arg12, arg13, arg14, arg15,
        arg16, arg17, arg18, arg19, arg20, arg21, arg22, arg23, arg24, arg25, 0,
    };
    static char *envp[] = {env0, env1, env2, env3, env4, env5, 0};

    print("[JAVA] launching jtreg java.base smoke subset\n");
    long ret = sys_execve(path, argv, envp);
    print("[JAVA] execve returned ");
    print_num(ret);
    print("\n");
    sys_exit((ret == 0) ? 0 : 1);
}
