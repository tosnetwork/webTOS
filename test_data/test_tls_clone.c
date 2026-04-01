/*
 * test_tls_clone.c — Verify arch_prctl TLS state and clone TLS inheritance
 *
 * Build:
 *   gcc -nostdlib -static -Wl,-Ttext=0x40000000 -o test_tls_clone.elf test_tls_clone.c
 */

typedef unsigned long u64;
typedef long i64;
typedef unsigned int u32;

#define SYS_WRITE 1
#define SYS_EXIT 60
#define SYS_WAIT4 61
#define SYS_UNAME 63
#define SYS_ARCH_PRCTL 158
#define SYS_CLONE 56
#define SYS_FUTEX 202
#define SYS_GETTID 186
#define SYS_SET_TID_ADDRESS 218
#define SYS_SET_ROBUST_LIST 273
#define SYS_GET_ROBUST_LIST 274
#define SYS_PRLIMIT64 302
#define SYS_PRCTL 157

#define ARCH_SET_GS 0x1001
#define ARCH_SET_FS 0x1002
#define ARCH_GET_FS 0x1003
#define ARCH_GET_GS 0x1004

#define CLONE_VM 0x00000100UL
#define CLONE_CHILD_SETTID 0x01000000UL
#define CLONE_PARENT_SETTID 0x00100000UL
#define CLONE_CHILD_CLEARTID 0x00200000UL
#define CLONE_SETTLS 0x00080000UL
#define SIGCHLD 17

#define PR_SET_NAME 15
#define PR_GET_NAME 16

#define FUTEX_WAIT 0

#define RLIMIT_STACK 3
#define RLIMIT_NOFILE 7

#define EFAULT 14
#define EINVAL 22

#define UTSNAME_LENGTH 65

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

static i64 sys_arch_prctl(u64 code, u64 addr) {
    return sys_call6(SYS_ARCH_PRCTL, code, addr, 0, 0, 0, 0);
}

static i64 sys_wait4(i64 pid, u32 *wstatus) {
    return sys_call6(SYS_WAIT4, (u64)pid, (u64)wstatus, 0, 0, 0, 0);
}

static i64 sys_uname(void *buf) {
    return sys_call6(SYS_UNAME, (u64)buf, 0, 0, 0, 0, 0);
}

static i64 sys_gettid(void) {
    return sys_call6(SYS_GETTID, 0, 0, 0, 0, 0, 0);
}

static i64 sys_set_tid_address(u32 *tidptr) {
    return sys_call6(SYS_SET_TID_ADDRESS, (u64)tidptr, 0, 0, 0, 0, 0);
}

static i64 sys_set_robust_list(void *head, u64 len) {
    return sys_call6(SYS_SET_ROBUST_LIST, (u64)head, len, 0, 0, 0, 0);
}

static i64 sys_get_robust_list(i64 pid, void **head, u64 *len) {
    return sys_call6(SYS_GET_ROBUST_LIST, (u64)pid, (u64)head, (u64)len, 0, 0, 0);
}

static i64 sys_prctl(u64 option, u64 arg2, u64 arg3, u64 arg4, u64 arg5) {
    return sys_call6(SYS_PRCTL, option, arg2, arg3, arg4, arg5, 0);
}

static i64 sys_futex(u32 *uaddr, u32 op, u32 val, const void *timeout) {
    return sys_call6(SYS_FUTEX, (u64)uaddr, op, val, (u64)timeout, 0, 0);
}

static i64 sys_prlimit64(i64 pid, u32 resource, const void *new_limit, void *old_limit) {
    return sys_call6(SYS_PRLIMIT64, (u64)pid, resource, (u64)new_limit, (u64)old_limit, 0, 0);
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

static volatile u64 child_fs_seen = 0;
static volatile u64 child_gs_seen = 0;
static volatile u32 child_tid_seen = 0;
static volatile u32 parent_tid_seen = 0;
static volatile u32 child_clear_tid = 0;
static volatile i64 wait_ret_seen = -1;
static unsigned char child_stack[8192];

static int streq(const char *a, const char *b) {
    while (*a && *b) {
        if (*a != *b) return 0;
        a++;
        b++;
    }
    return *a == *b;
}

static int streq_field(const char *field, const char *expect) {
    int i = 0;
    while (field[i] && expect[i]) {
        if (field[i] != expect[i]) return 0;
        i++;
    }
    return field[i] == 0 && expect[i] == 0;
}

struct rlimit64 {
    u64 cur;
    u64 max;
};

void _start(void) {
    const u64 parent_fs = 0x12345000UL;
    const u64 parent_gs = 0x56789000UL;
    const u64 child_tls = 0x2468ac00UL;
    const u64 invalid_tls = 0x0000800000000000UL;
    u64 got_fs = 0;
    u64 got_gs = 0;
    u64 robust_len = 0;
    void *robust_head_seen = (void *)0;
    u64 robust_head[3] = {0, 0, 0};
    char set_name[16] = "tls-probe";
    char get_name[16] = {0};
    char utsname[UTSNAME_LENGTH * 6] = {0};
    struct rlimit64 old_nofile = {0, 0};
    struct rlimit64 old_stack = {0, 0};
    struct rlimit64 new_limit = {123, 456};
    u32 futex_word = 1;
    u32 wstatus = 0;
    i64 self_tid = sys_gettid();

    print("=== TOS TLS/clone smoke test ===\n");

    check("arch_prctl(SET_FS)", sys_arch_prctl(ARCH_SET_FS, parent_fs) == 0);
    check("arch_prctl(SET_GS)", sys_arch_prctl(ARCH_SET_GS, parent_gs) == 0);
    check("arch_prctl(GET_FS)", sys_arch_prctl(ARCH_GET_FS, (u64)&got_fs) == 0);
    check("arch_prctl(GET_FS) matches", got_fs == parent_fs);
    check("arch_prctl(GET_GS)", sys_arch_prctl(ARCH_GET_GS, (u64)&got_gs) == 0);
    check("arch_prctl(GET_GS) matches", got_gs == parent_gs);
    check("arch_prctl(GET_FS, NULL) -> EFAULT", sys_arch_prctl(ARCH_GET_FS, 0) == -EFAULT);
    check("arch_prctl(GET_GS, NULL) -> EFAULT", sys_arch_prctl(ARCH_GET_GS, 0) == -EFAULT);
    check("arch_prctl(SET_FS, invalid) -> EINVAL", sys_arch_prctl(ARCH_SET_FS, invalid_tls) == -EINVAL);
    check("arch_prctl(SET_GS, invalid) -> EINVAL", sys_arch_prctl(ARCH_SET_GS, invalid_tls) == -EINVAL);
    check("set_tid_address returns tid", sys_set_tid_address((u32 *)&child_clear_tid) == self_tid);
    check("set_robust_list", sys_set_robust_list(robust_head, 24) == 0);
    check("get_robust_list", sys_get_robust_list(0, &robust_head_seen, &robust_len) == 0);
    check("get_robust_list head matches", robust_head_seen == (void *)robust_head);
    check("get_robust_list len == 24", robust_len == 24);
    check("get_robust_list(NULL head) -> EFAULT", sys_get_robust_list(0, (void **)0, &robust_len) == -EFAULT);
    check("get_robust_list(NULL len) -> EFAULT", sys_get_robust_list(0, &robust_head_seen, (u64 *)0) == -EFAULT);
    check("prctl(PR_SET_NAME)", sys_prctl(PR_SET_NAME, (u64)set_name, 0, 0, 0) == 0);
    check("prctl(PR_GET_NAME)", sys_prctl(PR_GET_NAME, (u64)get_name, 0, 0, 0) == 0);
    check("prctl(PR_GET_NAME) matches", streq(get_name, "tls-probe"));
    check("uname(NULL) -> EFAULT", sys_uname((void *)0) == -EFAULT);
    check("uname()", sys_uname(utsname) == 0);
    check("uname.sysname == Linux", streq_field(&utsname[0], "Linux"));
    check("uname.machine == x86_64", streq_field(&utsname[UTSNAME_LENGTH * 4], "x86_64"));
    check("prlimit64(RLIMIT_NOFILE)", sys_prlimit64(0, RLIMIT_NOFILE, (void *)0, &old_nofile) == 0);
    check("prlimit64 nofile cur==max", old_nofile.cur == old_nofile.max && old_nofile.cur >= 256);
    check("prlimit64(RLIMIT_STACK)", sys_prlimit64(0, RLIMIT_STACK, (void *)0, &old_stack) == 0);
    check("prlimit64 stack cur==max", old_stack.cur == old_stack.max && old_stack.cur >= 65536);
    check("prlimit64(NULL old ptr with new ptr)", sys_prlimit64(0, RLIMIT_NOFILE, &new_limit, (void *)0) == 0);
    check("prlimit64(invalid new ptr) -> EFAULT", sys_prlimit64(0, RLIMIT_NOFILE, (void *)1, (void *)0) == -EFAULT);
    check("prlimit64(invalid old ptr) -> EFAULT", sys_prlimit64(0, RLIMIT_NOFILE, (void *)0, (void *)1) == -EFAULT);
    check("futex WAIT invalid timeout -> EFAULT", sys_futex(&futex_word, FUTEX_WAIT, 1, (void *)1) == -EFAULT);

    u64 child_stack_top = ((u64)(child_stack + sizeof(child_stack)) & ~0xFUL);
    i64 clone_ret;
    {
        u64 flags =
            CLONE_VM | CLONE_SETTLS | CLONE_PARENT_SETTID | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID | SIGCHLD;
        register u64 r10 __asm__("r10") = (u64)&child_clear_tid;
        register u64 r8 __asm__("r8") = child_tls;
        register u64 r9 __asm__("r9") = 0;
        __asm__ volatile(
            "syscall"
            : "=a"(clone_ret)
            : "a"(SYS_CLONE),
              "D"(flags),
              "S"(child_stack_top),
              "d"((u64)&parent_tid_seen),
              "r"(r10),
              "r"(r8),
              "r"(r9)
            : "rcx", "r11", "memory");
    }

    if (clone_ret == 0) {
        u64 local_fs = 0;
        u64 local_gs = 0;
        child_tid_seen = child_clear_tid;
        (void)sys_arch_prctl(ARCH_GET_FS, (u64)&local_fs);
        (void)sys_arch_prctl(ARCH_GET_GS, (u64)&local_gs);
        child_fs_seen = local_fs;
        child_gs_seen = local_gs;
        sys_exit(0);
    }

    check("clone(CLONE_SETTLS)", clone_ret > 0);
    check("parent_tid written", clone_ret > 0 && parent_tid_seen == (u32)clone_ret);
    wait_ret_seen = sys_wait4(clone_ret, &wstatus);
    check("wait4(child)", wait_ret_seen == (i64)parent_tid_seen);
    check("child exit status == 0", (wstatus & 0xff) == 0 && ((wstatus >> 8) & 0xff) == 0);
    check("child CLONE_CHILD_SETTID written", child_tid_seen == parent_tid_seen);
    check("child FS seen == tls", child_fs_seen == child_tls);
    check("child GS inherited", child_gs_seen == parent_gs);
    check("child clear_tid cleared on exit", child_clear_tid == 0);

    print("\n=== Results: ");
    if (pass_count >= 10) {
        char tens = '0' + (pass_count / 10);
        sys_write(1, &tens, 1);
    }
    {
        char ones = '0' + (pass_count % 10);
        sys_write(1, &ones, 1);
    }
    print(" passed, ");
    {
        char digit = '0' + fail_count;
        sys_write(1, &digit, 1);
    }
    print(" failed ===\n");

    sys_exit(fail_count);
}
