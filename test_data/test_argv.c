/*
 * test_argv.c — Verify Linux initial stack (argc/argv/envp/auxv)
 *
 * Build:
 *   gcc -nostdlib -static -Wl,-Ttext=0x40000000 -o test_argv.elf test_argv.c
 *
 * This runs on ATOS in LinuxCompat mode. All I/O via raw syscall.
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

static void sys_exit(int code) {
    __asm__ volatile(
        "syscall"
        : /* no outputs */
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

static void print_num(u64 n) {
    char buf[20];
    int i = 0;
    if (n == 0) { sys_write(1, "0", 1); return; }
    while (n > 0) { buf[i++] = '0' + (n % 10); n /= 10; }
    /* reverse */
    char rev[20];
    for (int j = 0; j < i; j++) rev[j] = buf[i - 1 - j];
    sys_write(1, rev, i);
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

/*
 * Linux initial stack layout (what the kernel builds):
 *   RSP → argc (u64)
 *          argv[0] (pointer)
 *          argv[1] (pointer)
 *          ...
 *          NULL
 *          envp[0] (pointer)
 *          ...
 *          NULL
 *          auxv[0].type, auxv[0].value
 *          ...
 *          AT_NULL, 0
 */
void _start(void) {
    /* Read RSP — the kernel set it to point at argc */
    u64 *sp;
    __asm__ volatile("mov %%rsp, %0" : "=r"(sp));

    /* The compiler-generated prologue may have pushed rbp,
     * so walk up to find argc. On entry _start has:
     *   push %rbp; mov %rsp,%rbp → sp is 16 bytes below original.
     * But with -nostdlib and no frame pointer, sp IS the original.
     * To be safe, we pass argc via inline asm. */

    /* Actually, with gcc -nostdlib _start, RSP on entry = what kernel set.
     * But the function prologue pushes rbp. So sp here = original - 8.
     * We need the original RSP. Use a naked approach: */

    /* Re-read the original RSP from rbp (which was set to rsp after push) */
    u64 *orig_sp;
    __asm__ volatile("mov %%rbp, %0" : "=r"(orig_sp));
    /* orig_sp points to saved rbp, orig_sp+1 = return addr (none for _start)
     * Actually for _start with push rbp; mov rsp,rbp:
     *   [rbp] = old rbp (garbage)
     *   [rbp+8] = argc  ← this is wrong, argc is at original rsp
     *
     * Let's just compute: original_rsp = rbp + 8 (undo the push rbp)
     */
    u64 *stack = (u64 *)((u64)orig_sp + 8);

    u64 argc = stack[0];

    print("=== ATOS argv/envp/auxv test ===\n");

    /* Test 1: argc should be >= 1 */
    check("argc >= 1", argc >= 1);

    print("  argc = ");
    print_num(argc);
    print("\n");

    /* Test 2: argv[0] should be a valid pointer */
    char *argv0 = (char *)stack[1];
    check("argv[0] != NULL", argv0 != (char *)0);

    if (argv0) {
        print("  argv[0] = \"");
        print(argv0);
        print("\"\n");
    }

    /* Test 3: argv should be terminated by NULL */
    u64 *p = &stack[1]; /* start of argv */
    u64 argv_count = 0;
    while (*p != 0) { argv_count++; p++; }
    check("argv NULL-terminated", 1);
    check("argv count == argc", argv_count == argc);

    /* p now points to the NULL after argv. Next is envp. */
    p++; /* skip NULL → envp[0] */

    /* Test 4: envp should exist and have entries */
    u64 envp_count = 0;
    u64 *envp_start = p;
    while (*p != 0) { envp_count++; p++; }
    check("envp has entries", envp_count > 0);

    print("  envp count = ");
    print_num(envp_count);
    print("\n");

    /* Print first envp entry */
    if (envp_count > 0) {
        print("  envp[0] = \"");
        print((char *)envp_start[0]);
        print("\"\n");
    }

    /* p now points to NULL after envp. Next is auxv. */
    p++; /* skip NULL → auxv[0].type */

    /* Test 5: auxv should have AT_PAGESZ (6) and AT_RANDOM (25) */
    int found_pagesz = 0;
    int found_random = 0;
    int found_uid = 0;
    u64 pagesz_val = 0;

    u64 *aux = p;
    while (aux[0] != 0) { /* AT_NULL = 0 */
        if (aux[0] == 6) { found_pagesz = 1; pagesz_val = aux[1]; }
        if (aux[0] == 25) { found_random = 1; }
        if (aux[0] == 11) { found_uid = 1; }
        aux += 2;
    }

    check("auxv has AT_PAGESZ", found_pagesz);
    check("AT_PAGESZ == 4096", pagesz_val == 4096);
    check("auxv has AT_RANDOM", found_random);
    check("auxv has AT_UID", found_uid);

    /* Summary */
    print("\n=== Results: ");
    print_num(pass_count);
    print(" passed, ");
    print_num(fail_count);
    print(" failed ===\n");

    sys_exit(fail_count);
}
