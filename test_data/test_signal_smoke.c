/*
 * test_signal_smoke.c — Minimal dynamic signal-handler smoke test for ATOS.
 *
 * Build with musl:
 *   musl-gcc -o test_signal_smoke.elf test_signal_smoke.c
 *
 * This verifies the Linux-compat signal path:
 *   sigaction(SIGUSR1, handler)
 *   kill(getpid(), SIGUSR1)
 *   handler returns through rt_sigreturn
 */
#include <signal.h>
#include <errno.h>
#include <stdint.h>
#include <unistd.h>

static volatile sig_atomic_t handled = 0;
static volatile sig_atomic_t handled_count = 0;
static volatile sig_atomic_t nested_seen = 0;
static volatile sig_atomic_t altstack_seen = 0;
static unsigned char alt_stack_mem[SIGSTKSZ];

static void on_sigusr1(int signum) {
    handled = signum;
    handled_count++;
    static const char msg[] = "ATOS-SIGNAL-HANDLER sig=10\n";
    write(1, msg, sizeof(msg) - 1);
}

static void on_sigusr1_nodefer(int signum) {
    handled = signum;
    handled_count++;
    if (handled_count == 1) {
        if (kill(getpid(), SIGUSR1) == 0) {
            nested_seen = 1;
        }
    }
}

static void on_sigusr1_resethand(int signum) {
    handled = signum;
    handled_count++;
}

static void on_sigusr2_altstack(int signum) {
    volatile unsigned char marker = 0;
    uintptr_t addr = (uintptr_t)&marker;
    uintptr_t base = (uintptr_t)alt_stack_mem;
    uintptr_t end = base + sizeof(alt_stack_mem);
    if (addr >= base && addr < end) {
        altstack_seen = signum;
    }
}

int main(void) {
    struct sigaction sa;
    struct sigaction nested_sa;
    struct sigaction alt_sa;
    sigset_t set;
    sigset_t old_set;
    sigset_t kill_only;
    sigset_t mask_check;
    sigset_t pending;
    struct sigaction old_sa;
    stack_t alt_stack;
    stack_t old_stack;
    for (unsigned long i = 0; i < sizeof(sa); i++) {
        ((unsigned char *)&sa)[i] = 0;
    }
    for (unsigned long i = 0; i < sizeof(nested_sa); i++) {
        ((unsigned char *)&nested_sa)[i] = 0;
    }
    for (unsigned long i = 0; i < sizeof(alt_sa); i++) {
        ((unsigned char *)&alt_sa)[i] = 0;
    }
    for (unsigned long i = 0; i < sizeof(old_sa); i++) {
        ((unsigned char *)&old_sa)[i] = 0;
    }
    for (unsigned long i = 0; i < sizeof(old_stack); i++) {
        ((unsigned char *)&old_stack)[i] = 0;
    }
    sa.sa_handler = on_sigusr1;
    nested_sa.sa_handler = on_sigusr1_nodefer;
    nested_sa.sa_flags = SA_NODEFER;
    alt_sa.sa_handler = on_sigusr2_altstack;
    alt_sa.sa_flags = SA_ONSTACK;

    errno = 0;
    if (sigpending((sigset_t *)0) != -1 || errno != EFAULT) {
        static const char msg[] = "ATOS-SIGNAL-FAIL sigpending-null\n";
        write(1, msg, sizeof(msg) - 1);
        return 10;
    }

    if (sigaltstack((stack_t *)0, &old_stack) != 0 ||
        old_stack.ss_flags != SS_DISABLE || old_stack.ss_sp != 0 || old_stack.ss_size != 0) {
        static const char msg[] = "ATOS-SIGNAL-FAIL sigaltstack-default\n";
        write(1, msg, sizeof(msg) - 1);
        return 27;
    }

    alt_stack.ss_sp = alt_stack_mem;
    alt_stack.ss_size = sizeof(alt_stack_mem);
    alt_stack.ss_flags = 0;
    if (sigaltstack(&alt_stack, (stack_t *)0) != 0) {
        static const char msg[] = "ATOS-SIGNAL-FAIL sigaltstack-set\n";
        write(1, msg, sizeof(msg) - 1);
        return 28;
    }

    if (sigaltstack((stack_t *)0, &old_stack) != 0 ||
        old_stack.ss_sp != alt_stack_mem ||
        old_stack.ss_size != sizeof(alt_stack_mem) ||
        old_stack.ss_flags != 0) {
        static const char msg[] = "ATOS-SIGNAL-FAIL sigaltstack-query\n";
        write(1, msg, sizeof(msg) - 1);
        return 29;
    }

    alt_stack.ss_sp = alt_stack_mem;
    alt_stack.ss_size = MINSIGSTKSZ - 1;
    alt_stack.ss_flags = 0;
    errno = 0;
    if (sigaltstack(&alt_stack, (stack_t *)0) != -1 || errno != ENOMEM) {
        static const char msg[] = "ATOS-SIGNAL-FAIL sigaltstack-small\n";
        write(1, msg, sizeof(msg) - 1);
        return 30;
    }

    if (sigaction(SIGUSR1, &sa, 0) != 0) {
        static const char msg[] = "ATOS-SIGNAL-FAIL sigaction\n";
        write(1, msg, sizeof(msg) - 1);
        return 1;
    }

    errno = 0;
    if (sigaction(SIGUSR1, 0, &old_sa) != 0 || old_sa.sa_handler != on_sigusr1) {
        static const char msg[] = "ATOS-SIGNAL-FAIL sigaction-oldact\n";
        write(1, msg, sizeof(msg) - 1);
        return 11;
    }

    errno = 0;
    if (sigaction(SIGKILL, &sa, 0) != -1 || errno != EINVAL) {
        static const char msg[] = "ATOS-SIGNAL-FAIL sigaction-sigkill\n";
        write(1, msg, sizeof(msg) - 1);
        return 12;
    }

    if (sigemptyset(&set) != 0 || sigaddset(&set, SIGUSR1) != 0) {
        static const char msg[] = "ATOS-SIGNAL-FAIL sigset\n";
        write(1, msg, sizeof(msg) - 1);
        return 2;
    }

    if (sigemptyset(&kill_only) != 0 || sigaddset(&kill_only, SIGKILL) != 0) {
        static const char msg[] = "ATOS-SIGNAL-FAIL sigkill-set\n";
        write(1, msg, sizeof(msg) - 1);
        return 14;
    }

    errno = 0;
    if (sigprocmask(123, &set, 0) != -1 || errno != EINVAL) {
        static const char msg[] = "ATOS-SIGNAL-FAIL bad-how\n";
        write(1, msg, sizeof(msg) - 1);
        return 13;
    }

    if (sigprocmask(SIG_BLOCK, &set, &old_set) != 0) {
        static const char msg[] = "ATOS-SIGNAL-FAIL block\n";
        write(1, msg, sizeof(msg) - 1);
        return 3;
    }

    if (sigismember(&old_set, SIGUSR1) != 0) {
        static const char msg[] = "ATOS-SIGNAL-FAIL old-mask\n";
        write(1, msg, sizeof(msg) - 1);
        return 15;
    }

    if (kill(getpid(), SIGUSR1) != 0) {
        static const char msg[] = "ATOS-SIGNAL-FAIL kill\n";
        write(1, msg, sizeof(msg) - 1);
        return 4;
    }

    if (handled != 0) {
        static const char msg[] = "ATOS-SIGNAL-FAIL blocked-delivery\n";
        write(1, msg, sizeof(msg) - 1);
        return 5;
    }

    if (sigpending(&pending) != 0) {
        static const char msg[] = "ATOS-SIGNAL-FAIL sigpending\n";
        write(1, msg, sizeof(msg) - 1);
        return 6;
    }

    if (sigismember(&pending, SIGUSR1) != 1) {
        static const char msg[] = "ATOS-SIGNAL-FAIL not-pending\n";
        write(1, msg, sizeof(msg) - 1);
        return 7;
    }

    static const char pending_ok[] = "ATOS-SIGNAL-PENDING sig=10\n";
    write(1, pending_ok, sizeof(pending_ok) - 1);

    if (sigprocmask(SIG_UNBLOCK, &set, 0) != 0) {
        static const char msg[] = "ATOS-SIGNAL-FAIL unblock\n";
        write(1, msg, sizeof(msg) - 1);
        return 8;
    }

    if (handled != SIGUSR1) {
        static const char msg[] = "ATOS-SIGNAL-FAIL handler-missed\n";
        write(1, msg, sizeof(msg) - 1);
        return 9;
    }

    if (sigprocmask(SIG_SETMASK, &kill_only, 0) != 0) {
        static const char msg[] = "ATOS-SIGNAL-FAIL setmask-kill\n";
        write(1, msg, sizeof(msg) - 1);
        return 16;
    }

    if (sigprocmask(SIG_SETMASK, (sigset_t *)0, &mask_check) != 0) {
        static const char msg[] = "ATOS-SIGNAL-FAIL getmask\n";
        write(1, msg, sizeof(msg) - 1);
        return 17;
    }

    if (sigismember(&mask_check, SIGKILL) != 0) {
        static const char msg[] = "ATOS-SIGNAL-FAIL sigkill-blocked\n";
        write(1, msg, sizeof(msg) - 1);
        return 18;
    }

    if (sigemptyset(&set) != 0 || sigprocmask(SIG_SETMASK, &set, 0) != 0) {
        static const char msg[] = "ATOS-SIGNAL-FAIL clear-mask\n";
        write(1, msg, sizeof(msg) - 1);
        return 19;
    }

    handled = 0;
    handled_count = 0;
    nested_seen = 0;
    if (sigaction(SIGUSR1, &nested_sa, 0) != 0) {
        static const char msg[] = "ATOS-SIGNAL-FAIL sigaction-nodefer\n";
        write(1, msg, sizeof(msg) - 1);
        return 20;
    }

    if (kill(getpid(), SIGUSR1) != 0) {
        static const char msg[] = "ATOS-SIGNAL-FAIL kill-nodefer\n";
        write(1, msg, sizeof(msg) - 1);
        return 21;
    }

    if (handled != SIGUSR1 || handled_count != 2 || nested_seen != 1) {
        static const char msg[] = "ATOS-SIGNAL-FAIL nodefer-delivery\n";
        write(1, msg, sizeof(msg) - 1);
        return 22;
    }

    nested_sa.sa_handler = on_sigusr1_resethand;
    nested_sa.sa_flags = SA_RESETHAND;
    handled = 0;
    handled_count = 0;
    nested_seen = 0;
    if (sigaction(SIGUSR1, &nested_sa, 0) != 0) {
        static const char msg[] = "ATOS-SIGNAL-FAIL sigaction-resethand\n";
        write(1, msg, sizeof(msg) - 1);
        return 23;
    }

    if (kill(getpid(), SIGUSR1) != 0) {
        static const char msg[] = "ATOS-SIGNAL-FAIL kill-resethand\n";
        write(1, msg, sizeof(msg) - 1);
        return 24;
    }

    if (handled != SIGUSR1 || handled_count != 1) {
        static const char msg[] = "ATOS-SIGNAL-FAIL resethand-delivery\n";
        write(1, msg, sizeof(msg) - 1);
        return 25;
    }

    if (sigaction(SIGUSR1, 0, &old_sa) != 0 || old_sa.sa_handler != SIG_DFL) {
        static const char msg[] = "ATOS-SIGNAL-FAIL resethand-state\n";
        write(1, msg, sizeof(msg) - 1);
        return 26;
    }

    if (sigaction(SIGUSR2, &alt_sa, 0) != 0) {
        static const char msg[] = "ATOS-SIGNAL-FAIL sigaction-onstack\n";
        write(1, msg, sizeof(msg) - 1);
        return 31;
    }

    altstack_seen = 0;
    if (kill(getpid(), SIGUSR2) != 0 || altstack_seen != SIGUSR2) {
        static const char msg[] = "ATOS-SIGNAL-FAIL onstack-delivery\n";
        write(1, msg, sizeof(msg) - 1);
        return 32;
    }

    alt_stack.ss_sp = (void *)0;
    alt_stack.ss_size = 0;
    alt_stack.ss_flags = SS_DISABLE;
    if (sigaltstack(&alt_stack, (stack_t *)0) != 0) {
        static const char msg[] = "ATOS-SIGNAL-FAIL sigaltstack-disable\n";
        write(1, msg, sizeof(msg) - 1);
        return 33;
    }

    if (sigaltstack((stack_t *)0, &old_stack) != 0 ||
        old_stack.ss_flags != SS_DISABLE || old_stack.ss_sp != 0 || old_stack.ss_size != 0) {
        static const char msg[] = "ATOS-SIGNAL-FAIL sigaltstack-disabled-query\n";
        write(1, msg, sizeof(msg) - 1);
        return 34;
    }

    static const char ok[] = "ATOS-SIGNAL-OK\n";
    write(1, ok, sizeof(ok) - 1);
    return 0;
}
