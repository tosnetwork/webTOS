// Deterministic Claude-TUI fixture for the browser/PTY acceptance driver.
// It is intentionally a static ELF program: webTOS does not yet implement
// Linux shebang/binfmt-script loading, while the real Claude entrypoint is an
// ELF binary.  The fixture covers the controller's protocol, not model logic.
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/syscall.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

// Bun/Claude keeps non-UI workers runnable while the foreground renderer is
// blocked in a terminal read.  This fixture deliberately recreates that
// scheduling shape without pretending to emulate Bun or model inference.
// The browser host must discover the pending PTY reader independently of a
// whole-machine "all tasks idle" status.
static _Atomic int worker_stop;

static void *runnable_worker(void *unused) {
    (void)unused;
    int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    struct epoll_event event;
    // A zero timeout deliberately models a runtime's immediate event-loop
    // turn.  It exercises the same epoll_pwait2 ABI the real Bun trace uses,
    // while sched_yield keeps the fixture usable if a host lacks that optional
    // syscall.
    const struct timespec poll_now = {0, 0};
    while (!atomic_load_explicit(&worker_stop, memory_order_relaxed)) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
#ifdef SYS_epoll_pwait2
        if (epoll_fd >= 0) {
            syscall(SYS_epoll_pwait2, epoll_fd, &event, 1, &poll_now, NULL, 0);
        }
#endif
        // A real runtime cooperatively yields between event-loop turns.
        sched_yield();
    }
    if (epoll_fd >= 0) close(epoll_fd);
    return NULL;
}

static int read_line(char *line, size_t capacity) {
    size_t used = 0;
    while (used + 1 < capacity) {
        char c;
        if (read(STDIN_FILENO, &c, 1) != 1) return -1;
        if (c == '\r' || c == '\n') {
            line[used] = '\0';
            return 0;
        }
        line[used++] = c;
    }
    return -1;
}

int main(void) {
    char line[2048];
    pthread_t worker;
    int worker_started = 0;
    struct termios term;
    if (tcgetattr(STDIN_FILENO, &term) != 0) return 9;
    cfmakeraw(&term);
    if (tcsetattr(STDIN_FILENO, TCSANOW, &term) != 0) return 9;
    fputs("\033[?25lQuick\033[8Gsafety\033[16Gcheck:\n"
          "  No, exit\n  Yes, I trust this folder\n", stdout);
    fflush(stdout);
    if (read_line(line, sizeof(line)) != 0) return 10;

    fputs("\033[?25hWelcome\033[8Gto\033[16GClaude\033[24GCode\n"
          "What\033[8Gcan\033[16GI\033[20Ghelp\033[28Gyou\033[32Gwith?\n> ", stdout);
    fflush(stdout);
    if (pthread_create(&worker, NULL, runnable_worker, NULL) != 0) return 15;
    worker_started = 1;
    if (read_line(line, sizeof(line)) != 0 || !strstr(line, "M9_PENDING")) return 11;

    int fd = open("/work/input.txt", O_WRONLY | O_TRUNC);
    if (fd < 0) return 12;
    static const char completion[] = "M9_CLAUDE_COMPLETED\n";
    if (write(fd, completion, sizeof(completion) - 1) != (ssize_t)(sizeof(completion) - 1)) return 13;
    close(fd);
    fputs("WEBTOS_TASK_DONE\n", stdout);
    fflush(stdout);

    while (read_line(line, sizeof(line)) == 0) {
        if (strncmp(line, "/exit", 5) == 0) {
            atomic_store_explicit(&worker_stop, 1, memory_order_relaxed);
            pthread_join(worker, NULL);
            return 0;
        }
    }
    if (worker_started) {
        atomic_store_explicit(&worker_stop, 1, memory_order_relaxed);
        pthread_join(worker, NULL);
    }
    return 14;
}
