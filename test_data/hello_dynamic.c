/*
 * hello_dynamic.c — Minimal dynamically-linked test for ATOS
 *
 * Build with musl:
 *   musl-gcc -o hello_dynamic.elf hello_dynamic.c
 *
 * This creates a dynamically-linked ELF with PT_INTERP = /lib/ld-musl-x86_64.so.1.
 * The ATOS agent loader resolves the interpreter via VFS and loads it from
 * BASE_IMAGE_KEYSPACE.
 */
#include <unistd.h>

extern char **environ;

int main(int argc, char **argv) {
    const char msg[] = "[DYNAMIC] Hello from dynamically-linked musl binary!\n";
    write(1, msg, sizeof(msg) - 1);

    /* Print argc */
    char buf[64];
    int n = 0;
    buf[n++] = '['; buf[n++] = 'D'; buf[n++] = 'Y'; buf[n++] = 'N';
    buf[n++] = 'A'; buf[n++] = 'M'; buf[n++] = 'I'; buf[n++] = 'C';
    buf[n++] = ']'; buf[n++] = ' ';
    buf[n++] = 'a'; buf[n++] = 'r'; buf[n++] = 'g'; buf[n++] = 'c';
    buf[n++] = '=';
    buf[n++] = '0' + argc;
    buf[n++] = '\n';
    write(1, buf, n);

    /* Print argv[0] if available */
    if (argc > 0 && argv[0]) {
        write(1, "[DYNAMIC] argv[0]=", 18);
        int len = 0;
        while (argv[0][len]) len++;
        write(1, argv[0], len);
        write(1, "\n", 1);
    }

    if (argc > 1 && argv[1]) {
        write(1, "[DYNAMIC] argv[1]=", 18);
        int len = 0;
        while (argv[1][len]) len++;
        write(1, argv[1], len);
        write(1, "\n", 1);
    }

    if (environ && environ[0]) {
        write(1, "[DYNAMIC] envp[0]=", 18);
        int len = 0;
        while (environ[0][len]) len++;
        write(1, environ[0], len);
        write(1, "\n", 1);
    }

    return 0;
}
