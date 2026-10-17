/* noreturn_wrappers: wrappers around exit, _exit and abort, and an endless loop. */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "fixture.h"

NOIPA __attribute__((noreturn)) void die(const char *msg) {
    fprintf(stderr, "fatal: %s\n", msg);
    exit(2);
}

NOIPA __attribute__((noreturn)) void die_code(int code) {
    puts("aborting now");
    _exit(code);
}

/* No noreturn attribute: only its body shows that it never returns. */
NOIPA void fatal_abort(void) {
    puts("internal fault");
    abort();
}

/* An endless loop, so the function never returns. */
NOIPA void spin_forever(volatile int *flag) {
    for (;;) {
        *flag += 1;
    }
}

NOIPA int check_args(int argc) {
    if (argc > 4) {
        die("too many arguments");
    }
    if (argc == 4) {
        die_code(3);
    }
    if (argc == 3) {
        fatal_abort();
    }
    return argc * 2;
}

int main(int argc, char **argv) {
    static volatile int flag;
    if (argc > 1 && argv[1][0] == 's') {
        spin_forever(&flag);
    }
    printf("ok %d\n", check_args(argc));
    return 0;
}
