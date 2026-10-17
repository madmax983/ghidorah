/* hello: a greeting and a tail call. */
#include <stdio.h>

#include "fixture.h"

NOIPA void greet(const char *who) {
    printf("Hello, %s!\n", who);
}

NOIPA int finish(int code) {
    puts("Goodbye.");
    return code;
}

/* The call to finish is in tail position. */
NOIPA int run(int argc) {
    greet(argc > 1 ? "friend" : "world");
    return finish(argc - 1);
}

int main(int argc, char **argv) {
    (void)argv;
    return run(argc);
}
