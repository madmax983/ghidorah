/* cold_split: rare error paths that gcc -O2 moves into .cold parts. */
#include <stdio.h>
#include <stdlib.h>

#include "fixture.h"

__attribute__((cold)) NOIPA void report_error(const char *what, int code) {
    fprintf(stderr, "error: %s (%d)\n", what, code);
}

NOIPA __attribute__((noreturn)) void die(const char *what) {
    fprintf(stderr, "die: %s\n", what);
    exit(3);
}

NOIPA int parse_digit(int c) {
    if (__builtin_expect(c < '0' || c > '9', 0)) {
        report_error("not a digit", c);
        fprintf(stderr, "input was %c\n", c);
        return -1;
    }
    return c - '0';
}

NOIPA int parse_number(const char *s) {
    int value = 0;
    if (__builtin_expect(s == NULL, 0)) {
        die("no input");
    }
    for (; *s != '\0'; s++) {
        int d = parse_digit(*s);
        if (__builtin_expect(d < 0, 0)) {
            report_error("bad number", value);
            fprintf(stderr, "stopped at %s\n", s);
            return -1;
        }
        value = value * 10 + d;
    }
    return value;
}

int main(int argc, char **argv) {
    printf("%d\n", parse_number(argc > 1 ? argv[1] : "123"));
    return 0;
}
