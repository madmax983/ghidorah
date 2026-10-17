/* func_ptrs: a handler table, a callback slot and a qsort comparator. */
#include <stdio.h>
#include <stdlib.h>

#include "fixture.h"

typedef int64_t (*op_fn)(int64_t, int64_t);

NOIPA int64_t op_add(int64_t a, int64_t b) {
    return a + b;
}

NOIPA int64_t op_sub(int64_t a, int64_t b) {
    return a - b;
}

NOIPA int64_t op_mul(int64_t a, int64_t b) {
    return a * b;
}

NOIPA int64_t op_div(int64_t a, int64_t b) {
    return b == 0 ? 0 : a / b;
}

/* op_mod is not in the table. Only main calls it, and only directly. */
NOIPA int64_t op_mod(int64_t a, int64_t b) {
    return b == 0 ? 0 : a % b;
}

static op_fn const ops[4] = {op_add, op_sub, op_mul, op_div};

/* An indirect call through the table, indexed by input. */
NOIPA int64_t run_op(uint32_t idx, int64_t a, int64_t b) {
    return ops[idx & 3](a, b);
}

typedef void (*callback_fn)(int);

static callback_fn on_event;

NOIPA void log_event(int code) {
    printf("event %d\n", code);
}

NOIPA void set_callback(callback_fn fn) {
    on_event = fn;
}

/* The callback slot changes at run time. */
NOIPA void fire(int code) {
    if (on_event != NULL) {
        on_event(code);
    }
}

NOIPA int cmp_long(const void *a, const void *b) {
    long x = *(const long *)a;
    long y = *(const long *)b;
    return (x > y) - (x < y);
}

int main(int argc, char **argv) {
    long values[4] = {9, 2, 7, 4};
    qsort(values, 4, sizeof values[0], cmp_long);
    /* A volatile copy keeps clang from making a specialized clone of set_callback. */
    callback_fn volatile cb = log_event;
    set_callback(cb);
    fire(argc);
    int64_t r = run_op((uint32_t)(argc > 1 ? atoi(argv[1]) : 0), 20, 6) + op_mod(20, 6);
    printf("%lld %ld\n", (long long)r, values[0]);
    return 0;
}
