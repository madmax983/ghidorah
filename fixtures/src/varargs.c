/* varargs: the calling-convention fixture. Functions take 0 to 8 parameters or varargs. */
#include <stdarg.h>
#include <stdio.h>

#include "fixture.h"

NOIPA int64_t p0(void) {
    return 42;
}

NOIPA int64_t p1(int64_t a) {
    return a * 3;
}

NOIPA int64_t p2(int64_t a, int64_t b) {
    return a - b * 2;
}

NOIPA int64_t p3(int64_t a, int64_t b, int64_t c) {
    return a * b + c;
}

NOIPA int64_t p4(int64_t a, int64_t b, int64_t c, int64_t d) {
    return (a ^ b) + (c | d);
}

NOIPA int64_t p5(int64_t a, int64_t b, int64_t c, int64_t d, int64_t e) {
    return a + b * 2 + c * 3 + d * 4 + e * 5;
}

NOIPA int64_t p6(int64_t a, int64_t b, int64_t c, int64_t d, int64_t e, int64_t f) {
    return a - b + c - d + e - f;
}

/* The seventh parameter is on the stack. */
NOIPA int64_t p7(int64_t a, int64_t b, int64_t c, int64_t d, int64_t e, int64_t f, int64_t g) {
    return a + b + c + d + e + f + g * 7;
}

NOIPA int64_t p8(int64_t a, int64_t b, int64_t c, int64_t d, int64_t e, int64_t f, int64_t g,
                 int64_t h) {
    return (a + b + c + d) * (e + f + g + h);
}

NOIPA int32_t narrow(int8_t a, int16_t b, uint32_t c) {
    return a + b + (int32_t)c;
}

NOIPA double scale(double x, int32_t k) {
    return x * (double)k;
}

/* Varargs: the sum of n int arguments. */
NOIPA int64_t sum_va(int32_t n, ...) {
    va_list ap;
    int64_t total = 0;
    va_start(ap, n);
    for (int32_t i = 0; i < n; i++) {
        total += va_arg(ap, int);
    }
    va_end(ap);
    return total;
}

/* Varargs: a printf-like logger. */
NOIPA int log_msg(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int n = vprintf(fmt, ap);
    va_end(ap);
    return n;
}

int main(int argc, char **argv) {
    (void)argv;
    int64_t a = argc;
    int64_t r = p0() + p1(a) + p2(a, 2) + p3(a, 2, 3) + p4(a, 2, 3, 4) + p5(a, 2, 3, 4, 5) +
                p6(a, 2, 3, 4, 5, 6) + p7(a, 2, 3, 4, 5, 6, 7) + p8(a, 2, 3, 4, 5, 6, 7, 8) +
                narrow((int8_t)a, 300, 7u) + sum_va(3, 1, 2, (int)a);
    log_msg("%lld %f\n", (long long)r, scale(1.5, (int32_t)a));
    return 0;
}
