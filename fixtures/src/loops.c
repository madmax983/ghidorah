/* loops: counted loops, while loops and nested loops in leaf functions. */
#include <stdio.h>
#include <stdlib.h>

#include "fixture.h"

/* The sum of i * i for i below n % 64. */
LEAF uint64_t sum_squares(uint64_t n) {
    uint64_t total = 0;
    for (uint64_t i = 0; i < (n & 63); i++) {
        total += i * i;
    }
    return total;
}

/* Euclid's algorithm. */
LEAF uint64_t gcd(uint64_t a, uint64_t b) {
    while (b != 0) {
        uint64_t t = a % b;
        a = b;
        b = t;
    }
    return a;
}

/* The number of set bits, one bit per round. */
LEAF uint32_t count_bits(uint64_t x) {
    uint32_t count = 0;
    while (x != 0) {
        x &= x - 1;
        count++;
    }
    return count;
}

/* Reverses the 32 bits of x. */
LEAF uint32_t reverse_bits(uint32_t x) {
    uint32_t out = 0;
    for (int i = 0; i < 32; i++) {
        out = (out << 1) | (x & 1);
        x >>= 1;
    }
    return out;
}

/* A nested loop over a small grid. */
LEAF int32_t grid_walk(int32_t w, int32_t h) {
    int32_t acc = 0;
    for (int32_t y = 0; y < (h & 15); y++) {
        for (int32_t x = 0; x < (w & 15); x++) {
            acc += (x ^ y) - 3;
        }
    }
    return acc;
}

int main(int argc, char **argv) {
    uint64_t n = argc > 1 ? strtoull(argv[1], NULL, 0) : 10;
    printf("%llu %llu %u %u %d\n", (unsigned long long)sum_squares(n),
           (unsigned long long)gcd(n, 84), count_bits(n),
           reverse_bits((uint32_t)n), grid_walk((int32_t)n, 7));
    return 0;
}
