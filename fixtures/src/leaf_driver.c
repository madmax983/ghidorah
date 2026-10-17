/* The leaf driver: it calls each leaf function of one fixture object on fixed inputs.
 *
 * The fixture build links this file with the object of a fixture build. It renames
 * main in that object to fixture_main first. LEAF_LIST names a generated header with
 * one line per leaf function:
 *
 *   LEAF1(name, R, A)  LEAF2(name, R, A, B)  LEAF3(name, R, A, B, C)
 *
 * The driver prints one JSON line per call: the function name, the argument bits and
 * the result bits, each masked to the width of its type. The inputs come from a
 * SplitMix64 stream seeded with the FNV-1a hash of the function name, so every build
 * gets the same inputs.
 */
#include <stdint.h>
#include <stdio.h>

#ifndef LEAF_CASES
#define LEAF_CASES 1000
#endif

#define LEAF1(n, R, A) R n(A);
#define LEAF2(n, R, A, B) R n(A, B);
#define LEAF3(n, R, A, B, C) R n(A, B, C);
#include LEAF_LIST
#undef LEAF1
#undef LEAF2
#undef LEAF3

int fixture_main(int argc, char **argv);

static uint64_t state;

static void seed(const char *name) {
    uint64_t h = 0xcbf29ce484222325ull;
    for (const char *p = name; *p != '\0'; p++) {
        h ^= (unsigned char)*p;
        h *= 0x100000001b3ull;
    }
    state = h;
}

static uint64_t next(void) {
    uint64_t z = (state += 0x9e3779b97f4a7c15ull);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ull;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebull;
    return z ^ (z >> 31);
}

static const uint64_t edges[] = {
    0x0, 0x1, 0x2, 0x3, 0x7, 0x8, 0x10, 0x1f, 0x20, 0x3f, 0x40, 0x7f, 0x80, 0xff, 0x100,
    0x7fff, 0x8000, 0xffff, 0x10000, 0x7fffffff, 0x80000000, 0xffffffff, 0x100000000,
    0x7fffffffffffffff, 0x8000000000000000, 0xfffffffffffffffe, 0xffffffffffffffff,
};

#define EDGE_COUNT (sizeof edges / sizeof edges[0])

/* Case i, argument k: small values, edge values and full random values in turn. */
static uint64_t pick(unsigned i, unsigned k) {
    uint64_t r = next();
    switch ((i + k) % 4) {
    case 0:
        return r % 16;
    case 1:
        return edges[r % EDGE_COUNT];
    case 2:
        return r % 1024;
    default:
        return r;
    }
}

#define MASK(T, v) ((unsigned long long)(v) & (~0ull >> (64 - 8 * sizeof(T))))

#define LEAF1(n, R, A)                                                                  \
    static void run_##n(void) {                                                         \
        seed(#n);                                                                       \
        for (unsigned i = 0; i < LEAF_CASES; i++) {                                     \
            A a = (A)pick(i, 0);                                                        \
            R r = n(a);                                                                 \
            printf("{\"fn\":\"%s\",\"args\":[\"0x%llx\"],\"ret\":\"0x%llx\"}\n", #n,     \
                   MASK(A, a), MASK(R, r));                                             \
        }                                                                               \
    }
#define LEAF2(n, R, A, B)                                                               \
    static void run_##n(void) {                                                         \
        seed(#n);                                                                       \
        for (unsigned i = 0; i < LEAF_CASES; i++) {                                     \
            A a = (A)pick(i, 0);                                                        \
            B b = (B)pick(i, 1);                                                        \
            R r = n(a, b);                                                              \
            printf("{\"fn\":\"%s\",\"args\":[\"0x%llx\",\"0x%llx\"],\"ret\":\"0x%llx\"}\n", \
                   #n, MASK(A, a), MASK(B, b), MASK(R, r));                             \
        }                                                                               \
    }
#define LEAF3(n, R, A, B, C)                                                            \
    static void run_##n(void) {                                                         \
        seed(#n);                                                                       \
        for (unsigned i = 0; i < LEAF_CASES; i++) {                                     \
            A a = (A)pick(i, 0);                                                        \
            B b = (B)pick(i, 1);                                                        \
            C c = (C)pick(i, 2);                                                        \
            R r = n(a, b, c);                                                           \
            printf("{\"fn\":\"%s\",\"args\":[\"0x%llx\",\"0x%llx\",\"0x%llx\"],"         \
                   "\"ret\":\"0x%llx\"}\n",                                             \
                   #n, MASK(A, a), MASK(B, b), MASK(C, c), MASK(R, r));                 \
        }                                                                               \
    }
#include LEAF_LIST
#undef LEAF1
#undef LEAF2
#undef LEAF3

int main(void) {
#define LEAF1(n, R, A) run_##n();
#define LEAF2(n, R, A, B) run_##n();
#define LEAF3(n, R, A, B, C) run_##n();
#include LEAF_LIST
    return 0;
}
