/* switch: dense switches with jump tables and a sparse switch without one. */
#include <stdio.h>
#include <stdlib.h>

#include "fixture.h"

/* A dense switch with distinct arithmetic per case gives a jump table. */
LEAF uint64_t apply_op(uint64_t op, uint64_t x) {
    switch (op) {
    case 0:
        return x + 7;
    case 1:
        return x * 3;
    case 2:
        return x ^ 0x55aa;
    case 3:
        return x << 3;
    case 4:
        return x >> 2;
    case 5:
        return x - 19;
    case 6:
        return ~x;
    case 8:
        return x * x;
    default:
        return 0;
    }
}

/* A sparse switch: the compiler uses compares, not a table. */
LEAF uint32_t sparse_code(uint32_t key) {
    switch (key) {
    case 3:
        return 30;
    case 100:
        return 1000;
    case 4096:
        return 7;
    case 65535:
        return 1;
    default:
        return 99;
    }
}

/* A dense switch whose cases call functions. */
NOIPA void run_command(int cmd) {
    switch (cmd) {
    case 0:
        puts("start");
        break;
    case 1:
        puts("stop");
        break;
    case 2:
        puts("pause");
        break;
    case 3:
        puts("resume");
        break;
    case 4:
        puts("status");
        break;
    case 5:
        puts("reset");
        break;
    default:
        puts("unknown command");
        break;
    }
}

int main(int argc, char **argv) {
    int cmd = argc > 1 ? atoi(argv[1]) : 0;
    run_command(cmd);
    printf("%llu %u\n", (unsigned long long)apply_op((uint64_t)cmd, 41),
           sparse_code((uint32_t)cmd));
    return 0;
}
