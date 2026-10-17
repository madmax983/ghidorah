/* xor_decode: a rolling-key XOR decoder and integer mixing leaf functions. */
#include <stdio.h>
#include <string.h>

#include "fixture.h"

/* "attack at dawn" XOR key_at(i). */
static const unsigned char blob[] = {0x3b, 0x29, 0x14, 0x02, 0x05, 0x02, 0x4c, 0x0e,
                                     0x06, 0x55, 0x1c, 0x1a, 0x09, 0xef};

/* The key byte for position i: 0x5a + 3 * i, modulo 256. */
LEAF uint8_t key_at(uint32_t i) {
    return (uint8_t)(0x5a + 3 * i);
}

LEAF uint32_t rotl32(uint32_t x, uint32_t n) {
    n &= 31;
    return n == 0 ? x : (x << n) | (x >> (32 - n));
}

LEAF uint32_t mix32(uint32_t a, uint32_t b) {
    uint32_t h = a * 0x9e3779b1u;
    h ^= (b << 13) | (b >> 19);
    h += (h >> 7) ^ 0x7f4a7c15u;
    return h;
}

NOIPA void decode(char *dst, const unsigned char *src, size_t n) {
    for (size_t i = 0; i < n; i++) {
        dst[i] = (char)(src[i] ^ key_at((uint32_t)i));
    }
    dst[n] = '\0';
}

int main(int argc, char **argv) {
    char text[sizeof blob + 1];
    decode(text, blob, sizeof blob);
    if (argc > 1 && strcmp(argv[1], "-v") == 0) {
        puts(text);
    }
    printf("%08x\n", mix32((uint32_t)strlen(text), (uint32_t)argc));
    return 0;
}
