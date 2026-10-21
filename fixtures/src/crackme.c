/* crackme: a password check against XOR-encoded bytes, plus an unowned code blob. */
#include <stdio.h>
#include <string.h>

#include "fixture.h"

/* "s3cr3t-k3y", each byte XOR 0x5a. */
static const unsigned char encoded[] = {0x29, 0x69, 0x39, 0x28, 0x69, 0x2e, 0x77, 0x31, 0x69, 0x23};

#define KEY 0x5a

/* Code that no function owns: no symbol type, no unwind entry and no caller. */
__asm__(".text\n"
        ".p2align 4\n"
        "hidden_gate:\n"
        "movl $0x1337, %eax\n"
        "xorl %edi, %eax\n"
        "ret\n"
        ".size hidden_gate, .-hidden_gate\n");

NOIPA int check_password(const char *input) {
    if (strlen(input) != sizeof encoded) {
        return 0;
    }
    for (size_t i = 0; i < sizeof encoded; i++) {
        if (((unsigned char)input[i] ^ KEY) != encoded[i]) {
            return 0;
        }
    }
    return 1;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        puts("usage: crackme <password>");
        return 2;
    }
    if (check_password(argv[1])) {
        puts("Access granted");
        return 0;
    }
    puts("Access denied");
    return 1;
}
