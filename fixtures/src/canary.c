/* canary: stack buffers that the stack protector guards. */
#include <stdio.h>
#include <string.h>

#include "fixture.h"

NOIPA int copy_name(const char *src) {
    char buf[32];
    size_t n = strlen(src);
    if (n >= sizeof buf) {
        n = sizeof buf - 1;
    }
    memcpy(buf, src, n);
    buf[n] = '\0';
    return puts(buf);
}

NOIPA int checksum_line(const char *src) {
    char line[64];
    int sum = 0;
    snprintf(line, sizeof line, "line:%s", src);
    for (size_t i = 0; line[i] != '\0'; i++) {
        sum += (unsigned char)line[i];
    }
    return sum;
}

int main(int argc, char **argv) {
    const char *name = argc > 1 ? argv[1] : "canary";
    copy_name(name);
    printf("%d\n", checksum_line(name));
    return 0;
}
