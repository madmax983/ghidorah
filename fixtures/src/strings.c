/* strings: ASCII, UTF-8 and UTF-16LE strings, and one unreferenced string. */
#include <stdio.h>
#include <string.h>
#include <uchar.h>

#include "fixture.h"

/* A string that no code reads. The used attribute keeps it in the binary. */
__attribute__((used)) static const char unused_note[] = "unused configuration banner";

static const char16_t wide_greeting[] = u"Wide hello from UTF-16";

NOIPA size_t wide_length(const char16_t *s) {
    size_t n = 0;
    while (s[n] != 0) {
        n++;
    }
    return n;
}

NOIPA void show_banner(void) {
    puts("Welcome to the string fixture");
    puts("Caf\xc3\xa9 na\xc3\xafve r\xc3\xa9sum\xc3\xa9");
}

NOIPA int find_keyword(const char *text) {
    return strstr(text, "password") != NULL;
}

int main(int argc, char **argv) {
    show_banner();
    printf("%zu %d\n", wide_length(wide_greeting),
           find_keyword(argc > 1 ? argv[1] : "no secret here"));
    return 0;
}
