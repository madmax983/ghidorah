/* two_helpers: two static functions named helper, one in each source file. */
#include <stdio.h>

#include "fixture.h"

int right_value(int x);

static NOIPA int helper(int x) {
    return x * 5 + 1;
}

NOIPA int left_value(int x) {
    return helper(x) + 1;
}

int main(int argc, char **argv) {
    (void)argv;
    printf("%d %d\n", left_value(argc), right_value(argc));
    return 0;
}
