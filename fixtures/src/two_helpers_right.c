/* two_helpers, second source file: the other static helper. */
#include "fixture.h"

static NOIPA int helper(int x) {
    return x * 7 - 2;
}

NOIPA int right_value(int x) {
    return helper(x) * 2;
}
