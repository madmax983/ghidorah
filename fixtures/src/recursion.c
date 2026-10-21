/* recursion: self calls, mutual recursion and a tree walk with a visitor. */
#include <stdio.h>
#include <stdlib.h>

#include "fixture.h"

NOIPA uint64_t fib(uint32_t n) {
    if (n < 2) {
        return n;
    }
    return fib(n - 1) + fib(n - 2);
}

NOIPA int is_odd(uint32_t n);

NOIPA int is_even(uint32_t n) {
    return n == 0 ? 1 : is_odd(n - 1);
}

NOIPA int is_odd(uint32_t n) {
    return n == 0 ? 0 : is_even(n - 1);
}

struct node {
    int value;
    struct node *left;
    struct node *right;
};

typedef void (*visit_fn)(const struct node *);

/* The visitor is a function pointer, so the call target is not fixed. */
NOIPA void walk(const struct node *n, visit_fn visit) {
    if (n == NULL) {
        return;
    }
    walk(n->left, visit);
    visit(n);
    walk(n->right, visit);
}

NOIPA void print_node(const struct node *n) {
    printf("%d\n", n->value);
}

int main(int argc, char **argv) {
    (void)argv;
    struct node leaf_a = {1, NULL, NULL};
    struct node leaf_b = {3, NULL, NULL};
    struct node root = {2, &leaf_a, &leaf_b};
    /* A volatile copy keeps clang from making a specialized clone of walk. */
    visit_fn volatile visit = print_node;
    walk(&root, visit);
    printf("%llu %d\n", (unsigned long long)fib((uint32_t)argc + 10),
           is_even((uint32_t)argc));
    return 0;
}
