/* struct_access: field reads and writes through pointers to a linked record. */
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fixture.h"

struct record {
    int32_t id;
    char name[12];
    int64_t count;
    struct record *next;
};

_Static_assert(offsetof(struct record, id) == 0, "id offset");
_Static_assert(offsetof(struct record, name) == 4, "name offset");
_Static_assert(offsetof(struct record, count) == 16, "count offset");
_Static_assert(offsetof(struct record, next) == 24, "next offset");
_Static_assert(sizeof(struct record) == 32, "record size");

NOIPA struct record *new_record(int32_t id, const char *name, struct record *next) {
    struct record *r = malloc(sizeof *r);
    if (r == NULL) {
        return next;
    }
    r->id = id;
    strncpy(r->name, name, sizeof r->name - 1);
    r->name[sizeof r->name - 1] = '\0';
    r->count = 0;
    r->next = next;
    return r;
}

NOIPA void bump_count(struct record *r, int64_t by) {
    r->count += by;
}

NOIPA int64_t sum_counts(const struct record *r) {
    int64_t total = 0;
    while (r != NULL) {
        total += r->count;
        r = r->next;
    }
    return total;
}

NOIPA void free_list(struct record *r) {
    while (r != NULL) {
        struct record *next = r->next;
        free(r);
        r = next;
    }
}

int main(int argc, char **argv) {
    (void)argv;
    struct record *list = new_record(1, "alpha", NULL);
    list = new_record(2, "beta", list);
    bump_count(list, argc);
    bump_count(list->next, 5);
    printf("%lld\n", (long long)sum_counts(list));
    free_list(list);
    return 0;
}
