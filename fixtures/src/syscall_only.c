/* syscall_only: no libc. Each function makes its system calls with constant arguments.
 * Build flags: -nostdlib -static -fno-stack-protector.
 */
#include "fixture.h"

#define SYSCALL0(nr)                                                                      \
    ({                                                                                    \
        long ret_;                                                                        \
        __asm__ volatile("syscall" : "=a"(ret_) : "a"((long)(nr)) : "rcx", "r11", "memory"); \
        ret_;                                                                             \
    })

#define SYSCALL1(nr, a)                                                                   \
    ({                                                                                    \
        long ret_;                                                                        \
        __asm__ volatile("syscall"                                                        \
                         : "=a"(ret_)                                                     \
                         : "a"((long)(nr)), "D"((long)(a))                                \
                         : "rcx", "r11", "memory");                                       \
        ret_;                                                                             \
    })

#define SYSCALL3(nr, a, b, c)                                                             \
    ({                                                                                    \
        long ret_;                                                                        \
        __asm__ volatile("syscall"                                                        \
                         : "=a"(ret_)                                                     \
                         : "a"((long)(nr)), "D"((long)(a)), "S"((long)(b)), "d"((long)(c)) \
                         : "rcx", "r11", "memory");                                       \
        ret_;                                                                             \
    })

static const char banner[] = "syscall only\n";
static const char status[] = "status: ok\n";

/* write(1, banner, 13) */
NOIPA void emit_banner(void) {
    SYSCALL3(1, 1, banner, 13);
}

/* write(2, status, 11) */
NOIPA void emit_status(void) {
    SYSCALL3(1, 2, status, 11);
}

/* getpid() */
NOIPA long get_pid(void) {
    return SYSCALL0(39);
}

/* exit(0) */
NOIPA __attribute__((noreturn)) void exit_ok(void) {
    SYSCALL1(60, 0);
    __builtin_unreachable();
}

void _start(void) {
    emit_banner();
    if (get_pid() > 0) {
        emit_status();
    }
    exit_ok();
}
