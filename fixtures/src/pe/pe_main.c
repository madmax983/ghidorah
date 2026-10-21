/* PE fixture pe_main.exe: imports by name, by ordinal, a delay import, a TLS callback,
 * a switch with a jump table, base relocations and .pdata (design Section 4.15). */
#include "pe_rt.h"

DLLIMPORT u32 GetTickCount(void);
DLLIMPORT __declspec(noreturn) void ExitProcess(u32 code);
void Sleep(u32 ms); /* no dllimport: the linker makes a jmp [rip+IAT] thunk */

DLLIMPORT int alpha_five(int x); /* alpha.dll exports it by ordinal 5 only */
int alpha_named(int x);          /* no dllimport: a thunk */

DLLIMPORT int beta_delayed(int x); /* /delayload:beta.dll */

int _fltused = 0;

/* The delay load helper of the C runtime. The fixtures never run. */
void *__delayLoadHelper2(const void *descriptor, void **slot) {
    (void)descriptor;
    return *slot;
}

volatile int sink;

NOINLINE int classify(int x) {
    switch (x) {
    case 0: return sink + 11;
    case 1: return sink * 7;
    case 2: return sink - 3;
    case 3: return sink ^ 0x55;
    case 4: return sink + 101;
    case 5: return sink * 13;
    case 6: return sink - 77;
    case 7: return sink | 0x100;
    default: return -1;
    }
}

NOINLINE int twice(int x) { return x * 2 + sink; }
NOINLINE int thrice(int x) { return x * 3 + sink; }

typedef int (*handler)(int);
handler handlers[2] = {twice, thrice};

NOINLINE int dispatch(int which, int x) {
    int r = handlers[which & 1](x);
    Sleep((u32)r);
    return r + (int)GetTickCount();
}

NOINLINE int imports(int x) {
    int a = alpha_five(x);
    int b = alpha_named(a);
    int c = beta_delayed(b);
    return a + b + c;
}

NOINLINE __declspec(noreturn) void finish(int code) {
    sink = code;
    ExitProcess((u32)code);
}

void pe_start(void) {
    int total = 0;
    for (int i = 0; i < 9; i++) {
        total += classify(i);
    }
    total += dispatch(total, 5);
    total += imports(total);
    finish(total);
}
