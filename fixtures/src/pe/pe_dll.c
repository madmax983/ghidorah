/* PE fixture pe_dll.dll: named exports, an export by ordinal only and two forwarders
 * (design Section 4.15). The forwarders come from pe_dll.def. */
#include "pe_rt.h"

int _fltused = 0;
volatile int dll_state;

NOINLINE int dll_add(int a, int b) { return a + b + dll_state; }
NOINLINE int dll_mul(int a, int b) { return a * b - dll_state; }
NOINLINE int dll_secret(int a) { return dll_add(a, 7) ^ dll_mul(a, 3); }

int dll_entry(void *module, u32 reason, void *reserved) {
    (void)module;
    (void)reserved;
    dll_state = (int)reason;
    return 1;
}
