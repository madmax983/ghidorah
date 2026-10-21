/* The TLS directory and one TLS callback of a PE fixture without the C runtime. */
#include "pe_rt.h"

#pragma section(".CRT$XLA", read)
#pragma section(".CRT$XLB", read)
#pragma section(".CRT$XLZ", read)
#pragma section(".tls", read, write)
#pragma section(".tls$ZZZ", read, write)

__declspec(allocate(".tls")) char _tls_start = 0;
__declspec(allocate(".tls$ZZZ")) char _tls_end = 0;
u32 _tls_index = 0;
volatile int tls_seen = 0;

NOINLINE void tls_callback_one(void *module, unsigned long reason, void *reserved) {
    (void)module;
    (void)reserved;
    tls_seen += (int)reason;
}

__declspec(allocate(".CRT$XLA")) tls_callback __xl_a = 0;
__declspec(allocate(".CRT$XLB")) tls_callback __xl_b = tls_callback_one;
__declspec(allocate(".CRT$XLZ")) tls_callback __xl_z = 0;

struct tls_directory {
    u64 start;
    u64 end;
    u64 index;
    u64 callbacks;
    u32 zero_fill;
    u32 characteristics;
};

const struct tls_directory _tls_used = {
    (u64)&_tls_start, (u64)&_tls_end, (u64)&_tls_index, (u64)(&__xl_a + 1), 0, 0,
};
