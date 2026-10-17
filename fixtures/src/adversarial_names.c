/* adversarial_names: symbol names that look like stubs, versions, default names,
 * sections and cold parts.
 */
#include <stdio.h>

#include "fixture.h"

/* A function named x@plt. The assembler reads @plt in a reference as a relocation
 * suffix, so callers use the second label adv_plt_entry.
 */
__asm__(".text\n"
        ".p2align 4\n"
        ".type \"x@plt\", @function\n"
        "\"x@plt\":\n"
        "adv_plt_entry:\n"
        ".cfi_startproc\n"
        "leal 1(%rdi,%rdi,2), %eax\n"
        "ret\n"
        ".cfi_endproc\n"
        ".size \"x@plt\", .-\"x@plt\"\n");

extern int adv_plt_entry(int v);

/* A local function whose name looks like a versioned import. */
static NOIPA int adv_versioned(int v) ASM_NAME("puts@GLIBC_2.2.5");
static NOIPA int adv_versioned(int v) {
    return v ^ 0x55;
}

/* A real function with a default-looking name. */
NOIPA int FUN_00401000(int v) {
    return v - 7;
}

/* A function named like a section of the binary. */
NOIPA int adv_section(int v) ASM_NAME(".fini");
NOIPA int adv_section(int v) {
    return v << 2;
}

/* A function named like a cold part. No function named foo exists. */
NOIPA int adv_cold(int v) ASM_NAME("foo.cold");
NOIPA int adv_cold(int v) {
    return v + 100;
}

int main(int argc, char **argv) {
    (void)argv;
    int v = adv_plt_entry(argc) + adv_versioned(argc) + FUN_00401000(argc) +
            adv_section(argc) + adv_cold(argc);
    printf("%d\n", v);
    return 0;
}
