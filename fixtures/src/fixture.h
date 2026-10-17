/* Shared macros of the ghidorah T1 fixtures (Apache-2.0, first-party code).
 *
 * NOIPA keeps a function out of inlining and cloning, so the call edges of
 * the source stay in every build. LEAF marks a leaf function: integer
 * arguments, an integer result, no calls and no global memory. The fixture
 * build reads each LEAF line and runs the leaf driver on it.
 * ASM_NAME gives a symbol name that C cannot spell.
 */
#ifndef GHIDORAH_FIXTURE_H
#define GHIDORAH_FIXTURE_H

#include <stdint.h>

#if defined(__clang__)
#define NOIPA __attribute__((noinline))
#define ASM_NAME(s) __asm__(s)
#else
#define NOIPA __attribute__((noipa))
#define ASM_NAME(s) __asm__("\"" s "\"")
#endif

#define LEAF NOIPA

#endif
