/* The small runtime of the PE fixtures: no C runtime is linked (/nodefaultlib). */
#ifndef PE_RT_H
#define PE_RT_H

typedef unsigned long long u64;
typedef unsigned int u32;
typedef void (*tls_callback)(void *module, unsigned long reason, void *reserved);

#define NOINLINE __declspec(noinline)
#define DLLIMPORT __declspec(dllimport)

#endif
