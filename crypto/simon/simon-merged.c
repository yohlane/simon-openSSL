/*
simon-merged.c version 20080118
D. J. Bernstein
Public domain.
*/

#include <sys/types.h>

#include <stdint.h>

struct simon_ctx {
	u64 n;
    u64 m;
    u64 T;
    u64 j;
};


static inline void
simon_keysetup(simon_ctx *x, const u64 *k)
{
	printf("set key\n");
}

static inline void
simon_ivsetup()
{
}

static inline void
simon_encrypt_bytes()
{
	
}