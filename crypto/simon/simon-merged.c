/*
simon-merged.c version 20080118
D. J. Bernstein
Public domain.
*/

#include <sys/types.h>

#include <stdint.h>

#define WORD_MASK (0xffffffffffffffffull)
#define CONST_C ((0xffffffffffffffffull ^ 0x3ull) & WORD_MASK)

struct simon_ctx {
	u64 n;
    u64 m;
    u64 *k;
    u64 T;
    u64 j;
};

char Simon_z[5][65] =
{"11111010001001010110000111001101111101000100101011000011100110",
"10001110111110010011000010110101000111011111001001100001011010",
"10101111011100000011010010011000101000010001111110010110110011",
"11011011101011000110010111100000010010001010011100110100001111",
"11010001111001101011011000100000010111000011001010010011101111"};

static inline void
simon_keysetup(simon_ctx *ctx)
{
	u64 i;
	
	u64 tmp;
	for (i = ctx->m; i < ctx->T; i++)
	{
		tmp = ROTL2(-3,ctx->k[i-1],ctx->n);
		if(ctx->m == 4)
			tmp ^= ctx->k[i-3];
		tmp ^= ROTL2(-1,tmp,ctx->n);

		u64 t1 = ~(0xffffffffffffffff << ctx->n);

		ctx->k[i] = (~(ctx->k[i-ctx->m]) & t1) ^ tmp ^ (Simon_z[ctx->j][(i-ctx->m) % 62]-'0') ^ 3;
	}
}

static inline void
simon_encrypt_bytes(simon_ctx *ctx, u64 *x, u64 *y)
{
	u64 i;

	for(i=0; i<68; i+=2) R2(*x, *y, ctx->k[i], ctx->k[i+1]);

	/*
	u64 tmp;
	for (i = 0; i < ctx->T; i ++)
	{
		tmp = *x;
		*x = *y ^ ( ROTL2(1,*x,ctx->n) & ROTL2(8,*x,ctx->n) ) ^ ROTL2(2,*x,ctx->n) ^ ctx->k[i];
		*y = tmp;
	}

	/*
	int i;
	u64 tmp;
	for (i = 0; i < ctx->T - 1; ++i)
	{
		tmp = (u64) *x;
		*x =  (u64) *y 
			^ (rotate(ctx, (u64) *x, 1) & rotate(ctx, (u64) *x, 8)) 
			^ rotate(ctx, (u64) *x, 2) 
			^ ctx->k[i];
		*y = (u64) tmp;
	}*/
}