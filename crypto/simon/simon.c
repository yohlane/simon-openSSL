/*
 * Copyright (c) 2015 Yohann Gely <yohann.gely@gmail.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <stdint.h>

#include <openssl/simon.h>
#include <assert.h>
#include <openssl/modes.h>

u64 Simon_z[5][62] = {
    {1,1,1,1,1,0,1,0,0,0,1,0,0,1,0,1,0,1,1,0,0,0,0,1,1,1,0,0,1,1,0,1,1,1,1,1,0,1,0,0,0,1,0,0,1,0,1,0,1,1,0,0,0,0,1,1,1,0,0,1,1,0},
    {1,0,0,0,1,1,1,0,1,1,1,1,1,0,0,1,0,0,1,1,0,0,0,0,1,0,1,1,0,1,0,1,0,0,0,1,1,1,0,1,1,1,1,1,0,0,1,0,0,1,1,0,0,0,0,1,0,1,1,0,1,0},
    {1,0,1,0,1,1,1,1,0,1,1,1,0,0,0,0,0,0,1,1,0,1,0,0,1,0,0,1,1,0,0,0,1,0,1,0,0,0,0,1,0,0,0,1,1,1,1,1,1,0,0,1,0,1,1,0,1,1,0,0,1,1},
    {1,1,0,1,1,0,1,1,1,0,1,0,1,1,0,0,0,1,1,0,0,1,0,1,1,1,1,0,0,0,0,0,0,1,0,0,1,0,0,0,1,0,1,0,0,1,1,1,0,0,1,1,0,1,0,0,0,0,1,1,1,1},
    {1,1,0,1,0,0,0,1,1,1,1,0,0,1,1,0,1,0,1,1,0,1,1,0,0,0,1,0,0,0,0,0,0,1,0,1,1,1,0,0,0,0,1,1,0,0,1,0,1,0,0,1,0,0,1,1,1,0,1,1,1,1}
};

void
Simon_init(simon_ctx *ctx, u64 *key, int n, int keysize){
    int i;

    ctx->n = n;

    ctx->m = keysize/ctx->n;

    for(i = 0;      i<ctx->m;   i++)
        ctx->k[i]=key[i];


    if (ctx->n == 16) {ctx->T=32;ctx->j=0;}
    if (ctx->n == 24 && ctx->m == 3) { ctx->T=36; ctx->j=0;}
    if (ctx->n == 24 && ctx->m == 4) { ctx->T=36; ctx->j=1;}
    if (ctx->m==3 && ctx->n==32) {ctx->T=42;ctx->j=2;}
    if (ctx->m==4 && ctx->n==32) {ctx->T=44;ctx->j=3;}
    if (ctx->m==2 && ctx->n==48) {ctx->T=52;ctx->j=2;}
    if (ctx->m==3 && ctx->n==48) {ctx->T=54;ctx->j=3;}
    if (ctx->m==2 && ctx->n==64) {ctx->T=68;ctx->j=2;}
    if (ctx->m==3 && ctx->n==64) {ctx->T=69;ctx->j=3;}
    if (ctx->m==4 && ctx->n==64) {ctx->T=72;ctx->j=4;}
}

void
Simon_keysetup(simon_ctx *ctx)
{
    int i;
    u64 tmp;
    for (i = ctx->m; i < ctx->T; i++)
        {
        tmp = ROTL2(-3,ctx->k[i-1],ctx->n);
        if(ctx->m == 4)
            tmp ^= ctx->k[i-3];
        tmp ^= ROTL2(-1,tmp,ctx->n);

        ctx->k[i] = (~ctx->k[i-ctx->m]) ^ tmp ^ Simon_z[ctx->j][(i-ctx->m) % 62] ^ 3;

    }
}

void 
Simon(u64 *x, u64 *y, u64 *key, int n, int keysize){

	simon_ctx ctx;

    Simon_init(&ctx, key, n, keysize);

    Simon_keysetup(&ctx);

    Simon_encrypt_bytes(&ctx, x, y);    
}

void
Simon_encrypt_bytes(simon_ctx *ctx, u64 *x, u64 *y)
{
    int i;
    u64 tmp;
    for (i = 0; i < ctx->T; i++)
    {
        tmp = *x;
        *x = *y ^ ( ROTL2(1,*x,ctx->n) & ROTL2(8,*x,ctx->n) ) ^ ROTL2(2,*x,ctx->n) ^ ctx->k[i];
        *y = tmp;
    }
}

void Simon_decrypt_bytes(simon_ctx *ctx, u64 *x, u64 *y) 
{

    int i;
    u64 tmp;
    for (i = 0; i < ctx->T; i++) {
        tmp = *y;
        *y = *x ^ ( ROTL2(1,*y,ctx->n) & ROTL2(8,*y,ctx->n) ) ^ ROTL2(2,*y,ctx->n) ^ ctx->k[ctx->T-i-1];
        *x = tmp;
    }
}

/*
 * Encrypt a single block
 * in and out can overlap
 */
void
Simon_encrypt(const unsigned char *in, unsigned char *out, const u64 *key)
{
    int i;
    //printf("Simon_encrypt: start\n");
    assert(in && out && key);

    //u64 x, y;
    //x = GETU64(in);

    printf("in: "); for(i = 0; i < 16; i++) printf("%02x ",in[i]); printf("\n");

    u64 x = GETU64(in), y = GETU64(in + 8);

    printf("PlainText:\t");
    printf("%08X",(unsigned int)(x>>32));printf("%08X ",(unsigned int)x);
    printf("%08X",(unsigned int)(y>>32));printf("%08X\n",(unsigned int)y);

    //Simon_encrypt_bytes(simon_ctx *ctx, &x, &y)

}

/*
 * Encrypt a single block
 * in and out can overlap
 */
void
Simon_decrypt(const unsigned char *in, unsigned char *out, const u64 *key)
{

    //printf("Simon_decrypt: start\n");
    assert(in && out && key);

    //u64 x, y;
    //x = GETU64(in);

}

void
Simon_cbc_encrypt(const unsigned char *in, unsigned char *out,
size_t len, const simon_ctx *key, unsigned char *ivec, const int enc)
{

    //printf("Simon_cbc_encrypt\n");
    if (enc)
        CRYPTO_cbc128_encrypt(in, out, len, key, ivec, (block128_f) Simon_encrypt);
    else
        CRYPTO_cbc128_decrypt(in, out, len, key, ivec, (block128_f) Simon_decrypt);
}