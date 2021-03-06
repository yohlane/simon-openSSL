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

#ifndef HEADER_SIMON_H
#define HEADER_SIMON_H

#include <openssl/opensslconf.h>
 #include <x86intrin.h>

#if defined(OPENSSL_NO_SIMON)
#error Simon is disabled.
#endif

#include <stddef.h>
#include <stdint.h>

#ifdef  __cplusplus
extern "C" {
#endif

//Modify from aes_locl.h
#define GETU64(pt) (((u64)(pt)[0] << 56) ^ ((u64)(pt)[1] << 48) ^ ((u64)(pt)[2] <<  40) ^ ((u64)(pt)[3] << 32) ^ ((u64)(pt)[4] << 24) ^ ((u64)(pt)[5] << 16) ^ ((u64)(pt)[6] << 8) ^ ((u64)(pt)[7]))
#define PUTU64(ct, st) { (ct)[0] = (u8)((st) >> 56); (ct)[1] = (u8)((st) >> 48); (ct)[2] = (u8)((st) >>  40); (ct)[3] = (u8)((st) >>  32); (ct)[4] = (u8)((st) >>  24); (ct)[5] = (u8)((st) >>  16); (ct)[6] = (u8)((st) >> 8); (ct)[7] = (u8)(st); }

#define ROTL2( n, X, L )    ( ( ( X ) << ( n + 64 - L ) >> (64-L)) | ( ( X ) >> ( L - n ) ) )
//#define u64 unsigned long long
typedef unsigned long long u64;
typedef unsigned char u8;

typedef struct{
    int n;
    int m;
    u64 k[72];
    int T;
    int j;
}simon_ctx;

void Simon_init(simon_ctx *ctx, u64 *key, int n, int keysize);
void Simon_keysetup(simon_ctx *ctx);
void Simon(u64 *x, u64 *y, u64 *key, int n, int keysize);
void Simon_encrypt_bytes(simon_ctx *ctx, u64 *x, u64 *y);
void Simon_decrypt_bytes(simon_ctx *ctx, u64 *x, u64 *y);

void Simon_encrypt(const unsigned char *in, unsigned char *out, simon_ctx *ctx);
void Simon_decrypt(const unsigned char *in, unsigned char *out, simon_ctx *ctx);
void Simon_cbc_encrypt(const unsigned char *in, unsigned char *out,
  size_t len, const simon_ctx *key, unsigned char *ivec, const int enc);

#ifdef  __cplusplus
}
#endif

#endif /* HEADER_SIMON_H */
