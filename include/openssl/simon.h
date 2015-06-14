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

#define ROTL2( n, X, L )    ( ( ( X ) << ( n + 64 - L ) >> (64-L)) | ( ( X ) >> ( L - n ) ) )
//#define u64 unsigned long long
typedef unsigned long long u64;

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

#ifdef  __cplusplus
}
#endif

#endif /* HEADER_SIMON_H */
