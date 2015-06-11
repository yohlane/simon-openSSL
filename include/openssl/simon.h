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

#if defined(OPENSSL_NO_SIMON)
#error Simon is disabled.
#endif

#include <stddef.h>
#include <stdint.h>

#ifdef  __cplusplus
extern "C" {
#endif

typedef uint64_t u64;

typedef struct{
    u64 n;
    u64 m;
    u64 k;
    u64 T;
    u64 j;
}simon_ctx;

void Simon_set_key(simon_ctx *x, const u64 *k);
void Simon_set_iv();
void Simon();


#ifdef  __cplusplus
}
#endif

#endif /* HEADER_SIMON_H */
