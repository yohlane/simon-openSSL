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

#include <openssl/opensslconf.h>

#ifndef OPENSSL_NO_SIMON

#include <openssl/simon.h>
#include <openssl/evp.h>
#include <openssl/objects.h>

#include "evp_locl.h"
#include "modes_lcl.h"

typedef struct {
    simon_ctx ks;
    //block128_f block;
    cbc128_f cbc;
} EVP_SIMON_KEY;

static int simon_cbc_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
const unsigned char *in, size_t len);
static int simon_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
const unsigned char *iv, int enc);

static const EVP_CIPHER simon_128_cbc_cipher = {
    .nid =  NID_simon,
    .block_size = 128 /8,
    .key_len = 128 / 8,
    .flags = EVP_CIPH_CBC_MODE,
    .init = simon_init,
    .do_cipher = simon_cbc_cipher,
    .ctx_size = sizeof(simon_ctx)
};

const EVP_CIPHER *
EVP_simon_128_cbc(void)
{
    return (&simon_128_cbc_cipher);
}

static int simon_cbc_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
const unsigned char *in, size_t len){

    EVP_SIMON_KEY *dat = (EVP_SIMON_KEY *)ctx->cipher_data;

    //printf("simon_cipher: start : len %d\n",len);

    if (dat->cbc){
        //printf("cbc\n");
        (*dat->cbc)(in, out, len, &dat->ks, ctx->iv,ctx->encrypt);
    }
    //printf("out: "); for(i = 0; i < 16; i++) printf("%02x ",out[i]); printf("\n");
    
    return 1;
}
static int
simon_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
const unsigned char *iv, int enc)
{
    //printf("simon_init CBC \n");

    int mode;
    int i;
    //printf("key: "); for(i = 0; i < 16; i++) printf("%02x ",key[i]); printf("\n");

    u64 u64Key[75] = {0};

    //printf("key_len %d\ni: %d\n", ctx->key_len, ctx->key_len / 8);


    printf("Key:\t\t");
    for (i = 0; i < ctx->key_len / 8; ++i)
    {
        u64Key[(ctx->key_len / 8) - i -1] = GETU64(key + 8*i);
        printf("%08X",(unsigned int)(u64Key[(ctx->key_len / 8) - i -1]>>32));printf("%08X ",(unsigned int)u64Key[(ctx->key_len / 8) - i -1]);

    }
    printf("\n");

    EVP_SIMON_KEY *dat = (EVP_SIMON_KEY *)ctx->cipher_data;
    Simon_init(&dat->ks, u64Key, 64,ctx->key_len * 8);
    Simon_keysetup(&dat->ks);

    mode = ctx->cipher->flags & EVP_CIPH_MODE;
    if ((mode == EVP_CIPH_CBC_MODE) && !enc) {
        dat->cbc = (cbc128_f)Simon_cbc_encrypt;
    } else {
        dat->cbc = (cbc128_f)Simon_cbc_encrypt;
    }
    return 1;
}
#endif
