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
    block128_f block;
    cbc128_f cbc;
} EVP_SIMON_KEY;

static int simon_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
const unsigned char *in, size_t len);
static int simon_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
const unsigned char *iv, int enc);

static const EVP_CIPHER simon_128_cipher = {
    .nid = 15,// NID_simon_128_cbc,
    .block_size = 128,
    .key_len = 128 / 8,
    .flags = EVP_CIPH_CBC_MODE,
    .init = simon_init,
    .do_cipher = simon_cipher,
    .ctx_size = sizeof(simon_ctx)
};

const EVP_CIPHER *
EVP_simon_128_cbc(void)
{
    return (&simon_128_cipher);
}

static int simon_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
const unsigned char *in, size_t len){

    EVP_SIMON_KEY *dat = (EVP_SIMON_KEY *)ctx->cipher_data;

    printf("simon_cipher_128: start : len %d\n",len);
    int i;
    //~ printf("in: "); for(i = 0; i < 16; i++) printf("%02x ",in[i]); printf("\n");
    if (dat->cbc){
        //~ printf("cdc\n");
        (*dat->cbc)(in, out, len, &dat->ks, ctx->iv,ctx->encrypt);
    }
    else if (ctx->encrypt){
        //~ printf("ctx_encrypt\n");
        CRYPTO_cbc128_encrypt(in, out, len, &dat->ks, ctx->iv,dat->block);
    }
    else{
        //~ printf("ctx_decrypt\n");
        CRYPTO_cbc128_decrypt(in, out, len, &dat->ks, ctx->iv,dat->block);
    }
    printf("out: "); for(i = 0; i < 16; i++) printf("%02x ",out[i]); printf("\n");
    return 1;
}
static int
simon_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
const unsigned char *iv, int enc)
{
    /*int ret, mode;

    EVP_SIMON_KEY *dat = (EVP_SIMON_KEY *)ctx->cipher_data;
    mode = ctx->cipher->flags & EVP_CIPH_MODE;
    if ((mode == EVP_CIPH_CBC_MODE) && !enc) {
        Simon_keysetup(key, ctx->key_len * 8,
        &dat->ks);
        dat->cbc = (cbc128_f)SIMON_cbc_encrypt;
    } else {
        Simon_keysetup(key, ctx->key_len * 8,
        &dat->ks);
        dat->cbc = (cbc128_f)SIMON_cbc_encrypt;
    }
    if (ret < 0) {
        printf("e_simon.c -> simon_init: ret < 0 ERROR");
        return 0;
    }*/
    return 1;
}
#endif
