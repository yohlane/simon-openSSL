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

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/simon.h>

struct simon_tv {
	const char *desc;
	const unsigned char key[32];
	const size_t len;
	const unsigned char out[512];
};

int
main(int argc, char **argv)
{
	int failed = 0;
	//printf("Simon Test\n");

    simon_ctx ctx;

    u64 k[4]={0};
    u64 x, y;

    k[1]=0x0f0e0d0c0b0a0908;k[0]=0x0706050403020100;
    x = 0x6373656420737265;y = 0x6c6c657661727420;
    Simon_init(&ctx, k, 64,128);
    Simon_keysetup(&ctx);
    Simon_encrypt_bytes(&ctx, &x, &y);

    if(x != 0x49681b1e1e54fe3f || y != 0x65aa832af84e0bbc)
        failed = 1;

    Simon_decrypt_bytes(&ctx, &x, &y);
    if(x != 0x6373656420737265 || y != 0x6c6c657661727420)
        failed = 1;

    k[2]=0x1716151413121110;k[1]=0x0f0e0d0c0b0a0908;k[0]=0x0706050403020100;
    x=0x206572656874206e; y=0x6568772065626972;
    Simon_init(&ctx, k, 64,192);
    Simon_keysetup(&ctx);
    Simon_encrypt_bytes(&ctx, &x, &y);

    if(x != 0xc4ac61effcdc0d4f || y != 0x6c9c8d6e2597b85b)
        failed = 1;

    Simon_decrypt_bytes(&ctx, &x, &y);
    if(x != 0x206572656874206e || y != 0x6568772065626972)
        failed = 1;

    k[3]=0x1f1e1d1c1b1a1918;k[2]=0x1716151413121110;k[1]=0x0f0e0d0c0b0a0908;k[0]=0x0706050403020100;
    x=0x74206e69206d6f6f; y=0x6d69732061207369;
    Simon_init(&ctx, k, 64,256);
    Simon_keysetup(&ctx);
    Simon_encrypt_bytes(&ctx, &x, &y);

    if(x != 0x8d2b5579afc8a3a0 || y != 0x3bf72a87efe7b868)
        failed = 1;

    Simon_decrypt_bytes(&ctx, &x, &y);
    if(x != 0x74206e69206d6f6f || y != 0x6d69732061207369)
        failed = 1;

    /*printf("Key:\t\t");
    printf("%08X",(unsigned int)(k[1]>>32));printf("%08X ",(unsigned int)k[1]);
    printf("%08X",(unsigned int)(k[0]>>32));printf("%08X\n",(unsigned int)k[0]);

    //Simon_set_key(&ctx, key);

    printf("PlainText:\t");
    printf("%08X",(unsigned int)(x>>32));printf("%08X ",(unsigned int)x);
    printf("%08X",(unsigned int)(y>>32));printf("%08X\n",(unsigned int)y);
    Simon(&x, &y, k,64, 128);

    printf("CipherText:\t");
    printf("%08X",(unsigned int)(x>>32));printf("%08X ",(unsigned int)x);
    printf("%08X",(unsigned int)(y>>32));printf("%08X\n",(unsigned int)y);

    if(x != 0x49681b1e1e54fe3f || y != 0x65aa832af84e0bbc)
        failed = 1;

    */

	return failed;
}
