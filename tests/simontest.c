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
	printf("Simon Test\n");

    u64 k[4]={0};
    k[1]=0x0f0e0d0c0b0a0908;
    k[0]=0x0706050403020100;

    u64 x = 0x6373656420737265;
    u64 y = 0x6c6c657661727420;

    printf("Key:\t\t");
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

	return failed;
}
