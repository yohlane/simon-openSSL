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

#include "simon-merged.c"

char Simonz[5][65] =
{"11111010001001010110000111001101111101000100101011000011100110",
"10001110111110010011000010110101000111011111001001100001011010",
"10101111011100000011010010011000101000010001111110010110110011",
"11011011101011000110010111100000010010001010011100110100001111",
"11010001111001101011011000100000010111000011001010010011101111"};

void 
Simon(u64 *x, u64 *y, u64 *key, int n, int keysize){

    //u64 k[72]={0};
    /*
    -------------------------- definitions --------------------------
    nn = word size (16, 24, 32, 48, or 64) - this version works for up to 32
    mm = number of key words (must be 4 if n = 16,
    3 or 4 if nn = 24 or 32,
    2 or 3 if nn = 48,
    2, 3, or 4 if nn = 64
    T = number of rounds, in this code it is variable
    Cj = const seq number, avoids self-similarity between different versions
    (T, Cj) = (32,0) if nn = 16
    = (36,0) or (36,1) if nn = 24, mm = 3 or 4
    = (42,2) or (44,3) if nn = 32, mm = 3 or 4
    = (52,2) or (54,3) if nn = 48, mm = 2 or 3
    = (68,2), (69,3), or (72,4) if nn = 64, mm = 2, 3, or 4
    x,y = plaintext words on nn bits
    k[m-1]..k[0] = key words on nn bits
    //*/
/*
    //------------------------- key expansion -------------------------
    int mm=keysize/nn;
    int Cj=0,T=0;

    if (nn == 16) {T=32;Cj=0;}
    if (nn == 24 && mm == 3) { T=36; Cj=0;}
    if (nn == 24 && mm == 4) { T=36; Cj=1;}
    if (mm==3 && nn==32) {T=42;Cj=2;}
    if (mm==4 && nn==32) {T=44;Cj=3;}
    if (mm==2 && nn==48) {T=52;Cj=2;}
    if (mm==3 && nn==48) {T=54;Cj=3;}
    if (mm==2 && nn==64) {T=68;Cj=2;}
    if (mm==3 && nn==64) {T=69;Cj=3;}
    if (mm==4 && nn==64) {T=72;Cj=4;}

    int i,j=0;
    for(i = 0;      i<mm;   i++)
        k[i]=key[i];
    for(i = mm;     i<T;    i++)
    {
        u64 tmp=ROTL2((nn-3),k[i-1],nn);
        if (mm == 4)
            tmp ^= k[i-3];
        tmp = tmp ^ ROTL2((nn-1),tmp,nn);
        //is it bitwise negation?
        u64 t1 = ~(0xffffffffffffffff << nn);

        k[i] = (~(k[i-mm]) & t1) ^ tmp ^ (Simonz[Cj][(i-mm) % 62]-'0') ^ 3;

    };
    //-------------------------- encryption ---------------------------
    
    for(i = 0;      i<T ;        i++)
    {
        u64 tmp = *x;
        *x = *y ^ ROTL2(1,*x,nn) & ROTL2(8,*x,nn) ^ ROTL2(2,*x,nn) ^ k[i];
        *y = tmp;
    };
}
    */
	simon_ctx ctx;
    int i;

    ctx.n = n;

    ctx.m = keysize/ctx.n;

    for(i = 0;      i<ctx.m;   i++)
        ctx.k[i]=key[i];


    if (ctx.n == 16) {ctx.T=32;ctx.j=0;}
    if (ctx.n == 24 && ctx.m == 3) { ctx.T=36; ctx.j=0;}
    if (ctx.n == 24 && ctx.m == 4) { ctx.T=36; ctx.j=1;}
    if (ctx.m==3 && ctx.n==32) {ctx.T=42;ctx.j=2;}
    if (ctx.m==4 && ctx.n==32) {ctx.T=44;ctx.j=3;}
    if (ctx.m==2 && ctx.n==48) {ctx.T=52;ctx.j=2;}
    if (ctx.m==3 && ctx.n==48) {ctx.T=54;ctx.j=3;}
    if (ctx.m==2 && ctx.n==64) {ctx.T=68;ctx.j=2;}
    if (ctx.m==3 && ctx.n==64) {ctx.T=69;ctx.j=3;}
    if (ctx.m==4 && ctx.n==64) {ctx.T=72;ctx.j=4;}

	simon_keysetup(&ctx);

    simon_encrypt_bytes(&ctx, x, y);
}