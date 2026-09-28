/**
 * SPDX-License-Identifier: GPL-3.0-only
 * SPDX-FileCopyrightText: Copyright ntop.org and contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not see see <http://www.gnu.org/licenses/>
 *
 */


#if defined (__AVX512F__)  // AVX512 support ----------------------------------------------------------------------


// cipher SPECK -- 128 bit block size -- 128 and 256 bit key size -- CTR mode
// taken from (and modified: removed pure crypto-stream generation and seperated key expansion)
// https://github.com/nsacyber/simon-speck-supercop/blob/master/crypto_stream/speck128256ctr/


#include "speck.h"
#include "portable_endian.h"  // for htole64, le64toh
#include <stdlib.h>     // for size_t, malloc, free

#if defined (SPECK_ALIGNED_CTX)
#include <mm_malloc.h>  // for _mm_free, _mm_malloc
#endif

#define LCS(x,r) (((x)<<r)|((x)>>(64-r)))
#define RCS(x,r) (((x)>>r)|((x)<<(64-r)))

#define SET _mm512_set_epi64
#define XOR _mm512_xor_si512
#define ADD _mm512_add_epi64
#define AND _mm512_and_si512
#define ROL(X,r) (_mm512_rol_epi64(X,r))
#define ROR(X,r) (_mm512_ror_epi64(X,r))

#define _q8 SET(0x7LL,0x3LL,0x6LL,0x2LL,0x5LL,0x1LL,0x4LL,0x0LL)
#define _eight SET(0x8LL,0x8LL,0x8LL,0x8LL,0x8LL,0x8LL,0x8LL,0x8LL)

#define SET1(X,c) (X=SET(c,c,c,c,c,c,c,c))
#define SET8(X,c) (X=SET(c,c,c,c,c,c,c,c), X=ADD(X,_q8))

#define LOW  _mm512_unpacklo_epi64
#define HIGH _mm512_unpackhi_epi64
#define LD(ip) _mm512_loadu_si512((void *)(ip))
#define ST(ip,X) _mm512_storeu_si512((void *)(ip),X)
#define STORE(out,X,Y) (ST(out,LOW(Y,X)), ST(out+64,HIGH(Y,X)))
#define XOR_STORE(in,out,X,Y) (ST(out,XOR(LD(in),LOW(Y,X))), ST(out+64,XOR(LD(in+64),HIGH(Y,X))))

#define Rx8(X,Y,k)  (X[0]=XOR(ADD(ROR(X[0],8),Y[0]),k), \
                     Y[0]=XOR(ROL(Y[0],3),X[0]))
#define Rx16(X,Y,k) (X[0]=XOR(ADD(ROR(X[0],8),Y[0]),k), X[1]=XOR(ADD(ROR(X[1],8),Y[1]),k), \
                     Y[0]=XOR(ROL(Y[0],3),X[0]), Y[1]=XOR(ROL(Y[1],3),X[1]))
#define Rx24(X,Y,k) (X[0]=XOR(ADD(ROR(X[0],8),Y[0]),k), X[1]=XOR(ADD(ROR(X[1],8),Y[1]),k), X[2]=XOR(ADD(ROR(X[2],8),Y[2]),k), \
                     Y[0]=XOR(ROL(Y[0],3),X[0]), Y[1]=XOR(ROL(Y[1],3),X[1]), Y[2]=XOR(ROL(Y[2],3),X[2]))
#define Rx32(X,Y,k) (X[0]=XOR(ADD(ROR(X[0],8),Y[0]),k), X[1]=XOR(ADD(ROR(X[1],8),Y[1]),k), \
                     X[2]=XOR(ADD(ROR(X[2],8),Y[2]),k), X[3]=XOR(ADD(ROR(X[3],8),Y[3]),k), \
                     Y[0]=XOR(ROL(Y[0],3),X[0]), Y[1]=XOR(ROL(Y[1],3),X[1]),               \
                     Y[2]=XOR(ROL(Y[2],3),X[2]), Y[3]=XOR(ROL(Y[3],3),X[3]))

#define Rx1(x,y,k)  (x[0]=RCS(x[0],8), x[0]+=y[0], x[0]^=k, y[0]=LCS(y[0],3), y[0]^=x[0])
#define Rx1b(x,y,k) (x=RCS(x,8), x+=y, x^=k, y=LCS(y,3), y^=x)
#define Rx2(x,y,k)  (x[0]=RCS(x[0],8), x[1]=RCS(x[1],8), x[0]+=y[0], x[1]+=y[1],                   \
                     x[0]^=k, x[1]^=k, y[0]=LCS(y[0],3), y[1]=LCS(y[1],3), y[0]^=x[0], y[1]^=x[1])

#define Encrypt_128(X,Y,k,n) (Rx ## n(X,Y,k[0]),  Rx ## n(X,Y,k[1]),  Rx ## n(X,Y,k[2]),  Rx ## n(X,Y,k[3]),  Rx ## n(X,Y,k[4]),  Rx ## n(X,Y,k[5]),  Rx ## n(X,Y,k[6]),  Rx ## n(X,Y,k[7]),  \
                              Rx ## n(X,Y,k[8]),  Rx ## n(X,Y,k[9]),  Rx ## n(X,Y,k[10]), Rx ## n(X,Y,k[11]), Rx ## n(X,Y,k[12]), Rx ## n(X,Y,k[13]), Rx ## n(X,Y,k[14]), Rx ## n(X,Y,k[15]), \
                              Rx ## n(X,Y,k[16]), Rx ## n(X,Y,k[17]), Rx ## n(X,Y,k[18]), Rx ## n(X,Y,k[19]), Rx ## n(X,Y,k[20]), Rx ## n(X,Y,k[21]), Rx ## n(X,Y,k[22]), Rx ## n(X,Y,k[23]), \
                              Rx ## n(X,Y,k[24]), Rx ## n(X,Y,k[25]), Rx ## n(X,Y,k[26]), Rx ## n(X,Y,k[27]), Rx ## n(X,Y,k[28]), Rx ## n(X,Y,k[29]), Rx ## n(X,Y,k[30]), Rx ## n(X,Y,k[31]))

#define Encrypt_256(X,Y,k,n) (Encrypt_128(X,Y,k,n),               \
                              Rx ## n(X,Y,k[32]), Rx ## n(X,Y,k[33]))

#define RK(X,Y,k,key,i)   (SET1(k[i],Y), key[i]=Y, X=RCS(X,8), X+=Y, X^=i, Y=LCS(Y,3), Y^=X)

#define EK(A,B,C,D,k,key) (RK(B,A,k,key,0),  RK(C,A,k,key,1),  RK(D,A,k,key,2),  RK(B,A,k,key,3),  RK(C,A,k,key,4),  RK(D,A,k,key,5),  RK(B,A,k,key,6),  \
                           RK(C,A,k,key,7),  RK(D,A,k,key,8),  RK(B,A,k,key,9),  RK(C,A,k,key,10), RK(D,A,k,key,11), RK(B,A,k,key,12), RK(C,A,k,key,13), \
                           RK(D,A,k,key,14), RK(B,A,k,key,15), RK(C,A,k,key,16), RK(D,A,k,key,17), RK(B,A,k,key,18), RK(C,A,k,key,19), RK(D,A,k,key,20), \
                           RK(B,A,k,key,21), RK(C,A,k,key,22), RK(D,A,k,key,23), RK(B,A,k,key,24), RK(C,A,k,key,25), RK(D,A,k,key,26), RK(B,A,k,key,27), \
                           RK(C,A,k,key,28), RK(D,A,k,key,29), RK(B,A,k,key,30), RK(C,A,k,key,31), RK(D,A,k,key,32), RK(B,A,k,key,33))

#define Encrypt_Dispatcher(keysize)                                                       \
    u64 x[2], y[2];                                                                      \
    u512 X[4], Y[4];                                                                      \
    unsigned char block1024[128];                                                         \
                                                                                          \
    if(numbytes == 16) {                                                                  \
        x[0] = nonce[1]; y[0] = nonce[0]; nonce[0]++;                                     \
        Encrypt_ ## keysize(x, y, ctx->key, 1);                                             \
        ((u64 *)out)[1] = x[0]; ((u64 *)out)[0] = y[0];                                   \
        return 0;                                                                         \
    }                                                                                     \
                                                                                          \
    if(numbytes == 32) {                                                                  \
        x[0] = nonce[1]; y[0] = nonce[0]; nonce[0]++;                                     \
        x[1] = nonce[1]; y[1] = nonce[0]; nonce[0]++;                                     \
        Encrypt_ ## keysize(x, y, ctx->key, 2);                                             \
        ((u64 *)out)[1] = x[0] ^ ((u64 *)in)[1]; ((u64 *)out)[0] = y[0] ^ ((u64 *)in)[0]; \
        ((u64 *)out)[3] = x[1] ^ ((u64 *)in)[3]; ((u64 *)out)[2] = y[1] ^ ((u64 *)in)[2]; \
        return 0;                                                                         \
    }                                                                                     \
                                                                                          \
    if(numbytes == 64) {                                                                  \
        SET1(X[0], nonce[1]);                                                             \
        SET8(Y[0], nonce[0]);                                                             \
        Encrypt_ ## keysize(X, Y, ctx->rk, 8);                                              \
        nonce[0] += (numbytes >> 4);                                                      \
        memcpy(block1024, in, 64);                                                        \
        XOR_STORE(block1024, block1024, X[0], Y[0]);                                      \
        memcpy(out, block1024, 64);                                                       \
        return 0;                                                                         \
    }                                                                                     \
                                                                                          \
    SET1(X[0], nonce[1]); SET8(Y[0], nonce[0]);                                           \
                                                                                          \
    if(numbytes == 128)                                                                   \
    Encrypt_ ## keysize(X, Y, ctx->rk, 8);                                              \
    else {                                                                                \
        X[1] = X[0];                                                                      \
        Y[1] = ADD(Y[0], _eight);                                                         \
        if(numbytes == 256)                                                               \
        Encrypt_ ## keysize(X, Y, ctx->rk, 16);                                         \
        else {                                                                            \
            X[2] = X[0];                                                                  \
            Y[2] = ADD(Y[1], _eight);                                                     \
            if(numbytes == 384)                                                           \
            Encrypt_ ## keysize(X, Y, ctx->rk, 24);                                     \
            else {                                                                        \
                X[3] = X[0];                                                              \
                Y[3] = ADD(Y[2], _eight);                                                 \
                Encrypt_ ## keysize(X, Y, ctx->rk, 32);                                     \
            }                                                                             \
        }                                                                                 \
    }                                                                                     \
                                                                                          \
    nonce[0] += (numbytes >> 4);                                                          \
                                                                                          \
    XOR_STORE(in, out, X[0], Y[0]);                                                       \
    if(numbytes >= 256)                                                                  \
    XOR_STORE(in + 128, out + 128, X[1], Y[1]);                                       \
    if(numbytes >= 384)                                                                   \
    XOR_STORE(in + 256, out + 256, X[2], Y[2]);                                       \
    if(numbytes >= 512)                                                                   \
    XOR_STORE(in + 384, out + 384, X[3], Y[3]);                                       \
                                                                                          \
    return 0


static int speck_encrypt_xor (unsigned char *out, const unsigned char *in, u64 nonce[], speck_context_t *ctx, int numbytes) {

    if(ctx->keysize == 256) {
        Encrypt_Dispatcher(256);
    } else {
        Encrypt_Dispatcher(128);
    }
}


static int internal_speck_ctr (unsigned char *out, const unsigned char *in, unsigned long long inlen,
                               const unsigned char *n, speck_context_t *ctx) {

    int i;
    u64 nonce[2];
    unsigned char block[16];
    u64 * const block64 = (u64 *)block;

    if(!inlen)
        return 0;

    nonce[0] = ((u64 *)n)[0];
    nonce[1] = ((u64 *)n)[1];

    while(inlen >= 512) {
        speck_encrypt_xor(out, in, nonce, ctx, 512);
        in += 512; inlen -= 512; out += 512;
    }

    if(inlen >= 384) {
        speck_encrypt_xor(out, in, nonce, ctx, 384);
        in += 384; inlen -= 384; out += 384;
    }

    if(inlen >= 256) {
        speck_encrypt_xor(out, in, nonce, ctx, 256);
        in += 256; inlen -= 256; out += 256;
    }

    if(inlen >= 128) {
        speck_encrypt_xor(out, in, nonce, ctx, 128);
        in += 128; inlen -= 128; out += 128;
    }

    if(inlen >= 64) {
        speck_encrypt_xor(out, in, nonce, ctx, 64);
        in += 64; inlen -= 64; out += 64;
    }

    if(inlen >= 32) {
        speck_encrypt_xor(out, in, nonce, ctx, 32);
        in += 32; inlen -= 32; out += 32;
    }

    if(inlen >= 16) {
        speck_encrypt_xor(block, in, nonce, ctx, 16);
        ((u64 *)out)[0] = block64[0] ^ ((u64 *)in)[0];
        ((u64 *)out)[1] = block64[1] ^ ((u64 *)in)[1];
        in += 16; inlen -= 16; out += 16;
    }

    if(inlen > 0) {
        speck_encrypt_xor(block, in, nonce, ctx, 16);
        for(i = 0; i < inlen; i++)
            out[i] = block[i] ^ in[i];
    }

    return 0;
}


static int speck_expand_key (speck_context_t *ctx, const unsigned char *k, int keysize) {

    u64 K[4];
    size_t i;

    for(i = 0; i < (keysize >> 6); i++)
        K[i] = ((u64 *)k)[i];

    // 128 bit has only two keys A and B thus replacing both C and D with B then
    if(keysize == 128) {
        EK(K[0], K[1], K[1], K[1], ctx->rk, ctx->key);
    } else {
        EK(K[0], K[1], K[2], K[3], ctx->rk, ctx->key);
    }

    ctx->keysize = keysize;

    return 0;
}


// this functions wraps the call to internal_speck_ctr functions which have slightly different
// signature -- ctx by value for SSE with SPECK_CTX_BYVAL defined in speck.h, by name otherwise
int speck_ctr (unsigned char *out, const unsigned char *in, unsigned long long inlen,
               const unsigned char *n, speck_context_t *ctx) {

    return internal_speck_ctr(out, in, inlen, n,
#if defined (SPECK_CTX_BYVAL)
                              *ctx);
#else
                              ctx);
#endif
}


// create context loaded with round keys ready for use, key size either 128 or 256 (bits)
int speck_init (speck_context_t **ctx, const unsigned char *k, int keysize) {

#if defined (SPECK_ALIGNED_CTX)
    *ctx = (speck_context_t*)_mm_malloc(sizeof(speck_context_t), SPECK_ALIGNED_CTX);
#else
    *ctx = (speck_context_t*)calloc(1, sizeof(speck_context_t));
#endif
    if(!(*ctx)) {
        return -1;
    }

    return speck_expand_key(*ctx, k, keysize);
}


int speck_deinit (speck_context_t *ctx) {

    if(ctx) {
#if defined (SPECK_ALIGNED_CTX)
        _mm_free(ctx);
#else
        free(ctx);
#endif
    }

    return 0;
}


#elif defined (__AVX2__)  // AVX2 support -------------------------------------------------------------------------
#elif defined (__SSE2__) // SSE support ---------------------------------------------------------------------------
#elif defined (__ARM_NEON) && defined (SPECK_ARM_NEON)      // NEON support ---------------------------------------
#else           // plain C ----------------------------------------------------------------------------------------
#endif          // AVX, SSE, NEON, plain C ------------------------------------------------------------------------
