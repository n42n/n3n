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
#elif defined (__AVX2__)  // AVX2 support -------------------------------------------------------------------------
#elif defined (__SSE2__) // SSE support ---------------------------------------------------------------------------
#elif defined (__ARM_NEON) && defined (SPECK_ARM_NEON)      // NEON support ---------------------------------------


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

#define XOR veorq_u64
#define AND vandq_u64
#define ADD vaddq_u64
#define SL vshlq_n_u64
#define SR vshrq_n_u64

#define SET(a,b) vcombine_u64((uint64x1_t)(a),(uint64x1_t)(b))
#define SET1(X,c) (X=SET(c,c))
#define SET2(X,c) (SET1(X,c), X=ADD(X,SET(0x1ll,0x0ll)),c+=2)

#define LOW(Z) vgetq_lane_u64(Z,0)
#define HIGH(Z) vgetq_lane_u64(Z,1)
#define STORE(ip,X,Y) (((u64 *)(ip))[0]=HIGH(Y), ((u64 *)(ip))[1]=HIGH(X), ((u64 *)(ip))[2]=LOW(Y), ((u64 *)(ip))[3]=LOW(X))
#define XOR_STORE(in,out,X,Y) (Y=XOR(Y,SET(((u64 *)(in))[2],((u64 *)(in))[0])), X=XOR(X,SET(((u64 *)(in))[3],((u64 *)(in))[1])), STORE(out,X,Y))

#define ROR(X,r) vsriq_n_u64(SL(X,(64-r)),X,r)
#define ROL(X,r) ROR(X,(64-r))

#define tableR vcreate_u8(0x0007060504030201LL)
#define tableL vcreate_u8(0x0605040302010007LL)
#define ROR8(X) SET(vtbl1_u8((uint8x8_t)vget_low_u64(X),tableR), vtbl1_u8((uint8x8_t)vget_high_u64(X),tableR))
#define ROL8(X) SET(vtbl1_u8((uint8x8_t)vget_low_u64(X),tableL), vtbl1_u8((uint8x8_t)vget_high_u64(X),tableL))

#define R(X,Y,k) (X=XOR(ADD(ROR8(X),Y),k), Y=XOR(ROL(Y,3),X))

#define Rx2(X,Y,k) (R(X[0],Y[0],k))
#define Rx4(X,Y,k) (R(X[0],Y[0],k), R(X[1],Y[1],k))
#define Rx6(X,Y,k) (R(X[0],Y[0],k), R(X[1],Y[1],k), R(X[2],Y[2],k))
#define Rx8(X,Y,k) (X[0]=ROR8(X[0]), X[0]=ADD(X[0],Y[0]), X[0]=XOR(X[0],k), X[1]=ROR8(X[1]), X[1]=ADD(X[1],Y[1]), X[1]=XOR(X[1],k), \
                    X[2]=ROR8(X[2]), X[2]=ADD(X[2],Y[2]), X[2]=XOR(X[2],k), X[3]=ROR8(X[3]), X[3]=ADD(X[3],Y[3]), X[3]=XOR(X[3],k), \
                    Z[0]=SL(Y[0],3), Z[1]=SL(Y[1],3), Z[2]=SL(Y[2],3), Z[3]=SL(Y[3],3), \
                    Y[0]=SR(Y[0],61), Y[1]=SR(Y[1],61), Y[2]=SR(Y[2],61), Y[3]=SR(Y[3],61), \
                    Y[0]=XOR(Y[0],Z[0]), Y[1]=XOR(Y[1],Z[1]), Y[2]=XOR(Y[2],Z[2]), Y[3]=XOR(Y[3],Z[3]), \
                    Y[0]=XOR(X[0],Y[0]), Y[1]=XOR(X[1],Y[1]), Y[2]=XOR(X[2],Y[2]), Y[3]=XOR(X[3],Y[3]))

#define Rx1(x,y,k) (x[0]=RCS(x[0],8), x[0]+=y[0], x[0]^=k, y[0]=LCS(y[0],3), y[0]^=x[0])
#define Rx1b(x,y,k) (x=RCS(x,8), x+=y, x^=k, y=LCS(y,3), y^=x)

#define Encrypt_128(X,Y,k,n) (Rx ## n(X,Y,k[0]),  Rx ## n(X,Y,k[1]),  Rx ## n(X,Y,k[2]),  Rx ## n(X,Y,k[3]),  Rx ## n(X,Y,k[4]),  Rx ## n(X,Y,k[5]),  Rx ## n(X,Y,k[6]),  Rx ## n(X,Y,k[7]), \
                              Rx ## n(X,Y,k[8]),  Rx ## n(X,Y,k[9]),  Rx ## n(X,Y,k[10]), Rx ## n(X,Y,k[11]), Rx ## n(X,Y,k[12]), Rx ## n(X,Y,k[13]), Rx ## n(X,Y,k[14]), Rx ## n(X,Y,k[15]), \
                              Rx ## n(X,Y,k[16]), Rx ## n(X,Y,k[17]), Rx ## n(X,Y,k[18]), Rx ## n(X,Y,k[19]), Rx ## n(X,Y,k[20]), Rx ## n(X,Y,k[21]), Rx ## n(X,Y,k[22]), Rx ## n(X,Y,k[23]), \
                              Rx ## n(X,Y,k[24]), Rx ## n(X,Y,k[25]), Rx ## n(X,Y,k[26]), Rx ## n(X,Y,k[27]), Rx ## n(X,Y,k[28]), Rx ## n(X,Y,k[29]), Rx ## n(X,Y,k[30]), Rx ## n(X,Y,k[31]))

#define Encrypt_256(X,Y,k,n) (Encrypt_128(X,Y,k,n),               \
                              Rx ## n(X,Y,k[32]), Rx ## n(X,Y,k[33]))

#define RK(X,Y,k,key,i) (SET1(k[i],Y), key[i]=Y, X=RCS(X,8), X+=Y, X^=i, Y=LCS(Y,3), Y^=X)

#define EK(A,B,C,D,k,key) (RK(B,A,k,key,0),  RK(C,A,k,key,1),  RK(D,A,k,key,2),  RK(B,A,k,key,3),  RK(C,A,k,key,4),  RK(D,A,k,key,5),  RK(B,A,k,key,6), \
                           RK(C,A,k,key,7),  RK(D,A,k,key,8),  RK(B,A,k,key,9),  RK(C,A,k,key,10), RK(D,A,k,key,11), RK(B,A,k,key,12), RK(C,A,k,key,13), \
                           RK(D,A,k,key,14), RK(B,A,k,key,15), RK(C,A,k,key,16), RK(D,A,k,key,17), RK(B,A,k,key,18), RK(C,A,k,key,19), RK(D,A,k,key,20), \
                           RK(B,A,k,key,21), RK(C,A,k,key,22), RK(D,A,k,key,23), RK(B,A,k,key,24), RK(C,A,k,key,25), RK(D,A,k,key,26), RK(B,A,k,key,27), \
                           RK(C,A,k,key,28), RK(D,A,k,key,29), RK(B,A,k,key,30), RK(C,A,k,key,31), RK(D,A,k,key,32), RK(B,A,k,key,33))

#define Encrypt_Dispatcher(keysize)                     \
    u64 x[2], y[2];                                    \
    u128 X[4], Y[4], Z[4];                              \
                                                        \
    if(numbytes == 16) {                                \
        x[0] = nonce[1]; y[0]=nonce[0]; nonce[0]++;     \
        Encrypt_ ## keysize(x, y, ctx->key, 1);           \
        ((u64 *)out)[1] = x[0]; ((u64 *)out)[0] = y[0]; \
        return 0;                                       \
    }                                                   \
                                                        \
    /* Each size stores its blocks in its own branch, so \
     * that the compiler sees that only initialised X[] \
     * and Y[] get stored */                            \
    SET1(X[0], nonce[1]); SET2(Y[0], nonce[0]);         \
                                                        \
    if(numbytes == 32) {                                \
        Encrypt_ ## keysize(X, Y, ctx->rk, 2);          \
        XOR_STORE(in, out, X[0], Y[0]);                 \
        return 0;                                       \
    }                                                   \
                                                        \
    X[1] = X[0]; SET2(Y[1], nonce[0]);                  \
    if(numbytes == 64) {                                \
        Encrypt_ ## keysize(X, Y, ctx->rk, 4);          \
        XOR_STORE(in, out, X[0], Y[0]);                 \
        XOR_STORE(in + 32, out + 32, X[1], Y[1]);       \
        return 0;                                       \
    }                                                   \
                                                        \
    X[2] = X[0]; SET2(Y[2], nonce[0]);                  \
    if(numbytes == 96) {                                \
        Encrypt_ ## keysize(X, Y, ctx->rk, 6);          \
        XOR_STORE(in, out, X[0], Y[0]);                 \
        XOR_STORE(in + 32, out + 32, X[1], Y[1]);       \
        XOR_STORE(in + 64, out + 64, X[2], Y[2]);       \
        return 0;                                       \
    }                                                   \
                                                        \
    X[3] = X[0]; SET2(Y[3], nonce[0]);                  \
    Encrypt_ ## keysize(X, Y, ctx->rk, 8);              \
    XOR_STORE(in, out, X[0], Y[0]);                     \
    XOR_STORE(in + 32, out + 32, X[1], Y[1]);           \
    XOR_STORE(in + 64, out + 64, X[2], Y[2]);           \
    XOR_STORE(in + 96, out + 96, X[3], Y[3]);           \
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
    u64 *const block64 = (u64 *)block;

    if(!inlen)
        return 0;

    nonce[0] = ((u64 *)n)[0];
    nonce[1] = ((u64 *)n)[1];

    while(inlen >= 128) {
        speck_encrypt_xor(out, in, nonce, ctx, 128);
        in += 128; inlen -= 128; out += 128;
    }

    if(inlen >= 96) {
        speck_encrypt_xor(out, in, nonce, ctx, 96);
        in += 96; inlen -= 96; out += 96;
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


#else           // plain C ----------------------------------------------------------------------------------------
#endif          // AVX, SSE, NEON, plain C ------------------------------------------------------------------------
