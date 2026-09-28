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


#include "portable_endian.h"  // for htole64, le64toh
#include "speck.h"

// NOTE: these includes are used by code outside of all these ifdefs

#if defined (__AVX512F__)  // AVX512 support ----------------------------------------------------------------------
#elif defined (__AVX2__)  // AVX2 support -------------------------------------------------------------------------
#elif defined (__SSE2__) // SSE support ---------------------------------------------------------------------------
#elif defined (__ARM_NEON) && defined (SPECK_ARM_NEON)      // NEON support ---------------------------------------
#else           // plain C ----------------------------------------------------------------------------------------


// cipher SPECK -- 128 bit block size -- 128 and 256 bit key size -- CTR mode
// taken from (and modified: removed pure crypto-stream generation and seperated key expansion)
// https://github.com/nsacyber/simon-speck-supercop/blob/master/crypto_stream/speck128256ctr/


#include <stdlib.h>     // for size_t, malloc, free

#if defined (SPECK_ALIGNED_CTX)
#include <mm_malloc.h>  // for _mm_free, _mm_malloc
#endif

#define ROR(x,r) (((x)>>(r))|((x)<<(64-(r))))
#define ROL(x,r) (((x)<<(r))|((x)>>(64-(r))))
#define R(x,y,k) (x=ROR(x,8), x+=y, x^=k, y=ROL(y,3), y^=x)


static int speck_encrypt (u64 *u, u64 *v, speck_context_t *ctx, int numrounds) {

    u64 i, x = *u, y = *v;

    for(i = 0; i < numrounds; i++)
        R(x, y, ctx->key[i]);
    *u = x; *v = y;

    return 0;
}


static int internal_speck_ctr (unsigned char *out, const unsigned char *in, unsigned long long inlen,
                               const unsigned char *n, speck_context_t *ctx) {

    u64 i, nonce[2], x, y, t;
    unsigned char *block = malloc(16);
    int numrounds = (ctx->keysize == 256)?34:32;

    if(!inlen) {
        free(block);
        return 0;
    }
    nonce[0] = htole64( ((u64*)n)[0] );
    nonce[1] = htole64( ((u64*)n)[1] );

    t=0;
    while(inlen >= 16) {
        x = nonce[1]; y = nonce[0]; nonce[0]++;
        speck_encrypt(&x, &y, ctx, numrounds);
        ((u64 *)out)[1+t] = htole64(x ^ ((u64 *)in)[1+t]);
        ((u64 *)out)[0+t] = htole64(y ^ ((u64 *)in)[0+t]);
        t += 2;
        inlen -= 16;
    }

    if(inlen > 0) {
        x = nonce[1]; y = nonce[0];
        speck_encrypt(&x, &y, ctx, numrounds);
        ((u64 *)block)[1] = htole64(x); ((u64 *)block)[0] = htole64(y);
        for(i = 0; i < inlen; i++)
            out[i + 8*t] = block[i] ^ in[i + 8*t];
    }

    free(block);

    return 0;
}


static int speck_expand_key (speck_context_t *ctx, const unsigned char *k, int keysize) {

    u64 K[4];
    u64 i;

    for(i = 0; i < (keysize >> 6); i++)
        K[i] = htole64( ((u64 *)k)[i] );

    for(i = 0; i < 33; i += 3) {
        ctx->key[i  ] = K[0];
        R(K[1], K[0], i    );

        if(keysize == 256) {
            ctx->key[i+1] = K[0];
            R(K[2], K[0], i + 1);
            ctx->key[i+2] = K[0];
            R(K[3], K[0], i + 2);
        } else {
            // counter the i += 3 to make the loop go one by one in this case
            // we can afford the unused 31 and 32
            i -= 2;
        }
    }
    ctx->key[33] = K[0];

    ctx->keysize = keysize;

    return 1;
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


#endif          // AVX, SSE, NEON, plain C ------------------------------------------------------------------------


// ----------------------------------------------------------------------------------------------------------------


// cipher SPECK -- 128 bit block size -- 128 bit key size -- ECB mode (decrypt only)
// follows endianess rules as used in official implementation guide and NOT as in original 2013 cipher presentation
// used for IV in header encryption (one block) and challenge encryption (user/password)
// for now: just plain C -- probably no need for AVX, SSE, NEON


#define ROTL64(x,r) (((x)<<(r))|((x)>>(64-(r))))
#define ROTR64(x,r) (((x)>>(r))|((x)<<(64-(r))))
#define DR128(x,y,k) (y^=x, y=ROTR64(y,3), x^=k, x-=y, x=ROTL64(x,8))
#define ER128(x,y,k) (x=(ROTR64(x,8)+y)^k, y=ROTL64(y,3)^x)

int speck_128_decrypt (unsigned char *inout, speck_context_t *ctx) {

    u64 x, y;
    int i;

    x = le64toh( *(u64*)&inout[8] );
    y = le64toh( *(u64*)&inout[0] );

    for(i = 31; i >= 0; i--)
        DR128(x, y, ctx->key[i]);

    ((u64*)inout)[1] = htole64(x);
    ((u64*)inout)[0] = htole64(y);

    return 0;
}


int speck_128_encrypt (unsigned char *inout, speck_context_t *ctx) {

    u64 x, y;
    int i;

    x = le64toh( *(u64*)&inout[8] );
    y = le64toh( *(u64*)&inout[0] );

    for(i = 0; i < 32; i++)
        ER128(x, y, ctx->key[i]);

    ((u64*)inout)[1] = htole64(x);
    ((u64*)inout)[0] = htole64(y);

    return 0;
}
