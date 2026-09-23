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

#include "config.h"     // for HAVE_LIBCRYPTO

#include <n3n/logging.h> // for traceEvent
#include <stdint.h>  // for uint32_t, uint8_t
#include <stdlib.h>  // for calloc, free
#include <string.h>  // for memcpy, size_t
#include "aes.h"     // for AES_BLOCK_SIZE, aes_context_t, AES128_KEY_BYTES
#include "portable_endian.h"  // for be32toh, htobe32


#ifdef HAVE_LIBCRYPTO // openSSL 1.1 ---------------------------------------------------------------------
#elif defined (__AES__) && defined (__SSE2__) // Intel's AES-NI ---------------------------------------------------


// inspired by https://gist.github.com/acapola/d5b940da024080dfaf5f
// furthered by the help of Sebastian Ramacher's implementation found at
// https://chromium.googlesource.com/external/github.com/dlitz/pycrypto/+/junk/master/src/AESNI.c
// modified along Intel's white paper on AES Instruction Set
// https://www.intel.com/content/dam/doc/white-paper/advanced-encryption-standard-new-instructions-set-paper.pdf


static __m128i aes128_keyexpand (__m128i key, __m128i keygened, uint8_t shuf) {

    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));

    // unfortunately, shuffle expects immediate argument, thus the not-so-stylish switch ...
    // REVISIT: either macrorize this whole function (and perhaps the following one) or
    //          use shuffle_epi8 (which would require SSSE3 instead of SSE2)
    switch(shuf) {
        case 0x55:
            keygened = _mm_shuffle_epi32(keygened, 0x55 );
            break;
        case 0xaa:
            keygened = _mm_shuffle_epi32(keygened, 0xaa );
            break;
        case 0xff:
            keygened = _mm_shuffle_epi32(keygened, 0xff );
            break;
        default:
            break;
    }

    return _mm_xor_si128(key, keygened);
}


static __m128i aes192_keyexpand_2 (__m128i key, __m128i key2) {

    key = _mm_shuffle_epi32(key, 0xff);
    key2 = _mm_xor_si128(key2, _mm_slli_si128(key2, 4));

    return _mm_xor_si128(key, key2);
}


#define KEYEXP128(K, I)      aes128_keyexpand(K,  _mm_aeskeygenassist_si128(K,  I),    0xff)
#define KEYEXP192(K1, K2, I) aes128_keyexpand(K1, _mm_aeskeygenassist_si128(K2, I),    0x55)
#define KEYEXP192_2(K1, K2)  aes192_keyexpand_2(K1, K2)
#define KEYEXP256(K1, K2, I) aes128_keyexpand(K1, _mm_aeskeygenassist_si128(K2, I),    0xff)
#define KEYEXP256_2(K1, K2)  aes128_keyexpand(K1, _mm_aeskeygenassist_si128(K2, 0x00), 0xaa)


// key setup
static int aes_internal_key_setup (aes_context_t *ctx, const uint8_t *key, int key_bits) {

    // number of rounds
    ctx->Nr = 6 + (key_bits / 32);

    // encryption keys
    switch(key_bits) {
        case 128: {
            ctx->rk_enc[ 0] = _mm_loadu_si128((const __m128i*)key);
            ctx->rk_enc[ 1] = KEYEXP128(ctx->rk_enc[0], 0x01);
            ctx->rk_enc[ 2] = KEYEXP128(ctx->rk_enc[1], 0x02);
            ctx->rk_enc[ 3] = KEYEXP128(ctx->rk_enc[2], 0x04);
            ctx->rk_enc[ 4] = KEYEXP128(ctx->rk_enc[3], 0x08);
            ctx->rk_enc[ 5] = KEYEXP128(ctx->rk_enc[4], 0x10);
            ctx->rk_enc[ 6] = KEYEXP128(ctx->rk_enc[5], 0x20);
            ctx->rk_enc[ 7] = KEYEXP128(ctx->rk_enc[6], 0x40);
            ctx->rk_enc[ 8] = KEYEXP128(ctx->rk_enc[7], 0x80);
            ctx->rk_enc[ 9] = KEYEXP128(ctx->rk_enc[8], 0x1B);
            ctx->rk_enc[10] = KEYEXP128(ctx->rk_enc[9], 0x36);
            break;
        }
        case 192: {
            __m128i temp[2];
            ctx->rk_enc[ 0] = _mm_loadu_si128((const __m128i*) key);

            ctx->rk_enc[ 1] = _mm_loadu_si128((const __m128i*) (key+16));
            temp[0] = KEYEXP192(ctx->rk_enc[0], ctx->rk_enc[1], 0x01);
            temp[1] = KEYEXP192_2(temp[0], ctx->rk_enc[1]);
            ctx->rk_enc[ 1] = (__m128i)_mm_shuffle_pd((__m128d)ctx->rk_enc[1], (__m128d)temp[0], 0);

            ctx->rk_enc[ 2] = (__m128i)_mm_shuffle_pd((__m128d)temp[0], (__m128d)temp[1], 1);
            ctx->rk_enc[ 3] = KEYEXP192(temp[0], temp[1], 0x02);

            ctx->rk_enc[ 4] = KEYEXP192_2(ctx->rk_enc[3], temp[1]);
            temp[0] = KEYEXP192(ctx->rk_enc[3], ctx->rk_enc[4], 0x04);
            temp[1] = KEYEXP192_2(temp[0], ctx->rk_enc[4]);
            ctx->rk_enc[ 4] = (__m128i)_mm_shuffle_pd((__m128d)ctx->rk_enc[4], (__m128d)temp[0], 0);

            ctx->rk_enc[ 5] = (__m128i)_mm_shuffle_pd((__m128d)temp[0], (__m128d)temp[1], 1);
            ctx->rk_enc[ 6] = KEYEXP192(temp[0], temp[1], 0x08);

            ctx->rk_enc[ 7] = KEYEXP192_2(ctx->rk_enc[6], temp[1]);
            temp[0] = KEYEXP192(ctx->rk_enc[6], ctx->rk_enc[7], 0x10);
            temp[1] = KEYEXP192_2(temp[0], ctx->rk_enc[7]);
            ctx->rk_enc[ 7] = (__m128i)_mm_shuffle_pd((__m128d)ctx->rk_enc[7], (__m128d)temp[0], 0);

            ctx->rk_enc[ 8] = (__m128i)_mm_shuffle_pd((__m128d)temp[0], (__m128d)temp[1], 1);
            ctx->rk_enc[ 9] = KEYEXP192(temp[0], temp[1], 0x20);

            ctx->rk_enc[10] = KEYEXP192_2(ctx->rk_enc[9], temp[1]);
            temp[0] = KEYEXP192(ctx->rk_enc[9], ctx->rk_enc[10], 0x40);
            temp[1] = KEYEXP192_2(temp[0], ctx->rk_enc[10]);
            ctx->rk_enc[10] = (__m128i)_mm_shuffle_pd((__m128d)ctx->rk_enc[10], (__m128d) temp[0], 0);

            ctx->rk_enc[11] = (__m128i)_mm_shuffle_pd((__m128d)temp[0],(__m128d) temp[1], 1);
            ctx->rk_enc[12] = KEYEXP192(temp[0], temp[1], 0x80);
            break;
        }
        case 256: {
            ctx->rk_enc[ 0] = _mm_loadu_si128((const __m128i*) key);
            ctx->rk_enc[ 1] = _mm_loadu_si128((const __m128i*) (key+16));
            ctx->rk_enc[ 2] = KEYEXP256(ctx->rk_enc[0], ctx->rk_enc[1], 0x01);
            ctx->rk_enc[ 3] = KEYEXP256_2(ctx->rk_enc[1], ctx->rk_enc[2]);
            ctx->rk_enc[ 4] = KEYEXP256(ctx->rk_enc[2], ctx->rk_enc[3], 0x02);
            ctx->rk_enc[ 5] = KEYEXP256_2(ctx->rk_enc[3], ctx->rk_enc[4]);
            ctx->rk_enc[ 6] = KEYEXP256(ctx->rk_enc[4], ctx->rk_enc[5], 0x04);
            ctx->rk_enc[ 7] = KEYEXP256_2(ctx->rk_enc[5], ctx->rk_enc[6]);
            ctx->rk_enc[ 8] = KEYEXP256(ctx->rk_enc[6], ctx->rk_enc[7], 0x08);
            ctx->rk_enc[ 9] = KEYEXP256_2(ctx->rk_enc[7], ctx->rk_enc[8]);
            ctx->rk_enc[10] = KEYEXP256(ctx->rk_enc[8], ctx->rk_enc[9], 0x10);
            ctx->rk_enc[11] = KEYEXP256_2(ctx->rk_enc[9], ctx->rk_enc[10]);
            ctx->rk_enc[12] = KEYEXP256(ctx->rk_enc[10], ctx->rk_enc[11], 0x20);
            ctx->rk_enc[13] = KEYEXP256_2(ctx->rk_enc[11], ctx->rk_enc[12]);
            ctx->rk_enc[14] = KEYEXP256(ctx->rk_enc[12], ctx->rk_enc[13], 0x40);
            break;
        }
    }

    // derive decryption keys
    for(int i = 1; i < ctx->Nr; ++i) {
        ctx->rk_dec[ctx->Nr - i] = _mm_aesimc_si128(ctx->rk_enc[i]);
    }
    ctx->rk_dec[ 0] = ctx->rk_enc[ctx->Nr];

    return ctx->Nr;
}


static void aes_internal_encrypt (aes_context_t *ctx, const uint8_t pt[16], uint8_t ct[16]) {

    __m128i tmp = _mm_loadu_si128((__m128i*)pt);

    tmp = _mm_xor_si128(tmp, ctx->rk_enc[ 0]);
    tmp = _mm_aesenc_si128(tmp, ctx->rk_enc[ 1]);
    tmp = _mm_aesenc_si128(tmp, ctx->rk_enc[ 2]);
    tmp = _mm_aesenc_si128(tmp, ctx->rk_enc[ 3]);
    tmp = _mm_aesenc_si128(tmp, ctx->rk_enc[ 4]);
    tmp = _mm_aesenc_si128(tmp, ctx->rk_enc[ 5]);
    tmp = _mm_aesenc_si128(tmp, ctx->rk_enc[ 6]);
    tmp = _mm_aesenc_si128(tmp, ctx->rk_enc[ 7]);
    tmp = _mm_aesenc_si128(tmp, ctx->rk_enc[ 8]);
    tmp = _mm_aesenc_si128(tmp, ctx->rk_enc[ 9]);
    if(ctx->Nr > 10) {
        tmp = _mm_aesenc_si128(tmp, ctx->rk_enc[10]);
        tmp = _mm_aesenc_si128(tmp, ctx->rk_enc[11]);
        if(ctx->Nr > 12) {
            tmp = _mm_aesenc_si128(tmp, ctx->rk_enc[12]);
            tmp = _mm_aesenc_si128(tmp, ctx->rk_enc[13]);
        }
    }
    tmp = _mm_aesenclast_si128(tmp, ctx->rk_enc[ctx->Nr]);

    _mm_storeu_si128((__m128i*) ct, tmp);
}


static void aes_internal_decrypt (aes_context_t *ctx, const uint8_t ct[16], uint8_t pt[16]) {

    __m128i tmp = _mm_loadu_si128((__m128i*)ct);

    tmp = _mm_xor_si128(tmp, ctx->rk_dec[ 0]);
    tmp = _mm_aesdec_si128(tmp, ctx->rk_dec[ 1]);
    tmp = _mm_aesdec_si128(tmp, ctx->rk_dec[ 2]);
    tmp = _mm_aesdec_si128(tmp, ctx->rk_dec[ 3]);
    tmp = _mm_aesdec_si128(tmp, ctx->rk_dec[ 4]);
    tmp = _mm_aesdec_si128(tmp, ctx->rk_dec[ 5]);
    tmp = _mm_aesdec_si128(tmp, ctx->rk_dec[ 6]);
    tmp = _mm_aesdec_si128(tmp, ctx->rk_dec[ 7]);
    tmp = _mm_aesdec_si128(tmp, ctx->rk_dec[ 8]);
    tmp = _mm_aesdec_si128(tmp, ctx->rk_dec[ 9]);
    if(ctx->Nr > 10) {
        tmp = _mm_aesdec_si128(tmp, ctx->rk_dec[10]);
        tmp = _mm_aesdec_si128(tmp, ctx->rk_dec[11]);
        if(ctx->Nr > 12) {
            tmp = _mm_aesdec_si128(tmp, ctx->rk_dec[12]);
            tmp = _mm_aesdec_si128(tmp, ctx->rk_dec[13]);
        }
    }
    tmp = _mm_aesdeclast_si128(tmp, ctx->rk_enc[ 0]);

    _mm_storeu_si128((__m128i*) pt, tmp);
}


// public API


int aes_ecb_decrypt (unsigned char *out, const unsigned char *in, aes_context_t *ctx) {

    aes_internal_decrypt(ctx, in, out);

    return AES_BLOCK_SIZE;
}


// not used
int aes_ecb_encrypt (unsigned char *out, const unsigned char *in, aes_context_t *ctx) {

    aes_internal_encrypt(ctx, in, out);

    return AES_BLOCK_SIZE;
}


int aes_cbc_encrypt (unsigned char *out, const unsigned char *in, size_t in_len,
                     const unsigned char *iv, aes_context_t *ctx) {

    int n;                       /* number of blocks */
    int ret = (int)in_len & 15;  /* remainder        */

    __m128i ivec = _mm_loadu_si128((__m128i*)iv);

    for(n = in_len / 16; n != 0; n--) {
        __m128i tmp = _mm_loadu_si128((__m128i*)in);
        in += 16;
        tmp = _mm_xor_si128(tmp, ivec);

        tmp = _mm_xor_si128(tmp, ctx->rk_enc[ 0]);
        tmp = _mm_aesenc_si128(tmp, ctx->rk_enc[ 1]);
        tmp = _mm_aesenc_si128(tmp, ctx->rk_enc[ 2]);
        tmp = _mm_aesenc_si128(tmp, ctx->rk_enc[ 3]);
        tmp = _mm_aesenc_si128(tmp, ctx->rk_enc[ 4]);
        tmp = _mm_aesenc_si128(tmp, ctx->rk_enc[ 5]);
        tmp = _mm_aesenc_si128(tmp, ctx->rk_enc[ 6]);
        tmp = _mm_aesenc_si128(tmp, ctx->rk_enc[ 7]);
        tmp = _mm_aesenc_si128(tmp, ctx->rk_enc[ 8]);
        tmp = _mm_aesenc_si128(tmp, ctx->rk_enc[ 9]);
        if(ctx->Nr > 10) {
            tmp = _mm_aesenc_si128(tmp, ctx->rk_enc[10]);
            tmp = _mm_aesenc_si128(tmp, ctx->rk_enc[11]);
            if(ctx->Nr > 12) {
                tmp = _mm_aesenc_si128(tmp, ctx->rk_enc[12]);
                tmp = _mm_aesenc_si128(tmp, ctx->rk_enc[13]);
            }
        }
        tmp = _mm_aesenclast_si128(tmp, ctx->rk_enc[ctx->Nr]);

        ivec = tmp;

        _mm_storeu_si128((__m128i*)out, tmp);
        out += 16;
    }

    return ret;
}


// encrypts several packets, each with its own CBC chain, at once
//
// AESENC has a latency of several cycles and CBC feeds every cipher text block
// into the next one, so encrypting a single packet leaves most of the pipeline
// idle (in contrast to decryption, which has independent blocks and uses four
// rails below). Packets are independent of each other, so four of them are
// encrypted in parallel here, which fills the same pipeline.
//
// All packets use the same iv, as they do in transform_aes.c, where the first
// block of every packet is a random value.
int aes_cbc_encrypt_multi (unsigned char *out[], const unsigned char *in[], const size_t in_len[],
                           const unsigned char *iv, aes_context_t *ctx, int count) {

    int i;                       /* first packet of the current group of four */
    uint8_t ivec_bytes[16];      /* chaining value of a rail that has blocks left */

    for(i = 0; i + 4 <= count; i += 4) {
        const unsigned char *in1 = in[i];
        const unsigned char *in2 = in[i+1];
        const unsigned char *in3 = in[i+2];
        const unsigned char *in4 = in[i+3];

        unsigned char *out1 = out[i];
        unsigned char *out2 = out[i+1];
        unsigned char *out3 = out[i+2];
        unsigned char *out4 = out[i+3];

        size_t n1 = in_len[i] / 16;
        size_t n2 = in_len[i+1] / 16;
        size_t n3 = in_len[i+2] / 16;
        size_t n4 = in_len[i+3] / 16;
        size_t n;                /* blocks all four packets have in common */

        __m128i ivec1 = _mm_loadu_si128((__m128i*)iv);
        __m128i ivec2 = ivec1;
        __m128i ivec3 = ivec1;
        __m128i ivec4 = ivec1;

        // the four rails run in lockstep for as long as all four packets have blocks left
        n = n1;
        if(n2 < n) n = n2;
        if(n3 < n) n = n3;
        if(n4 < n) n = n4;

        n1 -= n; n2 -= n; n3 -= n; n4 -= n;

        for(; n != 0; n--) {
            __m128i tmp1 = _mm_loadu_si128((__m128i*)in1); in1 += 16;
            __m128i tmp2 = _mm_loadu_si128((__m128i*)in2); in2 += 16;
            __m128i tmp3 = _mm_loadu_si128((__m128i*)in3); in3 += 16;
            __m128i tmp4 = _mm_loadu_si128((__m128i*)in4); in4 += 16;

            tmp1 = _mm_xor_si128(tmp1, ivec1); tmp2 = _mm_xor_si128(tmp2, ivec2);
            tmp3 = _mm_xor_si128(tmp3, ivec3); tmp4 = _mm_xor_si128(tmp4, ivec4);

            tmp1 = _mm_xor_si128(tmp1, ctx->rk_enc[ 0]); tmp2 = _mm_xor_si128(tmp2, ctx->rk_enc[ 0]);
            tmp3 = _mm_xor_si128(tmp3, ctx->rk_enc[ 0]); tmp4 = _mm_xor_si128(tmp4, ctx->rk_enc[ 0]);

            tmp1 = _mm_aesenc_si128(tmp1, ctx->rk_enc[ 1]); tmp2 = _mm_aesenc_si128(tmp2, ctx->rk_enc[ 1]);
            tmp3 = _mm_aesenc_si128(tmp3, ctx->rk_enc[ 1]); tmp4 = _mm_aesenc_si128(tmp4, ctx->rk_enc[ 1]);

            tmp1 = _mm_aesenc_si128(tmp1, ctx->rk_enc[ 2]); tmp2 = _mm_aesenc_si128(tmp2, ctx->rk_enc[ 2]);
            tmp3 = _mm_aesenc_si128(tmp3, ctx->rk_enc[ 2]); tmp4 = _mm_aesenc_si128(tmp4, ctx->rk_enc[ 2]);

            tmp1 = _mm_aesenc_si128(tmp1, ctx->rk_enc[ 3]); tmp2 = _mm_aesenc_si128(tmp2, ctx->rk_enc[ 3]);
            tmp3 = _mm_aesenc_si128(tmp3, ctx->rk_enc[ 3]); tmp4 = _mm_aesenc_si128(tmp4, ctx->rk_enc[ 3]);

            tmp1 = _mm_aesenc_si128(tmp1, ctx->rk_enc[ 4]); tmp2 = _mm_aesenc_si128(tmp2, ctx->rk_enc[ 4]);
            tmp3 = _mm_aesenc_si128(tmp3, ctx->rk_enc[ 4]); tmp4 = _mm_aesenc_si128(tmp4, ctx->rk_enc[ 4]);

            tmp1 = _mm_aesenc_si128(tmp1, ctx->rk_enc[ 5]); tmp2 = _mm_aesenc_si128(tmp2, ctx->rk_enc[ 5]);
            tmp3 = _mm_aesenc_si128(tmp3, ctx->rk_enc[ 5]); tmp4 = _mm_aesenc_si128(tmp4, ctx->rk_enc[ 5]);

            tmp1 = _mm_aesenc_si128(tmp1, ctx->rk_enc[ 6]); tmp2 = _mm_aesenc_si128(tmp2, ctx->rk_enc[ 6]);
            tmp3 = _mm_aesenc_si128(tmp3, ctx->rk_enc[ 6]); tmp4 = _mm_aesenc_si128(tmp4, ctx->rk_enc[ 6]);

            tmp1 = _mm_aesenc_si128(tmp1, ctx->rk_enc[ 7]); tmp2 = _mm_aesenc_si128(tmp2, ctx->rk_enc[ 7]);
            tmp3 = _mm_aesenc_si128(tmp3, ctx->rk_enc[ 7]); tmp4 = _mm_aesenc_si128(tmp4, ctx->rk_enc[ 7]);

            tmp1 = _mm_aesenc_si128(tmp1, ctx->rk_enc[ 8]); tmp2 = _mm_aesenc_si128(tmp2, ctx->rk_enc[ 8]);
            tmp3 = _mm_aesenc_si128(tmp3, ctx->rk_enc[ 8]); tmp4 = _mm_aesenc_si128(tmp4, ctx->rk_enc[ 8]);

            tmp1 = _mm_aesenc_si128(tmp1, ctx->rk_enc[ 9]); tmp2 = _mm_aesenc_si128(tmp2, ctx->rk_enc[ 9]);
            tmp3 = _mm_aesenc_si128(tmp3, ctx->rk_enc[ 9]); tmp4 = _mm_aesenc_si128(tmp4, ctx->rk_enc[ 9]);
            if(ctx->Nr > 10) {
                tmp1 = _mm_aesenc_si128(tmp1, ctx->rk_enc[10]); tmp2 = _mm_aesenc_si128(tmp2, ctx->rk_enc[10]);
                tmp3 = _mm_aesenc_si128(tmp3, ctx->rk_enc[10]); tmp4 = _mm_aesenc_si128(tmp4, ctx->rk_enc[10]);

                tmp1 = _mm_aesenc_si128(tmp1, ctx->rk_enc[11]); tmp2 = _mm_aesenc_si128(tmp2, ctx->rk_enc[11]);
                tmp3 = _mm_aesenc_si128(tmp3, ctx->rk_enc[11]); tmp4 = _mm_aesenc_si128(tmp4, ctx->rk_enc[11]);

                if(ctx->Nr > 12) {
                    tmp1 = _mm_aesenc_si128(tmp1, ctx->rk_enc[12]); tmp2 = _mm_aesenc_si128(tmp2, ctx->rk_enc[12]);
                    tmp3 = _mm_aesenc_si128(tmp3, ctx->rk_enc[12]); tmp4 = _mm_aesenc_si128(tmp4, ctx->rk_enc[12]);

                    tmp1 = _mm_aesenc_si128(tmp1, ctx->rk_enc[13]); tmp2 = _mm_aesenc_si128(tmp2, ctx->rk_enc[13]);
                    tmp3 = _mm_aesenc_si128(tmp3, ctx->rk_enc[13]); tmp4 = _mm_aesenc_si128(tmp4, ctx->rk_enc[13]);
                }
            }
            tmp1 = _mm_aesenclast_si128(tmp1, ctx->rk_enc[ctx->Nr]); tmp2 = _mm_aesenclast_si128(tmp2, ctx->rk_enc[ctx->Nr]);
            tmp3 = _mm_aesenclast_si128(tmp3, ctx->rk_enc[ctx->Nr]); tmp4 = _mm_aesenclast_si128(tmp4, ctx->rk_enc[ctx->Nr]);

            ivec1 = tmp1; ivec2 = tmp2; ivec3 = tmp3; ivec4 = tmp4;

            _mm_storeu_si128((__m128i*)out1, tmp1); out1 += 16;
            _mm_storeu_si128((__m128i*)out2, tmp2); out2 += 16;
            _mm_storeu_si128((__m128i*)out3, tmp3); out3 += 16;
            _mm_storeu_si128((__m128i*)out4, tmp4); out4 += 16;
        }

        // whatever is longer than the shortest packet of the four finishes on its own
        if(n1) {
            _mm_storeu_si128((__m128i*)ivec_bytes, ivec1);
            aes_cbc_encrypt(out1, in1, n1 * 16, ivec_bytes, ctx);
        }
        if(n2) {
            _mm_storeu_si128((__m128i*)ivec_bytes, ivec2);
            aes_cbc_encrypt(out2, in2, n2 * 16, ivec_bytes, ctx);
        }
        if(n3) {
            _mm_storeu_si128((__m128i*)ivec_bytes, ivec3);
            aes_cbc_encrypt(out3, in3, n3 * 16, ivec_bytes, ctx);
        }
        if(n4) {
            _mm_storeu_si128((__m128i*)ivec_bytes, ivec4);
            aes_cbc_encrypt(out4, in4, n4 * 16, ivec_bytes, ctx);
        }
    }

    // fewer than four packets left over
    for(; i < count; i++) {
        aes_cbc_encrypt(out[i], in[i], in_len[i], iv, ctx);
    }

    return 0;
}


int aes_cbc_decrypt (unsigned char *out, const unsigned char *in, size_t in_len,
                     const unsigned char *iv, aes_context_t *ctx) {

    int n;                       /* number of blocks */
    int ret = (int)in_len & 15;  /* remainder        */

    __m128i ivec = _mm_loadu_si128((__m128i*)iv);

    // 4 parallel rails of AES decryption to reduce data dependencies in x86's deep pipelines
    for(n = in_len / 16; n > 3; n -=4) {
        __m128i tmp1 = _mm_loadu_si128((__m128i*)in); in += 16;
        __m128i tmp2 = _mm_loadu_si128((__m128i*)in); in += 16;
        __m128i tmp3 = _mm_loadu_si128((__m128i*)in); in += 16;
        __m128i tmp4 = _mm_loadu_si128((__m128i*)in); in += 16;

        __m128i old_in1 = tmp1;
        __m128i old_in2 = tmp2;
        __m128i old_in3 = tmp3;
        __m128i old_in4 = tmp4;

        tmp1 = _mm_xor_si128(tmp1, ctx->rk_dec[ 0]); tmp2 = _mm_xor_si128(tmp2, ctx->rk_dec[ 0]);
        tmp3 = _mm_xor_si128(tmp3, ctx->rk_dec[ 0]); tmp4 = _mm_xor_si128(tmp4, ctx->rk_dec[ 0]);

        tmp1 = _mm_aesdec_si128(tmp1, ctx->rk_dec[ 1]); tmp2 = _mm_aesdec_si128(tmp2, ctx->rk_dec[ 1]);
        tmp3 = _mm_aesdec_si128(tmp3, ctx->rk_dec[ 1]); tmp4 = _mm_aesdec_si128(tmp4, ctx->rk_dec[ 1]);

        tmp1 = _mm_aesdec_si128(tmp1, ctx->rk_dec[ 2]); tmp2 = _mm_aesdec_si128(tmp2, ctx->rk_dec[ 2]);
        tmp3 = _mm_aesdec_si128(tmp3, ctx->rk_dec[ 2]); tmp4 = _mm_aesdec_si128(tmp4, ctx->rk_dec[ 2]);

        tmp1 = _mm_aesdec_si128(tmp1, ctx->rk_dec[ 3]); tmp2 = _mm_aesdec_si128(tmp2, ctx->rk_dec[ 3]);
        tmp3 = _mm_aesdec_si128(tmp3, ctx->rk_dec[ 3]); tmp4 = _mm_aesdec_si128(tmp4, ctx->rk_dec[ 3]);

        tmp1 = _mm_aesdec_si128(tmp1, ctx->rk_dec[ 4]); tmp2 = _mm_aesdec_si128(tmp2, ctx->rk_dec[ 4]);
        tmp3 = _mm_aesdec_si128(tmp3, ctx->rk_dec[ 4]); tmp4 = _mm_aesdec_si128(tmp4, ctx->rk_dec[ 4]);

        tmp1 = _mm_aesdec_si128(tmp1, ctx->rk_dec[ 5]); tmp2 = _mm_aesdec_si128(tmp2, ctx->rk_dec[ 5]);
        tmp3 = _mm_aesdec_si128(tmp3, ctx->rk_dec[ 5]); tmp4 = _mm_aesdec_si128(tmp4, ctx->rk_dec[ 5]);

        tmp1 = _mm_aesdec_si128(tmp1, ctx->rk_dec[ 6]); tmp2 = _mm_aesdec_si128(tmp2, ctx->rk_dec[ 6]);
        tmp3 = _mm_aesdec_si128(tmp3, ctx->rk_dec[ 6]); tmp4 = _mm_aesdec_si128(tmp4, ctx->rk_dec[ 6]);

        tmp1 = _mm_aesdec_si128(tmp1, ctx->rk_dec[ 7]); tmp2 = _mm_aesdec_si128(tmp2, ctx->rk_dec[ 7]);
        tmp3 = _mm_aesdec_si128(tmp3, ctx->rk_dec[ 7]); tmp4 = _mm_aesdec_si128(tmp4, ctx->rk_dec[ 7]);

        tmp1 = _mm_aesdec_si128(tmp1, ctx->rk_dec[ 8]); tmp2 = _mm_aesdec_si128(tmp2, ctx->rk_dec[ 8]);
        tmp3 = _mm_aesdec_si128(tmp3, ctx->rk_dec[ 8]); tmp4 = _mm_aesdec_si128(tmp4, ctx->rk_dec[ 8]);

        tmp1 = _mm_aesdec_si128(tmp1, ctx->rk_dec[ 9]); tmp2 = _mm_aesdec_si128(tmp2, ctx->rk_dec[ 9]);
        tmp3 = _mm_aesdec_si128(tmp3, ctx->rk_dec[ 9]); tmp4 = _mm_aesdec_si128(tmp4, ctx->rk_dec[ 9]);

        if(ctx->Nr > 10) {
            tmp1 = _mm_aesdec_si128(tmp1, ctx->rk_dec[10]); tmp2 = _mm_aesdec_si128(tmp2, ctx->rk_dec[10]);
            tmp3 = _mm_aesdec_si128(tmp3, ctx->rk_dec[10]); tmp4 = _mm_aesdec_si128(tmp4, ctx->rk_dec[10]);

            tmp1 = _mm_aesdec_si128(tmp1, ctx->rk_dec[11]); tmp2 = _mm_aesdec_si128(tmp2, ctx->rk_dec[11]);
            tmp3 = _mm_aesdec_si128(tmp3, ctx->rk_dec[11]); tmp4 = _mm_aesdec_si128(tmp4, ctx->rk_dec[11]);

            if(ctx->Nr > 12) {
                tmp1 = _mm_aesdec_si128(tmp1, ctx->rk_dec[12]); tmp2 = _mm_aesdec_si128(tmp2, ctx->rk_dec[12]);
                tmp3 = _mm_aesdec_si128(tmp3, ctx->rk_dec[12]); tmp4 = _mm_aesdec_si128(tmp4, ctx->rk_dec[12]);

                tmp1 = _mm_aesdec_si128(tmp1, ctx->rk_dec[13]); tmp2 = _mm_aesdec_si128(tmp2, ctx->rk_dec[13]);
                tmp3 = _mm_aesdec_si128(tmp3, ctx->rk_dec[13]); tmp4 = _mm_aesdec_si128(tmp4, ctx->rk_dec[13]);
            }
        }
        tmp1 =     _mm_aesdeclast_si128(tmp1, ctx->rk_enc[ 0]); tmp2 = _mm_aesdeclast_si128(tmp2, ctx->rk_enc[ 0]);
        tmp3 =     _mm_aesdeclast_si128(tmp3, ctx->rk_enc[ 0]); tmp4 = _mm_aesdeclast_si128(tmp4, ctx->rk_enc[ 0]);

        tmp1 = _mm_xor_si128(tmp1, ivec); tmp2 = _mm_xor_si128(tmp2, old_in1);
        tmp3 = _mm_xor_si128(tmp3, old_in2); tmp4 = _mm_xor_si128(tmp4, old_in3);

        ivec = old_in4;

        _mm_storeu_si128((__m128i*) out, tmp1); out += 16;
        _mm_storeu_si128((__m128i*) out, tmp2); out += 16;
        _mm_storeu_si128((__m128i*) out, tmp3); out += 16;
        _mm_storeu_si128((__m128i*) out, tmp4); out += 16;
    }
    // now: less than 4 blocks remaining

    // if 2 or 3 blocks remaining --> this code handles two of them
    if(n > 1) {
        n-= 2;

        __m128i tmp1 = _mm_loadu_si128((__m128i*)in); in += 16;
        __m128i tmp2 = _mm_loadu_si128((__m128i*)in); in += 16;

        __m128i old_in1 = tmp1;
        __m128i old_in2 = tmp2;

        tmp1 = _mm_xor_si128(tmp1, ctx->rk_dec[ 0]); tmp2 = _mm_xor_si128(tmp2, ctx->rk_dec[ 0]);
        tmp1 = _mm_aesdec_si128(tmp1, ctx->rk_dec[ 1]); tmp2 = _mm_aesdec_si128(tmp2, ctx->rk_dec[ 1]);
        tmp1 = _mm_aesdec_si128(tmp1, ctx->rk_dec[ 2]); tmp2 = _mm_aesdec_si128(tmp2, ctx->rk_dec[ 2]);
        tmp1 = _mm_aesdec_si128(tmp1, ctx->rk_dec[ 3]); tmp2 = _mm_aesdec_si128(tmp2, ctx->rk_dec[ 3]);
        tmp1 = _mm_aesdec_si128(tmp1, ctx->rk_dec[ 4]); tmp2 = _mm_aesdec_si128(tmp2, ctx->rk_dec[ 4]);
        tmp1 = _mm_aesdec_si128(tmp1, ctx->rk_dec[ 5]); tmp2 = _mm_aesdec_si128(tmp2, ctx->rk_dec[ 5]);
        tmp1 = _mm_aesdec_si128(tmp1, ctx->rk_dec[ 6]); tmp2 = _mm_aesdec_si128(tmp2, ctx->rk_dec[ 6]);
        tmp1 = _mm_aesdec_si128(tmp1, ctx->rk_dec[ 7]); tmp2 = _mm_aesdec_si128(tmp2, ctx->rk_dec[ 7]);
        tmp1 = _mm_aesdec_si128(tmp1, ctx->rk_dec[ 8]); tmp2 = _mm_aesdec_si128(tmp2, ctx->rk_dec[ 8]);
        tmp1 = _mm_aesdec_si128(tmp1, ctx->rk_dec[ 9]); tmp2 = _mm_aesdec_si128(tmp2, ctx->rk_dec[ 9]);
        if(ctx->Nr > 10) {
            tmp1 = _mm_aesdec_si128(tmp1, ctx->rk_dec[10]); tmp2 = _mm_aesdec_si128(tmp2, ctx->rk_dec[10]);
            tmp1 = _mm_aesdec_si128(tmp1, ctx->rk_dec[11]); tmp2 = _mm_aesdec_si128(tmp2, ctx->rk_dec[11]);
            if(ctx->Nr > 12) {
                tmp1 = _mm_aesdec_si128(tmp1, ctx->rk_dec[12]); tmp2 = _mm_aesdec_si128(tmp2, ctx->rk_dec[12]);
                tmp1 = _mm_aesdec_si128(tmp1, ctx->rk_dec[13]); tmp2 = _mm_aesdec_si128(tmp2, ctx->rk_dec[13]);
            }
        }
        tmp1 = _mm_aesdeclast_si128(tmp1, ctx->rk_enc[ 0]); tmp2 = _mm_aesdeclast_si128(tmp2, ctx->rk_enc[ 0]);

        tmp1 = _mm_xor_si128(tmp1, ivec); tmp2 = _mm_xor_si128(tmp2, old_in1);

        ivec = old_in2;

        _mm_storeu_si128((__m128i*) out, tmp1); out += 16;
        _mm_storeu_si128((__m128i*) out, tmp2); out += 16;
    }

    // one block remaining
    if(n) {
        __m128i tmp = _mm_loadu_si128((__m128i*)in);

        tmp = _mm_xor_si128(tmp, ctx->rk_dec[ 0]);
        tmp = _mm_aesdec_si128(tmp, ctx->rk_dec[ 1]);
        tmp = _mm_aesdec_si128(tmp, ctx->rk_dec[ 2]);
        tmp = _mm_aesdec_si128(tmp, ctx->rk_dec[ 3]);
        tmp = _mm_aesdec_si128(tmp, ctx->rk_dec[ 4]);
        tmp = _mm_aesdec_si128(tmp, ctx->rk_dec[ 5]);
        tmp = _mm_aesdec_si128(tmp, ctx->rk_dec[ 6]);
        tmp = _mm_aesdec_si128(tmp, ctx->rk_dec[ 7]);
        tmp = _mm_aesdec_si128(tmp, ctx->rk_dec[ 8]);
        tmp = _mm_aesdec_si128(tmp, ctx->rk_dec[ 9]);
        if(ctx->Nr > 10) {
            tmp = _mm_aesdec_si128(tmp, ctx->rk_dec[10]);
            tmp = _mm_aesdec_si128(tmp, ctx->rk_dec[11]);
            if(ctx->Nr > 12) {
                tmp = _mm_aesdec_si128(tmp, ctx->rk_dec[12]);
                tmp = _mm_aesdec_si128(tmp, ctx->rk_dec[13]);
            }
        }
        tmp = _mm_aesdeclast_si128(tmp, ctx->rk_enc[ 0]);

        tmp = _mm_xor_si128(tmp, ivec);

        _mm_storeu_si128((__m128i*) out, tmp);
    }

    return ret;
}


int aes_init (const unsigned char *key, size_t key_size, aes_context_t **ctx) {

    // allocate context...
    *ctx = (aes_context_t*) calloc(1, sizeof(aes_context_t));
    if(!(*ctx))
        return -1;
    // ...and fill her up:

    // initialize data structures

    // check key size and make key size (given in bytes) dependant settings
    switch(key_size) {
        case AES128_KEY_BYTES:    // 128 bit key size
            break;
        case AES192_KEY_BYTES:    // 192 bit key size
            break;
        case AES256_KEY_BYTES:    // 256 bit key size
            break;
        default:
            traceEvent(TRACE_ERROR, "aes_init invalid key size %u\n", key_size);
            return -1;
    }

    // key materiel handling
    aes_internal_key_setup( *ctx, key, 8 * key_size);

    return 0;
}

int aes_deinit (aes_context_t *ctx) {

    if(ctx) free(ctx);

    return 0;
}

#endif // openSSL 1.1, AES-NI, plain C ----------------------------------------------------------------------------
