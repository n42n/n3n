/**
 * (C) 2007-22 - ntop.org and contributors
 * Copyright (C) 2023-25 Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
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


#include <n3n/logging.h> // for traceEvent
#include <stdlib.h>     // for calloc, free, size_t
#include <string.h>     // for memcpy

#include "cc20.h"
#include "config.h"  // HAVE_LIBCRYPTO
#include "portable_endian.h"  // for htole32


#ifdef HAVE_LIBCRYPTO // openSSL 1.1 ---------------------------------------------------------------------


// get any erorr message out of openssl
// taken from https://en.wikibooks.org/wiki/OpenSSL/Error_handling
static char *openssl_err_as_string (void) {

    BIO *bio = BIO_new(BIO_s_mem());
    ERR_print_errors(bio);
    char *buf = NULL;
    size_t len = BIO_get_mem_data(bio, &buf);
    char *ret = (char *)calloc(1, 1 + len);

    if(ret)
        memcpy(ret, buf, len);

    BIO_free(bio);

    return ret;
}


// encryption == decryption
int cc20_crypt (unsigned char *out, const unsigned char *in, size_t in_len,
                const unsigned char *iv, cc20_context_t *ctx) {

    int evp_len;
    int evp_ciphertext_len;

    if(1 == EVP_EncryptInit_ex(ctx->ctx, ctx->cipher, NULL, ctx->key, iv)) {
        if(1 == EVP_CIPHER_CTX_set_padding(ctx->ctx, 0)) {
            if(1 == EVP_EncryptUpdate(ctx->ctx, out, &evp_len, in, in_len)) {
                evp_ciphertext_len = evp_len;
                if(1 == EVP_EncryptFinal_ex(ctx->ctx, out + evp_len, &evp_len)) {
                    evp_ciphertext_len += evp_len;
                    if(evp_ciphertext_len != in_len)
                        traceEvent(TRACE_ERROR, "cc20_crypt openssl encryption: encrypted %u bytes where %u were expected",
                                   evp_ciphertext_len, in_len);
                } else
                    traceEvent(TRACE_ERROR, "cc20_crypt openssl final encryption: %s",
                               openssl_err_as_string());
            } else
                traceEvent(TRACE_ERROR, "cc20_encrypt openssl encrpytion: %s",
                           openssl_err_as_string());
        } else
            traceEvent(TRACE_ERROR, "cc20_encrypt openssl padding setup: %s",
                       openssl_err_as_string());
    } else
        traceEvent(TRACE_ERROR, "cc20_encrypt openssl init: %s",
                   openssl_err_as_string());

    EVP_CIPHER_CTX_reset(ctx->ctx);

    return 0;
}


#elif defined (__AVX512F__)  // AVX512 ------------------------------------------------------------------------------


// same approach as the SSE2 code below, but with four blocks per register: each
// 128 bit lane of a __m512i holds one row of one block, so the same permutes and
// rounds work lane by lane and four blocks are computed at once


#include <immintrin.h>  // for _mm512_xor_si512, _mm512_add_epi32, _mm512_rol_epi32
#include <xmmintrin.h>  // for _MM_SHUFFLE


#define XOR _mm512_xor_si512
#define ADD _mm512_add_epi32
#define ROL(X,r) (_mm512_rol_epi32(X,r))  /* AVX512F rotates, no shift and or needed */

#define ROL8(X)  ROL(X,8)
#define ROL16(X) ROL(X,16)

#define ZERO_TO_THREE _mm512_setr_epi32(0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0)
#define FOUR          _mm512_setr_epi32(4, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0)
#define EIGHT         _mm512_setr_epi32(8, 0, 0, 0, 8, 0, 0, 0, 8, 0, 0, 0, 8, 0, 0, 0)


#define CC20_PERMUTE_ROWS(A,B,C,D)                        \
    B = _mm512_shuffle_epi32(B, _MM_SHUFFLE(0, 3, 2, 1)); \
    C = _mm512_shuffle_epi32(C, _MM_SHUFFLE(1, 0, 3, 2)); \
    D = _mm512_shuffle_epi32(D, _MM_SHUFFLE(2, 1, 0, 3))

#define CC20_PERMUTE_ROWS_INV(A,B,C,D)                    \
    B = _mm512_shuffle_epi32(B, _MM_SHUFFLE(2, 1, 0, 3)); \
    C = _mm512_shuffle_epi32(C, _MM_SHUFFLE(1, 0, 3, 2)); \
    D = _mm512_shuffle_epi32(D, _MM_SHUFFLE(0, 3, 2, 1))

#define CC20_ODD_ROUND(A,B,C,D)            \
    /* odd round */                        \
    A = ADD(A, B); D = ROL16(XOR(D, A));   \
    C = ADD(C, D); B = ROL(XOR(B, C), 12); \
    A = ADD(A, B); D = ROL8(XOR(D, A));    \
    C = ADD(C, D); B = ROL(XOR(B, C),  7)

#define CC20_EVEN_ROUND(A,B,C,D)   \
    CC20_PERMUTE_ROWS(A, B, C, D); \
    CC20_ODD_ROUND(A, B, C, D);    \
    CC20_PERMUTE_ROWS_INV(A, B, C, D)

#define CC20_DOUBLE_ROUND(A,B,C,D) \
    CC20_ODD_ROUND(A, B, C, D);    \
    CC20_EVEN_ROUND(A, B, C, D)

// the four rows of a block sit in the same lane of four registers, gather them
// into one register per block (lane j of K0..K3 becomes block j)
#define CC20_LANES_TO_BLOCKS(K0,K1,K2,K3,B0,B1,B2,B3)    \
    B0 = _mm512_shuffle_i32x4(K0, K1, _MM_SHUFFLE(1, 0, 1, 0)); \
    B1 = _mm512_shuffle_i32x4(K2, K3, _MM_SHUFFLE(1, 0, 1, 0)); \
    B2 = _mm512_shuffle_i32x4(K0, K1, _MM_SHUFFLE(3, 2, 3, 2)); \
    B3 = _mm512_shuffle_i32x4(K2, K3, _MM_SHUFFLE(3, 2, 3, 2)); \
    K0 = _mm512_shuffle_i32x4(B0, B1, _MM_SHUFFLE(2, 0, 2, 0)); \
    K1 = _mm512_shuffle_i32x4(B0, B1, _MM_SHUFFLE(3, 1, 3, 1)); \
    K2 = _mm512_shuffle_i32x4(B2, B3, _MM_SHUFFLE(2, 0, 2, 0)); \
    K3 = _mm512_shuffle_i32x4(B2, B3, _MM_SHUFFLE(3, 1, 3, 1))

#define STOREXOR(O,I,X)                                              \
    _mm512_storeu_si512((__m512i*)O,                                 \
                        _mm512_xor_si512(_mm512_loadu_si512((__m512i*)I), X)); \
    I += 64; O += 64                                                 \

#define STORE(O,X)                          \
    _mm512_storeu_si512((__m512i*)O, X);    \
    O += 64                                 \


int cc20_crypt (unsigned char *out, const unsigned char *in, size_t in_len,
                const unsigned char *iv, cc20_context_t *ctx) {

    __m512i a, b, c, d, k0, k1, k2, k3, k4, k5, k6, k7, t0, t1, t2, t3;

    uint8_t keystream8[256];
    uint8_t *keystream_p;

    const uint8_t *magic_constant = (uint8_t*)"expand 32-byte k";

    a = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)magic_constant));
    b = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(ctx->key)));
    c = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)((ctx->key)+16)));
    d = ADD(_mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)iv)), ZERO_TO_THREE);

    while(in_len >= 512) {
        k0 = a; k1 = b; k2 = c; k3 = d;
        k4 = a; k5 = b; k6 = c; k7 = ADD(d, FOUR);

        // 10 double rounds -- two in parallel to make better use of all registers
        CC20_DOUBLE_ROUND(k0, k1, k2, k3); CC20_DOUBLE_ROUND(k4, k5, k6, k7);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3); CC20_DOUBLE_ROUND(k4, k5, k6, k7);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3); CC20_DOUBLE_ROUND(k4, k5, k6, k7);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3); CC20_DOUBLE_ROUND(k4, k5, k6, k7);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3); CC20_DOUBLE_ROUND(k4, k5, k6, k7);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3); CC20_DOUBLE_ROUND(k4, k5, k6, k7);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3); CC20_DOUBLE_ROUND(k4, k5, k6, k7);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3); CC20_DOUBLE_ROUND(k4, k5, k6, k7);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3); CC20_DOUBLE_ROUND(k4, k5, k6, k7);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3); CC20_DOUBLE_ROUND(k4, k5, k6, k7);

        k0 = ADD(k0, a); k1 = ADD(k1, b); k2 = ADD(k2, c); k3 = ADD(k3, d);
        k4 = ADD(k4, a); k5 = ADD(k5, b); k6 = ADD(k6, c); k7 = ADD(k7, d); k7 = ADD(k7, FOUR);

        CC20_LANES_TO_BLOCKS(k0, k1, k2, k3, t0, t1, t2, t3);
        STOREXOR(out, in, k0); STOREXOR(out, in, k1); STOREXOR(out, in, k2); STOREXOR(out, in, k3);

        CC20_LANES_TO_BLOCKS(k4, k5, k6, k7, t0, t1, t2, t3);
        STOREXOR(out, in, k4); STOREXOR(out, in, k5); STOREXOR(out, in, k6); STOREXOR(out, in, k7);

        // increment counter, make sure it is and stays little endian in memory
        d = ADD(d, EIGHT);

        in_len -= 512;
    }

    while(in_len >= 256) {
        k0 = a; k1 = b; k2 = c; k3 = d;

        // 10 double rounds
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);

        k0 = ADD(k0, a); k1 = ADD(k1, b); k2 = ADD(k2, c); k3 = ADD(k3, d);

        CC20_LANES_TO_BLOCKS(k0, k1, k2, k3, t0, t1, t2, t3);
        STOREXOR(out, in, k0); STOREXOR(out, in, k1); STOREXOR(out, in, k2); STOREXOR(out, in, k3);

        // increment counter, make sure it is and stays little endian in memory
        d = ADD(d, FOUR);

        in_len -= 256;
    }

    if(in_len) {
        k0 = a; k1 = b; k2 = c; k3 = d;

        // 10 double rounds
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);

        k0 = ADD(k0, a); k1 = ADD(k1, b); k2 = ADD(k2, c); k3 = ADD(k3, d);

        CC20_LANES_TO_BLOCKS(k0, k1, k2, k3, t0, t1, t2, t3);

        keystream_p = keystream8;
        STORE(keystream_p, k0); STORE(keystream_p, k1); STORE(keystream_p, k2); STORE(keystream_p, k3);

        // keep in mind that out and in got increased inside the last loop
        // and point to current position now
        while(in_len > 0) {
            in_len--;
            out[in_len] = in[in_len] ^ keystream8[in_len];
        }
    }

    return(0);
}


#elif defined (__AVX2__)  // AVX2 -----------------------------------------------------------------------------------


// same approach as the SSE2 code below, but with two blocks per register: each
// 128 bit lane of a __m256i holds one row of one block, so the same permutes and
// rounds work lane by lane and two blocks are computed at once


#include <immintrin.h>  // for _mm256_xor_si256, _mm256_add_epi32, _mm256_shuffle_epi8
#include <xmmintrin.h>  // for _MM_SHUFFLE


#define SL  _mm256_slli_epi32
#define SR  _mm256_srli_epi32
#define XOR _mm256_xor_si256
#define ADD _mm256_add_epi32
#define ROL(X,r) (XOR(SL(X,r),SR(X,(32-r))))

// AVX2 always has the byte shuffle, so these two rotations are one instruction
#define L8  _mm256_set_epi32(0x0e0d0c0fL, 0x0a09080bL, 0x06050407L, 0x02010003L, \
                             0x0e0d0c0fL, 0x0a09080bL, 0x06050407L, 0x02010003L)
#define L16 _mm256_set_epi32(0x0d0c0f0eL, 0x09080b0aL, 0x05040706L, 0x01000302L, \
                             0x0d0c0f0eL, 0x09080b0aL, 0x05040706L, 0x01000302L)
#define ROL8(X)  (_mm256_shuffle_epi8(X, L8))
#define ROL16(X) (_mm256_shuffle_epi8(X, L16))

#define ZERO_ONE _mm256_setr_epi32(0, 0, 0, 0, 1, 0, 0, 0)
#define TWO      _mm256_setr_epi32(2, 0, 0, 0, 2, 0, 0, 0)
#define FOUR     _mm256_setr_epi32(4, 0, 0, 0, 4, 0, 0, 0)


#define CC20_PERMUTE_ROWS(A,B,C,D)                        \
    B = _mm256_shuffle_epi32(B, _MM_SHUFFLE(0, 3, 2, 1)); \
    C = _mm256_shuffle_epi32(C, _MM_SHUFFLE(1, 0, 3, 2)); \
    D = _mm256_shuffle_epi32(D, _MM_SHUFFLE(2, 1, 0, 3))

#define CC20_PERMUTE_ROWS_INV(A,B,C,D)                    \
    B = _mm256_shuffle_epi32(B, _MM_SHUFFLE(2, 1, 0, 3)); \
    C = _mm256_shuffle_epi32(C, _MM_SHUFFLE(1, 0, 3, 2)); \
    D = _mm256_shuffle_epi32(D, _MM_SHUFFLE(0, 3, 2, 1))

#define CC20_ODD_ROUND(A,B,C,D)            \
    /* odd round */                        \
    A = ADD(A, B); D = ROL16(XOR(D, A));   \
    C = ADD(C, D); B = ROL(XOR(B, C), 12); \
    A = ADD(A, B); D = ROL8(XOR(D, A));    \
    C = ADD(C, D); B = ROL(XOR(B, C),  7)

#define CC20_EVEN_ROUND(A,B,C,D)   \
    CC20_PERMUTE_ROWS(A, B, C, D); \
    CC20_ODD_ROUND(A, B, C, D);    \
    CC20_PERMUTE_ROWS_INV(A, B, C, D)

#define CC20_DOUBLE_ROUND(A,B,C,D) \
    CC20_ODD_ROUND(A, B, C, D);    \
    CC20_EVEN_ROUND(A, B, C, D)

// the four rows of a block sit in the same lane of four registers, gather them
// into two registers per block (low lanes are the first block, high lanes the second)
#define CC20_LANES_TO_BLOCKS(K0,K1,K2,K3,B0,B1,B2,B3)  \
    B0 = _mm256_permute2x128_si256(K0, K1, 0x20);      \
    B1 = _mm256_permute2x128_si256(K2, K3, 0x20);      \
    B2 = _mm256_permute2x128_si256(K0, K1, 0x31);      \
    B3 = _mm256_permute2x128_si256(K2, K3, 0x31);      \
    K0 = B0; K1 = B1; K2 = B2; K3 = B3

#define STOREXOR(O,I,X)                                              \
    _mm256_storeu_si256((__m256i*)O,                                 \
                        _mm256_xor_si256(_mm256_loadu_si256((__m256i*)I), X)); \
    I += 32; O += 32                                                 \

#define STORE(O,X)                          \
    _mm256_storeu_si256((__m256i*)O, X);    \
    O += 32                                 \


int cc20_crypt (unsigned char *out, const unsigned char *in, size_t in_len,
                const unsigned char *iv, cc20_context_t *ctx) {

    __m256i a, b, c, d, k0, k1, k2, k3, k4, k5, k6, k7, t0, t1, t2, t3;

    uint8_t keystream8[128];
    uint8_t *keystream_p;

    const uint8_t *magic_constant = (uint8_t*)"expand 32-byte k";

    a = _mm256_broadcastsi128_si256(_mm_loadu_si128((__m128i*)magic_constant));
    b = _mm256_broadcastsi128_si256(_mm_loadu_si128((__m128i*)(ctx->key)));
    c = _mm256_broadcastsi128_si256(_mm_loadu_si128((__m128i*)((ctx->key)+16)));
    d = ADD(_mm256_broadcastsi128_si256(_mm_loadu_si128((__m128i*)iv)), ZERO_ONE);

    while(in_len >= 256) {
        k0 = a; k1 = b; k2 = c; k3 = d;
        k4 = a; k5 = b; k6 = c; k7 = ADD(d, TWO);

        // 10 double rounds -- two in parallel to make better use of all registers
        CC20_DOUBLE_ROUND(k0, k1, k2, k3); CC20_DOUBLE_ROUND(k4, k5, k6, k7);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3); CC20_DOUBLE_ROUND(k4, k5, k6, k7);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3); CC20_DOUBLE_ROUND(k4, k5, k6, k7);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3); CC20_DOUBLE_ROUND(k4, k5, k6, k7);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3); CC20_DOUBLE_ROUND(k4, k5, k6, k7);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3); CC20_DOUBLE_ROUND(k4, k5, k6, k7);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3); CC20_DOUBLE_ROUND(k4, k5, k6, k7);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3); CC20_DOUBLE_ROUND(k4, k5, k6, k7);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3); CC20_DOUBLE_ROUND(k4, k5, k6, k7);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3); CC20_DOUBLE_ROUND(k4, k5, k6, k7);

        k0 = ADD(k0, a); k1 = ADD(k1, b); k2 = ADD(k2, c); k3 = ADD(k3, d);
        k4 = ADD(k4, a); k5 = ADD(k5, b); k6 = ADD(k6, c); k7 = ADD(k7, d); k7 = ADD(k7, TWO);

        CC20_LANES_TO_BLOCKS(k0, k1, k2, k3, t0, t1, t2, t3);
        STOREXOR(out, in, k0); STOREXOR(out, in, k1); STOREXOR(out, in, k2); STOREXOR(out, in, k3);

        CC20_LANES_TO_BLOCKS(k4, k5, k6, k7, t0, t1, t2, t3);
        STOREXOR(out, in, k4); STOREXOR(out, in, k5); STOREXOR(out, in, k6); STOREXOR(out, in, k7);

        // increment counter, make sure it is and stays little endian in memory
        d = ADD(d, FOUR);

        in_len -= 256;
    }

    while(in_len >= 128) {
        k0 = a; k1 = b; k2 = c; k3 = d;

        // 10 double rounds
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);

        k0 = ADD(k0, a); k1 = ADD(k1, b); k2 = ADD(k2, c); k3 = ADD(k3, d);

        CC20_LANES_TO_BLOCKS(k0, k1, k2, k3, t0, t1, t2, t3);
        STOREXOR(out, in, k0); STOREXOR(out, in, k1); STOREXOR(out, in, k2); STOREXOR(out, in, k3);

        // increment counter, make sure it is and stays little endian in memory
        d = ADD(d, TWO);

        in_len -= 128;
    }

    if(in_len) {
        k0 = a; k1 = b; k2 = c; k3 = d;

        // 10 double rounds
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);

        k0 = ADD(k0, a); k1 = ADD(k1, b); k2 = ADD(k2, c); k3 = ADD(k3, d);

        CC20_LANES_TO_BLOCKS(k0, k1, k2, k3, t0, t1, t2, t3);

        keystream_p = keystream8;
        STORE(keystream_p, k0); STORE(keystream_p, k1); STORE(keystream_p, k2); STORE(keystream_p, k3);

        // keep in mind that out and in got increased inside the last loop
        // and point to current position now
        while(in_len > 0) {
            in_len--;
            out[in_len] = in[in_len] ^ keystream8[in_len];
        }
    }

    return(0);
}


#elif defined (__SSE2__)  // SSE2 ---------------------------------------------------------------------------------


// taken (and heavily modified and enhanced) from
// https://github.com/Ginurx/chacha20-c (public domain)


#include <immintrin.h>  // for _mm_xor_si128, _mm_add_epi32, _mm_slli_epi32
#include <xmmintrin.h>  // for _MM_SHUFFLE


#define SL  _mm_slli_epi32
#define SR  _mm_srli_epi32
#define XOR _mm_xor_si128
#define AND _mm_and_si128
#define ADD _mm_add_epi32
#define ROL(X,r) (XOR(SL(X,r),SR(X,(32-r))))

#define ONE   _mm_setr_epi32(1, 0, 0, 0)
#define TWO   _mm_setr_epi32(2, 0, 0, 0)

#if defined (__SSSE3__) // --- SSSE3

#define L8  _mm_set_epi32(0x0e0d0c0fL, 0x0a09080bL, 0x06050407L, 0x02010003L)
#define L16 _mm_set_epi32(0x0d0c0f0eL, 0x09080b0aL, 0x05040706L, 0x01000302L)
#define ROL8(X)  ( _mm_shuffle_epi8(X, L8))  /* SSSE 3 */
#define ROL16(X) ( _mm_shuffle_epi8(X, L16)) /* SSSE 3 */

#else // --- regular SSE2 ----------

#define ROL8(X)  ROL(X,8)
#define ROL16(X) ROL(X,16)

#endif // --------------------------


#define CC20_PERMUTE_ROWS(A,B,C,D)                     \
    B = _mm_shuffle_epi32(B, _MM_SHUFFLE(0, 3, 2, 1)); \
    C = _mm_shuffle_epi32(C, _MM_SHUFFLE(1, 0, 3, 2)); \
    D = _mm_shuffle_epi32(D, _MM_SHUFFLE(2, 1, 0, 3))

#define CC20_PERMUTE_ROWS_INV(A,B,C,D)                 \
    B = _mm_shuffle_epi32(B, _MM_SHUFFLE(2, 1, 0, 3)); \
    C = _mm_shuffle_epi32(C, _MM_SHUFFLE(1, 0, 3, 2)); \
    D = _mm_shuffle_epi32(D, _MM_SHUFFLE(0, 3, 2, 1))

#define CC20_ODD_ROUND(A,B,C,D)            \
    /* odd round */                        \
    A = ADD(A, B); D = ROL16(XOR(D, A));   \
    C = ADD(C, D); B = ROL(XOR(B, C), 12); \
    A = ADD(A, B); D = ROL8(XOR(D, A));    \
    C = ADD(C, D); B = ROL(XOR(B, C),  7)

#define CC20_EVEN_ROUND(A,B,C,D)       \
    CC20_PERMUTE_ROWS(A, B, C, D); \
    CC20_ODD_ROUND(A, B, C, D); \
    CC20_PERMUTE_ROWS_INV(A, B, C, D)

#define CC20_DOUBLE_ROUND(A,B,C,D)   \
    CC20_ODD_ROUND(A, B, C, D);     \
    CC20_EVEN_ROUND(A, B, C, D)

#define STOREXOR(O,I,X)                                                \
    _mm_storeu_si128((__m128i*)O,                                      \
                     _mm_xor_si128(_mm_loadu_si128((__m128i*)I), X)); \
    I += 16; O += 16                                                   \


int cc20_crypt (unsigned char *out, const unsigned char *in, size_t in_len,
                const unsigned char *iv, cc20_context_t *ctx) {

    __m128i a, b, c, d, k0, k1, k2, k3, k4, k5, k6, k7;

    uint8_t   *keystream8 = (uint8_t*)ctx->keystream32;

    const uint8_t *magic_constant = (uint8_t*)"expand 32-byte k";

    a = _mm_loadu_si128((__m128i*)magic_constant);
    b = _mm_loadu_si128((__m128i*)(ctx->key));
    c = _mm_loadu_si128( (__m128i*)((ctx->key)+16));
    d = _mm_loadu_si128((__m128i*)iv);

    while(in_len >= 128) {
        k0 = a; k1 = b; k2 = c; k3 = d;
        k4 = a; k5 = b; k6 = c; k7 = ADD(d, ONE);

        // 10 double rounds -- two in parallel to make better use of all 8 SSE registers
        CC20_DOUBLE_ROUND(k0, k1, k2, k3); CC20_DOUBLE_ROUND(k4, k5, k6, k7);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3); CC20_DOUBLE_ROUND(k4, k5, k6, k7);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3); CC20_DOUBLE_ROUND(k4, k5, k6, k7);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3); CC20_DOUBLE_ROUND(k4, k5, k6, k7);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3); CC20_DOUBLE_ROUND(k4, k5, k6, k7);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3); CC20_DOUBLE_ROUND(k4, k5, k6, k7);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3); CC20_DOUBLE_ROUND(k4, k5, k6, k7);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3); CC20_DOUBLE_ROUND(k4, k5, k6, k7);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3); CC20_DOUBLE_ROUND(k4, k5, k6, k7);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3); CC20_DOUBLE_ROUND(k4, k5, k6, k7);

        k0 = ADD(k0, a); k1 = ADD(k1, b); k2 = ADD(k2, c); k3 = ADD(k3, d);
        k4 = ADD(k4, a); k5 = ADD(k5, b); k6 = ADD(k6, c); k7 = ADD(k7, d); k7 = ADD(k7, ONE);

        STOREXOR(out, in, k0); STOREXOR(out, in, k1); STOREXOR(out, in, k2); STOREXOR(out, in, k3);
        STOREXOR(out, in, k4); STOREXOR(out, in, k5); STOREXOR(out, in, k6); STOREXOR(out, in, k7);

        // increment counter, make sure it is and stays little endian in memory
        d = ADD(d, TWO);

        in_len -= 128;
    }

    if(in_len >= 64) {
        k0 = a; k1 = b; k2 = c; k3 = d;

        // 10 double rounds
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);

        k0 = ADD(k0, a); k1 = ADD(k1, b); k2 = ADD(k2, c); k3 = ADD(k3, d);

        STOREXOR(out, in, k0); STOREXOR(out, in, k1); STOREXOR(out, in, k2); STOREXOR(out, in, k3);

        // increment counter, make sure it is and stays little endian in memory
        d = ADD(d, ONE);

        in_len -= 64;
    }

    if(in_len) {
        k0 = a; k1 = b; k2 = c; k3 = d;

        // 10 double rounds
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);

        k0 = ADD(k0, a); k1 = ADD(k1, b); k2 = ADD(k2, c); k3 = ADD(k3, d);

        _mm_storeu_si128((__m128i*)&(ctx->keystream32[ 0]), k0);
        _mm_storeu_si128((__m128i*)&(ctx->keystream32[ 4]), k1);
        _mm_storeu_si128((__m128i*)&(ctx->keystream32[ 8]), k2);
        _mm_storeu_si128((__m128i*)&(ctx->keystream32[12]), k3);

        // keep in mind that out and in got increased inside the last loop
        // and point to current position now
        while(in_len > 0) {
            in_len--;
            out[in_len] = in[in_len] ^ keystream8[in_len];
        }
    }

    return(0);
}


#else // plain C --------------------------------------------------------------------------------------------------


// taken (and modified) from https://github.com/Ginurx/chacha20-c (public domain)


static void cc20_init_block (cc20_context_t *ctx, const uint8_t nonce[]) {

    const uint8_t *magic_constant = (uint8_t*)"expand 32-byte k";

    memcpy(&(ctx->state[ 0]), magic_constant, 16);
    memcpy(&(ctx->state[ 4]), ctx->key, CC20_KEY_BYTES);
    memcpy(&(ctx->state[12]), nonce, CC20_IV_SIZE);
}


#define ROL32(x,r) (((x)<<(r))|((x)>>(32-(r))))

#define CC20_QUARTERROUND(x, a, b, c, d)         \
    x[a] += x[b]; x[d] = ROL32(x[d] ^ x[a], 16); \
    x[c] += x[d]; x[b] = ROL32(x[b] ^ x[c], 12); \
    x[a] += x[b]; x[d] = ROL32(x[d] ^ x[a],  8); \
    x[c] += x[d]; x[b] = ROL32(x[b] ^ x[c],  7)

#define CC20_DOUBLE_ROUND(s)            \
    /* odd round */                     \
    CC20_QUARTERROUND(s, 0, 4,  8, 12); \
    CC20_QUARTERROUND(s, 1, 5,  9, 13); \
    CC20_QUARTERROUND(s, 2, 6, 10, 14); \
    CC20_QUARTERROUND(s, 3, 7, 11, 15); \
    /* even round */                    \
    CC20_QUARTERROUND(s, 0, 5, 10, 15); \
    CC20_QUARTERROUND(s, 1, 6, 11, 12); \
    CC20_QUARTERROUND(s, 2, 7,  8, 13); \
    CC20_QUARTERROUND(s, 3, 4,  9, 14)


static void cc20_block_next (cc20_context_t *ctx) {

    uint32_t *counter = ctx->state + 12;

    ctx->keystream32[ 0] = ctx->state[ 0];
    ctx->keystream32[ 1] = ctx->state[ 1];
    ctx->keystream32[ 2] = ctx->state[ 2];
    ctx->keystream32[ 3] = ctx->state[ 3];
    ctx->keystream32[ 4] = ctx->state[ 4];
    ctx->keystream32[ 5] = ctx->state[ 5];
    ctx->keystream32[ 6] = ctx->state[ 6];
    ctx->keystream32[ 7] = ctx->state[ 7];
    ctx->keystream32[ 8] = ctx->state[ 8];
    ctx->keystream32[ 9] = ctx->state[ 9];
    ctx->keystream32[10] = ctx->state[10];
    ctx->keystream32[11] = ctx->state[11];
    ctx->keystream32[12] = ctx->state[12];
    ctx->keystream32[13] = ctx->state[13];
    ctx->keystream32[14] = ctx->state[14];
    ctx->keystream32[15] = ctx->state[15];

    // 10 double rounds
    CC20_DOUBLE_ROUND(ctx->keystream32);
    CC20_DOUBLE_ROUND(ctx->keystream32);
    CC20_DOUBLE_ROUND(ctx->keystream32);
    CC20_DOUBLE_ROUND(ctx->keystream32);
    CC20_DOUBLE_ROUND(ctx->keystream32);
    CC20_DOUBLE_ROUND(ctx->keystream32);
    CC20_DOUBLE_ROUND(ctx->keystream32);
    CC20_DOUBLE_ROUND(ctx->keystream32);
    CC20_DOUBLE_ROUND(ctx->keystream32);
    CC20_DOUBLE_ROUND(ctx->keystream32);

    ctx->keystream32[ 0] += ctx->state[ 0];
    ctx->keystream32[ 1] += ctx->state[ 1];
    ctx->keystream32[ 2] += ctx->state[ 2];
    ctx->keystream32[ 3] += ctx->state[ 3];
    ctx->keystream32[ 4] += ctx->state[ 4];
    ctx->keystream32[ 5] += ctx->state[ 5];
    ctx->keystream32[ 6] += ctx->state[ 6];
    ctx->keystream32[ 7] += ctx->state[ 7];
    ctx->keystream32[ 8] += ctx->state[ 8];
    ctx->keystream32[ 9] += ctx->state[ 9];
    ctx->keystream32[10] += ctx->state[10];
    ctx->keystream32[11] += ctx->state[11];
    ctx->keystream32[12] += ctx->state[12];
    ctx->keystream32[13] += ctx->state[13];
    ctx->keystream32[14] += ctx->state[14];
    ctx->keystream32[15] += ctx->state[15];

    // increment counter, make sure it is and stays little endian in memory
    *counter = htole32(le32toh(*counter)+1);
}


static void cc20_init_context (cc20_context_t *ctx, const uint8_t *nonce) {

    cc20_init_block(ctx, nonce);
}


int cc20_crypt (unsigned char *out, const unsigned char *in, size_t in_len,
                const unsigned char *iv, cc20_context_t *ctx) {

    uint8_t   *keystream8 = (uint8_t*)ctx->keystream32;
    uint32_t * in_p       = (uint32_t*)in;
    uint32_t * out_p      = (uint32_t*)out;
    size_t tmp_len      = in_len;

    cc20_init_context(ctx, iv);

    while(in_len >= 64) {
        cc20_block_next(ctx);

        *(uint32_t*)out_p = *(uint32_t*)in_p ^ ctx->keystream32[ 0]; in_p++; out_p++;
        *(uint32_t*)out_p = *(uint32_t*)in_p ^ ctx->keystream32[ 1]; in_p++; out_p++;
        *(uint32_t*)out_p = *(uint32_t*)in_p ^ ctx->keystream32[ 2]; in_p++; out_p++;
        *(uint32_t*)out_p = *(uint32_t*)in_p ^ ctx->keystream32[ 3]; in_p++; out_p++;
        *(uint32_t*)out_p = *(uint32_t*)in_p ^ ctx->keystream32[ 4]; in_p++; out_p++;
        *(uint32_t*)out_p = *(uint32_t*)in_p ^ ctx->keystream32[ 5]; in_p++; out_p++;
        *(uint32_t*)out_p = *(uint32_t*)in_p ^ ctx->keystream32[ 6]; in_p++; out_p++;
        *(uint32_t*)out_p = *(uint32_t*)in_p ^ ctx->keystream32[ 7]; in_p++; out_p++;
        *(uint32_t*)out_p = *(uint32_t*)in_p ^ ctx->keystream32[ 8]; in_p++; out_p++;
        *(uint32_t*)out_p = *(uint32_t*)in_p ^ ctx->keystream32[ 9]; in_p++; out_p++;
        *(uint32_t*)out_p = *(uint32_t*)in_p ^ ctx->keystream32[10]; in_p++; out_p++;
        *(uint32_t*)out_p = *(uint32_t*)in_p ^ ctx->keystream32[11]; in_p++; out_p++;
        *(uint32_t*)out_p = *(uint32_t*)in_p ^ ctx->keystream32[12]; in_p++; out_p++;
        *(uint32_t*)out_p = *(uint32_t*)in_p ^ ctx->keystream32[13]; in_p++; out_p++;
        *(uint32_t*)out_p = *(uint32_t*)in_p ^ ctx->keystream32[14]; in_p++; out_p++;
        *(uint32_t*)out_p = *(uint32_t*)in_p ^ ctx->keystream32[15]; in_p++; out_p++;

        in_len -= 64;
    }

    if(in_len > 0) {
        cc20_block_next(ctx);

        tmp_len -= in_len;
        while(in_len > 0) {
            out[tmp_len] = in[tmp_len] ^ keystream8[tmp_len%64];
            tmp_len++;
            in_len--;
        }
    }

    return(0);
}


#endif // openSSL 1.1, plain C ------------------------------------------------------------------------------------


int cc20_init (const unsigned char *key, cc20_context_t **ctx) {

    // allocate context...
    *ctx = (cc20_context_t*)calloc(1, sizeof(cc20_context_t));
    if(!(*ctx))
        return -1;
#ifdef HAVE_LIBCRYPTO
    if(!((*ctx)->ctx = EVP_CIPHER_CTX_new())) {
        traceEvent(TRACE_ERROR, "cc20_init openssl's evp_* encryption context creation failed: %s",
                   openssl_err_as_string());
        return -1;
    }

    (*ctx)->cipher = EVP_chacha20();
#endif
    memcpy((*ctx)->key, key, CC20_KEY_BYTES);

    return 0;
}


int cc20_deinit (cc20_context_t *ctx) {

#ifdef HAVE_LIBCRYPTO
    if(ctx->ctx) EVP_CIPHER_CTX_free(ctx->ctx);
#endif
    free(ctx);
    return 0;
}
