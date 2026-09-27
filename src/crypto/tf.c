/**
 * (C) 2007-22 - ntop.org and contributors
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


// taken (and modified) from github/fudanchii/twofish as of August 2020
// which itself is a modified copy of Andrew T. Csillag's implementation
// published on github/drewcsillag/twofish


/**
 * The MIT License (MIT)
 *
 * Copyright (c) 2015 Andrew T. Csillag
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */


#include "tf.h"
#include "portable_endian.h"  // for le32toh, htole32
#include <string.h>  // for memcpy


const uint8_t RS[4][8] = { { 0x01, 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E, },
                           { 0xA4, 0x56, 0x82, 0xF3, 0x1E, 0xC6, 0x68, 0xE5, },
                           { 0x02, 0xA1, 0xFC, 0xC1, 0x47, 0xAE, 0x3D, 0x19, },
                           { 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E, 0x03  } };

const uint8_t Q0[] = { 0xA9, 0x67, 0xB3, 0xE8, 0x04, 0xFD, 0xA3, 0x76, 0x9A, 0x92, 0x80, 0x78, 0xE4, 0xDD, 0xD1, 0x38,
                       0x0D, 0xC6, 0x35, 0x98, 0x18, 0xF7, 0xEC, 0x6C, 0x43, 0x75, 0x37, 0x26, 0xFA, 0x13, 0x94, 0x48,
                       0xF2, 0xD0, 0x8B, 0x30, 0x84, 0x54, 0xDF, 0x23, 0x19, 0x5B, 0x3D, 0x59, 0xF3, 0xAE, 0xA2, 0x82,
                       0x63, 0x01, 0x83, 0x2E, 0xD9, 0x51, 0x9B, 0x7C, 0xA6, 0xEB, 0xA5, 0xBE, 0x16, 0x0C, 0xE3, 0x61,
                       0xC0, 0x8C, 0x3A, 0xF5, 0x73, 0x2C, 0x25, 0x0B, 0xBB, 0x4E, 0x89, 0x6B, 0x53, 0x6A, 0xB4, 0xF1,
                       0xE1, 0xE6, 0xBD, 0x45, 0xE2, 0xF4, 0xB6, 0x66, 0xCC, 0x95, 0x03, 0x56, 0xD4, 0x1C, 0x1E, 0xD7,
                       0xFB, 0xC3, 0x8E, 0xB5, 0xE9, 0xCF, 0xBF, 0xBA, 0xEA, 0x77, 0x39, 0xAF, 0x33, 0xC9, 0x62, 0x71,
                       0x81, 0x79, 0x09, 0xAD, 0x24, 0xCD, 0xF9, 0xD8, 0xE5, 0xC5, 0xB9, 0x4D, 0x44, 0x08, 0x86, 0xE7,
                       0xA1, 0x1D, 0xAA, 0xED, 0x06, 0x70, 0xB2, 0xD2, 0x41, 0x7B, 0xA0, 0x11, 0x31, 0xC2, 0x27, 0x90,
                       0x20, 0xF6, 0x60, 0xFF, 0x96, 0x5C, 0xB1, 0xAB, 0x9E, 0x9C, 0x52, 0x1B, 0x5F, 0x93, 0x0A, 0xEF,
                       0x91, 0x85, 0x49, 0xEE, 0x2D, 0x4F, 0x8F, 0x3B, 0x47, 0x87, 0x6D, 0x46, 0xD6, 0x3E, 0x69, 0x64,
                       0x2A, 0xCE, 0xCB, 0x2F, 0xFC, 0x97, 0x05, 0x7A, 0xAC, 0x7F, 0xD5, 0x1A, 0x4B, 0x0E, 0xA7, 0x5A,
                       0x28, 0x14, 0x3F, 0x29, 0x88, 0x3C, 0x4C, 0x02, 0xB8, 0xDA, 0xB0, 0x17, 0x55, 0x1F, 0x8A, 0x7D,
                       0x57, 0xC7, 0x8D, 0x74, 0xB7, 0xC4, 0x9F, 0x72, 0x7E, 0x15, 0x22, 0x12, 0x58, 0x07, 0x99, 0x34,
                       0x6E, 0x50, 0xDE, 0x68, 0x65, 0xBC, 0xDB, 0xF8, 0xC8, 0xA8, 0x2B, 0x40, 0xDC, 0xFE, 0x32, 0xA4,
                       0xCA, 0x10, 0x21, 0xF0, 0xD3, 0x5D, 0x0F, 0x00, 0x6F, 0x9D, 0x36, 0x42, 0x4A, 0x5E, 0xC1, 0xE0 };

const uint8_t Q1[] = { 0x75, 0xF3, 0xC6, 0xF4, 0xDB, 0x7B, 0xFB, 0xC8, 0x4A, 0xD3, 0xE6, 0x6B, 0x45, 0x7D, 0xE8, 0x4B,
                       0xD6, 0x32, 0xD8, 0xFD, 0x37, 0x71, 0xF1, 0xE1, 0x30, 0x0F, 0xF8, 0x1B, 0x87, 0xFA, 0x06, 0x3F,
                       0x5E, 0xBA, 0xAE, 0x5B, 0x8A, 0x00, 0xBC, 0x9D, 0x6D, 0xC1, 0xB1, 0x0E, 0x80, 0x5D, 0xD2, 0xD5,
                       0xA0, 0x84, 0x07, 0x14, 0xB5, 0x90, 0x2C, 0xA3, 0xB2, 0x73, 0x4C, 0x54, 0x92, 0x74, 0x36, 0x51,
                       0x38, 0xB0, 0xBD, 0x5A, 0xFC, 0x60, 0x62, 0x96, 0x6C, 0x42, 0xF7, 0x10, 0x7C, 0x28, 0x27, 0x8C,
                       0x13, 0x95, 0x9C, 0xC7, 0x24, 0x46, 0x3B, 0x70, 0xCA, 0xE3, 0x85, 0xCB, 0x11, 0xD0, 0x93, 0xB8,
                       0xA6, 0x83, 0x20, 0xFF, 0x9F, 0x77, 0xC3, 0xCC, 0x03, 0x6F, 0x08, 0xBF, 0x40, 0xE7, 0x2B, 0xE2,
                       0x79, 0x0C, 0xAA, 0x82, 0x41, 0x3A, 0xEA, 0xB9, 0xE4, 0x9A, 0xA4, 0x97, 0x7E, 0xDA, 0x7A, 0x17,
                       0x66, 0x94, 0xA1, 0x1D, 0x3D, 0xF0, 0xDE, 0xB3, 0x0B, 0x72, 0xA7, 0x1C, 0xEF, 0xD1, 0x53, 0x3E,
                       0x8F, 0x33, 0x26, 0x5F, 0xEC, 0x76, 0x2A, 0x49, 0x81, 0x88, 0xEE, 0x21, 0xC4, 0x1A, 0xEB, 0xD9,
                       0xC5, 0x39, 0x99, 0xCD, 0xAD, 0x31, 0x8B, 0x01, 0x18, 0x23, 0xDD, 0x1F, 0x4E, 0x2D, 0xF9, 0x48,
                       0x4F, 0xF2, 0x65, 0x8E, 0x78, 0x5C, 0x58, 0x19, 0x8D, 0xE5, 0x98, 0x57, 0x67, 0x7F, 0x05, 0x64,
                       0xAF, 0x63, 0xB6, 0xFE, 0xF5, 0xB7, 0x3C, 0xA5, 0xCE, 0xE9, 0x68, 0x44, 0xE0, 0x4D, 0x43, 0x69,
                       0x29, 0x2E, 0xAC, 0x15, 0x59, 0xA8, 0x0A, 0x9E, 0x6E, 0x47, 0xDF, 0x34, 0x35, 0x6A, 0xCF, 0xDC,
                       0x22, 0xC9, 0xC0, 0x9B, 0x89, 0xD4, 0xED, 0xAB, 0x12, 0xA2, 0x0D, 0x52, 0xBB, 0x02, 0x2F, 0xA9,
                       0xD7, 0x61, 0x1E, 0xB4, 0x50, 0x04, 0xF6, 0xC2, 0x16, 0x25, 0x86, 0x56, 0x55, 0x09, 0xBE, 0x91 };

const uint8_t mult5B[] = { 0x00, 0x5B, 0xB6, 0xED, 0x05, 0x5E, 0xB3, 0xE8, 0x0A, 0x51, 0xBC, 0xE7, 0x0F, 0x54, 0xB9, 0xE2,
                           0x14, 0x4F, 0xA2, 0xF9, 0x11, 0x4A, 0xA7, 0xFC, 0x1E, 0x45, 0xA8, 0xF3, 0x1B, 0x40, 0xAD, 0xF6,
                           0x28, 0x73, 0x9E, 0xC5, 0x2D, 0x76, 0x9B, 0xC0, 0x22, 0x79, 0x94, 0xCF, 0x27, 0x7C, 0x91, 0xCA,
                           0x3C, 0x67, 0x8A, 0xD1, 0x39, 0x62, 0x8F, 0xD4, 0x36, 0x6D, 0x80, 0xDB, 0x33, 0x68, 0x85, 0xDE,
                           0x50, 0x0B, 0xE6, 0xBD, 0x55, 0x0E, 0xE3, 0xB8, 0x5A, 0x01, 0xEC, 0xB7, 0x5F, 0x04, 0xE9, 0xB2,
                           0x44, 0x1F, 0xF2, 0xA9, 0x41, 0x1A, 0xF7, 0xAC, 0x4E, 0x15, 0xF8, 0xA3, 0x4B, 0x10, 0xFD, 0xA6,
                           0x78, 0x23, 0xCE, 0x95, 0x7D, 0x26, 0xCB, 0x90, 0x72, 0x29, 0xC4, 0x9F, 0x77, 0x2C, 0xC1, 0x9A,
                           0x6C, 0x37, 0xDA, 0x81, 0x69, 0x32, 0xDF, 0x84, 0x66, 0x3D, 0xD0, 0x8B, 0x63, 0x38, 0xD5, 0x8E,
                           0xA0, 0xFB, 0x16, 0x4D, 0xA5, 0xFE, 0x13, 0x48, 0xAA, 0xF1, 0x1C, 0x47, 0xAF, 0xF4, 0x19, 0x42,
                           0xB4, 0xEF, 0x02, 0x59, 0xB1, 0xEA, 0x07, 0x5C, 0xBE, 0xE5, 0x08, 0x53, 0xBB, 0xE0, 0x0D, 0x56,
                           0x88, 0xD3, 0x3E, 0x65, 0x8D, 0xD6, 0x3B, 0x60, 0x82, 0xD9, 0x34, 0x6F, 0x87, 0xDC, 0x31, 0x6A,
                           0x9C, 0xC7, 0x2A, 0x71, 0x99, 0xC2, 0x2F, 0x74, 0x96, 0xCD, 0x20, 0x7B, 0x93, 0xC8, 0x25, 0x7E,
                           0xF0, 0xAB, 0x46, 0x1D, 0xF5, 0xAE, 0x43, 0x18, 0xFA, 0xA1, 0x4C, 0x17, 0xFF, 0xA4, 0x49, 0x12,
                           0xE4, 0xBF, 0x52, 0x09, 0xE1, 0xBA, 0x57, 0x0C, 0xEE, 0xB5, 0x58, 0x03, 0xEB, 0xB0, 0x5D, 0x06,
                           0xD8, 0x83, 0x6E, 0x35, 0xDD, 0x86, 0x6B, 0x30, 0xD2, 0x89, 0x64, 0x3F, 0xD7, 0x8C, 0x61, 0x3A,
                           0xCC, 0x97, 0x7A, 0x21, 0xC9, 0x92, 0x7F, 0x24, 0xC6, 0x9D, 0x70, 0x2B, 0xC3, 0x98, 0x75, 0x2E };

const uint8_t multEF[] = { 0x00, 0xEF, 0xB7, 0x58, 0x07, 0xE8, 0xB0, 0x5F, 0x0E, 0xE1, 0xB9, 0x56, 0x09, 0xE6, 0xBE, 0x51,
                           0x1C, 0xF3, 0xAB, 0x44, 0x1B, 0xF4, 0xAC, 0x43, 0x12, 0xFD, 0xA5, 0x4A, 0x15, 0xFA, 0xA2, 0x4D,
                           0x38, 0xD7, 0x8F, 0x60, 0x3F, 0xD0, 0x88, 0x67, 0x36, 0xD9, 0x81, 0x6E, 0x31, 0xDE, 0x86, 0x69,
                           0x24, 0xCB, 0x93, 0x7C, 0x23, 0xCC, 0x94, 0x7B, 0x2A, 0xC5, 0x9D, 0x72, 0x2D, 0xC2, 0x9A, 0x75,
                           0x70, 0x9F, 0xC7, 0x28, 0x77, 0x98, 0xC0, 0x2F, 0x7E, 0x91, 0xC9, 0x26, 0x79, 0x96, 0xCE, 0x21,
                           0x6C, 0x83, 0xDB, 0x34, 0x6B, 0x84, 0xDC, 0x33, 0x62, 0x8D, 0xD5, 0x3A, 0x65, 0x8A, 0xD2, 0x3D,
                           0x48, 0xA7, 0xFF, 0x10, 0x4F, 0xA0, 0xF8, 0x17, 0x46, 0xA9, 0xF1, 0x1E, 0x41, 0xAE, 0xF6, 0x19,
                           0x54, 0xBB, 0xE3, 0x0C, 0x53, 0xBC, 0xE4, 0x0B, 0x5A, 0xB5, 0xED, 0x02, 0x5D, 0xB2, 0xEA, 0x05,
                           0xE0, 0x0F, 0x57, 0xB8, 0xE7, 0x08, 0x50, 0xBF, 0xEE, 0x01, 0x59, 0xB6, 0xE9, 0x06, 0x5E, 0xB1,
                           0xFC, 0x13, 0x4B, 0xA4, 0xFB, 0x14, 0x4C, 0xA3, 0xF2, 0x1D, 0x45, 0xAA, 0xF5, 0x1A, 0x42, 0xAD,
                           0xD8, 0x37, 0x6F, 0x80, 0xDF, 0x30, 0x68, 0x87, 0xD6, 0x39, 0x61, 0x8E, 0xD1, 0x3E, 0x66, 0x89,
                           0xC4, 0x2B, 0x73, 0x9C, 0xC3, 0x2C, 0x74, 0x9B, 0xCA, 0x25, 0x7D, 0x92, 0xCD, 0x22, 0x7A, 0x95,
                           0x90, 0x7F, 0x27, 0xC8, 0x97, 0x78, 0x20, 0xCF, 0x9E, 0x71, 0x29, 0xC6, 0x99, 0x76, 0x2E, 0xC1,
                           0x8C, 0x63, 0x3B, 0xD4, 0x8B, 0x64, 0x3C, 0xD3, 0x82, 0x6D, 0x35, 0xDA, 0x85, 0x6A, 0x32, 0xDD,
                           0xA8, 0x47, 0x1F, 0xF0, 0xAF, 0x40, 0x18, 0xF7, 0xA6, 0x49, 0x11, 0xFE, 0xA1, 0x4E, 0x16, 0xF9,
                           0xB4, 0x5B, 0x03, 0xEC, 0xB3, 0x5C, 0x04, 0xEB, 0xBA, 0x55, 0x0D, 0xE2, 0xBD, 0x52, 0x0A, 0xE5 };


#define RS_MOD 0x14D
#define RHO 0x01010101L

#define ROL(x,n) (((x) << ((n) & 0x1F)) | ((x) >> (32-((n) & 0x1F))))
#define ROR(x,n) (((x) >> ((n) & 0x1F)) | ((x) << (32-((n) & 0x1F))))

#define _b(x, N) (((x) >> (N*8)) & 0xFF)

#define b0(x) ((uint8_t)(x))
#define b1(x) ((uint8_t)((x) >> 8))
#define b2(x) ((uint8_t)((x) >> 16))
#define b3(x) ((uint8_t)((x) >> 24))

#define U8ARRAY_TO_U32(r) ((r[0] << 24) ^ (r[1] << 16) ^ (r[2] << 8) ^ r[3])
#define U8S_TO_U32(r0, r1, r2, r3) ((r0 << 24) ^ (r1 << 16) ^ (r2 << 8) ^ r3)


// The block functions below work on blocks of TF_BLOCK_WORDS host-aligned 32-bit
// words, holding the block in wire (little endian) order. Callers copy whole blocks
// in and out of their own buffers, so nothing here depends on the alignment of the
// caller's packet buffer and no word is accessed through a cast.

#define TF_BLOCK_WORDS (TF_BLOCK_SIZE / 4)

// whiten one input word
#define WHITEN_IN(dst, src, key) ((dst) = le32toh(src) ^ (key))

// whiten one output word
#define WHITEN_OUT(dst, val, key) ((dst) = htole32((val) ^ (key)))

// whiten one output word and chain it with the preceding cipher text word. The
// chaining value is not byteswapped: XOR commutes with a byteswap.
#define WHITEN_CHAIN_OUT(dst, val, key, iv) ((dst) = htole32((val) ^ (key)) ^ (iv))

// read and write one 32 bit word through a buffer of unknown alignment.
// memcpy() with a constant size is the portable way of saying "reinterpret
// these four bytes"; gcc and clang both emit a single mov for it, so this
// costs nothing at runtime and is the only spelling that is not undefined
// behaviour on a uint8_t* that may be unaligned
static inline uint32_t tf_load32 (const void *src) {

    uint32_t v;

    memcpy(&v, src, sizeof(v));

    return v;
}

static inline void tf_store32 (void *dst, uint32_t v) {

    memcpy(dst, &v, sizeof(v));
}

// whiten one output word, chain it and store it straight into the output
// buffer, so that it never has to visit the stack
#define WHITEN_CHAIN_STORE(dst, val, key, iv) tf_store32(dst, htole32((val) ^ (key)) ^ (iv))

// multiply two polynomials represented as u32's, actually called with bytes
uint32_t polyMult (uint32_t a, uint32_t b) {

    uint32_t t=0;

    while(a) {
        if(a & 1)
            t^=b;
        b <<= 1;
        a >>= 1;
    }

    return t;
}


// take the polynomial t and return the t % modulus in GF(256)
uint32_t gfMod (uint32_t t, uint32_t modulus) {

    int i;
    uint32_t tt;

    modulus <<= 7;
    for(i = 0; i < 8; i++) {
        tt = t ^ modulus;
        if(tt < t)
            t = tt;
        modulus >>= 1;
    }

    return t;
}


// multiply a and b and return the modulus
#define gfMult(a, b, modulus) gfMod(polyMult(a, b), modulus)


// return a u32 containing the result of multiplying the RS Code matrix by the sd matrix
uint32_t RSMatrixMultiply (uint8_t sd[8]) {

    int j, k;
    uint8_t t;
    uint8_t result[4];

    for(j = 0; j < 4; j++) {
        t = 0;
        for(k = 0; k < 8; k++) {
            t ^= gfMult(RS[j][k], sd[k], RS_MOD);
        }
        result[3-j] = t;
    }

    return U8ARRAY_TO_U32(result);
}


// the Zero-keyed h function (used by the key setup routine)
uint32_t h (uint32_t X, uint32_t L[4], int k) {

    uint8_t y0, y1, y2, y3;
    uint8_t z0, z1, z2, z3;

    y0 = b0(X);
    y1 = b1(X);
    y2 = b2(X);
    y3 = b3(X);

    switch(k) {
        case 4:
            y0 = Q1[y0] ^ b0(L[3]);
            y1 = Q0[y1] ^ b1(L[3]);
            y2 = Q0[y2] ^ b2(L[3]);
            y3 = Q1[y3] ^ b3(L[3]);
        case 3:
            y0 = Q1[y0] ^ b0(L[2]);
            y1 = Q1[y1] ^ b1(L[2]);
            y2 = Q0[y2] ^ b2(L[2]);
            y3 = Q0[y3] ^ b3(L[2]);
        case 2:
            y0 = Q1[  Q0 [ Q0[y0] ^ b0(L[1]) ] ^ b0(L[0]) ];
            y1 = Q0[  Q0 [ Q1[y1] ^ b1(L[1]) ] ^ b1(L[0]) ];
            y2 = Q1[  Q1 [ Q0[y2] ^ b2(L[1]) ] ^ b2(L[0]) ];
            y3 = Q0[  Q1 [ Q1[y3] ^ b3(L[1]) ] ^ b3(L[0]) ];
    }

    // inline the MDS matrix multiply
    z0 = multEF[y0] ^ y1 ^         multEF[y2] ^ mult5B[y3];
    z1 = multEF[y0] ^ mult5B[y1] ^ y2 ^         multEF[y3];
    z2 = mult5B[y0] ^ multEF[y1] ^ multEF[y2] ^ y3;
    z3 = y0 ^         multEF[y1] ^ mult5B[y2] ^ mult5B[y3];

    return U8S_TO_U32(z0, z1, z2, z3);
}


// given the Sbox keys, create the fully keyed QF and the keyed byte S-boxes SB
void fullKey (uint32_t L[4], int k, uint32_t QF[4][256], uint8_t SB[4][256]) {

    uint8_t y0, y1, y2, y3;
    int i;

    // for all input values to the Q permutations
    for(i = 0; i < 256; i++) {
        // run the Q permutations
        y0 = i; y1 = i; y2 = i; y3 = i;
        switch(k) {
            case 4:
                y0 = Q1[y0] ^ b0(L[3]);
                y1 = Q0[y1] ^ b1(L[3]);
                y2 = Q0[y2] ^ b2(L[3]);
                y3 = Q1[y3] ^ b3(L[3]);
            case 3:
                y0 = Q1[y0] ^ b0(L[2]);
                y1 = Q1[y1] ^ b1(L[2]);
                y2 = Q0[y2] ^ b2(L[2]);
                y3 = Q0[y3] ^ b3(L[2]);
            case 2:
                y0 = Q1[  Q0 [ Q0[y0] ^ b0(L[1]) ] ^ b0(L[0]) ];
                y1 = Q0[  Q0 [ Q1[y1] ^ b1(L[1]) ] ^ b1(L[0]) ];
                y2 = Q1[  Q1 [ Q0[y2] ^ b2(L[1]) ] ^ b2(L[0]) ];
                y3 = Q0[  Q1 [ Q1[y3] ^ b3(L[1]) ] ^ b3(L[0]) ];
        }

        SB[0][i] = y0; SB[1][i] = y1; SB[2][i] = y2; SB[3][i] = y3;

        // now do the partial MDS matrix multiplies
        QF[0][i] = ((multEF[y0] << 24)
                    | (multEF[y0] << 16)
                    | (mult5B[y0] << 8)
                    | y0);
        QF[1][i] = ((y1 << 24)
                    | (mult5B[y1] << 16)
                    | (multEF[y1] << 8)
                    | multEF[y1]);
        QF[2][i] = ((multEF[y2] << 24)
                    | (y2 << 16)
                    | (multEF[y2] << 8)
                    | mult5B[y2]);
        QF[3][i] = ((mult5B[y3] << 24)
                    | (multEF[y3] << 16)
                    | (y3 << 8)
                    | mult5B[y3]);
    }
}

// ----------------------------------------------------------------------------------------------------------------


// fully keyed h (aka g) function
#define fkh(X) (ctx->QF[0][b0(X)]^ctx->QF[1][b1(X)]^ctx->QF[2][b2(X)]^ctx->QF[3][b3(X)])

// fkh(ROL(X,8)), without materializing the rotated value: ROL(X,8) sends
// byte i -> byte (i+1)%4, so its bytes are (b3,b0,b1,b2) instead of
// (b0,b1,b2,b3); reindex which QF table each byte feeds and skip the rotate.
#define fkh8(X) (ctx->QF[0][b3(X)]^ctx->QF[1][b0(X)]^ctx->QF[2][b1(X)]^ctx->QF[3][b2(X)])


// ----------------------------------------------------------------------------------------------------------------


// one encryption round
#define ENC_ROUND(R0, R1, R2, R3, round) \
    T0 = fkh(R0); \
    T1 = fkh8(R1); \
    R2 = ROR(R2 ^ (T1 + T0 + ctx->K[2*round+8]), 1); \
    R3 = ROL(R3, 1) ^ (2*T1 + T0 + ctx->K[2*round+9]);


// encrypts the block PT in place
void twofish_internal_encrypt (uint32_t PT[TF_BLOCK_WORDS], tf_context_t *ctx) {

    uint32_t R0, R1, R2, R3;
    uint32_t T0, T1;

    // load/byteswap/whiten input
    WHITEN_IN(R3, PT[3], ctx->K[3]);
    WHITEN_IN(R2, PT[2], ctx->K[2]);
    WHITEN_IN(R1, PT[1], ctx->K[1]);
    WHITEN_IN(R0, PT[0], ctx->K[0]);

    ENC_ROUND(R0, R1, R2, R3,  0);
    ENC_ROUND(R2, R3, R0, R1,  1);
    ENC_ROUND(R0, R1, R2, R3,  2);
    ENC_ROUND(R2, R3, R0, R1,  3);
    ENC_ROUND(R0, R1, R2, R3,  4);
    ENC_ROUND(R2, R3, R0, R1,  5);
    ENC_ROUND(R0, R1, R2, R3,  6);
    ENC_ROUND(R2, R3, R0, R1,  7);
    ENC_ROUND(R0, R1, R2, R3,  8);
    ENC_ROUND(R2, R3, R0, R1,  9);
    ENC_ROUND(R0, R1, R2, R3, 10);
    ENC_ROUND(R2, R3, R0, R1, 11);
    ENC_ROUND(R0, R1, R2, R3, 12);
    ENC_ROUND(R2, R3, R0, R1, 13);
    ENC_ROUND(R0, R1, R2, R3, 14);
    ENC_ROUND(R2, R3, R0, R1, 15);

    // whiten/byteswap/store output
    WHITEN_OUT(PT[3], R1, ctx->K[7]);
    WHITEN_OUT(PT[2], R0, ctx->K[6]);
    WHITEN_OUT(PT[1], R3, ctx->K[5]);
    WHITEN_OUT(PT[0], R2, ctx->K[4]);
}


// ----------------------------------------------------------------------------------------------------------------


// one decryption round
#define DEC_ROUND(R0, R1, R2, R3, round) \
    T0 = fkh(R0); \
    T1 = fkh8(R1); \
    R2 = ROL(R2, 1) ^ (T0 + T1 + ctx->K[2*round+8]); \
    R3 = ROR(R3 ^ (T0 + 2*T1 + ctx->K[2*round+9]), 1);


void twofish_internal_decrypt (uint32_t PT[TF_BLOCK_WORDS], const uint32_t CT[TF_BLOCK_WORDS], tf_context_t *ctx) {

    uint32_t T0, T1;
    uint32_t R0, R1, R2, R3;

    // load/byteswap/whiten input
    WHITEN_IN(R3, CT[3], ctx->K[7]);
    WHITEN_IN(R2, CT[2], ctx->K[6]);
    WHITEN_IN(R1, CT[1], ctx->K[5]);
    WHITEN_IN(R0, CT[0], ctx->K[4]);

    DEC_ROUND(R0, R1, R2, R3, 15);
    DEC_ROUND(R2, R3, R0, R1, 14);
    DEC_ROUND(R0, R1, R2, R3, 13);
    DEC_ROUND(R2, R3, R0, R1, 12);
    DEC_ROUND(R0, R1, R2, R3, 11);
    DEC_ROUND(R2, R3, R0, R1, 10);
    DEC_ROUND(R0, R1, R2, R3,  9);
    DEC_ROUND(R2, R3, R0, R1,  8);
    DEC_ROUND(R0, R1, R2, R3,  7);
    DEC_ROUND(R2, R3, R0, R1,  6);
    DEC_ROUND(R0, R1, R2, R3,  5);
    DEC_ROUND(R2, R3, R0, R1,  4);
    DEC_ROUND(R0, R1, R2, R3,  3);
    DEC_ROUND(R2, R3, R0, R1,  2);
    DEC_ROUND(R0, R1, R2, R3,  1);
    DEC_ROUND(R2, R3, R0, R1,  0);

    // whiten/byteswap/store output
    WHITEN_OUT(PT[3], R1, ctx->K[3]);
    WHITEN_OUT(PT[2], R0, ctx->K[2]);
    WHITEN_OUT(PT[1], R3, ctx->K[1]);
    WHITEN_OUT(PT[0], R2, ctx->K[0]);
}


// -------------------------------------------------------------------------------------


// the key schedule routine
void keySched (const uint8_t M[], int N, uint32_t **S, uint32_t K[40], int *k) {

    uint32_t Mo[4], Me[4], Mw[8];
    int i, j;
    uint8_t vector[8];
    uint32_t A, B;

    *k = (N + 63) / 64;
    *S = (uint32_t*)malloc(sizeof(uint32_t) * (*k));

    memcpy(Mw, M, 8 * *k);
    for(i = 0; i < *k; i++) {
        Me[i] = le32toh(Mw[2*i]);
        Mo[i] = le32toh(Mw[2*i+1]);
    }

    for(i = 0; i < *k; i++) {
        for(j = 0; j < 4; j++)
            vector[j] = _b(Me[i], j);
        for(j = 0; j < 4; j++)
            vector[j+4] = _b(Mo[i], j);
        (*S)[(*k)-i-1] = RSMatrixMultiply(vector);
    }

    for(i = 0; i < 20; i++) {
        A = h(2*i*RHO, Me, *k);
        B = ROL(h(2*i*RHO + RHO, Mo, *k), 8);
        K[2*i] = A+B;
        K[2*i+1] = ROL(A + 2*B, 9);
    }
}


// ----------------------------------------------------------------------------------------------------------------


// ----------------------------------------------------------------------------------------------------------------


#if defined (__AVX512F__) && defined (__AVX512BW__) && defined (__AVX512VBMI__) && defined (__GFNI__) // AVX512 support


#include <immintrin.h>


// 16 blocks at a time: one __m512i holds the same state word of 16 independent blocks,
// one block per 32-bit lane. Unlike the scalar rails, the g function does not use the
// QF tables from memory. Instead, the four keyed byte S-boxes s0..s3 (256 bytes each)
// are kept in registers and looked up with VPERMI2B, and the MDS multiplication is done
// with GF2P8AFFINEQB. Multiplying by a constant in GF(2^8) is linear over GF(2) for any
// reduction polynomial, so this works for Twofish's 0x169 as well (not only AES' 0x11B).
// As a side effect, this path does not do secret-indexed memory lookups.

// 8x8 bit matrices for multiplication by 0xEF and 0x5B mod 0x169, in GF2P8AFFINEQB
// layout (row for output bit i in byte 7-i), checked against multEF[] / mult5B[]
#define TF_AFFINE_MUL_EF 0x070F1F3972E3C183ULL
#define TF_AFFINE_MUL_5B 0x050B162953A24182ULL


// in-lane 4x4 transpose of 32-bit words, maps 16 blocks in memory order to (a permutation
// of) one block per lane and back, it is its own inverse
#define TRANSPOSE_4X4_512(X0, X1, X2, X3) { \
        __m512i t0 = _mm512_unpacklo_epi32(X0, X1), t1 = _mm512_unpackhi_epi32(X0, X1); \
        __m512i t2 = _mm512_unpacklo_epi32(X2, X3), t3 = _mm512_unpackhi_epi32(X2, X3); \
        X0 = _mm512_unpacklo_epi64(t0, t2); X1 = _mm512_unpackhi_epi64(t0, t2); \
        X2 = _mm512_unpacklo_epi64(t1, t3); X3 = _mm512_unpackhi_epi64(t1, t3); }


typedef struct {
    __m512i sb[4][4];                     // sb[p][c] holds s_p[64*c .. 64*c+63]
    __m512i mul_ef, mul_5b;               // affine matrices
    __m512i shA, shB1, shB2, shC1, shC2;  // MDS byte shuffles
} tf_avx512_sbox_t;


// byte position p within each 32-bit lane
#define POS_MASK(p) (0x1111111111111111ULL << (p))

// load the four 64 byte chunks of one keyed byte S-box (computed per key in tf_init)
#define LOAD_SB(s, ctx, p) ((s)->sb[p][0] = _mm512_loadu_si512((const void*)&(ctx)->SB[p][0]), \
                            (s)->sb[p][1] = _mm512_loadu_si512((const void*)&(ctx)->SB[p][64]), \
                            (s)->sb[p][2] = _mm512_loadu_si512((const void*)&(ctx)->SB[p][128]), \
                            (s)->sb[p][3] = _mm512_loadu_si512((const void*)&(ctx)->SB[p][192]))

// with y = S-box outputs (bytes y0..y3 per lane), A = y, B = 0xEF*y, C = 0x5B*y,
// the MDS output bytes are (read off the QF construction in fullKey()):
//   z0 = A0 ^ B1 ^ C2 ^ C3      z1 = C0 ^ B1 ^ B2 ^ A3
//   z2 = B0 ^ C1 ^ A2 ^ B3      z3 = B0 ^ A1 ^ B2 ^ C3
// gathered with in-lane byte shuffles (Z = zero)
#define Z (-128) /* index with top bit set yields zero, stays negative after the +4/+8/+12 */
#define SH(a, b, c, d) _mm512_broadcast_i32x4(_mm_setr_epi8(a,  b,  c,  d,  4+(a), 4+(b), 4+(c), 4+(d), \
                                                            8+(a), 8+(b), 8+(c), 8+(d), 12+(a), 12+(b), 12+(c), 12+(d)))

static void tf_avx512_setup (tf_avx512_sbox_t *s, const tf_context_t *ctx) {

    LOAD_SB(s, ctx, 0);
    LOAD_SB(s, ctx, 1);
    LOAD_SB(s, ctx, 2);
    LOAD_SB(s, ctx, 3);

    s->mul_ef = _mm512_set1_epi64((long long)TF_AFFINE_MUL_EF);
    s->mul_5b = _mm512_set1_epi64((long long)TF_AFFINE_MUL_5B);

    s->shA  = SH(0, 3, 2, 1);
    s->shB1 = SH(1, 1, 0, 0);
    s->shB2 = SH(Z, 2, 3, 2);
    s->shC1 = SH(2, 0, 1, 3);
    s->shC2 = SH(3, Z, Z, Z);
}
#undef Z
#undef SH


// 16-lane keyed S-box step: the byte at position p of each lane goes through s_p,
// TBL-style, one masked VPERMI2B per position and table half. As with fkh() above,
// the arguments are used more than once, so pass variables and not expressions.
#define SBOX_512(dst, X, s) do { \
        __mmask64 hi_ = _mm512_movepi8_mask(X); \
        __m512i r0_, r1_, r2_, r3_, r4_, r5_, r6_, r7_; \
        r0_ = _mm512_maskz_permutex2var_epi8(POS_MASK(0) & ~hi_, (s)->sb[0][0], X, (s)->sb[0][1]); \
        r1_ = _mm512_maskz_permutex2var_epi8(POS_MASK(0) &  hi_, (s)->sb[0][2], X, (s)->sb[0][3]); \
        r2_ = _mm512_maskz_permutex2var_epi8(POS_MASK(1) & ~hi_, (s)->sb[1][0], X, (s)->sb[1][1]); \
        r3_ = _mm512_maskz_permutex2var_epi8(POS_MASK(1) &  hi_, (s)->sb[1][2], X, (s)->sb[1][3]); \
        r4_ = _mm512_maskz_permutex2var_epi8(POS_MASK(2) & ~hi_, (s)->sb[2][0], X, (s)->sb[2][1]); \
        r5_ = _mm512_maskz_permutex2var_epi8(POS_MASK(2) &  hi_, (s)->sb[2][2], X, (s)->sb[2][3]); \
        r6_ = _mm512_maskz_permutex2var_epi8(POS_MASK(3) & ~hi_, (s)->sb[3][0], X, (s)->sb[3][1]); \
        r7_ = _mm512_maskz_permutex2var_epi8(POS_MASK(3) &  hi_, (s)->sb[3][2], X, (s)->sb[3][3]); \
        r0_ = _mm512_ternarylogic_epi32(r0_, r1_, r2_, 0xFE); /* a | b | c */ \
        r3_ = _mm512_ternarylogic_epi32(r3_, r4_, r5_, 0xFE); \
        (dst) = _mm512_ternarylogic_epi32(r0_, r3_, _mm512_or_si512(r6_, r7_), 0xFE); } while(0)


// 16-lane fully keyed h (aka g) function
#define G_512(dst, X, s) do { \
        __m512i y_, b_, c_, z_; \
        SBOX_512(y_, X, s); \
        b_ = _mm512_gf2p8affine_epi64_epi8(y_, (s)->mul_ef, 0); \
        c_ = _mm512_gf2p8affine_epi64_epi8(y_, (s)->mul_5b, 0); \
        z_ = _mm512_ternarylogic_epi32(_mm512_shuffle_epi8(y_, (s)->shA), /* a ^ b ^ c */ \
                                       _mm512_shuffle_epi8(b_, (s)->shB1), \
                                       _mm512_shuffle_epi8(b_, (s)->shB2), 0x96); \
        (dst) = _mm512_ternarylogic_epi32(z_, _mm512_shuffle_epi8(c_, (s)->shC1), \
                                          _mm512_shuffle_epi8(c_, (s)->shC2), 0x96); } while(0)


// 16-lane version of DEC_ROUND, ROL(R1, 8) is a single VPROLD here so no fkh8 trick needed
#define DEC_ROUND_512(R0, R1, R2, R3, round) do { \
        __m512i rot_ = _mm512_rol_epi32(R1, 8); \
        G_512(T0, R0, &sbox); \
        G_512(T1, rot_, &sbox); \
        R2 = _mm512_xor_si512(_mm512_rol_epi32(R2, 1), \
                              _mm512_add_epi32(_mm512_add_epi32(T0, T1), \
                                               _mm512_set1_epi32(ctx->K[2*round+8]))); \
        R3 = _mm512_ror_epi32(_mm512_xor_si512(R3, \
                                               _mm512_add_epi32(_mm512_add_epi32(T0, _mm512_add_epi32(T1, T1)), \
                                                                _mm512_set1_epi32(ctx->K[2*round+9]))), 1); } while(0)


// CBC-decrypt n16 * 16 blocks, updates ivec to the last ciphertext block; in == out is fine
static void tf_cbc_decrypt_16way (unsigned char *out, const unsigned char *in, int n16,
                                  uint32_t ivec[TF_BLOCK_WORDS], tf_context_t *ctx) {

    tf_avx512_sbox_t sbox;
    __m512i R0, R1, R2, R3, T0, T1;
    __m512i P0, P1, P2, P3; // chaining values
    uint8_t first[64];      // ivec followed by the first three ciphertext blocks

    tf_avx512_setup(&sbox, ctx);

    for(; n16 > 0; n16--) {
        // x86 is little endian, so no byteswapping on loads and stores
        R0 = _mm512_loadu_si512((const void*)(in +   0));
        R1 = _mm512_loadu_si512((const void*)(in +  64));
        R2 = _mm512_loadu_si512((const void*)(in + 128));
        R3 = _mm512_loadu_si512((const void*)(in + 192));

        // chaining values are the preceding ciphertext blocks, read them now so
        // that in-place (in == out) operation does not clobber them
        memcpy(first, ivec, TF_BLOCK_SIZE);
        memcpy(first + TF_BLOCK_SIZE, in, 3 * TF_BLOCK_SIZE);
        P0 = _mm512_loadu_si512((const void*)first);
        P1 = _mm512_loadu_si512((const void*)(in +  48));
        P2 = _mm512_loadu_si512((const void*)(in + 112));
        P3 = _mm512_loadu_si512((const void*)(in + 176));
        memcpy(ivec, in + 15 * TF_BLOCK_SIZE, TF_BLOCK_SIZE);

        // transpose, whiten input
        TRANSPOSE_4X4_512(R0, R1, R2, R3);
        R0 = _mm512_xor_si512(R0, _mm512_set1_epi32(ctx->K[4]));
        R1 = _mm512_xor_si512(R1, _mm512_set1_epi32(ctx->K[5]));
        R2 = _mm512_xor_si512(R2, _mm512_set1_epi32(ctx->K[6]));
        R3 = _mm512_xor_si512(R3, _mm512_set1_epi32(ctx->K[7]));

        DEC_ROUND_512(R0, R1, R2, R3, 15);
        DEC_ROUND_512(R2, R3, R0, R1, 14);
        DEC_ROUND_512(R0, R1, R2, R3, 13);
        DEC_ROUND_512(R2, R3, R0, R1, 12);
        DEC_ROUND_512(R0, R1, R2, R3, 11);
        DEC_ROUND_512(R2, R3, R0, R1, 10);
        DEC_ROUND_512(R0, R1, R2, R3,  9);
        DEC_ROUND_512(R2, R3, R0, R1,  8);
        DEC_ROUND_512(R0, R1, R2, R3,  7);
        DEC_ROUND_512(R2, R3, R0, R1,  6);
        DEC_ROUND_512(R0, R1, R2, R3,  5);
        DEC_ROUND_512(R2, R3, R0, R1,  4);
        DEC_ROUND_512(R0, R1, R2, R3,  3);
        DEC_ROUND_512(R2, R3, R0, R1,  2);
        DEC_ROUND_512(R0, R1, R2, R3,  1);
        DEC_ROUND_512(R2, R3, R0, R1,  0);

        // whiten output (output word order is R2, R3, R0, R1), transpose back, chain, store
        T0 = _mm512_xor_si512(R2, _mm512_set1_epi32(ctx->K[0]));
        T1 = _mm512_xor_si512(R3, _mm512_set1_epi32(ctx->K[1]));
        R0 = _mm512_xor_si512(R0, _mm512_set1_epi32(ctx->K[2]));
        R1 = _mm512_xor_si512(R1, _mm512_set1_epi32(ctx->K[3]));
        TRANSPOSE_4X4_512(T0, T1, R0, R1);

        _mm512_storeu_si512((void*)(out +   0), _mm512_xor_si512(T0, P0));
        _mm512_storeu_si512((void*)(out +  64), _mm512_xor_si512(T1, P1));
        _mm512_storeu_si512((void*)(out + 128), _mm512_xor_si512(R0, P2));
        _mm512_storeu_si512((void*)(out + 192), _mm512_xor_si512(R1, P3));

        in += 16 * TF_BLOCK_SIZE; out += 16 * TF_BLOCK_SIZE;
    }
}


#endif // AVX512 support -------------------------------------------------------------------------------------------


// ----------------------------------------------------------------------------------------------------------------


// public API


int tf_ecb_decrypt (unsigned char *out, const unsigned char *in, tf_context_t *ctx) {

    uint32_t pt[TF_BLOCK_WORDS], ct[TF_BLOCK_WORDS];

    memcpy(ct, in, TF_BLOCK_SIZE);
    twofish_internal_decrypt(pt, ct, ctx);
    memcpy(out, pt, TF_BLOCK_SIZE);

    return TF_BLOCK_SIZE;
}


// not used
int tf_ecb_encrypt (unsigned char *out, const unsigned char *in, tf_context_t *ctx) {

    uint32_t pt[TF_BLOCK_WORDS];

    memcpy(pt, in, TF_BLOCK_SIZE);
    twofish_internal_encrypt(pt, ctx);
    memcpy(out, pt, TF_BLOCK_SIZE);

    return TF_BLOCK_SIZE;
}


int tf_cbc_encrypt (unsigned char *out, const unsigned char *in, size_t in_len,
                    const unsigned char *iv, tf_context_t *ctx) {

    uint32_t cv[TF_BLOCK_WORDS], blk[TF_BLOCK_WORDS];
    size_t i;
    size_t n;

    memcpy(cv, iv, TF_BLOCK_SIZE);

    n = in_len / TF_BLOCK_SIZE;
    for(i = 0; i < n; i++) {
        // encrypting (plain text XOR previous cipher text) gives the next cipher
        // text block, which is also the next chaining value
        memcpy(blk, &in[i * TF_BLOCK_SIZE], TF_BLOCK_SIZE);
        cv[0] ^= blk[0];
        cv[1] ^= blk[1];
        cv[2] ^= blk[2];
        cv[3] ^= blk[3];
        twofish_internal_encrypt(cv, ctx);
        memcpy(&out[i * TF_BLOCK_SIZE], cv, TF_BLOCK_SIZE);
    }

    return n * TF_BLOCK_SIZE;
}


int tf_cbc_decrypt (unsigned char *out, const unsigned char *in, size_t in_len,
                    const unsigned char *iv, tf_context_t *ctx) {

    int n;                        /* number of blocks */

    uint32_t ivw[TF_BLOCK_WORDS]; /* chaining value, the preceding cipher text block */
    uint32_t old[TF_BLOCK_WORDS]; /* saved cipher text, out is allowed to be in */

    memcpy(ivw, iv, TF_BLOCK_SIZE);

    n = in_len / TF_BLOCK_SIZE;

#if defined (__AVX512F__) && defined (__AVX512BW__) && defined (__AVX512VBMI__) && defined (__GFNI__)
    // 16 parallel lanes of twofish decryption
    if(n > 15) {
        tf_cbc_decrypt_16way(out, in, n / 16, ivw, ctx);
        in += (n & ~15) * TF_BLOCK_SIZE; out += (n & ~15) * TF_BLOCK_SIZE;
        n &= 15;
    }
#endif

    // 3 parallel rails of twofish decryption
    for(; n > 2; n -= 3) {

        uint32_t T0, T1;
        uint32_t Q0, Q1, Q2, Q3, R0, R1, R2, R3, S0, S1, S2, S3;

        // the last cipher text block of this group is the chaining value of the
        // next one, and writing out would lose it if out == in
        memcpy(old, in + 2 * TF_BLOCK_SIZE, TF_BLOCK_SIZE);

        // load/byteswap/whiten input
        WHITEN_IN(Q3, tf_load32(in + 12), ctx->K[7]);
        WHITEN_IN(Q2, tf_load32(in +  8), ctx->K[6]);
        WHITEN_IN(Q1, tf_load32(in +  4), ctx->K[5]);
        WHITEN_IN(Q0, tf_load32(in +  0), ctx->K[4]);

        WHITEN_IN(R3, tf_load32(in + 28), ctx->K[7]);
        WHITEN_IN(R2, tf_load32(in + 24), ctx->K[6]);
        WHITEN_IN(R1, tf_load32(in + 20), ctx->K[5]);
        WHITEN_IN(R0, tf_load32(in + 16), ctx->K[4]);

        WHITEN_IN(S3, tf_load32(in + 44), ctx->K[7]);
        WHITEN_IN(S2, tf_load32(in + 40), ctx->K[6]);
        WHITEN_IN(S1, tf_load32(in + 36), ctx->K[5]);
        WHITEN_IN(S0, tf_load32(in + 32), ctx->K[4]);

        DEC_ROUND(Q0, Q1, Q2, Q3, 15); DEC_ROUND(R0, R1, R2, R3, 15); DEC_ROUND(S0, S1, S2, S3, 15);
        DEC_ROUND(Q2, Q3, Q0, Q1, 14); DEC_ROUND(R2, R3, R0, R1, 14); DEC_ROUND(S2, S3, S0, S1, 14);
        DEC_ROUND(Q0, Q1, Q2, Q3, 13); DEC_ROUND(R0, R1, R2, R3, 13); DEC_ROUND(S0, S1, S2, S3, 13);
        DEC_ROUND(Q2, Q3, Q0, Q1, 12); DEC_ROUND(R2, R3, R0, R1, 12); DEC_ROUND(S2, S3, S0, S1, 12);
        DEC_ROUND(Q0, Q1, Q2, Q3, 11); DEC_ROUND(R0, R1, R2, R3, 11); DEC_ROUND(S0, S1, S2, S3, 11);
        DEC_ROUND(Q2, Q3, Q0, Q1, 10); DEC_ROUND(R2, R3, R0, R1, 10); DEC_ROUND(S2, S3, S0, S1, 10);
        DEC_ROUND(Q0, Q1, Q2, Q3,  9); DEC_ROUND(R0, R1, R2, R3,  9); DEC_ROUND(S0, S1, S2, S3,  9);
        DEC_ROUND(Q2, Q3, Q0, Q1,  8); DEC_ROUND(R2, R3, R0, R1,  8); DEC_ROUND(S2, S3, S0, S1,  8);
        DEC_ROUND(Q0, Q1, Q2, Q3,  7); DEC_ROUND(R0, R1, R2, R3,  7); DEC_ROUND(S0, S1, S2, S3,  7);
        DEC_ROUND(Q2, Q3, Q0, Q1,  6); DEC_ROUND(R2, R3, R0, R1,  6); DEC_ROUND(S2, S3, S0, S1,  6);
        DEC_ROUND(Q0, Q1, Q2, Q3,  5); DEC_ROUND(R0, R1, R2, R3,  5); DEC_ROUND(S0, S1, S2, S3,  5);
        DEC_ROUND(Q2, Q3, Q0, Q1,  4); DEC_ROUND(R2, R3, R0, R1,  4); DEC_ROUND(S2, S3, S0, S1,  4);
        DEC_ROUND(Q0, Q1, Q2, Q3,  3); DEC_ROUND(R0, R1, R2, R3,  3); DEC_ROUND(S0, S1, S2, S3,  3);
        DEC_ROUND(Q2, Q3, Q0, Q1,  2); DEC_ROUND(R2, R3, R0, R1,  2); DEC_ROUND(S2, S3, S0, S1,  2);
        DEC_ROUND(Q0, Q1, Q2, Q3,  1); DEC_ROUND(R0, R1, R2, R3,  1); DEC_ROUND(S0, S1, S2, S3,  1);
        DEC_ROUND(Q2, Q3, Q0, Q1,  0); DEC_ROUND(R2, R3, R0, R1,  0); DEC_ROUND(S2, S3, S0, S1,  0);

        // whiten/byteswap output, chained with the preceding cipher text block.
        // The blocks are stored back to front on purpose: each one still reads
        // cipher text words of the block before it, so if out == in the later
        // block has to be written before the earlier one overwrites its input
        WHITEN_CHAIN_STORE(out + 44, S1, ctx->K[3], tf_load32(in + 28));
        WHITEN_CHAIN_STORE(out + 40, S0, ctx->K[2], tf_load32(in + 24));
        WHITEN_CHAIN_STORE(out + 36, S3, ctx->K[1], tf_load32(in + 20));
        WHITEN_CHAIN_STORE(out + 32, S2, ctx->K[0], tf_load32(in + 16));

        WHITEN_CHAIN_STORE(out + 28, R1, ctx->K[3], tf_load32(in + 12));
        WHITEN_CHAIN_STORE(out + 24, R0, ctx->K[2], tf_load32(in +  8));
        WHITEN_CHAIN_STORE(out + 20, R3, ctx->K[1], tf_load32(in +  4));
        WHITEN_CHAIN_STORE(out + 16, R2, ctx->K[0], tf_load32(in +  0));

        WHITEN_CHAIN_STORE(out + 12, Q1, ctx->K[3], ivw[3]);
        WHITEN_CHAIN_STORE(out +  8, Q0, ctx->K[2], ivw[2]);
        WHITEN_CHAIN_STORE(out +  4, Q3, ctx->K[1], ivw[1]);
        WHITEN_CHAIN_STORE(out +  0, Q2, ctx->K[0], ivw[0]);

        memcpy(ivw, old, TF_BLOCK_SIZE);

        in += 3 * TF_BLOCK_SIZE; out += 3 * TF_BLOCK_SIZE;
    }

    // handle the two or less remaining block on a single rail
    for(; n != 0; n--) {

        uint32_t T0, T1;
        uint32_t Q0, Q1, Q2, Q3;

        memcpy(old, in, TF_BLOCK_SIZE);

        // load/byteswap/whiten input
        WHITEN_IN(Q3, tf_load32(in + 12), ctx->K[7]);
        WHITEN_IN(Q2, tf_load32(in +  8), ctx->K[6]);
        WHITEN_IN(Q1, tf_load32(in +  4), ctx->K[5]);
        WHITEN_IN(Q0, tf_load32(in +  0), ctx->K[4]);

        DEC_ROUND(Q0, Q1, Q2, Q3, 15);
        DEC_ROUND(Q2, Q3, Q0, Q1, 14);
        DEC_ROUND(Q0, Q1, Q2, Q3, 13);
        DEC_ROUND(Q2, Q3, Q0, Q1, 12);
        DEC_ROUND(Q0, Q1, Q2, Q3, 11);
        DEC_ROUND(Q2, Q3, Q0, Q1, 10);
        DEC_ROUND(Q0, Q1, Q2, Q3,  9);
        DEC_ROUND(Q2, Q3, Q0, Q1,  8);
        DEC_ROUND(Q0, Q1, Q2, Q3,  7);
        DEC_ROUND(Q2, Q3, Q0, Q1,  6);
        DEC_ROUND(Q0, Q1, Q2, Q3,  5);
        DEC_ROUND(Q2, Q3, Q0, Q1,  4);
        DEC_ROUND(Q0, Q1, Q2, Q3,  3);
        DEC_ROUND(Q2, Q3, Q0, Q1,  2);
        DEC_ROUND(Q0, Q1, Q2, Q3,  1);
        DEC_ROUND(Q2, Q3, Q0, Q1,  0);

        // whiten/byteswap output, chained with the preceding cipher text block
        WHITEN_CHAIN_STORE(out + 12, Q1, ctx->K[3], ivw[3]);
        WHITEN_CHAIN_STORE(out +  8, Q0, ctx->K[2], ivw[2]);
        WHITEN_CHAIN_STORE(out +  4, Q3, ctx->K[1], ivw[1]);
        WHITEN_CHAIN_STORE(out +  0, Q2, ctx->K[0], ivw[0]);

        memcpy(ivw, old, TF_BLOCK_SIZE);

        in += TF_BLOCK_SIZE; out += TF_BLOCK_SIZE;
    }

    return n * TF_BLOCK_SIZE;
}


// by definition twofish can only accept key up to 256 bit
// we wont do any checking here and will assume user already
// know about it. twofish is undefined for key larger than 256 bit
int tf_init (const unsigned char *key, size_t key_size, tf_context_t **ctx) {

    int k;
    uint32_t *S;

    *ctx = calloc(1, sizeof(tf_context_t));
    if(!(*ctx)) {
        return -1;
    }

    (*ctx)->N = key_size;
    keySched(key, key_size, &S, (*ctx)->K, &k);
    fullKey(S, k, (*ctx)->QF, (*ctx)->SB);
    free(S); /* allocated in keySched(...) */

    return 0;
}


int tf_deinit (tf_context_t *ctx) {

    if(ctx) free(ctx);

    return 0;
}
