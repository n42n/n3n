/*
 * SPDX-FileCopyrightText: Copyright Honey Bunny QT
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Unit tests of AES, whichever implementation is built: plain C, AES-NI,
 * the ARMv8 Cryptography Extension or OpenSSL
 */

#include <stdio.h>            // for printf
#include <string.h>           // for memcmp, memset
#include "../src/crypto/aes.h" // for aes_init, aes_cbc_encrypt, ...


// FIPS-197 appendix C: the key is 00 01 02 ..., the plaintext
// 00 11 22 ... ff, for each key size
static const uint8_t fips_pt[16] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
};

static const uint8_t fips_ct[3][16] = {
    {   // AES-128
        0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
        0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a,
    },
    {   // AES-192
        0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0,
        0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91,
    },
    {   // AES-256
        0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf,
        0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89,
    },
};


// a block encrypted with a zero IV is the block cipher itself
static int test_fips (int k) {
    uint8_t key[32];
    uint8_t iv[16] = {0};
    uint8_t ct[16];
    uint8_t pt[16];
    aes_context_t *ctx;
    size_t key_size = 16 + 8 * k;
    int failed = 0;

    for(int i = 0; i < 32; i++) {
        key[i] = i;
    }
    if(aes_init(key, key_size, &ctx)) {
        printf("AES-%d: aes_init failed\n", (int)key_size * 8);
        return 1;
    }

    aes_cbc_encrypt(ct, fips_pt, 16, iv, ctx);
    failed |= memcmp(ct, fips_ct[k], 16) != 0;

    aes_ecb_decrypt(pt, ct, ctx);
    failed |= memcmp(pt, fips_pt, 16) != 0;

    aes_cbc_decrypt(pt, ct, 16, iv, ctx);
    failed |= memcmp(pt, fips_pt, 16) != 0;

    printf("AES-%d: FIPS-197 vector: %s\n", (int)key_size * 8, failed ? "FAIL" : "ok");
    aes_deinit(ctx);
    return failed;
}


// CBC of packets of several lengths, decrypted into another buffer and in
// place
static int test_cbc (int k) {
    enum { PKTS = 9, MAXLEN = 16 * 13 };
    uint8_t key[32];
    uint8_t iv[16];
    uint8_t in[PKTS][MAXLEN];
    uint8_t one[PKTS][MAXLEN];
    uint8_t back[MAXLEN];
    size_t len[PKTS];
    aes_context_t *ctx;
    size_t key_size = 16 + 8 * k;
    int failed = 0;

    for(int i = 0; i < 32; i++) {
        key[i] = 0xa5 ^ (i * 7);
    }
    for(int i = 0; i < 16; i++) {
        iv[i] = 0x3c + i;
    }
    if(aes_init(key, key_size, &ctx)) {
        return 1;
    }

    for(int p = 0; p < PKTS; p++) {
        len[p] = 16 * (1 + (p * 5) % 13);
        for(size_t i = 0; i < len[p]; i++) {
            in[p][i] = (uint8_t)(p * 31 + i * 13);
        }
        aes_cbc_encrypt(one[p], in[p], len[p], iv, ctx);

        // decrypt into a separate buffer, then in place
        aes_cbc_decrypt(back, one[p], len[p], iv, ctx);
        failed |= memcmp(back, in[p], len[p]) != 0;
        memcpy(back, one[p], len[p]);
        aes_cbc_decrypt(back, back, len[p], iv, ctx);
        failed |= memcmp(back, in[p], len[p]) != 0;
    }

    printf("AES-%d: CBC and in place: %s\n", (int)key_size * 8, failed ? "FAIL" : "ok");
    aes_deinit(ctx);
    return failed;
}


int main (int argc, char * argv[]) {
    int failed = 0;

    for(int k = 0; k < 3; k++) {
        failed |= test_fips(k);
        failed |= test_cbc(k);
    }

    return failed;
}
