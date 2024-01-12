/*
 * Copyright (C) 2023-24 Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 */

#include <inttypes.h>  // for PRIx64, PRIx16, PRIx32
#include <stdint.h>    // for uint8_t, uint16_t, uint32_t, uint64_t
#include <stdio.h>     // for printf, fprintf, stderr, stdout
#include <string.h>    // for memcmp
#include "n2n.h"
#include "hexdump.h"   // for fhexdump
#include "pearson.h"   // for pearson_hash_128, pearson_hash_16, pearson_has...


static uint8_t PKT_CONTENT[]={
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
};

static const uint16_t expected_pearson_hash_16 = 0x8be;
static const uint32_t expected_pearson_hash_32 = 0x2ea108be;
static const uint64_t expected_pearson_hash_64 = 0xb2d98fa82ea108be;
static const uint8_t expected_pearson_hash_128[] = {
    0xb5,0x3d,0xcf,0xb3,0xa7,0xed,0x18,0x56,
    0xb2,0xd9,0x8f,0xa8,0x2e,0xa1,0x08,0xbe,
};
static const uint8_t expected_pearson_hash_256[] = {
    0x40,0x09,0x5c,0xca,0x28,0x6b,0xfb,0x93,
    0x4c,0x4a,0xf7,0xc0,0x79,0xa8,0x04,0x5a,
    0xb5,0x3d,0xcf,0xb3,0xa7,0xed,0x18,0x56,
    0xb2,0xd9,0x8f,0xa8,0x2e,0xa1,0x08,0xbe,
};

static int test_pearson_16 (int level) {
    char *test_name = "pearson_hash_16";

    uint16_t hash = pearson_hash_16(PKT_CONTENT, sizeof(PKT_CONTENT));

    fprintf(stderr, "%s: tested\n", test_name);
    if(level) {
        printf("%s: output = 0x%" PRIx16 "\n", test_name, hash);
        printf("\n");
    }

    if(hash != expected_pearson_hash_16) {
        return 1;
    }
    return 0;
}

static int test_pearson_32 (int level) {
    char *test_name = "pearson_hash_32";

    uint32_t hash = pearson_hash_32(PKT_CONTENT, sizeof(PKT_CONTENT));

    fprintf(stderr, "%s: tested\n", test_name);
    if(level) {
        printf("%s: output = 0x%" PRIx32 "\n", test_name, hash);
        printf("\n");
    }

    if(hash != expected_pearson_hash_32) {
        return 1;
    }
    return 0;
}

static int test_pearson_64 (int level) {
    char *test_name = "pearson_hash_64";

    uint64_t hash = pearson_hash_64(PKT_CONTENT, sizeof(PKT_CONTENT));

    fprintf(stderr, "%s: tested\n", test_name);
    if(level) {
        printf("%s: output = 0x%" PRIx64 "\n", test_name, hash);
        printf("\n");
    }

    if(hash != expected_pearson_hash_64) {
        return 1;
    }
    return 0;
}

static int test_pearson_128 (int level) {
    char *test_name = "pearson_hash_128";

    uint8_t hash[16];
    pearson_hash_128(hash, PKT_CONTENT, sizeof(PKT_CONTENT));

    fprintf(stderr, "%s: tested\n", test_name);
    if(level) {
        printf("%s: output:\n", test_name);
        fhexdump(0, hash, sizeof(hash), stdout);
        printf("\n");
    }

    if(memcmp(hash, expected_pearson_hash_128, sizeof(hash)) != 0) {
        return 1;
    }
    return 0;
}

static int test_pearson_256 (int level) {
    char *test_name = "pearson_hash_256";

    uint8_t hash[32];
    pearson_hash_256(hash, PKT_CONTENT, sizeof(PKT_CONTENT));

    fprintf(stderr, "%s: tested\n", test_name);
    if(level) {
        printf("%s: output:\n", test_name);
        fhexdump(0, hash, sizeof(hash), stdout);
        printf("\n");
    }

    if(memcmp(hash, expected_pearson_hash_256, sizeof(hash)) != 0) {
        return 1;
    }
    return 0;
}

int test_hashing (int level) {
    int result = 0;

    pearson_hash_init();

    char *test_name = "environment";
    if(level) {
        printf(
            "%s: input size = 0x%" PRIx64 "\n",
            test_name,
            sizeof(PKT_CONTENT)
            );
        fhexdump(0, PKT_CONTENT, sizeof(PKT_CONTENT), stdout);
        printf("\n");
    }

    result += test_pearson_256(level);
    result += test_pearson_128(level);
    result += test_pearson_64(level);
    result += test_pearson_32(level);
    result += test_pearson_16(level);

    return 0;
}

