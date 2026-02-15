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

#include <inttypes.h>  // for PRIx64, PRIx16, PRIx32
#include <n3n/benchmark.h>
#include <n3n/hexdump.h>  // for fhexdump
#include <stdlib.h>
#include <stdio.h>
#include <string.h>    // for memcmp


// taken from https://github.com/Logan007/pearsonB
// this is free and unencumbered software released into the public domain


#include "pearson.h"
#include "portable_endian.h"  // for le64toh, htobe64


// Christopher Wellons' triple32 from https://github.com/skeeto/hash-prospector
// published under The Unlicense
#define permute32(in) \
    in ^= in >> 17;   \
    in *= 0xed5ad4bb; \
    in ^= in >> 11;   \
    in *= 0xac4c1b51; \
    in ^= in >> 15;   \
    in *= 0x31848bab; \
    in ^= in >> 14

// David Stafford's Mix13 from http://zimbry.blogspot.com/2011/09/better-bit-mixing-improving-on.html
// the author clarified via eMail that this of his work is released to the public domain
#define permute64(in)         \
    in ^= (in >> 30);         \
    in *= 0xbf58476d1ce4e5b9; \
    in ^= (in >> 27);         \
    in *= 0x94d049bb133111eb; \
    in ^= (in >> 31)

#define dec1(in) \
    in--

#define dec2(in) \
    dec1(in);    \
    dec1(in)

#define dec3(in) \
    dec2(in);    \
    dec1(in)

#define dec4(in) \
    dec3(in);    \
    dec1(in)

#define hash_round(hash, in, part) \
    hash ## part ^= in;              \
    dec ## part(hash ## part);         \
    permute64(hash ## part)


void pearson_hash_256 (uint8_t *out, const uint8_t *in, size_t len) {

    uint64_t *current;
    current = (uint64_t*)in;
    uint64_t org_len = len;
    uint64_t hash1 = 0;
    uint64_t hash2 = 0;
    uint64_t hash3 = 0;
    uint64_t hash4 = 0;

    while(len > 7) {
        // digest words little endian first
        hash_round(hash, le64toh(*current), 1);
        hash_round(hash, le64toh(*current), 2);
        hash_round(hash, le64toh(*current), 3);
        hash_round(hash, le64toh(*current), 4);

        current++;
        len-=8;
    }

    // handle the rest
    hash1 = ~hash1;
    hash2 = ~hash2;
    hash3 = ~hash3;
    hash4 = ~hash4;

    while(len) {
        // byte-wise, no endianess
        hash_round(hash, *(uint8_t*)current, 1);
        hash_round(hash, *(uint8_t*)current, 2);
        hash_round(hash, *(uint8_t*)current, 3);
        hash_round(hash, *(uint8_t*)current, 4);

        current = (uint64_t*)((uint8_t*)current + 1);
        len--;
    }

    // digest length
    hash1 = ~hash1;
    hash2 = ~hash2;
    hash3 = ~hash3;
    hash4 = ~hash4;

    hash_round(hash, org_len, 1);
    hash_round(hash, org_len, 2);
    hash_round(hash, org_len, 3);
    hash_round(hash, org_len, 4);

    // hash string is stored big endian, the natural way to read
    uint64_t *o;
    o = (uint64_t*)out;
    *o = htobe64(hash4);
    o++;
    *o = htobe64(hash3);
    o++;
    *o = htobe64(hash2);
    o++;
    *o = htobe64(hash1);
}


void pearson_hash_128 (uint8_t *out, const uint8_t *in, size_t len) {

    uint64_t *current;
    current = (uint64_t*)in;
    uint64_t org_len = len;
    uint64_t hash1 = 0;
    uint64_t hash2 = 0;

    while(len > 7) {
        // digest words little endian first
        hash_round(hash, le64toh(*current), 1);
        hash_round(hash, le64toh(*current), 2);

        current++;
        len-=8;
    }

    // handle the rest
    hash1 = ~hash1;
    hash2 = ~hash2;

    while(len) {
        // byte-wise, no endianess
        hash_round(hash, *(uint8_t*)current, 1);
        hash_round(hash, *(uint8_t*)current, 2);

        current = (uint64_t*)((uint8_t*)current + 1);
        len--;
    }

    // digest length
    hash1 = ~hash1;
    hash2 = ~hash2;

    hash_round(hash, org_len, 1);
    hash_round(hash, org_len, 2);

    // hash string is stored big endian, the natural way to read
    uint64_t *o;
    o = (uint64_t*)out;
    *o = htobe64(hash2);
    o++;
    *o = htobe64(hash1);
}


uint64_t pearson_hash_64 (const uint8_t *in, size_t len) {

    uint64_t *current;
    current = (uint64_t*)in;
    uint64_t org_len = len;
    uint64_t hash1 = 0;

    while(len > 7) {
        // digest words little endian first
        hash_round(hash, le64toh(*current), 1);

        current++;
        len-=8;
    }

    // handle the rest
    hash1 = ~hash1;
    while(len) {
        // byte-wise, no endianess
        hash_round(hash, *(uint8_t*)current, 1);

        current = (uint64_t*)((uint8_t*)current + 1);
        len--;
    }

    // digest length
    hash1 = ~hash1;
    hash_round(hash, org_len, 1);

    // caller is responsible for storing it big endian to memory (if ever)
    return hash1;
}


uint32_t pearson_hash_32 (const uint8_t *in, size_t len) {

    return pearson_hash_64(in, len);
}


uint16_t pearson_hash_16 (const uint8_t *in, size_t len) {

    return pearson_hash_64(in, len);
}

static const uint16_t expected_pearson_hash_16 = 0x8be;
static const uint32_t expected_pearson_hash_32 = 0x2ea108be;
static const uint64_t expected_pearson_hash_64 = 0xb2d98fa82ea108be;

static void *bench_pearson_setup (void) {
    // largest result size plus one for the length
    return malloc(32 + 1);
}

static void bench_pearson_teardown (void *ctx) {
    return free(ctx);
}

static const ssize_t bench_16_run (
    void *ctx,
    const void *data_in,
    const ssize_t data_in_size,
    ssize_t *bytes_in
) {
    uint16_t *result = (uint16_t *)ctx;
    uint8_t *bytes = (uint8_t *)ctx;

    *result = pearson_hash_16(data_in, data_in_size);
    *bytes_in = data_in_size;
    bytes[32] = 2;
    return bytes[32];
}

static int bench_16_check (void *ctx, int level) {
    uint16_t *result = (uint16_t *)ctx;
    if(level) {
        printf("%s: output = 0x%" PRIx16 "\n", "pearson_hash_16", *result);
        printf("\n");
    }

    uint8_t *bytes = (uint8_t *)ctx;
    if(bytes[32] != 2) {
        // wrong size is an error
        return 1;
    }

    if(*result != expected_pearson_hash_16) {
        // not matching expected result is an error
        return 1;
    }

    return 0;
}

static const ssize_t bench_32_run (
    void *ctx,
    const void *data_in,
    const ssize_t data_in_size,
    ssize_t *bytes_in
) {
    uint32_t *result = (uint32_t *)ctx;
    uint8_t *bytes = (uint8_t *)ctx;

    *result = pearson_hash_32(data_in, data_in_size);
    *bytes_in = data_in_size;
    bytes[32] = 4;
    return bytes[32];
}

static int bench_32_check (void *ctx, int level) {
    uint32_t *result = (uint32_t *)ctx;
    if(level) {
        printf("%s: output = 0x%" PRIx32 "\n", "pearson_hash_32", *result);
        printf("\n");
    }

    uint8_t *bytes = (uint8_t *)ctx;
    if(bytes[32] != 4) {
        // wrong size is an error
        return 1;
    }

    if(*result != expected_pearson_hash_32) {
        // not matching expected result is an error
        return 1;
    }

    return 0;
}

static const ssize_t bench_64_run (
    void *ctx,
    const void *data_in,
    const ssize_t data_in_size,
    ssize_t *bytes_in
) {
    uint64_t *result = (uint64_t *)ctx;
    uint8_t *bytes = (uint8_t *)ctx;

    *result = pearson_hash_64(data_in, data_in_size);
    *bytes_in = data_in_size;
    bytes[32] = 8;
    return bytes[32];
}

static int bench_64_check (void *ctx, int level) {
    uint64_t *result = (uint64_t *)ctx;
    if(level) {
        printf("%s: output = 0x%" PRIx64 "\n", "pearson_hash_64", *result);
        printf("\n");
    }

    uint8_t *bytes = (uint8_t *)ctx;
    if(bytes[32] != 8) {
        // wrong size is an error
        return 1;
    }

    if(*result != expected_pearson_hash_64) {
        // not matching expected result is an error
        return 1;
    }

    return 0;
}

static const ssize_t bench_128_run (
    void *ctx,
    const void *data_in,
    const ssize_t data_in_size,
    ssize_t *bytes_in
) {
    uint8_t *bytes = (uint8_t *)ctx;

    pearson_hash_128(ctx, data_in, data_in_size);
    *bytes_in = data_in_size;
    bytes[32] = 16;
    return bytes[32];
}

static const ssize_t bench_256_run (
    void *ctx,
    const void *data_in,
    const ssize_t data_in_size,
    ssize_t *bytes_in
) {
    uint8_t *bytes = (uint8_t *)ctx;

    pearson_hash_256(ctx, data_in, data_in_size);
    *bytes_in = data_in_size;
    bytes[32] = 32;
    return bytes[32];
}

static const void *const bench_get_output (void *const ctx) {
    return ctx;
}

static struct bench_item bench_16 = {
    .name = "pearson_hash_16",
    .flags = BENCH_ITEM_CHECKONLY,
    .setup = bench_pearson_setup,
    .run = bench_16_run,
    .check = bench_16_check,
    .teardown = bench_pearson_teardown,
    .data_in = test_data_32x16,
};

static struct bench_item bench_32 = {
    .name = "pearson_hash_32",
    .flags = BENCH_ITEM_CHECKONLY,
    .setup = bench_pearson_setup,
    .run = bench_32_run,
    .check = bench_32_check,
    .teardown = bench_pearson_teardown,
    .data_in = test_data_32x16,
};

static struct bench_item bench_64 = {
    .name = "pearson_hash_64",
    .setup = bench_pearson_setup,
    .run = bench_64_run,
    .check = bench_64_check,
    .teardown = bench_pearson_teardown,
    .data_in = test_data_32x16,
};

static struct bench_item bench_128 = {
    .name = "pearson_hash_128",
    .flags = BENCH_ITEM_CHECKONLY,
    .setup = bench_pearson_setup,
    .run = bench_128_run,
    .get_output = bench_get_output,
    .teardown = bench_pearson_teardown,
    .data_in = test_data_32x16,
    .data_out = test_data_pearson_128,
};

static struct bench_item bench_256 = {
    .name = "pearson_hash_256",
    .flags = BENCH_ITEM_CHECKONLY,
    .setup = bench_pearson_setup,
    .run = bench_256_run,
    .get_output = bench_get_output,
    .teardown = bench_pearson_teardown,
    .data_in = test_data_32x16,
    .data_out = test_data_pearson_256,
};

void n3n_initfuncs_pearson (void) {
    n3n_benchmark_register(&bench_16);
    n3n_benchmark_register(&bench_32);
    n3n_benchmark_register(&bench_64);
    n3n_benchmark_register(&bench_128);
    n3n_benchmark_register(&bench_256);
}
