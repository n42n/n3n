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


#include <n3n/benchmark.h>
#include <n3n/hexdump.h>   // for fhexdump
#include <n3n/logging.h> // for traceEvent
#include <n3n/transform.h>   // for n3n_transform_register
#include <stdint.h>     // for uint8_t
#include <stdlib.h>     // for size_t, calloc, free, NULL
#include <string.h>     // for memset
#include <stdbool.h>

#include "minilzo.h"    // for lzo1x_1_compress, lzo1x_decompress, LZO1X_1_M...
#include "n2n.h"        // for n2n_trans_op_t, N2N_...
#include "n2n_define.h"
#include "n2n_typedefs.h"


/* heap allocation for compression as per lzo example doc  */
#define HEAP_ALLOC(var,size)   lzo_align_t __LZO_MMODEL var [ ((size) + (sizeof(lzo_align_t) - 1)) / sizeof(lzo_align_t) ]


typedef struct transop_lzo {
    HEAP_ALLOC(wrkmem, LZO1X_1_MEM_COMPRESS);
} transop_lzo_t;


static int transop_deinit_lzo (n2n_trans_op_t *arg) {

    transop_lzo_t *priv = (transop_lzo_t *)arg->priv;

    if(priv)
        free(priv);

    return 0;
}


// returns compressed packet length
// returns 0 if error occured, the caller would have to use
// original, i.e. uncompressed data then
static int transop_encode_lzo (n2n_trans_op_t *arg,
                               uint8_t *outbuf,
                               size_t out_len,
                               const uint8_t *inbuf,
                               size_t in_len,
                               const uint8_t *peer_mac) {

    transop_lzo_t *priv = (transop_lzo_t *)arg->priv;
    lzo_uint compression_len = 0;

    if(in_len > N2N_PKT_BUF_SIZE) {
        traceEvent(TRACE_ERROR, "encode_lzo inbuf wrong size (%ul) to compress", in_len);
        return 0;
    }

    if(out_len < in_len + in_len / 16 + 64 + 3) {
        traceEvent(TRACE_ERROR, "encode_lzo outbuf too small (%ul) to compress inbuf (%ul)",
                   out_len, in_len);
        return 0;
    }

    if(lzo1x_1_compress(inbuf, in_len, outbuf, &compression_len, priv->wrkmem) != LZO_E_OK) {
        traceEvent(TRACE_ERROR, "encode_lzo compression error");
        compression_len = 0;
    }

    return compression_len;
}


static int transop_decode_lzo (n2n_trans_op_t *arg,
                               uint8_t *outbuf,
                               size_t out_len,
                               const uint8_t *inbuf,
                               size_t in_len,
                               const uint8_t *peer_mac) {

    lzo_uint deflated_len = N2N_PKT_BUF_SIZE;

    if(in_len > N2N_PKT_BUF_SIZE) {
        traceEvent(TRACE_ERROR, "decode_lzo inbuf wrong size (%ul) to decompress", in_len);
        return 0;
    }

    lzo1x_decompress(inbuf, in_len, outbuf, &deflated_len, NULL);

    if(deflated_len > N2N_PKT_BUF_SIZE) {
        traceEvent(TRACE_ERROR, "decode_lzo outbuf wrong size (%ul) decompressed", deflated_len);
        return 0;
    }

    return deflated_len;
}


// lzo initialization function
int n2n_transop_lzo_init (const n2n_edge_conf_t *conf, n2n_trans_op_t *ttt) {

    transop_lzo_t *priv;

    memset(ttt, 0, sizeof(*ttt));
    ttt->transform_id = N2N_COMPRESSION_ID_LZO;

    ttt->deinit       = transop_deinit_lzo;
    ttt->fwd          = transop_encode_lzo;
    ttt->rev          = transop_decode_lzo;

    priv = (transop_lzo_t*)calloc(1, sizeof(transop_lzo_t));
    if(!priv) {
        traceEvent(TRACE_ERROR, "lzo_init cannot allocate transop_lzo memory");
        return -1;
    }
    ttt->priv = priv;

    if(lzo_init() != LZO_E_OK) {
        traceEvent(TRACE_ERROR, "lzo_init cannot init lzo compression");
        return -1;
    }

    return 0;
}

struct bench_ctx {
    transop_lzo_t priv;
    // for compression, want a outbuf (0x200 * 2) / 16 + 64 + 3 bytes
    // for uncompression, want to be able to test the largest expected MTU
    uint8_t outbuf[2048];
    lzo_uint outbuf_size;
};

static void *bench_lzo_setup (void) {
    return calloc(1, sizeof(struct bench_ctx));
}

static void bench_lzo_teardown (void *ctx) {
    free(ctx);
}

static const ssize_t bench_lzo_comp_run (
    void *_ctx,
    const void *data_in,
    const ssize_t data_in_size,
    ssize_t *bytes_in
) {
    struct bench_ctx *ctx = (struct bench_ctx *)_ctx;

    ctx->outbuf_size = 0;

    int result = lzo1x_1_compress(
        data_in,
        data_in_size,
        ctx->outbuf,
        &ctx->outbuf_size,
        ctx->priv.wrkmem
    );

    if(result != LZO_E_OK) {
        traceEvent(TRACE_ERROR, "encode_lzo compression error");
        ctx->outbuf_size = 0;
    }

    *bytes_in = data_in_size;
    return ctx->outbuf_size;
}

static const ssize_t bench_lzo_uncomp_run (
    void *_ctx,
    const void *data_in,
    const ssize_t data_in_size,
    ssize_t *bytes_in
) {
    struct bench_ctx *ctx = (struct bench_ctx *)_ctx;

    ctx->outbuf_size = sizeof(ctx->outbuf);

    lzo1x_decompress(
        data_in,
        data_in_size,
        ctx->outbuf,
        &ctx->outbuf_size,
        NULL
    );

    *bytes_in = data_in_size;
    return ctx->outbuf_size;
}

static const void *const bench_lzo_get_output (void *const _ctx) {
    struct bench_ctx *ctx = (struct bench_ctx *)_ctx;
    return &ctx->outbuf;
}

static struct n3n_transform transform = {
    .name = "lzo",
    .id = N2N_COMPRESSION_ID_LZO,
    .is_compress = true,
};

static struct bench_item bench_lzo_comp = {
    .name = "lzo_comp",
    .setup = bench_lzo_setup,
    .run = bench_lzo_comp_run,
    .get_output = bench_lzo_get_output,
    .teardown = bench_lzo_teardown,
    .data_in = test_data_32x16,
    .data_out = test_data_lzo,
};

static struct bench_item bench_lzo_uncomp = {
    .name = "lzo_uncomp",
    .setup = bench_lzo_setup,
    .run = bench_lzo_uncomp_run,
    .get_output = bench_lzo_get_output,
    .teardown = bench_lzo_teardown,
    .data_in = test_data_lzo,
    .data_out = test_data_32x16,
};

void n3n_initfuncs_transform_lzo () {
    n3n_transform_register(&transform);
    n3n_benchmark_register(&bench_lzo_comp);
    n3n_benchmark_register(&bench_lzo_uncomp);
}
