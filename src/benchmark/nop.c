/*
 * SPDX-License-Identifier: GPL-2.0-only
 * SPDX-FileCopyrightText: Copyright Hamish Coleman
 *
 */

#include <n3n/benchmark.h>
#include <n3n/pktbuf.h>

/* A do-nothing function to time the benchmark framework */
static const ssize_t bench_nop_run (
    void *ctx,
    const struct n3n_pktbuf *inbuf,
    ssize_t *in
) {
    *in = 0;
    return 0;
}

static struct bench_item bench_nop = {
    .name = "NOP",
    .flags = BENCH_SKIP_CHECK,
    .ctx_size = 0,
    .run = bench_nop_run,
    .data_in = test_data_none,
    .data_out = test_data_none,
};

void n3n_initfuncs_benchmark_nop () {
    n3n_benchmark_register(&bench_nop);
}
