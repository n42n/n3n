/*
 * SPDX-License-Identifier: GPL-2.0-only
 * SPDX-FileCopyrightText: Copyright Hamish Coleman
 *
 */

#include <n3n/benchmark.h>

/* A do-nothing function to time the benchmark framework */
static const ssize_t bench_nop_run (
    void *ctx,
    const void *data_in,
    const ssize_t data_in_size,
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
