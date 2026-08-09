/*
 * SPDX-License-Identifier: GPL-2.0-only
 * SPDX-FileCopyrightText: Copyright Hamish Coleman
 *
 */

#include <n3n/benchmark.h>
#include <time.h>
#include <sys/time.h>

struct bench_ctx {
    time_t time;
    struct timeval tv;
};

static void *bench_setup (void *const _ctx) {
    struct bench_ctx *ctx = (struct bench_ctx *)_ctx;

    ctx->time = 0;
    ctx->tv.tv_sec = 0;
    ctx->tv.tv_usec = 0;
    return ctx;
}

static const ssize_t bench_time_run (
    void *_ctx,
    const void *data_in,
    const ssize_t data_in_size,
    ssize_t *in
) {
    struct bench_ctx *ctx = (struct bench_ctx *)_ctx;

    *in = 0;
    ctx->time = time(NULL);
    return sizeof(ctx->time);
}

static const ssize_t bench_gettimeofday_run (
    void *_ctx,
    const void *data_in,
    const ssize_t data_in_size,
    ssize_t *in
) {
    struct bench_ctx *ctx = (struct bench_ctx *)_ctx;

    *in = 0;
    gettimeofday(&ctx->tv, NULL);
    return sizeof(ctx->tv);
}

static struct bench_item bench_time = {
    .name = "time",
    .flags = BENCH_SKIP_CHECK,
    .ctx_size = sizeof(struct bench_ctx),
    .setup = bench_setup,
    .run = bench_time_run,
    .data_in = test_data_none,
    .data_out = test_data_none,
};

static struct bench_item bench_gettimeofday = {
    .name = "gettimeofday",
    .flags = BENCH_SKIP_CHECK,
    .ctx_size = sizeof(struct bench_ctx),
    .setup = bench_setup,
    .run = bench_gettimeofday_run,
    .data_in = test_data_none,
    .data_out = test_data_none,
};

void n3n_initfuncs_benchmark_gettime () {
    n3n_benchmark_register(&bench_gettimeofday);
    n3n_benchmark_register(&bench_time);
}
