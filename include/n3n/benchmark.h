/*
 * Copyright (C) Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 */

#ifndef _N3N_BENCHMARK_H_
#define _N3N_BENCHMARK_H_

#include <sys/types.h>
#include <stdint.h>

enum n3n_test_data {
    test_data_none = 0,
    test_data_32x16,
    test_data_pearson_256,
    test_data_pearson_128,
    test_data_lzo,
    test_data_speck,
    test_data_cc20,
    test_data_aes,
    test_data_tf,
    test_data_pdu_v3,
    test_data_pdu_eth,
};

#define BENCH_ITEM_CHECKONLY   0x1  // benchmark should be skipped

struct bench_item {
    struct bench_item *next;

    const char *name;                     // What is this testing
    const char *variant;                  // variant, eg name of optimisation
    int flags;
    void *(*const setup)(void);           // Any pre-run setup
    const ssize_t(*const run)(
        void *const ctx,
        const void *data_in,
        const ssize_t data_in_size,
        ssize_t *const bytes_in
    );
    int(*const check)(void *const ctx, const int level);   // Custom check fn
    const void *const (*const get_output)(void *const ctx);
    void(*const teardown)(void *const ctx);   // destroy any setup done
    enum n3n_test_data data_in;     // What test_data buffer to use as input
    enum n3n_test_data data_out;    // What test_data buffer to check output

    // Perf processing tmp storage
    int fd[2];              // perf event fd (.0 == group leader)
    int id[2];              // perf event id

    // Returned Results
    int sec;            // How many seconds did we run for
    int usec;           // add how many microseconds
    ssize_t bytes_in;  // Total input bytes processed by all the runs
    ssize_t bytes_out; // Total output bytes processed by all the runs
    uint64_t loops;     // How many loops did we get
    uint64_t cycles;    // how many CPU cycles elapsed
    uint64_t instr;     // how many CPU instructions retired
};

void n3n_benchmark_register (struct bench_item *);

void benchmark_run_all (const int level, const int seconds);
int benchmark_check_all (int level);

#endif
