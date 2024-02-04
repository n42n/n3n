/** @file
 * Internal interface definitions for the strbuf abstraction
 *
 * Copyright (C) Hamish Coleman
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef STRBUF_H
#define STRBUF_H 1

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/**
 * The strbuf type
 *
 */
typedef struct strbuf {
    unsigned int capacity;      //!< The current storage capacity of str[]
    unsigned int capacity_max;  //!< The largest automatic allowed capacity
    unsigned int wr_pos;        //!< str[] append position (arriving data)
    unsigned int rd_pos;        //!< str[] read position (processing data)
    char str[];
} strbuf_t;

/**
 * Initialise a memory area to become a strbuf.
 *
 * @param buf is a strbuf pointer
 * @param p is a the pre-defined memory that we will use for the
 * strbuf object (must be a known sized object)
 */
#define STRBUF_INIT(buf,p) do { \
        buf = (void *)p; \
        buf->capacity = sizeof(p) - sizeof(strbuf_t); \
        buf->capacity_max = buf->capacity; \
        buf->wr_pos = 0; \
} while(0)

void sb_zero(strbuf_t *);
strbuf_t *sb_malloc(size_t, size_t) __attribute__ ((malloc));
strbuf_t *sb_realloc(strbuf_t **, size_t);
size_t sb_len(strbuf_t *);
ssize_t sb_avail(strbuf_t *);
bool sb_full(strbuf_t *);
size_t sb_append(strbuf_t *, void *, ssize_t);
strbuf_t *sb_reappend(strbuf_t **, void *, size_t);
size_t sb_vprintf(strbuf_t *, const char *, va_list);
size_t sb_printf(strbuf_t *, const char *, ...)
__attribute__ ((format (printf, 2, 3)));
size_t sb_reprintf(strbuf_t **, const char *, ...)
__attribute__ ((format (printf, 2, 3)));
ssize_t sb_read(int, strbuf_t *);
ssize_t sb_write(int, strbuf_t *, int, ssize_t);
void sb_dump(strbuf_t *);

// Collect some metrics
struct strbuf_metrics {
    uint32_t zero;
    uint32_t alloc;
    uint32_t realloc_full;
    uint32_t append_full;
    uint32_t append_trunc;
};
extern struct strbuf_metrics strbuf_metrics;

#ifdef METRICS
#define STRBUF_METRIC(n) strbuf_metrics.n++
#else
#define STRBUF_METRIC(n)
#endif

#endif
