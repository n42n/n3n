/**
 * Copyright (C) Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Routines for handling a pool of packet-sized buffers
 */

#include <n3n/metrics.h>
#include <stdlib.h>
#include <string.h>

#include "pktbuf.h"

static struct metrics {
    uint32_t alloc;     // n3n_pktbuf_alloc() is called
    uint32_t free;      // n3n_pktbuf_free() is called
} metrics;

static struct n3n_metrics_items_llu32 metrics_items = {
    .name = "count",
    .desc = "Track the pktbuf pool",
    .name1 = "event",
    .items = {
        {
            .val1 = "alloc",
            .offset = offsetof(struct metrics, alloc),
        },
        {
            .val1 = "free",
            .offset = offsetof(struct metrics, free),
        },
        { },
    },
};

static struct n3n_metrics_module metrics_module_static = {
    .name = "pktbuf",
    .data = &metrics,
    .items_llu32 = &metrics_items,
    .type = n3n_metrics_type_llu32,
};

static void *pool_buf;
static struct n3n_pktbuf *pool;
static struct n3n_pktbuf *pool_item_next_search;
static struct n3n_pktbuf *pool_item_max;
static ssize_t pool_item_size;
static ssize_t pool_item_data_size;
static int pool_item_count;

// Leave space at the start for any header prepend needed
static const ssize_t pool_item_prefix = 16;

void n3n_pktbuf_initialise(ssize_t mtu, int count) {
    if(pool) {
        if(metrics.alloc != metrics.free) {
            // Simplify logic by not allowing the pool shape to change while
            // there are any users
            return;
        }
        free(pool);
        free(pool_buf);
    }

    // Round up to a multiple
    int item_size = (mtu + 2047) & ~0x7ff;
    
    pool_buf = calloc(count, item_size);
    if(!pool_buf) {
        abort();
    }

    pool = calloc(count, sizeof(struct n3n_pktbuf));
    if(!pool) {
        abort();
    }

    pool_item_size = item_size;
    pool_item_count = count;
    pool_item_next_search = pool;
    pool_item_max = pool + (count - 1) * sizeof(struct n3n_pktbuf);

    // The prefix space is used for prepending headers, not for data, so 
    // subtract it from the data size calculation
    pool_item_data_size = item_size - pool_item_prefix;

    int i;
    for(i=0; i < pool_item_count; i++) {
        pool[i].buf = pool_buf + i * item_size;
        pool[i].capacity = item_size;
        pool[i].owner = n3n_pktbuf_owner_none;
        n3n_pktbuf_zero(&pool[i]);
    }
}

struct n3n_pktbuf *n3n_pktbuf_alloc(ssize_t size) {
    // We only have one pool, so we can use a simple check
    if(size > pool_item_data_size) {
        return NULL;
    }

    struct n3n_pktbuf *p = pool_item_next_search;
    int count = pool_item_count;

    while(count) {
        if(p > (struct n3n_pktbuf *)pool_item_max) {
            p = pool;
        }

        if(p->owner == n3n_pktbuf_owner_none) {
            p->owner = n3n_pktbuf_owner_alloc;
            n3n_pktbuf_zero(p);

            pool_item_next_search = p + pool_item_size;
            metrics.alloc++;
            return p;
        }

        p += pool_item_size;
        count--;
    }
    return NULL;
}

void n3n_pktbuf_free(struct n3n_pktbuf *p) {
    // Confirm we are within the pool boundaries
    if(p < (struct n3n_pktbuf *)pool) {
        return;
    }
    if(p > (struct n3n_pktbuf *)pool_item_max) {
        return;
    }

    p->owner = n3n_pktbuf_owner_none;
    pool_item_next_search = p;
    metrics.free++;
}

void n3n_pktbuf_zero(struct n3n_pktbuf *p) {
    p->offset_start = pool_item_prefix;
    p->offset_end = pool_item_prefix;
}

ssize_t n3n_pktbuf_getbufsize(struct n3n_pktbuf *p) {
    return p->offset_end - p->offset_start;
}

ssize_t n3n_pktbuf_getbufavail(struct n3n_pktbuf *p) {
    return p->capacity - p->offset_end;
}

void *n3n_pktbuf_getbufptr(struct n3n_pktbuf *p) {
    return &p->buf[p->offset_start];
}

int n3n_pktbuf_prepend(struct n3n_pktbuf *p, ssize_t size) {
    int new_start = p->offset_start + size;
    if(new_start < 0) {
        return -1;
    }
    p->offset_start = new_start;
    return 1;
}

int n3n_pktbuf_append(struct n3n_pktbuf *p, ssize_t size, void *buf) {
    int new_end = p->offset_end + size;
    if(new_end > p->capacity) {
        return -1;
    }
    p->offset_end = new_end;
    memcpy(&p->buf[p->offset_end], buf, size);
    return 1;
}

void n3n_initfuncs_pktbuf() {
    n3n_metrics_register(&metrics_module_static);
}
