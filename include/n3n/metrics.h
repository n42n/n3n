/**
 * Copyright (C) 2024 Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Public API for adding metrics
 */

#ifndef _N2N_METRICS_H_
#define _N2N_METRICS_H_

#include <connslot/strbuf.h>
#include <stdbool.h>

enum n3n_metrics_size {
    n3n_metrics_invalid = 0,
    n3n_metrics_uint32,
};

struct n3n_metrics_item {
    const char *name;           // What is this metric called
    const char *desc;           // Short description
    const int offset;           // byte Offset from the start of the void
    const enum n3n_metrics_size size;  // The storage size
    // type - today, they are all counters
    // unit - today, they are all unitless
};

struct n3n_metrics_module {
    struct n3n_metrics_module *next;     // the metrics.c manages this
    const char *name;           // What is this module called
    void *data;                 // pointer to the data
    const struct n3n_metrics_item *item;
    bool enabled;               // Allows the registering owner to disable
};

// Register a block of metrics
void n3n_metrics_register (struct n3n_metrics_module *);

// Render all the metrics into a strbuf
void n3n_metrics_render (strbuf_t **reply);

#endif
