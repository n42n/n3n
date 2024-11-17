/**
 * Copyright (C) 2024 Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Public API for adding metrics
 */

#ifndef _N2N_METRICS_H_
#define _N2N_METRICS_H_

#include <connslot/strbuf.h>

enum __attribute__((__packed__)) n3n_metrics_items_type {
    n3n_metrics_type_invalid = 0,
    n3n_metrics_type_uint32,    // items_uint32 is valid
    n3n_metrics_type_llu32,
};

// The simplest type of metrics: everything is the same storage type, there are
// no custom labels are added to anything and only one instance is possible.
// The module definition points to an array of items, terminated with an entry
// that has item->name == NULL.
// This can be rendered with no callbacks by the metrics renderer
struct n3n_metrics_items_uint32 {
    const char *name;           // tail of the metrics name
    const char *desc;           // Help text for the metric
    const int offset;           // Offset from the start of the void
    // const enum foo type - today, they are all counters
    // const enum foo unit - today, they are all unitless
};

struct n3n_metrics_items_llu32_ent {
    const char *val1;
    const char *val2;
    const int offset;           // Offset from the start of the void
};

struct n3n_metrics_items_llu32 {
    const char *name;           // tail of the metrics name
    const char *desc;           // Help text for the metric
    const char *name1;
    const char *name2;
    const struct n3n_metrics_items_llu32_ent items[];
    // const enum foo type - today, they are all counters
    // const enum foo unit - today, they are all unitless
};

struct n3n_metrics_module {
    struct n3n_metrics_module *next;     // the metrics.c manages this
    const char *name;           // What is this module called
    void *data;                 // opaque pointer to the data
    union {
        const struct n3n_metrics_items_uint32 *items_uint32;
        const struct n3n_metrics_items_llu32 *items_llu32;
    };
    const enum n3n_metrics_items_type type;
};

// Register a block of metrics
void n3n_metrics_register (struct n3n_metrics_module *);

// Render all the metrics into a strbuf
void n3n_metrics_render (strbuf_t **reply);

// Set the session name for all metrics
void n3n_metrics_set_session (const char *);

#endif
