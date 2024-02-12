/**
 * Copyright (C) 2024 Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * code for generically displaying and enumerating metrics
 */

#include <connslot/strbuf.h>
#include <n3n/metrics.h>
#include <stdint.h>

static struct n3n_metrics_module *registered_metrics;

void n3n_metrics_register (struct n3n_metrics_module *module) {
    module->next = registered_metrics;
    registered_metrics = module;
}

static void metric_stringify (strbuf_t **buf, const struct n3n_metrics_item item, void *data) {
    if(item.offset < 0) {
        sb_reprintf(buf, "offset<0");
        return;
    }
    void *valvoid = (char *)data + item.offset;

    switch(item.size) {
        case n3n_metrics_invalid:
            sb_reprintf(buf, "n3n_metrics_invalid");
            return;
        case n3n_metrics_uint32: {
            uint32_t *val = (uint32_t *)valvoid;
            sb_reprintf(buf, "%u", *val);
            return;
        }
    }
}

void n3n_metrics_render (strbuf_t **reply) {
    sb_zero(*reply);
    sb_reprintf(reply, "Temporary testing format for metric output!\n");

    struct n3n_metrics_module *module;
    for(module = registered_metrics; module; module = module->next) {
        sb_reprintf(reply, "[%s]\n", module->name);
        if(!module->item) {
            continue;
        }
        if(!module->data) {
            continue;
        }
        if(!module->enabled) {
            continue;
        }

        for(int i = 0; module->item[i].name; i++) {
            sb_reprintf(reply, "%s=", module->item[i].name);
            metric_stringify(reply, module->item[i], module->data);
            sb_reprintf(reply, "\n");
        }
    }
}

/**********************************************************/
// Register some metrics captured by external libraries

static struct n3n_metrics_item strbuf_metrics_items[] = {
    {
        .name = "zero",
        .offset = offsetof(struct strbuf_metrics, zero),
        .size = n3n_metrics_uint32,
    },
    {
        .name = "alloc",
        .offset = offsetof(struct strbuf_metrics, alloc),
        .size = n3n_metrics_uint32,
    },
    {
        .name = "realloc",
        .offset = offsetof(struct strbuf_metrics, realloc),
        .size = n3n_metrics_uint32,
    },
    {
        .name = "realloc_full",
        .offset = offsetof(struct strbuf_metrics, realloc_full),
        .size = n3n_metrics_uint32,
    },
    {
        .name = "append_full",
        .offset = offsetof(struct strbuf_metrics, append_full),
        .size = n3n_metrics_uint32,
    },
    {
        .name = "append_trunc",
        .offset = offsetof(struct strbuf_metrics, append_trunc),
        .size = n3n_metrics_uint32,
    },
    { },
};

static struct n3n_metrics_module strbuf_metrics_module = {
    .name = "strbuf",
    .data = &strbuf_metrics,
    .item = strbuf_metrics_items,
    .enabled = true,
};

/**********************************************************/

void n3n_initfuncs_metrics () {
    n3n_metrics_register(&strbuf_metrics_module);
}
