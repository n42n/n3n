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

static void metric_stringify_uint32 (strbuf_t **buf, const int offset, void *data) {
    if(offset < 0) {
        sb_reprintf(buf, "offset<0");
        return;
    }
    void *valvoid = (char *)data + offset;
    uint32_t *val = (uint32_t *)valvoid;
    sb_reprintf(buf, "%u", *val);
    return;
}

static void metrics_name (strbuf_t **reply, const char *module_name, const char *name) {
    const char *program_prefix = "n3n";
    // TODO session_name

    sb_reprintf(
        reply,
        "%s_%s_%s",
        program_prefix,
        module_name,
        name
    );
}

static void metrics_render_uint32 (strbuf_t **reply, struct n3n_metrics_module *module) {
    for(int i = 0; module->items_uint32[i].name; i++) {
        // TODO:
        // - " TYPE name type\n"
        // - " UNIT name type\n"
        // - " HELP name type\n"
        metrics_name(reply, module->name, module->items_uint32[i].name);
        sb_reprintf(reply, " ");
        metric_stringify_uint32(
            reply,
            module->items_uint32[i].offset,
            module->data
        );
        sb_reprintf(reply, "\n");
    }
}

static void metrics_render_llu32 (strbuf_t **reply, struct n3n_metrics_module *module) {
    const struct n3n_metrics_items_llu32 *info = module->items_llu32;

    if(info->desc) {
        sb_reprintf(reply, "# HELP ");
        metrics_name(reply, module->name, info->name);
        sb_reprintf(reply, "%s\n", info->desc);
    }

    for(int i = 0; info->items[i].val1; i++) {
        // TODO:
        // - " TYPE name type\n"
        // - " UNIT name type\n"
        metrics_name(reply, module->name, info->name);
        sb_reprintf(
            reply,
            "{%s=\"%s\",%s=\"%s\"} ",
            info->name1,
            info->items[i].val1,
            info->name2,
            info->items[i].val2
        );
        metric_stringify_uint32(
            reply,
            info->items[i].offset,
            module->data
        );
        sb_reprintf(reply, "\n");
    }
}

void n3n_metrics_render (strbuf_t **reply) {
    sb_zero(*reply);
    sb_reprintf(reply, "# Still unstable testing format for metric output!\n");

    struct n3n_metrics_module *module;
    for(module = registered_metrics; module; module = module->next) {
        sb_reprintf(reply, "## module=%s\n", module->name);

        switch(module->type) {
            case n3n_metrics_type_invalid:
                break;
            case n3n_metrics_type_uint32:
                metrics_render_uint32(reply, module);
                break;
            case n3n_metrics_type_llu32:
                metrics_render_llu32(reply, module);
                break;
        }
    }
}

/**********************************************************/
// Register some metrics captured by external libraries

static struct n3n_metrics_items_llu32 strbuf_metrics_items = {
    .name = "count",
    .desc = "Track the events in the lifecycle of strbuf objects",
    .name1 = "severity",
    .name2 = "event",
    .items = {
        {
            .val1 = "info",
            .val2 = "zero",
            .offset = offsetof(struct strbuf_metrics, zero),
        },
        {
            .val1 = "info",
            .val2 = "alloc",
            .offset = offsetof(struct strbuf_metrics, alloc),
        },
        {
            .val1 = "info",
            .val2 = "realloc",
            .offset = offsetof(struct strbuf_metrics, realloc),
        },
        {
            .val1 = "warn",
            .val2 = "realloc_full",
            .offset = offsetof(struct strbuf_metrics, realloc_full),
        },
        {
            .val1 = "warn",
            .val2 = "append_full",
            .offset = offsetof(struct strbuf_metrics, append_full),
        },
        {
            .val1 = "warn",
            .val2 = "append_trunc",
            .offset = offsetof(struct strbuf_metrics, append_trunc),
        },
        { },
    },
};

static struct n3n_metrics_module strbuf_metrics_module = {
    .name = "strbuf",
    .data = &strbuf_metrics,
    .items_llu32 = &strbuf_metrics_items,
    .type = n3n_metrics_type_llu32,
};

/**********************************************************/

void n3n_initfuncs_metrics () {
    n3n_metrics_register(&strbuf_metrics_module);
}
