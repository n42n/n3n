/*
 * Copyright (C) 2023 Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Handlers for configuration files
 */

#include <n3n/conffile.h>
#include <stdio.h>              // for printf
#include <stdlib.h>             // for malloc
#include <string.h>             // for strcmp

static struct n3n_conf_section *registered_sections;

void n3n_config_register_section (char *name, struct n3n_conf_option options[]) {
    struct n3n_conf_section *section;
    section = malloc(sizeof(*section));
    if(!section) {
        return;
    }

    // TODO: should confirm that we register each section name only once

    section->next = registered_sections;
    section->name = name;
    section->options = options;
    registered_sections = section;
}

static struct n3n_conf_option *lookup_section (char *section) {
    struct n3n_conf_section *p = registered_sections;
    while(p) {
        if(0==strcmp(p->name, section)) {
            return p->options;
        }
        p = p->next;
    }
    return NULL;
}

static struct n3n_conf_option *lookup_option (char *section, char *option) {
    struct n3n_conf_option *p = lookup_section(section);
    if(!p) {
        return NULL;
    }

    while(p->name) {
        if(0==strcmp(p->name, option)) {
            return p;
        }
        p++;
    }
    return NULL;
}

int n3n_config_set_option (void *conf, char *section, char *option, char *value) {
    struct n3n_conf_option *p = lookup_option(section, option);
    if(!p) {
        return -1;
    }

    switch(p->type) {
        case n3n_conf_strncpy: {
            char *dst = (char *)conf + p->offset;

            strncpy(dst, value, p->length);
            dst[p->length -1] = 0;
            return 0;
        }
    }
    return -1;
}
