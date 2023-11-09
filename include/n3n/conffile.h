/**
 * Copyright (C) 2023 Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Public API for configuration management
 */

#ifndef _N2N_CONFFILE_H_
#define _N2N_CONFFILE_H_

enum n3n_conf_type {
    n3n_conf_strncpy,
    n3n_conf_bool,
    n3n_conf_uint32,
    n3n_conf_strdup,
    n3n_conf_transform,
};

struct n3n_conf_option {
    char *name;                 // The name used to configure this option
    enum n3n_conf_type type;    // Which parser/validator to use
    int length;                 // Max length for string copy types
    int offset;                 // offset within the conf structure of value
    char *desc;                 // Short description
    char *help;                 // lengthy description
};

struct n3n_conf_section {
    struct n3n_conf_section *next;
    char *name;                 // The name of this config section
    struct n3n_conf_option *options;
};

void n3n_config_register_section (char *, struct n3n_conf_option[]);

int n3n_config_set_option (void *, char *, char *, char *);

#endif

