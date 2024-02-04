/**
 * Copyright (C) 2023-24 Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Public API for configuration management
 */

#ifndef _N2N_CONFFILE_H_
#define _N2N_CONFFILE_H_

#include <getopt.h>

#include <stdbool.h>
#include <stdio.h>

enum n3n_conf_type {
    n3n_conf_strncpy,
    n3n_conf_bool,
    n3n_conf_uint32,
    n3n_conf_strdup,
    n3n_conf_transform,
    n3n_conf_headerenc,
    n3n_conf_compression,
    n3n_conf_supernode,     // TODO: could merge with _conf_sockaddr
    n3n_conf_privatekey,
    n3n_conf_publickey,
    n3n_conf_sockaddr,
    n3n_conf_n2n_sock_addr, // TODO: want to replace users with sockaddr
    n3n_conf_sn_selection,
    n3n_conf_verbose,
    n3n_conf_filter_rule,
    n3n_conf_ip_subnet,
    n3n_conf_ip_mode,
    n3n_conf_userid,
    n3n_conf_groupid,
};

struct n3n_conf_option {
    char *name;                 // The name used to configure this option
    int length;                 // Max length for string copy types
    int offset;                 // offset within the conf structure of value
    char *desc;                 // Short description
    char *help;                 // lengthy description
    enum n3n_conf_type type;    // Which parser/validator to use
};

struct n3n_conf_section {
    struct n3n_conf_section *next;
    char *name;                 // The name of this config section
    char *help;                 // A description for this section
    struct n3n_conf_option *options;
};

void n3n_config_register_section (char *, char *, struct n3n_conf_option[]);

int n3n_config_set_option (void *, char *, char *, char *);

void n3n_config_dump (void *, FILE *, int);
void n3n_config_debug_addr (void *, FILE *);

int n3n_config_load_env (void *);

int n3n_config_load_file (void *, char *);

enum n3n_subcmd_type {
    n3n_subcmd_type_nest = 1,
    n3n_subcmd_type_fn
};
struct n3n_subcmd_def {
    char *name;
    char *help;
    union {
        struct n3n_subcmd_def *nest;
        void (*fn)(int argc, char **argv, void *conf);
    };
    enum n3n_subcmd_type type;
    bool session_arg;   // is the next arg a session name to load?
};

enum n3n_subcmd_result_type {
    n3n_subcmd_result_unknown,
    n3n_subcmd_result_version,
    n3n_subcmd_result_about,
    n3n_subcmd_result_ok
};
struct n3n_subcmd_result {
    char **argv;
    char *sessionname;
    int argc;
    enum n3n_subcmd_result_type type;
    struct n3n_subcmd_def *subcmd;
};

void n3n_subcmd_help (struct n3n_subcmd_def *, int, bool);
struct n3n_subcmd_result n3n_subcmd_parse (int, char **, char *, const struct option *, struct n3n_subcmd_def *);

struct n3n_config_getopt {
    int optkey;
    char *section;
    char *option;
    char *value;    // if no optarg, then use this for the value
    char *help;
};

void n3n_config_from_getopt (const struct n3n_config_getopt *map, void *conf, int optkey, char *optarg);
void n3n_config_help_options (const struct n3n_config_getopt *map, const struct option *long_options);

typedef struct n2n_edge_conf n2n_edge_conf_t;
int n3n_config_setup_sessiondir (n2n_edge_conf_t *conf);
#endif
