/*
 * Copyright (C) 2024 Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Command line helper to expose the built-in crypto routines and allow them 
 * to be easily used in tests.
 */

#include <getopt.h>            // for required_argument, getopt_long, no_arg...
#include <n3n/conffile.h>
#include <n3n/initfuncs.h>
#include <pearson.h>
#include <stdlib.h>
#include <unistd.h>             // for read, write

#define GETOPTS "Vhv"

static const struct option long_options[] = {
    {"help",                no_argument,       NULL, 'h'},
    {"verbose",             no_argument,       NULL, 'v'},
    {"version",             no_argument,       NULL, 'V'},
    {NULL,                  0,                 NULL, 0}
};
static struct n3n_subcmd_def cmd_top[]; // Forward define

static void cmd_help_about (int argc, char **argv, void *conf) {
    printf("n3n - helper for using internal crypto functions\n"
           "\n"
           " usage: crypto_helper [options...] [command] [command args]\n"
           "\n"
           "  Runs the crypto operation specified on the commandline\n"
           "\n"
           "Some commands for more help:\n"
           "\n"
           " supernode help commands\n"
           " supernode help\n"
           "\n"
           );
    exit(0);
}

static void cmd_help_commands (int argc, char **argv, void *conf) {
    n3n_subcmd_help(cmd_top, 1, true);
    exit(0);
}

static void cmd_pearson_128 (int argc, char **argv, void *conf) {
    int size;
    unsigned char buf[4096];
    unsigned char hash[16];
    size = read(0, &buf, sizeof(buf));
    pearson_hash_128(hash, buf, size);
    write(1, &hash, sizeof(hash));
    exit(0);
}

static struct n3n_subcmd_def cmd_help[] = {
    {
        .name = "about",
        .help = "Basic command help",
        .type = n3n_subcmd_type_fn,
        .fn = cmd_help_about,
    },
    {
        .name = "commands",
        .help = "Show all possible commandline commands",
        .type = n3n_subcmd_type_fn,
        .fn = cmd_help_commands,
    },
    { .name = NULL }
};

static struct n3n_subcmd_def cmd_pearson[] = {
    {
        .name = "128",
        .type = n3n_subcmd_type_fn,
        .fn = cmd_pearson_128,
    },
    { .name = NULL }
};

static struct n3n_subcmd_def cmd_top[] = {
    {
        .name = "help",
        .type = n3n_subcmd_type_nest,
        .nest = cmd_help,
    },
    {
        .name = "pearson",
        .type = n3n_subcmd_type_nest,
        .nest = cmd_pearson,
    },
    { .name = NULL }
};

static void process_cli (int argc, char **argv) {

    struct n3n_subcmd_result cmd = n3n_subcmd_parse(
        argc,
        argv,
        GETOPTS,
        long_options,
        cmd_top
        );

    switch(cmd.type) {
        case n3n_subcmd_result_unknown:
            // Shouldnt happen
            abort();
        case n3n_subcmd_result_version:
            printf("%s\n", VERSION);
            exit(0);
        case n3n_subcmd_result_about:
            cmd_help_about(0, NULL, NULL);
        case n3n_subcmd_result_ok:
            break;
    }

    // Do the selected subcmd
    cmd.subcmd->fn(cmd.argc, cmd.argv, NULL);
}

int main(int argc, char **argv) {
    // Do this early to register the internals
    n3n_initfuncs();

    process_cli(argc, argv);
}
