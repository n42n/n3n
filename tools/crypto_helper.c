/*
 * Copyright (C) 2024 Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Command line helper to expose the built-in crypto routines and allow them
 * to be easily used in tests.
 */

#include <getopt.h>             // for required_argument, getopt_long, no_arg...
#include <header_encryption.h>  // for packet_header_setup_key, packet_header...
#include <n2n_typedefs.h>       //
#include <n3n/conffile.h>
#include <n3n/initfuncs.h>
#include <pearson.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>             // for read, write


#define GETOPTS "Vhv"

static const struct option long_options[] = {
    {"help",                no_argument,       NULL, 'h'},
    {"verbose",             no_argument,       NULL, 'v'},
    {"version",             no_argument,       NULL, 'V'},
    {NULL,                  0,                 NULL, 0}
};
static struct n3n_subcmd_def cmd_top[]; // Forward define

static void cmd_header_decrypt (int argc, char **argv, void *conf) {
    if(!argv[1]) {
        printf("Need community name arg\n");
        exit(1);
    }

    n2n_community_t community;
    strncpy((char *)&community, argv[1], sizeof(community));
    community[sizeof(community)-1] = 0;

    struct speck_context_t *ctx_static;
    struct speck_context_t *ctx_dynamic;
    struct speck_context_t *ctx_iv_static;
    struct speck_context_t *ctx_iv_dynamic;

    packet_header_setup_key(
        community,
        &ctx_static,
        &ctx_dynamic,
        &ctx_iv_static,
        &ctx_iv_dynamic
    );

    int size;
    unsigned char buf[4096];
    size = read(0, &buf, sizeof(buf));

    uint64_t stamp = 0;
    int ok = packet_header_decrypt(
        buf,
        size,
        community,
        ctx_dynamic,
        ctx_iv_dynamic,
        &stamp
    );

    if(!ok) {
        uint8_t hash_buf[16] = {0};
        pearson_hash_128(
            hash_buf,
            buf,
            max(0, (int)size - (int)N2N_REG_SUP_HASH_CHECK_LEN)
        );
        ok = packet_header_decrypt(
            buf,
            max(0, (int)size - (int)N2N_REG_SUP_HASH_CHECK_LEN),
            community,
            ctx_static,
            ctx_iv_static,
            &stamp
        );
    }

    if(!ok) {
        exit(1);
    }

    write(1, &buf, size);
    exit(0);

}

static void cmd_help_about (int argc, char **argv, void *conf) {
    printf("n3n - helper for using internal crypto functions\n"
           "\n"
           " usage: crypto_helper [options...] [command] [command args]\n"
           "\n"
           " e.g: crypto_helper header decrypt '*Federation' <packet |hd\n"
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

static struct n3n_subcmd_def cmd_header[] = {
    {
        .name = "decrypt",
        .type = n3n_subcmd_type_fn,
        .fn = cmd_header_decrypt,
    },
    { .name = NULL }
};

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
        .name = "header",
        .type = n3n_subcmd_type_nest,
        .nest = cmd_header,
    },
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

int main (int argc, char **argv) {
    // Do this early to register the internals
    n3n_initfuncs();

    process_cli(argc, argv);
}
