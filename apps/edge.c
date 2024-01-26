/**
 * (C) 2007-22 - ntop.org and contributors
 * Copyright (C) 2023-24 Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.    See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not see see <http://www.gnu.org/licenses/>
 *
 */


#include <ctype.h>                   // for isspace
#include <errno.h>                   // for errno
#include <getopt.h>                  // for required_argument, no_argument
#include <n3n/conffile.h>            // for n3n_config_set_option
#include <n3n/edge.h>
#include <n3n/initfuncs.h>           // for n3n_initfuncs()
#include <n3n/logging.h>             // for traceEvent
#include <n3n/tests.h>               // for test_hashing
#include <n3n/transform.h>           // for n3n_transform_lookup_id
#include <signal.h>                  // for signal, SIG_IGN, SIGPIPE, SIGCHLD
#include <stdbool.h>
#include <stdint.h>                  // for uint8_t, uint16_t
#include <stdio.h>                   // for printf, NULL, fclose, snprintf
#include <stdlib.h>                  // for atoi, exit, calloc, free, malloc
#include <string.h>                  // for strncpy, memset, strlen, strcmp
#include <sys/param.h>               // for MIN
#include <sys/time.h>                // for timeval
#include <sys/types.h>               // for u_char
#include <time.h>                    // for time
#include <unistd.h>                  // for setuid, _exit, chdir, fork, getgid
#include "auth.h"                    // for generate_private_key, generate_p...
#include "n2n.h"                     // for n2n_edge_conf_t, n2n_edge_t, fil...
#include "pearson.h"                 // for pearson_hash_64
#include "portable_endian.h"         // for htobe32
#include "random_numbers.h"          // for n2n_seed, n2n_srand
#include "sn_selection.h"            // for sn_selection_sort, sn_selection_...
#include "speck.h"                   // for speck_init, speck_context_t
#include "uthash.h"                  // for UT_hash_handle, HASH_ADD, HASH_C...

// FIXME, including a private header
#include "../src/peer_info.h"        // for peer_info, peer_info_t

#ifdef _WIN32
#include "../src/win32/defs.h"  // FIXME: untangle the include path
#else
#include <arpa/inet.h>               // for inet_addr, inet_ntop
#include <netinet/in.h>              // for INADDR_ANY, INADDR_NONE, ntohl
#include <pwd.h>                     // for getpwnam, passwd
#include <sys/select.h>              // for select, FD_ISSET, FD_SET, FD_ZERO
#include <sys/socket.h>              // for AF_INET
#endif

/* *************************************************** */

/** maximum length of command line arguments */
#define MAX_CMDLINE_BUFFER_LENGTH        4096

/** maximum length of a line in the configuration file */
#define MAX_CONFFILE_LINE_LENGTH         1024

/* ***************************************************** */

#ifdef HAVE_LIBCAP

#include <sys/capability.h>
#include <sys/prctl.h>

static cap_value_t cap_values[] = {
    //CAP_NET_RAW,            /* Use RAW and PACKET sockets */
    CAP_NET_ADMIN         /* Needed to performs routes cleanup at exit */
};

int num_cap = sizeof(cap_values)/sizeof(cap_value_t);
#endif

// forward declaration for use in main()
void send_register_super (n2n_edge_t *eee);
void send_query_peer (n2n_edge_t *eee, const n2n_mac_t dst_mac);
int supernode_connect (n2n_edge_t *eee);
int supernode_disconnect (n2n_edge_t *eee);
int fetch_and_eventually_process_data (n2n_edge_t *eee, SOCKET sock,
                                       uint8_t *pktbuf, uint16_t *expected, uint16_t *position,
                                       time_t now);
int resolve_check (n2n_resolve_parameter_t *param, uint8_t resolution_request, time_t now);

/* *************************************************** */

#define GETOPTS "k:a:c:Eu:g:m:M:s:d:l:p:fvVhrt:i:I:J:P:S:DL:z:A:Hn:R:e:T:x:O:"

static const struct option long_options[] = {
    { "community",           required_argument, NULL, 'c' },
    { "help",                no_argument,       NULL, 'h' },
    { "supernode-list",      required_argument, NULL, 'l' },
    { "verbose",             no_argument,       NULL, 'v' },
    { "version",             no_argument,       NULL, 'V' },
    { NULL,                  0,                 NULL,  0  }
};

static const struct option_map_def {
    int optkey;
    char *section;
    char *option;
    char *value;    // if no optarg, then use this for the value
    char *help;
} option_map[] = {
    { 'A',  "community",    "cipher",           NULL },
    { 'O', NULL, NULL, NULL, "<section>.<option>=<value>  Set any config" },
    { 'V', NULL, NULL, NULL, "       Show the version" },
    { 'a', NULL, NULL, NULL, "<arg>  Set tuntap.address and tuntap.address_mode" },
    { 'c',  "community",    "name",             NULL },
    { 'f',  "daemon",       "background",       "false" },
    { 'k',  "community",    "key",              NULL },
    { 'l',  "community",    "supernode",        NULL },
    { 'r',  "filter",       "allow_routing",    "true" },
    { 'v', NULL, NULL, NULL, "       Increase logging verbosity" },
    { 'z',  "community",    "compression",      NULL },
    { .optkey = 0 }
};

/* *********************************************** */

// little wrapper to show errors if the conffile parser has a problem
static void set_option_wrap (n2n_edge_conf_t *conf, char *section, char *option, char *value) {
    int i = n3n_config_set_option(conf, section, option, value);
    if(i==0) {
        return;
    }

    traceEvent(TRACE_WARNING, "Error setting %s.%s=%s\n", section, option, value);
}

static void set_from_option_map (n2n_edge_conf_t *conf, int optkey, char *optarg) {
    int i = 0;
    while(option_map[i].optkey) {
        if(optkey != option_map[i].optkey) {
            i++;
            continue;
        }

        if((!optarg && !option_map[i].value) || !option_map[i].section || !option_map[i].option) {
            printf("Internal error with option_map for -%c\n", optkey);
            exit(1);
        }

        if(!optarg) {
            optarg = option_map[i].value;
        }

        set_option_wrap(
            conf,
            option_map[i].section,
            option_map[i].option,
            optarg
            );
        return;
    }

    printf("unknown option -%c", (char)optkey);
}

/* *************************************************** */

/* read command line options */
static void loadFromCLI (int argc, char *argv[], n2n_edge_conf_t *conf) {

    int c = 0;
    while(c != -1) {
        c = getopt_long(
            argc, argv,
            // The superset of all possible short options
            GETOPTS,
            long_options,
            NULL
            );

        /* traceEvent(TRACE_NORMAL, "Option %c = %s", optkey, optarg ? optarg : ""); */

        switch(c) {
            case 'O': { // Set any config option
                char *section = strtok(optarg, ".");
                char *option = strtok(NULL, "=");
                char *value = strtok(NULL, "");
                set_option_wrap(conf, section, option, value);
                break;
            }
            case 'a': /* IP address and mode of TUNTAP interface */ {
                /*
                 * of the form:
                 *
                 * ["static:"|"dhcp:","auto:"] <ip> [/<cidr subnet mask>]
                 *
                 * for example        static:192.168.8.5/24
                 *
                 */
                char *field2 = strchr(optarg, ':');
                if(field2) {
                    // We have a field #1, extract it
                    *field2++ = 0;
                    set_option_wrap(conf, "tuntap", "address_mode", optarg);
                } else {
                    set_option_wrap(conf, "tuntap", "address_mode", "static");
                    field2 = optarg;
                }

                set_option_wrap(conf, "tuntap", "address", field2);
                break;
            }

            case 'v': /* verbose */
                setTraceLevel(getTraceLevel() + 1);
                break;

            case -1: // dont try to set from option map the end sentinal
                break;

            default: {
                set_from_option_map(conf, c, optarg);
            }
        }
    }
}

/********************************************************************/
// Sub command generic processor

enum subcmd_type {
    subcmd_type_nest = 1,
    subcmd_type_fn
};
struct subcmd_def {
    char *name;
    char *help;
    union {
        struct subcmd_def *nest;
        void (*fn)(int argc, char **argv, n2n_edge_conf_t *conf);
    };
    enum subcmd_type type;
    bool session_arg;   // is the next arg a session name to load?
};
struct subcmd_result {
    int argc;
    char **argv;
    char *sessionname;
    struct subcmd_def *subcmd;
};

void subcmd_help (struct subcmd_def *p, int indent, bool recurse) {
    while(p->name) {
        printf(
            "%*c%-10s",
            indent,
            ' ',
            p->name
            );
        if(p->type == subcmd_type_nest) {
            printf(" ->");
        }
        if(p->help) {
            printf(" %s", p->help);
        }
        printf("\n");
        if(recurse && p->type == subcmd_type_nest) {
            subcmd_help(p->nest, indent +2, recurse);
        }
        p++;
    }
}

static void subcmd_help_simple (struct subcmd_def *p) {
    printf(
        "\n"
        "Try edge -h for help\n"
        "\n"
        "or add a subcommand:\n"
        "\n"
        );
    subcmd_help(p, 1, false);
    exit(1);
}

struct subcmd_result subcmd_lookup (struct subcmd_def *top, int argc, char **argv) {
    struct subcmd_result r;
    struct subcmd_def *p = top;
    while(p->name) {
        if(argc < 1) {
            // No subcmd to process
            subcmd_help_simple(top);
        }
        if(!argv) {
            // Null subcmd
            subcmd_help_simple(top);
        }

        if(strcmp(p->name, argv[0])!=0) {
            p++;
            continue;
        }

        switch(p->type) {
            case subcmd_type_nest:
                argc--;
                argv++;
                top = p->nest;
                p = top;
                continue;
            case subcmd_type_fn:
                if(p->session_arg) {
                    r.sessionname = argv[1];
                } else {
                    r.sessionname = NULL;
                }
                r.argc = argc;
                r.argv = argv;
                r.subcmd = p;
                return r;
        }
        printf("Internal Error subcmd->type: %i\n", p->type);
        exit(1);
    }
    printf("Unknown subcmd: '%s'\n", argv[0]);
    exit(1);
}

/********************************************************************/

static struct subcmd_def cmd_top[]; // Forward define

static void cmd_help_about (int argc, char **argv, n2n_edge_conf_t *conf) {
    printf("n3n - a peer to peer VPN for when you have noLAN\n"
           "\n"
           " usage: edge [options...] [command] [command args]\n"
           "\n"
           " e.g: edge start [sessionname]\n"
           "\n"
           "  Loads the config based on the sessionname (default 'edge.conf')\n"
           "  Any commandline options override the config loaded\n"
           "\n"
           "Some commands for more help:\n"
           "\n"
           " edge help commands\n"
           " edge help options\n"
           " edge help\n"
           "\n"
           );
    exit(0);
}

static void cmd_help_commands (int argc, char **argv, n2n_edge_conf_t *conf) {
    subcmd_help(cmd_top, 1, true);
    exit(0);
}

static void cmd_help_config (int argc, char **argv, n2n_edge_conf_t *conf) {
    n3n_config_dump(conf, stdout, 4);
    exit(0);
}

static void cmd_help_options (int argc, char **argv, n2n_edge_conf_t *conf) {
    int i;

    printf(" option    config\n");
    i = 0;
    while(option_map[i].optkey) {
        if(isprint(option_map[i].optkey)) {
            printf(" -%c ", option_map[i].optkey);
            if(option_map[i].help) {
                // Dont generate any text, just use the help text
                // (This is used for options that have no true mapping)
                printf("%s\n", option_map[i].help);
                i++;
                continue;
            }
            if(!option_map[i].value) {
                // We are expecting an arg with this option
                printf("<arg>");
            } else {
                printf("     ");
            }
            printf("  %s.%s=", option_map[i].section, option_map[i].option);
            if(!option_map[i].value) {
                printf("<arg>");
            } else {
                printf("%s", option_map[i].value);
            }
            printf("\n");
        }
        i++;
    }
    printf("\n");
    printf(" short  long\n");

    i = 0;
    while(long_options[i].name) {
        if(isprint(long_options[i].val)) {
            printf(" -%c     --%s", long_options[i].val, long_options[i].name);
            if(long_options[i].has_arg == required_argument) {
                printf("=<arg>");
            }
            printf("\n");
        }
        i++;
    }

    exit(0);
}

static void cmd_help_transform (int argc, char **argv, n2n_edge_conf_t *conf) {
    // TODO: add an interface to the registered transform lookups and print
    // out the list
    printf("Not implemented\n");
    exit(1);
}

static void cmd_help_version (int argc, char **argv, n2n_edge_conf_t *conf) {
    print_n3n_version();
    exit(0);
}

static void cmd_debug_config_addr (int argc, char **argv, n2n_edge_conf_t *conf) {
    n3n_config_debug_addr(conf, stdout);
    exit(0);
}

static void cmd_debug_config_dump (int argc, char **argv, n2n_edge_conf_t *conf) {
    int level=1;
    if(argv[1]) {
        level = atoi(argv[1]);
    }
    n3n_config_dump(conf, stdout, level);
    exit(0);
}

static void cmd_debug_config_load_dump (int argc, char **argv, n2n_edge_conf_t *conf) {
    n3n_config_dump(conf, stdout, 1);
    exit(0);
}

static void cmd_test_config_roundtrip (int argc, char **argv, n2n_edge_conf_t *conf) {
    if(!argv[1]) {
        printf("No session name given\n");
        exit(1);
    }

    // Because we want this test to be deterministic, we dont use the defaults
    // or load the normal way, we start with a zeroed out conf
    conf = malloc(sizeof(*conf));
    memset(conf, 0, sizeof(*conf));

    int r = n3n_config_load_file(conf, argv[1]);
    if(r != 0) {
        printf("Error loading config file (%i)\n", r);
        exit(1);
    }

    fprintf(stderr, "Loaded config file for session name: '%s'\n", argv[1]);

    // Save the session name for later
    conf->sessionname = argv[1];

    // Then dump it out
    n3n_config_dump(conf, stdout, 1);
    exit(0);
}

static void cmd_test_hashing (int argc, char **argv, n2n_edge_conf_t *conf) {
    int level=0;
    if(argv[1]) {
        level = atoi(argv[1]);
    }
    int errors = test_hashing(level);
    if(!errors) {
        printf("OK\n");
    }
    exit(errors);
}

static void cmd_tools_keygen (int argc, char **argv, n2n_edge_conf_t *conf) {
    if(argc == 1) {
        printf(
            "n3n keygen tool\n"
            "\n"
            "  usage: edge tools keygen <username> <password>\n"
            "\n"
            "     or  edge tools keygen <federation name>\n"
            "\n"
            "   outputs a line to insert at supernode's community file for\n"
            "   user-and-password authentication or the config option\n"
            "   value with the public federation key for use in the edge's\n"
            "   config, please refer to the doc/Authentication.md document\n"
            "   for more details\n"
            "\n"
            );
        exit(1);
    }

    char *private;
    n2n_private_public_key_t prv;  // 32 bytes private key
    n2n_private_public_key_t bin;  // 32 bytes public key binary output buffer
    char asc[44];   // 43 bytes + 0-terminator ascii string output
    bool fed;

    switch(argc) {
        case 3:
            private = argv[2];
            fed = false;
            break;
        case 2:
            private = argv[1];
            fed = true;
            break;
        default:
            printf("Unexpected number of args\n");
            exit(1);
    }

    // derive private key from username and password:
    // hash username once, hash password twice (so password is bound
    // to username but username and password are not interchangeable),
    // finally xor the result
    // in federation mode: only hash federation name, twice
    generate_private_key(prv, private);

    if(!fed) {
        // hash user name only if required
        bind_private_key_to_username(prv, argv[1]);
    }

    // calculate the public key into binary output buffer
    generate_public_key(bin, prv);

    // clear out the private key
    memset(prv, 0, sizeof(prv));

    // convert binary output to 6-bit-ascii string output
    bin_to_ascii(asc, bin, sizeof(bin));

    if(!fed) {
        printf("%c %s %s\n", N2N_USER_KEY_LINE_STARTER, argv[1], asc);
    } else {
        printf("auth.pubkey=%s\n", asc);
    }
    exit(0);
}

static void cmd_start (int argc, char **argv, n2n_edge_conf_t *conf) {
    // Simply avoid triggering the "Unknown sub com" message
    return;
}

static struct subcmd_def cmd_debug_config[] = {
    {
        .name = "addr",
        .help = "show internal config addresses and sizes",
        .type = subcmd_type_fn,
        .fn = &cmd_debug_config_addr,
    },
    {
        .name = "dump",
        .help = "[level] - just dump the default config",
        .type = subcmd_type_fn,
        .fn = &cmd_debug_config_dump,
    },
    {
        .name = "load_dump",
        .help = "[sessionname] - load from all normal sources, then dump",
        .type = subcmd_type_fn,
        .fn = &cmd_debug_config_load_dump,
        .session_arg = true,
    },
    { .name = NULL }
};

static struct subcmd_def cmd_debug[] = {
    {
        .name = "config",
        .type = subcmd_type_nest,
        .nest = cmd_debug_config,
    },
    { .name = NULL }
};

static struct subcmd_def cmd_help[] = {
    {
        .name = "about",
        .help = "Basic command help",
        .type = subcmd_type_fn,
        .fn = cmd_help_about,
    },
    {
        .name = "commands",
        .help = "Show all possible commandline commands",
        .type = subcmd_type_fn,
        .fn = cmd_help_commands,
    },
    {
        .name = "config",
        .help = "All config file help text",
        .type = subcmd_type_fn,
        .fn = cmd_help_config,
    },
    {
        .name = "options",
        .help = "Describe all commandline options ",
        .type = subcmd_type_fn,
        .fn = cmd_help_options,
    },
    {
        .name = "transform",
        .help = "Show compiled encryption and compression modules",
        .type = subcmd_type_fn,
        .fn = cmd_help_transform,
    },
    {
        .name = "version",
        .help = "Show the version",
        .type = subcmd_type_fn,
        .fn = cmd_help_version,
    },
    { .name = NULL }
};

static struct subcmd_def cmd_test_config[] = {
    {
        .name = "roundtrip",
        .help = "<sessionname> - load only the config file and then dump it",
        .type = subcmd_type_fn,
        .fn = &cmd_test_config_roundtrip,
    },
    { .name = NULL }
};

static struct subcmd_def cmd_tools[] = {
    {
        .name = "keygen",
        .help = "generate public keys",
        .type = subcmd_type_fn,
        .fn = &cmd_tools_keygen,
    },
    { .name = NULL }
};

static struct subcmd_def cmd_test[] = {
    {
        .name = "config",
        .type = subcmd_type_nest,
        .nest = cmd_test_config,
    },
    {
        .name = "hashing",
        .help = "test hashing functions",
        .type = subcmd_type_fn,
        .fn = &cmd_test_hashing,
    },
    { .name = NULL }
};

static struct subcmd_def cmd_top[] = {
    {
        .name = "debug",
        .type = subcmd_type_nest,
        .nest = cmd_debug,
    },
    {
        .name = "help",
        .type = subcmd_type_nest,
        .nest = cmd_help,
    },
    {
        .name = "start",
        .help = "[sessionname] - starts daemon",
        .type = subcmd_type_fn,
        .fn = &cmd_start,
        .session_arg = true,
    },
    {
        .name = "tools",
        .type = subcmd_type_nest,
        .nest = cmd_tools,
    },
    {
        .name = "test",
        .type = subcmd_type_nest,
        .nest = cmd_test,
    },
    { .name = NULL }
};

static void n3n_config (int argc, char **argv, char *defname, n2n_edge_conf_t *conf) {

    // A first pass through to reorder the argv
    int c = 0;
    while(c != -1) {
        c = getopt_long(
            argc, argv,
            // The superset of all possible short options
            GETOPTS,
            long_options,
            NULL
            );

        switch(c) {
            case '?': // An invalid arg, or a missing optarg
                exit(1);
            case 'V':
                cmd_help_version(0, NULL, NULL);
            case 'h': /* quick reference */
                cmd_help_about(0, NULL, NULL);
        }
    }

    if(optind >= argc) {
        // There is no sub-command provided
        subcmd_help_simple(cmd_top);
    }
    // We now know there is a sub command on the commandline

    struct subcmd_result cmd = subcmd_lookup(
        cmd_top,
        argc - optind,
        &argv[optind]
        );

    // If no session name has been found, use the default
    if(!cmd.sessionname) {
        cmd.sessionname = defname;
    }

    // Now that we might need it, setup some default config
    edge_init_conf_defaults(conf);

    if(cmd.subcmd->session_arg) {
        // the cmd structure can request the normal loading of config

        int r = n3n_config_load_file(conf, cmd.sessionname);
        if(r == -1) {
            printf("Error loading config file\n");
            exit(1);
        }
        if(r == -2) {
            printf(
                "Warning: no config file found for session '%s'\n",
                cmd.sessionname
                );
        }

        // Update the loaded conf with the current environment
        if(n3n_config_load_env(conf)!=0) {
            printf("Error loading environment variables\n");
            exit(1);
        }

        // Update the loaded conf with any option args
        optind = 1;
        loadFromCLI(argc, argv, conf);

        // Record the session name we used
        conf->sessionname = cmd.sessionname;
    }

    // Do the selected subcmd
    cmd.subcmd->fn(cmd.argc, cmd.argv, conf);
}

/* ************************************** */

#ifndef _WIN32
static void daemonize () {
    int childpid;

    traceEvent(TRACE_NORMAL, "parent process is exiting (this is normal)");

    signal(SIGPIPE, SIG_IGN);
    signal(SIGHUP,  SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
    signal(SIGQUIT, SIG_IGN);

    if((childpid = fork()) < 0)
        traceEvent(TRACE_ERROR, "occurred while daemonizing (errno=%d)",
                   errno);
    else {
        if(!childpid) { /* child */
            int rc;

            //traceEvent(TRACE_NORMAL, "Bye bye: I'm becoming a daemon...");
            rc = chdir("/");
            if(rc != 0)
                traceEvent(TRACE_ERROR, "error while moving to / directory");

            setsid();    /* detach from the terminal */

            fclose(stdin);
            fclose(stdout);
            /* fclose(stderr); */

            /*
             * clear any inherited file mode creation mask
             */
            //umask(0);

            /*
             * Use line buffered stdout
             */
            /* setlinebuf (stdout); */
            setvbuf(stdout, (char *)NULL, _IOLBF, 0);
        } else /* father */
            exit(0);
    }
}
#endif

/* *************************************************** */

static bool keep_on_running = true;

static void term_handler (int sig) {
    static int called = 0;

    if(called) {
        traceEvent(TRACE_NORMAL, "ok, I am leaving now");
        _exit(0);
    } else {
        traceEvent(TRACE_NORMAL, "shutting down...");
        called = 1;
    }

    keep_on_running = false;
}

#ifdef _WIN32
BOOL WINAPI ConsoleCtrlHandler (DWORD sig) {
    term_handler(sig);

    switch(sig) {
        case CTRL_CLOSE_EVENT:
        case CTRL_LOGOFF_EVENT:
        case CTRL_SHUTDOWN_EVENT:
            // Will terminate us after we return, blocking it to cleanup
            Sleep(INFINITE);
    }
    return(TRUE);
}
#endif

/* *************************************************** */

/** Entry point to program from kernel. */
int main (int argc, char* argv[]) {

    int rc;
    n2n_edge_t *eee;              /* single instance for this program */
    n2n_edge_conf_t conf;         /* generic N2N edge config */
    uint8_t runlevel = 0;         /* bootstrap: runlevel */
    uint8_t seek_answer = 1;      /*            expecting answer from supernode */
    time_t now, last_action = 0;  /*            timeout */
    macstr_t mac_buf;             /*            output mac address */
    fd_set socket_mask;           /*            for supernode answer */
    struct timeval wait_time;     /*            timeout for sn answer */
    peer_info_t *scan, *scan_tmp; /*            supernode iteration */

    uint16_t expected = sizeof(uint16_t);
    uint16_t position = 0;
    uint8_t pktbuf[N2N_SN_PKTBUF_SIZE + sizeof(uint16_t)]; /* buffer + prepended buffer length in case of tcp */

#ifdef HAVE_LIBCAP
    cap_t caps;
#endif
#ifdef _WIN32
    initWin32();
#endif

    // Do this early to register all internals
    n3n_initfuncs();

    n3n_config(argc, argv, "edge", &conf);

    // --- additional crypto setup; REVISIT: move to edge_init()?
    // payload
    if(conf.transop_id == N2N_TRANSFORM_ID_NULL) {
        if(conf.encrypt_key) {
            // make sure that AES is default cipher if key only (and no cipher) is specified
            traceEvent(TRACE_WARNING, "switching to AES as key was provided and no cipher set");
            conf.transop_id = N2N_TRANSFORM_ID_AES;
        }
    }
    // user auth
    if(conf.shared_secret /* containing private key only so far*/) {
        // if user-password auth and no federation public key provided, use default
        if(!conf.federation_public_key) {
            conf.federation_public_key = calloc(1, sizeof(n2n_private_public_key_t));
            if(conf.federation_public_key) {
                traceEvent(
                    TRACE_WARNING,
                    "using default federation public key; "
                    "FOR TESTING ONLY, usage of a custom federation name and "
                    "key (auth.pubkey) is highly recommended!"
                    );
                generate_private_key(*(conf.federation_public_key), &FEDERATION_NAME[1]);
                generate_public_key(*(conf.federation_public_key), *(conf.federation_public_key));
            }
        }
        // calculate public key and shared secret
        if(conf.federation_public_key) {
            traceEvent(TRACE_NORMAL, "using username and password for edge authentication");
            bind_private_key_to_username(*(conf.shared_secret), (char *)conf.dev_desc);
            conf.public_key = calloc(1, sizeof(n2n_private_public_key_t));
            if(conf.public_key)
                generate_public_key(*conf.public_key, *(conf.shared_secret));
            generate_shared_secret(*(conf.shared_secret), *(conf.shared_secret), *(conf.federation_public_key));
            // prepare (first 128 bit) for use as key
            conf.shared_secret_ctx = (he_context_t*)calloc(1, sizeof(speck_context_t));
            speck_init((speck_context_t**)&(conf.shared_secret_ctx), *(conf.shared_secret), 128);
        }
        // force header encryption
        if(conf.header_encryption != HEADER_ENCRYPTION_ENABLED) {
            traceEvent(TRACE_NORMAL, "enabling header encryption for edge authentication");
            conf.header_encryption = HEADER_ENCRYPTION_ENABLED;
        }
    }

    if(edge_verify_conf(&conf) != 0)
        cmd_help_about(0, NULL, NULL);

    traceEvent(TRACE_NORMAL, "starting n3n edge %s %s", VERSION, BUILDDATE);

#ifdef HAVE_LIBCRYPTO
    traceEvent(TRACE_NORMAL, "using %s", OpenSSL_version(0));
#endif

    traceEvent(TRACE_NORMAL, "using compression: %s.", n3n_compression_id2str(conf.compression));
    traceEvent(TRACE_NORMAL, "using %s cipher.", n3n_transform_id2str(conf.transop_id));

    /* Random seed */
    n2n_srand(n2n_seed());

#ifndef _WIN32
    /* If running suid root then we need to setuid before using the force. */
    if(setuid(0) != 0)
        traceEvent(TRACE_ERROR, "unable to become root [%u/%s]", errno, strerror(errno));
    /* setgid(0); */
#endif

    if(conf.encrypt_key && !strcmp((char*)conf.community_name, conf.encrypt_key))
        traceEvent(TRACE_WARNING, "community and encryption key must differ, otherwise security will be compromised");

    if((eee = edge_init(&conf, &rc)) == NULL) {
        traceEvent(TRACE_ERROR, "failed in edge_init");
        exit(1);
    }

    switch(eee->conf.tuntap_ip_mode) {
        case TUNTAP_IP_MODE_SN_ASSIGN:
            traceEvent(TRACE_NORMAL, "automatically assign IP address by supernode");
            break;
        case TUNTAP_IP_MODE_STATIC:
            traceEvent(TRACE_NORMAL, "use manually set IP address");
            break;
        case TUNTAP_IP_MODE_DHCP:
            traceEvent(TRACE_NORMAL, "obtain IP from other edge DHCP services");
            break;
        default:
            traceEvent(TRACE_ERROR, "unknown ip_mode");
            break;
    }

    // mini main loop for bootstrap, not using main loop code because some of its mechanisms do not fit in here
    // for the sake of quickly establishing connection. REVISIT when a more elegant way to re-use main loop code
    // is found

    // find at least one supernode alive to faster establish connection
    // exceptions:
    if((HASH_COUNT(eee->conf.supernodes) <= 1) || (eee->conf.connect_tcp) || (eee->conf.shared_secret)) {
        // skip the initial supernode ping
        traceEvent(TRACE_DEBUG, "skip PING to supernode");
        runlevel = 2;
    }

    eee->last_sup = 0; /* if it wasn't zero yet */
    eee->curr_sn = eee->conf.supernodes;
    supernode_connect(eee);
    while(runlevel < 5) {

        now = time(NULL);

        // we do not use switch-case because we also check for 'greater than'

        if(runlevel == 0) { /* PING to all known supernodes */
            last_action = now;
            eee->sn_pong = 0;
            // (re-)initialize the number of max concurrent pings (decreases by calling send_query_peer)
            eee->conf.number_max_sn_pings = NUMBER_SN_PINGS_INITIAL;
            send_query_peer(eee, null_mac);
            traceEvent(TRACE_INFO, "send PING to supernodes");
            runlevel++;
        }

        if(runlevel == 1) { /* PING has been sent to all known supernodes */
            if(eee->sn_pong) {
                // first answer
                eee->sn_pong = 0;
                sn_selection_sort(&(eee->conf.supernodes));
                eee->curr_sn = eee->conf.supernodes;
                supernode_connect(eee);
                traceEvent(TRACE_NORMAL, "received first PONG from supernode [%s]", eee->curr_sn->ip_addr);
                runlevel++;
            } else if(last_action <= (now - BOOTSTRAP_TIMEOUT)) {
                // timeout
                runlevel--;
                // skip waiting for answer to direcly go to send PING again
                seek_answer = 0;
                traceEvent(TRACE_DEBUG, "PONG timeout");
            }
        }

        // by the way, have every later PONG cause the remaining (!) list to be sorted because the entries
        // before have already been tried; as opposed to initial PONG, do not change curr_sn
        if(runlevel > 1) {
            if(eee->sn_pong) {
                eee->sn_pong = 0;
                if(eee->curr_sn->hh.next) {
                    sn_selection_sort((peer_info_t**)&(eee->curr_sn->hh.next));
                    traceEvent(TRACE_DEBUG, "received additional PONG from supernode");
                    // here, it is hard to detemine from which one, so no details to output
                }
            }
        }

        if(runlevel == 2) { /* send REGISTER_SUPER to get auto ip address from a supernode */
            if(eee->conf.tuntap_ip_mode == TUNTAP_IP_MODE_SN_ASSIGN) {
                last_action = now;
                eee->sn_wait = 1;
                send_register_super(eee);
                runlevel++;
                traceEvent(TRACE_INFO, "send REGISTER_SUPER to supernode [%s] asking for IP address",
                           eee->curr_sn->ip_addr);
            } else {
                runlevel += 2; /* skip waiting for TUNTAP IP address */
                traceEvent(TRACE_DEBUG, "skip auto IP address asignment");
            }
        }

        if(runlevel == 3) { /* REGISTER_SUPER to get auto ip address from a sn has been sent */
            if(!eee->sn_wait) { /* TUNTAP IP address received */
                runlevel++;
                traceEvent(TRACE_INFO, "received REGISTER_SUPER_ACK from supernode for IP address asignment");
                // it should be from curr_sn, but we can't determine definitely here, so no details to output
            } else if(last_action <= (now - BOOTSTRAP_TIMEOUT)) {
                // timeout, so try next supernode
                if(eee->curr_sn->hh.next)
                    eee->curr_sn = eee->curr_sn->hh.next;
                else
                    eee->curr_sn = eee->conf.supernodes;
                supernode_connect(eee);
                runlevel--;
                // skip waiting for answer to direcly go to send REGISTER_SUPER again
                seek_answer = 0;
                traceEvent(TRACE_DEBUG, "REGISTER_SUPER_ACK timeout");
            }
        }

        if(runlevel == 4) { /* configure the TUNTAP device, including routes */
            if(tuntap_open(&eee->device,
                           eee->conf.tuntap_dev_name,
                           eee->conf.tuntap_ip_mode,
                           eee->conf.tuntap_v4,
                           eee->conf.device_mac,
                           eee->conf.mtu,
                           eee->conf.metric) < 0)
                exit(1);
            in_addr_t addr = eee->conf.tuntap_v4.net_addr;
            traceEvent(TRACE_NORMAL, "created local tap device IPv4: %s/%u, MAC: %s",
                       inet_ntoa(*(struct in_addr*)&addr),
                       eee->conf.tuntap_v4.net_bitlen,
                       macaddr_str(mac_buf, eee->device.mac_addr));
            runlevel = 5;
            // no more answers required
            seek_answer = 0;
        }

        // we usually wait for some answer, there however are exceptions when going back to a previous runlevel
        if(seek_answer) {
            FD_ZERO(&socket_mask);
            FD_SET(eee->sock, &socket_mask);
            wait_time.tv_sec = BOOTSTRAP_TIMEOUT;
            wait_time.tv_usec = 0;

            if(select(eee->sock + 1, &socket_mask, NULL, NULL, &wait_time) > 0) {
                if(FD_ISSET(eee->sock, &socket_mask)) {

                    fetch_and_eventually_process_data(eee, eee->sock,
                                                      pktbuf, &expected, &position,
                                                      now);
                }
            }
        }
        seek_answer = 1;

        resolve_check(eee->resolve_parameter, 0 /* no intermediate resolution requirement at this point */, now);
    }
    // allow a higher number of pings for first regular round of ping
    // to quicker get an inital 'supernode selection criterion overview'
    eee->conf.number_max_sn_pings = NUMBER_SN_PINGS_INITIAL;
    // shape supernode list; make current one the first on the list
    HASH_ITER(hh, eee->conf.supernodes, scan, scan_tmp) {
        if(scan == eee->curr_sn)
            sn_selection_criterion_good(&(scan->selection_criterion));
        else
            sn_selection_criterion_default(&(scan->selection_criterion));
    }
    sn_selection_sort(&(eee->conf.supernodes));
    // do not immediately ping again, allow some time
    eee->last_sweep = now - SWEEP_TIME + 2 * BOOTSTRAP_TIMEOUT;
    eee->sn_wait = 1;
    eee->last_register_req = 0;

#ifndef _WIN32
    if(conf.daemon) {
        setUseSyslog(1); /* traceEvent output now goes to syslog. */
        daemonize();
    }

#ifdef HAVE_LIBCAP
    /* Before dropping the privileges, retain capabilities to regain them in future. */
    caps = cap_get_proc();

    cap_set_flag(caps, CAP_PERMITTED, num_cap, cap_values, CAP_SET);
    cap_set_flag(caps, CAP_EFFECTIVE, num_cap, cap_values, CAP_SET);

    if((cap_set_proc(caps) != 0) || (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) != 0))
        traceEvent(TRACE_WARNING, "unable to retain permitted capabilities [%s]\n", strerror(errno));
#else
#ifndef __APPLE__
    traceEvent(TRACE_WARNING, "n3n has not been compiled with libcap-dev; some commands may fail");
#endif
#endif /* HAVE_LIBCAP */

    if((conf.userid != 0) || (conf.groupid != 0)) {
        traceEvent(TRACE_NORMAL, "dropping privileges to uid=%d, gid=%d",
                   (signed int)conf.userid, (signed int)conf.groupid);

        /* Finished with the need for root privileges. Drop to unprivileged user. */
        if((setgid(conf.groupid) != 0)
           || (setuid(conf.userid) != 0)) {
            traceEvent(TRACE_ERROR, "unable to drop privileges [%u/%s]", errno, strerror(errno));
            exit(1);
        }
    }

    if((getuid() == 0) || (getgid() == 0))
        traceEvent(TRACE_WARNING, "running as root is discouraged, check out the -u/-g options");
#endif /* _WIN32 */

#ifndef _WIN32
    signal(SIGPIPE, SIG_IGN);
    signal(SIGTERM, term_handler);
    signal(SIGINT,  term_handler);
#endif
#ifdef _WIN32
    SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);
#endif

    eee->keep_running = &keep_on_running;
    traceEvent(TRACE_NORMAL, "edge started");
    rc = run_edge_loop(eee);
    print_edge_stats(eee);

#ifdef HAVE_LIBCAP
    /* Before completing the cleanup, regain the capabilities as some
     * cleanup tasks require them (e.g. routes cleanup). */
    cap_set_flag(caps, CAP_EFFECTIVE, num_cap, cap_values, CAP_SET);

    if(cap_set_proc(caps) != 0)
        traceEvent(TRACE_WARNING, "could not regain the capabilities [%s]\n", strerror(errno));

    cap_free(caps);
#endif

    /* Cleanup */
    edge_term_conf(&eee->conf);
    tuntap_close(&eee->device);
    edge_term(eee);

    return(rc);
}

/* ************************************** */
