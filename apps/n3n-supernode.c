/**
 * (C) 2007-22 - ntop.org and contributors
 * Copyright (C) 2023 Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not see see <http://www.gnu.org/licenses/>
 *
 */


#include <connslot/connslot.h>
#include <ctype.h>             // for isspace
#include <errno.h>             // for errno
#include <getopt.h>            // for required_argument, getopt_long, no_arg...
#include <header_encryption.h> // for packet_header_setup_key
#include <n3n/conffile.h>      // for n3n_config_set_option
#include <n3n/initfuncs.h>     // for n3n_initfuncs()
#include <n3n/logging.h>       // for traceEvent
#include <n3n/supernode.h>     // for load_allowed_sn_community, calculate_s...
#include <signal.h>            // for signal, SIGHUP, SIGINT, SIGPIPE, SIGTERM
#include <stdbool.h>
#include <stdint.h>            // for uint8_t, uint32_t
#include <stdio.h>             // for printf, NULL, fclose, fgets, fopen
#include <stdlib.h>            // for exit, atoi, calloc, free
#include <string.h>            // for strerror, strlen, memcpy, strncpy, str...
#include <sys/types.h>         // for time_t, u_char, u_int
#include <time.h>              // for time
#include <unistd.h>            // for _exit, daemon, getgid, getuid, setgid
#include "n2n.h"               // for n2n_edge, sn_community
#include "uthash.h"            // for UT_hash_handle, HASH_ITER, HASH_ADD_STR

// FIXME, including private headers
#include "../src/peer_info.h"         // for peer_info

#ifdef _WIN32
#include "../src/win32/defs.h"  // FIXME: untangle the include path
#else
#include <arpa/inet.h>         // for inet_addr
#include <netinet/in.h>        // for ntohl, INADDR_ANY, INADDR_NONE, in_addr_t
#include <pwd.h>               // for getpwnam, passwd
#include <sys/socket.h>        // for listen, AF_INET
#endif

#define HASH_FIND_COMMUNITY(head, name, out) HASH_FIND_STR(head, name, out)

static struct n3n_runtime_data sss_node;

/* *************************************************** */

#define GETOPTS "O:Vdhv"

static const struct option long_options[] = {
    {"daemon",              no_argument,       NULL, 'd'},
    {"help",                no_argument,       NULL, 'h'},
    {"verbose",             no_argument,       NULL, 'v'},
    {"version",             no_argument,       NULL, 'V'},
    {NULL,                  0,                 NULL, 0}
};

static const struct n3n_config_getopt option_map[] = {
    { 'O', NULL, NULL, NULL, "<section>.<option>=<value>  Set any config" },
    { 'V', NULL, NULL, NULL, "       Show the version" },
    { 'd',  "daemon",       "background",           "true" },
    { 'v', NULL, NULL, NULL, "       Increase logging verbosity" },
    { .optkey = 0 }
};

/* *************************************************** */

// little wrapper to show errors if the conffile parser has a problem
static void set_option_wrap (n2n_edge_conf_t *conf, char *section, char *option, char *value) {
    int i = n3n_config_set_option(conf, section, option, value);
    if(i==0) {
        return;
    }

    traceEvent(TRACE_WARNING, "Error setting %s.%s=%s\n", section, option, value);
}

/* *************************************************** */

/* read command line options */
static void loadFromCLI (int argc, char * const argv[], struct n3n_runtime_data *sss) {
    struct n2n_edge_conf *conf = &sss->conf;
    // TODO: refactor the getopt to only need conf, and avoid passing sss

    int c = 0;
    while(c != -1) {
        c = getopt_long(
            argc,
            argv,
            GETOPTS,
            long_options,
            NULL
        );

        //traceEvent(TRACE_NORMAL, "Option %c = %s", optkey, optarg ? optarg : "");

        switch(c) {
            case 'O': { // Set any config option
                char *section = strtok(optarg, ".");
                char *option = strtok(NULL, "=");
                char *value = strtok(NULL, "");
                set_option_wrap(conf, section, option, value);
                break;
            }

            case 'v': /* verbose */
                setTraceLevel(getTraceLevel() + 1);
                break;

            case -1: // dont try to set from option map the end sentinal
                break;

            default:
                n3n_config_from_getopt(option_map, conf, c, optarg);
        }
    }
}

/********************************************************************/

static struct n3n_subcmd_def cmd_top[]; // Forward define


static void cmd_debug_config_addr (int argc, char **argv, void *conf) {
    n3n_config_debug_addr(conf, stdout);
    exit(0);
}

static void cmd_debug_config_dump (int argc, char **argv, void *conf) {
    int level=1;
    if(argv[1]) {
        level = atoi(argv[1]);
    }
    n3n_config_dump(conf, stdout, level);
    exit(0);
}

static void cmd_debug_config_load_dump (int argc, char **argv, void *conf) {
    n3n_config_dump(conf, stdout, 1);
    exit(0);
}

static void cmd_help_about (int argc, char **argv, void *conf) {
    printf("n3n - a peer to peer VPN for when you have noLAN\n"
           "\n"
           " usage: supernode [options...] [command] [command args]\n"
           "\n"
           " e.g: supernode start [sessionname]\n"
           "\n"
           "  Loads the config based on the sessionname (default 'supernode.conf')\n"
           "  Any commandline options override the config loaded\n"
           "\n"
           "Some commands for more help:\n"
           "\n"
           " supernode help commands\n"
           " supernode help options\n"
           " supernode help\n"
           "\n"
    );
    exit(0);
}

static void cmd_help_commands (int argc, char **argv, void *conf) {
    n3n_subcmd_help(cmd_top, 1, true);
    exit(0);
}

static void cmd_help_config (int argc, char **argv, void *conf) {
    printf("Full config file description is available using the edge:\n");
    printf("    edge help config\n");
    exit(0);
}

static void cmd_help_options (int argc, char **argv, void *conf) {
    n3n_config_help_options(option_map, long_options);
    exit(0);
}

static void cmd_help_version (int argc, char **argv, void *conf) {
    print_n3n_version();
    exit(0);
}

static void cmd_start (int argc, char **argv, void *conf) {
    // Simply avoid triggering the "Unknown sub com" message
    return;
}

static struct n3n_subcmd_def cmd_debug_config[] = {
    {
        .name = "addr",
        .help = "show internal config addresses and sizes",
        .type = n3n_subcmd_type_fn,
        .fn = &cmd_debug_config_addr,
    },
    {
        .name = "dump",
        .help = "[level] - just dump the default config",
        .type = n3n_subcmd_type_fn,
        .fn = &cmd_debug_config_dump,
    },
    {
        .name = "load_dump",
        .help = "[sessionname] - load from all normal sources, then dump",
        .type = n3n_subcmd_type_fn,
        .fn = &cmd_debug_config_load_dump,
        .session_arg = true,
    },
    { .name = NULL }
};

static struct n3n_subcmd_def cmd_debug[] = {
    {
        .name = "config",
        .type = n3n_subcmd_type_nest,
        .nest = cmd_debug_config,
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
    {
        .name = "config",
        .help = "config file help",
        .type = n3n_subcmd_type_fn,
        .fn = cmd_help_config,
    },
    {
        .name = "options",
        .help = "Describe all commandline options ",
        .type = n3n_subcmd_type_fn,
        .fn = cmd_help_options,
    },
    {
        .name = "version",
        .help = "Show the version",
        .type = n3n_subcmd_type_fn,
        .fn = cmd_help_version,
    },
    { .name = NULL }
};

static struct n3n_subcmd_def cmd_top[] = {
    {
        .name = "debug",
        .type = n3n_subcmd_type_nest,
        .nest = cmd_debug,
    },
    {
        .name = "help",
        .type = n3n_subcmd_type_nest,
        .nest = cmd_help,
    },
    {
        .name = "start",
        .help = "[sessionname] - starts session",
        .type = n3n_subcmd_type_fn,
        .fn = &cmd_start,
        .session_arg = true,
    },
    { .name = NULL }
};

// Almost, but not quite, the same as the edge version
// TODO: refactor them to be the same, and then reuse the implementation
static void n3n_sn_config (int argc, char **argv, char *defname, struct n3n_runtime_data *sss) {
    n2n_edge_conf_t *conf = &sss->conf;

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
            cmd_help_version(0, NULL, NULL);
        case n3n_subcmd_result_about:
            cmd_help_about(0, NULL, NULL);
        case n3n_subcmd_result_ok:
            break;
    }

    // If no session name has been found, use the default
    if(!cmd.sessionname) {
        cmd.sessionname = defname;
    }

    // Now that we might need it, setup some default config
    sn_init_conf_defaults(sss, cmd.sessionname);

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
        loadFromCLI(argc, argv, sss);
    }

    // Do the selected subcmd
    cmd.subcmd->fn(cmd.argc, cmd.argv, conf);
}



/* *************************************************** */

static bool keep_running = true;

#if defined(__linux__) || defined(_WIN32)
#ifdef _WIN32
BOOL WINAPI term_handler (DWORD sig)
#else
static void term_handler (int sig)
#endif
{
    static int called = 0;

    if(called) {
        traceEvent(TRACE_NORMAL, "ok, I am leaving now");
        _exit(0);
    } else {
        traceEvent(TRACE_NORMAL, "shutting down...");
        called = 1;
    }

    keep_running = false;
#ifdef _WIN32
    return(TRUE);
#endif
}
#endif /* defined(__linux__) || defined(_WIN32) */

/* *************************************************** */

/** Main program entry point from kernel. */
int main (int argc, char * argv[]) {

    // Do this early to register all internals
    n3n_initfuncs();

    n3n_sn_config(argc, argv, "supernode", &sss_node);

    if(sss_node.conf.community_file)
        load_allowed_sn_community(&sss_node);

#ifndef _WIN32
    if(sss_node.conf.background) {
        setUseSyslog(1); /* traceEvent output now goes to syslog. */

        if(-1 == daemon(0, 0)) {
            traceEvent(TRACE_ERROR, "failed to become daemon");
            exit(-5);
        }
    }
#endif

    /* Initialize the federation name from conf */
    sss_node.federation->community[0] = '*';
    memcpy(
        &sss_node.federation->community[1],
        sss_node.conf.sn_federation,
        N2N_COMMUNITY_SIZE - 2
    );
    sss_node.federation->community[N2N_COMMUNITY_SIZE - 1] = '\0';

    /*setup the encryption key */
    packet_header_setup_key(sss_node.federation->community,
                            &(sss_node.federation->header_encryption_ctx_static),
                            &(sss_node.federation->header_encryption_ctx_dynamic),
                            &(sss_node.federation->header_iv_ctx_static),
                            &(sss_node.federation->header_iv_ctx_dynamic));

    HASH_ADD_STR(sss_node.communities, community, sss_node.federation);

    uint32_t num_communities = HASH_COUNT(sss_node.communities);

    traceEvent(
        TRACE_INFO,
        "added federation '%s' to the list of communities [total: %u]",
        (char*)sss_node.federation->community,
        num_communities
    );

    // warn on default federation name
    if(!strcmp(&sss_node.federation->community[1], FEDERATION_NAME_DEFAULT)) {
        traceEvent(TRACE_WARNING, "The default federation name is FOR TESTING ONLY - use of a custom setting for supernode.federation is highly recommended!");
    }

    // After configuration phase, move the federation edges to their runtime
    // place
    sss_node.federation->edges = sss_node.conf.sn_edges;

    if(!sss_node.conf.spoofing_protection) {
        traceEvent(
            TRACE_WARNING,
            "disabled MAC and IP address spoofing protection; "
            "FOR TESTING ONLY, usage of user-password authentication options "
            "is recommended instead!"
        );
    }

    if(sss_node.conf.sn_min_auto_ip_net.net_bitlen != sss_node.conf.sn_max_auto_ip_net.net_bitlen) {
        traceEvent(
            TRACE_ERROR,
            "mismatched auto IP subnet (%i != %i)",
            sss_node.conf.sn_min_auto_ip_net.net_bitlen,
            sss_node.conf.sn_max_auto_ip_net.net_bitlen
        );
        exit(1);
    }
    if(sss_node.conf.sn_min_auto_ip_net.net_bitlen > 30 || sss_node.conf.sn_min_auto_ip_net.net_bitlen == 0) {
        traceEvent(
            TRACE_ERROR,
            "invalid auto IP subnet (0 > %i > 30)",
            sss_node.conf.sn_min_auto_ip_net.net_bitlen
        );
        exit(1);
    }

    if(ntohl(sss_node.conf.sn_min_auto_ip_net.net_addr) > ntohl(sss_node.conf.sn_max_auto_ip_net.net_bitlen)) {
        traceEvent(TRACE_ERROR, "auto IP min cannot be > max");
        exit(1);
    }

    dec_ip_str_t ip_min_str = {'\0'};
    dec_ip_str_t ip_max_str = {'\0'};

    inet_ntop(
        AF_INET,
        &sss_node.conf.sn_min_auto_ip_net.net_addr,
        ip_min_str,
        sizeof(ip_min_str)
    );
    inet_ntop(
        AF_INET,
        &sss_node.conf.sn_max_auto_ip_net.net_addr,
        ip_max_str,
        sizeof(ip_max_str)
    );

    traceEvent(
        TRACE_NORMAL,
        "auto ip address range is '%s...%s/%hhu'",
        ip_min_str,
        ip_max_str,
        sss_node.conf.sn_min_auto_ip_net.net_bitlen
    );

    calculate_shared_secrets(&sss_node);

    traceEvent(TRACE_DEBUG, "traceLevel is %d", getTraceLevel());

    struct sockaddr_in *sa = (struct sockaddr_in *)sss_node.conf.bind_address;

    sss_node.sock = open_socket(
        sss_node.conf.bind_address,
        sizeof(*sss_node.conf.bind_address),
        0 /* UDP */
    );

    if(-1 == sss_node.sock) {
        traceEvent(TRACE_ERROR, "failed to open main socket. %s", strerror(errno));
        exit(-2);
    } else {
        traceEvent(TRACE_NORMAL, "supernode is listening on UDP %u (main)", ntohs(sa->sin_port));
    }

#ifdef N2N_HAVE_TCP
    sss_node.tcp_sock = open_socket(
        sss_node.conf.bind_address,
        sizeof(*sss_node.conf.bind_address),
        1 /* TCP */
    );
    if(-1 == sss_node.tcp_sock) {
        traceEvent(TRACE_ERROR, "failed to open auxiliary TCP socket, %s", strerror(errno));
        exit(-2);
    } else {
        traceEvent(TRACE_INFO, "supernode opened TCP %u (aux)", ntohs(sa->sin_port));
    }

    if(-1 == listen(sss_node.tcp_sock, N2N_TCP_BACKLOG_QUEUE_SIZE)) {
        traceEvent(TRACE_ERROR, "failed to listen on auxiliary TCP socket, %s", strerror(errno));
        exit(-2);
    } else {
        traceEvent(TRACE_NORMAL, "supernode is listening on TCP %u (aux)", ntohs(sa->sin_port));
    }
#endif

    sss_node.mgmt_slots = slots_malloc(5, 5000, 500);
    if(!sss_node.mgmt_slots) {
        abort();
    }

    if(sss_node.conf.mgmt_port) {
        if(slots_listen_tcp(sss_node.mgmt_slots, sss_node.conf.mgmt_port, false)!=0) {
            perror("slots_listen_tcp");
            exit(1);
        }
        traceEvent(TRACE_NORMAL, "supernode is listening on TCP %u (management)", sss_node.conf.mgmt_port);
    }

    n3n_config_setup_sessiondir(&sss_node.conf);

#ifndef _WIN32
    char unixsock[1024];
    snprintf(unixsock, sizeof(unixsock), "%s/mgmt", sss_node.conf.sessiondir);

    int e = slots_listen_unix(
        sss_node.mgmt_slots,
        unixsock,
        sss_node.conf.mgmt_sock_perms,
        sss_node.conf.userid,
        sss_node.conf.groupid
    );
    // TODO:
    // - do we actually want to tie the user/group to the running pid?

    if(e !=0) {
        perror("slots_listen_tcp");
        exit(1);
    }
#endif

    // Add our freshly opened socket to any edges added by federation
    // TODO: this uses internal peer_info struct, move it to sn_utils?
    // (It is the last user in this file, so yes, move it)
    struct peer_info *scan, *tmp;
    HASH_ITER(hh, sss_node.federation->edges, scan, tmp) {
        scan->socket_fd = sss_node.sock;
    }

#ifndef _WIN32

    /*
     * If we have a non-zero requested uid/gid, attempt to switch to use
     * those
     */
    if((sss_node.conf.userid != 0) || (sss_node.conf.groupid != 0)) {
        traceEvent(TRACE_INFO, "dropping privileges to uid=%d, gid=%d",
                   (signed int)sss_node.conf.userid, (signed int)sss_node.conf.groupid);

        /* Finished with the need for root privileges. Drop to unprivileged user. */
        if((setgid(sss_node.conf.groupid) != 0)
           || (setuid(sss_node.conf.userid) != 0)) {
            traceEvent(TRACE_ERROR, "unable to drop privileges [%u/%s]", errno, strerror(errno));
        }
    }

    if((getuid() == 0) || (getgid() == 0)) {
        traceEvent(
            TRACE_WARNING,
            "running as root is discouraged, check out the userid/groupid options"
        );
    }
#endif

    sn_init(&sss_node);

    traceEvent(TRACE_NORMAL, "supernode started");

#ifdef __linux__
    signal(SIGPIPE, SIG_IGN);
    signal(SIGTERM, term_handler);
    signal(SIGINT,  term_handler);
#endif
#ifdef _WIN32
    SetConsoleCtrlHandler(term_handler, TRUE);
#endif

    sss_node.keep_running = &keep_running;
    return run_sn_loop(&sss_node);
}
