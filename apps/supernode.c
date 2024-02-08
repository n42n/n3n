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
#include "pearson.h"           // for pearson_hash_64
#include "uthash.h"            // for UT_hash_handle, HASH_ITER, HASH_ADD_STR

// FIXME, including private headers
#include "../src/peer_info.h"         // for peer_info, peer_info_init
#include "../src/resolve.h"           // for supernode2sock

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

#define GETOPTS "p:l:t:a:c:F:vhMV:m:fu:g:O:"

static const struct option long_options[] = {
    {"autoip",              required_argument, NULL, 'a'},
    {"communities",         required_argument, NULL, 'c'},
    {"help",                no_argument,       NULL, 'h'},
    {"verbose",             no_argument,       NULL, 'v'},
    {"version",             no_argument,       NULL, 'V'},
    {NULL,                  0,                 NULL, 0}
};

static const struct n3n_config_getopt option_map[] = {
    { 'O', NULL, NULL, NULL, "<section>.<option>=<value>  Set any config" },
    { 'a', NULL, NULL, NULL, "<arg>  Autoip network range" },
    { 'c',  "supernode",    "community_file",       NULL },
    { 'f',  "daemon",       "background",           "false" },
    { 'l', NULL, NULL, NULL, "<hostname>:<port>  Set a federated supernode" },
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
            case 'l': { /* supernode:port */
                // FIXME: needs a generic parser option

                if(!sss->federation) {
                    // Should never happen - sn_init_conf_defaults is called
                    // first and aborts if it cannot malloc it
                    break;
                }

                // TODO: This is almost identical to edge_conf_add_supernode()

                n2n_sock_t sock;
                memset(&sock, 0, sizeof(sock));

                int rv = supernode2sock(&sock, optarg);

                if(rv < -2) { /* we accept resolver failure as it might resolve later */
                    traceEvent(TRACE_WARNING, "invalid supernode parameter");
                    break;
                }

                int skip_add = SN_ADD;
                struct peer_info *anchor_sn = add_sn_to_list_by_mac_or_sock(&(sss->federation->edges), &sock, null_mac, &skip_add);

                if(!anchor_sn) {
                    break;
                }

                // FIXME: what if ->ip_addr is already set?
                anchor_sn->ip_addr = calloc(1, N2N_EDGE_SN_HOST_SIZE);
                if(!anchor_sn->ip_addr) {
                    // FIXME: add to list, but left half initialised
                    break;
                }
                strncpy(anchor_sn->ip_addr, optarg, N2N_EDGE_SN_HOST_SIZE - 1);
                memcpy(&(anchor_sn->sock), &sock, sizeof(sock));

                // If it added an entry, it is already peer_info_init()
                if(skip_add != SN_ADD_ADDED) {
                    peer_info_init(anchor_sn, null_mac);
                }

                // This is one of only two places where the default purgeable
                // is overwritten after an _alloc or _init
                anchor_sn->purgeable = false;

                break;
            }

            case 'a': {
                // FIXME: needs a generic parser option

                dec_ip_str_t ip_min_str = {'\0'};
                dec_ip_str_t ip_max_str = {'\0'};
                in_addr_t net_min, net_max;
                uint8_t bitlen;
                uint32_t mask;

                if(sscanf(optarg, "%15[^\\-]-%15[^/]/%hhu", ip_min_str, ip_max_str, &bitlen) != 3) {
                    traceEvent(TRACE_WARNING, "bad net-net/bit format '%s'.", optarg);
                    break;
                }

                net_min = inet_addr(ip_min_str);
                net_max = inet_addr(ip_max_str);
                mask = bitlen2mask(bitlen);
                if((net_min == (in_addr_t)(-1)) || (net_min == INADDR_NONE) || (net_min == INADDR_ANY)
                   || (net_max == (in_addr_t)(-1)) || (net_max == INADDR_NONE) || (net_max == INADDR_ANY)
                   || (ntohl(net_min) >  ntohl(net_max))
                   || ((ntohl(net_min) & ~mask) != 0) || ((ntohl(net_max) & ~mask) != 0)) {
                    traceEvent(TRACE_WARNING, "bad network range '%s...%s/%u' in '%s', defaulting to '%s...%s/%d'",
                               ip_min_str, ip_max_str, bitlen, optarg,
                               N2N_SN_MIN_AUTO_IP_NET_DEFAULT, N2N_SN_MAX_AUTO_IP_NET_DEFAULT, N2N_SN_AUTO_IP_NET_BIT_DEFAULT);
                    break;
                }

                if((bitlen > 30) || (bitlen == 0)) {
                    traceEvent(TRACE_WARNING, "bad prefix '%hhu' in '%s', defaulting to '%s...%s/%d'",
                               bitlen, optarg,
                               N2N_SN_MIN_AUTO_IP_NET_DEFAULT, N2N_SN_MAX_AUTO_IP_NET_DEFAULT, N2N_SN_AUTO_IP_NET_BIT_DEFAULT);
                    break;
                }

                traceEvent(TRACE_NORMAL, "the network range for community ip address service is '%s...%s/%hhu'", ip_min_str, ip_max_str, bitlen);

                sss->min_auto_ip_net.net_addr = ntohl(net_min);
                sss->min_auto_ip_net.net_bitlen = bitlen;
                sss->max_auto_ip_net.net_addr = ntohl(net_max);
                sss->max_auto_ip_net.net_bitlen = bitlen;

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
        .help = "All config file help text",
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
        .name = "help",
        .type = n3n_subcmd_type_nest,
        .nest = cmd_help,
    },
    {
        .name = "start",
        .help = "[sessionname] - starts daemon",
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

#ifdef __linux__
static void dump_registrations (int signo) {

    struct sn_community *comm, *ctmp;
    struct peer_info *list, *tmp;
    char buf[32];
    time_t now = time(NULL);
    u_int num = 0;

    traceEvent(TRACE_NORMAL, "====================================");

    HASH_ITER(hh, sss_node.communities, comm, ctmp) {
        traceEvent(TRACE_NORMAL, "dumping community: %s", comm->community);

        HASH_ITER(hh, comm->edges, list, tmp) {
            if(list->sock.family == AF_INET) {
                traceEvent(TRACE_NORMAL, "[id: %u][MAC: %s][edge: %u.%u.%u.%u:%u][last seen: %u sec ago]",
                           ++num, macaddr_str(buf, list->mac_addr),
                           list->sock.addr.v4[0], list->sock.addr.v4[1], list->sock.addr.v4[2], list->sock.addr.v4[3],
                           list->sock.port,
                           now - list->last_seen);
            } else {
                traceEvent(TRACE_NORMAL, "[id: %u][MAC: %s][edge: IPv6:%u][last seen: %u sec ago]",
                           ++num, macaddr_str(buf, list->mac_addr), list->sock.port,
                           now - list->last_seen);
            }
        }
    }

    traceEvent(TRACE_NORMAL, "====================================");
}
#endif

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

    struct peer_info *scan, *tmp;

#ifdef _WIN32
    initWin32();
#endif

    // Do this early to register all internals
    n3n_initfuncs();

    n3n_sn_config(argc, argv, "supernode", &sss_node);

    if(sss_node.conf.community_file)
        load_allowed_sn_community(&sss_node);

#ifndef _WIN32
    if(sss_node.conf.daemon) {
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

    if(!sss_node.conf.spoofing_protection) {
        traceEvent(
            TRACE_WARNING,
            "disabled MAC and IP address spoofing protection; "
            "FOR TESTING ONLY, usage of user-password authentication options "
            "is recommended instead!"
            );
    }

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

    sss_node.mgmt_slots = slots_malloc(5, 3000, 500);
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

    if(slots_listen_unix(sss_node.mgmt_slots, unixsock)!=0) {
        perror("slots_listen_tcp");
        exit(1);
    }
    chown(unixsock, sss_node.conf.userid, sss_node.conf.groupid);
#endif

    // Add our freshly opened socket to any edges added by federation
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
    signal(SIGHUP,  dump_registrations);
#endif
#ifdef _WIN32
    SetConsoleCtrlHandler(term_handler, TRUE);
#endif

    sss_node.keep_running = &keep_running;
    return run_sn_loop(&sss_node);
}
