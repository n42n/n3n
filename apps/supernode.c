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

/** Help message to print if the command line arguments are not valid. */
static void help (int level) {

    if(level == 0) /* no help required */
        return;

    printf("\n");
    print_n3n_version();

    if(level == 1) {
        /* short help */

        printf("   basic usage:  supernode <config file> (see supernode.conf)\n"
               "\n"
               "            or   supernode "
               "[optional parameters, at least one] "
               "\n                      "
               "\n technically, all parameters are optional, but the supernode executable"
               "\n requires at least one parameter to run, .e.g. -v or -f, as otherwise this"
               "\n short help text is displayed"
               "\n\n  -h    shows a quick reference including all available options"
               "\n --help gives a detailed parameter description"
               "\n   man  files for n3n, edge, and supernode contain in-depth information"
               "\n\n");

    } else if(level == 2) {
        /* quick reference */

        printf(" general usage:  supernode <config file> (see supernode.conf)\n"
               "\n"
               "            or   supernode "
               "[-p [<local bind ip address>:]<local port>] "
               "\n                           "
               "[-F <federation name>] "
               "\n options for under-        "
               "[-l <supernode host:port>] "
               "\n lying connection          "
               "[-m <mac address>] "
               "[-M] "
               "[-V <version text>] "
               "\n\n overlay network           "
               "[-c <community list file>] "
               "\n configuration             "
               "[-a <net ip>-<net ip>/<cidr suffix>] "
               "\n\n local options             "
               "[-t <management port>] "
               "\n                           "
               "[--management-password <pw>] "
               "[-v] "
               "\n                           "
               "[-u <numerical user id>]"
               "[-g <numerical group id>]"
               "\n\n meaning of the            "
               "[-M]  disable MAC and IP address spoofing protection"
               "\n flag options              "
               "[-f]  do not fork but run in foreground"
               "\n                           "
               "[-v]  make more verbose, repeat as required"
               "\n                           "
               "\n technically, all parameters are optional, but the supernode executable"
               "\n requires at least one parameter to run, .e.g. -v or -f, as otherwise a"
               "\n short help text is displayed"
               "\n\n  -h    shows this quick reference including all available options"
               "\n --help gives a detailed parameter description"
               "\n   man  files for n3n, edge, and supernode contain in-depth information"
               "\n\n");

    } else {
        /* long help */

        printf(" general usage:  supernode <config file> (see supernode.conf)\n"
               "\n"
               "            or   supernode [optional parameters, at least one]\n\n"
               );
        printf(" OPTIONS FOR THE UNDERLYING NETWORK CONNECTION\n");
        printf(" ---------------------------------------------\n\n");
        printf(" -p [<ip>:]<port>  | fixed local UDP port (defaults to %u) and optionally\n"
               "                   | bind to specified local IP address only ('any' by default)\n", N2N_SN_LPORT_DEFAULT);
        printf(" -F <fed name>     | name of the supernode's federation, defaults to\n"
               "                   | '%s'\n", (char *)FEDERATION_NAME);
        printf(" -l <host:port>    | ip address or name, and port of known supernode\n");
        printf(" -m <mac>          | fixed MAC address for the supernode, e.g.\n"
               "                   | '-m 10:20:30:40:50:60', random otherwise\n");
        printf(" -M                | disable MAC and IP address spoofing protection for all\n"
               "                   | non-username-password-authenticating communities\n");
        printf(" -V <version text> | sends a custom supernode version string of max 19 letters \n"
               "                   | length to edges, visible in their management port output\n");
        printf("\n");
        printf(" TAP DEVICE AND OVERLAY NETWORK CONFIGURATION\n");
        printf(" --------------------------------------------\n\n");
        printf(" -c <path>         | file containing the allowed communities\n");
        printf(" -a <net-net/n>    | subnet range for auto ip address service, e.g.\n"
               "                   | '-a 192.168.0.0-192.168.255.0/24', defaults\n"
               "                   | to '10.128.255.0-10.255.255.0/24'\n");
        printf("\n");
        printf(" LOCAL OPTIONS\n");
        printf(" -------------\n\n");
        printf(" -f                | do not fork and run as a daemon, rather run in foreground\n");
        printf(" -t <port>         | management UDP port, for multiple supernodes on a machine,\n"
               "                   | defaults to %u\n", N2N_SN_MGMT_PORT);
        printf(" --management_...  | management port password, defaults to '%s'\n"
               " ...password <pw>  | \n", N3N_MGMT_PASSWORD);
        printf(" -v                | make more verbose, repeat as required\n");
        printf(" -u <UID>          | numeric user ID to use when privileges are dropped\n");
        printf(" -g <GID>          | numeric group ID to use when privileges are dropped\n");
        printf("\n technically, all parameters are optional, but the supernode executable"
               "\n requires at least one parameter to run, .e.g. -v or -f, as otherwise a"
               "\n short help text is displayed"
               "\n\n  -h    shows a quick reference including all available options"
               "\n --help gives this detailed parameter description"
               "\n   man  files for n3n, edge, and supernode contain in-depth information"
               "\n\n");
    }

    exit(0);
}


/* *************************************************** */

// little wrapper to show errors if the conffile parser has a problem
static void set_option_wrap (n2n_edge_conf_t *conf, char *section, char *option, char *value) {
    int i = n3n_config_set_option(conf, section, option, value);
    if(i==0) {
        return;
    }

    traceEvent(TRACE_WARNING, "Error setting %s.%s=%s\n", section, option, value);
}

static int setOption (int optkey, char *_optarg, struct n3n_runtime_data *sss) {

    //traceEvent(TRACE_NORMAL, "Option %c = %s", optkey, _optarg ? _optarg : "");

    switch(optkey) {
        case 'p': { /* local-port */
            set_option_wrap(&sss->conf, "connection", "bind", _optarg);
            break;
        }

        case 't': /* mgmt-port */
            set_option_wrap(&sss->conf, "management", "port", _optarg);
            break;

        case 'l': { /* supernode:port */
            char *double_column = strchr(_optarg, ':');

            size_t length = strlen(_optarg);
            if(length >= N2N_EDGE_SN_HOST_SIZE) {
                traceEvent(TRACE_WARNING, "size of -l argument too long: %zu; maximum size is %d", length, N2N_EDGE_SN_HOST_SIZE);
                return 1;
            }

            if(!double_column) {
                traceEvent(TRACE_WARNING, "invalid -l format, missing port");
                return 1;
            }

            n2n_sock_t *socket = (n2n_sock_t *)calloc(1, sizeof(n2n_sock_t));
            int rv = supernode2sock(socket, _optarg);

            if(rv < -2) { /* we accept resolver failure as it might resolve later */
                traceEvent(TRACE_WARNING, "invalid supernode parameter");
                free(socket);
                return 1;
            }

            if(!sss->federation) {
                free(socket);
                break;
            }

            int skip_add = SN_ADD;
            struct peer_info *anchor_sn = add_sn_to_list_by_mac_or_sock(&(sss->federation->edges), socket, null_mac, &skip_add);

            if(!anchor_sn) {
                free(socket);
                break;
            }

            anchor_sn->ip_addr = calloc(1, N2N_EDGE_SN_HOST_SIZE);
            if(!anchor_sn->ip_addr) {
                free(socket);
                break;
            }

            peer_info_init(anchor_sn, null_mac);
            // This is the only place where the default purgeable
            // is overwritten after an _alloc or _init
            anchor_sn->purgeable = false;

            strncpy(anchor_sn->ip_addr, _optarg, N2N_EDGE_SN_HOST_SIZE - 1);
            memcpy(&(anchor_sn->sock), socket, sizeof(n2n_sock_t));

            free(socket);
            break;
        }

        case 'a': {
            dec_ip_str_t ip_min_str = {'\0'};
            dec_ip_str_t ip_max_str = {'\0'};
            in_addr_t net_min, net_max;
            uint8_t bitlen;
            uint32_t mask;

            if(sscanf(_optarg, "%15[^\\-]-%15[^/]/%hhu", ip_min_str, ip_max_str, &bitlen) != 3) {
                traceEvent(TRACE_WARNING, "bad net-net/bit format '%s'.", _optarg);
                return 2;
            }

            net_min = inet_addr(ip_min_str);
            net_max = inet_addr(ip_max_str);
            mask = bitlen2mask(bitlen);
            if((net_min == (in_addr_t)(-1)) || (net_min == INADDR_NONE) || (net_min == INADDR_ANY)
               || (net_max == (in_addr_t)(-1)) || (net_max == INADDR_NONE) || (net_max == INADDR_ANY)
               || (ntohl(net_min) >  ntohl(net_max))
               || ((ntohl(net_min) & ~mask) != 0) || ((ntohl(net_max) & ~mask) != 0)) {
                traceEvent(TRACE_WARNING, "bad network range '%s...%s/%u' in '%s', defaulting to '%s...%s/%d'",
                           ip_min_str, ip_max_str, bitlen, _optarg,
                           N2N_SN_MIN_AUTO_IP_NET_DEFAULT, N2N_SN_MAX_AUTO_IP_NET_DEFAULT, N2N_SN_AUTO_IP_NET_BIT_DEFAULT);
                return 2;
            }

            if((bitlen > 30) || (bitlen == 0)) {
                traceEvent(TRACE_WARNING, "bad prefix '%hhu' in '%s', defaulting to '%s...%s/%d'",
                           bitlen, _optarg,
                           N2N_SN_MIN_AUTO_IP_NET_DEFAULT, N2N_SN_MAX_AUTO_IP_NET_DEFAULT, N2N_SN_AUTO_IP_NET_BIT_DEFAULT);
                return 2;
            }

            traceEvent(TRACE_NORMAL, "the network range for community ip address service is '%s...%s/%hhu'", ip_min_str, ip_max_str, bitlen);

            sss->min_auto_ip_net.net_addr = ntohl(net_min);
            sss->min_auto_ip_net.net_bitlen = bitlen;
            sss->max_auto_ip_net.net_addr = ntohl(net_max);
            sss->max_auto_ip_net.net_bitlen = bitlen;

            break;
        }
        case 'u': /* unprivileged uid */
            set_option_wrap(&sss->conf, "daemon", "userid", _optarg);
            break;

        case 'g': /* unprivileged uid */
            set_option_wrap(&sss->conf, "daemon", "groupid", _optarg);
            break;
        case 'F': { /* federation name */
            snprintf(sss->federation->community, N2N_COMMUNITY_SIZE - 1, "*%s", _optarg);
            sss->federation->community[N2N_COMMUNITY_SIZE - 1] = '\0';
            sss->federation->purgeable = false;
            break;
        }
        case 'm': {/* MAC address */
            str2mac(sss->mac_addr, _optarg);

            // clear multicast bit
            sss->mac_addr[0] &= ~0x01;
            // set locally-assigned bit
            sss->mac_addr[0] |= 0x02;

            break;
        }
        case 'M': /* override spoofing protection */
            set_option_wrap(&sss->conf, "supernode", "spoofing_protection", "false");
            break;

        case 'V': /* version text */
            set_option_wrap(&sss->conf, "supernode", "version_string", _optarg);
            break;
        case 'c': /* community file */
            set_option_wrap(&sss->conf, "supernode", "community_file", _optarg);
            break;

        case ']': /* password for management port */ {
            set_option_wrap(&sss->conf, "management", "password", _optarg);
            break;
        }
        case 'f': /* foreground */
            set_option_wrap(&sss->conf, "daemon", "background", "false");
            break;
        case 'h': /* quick reference */
            return 2;

        case '@': /* long help */
            return 3;

        case 'v': /* verbose */
            setTraceLevel(getTraceLevel() + 1);
            break;

        default:
            traceEvent(TRACE_WARNING, "unknown option -%c:", (char) optkey);
            return 2;
    }

    return 0;
}


/* *********************************************** */

static const struct option long_options[] = {
    {"communities",         required_argument, NULL, 'c'},
    {"foreground",          no_argument,       NULL, 'f'},
    {"local-port",          required_argument, NULL, 'p'},
    {"mgmt-port",           required_argument, NULL, 't'},
    {"autoip",              required_argument, NULL, 'a'},
    {"verbose",             no_argument,       NULL, 'v'},
    {"help",                no_argument,       NULL, '@'}, /* special character '@' to identify long help case */
    {"management-password", required_argument, NULL, ']' }, /*                  ']'             management port password */
    {NULL,                  0,                 NULL, 0}
};

/* *************************************************** */

/* read command line options */
static int loadFromCLI (int argc, char * const argv[], struct n3n_runtime_data *sss) {

    u_char c;

    while((c = getopt_long(argc, argv,
                           "p:l:t:a:c:F:vhMV:"
                           "m:"
                           "f"
                           "u:g:"
                           ,
                           long_options, NULL)) != '?') {
        if(c == 255) {
            break;
        }
        help(setOption(c, optarg, sss));
    }

    return 0;
}

/* *************************************************** */

static char *trim (char *s) {

    char *end;

    while(isspace(s[0]) || (s[0] == '"') || (s[0] == '\'')) {
        s++;
    }

    if(s[0] == 0) {
        return s;
    }

    end = &s[strlen(s) - 1];
    while(end > s && (isspace(end[0])|| (end[0] == '"') || (end[0] == '\''))) {
        end--;
    }
    end[1] = 0;

    return s;
}

/* *************************************************** */

/* parse the configuration file */
static int loadFromFile (const char *path, struct n3n_runtime_data *sss) {

    char buffer[4096], *line;
    char *line_vec[3];
    int tmp;

    FILE *fd;

    fd = fopen(path, "r");

    if(fd == NULL) {
        traceEvent(TRACE_WARNING, "config file %s not found", path);
        return -1;
    }

    // we mess around with optind, better save it
    tmp = optind;

    while((line = fgets(buffer, sizeof(buffer), fd)) != NULL) {
        line = trim(line);

        if(strlen(line) < 2 || line[0] == '#') {
            continue;
        }

        // executable, cannot be omitted, content can be anything
        line_vec[0] = line;
        // first token, e.g. `-p`, eventually followed by a whitespace or '=' delimiter
        line_vec[1] = strtok(line, "\t =");
        // separate parameter option, if present
        line_vec[2] = strtok(NULL, "\t ");

        // not to duplicate the option parser code, call loadFromCLI and pretend we have no option read yet
        optind = 0;
        // if separate second token present (optional argument, not part of first), then announce 3 vector members
        loadFromCLI(line_vec[2] ? 3 : 2, line_vec, sss);
    }

    fclose(fd);
    optind = tmp;

    return 0;
}

/* *************************************************** */

/* Add the federation to the communities list of a supernode */
static int add_federation_to_communities (struct n3n_runtime_data *sss) {

    uint32_t num_communities = 0;

    if(sss->federation != NULL) {
        HASH_ADD_STR(sss->communities, community, sss->federation);

        num_communities = HASH_COUNT(sss->communities);

        traceEvent(TRACE_INFO, "added federation '%s' to the list of communities [total: %u]",
                   (char*)sss->federation->community, num_communities);
    }

    return 0;
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
int main (int argc, char * const argv[]) {

    int rc;
#ifndef _WIN32
    struct passwd *pw = NULL;
#endif
    struct peer_info *scan, *tmp;

#ifdef _WIN32
    initWin32();
#endif

    // Do this early to register all internals
    n3n_initfuncs();

    sn_init_defaults(&sss_node);
    add_federation_to_communities(&sss_node);

    if((argc >= 2) && (argv[1][0] != '-')) {
        rc = loadFromFile(argv[1], &sss_node);
        if(argc > 2) {
            rc = loadFromCLI(argc, argv, &sss_node);
        }
    } else if(argc > 1) {
        rc = loadFromCLI(argc, argv, &sss_node);
    } else

#ifdef _WIN32
        // load from current directory
        rc = loadFromFile("supernode.conf", &sss_node);
#else
        rc = -1;
#endif

    if(rc < 0) {
        help(1); /* short help */
    }

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

    // warn on default federation name
    if(!strcmp(sss_node.federation->community, FEDERATION_NAME)) {
        traceEvent(TRACE_WARNING, "using default federation name; FOR TESTING ONLY, usage of a custom federation name (-F) is highly recommended!");
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

    struct sockaddr_in local_address;
    memset(&local_address, 0, sizeof(local_address));
    local_address.sin_family = AF_INET;
    local_address.sin_port = htons(sss_node.conf.mgmt_port);
    local_address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    sss_node.mgmt_slots = slots_malloc(5);
    if(!sss_node.mgmt_slots) {
        abort();
    }

    if(slots_listen_tcp(sss_node.mgmt_slots, sss_node.conf.mgmt_port, false)!=0) {
        perror("slots_listen_tcp");
        exit(1);
    }
    traceEvent(TRACE_NORMAL, "supernode is listening on TCP %u (management)", sss_node.conf.mgmt_port);

    // TODO: merge conf and then can:
    // n3n_config_setup_sessiondir(&sss->conf);
    //
    // also slots_listen_unix()

    HASH_ITER(hh, sss_node.federation->edges, scan, tmp)
    scan->socket_fd = sss_node.sock;

#ifndef _WIN32
    /*
     * If no uid/gid is specified on the commandline, use the uid/gid of the
     * first found out of user "n2n" or "nobody"
     */
    if(((pw = getpwnam("n3n")) != NULL) || ((pw = getpwnam("nobody")) != NULL)) {
        /*
         * If the uid/gid is not set from the CLI, set it from getpwnam
         * otherwise reset it to zero
         * (TODO: this looks wrong)
         */
        sss_node.conf.userid = sss_node.conf.userid == 0 ? pw->pw_uid : 0;
        sss_node.conf.groupid = sss_node.conf.groupid == 0 ? pw->pw_gid : 0;
    }

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
        traceEvent(TRACE_WARNING, "running as root is discouraged, check out the -u/-g options");
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
