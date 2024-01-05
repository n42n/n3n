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
#include <n3n/initfuncs.h>           // for n3n_initfuncs()
#include <n3n/logging.h>             // for traceEvent
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
#include "config.h"                  // for PACKAGE_BUILDDATE, PACKAGE_VERSION
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

static void help (int level) {

    if(level == 0) return; /* no help required */

    printf("\n");
    print_n3n_version();

    if(level == 1) {
        /* short help */

        printf("   basic usage:  edge start [sessionname]\n"
               "\n  -h    shows a quick reference including all available options"
               "\n --help gives a detailed parameter description"
               "\n   man  files for n3n, edge, and supernode contain in-depth information"
               "\n\n");

    } else if(level == 2) {
        /* quick reference */

        printf(" general usage:  edge start [sessionname]\n"
               "\n"
               "Loads a config file named from the sessionname (default 'edge.conf')\n"
               "Any commandline options override the config loaded\n"
               "\n                      "
               " -c <community name>"
               " -l <supernode host:port>"
               "\n                      "
               "[-p [<local bind ip address>:]<local port>] "
               "\n                      "

#ifdef __linux__
               "[-T <type of service>] "
#endif
#ifndef __APPLE__
               "[-D] "
#endif
               "\n options for under-   "
               "[-i <registration interval>] "
               "[-L <registration ttl>] "
               "\n lying connection     "
               "[-k <key>] "
               "[-A<cipher>] "
               "[-H] "
               "[-z<compression>] "
               "\n                      "
               "[-e <preferred local IP address>] [-S<level of solitude>]"
               "\n                      "
               "[--select-rtt] "
#if defined(HAVE_MINIUPNP) || defined(HAVE_NATPMP)
               "[--no-port-forwarding] "
#endif // HAVE_MINIUPNP || HAVE_NATPMP
               "\n\n tap device and       "
               "[-a [static:|dhcp:]<tap IP address>[/<cidr suffix>]] "
               "\n overlay network      "
               "[-m <tap MAC address>] "
#if defined(N2N_CAN_NAME_IFACE)
               "[-d <tap device name>] "
#endif
               "\n configuration        "
               "[-M <tap MTU>] "
               "[-r] "
               "[-E] "
               "[-I <edge description>] "
               "\n                      "
               "[-J <password>] "
               "[-P <public key>] "
               "[-R <rule string>] "
#ifdef _WIN32
               "\n                      "
               "[-x <metric>] "
#endif
               "\n\n local options        "
#ifndef _WIN32
               "[-f] "
#endif
               "[-t <management port>] "
               "[--management-password <pw>] "
               "\n                      "
               "[-v] "
               "[-V] "
#ifndef _WIN32
               "\n                      "
               "[-u <numerical user id>] "
               "[-g <numerical group id>] "
#endif
               "\n\n environment          "
               "N2N_KEY         instead of [-k <key>]"
               "\n variables            "
               "N2N_COMMUNITY   instead of -c <community>"
               "\n                      "
               "N2N_PASSWORD    instead of [-J <password>]"
               "\n                      "
               "\n meaning of the       "
#ifndef __APPLE__
               "[-D]  enable PMTU discovery"
#endif
               "\n flag options         [-H]  enable header encryption"
               "\n                      [-r]  enable packet forwarding through n3n community"
               "\n                      [-E]  accept multicast MAC addresses"
               "\n            [--select-rtt]  select supernode by round trip time"
               "\n            [--select-mac]  select supernode by MAC address"
#ifndef _WIN32
               "\n                      [-f]  do not fork but run in foreground"
#endif
               "\n                      [-v]  make more verbose, repeat as required"
               "\n                      [-V]  make less verbose, repeat as required"
               "\n                      "

               "\n  -h    shows this quick reference including all available options"
               "\n --help gives a detailed parameter description"
               "\n   man  files for n3n, edge, and supernode contain in-depth information"
               "\n\n");

    } else {
        /* long help */

        printf(" general usage:  edge start [sessionname]\n"
               "\n"
               "Loads a config file named from the sessionname (default 'edge.conf')\n"
               "Any commandline options override the config loaded\n\n"
               );
        printf(" OPTIONS FOR THE UNDERLYING NETWORK CONNECTION\n");
        printf(" ---------------------------------------------\n\n");
        printf(" -c <community>    | n3n community name the edge belongs to\n");
        printf(" -l <host:port>    | supernode ip address or name, and port\n");
        printf(" -p [<ip>:]<port>  | fixed local UDP port and optionally bind to the\n"
               "                   | sepcified local IP address only (any by default)\n");
#ifdef __linux__
        printf(" -T <tos>          | TOS for packets, e.g. 0x48 for SSH like priority\n");
#endif
#ifndef __APPLE__
        printf(" -D                | enable PMTU discovery, it can reduce fragmentation but\n"
               "                   | causes connections to stall if not properly supported\n");
#endif
        printf(" -e <local ip>     | advertises the provided local IP address as preferred,\n"
               "                   | useful if multicast peer detection is not available,\n"
               "                   | '-e auto' tries IP address auto-detection\n");
        printf(" -S1 ... -S2       | do not connect p2p, always use the supernode,\n"
               "                   | -S1 = via UDP"

#ifdef N2N_HAVE_TCP
               ", -S2 = via TCP"
#endif
               "\n");
        printf(" -i <reg_interval> | registration interval, for NAT hole punching (default\n"
               "                   | %u seconds)\n", REGISTER_SUPER_INTERVAL_DFL);
        printf(" -L <reg_ttl>      | TTL for registration packet for NAT hole punching through\n"
               "                   | supernode (default 0 for not set)\n");
        printf(" -k <key>          | encryption key (ASCII) - also N2N_KEY=<key>\n");
        printf(" -A <cipher>       | choose a cipher for payload encryption, requires a key,\n"
               "                   | Twofish, AES (default if key provided),\n"
               "                   | ChaCha20, Speck\n");
        printf(" -H                | use header encryption, supernode needs fixed community\n");
        printf(" -z1 ... -z2       | compress outgoing data packets, -z1 = lzo1x,\n"
               "                   | "
#ifdef HAVE_ZSTD
               "-z2 = zstd, "
#endif
               "disabled by default\n");
        printf("--select-rtt       | supernode selection based on round trip time\n"
               "--select-mac       | supernode selection based on MAC address (default:\n"
               "                   | by load)\n");
        printf("\n");
        printf(" TAP DEVICE AND OVERLAY NETWORK CONFIGURATION\n");
        printf(" --------------------------------------------\n\n");
        printf(" -a [mode]<ip>[/n] | interface address and optional CIDR subnet, default '/24',\n"
               "                   | mode = [static|dhcp]:, for DHCP use '-r -a dhcp:0.0.0.0',\n"
               "                   | edge draws IP address from supernode if no '-a ...' given\n");
        printf(" -m <mac>          | fixed MAC address for the TAP interface, e.g.\n"
               "                   | '-m 10:20:30:40:50:60', random otherwise\n");
#if defined(N2N_CAN_NAME_IFACE)
        printf(" -d <device>       | TAP device name\n");
#endif
        printf(" -M <mtu>          | specify n3n MTU of TAP interface, default %d\n", DEFAULT_MTU);
        printf(" -r                | enable packet forwarding through n3n community,\n"
               "                   | also required for bridging\n");
        printf(" -E                | accept multicast MAC addresses, drop by default\n");
        printf(" -I <description>  | annotate the edge's description used for easier\n"
               "                   | identification in management port output or username\n");
        printf(" -J <password>     | password for user-password edge authentication\n");
        printf(" -P <public key>   | federation public key for user-password authentication\n");
        printf(" -R <rule>         | drop or accept packets by rules, can be set multiple times\n");
        printf("                   | rule format:    'src_ip/n:[s_port,e_port],...\n"
               "                   |    |on same|  ...dst_ip/n:[s_port,e_port],...\n"
               "                   |    | line  |  ...TCP+/-,UDP+/-,ICMP+/-'\n");
#ifdef _WIN32
        printf(" -x <metric>       | set TAP interface metric, defaults to 0 (auto),\n"
               "                   | e.g. set to 1 for better multiplayer game detection\n");
#endif
        printf("\n");
        printf(" LOCAL OPTIONS\n");
        printf(" -------------\n\n");
#ifndef _WIN32
        printf(" -f                | do not fork and run as a daemon, rather run in foreground\n");
#endif
        printf(" -t <port>         | management UDP port, for multiple edges on a machine,\n"
               "                   | defaults to %u\n", N2N_EDGE_MGMT_PORT);
        printf(" --management_...  | management port password, defaults to '%s'\n"
               " ...password <pw>  | \n", N2N_MGMT_PASSWORD);
        printf(" -v                | make more verbose, repeat as required\n");
        printf(" -V                | make less verbose, repeat as required\n");
#ifndef _WIN32
        printf(" -u <UID>          | numeric user ID to use when privileges are dropped\n");
        printf(" -g <GID>          | numeric group ID to use when privileges are dropped\n");
#endif
        printf("\n");
        printf(" ENVIRONMENT VARIABLES\n");
        printf(" ---------------------\n\n");
        printf(" N2N_KEY           | encryption key (ASCII), not with '-k ...'\n");
        printf(" N2N_COMMUNITY     | community name (ASCII), overwritten by '-c ...'\n");
        printf(" N2N_PASSWORD      | password (ASCII) for user-password authentication,\n"
               "                   | overwritten by '-J ...'\n");
#ifdef _WIN32
        printf("\n");
        printf(" AVAILABLE TAP ADAPTERS\n");
        printf(" ----------------------\n\n");
        win_print_available_adapters();
#endif
        printf("\n"
               "\n  -h    shows a quick reference including all available options"
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

static int setOption (int optkey, char *optargument, n2n_edge_conf_t *conf) {

    /* traceEvent(TRACE_NORMAL, "Option %c = %s", optkey, optargument ? optargument : ""); */

    switch(optkey) {
        case 'a': /* IP address and mode of TUNTAP interface */ {
            /*
             * of the form:
             *
             * ["static:"|"dhcp:","auto:"] <ip> [/<cidr subnet mask>]
             *
             * for example        static:192.168.8.5/24
             *
             */
            char *field2 = strchr(optargument, ':');
            if(field2) {
                // We have a field #1, extract it
                *field2++ = 0;
                set_option_wrap(conf, "tuntap", "address_mode", optargument);
            } else {
                set_option_wrap(conf, "tuntap", "address_mode", "static");
                field2 = optargument;
            }

            set_option_wrap(conf, "tuntap", "address", field2);
            break;
        }

        case 'c': /* community as a string */ {
            set_option_wrap(conf, "community", "name", optargument);
            break;
        }

        case 'E': /* multicast ethernet addresses accepted. */ {
            set_option_wrap(conf, "filter", "drop_multicast", "false");
            break;
        }

        case 'u': /* unprivileged uid */ {
            set_option_wrap(conf, "daemon", "userid", optargument);
            break;
        }

        case 'g': /* unprivileged uid */ {
            set_option_wrap(conf, "daemon", "groupid", optargument);
            break;
        }

        case 'f': /* do not fork as daemon */ {
            set_option_wrap(conf, "daemon", "background", "false");
            break;
        }

        case 'm': /* TUNTAP MAC address */ {
            set_option_wrap(conf, "tuntap", "macaddr", optargument);
            break;
        }

        case 'M': /* TUNTAP MTU */ {
            set_option_wrap(conf, "tuntap", "mtu", optargument);
            break;
        }

        case 'D': /* enable PMTU discovery */ {
            set_option_wrap(conf, "connection", "disable_pmtu", "false");
            break;
        }

        case 'k': /* encrypt key */ {
            set_option_wrap(conf, "community", "key", optargument);
            break;
        }

        case 'r': /* enable packet routing across n2n endpoints */ {
            set_option_wrap(conf, "filter", "allow_routing", "true");
            break;
        }

        case 'A': {
            set_option_wrap(conf, "community", "cipher", optargument);
            break;
        }

        case 'H': /* indicate header encryption */ {
            /* we cannot be sure if this gets parsed before the community name is set.
             * so, only an indicator is set, action is taken later*/
            set_option_wrap(conf, "community", "header_encryption", "true");
            break;
        }

        case 'z': {
            set_option_wrap(conf, "community", "compression", optargument);
            break;
        }

        case 'l': /* supernode-list */ {
            set_option_wrap(conf, "community", "supernode", optargument);
            break;
        }

        case 'i': /* supernode registration interval */
            set_option_wrap(conf, "connection", "register_interval", optargument);
            break;

        case 'L': /* supernode registration interval */
            set_option_wrap(conf, "connection", "register_ttl", optargument);
            break;

        case 'd': /* TUNTAP name */ {
            set_option_wrap(conf, "tuntap", "name", optargument);
            break;
        }

        case 'I': /* Device Description (hint) or username */ {
            set_option_wrap(conf, "connection", "description", optargument);
            break;
        }

        case 'J': /* password for user-password authentication */ {
            set_option_wrap(conf, "auth", "password", optargument);

            // the hash of the username (-I) gets xored into this key later,
            // we can't be sure to already have it at this point
            // also, the complete shared secret will be calculated then as we
            // might still be missing the federation public key as well
            break;
        }

        case 'P': /* federation public key for user-password authentication */ {
            set_option_wrap(conf, "auth", "pubkey", optargument);
            break;
        }

        case 'p': {
            set_option_wrap(conf, "connection", "bind", optargument);
            break;
        }

        case 'e': {
            set_option_wrap(conf, "connection", "advertise_addr", optargument);
            break;
        }

        case 't': {
            set_option_wrap(conf, "management", "port", optargument);
            break;
        }
        case 'T': {
            set_option_wrap(conf, "connection", "tos", optargument);
            break;
        }
        case 'S': {
            int solitude;
            if(optargument) {
                solitude = atoi(optargument);
            } else {
                traceEvent(TRACE_ERROR, "unknown -S value");
                break;
            }

            // set the level
            if(solitude >= 1)
                set_option_wrap(conf, "connection", "allow_p2p", "false");
            if(solitude == 2)
                set_option_wrap(conf, "connection", "connect_tcp", "true");
            break;
        }

        case '[': /* round-trip-time-based supernode selection strategy */ {
            set_option_wrap(conf, "connection", "supernode_selection", "rtt");
            break;
        }

        case ']': /* mac-address-based supernode selection strategy */ {
            set_option_wrap(conf, "connection", "supernode_selection", "mac");
            break;
        }

        case '{': /* password for management port */ {
            set_option_wrap(conf, "management", "password", optargument);
            break;
        }

        case 'h': /* quick reference */ {
            return 2;
        }

        case '@': /* long help */ {
            return 3;
        }

        case 'v': /* verbose */
            setTraceLevel(getTraceLevel() + 1);
            break;

        case 'V': /* less verbose */ {
            setTraceLevel(getTraceLevel() - 1);
            break;
        }

        case 'R': /* network traffic filter */ {
            set_option_wrap(conf, "filter", "rule", optargument);
            break;
        }

        case 'x': {
            set_option_wrap(conf, "tuntap", "metric", optargument);
            break;
        }

        default: {
            traceEvent(TRACE_WARNING, "unknown option -%c", (char)optkey);
            return 2;
        }
    }

    return 0;
}

/* *********************************************** */


static const struct option long_options[] = {
    { "community",           required_argument, NULL, 'c' },
    { "supernode-list",      required_argument, NULL, 'l' },
    { "tap-device",          required_argument, NULL, 'd' },
    { "euid",                required_argument, NULL, 'u' },
    { "egid",                required_argument, NULL, 'g' },
    { "verbose",             no_argument,       NULL, 'v' },
    { "help",                no_argument,       NULL, '@' }, /* internal special character '@' to identify long help case */
    { "select-rtt",          no_argument,       NULL, '[' }, /*                            '['             rtt selection strategy */
    { "select-mac",          no_argument,       NULL, ']' }, /*                            ']'             mac selection strategy */
    { "management-password", required_argument, NULL, '{' }, /*                            '{'             management port password */
    { NULL,                  0,                 NULL,  0  }
};

/* *************************************************** */

/* read command line options */
static void loadFromCLI (int argc, char *argv[], n2n_edge_conf_t *conf) {

    u_char c;

    while((c = getopt_long(argc, argv,
                           "k:a:c:Eu:g:m:M:s:d:l:p:fvVhrt:i:I:J:P:S:DL:z:A:Hn:R:e:"
#ifdef __linux__
                           "T:"
#endif
#ifdef _WIN32
                           "x:"
#endif
                           ,
                           long_options, NULL)) != '?') {

        if(c == 255) break;
        help(setOption(c, optarg, conf));

    }
}

/* *************************************************** */

static char *trim (char *s) {

    char *end;

    while(isspace(s[0]) || (s[0] == '"') || (s[0] == '\'')) s++;
    if(s[0] == 0) return s;

    end = &s[strlen(s) - 1];
    while(end > s
          && (isspace(end[0])|| (end[0] == '"') || (end[0] == '\'')))
        end--;
    end[1] = 0;

    return s;
}

/* *************************************************** */

/* parse the configuration file */
static int loadFromFile (const char *path, n2n_edge_conf_t *conf) {

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

        if(strlen(line) < 2 || line[0] == '#')
            continue;

        // executable, cannot be omitted, content can be anything
        line_vec[0] = line;
        // first token, e.g. `-p` or `-A3', eventually followed by a whitespace or '=' delimiter
        line_vec[1] = strtok(line, "\t =");
        // separate parameter option, if present
        line_vec[2] = strtok(NULL, "");
        if(line_vec[2])
            line_vec[2] = trim(line_vec[2]);
        // not to duplicate the option parser code, call loadFromCLI and pretend we have no option read yet at all
        optind = 0;
        // if second token present (optional argument, not part of first), then announce 3 vector members
        loadFromCLI(line_vec[2] ? 3 : 2, line_vec, conf);
    }

    fclose(fd);
    optind = tmp;

    return 0;


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
    enum subcmd_type type;
    union {
        struct subcmd_def *nest;
        void (*fn)(int argc, char **argv, char *, n2n_edge_conf_t *conf);
    };
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
    printf("Subcommand help:\n\n");
    subcmd_help(p, 1, false);
    exit(1);
}

void subcmd_lookup (struct subcmd_def *top, int argc, char **argv, char *defname, n2n_edge_conf_t *conf) {
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
                p->fn(argc, argv, defname, conf);
                return;
        }
        printf("Internal Error subcmd->type: %i\n", p->type);
        exit(1);
    }
    printf("Unknown subcmd: '%s'\n", argv[0]);
    exit(1);
}

/********************************************************************/

static struct subcmd_def cmd_top[]; // Forward define

static void cmd_help_commands (int argc, char **argv, char *_, n2n_edge_conf_t *conf) {
    subcmd_help(cmd_top, 1, true);
    exit(0);
}

static void cmd_help_config (int argc, char **argv, char *_, n2n_edge_conf_t *conf) {
    n3n_config_dump(conf, stdout, 4);
    exit(0);
}

static void cmd_help_options (int argc, char **argv, char *_, n2n_edge_conf_t *conf) {
    // TODO: once we implement the optarg to option-name mapping table, we
    // can print it out here
    printf("Not implemented\n");
    exit(1);
}

static void cmd_help_transform (int argc, char **argv, char *_, n2n_edge_conf_t *conf) {
    // TODO: add an interface to the registered transform lookups and print
    // out the list
    printf("Not implemented\n");
    exit(1);
}

static void cmd_test_config_dump (int argc, char **argv, char *_, n2n_edge_conf_t *conf) {
    int level=1;
    if(argv[1]) {
        level = atoi(argv[1]);
    }
    n3n_config_dump(conf, stdout, level);
    exit(0);
}

static void cmd_start (int argc, char **argv, char *_, n2n_edge_conf_t *conf) {
    // Simply avoid triggering the "Unknown sub com" message
    return;
}

static struct subcmd_def cmd_help[] = {
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
    { .name = NULL }
};

static struct subcmd_def cmd_test_config[] = {
    {
        .name = "dump",
        .help = "[level] - just dump the current config",
        .type = subcmd_type_fn,
        .fn = &cmd_test_config_dump,
    },
    { .name = NULL }
};

static struct subcmd_def cmd_test[] = {
    {
        .name = "config",
        .type = subcmd_type_nest,
        .nest = cmd_test_config,
    },
    { .name = NULL }
};

static struct subcmd_def cmd_top[] = {
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
            "k:a:c:Eu:g:m:M:s:d:l:p:fvVhrt:i:I:J:P:S:DL:z:A:Hn:R:e:T:x:",
            long_options,
            NULL
            );

        switch(c) {
            case '?': // An invalid arg, or a missing optarg
                exit(1);
            case 'h': /* quick reference */
                help(2);
            case '@': /* long help */
                help(3);
        }
    }

    if(optind >= argc) {
        // There is no sub-command
        subcmd_help_simple(cmd_top);
    }
    // We now know there is a sub command on the commandline

    char **subargv = &argv[optind];
    int subargc = argc - optind;

    // The start subcmd loads config, which then gets overwitten by any
    // commandline args, so it gets done first
    // TODO: work out a nicer way to integrate this into the subcmd parser
    if(strncmp(subargv[0],"start",6)==0) {
        char *arg = argv[optind+1];

        if(!arg) {
            // If no session name is specified, use the default
            arg = defname;
        }

        // TODO: want to have a searchpath for the conf file
        // which would also allow avoiding the ifdef

        char pathname[1024];
#ifdef _WIN32
        // load from current directory
        snprintf(pathname, sizeof(pathname), "%s.conf", arg);
#else
        snprintf(pathname, sizeof(pathname), "/etc/n3n/%s.conf", arg);
#endif
        loadFromFile(pathname, conf);
        // Ignore any error as it currently can only be "file not found"
    }

    // Update the loaded conf with any option args
    optind = 1;
    loadFromCLI(argc, argv, conf);

    subcmd_lookup(cmd_top, subargc, subargv, defname, conf);
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

#if defined(__linux__) || defined(_WIN32)
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
#endif /* defined(__linux__) || defined(_WIN32) */

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

    /* Defaults */
    edge_init_conf_defaults(&conf);

#ifndef _WIN32
    struct passwd *pw = NULL;
    if(((pw = getpwnam("n3n")) != NULL) ||
       ((pw = getpwnam("nobody")) != NULL)) {
        conf.userid = pw->pw_uid;
        conf.groupid = pw->pw_gid;
    }
#endif

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
                traceEvent(TRACE_WARNING, "using default federation public key; FOR TESTING ONLY, usage of a custom federation name and key (-P) is highly recommended!");
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

    if(rc < 0)
        help(1); /* short help */

    if(edge_verify_conf(&conf) != 0)
        help(1); /* short help */

    traceEvent(TRACE_NORMAL, "starting n3n edge %s %s", PACKAGE_VERSION, PACKAGE_BUILDDATE);

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

#ifdef __linux__
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
