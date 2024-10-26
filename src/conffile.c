/*
 * Copyright (C) 2023-24 Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Handlers for configuration files
 */

#include <ctype.h>              // for isprint and friends
#include <errno.h>              // for errno
#include <n3n/conffile.h>
#include <n3n/peer_info.h>      // for n3n_peer_add_by_hostname
#include <n3n/logging.h>        // for setTraceLevel
#include <n3n/transform.h>      // for n3n_transform_lookup_
#include <n3n/network_traffic_filter.h>
#include <stdbool.h>            // for true, false
#include <stdint.h>             // for uint32_t
#include <stdio.h>              // for printf
#include <stdlib.h>             // for malloc
#include <string.h>             // for strcmp
#include <sys/stat.h>           // for mkdir
#include <unistd.h>             // for access
#include <bits/getopt_core.h>
#include <getopt.h>
#include <pwd.h>
#include <sys/socket.h>

#include "peer_info.h"          // for struct peer_info
#include "n2n_typedefs.h"
#include "n3n/ethernet.h"
#include "uthash.h"

#ifdef _WIN32
#include "win32/defs.h"

#include <direct.h>             // for _mkdir
#else
#include <arpa/inet.h>
#include <grp.h>                // for getgrnam
#include <netinet/in.h>  // for sockaddr_in
#endif

#include <auth.h>               // for generate_private_key
#include <n2n_define.h>         // for HEADER_ENCRYPTION_UNKNOWN...

static struct n3n_conf_section *registered_sections = NULL;

void n3n_config_register_section (char *name, char *help, struct n3n_conf_option options[]) {
    struct n3n_conf_section *section;
    section = malloc(sizeof(*section));
    if(!section) {
        return;
    }

    // TODO: should confirm that we register each section name only once

    section->next = registered_sections;
    section->name = name;
    section->help = help;
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
    if(!value) {
        // Dont (currently?) support missing values
        return -1;
    }

    struct n3n_conf_option *p = lookup_option(section, option);
    if(!p) {
        return -1;
    }

    void *valvoid = NULL;

    // Entries that cannot be set via a pointer are marked with
    // a negative offset
    if(p->offset >= 0) {
        valvoid = (char *)conf + p->offset;
    }

    switch(p->type) {
        case n3n_conf_strncpy: {
            char *val = (char *)valvoid;

            strncpy(val, value, p->length);
            val[p->length -1] = 0;
            return 0;
        }
        case n3n_conf_bool: {
            bool *val = (bool *)valvoid;

            if(0==strcmp("true", value)) {
                *val = true;
            } else if(0==strcmp("false", value)) {
                *val = false;
            } else {
                return -1;
            }
            return 0;
        }
        case n3n_conf_uint32:
try_uint32:
            {
                uint32_t *val = (uint32_t *)valvoid;
                char *endptr;
                uint32_t i = strtoul(value, &endptr, 0);

                if(*value && !*endptr) {
                    // "the entire string is valid"
                    *val = i;
                    return 0;
                }
                return -1;
            }
        case n3n_conf_strdup: {
            char **val = (char **)valvoid;
            if(*val) {
                free(*val);
            }
            *val = strdup(value);
            if(*val) {
                return 0;
            }
            return -1;
        }
        case n3n_conf_transform: {
            uint8_t *val = (uint8_t *)valvoid;

            struct n3n_transform *transform;
            transform = n3n_transform_lookup_name(value);
            if(transform) {
                *val = transform->id;
                return 0;
            }
            return -1;
        }
        case n3n_conf_headerenc: {
            uint8_t *val = (uint8_t *)valvoid;
            // TODO: this is a bit of an odd one out, since it is a tristate boolean

            if(0==strcmp("true", value)) {
                *val = HEADER_ENCRYPTION_ENABLED;
            } else if(0==strcmp("false", value)) {
                *val = HEADER_ENCRYPTION_NONE;
            } else if(0==strcmp("unknown", value)) {
                *val = HEADER_ENCRYPTION_UNKNOWN;
            } else {
                return -1;
            }
            return 0;
        }
        case n3n_conf_compression: {
            uint8_t *val = (uint8_t *)valvoid;

            struct n3n_transform *transform;
            transform = n3n_compression_lookup_name(value);
            if(transform) {
                *val = transform->id;
                return 0;
            }
            return -1;
        }
        case n3n_conf_supernode: {
            peer_info_t **supernodes = (peer_info_t **)valvoid;
            return n3n_peer_add_by_hostname(supernodes, value);
        }
        case n3n_conf_privatekey: {
            n2n_private_public_key_t **val = (n2n_private_public_key_t **)valvoid;
            if(*val) {
                free(*val);
            }
            *val = malloc(sizeof(**val));
            if(!*val) {
                return -1;
            }
            generate_private_key(**val, value);
            return 0;
        }
        case n3n_conf_publickey: {
            n2n_private_public_key_t **val = (n2n_private_public_key_t **)valvoid;
            if(strlen(value) >= ((N2N_PRIVATE_PUBLIC_KEY_SIZE * 8 + 5)/ 6 + 1)) {
                return -1;
            }
            if(*val) {
                free(*val);
            }
            *val = malloc(sizeof(**val));
            if(!*val) {
                return -1;
            }
            ascii_to_bin(**val, value);
            return 0;
        }
        case n3n_conf_sockaddr: {
            // TODO: this currently only supports IPv4
            struct sockaddr_in **val = (struct sockaddr_in **)valvoid;
            if(*val) {
                free(*val);
            }
            *val = malloc(sizeof(**val));
            if(!*val) {
                return -1;
            }
            struct sockaddr_in *sa = *val;

            memset(sa, 0, sizeof(*sa));
            sa->sin_family = AF_INET;

            in_addr_t bind_address = INADDR_ANY;
            int local_port = 0;

            char* colon = strpbrk(value, ":");
            if(colon) { /*ip address:port */
                *colon = 0;
                bind_address = ntohl(inet_addr(value));
                local_port = atoi(++colon);

                if(bind_address == INADDR_NONE) {
                    // traceEvent(TRACE_WARNING, "bad address to bind to, binding to any IP address");
                    bind_address = INADDR_ANY;
                }
                // if(local_port == 0) {
                //     traceEvent(TRACE_WARNING, "bad local port format, using OS assigned port");
                // }
            } else { /* ip address or port only */
                char* dot = strpbrk(value, ".");
                if(dot) { /* ip address only */
                    bind_address = ntohl(inet_addr(value));
                    if(bind_address == INADDR_NONE) {
                        // traceEvent(TRACE_WARNING, "bad address to bind to, binding to any IP address");
                        bind_address = INADDR_ANY;
                    }
                } else { /* port only */
                    local_port = atoi(value);
                    // if(local_port == 0) {
                    //     traceEvent(TRACE_WARNING, "bad local port format, using OS assigned port");
                    // }
                }
            }

            sa->sin_port = htons(local_port);
            sa->sin_addr.s_addr = htonl(bind_address);
            return 0;
        }
        case n3n_conf_n2n_sock_addr: {
            struct n2n_sock *val = (struct n2n_sock *)valvoid;
            if(!strcmp(value, "auto")) {
                val->family = AF_INVALID;
                return 0;
            }

            in_addr_t address_tmp = inet_addr(value);
            if(address_tmp == INADDR_NONE) {
                val->family = AF_INVALID;
                return -1;
            }

            memcpy(&(val->addr.v4), &(address_tmp), IPV4_SIZE);
            val->family = AF_INET;
            return 0;
        }
        case n3n_conf_sn_selection: {
            uint8_t *val = (uint8_t *)valvoid;
            // TODO: in the future, we should lookup against a struct of
            // registered selection strategies

            if(!strcmp(value, "rtt")) {
                *val = SN_SELECTION_STRATEGY_RTT;
                return 0;
            }
            if(!strcmp(value, "mac")) {
                *val = SN_SELECTION_STRATEGY_MAC;
                return 0;
            }
            if(!strcmp(value, "load")) {
                *val = SN_SELECTION_STRATEGY_LOAD;
                return 0;
            }

            return -1;
        }
        case n3n_conf_verbose: {
            char *endptr;
            uint32_t i = strtoul(value, &endptr, 0);

            if(*value && !*endptr) {
                // "the entire string is valid"
                setTraceLevel(i);
                return 0;
            }
            return -1;
        }
        case n3n_conf_filter_rule: {
            filter_rule_t **val = (filter_rule_t **)valvoid;

            filter_rule_t *new_rule = malloc(sizeof(filter_rule_t));
            memset(new_rule, 0, sizeof(filter_rule_t));

            if(process_traffic_filter_rule_str(value, new_rule)) {
                HASH_ADD(hh, *val, key, sizeof(filter_rule_key_t), new_rule);
            } else {
                free(new_rule);
                return -1;
            }

            return 0;
        }
        case n3n_conf_ip_subnet: {
            struct n2n_ip_subnet *val = (struct n2n_ip_subnet *)valvoid;
            struct n2n_ip_subnet tmp;
            tmp.net_bitlen = N2N_EDGE_DEFAULT_V4MASKLEN;

            char *endptr;

            char *bitlen_str = strchr(value, '/');
            if(bitlen_str) {
                // Found a subnet length, try to parse it
                *bitlen_str++ = 0;
                tmp.net_bitlen = strtoul(bitlen_str, &endptr, 10);
                if(*endptr) {
                    // there were non parsable chars in the string
                    return -1;
                }
            }

            if(inet_pton(AF_INET, value, &tmp.net_addr) != 1) {
                // error parsing
                return -1;
            }

            val->net_addr = tmp.net_addr;
            val->net_bitlen = tmp.net_bitlen;
            return 0;
        }
        case n3n_conf_ip_mode: {
            uint8_t *val = (uint8_t *)valvoid;

            if(0 == strcmp("static", value)) {
                *val = TUNTAP_IP_MODE_STATIC;
            } else if(0 == strcmp("dhcp", value)) {
                *val = TUNTAP_IP_MODE_DHCP;
            } else if(0 == strcmp("auto", value)) {
                *val = TUNTAP_IP_MODE_SN_ASSIGN;
            } else {
                return -1;
            }
            return 0;
        }
        case n3n_conf_userid: {
#ifndef _WIN32
            uint32_t *val = (uint32_t *)valvoid;
            struct passwd *pw = getpwnam(value);
            if(pw != NULL) {
                *val = pw->pw_uid;
                return 0;
            }
#endif
            // if we could not lookup that name (or it is windows)
            // just try interpreting the string value as an integer
            goto try_uint32;
        }
        case n3n_conf_groupid: {

#ifndef _WIN32
            uint32_t *val = (uint32_t *)valvoid;
            struct group *gr = getgrnam(value);
            if(gr != NULL) {
                *val = gr->gr_gid;
                return 0;
            }
#endif
            // if we could not lookup that name (or it is windows)
            // just try interpreting the string value as an integer
            goto try_uint32;
        }
        case n3n_conf_macaddr: {
            n2n_mac_t *val = (n2n_mac_t *)valvoid;
            str2mac((uint8_t *)val, value);

            // clear multicast bit
            *val[0] &= ~0x01;
            // set locally-assigned bit
            *val[0] |= 0x02;
            return 0;
        }
    }
    return -1;
}

static void dump_wordwrap (FILE *f, char *prefix, char *line, int width) {
    char *line_copy = strdup(line);

    int column = 0;
    column += fprintf(f, "%s", prefix);

    char *tok = strtok(line_copy, " ");
    while(tok) {
        if((column + strlen(tok)) > width) {
            fprintf(f, "\n");
            column = 0;
            column += fprintf(f, "%s", prefix);
        }
        column += fprintf(f, " %s", tok);
        tok = strtok(NULL, " ");
    }
    fprintf(f, "\n");

    free(line_copy);
}

// Stringifies the given option.  May use the provided buffer as temp space
// for the string - or may return a static string.  A return of NULL means
// that the option could not be rendered.
// Buffer overflow is handled simplisticly by simply filling the buffer.
static const char * stringify_option (void *conf, struct n3n_conf_option *option, char *buf, size_t buflen) {
    void *valvoid = NULL;

    // Entries that cannot be set via a pointer are marked with
    // a negative offset
    if(option->offset >= 0) {
        valvoid = (char *)conf + option->offset;
    }

    switch(option->type) {
        case n3n_conf_strncpy: {
            char *val = (char *)valvoid;

            if(*val == 0) {
                // Cannot display empty strings
                return NULL;
            }

            // Our setter routine ensures that the value is always NULL
            // so we can simply return it
            return val;
        }
        case n3n_conf_bool: {
            bool *val = (bool *)valvoid;

            if(*val == false) {
                return "false";
            }
            if(*val == true) {
                return "true";
            }

            // TODO: other values are also "true"
            // - output a "true"?
            // - output a "unexpected value"?
            // - dont return a falure?

            return NULL;
        }
        case n3n_conf_userid:
        case n3n_conf_groupid:
        case n3n_conf_uint32: {
            uint32_t *val = (uint32_t *)valvoid;

            snprintf(buf, buflen, "%u", *val);
            return buf;
        }
        case n3n_conf_strdup: {
            char **val = (char **)valvoid;
            return *val;
        }
        case n3n_conf_transform: {
            uint8_t *val = (uint8_t *)valvoid;
            return n3n_transform_id2str(*val);
        }
        case n3n_conf_headerenc: {
            uint8_t *val = (uint8_t *)valvoid;
            // TODO: a tristate boolean is wierd

            switch(*val) {
                case HEADER_ENCRYPTION_ENABLED:
                    return "true";
                case HEADER_ENCRYPTION_NONE:
                    return "false";
                case HEADER_ENCRYPTION_UNKNOWN:
                    return "unknown";
            }
            return NULL;
        }
        case n3n_conf_compression: {
            uint8_t *val = (uint8_t *)valvoid;
            return n3n_compression_id2str(*val);
        }
        case n3n_conf_supernode: {
            // This is a multi-value item, so needs special handling to dump
            return NULL;
        }
        case n3n_conf_privatekey: {
            // This uses a one-way hash, so cannot be dumped
            return NULL;
        }
        case n3n_conf_publickey: {
            n2n_private_public_key_t **val = (n2n_private_public_key_t **)valvoid;
            if(!*val) {
                return NULL;
            }
            char localbuf[((N2N_PRIVATE_PUBLIC_KEY_SIZE * 8 + 5)/ 6 + 1)];

            bin_to_ascii(localbuf, (void *)*val, sizeof(**val));
            snprintf(buf, buflen, "%s", localbuf);
            return buf;
        }
        case n3n_conf_sockaddr: {
            // TODO: this currently only supports IPv4
            struct sockaddr_in **val = (struct sockaddr_in **)valvoid;
            if(!*val) {
                return NULL;
            }
            struct sockaddr_in *sa = *val;

            if(inet_ntop(AF_INET, &sa->sin_addr.s_addr, buf, buflen) == NULL) {
                return NULL;
            }
            ssize_t used = strlen(buf);
            snprintf(buf + used, buflen - used, ":%i", htons(sa->sin_port));
            return buf;
        }
        case n3n_conf_n2n_sock_addr: {
            struct n2n_sock *val = (struct n2n_sock *)valvoid;
            if(val->family == AF_INVALID) {
                return "auto";
            }

            return (char *)inet_ntop(AF_INET, &val->addr.v4, buf, buflen);
        }
        case n3n_conf_sn_selection: {
            uint8_t *val = (uint8_t *)valvoid;
            // TODO: in the future, we should lookup against a struct of
            // registered selection strategies

            switch(*val) {
                case SN_SELECTION_STRATEGY_RTT:
                    return "rtt";
                case SN_SELECTION_STRATEGY_MAC:
                    return "mac";
                case SN_SELECTION_STRATEGY_LOAD:
                    return "load";
            }
            return NULL;
        }
        case n3n_conf_verbose: {
            snprintf(buf, buflen, "%i", getTraceLevel());
            return buf;
        }
        case n3n_conf_filter_rule: {
            // This is a multi-value item, so needs special handling to dump
            return NULL;
        }
        case n3n_conf_ip_subnet: {
            struct n2n_ip_subnet *val = (struct n2n_ip_subnet *)valvoid;

            if(inet_ntop(AF_INET, &val->net_addr, buf, buflen) == NULL) {
                return NULL;
            }
            ssize_t used = strlen(buf);
            snprintf(buf + used, buflen - used, "/%i", val->net_bitlen);
            return buf;
        }
        case n3n_conf_ip_mode: {
            uint8_t *val = (uint8_t *)valvoid;

            switch(*val) {
                case TUNTAP_IP_MODE_STATIC:
                    return "static";
                case TUNTAP_IP_MODE_DHCP:
                    return "dhcp";
                case TUNTAP_IP_MODE_SN_ASSIGN:
                    return "auto";
            }
            return NULL;
        }
        case n3n_conf_macaddr: {
            n2n_mac_t *val = (n2n_mac_t *)valvoid;
            if(buflen < N2N_MACSTR_SIZE) {
                return NULL;
            }
            macaddr_str(buf, *val);
            return buf;
        }
    }

    return NULL;
}

static int option_storagesize (struct n3n_conf_option *option) {
    void *valvoid = NULL;
    switch(option->type) {
        case n3n_conf_strncpy: {
            return option->length;
        }
        case n3n_conf_bool: {
            bool *val = (bool *)valvoid;
            return sizeof(*val);
        }
        case n3n_conf_userid:
        case n3n_conf_groupid:
        case n3n_conf_uint32: {
            uint32_t *val = (uint32_t *)valvoid;
            return sizeof(*val);
        }
        case n3n_conf_strdup: {
            char **val = (char **)valvoid;
            return sizeof(*val);
        }
        case n3n_conf_transform: {
            uint8_t *val = (uint8_t *)valvoid;
            return sizeof(*val);
        }
        case n3n_conf_headerenc: {
            uint8_t *val = (uint8_t *)valvoid;
            return sizeof(*val);
        }
        case n3n_conf_compression: {
            uint8_t *val = (uint8_t *)valvoid;
            return sizeof(*val);
        }
        case n3n_conf_supernode: {
            return -1;
        }
        case n3n_conf_privatekey: {
            n2n_private_public_key_t **val = (n2n_private_public_key_t **)valvoid;
            return sizeof(*val);
        }
        case n3n_conf_publickey: {
            n2n_private_public_key_t **val = (n2n_private_public_key_t **)valvoid;
            return sizeof(*val);
        }
        case n3n_conf_sockaddr: {
            struct sockaddr_in **val = (struct sockaddr_in **)valvoid;
            return sizeof(*val);
        }
        case n3n_conf_n2n_sock_addr: {
            struct n2n_sock *val = (struct n2n_sock *)valvoid;
            return sizeof(*val);
        }
        case n3n_conf_sn_selection: {
            uint8_t *val = (uint8_t *)valvoid;
            return sizeof(*val);
        }
        case n3n_conf_verbose: {
            return -1;
        }
        case n3n_conf_filter_rule: {
            return -1;
        }
        case n3n_conf_ip_subnet: {
            struct n2n_ip_subnet *val = (struct n2n_ip_subnet *)valvoid;
            return sizeof(*val);
        }
        case n3n_conf_ip_mode: {
            uint8_t *val = (uint8_t *)valvoid;
            return sizeof(*val);
        }
        case n3n_conf_macaddr: {
            n2n_mac_t *val = (n2n_mac_t *)valvoid;
            return sizeof(*val);
        }
    }
    return -1;
}

/*
 * Dump details about a single option.
 * level specifies how much data to output:
 * 0 = just the variable name
 * 1 = name and current value
 * 2 = name, value and short desc
 * 3 = name, value, desc and schema (currently schema prints nothing)
 * 4 = name, value, desc, schema and long help
 *
 */
static void dump_option (FILE *f, void *conf, int level, struct n3n_conf_option *option) {
    if(!option) {
        return;
    }
    if(!option->name) {
        return;
    }


    if(level > 1) {
        // ensure a gap between items when there is any help text
        fprintf(f, "\n");
    }
    if(level >= 2) {
        // prefix with a short desc
        fprintf(f, "# %s\n", option->desc);
    }
#if 0
    if(level >= 3) {
        // TODO: render type / schema
        fprintf(f, "\t# %s", "?");
    }
#endif
    if(level >= 4) {
        // also prefix with a long help
        dump_wordwrap(f, "#", option->help, 78);
    }

    if(level >= 1) {
        // show both name and value

        if(option->type == n3n_conf_supernode) {
            // special case for this multi-value item
            // TODO: this breaks layering, but I cannot think of a simple
            // alternative
            fprintf(f, "#%s=\n", option->name);
            void *valvoid = (char *)conf + option->offset;
            struct peer_info **supernodes = (struct peer_info **)valvoid;
            struct peer_info *scan, *tmp;
            HASH_ITER(hh, *supernodes, scan, tmp) {
                fprintf(
                    f,
                    "%s=%s\n",
                    option->name,
                    peer_info_get_hostname(scan)
                );
            }
            fprintf(f, "\n");
            return;
        }
        // TODO: if type == n3n_conf_filter_rule ...

        char buf[100];
        char const *p = stringify_option(conf, option, buf, sizeof(buf));

        if(!p) {
            // couldnt stringify this option

            if(level >= 2) {
                // only show the invalids in levels with help texts
                fprintf(f, "#%s=\n", option->name);
            }
            return;
        }

        fprintf(f, "%s=%s\n", option->name, p);
        return;
    }

    // level must be <= 0
    // just print the variable name
    fprintf(f, "%s=\n", option->name);
}

void n3n_config_dump (void *conf, FILE *f, int level) {
    struct n3n_conf_section *section = registered_sections;
    struct n3n_conf_option *option;

    fprintf(f, "# Autogenerated config dump\n");
    while(section) {
        fprintf(f, "\n");
        if(level >= 2) {
            fprintf(f, "####################\n");

            if(section->help) {
                dump_wordwrap(f, "#", section->help, 78);
            }
        }
        fprintf(f, "[%s]\n", section->name);

        option = section->options;
        while(option->name) {
            dump_option(f, conf, level, option);
            option++;
        }

        section = section->next;
    }
}

void n3n_config_debug_addr (void *conf, FILE *f) {
    struct n3n_conf_section *section = registered_sections;
    struct n3n_conf_option *option;

    fprintf(f, "# Internal Address consistancy checks\n");
    while(section) {
        option = section->options;
        while(option->name) {
            if(option->type == n3n_conf_supernode) {
                option++;
                continue;
            }
            void *first = NULL;
            void *last = NULL;

            // Entries that cannot be set via a pointer are marked with
            // a negative offset
            if(option->offset >= 0) {
                first = (char *)conf + option->offset;
            }

            int size = option_storagesize(option);
            if(size > 0) {
                last = first + (size-1);
            }

            fprintf(
                f,
                "%p..%p / %i == %s.%s (%i)\n",
                first,
                last,
                size,
                section->name,
                option->name,
                option->type
            );
            option++;
        }

        section = section->next;
    }
}

int n3n_config_load_env (void *conf) {
    char *s;
    int rc = 0;

    s = getenv("N3N_KEY");
    if(s) {
        rc += n3n_config_set_option(conf, "community", "key", s);
        rc += n3n_config_set_option(conf, "community", "cipher", "AES");
    }

    s = getenv("N3N_COMMUNITY");
    if(s) {
        rc += n3n_config_set_option(conf, "community", "name", s);
    }

    s = getenv("N3N_PASSWORD");
    if(s) {
        rc += n3n_config_set_option(conf, "auth", "password", s);
    }

    return rc;
}

/*
 * Find the right config file for a given session name.  Or return NULL
 *
 * If the session name is a simple name, then this just looks in the "correct"
 * directory for the matching config file.
 *
 * If the session name starts with a "/" or "./" then it is assumed to be
 * a filename, which is then used to open the config.
 *
 * If the session name is a filename, then it is modified in place to become
 * an actual session name (basically, the basename with no extension is used)
 *
 */
static char *find_config (char *name) {
    if(!name) {
        return NULL;
    }

    if((*name == '/') || (name[0] == '.' && name[1] == '/')) {
        // Handle the case where the given "session name" is actually a
        // pathname

        if(access(name, R_OK) != 0) {
            return NULL;
        }
        char *filename = strdup(name);

        // Find the last path component (we know we at least start with one)
        char *p = strrchr(name, '/');
        p++;

        char *dst = name;
        // Replace the given name with the basename
        while(*p) {
            *dst++ = *p++;
        }
        *dst = 0;

        // Remove any filename extension
        p = strrchr(name, '.');
        if(p) {
            *p = 0;
        }

        return filename;
    }

#ifdef _WIN32
    char profiledir[1024];
    profiledir[0] = 0;

    char *userprofile = getenv("USERPROFILE");
    if(userprofile) {
        snprintf(profiledir, sizeof(profiledir), "%s/n3n", userprofile);
    }
#endif

    // TODO: Are there other places that should be searched?
    char *searchpath[] = {
#ifndef _WIN32
        "/etc/n3n",
#endif
#ifdef _WIN32
        profiledir,
#endif
    };

    for(int i=0; i < (sizeof(searchpath) / sizeof(searchpath[0])); i++) {
        if(!searchpath[i]) {
            continue;
        }
        char buf[1024];
        snprintf(buf, sizeof(buf), "%s/%s.conf", searchpath[i], name);

        if(access(buf, R_OK) == 0) {
            char *filename = strdup(buf);
            return filename;
        }
    }
    return NULL;
}

// Input a line containing a section header definition.
// return just the string with the section name
char *extract_section (char *line) {
    // Skip the open bracket
    line++;
    char *section = line;
    bool closed = false;

    while(*line) {
        if(isspace(*line)) {
            // Any space terminates the section name and introduces
            // the (unused in this parser) instance name
            *line++ = 0;
            continue;
        }
        if(closed) {
            if(*line == '#') {
                // Dont care what comes after a comment start
                break;
            }
            printf("Error: unexpected text trailing section name\n");
            return NULL;
        }
        if(*line == ']') {
            // Found the close bracket
            *line++ = 0;
            closed = true;
            continue;
        }
        if(isalnum(*line)) {
            // These are valid chars for a name
            line++;
            continue;
        }
        printf("Error: unexpected characters in section name\n");
        return NULL;
    }

    if(!*section) {
        printf("Error: empty section name\n");
        return NULL;
    }
    if(!closed) {
        printf("Error: unterminated section header\n");
        return NULL;
    }
    return section;
}

int n3n_config_load_file (void *conf, char *name) {
    int error = -1;
    char *section = NULL;

    char *filename = find_config(name);
    if(!filename) {
        // Couldnt find a filename
        return -2;
    }
    FILE *f = fopen(filename, "r");
    if(!f) {
        // Shouldnt happen, since find_config found a file
        printf("Unexpected error opening %s\n", filename);
        goto out1;
    }

    char buf[1024];
    char *line;
    int linenr = 0;

    while((line = fgets(buf, sizeof(buf), f))) {
        linenr++;
        while(isspace(*line)) {
            line++;
        }
        if(!*line || *line == '\r' ) {
            // Skip lines that are empty
            continue;
        }
        if(*line == '#') {
            // Skip lines starting with a comment
            continue;
        }
        if(*line == '[') {
            // A section heading
            free(section);
            char *tmp_section = extract_section(line);
            if(!tmp_section) {
                printf(
                    "Error:%s:%i: could not extract section\n",
                    filename,
                    linenr
                );
                goto out;
            }
            section = strdup(tmp_section);
            if(!lookup_section(section)) {
                printf("Warning: unknown section %s\n", section);
            }
            continue;
        }

        if(!section) {
            printf(
                "Error:%s:%i: options outside of a section\n",
                filename,
                linenr
            );
            goto out;
        }

        char *option = line;

        while(*line) {
            if(isalnum(*line) || (*line == '_')) {
                // These are valid chars for a name
                line++;
                continue;
            }
            if(isspace(*line)) {
                *line++ = 0;
                break;
            }
            if(*line == '=') {
                break;
            }
        }
        if(!*line) {
            printf("Error:%s:%i: unexpected end of line\n", filename, linenr);
            goto out;
        }

        while(*line) {
            if(isspace(*line)) {
                *line++ = 0;
                continue;
            }
            if(*line == '=') {
                break;
            }
        }
        if(*line != '=') {
            printf("Error:%s:%i: expected equals\n", filename, linenr);
            goto out;
        }

        // Skip the equals
        *line++ = 0;

        while(*line) {
            if(isspace(*line)) {
                line++;
                continue;
            }
            break;
        }
        if(!*line) {
            printf("Error:%s:%i: unexpected end of line\n", filename, linenr);
            goto out;
        }

        char *comment = strchr(line, '#');
        if(comment) {
            *comment = 0;
        }

        // Strip trailing spaces
        char *end = &line[strlen(line) - 1];
        while(end > line && isspace(*end)) {
            end--;
        }
        end[1] = 0;

        if(n3n_config_set_option(conf, section, option, line)!=0) {
            printf(
                "Error:%s:%i: while setting %s.%s=%s\n",
                filename,
                linenr,
                section,
                option,
                line
            );
        }
    }
    error = 0;

out:
    fclose(f);
out1:
    free(section);
    free(filename);
    return error;
}


/********************************************************************/
// Sub command generic processor

void n3n_subcmd_help (struct n3n_subcmd_def *p, int indent, bool recurse) {
    while(p->name) {
        printf(
            "%*c%-10s",
            indent,
            ' ',
            p->name
        );
        if(p->type == n3n_subcmd_type_nest) {
            printf(" ->");
        }
        if(p->help) {
            printf(" %s", p->help);
        }
        printf("\n");
        if(recurse && p->type == n3n_subcmd_type_nest) {
            n3n_subcmd_help(p->nest, indent +2, recurse);
        }
        p++;
    }
}

static void subcmd_help_simple (struct n3n_subcmd_def *p) {
    printf(
        "\n"
        "Try -h for help\n"
        "\n"
        "or add a subcommand:\n"
        "\n"
    );
    n3n_subcmd_help(p, 1, false);
    exit(1);
}

static struct n3n_subcmd_result subcmd_lookup (struct n3n_subcmd_def *top, int argc, char **argv) {
    struct n3n_subcmd_result r;
    struct n3n_subcmd_def *p = top;
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
            case n3n_subcmd_type_nest:
                argc--;
                argv++;
                top = p->nest;
                p = top;
                continue;
            case n3n_subcmd_type_fn:
                if(p->session_arg) {
                    r.sessionname = argv[1];
                } else {
                    r.sessionname = NULL;
                }
                r.argc = argc;
                r.argv = argv;
                r.subcmd = p;
                r.type = n3n_subcmd_result_ok;
                return r;
        }
        printf("Internal Error subcmd->type: %i\n", p->type);
        exit(1);
    }
    printf("Unknown subcmd: '%s'\n", argv[0]);
    exit(1);
}

struct n3n_subcmd_result n3n_subcmd_parse (int argc, char **argv, char *getopts, const struct option *long_options, struct n3n_subcmd_def *top) {
    struct n3n_subcmd_result cmd;

    // A first pass through to reorder the argv
    int c = 0;
    while(c != -1) {
        c = getopt_long(
            argc, argv,
            // The superset of all possible short options
            getopts,
            long_options,
            NULL
        );

        switch(c) {
            case '?': // An invalid arg, or a missing optarg
                exit(1);
            case 'V':
                cmd.type = n3n_subcmd_result_version;
                return cmd;
            case 'h': /* quick reference */
                cmd.type = n3n_subcmd_result_about;
                return cmd;
        }
    }

    if(optind >= argc) {
        // There is no sub-command provided
        subcmd_help_simple(top);
    }
    // We now know there is a sub command on the commandline

    cmd = subcmd_lookup(
        top,
        argc - optind,
        &argv[optind]
    );

    return cmd;
}

void n3n_config_from_getopt (const struct n3n_config_getopt *map, void *conf, int optkey, char *optarg) {
    int i = 0;
    while(map[i].optkey) {
        if(optkey != map[i].optkey) {
            i++;
            continue;
        }

        if((!optarg && !map[i].value) || !map[i].section || !map[i].option) {
            printf("Internal error with option_map for -%c\n", optkey);
            abort();
        }

        if(!optarg) {
            optarg = map[i].value;
        }

        int rv = n3n_config_set_option(
            conf,
            map[i].section,
            map[i].option,
            optarg
        );
        if(rv==0) {
            return;
        }

        traceEvent(
            TRACE_WARNING,
            "Error setting %s.%s=%s\n",
            map[i].section,
            map[i].option,
            optarg);
        return;
    }

    // Should only happen if the caller has a bad getopt loop
    printf("unknown option -%c", (char)optkey);
}

void n3n_config_help_options (const struct n3n_config_getopt *map, const struct option *long_options) {
    int i;

    printf(" option    equivalent config setting\n");
    i = 0;
    while(map[i].optkey) {
        if(isprint(map[i].optkey)) {
            printf(" -%c ", map[i].optkey);
            if(map[i].help) {
                // Dont generate any text, just use the help text
                // (This is used for options that have no true mapping)
                printf("%s\n", map[i].help);
                i++;
                continue;
            }
            if(!map[i].value) {
                // We are expecting an arg with this option
                printf("<arg>");
            } else {
                printf("     ");
            }
            printf("  %s.%s=", map[i].section, map[i].option);
            if(!map[i].value) {
                printf("<arg>");
            } else {
                printf("%s", map[i].value);
            }
            printf("\n");
        }
        i++;
    }
    printf("\n");
    printf(" short  has an equivalent long\n");

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
}

static int mkdir_p (const char *pathname, int mode, int uid, int gid) {
    if(access(pathname, R_OK) == 0) {
        // it already exists (may not be a dir though)
        return 0;
    }

    if(errno != ENOENT) {
        // some other error
        return -1;
    }

#ifndef _WIN32
    if(mkdir(pathname, mode) == -1) {
        return -1;
    }
    if(chown(pathname, uid, gid) == -1) {
        return -1;
    }

#else
    // Some versions of windows appear to have mkdir(), others _mkdir()
    // using this gives some undefined warnings, but is most compatible
    if(_mkdir(pathname) == -1) {
        return -1;
    }
#endif

    return 0;
}

int n3n_config_setup_sessiondir (n2n_edge_conf_t *conf) {
    if(!conf->sessionname) {
        traceEvent(TRACE_NORMAL, "cannot setup sessiondir: no sessionname");
        return -1;
    }

    // In the future, once we can run tests on the edge without elevated
    // permissions, this will probably need a way to check the environment
    // for the basedir for session dirs


#ifndef _WIN32
    char *basedir = CONFIG_RUNDIR "/n3n";
#endif
#ifdef _WIN32
    char basedir[1024];
    basedir[0] = 0;

    char *userprofile = getenv("USERPROFILE");
    if(!userprofile) {
        // TODO: surely, there is a better location?
        userprofile = getenv("TEMP");
    }
    if(!userprofile) {
        return -1;
    }

    snprintf(basedir, sizeof(basedir), "%s/n3n", userprofile);
#endif

    if(mkdir_p(basedir, 0755, conf->userid, conf->groupid) == -1) {
        traceEvent(TRACE_ERROR, "cannot mkdir %s", basedir);
        return -1;
    }

    char buf[1024];
    snprintf(buf, sizeof(buf), "%s/%s", basedir, conf->sessionname);
    conf->sessiondir = strdup(buf);

    if(mkdir_p(buf, 0755, conf->userid, conf->groupid) == -1) {
        traceEvent(TRACE_ERROR, "cannot mkdir %s", buf);
        return -1;
    }

    traceEvent(TRACE_NORMAL, "sessiondir: %s", conf->sessiondir);

    return 0;
}
