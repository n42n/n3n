/*
 * Copyright (C) 2023-24 Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Handlers for configuration files
 */

#include <n3n/conffile.h>
#include <n3n/logging.h>        // for setTraceLevel
#include <n3n/transform.h>      // for n3n_transform_lookup_
#include <n3n/network_traffic_filter.h>
#include <stdbool.h>            // for true, false
#include <stdint.h>             // for uint32_t
#include <stdio.h>              // for printf
#include <stdlib.h>             // for malloc
#include <string.h>             // for strcmp
#include "peer_info.h"          // for struct peer_info

#ifdef _WIN32
#include "win32/defs.h"
#else
#include <netinet/in.h>  // for sockaddr_in
#endif

#include <auth.h>               // for generate_private_key
#include <n2n.h>                // for edge_conf_add_supernode
#include <n2n_define.h>         // for HEADER_ENCRYPTION_UNKNOWN...

static struct n3n_conf_section *registered_sections = NULL;

void n3n_config_register_section (char *name, struct n3n_conf_option options[]) {
    struct n3n_conf_section *section;
    section = malloc(sizeof(*section));
    if(!section) {
        return;
    }

    // TODO: should confirm that we register each section name only once

    section->next = registered_sections;
    section->name = name;
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

    void *valvoid = (char *)conf + p->offset;

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
        case n3n_conf_uint32: {
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
            return edge_conf_add_supernode(conf, value);
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

static void fprintf_v4addr (FILE *f, void *v4addr) {
    char buf[20];
    buf[0]=0;
    inet_ntop(AF_INET, v4addr, buf, sizeof(buf));
    fprintf(f, "%s", buf);
}

static int dump_value (FILE *f, void *conf, struct n3n_conf_option *option) {
    void *valvoid = (char *)conf + option->offset;

    switch(option->type) {
        case n3n_conf_strncpy: {
            char *val = (char *)valvoid;

            // Our setter routine ensures that the value is always NULL
            // terminated, so this degrades into a simple printf
            fprintf(f, "%s", val);
            return 0;
        }
        case n3n_conf_bool: {
            bool *val = (bool *)valvoid;

            if(*val == false) {
                fprintf(f, "false");
                return 0;
            }
            if(*val == true) {
                fprintf(f, "true");
                return 0;
            }

            // TODO: other values are also "true"
            // - output a "true"?
            // - output a "unexpected value"?
            // - dont return a falure?

            return -1;
        }
        case n3n_conf_uint32: {
            uint32_t *val = (uint32_t *)valvoid;

            fprintf(f, "%u", *val);
            return 0;
        }
        case n3n_conf_strdup: {
            char **val = (char **)valvoid;
            if(!*val) {
                fprintf(f, "(null)");
                return -1;
            }
            fprintf(f, "%s", *val);
            return 0;
        }
        case n3n_conf_transform: {
            uint8_t *val = (uint8_t *)valvoid;
            fprintf(f, "%s", n3n_transform_id2str(*val));
            return 0;
        }
        case n3n_conf_headerenc: {
            uint8_t *val = (uint8_t *)valvoid;
            // TODO: a tristate boolean is wierd

            switch(*val) {
                case HEADER_ENCRYPTION_ENABLED:
                    fprintf(f, "true");
                    return 0;
                case HEADER_ENCRYPTION_NONE:
                    fprintf(f, "false");
                    return 0;
                case HEADER_ENCRYPTION_UNKNOWN:
                    fprintf(f, "unknown");
                    return 0;
            }
            return -1;
        }
        case n3n_conf_compression: {
            uint8_t *val = (uint8_t *)valvoid;
            fprintf(f, "%s", n3n_compression_id2str(*val));
            return 0;
        }
        case n3n_conf_supernode: {
            // This is a multi-value item, so needs special handling to dump
            return -1;
        }
        case n3n_conf_privatekey: {
            // This uses a one-way hash, so cannot be dumped
            return -1;
        }
        case n3n_conf_publickey: {
            n2n_private_public_key_t **val = (n2n_private_public_key_t **)valvoid;
            if(!*val) {
                return 0;
            }
            char buf[((N2N_PRIVATE_PUBLIC_KEY_SIZE * 8 + 5)/ 6 + 1)];

            bin_to_ascii(buf, (void *)*val, sizeof(**val));
            fprintf(f, "%s", buf);
            return 0;
        }
        case n3n_conf_sockaddr: {
            // TODO: this currently only supports IPv4
            struct sockaddr_in **val = (struct sockaddr_in **)valvoid;
            if(!*val) {
                return 0;
            }
            struct sockaddr_in *sa = *val;

            fprintf_v4addr(f, &sa->sin_addr.s_addr);
            fprintf(f, ":%i", htons(sa->sin_port));
            return 0;
        }
        case n3n_conf_n2n_sock_addr: {
            struct n2n_sock *val = (struct n2n_sock *)valvoid;
            if(val->family == AF_INVALID) {
                fprintf(f, "auto");
                return 0;
            }

            fprintf_v4addr(f, &val->addr.v4);
            return 0;
        }
        case n3n_conf_sn_selection: {
            uint8_t *val = (uint8_t *)valvoid;
            // TODO: in the future, we should lookup against a struct of
            // registered selection strategies

            switch(*val) {
                case SN_SELECTION_STRATEGY_RTT:
                    fprintf(f, "rtt");
                    return 0;
                case SN_SELECTION_STRATEGY_MAC:
                    fprintf(f, "mac");
                    return 0;
                case SN_SELECTION_STRATEGY_LOAD:
                    fprintf(f, "load");
                    return 0;
            }
            return -1;
        }
        case n3n_conf_verbose: {
            fprintf(f, "%i", getTraceLevel());
            return 0;
        }
        case n3n_conf_filter_rule: {
            // This is a multi-value item, so needs special handling to dump
            return -1;
        }
        case n3n_conf_ip_subnet: {
            struct n2n_ip_subnet *val = (struct n2n_ip_subnet *)valvoid;
            fprintf_v4addr(f, &val->net_addr);
            fprintf(f, "/%i", val->net_bitlen);
            return 0;
        }
        case n3n_conf_ip_mode: {
            uint8_t *val = (uint8_t *)valvoid;

            switch(*val) {
                case TUNTAP_IP_MODE_STATIC:
                    fprintf(f, "static");
                    return 0;
                case TUNTAP_IP_MODE_DHCP:
                    fprintf(f, "dhcp");
                    return 0;
                case TUNTAP_IP_MODE_SN_ASSIGN:
                    fprintf(f, "auto");
                    return 0;
            }
            return -1;
        }
    }

    fprintf(f, "%s", "?");
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

    if(level >= 2) {
        fprintf(f, "# %s\n", option->desc);
    }
    if(level >= 4) {
        dump_wordwrap(f, "#", option->help, 78);
    }

    if(level >= 1) {
        if(option->type == n3n_conf_supernode) {
            // special case for a multi-value item
            // TODO: this breaks layering, but I cannot think of a simple
            // alternative
            void *valvoid = (char *)conf + option->offset;
            struct peer_info **supernodes = (struct peer_info **)valvoid;
            struct peer_info *scan, *tmp;
            HASH_ITER(hh, *supernodes, scan, tmp) {
                fprintf(f, "%s=%s\n", option->name, scan->ip_addr);
            }
        } else {
            fprintf(f, "%s=", option->name);
            dump_value(f, conf, option);
        }
        // TODO: else if type == n3n_conf_filter_rule ...
    } else {
        fprintf(f, "%s=", option->name);
    }
#if 0
    if(level >= 3) {
        // TODO: render type / schema
        fprintf(f, "\t# %s", "?");
    }
#endif
    fprintf(f, "\n");


    if(level > 1) {
        fprintf(f, "\n");
    }
}

void n3n_config_dump (void *conf, FILE *f, int level) {
    struct n3n_conf_section *section = registered_sections;
    struct n3n_conf_option *option;

    fprintf(f, "# Autogenerated config dump\n");
    while(section) {
        fprintf(f, "\n[%s]\n", section->name);

        option = section->options;
        while(option->name) {
            dump_option(f, conf, level, option);
            option++;
        }

        section = section->next;
    }
}
