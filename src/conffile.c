/*
 * Copyright (C) 2023 Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Handlers for configuration files
 */

#include <n3n/conffile.h>
#include <n3n/logging.h>        // for setTraceLevel
#include <n3n/network_traffic_filter.h>
#include <stdbool.h>            // for true, false
#include <stdint.h>             // for uint32_t
#include <stdio.h>              // for printf
#include <stdlib.h>             // for malloc
#include <string.h>             // for strcmp

#ifdef _WIN32
#include "win32/defs.h"
#else
#include <netinet/in.h>  // for sockaddr_in
#endif

#include <auth.h>               // for generate_private_key
#include <n2n.h>                // for edge_conf_add_supernode
#include <n2n_define.h>         // for HEADER_ENCRYPTION_UNKNOWN...

static struct n3n_conf_section *registered_sections;

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
            // TODO: in the future, we should lookup against a struct of
            // registered transforms and prefer to use strings instead of
            // numbers.
            // For now, manually keep the max ids in sync with n2n_transform_t

            char *endptr;
            uint32_t i = strtoul(value, &endptr, 10);

            if(*value && !*endptr) {
                // "the entire string is valid"

                if(i>0 && i<6) {
                    // N2N_TRANSFORM_ID_NULL = 1
                    // ...
                    // N2N_TRANSFORM_ID_SPECK = 5
                    *val = i;
                    return 0;
                }
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
            // TODO: in the future, we should lookup against a struct of
            // registered compressions and prefer to use strings instead of
            // numbers.
            // For now, manually keep the max ids in sync with n2n_transform_t

            char *endptr;
            uint32_t i = strtoul(value, &endptr, 10);

            if(*value && !*endptr) {
                // "the entire string is valid"

                switch(i) {
                    case 0:
                        *val = N2N_COMPRESSION_ID_NONE;
                        return 0;
                    case 1:
                        *val = N2N_COMPRESSION_ID_LZO;
                        return 0;
#ifdef HAVE_ZSTD
// FIXME: codebase has these defs wrong, they should be HAVE_LIBZSTD
                    case 2:
                        *val = N2N_COMPRESSION_ID_ZSTD;
                        return 0;
#endif
                }
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
