/*
 * Copyright (C) 2023 Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Handlers for configuration files
 */

#include <n3n/conffile.h>
#include <n3n/logging.h>        // for setTraceLevel
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

    switch(p->type) {
        case n3n_conf_strncpy: {
            char *dst = (char *)conf + p->offset;

            strncpy(dst, value, p->length);
            dst[p->length -1] = 0;
            return 0;
        }
        case n3n_conf_bool: {
            bool *dst = (bool *)((char *)conf + p->offset);

            if(0==strcmp("true", value)) {
                *dst = true;
            } else if(0==strcmp("false", value)) {
                *dst = false;
            } else {
                return -1;
            }
            return 0;
        }
        case n3n_conf_uint32: {
            uint32_t *dst = (uint32_t *)((char *)conf + p->offset);
            char *endptr;
            uint32_t i = strtoul(value, &endptr, 0);

            if(*value && !*endptr) {
                // "the entire string is valid"
                *dst = i;
                return 0;
            }
            return -1;
        }
        case n3n_conf_strdup: {
            char **dst = (char **)((char *)conf + p->offset);
            if(*dst) {
                free(*dst);
            }
            *dst = strdup(value);
            if(*dst) {
                return 0;
            }
            return -1;
        }
        case n3n_conf_transform: {
            uint8_t *dst = ((uint8_t *)conf + p->offset);
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
                    *dst = i;
                    return 0;
                }
            }
            return -1;
        }
        case n3n_conf_headerenc: {
            uint8_t *dst = ((uint8_t *)conf + p->offset);
            // TODO: this is a bit of an odd one out, since it is a tristate boolean

            if(0==strcmp("true", value)) {
                *dst = HEADER_ENCRYPTION_ENABLED;
            } else if(0==strcmp("false", value)) {
                *dst = HEADER_ENCRYPTION_NONE;
            } else if(0==strcmp("unknown", value)) {
                *dst = HEADER_ENCRYPTION_UNKNOWN;
            } else {
                return -1;
            }
            return 0;
        }
        case n3n_conf_compression: {
            uint8_t *dst = ((uint8_t *)conf + p->offset);
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
                        *dst = N2N_COMPRESSION_ID_NONE;
                        return 0;
                    case 1:
                        *dst = N2N_COMPRESSION_ID_LZO;
                        return 0;
#ifdef HAVE_ZSTD
// FIXME: codebase has these defs wrong, they should be HAVE_LIBZSTD
                    case 2:
                        *dst = N2N_COMPRESSION_ID_ZSTD;
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
            n2n_private_public_key_t **dst = (n2n_private_public_key_t **)((char *)conf + p->offset);
            if(*dst) {
                free(*dst);
            }
            *dst = malloc(sizeof(**dst));
            if(!*dst) {
                return -1;
            }
            generate_private_key(**dst, value);
            return 0;
        }
        case n3n_conf_publickey: {
            if(strlen(value) >= ((N2N_PRIVATE_PUBLIC_KEY_SIZE * 8 + 5)/ 6 + 1)) {
                return -1;
            }
            n2n_private_public_key_t **dst = (n2n_private_public_key_t **)((char *)conf + p->offset);
            if(*dst) {
                free(*dst);
            }
            *dst = malloc(sizeof(**dst));
            if(!*dst) {
                return -1;
            }
            ascii_to_bin(**dst, value);
            return 0;
        }
        case n3n_conf_sockaddr: {
            // TODO: this currently only supports IPv4
            struct sockaddr_in **dst = (struct sockaddr_in **)((char *)conf + p->offset);
            if(*dst) {
                free(*dst);
            }
            *dst = malloc(sizeof(**dst));
            if(!*dst) {
                return -1;
            }
            struct sockaddr_in *sa = *dst;

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
            struct n2n_sock *dst = (struct n2n_sock *)((char *)conf + p->offset);
            if(!strcmp(value, "auto")) {
                dst->family = AF_INVALID;
                return 0;
            }

            in_addr_t address_tmp = inet_addr(value);
            if(address_tmp == INADDR_NONE) {
                dst->family = AF_INVALID;
                return -1;
            }

            memcpy(&(dst->addr.v4), &(address_tmp), IPV4_SIZE);
            dst->family = AF_INET;
            return 0;
        }
        case n3n_conf_sn_selection: {
            uint8_t *dst = ((uint8_t *)conf + p->offset);
            // TODO: in the future, we should lookup against a struct of
            // registered selection strategies

            if(!strcmp(value, "rtt")) {
                *dst = SN_SELECTION_STRATEGY_RTT;
                return 0;
            }
            if(!strcmp(value, "mac")) {
                *dst = SN_SELECTION_STRATEGY_MAC;
                return 0;
            }
            if(!strcmp(value, "load")) {
                *dst = SN_SELECTION_STRATEGY_LOAD;
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
    }
    return -1;
}
