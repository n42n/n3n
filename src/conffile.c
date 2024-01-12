/*
 * Copyright (C) 2023-24 Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Handlers for configuration files
 */

#include <ctype.h>              // for isprint and friends
#include <n3n/conffile.h>
#include <n3n/logging.h>        // for setTraceLevel
#include <n3n/transform.h>      // for n3n_transform_lookup_
#include <n3n/network_traffic_filter.h>
#include <stdbool.h>            // for true, false
#include <stdint.h>             // for uint32_t
#include <stdio.h>              // for printf
#include <stdlib.h>             // for malloc
#include <string.h>             // for strcmp
#include <unistd.h>             // for access
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

// Stringifies the given option.  May use the provided buffer as temp space
// for the string - or may return a static string.  A return of NULL means
// that the option could not be rendered.
// Buffer overflow is handled simplisticly by simply filling the buffer.
static char * stringify_option (void *conf, struct n3n_conf_option *option, char *buf, size_t buflen) {
    void *valvoid = (char *)conf + option->offset;

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
    }

    return NULL;
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
            void *valvoid = (char *)conf + option->offset;
            struct peer_info **supernodes = (struct peer_info **)valvoid;
            struct peer_info *scan, *tmp;
            HASH_ITER(hh, *supernodes, scan, tmp) {
                fprintf(f, "%s=%s\n", option->name, scan->ip_addr);
            }
            fprintf(f, "\n");
            return;
        }
        // TODO: if type == n3n_conf_filter_rule ...

        char buf[100];
        char *p = stringify_option(conf, option, buf, sizeof(buf));

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
        fprintf(f, "\n####################\n");
        if(section->help && (level >= 2)) {
            dump_wordwrap(f, "#", section->help, 78);
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

int n3n_config_load_env (void *conf) {
    char *s;
    int rc = 0;

    s = getenv("N2N_KEY");
    if(s) {
        rc += n3n_config_set_option(conf, "community", "key", s);
        rc += n3n_config_set_option(conf, "community", "cipher", "AES");
    }

    s = getenv("N2N_COMMUNITY");
    if(s) {
        rc += n3n_config_set_option(conf, "community", "name", s);
    }

    s = getenv("N2N_PASSWORD");
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

    // TODO: Are there other places that should be searched?
    char *searchpath[] = {
#ifndef _WIN32
        "/etc/n3n",
#endif
#ifdef _WIN32
        getenv("USERPROFILE"),
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
    char *filename = find_config(name);
    if(!filename) {
        // Couldnt find a filename
        return -2;
    }
    FILE *f = fopen(filename, "r");
    if(!f) {
        // Shouldnt happen, since find_config found a file
        goto out;
    }

    char *section = NULL;

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
    free(section);
    free(filename);
    return error;
}
