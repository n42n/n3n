/*
 * A very simplistic set of tools for extracting data from json strings
 * with no memory allocations (It adds null bytes to the input string)
 * and no expectation for seamlessly working with complex data input.
 *
 *
 * Copyright (C) Hamish Coleman
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <ctype.h>
#include <string.h>

#include "jsonrpc.h"

char *json_find_field(char *haystack, char *field) {
    // field must include the start and end doublequotes

    char *p = strstr(haystack, field);
    if (!p) {
        return NULL;
    }

    p += strlen(field);

    while (isspace(*p)) {p++;}

    if (*p != ':') {
        return NULL;
    }
    p++;

    while (isspace(*p)) {p++;}

    return p;
}

char *json_extract_val(char *p) {
    // modifies the source string
    char *e;

    if (!p) {
        return NULL;
    }

    // A string val
    if (*p == '"') {
        p++;
        e = p;
        while (*e != '"') {e++;}
        *e = '\0';
        return p;
    }

    // A positive integer val
    if (isdigit(*p)) {
        e = p;
        while (isdigit(*e)) {e++;}
        *e = '\0';
        return p;
    }

    // The null value
    // TODO: this return is indistinguishable from "null"
    if (strncmp(p,"null",4)==0) {
        p[4] = '\0';
        return p;
    }

    char open;
    char close;

    // A dictionary, an array or an error
    if (*p == '{') {
        open = '{';
        close = '}';
    } else if (*p == '[') {
        open = '[';
        close = ']';
    } else {
        return NULL;
    }

    e = p+1;
    int depth = 1;
    while (depth) {
        if (*e == '\0') {
            return NULL;
        }
        if (*e == open) {
            depth++;
        } else if (*e == close) {
            depth--;
        }
        e++;
    }
    *e = '\0';
    return p;
}

int jsonrpc_parse(char *p, jsonrpc_t *json) {
    if (!json) {
        return -1;
    }
    if (p[0] != '{') {
        json->method = NULL;
        json->params = NULL;
        json->id = NULL;
        return -2;
    }
    p++;

    // char *ver = json_find_field(p, "\"jsonrpc\"");
    char *method = json_find_field(p, "\"method\"");
    char *params = json_find_field(p, "\"params\"");
    char *id = json_find_field(p, "\"id\"");

    if(!method || !id) {
        // not a valid jsonrpc request without these fields found
        return -3;
    }

    // do all the field finding first, since the value extractor will
    // insert nulls at the end of its strings

    // TODO: confirm that version == "2.0"
    json->method = json_extract_val(method);
    json->params = json_extract_val(params);
    json->id = json_extract_val(id);
    return 0;
}

