/*
 *
 * Copyright (C) Hamish Coleman
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef JSONRPC_H
#define JSONRPC_H

typedef struct jsonrpc {
    char *id;
    char *method;
    char *params;
} jsonrpc_t;

int jsonrpc_parse(char *, jsonrpc_t *);
char *json_find_field(char *, char *);
char *json_extract_val(char *);
#endif
