/*
 * (C) 2007-22 - ntop.org and contributors
 * Copyright (C) 2023-25 Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * The resolver thread minimal public API
 */

#ifndef _N3N_RESOLVE_H_
#define _N3N_RESOLVE_H_

typedef struct n3n_resolve_parameter n3n_resolve_parameter_t;

#define RESOLVE_LIST_SUPERNODE  1   // edge uses to list supernode hostnames
#define RESOLVE_LIST_PEER       2   // supernode uses to list peer hostnames

void resolve_hostnames_str_add (int, const char *);

#endif
