/*
 * (C) 2007-22 - ntop.org and contributors
 * Copyright (C) 2023-25 Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * The resolver thread non-public API
 */

#ifndef _RESOLVE_H_
#define _RESOLVE_H_

#include <n2n_typedefs.h>   // for n3n_sock_t
#include <n3n/resolve.h>    // for n2n_resolve_parameter_t
#include <stdbool.h>
#include <time.h>
#include <uthash.h>         // for UT_hash_handle

#include "config.h"         // for HAVE_LIBPTHREAD
#include "peer_info.h"      // for struct peer_info

struct peer_info;

#ifdef HAVE_LIBPTHREAD
struct n3n_resolve_ip_sock {
    char          *org_ip;            /* pointer to original ip/named address string (used read only) */
    n3n_sock_t sock;                  /* resolved socket */
    n3n_sock_t    *org_sock;          /* pointer to original socket where 'sock' gets copied to from time to time */
    int error_code;                   /* result of last resolution attempt */

    UT_hash_handle hh;                /* makes this structure hashable */
};

// structure to hold resolver thread's parameters
struct n3n_resolve_parameter {
    struct n3n_resolve_ip_sock *list;      /* pointer to list of to be resolved nodes */
    time_t check_interval;                 /* interval to checik resolover results */
    time_t last_checked;                   /* last time the resolver results were cheked */
    time_t last_resolved;                  /* last time the resolver completed */
    bool changed;                          /* indicates a change */
    bool request;                          /* flags main thread's need for intermediate resolution */
    pthread_t id;                          /* thread id */
    pthread_mutex_t access;                /* mutex for shared access */
};
#endif

int resolve_create_thread (n3n_resolve_parameter_t **param, struct peer_info *sn_list);
bool resolve_check (n3n_resolve_parameter_t *param, bool resolution_request, time_t now);
void resolve_cancel_thread (n3n_resolve_parameter_t *param);

// Internal resolver function, will turn static once supernode.c doesnt use it
int supernode2sock (n3n_sock_t * sn, const char *addrIn);

// called from edge_utils, runs supernode2sock only ifndef HAVE_LIBPTHREAD
int maybe_supernode2sock (n3n_sock_t * sn, const char *addrIn);

const char *resolve_hostnames_str_get (int, int);
void resolve_log_hostnames (int);
int resolve_hostnames_str_to_peer_info (int, struct peer_info **);

#endif
