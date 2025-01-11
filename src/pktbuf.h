/**
 * Copyright (C) Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Private interface to the packet-sized buffers
 */

#ifndef _PKTBUF_H
#define _PKTBUF_H

#include <stddef.h>     // for ssize_t

enum __attribute__((__packed__)) n3n_pktbuf_owner {
    n3n_pktbuf_owner_none = 0,          // Nobody owns it, ready for alloc
    n3n_pktbuf_owner_alloc,             // the new requester owns it
    n3n_pktbuf_owner_resolver_query,
    n3n_pktbuf_owner_resolver_result,
};

struct n3n_pktbuf {
    int capacity;       // Total size of buf
    int offset_start;   // Offset to start of data
    int offset_end;     // Offset to end of data
    enum n3n_pktbuf_owner owner;    // What process and data owns this
    unsigned char buf[];
} __attribute__((__packed__));

void n3n_pktbuf_initialise(ssize_t mtu, int count);

struct n3n_pktbuf *n3n_pktbuf_alloc(ssize_t);
void n3n_pktbuf_free(struct n3n_pktbuf *);

void n3n_pktbuf_zero(struct n3n_pktbuf *);

ssize_t n3n_pktbuf_getbufsize(struct n3n_pktbuf *);
ssize_t n3n_pktbuf_getbufavail(struct n3n_pktbuf *);
void *n3n_pktbuf_getbufptr(struct n3n_pktbuf *);

int n3n_pktbuf_prepend(struct n3n_pktbuf *, ssize_t);
int n3n_pktbuf_append(struct n3n_pktbuf *, ssize_t, void *);

#endif
