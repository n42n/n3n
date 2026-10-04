/**
 * SPDX-License-Identifier: LGPL-2.1-only
 * SPDX-FileCopyrightText: Copyright Hamish Coleman
 *
 * Management of packet-sized buffers
 */

#ifndef _PKTBUF_H
#define _PKTBUF_H

#include <inttypes.h>   // for uint8_t
#include <sys/types.h>  // for ssize_t

enum __attribute__((__packed__)) n3n_pktbuf_owner {
    n3n_pktbuf_owner_none = 0,          // Nobody owns it, ready for alloc
    n3n_pktbuf_owner_staticdata,        // Data compiled into the binary
    n3n_pktbuf_owner_alloc,             // the new requester owns it
    n3n_pktbuf_owner_resolver_query,
    n3n_pktbuf_owner_resolver_result,
    n3n_pktbuf_owner_rx_pdu,
};

struct n3n_pktbuf {
    uint8_t *const buf;
    const short capacity;       // Total size of buf
    short offset_start;   // Offset to start of data
    short offset_end;     // Offset to end of data
    enum n3n_pktbuf_owner owner;    // What process and data owns this
};

void n3n_pktbuf_initialise (ssize_t mtu, int count);

struct n3n_pktbuf *n3n_pktbuf_alloc(ssize_t);
void n3n_pktbuf_free (struct n3n_pktbuf *);

void n3n_pktbuf_zero (struct n3n_pktbuf *);

ssize_t n3n_pktbuf_getbufsize (const struct n3n_pktbuf);
ssize_t n3n_pktbuf_getbufavail (const struct n3n_pktbuf);
void *n3n_pktbuf_getbufptr (const struct n3n_pktbuf);

int n3n_pktbuf_prepend(struct n3n_pktbuf *, ssize_t);
int n3n_pktbuf_append(struct n3n_pktbuf *, ssize_t, void *);

#endif
