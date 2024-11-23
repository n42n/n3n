/** @file
 * Internal interface definitions for the connslot abstraction
 *
 * Copyright (C) Hamish Coleman
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef CONNSLOT_H
#define CONNSLOT_H

#include <stdbool.h>     // for bool
#include <sys/types.h>   // for ssize_t

#ifndef _WIN32
#include <sys/select.h>  // for fd_set
#endif

#ifdef _WIN32
#include <winsock2.h>
#endif

#include "strbuf.h"      // for strbuf_t

#ifdef _WIN32
void *memmem(void *haystack, size_t haystack_len, void * needle, size_t needle_len);
#endif

enum __attribute__((__packed__)) conn_state {
    CONN_EMPTY = 0,
    CONN_READING = 1,
    CONN_READY = 2,
    CONN_SENDING = 3,
    CONN_CLOSED = 4,
    CONN_ERROR = 5,
};

enum __attribute__((__packed__)) conn_proto {
    CONN_PROTO_UNK = 0,
    CONN_PROTO_HTTP = 1,
    CONN_PROTO_BE16LEN = 2,
};

typedef struct conn {
    strbuf_t *request;      // Request from remote
    strbuf_t *reply_header; // not shared reply data
    strbuf_t *reply;        // shared reply data (const struct)
    int activity;           // truncated timestamp of last txn
    int fd;
    unsigned int reply_sendpos;
    enum conn_state state;
    enum conn_proto proto;
} conn_t;

#define SLOTS_LISTEN 2
typedef struct slots {
    int nr_slots;
    int nr_open;
    int listen[SLOTS_LISTEN];
    int timeout;
    conn_t conn[];
} slots_t;

void conn_zero(conn_t *);
int conn_init(conn_t *, size_t, size_t);
void conn_read(conn_t *, int);
ssize_t conn_write(conn_t *, int);
int conn_iswriter(conn_t *);
void conn_close(conn_t *, int);

void slots_free(slots_t *slots);
slots_t *slots_malloc(int nr_slots, size_t, size_t);
int slots_create_listen_tcp(int, bool);
int slots_listen_tcp(slots_t *, int, bool);
int slots_create_listen_unix(char *, int, int, int);
int slots_listen_unix(slots_t *, char *, int, int, int);
void slots_listen_close(slots_t *);
int slots_fdset(slots_t *, fd_set *, fd_set *);
int slots_accept(slots_t *, int, enum conn_proto);
int slots_closeidle(slots_t *);
int slots_fdset_loop(slots_t *, fd_set *, fd_set *);
void slots_dump(strbuf_t **, slots_t *);
#endif
