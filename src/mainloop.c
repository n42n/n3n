/**
 * Copyright (C) Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 */

#include <assert.h>
#include <connslot/connslot.h>  // for slots_fdset
#include <n2n_typedefs.h>       // for n3n_runtime_data
#include <n3n/edge.h>           // for edge_read_proto3_udp
#include <n3n/logging.h>        // for traceEvent
#include <n3n/mainloop.h>       // for fd_info_proto
#include <n3n/metrics.h>
#include <n3n/logging.h>        // for traceEvent
#include <stddef.h>
#include <stdint.h>

#ifndef _WIN32
#include <sys/select.h>         // for select, FD_ZERO,
#include <unistd.h>             // for close
#endif

#include "edge_utils.h"         // for edge_read_from_tap
#include "management.h"         // for readFromMgmtSocket
#include "minmax.h"             // for min, max

#ifndef _WIN32
// Another wonderful gift from the world of POSIX compliance is not worth much
#define closesocket(a) close(a)
#endif

static struct metrics {
    uint32_t mainloop;      // mainloop_runonce() is called
    uint32_t register_fd;   // mainloop_register_fd() is called
    uint32_t unregister_fd; // mainloop_unregister_fd() is called
    uint32_t connlist_alloc;
    uint32_t connlist_free;
} metrics;

static struct n3n_metrics_items_llu32 metrics_items = {
    .name = "count",
    .desc = "Track the events in the lifecycle of mainloop objects",
    .name1 = "event",
    .items = {
        {
            .val1 = "mainloop",
            .offset = offsetof(struct metrics, mainloop),
        },
        {
            .val1 = "register_fd",
            .offset = offsetof(struct metrics, register_fd),
        },
        {
            .val1 = "unregister_fd",
            .offset = offsetof(struct metrics, unregister_fd),
        },
        {
            .val1 = "connlist_alloc",
            .offset = offsetof(struct metrics, connlist_alloc),
        },
        {
            .val1 = "connlist_free",
            .offset = offsetof(struct metrics, connlist_free),
        },
        { },
    },
};

static char *proto_str[] = {
    [fd_info_proto_unknown] = "?",
    [fd_info_proto_tuntap] = "tuntap",
    [fd_info_proto_listen_http] = "listen_http",
    [fd_info_proto_v3udp] = "v3udp",
    [fd_info_proto_http] = "http",
};

struct fd_info {
    int fd;                     // The file descriptor for this connection
    int stats_reads;            // The number of ready to read events
    enum fd_info_proto proto;   // What protocol to use on a read event
    int8_t connnr;              // which connlist[] is being used as buffer
};

// A static array of known file descriptors will not scale once full TCP
// connection support is added, but will work for now
#define MAX_HANDLES 16
static struct fd_info fdlist[MAX_HANDLES];
static int fdlist_next_search;

#define MAX_CONN 8
// TODO: need pools of struct conn, for each expected buffer size
static struct conn connlist[MAX_CONN];
static int connlist_next_search;

static void metrics_callback (strbuf_t **reply, const struct n3n_metrics_module *module) {
    int slot = 0;
    char buf[16];
    while(slot < MAX_HANDLES) {
        if(fdlist[slot].fd == -1) {
            slot++;
            continue;
        }

        snprintf(buf, sizeof(buf), "%i", fdlist[slot].fd);

        n3n_metrics_render_u32tags(
            reply,
            module,
            "fd_reads",
            (char *)&fdlist[slot].stats_reads - (char *)&fdlist,
            2,  // number of tag+val pairs
            "fd",
            buf,
            "proto",
            proto_str[fdlist[slot].proto]
        );
        // TODO:
        // - do we need to keep each fd lifecycle clear by tracking and
        // outputting the open timestamp?
        slot++;
    }
}

static struct n3n_metrics_module metrics_module_dynamic = {
    .name = "mainloop",
    .data = &fdlist,
    .cb = &metrics_callback,
    .type = n3n_metrics_type_cb,
};

static struct n3n_metrics_module metrics_module_static = {
    .name = "mainloop",
    .data = &metrics,
    .items_llu32 = &metrics_items,
    .type = n3n_metrics_type_llu32,
};

static void connlist_init () {
    int conn = 0;
    while(conn < MAX_CONN) {
        conn_init(&connlist[conn], 4000, 1000);
        conn++;
    }
    connlist_next_search = 0;
}

static int connlist_alloc (enum conn_proto proto) {
    int conn = connlist_next_search % MAX_CONN;
    int count = MAX_CONN;
    while(count) {
        if(connlist[conn].proto == CONN_PROTO_UNK) {
            connlist[conn].proto = proto;
            connlist_next_search = conn + 1;
            metrics.connlist_alloc++;
            return conn;
        }
        conn = (conn + 1) % MAX_CONN;
        count--;
    }
    return -1;
}

static void connlist_free (int connnr) {
    if(connnr > MAX_CONN) {
        // TODO: error!
        return;
    }
    connlist[connnr].proto = CONN_PROTO_UNK;
    fdlist_next_search = connnr;
    metrics.connlist_free++;
}

// Used only to initialise the array at startup
static void fdlist_zero () {
    int slot = 0;
    while(slot < MAX_HANDLES) {
        fdlist[slot].connnr = -1;
        fdlist[slot].fd = -1;
        fdlist[slot].proto = fd_info_proto_unknown;
        slot++;
    }
    fdlist_next_search = 0;
}

static int fdlist_allocslot (int fd, enum fd_info_proto proto) {
    int slot = fdlist_next_search % MAX_HANDLES;
    int count = MAX_HANDLES;
    while(count) {
        if(fdlist[slot].fd == -1) {
            metrics.register_fd++;
            fdlist[slot].fd = fd;
            fdlist[slot].proto = proto;
            fdlist[slot].stats_reads = 0;
            fdlist_next_search = slot + 1;
            return slot;
        }
        slot = (slot + 1) % MAX_HANDLES;
        count--;
    }
    return -1;
}

static void fdlist_freefd (int fd) {
    int slot = 0;
    while(slot < MAX_HANDLES) {
        if(fdlist[slot].fd != fd) {
            slot++;
            continue;
        }
        metrics.unregister_fd++;
        fdlist[slot].fd = -1;
        fdlist[slot].proto = fd_info_proto_unknown;
        fdlist_next_search = slot;
        if(fdlist[slot].connnr != -1) {
            connlist_free(fdlist[slot].connnr);
        }
        return;
    }

    // TODO:
    // - could assert or similar
}

static int fdlist_fd_set (fd_set *rd, fd_set *wr) {
    int max_sock = 0;
    int slot = 0;
    while(slot < MAX_HANDLES) {
        if(fdlist[slot].fd == -1) {
            slot++;
            continue;
        }

        // TODO:
        // - if no empty conn, dont FD_SET on proto TCP listen

        FD_SET(fdlist[slot].fd, rd);
        max_sock = MAX(max_sock, fdlist[slot].fd);

        if(fdlist[slot].connnr == -1) {
            slot++;
            continue;
        }

        if(conn_iswriter(&connlist[fdlist[slot].connnr])) {
            FD_SET(fdlist[slot].fd, wr);
        }

        slot++;
    }
    return max_sock;
}

static void handle_fd (const time_t now, const struct fd_info info, struct n3n_runtime_data *eee) {
    switch(info.proto) {
        case fd_info_proto_unknown:
            // should not happen!
            assert(false);
            return;

        case fd_info_proto_tuntap:
            // read an ethernet frame from the TAP socket; write on the IP
            // socket
            // TODO: change API to tell it which fd
            edge_read_from_tap(eee);
            return;

        case fd_info_proto_listen_http: {
            int client = accept(info.fd, NULL, 0);
            if(client == -1) {
                // TODO:
                // - increment error stats
                return;
            }

            int slotnr = fdlist_allocslot(client, fd_info_proto_http);
            int connnr = connlist_alloc(CONN_PROTO_HTTP);
            if(slotnr < 0 || connnr < 0) {
                // TODO:
                // - increment error stats
                // - send static text
                closesocket(client);
                return;
            }
            fdlist[slotnr].connnr = connnr;
            conn_accept(&connlist[connnr], client, CONN_PROTO_HTTP);

            return;
        }

        case fd_info_proto_v3udp: {
            uint8_t pktbuf[N2N_PKT_BUF_SIZE];
            edge_read_proto3_udp(
                eee,
                info.fd,
                pktbuf,
                sizeof(pktbuf),
                now
            );
            return;
        }

        case fd_info_proto_http: {
            struct conn *conn = &connlist[info.connnr];
            conn_read(conn, info.fd);

            switch(conn->state) {
                case CONN_EMPTY:
                case CONN_READING:
                case CONN_SENDING:
                    // These states dont require us to do anything
                    // TODO:
                    // - handle reading/sending simultaneous?
                    return;

                case CONN_READY:
                    mgmt_api_handler(eee, conn);
                    return;

                case CONN_ERROR:
                case CONN_CLOSED:
                    conn_close(conn, info.fd);
                    // TODO: freefd() is doing a fd search, we could optimise
                    fdlist_freefd(info.fd);
            }
            return;
        }
    }
}

static void fdlist_check_ready (fd_set *rd, fd_set *wr, const time_t now, struct n3n_runtime_data *eee) {
    int slot = 0;
    // A linear scan is not ideal, but until we support things other than
    // select() it will need to suffice
    while(slot < MAX_HANDLES) {
        int fd = fdlist[slot].fd;
        if(fd == -1) {
            slot++;
            continue;
        }
        if(FD_ISSET(fd, rd)) {
            fdlist[slot].stats_reads++;
            handle_fd(now, fdlist[slot], eee);
        }
        if(FD_ISSET(fd, wr)) {
            // We should not be listening on this socket if there is no
            // connnr assigned, but paranoia..
            if(fdlist[slot].connnr == -1) {
                traceEvent(TRACE_DEBUG, "writer bad connnr");
                slot++;
                continue;
            }

            // TODO: track the stats on writes?
            conn_write(&connlist[fdlist[slot].connnr], fd);
        }

        if(fdlist[slot].connnr != -1) {
            int timeout = 60;
            conn_closeidle(&connlist[fdlist[slot].connnr], now, timeout);
        }
        slot++;
    }
}

static int setup_select (fd_set *rd, fd_set *wr, struct n3n_runtime_data *eee) {
    FD_ZERO(rd);
    FD_ZERO(wr);
    int max_sock = fdlist_fd_set(rd, wr);

    // HACK - until this mainloop supports v3tcp proto sockets
    if((eee->conf.connect_tcp) && (eee->sock != -1)) {
        FD_SET(eee->sock, rd);
        max_sock = MAX(max_sock, eee->sock);
    }

    return max_sock;
}

int mainloop_runonce (fd_set *rd, fd_set *wr, struct n3n_runtime_data *eee) {
    metrics.mainloop ++;

    int maxfd = setup_select(rd, wr, eee);

    // FIXME:
    // unlock the windows tun reader thread before select() and lock it
    // again after select().  It currently works by accident, but the
    // structures it manipulates are not thread-safe, so try to make it
    // work by /design/

    struct timeval wait_time;
    if(eee->sn_wait) {
        wait_time.tv_sec = (SOCKET_TIMEOUT_INTERVAL_SECS / 10 + 1);
    } else {
        wait_time.tv_sec = (SOCKET_TIMEOUT_INTERVAL_SECS);
    }
    wait_time.tv_usec = 0;

    int ready = select(maxfd + 1, rd, wr, NULL, &wait_time);

    if(ready < 1) {
        // Nothing ready or an error
        return ready;
    }

    // One timestamp to use for this entire loop iteration
    time_t now = time(NULL);

    fdlist_check_ready(rd, wr, now, eee);

    return ready;
}

void mainloop_register_fd (int fd, enum fd_info_proto proto) {
    int slot = fdlist_allocslot(fd, proto);

    // TODO: the moment this starts to fire, we need to revamp the
    // implementation of the fdlist table
    assert(slot != -1);
}

void mainloop_unregister_fd (int fd) {
    fdlist_freefd(fd);
}

void n3n_initfuncs_mainloop () {
    connlist_init();
    fdlist_zero();
    n3n_metrics_register(&metrics_module_dynamic);
    n3n_metrics_register(&metrics_module_static);
}
