/**
 * Copyright (C) Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 */

#include <assert.h>
#include <connslot/connslot.h>  // for slots_fdset
#include <n2n_typedefs.h>       // for n3n_runtime_data
#include <n3n/mainloop.h>       // for fd_info_proto
#include <n3n/logging.h>        // for traceEvent
#include <stddef.h>
#include <stdint.h>

#ifndef _WIN32
#include <sys/select.h>         // for select, FD_ZERO,
#endif

#include "edge_utils.h"         // for edge_read_from_tap
#include "management.h"         // for readFromMgmtSocket
#include "minmax.h"             // for min, max
#include "n2n_define.h"

static void handle_fd (int fd, enum fd_info_proto proto, struct n3n_runtime_data *eee) {
    switch(proto) {
        case fd_info_proto_unknown:
            // should not happen!
            assert(false);
            return;

        case fd_info_proto_tuntap:
            // read an ethernet frame from the TAP socket; write on the IP
            // socket
            edge_read_from_tap(eee);
            return;

        case fd_info_proto_listen_http:
            int slotnr = slots_accept(eee->mgmt_slots, fd, CONN_PROTO_HTTP);
            if(slotnr < 0) {
                // TODO: increment error stats
                return;
            }
            // TODO: Schedule slot for immediately reading
            // FD_SET(eee->mgmt_slots->conn[slotnr].fd, rd);
            return;
    }
}

struct fd_info {
    int fd;
    enum fd_info_proto proto;
};

// A static array of known file descriptors will not scale once full TCP
// connection support is added, but will work for now
#define MAX_HANDLES 16
static struct fd_info fdlist[MAX_HANDLES];
static int fdlist_next_search;

// Used only to initialise the array at startup
static void fdlist_zero () {
    int slot = 0;
    while(slot < MAX_HANDLES) {
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
            fdlist[slot].fd = fd;
            fdlist[slot].proto = proto;
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
            continue;
        }
        fdlist[slot].fd = -1;
        fdlist[slot].proto = fd_info_proto_unknown;
        fdlist_next_search = slot;
        return;
    }

    // TODO:
    // - could assert or similar
}

static int fdlist_read_fd_set (fd_set *rd) {
    int max_sock = 0;
    int slot = 0;
    while(slot < MAX_HANDLES) {
        if(fdlist[slot].fd != -1) {
            FD_SET(fdlist[slot].fd, rd);
            max_sock = MAX(max_sock, fdlist[slot].fd);
        }
        slot++;
    }
    return max_sock;
}

static void fdlist_check_ready (fd_set *rd, struct n3n_runtime_data *eee) {
    int slot = 0;
    // A linear scan is not ideal, but until we support things other than
    // select() it will need to suffice
    while(slot < MAX_HANDLES) {
        if(fdlist[slot].fd == -1) {
            slot++;
            continue;
        }
        if(!FD_ISSET(fdlist[slot].fd, rd)) {
            slot++;
            continue;
        }

        handle_fd(fdlist[slot].fd, fdlist[slot].proto, eee);
        slot++;
    }
}

static int setup_select (fd_set *rd, fd_set *wr, struct n3n_runtime_data *eee) {
    FD_ZERO(rd);
    FD_ZERO(wr);
    int max_sock = fdlist_read_fd_set(rd);

    if(eee->sock >= 0) {
        FD_SET(eee->sock, rd);
        max_sock = MAX(max_sock, eee->sock);
    }
#ifndef SKIP_MULTICAST_PEERS_DISCOVERY
    if((eee->conf.allow_p2p)
       && (eee->conf.preferred_sock.family == (uint8_t)AF_INVALID)) {
        FD_SET(eee->udp_multicast_sock, rd);
        max_sock = MAX(max_sock, eee->udp_multicast_sock);
    }
#endif

    max_sock = MAX(
        max_sock,
        slots_fdset(
            eee->mgmt_slots,
            rd,
            wr
        )
    );

    return max_sock;
}

int mainloop_runonce (fd_set *rd, fd_set *wr, struct n3n_runtime_data *eee) {

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
    // time_t now = time(NULL);

    fdlist_check_ready(rd, eee);

    int slots_ready = slots_fdset_loop(
        eee->mgmt_slots,
        rd,
        wr
    );

    if(slots_ready < 0) {
        traceEvent(
            TRACE_ERROR,
            "slots_fdset_loop returns %i (Is daemon exiting?)", slots_ready
        );
    } else if(slots_ready > 0) {
        // A linear scan is not ideal, but this is a select() loop
        // not one built for performance.
        // - update connslot to have callbacks instead of scan
        // - switch to a modern poll loop (and reimplement differently
        //   for each OS supported)
        // This should only be a concern if we are doing a large
        // number of slot connections
        for(int i=0; i<eee->mgmt_slots->nr_slots; i++) {
            if(eee->mgmt_slots->conn[i].fd == -1) {
                continue;
            }

            if(eee->mgmt_slots->conn[i].state == CONN_READY) {
                mgmt_api_handler(eee, &eee->mgmt_slots->conn[i]);
            }
        }
    }

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
    fdlist_zero();
}
