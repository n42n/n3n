/**
 * Copyright (C) Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 */

#include <connslot/connslot.h>  // for slots_fdset
#include <n2n_typedefs.h>       // for n3n_runtime_data
#include <n3n/logging.h>        // for traceEvent
#include <stddef.h>
#include <stdint.h>

#ifndef _WIN32
#include <sys/select.h>         // for select, FD_ZERO,
#endif

#include "edge_utils.h"         // for edge_read_from_tap
#include "management.h"         // for readFromMgmtSocket
#include "n2n_define.h"

#ifndef max
#define max(a, b) (((a) < (b)) ? (b) : (a))
#endif

#ifndef min
#define min(a, b) (((a) >(b)) ? (b) : (a))
#endif

static int setup_select (fd_set *rd, fd_set *wr, struct n3n_runtime_data *eee) {
    FD_ZERO(rd);
    FD_ZERO(wr);
    int max_sock = 0;

    if(eee->sock >= 0) {
        FD_SET(eee->sock, rd);
        max_sock = max(max_sock, eee->sock);
    }
#ifndef SKIP_MULTICAST_PEERS_DISCOVERY
    if((eee->conf.allow_p2p)
       && (eee->conf.preferred_sock.family == (uint8_t)AF_INVALID)) {
        FD_SET(eee->udp_multicast_sock, rd);
        max_sock = max(max_sock, eee->udp_multicast_sock);
    }
#endif

#ifndef _WIN32
    FD_SET(eee->device.fd, rd);
    max_sock = max(max_sock, eee->device.fd);
#endif

    max_sock = max(
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

#ifndef _WIN32
    if((eee->device.fd != -1) && FD_ISSET(eee->device.fd, rd)) {
        // read an ethernet frame from the TAP socket; write on the IP socket
        edge_read_from_tap(eee);
    }
#endif

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
