/**
 * Copyright (C) Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 */

#include <connslot/connslot.h>  // for slots_fdset
#include <n2n_typedefs.h>       // for n3n_runtime_data
#include <stddef.h>
#include <stdint.h>
#include <sys/select.h>         // for select, FD_ZERO,

#include "n2n_define.h"

#ifndef max
#define max(a, b) (((a) < (b)) ? (b) : (a))
#endif

#ifndef min
#define min(a, b) (((a) >(b)) ? (b) : (a))
#endif

static int setup_select(fd_set *rd, fd_set *wr, struct n3n_runtime_data *eee) {
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

int mainloop_runonce(fd_set *rd, fd_set *wr, struct n3n_runtime_data *eee) {

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
    
    int rc = select(maxfd + 1, rd, wr, NULL, &wait_time);

    return rc;
}
