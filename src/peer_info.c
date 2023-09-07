/**
 * (C) 2007-23 - ntop.org and contributors
 * Copyright (C) 2023 Hamish Coleman
 *
 */

#include <n2n.h>        // for time_stamp
#include <n2n_define.h> // for TIME_STAMP_FRAME
#include <stdbool.h>
#include "peer_info.h"

// returns an initial time stamp for use with replay protection
uint64_t initial_time_stamp (void) {

    return time_stamp() - TIME_STAMP_FRAME;
}

void peer_info_init (struct peer_info *peer, const n2n_mac_t mac) {
    peer->purgeable = true;
    peer->last_valid_time_stamp = initial_time_stamp();
    memcpy(peer->mac_addr, mac, sizeof(n2n_mac_t));
}

struct peer_info* peer_info_malloc (const n2n_mac_t mac) {
    struct peer_info *peer;
    peer = (struct peer_info*)calloc(1, sizeof(struct peer_info));
    if (!peer) {
        return NULL;
    }
    peer->purgeable = true;
    // TODO peer->last_valid_time_stamp = initial_time_stamp();
    
    return peer;
}
