/**
 * (C) 2007-23 - ntop.org and contributors
 * Copyright (C) 2023 Hamish Coleman
 *
 */

#include <n2n.h>        // for time_stamp
#include <stdbool.h>
#include "peer_info.h"

struct peer_info* peer_info_malloc() {
    struct peer_info *peer;
    peer = (struct peer_info*)calloc(1, sizeof(struct peer_info));
    if (!peer) {
        return NULL;
    }
    peer->purgeable = true;
    // TODO peer->last_valid_time_stamp = initial_time_stamp();
    
    return peer;
}
