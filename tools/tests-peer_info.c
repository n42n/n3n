/*
 * Copyright (C) n3n contributors
 * SPDX-License-Identifier: GPL-3.0-only
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "peer_info.h"


static struct peer_info *add_peer (struct peer_info **peers,
                                   uint8_t mac_suffix,
                                   bool purgeable,
                                   time_t last_seen) {

    n2n_mac_t mac = {0, 0, 0, 0, 0, mac_suffix};
    struct peer_info *peer = calloc(1, sizeof(*peer));

    if(!peer) {
        return NULL;
    }

    memcpy(peer->mac_addr, mac, sizeof(peer->mac_addr));
    peer->purgeable = purgeable;
    peer->last_seen = last_seen;
    peer->socket_fd = -1;
    HASH_ADD_PEER(*peers, peer);

    return peer;
}


static bool peer_is_present (struct peer_info *peers, uint8_t mac_suffix) {

    n2n_mac_t mac = {0, 0, 0, 0, 0, mac_suffix};
    struct peer_info *peer;

    HASH_FIND_PEER(peers, mac, peer);
    return peer != NULL;
}


static bool test_boundary (unsigned int peer_count) {

    struct peer_info *peers = NULL;
    size_t removed;
    size_t expected_removed = peer_count ? 1 : 0;
    unsigned int i;
    bool failed = false;

    for(i = 0; i < peer_count; i++) {
        if(!add_peer(&peers, i + 1, true, i ? 150 : 50)) {
            failed = true;
            break;
        }
    }

    removed = purge_peer_list(&peers, -1, NULL, 100);
    printf("purge_peer_list boundary peers=%u: removed=%zu remaining=%u\n",
           peer_count, removed, HASH_COUNT(peers));

    failed = failed
             || removed != expected_removed
             || HASH_COUNT(peers) != peer_count - expected_removed;

    clear_peer_list(&peers);
    return failed;
}


static bool test_peer_properties (void) {

    struct peer_info *peers = NULL;
    size_t removed;
    bool stale_present;
    bool fresh_present;
    bool non_purgeable_present;
    int failed;

    if(!add_peer(&peers, 1, true, 50)
       || !add_peer(&peers, 2, true, 150)
       || !add_peer(&peers, 3, false, 50)) {
        clear_peer_list(&peers);
        return true;
    }

    removed = purge_peer_list(&peers, -1, NULL, 100);
    stale_present = peer_is_present(peers, 1);
    fresh_present = peer_is_present(peers, 2);
    non_purgeable_present = peer_is_present(peers, 3);

    printf("purge_peer_list small-list: removed=%zu remaining=%u\n",
           removed, HASH_COUNT(peers));
    printf("stale purgeable peer present=%d\n", stale_present);
    printf("fresh purgeable peer present=%d\n", fresh_present);
    printf("stale non-purgeable peer present=%d\n", non_purgeable_present);

    failed = removed != 1
             || HASH_COUNT(peers) != 2
             || stale_present
             || !fresh_present
             || !non_purgeable_present;

    clear_peer_list(&peers);
    return failed;
}


int main (void) {

    int failed = false;

    failed |= test_boundary(0);
    failed |= test_boundary(1);
    failed |= test_boundary(3);
    failed |= test_boundary(15);
    failed |= test_boundary(16);
    failed |= test_boundary(17);
    failed |= test_peer_properties();

    return failed;
}
