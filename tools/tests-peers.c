/*
 * SPDX-FileCopyrightText: Copyright Honey Bunny QT
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Unit tests of the peer tables
 */

#include <stdio.h>               // for printf
#include <string.h>              // for memset
#include <time.h>                // for time
#include "n2n.h"                 // for n2n_mac_t
#include "../src/peer_info.h"    // for peer_info_malloc, purge_peer_list, ...
#include "uthash.h"              // for HASH_COUNT, HASH_ITER


// purge_peer_list() on a table of count peers: every third one is fresh,
// every fifth one not purgeable, all the others expired.  Expired purgeable
// peers have to go, fresh or not purgeable ones have to stay - whatever the
// size of the table (n42n/n3n#142: tables of less than 16 were not purged).
static int test_purge (int count) {
    struct peer_info *list = NULL;
    struct peer_info *scan, *tmp;
    time_t now = time(NULL);
    int expect_kept = 0;
    int failed = 0;

    for(int i = 0; i < count; i++) {
        n2n_mac_t mac = {0x02, 0x00, 0x00, 0x00, 0x00, (uint8_t)i};
        struct peer_info *peer = peer_info_malloc(mac);

        peer->socket_fd = -1;
        peer->purgeable = (i % 5) != 4;
        peer->last_seen = ((i % 3) == 0) ? now : now - 600;
        expect_kept += !peer->purgeable || (peer->last_seen == now);
        HASH_ADD_PEER(list, peer);
    }

    size_t purged = purge_peer_list(&list, -1, NULL, now - 60);

    HASH_ITER(hh, list, scan, tmp) {
        if(scan->purgeable && (scan->last_seen < now - 60)) {
            failed = 1;
        }
    }
    if(((int)HASH_COUNT(list) != expect_kept) || ((int)purged != count - expect_kept)) {
        failed = 1;
    }

    printf("purge_peer_list: %2i peers, %2i purged, %2i kept: %s\n",
           count, (int)purged, (int)HASH_COUNT(list), failed ? "FAIL" : "ok");

    clear_peer_list(&list);
    return failed;
}


int main (int argc, char * argv[]) {
    int failed = 0;
    int sizes[] = {0, 1, 3, 15, 16, 17};

    for(size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
        failed |= test_purge(sizes[i]);
    }

    return failed;
}
