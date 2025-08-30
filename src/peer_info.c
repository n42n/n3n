/**
 * (C) 2007-23 - ntop.org and contributors
 * Copyright (C) 2023-25 Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 */

#include <n2n.h>        // for time_stamp
#include <n2n_define.h> // for TIME_STAMP_FRAME
#include <n2n_wire.h>   // for fill_n3nsock
#include <n3n/ethernet.h> // for for n2n_mac_t
#include <n3n/logging.h> // for traceEvent
#include <n3n/metrics.h> // for traceEvent
#include <sn_selection.h>   // for sn_selection_criterion_default
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <sys/socket.h>
#endif

#include "management.h" // for mgmt_event_post
#include "peer_info.h"
#include "uthash.h"

#ifndef _WIN32
// Another wonderful gift from the world of POSIX compliance is not worth much
#define closesocket(a) close(a)
#endif

static struct metrics {
    uint32_t init;      // peer_info_init() is called
    uint32_t alloc;     // peer_info_malloc() is called
    uint32_t free;      // peer_info_free() is called
    uint32_t hostname;  // n3n_peer_add_by_hostname() is called
} metrics;

static struct n3n_metrics_items_llu32 metrics_items = {
    .name = "count",
    .desc = "Track the events in the lifecycle of peer_info objects",
    .name1 = "speed",
    .name2 = "event",
    .items = {
        {
            .val1 = "fast",
            .val2 = "alloc",
            .offset = offsetof(struct metrics, alloc),
        },
        {
            .val1 = "fast",
            .val2 = "free",
            .offset = offsetof(struct metrics, free),
        },
        {
            .val1 = "slow",
            .val2 = "hostname",
            .offset = offsetof(struct metrics, hostname),
        },
        {
            .val1 = "fast",
            .val2 = "init",
            .offset = offsetof(struct metrics, init),
        },
        { },
    },
};

static struct n3n_metrics_module metrics_module = {
    .name = "peer_info",
    .data = &metrics,
    .items_llu32 = &metrics_items,
    .type = n3n_metrics_type_llu32,
};

void n3n_initfuncs_peer_info () {
    n3n_metrics_register(&metrics_module);
}

/* ************************************** */

// returns an initial time stamp for use with replay protection
uint64_t initial_time_stamp (void) {

    return time_stamp() - TIME_STAMP_FRAME;
}

void peer_info_init (struct peer_info *peer, const n2n_mac_t mac) {
    metrics.init++;
    peer->purgeable = true;
    peer->last_valid_time_stamp = initial_time_stamp();
    memcpy(peer->mac_addr, mac, sizeof(n2n_mac_t));
}

struct peer_info* peer_info_malloc (const n2n_mac_t mac) {
    metrics.alloc++;
    struct peer_info *peer;
    peer = (struct peer_info*)calloc(1, sizeof(struct peer_info));
    if(!peer) {
        return NULL;
    }
    peer->time_alloc = time(NULL);

    peer_info_init(peer, mac);

    return peer;
}

void peer_info_free (struct peer_info *p) {
    metrics.free++;
    free(p->hostname);
    free(p);
}

/*
 * If the peer is still valid, returns it.
 * If the peer has timed out, frees it and returns NULL
 * Used after a HASH_FIND_PEER to validate the found peer
 */
struct peer_info* peer_info_validate (struct peer_info **list, struct peer_info *p) {
    if(!p) {
        return NULL;
    }
    if(!p->purgeable) {
        return p;
    }
    time_t now = time(NULL);
    if(p->last_seen >= now - REGISTRATION_TIMEOUT) {
        return p;
    }
    HASH_DEL(*list, p);
    mgmt_event_post(N3N_EVENT_PEER,N3N_EVENT_PEER_PURGE,p);
    peer_info_free(p);
    return NULL;
}

inline char *peer_info_get_hostname (struct peer_info *p) {
    if(!p) {
        return NULL;
    }
    return p->hostname;
}

/** Purge old items from the peer_list, eventually close the related socket, and
 * return the number of items that were removed. */
size_t purge_peer_list (struct peer_info **peer_list,
                        SOCKET socket_not_to_close,
                        n2n_tcp_connection_t **tcp_connections,
                        time_t purge_before) {

    struct peer_info *scan, *tmp;
    n2n_tcp_connection_t *conn;
    size_t retval = 0;

    // If our table is small, dont bother purging it
    // TODO: should the table size be a config param?
    if(HASH_COUNT(*peer_list) < 16) {
        return retval;
    }

    HASH_ITER(hh, *peer_list, scan, tmp) {
        // TODO: untangle the tcp_connections usage and use
        // peer_info_validate() as the core of this loop
        if(scan->purgeable && scan->last_seen < purge_before) {
            if((scan->socket_fd >=0) && (scan->socket_fd != socket_not_to_close)) {
                if(tcp_connections) {
                    HASH_FIND_INT(*tcp_connections, &scan->socket_fd, conn);
                    if(conn) {
                        HASH_DEL(*tcp_connections, conn);
                        free(conn);
                    }
                    shutdown(scan->socket_fd, SHUT_RDWR);
                    closesocket(scan->socket_fd);
                }
            }
            HASH_DEL(*peer_list, scan);
            mgmt_event_post(N3N_EVENT_PEER,N3N_EVENT_PEER_PURGE,scan);
            /* FIXME: generates events for more than just p2p */
            retval++;
            peer_info_free(scan);
        }
    }

    return retval;
}

/** Purge all items from the peer_list and return the number of items that were removed. */
size_t clear_peer_list (struct peer_info ** peer_list) {

    struct peer_info *scan, *tmp;
    size_t retval = 0;

    HASH_ITER(hh, *peer_list, scan, tmp) {
        HASH_DEL(*peer_list, scan);
        mgmt_event_post(N3N_EVENT_PEER,N3N_EVENT_PEER_CLEAR,scan);
        /* FIXME: generates events for more than just p2p */
        retval++;
        peer_info_free(scan);
    }

    return retval;
}

size_t purge_expired_nodes (struct peer_info **peer_list,
                            SOCKET socket_not_to_close,
                            n2n_tcp_connection_t **tcp_connections,
                            time_t *p_last_purge,
                            int frequency, int timeout) {

    time_t now = time(NULL);
    size_t num_reg = 0;

    if((now - (*p_last_purge)) < frequency) {
        return 0;
    }

    traceEvent(TRACE_DEBUG, "Purging old registrations");

    num_reg = purge_peer_list(peer_list, socket_not_to_close, tcp_connections, now - timeout);

    (*p_last_purge) = now;
    traceEvent(TRACE_DEBUG, "Remove %ld registrations", num_reg);

    return num_reg;
}

/* ************************************** */

int find_and_remove_peer (struct peer_info **head, const n2n_mac_t mac) {

    struct peer_info *peer;

    HASH_FIND_PEER(*head, mac, peer);
    if(peer) {
        HASH_DEL(*head, peer);
        peer_info_free(peer);
        return(1);
    }

    return(0);
}

/* ************************************** */

struct peer_info* find_peer_by_sock (const n3n_sock_t *sock, struct peer_info *peer_list) {

    struct peer_info *scan, *tmp, *ret = NULL;

    HASH_ITER(hh, peer_list, scan, tmp) {
        if(memcmp(&(scan->sock), sock, sizeof(n3n_sock_t)) == 0) {
            ret = scan;
            break;
        }
    }

    return ret;
}

/* *********************************************** */

struct peer_info* add_sn_to_list_by_mac_or_sock (struct peer_info **sn_list, n3n_sock_t *sock, const n2n_mac_t mac, int *skip_add) {

    struct peer_info *scan, *tmp, *peer = NULL;

    if(!is_null_mac(mac)) { /* not zero MAC */
        HASH_FIND_PEER(*sn_list, mac, peer);
    }

    if(peer) {
        return peer;
    }

    /* zero MAC, search by socket */
    HASH_ITER(hh, *sn_list, scan, tmp) {
        if(memcmp(&(scan->sock), sock, sizeof(n3n_sock_t)) != 0) {
            continue;
        }

        // update mac if appropriate
        // (needs to be deleted first because it is key to the hash list)
        if(!is_null_mac(mac)) {
            HASH_DEL(*sn_list, scan);
            memcpy(scan->mac_addr, mac, sizeof(n2n_mac_t));
            HASH_ADD_PEER(*sn_list, scan);
        }

        peer = scan;
        break;
    }

    if(peer) {
        return peer;
    }

    if(*skip_add != SN_ADD) {
        return peer;
    }

    peer = peer_info_malloc(mac);
    if(!peer) {
        return peer;
    }

    peer->selection_criterion = sn_selection_criterion_default();
    memcpy(&(peer->sock), sock, sizeof(n3n_sock_t));
    HASH_ADD_PEER(*sn_list, peer);
    *skip_add = SN_ADD_ADDED;

    return peer;
}

struct peer_info* peer_upsert_by_sockaddr (
    struct peer_info **list,
    struct sockaddr *addr,
    size_t addrlen
) {
    struct n2n_sock sock;
    if(fill_n3nsock(&sock, addr) != 0) {
        return NULL;
    }

    struct peer_info *peer = NULL;

    // TODO:
    // - keep count of how many non-indexed "full scan" are done
    // - if there are many, could add an index for that

    /* search by socket */
    {
        struct peer_info *scan, *tmp;
        HASH_ITER(hh, *list, scan, tmp) {
            if(memcmp(&(scan->sock), &sock, sizeof(sock)) != 0) {
                continue;
            }

            peer = scan;
            break;
        }
    }

    // If we didnt find one, alloc one
    if(!peer) {
        n2n_mac_t null = {0,0,0,0,0,0};
        peer = peer_info_malloc(null);

        // If the alloc didnt work, bail out
        if(!peer) {
            return NULL;
        }

        peer->selection_criterion = sn_selection_criterion_default();
        memcpy(&(peer->sock), &sock, sizeof(n3n_sock_t));

        HASH_ADD_PEER(*list, peer);
    }

    return peer;
}

/* ***************************************************** */


// checks if a provided time stamp is consistent with current time and previously valid time stamps
// and, in case of validity, updates the "last valid time stamp"
static int time_stamp_verify_and_update (uint64_t stamp, uint64_t *previous_stamp, int allow_jitter) {

    int64_t diff; /* do not change to unsigned */
    uint64_t co;  /* counter only mode (for sub-seconds) */

    co = (stamp << 63) >> 63;

    // is it around current time (+/- allowed deviation TIME_STAMP_FRAME)?
    diff = stamp - time_stamp();
    // abs()
    diff = (diff < 0 ? -diff : diff);
    if(diff >= TIME_STAMP_FRAME) {
        traceEvent(TRACE_DEBUG, "time_stamp_verify_and_update found a timestamp out of allowed frame.");
        return 0; // failure
    }

    // if applicable: is it higher than previous time stamp (including allowed deviation of TIME_STAMP_JITTER)?
    if(NULL != previous_stamp) {
        diff = stamp - *previous_stamp;
        if(allow_jitter) {
            // 8 times higher jitter allowed for counter-only flagged timestamps ( ~ 1.25 sec with 160 ms default jitter)
            diff += TIME_STAMP_JITTER << (co << 3);
        }

        if(diff <= 0) {
            traceEvent(TRACE_DEBUG, "time_stamp_verify_and_update found a timestamp too old compared to previous.");
            return 0; // failure
        }
        // for not allowing to exploit the allowed TIME_STAMP_JITTER to "turn the clock backwards",
        // set the higher of the values
        *previous_stamp = (stamp > *previous_stamp ? stamp : *previous_stamp);
    }

    return 1; // success
}

/***
 *
 * For a given packet, find the apporopriate internal last valid time stamp for lookup
 * and verify it (and also update, if applicable).
 */
int find_peer_time_stamp_and_verify (
    struct peer_info *peers1,
    struct peer_info *peers2,
    struct peer_info *sn,
    const n2n_mac_t mac,
    uint64_t stamp,
    int allow_jitter) {

    uint64_t *previous_stamp = NULL;

    if(sn) {
        // from supernode
        previous_stamp = &(sn->last_valid_time_stamp);
    } else {
        // from (peer) edge
        struct peer_info *peer;
        HASH_FIND_PEER(peers1, mac, peer);
        if(!peer && peers2) {
            HASH_FIND_PEER(peers2, mac, peer);
        }

        if(peer) {
            // time_stamp_verify_and_update allows the pointer a previous
            // stamp to be NULL if it is a (so far) unknown peer
            previous_stamp = &(peer->last_valid_time_stamp);
        }
    }

    // failure --> 0;    success --> 1
    return time_stamp_verify_and_update(stamp, previous_stamp, allow_jitter);
}
