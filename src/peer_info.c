/**
 * (C) 2007-23 - ntop.org and contributors
 * Copyright (C) 2023 Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 */

#include <n2n.h>        // for time_stamp
#include <n2n_define.h> // for TIME_STAMP_FRAME
#include <n3n/logging.h> // for traceEvent
#include <n3n/metrics.h> // for traceEvent
#include <stdbool.h>
#include "management.h" // for mgmt_event_post
#include "peer_info.h"

static struct metrics {
    uint32_t init;
    uint32_t alloc;
    uint32_t free;
} metrics;

static struct n3n_metrics_item metrics_items[] = {
    {
        .name = "alloc",
        .desc = "peer_info_malloc() is called",
        .offset = offsetof(struct metrics, alloc),
        .size = n3n_metrics_uint32,
    },
    {
        .name = "free",
        .desc = "peer_info_free() is called",
        .offset = offsetof(struct metrics, free),
        .size = n3n_metrics_uint32,
    },
    {
        .name = "init",
        .desc = "peer_info_init() is called",
        .offset = offsetof(struct metrics, init),
        .size = n3n_metrics_uint32,
    },
    { },
};

static struct n3n_metrics_module metrics_module = {
    .name = "peer_info",
    .data = &metrics,
    .item = metrics_items,
    .enabled = true,
};

void n3n_initfuncs_peer_info() {
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

    peer_info_init(peer, mac);

    return peer;
}

void peer_info_free(struct peer_info *p) {
    metrics.free++;
    free(p);
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

    HASH_ITER(hh, *peer_list, scan, tmp) {
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
        if(!scan->purgeable && scan->ip_addr) {
            free(scan->ip_addr);
        }
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

struct peer_info* find_peer_by_sock (const n2n_sock_t *sock, struct peer_info *peer_list) {

    struct peer_info *scan, *tmp, *ret = NULL;

    HASH_ITER(hh, peer_list, scan, tmp) {
        if(memcmp(&(scan->sock), sock, sizeof(n2n_sock_t)) == 0) {
            ret = scan;
            break;
        }
    }

    return ret;
}
