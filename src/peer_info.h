/**
 * (C) 2007-22 - ntop.org and contributors
 * Copyright (C) 2023 Hamish Coleman
 *
 * non public structure and function definitions
 */

#ifndef _PEER_INFO_H_
#define _PEER_INFO_H_

#include <n2n_typedefs.h>   // for n2n_mac_t, n2n_ip_subnet_t, n2n_desc_t, n2n_sock_t

struct peer_info {
    n2n_mac_t mac_addr;
    bool purgeable;
    uint8_t local;
    n2n_ip_subnet_t dev_addr;
    n2n_desc_t dev_desc;
    n2n_sock_t sock;
    SOCKET socket_fd;
    n2n_sock_t preferred_sock;
    n2n_cookie_t last_cookie;
    n2n_auth_t auth;
    int timeout;
    time_t last_seen;
    time_t last_p2p;
    time_t last_sent_query;
    SN_SELECTION_CRITERION_DATA_TYPE selection_criterion;
    uint64_t last_valid_time_stamp;
    char                             *ip_addr;
    time_t uptime;
    n2n_version_t version;

    UT_hash_handle hh;     /* makes this structure hashable */
};

typedef struct peer_info peer_info_t;

void peer_info_init (struct peer_info *, const n2n_mac_t mac);
struct peer_info* peer_info_malloc (const n2n_mac_t mac);
void peer_info_free (struct peer_info *);

/* Operations on peer_info lists. */
size_t purge_peer_list (struct peer_info ** peer_list,
                        SOCKET socket_not_to_close,
                        n2n_tcp_connection_t **tcp_connections,
                        time_t purge_before);

size_t clear_peer_list (struct peer_info ** peer_list);

size_t purge_expired_nodes (struct peer_info **peer_list,
                            SOCKET socket_not_to_close,
                            n2n_tcp_connection_t **tcp_connections,
                            time_t *p_last_purge,
                            int frequency, int timeout);

int find_and_remove_peer (struct peer_info **, const n2n_mac_t);
struct peer_info* find_peer_by_sock (const n2n_sock_t *, struct peer_info *);

#endif
