/**
 * (C) 2007-22 - ntop.org and contributors
 * Copyright (C) 2023 Hamish Coleman
 *
 */

#ifndef _PEER_INFO_H_
#define _PEER_INFO_H_

#include <n2n_typedefs.h>   // for n2n_mac_t, n2n_ip_subnet_t, n2n_desc_t, n2n_sock_t

struct peer_info {
    n2n_mac_t                        mac_addr;
    n2n_ip_subnet_t                  dev_addr;
    n2n_desc_t                       dev_desc;
    n2n_sock_t                       sock;
    SOCKET                           socket_fd;
    n2n_sock_t                       preferred_sock;
    n2n_cookie_t                     last_cookie;
    n2n_auth_t                       auth;
    int                              timeout;
    bool                             purgeable;
    time_t                           last_seen;
    time_t                           last_p2p;
    time_t                           last_sent_query;
    SN_SELECTION_CRITERION_DATA_TYPE selection_criterion;
    uint64_t                         last_valid_time_stamp;
    char                             *ip_addr;
    uint8_t                          local;
    time_t                           uptime;
    n2n_version_t                    version;

    UT_hash_handle     hh; /* makes this structure hashable */
};

typedef struct peer_info peer_info_t;

#endif
