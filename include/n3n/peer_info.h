/**
 * Copyright (C) 2024 Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Public API for peer_info
 */

// TODO: refactor to remove public users

#ifndef _N3N_PEER_INFO_H_
#define _N3N_PEER_INFO_H_

#include <stdint.h>         // for uint8_t, uint16_t
#include <time.h>           // for time_t
#include <n2n_typedefs.h>   // for n3n_runtime_data, n2n_mac_t, SOCKET

// Allow public pointers to reference the private structure
typedef struct peer_info peer_info_t;

int n3n_peer_add_by_hostname (peer_info_t **list, const char *ip_and_port);

#endif

