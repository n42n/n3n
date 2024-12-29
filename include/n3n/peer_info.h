/**
 * Copyright (C) 2024 Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Public API for peer_info
 */

// TODO: refactor to remove public users

#ifndef _N3N_PEER_INFO_H_
#define _N3N_PEER_INFO_H_

#include <n3n/strlist.h>

// Allow public pointers to reference the private structure
typedef struct peer_info peer_info_t;

int n3n_peer_add_strlist (struct peer_info **peers, struct n3n_strlist **list);

#endif

