/**
 * (C) 2007-22 - ntop.org and contributors
 * Copyright (C) 2023-25 Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Public API for edge
 */

// TODO: refactor into public and private definitions

#ifndef _N3N_EDGE_H_
#define _N3N_EDGE_H_

#include <stdint.h>         // for uint8_t, uint16_t
#include <time.h>           // for time_t
#include <n2n_typedefs.h>   // for n3n_runtime_data, n2n_mac_t, SOCKET

// Allow public pointers to reference the private structure
typedef struct n2n_edge_conf n2n_edge_conf_t;


/* Edge conf */
int edge_verify_conf (const n2n_edge_conf_t *conf);
void edge_init_conf_defaults (n2n_edge_conf_t *conf, char *sessionname);
void edge_term_conf (n2n_edge_conf_t *conf);


void send_register_super (struct n3n_runtime_data *eee);
void send_query_peer (struct n3n_runtime_data *eee, const n2n_mac_t dst_mac);
int supernode_connect (struct n3n_runtime_data *eee);

#endif
