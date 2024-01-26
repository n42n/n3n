/**
 * (C) 2007-22 - ntop.org and contributors
 * Copyright (C) 2023-24 Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Public API for edge
 */

#ifndef _N3N_EDGEG_H_
#define _N3N_EDGEG_H_

// Allow public pointers to reference the private structure
typedef struct n2n_edge_conf n2n_edge_conf_t;

/* Edge conf */
int edge_conf_add_supernode (n2n_edge_conf_t *conf, const char *ip_and_port);
int edge_verify_conf (const n2n_edge_conf_t *conf);
void edge_init_conf_defaults (n2n_edge_conf_t *conf);
void edge_term_conf (n2n_edge_conf_t *conf);

#endif
