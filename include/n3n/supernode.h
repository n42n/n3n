/**
 * Copyright (C) 2024 Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Public API for supernode
 */

// TODO: need to go through these definitions and sort them into public
// and private

#ifndef _N3N_SUPERNODE_H_
#define _N3N_SUPERNODE_H_

#include <n2n_typedefs.h>   // for n3n_runtime_data

int load_allowed_sn_community (struct n3n_runtime_data *sss);
void calculate_shared_secrets (struct n3n_runtime_data *sss);
void sn_init_conf_defaults (struct n3n_runtime_data *sss, char *sessionname);

int run_sn_loop (struct n3n_runtime_data *sss);
#endif

