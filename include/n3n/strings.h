/**
 * Copyright (C) Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Public API for stringification helpers
 */

// TODO: determine if these are actually public

#ifndef _N3N_STRINGS_H_
#define _N3N_STRINGS_H_

#include <n2n_typedefs.h>   // for dec_ip_bit_str_t, n2n_ip_subnet_t, n2n_...

char * ip_subnet_to_str (dec_ip_bit_str_t buf, const n2n_ip_subnet_t *ipaddr);

char* sock_to_cstr (n3n_sock_str_t out,
                    const n3n_sock_t * sock);

int parse_address_spec (n3n_parsed_address_t *out, const n3n_sock_str_t spec_in);

#endif

