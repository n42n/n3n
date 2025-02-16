/**
 * Copyright (C) Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Public API for ethernet helpers
 */

// TODO: determine if these are actually public

#ifndef _N3N_ETHERNET_H_
#define _N3N_ETHERNET_H_

#include <stdint.h> // for uint8_t

#define N2N_MAC_SIZE               6
#define N2N_MACSTR_SIZE 32

typedef uint8_t n2n_mac_t[N2N_MAC_SIZE];
typedef char macstr_t[N2N_MACSTR_SIZE];

uint8_t is_null_mac (const n2n_mac_t dest_mac);

char* macaddr_str (macstr_t buf, const n2n_mac_t mac);
int str2mac (uint8_t * outmac /* 6 bytes */, const char * s);

#endif


