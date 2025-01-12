/**
 * Copyright (C) Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 */

#ifndef _EDGE_UTILS_H_
#define _EDGE_UTILS_H_

#include "pktbuf.h"     // for n3n_pktbuf

void edge_read_from_tap (struct n3n_runtime_data *eee);

void edge_read_proto3_udp (struct n3n_runtime_data *eee,
                           SOCKET sock,
                           struct n3n_pktbuf *pktbuf,
                           time_t now);
void edge_read_proto3_tcp (struct n3n_runtime_data *eee,
                           SOCKET sock,
                           uint8_t *pktbuf,
                           ssize_t pktbuf_len,
                           time_t now);

#endif
