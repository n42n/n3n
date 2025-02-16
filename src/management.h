/*
 * Copyright (C) Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Internal interface definitions for the management interfaces
 *
 * This header is not part of the public library API and is thus not in
 * the public include folder
 */

#ifndef MANAGEMENT_H
#define MANAGEMENT_H 1

#include <connslot/connslot.h>  // for conn_t
#include <connslot/strbuf.h>    // for strbuf_t
#include <n2n_typedefs.h>  // For the n3n_runtime_data
#include <stdbool.h>
#include <stddef.h>        // for size_t
#include <stdint.h>        // for uint64_t
#include <sys/types.h>     // for ssize_t

#include "n2n_define.h"    // for n2n_event_topic

struct n3n_runtime_data;

#ifdef _WIN32
#include <winsock2.h>
#else
#include <sys/socket.h>    // for sockaddr, sockaddr_storage, socklen_t
#endif

void mgmt_event_post (const enum n3n_event_topic topic, const int data0, const void *data1);
void mgmt_api_handler (struct n3n_runtime_data *, conn_t *);
#endif
