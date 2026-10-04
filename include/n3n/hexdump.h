/*
 * SPDX-FileCopyrightText: Copyright Hamish Coleman
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef HEXDUMP_H
#define HEXDUMP_H

#include <stdint.h>
#include <stdio.h>


void fhexdump (uint64_t display_addr, const void *in, int size, FILE *stream);

#endif
