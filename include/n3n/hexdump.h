/*
 * Copyright (C) Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 */

#ifndef HEXDUMP_H
#define HEXDUMP_H

#include <stdint.h>
#include <stdio.h>


void fhexdump (uint64_t display_addr, const void *in, int size, FILE *stream);

#endif
