/*
 * Copyright (C) Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 */

#ifndef HEXDUMP_H
#define HEXDUMP_H

#include <stdio.h>

void fhexdump(unsigned int display_addr, void *in, int size, FILE *stream);

#endif
