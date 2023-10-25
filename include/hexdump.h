/*
 * Copyright (C) 2023 Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 */

#ifndef HEXDUMP_H
#define HEXDUMP_H

void fhexdump(unsigned int display_addr, void *in, int size, FILE *stream);

#endif
