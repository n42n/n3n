/**
 * Copyright (C) 2023-24 Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Public API for managing transformation algos
 */

#ifndef _N2N_TRANSFORM_H_
#define _N2N_TRANSFORM_H_

#include <stdbool.h>

struct n3n_transform {
    struct n3n_transform *next;
    const char *name;                 // The name of this config section
    const char *desc;                 // A short description for this section
    const int id;
    const bool is_compress;           // this transform is not an encryption
};

// Register a transform implementation
void n3n_transform_register (struct n3n_transform *);

// Return the only transform registered with this unique name
struct n3n_transform *n3n_transform_lookup_name (char *);

// Return the first registered transform with this id
struct n3n_transform *n3n_transform_lookup_id (int);

// Convenience helper to do a lookup and return a non null string
const char *n3n_transform_id2str (int);

// Return the only compression transform registered with this unique name
struct n3n_transform *n3n_compression_lookup_name (char *);

// Return the first registered compression transform with this id
struct n3n_transform *n3n_compression_lookup_id (int);

// Convenience helper to do a compression lookup and return a non null string
const char *n3n_compression_id2str (int);

#endif
