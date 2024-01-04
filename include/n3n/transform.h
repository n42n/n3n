/**
 * Copyright (C) 2023 Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Public API for managing transformation algos
 */

#ifndef _N2N_TRANSFORM_H_
#define _N2N_TRANSFORM_H_

struct n3n_transform {
    struct n3n_transform *next;
    char *name;                 // The name of this config section
    char *desc;                 // A short description for this section
    int id;
};

// Register a transform implementation
void n3n_transform_register (struct n3n_transform *);

// Return the only transform registered with this unique name
struct n3n_transform *n3n_transform_lookup_name (char *);

// Return the first registered transform with this id
struct n3n_transform *n3n_transform_lookup_id (int);

// Convenience helper to do a lookup and return a non null string
char *n3n_transform_id2str (int id);

#endif
