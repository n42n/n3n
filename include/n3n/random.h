/**
 * (C) 2007-22 - ntop.org and contributors
 * Copyright (C) 2024-25 Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not see see <http://www.gnu.org/licenses/>
 *
 */

#ifndef _N3N_RANDOM_H_
#define _N3N_RANDOM_H_


#include <stdint.h>   // for uint64_t, uint32_t

uint64_t n3n_rand (void);

// Only use when attempting to make a reproducible test case
void n3n_srand_stable_default (void);

uint32_t n3n_rand_sqr (uint32_t max_n);


struct n3n_rand_seeds_def {
    char *name;
    uint64_t (*seed)();
};

extern const struct n3n_rand_seeds_def n3n_rand_seeds[];
extern const int n3n_rand_seeds_size;

#endif // _N3N_RANDOM_H_
