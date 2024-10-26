/**
 * Copyright (C) 2024 Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 */

#include <n3n/transform.h>   // for n3n_transform_register
#include <stdbool.h>

#include "n2n_define.h"      // for N2N_COMPRESSION_ID_NONE

// A dummy transform struct for the no-op compression
static struct n3n_transform transform = {
    .name = "none",
    .id = N2N_COMPRESSION_ID_NONE,
    .is_compress = true,
};

void n3n_initfuncs_transform_none () {
    n3n_transform_register(&transform);
}
