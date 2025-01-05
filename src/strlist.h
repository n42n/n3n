/**
 * Copyright (C) Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 */

#ifndef _STRLIST_H
#define _STRLIST_H

#include <n3n/strlist.h>
#include "uthash.h"

struct n3n_strlist {
    UT_hash_handle hh;
    int id;
    // 4 bytes hole, could add flags here
    char *s;
};

#endif
