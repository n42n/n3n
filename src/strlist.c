/**
 * Copyright (C) Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 */

#include <n3n/strlist.h>
#include <stdlib.h>
#include <string.h>

#include "strlist.h"
#include "uthash.h"

int n3n_strlist_add (struct n3n_strlist **list, const char *s) {
    struct n3n_strlist *new = NULL;

    // Start guessing ID with the minimum number that might be unused
    int new_id = HASH_COUNT(*list);
    while(1) {
        HASH_FIND_INT(*list, &new_id, new);
        if(!new) {
            // Found an unused number
            break;
        }
        new_id++;
        // TODO:
        // - keep statistics on how inefficient this loop is
    }

    new = malloc(sizeof(*new));
    if(!new) {
        abort();
    }
    new->id = new_id;
    new->s = strdup(s);

    HASH_ADD_INT(*list, id, new);
    return new_id;
}
