/*
 * Tests for the connection/slots abstraction
 *
 * Copyright (C) Hamish Coleman
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "connslot.h"

// Tests are silent and return if everything is OK, or abort if issues
void connslot_tests() {
    slots_t *p = slots_malloc(5, 1000, 1000);
    assert(p);
    assert(p->nr_slots==5);
    assert(p->nr_open==0);
    assert(p->listen[0]==-1);
    assert(p->listen[1]==-1);
    assert(p->timeout==60);

    slots_free(p);
}

int main() {
    printf("Running conslot tests\n");

    // Many sizes are acceptable, so this is informational only
    printf("sizeof(conn_t) = %li\n", sizeof(conn_t));
    printf("sizeof(slots_t) = %li\n", sizeof(slots_t));

    connslot_tests();
}
