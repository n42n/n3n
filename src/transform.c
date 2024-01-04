/*
 * Copyright (C) 2023 Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 *
 */

#include <n3n/transform.h>
#include <stddef.h>
#include <string.h>

static struct n3n_transform *registered_transforms = NULL;

void n3n_transform_register (struct n3n_transform *transform) {
    if(!transform) {
        return;
    }

    // TODO: should confirm that we register each name only once

    transform->next = registered_transforms;
    registered_transforms = transform;
}

struct n3n_transform *n3n_transform_lookup_name (char *name) {
    struct n3n_transform *p = registered_transforms;
    while(p) {
        if(0==strcmp(p->name, name)) {
            return p;
        }
        p = p->next;
    }
    return NULL;
}

struct n3n_transform *n3n_transform_lookup_id (int id) {
    struct n3n_transform *p = registered_transforms;
    while(p) {
        if(p->id == id) {
            return p;
        }
        p = p->next;
    }
    return NULL;
}

char *n3n_transform_id2str (int id) {
    struct n3n_transform *p = n3n_transform_lookup_id(id);
    if(!p) {
        return "(null)";
    }
    return p->name;
}

// prototype any internal (non-public) initfuncs
void n3n_initfuncs_transform_aes ();
void n3n_initfuncs_transform_cc20 ();
void n3n_initfuncs_transform_null ();
void n3n_initfuncs_transform_speck ();
void n3n_initfuncs_transform_twofish ();

void n3n_initfuncs_transform () {
    n3n_initfuncs_transform_aes();
    n3n_initfuncs_transform_cc20();
    n3n_initfuncs_transform_null();
    n3n_initfuncs_transform_speck();
    n3n_initfuncs_transform_twofish();
}
