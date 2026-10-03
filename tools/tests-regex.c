/*
 * SPDX-FileCopyrightText: Copyright Honey Bunny QT
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Unit tests of the regular expressions a supernode matches community
 * names with
 */

#include <stdio.h>             // for printf
#include <stdlib.h>            // for free
#include <string.h>            // for strlen
#include "n2n_typedefs.h"      // for re_t
#include "n2n_regex.h"         // for re_compile, re_matchp


// As the supernode does: only a match of the whole name counts
static int full_match (re_t re, const char *name) {
    int len;
    int at = re_matchp(re, name, &len);

    return (at == 0) && (len == (int)strlen(name));
}

static const struct {
    const char *name;
    int match[3];       // by each of the three rules
} cases[] = {
    { "net42",   { 1, 0, 0 } },
    { "net",     { 0, 0, 0 } },
    { "labxyz",  { 0, 1, 0 } },
    { "lab7",    { 0, 0, 0 } },
    { "home.de", { 0, 0, 1 } },
    { "home-de", { 0, 0, 0 } },
};

int main (int argc, char * argv[]) {
    // all compiled before any is used, as the supernode does: each keeps
    // its own character classes
    re_t rules[3] = {
        re_compile("net[0-9]+"),
        re_compile("lab[a-z]+"),
        re_compile("home\\.[^0-9]+"),
    };
    int failed = 0;

    for(int i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        for(int r = 0; r < 3; r++) {
            int m = full_match(rules[r], cases[i].name);
            if(m != cases[i].match[r]) {
                printf("regex: rule %i on '%s': %i, expected %i: FAIL\n",
                       r, cases[i].name, m, cases[i].match[r]);
                failed = 1;
            }
        }
    }
    printf("regex: %i names against 3 rules: %s\n",
           (int)(sizeof(cases) / sizeof(cases[0])), failed ? "FAIL" : "ok");

    for(int r = 0; r < 3; r++) {
        free(rules[r]);
    }
    return failed;
}
