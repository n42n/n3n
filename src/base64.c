/*
 * Copyright (C) 2024 Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Base64 decoder
 *
 */

#include <stdlib.h>
#include <string.h>

static int letter2number (const char ch) {
    if(ch >= 'A' && ch <= 'Z') {
        return ch-'A';
    }
    if(ch >= 'a' && ch <= 'z') {
        return ch-'a'+26;
    }
    if(ch >= '0' && ch <= '9') {
        return ch-'0'+52;
    }
    if(ch == '+') {
        return 62;
    }
    if(ch == '/') {
        return 63;
    }
    return -1;
}

char *base64decode (const char *in) {
    int len = ((strlen(in) / 4) * 3) +1;
    char *out = malloc(len);
    if(!out) {
        return NULL;
    }

    char *p = out;
    while(len) {
        int i1 = letter2number(*in++);
        int i2 = letter2number(*in++);
        int i3 = letter2number(*in++);
        int i4 = letter2number(*in++);

        if(i1 == -1) return NULL;
        if(i2 == -1) return NULL;

        *p++ = (i1 << 2) | (i2 >> 4);
        len--;

        if(i3 == -1) break;

        *p++ = (i2 << 4) | (i3 >> 2);
        len--;

        if(i4 == -1) break;

        *p++ = (i3 << 6) | (i4);
        len--;
    }
    *p = 0;
    return out;
}
