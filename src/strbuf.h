/*
 * Copyright (C) 2023 Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Internal interface definitions for the strbuf abstrction
 *
 * This header is not part of the public library API and is thus not in
 * the public include folder
 */

#ifndef OLD_STRBUF_H
#define OLD_STRBUF_H 1

typedef struct old_strbuf {
    size_t size;
    char str[];
} old_strbuf_t;

// Initialise the strbuf pointer buf to point at the storage area p
// of size buflen
#define OLD_STRBUF_INIT(buf,p,buflen) do { \
        buf = (void *)p; \
        buf->size = buflen - sizeof(size_t); \
} while(0)


#endif
