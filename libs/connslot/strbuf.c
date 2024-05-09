/** @file
 * A memory buffer abstraction that stores counted bytestrings and allows
 * automatic resizing.
 *
 * Copyright (C) Hamish Coleman
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <sys/socket.h>
#endif

#include "strbuf.h"

#ifdef METRICS
struct strbuf_metrics strbuf_metrics;
#endif


/**
 * Reset the strbuf to show as empty, without changing any allocations
 * @param p is the buffer to initialise
 */
void sb_zero(strbuf_t *p) {
    STRBUF_METRIC(zero);
    p->wr_pos = 0;
    p->rd_pos = 0;
    p->overflowed = false;
    p->str[0] = 0;
}

/**
 * Allocate a new buffer with the given capacity.
 * Note that the total memory allocated will be slightly larger to allow room
 * for the structure header.
 * @param size is the storage capacity to allocate
 * @return the allocated buffer or NULL
 */
strbuf_t *sb_malloc(size_t size, size_t size_max) {
    STRBUF_METRIC(alloc);
    size_t headersize = sizeof(strbuf_t);
    strbuf_t *p = malloc(headersize+size);
    if (p) {
        p->capacity = size;
        p->capacity_max = size_max;
        sb_zero(p);
    }
    return p;
}

/**
 * Re-allocate an existing buffer.
 * This will not allow a buffer larger than capacity_max.
 * If the buffer is shrinking, a null terminator byte is placed at the end
 * of the buffer.
 * @param pp is the reference to the buffer pointer.
 *      This might be updated during the reallocation.
 * @param size is the storage capacity to allocate
 * @return the allocated buffer or NULL
 */
strbuf_t *sb_realloc(strbuf_t **pp, size_t size) {
    STRBUF_METRIC(realloc);
    size_t headersize = sizeof(strbuf_t);
    strbuf_t *p = *pp;
    if (size > p->capacity_max) {
        STRBUF_METRIC(realloc_full);
        p->overflowed = true;
        size = p->capacity_max;
    }

    strbuf_t *newp = realloc(p, headersize + size);
    if (!newp) {
        return NULL;
    }
    p = newp;

    p->capacity = size;
    if (p->wr_pos >= p->capacity) {
        // We truncated
        p->wr_pos = p->capacity-1;
        p->str[p->wr_pos] = 0;
    }

    // update the original pointer
    *pp = p;
    return p;
}

/**
 * Get the length of the stored data
 * @param p is the strbuf to query
 * @return the size of the stored data
 */
size_t sb_len(strbuf_t *p) {
    return p->wr_pos;
}

/**
 * Get the length of the available space in the buffer
 * @param p is the strbuf to query
 * @return the number of bytes available before the strbuf would need to be
 * resized.  This will be zero if an overflow has happened.  This could be
 * a negative number if an unchecked overflow has happened.
 */
ssize_t sb_avail(strbuf_t *p) {
    return p->capacity - p->wr_pos;
}

/**
 * Check if the buffer has reached its capacity.
 * Mostly used when an overflow is unexpected and thus one check can be done
 * at the end of a series of sb_append/sb_reprintf or similar
 * statements.
 * @param p is the strbuf to query
 * @return a boolean result
 */
bool sb_full(strbuf_t *p) {
    return sb_avail(p) == 0;
}

/**
 * Check if the buffer looks like it has overflowed.
 */
bool sb_overflowed(strbuf_t *p) {
    return p->overflowed;
}

/**
 * Appends (by copying) the given buffer to the strbuf.
 * If the strbuf is not large enough to store the new buffer then as much as
 * will fit is copied (this will result in setting the sb_full() condition)
 * @param p is the strbuf
 * @param buf is the new data to copy
 * @param bufsize is the length of the new data to copy
 * @return the total length of the stored data
 */
size_t sb_append(strbuf_t *p, void *buf, ssize_t bufsize) {
    ssize_t avail = sb_avail(p);
    if (avail <= 0) {
        // Cannot append to a full buffer
        STRBUF_METRIC(append_full);
        return -1;
    }

    if (avail < bufsize) {
        // Truncate the new data to fit
        STRBUF_METRIC(append_trunc);
        p->overflowed = true;
        bufsize = avail;
    }

    memcpy(&p->str[p->wr_pos], buf, bufsize);
    p->wr_pos += bufsize;
    return p->wr_pos;
}

/**
 * Appends (by copying) the given buffer to the strbuf, expanding if needed.
 * If the strbuf is not currently large enough to store the new buffer then
 * the sb_realloc() function is called to expand it.
 * If the strbuf is still not large enough even after realloc (either because
 * the max_capacity has been reached or because there was a malloc failure)
 * then all the data that will fit is copied (this will result in setting the
 * sb_full() condition)
 * @param pp is a pointer to strbuf pointer.  This may be updated if there is
 * a sb_realloc() call.
 * @param buf is the new data to copy
 * @param bufsize is the length of the new data to copy
 * @return the total length of the stored data
 */
strbuf_t *sb_reappend(strbuf_t **pp, void *buf, size_t bufsize) {
    strbuf_t *p = *pp;
    size_t needed = p->wr_pos + bufsize;
    if (needed > p->capacity) {
        strbuf_t *newp = sb_realloc(pp, needed);
        if (!newp) {
            return NULL;
        }
        p = newp;
        // update the original pointer
        *pp = p;
    }
    sb_append(p, buf, bufsize);
    return p;
}

size_t sb_vprintf(strbuf_t *p, const char *format, va_list ap) {
    size_t avail = sb_avail(p);

    size_t size = vsnprintf(&p->str[p->wr_pos], avail, format, ap);

    if (size < avail) {
        // The new data fit in the buffer
        p->wr_pos += size;

        return sb_len(p);
    }

    // Return the size the buffer would need to be
    return p->wr_pos + size;
}

/**
 * Using printf formatting, append the string to the strbuf
 * @return the number of bytes appended, or - if the strbuf is full - the
 * number of bytes that would have been appended if space was available
 */
size_t sb_printf(strbuf_t *p, const char *format, ...) {
    va_list ap;
    size_t r;

    va_start(ap, format);
    r =  sb_vprintf(p, format, ap);
    va_end(ap);
    return r;
}

/**
 * Using printf formatting, append the string to the strbuf.  If needed, will
 * call sb_realloc() to expand the strbuf allocation.
 * @return the number of bytes appended, or - if the strbuf is full - the
 * number of bytes that would have been appended if space was available.
 * Will also return -1 if errors are detected.
 */
size_t sb_reprintf(strbuf_t **pp, const char *format, ...) {
    va_list ap;
    size_t size;

    if (!*pp) {
        return -1;
    }

    int loop = 0;
    while(1) {

        va_start(ap, format);
        size = sb_vprintf(*pp, format, ap);
        va_end(ap);

        if (size < (*pp)->capacity) {
            // The new data fit in the buffer
            return sb_len(*pp);
        }

        if (loop) {
            // Something went wrong, we already passed through the realloc
            // and still dont have enough buffer space for the printf
            return -1;
        }

        strbuf_t *r = sb_realloc(pp, size + 1);
        if (!r) {
            return -1;
        }
        loop = 1;
    }
}

/**
 * Read from the file descriptor into the strbuf.  Will attempt to read as
 * many bytes as are available in the strbuf.
 * @param fd is the file descriptor to read from
 * @return the number of bytes read or -1 for error
 */
ssize_t sb_read(int fd, strbuf_t *p) {
    ssize_t size;
    ssize_t avail = sb_avail(p);

    size = recv(fd, &p->str[p->wr_pos], avail, 0);

    if (size != -1) {
        p->wr_pos += size;
    }
    return size;
}

/**
 * Write size bytes from the strbuf into a file descriptor.
 * @param fd is the file descriptor to write to
 * @index is the offset within the strbuf to start writing from
 * @size is the number of bytes to write, or -1 to write the remainder of the
 * strbuf
 * @return the number of bytes written or -1 for error
 */
ssize_t sb_write(int fd, strbuf_t *p, int index, ssize_t size) {
    if (size == -1) {
        size = p->wr_pos - index;
    }

    // TODO?
    // if index > wr_pos, error
    // if index + size > wr_pos, error

    return send(fd, &p->str[index], size, 0);
}

void sb_dump(strbuf_t *p) {
    if (!p) {
        printf("NULL\n");
        return;
    }
    printf("%p(%u) (%u) = '%s' ", p, p->capacity, p->wr_pos, p->str);
    for (int i=0; i<16; i++) {
        printf("%02x ",p->str[i]);
    }
    printf("\n");
}
