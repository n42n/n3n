/**
 * (C) 2007-22 - ntop.org and contributors
 * Copyright (C) 2023-25 Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not see see <http://www.gnu.org/licenses/>
 *
 */


#include <errno.h>           // for errno
#include <n3n/ethernet.h>    // for is_null_mac, N2N_MACSTR_SIZE
#include <n3n/logging.h>     // for traceEvent
#include <n3n/random.h>      // for n3n_rand
#include <n3n/strings.h>     // for ip_subnet_to_str, sock_to_cstr
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>          // for free, atoi, calloc, strtol
#include <string.h>          // for memcmp, memcpy, memset, strlen, strerror
#include <sys/time.h>        // for gettimeofday, timeval

#include "n2n.h"
#include "n2n_define.h"
#include "n2n_typedefs.h"

#ifdef _WIN32
#include "win32/defs.h"

#include <ws2def.h>
#else
#include <arpa/inet.h>       // for inet_ntop
#include <netinet/in.h>
#include <sys/socket.h>      // for AF_INET, PF_INET, bind, setsockopt, shut...
#endif


/* ************************************** */

SOCKET open_socket (struct sockaddr *local_address, socklen_t addrlen, int type /* 0 = UDP, TCP otherwise */) {

    SOCKET sock_fd;
    int sockopt;

    if((int)(sock_fd = socket(PF_INET, ((type == 0) ? SOCK_DGRAM : SOCK_STREAM), 0)) < 0) {
        traceEvent(TRACE_ERROR, "Unable to create socket [%s][%d]\n",
                   strerror(errno), sock_fd);
        return(-1);
    }

#ifndef _WIN32
    /* fcntl(sock_fd, F_SETFL, O_NONBLOCK); */
#endif

    int result;

    sockopt = 1;
    result = setsockopt(
        sock_fd,
        SOL_SOCKET,
        SO_REUSEADDR,
        (char *)&sockopt,
        sizeof(sockopt)
    );
    if(result == -1) {
        traceEvent(
            TRACE_ERROR,
            "SO_REUSEADDR fd=%i, error=%s\n",
            sock_fd,
            strerror(errno)
        );
    }
#ifdef SO_REUSEPORT /* no SO_REUSEPORT in Windows / old linux versions */
    result = setsockopt(
        sock_fd,
        SOL_SOCKET,
        SO_REUSEPORT,
        (char *)&sockopt,
        sizeof(sockopt)
    );
    if(result == -1) {
        traceEvent(
            TRACE_ERROR,
            "SO_REUSEPORT fd=%i, error=%s\n",
            sock_fd,
            strerror(errno)
        );
    }
#endif

    if(!local_address) {
        // skip binding if we dont have the right details
        return(sock_fd);
    }

    if(bind(sock_fd,local_address, addrlen) == -1) {
        traceEvent(TRACE_ERROR, "Bind error on local addr [%s]\n", strerror(errno));
        // TODO: use a generic sockaddr stringify to show which bind failed
        return(-1);
    }

    return(sock_fd);
}


/* *********************************************** */


/** Convert subnet prefix bit length to host order subnet mask. */
uint32_t bitlen2mask (uint8_t bitlen) {

    uint8_t i;
    uint32_t mask = 0;

    for(i = 1; i <= bitlen; ++i) {
        mask |= 1 << (32 - i);
    }

    return mask;
}


/* *********************************************** */

// TODO: move to a ethernet helper source file
char * macaddr_str (macstr_t buf,
                    const n2n_mac_t mac) {

    snprintf(buf, N2N_MACSTR_SIZE, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0] & 0xFF, mac[1] & 0xFF, mac[2] & 0xFF,
             mac[3] & 0xFF, mac[4] & 0xFF, mac[5] & 0xFF);

    return(buf);
}

/* ************************************************ */


/* http://www.faqs.org/rfcs/rfc908.html */
uint8_t is_multi_broadcast (const n2n_mac_t dest_mac) {

    int is_broadcast = (memcmp(broadcast_mac, dest_mac, N2N_MAC_SIZE) == 0);
    int is_multicast = (memcmp(multicast_mac, dest_mac, 3) == 0) && !(dest_mac[3] >> 7);
    int is_ipv6_multicast = (memcmp(ipv6_multicast_mac, dest_mac, 2) == 0);

    return is_broadcast || is_multicast || is_ipv6_multicast;
}


// TODO: move to a ethernet helper source file
uint8_t is_null_mac (const n2n_mac_t dest_mac) {

    int is_null_mac = (memcmp(null_mac, dest_mac, N2N_MAC_SIZE) == 0);

    return is_null_mac;
}


/* *********************************************** */

void print_n3n_version () {

    printf("n3n v%s, configured %s\n"
           "Copyright 2007-2022 - ntop.org and contributors\n"
           "Copyright (C) 2023-25 Hamish Coleman\n\n",
           VERSION, BUILDDATE);
}

/* *********************************************** */

// TODO: move to a strings helper source file
static uint8_t hex2byte (const char * s) {

    char tmp[3];
    tmp[0] = s[0];
    tmp[1] = s[1];
    tmp[2] = 0; /* NULL term */

    return((uint8_t)strtol(tmp, NULL, 16));
}

// TODO: move to a ethernet/strings helper source file
extern int str2mac (uint8_t * outmac /* 6 bytes */, const char * s) {

    size_t i;

    /* break it down as one case for the first "HH", the 5 x through loop for
     * each ":HH" where HH is a two hex nibbles in ASCII. */

    *outmac = hex2byte(s);
    ++outmac;
    s += 2; /* don't skip colon yet - helps generalise loop. */

    for(i = 1; i < 6; ++i) {
        s += 1;
        *outmac = hex2byte(s);
        ++outmac;
        s += 2;
    }

    return 0; /* ok */
}

// TODO: move to a strings helper source file
extern char * sock_to_cstr (n2n_sock_str_t out,
                            const n2n_sock_t * sock) {


    if(NULL == out) {
        return NULL;
    }
    memset(out, 0, N2N_SOCKBUF_SIZE);

    bool is_tcp = (sock->type == SOCK_STREAM);

    if(AF_INET6 == sock->family) {
        char tmp[INET6_ADDRSTRLEN+1];

        tmp[0] = '\0';
        inet_ntop(AF_INET6, sock->addr.v6, tmp, sizeof(n2n_sock_str_t));
        snprintf(
            out,
            N2N_SOCKBUF_SIZE,
            "%s[%s]:%hu",
            is_tcp ? "TCP/" : "",
            tmp[0] ? tmp : "",
            sock->port
        );
        return out;
    }

    const uint8_t * a = sock->addr.v4;

    snprintf(out, N2N_SOCKBUF_SIZE, "%s%hu.%hu.%hu.%hu:%hu",
             is_tcp ? "TCP/" : "",
             (unsigned short)(a[0] & 0xff),
             (unsigned short)(a[1] & 0xff),
             (unsigned short)(a[2] & 0xff),
             (unsigned short)(a[3] & 0xff),
             (unsigned short)sock->port);
    return out;
}

// TODO: move to a strings helper source file
char *ip_subnet_to_str (dec_ip_bit_str_t buf, const n2n_ip_subnet_t *ipaddr) {

    snprintf(buf, sizeof(dec_ip_bit_str_t), "%u.%u.%u.%u/%u",
             (uint8_t) ((ipaddr->net_addr >> 24) & 0xFF),
             (uint8_t) ((ipaddr->net_addr >> 16) & 0xFF),
             (uint8_t) ((ipaddr->net_addr >> 8) & 0xFF),
             (uint8_t) (ipaddr->net_addr & 0xFF),
             ipaddr->net_bitlen);

    return buf;
}


/* @return 1 if the two sockets are equivalent. */
int sock_equal (const n2n_sock_t * a,
                const n2n_sock_t * b) {

    if(a->port != b->port) {
        return(0);
    }

    if(a->family != b->family) {
        return(0);
    }

    switch(a->family) {
        case AF_INET:
            if(memcmp(a->addr.v4, b->addr.v4, IPV4_SIZE)) {
                return(0);
            }
            break;

        default:
            if(memcmp(a->addr.v6, b->addr.v6, IPV6_SIZE)) {
                return(0);
            }
            break;
    }

    /* equal */
    return(1);
}


/* *********************************************** */

// exclusive-ors a specified memory area with another
int memxor (uint8_t *destination, const uint8_t *source, size_t len) {

    for(; len >= 4; len -= 4) {
        *(uint32_t*)destination ^= *(uint32_t*)source;
        source += 4;
        destination += 4;
    }

    for(; len > 0; len--) {
        *destination ^= *source;
        source++;
        destination++;
    }

    return 0;
}

/* *********************************************** */

// stores the previously issued time stamp
static uint64_t previously_issued_time_stamp = 0;


// returns a time stamp for use with replay protection (branchless code)
//
// depending on the self-detected accuracy, it has the following format
//
// MMMMMMMMCCCCCCCF or
//
// MMMMMMMMSSSSSCCF
//
// with M being the 32-bit second time stamp
//      S       the 20-bit sub-second (microsecond) time stamp part, if applicable
//      C       a counter (8 bit or 24 bit) reset to 0 with every MMMMMMMM(SSSSS) turn-over
//      F       a 4-bit flag field with
//      ...c    being the accuracy indicator (if set, only counter and no sub-second accuracy)
//
uint64_t time_stamp (void) {

    struct timeval tod;
    uint64_t micro_seconds;
    uint64_t co, mask_lo, mask_hi, hi_unchanged, counter, new_co;

    gettimeofday(&tod, NULL);

    // (roughly) calculate the microseconds since 1970, leftbound
    micro_seconds = ((uint64_t)(tod.tv_sec) << 32) + ((uint64_t)tod.tv_usec << 12);
    // more exact but more costly due to the multiplication:
    // micro_seconds = ((uint64_t)(tod.tv_sec) * 1000000ULL + tod.tv_usec) << 12;

    // extract "counter only" flag (lowest bit)
    co = (previously_issued_time_stamp << 63) >> 63;
    // set mask accordingly
    mask_lo   = -co;
    mask_lo >>= 32;
    // either 0x00000000FFFFFFFF (if co flag set) or 0x0000000000000000 (if co flag not set)

    mask_lo  |= (~mask_lo) >> 52;
    // either 0x00000000FFFFFFFF (unchanged)      or 0x0000000000000FFF (lowest 12 bit set)

    mask_hi   = ~mask_lo;

    hi_unchanged = ((previously_issued_time_stamp & mask_hi) == (micro_seconds & mask_hi));
    // 0 if upper bits unchanged (compared to previous stamp), 1 otherwise

    // read counter and shift right for flags
    counter   = (previously_issued_time_stamp & mask_lo) >> 4;

    counter  += hi_unchanged;
    counter  &= -hi_unchanged;
    // either counter++ if upper part of timestamp unchanged, 0 otherwise

    // back to time stamp format
    counter <<= 4;

    // set new co flag if counter overflows while upper bits unchanged or if it was set before
    new_co   = (((counter & mask_lo) == 0) & hi_unchanged) | co;

    // in case co flag changed, masks need to be recalculated
    mask_lo   = -new_co;
    mask_lo >>= 32;
    mask_lo  |= (~mask_lo) >> 52;
    mask_hi   = ~mask_lo;

    // assemble new timestamp
    micro_seconds &= mask_hi;
    micro_seconds |= counter;
    micro_seconds |= new_co;

    previously_issued_time_stamp = micro_seconds;

    return micro_seconds;
}
