/**
 * (C) 2007-22 - ntop.org and contributors
 * Copyright (C) 2023-24 Hamish Coleman
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
#include <stdbool.h>
#include <stdlib.h>          // for free, atoi, calloc, strtol
#include <string.h>          // for memcmp, memcpy, memset, strlen, strerror
#include <sys/time.h>        // for gettimeofday, timeval
#include <time.h>            // for time, localtime, strftime
#include "n2n.h"
#include "sn_selection.h"    // for sn_selection_criterion_default
#include "uthash.h"          // for UT_hash_handle, HASH_DEL, HASH_ITER, HAS...

#ifdef _WIN32
#include "win32/defs.h"
#include <ws2def.h>
#else
#include <arpa/inet.h>       // for inet_ntop
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

    sockopt = 1;
    setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&sockopt, sizeof(sockopt));

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


/* stringify in_addr type to ipstr_t */
char* inaddrtoa (ipstr_t out, struct in_addr addr) {

    if(!inet_ntop(AF_INET, &addr, out, sizeof(ipstr_t)))
        out[0] = '\0';

    return out;
}


/* addr should be in network order. Things are so much simpler that way. */
char* intoa (uint32_t /* host order */ addr, char* buf, uint16_t buf_len) {

    char *cp, *retStr;
    uint8_t byteval;
    int n;

    cp = &buf[buf_len];
    *--cp = '\0';

    n = 4;
    do {
        byteval = addr & 0xff;
        *--cp = byteval % 10 + '0';
        byteval /= 10;
        if(byteval > 0) {
            *--cp = byteval % 10 + '0';
            byteval /= 10;
            if(byteval > 0) {
                *--cp = byteval + '0';
            }
        }
        *--cp = '.';
        addr >>= 8;
    } while(--n > 0);

    /* Convert the string to lowercase */
    retStr = (char*)(cp + 1);

    return(retStr);
}


/** Convert subnet prefix bit length to host order subnet mask. */
uint32_t bitlen2mask (uint8_t bitlen) {

    uint8_t i;
    uint32_t mask = 0;

    for(i = 1; i <= bitlen; ++i) {
        mask |= 1 << (32 - i);
    }

    return mask;
}


/** Convert host order subnet mask to subnet prefix bit length. */
uint8_t mask2bitlen (uint32_t mask) {

    uint8_t i, bitlen = 0;

    for(i = 0; i < 32; ++i) {
        if((mask << i) & 0x80000000) {
            ++bitlen;
        } else {
            break;
        }
    }

    return bitlen;
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

/* *********************************************** */

struct peer_info* add_sn_to_list_by_mac_or_sock (struct peer_info **sn_list, n2n_sock_t *sock, const n2n_mac_t mac, int *skip_add) {

    struct peer_info *scan, *tmp, *peer = NULL;

    if(!is_null_mac(mac)) { /* not zero MAC */
        HASH_FIND_PEER(*sn_list, mac, peer);
    }

    if(peer) {
        return peer;
    }

    /* zero MAC, search by socket */
    HASH_ITER(hh, *sn_list, scan, tmp) {
        if(memcmp(&(scan->sock), sock, sizeof(n2n_sock_t)) != 0) {
            continue;
        }

        // update mac if appropriate
        // (needs to be deleted first because it is key to the hash list)
        if(!is_null_mac(mac)) {
            HASH_DEL(*sn_list, scan);
            memcpy(scan->mac_addr, mac, sizeof(n2n_mac_t));
            HASH_ADD_PEER(*sn_list, scan);
        }

        peer = scan;
        break;
    }

    if(peer) {
        return peer;
    }

    if(*skip_add != SN_ADD) {
        return peer;
    }

    peer = peer_info_malloc(mac);
    if(!peer) {
        return peer;
    }

    sn_selection_criterion_default(&(peer->selection_criterion));
    memcpy(&(peer->sock), sock, sizeof(n2n_sock_t));
    HASH_ADD_PEER(*sn_list, peer);
    *skip_add = SN_ADD_ADDED;

    return peer;
}

/* ************************************************ */


/* http://www.faqs.org/rfcs/rfc908.html */
uint8_t is_multi_broadcast (const n2n_mac_t dest_mac) {

    int is_broadcast = (memcmp(broadcast_mac, dest_mac, N2N_MAC_SIZE) == 0);
    int is_multicast = (memcmp(multicast_mac, dest_mac, 3) == 0) && !(dest_mac[3] >> 7);
    int is_ipv6_multicast = (memcmp(ipv6_multicast_mac, dest_mac, 2) == 0);

    return is_broadcast || is_multicast || is_ipv6_multicast;
}


uint8_t is_broadcast (const n2n_mac_t dest_mac) {

    int is_broadcast = (memcmp(broadcast_mac, dest_mac, N2N_MAC_SIZE) == 0);

    return is_broadcast;
}


// TODO: move to a ethernet helper source file
uint8_t is_null_mac (const n2n_mac_t dest_mac) {

    int is_null_mac = (memcmp(null_mac, dest_mac, N2N_MAC_SIZE) == 0);

    return is_null_mac;
}


/* *********************************************** */

char* msg_type2str (uint16_t msg_type) {

    switch(msg_type) {
        case MSG_TYPE_REGISTER: return("MSG_TYPE_REGISTER");
        case MSG_TYPE_DEREGISTER: return("MSG_TYPE_DEREGISTER");
        case MSG_TYPE_PACKET: return("MSG_TYPE_PACKET");
        case MSG_TYPE_REGISTER_ACK: return("MSG_TYPE_REGISTER_ACK");
        case MSG_TYPE_REGISTER_SUPER: return("MSG_TYPE_REGISTER_SUPER");
        case MSG_TYPE_REGISTER_SUPER_ACK: return("MSG_TYPE_REGISTER_SUPER_ACK");
        case MSG_TYPE_REGISTER_SUPER_NAK: return("MSG_TYPE_REGISTER_SUPER_NAK");
        case MSG_TYPE_FEDERATION: return("MSG_TYPE_FEDERATION");
        default: return("???");
    }

    return("???");
}

/* *********************************************** */

void print_n3n_version () {

    printf("n3n v%s, configured %s\n"
           "Copyright 2007-2022 - ntop.org and contributors\n"
           "Copyright (C) 2023-24 Hamish Coleman\n\n",
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

    if(AF_INET6 == sock->family) {
        char tmp[INET6_ADDRSTRLEN+1];

        tmp[0] = '\0';
        inet_ntop(AF_INET6, sock->addr.v6, tmp, sizeof(n2n_sock_str_t));
        snprintf(out, N2N_SOCKBUF_SIZE, "[%s]:%hu", tmp[0] ? tmp : "", ntohs(sock->port));
        return out;
    } else {
        const uint8_t * a = sock->addr.v4;

        snprintf(out, N2N_SOCKBUF_SIZE, "%hu.%hu.%hu.%hu:%hu",
                 (unsigned short)(a[0] & 0xff),
                 (unsigned short)(a[1] & 0xff),
                 (unsigned short)(a[2] & 0xff),
                 (unsigned short)(a[3] & 0xff),
                 (unsigned short)ntohs(sock->port));
        return out;
    }
}

// TODO: move to a strings helper source file
char *ip_subnet_to_str (dec_ip_bit_str_t buf, const n2n_ip_subnet_t *ipaddr) {

    snprintf(buf, sizeof(dec_ip_bit_str_t), "%hhu.%hhu.%hhu.%hhu/%hhu",
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

// fills a specified memory area with random numbers
int memrnd (uint8_t *address, size_t len) {

    for(; len >= 4; len -= 4) {
        *(uint32_t*)address = n3n_rand();
        address += 4;
    }

    for(; len > 0; len--) {
        *address = n3n_rand();
        address++;
    }

    return 0;
}


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

#ifdef _WIN32
int gettimeofday (struct timeval *tp, void *tzp) {

    time_t clock;
    struct tm tm;
    SYSTEMTIME wtm;

    GetLocalTime(&wtm);
    tm.tm_year = wtm.wYear - 1900;
    tm.tm_mon = wtm.wMonth - 1;
    tm.tm_mday = wtm.wDay;
    tm.tm_hour = wtm.wHour;
    tm.tm_min = wtm.wMinute;
    tm.tm_sec = wtm.wSecond;
    tm.tm_isdst = -1;
    clock = mktime(&tm);
    tp->tv_sec = clock;
    tp->tv_usec = wtm.wMilliseconds * 1000;

    return 0;
}
#endif


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


// checks if a provided time stamp is consistent with current time and previously valid time stamps
// and, in case of validity, updates the "last valid time stamp"
int time_stamp_verify_and_update (uint64_t stamp, uint64_t *previous_stamp, int allow_jitter) {

    int64_t diff; /* do not change to unsigned */
    uint64_t co;  /* counter only mode (for sub-seconds) */

    co = (stamp << 63) >> 63;

    // is it around current time (+/- allowed deviation TIME_STAMP_FRAME)?
    diff = stamp - time_stamp();
    // abs()
    diff = (diff < 0 ? -diff : diff);
    if(diff >= TIME_STAMP_FRAME) {
        traceEvent(TRACE_DEBUG, "time_stamp_verify_and_update found a timestamp out of allowed frame.");
        return 0; // failure
    }

    // if applicable: is it higher than previous time stamp (including allowed deviation of TIME_STAMP_JITTER)?
    if(NULL != previous_stamp) {
        diff = stamp - *previous_stamp;
        if(allow_jitter) {
            // 8 times higher jitter allowed for counter-only flagged timestamps ( ~ 1.25 sec with 160 ms default jitter)
            diff += TIME_STAMP_JITTER << (co << 3);
        }

        if(diff <= 0) {
            traceEvent(TRACE_DEBUG, "time_stamp_verify_and_update found a timestamp too old compared to previous.");
            return 0; // failure
        }
        // for not allowing to exploit the allowed TIME_STAMP_JITTER to "turn the clock backwards",
        // set the higher of the values
        *previous_stamp = (stamp > *previous_stamp ? stamp : *previous_stamp);
    }

    return 1; // success
}
