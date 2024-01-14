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

//
// Zhou Bin <joshuafc@foxmail.com>
//

// TODO: refactor into public and private definitions

#ifndef _N3N_NETWORK_TRAFFIC_FILTER_H_
#define _N3N_NETWORK_TRAFFIC_FILTER_H_

#include <n3n/endian.h> // for __LITTLE_ENDIAN__, __BIG_ENDIAN__
#include <stdint.h>     // for uint8_t and friends
#include <uthash.h>

#ifdef _WIN32
// FIXME: I dont even
typedef unsigned long in_addr_t;
#else
#include <arpa/inet.h>  // for in_addr_t
#endif

#if defined(_MSC_VER) || defined(__MINGW32__)
#pragma pack(push,1)
#endif

#ifdef __GNUC__
#define PACK_STRUCT __attribute__((__packed__))
#else
#define PACK_STRUCT
#endif

struct n2n_iphdr {
#if defined(__LITTLE_ENDIAN__)
    uint8_t ihl : 4, version : 4;
#elif defined(__BIG_ENDIAN__)
    uint8_t version : 4, ihl : 4;
#else
# error "Byte order must be defined"
#endif
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
} PACK_STRUCT;

struct n2n_tcphdr {
    uint16_t source;
    uint16_t dest;
    uint32_t seq;
    uint32_t ack_seq;
#if defined(__LITTLE_ENDIAN__)
    uint16_t res1 : 4, doff : 4, fin : 1, syn : 1, rst : 1, psh : 1, ack : 1, urg : 1, ece : 1, cwr : 1;
#elif defined(__BIG_ENDIAN__)
    uint16_t doff : 4, res1 : 4, cwr : 1, ece : 1, urg : 1, ack : 1, psh : 1, rst : 1, syn : 1, fin : 1;
#else
# error "Byte order must be defined"
#endif
    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr;
} PACK_STRUCT;

struct n2n_udphdr {
    uint16_t source;
    uint16_t dest;
    uint16_t len;
    uint16_t check;
} PACK_STRUCT;

typedef struct port_range {
    uint16_t start_port; // range contain 'start_port' self
    uint16_t end_port;   // range contain 'end_port' self
} port_range_t;

#if defined(_MSC_VER) || defined(__MINGW32__)
#pragma pack(pop)
#endif

#undef PACK_STRUCT

typedef struct filter_rule_key {
    in_addr_t src_net_cidr;
    uint8_t src_net_bit_len;
    port_range_t src_port_range;
    in_addr_t dst_net_cidr;
    uint8_t dst_net_bit_len;
    port_range_t dst_port_range;
    uint8_t bool_tcp_configured;
    uint8_t bool_udp_configured;
    uint8_t bool_icmp_configured;
} filter_rule_key_t;

typedef struct filter_rule {
    filter_rule_key_t key;

    uint8_t bool_accept_icmp;
    uint8_t bool_accept_udp;
    uint8_t bool_accept_tcp;

    UT_hash_handle hh;   /* makes this structure hashable */
} filter_rule_t;

/* *************************************************** */

typedef enum {
    N2N_ACCEPT = 0,
    N2N_DROP =   1
} n2n_verdict;

/* *************************************************** */

typedef enum {
    FPP_UNKNOWN = 0,
    FPP_ARP =     1,
    FPP_TCP =     2,
    FPP_UDP =     3,
    FPP_ICMP =    4,
    FPP_IGMP =    5
} filter_packet_proto;

typedef struct packet_address_proto_info {
    in_addr_t src_ip;
    uint16_t src_port;
    in_addr_t dst_ip;
    uint16_t dst_port;
    filter_packet_proto proto;
}packet_address_proto_info_t;

typedef struct filter_rule_pair_cache {
    packet_address_proto_info_t key;

    uint8_t bool_allow_traffic;
    uint32_t active_count;

    UT_hash_handle hh;                 /* makes this structure hashable */
} filter_rule_pair_cache_t;

struct network_traffic_filter;
typedef struct network_traffic_filter network_traffic_filter_t;

network_traffic_filter_t* create_network_traffic_filter ();

void destroy_network_traffic_filter (network_traffic_filter_t* filter);

void network_traffic_filter_add_rule (network_traffic_filter_t* filter, filter_rule_t* rules);

//rule_str format: src_ip/len:[b_port,e_port],dst_ip/len:[s_port,e_port],TCP+/-,UDP+/-,ICMP+/-
uint8_t process_traffic_filter_rule_str (const char* rule_str, filter_rule_t* rule_struct);

#endif //N3N_NETWORK_TRAFFIC_FILTER_H
