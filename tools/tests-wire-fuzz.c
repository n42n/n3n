/*
 * Copyright (C) Honey Bunny QT
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>
 *
 * This code was made by Claude AI ass directed by Honey Bunny QT
 *
 * Truncation sweep for the wire decoders.
 *
 * For each message type this encodes one valid PDU and then offers the
 * decoder every possible truncation of it.  Two things must hold for every
 * one of them:
 *
 *   - a truncated PDU is rejected (negative return), because a decoder that
 *     accepts one hands its caller a half filled struct that looks valid
 *   - the decoder never advances idx past the number of bytes it was told
 *     were available
 *
 * The untruncated PDU must still decode and leave rem at zero.
 *
 * Exits non-zero if any of that fails, so it works as a plain test.
 *
 * Build (standalone, from the top of the tree after a normal make):
 *
 *   gcc -O1 -g -fsanitize=address,undefined -o tests-wire-fuzz \
 *       tools/tests-wire-fuzz.c -Iinclude -Ilibs -Isrc \
 *       -DCONFIG_RUNDIR='"/run"' -DHAVE_BRIDGING_SUPPORT \
 *       -DVERSION='"x"' -DBUILDDATE='"x"' -Lsrc -ln3n
 *
 * To wire it into the build instead, add "TESTS+=tests-wire-fuzz" to
 * tools/Makefile - the output is deterministic, so it can also be compared
 * against a tests/tests-wire-fuzz.expected in the usual way.
 */

#include <stdint.h>    // for uint8_t
#include <stdio.h>     // for printf
#include <string.h>    // for memset, memcpy, strncpy
#include "n2n.h"       // for n2n_common_t and the message structs
#include "n2n_wire.h"  // for encode_*, decode_*

// Guard bytes written past the logical end of the buffer, so that a decoder
// reading further than it was allowed shows up as poison in the output.
#define GUARD 64

static uint8_t buf[2048];

static void fill (void *p, size_t len, uint8_t seed) {
    uint8_t *b = p;
    size_t i;

    for(i = 0; i < len; i++) {
        b[i] = (uint8_t)(seed + i * 7);
    }
}

// Every message struct we might decode into, so one buffer serves all types
union any_msg {
    n2n_REGISTER_t reg;
    n2n_REGISTER_ACK_t ra;
    n2n_PACKET_t pkt;
    n2n_PEER_INFO_t pi;
    n2n_QUERY_PEER_t qp;
    n2n_REGISTER_SUPER_t rs;
    n2n_UNREGISTER_SUPER_t us;
    n2n_REGISTER_SUPER_NAK_t nak;
};

/* Decode whichever message type the common header says this is.
 * Returns what the type specific decoder returned. */
static int decode_by_type (union any_msg *out,
                           const n2n_common_t *cmn,
                           const uint8_t *base,
                           size_t *rem,
                           size_t *idx) {

    memset(out, 0, sizeof(*out));

    switch(cmn->pc) {
        case MSG_TYPE_REGISTER:
            return decode_REGISTER(&out->reg, cmn, base, rem, idx);
        case MSG_TYPE_REGISTER_ACK:
            return decode_REGISTER_ACK(&out->ra, cmn, base, rem, idx);
        case MSG_TYPE_PACKET:
            return decode_PACKET(&out->pkt, cmn, base, rem, idx);
        case MSG_TYPE_PEER_INFO:
            return decode_PEER_INFO(&out->pi, cmn, base, rem, idx);
        case MSG_TYPE_QUERY_PEER:
            return decode_QUERY_PEER(&out->qp, cmn, base, rem, idx);
        case MSG_TYPE_REGISTER_SUPER:
            return decode_REGISTER_SUPER(&out->rs, cmn, base, rem, idx);
        case MSG_TYPE_UNREGISTER_SUPER:
            return decode_UNREGISTER_SUPER(&out->us, cmn, base, rem, idx);
        case MSG_TYPE_REGISTER_SUPER_NAK:
            return decode_REGISTER_SUPER_NAK(&out->nak, cmn, base, rem, idx);
        default:
            return -1;
    }
}

/* Build one valid PDU of the named type into buf, return its length. */
static size_t build (const char *name, int with_sock) {
    n2n_common_t cmn;
    size_t idx = 0;

    memset(buf, 0, sizeof(buf));
    memset(&cmn, 0, sizeof(cmn));
    cmn.ttl = 2;
    strncpy((char *)cmn.community, "fuzzcomm", N2N_COMMUNITY_SIZE);
    if(with_sock) {
        cmn.flags = N2N_FLAGS_SOCKET;
    }

    if(!strncmp(name, "REGISTER_ACK", 12)) {
        n2n_REGISTER_ACK_t d;
        memset(&d, 0, sizeof(d));
        fill(&d.cookie, sizeof(d.cookie), 1);
        fill(d.srcMac, 6, 2);
        fill(d.dstMac, 6, 3);
        d.sock.family = AF_INET;
        cmn.pc = MSG_TYPE_REGISTER_ACK;
        encode_REGISTER_ACK(buf, &idx, &cmn, &d);
    } else if(!strncmp(name, "REGISTER_SUPER_NAK", 18)) {
        n2n_REGISTER_SUPER_NAK_t d;
        memset(&d, 0, sizeof(d));
        fill(&d.cookie, sizeof(d.cookie), 4);
        fill(d.srcMac, 6, 5);
        d.auth.scheme = n2n_auth_simple_id;
        d.auth.token_size = 16;
        fill(d.auth.token, 16, 6);
        cmn.pc = MSG_TYPE_REGISTER_SUPER_NAK;
        encode_REGISTER_SUPER_NAK(buf, &idx, &cmn, &d);
    } else if(!strncmp(name, "REGISTER_SUPER", 14)) {
        n2n_REGISTER_SUPER_t d;
        memset(&d, 0, sizeof(d));
        fill(&d.cookie, sizeof(d.cookie), 7);
        fill(d.edgeMac, 6, 8);
        d.sock.family = AF_INET;
        d.dev_addr.net_addr = 0x0a000001;
        d.dev_addr.net_bitlen = 24;
        d.auth.scheme = n2n_auth_simple_id;
        d.auth.token_size = 16;
        fill(d.auth.token, 16, 9);
        cmn.pc = MSG_TYPE_REGISTER_SUPER;
        encode_REGISTER_SUPER(buf, &idx, &cmn, &d);
    } else if(!strncmp(name, "UNREGISTER_SUPER", 16)) {
        n2n_UNREGISTER_SUPER_t d;
        memset(&d, 0, sizeof(d));
        d.auth.scheme = n2n_auth_simple_id;
        d.auth.token_size = 16;
        fill(d.auth.token, 16, 10);
        fill(d.srcMac, 6, 11);
        cmn.pc = MSG_TYPE_UNREGISTER_SUPER;
        encode_UNREGISTER_SUPER(buf, &idx, &cmn, &d);
    } else if(!strncmp(name, "REGISTER", 8)) {
        n2n_REGISTER_t d;
        memset(&d, 0, sizeof(d));
        fill(&d.cookie, sizeof(d.cookie), 12);
        fill(d.srcMac, 6, 13);
        fill(d.dstMac, 6, 14);
        d.sock.family = AF_INET;
        d.dev_addr.net_addr = 0x0a000002;
        d.dev_addr.net_bitlen = 24;
        strcpy((char *)d.dev_desc, "fuzz");
        cmn.pc = MSG_TYPE_REGISTER;
        encode_REGISTER(buf, &idx, &cmn, &d);
    } else if(!strncmp(name, "PACKET", 6)) {
        n2n_PACKET_t d;
        memset(&d, 0, sizeof(d));
        fill(d.srcMac, 6, 15);
        fill(d.dstMac, 6, 16);
        d.sock.family = AF_INET;
        cmn.pc = MSG_TYPE_PACKET;
        encode_PACKET(buf, &idx, &cmn, &d);
    } else if(!strncmp(name, "PEER_INFO", 9)) {
        n2n_PEER_INFO_t d;
        memset(&d, 0, sizeof(d));
        fill(d.srcMac, 6, 17);
        fill(d.mac, 6, 18);
        d.sock.family = AF_INET;
        cmn.pc = MSG_TYPE_PEER_INFO;
        encode_PEER_INFO(buf, &idx, &cmn, &d);
    } else {
        n2n_QUERY_PEER_t d;
        memset(&d, 0, sizeof(d));
        fill(d.srcMac, 6, 19);
        fill(d.targetMac, 6, 20);
        cmn.pc = MSG_TYPE_QUERY_PEER;
        encode_QUERY_PEER(buf, &idx, &cmn, &d);
    }

    return idx;
}

int main (void) {
    static const struct {
        const char *name;
        int with_sock;
    } cases[] = {
        { "REGISTER",            0 },
        { "REGISTER (sock)",     1 },
        { "REGISTER_ACK",        0 },
        { "REGISTER_ACK (sock)", 1 },
        { "PACKET",              0 },
        { "PEER_INFO",           0 },
        { "QUERY_PEER",          0 },
        { "REGISTER_SUPER",      1 },
        { "UNREGISTER_SUPER",    0 },
        { "REGISTER_SUPER_NAK",  0 },
    };
    const unsigned ncases = sizeof(cases) / sizeof(cases[0]);

    int failures = 0;
    int checked = 0;
    unsigned ci;

    for(ci = 0; ci < ncases; ci++) {
        const char *name = cases[ci].name;
        size_t full = build(name, cases[ci].with_sock);
        int accepted_short = 0;
        size_t worst_overread = 0;
        size_t avail;

        for(avail = 0; avail < full; avail++) {
            uint8_t save[GUARD];
            size_t guard = (avail + GUARD <= sizeof(buf)) ? GUARD : 0;
            n2n_common_t oc;
            union any_msg out;
            size_t rem = avail;
            size_t idx = 0;
            int rc;

            // poison everything past what we claim to have
            if(guard) {
                memcpy(save, buf + avail, guard);
                memset(buf + avail, 0xDD, guard);
            }

            memset(&oc, 0, sizeof(oc));
            rc = decode_common(&oc, buf, &rem, &idx);
            if(rc >= 0) {
                rc = decode_by_type(&out, &oc, buf, &rem, &idx);
            }

            if(guard) {
                memcpy(buf + avail, save, guard);
            }

            checked++;
            if((idx > avail) && ((idx - avail) > worst_overread)) {
                worst_overread = idx - avail;
            }
            if(rc >= 0) {
                accepted_short++;
                if(accepted_short <= 2) {
                    printf("  %-20s ACCEPTED %zu of %zu bytes "
                           "(rc=%d idx=%zu rem=%zu)\n",
                           name, avail, full, rc, idx, rem);
                }
            }
        }

        // the untruncated PDU must decode and consume exactly everything
        {
            n2n_common_t oc;
            union any_msg out;
            size_t rem = full;
            size_t idx = 0;
            int rc;
            int good;

            memset(&oc, 0, sizeof(oc));
            rc = decode_common(&oc, buf, &rem, &idx);
            if(rc >= 0) {
                rc = decode_by_type(&out, &oc, buf, &rem, &idx);
            }
            good = (rc >= 0) && (rem == 0);

            printf("%-20s len=%3zu  rejected=%3zu/%zu  valid=%s  overread=%zu\n",
                   name, full, full - accepted_short, full,
                   good ? "ok" : "BROKEN", worst_overread);

            if(accepted_short || !good || worst_overread) {
                failures++;
            }
        }
    }

    printf("\n%d truncations across %u message types: %s\n",
           checked, ncases,
           failures ? "FAILURES PRESENT" : "all rejected, no overread");

    return failures ? 1 : 0;
}
