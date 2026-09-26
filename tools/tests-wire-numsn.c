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
 * A REGISTER_SUPER_ACK carries num_sn backup supernodes in a payload that
 * decode_REGISTER_SUPER_ACK() copies into the caller's tmpbuf.  num_sn comes
 * off the wire, and it is bounded against REG_SUPER_ACK_PAYLOAD_SPACE - but
 * that only stops it being bigger than the buffer, not bigger than the
 * packet that actually arrived.
 *
 * If a short packet is accepted, decode_buf() reports the size it wanted
 * while copying nothing, so tmpbuf keeps whatever it held before.  The
 * caller in edge_utils.c then loops num_sn times over it and hands each
 * entry to add_sn_to_list_by_mac_or_sock(), adding supernodes built out of
 * uninitialised memory.
 *
 * This checks that a REGISTER_SUPER_ACK claiming more backup supernodes than
 * it carries is rejected.  Exits non-zero if it is accepted.
 *
 * Build (standalone, from the top of the tree after a normal make):
 *
 *   gcc -O1 -g -fsanitize=address -o tests-wire-numsn \
 *       tools/tests-wire-numsn.c -Iinclude -Ilibs -Isrc \
 *       -DCONFIG_RUNDIR='"/run"' -DHAVE_BRIDGING_SUPPORT \
 *       -DVERSION='"x"' -DBUILDDATE='"x"' -Lsrc -ln3n
 */

#include <stdint.h>    // for uint8_t
#include <stdio.h>     // for printf
#include <string.h>    // for memset, strncpy
#include "n2n.h"       // for n2n_common_t, n2n_REGISTER_SUPER_ACK_t
#include "n2n_wire.h"  // for encode_REGISTER_SUPER_ACK, decode_*

// how many backup supernodes the crafted packet will claim to carry
#define CLAIMED 3

// how many it will actually carry
#define CARRIED 1

static uint8_t buf[2048];

int main (void) {
    n2n_common_t cmn;
    n2n_REGISTER_SUPER_ACK_t ack;
    n2n_common_t out_cmn;
    n2n_REGISTER_SUPER_ACK_t out;
    uint8_t payload[REG_SUPER_ACK_PAYLOAD_SPACE];
    uint8_t tmpbuf[REG_SUPER_ACK_PAYLOAD_SPACE];
    size_t entry = REG_SUPER_ACK_PAYLOAD_ENTRY_SIZE;
    size_t idx = 0;
    size_t full;
    size_t offered;
    size_t rem;
    int rc;
    unsigned n;
    int stale = 0;

    memset(&cmn, 0, sizeof(cmn));
    cmn.ttl = 2;
    cmn.pc = MSG_TYPE_REGISTER_SUPER_ACK;
    strncpy((char *)cmn.community, "testcomm", N2N_COMMUNITY_SIZE);

    memset(&ack, 0, sizeof(ack));
    ack.srcMac[0] = 0x02;
    ack.sock.family = AF_INET;
    ack.lifetime = 60;
    ack.auth.scheme = n2n_auth_simple_id;
    ack.auth.token_size = 16;
    ack.num_sn = CLAIMED;

    memset(payload, 0x11, sizeof(payload));
    encode_REGISTER_SUPER_ACK(buf, &idx, &cmn, &ack, payload);
    full = idx;

    // hand the decoder a buffer holding only CARRIED of the CLAIMED entries
    offered = full - ((CLAIMED - CARRIED) * entry);

    // poison tmpbuf so stale entries are recognisable
    memset(tmpbuf, 0xAB, sizeof(tmpbuf));

    rem = offered;
    idx = 0;
    memset(&out_cmn, 0, sizeof(out_cmn));
    memset(&out, 0, sizeof(out));

    rc = decode_common(&out_cmn, buf, &rem, &idx);
    if(rc < 0) {
        printf("decode_common rejected the short packet, "
               "the type decoder is never reached\n");
        return 0;
    }

    rc = decode_REGISTER_SUPER_ACK(&out, &out_cmn, buf, &rem, &idx, tmpbuf);

    printf("full packet = %zu bytes, entry = %zu bytes\n", full, entry);
    printf("offered     = %zu bytes (claims %u supernodes, carries %u)\n",
           offered, (unsigned)CLAIMED, (unsigned)CARRIED);
    printf("decode      = %d, num_sn = %u\n", rc, out.num_sn);

    if(rc < 0) {
        printf("\nREJECTED - the caller never reaches the num_sn loop\n");
        return 0;
    }

    for(n = 0; n < out.num_sn; n++) {
        const uint8_t *e = tmpbuf + (size_t)n * entry;
        size_t k;
        int all_poison = 1;

        for(k = 0; k < entry; k++) {
            if(e[k] != 0xAB) {
                all_poison = 0;
                break;
            }
        }
        if(all_poison) {
            stale++;
        }
    }

    printf("\nACCEPTED - the caller will loop %u times over tmpbuf, "
           "of which %d entries are stale buffer contents\n",
           out.num_sn, stale);
    return 1;
}
