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

#include "n2n.h"           // for n2n_edge_t, N2N_...
// FIXME: if this headers is sorted alphabetically, the test_integration_edge
// fails with what looks like a struct rearrangement involving eee->stats

#include <errno.h>         // for errno
#include <n3n/logging.h>   // for traceEvent
#include <stdbool.h>
#include <stdint.h>        // for uint32_t
#include <stdio.h>         // for snprintf, size_t, NULL
#include <string.h>        // for memcmp, memcpy, strerror, strncpy
#include <sys/types.h>     // for ssize_t
#include <time.h>          // for time, time_t
#include "management.h"    // for mgmt_req_t, send_reply, send_json_1str
#include "n2n_define.h"    // for N2N_PKT_BUF_SIZE, N2N_EVENT_DEBUG, N2N_EVE...
#include "n2n_typedefs.h"  // for n2n_edge_t, n2n_edge_conf_t
#include "peer_info.h"     // for peer_info, peer_info_t
#include "sn_selection.h"  // for sn_selection_criterion_str, selection_crit...
#include "strbuf.h"        // for strbuf_t, STRBUF_INIT
#include "uthash.h"        // for UT_hash_handle, HASH_ITER

#ifdef _WIN32
#include "win32/defs.h"
#else
#include <arpa/inet.h>     // for inet_ntoa
#include <netinet/in.h>    // for in_addr, htonl, in_addr_t
#include <sys/socket.h>    // for sendto, recvfrom, sockaddr_storage
#endif

size_t event_debug (strbuf_t *buf, char *tag, int data0, void *data1) {
    traceEvent(TRACE_DEBUG, "Unexpected call to event_debug");
    return 0;
}

size_t event_test (strbuf_t *buf, char *tag, int data0, void *data1) {
    size_t msg_len = gen_json_1str(buf, tag, "event", "test", (char *)data1);
    return msg_len;
}

size_t event_peer (strbuf_t *buf, char *tag, int data0, void *data1) {
    int action = data0;
    struct peer_info *peer = (struct peer_info *)data1;

    macstr_t mac_buf;
    n2n_sock_str_t sockbuf;

    /*
     * Just the peer_info bits that are needed for lookup (maccaddr) or
     * firewall and routing (sockaddr)
     * If needed, other details can be fetched via the edges method call.
     */
    return snprintf(buf->str, buf->size,
                    "{"
                    "\"_tag\":\"%s\","
                    "\"_type\":\"event\","
                    "\"action\":%i,"
                    "\"macaddr\":\"%s\","
                    "\"sockaddr\":\"%s\"}\n",
                    tag,
                    action,
                    (is_null_mac(peer->mac_addr)) ? "" : macaddr_str(mac_buf, peer->mac_addr),
                    sock_to_cstr(sockbuf, &(peer->sock)));
}



static void mgmt_communities (mgmt_req_t *req, strbuf_t *buf) {

    if(req->eee->conf.header_encryption != HEADER_ENCRYPTION_NONE) {
        mgmt_error(req, buf, "noaccess");
        return;
    }

    send_json_1str(req, buf, "row", "community", (char *)req->eee->conf.community_name);
}

static void mgmt_supernodes (mgmt_req_t *req, strbuf_t *buf) {
    size_t msg_len;
    struct peer_info *peer, *tmpPeer;
    macstr_t mac_buf;
    n2n_sock_str_t sockbuf;
    selection_criterion_str_t sel_buf;

    HASH_ITER(hh, req->eee->conf.supernodes, peer, tmpPeer) {

        /*
         * TODO:
         * The version string provided by the remote supernode could contain
         * chars that make our JSON invalid.
         * - do we care?
         */

        msg_len = snprintf(buf->str, buf->size,
                           "{"
                           "\"_tag\":\"%s\","
                           "\"_type\":\"row\","
                           "\"version\":\"%s\","
                           "\"purgeable\":%i,"
                           "\"current\":%i,"
                           "\"macaddr\":\"%s\","
                           "\"sockaddr\":\"%s\","
                           "\"selection\":\"%s\","
                           "\"last_seen\":%li,"
                           "\"uptime\":%li}\n",
                           req->tag,
                           peer->version,
                           peer->purgeable,
                           (peer == req->eee->curr_sn) ? (req->eee->sn_wait ? 2 : 1 ) : 0,
                           is_null_mac(peer->mac_addr) ? "" : macaddr_str(mac_buf, peer->mac_addr),
                           sock_to_cstr(sockbuf, &(peer->sock)),
                           sn_selection_criterion_str(req->eee, sel_buf, peer),
                           peer->last_seen,
                           peer->uptime);

        send_reply(req, buf, msg_len);
    }
}

static void mgmt_edges_row (mgmt_req_t *req, strbuf_t *buf, struct peer_info *peer, char *mode) {
    size_t msg_len;
    macstr_t mac_buf;
    n2n_sock_str_t sockbuf;
    dec_ip_bit_str_t ip_bit_str = {'\0'};

    msg_len = snprintf(buf->str, buf->size,
                       "{"
                       "\"_tag\":\"%s\","
                       "\"_type\":\"row\","
                       "\"mode\":\"%s\","
                       "\"ip4addr\":\"%s\","
                       "\"purgeable\":%i,"
                       "\"local\":%i,"
                       "\"macaddr\":\"%s\","
                       "\"sockaddr\":\"%s\","
                       "\"desc\":\"%s\","
                       "\"last_p2p\":%li,\n"
                       "\"last_sent_query\":%li,\n"
                       "\"last_seen\":%li}\n",
                       req->tag,
                       mode,
                       (peer->dev_addr.net_addr == 0) ? "" : ip_subnet_to_str(ip_bit_str, &peer->dev_addr),
                       peer->purgeable,
                       peer->local,
                       (is_null_mac(peer->mac_addr)) ? "" : macaddr_str(mac_buf, peer->mac_addr),
                       sock_to_cstr(sockbuf, &(peer->sock)),
                       peer->dev_desc,
                       peer->last_p2p,
                       peer->last_sent_query,
                       peer->last_seen);

    send_reply(req, buf, msg_len);
}

static void mgmt_edges (mgmt_req_t *req, strbuf_t *buf) {
    struct peer_info *peer, *tmpPeer;

    // dump nodes with forwarding through supernodes
    HASH_ITER(hh, req->eee->pending_peers, peer, tmpPeer) {
        mgmt_edges_row(req, buf, peer, "pSp");
    }

    // dump peer-to-peer nodes
    HASH_ITER(hh, req->eee->known_peers, peer, tmpPeer) {
        mgmt_edges_row(req, buf, peer, "p2p");
    }
}

static void mgmt_edge_info (mgmt_req_t *req, strbuf_t *buf) {
    size_t msg_len;
    macstr_t mac_buf;
    struct in_addr ip_addr;
    ipstr_t ip_address;
    n2n_sock_str_t sockbuf;

    ip_addr.s_addr = req->eee->device.ip_addr;
    inaddrtoa(ip_address, ip_addr);

    msg_len = snprintf(buf->str, buf->size,
                       "{"
                       "\"_tag\":\"%s\","
                       "\"_type\":\"row\","
                       "\"version\":\"%s\","
                       "\"macaddr\":\"%s\","
                       "\"ip4addr\":\"%s\","
                       "\"ip4masklen\":\"%ul\","
                       "\"sockaddr\":\"%s\"}\n",
                       req->tag,
                       VERSION,
                       is_null_mac(req->eee->device.mac_addr) ? "" : macaddr_str(mac_buf, req->eee->device.mac_addr),
                       ip_address,
                       req->eee->conf.tuntap_v4.net_bitlen,
                       sock_to_cstr(sockbuf, &req->eee->conf.preferred_sock));

    send_reply(req, buf, msg_len);
}

static void mgmt_timestamps (mgmt_req_t *req, strbuf_t *buf) {
    size_t msg_len;

    msg_len = snprintf(buf->str, buf->size,
                       "{"
                       "\"_tag\":\"%s\","
                       "\"_type\":\"row\","
                       "\"start_time\":%lu,"
                       "\"last_super\":%ld,"
                       "\"last_p2p\":%ld}\n",
                       req->tag,
                       req->eee->start_time,
                       req->eee->last_sup,
                       req->eee->last_p2p);

    send_reply(req, buf, msg_len);
}

static void mgmt_packetstats (mgmt_req_t *req, strbuf_t *buf) {
    size_t msg_len;

    msg_len = snprintf(buf->str, buf->size,
                       "{"
                       "\"_tag\":\"%s\","
                       "\"_type\":\"row\","
                       "\"type\":\"transop\","
                       "\"tx_pkt\":%lu,"
                       "\"rx_pkt\":%lu}\n",
                       req->tag,
                       req->eee->transop.tx_cnt,
                       req->eee->transop.rx_cnt);

    send_reply(req, buf, msg_len);

    msg_len = snprintf(buf->str, buf->size,
                       "{"
                       "\"_tag\":\"%s\","
                       "\"_type\":\"row\","
                       "\"type\":\"p2p\","
                       "\"tx_pkt\":%u,"
                       "\"rx_pkt\":%u}\n",
                       req->tag,
                       req->eee->stats.tx_p2p,
                       req->eee->stats.rx_p2p);

    send_reply(req, buf, msg_len);

    msg_len = snprintf(buf->str, buf->size,
                       "{"
                       "\"_tag\":\"%s\","
                       "\"_type\":\"row\","
                       "\"type\":\"super\","
                       "\"tx_pkt\":%u,"
                       "\"rx_pkt\":%u}\n",
                       req->tag,
                       req->eee->stats.tx_sup,
                       req->eee->stats.rx_sup);

    send_reply(req, buf, msg_len);

    msg_len = snprintf(buf->str, buf->size,
                       "{"
                       "\"_tag\":\"%s\","
                       "\"_type\":\"row\","
                       "\"type\":\"super_broadcast\","
                       "\"tx_pkt\":%u,"
                       "\"rx_pkt\":%u}\n",
                       req->tag,
                       req->eee->stats.tx_sup_broadcast,
                       req->eee->stats.rx_sup_broadcast);

    send_reply(req, buf, msg_len);

    msg_len = snprintf(buf->str, buf->size,
                       "{"
                       "\"_tag\":\"%s\","
                       "\"_type\":\"row\","
                       "\"type\":\"tuntap_error\","
                       "\"tx_pkt\":%u,"
                       "\"rx_pkt\":%u}\n",
                       req->tag,
                       req->eee->stats.tx_tuntap_error,
                       req->eee->stats.rx_tuntap_error);

    send_reply(req, buf, msg_len);

    msg_len = snprintf(buf->str, buf->size,
                       "{"
                       "\"_tag\":\"%s\","
                       "\"_type\":\"row\","
                       "\"type\":\"multicast_drop\","
                       "\"tx_pkt\":%u,"
                       "\"rx_pkt\":%u}\n",
                       req->tag,
                       req->eee->stats.tx_multicast_drop,
                       req->eee->stats.rx_multicast_drop);

    send_reply(req, buf, msg_len);
}

static void mgmt_post_test (mgmt_req_t *req, strbuf_t *buf) {

    send_json_1str(req, buf, "row", "sending", "test");
    mgmt_event_post(N2N_EVENT_TEST, -1, req->argv);
}

// Forward define so we can include this in the mgmt_handlers[] table
static void mgmt_help (mgmt_req_t *req, strbuf_t *buf);
static void mgmt_help_events (mgmt_req_t *req, strbuf_t *buf);

static const mgmt_handler_t mgmt_handlers[] = {
    { .cmd = "reload_communities", .flags = FLAG_WROK, .help = "Reserved for supernode", .func = mgmt_unimplemented},

    { .cmd = "stop", .flags = FLAG_WROK, .help = "Gracefully exit edge", .func = mgmt_stop},
    { .cmd = "verbose", .flags = FLAG_WROK, .help = "Manage verbosity level", .func = mgmt_verbose},
    { .cmd = "communities", .help = "Show current community", .func = mgmt_communities},
    { .cmd = "edges", .help = "List current edges/peers", .func = mgmt_edges},
    { .cmd = "supernodes", .help = "List current supernodes", .func = mgmt_supernodes},
    { .cmd = "info", .help = "Provide basic edge information", .func = mgmt_edge_info},
    { .cmd = "timestamps", .help = "Event timestamps", .func = mgmt_timestamps},
    { .cmd = "packetstats", .help = "traffic counters", .func = mgmt_packetstats},
    { .cmd = "post.test", .help = "send a test event", .func = mgmt_post_test},
    { .cmd = "help", .flags = FLAG_WROK, .help = "Show JSON commands", .func = mgmt_help},
    { .cmd = "help.events", .help = "Show available Subscribe topics", .func = mgmt_help_events},
};

/* Current subscriber for each event topic */
static mgmt_req_t mgmt_event_subscribers[] = {
    [N2N_EVENT_DEBUG] = { .eee = NULL, .type = N2N_MGMT_UNKNOWN, .tag = "\0" },
    [N2N_EVENT_TEST] = { .eee = NULL, .type = N2N_MGMT_UNKNOWN, .tag = "\0" },
    [N2N_EVENT_PEER] = { .eee = NULL, .type = N2N_MGMT_UNKNOWN, .tag = "\0" },
};

/* Map topic number to function */
// TODO: want this to be const
static mgmt_event_handler_t *mgmt_events[] = {
    [N2N_EVENT_DEBUG] = event_debug,
    [N2N_EVENT_TEST] = event_test,
    [N2N_EVENT_PEER] = event_peer,
};

/* Allow help and subscriptions to use topic name */
static const mgmt_events_t mgmt_event_names[] = {
    { .cmd = "debug", .topic = N2N_EVENT_DEBUG, .help = "All events - for event debugging"},
    { .cmd = "test", .topic = N2N_EVENT_TEST, .help = "Used only by post.test"},
    { .cmd = "peer", .topic = N2N_EVENT_PEER, .help = "Changes to peer list"},
};

void mgmt_event_post (enum n2n_event_topic topic, int data0, void *data1) {
    mgmt_req_t *debug = &mgmt_event_subscribers[N2N_EVENT_DEBUG];
    mgmt_req_t *sub = &mgmt_event_subscribers[topic];
    mgmt_event_handler_t *fn =  mgmt_events[topic];

    mgmt_event_post2(topic, data0, data1, debug, sub, fn);
}

static void mgmt_help_events (mgmt_req_t *req, strbuf_t *buf) {
    int i;
    int nr_handlers = sizeof(mgmt_event_names) / sizeof(mgmt_events_t);
    for( i=0; i < nr_handlers; i++ ) {
        int topic = mgmt_event_names[i].topic;
        mgmt_req_t *sub = &mgmt_event_subscribers[topic];

        mgmt_help_events_row(req, buf, sub, mgmt_event_names[i].cmd, mgmt_event_names[i].help);
    }
}

// TODO: want to keep the mgmt_handlers defintion const static, otherwise
// this whole function could be shared
static void mgmt_help (mgmt_req_t *req, strbuf_t *buf) {
    /*
     * Even though this command is readonly, we deliberately do not check
     * the type - allowing help replies to both read and write requests
     */

    int i;
    int nr_handlers = sizeof(mgmt_handlers) / sizeof(mgmt_handler_t);
    for( i=0; i < nr_handlers; i++ ) {
        mgmt_help_row(req, buf, mgmt_handlers[i].cmd, mgmt_handlers[i].help);
    }
}

static void handleMgmtJson (mgmt_req_t *req, char *udp_buf, const int recvlen) {

    strbuf_t *buf;
    char cmdlinebuf[80];

    /* save a copy of the commandline before we reuse the udp_buf */
    strncpy(cmdlinebuf, udp_buf, sizeof(cmdlinebuf)-1);
    cmdlinebuf[sizeof(cmdlinebuf)-1] = 0;

    traceEvent(TRACE_DEBUG, "mgmt json %s", cmdlinebuf);

    /* we reuse the buffer already on the stack for all our strings */
    STRBUF_INIT(buf, udp_buf, N2N_SN_PKTBUF_SIZE);

    if(!mgmt_req_init2(req, buf, (char *)&cmdlinebuf)) {
        // if anything failed during init
        return;
    }

    if(req->type == N2N_MGMT_SUB) {
        int handler;
        lookup_handler(handler, mgmt_event_names, req->argv0);
        if(handler == -1) {
            mgmt_error(req, buf, "unknowntopic");
            return;
        }

        int topic = mgmt_event_names[handler].topic;
        if(mgmt_event_subscribers[topic].type == N2N_MGMT_SUB) {
            send_json_1str(&mgmt_event_subscribers[topic], buf,
                           "unsubscribed", "topic", req->argv0);
            send_json_1str(req, buf, "replacing", "topic", req->argv0);
        }

        memcpy(&mgmt_event_subscribers[topic], req, sizeof(*req));

        send_json_1str(req, buf, "subscribe", "topic", req->argv0);
        return;
    }

    int handler;
    lookup_handler(handler, mgmt_handlers, req->argv0);
    if(handler == -1) {
        mgmt_error(req, buf, "unknowncmd");
        return;
    }

    if((req->type==N2N_MGMT_WRITE) && !(mgmt_handlers[handler].flags & FLAG_WROK)) {
        mgmt_error(req, buf, "readonly");
        return;
    }

    /*
     * TODO:
     * The tag provided by the requester could contain chars
     * that make our JSON invalid.
     * - do we care?
     */
    send_json_1str(req, buf, "begin", "cmd", req->argv0);

    mgmt_handlers[handler].func(req, buf);

    send_json_1str(req, buf, "end", "cmd", req->argv0);
    return;
}

/** Read a datagram from the management UDP socket and take appropriate
 *    action. */
void readFromMgmtSocket (n2n_edge_t *eee) {

    char udp_buf[N2N_PKT_BUF_SIZE]; /* Compete UDP packet */
    ssize_t recvlen;
    mgmt_req_t req;

    req.sss = NULL;
    req.eee = eee;
    req.mgmt_sock = eee->udp_mgmt_sock;
    req.keep_running = eee->keep_running;
    req.mgmt_password = eee->conf.mgmt_password;
    req.sock_len = sizeof(req.sas);

    recvlen = recvfrom(eee->udp_mgmt_sock, udp_buf, N2N_PKT_BUF_SIZE, 0 /*flags*/,
                       &req.sender_sock, &req.sock_len);

    if(recvlen < 0) {
        traceEvent(TRACE_WARNING, "mgmt recvfrom failed: %d - %s", errno, strerror(errno));
        return; /* failed to receive data from UDP */
    }

    /* avoid parsing any uninitialized junk from the stack */
    udp_buf[recvlen] = 0;

    if((udp_buf[0] >= 'a' && udp_buf[0] <= 'z') && (udp_buf[1] == ' ')) {
        /* this is a JSON request */
        handleMgmtJson(&req, udp_buf, recvlen);
        return;
    }

    traceEvent(TRACE_WARNING, "unknown mgmt request");
}
