/*
 * Copyright (C) 2023-24 Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Common routines shared between the management interfaces
 *
 */


#include <connslot/connslot.h>  // for conn_t
#include <connslot/jsonrpc.h>   // for jsonrpc_t, jsonrpc_parse
#include <n3n/ethernet.h>       // for is_null_mac
#include <n3n/logging.h> // for traceEvent
#include <n3n/metrics.h> // for n3n_metrics_render
#include <n3n/strings.h> // for ip_subnet_to_str, sock_to_cstr
#include <n3n/supernode.h>      // for load_allowed_sn_community
#include <sn_selection.h> // for sn_selection_criterion_str
#include <stdbool.h>
#include <stdio.h>       // for snprintf, NULL, size_t
#include <stdlib.h>      // for strtoul
#include <string.h>      // for strtok, strlen, strncpy
#include "base64.h"      // for base64decode
#include "management.h"
#include "peer_info.h"   // for peer_info

#ifdef _WIN32
#include "win32/defs.h"
#else
#include <netdb.h>       // for getnameinfo, NI_NUMERICHOST, NI_NUMERICSERV
#include <sys/socket.h>  // for sendto, sockaddr
#endif

static void generate_http_headers (conn_t *conn, const char *type, int code) {
    strbuf_t **pp = &conn->reply_header;
    sb_reprintf(pp, "HTTP/1.1 %i result\r\n", code);
    // TODO:
    // - caching
    int len = sb_len(conn->reply);
    sb_reprintf(pp, "Content-Type: %s\r\n", type);
    sb_reprintf(pp, "Content-Length: %i\r\n\r\n", len);
}

static void render_error (conn_t *conn, const char *message) {
    sb_zero(conn->request);
    sb_printf(conn->request, "%s\n", message);

    // Update the reply buffer after last potential realloc
    conn->reply = conn->request;

    generate_http_headers(conn, "text/plain", 404);
}

static bool auth_check (struct n3n_runtime_data *eee, conn_t *conn) {
    char *p = strstr(conn->request->str, "Authorization:");
    if(!p) {
        // No auth header
        return false;
    }
    strtok(p, " "); // Skip the Authorization: header
    p = strtok(NULL, " ");
    if(strcmp(p, "Basic")) {
        // They sent something other than basic
        return false;
    }

    p = strtok(NULL, " \r\n");

    char *decoded = base64decode(p);
    if(!decoded) {
        // they didnt send us valid base64
        return false;
    }

    p = strtok(decoded,":"); // Skip the username
    p = strtok(NULL,":");
    if(!p) {
        // they didnt send us a complete auth header
        return false;
    }

    if(strcmp(eee->conf.mgmt_password, p)) {
        // They didnt send the right password
        free(decoded);
        return false;
    }

    free(decoded);
    return true;
}

static void auth_request (conn_t *conn) {
    sb_zero(conn->request);
    sb_printf(conn->request, "%s\n", "unauthorised");

    // Update the reply buffer after last potential realloc
    conn->reply = conn->request;

    strbuf_t **pp = &conn->reply_header;
    sb_reprintf(pp, "HTTP/1.1 401 unauth\r\n");
    int len = sb_len(conn->reply);
    sb_reprintf(pp, "Content-Type: text/plain\r\n");
    sb_reprintf(pp, "WWW-Authenticate: Basic realm=\"n3n\"\r\n");
    sb_reprintf(pp, "Content-Length: %i\r\n\r\n", len);
}

#if 0
/*
 * Check if the user is authorised for this command.
 * - this should be more configurable!
 * - for the moment we use some simple heuristics:
 *   Reads are not dangerous, so they are simply allowed
 *   Writes are possibly dangerous, so they need a fake password
 */
int mgmt_auth (mgmt_req_t *req, char *auth) {

    if(auth) {
        /* If we have an auth key, it must match */
        if(!strcmp(req->mgmt_password, auth)) {
            return 1;
        }
        return 0;
    }
    /* if we dont have an auth key, we can still read */
    if(req->type == N2N_MGMT_READ) {
        return 1;
    }

    return 0;
}
#endif

static void event_debug (strbuf_t *buf, enum n3n_event_topic topic, int data0, const void *data1) {
    traceEvent(TRACE_DEBUG, "Unexpected call to event_debug");
    return;
}

static void event_test (strbuf_t *buf, enum n3n_event_topic topic, int data0, const void *data1) {
    sb_printf(
        buf,
        "\x1e{"
        "\"event\":\"test\","
        "\"params\":%s}\n",
        (char *)data1);
}

static const char *event_peer_actions[] = {
    [N3N_EVENT_PEER_PURGE] = "purge",
    [N3N_EVENT_PEER_CLEAR] = "clear",
    [N3N_EVENT_PEER_DEL_P2P] = "del_p2p",
    [N3N_EVENT_PEER_ADD_P2P] = "add_p2p",
};

static void event_peer (strbuf_t *buf, enum n3n_event_topic topic, int data0, const void *data1) {
    int action = data0;
    struct peer_info *peer = (struct peer_info *)data1;

    macstr_t mac_buf;
    n2n_sock_str_t sockbuf;
    uint32_t age = time(NULL) - peer->time_alloc;

    /*
     * Just the peer_info bits that are needed for lookup (maccaddr) or
     * firewall and routing (sockaddr)
     * If needed, other details can be fetched via the edges method call.
     */
    sb_printf(
        buf,
        "\x1e{"
        "\"event\":\"peer\","
        "\"action\":\"%s\","
        "\"macaddr\":\"%s\","
        "\"age\":%u,"
        "\"sockaddr\":\"%s\"}\n",
        event_peer_actions[action],
        (is_null_mac(peer->mac_addr)) ? "" : macaddr_str(mac_buf, peer->mac_addr),
        age,
        sock_to_cstr(sockbuf, &(peer->sock))
    );

    // TODO: a generic truncation watcher for these buffers
}

/* Current subscriber for each event topic */
static SOCKET mgmt_event_subscribers[] = {
    [N3N_EVENT_DEBUG] = -1,
    [N3N_EVENT_TEST] = -1,
    [N3N_EVENT_PEER] = -1,
};

struct mgmt_event {
    char *topic;
    char *desc;
    void (*func)(strbuf_t *buf, enum n3n_event_topic topic, int data0, const void *data1);
};

static const struct mgmt_event mgmt_events[] = {
    [N3N_EVENT_DEBUG] = {
        .topic = "debug",
        .desc = "All events - for event debugging",
        .func = event_debug,
    },
    [N3N_EVENT_TEST] = {
        .topic = "test",
        .desc = "Used only by post.test",
        .func = event_test,
    },
    [N3N_EVENT_PEER] = {
        .topic = "peer",
        .desc = "Changes to peer list",
        .func = event_peer,
    },
};

static void event_subscribe (struct n3n_runtime_data *eee, conn_t *conn) {
    char *match = "GET /events/"; // what we expect to have been called with
    char *urltail = &conn->request->str[strlen(match)];
    char *topic = strtok(urltail, " ");

    enum n3n_event_topic topicid;

    int nr_topics = sizeof(mgmt_events) / sizeof(mgmt_events[0]);
    for( topicid=0; topicid < nr_topics; topicid++ ) {
        if(!strcmp(mgmt_events[topicid].topic,topic)) {
            break;
        }
    }
    if( topicid >= nr_topics ) {
        render_error(conn, "unknown topic");
        return;
    }

    bool replacing = false;

    if(mgmt_event_subscribers[topicid] != -1) {
        // TODO: send a goodbye message to old subscriber
        close(mgmt_event_subscribers[topicid]);

        replacing = true;
    }

    // Take the filehandle away from the connslots.
    mgmt_event_subscribers[topicid] = conn->fd;
    conn_zero(conn);

    // TODO: shutdown(fd, SHUT_RD) - but that does nothing for unix domain

    // The assigned mime type is actually application/json-seq, but firefox
    // will usefully show you the raw streaming data if we use the wrong
    // content type
    char *msg1 = "HTTP/1.1 200 event\r\nContent-Type: application/json\r\n\r\n";
    (void)write(mgmt_event_subscribers[topicid], msg1, strlen(msg1));
    // Ignore the result
    // (the message is leaving here fine, the problem must be at your end)

    if(replacing) {
        char *msg2 = "\x1e\"replacing\"\n";
        (void)write(mgmt_event_subscribers[topicid], msg2, strlen(msg2));
    }
}

void mgmt_event_post (const enum n3n_event_topic topic, int data0, const void *data1) {
    traceEvent(TRACE_DEBUG, "post topic=%i data0=%i", topic, data0);

    SOCKET debug = mgmt_event_subscribers[N3N_EVENT_DEBUG];
    SOCKET sub = mgmt_event_subscribers[topic];

    if( sub == -1 && debug == -1) {
        // If neither of this topic or the debug topic have a subscriber
        // then we dont need to do any work
        return;
    }

    char buf_space[200];
    strbuf_t *buf;
    STRBUF_INIT(buf, buf_space);

    mgmt_events[topic].func(buf, topic, data0, data1);

    if( sub != -1 ) {
        if(sb_write(sub, buf, 0, -1) == -1) {
            mgmt_event_subscribers[topic] = -1;
            close(sub);
        }
    }
    if( debug != -1 ) {
        if(sb_write(debug, buf, 0, -1) == -1) {
            mgmt_event_subscribers[N3N_EVENT_DEBUG] = -1;
            close(debug);
        }
    }
    // TODO:
    // - ideally, we would detect that the far end has gone away and
    //   set the subscriber socket back to -1
    // - this all assumes that the socket is set to non blocking
    // - if the write returns EWOULDBLOCK, increment a metric and return
}

static void jsonrpc_error (char *id, conn_t *conn, int code, char *message) {
    // Reuse the request buffer
    sb_zero(conn->request);

    sb_reprintf(
        &conn->request,
        "{"
        "\"jsonrpc\":\"2.0\","
        "\"id\":\"%s\","
        "\"error\":{"
        " \"code\":%i,"
        " \"message\":\"%s\""
        "}}",
        id,
        code,
        message
    );

    // Update the reply buffer after last potential realloc
    conn->reply = conn->request;
    generate_http_headers(conn, "application/json", code);
}

static void jsonrpc_result_head (char *id, conn_t *conn) {
    // Reuse the request buffer
    sb_zero(conn->request);

    sb_reprintf(
        &conn->request,
        "{"
        "\"jsonrpc\":\"2.0\","
        "\"id\":\"%s\","
        "\"result\":",
        id
    );
}

static void jsonrpc_result_tail (conn_t *conn, int code) {
    sb_reprintf(&conn->request, "}");

    // Update the reply buffer after last potential realloc
    conn->reply = conn->request;

    generate_http_headers(conn, "application/json", code);
}

static void jsonrpc_1uint (char *id, conn_t *conn, uint32_t result) {
    jsonrpc_result_head(id, conn);
    sb_reprintf(&conn->request, "%u", result);
    jsonrpc_result_tail(conn, 200);
}

static void jsonrpc_get_verbose (char *id, struct n3n_runtime_data *eee, conn_t *conn, const char *params) {
    jsonrpc_1uint(id, conn, getTraceLevel());
}

static void jsonrpc_set_verbose (char *id, struct n3n_runtime_data *eee, conn_t *conn, const char *params_in) {
    if(!auth_check(eee, conn)) {
        auth_request(conn);
        return;
    }

    if(!params_in) {
        jsonrpc_error(id, conn, 400, "missing param");
        return;
    }

    if(*params_in != '[') {
        jsonrpc_error(id, conn, 400, "expecting array");
        return;
    }

    // Avoid discarding the const attribute
    char *params = strdup(params_in+1);

    char *arg1 = json_extract_val(params);

    if(*arg1 == '"') {
        arg1++;
    }

    setTraceLevel(strtoul(arg1, NULL, 0));
    jsonrpc_get_verbose(id, eee, conn, params);
    free(params);
}

static void jsonrpc_stop (char *id, struct n3n_runtime_data *eee, conn_t *conn, const char *params) {
    if(!auth_check(eee, conn)) {
        auth_request(conn);
        return;
    }

    *eee->keep_running = false;

    jsonrpc_1uint(id, conn, *eee->keep_running);
}

static void jsonrpc_get_communities (char *id, struct n3n_runtime_data *eee, conn_t *conn, const char *params) {
    if(!eee->communities) {
        // This is an edge
        if(eee->conf.header_encryption != HEADER_ENCRYPTION_NONE) {
            jsonrpc_error(id, conn, 403, "Forbidden");
            return;
        }

        jsonrpc_result_head(id, conn);
        sb_reprintf(
            &conn->request,
            "[{\"community\":\"%s\"}]",
            eee->conf.community_name
        );
        jsonrpc_result_tail(conn, 200);
        return;
    }

    // Otherwise send the supernode's view
    struct sn_community *community, *tmp;
    dec_ip_bit_str_t ip_bit_str = {'\0'};

    jsonrpc_result_head(id, conn);
    sb_reprintf(&conn->request, "[");

    HASH_ITER(hh, eee->communities, community, tmp) {

        sb_reprintf(&conn->request,
                    "{"
                    "\"community\":\"%s\","
                    "\"purgeable\":%i,"
                    "\"is_federation\":%i,"
                    "\"ip4addr\":\"%s\"},",
                    (community->is_federation) ? "-/-" : community->community,
                    community->purgeable,
                    community->is_federation,
                    (community->auto_ip_net.net_addr == 0) ? "" : ip_subnet_to_str(ip_bit_str, &community->auto_ip_net));
    }

    // HACK: back up over the final ','
    if(conn->request->str[conn->request->wr_pos-1] == ',') {
        conn->request->wr_pos--;
    }

    sb_reprintf(&conn->request, "]");
    jsonrpc_result_tail(conn, 200);
}

static void jsonrpc_get_edges_row (strbuf_t **reply, struct peer_info *peer, const char *mode, const char *community) {
    macstr_t mac_buf;
    n2n_sock_str_t sockbuf;
    n2n_sock_str_t sockbuf2;
    dec_ip_bit_str_t ip_bit_str = {'\0'};

    sb_reprintf(reply,
                "{"
                "\"mode\":\"%s\","
                "\"community\":\"%s\","
                "\"ip4addr\":\"%s\","
                "\"purgeable\":%i,"
                "\"local\":%i,"
                "\"macaddr\":\"%s\","
                "\"sockaddr\":\"%s\","
                "\"prefered_sockaddr\":\"%s\","
                "\"desc\":\"%.20s\","
                "\"version\":\"%.20s\","
                "\"timeout\":%i,"
                "\"uptime\":%u,"
                "\"time_alloc\":%u,"
                "\"last_p2p\":%u,"
                "\"last_sent_query\":%u,"
                "\"last_seen\":%u},",
                mode,
                community,
                (peer->dev_addr.net_addr == 0) ? "" : ip_subnet_to_str(ip_bit_str, &peer->dev_addr),
                peer->purgeable,
                peer->local,
                (is_null_mac(peer->mac_addr)) ? "" : macaddr_str(mac_buf, peer->mac_addr),
                sock_to_cstr(sockbuf, &(peer->sock)),
                sock_to_cstr(sockbuf2, &(peer->preferred_sock)),
                peer->dev_desc,
                peer->version,
                peer->timeout,
                (uint32_t)peer->uptime,
                (uint32_t)peer->time_alloc,
                (uint32_t)peer->last_p2p,
                (uint32_t)peer->last_sent_query,
                (uint32_t)peer->last_seen
    );

    // TODO: add a proto: TCP|UDP item to the output
}

static void jsonrpc_get_edges (char *id, struct n3n_runtime_data *eee, conn_t *conn, const char *params) {
    struct peer_info *peer, *tmpPeer;

    jsonrpc_result_head(id, conn);
    sb_reprintf(&conn->request, "[");

    // dump nodes with forwarding through supernodes
    HASH_ITER(hh, eee->pending_peers, peer, tmpPeer) {
        jsonrpc_get_edges_row(
            &conn->request,
            peer,
            "pSp",
            eee->conf.community_name
        );
    }

    // dump peer-to-peer nodes
    HASH_ITER(hh, eee->known_peers, peer, tmpPeer) {
        jsonrpc_get_edges_row(
            &conn->request,
            peer,
            "p2p",
            eee->conf.community_name
        );
    }

    struct sn_community *community, *tmp;
    HASH_ITER(hh, eee->communities, community, tmp) {
        HASH_ITER(hh, community->edges, peer, tmpPeer) {
            jsonrpc_get_edges_row(
                &conn->request,
                peer,
                "sn",
                (community->is_federation) ? "-/-" : community->community
            );
        }
    }


    // HACK: back up over the final ','
    if(conn->request->str[conn->request->wr_pos-1] == ',') {
        conn->request->wr_pos--;
    }

    sb_reprintf(&conn->request, "]");
    jsonrpc_result_tail(conn, 200);
}

static void jsonrpc_get_info (char *id, struct n3n_runtime_data *eee, conn_t *conn, const char *params) {
    macstr_t mac_buf;
    n2n_sock_str_t sockbuf;

    struct in_addr ip_addr;
    ipstr_t ip_address;

    ip_addr.s_addr = eee->device.ip_addr;
    inaddrtoa(ip_address, ip_addr);

    jsonrpc_result_head(id, conn);

    sb_reprintf(&conn->request,
                "{"
                "\"version\":\"%s\","
                "\"builddate\":\"%s\","
                "\"is_edge\":%i,"
                "\"is_supernode\":%i,"
                "\"macaddr\":\"%s\","
                "\"ip4addr\":\"%s\","
                "\"sockaddr\":\"%s\"}",
                VERSION,
                BUILDDATE,
                eee->conf.is_edge,
                eee->conf.is_supernode,
                is_null_mac(eee->device.mac_addr) ? "" : macaddr_str(mac_buf, eee->device.mac_addr),
                ip_address,
                sock_to_cstr(sockbuf, &eee->conf.preferred_sock)
    );

    jsonrpc_result_tail(conn, 200);
}

static void jsonrpc_get_supernodes (char *id, struct n3n_runtime_data *eee, conn_t *conn, const char *params) {
    struct peer_info *peer, *tmpPeer;
    macstr_t mac_buf;
    n2n_sock_str_t sockbuf;
    selection_criterion_str_t sel_buf;

    jsonrpc_result_head(id, conn);
    sb_reprintf(&conn->request, "[");

    HASH_ITER(hh, eee->conf.supernodes, peer, tmpPeer) {

        /*
         * TODO:
         * The version string provided by the remote supernode could contain
         * chars that make our JSON invalid.
         * - do we care?
         */

        sb_reprintf(&conn->request,
                    "{"
                    "\"version\":\"%s\","
                    "\"purgeable\":%i,"
                    "\"current\":%i,"
                    "\"macaddr\":\"%s\","
                    "\"sockaddr\":\"%s\","
                    "\"selection\":\"%s\","
                    "\"last_seen\":%u,"
                    "\"uptime\":%u},",
                    peer->version,
                    peer->purgeable,
                    (peer == eee->curr_sn) ? (eee->sn_wait ? 2 : 1 ) : 0,
                    is_null_mac(peer->mac_addr) ? "" : macaddr_str(mac_buf, peer->mac_addr),
                    sock_to_cstr(sockbuf, &(peer->sock)),
                    sn_selection_criterion_str(eee, sel_buf, peer),
                    (uint32_t)peer->last_seen,
                    (uint32_t)peer->uptime);
    }

    // HACK: back up over the final ','
    if(conn->request->str[conn->request->wr_pos-1] == ',') {
        conn->request->wr_pos--;
    }

    sb_reprintf(&conn->request, "]");
    jsonrpc_result_tail(conn, 200);
}

static void jsonrpc_get_timestamps (char *id, struct n3n_runtime_data *eee, conn_t *conn, const char *params) {
    jsonrpc_result_head(id, conn);
    sb_reprintf(&conn->request,
                "{"
                "\"last_register_req\":%u,"
                "\"last_rx_p2p\":%u,"
                "\"last_rx_super\":%u,"
                "\"last_sweep\":%u,"
                "\"last_sn_fwd\":%u,"
                "\"last_sn_reg\":%u,"
                "\"start_time\":%u}",
                (uint32_t)eee->last_register_req,
                (uint32_t)eee->last_p2p,
                (uint32_t)eee->last_sup,
                (uint32_t)eee->last_sweep,
                (uint32_t)eee->last_sn_fwd,
                (uint32_t)eee->last_sn_reg,
                (uint32_t)eee->start_time
    );

    jsonrpc_result_tail(conn, 200);
}

static void jsonrpc_get_packetstats (char *id, struct n3n_runtime_data *eee, conn_t *conn, const char *params) {
    jsonrpc_result_head(id, conn);
    sb_reprintf(&conn->request, "[");

    sb_reprintf(&conn->request,
                "{"
                "\"type\":\"transop\","
                "\"tx_pkt\":%u,"
                "\"rx_pkt\":%u},",
                (uint32_t)eee->transop.tx_cnt,
                (uint32_t)eee->transop.rx_cnt);

    sb_reprintf(&conn->request,
                "{"
                "\"type\":\"p2p\","
                "\"tx_pkt\":%u,"
                "\"rx_pkt\":%u},",
                eee->stats.tx_p2p,
                eee->stats.rx_p2p);

    sb_reprintf(&conn->request,
                "{"
                "\"type\":\"super\","
                "\"tx_pkt\":%u,"
                "\"rx_pkt\":%u},",
                eee->stats.tx_sup,
                eee->stats.rx_sup);

    sb_reprintf(&conn->request,
                "{"
                "\"type\":\"super_broadcast\","
                "\"tx_pkt\":%u,"
                "\"rx_pkt\":%u},",
                eee->stats.tx_sup_broadcast,
                eee->stats.rx_sup_broadcast);

    sb_reprintf(&conn->request,
                "{"
                "\"type\":\"tuntap_error\","
                "\"tx_pkt\":%u},",
                eee->stats.tx_tuntap_error);

    sb_reprintf(&conn->request,
                "{"
                "\"type\":\"multicast_drop\","
                "\"tx_pkt\":%u,"
                "\"rx_pkt\":%u},",
                eee->stats.tx_multicast_drop,
                eee->stats.rx_multicast_drop);

    sb_reprintf(&conn->request,
                "{"
                "\"type\":\"sn_fwd\","
                "\"tx_pkt\":%u},",
                eee->stats.sn_fwd);

    sb_reprintf(&conn->request,
                "{"
                "\"type\":\"sn_broadcast\","
                "\"tx_pkt\":%u},",
                eee->stats.sn_broadcast);

    sb_reprintf(&conn->request,
                "{"
                "\"type\":\"sn_reg\","
                "\"tx_pkt\":%u,"
                "\"nak\":%u},",
                eee->stats.sn_reg,
                eee->stats.sn_reg_nak);

    /* Note: sn_reg_nak is not currently incremented anywhere */

    /* Generic errors when trying to sendto() */
    sb_reprintf(&conn->request,
                "{"
                "\"type\":\"sn_errors\","
                "\"tx_pkt\":%u},",
                eee->stats.sn_errors);

    // HACK: back up over the final ','
    if(conn->request->str[conn->request->wr_pos-1] == ',') {
        conn->request->wr_pos--;
    }

    sb_reprintf(&conn->request, "]");
    jsonrpc_result_tail(conn, 200);
}

#if 0
static void jsonrpc_todo (char *id, struct n3n_runtime_data *eee, conn_t *conn, const char *params) {
    jsonrpc_error(id, conn, 501, "TODO");
}
#endif

static void jsonrpc_post_test (char *id, struct n3n_runtime_data *eee, conn_t *conn, const char *params) {

    mgmt_event_post(N3N_EVENT_TEST, -1, params);

    jsonrpc_result_head(id, conn);
    sb_reprintf(&conn->request, "\"sent\"\n");
    jsonrpc_result_tail(conn, 200);
}


static void jsonrpc_reload_communities (char *id, struct n3n_runtime_data *eee, conn_t *conn, const char *params) {
    if(!auth_check(eee, conn)) {
        auth_request(conn);
        return;
    }

    int ok = load_allowed_sn_community(eee);

    jsonrpc_result_head(id, conn);
    sb_reprintf(&conn->request, "%i", ok);
    jsonrpc_result_tail(conn, 200);
}

static void jsonrpc_help_events (char *id, struct n3n_runtime_data *eee, conn_t *conn, const char *params) {
    int nr_handlers = sizeof(mgmt_events) / sizeof(mgmt_events[0]);

    jsonrpc_result_head(id, conn);
    sb_reprintf(&conn->request, "[");
    for( int topic=0; topic < nr_handlers; topic++ ) {
        int sub = mgmt_event_subscribers[topic];
        char host[40];
        char serv[6];
        host[0] = '?';
        host[1] = 0;
        serv[0] = '?';
        serv[1] = 0;

        if(sub != -1) {
            struct sockaddr_storage sa;
            socklen_t sa_size = sizeof(sa);

            if(getpeername(sub, (struct sockaddr *)&sa, &sa_size) == 0) {
                getnameinfo(
                    (struct sockaddr *)&sa, sa_size,
                    host, sizeof(host),
                    serv, sizeof(serv),
                    NI_NUMERICHOST|NI_NUMERICSERV
                );
            }
        }

        sb_reprintf(
            &conn->request,
            "{"
            "\"topic\":\"%s\","
            "\"sockaddr\":\"%s:%s\","
            "\"desc\":\"%s\"},",
            mgmt_events[topic].topic,
            host, serv,
            mgmt_events[topic].desc
        );
    }

    // HACK: back up over the final ','
    if(conn->request->str[conn->request->wr_pos-1] == ',') {
        conn->request->wr_pos--;
    }

    sb_reprintf(&conn->request, "]");
    jsonrpc_result_tail(conn, 200);
}

static void jsonrpc_help (char *id, struct n3n_runtime_data *eee, conn_t *conn, const char *params);

struct mgmt_jsonrpc_method {
    char *method;
    void (*func)(char *id, struct n3n_runtime_data *eee, conn_t *conn, const char *params);
    char *desc;
};

static const struct mgmt_jsonrpc_method jsonrpc_methods[] = {
    { "get_communities", jsonrpc_get_communities, "Show current communities" },
    { "get_edges", jsonrpc_get_edges, "List current edges/peers" },
    { "get_info", jsonrpc_get_info, "Provide basic edge information" },
    { "get_packetstats", jsonrpc_get_packetstats, "traffic counters" },
    { "get_supernodes", jsonrpc_get_supernodes, "List current supernodes" },
    { "get_timestamps", jsonrpc_get_timestamps, "Event timestamps" },
    { "get_verbose", jsonrpc_get_verbose, "Logging verbosity" },
    { "help", jsonrpc_help, "Show JsonRPC methods" },
    { "help.events", jsonrpc_help_events, "Show available event topics" },
    { "post.test", jsonrpc_post_test, "Send a test event" },
    { "reload_communities", jsonrpc_reload_communities, "Reloads communities and user's public keys" },
    { "set_verbose", jsonrpc_set_verbose, "Set logging verbosity" },
    { "stop", jsonrpc_stop, "Stop the daemon" },
    // get_last_event?
};

static void jsonrpc_help (char *id, struct n3n_runtime_data *eee, conn_t *conn, const char *params) {
    jsonrpc_result_head(id, conn);
    sb_reprintf(&conn->request, "[");

    int i;
    int nr_handlers = sizeof(jsonrpc_methods) / sizeof(jsonrpc_methods[0]);
    for( i=0; i < nr_handlers; i++ ) {
        sb_reprintf(&conn->request,
                    "{"
                    "\"method\":\"%s\","
                    "\"desc\":\"%s\"},",
                    jsonrpc_methods[i].method,
                    jsonrpc_methods[i].desc
        );

    }
    // HACK: back up over the final ','
    if(conn->request->str[conn->request->wr_pos-1] == ',') {
        conn->request->wr_pos--;
    }

    sb_reprintf(&conn->request, "]");
    jsonrpc_result_tail(conn, 200);
}

static void handle_jsonrpc (struct n3n_runtime_data *eee, conn_t *conn) {
    char *body = strstr(conn->request->str, "\r\n\r\n");
    if(!body) {
        render_error(conn, "Error: no body");
        return;
    }
    body += 4;

    jsonrpc_t json;

    if(jsonrpc_parse(body, &json) != 0) {
        render_error(conn, "Error: parsing json");
        return;
    }

    traceEvent(
        TRACE_DEBUG,
        "jsonrpc id=%s, method=%s, params=%s",
        json.id,
        json.method,
        json.params
    );

    // Since we are going to reuse the request buffer for the reply, copy
    // the id string out of it as every single reply will need it
    char idbuf[10];
    strncpy(idbuf, json.id, sizeof(idbuf)-1);

    int i;
    int nr_handlers = sizeof(jsonrpc_methods) / sizeof(jsonrpc_methods[0]);
    for( i=0; i < nr_handlers; i++ ) {
        if(!strcmp(
               jsonrpc_methods[i].method,
               json.method
           )) {
            break;
        }
    }
    if( i >= nr_handlers ) {
        render_error(conn, "Unknown method");
        return;
    } else {
        jsonrpc_methods[i].func(idbuf, eee, conn, json.params);
    }
    return;
}

static void render_todo_page (struct n3n_runtime_data *eee, conn_t *conn) {
    sb_zero(conn->request);
    sb_printf(conn->request, "TODO\n");

    // Update the reply buffer after last potential realloc
    conn->reply = conn->request;
    generate_http_headers(conn, "text/plain", 501);
}

static void render_metrics_page (struct n3n_runtime_data *eee, conn_t *conn) {
    n3n_metrics_render(&conn->request);

    // Update the reply buffer after last potential realloc
    conn->reply = conn->request;
    generate_http_headers(conn, "text/plain", 501);
}

#include "management_index.html.h"

// Generate the output for the human user interface
static void render_index_page (struct n3n_runtime_data *eee, conn_t *conn) {
    // TODO:
    // - could allow overriding of built in text with an external file
    conn->reply = &management_index;
    generate_http_headers(conn, "text/html", 200);
}

#include "management_script.js.h"

// Generate the output for the small set of javascript functions
static void render_script_page (struct n3n_runtime_data *eee, conn_t *conn) {
    conn->reply = &management_script;
    generate_http_headers(conn, "text/javascript", 200);
}

static void render_debug_slots (struct n3n_runtime_data *eee, conn_t *conn) {
    int status;
    sb_zero(conn->request);
    if(eee->conf.enable_debug_pages) {
        slots_dump(&conn->request, eee->mgmt_slots);
        status = 200;
    } else {
        sb_printf(conn->request, "enable_debug_pages is false\n");
        status = 403;
    }
    // Update the reply buffer after last potential realloc
    conn->reply = conn->request;
    generate_http_headers(conn, "text/plain", status);
}

static void render_help_page (struct n3n_runtime_data *eee, conn_t *conn);

struct mgmt_api_endpoint {
    char *match;    // when the request buffer starts with this
    void (*func)(struct n3n_runtime_data *eee, conn_t *conn);
    char *desc;
};

static const struct mgmt_api_endpoint api_endpoints[] = {
    { "POST /v1 ", handle_jsonrpc, "JsonRPC" },
    { "GET / ", render_index_page, "Human interface" },
    { "GET /debug/slots ", render_debug_slots, "Internal slots dump" },
    { "GET /events/", event_subscribe, "Subscribe to events" },
    { "GET /help ", render_help_page, "Describe available endpoints" },
    { "GET /metrics ", render_metrics_page, "Fetch metrics data" },
    { "GET /script.js ", render_script_page, "javascript helpers" },
    { "GET /status ", render_todo_page, "Quick health check" },
};

static void render_help_page (struct n3n_runtime_data *eee, conn_t *conn) {
    // Reuse the request buffer
    sb_zero(conn->request);
    sb_reprintf(&conn->request, "endpoint, desc\n");

    int i;
    int nr_handlers = sizeof(api_endpoints) / sizeof(api_endpoints[0]);
    for( i=0; i < nr_handlers; i++ ) {
        sb_reprintf(
            &conn->request,
            "%s, %s\n",
            api_endpoints[i].match,
            api_endpoints[i].desc
        );
    }

    // Update the reply buffer only after last potential realloc
    conn->reply = conn->request;

    generate_http_headers(conn, "text/plain", 200);
}

void mgmt_api_handler (struct n3n_runtime_data *eee, conn_t *conn) {
    int i;
    int nr_handlers = sizeof(api_endpoints) / sizeof(api_endpoints[0]);
    for( i=0; i < nr_handlers; i++ ) {
        if(!strncmp(
               api_endpoints[i].match,
               conn->request->str,
               strlen(api_endpoints[i].match))) {
            break;
        }
    }
    if( i >= nr_handlers ) {
        render_error(conn, "unknown endpoint");
    } else {
        api_endpoints[i].func(eee, conn);
    }

    // Try to immediately start sending the reply
    conn_write(conn);
}
