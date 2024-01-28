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
#include <n3n/strings.h> // for ip_subnet_to_str, sock_to_cstr
#include <pearson.h>     // for pearson_hash_64
#include <sn_selection.h> // for sn_selection_criterion_str
#include <stdbool.h>
#include <stdio.h>       // for snprintf, NULL, size_t
#include <stdlib.h>      // for strtoul
#include <string.h>      // for strtok, strlen, strncpy
#include "management.h"
#include "peer_info.h"   // for peer_info

#ifdef _WIN32
#include "win32/defs.h"
#else
#include <netdb.h>       // for getnameinfo, NI_NUMERICHOST, NI_NUMERICSERV
#include <sys/socket.h>  // for sendto, sockaddr
#endif


ssize_t send_reply (mgmt_req_t *req, strbuf_t *buf) {
    // TODO: better error handling (counters?)
    return sendto(req->mgmt_sock, buf->str, buf->wr_pos, 0,
                  &req->sender_sock, req->sock_len);
}

size_t gen_json_1str (strbuf_t *buf, char *tag, char *_type, char *key, char *val) {
    return sb_printf(buf,
                     "{"
                     "\"_tag\":\"%s\","
                     "\"_type\":\"%s\","
                     "\"%s\":\"%s\"}\n",
                     tag,
                     _type,
                     key,
                     val);
}

size_t gen_json_1uint (strbuf_t *buf, char *tag, char *_type, char *key, unsigned int val) {
    return sb_printf(buf,
                     "{"
                     "\"_tag\":\"%s\","
                     "\"_type\":\"%s\","
                     "\"%s\":%u}\n",
                     tag,
                     _type,
                     key,
                     val);
}

void send_json_1str (mgmt_req_t *req, strbuf_t *buf, char *_type, char *key, char *val) {
    gen_json_1str(buf, req->tag, _type, key, val);
    send_reply(req, buf);
}

void send_json_1uint (mgmt_req_t *req, strbuf_t *buf, char *_type, char *key, unsigned int val) {
    gen_json_1uint(buf, req->tag, _type, key, val);
    send_reply(req, buf);
}

void mgmt_error (mgmt_req_t *req, strbuf_t *buf, char *msg) {
    send_json_1str(req, buf, "error", "error", msg);
}

void mgmt_stop (mgmt_req_t *req, strbuf_t *buf) {

    if(req->type==N2N_MGMT_WRITE) {
        *req->keep_running = false;
    }

    send_json_1uint(req, buf, "row", "keep_running", *req->keep_running);
}

void mgmt_verbose (mgmt_req_t *req, strbuf_t *buf) {

    if(req->type==N2N_MGMT_WRITE) {
        if(req->argv) {
            setTraceLevel(strtoul(req->argv, NULL, 0));
        }
    }

    send_json_1uint(req, buf, "row", "traceLevel", getTraceLevel());
}

void mgmt_unimplemented (mgmt_req_t *req, strbuf_t *buf) {

    mgmt_error(req, buf, "unimplemented");
}

void mgmt_event_post2 (enum n2n_event_topic topic, int data0, void *data1, mgmt_req_t *debug, mgmt_req_t *sub, mgmt_event_handler_t fn) {
    traceEvent(TRACE_DEBUG, "post topic=%i data0=%i", topic, data0);

    if( sub->type != N2N_MGMT_SUB && debug->type != N2N_MGMT_SUB) {
        // If neither of this topic or the debug topic have a subscriber
        // then we dont need to do any work
        return;
    }

    char buf_space[100];
    strbuf_t *buf;
    STRBUF_INIT(buf, buf_space);

    char *tag;
    if(sub->type == N2N_MGMT_SUB) {
        tag = sub->tag;
    } else {
        tag = debug->tag;
    }

    fn(buf, tag, data0, data1);

    if(sub->type == N2N_MGMT_SUB) {
        send_reply(sub, buf);
    }
    if(debug->type == N2N_MGMT_SUB) {
        send_reply(debug, buf);
    }
    // TODO:
    // - ideally, we would detect that the far end has gone away and
    //   set the ->type back to N2N_MGMT_UNKNOWN, but we are not using
    //   a connected socket, so that is difficult
    // - failing that, we should require the client to send an unsubscribe
    //   and provide a manual unsubscribe
}

void mgmt_help_row (mgmt_req_t *req, strbuf_t *buf, char *cmd, char *help) {
    sb_printf(buf,
              "{"
              "\"_tag\":\"%s\","
              "\"_type\":\"row\","
              "\"cmd\":\"%s\","
              "\"help\":\"%s\"}\n",
              req->tag,
              cmd,
              help);

    send_reply(req, buf);
}

void mgmt_help_events_row (mgmt_req_t *req, strbuf_t *buf, mgmt_req_t *sub, char *cmd, char *help) {
    char host[40];
    char serv[6];

    if((sub->type != N2N_MGMT_SUB) ||
       getnameinfo((struct sockaddr *)&sub->sender_sock, sizeof(sub->sender_sock),
                   host, sizeof(host),
                   serv, sizeof(serv),
                   NI_NUMERICHOST|NI_NUMERICSERV) != 0) {
        host[0] = '?';
        host[1] = 0;
        serv[0] = '?';
        serv[1] = 0;
    }

    // TODO: handle a topic with no subscribers more cleanly

    sb_printf(buf,
              "{"
              "\"_tag\":\"%s\","
              "\"_type\":\"row\","
              "\"topic\":\"%s\","
              "\"tag\":\"%s\","
              "\"sockaddr\":\"%s:%s\","
              "\"help\":\"%s\"}\n",
              req->tag,
              cmd,
              sub->tag,
              host, serv,
              help);

    send_reply(req, buf);
}

// TODO: work out a method to keep the mgmt_handlers defintion const static,
// and then import the shared mgmt_help () definition to this file

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

/*
 * Handle the common and shred parts of the mgmt_req_t initialisation
 */
bool mgmt_req_init2 (mgmt_req_t *req, strbuf_t *buf, char *cmdline) {
    char *typechar;
    char *options;
    char *flagstr;
    int flags;
    char *auth;

    /* Initialise the tag field until we extract it from the cmdline */
    req->tag[0] = '-';
    req->tag[1] = '1';
    req->tag[2] = '\0';

    typechar = strtok(cmdline, " \r\n");
    if(!typechar) {
        /* should not happen */
        mgmt_error(req, buf, "notype");
        return false;
    }
    if(*typechar == 'r') {
        req->type=N2N_MGMT_READ;
    } else if(*typechar == 'w') {
        req->type=N2N_MGMT_WRITE;
    } else if(*typechar == 's') {
        req->type=N2N_MGMT_SUB;
    } else {
        mgmt_error(req, buf, "badtype");
        return false;
    }

    /* Extract the tag to use in all reply packets */
    options = strtok(NULL, " \r\n");
    if(!options) {
        mgmt_error(req, buf, "nooptions");
        return false;
    }

    req->argv0 = strtok(NULL, " \r\n");
    if(!req->argv0) {
        mgmt_error(req, buf, "nocmd");
        return false;
    }

    /*
     * The entire rest of the line is the argv. We apply no processing
     * or arg separation so that the cmd can use it however it needs.
     */
    req->argv = strtok(NULL, "\r\n");

    /*
     * There might be an auth token mixed in with the tag
     */
    char *tagp = strtok(options, ":");
    strncpy(req->tag, tagp, sizeof(req->tag)-1);
    req->tag[sizeof(req->tag)-1] = '\0';

    flagstr = strtok(NULL, ":");
    if(flagstr) {
        flags = strtoul(flagstr, NULL, 16);
    } else {
        flags = 0;
    }

    /* Only 1 flag bit defined at the moment - "auth option present" */
    if(flags & 1) {
        auth = strtok(NULL, ":");
    } else {
        auth = NULL;
    }

    if(!mgmt_auth(req, auth)) {
        mgmt_error(req, buf, "badauth");
        return false;
    }

    return true;
}

static void generate_http_headers (conn_t *conn, const char *type, int code) {
    strbuf_t **pp = &conn->reply_header;
    sb_reprintf(pp, "HTTP/1.1 %i result\r\n", code);
    // TODO:
    // - caching
    int len = sb_len(conn->reply);
    sb_reprintf(pp, "Content-Type: %s\r\n", type);
    sb_reprintf(pp, "Content-Length: %i\r\n\r\n", len);
}

static void jsonrpc_error (char *id, conn_t *conn, int code, char *message) {
    // Reuse the request buffer
    conn->reply = conn->request;
    sb_zero(conn->reply);

    strbuf_t **pp = &conn->reply;
    sb_reprintf(
        pp,
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


    generate_http_headers(conn, "application/json", code);
}

static void jsonrpc_result_head (char *id, conn_t *conn) {
    // Reuse the request buffer
    conn->reply = conn->request;
    sb_zero(conn->reply);

    sb_reprintf(
        &conn->reply,
        "{"
        "\"jsonrpc\":\"2.0\","
        "\"id\":\"%s\","
        "\"result\":",
        id
        );
}

static void jsonrpc_result_tail (conn_t *conn, int code) {
    strbuf_t **pp = &conn->reply;
    sb_reprintf(pp, "}");
    generate_http_headers(conn, "application/json", code);
}

static void jsonrpc_1uint (char *id, conn_t *conn, uint32_t result) {
    jsonrpc_result_head(id, conn);
    sb_reprintf(&conn->reply, "%u", result);
    jsonrpc_result_tail(conn, 200);
}

static void jsonrpc_1str (char *id, conn_t *conn, char *result) {
    jsonrpc_result_head(id, conn);
    sb_reprintf(&conn->reply, "\"%s\"", result);
    jsonrpc_result_tail(conn, 200);
}

static void jsonrpc_get_verbose (char *id, n2n_edge_t *eee, conn_t *conn) {
    jsonrpc_1uint(id, conn, getTraceLevel());
}

static void jsonrpc_get_community (char *id, n2n_edge_t *eee, conn_t *conn) {
    if(eee->conf.header_encryption != HEADER_ENCRYPTION_NONE) {
        jsonrpc_error(id, conn, 403, "Forbidden");
        return;
    }

    jsonrpc_1str(id, conn, (char *)eee->conf.community_name);
}

static void jsonrpc_get_edges_row (strbuf_t **reply, struct peer_info *peer, char *mode) {
    macstr_t mac_buf;
    n2n_sock_str_t sockbuf;
    dec_ip_bit_str_t ip_bit_str = {'\0'};

    sb_reprintf(reply,
                "{"
                "\"mode\":\"%s\","
                "\"ip4addr\":\"%s\","
                "\"purgeable\":%i,"
                "\"local\":%i,"
                "\"macaddr\":\"%s\","
                "\"sockaddr\":\"%s\","
                "\"desc\":\"%s\","
                "\"last_p2p\":%li,"
                "\"last_sent_query\":%li,"
                "\"last_seen\":%li},",
                mode,
                (peer->dev_addr.net_addr == 0) ? "" : ip_subnet_to_str(ip_bit_str, &peer->dev_addr),
                peer->purgeable,
                peer->local,
                (is_null_mac(peer->mac_addr)) ? "" : macaddr_str(mac_buf, peer->mac_addr),
                sock_to_cstr(sockbuf, &(peer->sock)),
                peer->dev_desc,
                peer->last_p2p,
                peer->last_sent_query,
                peer->last_seen
                );
}

static void jsonrpc_get_edges (char *id, n2n_edge_t *eee, conn_t *conn) {
    struct peer_info *peer, *tmpPeer;

    jsonrpc_result_head(id, conn);
    sb_reprintf(&conn->reply, "[");

    // dump nodes with forwarding through supernodes
    HASH_ITER(hh, eee->pending_peers, peer, tmpPeer) {
        jsonrpc_get_edges_row(&conn->reply, peer, "pSp");
    }

    // dump peer-to-peer nodes
    HASH_ITER(hh, eee->known_peers, peer, tmpPeer) {
        jsonrpc_get_edges_row(&conn->reply, peer, "p2p");
    }

    // back up over the final ','
    conn->reply->wr_pos--;

    sb_reprintf(&conn->reply, "]");
    jsonrpc_result_tail(conn, 200);
}

static void jsonrpc_get_supernodes (char *id, n2n_edge_t *eee, conn_t *conn) {
    struct peer_info *peer, *tmpPeer;
    macstr_t mac_buf;
    n2n_sock_str_t sockbuf;
    selection_criterion_str_t sel_buf;

    jsonrpc_result_head(id, conn);
    sb_reprintf(&conn->reply, "[");

    HASH_ITER(hh, eee->conf.supernodes, peer, tmpPeer) {

        /*
         * TODO:
         * The version string provided by the remote supernode could contain
         * chars that make our JSON invalid.
         * - do we care?
         */

        sb_reprintf(&conn->reply,
                    "{"
                    "\"version\":\"%s\","
                    "\"purgeable\":%i,"
                    "\"current\":%i,"
                    "\"macaddr\":\"%s\","
                    "\"sockaddr\":\"%s\","
                    "\"selection\":\"%s\","
                    "\"last_seen\":%li,"
                    "\"uptime\":%li},",
                    peer->version,
                    peer->purgeable,
                    (peer == eee->curr_sn) ? (eee->sn_wait ? 2 : 1 ) : 0,
                    is_null_mac(peer->mac_addr) ? "" : macaddr_str(mac_buf, peer->mac_addr),
                    sock_to_cstr(sockbuf, &(peer->sock)),
                    sn_selection_criterion_str(eee, sel_buf, peer),
                    peer->last_seen,
                    peer->uptime);
    }

    // back up over the final ','
    conn->reply->wr_pos--;

    sb_reprintf(&conn->reply, "]");
    jsonrpc_result_tail(conn, 200);
}

static void jsonrpc_get_timestamps (char *id, n2n_edge_t *eee, conn_t *conn) {
    jsonrpc_result_head(id, conn);
    sb_reprintf(&conn->reply,
                "{"
                "\"start_time\":%lu,"
                "\"last_super\":%ld,"
                "\"last_p2p\":%ld}\n",
                eee->start_time,
                eee->last_sup,
                eee->last_p2p);

    jsonrpc_result_tail(conn, 200);
}

static void jsonrpc_get_packetstats (char *id, n2n_edge_t *eee, conn_t *conn) {
    jsonrpc_result_head(id, conn);
    sb_reprintf(&conn->reply, "[");
    sb_reprintf(&conn->reply,
                "{"
                "\"type\":\"transop\","
                "\"tx_pkt\":%lu,"
                "\"rx_pkt\":%lu},",
                eee->transop.tx_cnt,
                eee->transop.rx_cnt);

    sb_reprintf(&conn->reply,
                "{"
                "\"type\":\"p2p\","
                "\"tx_pkt\":%u,"
                "\"rx_pkt\":%u},",
                eee->stats.tx_p2p,
                eee->stats.rx_p2p);

    sb_reprintf(&conn->reply,
                "{"
                "\"type\":\"super\","
                "\"tx_pkt\":%u,"
                "\"rx_pkt\":%u},",
                eee->stats.tx_sup,
                eee->stats.rx_sup);

    sb_reprintf(&conn->reply,
                "{"
                "\"type\":\"super_broadcast\","
                "\"tx_pkt\":%u,"
                "\"rx_pkt\":%u},",
                eee->stats.tx_sup_broadcast,
                eee->stats.rx_sup_broadcast);

    sb_reprintf(&conn->reply,
                "{"
                "\"type\":\"tuntap_error\","
                "\"tx_pkt\":%u,"
                "\"rx_pkt\":%u},",
                eee->stats.tx_tuntap_error,
                eee->stats.rx_tuntap_error);

    sb_reprintf(&conn->reply,
                "{"
                "\"type\":\"multicast_drop\","
                "\"tx_pkt\":%u,"
                "\"rx_pkt\":%u},",
                eee->stats.tx_multicast_drop,
                eee->stats.rx_multicast_drop);

    // back up over the final ','
    conn->reply->wr_pos--;

    sb_reprintf(&conn->reply, "]");
    jsonrpc_result_tail(conn, 200);
}

static void jsonrpc_todo (char *id, n2n_edge_t *eee, conn_t *conn) {
    jsonrpc_error(id, conn, 501, "TODO");
}

struct mgmt_jsonrpc_method {
    char *method;
    void (*func)(char *id, n2n_edge_t *eee, conn_t *conn);
    char *desc;
};

static const struct mgmt_jsonrpc_method jsonrpc_methods[] = {
    { "get_community", jsonrpc_get_community },
    { "get_edges", jsonrpc_get_edges },
    { "get_packetstats", jsonrpc_get_packetstats },
    { "get_supernodes", jsonrpc_get_supernodes },
    { "get_timestamps", jsonrpc_get_timestamps },
    { "get_verbose", jsonrpc_get_verbose },
    { "set_verbose", jsonrpc_todo },
};

static void render_error (n2n_edge_t *eee, conn_t *conn) {
    // Reuse the request buffer
    conn->reply = conn->request;
    sb_zero(conn->reply);
    sb_printf(conn->reply, "api error\n");

    generate_http_headers(conn, "text/plain", 404);
}

static void handle_jsonrpc (n2n_edge_t *eee, conn_t *conn) {
    char *body = strstr(conn->request->str, "\r\n\r\n");
    if(!body) {
        // "Error: no body"
        goto error;
    }
    body += 4;

    jsonrpc_t json;

    if(jsonrpc_parse(body, &json) != 0) {
        // "Error: parsing json"
        goto error;
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
        if(!strncmp(
               jsonrpc_methods[i].method,
               json.method,
               strlen(jsonrpc_methods[i].method))) {
            break;
        }
    }
    if( i >= nr_handlers ) {
        // "Unknown method
        goto error;
    } else {
        jsonrpc_methods[i].func(idbuf, eee, conn);
    }
    return;

error:
    render_error(eee, conn);
}

static void render_todo_page (n2n_edge_t *eee, conn_t *conn) {
    // Reuse the request buffer
    conn->reply = conn->request;
    sb_zero(conn->reply);
    sb_printf(conn->reply, "TODO\n");

    generate_http_headers(conn, "text/plain", 501);
}

#include "management_index.html.h"

// Generate the output for the human user interface
static void render_index_page (n2n_edge_t *eee, conn_t *conn) {
    // TODO:
    // - could allow overriding of built in text with an external file
    // - there is a race condition if multiple users are fetching the
    //   page and have partial writes (same for render_script_page)
    conn->reply = &management_index;
    generate_http_headers(conn, "text/html", 200);
}

#include "management_script.js.h"

// Generate the output for the small set of javascript functions
static void render_script_page (n2n_edge_t *eee, conn_t *conn) {
    conn->reply = &management_script;
    generate_http_headers(conn, "text/javascript", 200);
}

struct mgmt_api_endpoint {
    char *match;    // when the request buffer starts with this
    void (*func)(n2n_edge_t *eee, conn_t *conn);
    char *desc;
};

static const struct mgmt_api_endpoint api_endpoints[] = {
    { "POST /v1 ", handle_jsonrpc, "JsonRPC" },
    { "GET / ", render_index_page, "Human interface" },
    { "GET /help ", render_todo_page, "Describe available endpoints" },
    { "GET /metrics ", render_todo_page, "Fetch metrics data" },
    { "GET /script.js ", render_script_page, "javascript helpers" },
    { "GET /status ", render_todo_page, "Quick health check" },
};

void mgmt_api_handler (n2n_edge_t *eee, conn_t *conn) {
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
        render_error(eee, conn);
    } else {
        api_endpoints[i].func(eee, conn);
    }

    // Try to immediately start sending the reply
    conn_write(conn);
}
