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


#include <connslot/connslot.h>
#include <errno.h>              // for errno, EAFNOSUPPORT
#include <n3n/ethernet.h>       // for is_null_mac
#include <n3n/logging.h>        // for traceEvent
#include <n3n/random.h>         // for n3n_rand, n3n_rand_sqr
#include <n3n/strings.h>        // for ip_subnet_to_str, sock_to_cstr
#include <n3n/supernode.h>      // for load_allowed_sn_community, calculate_...
#include <stdbool.h>
#include <stdint.h>             // for uint8_t, uint32_t, uint16_t, uint64_t
#include <stdio.h>              // for sscanf, snprintf, fclose, fgets, fopen
#include <stdlib.h>             // for free, calloc, getenv
#include <string.h>             // for memcpy, NULL, memset, size_t, strerror
#include <sys/param.h>          // for MAX
#include <time.h>               // for time_t, time
#include <unistd.h>

#include "auth.h"               // for ascii_to_bin, calculate_dynamic_key
#include "header_encryption.h"  // for packet_header_encrypt, packet_header_...
#include "management.h"         // for process_mgmt
#include "minmax.h"                  // for MIN, MAX
#include "n2n.h"                // for sn_community, n3n_runtime_data
#include "n2n_define.h"
#include "n2n_regex.h"          // for re_matchp, re_compile
#include "n2n_typedefs.h"
#include "n2n_wire.h"           // for encode_buf, encode_PEER_INFO, encode_...
#include "pearson.h"            // for pearson_hash_128, pearson_hash_32
#include "peer_info.h"          // for purge_peer_list, clear_peer_list
#include "portable_endian.h"    // for be16toh, htobe16
#include "resolve.h"            // for resolve_create_thread, resolve_cancel...
#include "sn_selection.h"       // for sn_selection_criterion_gather_data
#include "speck.h"              // for speck_128_encrypt, speck_context_t
#include "uthash.h"             // for UT_hash_handle, HASH_ITER, HASH_DEL

#ifdef _WIN32
#include "win32/defs.h"

#include <direct.h>             // for _rmdir
#else
#include <arpa/inet.h>          // for inet_addr, inet_ntoa
#include <netinet/in.h>         // for ntohl, in_addr_t, sockaddr_in, INADDR...
#include <netinet/tcp.h>        // for TCP_NODELAY
#include <pwd.h>
#include <sys/select.h>         // for FD_ISSET, FD_SET, select, FD_SETSIZE
#include <sys/socket.h>         // for recvfrom, shutdown, sockaddr_storage
#endif

#ifndef _WIN32
// Another wonderful gift from the world of POSIX compliance is not worth much
#define closesocket(a) close(a)
#endif


#define HASH_FIND_COMMUNITY(head, name, out) HASH_FIND_STR(head, name, out)

static ssize_t sendto_peer (struct n3n_runtime_data *sss,
                            const struct peer_info *peer,
                            const uint8_t *pktbuf,
                            size_t pktsize);

static uint16_t reg_lifetime (struct n3n_runtime_data *sss);

static int update_edge (struct n3n_runtime_data *sss,
                        const n2n_common_t* cmn,
                        const n2n_REGISTER_SUPER_t* reg,
                        struct sn_community *comm,
                        const n2n_sock_t *sender_sock,
                        const SOCKET socket_fd,
                        n2n_auth_t *answer_auth,
                        int skip_add,
                        time_t now);

static int re_register_and_purge_supernodes (struct n3n_runtime_data *sss,
                                             struct sn_community *comm,
                                             time_t *p_last_re_reg_and_purge,
                                             time_t now,
                                             uint8_t forced);

static int purge_expired_communities (struct n3n_runtime_data *sss,
                                      time_t* p_last_purge,
                                      time_t now);

static int sort_communities (struct n3n_runtime_data *sss,
                             time_t* p_last_sort,
                             time_t now);

/* ************************************** */


void close_tcp_connection (struct n3n_runtime_data *sss, n2n_tcp_connection_t *conn) {

    struct sn_community *comm, *tmp_comm;
    struct peer_info *edge, *tmp_edge;

    if(!conn)
        return;

    // find peer by file descriptor
    HASH_ITER(hh, sss->communities, comm, tmp_comm) {
        HASH_ITER(hh, comm->edges, edge, tmp_edge) {
            if(edge->socket_fd == conn->socket_fd) {
                // remove peer
                HASH_DEL(comm->edges, edge);
                peer_info_free(edge);
                goto close_conn; /* break - level 2 */
            }
        }
    }

close_conn:
    // close the connection
    shutdown(conn->socket_fd, SHUT_RDWR);
    closesocket(conn->socket_fd);
    // forget about the connection, will be deleted later
    conn->inactive = 1;
}


/* *************************************************** */


// generate shared secrets for user authentication; can be done only after
// federation name is known and community list completely read
void calculate_shared_secrets (struct n3n_runtime_data *sss) {

    struct sn_community *comm, *tmp_comm;
    sn_user_t *user, *tmp_user;

    traceEvent(TRACE_INFO, "started shared secrets calculation for edge authentication");

    generate_private_key(sss->private_key, sss->federation->community + 1); /* skip '*' federation leading character */
    HASH_ITER(hh, sss->communities, comm, tmp_comm) {
        if(comm->is_federation) {
            continue;
        }
        HASH_ITER(hh, comm->allowed_users, user, tmp_user) {
            // calculate common shared secret (ECDH)
            generate_shared_secret(user->shared_secret, sss->private_key, user->public_key);
            // prepare for use as key
            speck_init((speck_context_t**)&user->shared_secret_ctx, user->shared_secret, 128);
        }
    }

    traceEvent(TRACE_INFO, "calculated shared secrets for edge authentication");
}


// calculate dynamic keys
void calculate_dynamic_keys (struct n3n_runtime_data *sss) {

    struct sn_community *comm, *tmp_comm = NULL;

    traceEvent(TRACE_INFO, "calculating dynamic keys");
    HASH_ITER(hh, sss->communities, comm, tmp_comm) {
        // skip federation
        if(comm->is_federation) {
            continue;
        }

        // calculate dynamic keys if this is a user/pw auth'ed community
        if(comm->allowed_users) {
            calculate_dynamic_key(comm->dynamic_key,           /* destination */
                                  sss->dynamic_key_time,       /* time - same for all */
                                  comm->community,  /* community name */
                                  sss->federation->community); /* federation name */
            packet_header_change_dynamic_key(comm->dynamic_key,
                                             &(comm->header_encryption_ctx_dynamic),
                                             &(comm->header_iv_ctx_dynamic));
            traceEvent(TRACE_DEBUG, "calculated dynamic key for community '%s'", comm->community);
        }
    }
}


// send RE_REGISTER_SUPER to all edges from user/pw auth'ed communites
void send_re_register_super (struct n3n_runtime_data *sss) {

    struct sn_community *comm, *tmp_comm = NULL;
    struct peer_info *edge, *tmp_edge = NULL;
    n2n_common_t cmn;
    uint8_t rereg_buf[N2N_SN_PKTBUF_SIZE];
    size_t encx = 0;
    n2n_sock_str_t sockbuf;

    HASH_ITER(hh, sss->communities, comm, tmp_comm) {
        if(comm->is_federation) {
            continue;
        }

        // send RE_REGISTER_SUPER to edges if this is a user/pw auth community
        if(comm->allowed_users) {
            // prepare
            cmn.ttl = N2N_DEFAULT_TTL;
            cmn.pc = MSG_TYPE_RE_REGISTER_SUPER;
            cmn.flags = N2N_FLAGS_FROM_SUPERNODE;
            memcpy(cmn.community, comm->community, N2N_COMMUNITY_SIZE);

            HASH_ITER(hh, comm->edges, edge, tmp_edge) {
                // encode
                encx = 0;
                encode_common(rereg_buf, &encx, &cmn);

                // send
                traceEvent(TRACE_DEBUG, "send RE_REGISTER_SUPER to %s",
                           sock_to_cstr(sockbuf, &(edge->sock)));

                packet_header_encrypt(rereg_buf, encx, encx,
                                      comm->header_encryption_ctx_dynamic, comm->header_iv_ctx_dynamic,
                                      time_stamp());

                /* sent = */ sendto_peer(sss, edge, rereg_buf, encx);
            }
        }
    }
}


/** Load the list of allowed communities. Existing/previous ones will be removed,
 *  return 0 on success, -1 if file not found, -2 if no valid entries found
 */
int load_allowed_sn_community (struct n3n_runtime_data *sss) {

    char buffer[4096], *line, *cmn_str, net_str[20], format[20];

    sn_user_t *user, *tmp_user;
    n2n_desc_t username;
    n2n_private_public_key_t public_key;
    char ascii_public_key[(N2N_PRIVATE_PUBLIC_KEY_SIZE * 8 + 5) / 6 + 1];

    dec_ip_str_t ip_str = {'\0'};
    uint8_t bitlen;
    in_addr_t net;
    uint32_t mask;
    FILE *fd = fopen(sss->conf.community_file, "r");

    struct sn_community *comm, *tmp_comm, *last_added_comm = NULL;
    struct peer_info *edge, *tmp_edge;
    node_supernode_association_t *assoc, *tmp_assoc;
    n2n_tcp_connection_t *conn;
    time_t any_time = 0;

    uint32_t num_communities = 0;

    struct sn_community_regular_expression *re, *tmp_re;
    uint32_t num_regex = 0;
    int has_net;

    if(fd == NULL) {
        traceEvent(TRACE_WARNING, "File %s not found", sss->conf.community_file);
        return -1;
    }

    // reset data structures ------------------------------

    // send RE_REGISTER_SUPER to all edges from user/pw auth communites, this is safe because
    // follow-up REGISTER_SUPER cannot be handled before this function ends
    send_re_register_super(sss);

    // remove communities (not: federation)
    HASH_ITER(hh, sss->communities, comm, tmp_comm) {
        if(comm->is_federation) {
            continue;
        }

        // remove all edges from community
        HASH_ITER(hh, comm->edges, edge, tmp_edge) {
            // remove all edge associations (with other supernodes)
            HASH_ITER(hh, comm->assoc, assoc, tmp_assoc) {
                HASH_DEL(comm->assoc, assoc);
                free(assoc);
            }

            // close TCP connections, if any (also causes reconnect)
            // and delete edge from list
            if((edge->socket_fd != sss->sock) && (edge->socket_fd >= 0)) {
                HASH_FIND_INT(sss->tcp_connections, &(edge->socket_fd), conn);
                close_tcp_connection(sss, conn); /* also deletes the edge */
            } else {
                HASH_DEL(comm->edges, edge);
                peer_info_free(edge);
            }
        }

        // remove allowed users from community
        HASH_ITER(hh, comm->allowed_users, user, tmp_user) {
            speck_deinit((speck_context_t*)user->shared_secret_ctx);
            HASH_DEL(comm->allowed_users, user);
            free(user);
        }

        // remove community
        HASH_DEL(sss->communities, comm);
        // remove header encryption keys
        free(comm->header_encryption_ctx_static);
        free(comm->header_iv_ctx_static);
        free(comm->header_encryption_ctx_dynamic);
        free(comm->header_iv_ctx_dynamic);
        free(comm);
    }

    // remove all regular expressions for allowed communities
    HASH_ITER(hh, sss->rules, re, tmp_re) {
        HASH_DEL(sss->rules, re);
        free(re);
    }

    // prepare reading data -------------------------------

    // new key_time for all communities, requires dynamic keys to be recalculated (see further below),
    // and  edges to re-register (see above) and ...
    sss->dynamic_key_time = time(NULL);
    // ... federated supernodes to re-register
    re_register_and_purge_supernodes(sss, sss->federation, &any_time, any_time, 1 /* forced */);

    // format definition for possible user-key entries
    sprintf(
        format,
        "%c %%%ds %%%us",
        N2N_USER_KEY_LINE_STARTER,
        N2N_DESC_SIZE - 1,
        (uint32_t)sizeof(ascii_public_key)-1
    );

    while((line = fgets(buffer, sizeof(buffer), fd)) != NULL) {
        int len = strlen(line);

        if((len < 2) || line[0] == '#') {
            continue;
        }

        len--;
        while(len > 0) {
            if((line[len] == '\n') || (line[len] == '\r')) {
                line[len] = '\0';
                len--;
            } else {
                break;
            }
        }
        // the loop above does not always determine correct 'len'
        len = strlen(line);

        // user-key line for edge authentication?
        if(line[0] == N2N_USER_KEY_LINE_STARTER) { /* special first character */
            if(sscanf(line, format, username, ascii_public_key) == 2) { /* correct format */
                if(last_added_comm) { /* is there a valid community to add users to */
                    user = (sn_user_t*)calloc(1, sizeof(sn_user_t));
                    if(user) {
                        // username
                        memcpy(user->name, username, sizeof(username));
                        // public key
                        ascii_to_bin(public_key, ascii_public_key);
                        memcpy(user->public_key, public_key, sizeof(public_key));
                        // common shared secret will be calculated later
                        // add to list
                        HASH_ADD(hh, last_added_comm->allowed_users, public_key, sizeof(n2n_private_public_key_t), user);
                        traceEvent(TRACE_INFO, "added user '%s' with public key '%s' to community '%s'",
                                   user->name, ascii_public_key, last_added_comm->community);
                        // enable header encryption
                        last_added_comm->header_encryption = HEADER_ENCRYPTION_ENABLED;
                        packet_header_setup_key(last_added_comm->community,
                                                &(last_added_comm->header_encryption_ctx_static),
                                                &(last_added_comm->header_encryption_ctx_dynamic),
                                                &(last_added_comm->header_iv_ctx_static),
                                                &(last_added_comm->header_iv_ctx_dynamic));
                        // dynamic key setup follows at a later point in code
                    }
                    continue;
                }
            }
        }

        // --- community name or regular expression

        // cut off any IP sub-network upfront
        cmn_str = (char*)calloc(len + 1, sizeof(char));
        has_net = (sscanf(line, "%s %s", cmn_str, net_str) == 2);

        // if it contains typical characters...
        if(NULL != strpbrk(cmn_str, ".*+?[]\\")) {
            // ...it is treated as regular expression
            re = (struct sn_community_regular_expression*)calloc(1, sizeof(struct sn_community_regular_expression));
            if(re) {
                re->rule = re_compile(cmn_str);
                HASH_ADD_PTR(sss->rules, rule, re);
                num_regex++;
                traceEvent(TRACE_INFO, "added regular expression for allowed communities '%s'", cmn_str);
                free(cmn_str);
                last_added_comm = NULL;
                continue;
            }
        }

        comm = (struct sn_community*)calloc(1,sizeof(struct sn_community));

        if(comm != NULL) {
            comm_init(comm, cmn_str);
            /* loaded from file, this community is unpurgeable */
            comm->purgeable = false;
            /* we do not know if header encryption is used in this community,
             * first packet will show. just in case, setup the key. */
            comm->header_encryption = HEADER_ENCRYPTION_UNKNOWN;
            packet_header_setup_key(comm->community,
                                    &(comm->header_encryption_ctx_static),
                                    &(comm->header_encryption_ctx_dynamic),
                                    &(comm->header_iv_ctx_static),
                                    &(comm->header_iv_ctx_dynamic));
            HASH_ADD_STR(sss->communities, community, comm);
            last_added_comm = comm;

            num_communities++;
            traceEvent(TRACE_INFO, "added allowed community '%s' [total: %u]",
                       (char*)comm->community, num_communities);

            // check for sub-network address
            if(has_net) {
                if(sscanf(net_str, "%15[^/]/%hhu", ip_str, &bitlen) != 2) {
                    traceEvent(TRACE_WARNING, "bad net/bit format '%s' for community '%c', ignoring; see comments inside community.list file",
                               net_str, cmn_str);
                    has_net = 0;
                }
                net = inet_addr(ip_str);
                mask = bitlen2mask(bitlen);
                if((net == (in_addr_t)(-1)) || (net == INADDR_NONE) || (net == INADDR_ANY)
                   || ((ntohl(net) & ~mask) != 0)) {
                    traceEvent(TRACE_WARNING, "bad network '%s/%u' in '%s' for community '%s', ignoring",
                               ip_str, bitlen, net_str, cmn_str);
                    has_net = 0;
                }
                if((bitlen > 30) || (bitlen == 0)) {
                    traceEvent(TRACE_WARNING, "bad prefix '%hhu' in '%s' for community '%s', ignoring",
                               bitlen, net_str, cmn_str);
                    has_net = 0;
                }
            }
            if(has_net) {
                comm->auto_ip_net.net_addr = ntohl(net);
                comm->auto_ip_net.net_bitlen = bitlen;
                struct in_addr *tmp = (struct in_addr *)&net;
                traceEvent(TRACE_INFO, "assigned sub-network %s/%u to community '%s'",
                           inet_ntoa(*tmp),
                           comm->auto_ip_net.net_bitlen,
                           comm->community);
            } else {
                assign_one_ip_subnet(sss, comm);
            }
        }
        free(cmn_str);
    }

    fclose(fd);

    if((num_regex + num_communities) == 0) {
        traceEvent(TRACE_WARNING, "file %s does not contain any valid community names or regular expressions", sss->conf.community_file);
        return -2;
    }

    traceEvent(TRACE_NORMAL, "loaded %u fixed-name communities from %s",
               num_communities, sss->conf.community_file);

    traceEvent(TRACE_NORMAL, "loaded %u regular expressions for community name matching from %s",
               num_regex, sss->conf.community_file);

    // calculate allowed user's shared secrets (shared with federation)
    calculate_shared_secrets(sss);

    // calculcate communties' dynamic keys
    calculate_dynamic_keys(sss);

    // no new communities will be allowed
    sss->lock_communities = true;

    return 0;
}


/* *************************************************** */


/** Send a datagram to a file descriptor socket.
 *
 *    @return -1 on error otherwise number of bytes sent
 */
static ssize_t sendto_fd (struct n3n_runtime_data *sss,
                          SOCKET socket_fd,
                          const struct sockaddr *socket,
                          const uint8_t *pktbuf,
                          size_t pktsize) {

    ssize_t sent = 0;
    n2n_tcp_connection_t *conn;

    sent = sendto(socket_fd, (void *)pktbuf, pktsize, 0 /* flags */,
                  socket, sizeof(struct sockaddr_in));

    if((sent <= 0) && (errno)) {
        char * c = strerror(errno);
        traceEvent(TRACE_ERROR, "sendto failed (%d) %s", errno, c);
#ifdef _WIN32
        traceEvent(TRACE_ERROR, "WSAGetLastError(): %u", WSAGetLastError());
#endif
        // if the erroneous connection is tcp, i.e. not the regular sock...
        if((socket_fd >= 0) && (socket_fd != sss->sock)) {
            // ...forget about the corresponding peer and the connection
            HASH_FIND_INT(sss->tcp_connections, &socket_fd, conn);
            close_tcp_connection(sss, conn);
            return -1;
        }
    } else {
        traceEvent(TRACE_DEBUG, "sendto_fd sent=%d", (signed int)sent);
    }

    return sent;
}


/** Send a datagram to a network order socket of type struct sockaddr.
 *
 *    @return -1 on error otherwise number of bytes sent
 */
static ssize_t sendto_sock (struct n3n_runtime_data *sss,
                            SOCKET socket_fd,
                            const struct sockaddr *socket,
                            const uint8_t *pktbuf,
                            size_t pktsize) {

    ssize_t sent = 0;
#ifdef _WIN32
    char value = 0;
#else
    int value = 0;
#endif

    // if the connection is tcp, i.e. not the regular sock...
    if((socket_fd >= 0) && (socket_fd != sss->sock)) {

        setsockopt(socket_fd, IPPROTO_TCP, TCP_NODELAY, &value, sizeof(value));
        value = 1;
#ifdef LINUX
        setsockopt(socket_fd, IPPROTO_TCP, TCP_CORK, &value, sizeof(value));
#endif

        // prepend packet length...
        uint16_t pktsize16 = htobe16(pktsize);
        sent = sendto_fd(sss, socket_fd, socket, (uint8_t*)&pktsize16, sizeof(pktsize16));

        if(sent <= 0)
            return -1;
        // ...before sending the actual data
    }

    sent = sendto_fd(sss, socket_fd, socket, pktbuf, pktsize);

    // if the connection is tcp, i.e. not the regular sock...
    if((socket_fd >= 0) && (socket_fd != sss->sock)) {
        value = 1; /* value should still be set to 1 */
        setsockopt(socket_fd, IPPROTO_TCP, TCP_NODELAY, (void *)&value, sizeof(value));
#ifdef LINUX
        value = 0;
        setsockopt(socket_fd, IPPROTO_TCP, TCP_CORK, &value, sizeof(value));
#endif
    }

    return sent;
}


/** Send a datagram to a peer whose destination socket is embodied in its sock field of type n2n_sock_t.
 *  It calls sendto_sock to do the final send.
 *
 *    @return -1 on error otherwise number of bytes sent
 */
static ssize_t sendto_peer (struct n3n_runtime_data *sss,
                            const struct peer_info *peer,
                            const uint8_t *pktbuf,
                            size_t pktsize) {

    n2n_sock_str_t sockbuf;

    if(AF_INET == peer->sock.family) {

        // network order socket
        struct sockaddr_in socket;
        fill_sockaddr((struct sockaddr *)&socket, sizeof(socket), &(peer->sock));

        traceEvent(TRACE_DEBUG, "sent %lu bytes to [%s]",
                   pktsize,
                   sock_to_cstr(sockbuf, &(peer->sock)));

        return sendto_sock(sss,
                           (peer->socket_fd >= 0) ? peer->socket_fd : sss->sock,
                           (const struct sockaddr*)&socket, pktbuf, pktsize);
    } else {
        /* AF_INET6 not implemented */
        errno = EAFNOSUPPORT;
        return -1;
    }
}


/** Try and broadcast a message to all edges in the community.
 *
 *    This will send the exact same datagram to zero or more edges registered to
 *    the supernode.
 */
static void try_broadcast (struct n3n_runtime_data * sss,
                           const struct sn_community *comm,
                           const n2n_common_t * cmn,
                           const n2n_mac_t srcMac,
                           bool from_supernode,
                           const uint8_t * pktbuf,
                           size_t pktsize,
                           time_t now) {

    struct peer_info        *scan, *tmp;
    macstr_t mac_buf;
    n2n_sock_str_t sockbuf;

    traceEvent(TRACE_DEBUG, "try_broadcast");

    /* We have to make sure that a broadcast reaches the other supernodes and edges
     * connected to them. try_broadcast needs a from_supernode parameter: if set,
     * do forward to edges of community only. If unset, forward to all locally known
     * nodes of community AND all supernodes associated with the community */

    if(!from_supernode) {
        // If the broadcast is not from a supernode, send it to all supernodes

        HASH_ITER(hh, sss->federation->edges, scan, tmp) {
            int data_sent_len;

            // only forward to active supernodes
            if(scan->last_seen + LAST_SEEN_SN_INACTIVE > now) {

                data_sent_len = sendto_peer(sss, scan, pktbuf, pktsize);

                if(data_sent_len != pktsize) {
                    ++(sss->stats.sn_errors);
                    traceEvent(TRACE_WARNING, "multicast %lu to supernode [%s] %s failed %s",
                               pktsize,
                               sock_to_cstr(sockbuf, &(scan->sock)),
                               macaddr_str(mac_buf, scan->mac_addr),
                               strerror(errno));
                } else {
                    ++(sss->stats.sn_broadcast);
                    traceEvent(TRACE_DEBUG, "multicast %lu to supernode [%s] %s",
                               pktsize,
                               sock_to_cstr(sockbuf, &(scan->sock)),
                               macaddr_str(mac_buf, scan->mac_addr));
                }
            }
        }
    }

    if(comm) {
        // If we know this community, send the broadcast to all known edges

        HASH_ITER(hh, comm->edges, scan, tmp) {
            if(memcmp(srcMac, scan->mac_addr, sizeof(n2n_mac_t)) != 0) {
                /* REVISIT: exclude if the destination socket is where the packet came from. */
                int data_sent_len;

                data_sent_len = sendto_peer(sss, scan, pktbuf, pktsize);

                if(data_sent_len != pktsize) {
                    ++(sss->stats.sn_errors);
                    traceEvent(TRACE_WARNING, "multicast %lu to [%s] %s failed %s",
                               pktsize,
                               sock_to_cstr(sockbuf, &(scan->sock)),
                               macaddr_str(mac_buf, scan->mac_addr),
                               strerror(errno));
                } else {
                    ++(sss->stats.sn_broadcast);
                    traceEvent(TRACE_DEBUG, "multicast %lu to [%s] %s",
                               pktsize,
                               sock_to_cstr(sockbuf, &(scan->sock)),
                               macaddr_str(mac_buf, scan->mac_addr));
                }
            }
        }
    }

    return;
}


static void try_forward (struct n3n_runtime_data * sss,
                         const struct sn_community *comm,
                         const n2n_common_t * cmn,
                         const n2n_mac_t dstMac,
                         bool from_supernode,
                         const uint8_t * pktbuf,
                         size_t pktsize,
                         time_t now) {

    struct peer_info *             scan;
    node_supernode_association_t   *assoc;
    macstr_t mac_buf;
    n2n_sock_str_t sockbuf;

    HASH_FIND_PEER(comm->edges, dstMac, scan);

    if(scan) {
        // We found an edge matching the dest mac

        int data_sent_len;
        data_sent_len = sendto_peer(sss, scan, pktbuf, pktsize);

        if(data_sent_len == pktsize) {
            ++(sss->stats.sn_fwd);
            traceEvent(TRACE_DEBUG, "unicast %lu to [%s] %s",
                       pktsize,
                       sock_to_cstr(sockbuf, &(scan->sock)),
                       macaddr_str(mac_buf, scan->mac_addr));
            return;
        } else {
            ++(sss->stats.sn_errors);
            traceEvent(TRACE_ERROR, "unicast %lu to [%s] %s FAILED (%d: %s)",
                       pktsize,
                       sock_to_cstr(sockbuf, &(scan->sock)),
                       macaddr_str(mac_buf, scan->mac_addr),
                       errno, strerror(errno));
            return;
        }

    }

    if(!from_supernode) {
        HASH_FIND(hh, comm->assoc, dstMac, sizeof(n2n_mac_t), assoc);
        if(assoc) {
            // if target edge is associated with a certain supernode
            traceEvent(
                TRACE_DEBUG,
                "found mac address associated with a known supernode, forwarding packet to that supernode"
            );
            sendto_sock(sss, sss->sock,
                        &(assoc->sock),
                        pktbuf, pktsize);
            return;
        } else {
            // otherwise, forwarding packet to all federated supernodes
            traceEvent(
                TRACE_DEBUG,
                "unknown mac address, broadcasting packet to all federated supernodes"
            );
            try_broadcast(
                sss,
                NULL,
                cmn,
                sss->conf.sn_mac_addr,
                from_supernode,
                pktbuf,
                pktsize,
                now
            );
            return;
        }
    }

    // Must be from a supernode then
    sss->stats.sn_drop++;
    traceEvent(
        TRACE_DEBUG,
        "unknown mac address in packet from a supernode, dropping the packet"
    );
    /* Not a known MAC so drop. */
    return;
}


/** Initialise some fields of the community structure **/
int comm_init (struct sn_community *comm, char *cmn) {

    strncpy((char*)comm->community, cmn, N2N_COMMUNITY_SIZE);
    comm->community[N2N_COMMUNITY_SIZE - 1] = '\0';
    comm->is_federation = false;

    return 0; /* OK */
}


/** Initialise the supernode structure */
void sn_init_conf_defaults (struct n3n_runtime_data *sss, char *sessionname) {
    // TODO: this should accept a conf parameter, not a sss
    n2n_edge_conf_t *conf = &sss->conf;

    memset(sss, 0, sizeof(struct n3n_runtime_data));

    // Record the session name we used
    if(sessionname) {
        conf->sessionname = sessionname;
    } else {
        conf->sessionname = "NULL";
    }

    conf->is_supernode = true;
    conf->spoofing_protection = true;

    strncpy(conf->version, VERSION, sizeof(n2n_version_t));
    conf->version[sizeof(n2n_version_t) - 1] = '\0';

    conf->bind_address = malloc(sizeof(*conf->bind_address));
    memset(conf->bind_address, 0, sizeof(*conf->bind_address));

#ifdef _WIN32
    // Cannot rely on having unix domain sockets on windows
    conf->mgmt_port = N2N_SN_MGMT_PORT;
#endif
    conf->mgmt_password = N3N_MGMT_PASSWORD;

    /* Random auth token */
    conf->auth.scheme = n2n_auth_simple_id;
    memrnd(conf->auth.token, N2N_AUTH_ID_TOKEN_SIZE);
    conf->auth.token_size = N2N_AUTH_ID_TOKEN_SIZE;

    /* Initialize the federation name */
    // TODO: the edge has a separate function for getenv() defaults
    char *federation = getenv("N3N_FEDERATION");
    if(!federation) {
        federation = FEDERATION_NAME_DEFAULT;
    }
    strncpy(conf->sn_federation, federation, sizeof(conf->sn_federation));

#ifndef _WIN32
    struct passwd *pw = NULL;

    // The supernod can run with no additional privs, so the default is
    // just to run as the user who starts it.
    // It should not be running as root, so detect that and change the
    // defaults

    conf->userid = getuid();
    conf->groupid = getgid();
    if((conf->userid == 0) || (conf->groupid == 0)) {
        // Search a couple of usernames for one to use
        pw = getpwnam("n3n");
        if(pw == NULL) {
            pw = getpwnam("nobody");
        }
        if(pw != NULL) {
            // If we find one, use that as our default
            conf->userid = pw->pw_uid;
            conf->groupid = pw->pw_gid;
        }
    }

#endif


    /* Random MAC address */
    memrnd(sss->conf.sn_mac_addr, N2N_MAC_SIZE);
    sss->conf.sn_mac_addr[0] &= ~0x01; /* Clear multicast bit */
    sss->conf.sn_mac_addr[0] |= 0x02;    /* Set locally-assigned bit */

    struct sockaddr_in *sa = (struct sockaddr_in *)conf->bind_address;
    sa->sin_family = AF_INET;
    sa->sin_port = htons(N2N_SN_LPORT_DEFAULT);
    sa->sin_addr.s_addr = htonl(INADDR_ANY);

    sss->sock = -1;
    conf->sn_min_auto_ip_net.net_addr = inet_addr(N2N_SN_MIN_AUTO_IP_NET_DEFAULT);
    conf->sn_min_auto_ip_net.net_bitlen = N2N_SN_AUTO_IP_NET_BIT_DEFAULT;
    conf->sn_max_auto_ip_net.net_addr = inet_addr(N2N_SN_MAX_AUTO_IP_NET_DEFAULT);
    conf->sn_max_auto_ip_net.net_bitlen = N2N_SN_AUTO_IP_NET_BIT_DEFAULT;

    sss->federation = (struct sn_community *)calloc(1, sizeof(struct sn_community));
    if(!sss->federation) {
        abort();
    }

    // Setup the fields of the federation record
    // Note that this is not really conf, so it probably should move
    //
    /* enable the flag for federation */
    sss->federation->is_federation = true;
    sss->federation->purgeable = false;
    /* header encryption enabled by default */
    sss->federation->header_encryption = HEADER_ENCRYPTION_ENABLED;
    sss->federation->edges = NULL;
}


/** Initialise the supernode */
void sn_init (struct n3n_runtime_data *sss) {
    n3n_peer_add_strlist(&sss->supernodes, &sss->conf.supernodes_str);

    if(resolve_create_thread(&(sss->resolve_parameter), sss->federation->edges) == 0) {
        traceEvent(TRACE_INFO, "successfully created resolver thread");
    }
}


/** Deinitialise the supernode structure and deallocate any memory owned by
 *    it. */
void sn_term (struct n3n_runtime_data *sss) {

    struct sn_community *community, *tmp;
    struct sn_community_regular_expression *re, *tmp_re;
    n2n_tcp_connection_t *conn, *tmp_conn;
    node_supernode_association_t *assoc, *tmp_assoc;

    resolve_cancel_thread(sss->resolve_parameter);

    if(sss->sock >= 0) {
        closesocket(sss->sock);
    }
    sss->sock = -1;

    HASH_ITER(hh, sss->tcp_connections, conn, tmp_conn) {
        shutdown(conn->socket_fd, SHUT_RDWR);
        closesocket(conn->socket_fd);
        HASH_DEL(sss->tcp_connections, conn);
        free(conn);
    }

    if(sss->tcp_sock >= 0) {
        shutdown(sss->tcp_sock, SHUT_RDWR);
        closesocket(sss->tcp_sock);
    }
    sss->tcp_sock = -1;

    HASH_ITER(hh, sss->communities, community, tmp) {
        clear_peer_list(&community->edges);
        free(community->header_encryption_ctx_static);
        free(community->header_encryption_ctx_dynamic);
        free(community->header_iv_ctx_static);
        free(community->header_iv_ctx_dynamic);

        // remove all associations
        HASH_ITER(hh, community->assoc, assoc, tmp_assoc) {
            HASH_DEL(community->assoc, assoc);
            free(assoc);
        }

        // remove allowed users from community
        sn_user_t *user, *tmp_user;
        HASH_ITER(hh, community->allowed_users, user, tmp_user) {
            speck_deinit((speck_context_t*)user->shared_secret_ctx);
            HASH_DEL(community->allowed_users, user);
            free(user);
        }

        HASH_DEL(sss->communities, community);
        free(community);
    }

    HASH_ITER(hh, sss->rules, re, tmp_re) {
        HASH_DEL(sss->rules, re);
        if(NULL != re->rule) {
            free(re->rule);
        }
        free(re);
    }

    free(sss->conf.bind_address);

    free(sss->conf.community_file);

#ifndef _WIN32
    char unixsock[1024];
    snprintf(unixsock, sizeof(unixsock), "%s/mgmt", sss->conf.sessiondir);
    unlink(unixsock);
    rmdir(sss->conf.sessiondir);
#else
    _rmdir(sss->conf.sessiondir);
#endif
    // Ignore errors in the unlink/rmdir as they could simply be that the
    // paths were chown/chmod by the administrator

    free(sss->conf.sessiondir);

    slots_free(sss->mgmt_slots);

#ifdef _WIN32
    destroyWin32();
#endif
}

void update_node_supernode_association (struct sn_community *comm,
                                        n2n_mac_t *edgeMac,
                                        const struct sockaddr *sender_sock,
                                        socklen_t sock_size,
                                        time_t now) {

    node_supernode_association_t *assoc;

    // Look for an existing assoc entry
    HASH_FIND(hh, comm->assoc, edgeMac, sizeof(n2n_mac_t), assoc);

    if(!assoc) {
        // none found, create a new association
        assoc = (node_supernode_association_t*)calloc(1, sizeof(node_supernode_association_t));
        if(!assoc) {
            // TODO: log/abort on alloc failure
            return;
        }

        // Initialise the required fields
        memcpy(&(assoc->mac), edgeMac, sizeof(n2n_mac_t));
        HASH_ADD(hh, comm->assoc, mac, sizeof(n2n_mac_t), assoc);
    }

    // update old entry or initialise new entry
    // TODO: check sock_size for overflow
    memcpy(&(assoc->sock), sender_sock, sock_size);
    assoc->sock_len = sock_size;
    assoc->last_seen = now;
    return;
}


/** Determine the appropriate lifetime for new registrations.
 *
 *    If the supernode has been put into a pre-shutdown phase then this lifetime
 *    should not allow registrations to continue beyond the shutdown point.
 */
static uint16_t reg_lifetime (struct n3n_runtime_data *sss) {

    /* NOTE: UDP firewalls usually have a 30 seconds timeout */
    return 15;
}


/** Verifies authentication tokens from known edges.
 *
 *  It is called by update_edge and during UNREGISTER_SUPER handling
 *  to verify the stored auth token.
 */
static int auth_edge (const n2n_auth_t *present, const n2n_auth_t *presented, n2n_auth_t *answer, struct sn_community *community) {

    sn_user_t *user = NULL;
    traceEvent(
        TRACE_INFO,
        "token scheme present=%i, presented=%i",
        present->scheme,
        presented->scheme
    );

    if(present->scheme == n2n_auth_none) {
        // n2n_auth_none scheme (set at supernode if cli option '-M')
        // if required, zero_token answer (not for NAK)
        if(answer)
            memset(answer, 0, sizeof(n2n_auth_t));
        // 0 == (always) successful
        return 0;
    }

    if((present->scheme == n2n_auth_simple_id) && (presented->scheme == n2n_auth_simple_id)) {
        // n2n_auth_simple_id scheme: if required, zero_token answer (not for NAK)
        if(answer)
            memset(answer, 0, sizeof(n2n_auth_t));

        // 0 = success (tokens are equal)
        return (memcmp(present, presented, sizeof(n2n_auth_t)));
    }

    if((present->scheme == n2n_auth_user_password) && (presented->scheme == n2n_auth_user_password)) {
        // check if submitted public key is in list of allowed users
        HASH_FIND(hh, community->allowed_users, &presented->token, sizeof(n2n_private_public_key_t), user);
        if(user) {
            if(answer) {
                memcpy(answer, presented, sizeof(n2n_auth_t));

                // return a double-encrypted challenge (just encrypt again) in the (first half of) public key field so edge can verify
                memcpy(answer->token, answer->token + N2N_PRIVATE_PUBLIC_KEY_SIZE, N2N_AUTH_CHALLENGE_SIZE);
                speck_128_encrypt(answer->token, (speck_context_t*)user->shared_secret_ctx);

                // decrypt the challenge using user's shared secret
                speck_128_decrypt(answer->token + N2N_PRIVATE_PUBLIC_KEY_SIZE, (speck_context_t*)user->shared_secret_ctx);
                // xor-in the community dynamic key
                memxor(answer->token + N2N_PRIVATE_PUBLIC_KEY_SIZE, community->dynamic_key, N2N_AUTH_CHALLENGE_SIZE);
                // xor-in the user's shared secret
                memxor(answer->token + N2N_PRIVATE_PUBLIC_KEY_SIZE, user->shared_secret, N2N_AUTH_CHALLENGE_SIZE);
                // encrypt it using user's shared secret
                speck_128_encrypt(answer->token + N2N_PRIVATE_PUBLIC_KEY_SIZE, (speck_context_t*)user->shared_secret_ctx);
                // user in list? success! (we will see if edge can handle the key for further com)
            }
            return 0;
        }
    }

    // if not successful earlier: failure
    traceEvent(TRACE_INFO, "auth default fail");
    return -1;
}


// provides the current / a new local auth token
// REVISIT: behavior should depend on some local auth scheme setting (to be implemented)
static int get_local_auth (struct n3n_runtime_data *sss, n2n_auth_t *auth) {

    // n2n_auth_simple_id scheme
    memcpy(auth, &(sss->conf.auth), sizeof(n2n_auth_t));

    return 0;
}


// handles an incoming (remote) auth token from a so far unknown edge,
// takes action as required by auth scheme, and
// could provide an answer auth token for use in REGISTER_SUPER_ACK
static int handle_remote_auth (struct n3n_runtime_data *sss, const n2n_auth_t *remote_auth,
                               n2n_auth_t *answer_auth,
                               struct sn_community *community) {

    sn_user_t *user = NULL;
    traceEvent(TRACE_INFO, "token scheme %i", remote_auth->scheme);

    if((NULL == community->allowed_users) != (remote_auth->scheme != n2n_auth_user_password)) {
        // received token's scheme does not match expected scheme
        traceEvent(TRACE_INFO, "token scheme mismatch");
        return -1;
    }

    switch(remote_auth->scheme) {
        // we do not handle n2n_auth_none because the edge always uses either
        // id or user/password
        // auth_none is sn-internal only (skipping MAC/IP address spoofing
        // protection)
        case n2n_auth_none:
        case n2n_auth_simple_id:
            // zero_token answer
            memset(answer_auth, 0, sizeof(n2n_auth_t));
            return 0;
        case n2n_auth_user_password:
            // check if submitted public key is in list of allowed users
            HASH_FIND(hh, community->allowed_users, &remote_auth->token, sizeof(n2n_private_public_key_t), user);
            if(user) {
                memcpy(answer_auth, remote_auth, sizeof(n2n_auth_t));

                // return a double-encrypted challenge (just encrypt again) in the (first half of) public key field so edge can verify
                memcpy(answer_auth->token, answer_auth->token + N2N_PRIVATE_PUBLIC_KEY_SIZE, N2N_AUTH_CHALLENGE_SIZE);
                speck_128_encrypt(answer_auth->token, (speck_context_t*)user->shared_secret_ctx);

                // wrap dynamic key for transmission
                // decrypt the challenge using user's shared secret
                speck_128_decrypt(answer_auth->token + N2N_PRIVATE_PUBLIC_KEY_SIZE, (speck_context_t*)user->shared_secret_ctx);
                // xor-in the community dynamic key
                memxor(answer_auth->token + N2N_PRIVATE_PUBLIC_KEY_SIZE, community->dynamic_key, N2N_AUTH_CHALLENGE_SIZE);
                // xor-in the user's shared secret
                memxor(answer_auth->token + N2N_PRIVATE_PUBLIC_KEY_SIZE, user->shared_secret, N2N_AUTH_CHALLENGE_SIZE);
                // encrypt it using user's shared secret
                speck_128_encrypt(answer_auth->token + N2N_PRIVATE_PUBLIC_KEY_SIZE, (speck_context_t*)user->shared_secret_ctx);
                return 0;
            }
            break;
        default:
            break;
    }

    // if not successful earlier: failure
    traceEvent(TRACE_INFO, "auth default fail");
    return -1;
}


/** Update the edge table with the details of the edge which contacted the
 *    supernode. */
static int update_edge (struct n3n_runtime_data *sss,
                        const n2n_common_t* cmn,
                        const n2n_REGISTER_SUPER_t* reg,
                        struct sn_community *comm,
                        const n2n_sock_t *sender_sock,
                        const SOCKET socket_fd,
                        n2n_auth_t *answer_auth,
                        int skip_add,
                        time_t now) {

    macstr_t mac_buf;
    n2n_sock_str_t sockbuf;
    struct peer_info *scan, *iter, *tmp;

    traceEvent(TRACE_DEBUG, "update_edge for %s [%s]",
               macaddr_str(mac_buf, reg->edgeMac),
               sock_to_cstr(sockbuf, sender_sock));

    HASH_FIND_PEER(comm->edges, reg->edgeMac, scan);

    // if unknown, make sure it is also not known by IP address
    if(NULL == scan) {
        HASH_ITER(hh,comm->edges,iter,tmp) {
            // TODO:
            // - needs ipv6 support
            // - I suspect that this can leak TCP connections
            // - convert to using a peer_info_*() call for manipulating the
            //   peer info lists
            if(iter->dev_addr.net_addr == reg->dev_addr.net_addr) {
                scan = iter;
                HASH_DEL(comm->edges, scan);
                memcpy(scan->mac_addr, reg->edgeMac, sizeof(n2n_mac_t));
                HASH_ADD_PEER(comm->edges, scan);
                break;
            }
        }
    }

    scan = peer_info_validate(&comm->edges, scan);

    if(NULL == scan) {
        /* Not known */
        if(handle_remote_auth(sss, &(reg->auth), answer_auth, comm) == 0) {
            if(skip_add == SN_ADD) {
                scan = peer_info_malloc(reg->edgeMac); /* deallocated in purge_expired_nodes */
                scan->dev_addr.net_addr = reg->dev_addr.net_addr;
                scan->dev_addr.net_bitlen = reg->dev_addr.net_bitlen;
                memcpy((char*)scan->dev_desc, reg->dev_desc, N2N_DESC_SIZE);
                memcpy(&(scan->sock), sender_sock, sizeof(n2n_sock_t));
                scan->socket_fd = socket_fd;
                scan->last_cookie = reg->cookie;
                // eventually, store edge's preferred local socket from REGISTER_SUPER
                if(cmn->flags & N2N_FLAGS_SOCKET)
                    memcpy(&scan->preferred_sock, &reg->sock, sizeof(n2n_sock_t));
                else
                    scan->preferred_sock.family = AF_INVALID;

                // store the submitted auth token
                memcpy(&(scan->auth), &(reg->auth), sizeof(n2n_auth_t));
                // manually set to type 'auth_none' if cli option disables
                // MAC/IP address spoofing protection for id based auth
                // communities. This will be obsolete when handling public
                // keys only (v4.0?)
                if((reg->auth.scheme == n2n_auth_simple_id) && (!sss->conf.spoofing_protection))
                    scan->auth.scheme = n2n_auth_none;

                HASH_ADD_PEER(comm->edges, scan);

                traceEvent(TRACE_INFO, "created edge  %s ==> %s",
                           macaddr_str(mac_buf, reg->edgeMac),
                           sock_to_cstr(sockbuf, sender_sock));

                scan->last_seen = now;
                return update_edge_new_sn;
            }
            return update_edge_new_sn;
        } else {
            traceEvent(TRACE_INFO, "authentication failed");
            return update_edge_auth_fail;
        }
    } else {
        /* Known */
        if(auth_edge(&(scan->auth), &(reg->auth), answer_auth, comm) == 0) {
            if(!sock_equal(sender_sock, &(scan->sock))) {
                scan->dev_addr.net_addr = reg->dev_addr.net_addr;
                scan->dev_addr.net_bitlen = reg->dev_addr.net_bitlen;
                memcpy((char*)scan->dev_desc, reg->dev_desc, N2N_DESC_SIZE);
                memcpy(&(scan->sock), sender_sock, sizeof(n2n_sock_t));
                scan->socket_fd = socket_fd;
                scan->last_cookie = reg->cookie;
                // eventually, update edge's preferred local socket from REGISTER_SUPER
                if(cmn->flags & N2N_FLAGS_SOCKET)
                    memcpy(&scan->preferred_sock, &reg->sock, sizeof(n2n_sock_t));
                else
                    scan->preferred_sock.family = AF_INVALID;

                traceEvent(TRACE_INFO, "updated edge  %s ==> %s",
                           macaddr_str(mac_buf, reg->edgeMac),
                           sock_to_cstr(sockbuf, sender_sock));
                scan->last_seen = now;
                return update_edge_sock_change;
            } else {
                scan->last_cookie = reg->cookie;

                traceEvent(TRACE_DEBUG, "edge unchanged %s ==> %s",
                           macaddr_str(mac_buf, reg->edgeMac),
                           sock_to_cstr(sockbuf, sender_sock));

                scan->last_seen = now;
                return update_edge_no_change;
            }
        } else {
            traceEvent(TRACE_INFO, "authentication failed");
            return update_edge_auth_fail;
        }
    }

    return 0;
}


/** checks if a certain ip address is still available, i.e. not used by any other edge of a given community */
static int ip_addr_available (struct sn_community *comm, n2n_ip_subnet_t *ip_addr) {

    int success = 1;
    struct peer_info *peer, *tmp_peer;

    // prerequisite: list of peers is sorted according to peer's tap ip address
    HASH_ITER(hh, comm->edges, peer, tmp_peer) {
        if(peer->dev_addr.net_addr  > ip_addr->net_addr) {
            break;
        }
        if(peer->dev_addr.net_addr == ip_addr->net_addr) {
            success = 0;
            break;
        }
    }

    return success;
}


static signed int peer_tap_ip_sort (struct peer_info *a, struct peer_info *b) {

    uint32_t a_host_id = a->dev_addr.net_addr & (~bitlen2mask(a->dev_addr.net_bitlen));
    uint32_t b_host_id = b->dev_addr.net_addr & (~bitlen2mask(b->dev_addr.net_bitlen));

    return ((signed int)a_host_id - (signed int)b_host_id);
}


/** The IP address assigned to the edge by the auto ip address function of sn. */
static int assign_one_ip_addr (struct sn_community *comm, n2n_desc_t dev_desc, n2n_ip_subnet_t *ip_addr) {

    uint32_t tmp, success, net_id, mask, max_host, host_id = 1;
    dec_ip_bit_str_t ip_bit_str = {'\0'};

    mask = bitlen2mask(comm->auto_ip_net.net_bitlen);
    net_id = comm->auto_ip_net.net_addr & mask;
    max_host = ~mask;

    // sorting is a prerequisite for more efficient availabilitiy check
    HASH_SORT(comm->edges, peer_tap_ip_sort);

    // first proposal derived from hash of mac address
    tmp = pearson_hash_32(dev_desc, sizeof(n2n_desc_t)) & max_host;
    if(tmp == 0) tmp++;        /* avoid 0 host */
    if(tmp == max_host) tmp--; /* avoid broadcast address */
    tmp |= net_id;

    // candidate
    ip_addr->net_bitlen = comm->auto_ip_net.net_bitlen;

    // check for availability starting from proposal, then downwards, ...
    for(host_id = tmp; host_id > net_id; host_id--) {
        ip_addr->net_addr = host_id;
        success = ip_addr_available(comm, ip_addr);
        if(success) {
            break;
        }
    }
    // ... then upwards
    if(!success) {
        for(host_id = tmp + 1; host_id < (net_id + max_host); host_id++) {
            ip_addr->net_addr = host_id;
            success = ip_addr_available(comm, ip_addr);
            if(success) {
                break;
            }
        }
    }

    if(success) {
        traceEvent(TRACE_INFO, "assign IP %s to tap adapter of edge", ip_subnet_to_str(ip_bit_str, ip_addr));
        return 0;
    } else {
        traceEvent(TRACE_WARNING, "no assignable IP to edge tap adapter");
        return -1;
    }
}


/** checks if a certain sub-network is still available, i.e. does not cut any other community's sub-network */
int subnet_available (struct n3n_runtime_data *sss,
                      struct sn_community *comm,
                      uint32_t net_id,
                      uint32_t mask) {

    struct sn_community *cmn, *tmpCmn;
    int success = 1;

    HASH_ITER(hh, sss->communities, cmn, tmpCmn) {
        if(cmn == comm) {
            continue;
        }
        if(cmn->is_federation) {
            continue;
        }
        if((net_id <= (cmn->auto_ip_net.net_addr + ~bitlen2mask(cmn->auto_ip_net.net_bitlen)))
           &&(net_id + ~mask >= cmn->auto_ip_net.net_addr)) {
            success = 0;
            break;
        }
    }

    return success;
}


/** The IP address range (subnet) assigned to the community by the auto ip address function of sn. */
int assign_one_ip_subnet (struct n3n_runtime_data *sss,
                          struct sn_community *comm) {

    uint32_t net_id, net_id_i, mask, net_increment;
    uint32_t no_subnets;
    uint8_t success;
    in_addr_t net_min;
    in_addr_t net_max;
    in_addr_t net;


    mask = bitlen2mask(sss->conf.sn_min_auto_ip_net.net_bitlen);
    net_min = ntohl(sss->conf.sn_min_auto_ip_net.net_addr);
    net_max = ntohl(sss->conf.sn_max_auto_ip_net.net_addr);

    // number of possible sub-networks
    no_subnets   = net_max - net_min;
    no_subnets >>= (32 - sss->conf.sn_min_auto_ip_net.net_bitlen);
    no_subnets  += 1;

    // proposal for sub-network to choose
    net_id    = pearson_hash_32((const uint8_t *)comm->community, N2N_COMMUNITY_SIZE) % no_subnets;
    net_id    = net_min + (net_id << (32 - sss->conf.sn_min_auto_ip_net.net_bitlen));

    // check for availability starting from net_id, then downwards, ...
    net_increment = (~mask+1);
    for(net_id_i = net_id; net_id_i >= net_min; net_id_i -= net_increment) {
        success = subnet_available(sss, comm, net_id_i, mask);
        if(success) {
            break;
        }
    }
    // ... then upwards
    if(!success) {
        for(net_id_i = net_id + net_increment; net_id_i <= net_max; net_id_i += net_increment) {
            success = subnet_available(sss, comm, net_id_i, mask);
            if(success) {
                break;
            }
        }
    }

    if(success) {
        comm->auto_ip_net.net_addr = net_id_i;
        comm->auto_ip_net.net_bitlen = sss->conf.sn_min_auto_ip_net.net_bitlen;
        net = htonl(comm->auto_ip_net.net_addr);
        struct in_addr *tmp = (struct in_addr *)&net;
        traceEvent(TRACE_INFO, "assigned sub-network %s/%u to community '%s'",
                   inet_ntoa(*tmp),
                   comm->auto_ip_net.net_bitlen,
                   comm->community);
        return 0;
    } else {
        comm->auto_ip_net.net_addr = 0;
        comm->auto_ip_net.net_bitlen = 0;
        traceEvent(TRACE_WARNING, "no assignable sub-network left for community '%s'",
                   comm->community);
        return -1;
    }
}


static int re_register_and_purge_supernodes (struct n3n_runtime_data *sss, struct sn_community *comm, time_t *p_last_re_reg_and_purge, time_t now, uint8_t forced) {

    time_t time;
    struct peer_info *peer, *tmp;

    if(!forced) {
        if((now - (*p_last_re_reg_and_purge)) < RE_REG_AND_PURGE_FREQUENCY) {
            return 0;
        }

        // purge long-time-not-seen supernodes
        if(comm) {
            purge_expired_nodes(&(comm->edges), sss->sock, &sss->tcp_connections, p_last_re_reg_and_purge,
                                RE_REG_AND_PURGE_FREQUENCY, LAST_SEEN_SN_INACTIVE);
        }
    }

    if(comm != NULL) {
        HASH_ITER(hh,comm->edges,peer,tmp) {

            time = now - peer->last_seen;

            if(!forced) {
                if(time <= LAST_SEEN_SN_ACTIVE) {
                    continue;
                }
            }

            /* re-register (send REGISTER_SUPER) */
            uint8_t pktbuf[N2N_PKT_BUF_SIZE] = {0};
            size_t idx;
            /* ssize_t sent; */
            n2n_common_t cmn;
            n2n_REGISTER_SUPER_t reg;
            n2n_sock_str_t sockbuf;

            memset(&cmn, 0, sizeof(cmn));
            memset(&reg, 0, sizeof(reg));

            cmn.ttl = N2N_DEFAULT_TTL;
            cmn.pc = MSG_TYPE_REGISTER_SUPER;
            cmn.flags = N2N_FLAGS_FROM_SUPERNODE;
            memcpy(cmn.community, comm->community, N2N_COMMUNITY_SIZE);

            reg.cookie = n3n_rand();
            peer->last_cookie = reg.cookie;

            reg.dev_addr.net_addr = ntohl(peer->dev_addr.net_addr);
            reg.dev_addr.net_bitlen = mask2bitlen(ntohl(peer->dev_addr.net_bitlen));
            get_local_auth(sss, &(reg.auth));

            reg.key_time = sss->dynamic_key_time;

            memcpy(reg.edgeMac, sss->conf.sn_mac_addr, sizeof(n2n_mac_t));

            idx = 0;
            encode_REGISTER_SUPER(pktbuf, &idx, &cmn, &reg);

            traceEvent(TRACE_DEBUG, "send REGISTER_SUPER to %s",
                       sock_to_cstr(sockbuf, &(peer->sock)));

            packet_header_encrypt(pktbuf, idx, idx,
                                  comm->header_encryption_ctx_static, comm->header_iv_ctx_static,
                                  time_stamp());

            /* sent = */ sendto_peer(sss, peer, pktbuf, idx);
        }
    }

    return 0; /* OK */
}


static int purge_expired_communities (struct n3n_runtime_data *sss,
                                      time_t* p_last_purge,
                                      time_t now) {

    struct sn_community *comm, *tmp_comm;
    node_supernode_association_t *assoc, *tmp_assoc;
    size_t num_reg = 0;
    size_t num_assoc = 0;

    if((now - (*p_last_purge)) < PURGE_REGISTRATION_FREQUENCY) {
        return 0;
    }

    traceEvent(TRACE_DEBUG, "purging old communities and edges");

    HASH_ITER(hh, sss->communities, comm, tmp_comm) {
        // federation is taken care of in re_register_and_purge_supernodes()
        if(comm->is_federation)
            continue;

        // purge the community's local peers
        num_reg += purge_peer_list(&comm->edges, sss->sock, &sss->tcp_connections, now - REGISTRATION_TIMEOUT);

        // purge the community's associated peers (connected to other supernodes)
        HASH_ITER(hh, comm->assoc, assoc, tmp_assoc) {
            if(comm->assoc->last_seen < (now - 3 * REGISTRATION_TIMEOUT)) {
                HASH_DEL(comm->assoc, assoc);
                free(assoc);
                num_assoc++;
            }
        }

        if((comm->edges == NULL) && (comm->purgeable)) {
            traceEvent(TRACE_INFO, "purging idle community %s", comm->community);
            if(NULL != comm->header_encryption_ctx_static) {
                /* this should not happen as 'purgeable' and thus only communities w/o encrypted header here */
                free(comm->header_encryption_ctx_static);
                free(comm->header_iv_ctx_static);
                free(comm->header_encryption_ctx_dynamic);
                free(comm->header_iv_ctx_dynamic);
            }
            // remove all associations
            HASH_ITER(hh, comm->assoc, assoc, tmp_assoc) {
                HASH_DEL(comm->assoc, assoc);
                free(assoc);
            }
            HASH_DEL(sss->communities, comm);
            free(comm);
        }
    }
    (*p_last_purge) = now;

    traceEvent(TRACE_DEBUG, "purge_expired_communities removed %ld locally registered edges and %ld remotely associated edges",
               num_reg, num_assoc);

    return 0;
}


static int number_enc_packets_sort (struct sn_community *a, struct sn_community *b) {

    // comparison function for sorting communities in descending order of their
    // number_enc_packets-fields
    return (b->number_enc_packets - a->number_enc_packets);
}


static int sort_communities (struct n3n_runtime_data *sss,
                             time_t* p_last_sort,
                             time_t now) {

    struct sn_community *comm, *tmp;

    if((now - (*p_last_sort)) < SORT_COMMUNITIES_INTERVAL) {
        return 0;
    }

    // this routine gets periodically called as defined in SORT_COMMUNITIES_INTERVAL
    // it sorts the communities in descending order of their number_enc_packets-fields...
    HASH_SORT(sss->communities, number_enc_packets_sort);

    // ... and afterward resets the number_enc__packets-fields to zero
    // (other models could reset it to half of their value to respect history)
    HASH_ITER(hh, sss->communities, comm, tmp) {
        comm->number_enc_packets = 0;
    }

    (*p_last_sort) = now;

    return 0;
}


/** Examine a datagram and determine what to do with it.
 *
 */
static int process_udp (struct n3n_runtime_data * sss,
                        const struct sockaddr *sender_sock, socklen_t sock_size,
                        const SOCKET socket_fd,
                        uint8_t * udp_buf,
                        size_t udp_size,
                        time_t now,
                        int type) {

    n2n_common_t cmn;        /* common fields in the packet header */
    size_t rem;
    size_t idx;
    size_t msg_type;
    bool from_supernode;
    struct peer_info *sn = NULL;
    n2n_sock_t sender;
    n2n_sock_t          *orig_sender;
    macstr_t mac_buf;
    macstr_t mac_buf2;
    n2n_sock_str_t sockbuf;
    uint8_t hash_buf[16] = {0};             /* always size of 16 (max) despite the actual value of N2N_REG_SUP_HASH_CHECK_LEN (<= 16) */

    struct sn_community *comm, *tmp;
    uint32_t header_enc = 0;            /* 1 == encrypted by static key, 2 == encrypted by dynamic key */
    uint64_t stamp;
    int skip_add;
    time_t any_time = 0;

    fill_n2nsock(&sender, sender_sock, SOCK_DGRAM);
    orig_sender = &sender;

    traceEvent(TRACE_DEBUG, "processing incoming UDP packet [len: %lu][sender: %s]",
               udp_size, sock_to_cstr(sockbuf, &sender));

    /* check if header is unencrypted. the following check is around 99.99962 percent reliable.
     * it heavily relies on the structure of packet's common part
     * changes to wire.c:encode/decode_common need to go together with this code */
    if(udp_size < 24) {
        traceEvent(TRACE_DEBUG, "dropped a packet too short to be valid");
        return -1;
    }
    // FIXME: if this is using be16toh then it is doing wire processing and
    // should be located in wire.c with the rest of the wire processing.
    if((udp_buf[23] == (uint8_t)0x00) // null terminated community name
       && (udp_buf[00] == N2N_PKT_VERSION) // correct packet version
       && ((be16toh(*(uint16_t*)&(udp_buf[02])) & N2N_FLAGS_TYPE_MASK) <= MSG_TYPE_MAX_TYPE) // message type
       && ( be16toh(*(uint16_t*)&(udp_buf[02])) < N2N_FLAGS_OPTIONS_MAX) // flags
    ) {
        /* most probably unencrypted */
        /* make sure, no downgrading happens here and no unencrypted packets can be
         * injected in a community which definitely deals with encrypted headers */
        HASH_FIND_COMMUNITY(sss->communities, (char *)&udp_buf[04], comm);
        if(comm) {
            if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
                traceEvent(TRACE_DEBUG, "dropped a packet with unencrypted header "
                           "addressed to community '%s' which uses encrypted headers",
                           comm->community);
                return -1;
            }
            if(comm->header_encryption == HEADER_ENCRYPTION_UNKNOWN) {
                traceEvent(TRACE_INFO, "locked community '%s' to "
                           "unencrypted headers", comm->community);
                /* set 'no encryption' in case it is not set yet */
                comm->header_encryption = HEADER_ENCRYPTION_NONE;
                free(comm->header_encryption_ctx_static);
                comm->header_encryption_ctx_static = NULL;
                free(comm->header_encryption_ctx_dynamic);
                comm->header_encryption_ctx_dynamic = NULL;
            }
        }
    } else {
        /* most probably encrypted */
        /* cycle through the known communities (as keys) to eventually decrypt */
        HASH_ITER(hh, sss->communities, comm, tmp) {
            /* skip the definitely unencrypted communities */
            if(comm->header_encryption == HEADER_ENCRYPTION_NONE) {
                continue;
            }

            // match with static (1) or dynamic (2) ctx?
            // check dynamic first as it is identical to static in normal header encryption mode
            if(packet_header_decrypt(udp_buf, udp_size,
                                     comm->community,
                                     comm->header_encryption_ctx_dynamic, comm->header_iv_ctx_dynamic,
                                     &stamp)) {
                header_enc = 2;
            }
            if(!header_enc) {
                pearson_hash_128(hash_buf, udp_buf, MAX(0, (int)udp_size - (int)N2N_REG_SUP_HASH_CHECK_LEN));
                header_enc = packet_header_decrypt(udp_buf, MAX(0, (int)udp_size - (int)N2N_REG_SUP_HASH_CHECK_LEN), comm->community,
                                                   comm->header_encryption_ctx_static, comm->header_iv_ctx_static, &stamp);
            }

            if(header_enc) {
                // time stamp verification follows in the packet specific section as it requires to determine the
                // sender from the hash list by its MAC, this all depends on packet type and packet structure
                // (MAC is not always in the same place)

                if(comm->header_encryption == HEADER_ENCRYPTION_UNKNOWN) {
                    traceEvent(TRACE_INFO, "locked community '%s' to "
                               "encrypted headers", comm->community);
                    /* set 'encrypted' in case it is not set yet */
                    comm->header_encryption = HEADER_ENCRYPTION_ENABLED;
                }
                // count the number of encrypted packets for sorting the communities from time to time
                // for the HASH_ITER a few lines above gets faster for the more busy communities
                (comm->number_enc_packets)++;
                // no need to test further communities
                break;
            }
        }
        if(!header_enc) {
            // no matching key/community
            traceEvent(TRACE_DEBUG, "dropped a packet with seemingly encrypted header "
                       "for which no matching community which uses encrypted headers was found");
            return -1;
        }
    }

    /* Use decode_common() to determine the kind of packet then process it:
     *
     * REGISTER_SUPER adds an edge and generate a return REGISTER_SUPER_ACK
     *
     * REGISTER, REGISTER_ACK and PACKET messages are forwarded to their
     * destination edge. If the destination is not known then PACKETs are
     * broadcast.
     */

    rem = udp_size; /* Counts down bytes of packet to protect against buffer overruns. */
    idx = 0; /* marches through packet header as parts are decoded. */

    if(decode_common(&cmn, udp_buf, &rem, &idx) < 0) {
        traceEvent(TRACE_ERROR, "failed to decode common section");
        return -1; /* failed to decode packet */
    }

    msg_type = cmn.pc; /* packet code */

    // special case for user/pw auth
    // community's auth scheme and message type need to match the used key (dynamic)
    if(comm) {
        if((comm->allowed_users)
           && (msg_type != MSG_TYPE_REGISTER_SUPER)
           && (msg_type != MSG_TYPE_REGISTER_SUPER_ACK)
           && (msg_type != MSG_TYPE_REGISTER_SUPER_NAK)) {
            if(header_enc != 2) {
                traceEvent(TRACE_WARNING, "dropped packet encrypted with static key where expecting dynamic key");
                return -1;
            }
        }
    }

    from_supernode = cmn.flags & N2N_FLAGS_FROM_SUPERNODE;
    if(from_supernode) {
        skip_add = SN_ADD_SKIP;
        sn = add_sn_to_list_by_mac_or_sock(&(sss->federation->edges), &sender, null_mac, &skip_add);
        // only REGISTER_SUPER allowed from unknown supernodes
        if((!sn) && (msg_type != MSG_TYPE_REGISTER_SUPER)) {
            traceEvent(TRACE_DEBUG, "dropped incoming data from unknown supernode");
            return -1;
        }
    }

    if(cmn.ttl < 1) {
        traceEvent(TRACE_WARNING, "expired TTL");
        return 0; /* Don't process further */
    }

    --(cmn.ttl); /* The value copied into all forwarded packets. */

    switch(msg_type) {
        case MSG_TYPE_PACKET: {
            /* PACKET from one edge to another edge via supernode. */

            /* pkt will be modified in place and recoded to an output of potentially
             * different size due to addition of the socket.*/
            n2n_PACKET_t pkt;
            n2n_common_t cmn2;
            uint8_t encbuf[N2N_SN_PKTBUF_SIZE];
            size_t encx = 0;
            int unicast;           /* non-zero if unicast */
            uint8_t *     rec_buf; /* either udp_buf or encbuf */

            if(!comm) {
                traceEvent(TRACE_DEBUG, "PACKET with unknown community %s", cmn.community);
                return -1;
            }

            sss->last_sn_fwd = now;
            decode_PACKET(&pkt, &cmn, udp_buf, &rem, &idx);

            // already checked for valid comm
            if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
                if(!find_peer_time_stamp_and_verify(
                       comm->edges,
                       NULL,
                       sn,
                       pkt.srcMac,
                       stamp,
                       TIME_STAMP_ALLOW_JITTER)) {
                    traceEvent(TRACE_DEBUG, "dropped PACKET due to time stamp error");
                    return -1;
                }
            }

            unicast = (0 == is_multi_broadcast(pkt.dstMac));

            traceEvent(TRACE_DEBUG, "RX PACKET (%s) %s -> %s %s",
                       (unicast ? "unicast" : "multicast"),
                       macaddr_str(mac_buf, pkt.srcMac),
                       macaddr_str(mac_buf2, pkt.dstMac),
                       (from_supernode ? "from sn" : "local"));

            if(!from_supernode) {
                memcpy(&cmn2, &cmn, sizeof(n2n_common_t));

                /* We are going to add socket even if it was not there before */
                cmn2.flags |= N2N_FLAGS_SOCKET | N2N_FLAGS_FROM_SUPERNODE;

                memcpy(&pkt.sock, &sender, sizeof(sender));

                rec_buf = encbuf;
                /* Re-encode the header. */
                encode_PACKET(encbuf, &encx, &cmn2, &pkt);

                uint16_t oldEncx = encx;

                /* Copy the original payload unchanged */
                encode_buf(encbuf, &encx, (udp_buf + idx), (udp_size - idx));

                if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
                    // in case of user-password auth, also encrypt the iv of payload assuming ChaCha20 and SPECK having the same iv size
                    packet_header_encrypt(rec_buf, oldEncx + (NULL != comm->allowed_users) * MIN(encx - oldEncx, N2N_SPECK_IVEC_SIZE), encx,
                                          comm->header_encryption_ctx_dynamic, comm->header_iv_ctx_dynamic,
                                          time_stamp());
                }
            } else {
                /* Already from a supernode. Nothing to modify, just pass to
                 * destination. */

                traceEvent(TRACE_DEBUG, "Rx PACKET fwd unmodified");

                rec_buf = udp_buf;
                encx = udp_size;

                if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
                    // in case of user-password auth, also encrypt the iv of payload assuming ChaCha20 and SPECK having the same iv size
                    packet_header_encrypt(rec_buf, idx + (NULL != comm->allowed_users) * MIN(encx - idx, N2N_SPECK_IVEC_SIZE), encx,
                                          comm->header_encryption_ctx_dynamic, comm->header_iv_ctx_dynamic,
                                          time_stamp());
                }
            }

            /* Common section to forward the final product. */
            if(unicast) {
                try_forward(sss, comm, &cmn, pkt.dstMac, from_supernode, rec_buf, encx, now);
            } else {
                try_broadcast(sss, comm, &cmn, pkt.srcMac, from_supernode, rec_buf, encx, now);
            }
            return 0;
        }

        case MSG_TYPE_REGISTER: {
            /* Forwarding a REGISTER from one edge to the next */

            n2n_REGISTER_t reg;
            n2n_common_t cmn2;
            uint8_t encbuf[N2N_SN_PKTBUF_SIZE];
            size_t encx = 0;
            int unicast;             /* non-zero if unicast */
            uint8_t *       rec_buf; /* either udp_buf or encbuf */

            if(!comm) {
                traceEvent(TRACE_DEBUG, "REGISTER from unknown community %s", cmn.community);
                return -1;
            }

            sss->last_sn_fwd = now;
            decode_REGISTER(&reg, &cmn, udp_buf, &rem, &idx);

            // already checked for valid comm
            if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
                if(!find_peer_time_stamp_and_verify(
                       comm->edges,
                       NULL,
                       sn,
                       reg.srcMac,
                       stamp,
                       TIME_STAMP_NO_JITTER)) {
                    traceEvent(TRACE_DEBUG, "dropped REGISTER due to time stamp error");
                    return -1;
                }
            }

            unicast = (0 == is_multi_broadcast(reg.dstMac));

            if(unicast) {
                traceEvent(TRACE_DEBUG, "Rx REGISTER %s -> %s %s",
                           macaddr_str(mac_buf, reg.srcMac),
                           macaddr_str(mac_buf2, reg.dstMac),
                           ((cmn.flags & N2N_FLAGS_FROM_SUPERNODE) ? "from sn" : "local"));

                if(0 == (cmn.flags & N2N_FLAGS_FROM_SUPERNODE)) {
                    memcpy(&cmn2, &cmn, sizeof(n2n_common_t));

                    /* We are going to add socket even if it was not there before */
                    cmn2.flags |= N2N_FLAGS_SOCKET | N2N_FLAGS_FROM_SUPERNODE;

                    memcpy(&reg.sock, &sender, sizeof(sender));

                    /* Re-encode the header. */
                    encode_REGISTER(encbuf, &encx, &cmn2, &reg);

                    rec_buf = encbuf;
                } else {
                    /* Already from a supernode. Nothing to modify, just pass to
                     * destination. */

                    rec_buf = udp_buf;
                    encx = udp_size;
                }

                if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
                    packet_header_encrypt(rec_buf, encx, encx,
                                          comm->header_encryption_ctx_dynamic, comm->header_iv_ctx_dynamic,
                                          time_stamp());
                }
                try_forward(sss, comm, &cmn, reg.dstMac, from_supernode, rec_buf, encx, now); /* unicast only */
            } else {
                traceEvent(TRACE_ERROR, "Rx REGISTER with multicast destination");
            }
            return 0;
        }

        case MSG_TYPE_REGISTER_ACK: {
            traceEvent(TRACE_DEBUG, "Rx REGISTER_ACK (not implemented) should not be via supernode");
            return 0;
        }

        case MSG_TYPE_REGISTER_SUPER: {
            n2n_REGISTER_SUPER_t reg;
            n2n_REGISTER_SUPER_ACK_t ack;
            n2n_REGISTER_SUPER_NAK_t nak;
            n2n_common_t cmn2;
            uint8_t ackbuf[N2N_SN_PKTBUF_SIZE];
            uint8_t payload_buf[REG_SUPER_ACK_PAYLOAD_SPACE];
            n2n_REGISTER_SUPER_ACK_payload_t       *payload;
            size_t encx = 0;
            struct sn_community_regular_expression *re, *tmp_re;
            struct peer_info                       *peer, *tmp_peer, *p;
            int8_t allowed_match = -1;
            uint8_t match = 0;
            int match_length = 0;
            n2n_ip_subnet_t ipaddr;
            int num = 0;
            int skip;
            int ret_value;
            sn_user_t                              *user = NULL;

            memset(&ack, 0, sizeof(n2n_REGISTER_SUPER_ACK_t));
            memset(&nak, 0, sizeof(n2n_REGISTER_SUPER_NAK_t));

            /* Edge/supernode requesting registration with us.    */
            sss->last_sn_reg=now;
            ++(sss->stats.sn_reg);
            decode_REGISTER_SUPER(&reg, &cmn, udp_buf, &rem, &idx);

            if(comm) {
                if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
                    if(!find_peer_time_stamp_and_verify(
                           comm->edges,
                           NULL,
                           sn,
                           reg.edgeMac,
                           stamp,
                           TIME_STAMP_NO_JITTER)) {
                        traceEvent(TRACE_DEBUG, "dropped REGISTER_SUPER due to time stamp error");
                        return -1;
                    }
                }
            }

            /*
                Before we move any further, we need to check if the requested
                community is allowed by the supernode. In case it is not we do
                not report any message back to the edge to hide the supernode
                existance (better from the security standpoint)
             */

            if(!comm && sss->lock_communities) {
                HASH_ITER(hh, sss->rules, re, tmp_re) {
                    allowed_match = re_matchp(re->rule, (const char *)cmn.community, &match_length);

                    if((allowed_match != -1)
                       && (match_length == strlen((const char *)cmn.community)) // --- only full matches allowed (remove, if also partial matches wanted)
                       && (allowed_match == 0)) { // --- only full matches allowed (remove, if also partial matches wanted)
                        match = 1;
                        break;
                    }
                }
                if(match != 1) {
                    traceEvent(TRACE_INFO, "discarded registration with unallowed community '%s'",
                               (char*)cmn.community);
                    return -1;
                }
            }

            if(!comm && (!sss->lock_communities || (match == 1))) {
                comm = (struct sn_community*)calloc(1, sizeof(struct sn_community));

                if(comm) {
                    comm_init(comm, (char *)cmn.community);
                    /* new communities introduced by REGISTERs could not have had encrypted header... */
                    comm->header_encryption = HEADER_ENCRYPTION_NONE;
                    free(comm->header_encryption_ctx_static);
                    comm->header_encryption_ctx_static = NULL;
                    free(comm->header_encryption_ctx_dynamic);
                    comm->header_encryption_ctx_dynamic = NULL;
                    /* ... and also are purgeable during periodic purge */
                    comm->purgeable = true;
                    comm->number_enc_packets = 0;
                    HASH_ADD_STR(sss->communities, community, comm);

                    traceEvent(TRACE_INFO, "new community: %s", comm->community);
                    assign_one_ip_subnet(sss, comm);
                }
            }

            if(!comm) {
                traceEvent(TRACE_INFO, "discarded registration with unallowed community '%s'",
                           (char*)cmn.community);
                return -1;
            }

            // hash check (user/pw auth only)
            if(comm->allowed_users) {
                // check if submitted public key is in list of allowed users
                HASH_FIND(hh, comm->allowed_users, &reg.auth.token, sizeof(n2n_private_public_key_t), user);
                if(user) {
                    speck_128_encrypt(hash_buf, (speck_context_t*)user->shared_secret_ctx);
                    if(memcmp(hash_buf, udp_buf + udp_size - N2N_REG_SUP_HASH_CHECK_LEN /* length has already been checked */, N2N_REG_SUP_HASH_CHECK_LEN)) {
                        traceEvent(TRACE_INFO, "Rx REGISTER_SUPER with wrong hash");
                        return -1;
                    }
                } else {
                    traceEvent(TRACE_INFO, "Rx REGISTER_SUPER from unknown user");
                    // continue and let auth check do the rest (otherwise, no NAK is sent)
                }
            }

            if(!memcmp(reg.edgeMac, sss->conf.sn_mac_addr, sizeof(n2n_mac_t))) {
                traceEvent(TRACE_DEBUG, "Rx REGISTER_SUPER from self, ignoring");
                return -1;
            }

            cmn2.ttl = N2N_DEFAULT_TTL;
            cmn2.pc = MSG_TYPE_REGISTER_SUPER_ACK;
            cmn2.flags = N2N_FLAGS_SOCKET | N2N_FLAGS_FROM_SUPERNODE;
            memcpy(cmn2.community, cmn.community, sizeof(n2n_community_t));

            ack.cookie = reg.cookie;
            memcpy(ack.srcMac, sss->conf.sn_mac_addr, sizeof(n2n_mac_t));

            if(!comm->is_federation) { /* alternatively, do not send zero tap ip address in federation REGISTER_SUPER */
                if((reg.dev_addr.net_addr == 0) || (reg.dev_addr.net_addr == 0xFFFFFFFF) || (reg.dev_addr.net_bitlen == 0) ||
                   ((reg.dev_addr.net_addr & 0xFFFF0000) == 0xA9FE0000 /* 169.254.0.0 */)) {
                    memset(&ipaddr, 0, sizeof(n2n_ip_subnet_t));
                    assign_one_ip_addr(comm, reg.dev_desc, &ipaddr);
                    ack.dev_addr.net_addr = ipaddr.net_addr;
                    ack.dev_addr.net_bitlen = ipaddr.net_bitlen;
                }
            }

            ack.lifetime = reg_lifetime(sss);

            memcpy(&ack.sock, &sender, sizeof(sender));

            /* Add sender's data to federation (or update it) */
            if(comm->is_federation) {
                skip_add = SN_ADD;
                p = add_sn_to_list_by_mac_or_sock(&(sss->federation->edges), &(ack.sock), reg.edgeMac, &skip_add);
                p->last_seen = now;
                // communication with other supernodes happens via standard udp port
                p->socket_fd = sss->sock;
            }

            /* Skip random numbers of supernodes before payload assembling, calculating an appropriate random_number.
             * That way, all supernodes have a chance to be propagated with REGISTER_SUPER_ACK. */
            skip = HASH_COUNT(sss->federation->edges) - (int)(REG_SUPER_ACK_PAYLOAD_ENTRY_SIZE / REG_SUPER_ACK_PAYLOAD_ENTRY_SIZE);
            skip = (skip < 0) ? 0 : n3n_rand_sqr(skip);

            /* Assembling supernode list for REGISTER_SUPER_ACK payload */
            payload = (n2n_REGISTER_SUPER_ACK_payload_t*)payload_buf;
            HASH_ITER(hh, sss->federation->edges, peer, tmp_peer) {
                if(skip) {
                    skip--;
                    continue;
                }
                if(peer->sock.family == (uint8_t)AF_INVALID)
                    continue; /* do not add unresolved supernodes to payload */
                if(memcmp(&(peer->sock), &(ack.sock), sizeof(n2n_sock_t)) == 0) continue; /* a supernode doesn't add itself to the payload */
                if((now - peer->last_seen) >= LAST_SEEN_SN_NEW) continue;  /* skip long-time-not-seen supernodes.
                                                                            * We need to allow for a little extra time because supernodes sometimes exceed
                                                                            * their SN_ACTIVE time before they get re-registred to. */
                if(((++num)*REG_SUPER_ACK_PAYLOAD_ENTRY_SIZE) > REG_SUPER_ACK_PAYLOAD_SPACE) break; /* no more space available in REGISTER_SUPER_ACK payload */

                // bugfix for https://github.com/ntop/n2n/issues/1029
                // REVISIT: best to be removed with 4.0 (replace with encode_sock)
                idx = 0;
                encode_sock_payload(payload->sock, &idx, &(peer->sock));

                memcpy(payload->mac, peer->mac_addr, sizeof(n2n_mac_t));
                // shift to next payload entry
                payload++;
            }
            ack.num_sn = num;

            traceEvent(TRACE_DEBUG, "Rx REGISTER_SUPER for %s [%s]",
                       macaddr_str(mac_buf, reg.edgeMac),
                       sock_to_cstr(sockbuf, &(ack.sock)));

            // check authentication
            ret_value = update_edge_no_change;
            if(!comm->is_federation) { /* REVISIT: auth among supernodes is not implemented yet */
                if(cmn.flags & N2N_FLAGS_FROM_SUPERNODE) {
                    ret_value = update_edge(sss, &cmn, &reg, comm, &(ack.sock), socket_fd, &(ack.auth), SN_ADD_SKIP, now);
                } else {
                    // do not add in case of null mac (edge asking for ip address)
                    ret_value = update_edge(sss, &cmn, &reg, comm, &(ack.sock), socket_fd, &(ack.auth), is_null_mac(reg.edgeMac) ? SN_ADD_SKIP : SN_ADD, now);
                }
            }

            if(ret_value == update_edge_auth_fail) {
                // send REGISTER_SUPER_NAK
                cmn2.pc = MSG_TYPE_REGISTER_SUPER_NAK;
                nak.cookie = reg.cookie;
                memcpy(nak.srcMac, reg.edgeMac, sizeof(n2n_mac_t));

                encode_REGISTER_SUPER_NAK(ackbuf, &encx, &cmn2, &nak);

                if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
                    packet_header_encrypt(ackbuf, encx, encx,
                                          comm->header_encryption_ctx_static, comm->header_iv_ctx_static,
                                          time_stamp());
                    // if user-password-auth
                    if(comm->allowed_users) {
                        encode_buf(ackbuf, &encx, hash_buf /* no matter what content */, N2N_REG_SUP_HASH_CHECK_LEN);
                    }
                }
                sendto_sock(sss, socket_fd, sender_sock, ackbuf, encx);

                traceEvent(TRACE_DEBUG, "Tx REGISTER_SUPER_NAK for %s",
                           macaddr_str(mac_buf, reg.edgeMac));

                return 0;
            }

            // if this is not already from a supernode ...
            // and not from federation, ...
            if((!(cmn.flags & N2N_FLAGS_FROM_SUPERNODE)) || (!(cmn.flags & N2N_FLAGS_SOCKET))) {
                // ... forward to all other supernodes (note try_broadcast()'s behavior with
                //     NULL comm and from_supernode parameter)
                // exception: do not forward auto ip draw
                if(!is_null_mac(reg.edgeMac)) {
                    memcpy(&reg.sock, &sender, sizeof(sender));

                    cmn2.pc = MSG_TYPE_REGISTER_SUPER;
                    encode_REGISTER_SUPER(ackbuf, &encx, &cmn2, &reg);

                    if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
                        packet_header_encrypt(ackbuf, encx, encx,
                                              comm->header_encryption_ctx_static, comm->header_iv_ctx_static,
                                              time_stamp());
                        // if user-password-auth
                        if(comm->allowed_users) {
                            // append an encrypted packet hash
                            pearson_hash_128(hash_buf, ackbuf, encx);
                            // same 'user' as above
                            speck_128_encrypt(hash_buf, (speck_context_t*)user->shared_secret_ctx);
                            encode_buf(ackbuf, &encx, hash_buf, N2N_REG_SUP_HASH_CHECK_LEN);
                        }
                    }

                    try_broadcast(sss, NULL, &cmn, reg.edgeMac, from_supernode, ackbuf, encx, now);
                }

                // dynamic key time handling if appropriate
                ack.key_time = 0;
                if(comm->is_federation) {
                    if(reg.key_time > sss->dynamic_key_time) {
                        traceEvent(TRACE_DEBUG, "setting new key time");
                        // have all edges re_register (using old dynamic key)
                        send_re_register_super(sss);
                        // set new key time
                        sss->dynamic_key_time = reg.key_time;
                        // calculate new dynamic keys for all communities
                        calculate_dynamic_keys(sss);
                        // force re-register with all supernodes
                        re_register_and_purge_supernodes(sss, sss->federation, &any_time, now, 1 /* forced */);
                    }
                    ack.key_time = sss->dynamic_key_time;
                }

                // send REGISTER_SUPER_ACK
                encx = 0;
                cmn2.pc = MSG_TYPE_REGISTER_SUPER_ACK;

                encode_REGISTER_SUPER_ACK(ackbuf, &encx, &cmn2, &ack, payload_buf);

                if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
                    packet_header_encrypt(ackbuf, encx, encx,
                                          comm->header_encryption_ctx_static, comm->header_iv_ctx_static,
                                          time_stamp());
                    // if user-password-auth
                    if(comm->allowed_users) {
                        // append an encrypted packet hash
                        pearson_hash_128(hash_buf, ackbuf, encx);
                        // same 'user' as above
                        speck_128_encrypt(hash_buf, (speck_context_t*)user->shared_secret_ctx);
                        encode_buf(ackbuf, &encx, hash_buf, N2N_REG_SUP_HASH_CHECK_LEN);
                    }
                }

                sendto_sock(sss, socket_fd, sender_sock, ackbuf, encx);

                traceEvent(TRACE_DEBUG, "Tx REGISTER_SUPER_ACK for %s [%s]",
                           macaddr_str(mac_buf, reg.edgeMac),
                           sock_to_cstr(sockbuf, &(ack.sock)));
            } else {
                // this is an edge with valid authentication registering with another supernode, so ...
                // 1- ... associate it with that other supernode
                update_node_supernode_association(comm, &(reg.edgeMac), sender_sock, sock_size, now);
                // 2- ... we can delete it from regular list if present (can happen)
                HASH_FIND_PEER(comm->edges, reg.edgeMac, peer);
                if(peer != NULL) {
                    if((peer->socket_fd != sss->sock) && (peer->socket_fd >= 0)) {
                        n2n_tcp_connection_t *conn;
                        HASH_FIND_INT(sss->tcp_connections, &(peer->socket_fd), conn);
                        close_tcp_connection(sss, conn); /* also deletes the peer */
                    } else {
                        HASH_DEL(comm->edges, peer);
                        free(peer);
                    }
                }
            }

            return 0;
        }

        case MSG_TYPE_UNREGISTER_SUPER: {
            n2n_UNREGISTER_SUPER_t unreg;
            struct peer_info       *peer;
            int auth;


            memset(&unreg, 0, sizeof(n2n_UNREGISTER_SUPER_t));

            if(!comm) {
                traceEvent(TRACE_DEBUG, "dropped UNREGISTER_SUPER with unknown community %s", cmn.community);
                return -1;
            }

            if((from_supernode) || (comm->is_federation)) {
                traceEvent(TRACE_DEBUG, "dropped UNREGISTER_SUPER: should not come from a supernode or federation.");
                return -1;
            }

            decode_UNREGISTER_SUPER(&unreg, &cmn, udp_buf, &rem, &idx);

            if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
                if(!find_peer_time_stamp_and_verify(
                       comm->edges,
                       NULL,
                       sn,
                       unreg.srcMac,
                       stamp,
                       TIME_STAMP_NO_JITTER)) {
                    traceEvent(TRACE_DEBUG, "dropped UNREGISTER_SUPER due to time stamp error");
                    return -1;
                }
            }

            traceEvent(TRACE_DEBUG, "Rx UNREGISTER_SUPER from %s",
                       macaddr_str(mac_buf, unreg.srcMac));

            HASH_FIND_PEER(comm->edges, unreg.srcMac, peer);
            if(peer != NULL) {
                if((auth = auth_edge(&(peer->auth), &unreg.auth, NULL, comm)) == 0) {
                    if((peer->socket_fd != sss->sock) && (peer->socket_fd >= 0)) {
                        n2n_tcp_connection_t *conn;
                        HASH_FIND_INT(sss->tcp_connections, &(peer->socket_fd), conn);
                        close_tcp_connection(sss, conn); /* also deletes the peer */
                    } else {
                        HASH_DEL(comm->edges, peer);
                        peer_info_free(peer);
                    }
                }
            }
            return 0;
        }

        case MSG_TYPE_REGISTER_SUPER_ACK: {
            n2n_REGISTER_SUPER_ACK_t ack;
            struct peer_info                 *scan, *tmp;
            n2n_sock_str_t sockbuf1;
            n2n_sock_str_t sockbuf2;
            macstr_t mac_buf1;
            int i;
            uint8_t dec_tmpbuf[REG_SUPER_ACK_PAYLOAD_SPACE];
            n2n_REGISTER_SUPER_ACK_payload_t *payload;
            n2n_sock_t payload_sock;

            memset(&ack, 0, sizeof(n2n_REGISTER_SUPER_ACK_t));

            if(!comm) {
                traceEvent(TRACE_DEBUG, "REGISTER_SUPER_ACK with unknown community %s", cmn.community);
                return -1;
            }

            if((!from_supernode) || (!comm->is_federation)) {
                traceEvent(TRACE_DEBUG, "dropped REGISTER_SUPER_ACK, should not come from an edge or regular community");
                return -1;
            }

            decode_REGISTER_SUPER_ACK(&ack, &cmn, udp_buf, &rem, &idx, dec_tmpbuf);
            orig_sender = &(ack.sock);

            if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
                if(!find_peer_time_stamp_and_verify(
                       comm->edges,
                       NULL,
                       sn,
                       ack.srcMac,
                       stamp,
                       TIME_STAMP_NO_JITTER)) {
                    traceEvent(TRACE_DEBUG, "dropped REGISTER_SUPER_ACK due to time stamp error");
                    return -1;
                }
            }

            traceEvent(TRACE_INFO, "Rx REGISTER_SUPER_ACK from MAC %s [%s] (external %s)",
                       macaddr_str(mac_buf1, ack.srcMac),
                       sock_to_cstr(sockbuf1, &sender),
                       sock_to_cstr(sockbuf2, orig_sender));

            skip_add = SN_ADD_SKIP;
            scan = add_sn_to_list_by_mac_or_sock(&(sss->federation->edges), &sender, ack.srcMac, &skip_add);
            if(scan != NULL) {
                scan->last_seen = now;
            } else {
                traceEvent(TRACE_DEBUG, "dropped REGISTER_SUPER_ACK due to an unknown supernode");
                return 0;
            }

            if(ack.cookie == scan->last_cookie) {

                payload = (n2n_REGISTER_SUPER_ACK_payload_t *)dec_tmpbuf;
                for(i = 0; i < ack.num_sn; i++) {
                    skip_add = SN_ADD;

                    // bugfix for https://github.com/ntop/n2n/issues/1029
                    // REVISIT: best to be removed with 4.0
                    idx = 0;
                    rem = sizeof(payload->sock);
                    decode_sock_payload(&payload_sock, payload->sock, &rem, &idx);

                    tmp = add_sn_to_list_by_mac_or_sock(&(sss->federation->edges), &(payload_sock), payload->mac, &skip_add);
                    // other supernodes communicate via standard udp socket
                    tmp->socket_fd = sss->sock;

                    if(skip_add == SN_ADD_ADDED) {
                        tmp->last_seen = now - LAST_SEEN_SN_NEW;
                    }

                    // shift to next payload entry
                    payload++;
                }

                if(ack.key_time > sss->dynamic_key_time) {
                    traceEvent(TRACE_DEBUG, "setting new key time");
                    // have all edges re_register (using old dynamic key)
                    send_re_register_super(sss);
                    // set new key time
                    sss->dynamic_key_time = ack.key_time;
                    // calculate new dynamic keys for all communities
                    calculate_dynamic_keys(sss);
                    // force re-register with all supernodes
                    re_register_and_purge_supernodes(sss, sss->federation, &any_time, now, 1 /* forced */);
                }

            } else {
                traceEvent(TRACE_INFO, "Rx REGISTER_SUPER_ACK with wrong or old cookie");
            }
            return 0;
        }

        case MSG_TYPE_REGISTER_SUPER_NAK: {
            n2n_REGISTER_SUPER_NAK_t nak;
            uint8_t nakbuf[N2N_SN_PKTBUF_SIZE];
            size_t encx = 0;
            struct peer_info          *peer;
            n2n_sock_str_t sockbuf;
            macstr_t mac_buf;

            memset(&nak, 0, sizeof(n2n_REGISTER_SUPER_NAK_t));

            if(!comm) {
                traceEvent(TRACE_DEBUG, "REGISTER_SUPER_NAK with unknown community %s", cmn.community);
                return -1;
            }

            decode_REGISTER_SUPER_NAK(&nak, &cmn, udp_buf, &rem, &idx);

            if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
                if(!find_peer_time_stamp_and_verify(
                       comm->edges,
                       NULL,
                       sn,
                       nak.srcMac,
                       stamp,
                       TIME_STAMP_NO_JITTER)) {
                    traceEvent(TRACE_DEBUG, "process_udp dropped REGISTER_SUPER_NAK due to time stamp error");
                    return -1;
                }
            }

            traceEvent(TRACE_INFO, "Rx REGISTER_SUPER_NAK from %s [%s]",
                       macaddr_str(mac_buf, nak.srcMac),
                       sock_to_cstr(sockbuf, &sender));

            HASH_FIND_PEER(comm->edges, nak.srcMac, peer);
            if(comm->is_federation) {
                if(peer != NULL) {
                    // this is a NAK for one of the edges conencted to this supernode, forward,
                    // i.e. re-assemble (memcpy from udpbuf to nakbuf could be sufficient as well)

                    // use incoming cmn (with already decreased TTL)
                    // NAK (cookie, srcMac, auth) remains unchanged

                    encode_REGISTER_SUPER_NAK(nakbuf, &encx, &cmn, &nak);

                    if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
                        packet_header_encrypt(nakbuf, encx, encx,
                                              comm->header_encryption_ctx_static, comm->header_iv_ctx_static,
                                              time_stamp());
                        // if user-password-auth
                        if(comm->allowed_users) {
                            encode_buf(nakbuf, &encx, hash_buf /* no matter what content */, N2N_REG_SUP_HASH_CHECK_LEN);
                        }
                    }

                    sendto_peer(sss, peer, nakbuf, encx);

                    if((peer->socket_fd != sss->sock) && (peer->socket_fd >= 0)) {
                        n2n_tcp_connection_t *conn;
                        HASH_FIND_INT(sss->tcp_connections, &(peer->socket_fd), conn);
                        close_tcp_connection(sss, conn); /* also deletes the peer */
                    } else {
                        HASH_DEL(comm->edges, peer);
                        peer_info_free(peer);
                    }
                }
            }
            return 0;
        }

        case MSG_TYPE_QUERY_PEER: {
            n2n_QUERY_PEER_t query;
            uint8_t encbuf[N2N_SN_PKTBUF_SIZE];
            size_t encx = 0;
            n2n_common_t cmn2;
            n2n_PEER_INFO_t pi;
            struct sn_community_regular_expression *re, *tmp_re;
            int8_t allowed_match = -1;
            uint8_t match = 0;
            int match_length = 0;

            if(!comm && sss->lock_communities) {
                HASH_ITER(hh, sss->rules, re, tmp_re) {
                    allowed_match = re_matchp(re->rule, (const char *)cmn.community, &match_length);

                    if((allowed_match != -1)
                       && (match_length == strlen((const char *)cmn.community)) // --- only full matches allowed (remove, if also partial matches wanted)
                       && (allowed_match == 0)) {                               // --- only full matches allowed (remove, if also partial matches wanted)
                        match = 1;
                        break;
                    }
                }
                if(match != 1) {
                    traceEvent(TRACE_DEBUG, "QUERY_PEER from unknown community %s", cmn.community);
                    return -1;
                }
            }

            if(!comm && sss->lock_communities && (match == 0)) {
                traceEvent(TRACE_DEBUG, "QUERY_PEER from not allowed community %s", cmn.community);
                return -1;
            }

            decode_QUERY_PEER( &query, &cmn, udp_buf, &rem, &idx );

            // to answer a PING, it is sufficient if the provided communtiy would be a valid one, there does not
            // neccessarily need to be a comm entry present, e.g. because there locally are no edges of the
            // community connected (several supernodes in a federation setup)
            if(comm) {
                if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
                    if(!find_peer_time_stamp_and_verify(
                           comm->edges,
                           NULL,
                           sn,
                           query.srcMac,
                           stamp,
                           TIME_STAMP_ALLOW_JITTER)) {
                        traceEvent(TRACE_DEBUG, "dropped QUERY_PEER due to time stamp error");
                        return -1;
                    }
                }
            }

            if(is_null_mac(query.targetMac)) {
                traceEvent(TRACE_DEBUG, "Rx PING from %s",
                           macaddr_str(mac_buf, query.srcMac));

                cmn2.ttl = N2N_DEFAULT_TTL;
                cmn2.pc = MSG_TYPE_PEER_INFO;
                cmn2.flags = N2N_FLAGS_FROM_SUPERNODE;
                memcpy(cmn2.community, cmn.community, sizeof(n2n_community_t));

                pi.aflags = 0;
                memcpy(pi.mac, query.targetMac, sizeof(n2n_mac_t));
                memcpy(pi.srcMac, sss->conf.sn_mac_addr, sizeof(n2n_mac_t));

                memcpy(&pi.sock, &sender, sizeof(sender));

                pi.load = sn_selection_criterion_gather_data(sss);

                snprintf(pi.version, sizeof(pi.version), "%s", sss->conf.version);
                pi.uptime = now - sss->start_time;

                encode_PEER_INFO(encbuf, &encx, &cmn2, &pi);

                if(comm) {
                    if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
                        packet_header_encrypt(encbuf, encx, encx, comm->header_encryption_ctx_dynamic,
                                              comm->header_iv_ctx_dynamic,
                                              time_stamp());
                    }
                }

                sendto_sock(sss, socket_fd, sender_sock, encbuf, encx);

                traceEvent(TRACE_DEBUG, "Tx PONG to %s",
                           macaddr_str(mac_buf, query.srcMac));

            } else {
                traceEvent(TRACE_DEBUG, "Rx QUERY_PEER from %s for %s",
                           macaddr_str(mac_buf, query.srcMac),
                           macaddr_str(mac_buf2, query.targetMac));

                struct peer_info *scan;

                // as opposed to the special case 'PING', proper QUERY_PEER processing requires a locally actually present community entry
                if(!comm) {
                    traceEvent(TRACE_DEBUG, "QUERY_PEER with unknown community %s", cmn.community);
                    return -1;
                }

                HASH_FIND_PEER(comm->edges, query.targetMac, scan);
                if(scan) {
                    cmn2.ttl = N2N_DEFAULT_TTL;
                    cmn2.pc = MSG_TYPE_PEER_INFO;
                    cmn2.flags = N2N_FLAGS_FROM_SUPERNODE;
                    memcpy(cmn2.community, cmn.community, sizeof(n2n_community_t));

                    pi.aflags = 0;
                    memcpy(pi.srcMac, query.srcMac, sizeof(n2n_mac_t));
                    memcpy(pi.mac, query.targetMac, sizeof(n2n_mac_t));
                    pi.sock = scan->sock;
                    if(scan->preferred_sock.family != (uint8_t)AF_INVALID) {
                        cmn2.flags |= N2N_FLAGS_SOCKET;
                        pi.preferred_sock = scan->preferred_sock;
                    }

                    // FIXME:
                    // If we get the request on TCP, the reply should indicate
                    // our prefered sock is TCP ??

                    encode_PEER_INFO(encbuf, &encx, &cmn2, &pi);

                    if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
                        packet_header_encrypt(encbuf, encx, encx, comm->header_encryption_ctx_dynamic,
                                              comm->header_iv_ctx_dynamic,
                                              time_stamp());
                    }
                    // back to sender, be it edge or supernode (which will forward to edge)
                    sendto_sock(sss, socket_fd, sender_sock, encbuf, encx);

                    traceEvent(TRACE_DEBUG, "Tx PEER_INFO to %s",
                               macaddr_str(mac_buf, query.srcMac));

                } else {

                    if(from_supernode) {
                        traceEvent(TRACE_DEBUG, "QUERY_PEER on unknown edge from supernode %s, dropping the packet",
                                   macaddr_str(mac_buf, query.srcMac));
                    } else {
                        traceEvent(TRACE_DEBUG, "QUERY_PEER from unknown edge %s, forwarding to all other supernodes",
                                   macaddr_str(mac_buf, query.srcMac));

                        memcpy(&cmn2, &cmn, sizeof(n2n_common_t));
                        cmn2.flags |= N2N_FLAGS_FROM_SUPERNODE;

                        encode_QUERY_PEER(encbuf, &encx, &cmn2, &query);

                        if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
                            packet_header_encrypt(encbuf, encx, encx, comm->header_encryption_ctx_dynamic,
                                                  comm->header_iv_ctx_dynamic,
                                                  time_stamp());
                        }

                        try_broadcast(sss, NULL, &cmn, query.srcMac, from_supernode, encbuf, encx, now);
                    }
                }
            }
            return 0;
        }

        case MSG_TYPE_PEER_INFO: {
            n2n_PEER_INFO_t pi;
            uint8_t encbuf[N2N_SN_PKTBUF_SIZE];
            size_t encx = 0;
            struct peer_info                       *peer;

            if(!comm) {
                traceEvent(TRACE_DEBUG, "PEER_INFO with unknown community %s", cmn.community);
                return -1;
            }

            decode_PEER_INFO(&pi, &cmn, udp_buf, &rem, &idx);

            if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
                if(!find_peer_time_stamp_and_verify(
                       comm->edges,
                       NULL,
                       sn,
                       pi.srcMac,
                       stamp,
                       TIME_STAMP_NO_JITTER)) {
                    traceEvent(TRACE_DEBUG, "dropped PEER_INFO due to time stamp error");
                    return -1;
                }
            }

            traceEvent(TRACE_INFO, "Rx PEER_INFO from %s [%s]",
                       macaddr_str(mac_buf, pi.srcMac),
                       sock_to_cstr(sockbuf, &sender));

            HASH_FIND_PEER(comm->edges, pi.srcMac, peer);
            if(peer != NULL) {
                if((comm->is_federation) && (!is_null_mac(pi.srcMac))) {
                    // snoop on the information to use for supernode forwarding (do not wait until first remote REGISTER_SUPER)
                    update_node_supernode_association(comm, &(pi.mac), sender_sock, sock_size, now);

                    // this is a PEER_INFO for one of the edges conencted to this supernode, forward,
                    // i.e. re-assemble (memcpy of udpbuf to encbuf could be sufficient as well)

                    // use incoming cmn (with already decreased TTL)
                    // PEER_INFO remains unchanged

                    encode_PEER_INFO(encbuf, &encx, &cmn, &pi);

                    if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
                        packet_header_encrypt(encbuf, encx, encx,
                                              comm->header_encryption_ctx_dynamic, comm->header_iv_ctx_dynamic,
                                              time_stamp());
                    }

                    sendto_peer(sss, peer, encbuf, encx);
                }
            }
            return 0;
        }

        default:
            /* Not a known message type */
            traceEvent(TRACE_WARNING, "unable to handle packet type %d: ignored", (signed int)msg_type);
    } /* switch(msg_type) */

    return 0;
}


/** Long lived processing entry point. Split out from main to simply
 *  daemonisation on some platforms. */
int run_sn_loop (struct n3n_runtime_data *sss) {

    uint8_t pktbuf[N2N_SN_PKTBUF_SIZE];
    time_t last_purge_edges = 0;
    time_t last_sort_communities = 0;
    time_t last_re_reg_and_purge = 0;

    sss->start_time = time(NULL);

    while(*sss->keep_running) {
        int rc;
        int max_sock;
        ssize_t bread;
        fd_set readers;
        fd_set writers;
        n2n_tcp_connection_t *conn;
        n2n_tcp_connection_t *tmp_conn;
        struct timeval wait_time;
        time_t before;
        time_t now;

        FD_ZERO(&readers);
        FD_ZERO(&writers);

        FD_SET(sss->sock, &readers);
        max_sock = sss->sock;

#ifdef N2N_HAVE_TCP
        n2n_sock_str_t sockbuf;
        FD_SET(sss->tcp_sock, &readers);

        // add the tcp connections' sockets
        HASH_ITER(hh, sss->tcp_connections, conn, tmp_conn) {
            //socket descriptor
            FD_SET(conn->socket_fd, &readers);
            if(conn->socket_fd > max_sock) {
                max_sock = MAX(max_sock, conn->socket_fd);
            }
        }
#endif

        slots_t *slots = sss->mgmt_slots;
        max_sock = MAX(
            max_sock,
            slots_fdset(
                slots,
                &readers,
                &writers
            )
        );

        wait_time.tv_sec = 10;
        wait_time.tv_usec = 0;

        before = time(NULL);

        rc = select(max_sock + 1, &readers, &writers, NULL, &wait_time);

        now = time(NULL);

        if(rc == 0) {
            if(((now - before) < wait_time.tv_sec) && (*sss->keep_running)) {
                // this is no real timeout, something went wrong with one of the tcp connections (probably)
                // close them all, edges will re-open if they detect closure
                // FIXME: untangle this as the description above is unlikely
                traceEvent(TRACE_DEBUG, "falsly claimed timeout, assuming issue with tcp connection, closing them all");
                HASH_ITER(hh, sss->tcp_connections, conn, tmp_conn) {
                    close_tcp_connection(sss, conn);
                }
            } else {
                traceEvent(TRACE_DEBUG, "timeout");
            }
        }

        if(rc > 0) {

            // external udp
            if(FD_ISSET(sss->sock, &readers)) {
                struct sockaddr_storage sas;
                struct sockaddr *sender_sock = (struct sockaddr*)&sas;
                socklen_t ss_size = sizeof(sas);

                bread = recvfrom(
                    sss->sock,
                    (void *)pktbuf,
                    N2N_SN_PKTBUF_SIZE,
                    0 /*flags*/,
                    sender_sock,
                    &ss_size
                );

                if((bread < 0)
#ifdef _WIN32
                   && (WSAGetLastError() != WSAECONNRESET)
#endif
                ) {
                    // FIXME: when would we get a WSAECONNRESET on a UDP read
                    // of a non connected socket

                    /* For UDP bread of zero just means no data (unlike TCP). */
                    /* The fd is no good now. Maybe we lost our interface. */
                    traceEvent(TRACE_ERROR, "recvfrom() failed %d errno %d (%s)", bread, errno, strerror(errno));
#ifdef _WIN32
                    traceEvent(TRACE_ERROR, "WSAGetLastError(): %u", WSAGetLastError());
#endif
                    *sss->keep_running = false;
                }

                // we have a datagram to process...
                if(bread > 0) {
                    // ...and the datagram has data (not just a header)
                    process_udp(
                        sss,
                        sender_sock,
                        ss_size,
                        sss->sock,
                        pktbuf,
                        bread,
                        now,
                        SOCK_DGRAM
                    );
                }
            }

#ifdef N2N_HAVE_TCP
            // the so far known tcp connections

            // beware: current conn and other items of the connection list may be found
            // due for deletion while processing packets. Even OTHER connections, e.g. if
            // forwarding to another edge node fails. connections due for deletion will
            // not immediately be deleted but marked 'inactive' for later deletion
            HASH_ITER(hh, sss->tcp_connections, conn, tmp_conn) {
                // do not process entries that have been marked inactive, those will be deleted
                // immediately after this loop
                if(conn->inactive)
                    continue;

                if(FD_ISSET(conn->socket_fd, &readers)) {
                    struct sockaddr_storage sas;
                    struct sockaddr *sender_sock = (struct sockaddr*)&sas;
                    socklen_t ss_size = sizeof(sas);

                    // TODO: this all looks like it could use a tcp buffer
                    // management layer - like the connslot abstraction
                    bread = recvfrom(
                        conn->socket_fd,
                        conn->buffer + conn->position,
                        conn->expected - conn->position,
                        0 /*flags*/,
                        sender_sock,
                        &ss_size
                    );

                    if(bread <= 0) {
                        traceEvent(TRACE_INFO, "closing tcp connection to [%s]", sock_to_cstr(sockbuf, (n2n_sock_t*)sender_sock));
                        traceEvent(TRACE_DEBUG, "recvfrom() returns %d and sees errno %d (%s)", bread, errno, strerror(errno));
#ifdef _WIN32
                        traceEvent(TRACE_DEBUG, "WSAGetLastError(): %u", WSAGetLastError());
#endif
                        close_tcp_connection(sss, conn);
                        continue;
                    }
                    conn->position += bread;

                    if(conn->position == conn->expected) {
                        if(conn->position == sizeof(uint16_t)) {
                            // the prepended length has been read, preparing for the packet
                            conn->expected += be16toh(*(uint16_t*)(conn->buffer));
                            if(conn->expected > N2N_SN_PKTBUF_SIZE) {
                                traceEvent(TRACE_INFO, "closing tcp connection to [%s]", sock_to_cstr(sockbuf, (n2n_sock_t*)sender_sock));
                                traceEvent(TRACE_DEBUG, "too many bytes in tcp packet expected");
                                close_tcp_connection(sss, conn);
                                continue;
                            }
                        } else {
                            // full packet read, handle it
                            process_udp(
                                sss,
                                &(conn->sock),
                                conn->sock_len,
                                conn->socket_fd,
                                conn->buffer + sizeof(uint16_t),
                                conn->position - sizeof(uint16_t),
                                now,
                                SOCK_STREAM
                            );

                            // reset, await new prepended length
                            conn->expected = sizeof(uint16_t);
                            conn->position = 0;
                        }
                    }
                }
            }

            // remove inactive / already closed tcp connections from list
            HASH_ITER(hh, sss->tcp_connections, conn, tmp_conn) {
                if(conn->inactive) {
                    HASH_DEL(sss->tcp_connections, conn);
                    free(conn);
                }
            }

            // accept new incoming tcp connection
            if(FD_ISSET(sss->tcp_sock, &readers)) {
                struct sockaddr_storage sas;
                struct sockaddr *sender_sock = (struct sockaddr*)&sas;
                socklen_t ss_size = sizeof(sas);

                if((HASH_COUNT(sss->tcp_connections) + 4) < FD_SETSIZE) {
                    SOCKET tmp_sock = accept(
                        sss->tcp_sock,
                        sender_sock,
                        &ss_size
                    );
                    // REVISIT: should we error out if ss_size returns bigger
                    // than before? can this ever happen?
                    if(tmp_sock >= 0) {
                        conn = (n2n_tcp_connection_t*)calloc(
                            1,
                            sizeof(n2n_tcp_connection_t)
                        );
                        if(conn) {
                            conn->socket_fd = tmp_sock;
                            memcpy(&(conn->sock), sender_sock, ss_size);
                            conn->sock_len = ss_size;
                            conn->inactive = 0;
                            conn->expected = sizeof(uint16_t);
                            conn->position = 0;
                            HASH_ADD_INT(sss->tcp_connections, socket_fd, conn);
                            traceEvent(
                                TRACE_INFO,
                                "accepted incoming TCP connection from [%s]",
                                sock_to_cstr(sockbuf, (n2n_sock_t*)sender_sock)
                            );
                        }
                    }
                } else {
                    // no space to store the socket for a new connection, close immediately
                    traceEvent(
                        TRACE_DEBUG,
                        "denied incoming TCP connection from [%s] due to max connections limit hit",
                        sock_to_cstr(sockbuf, (n2n_sock_t*)sender_sock)
                    );
                }
            }
#endif /* N2N_HAVE_TCP */

            int slots_ready = slots_fdset_loop(slots, &readers, &writers);

            if(slots_ready < 0) {
                traceEvent(
                    TRACE_ERROR,
                    "error: slots_fdset_loop = %i", slots_ready
                );
            } else if(slots_ready > 0) {
                // see edge_utils for note about linear scan
                for(int i=0; i<slots->nr_slots; i++) {
                    if(slots->conn[i].fd == -1) {
                        continue;
                    }

                    if(slots->conn[i].state == CONN_READY) {
                        mgmt_api_handler(sss, &slots->conn[i]);
                    }
                }
            }

        }

        // check for timed out slots
        slots_closeidle(slots);

        // If anything we recieved caused us to stop..
        if(!(*sss->keep_running))
            break;

        re_register_and_purge_supernodes(
            sss,
            sss->federation,
            &last_re_reg_and_purge,
            now,
            0 /* not forced */
        );
        purge_expired_communities(
            sss,
            &last_purge_edges,
            now
        );
        sort_communities(
            sss,
            &last_sort_communities,
            now
        );
        resolve_check(
            sss->resolve_parameter,
            false /* presumably, no special resolution requirement */,
            now
        );
    } /* while */

    sn_term(sss);

    return 0;
}
