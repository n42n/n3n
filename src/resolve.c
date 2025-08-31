/*
 * (C) 2007-22 - ntop.org and contributors
 * Copyright (C) 2023-25 Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * The resolver thread code and functions
 */

#include <errno.h>           // for EBUSY
#include <n3n/logging.h>
#include <n3n/metrics.h>
#include <n3n/resolve.h>     // for n3n_resolve_parameter_t
#include <n3n/strings.h>     // for sock_to_cstr
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>          // for sleep

#include "config.h"          // for HAVE_LIBPTHREAD
#include "resolve.h"
#include "n2n.h"             // for sock_equal
#include "n2n_define.h"
#include "n2n_typedefs.h"
#include "n2n_wire.h"        // for fill_n3nsock

struct peer_info;

#ifdef HAVE_LIBPTHREAD
#include <pthread.h>
#endif

#ifdef _WIN32
#include "win32/defs.h"
#include <ws2def.h>
#else
#include <netdb.h>           // for addrinfo, freeaddrinfo, gai_strerror
#include <netinet/in.h>
#include <sys/socket.h>      // for AF_INET, PF_INET
#include <sys/time.h>        // for gettimeofday, timersub
#endif

#define N2N_RESOLVE_INTERVAL            300 /* seconds until edge and supernode try to resolve supernode names again */
#define N2N_RESOLVE_CHECK_INTERVAL       30 /* seconds until main loop checking in on changes from resolver thread */

/**********************************************************/

static struct metrics {
    uint32_t count;
    uint32_t total_usec;
    uint32_t longest_usec;
} metrics;

static struct n3n_metrics_items_uint32 metrics_items[] = {
    {
        .name = "count",
        .desc = "Incremented for each name resolve",
        .offset = offsetof(struct metrics, count),
    },
    {
        .name = "total_usec",
        .desc = "Accumulated useconds waiting for name resolve results",
        .offset = offsetof(struct metrics, total_usec),
    },
    {
        .name = "longest_usec",
        .desc = "Time taken for longest resolve",
        .offset = offsetof(struct metrics, longest_usec),
    },
    { },
};

static struct n3n_metrics_module metrics_module = {
    .name = "resolve",
    .data = &metrics,
    .items_uint32 = metrics_items,
    .type = n3n_metrics_type_uint32,
};

/**********************************************************/

enum request_pkt_type {
    request_pkt_type_none = 0, // buf is unused
    request_pkt_type_error,    // contains an error result
    request_pkt_type_prep,     // preparing a request
    request_pkt_type_request,  // contains a request
    request_pkt_type_result,   // contains a non error result
};

#define REQUEST_PKT_MAX_HOSTNAME    64

struct request_pkt {
    enum request_pkt_type type;
    uint64_t id;               // Opaque data from requestor
    union {
        int error;
        char hostname[REQUEST_PKT_MAX_HOSTNAME];
        struct sockaddr_storage sa[15];
    };
};

static struct request_pkt request_pkt;

struct hostname_list_item {
    struct hostname_list_item *next;
    uint32_t next_resolve;  // Use 0 for "now"
    char s[];
};

// TODO: zeroth item unused
static struct hostname_list_item *hostname_lists[3];
// static struct supernode_str *supernode_next_resolve;

/** Resolve the supernode IP address.
 *
 */
// TODO: consider returning a list of n3n_sock_t in case a name resolves to IPv4 and IPv6 addresses
int supernode2sock (n3n_sock_t *sn, const char *addrIn) {

    char addr[64];  // FIXME: hardcoded max len for resolving
    char *supernode_host = NULL;
    char *supernode_port = NULL;
    char supernode_default_port[6];
    int nameerr;
    struct addrinfo aihints;
    struct addrinfo * ainfo = NULL;

    memset(&aihints, 0, sizeof(aihints));
    aihints.ai_family = AF_UNSPEC;     /* allow IPv4 or IPv6 */
    aihints.ai_socktype = SOCK_DGRAM;  /* default to UDP */

    // default to invalid output
    sn->family = AF_INVALID;

    if(!addrIn) {
        traceEvent(TRACE_DEBUG, "supernode2sock got NULL addrIn");
        return -6;
    }

    // check for prefixes "tcp://" or optionally "udp://" (default)
    const char *spec_start = addrIn;
    if(strncmp(spec_start, "tcp://", 6) == 0) {
        aihints.ai_socktype = SOCK_STREAM;
        spec_start += 6;
        traceEvent(TRACE_DEBUG, "supernode2sock found TCP protocol specified");
    } else if(strncmp(spec_start, "udp://", 6) == 0) {
        // already the default, just skip the prefix
        spec_start += 6;
    }

    // we will be working on a copy in *addr (without prefix, if any),
    // make sure it fits
    size_t length = strlen(spec_start);
    if(length > sizeof(addr) - 1) {
        traceEvent(
            TRACE_WARNING,
            "size of supernode argument too long: %zu; maximum size is %d",
            length,
            sizeof(addr) - 1
        );
        return -5;
    }
    strncpy(addr, spec_start, sizeof(addr) - 1);
    addr[sizeof(addr) - 1] = '\0'; /* ensure null termination */

    // parse the host and port
    supernode_host = addr;

    char *last_colon = strrchr(supernode_host, ':');
    char *closing_bracket = strrchr(supernode_host, ']');
    // a colon ':' is the port separator iff it's the last one and it appears
    // after any IPv6 address' closing bracket ']'
    if(last_colon && (last_colon > closing_bracket)) {
        *last_colon = '\0'; /* terminate the host_part at the colon */
        supernode_port = last_colon + 1;
    }

    // handle IPv6 address' brackets '[' ... ']' around the host part
    if((*supernode_host == '[') && closing_bracket) {
        *closing_bracket = '\0'; /* terminate the host_part at the bracket */
        supernode_host++;
    }

    // TODO: we could let getaddrinfo() handle this case which would lead to some
    // more descriptive error message; this code block might not be neccessary anymore
    if(*supernode_host == '\0') {
        traceEvent(
            TRACE_WARNING,
            "malformed supernode parameter (should be <host:port>) %s",
            addrIn
        );
        return -4;
    }

    // use default port if none was found
    if(!supernode_port || *supernode_port == '\0') {
        snprintf(supernode_default_port, sizeof(supernode_default_port), "%d", N2N_SN_LPORT_DEFAULT);
        supernode_port = supernode_default_port;
        traceEvent(
            TRACE_INFO,
            "no port specified, assuming default %s",
            supernode_port);
    }

    // TODO: the following line is fuse and needs to be removed for IPv6 support
    aihints.ai_family = AF_INET; /* enforce IPv4 */

    // resolve
    struct timeval time1;
    struct timeval time2;

    gettimeofday(&time1, NULL);
    nameerr = getaddrinfo(supernode_host, supernode_port, &aihints, &ainfo);
    gettimeofday(&time2, NULL);

    struct timeval elapsed;
    timersub(&time2, &time1, &elapsed);

    uint64_t elapsed_usec = elapsed.tv_sec * 1000000 + elapsed.tv_usec;

    metrics.count++;
    metrics.total_usec += elapsed_usec;
    if(metrics.longest_usec < elapsed_usec) {
        metrics.longest_usec = elapsed_usec;
    }

    if(nameerr != 0) {
        traceEvent(
            TRACE_WARNING,
            "supernode2sock fails to resolve supernode host %s, %d: %s",
            supernode_host,
            nameerr,
            gai_strerror(nameerr)
        );
        return -2;
    }

    if(!ainfo) {
        // shouldnt happen - if nameerr is zero, ainfo should not be null
        traceEvent(TRACE_WARNING, "supernode2sock unexpected error");
        return -1;
    }

    // TODO: remove this block when IPv6 is supported
    /* ainfo s the head of a linked list if non-NULL. */
    if(PF_INET != ainfo->ai_family) {
        /* should only return IPv4 addresses due to fused aihints. */
        traceEvent(
            TRACE_WARNING,
            "supernode2sock fails to resolve supernode IPv4 address for %s",
            supernode_host
        );
        freeaddrinfo(ainfo);
        return -1;
    }

    // loop through the results to find suitable output
    for(struct addrinfo *p = ainfo; p != NULL; p = p->ai_next) {
        // TODO: this block is another fuse to ensure IPv4 and only one result,
        //       needs rework for desired output format when IPv6 support
        if(p->ai_family == AF_INET) {
            if(fill_n3nsock(sn, p->ai_addr) == 0) {
                // Successfully filled the n3n_sock_t
                traceEvent(TRACE_INFO, "supernode2sock successfully resolved supernode IPv4 address for '%s'", supernode_host);
                break;
            } else {
                traceEvent(TRACE_WARNING, "supernode2sock: received an unsupported address family for %s", supernode_host);
                freeaddrinfo(ainfo);
                return -1;
            }
        }
    }

    // TODO: adapt when IPv6 support
    // if we got this far and haven't got a valid socket...
    if(sn->family == AF_INVALID) {
        // ... there is no valid IPv4 address
        traceEvent(TRACE_WARNING, "supernode2sock: Host '%s' resolved, but no usable IPv4 address was found.", supernode_host);
        freeaddrinfo(ainfo);
        return -1;
    }

    freeaddrinfo(ainfo); /* free everything allocated by getaddrinfo(). */

    return 0;
}


#ifdef HAVE_LIBPTHREAD

#ifdef _MSC_VER
// FIXME: this code may not work as expected - see also src/win32/n2n_win32.h
//
#define N2N_THREAD_RETURN_DATATYPE       DWORD WINAPI
#define N2N_THREAD_PARAMETER_DATATYPE    LPVOID
#else
#define N2N_THREAD_RETURN_DATATYPE        void*
#define N2N_THREAD_PARAMETER_DATATYPE     void*
#endif

N2N_THREAD_RETURN_DATATYPE resolve_thread (N2N_THREAD_PARAMETER_DATATYPE p) {

    n3n_resolve_parameter_t *param = (n3n_resolve_parameter_t*)p;
    struct n3n_resolve_ip_sock *entry;
    struct n3n_resolve_ip_sock *tmp_entry;
    time_t rep_time = N2N_RESOLVE_INTERVAL / 10;
    time_t now;

    while(1) {
        sleep(N2N_RESOLVE_INTERVAL / 60); /* wake up in-between to check for signaled requests */

        // what's the time?
        now = time(NULL);

        // lock access
        pthread_mutex_lock(&param->access);

        // is it time to resolve yet?
        if(((param->request)) || ((now - param->last_resolved) > rep_time)) {
            HASH_ITER(hh, param->list, entry, tmp_entry) {
                // resolve
                entry->error_code = supernode2sock(&entry->sock, entry->org_ip);
                // if socket changed and no error
                if(!sock_equal(&entry->sock, entry->org_sock)
                   && (!entry->error_code)) {
                    // flag the change
                    param->changed = true;
                }
            }
            param->last_resolved = now;

            // any request fulfilled
            param->request = false;

            // determine next resolver repetition (shorter time if resolver errors occured)
            rep_time = N2N_RESOLVE_INTERVAL;
            HASH_ITER(hh, param->list, entry, tmp_entry) {
                if(entry->error_code) {
                    rep_time = N2N_RESOLVE_INTERVAL / 10;
                    break;
                }
            }
        }

        // unlock access
        pthread_mutex_unlock(&param->access);
    }
}

int resolve_create_thread (n3n_resolve_parameter_t **param, struct peer_info *sn_list) {
    struct peer_info        *sn, *tmp_sn;
    struct n3n_resolve_ip_sock *entry;
    int ret;

    // create parameter structure
    *param = (n3n_resolve_parameter_t*)calloc(1, sizeof(n3n_resolve_parameter_t));
    if(*param) {
        HASH_ITER(hh, sn_list, sn, tmp_sn) {
            // create entries for those peers that come with hostname string (from command-line)
            if(sn->hostname) {
                entry = (struct n3n_resolve_ip_sock*)calloc(1, sizeof(struct n3n_resolve_ip_sock));
                if(entry) {
                    entry->org_ip = sn->hostname;
                    entry->org_sock = &(sn->sock);
                    memcpy(&(entry->sock), &(sn->sock), sizeof(n3n_sock_t));
                    HASH_ADD(hh, (*param)->list, org_ip, sizeof(char*), entry);
                } else
                    traceEvent(
                        TRACE_WARNING,
                        "resolve_create_thread was unable to add list entry for supernode '%s'",
                        sn->hostname
                    );
            }
        }
        (*param)->check_interval = N2N_RESOLVE_CHECK_INTERVAL;
    } else {
        traceEvent(TRACE_WARNING, "resolve_create_thread was unable to create list of supernodes");
        return -1;
    }

    // create thread
    ret = pthread_create(&((*param)->id), NULL, resolve_thread, (void *)*param);
    if(ret) {
        traceEvent(TRACE_WARNING, "resolve_create_thread failed to create resolver thread with error number %d", ret);
        return -1;
    }

    pthread_mutex_init(&((*param)->access), NULL);

    return 0;
}


void resolve_cancel_thread (n3n_resolve_parameter_t *param) {
    pthread_cancel(param->id);
    free(param);
}


bool resolve_check (n3n_resolve_parameter_t *param, bool requires_resolution, time_t now) {

    bool ret = requires_resolution; /* if trylock fails, it still requires resolution */

    struct n3n_resolve_ip_sock *entry;
    struct n3n_resolve_ip_sock *tmp_entry;
    n2n_sock_str_t sock_buf;

    if(NULL == param)
        return ret;

    // check_interval and last_check do not need to be guarded by the mutex because
    // their values get changed and evaluated only here

    if((now - param->last_checked > param->check_interval) || (requires_resolution)) {
        // try to lock access
        if(pthread_mutex_trylock(&param->access) == 0) {
            // any changes?
            if(param->changed) {
                // reset flag
                param->changed = false;
                // unselectively copy all socks (even those with error code, that would be the old one because
                // sockets do not get overwritten in case of error in resolve_thread) from list to supernode list
                HASH_ITER(hh, param->list, entry, tmp_entry) {
                    memcpy(entry->org_sock, &entry->sock, sizeof(n3n_sock_t));
                    traceEvent(TRACE_INFO, "resolve_check renews ip address of supernode '%s' to %s",
                               entry->org_ip, sock_to_cstr(sock_buf, &(entry->sock)));
                }
            }

            // let the resolver thread know eventual difficulties in reaching the supernode
            if(requires_resolution) {
                param->request = true;
                ret = false;
            }

            param->last_checked = now;

            // next appointment
            if(param->request)
                // earlier if resolver still working on fulfilling a request
                param->check_interval = N2N_RESOLVE_CHECK_INTERVAL / 10;
            else
                param->check_interval = N2N_RESOLVE_CHECK_INTERVAL;

            // unlock access
            pthread_mutex_unlock(&param->access);
        }
    }

    return ret;
}


int maybe_supernode2sock (n3n_sock_t * sn, const char *addrIn) {
    return 0;
}

#else // HAVE_LIBPTHREAD

int resolve_create_thread (n3n_resolve_parameter_t **param, struct peer_info *sn_list) {
    return -1;
}

void resolve_cancel_thread (n3n_resolve_parameter_t *param) {
    return;
}


bool resolve_check (n3n_resolve_parameter_t *param, bool requires_resolution, time_t now) {
    return requires_resolution;
}

int maybe_supernode2sock (n3n_sock_t * sn, const char *addrIn) {
    return supernode2sock(sn, addrIn);
}
#endif

/*
 * Remove all entries from a hostnames list
 *
 */
void resolve_hostnames_free (int listnr) {
    struct hostname_list_item *p = hostname_lists[listnr];
    while(p) {
        struct hostname_list_item *p_next = p->next;
        free(p);
        p = p_next;
    }
}

/*
 * Add a string to our list of resolvable supernodes
 */
void resolve_hostnames_str_add (int listnr, const char *s) {
    int len = sizeof(struct hostname_list_item) + strlen(s) + 1;
    struct hostname_list_item *p = malloc(len);
    if(!p) {
        return;
    }

    strcpy((char *)&(p->s), s);
    p->next_resolve = 0;    // mark as "Now"
    p->next = hostname_lists[listnr];
    hostname_lists[listnr] = p;
}

/*
 * For config dumping, provide a way to access the list
 * (Not intended to be called often, so not performant)
 */
const char *resolve_hostnames_str_get (int listnr, int index) {
    struct hostname_list_item *p = hostname_lists[listnr];
    while(index) {
        if(!p) {
            return NULL;
        }
        p = p->next;
        index--;
    }
    if(!p) {
        return NULL;
    }
    return p->s;
}

// Just dump the whole hostname list to the log
void resolve_log_hostnames (int listnr) {
    traceEvent(TRACE_INFO, "hostname list %i:", listnr);

    int count = 0;
    struct hostname_list_item *p = hostname_lists[listnr];
    while(p) {
        count++;
        traceEvent(TRACE_INFO, "name %i = %s\n", count, p->s);
        p = p->next;
    }
    traceEvent(TRACE_INFO, "number of hostnames in this list: %i\n", count);
}

/*
 * Convert one string into an added peer_info
 * (This is a refactor of n3n_peer_add_by_hostname)
 *
 */
static int resolve_hostnames_str_to_peer_info_one (
    struct peer_info **list,
    const char *s
) {

    n3n_sock_t sock;
    memset(&sock, 0, sizeof(sock));

    traceEvent(TRACE_DEBUG, "resolving %s", s);

    if(!s) {
        // With no hostname, cannot do anything
        return 1;
    }

    // WARN: this function could block for a name resolution
    int rv = supernode2sock(&sock, s);

    if(rv < 0) {
        /* just warn, since it might resolve next time */
        traceEvent(TRACE_WARNING, "could not resolve %s", s);
        return 1;
    }

    int skip_add = SN_ADD;
    struct peer_info *peer = add_sn_to_list_by_mac_or_sock(
        list,
        &sock,
        null_mac,
        &skip_add
    );

    if(!peer) {
        return 1;
    }

    if(!peer_info_get_hostname(peer)) {
        // We dup the string here because the peer_info_free() thinks it owns
        // the hostname and wants to free() it
        // TODO: refactor
        peer->hostname = strdup(s);
    }

    memcpy(&(peer->sock), &sock, sizeof(n3n_sock_t));

    // If a new peer was added, it has already been init, but we want to reset
    // the state of any old peer object
    if(skip_add != SN_ADD_ADDED) {
        peer_info_init(peer, null_mac);
    }

    // This is the only peer_info where the default purgeable=true
    // is overwritten
    peer->purgeable = false;

    // TODO: say something different if we updated an existing record?
    traceEvent(
        TRACE_INFO,
        "adding supernode = %s",
        peer_info_get_hostname(peer)
    );

    return 0;
}

/*
 * Convert the entire supernode list into peer_info structs
 *
 * TODO:
 * - update the next_resolve field, also use it to skip fast resolves
 * - support multiple hostname results (both A and AAAA as well)
 * - eventually, support SRV
 */
int resolve_hostnames_str_to_peer_info (int listnr, struct peer_info **peers) {
    if(!peers) {
        return 1;
    }
    struct hostname_list_item *p = hostname_lists[listnr];
    int rv = 0;
    while(p) {
        rv += resolve_hostnames_str_to_peer_info_one(peers, p->s);
        p = p->next;
    }
    return rv;
}

// This function is the main thread processor
static void request_pkt_process () {
    if(request_pkt.type != request_pkt_type_request) {
        // The request buf is not owned by us, return to sleep
        return;
    }

    char *p = (char *)&request_pkt.hostname;
    char *node = p;
    char *service;

    if(*p == '[') {
        // This is a IPv6 raw address
        node = p + 1;

        // find the end of the raw address
        p = strchr(p, ']');
        if(!p) {
            traceEvent(
                TRACE_ERROR,
                "Bad end of IPv6 address: %s",
                node - 1
            );
            request_pkt.type = request_pkt_type_error;
            request_pkt.error = 1000;
            return;
        }

        // and mark the raw addr end
        *p = '\0';

        // Point at the start of any possible port
        p++;
    }

    service = strchr(p, ':');
    if(service) {
        // mark the end of node name
        *service = '\0';
        // skip to the port
        service++;
    } else {
        service = "7654";   // The default port if none is specified
    }

    struct addrinfo hints = {
        .ai_family = AF_UNSPEC,     // Allow both
        .ai_socktype = SOCK_DGRAM,  // TODO: address this for TCP support
#ifdef AI_ADDRCONFIG
        // Another wierd Windows ifdef
        // TODO: understand and fix
        .ai_flags = AI_ADDRCONFIG,
#endif
        .ai_protocol = 0,
    };
    struct addrinfo *result;

    struct timeval time1;
    struct timeval time2;

    gettimeofday(&time1, NULL);
    int rc = getaddrinfo(node, service, &hints, &result);
    gettimeofday(&time2, NULL);

    struct timeval elapsed;
    timersub(&time2, &time1, &elapsed);

    uint64_t elapsed_usec = elapsed.tv_sec * 1000000 + elapsed.tv_usec;

    metrics.count++;
    metrics.total_usec += elapsed_usec;
    if(metrics.longest_usec < elapsed_usec) {
        metrics.longest_usec = elapsed_usec;
    }

    if(rc != 0) {
        // Since network disconnection events can happen, a failure to resolve
        // is not a TRACE_ERROR
        traceEvent(
            TRACE_WARNING,
            "getaddrinfo(%s, %s, ..) returned error %i",
            node,
            service,
            rc
        );
        request_pkt.error = rc;
        request_pkt.type = request_pkt_type_error;
        return;
    }

    struct addrinfo *rp;
    for(rp = result; rp != NULL; rp = rp->ai_next) {
        // append to results
        // if n > count of request_buf.sa
        // if rp->ai_addrlen > sizeof(request_buf.sa[0]) then error
        // memcpy to request_buf.sa[n] from rp->ai_addr size rp->ai_addrlen
        traceEvent(
            TRACE_ERROR,
            "rp %i %i %i %i %i sa %s",
            rp->ai_flags,
            rp->ai_family,
            rp->ai_socktype,
            rp->ai_protocol,
            rp->ai_addrlen,
            // sa
            rp->ai_canonname
        );
    }
    freeaddrinfo(result);
}

static int request_pkt_send (uint64_t id, char *hostname) {
    if(request_pkt.type != request_pkt_type_none) {
        // If the buf is already busy, we cannot add more to it
        return EBUSY;
    }

    // Mark it as incomplete
    request_pkt.type = request_pkt_type_prep;

    // Fill in the details
    request_pkt.id = id;
    strncpy(
        (char *)&request_pkt.hostname,
        hostname,
        REQUEST_PKT_MAX_HOSTNAME - 1
    );
    // request_pkt.hostname[sizeof(&request_pkt.hostname)] = 0;
    request_pkt.hostname[REQUEST_PKT_MAX_HOSTNAME - 1] = 0;

    // Mark it for processing by the resolve thread
    request_pkt.type = request_pkt_type_request;

    // TODO:
    // ifdef HAVE_LIBPTHREAD
    //   wake up the thread
    // else
    request_pkt_process();
    // endif

    // no error
    return 0;
}

static void request_pkt_init () {
    request_pkt.type = request_pkt_type_none;
}

void n3n_initfuncs_resolve () {
    n3n_metrics_register(&metrics_module);
    request_pkt_init();
}

void n3n_deinitfuncs_resolve () {
    // TODO: there chould be a _del() function that the original callers
    // can use to remove their entries in their own
    resolve_hostnames_free(RESOLVE_LIST_SUPERNODE);
    resolve_hostnames_free(RESOLVE_LIST_PEER);
}
