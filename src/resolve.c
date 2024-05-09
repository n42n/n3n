/*
 * (C) 2007-22 - ntop.org and contributors
 * Copyright (C) 2023-24 Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * The resolver thread code and functions
 */

#include <n2n.h>             // for sock_equal
#include <n3n/logging.h>
#include <n3n/metrics.h>
#include <n3n/resolve.h>     // for n3n_resolve_parameter_t
#include <n3n/strings.h>     // for sock_to_cstr
#include <unistd.h>          // for sleep
#include "resolve.h"
#include "config.h"          // for HAVE_LIBPTHREAD

#ifdef HAVE_LIBPTHREAD
#include <pthread.h>
#endif

#ifdef _WIN32
#include "win32/defs.h"
#include <ws2def.h>
#else
#include <netdb.h>           // for addrinfo, freeaddrinfo, gai_strerror
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

/** Resolve the supernode IP address.
 *
 */
int supernode2sock (n2n_sock_t *sn, const n2n_sn_name_t addrIn) {

    n2n_sn_name_t addr;
    char *supernode_host;
    char *supernode_port;
    int nameerr;
    const struct addrinfo aihints = {0, PF_INET, 0, 0, 0, NULL, NULL, NULL};
    struct addrinfo * ainfo = NULL;
    struct sockaddr_in * saddr;

    size_t length = strlen(addrIn);
    if(length >= N2N_EDGE_SN_HOST_SIZE) {
        traceEvent(
            TRACE_WARNING,
            "size of supernode argument too long: %zu; maximum size is %d",
            length,
            N2N_EDGE_SN_HOST_SIZE
        );
        return -5;;
    }

    sn->family = AF_INVALID;

    memcpy(addr, addrIn, N2N_EDGE_SN_HOST_SIZE);
    supernode_host = strtok(addr, ":");

    if(!supernode_host) {
        traceEvent(
            TRACE_WARNING,
            "malformed supernode parameter (should be <host:port>) %s",
            addrIn
        );
        return -4;
    }

    supernode_port = strtok(NULL, ":");

    if(!supernode_port) {
        traceEvent(
            TRACE_WARNING,
            "malformed supernode parameter (should be <host:port>) %s",
            addrIn
        );
        return -3;
    }

    sn->port = atoi(supernode_port);

    struct timeval time1;
    struct timeval time2;

    gettimeofday(&time1, NULL);
    nameerr = getaddrinfo(supernode_host, NULL, &aihints, &ainfo);
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

    /* ainfo s the head of a linked list if non-NULL. */
    if(PF_INET != ainfo->ai_family) {
        /* Should only return IPv4 addresses due to aihints. */
        traceEvent(
            TRACE_WARNING,
            "supernode2sock fails to resolve supernode IPv4 address for %s",
            supernode_host
        );
        freeaddrinfo(ainfo);
        return -1;
    }

    /* It is definitely and IPv4 address -> sockaddr_in */
    saddr = (struct sockaddr_in *)ainfo->ai_addr;
    memcpy(sn->addr.v4, &(saddr->sin_addr.s_addr), IPV4_SIZE);
    sn->family = AF_INET;
    traceEvent(TRACE_INFO, "supernode2sock successfully resolves supernode IPv4 address for %s", supernode_host);

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
                    memcpy(&(entry->sock), &(sn->sock), sizeof(n2n_sock_t));
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
                    memcpy(entry->org_sock, &entry->sock, sizeof(n2n_sock_t));
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


int maybe_supernode2sock (n2n_sock_t * sn, const n2n_sn_name_t addrIn) {
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

int maybe_supernode2sock (n2n_sock_t * sn, const n2n_sn_name_t addrIn) {
    return supernode2sock(sn, addrIn);
}
#endif

void n3n_initfuncs_resolve () {
    n3n_metrics_register(&metrics_module);
}
