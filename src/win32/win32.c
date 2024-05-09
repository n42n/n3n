/*
 * (C) 2007-22 - ntop.org and contributors
 * Copyright (C) 2024 Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Windows specific common functions
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "defs.h"

void n3n_initfuncs_win32 () {
    WSADATA wsaData;
    int err;

    err = WSAStartup(MAKEWORD(2, 2), &wsaData );
    if( err != 0 ) {
        /* Tell the user that we could not find a usable */
        /* WinSock DLL.                                  */
        printf("FATAL ERROR: unable to initialise Winsock 2.x.");
        exit(EXIT_FAILURE);
    }
}

void destroyWin32 () {
    WSACleanup();
}

/* ************************************** */
// Some polyfill functions
// TODO: switch to just using struct sockaddr everywhere and then can use
// getnameinfo directly and delete these functions

/*
 * The inet_ntop function was not included in windows until after Windows XP
 */

const char *fill_inet_ntop (int af, const void *src, char *dst, int size) {
    if(af == AF_INET) {
        struct sockaddr_in in;
        memset(&in, 0, sizeof(in));

        in.sin_family = AF_INET;
        memcpy(&in.sin_addr, src, sizeof(in.sin_addr));
        getnameinfo((struct sockaddr *)&in,sizeof(in),dst,size,NULL,0,NI_NUMERICHOST);
        return dst;
    }

    if(af == AF_INET6) {
        struct sockaddr_in6 in6;
        memset(&in6, 0, sizeof(in6));

        in6.sin6_family = AF_INET6;
        memcpy(&in6.sin6_addr, src, sizeof(in6.sin6_addr));
        getnameinfo((struct sockaddr *)&in6,sizeof(in6),dst,size,NULL,0,NI_NUMERICHOST);
        return dst;
    }

    return NULL;
}

int fill_inet_pton (int af, const char *restrict src, void *restrict dst) {
    if(af != AF_INET) {
        // We simply dont support IPv6 on old Windows
        return -1;
    }
    if((NULL == src) || (NULL == dst)) {
        return -1;
    }

    struct addrinfo *result = NULL;
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_flags = AI_NUMERICHOST;
    hints.ai_family = af;

    if(getaddrinfo(src, NULL, &hints, &result) != 0) {
        freeaddrinfo(result);
        return -1;
    }

    struct sockaddr_in *sa = (struct sockaddr_in *)result->ai_addr;
    *((uint32_t *)dst) = sa->sin_addr.s_addr;
    return 1;
}

void fill_timersub (struct timeval *a, struct timeval *b, struct timeval *res) {
    if(!a || !b || !res) {
        return;
    }

    res->tv_usec = a->tv_usec - b->tv_usec;
    if(res->tv_usec < 0) {
        a->tv_sec--;
        res->tv_usec += 1000000;
    }
    res->tv_sec = a->tv_sec - b->tv_sec;
}

int fill_gettimeofday (struct timeval * tv, void * tz) {
    if(!tv) {
        return -1;
    }

    SYSTEMTIME st;
    FILETIME ft;
    ULARGE_INTEGER wtf;

    GetSystemTime(&st);
    SystemTimeToFileTime(&st, &ft);

    wtf.u.LowPart = ft.dwLowDateTime;
    wtf.u.HighPart = ft.dwHighDateTime;

    // Convert from Windows Epoch to unix Epoch
    wtf.QuadPart -= 116444736000000000ULL;

    tv->tv_sec = wtf.QuadPart / 10000000L;
    tv->tv_usec = st.wMilliseconds * 1000;
    return 0;
}
