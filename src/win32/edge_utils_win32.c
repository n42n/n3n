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

#include "defs.h"
#include <iphlpapi.h>
#include <n3n/logging.h>    // for traceEvent

#include "edge_utils_win32.h"

/* ************************************** */
// TODO: move these polyfill functions into their own source file

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

/* ************************************** */

static DWORD* tunReadThread (LPVOID lpArg) {

    struct tunread_arg *arg = (struct tunread_arg*)lpArg;

    while(*arg->eee->keep_running) {
        edge_read_from_tap(arg->eee);
    }

    return((DWORD*)NULL);
}

/* ************************************** */

/** Start a second thread in Windows because TUNTAP interfaces do not expose
 *    file descriptors. */
HANDLE startTunReadThread (struct tunread_arg *arg) {

    DWORD dwThreadId;

    return(CreateThread(NULL,          /* security attributes */
                        0,             /* use default stack size */
                        (LPTHREAD_START_ROUTINE)tunReadThread, /* thread function */
                        (void*)arg,    /* argument to thread function */
                        0,             /* thread creation flags */
                        &dwThreadId)); /* thread id out */
}



int get_best_interface_ip (uint32_t addr_v4, dec_ip_str_t *ip_addr){
    DWORD interface_index = -1;
    DWORD dwRetVal = 0;
    PIP_ADAPTER_INFO pAdapterInfo = NULL, pAdapter = NULL;
    macstr_t mac_buf;
    ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);

    dwRetVal = GetBestInterface(addr_v4, &interface_index);
    if(dwRetVal != NO_ERROR) return -1;

    pAdapterInfo = (PIP_ADAPTER_INFO)malloc(ulOutBufLen);
    if(pAdapterInfo == NULL) {
        traceEvent(TRACE_INFO, "Error allocating memory needed to call GetAdaptersInfo\n");
        return -1;
    }

    dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen);
    if(dwRetVal == ERROR_BUFFER_OVERFLOW) {
        pAdapterInfo = (PIP_ADAPTER_INFO)realloc(pAdapterInfo, ulOutBufLen);
        if(pAdapterInfo == NULL) {
            traceEvent(TRACE_INFO, "Error allocating memory needed to call GetAdaptersInfo\n");
            return -1;
        }
    }

    dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen);
    if(dwRetVal == NO_ERROR) {
        for(pAdapter = pAdapterInfo; pAdapter != NULL; pAdapter = pAdapter->Next) {
            if(pAdapter->Index != interface_index) continue;

            traceEvent(TRACE_DEBUG, "Adapter Index: %ld\n", pAdapter->Index);
            traceEvent(TRACE_DEBUG, "Combo Index:   %ld\n", pAdapter->ComboIndex);
            traceEvent(TRACE_DEBUG, "Adapter Name:  %s\n", pAdapter->AdapterName);
            traceEvent(TRACE_DEBUG, "Adapter Desc:  %s\n", pAdapter->Description);
            traceEvent(TRACE_DEBUG, "Adapter Type:  %u\n", pAdapter->Type);
            macaddr_str(mac_buf, pAdapter->Address);
            traceEvent(TRACE_DEBUG, "Adapter Addr:  %s\n", mac_buf);
            traceEvent(TRACE_DEBUG, "DHCP Enabled:  %u\n", pAdapter->DhcpEnabled);
            traceEvent(TRACE_DEBUG, "DHCP Server:   %s\n", pAdapter->DhcpServer.IpAddress.String);
            traceEvent(TRACE_DEBUG, "IP Address:    %s\n", pAdapter->IpAddressList.IpAddress.String);
            traceEvent(TRACE_DEBUG, "IP Mask:       %s\n", pAdapter->IpAddressList.IpMask.String);
            traceEvent(TRACE_DEBUG, "Gateway:       %s\n", pAdapter->GatewayList.IpAddress.String);
            strncpy(ip_addr, pAdapter->IpAddressList.IpAddress.String, sizeof(*ip_addr));
        }
    } else {
        traceEvent(TRACE_WARNING, "GetAdaptersInfo failed with error: %d\n", dwRetVal);
    }
    if(pAdapterInfo != NULL) {
        free(pAdapterInfo);
        pAdapterInfo = NULL;
    }
    return 0;
}
