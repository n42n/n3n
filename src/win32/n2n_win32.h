/*

        (C) 2007-22 - Luca Deri <deri@ntop.org>

 */

#ifndef _N2N_WIN32_H_
#define _N2N_WIN32_H_

#include <winsock2.h>
#include <windows.h>
#include <ws2def.h>
#include <ws2ipdef.h>
#if defined(_MSC_VER)
#include <Iphlpapi.h>
#pragma comment(lib,"Iphlpapi.lib")
#endif
#include <netioapi.h>
#include <winioctl.h>
#include <iptypes.h>


#include "wintap.h"

#undef EAFNOSUPPORT
#define EAFNOSUPPORT   WSAEAFNOSUPPORT
#define MAX(a,b) (a > b ? a : b)
#define MIN(a,b) (a < b ? a : b)

#define snprintf _snprintf
#define strdup _strdup

#define socklen_t int


/* ************************************* */



#define index(a, b) strchr(a, b)
#define sleep(x) Sleep(x * 1000)


/* ************************************* */


#define HAVE_PTHREAD
#define pthread_t       HANDLE
#define pthread_mutex_t HANDLE

#define pthread_create(p_thread_handle, attr, thread_func, p_param)                         \
    (*p_thread_handle = CreateThread(0 /* default security flags */, 0 /*default stack*/,   \
                                     thread_func, p_param, 0 /* default creation flags */,                      \
                                     NULL) == 0)

#define pthread_cancel(p_thread_handle) \
    TerminateThread(p_thread_handle, 0)

#define pthread_mutex_init(p_mutex_handle, attr)                      \
    *p_mutex_handle = CreateMutex(NULL /*default security flags */,  \
                                  FALSE /* initially not owned */, NULL /* unnamed */)

#define pthread_mutex_lock(mutex)         \
    WaitForSingleObject(*mutex, INFINITE)

#define pthread_mutex_trylock(mutex)  \
    WaitForSingleObject(*mutex, NULL)

#define pthread_mutex_unlock(mutex) \
    ReleaseMutex(*mutex)


/* ************************************* */


#endif
