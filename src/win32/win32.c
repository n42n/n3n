/*
 * Copyright (C) 2024 Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Windows specific common functions
 */

#include <stdio.h>

#include "defs.h"

void n3n_initfunc_win32 () {
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
