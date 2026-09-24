/**
 * (C) 2007-22 - ntop.org and contributors
 * Copyright (C) 2023-25 Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Public API for logging
 */

#ifndef _N3N_LOGGING_H_
#define _N3N_LOGGING_H_

#include <stdio.h>  // for FILE

#define TRACE_ERROR       0
#define TRACE_WARNING     1
#define TRACE_NORMAL      2
#define TRACE_INFO        3
#define TRACE_DEBUG       4

void setTraceLevel (int level);
void setUseSyslog (int use_syslog);
int getTraceLevel ();
void closeTraceFile ();
void _traceEvent (int eventTraceLevel, char* file, int line, char * format, ...);

// check before call to not make expensive argument evaluation when not required
// do while is required when traceEvent call is in some if-then-ELSE because it can become our else here other-wise
#define traceEvent(level, format, ...) \
    do { \
        if((level) <= getTraceLevel()) { \
            _traceEvent(level, __FILE__, __LINE__, format, ## __VA_ARGS__); \
        } \
    } while(0)

#endif
