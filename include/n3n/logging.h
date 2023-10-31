/**
 * (C) 2007-22 - ntop.org and contributors
 * Copyright (C) 2023 Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Public API for logging
 */

#ifndef _N2N_LOGGING_H_
#define _N2N_LOGGING_H_

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
#define traceEvent(level, format, ...) _traceEvent(level, __FILE__, __LINE__, format, ## __VA_ARGS__)

#endif
