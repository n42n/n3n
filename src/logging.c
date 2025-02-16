/**
 * (C) 2007-22 - ntop.org and contributors
 * Copyright (C) 2023-25 Hamish Coleman
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 */

#include <n3n/logging.h>
#include <stdarg.h>  // for va_end, va_list, va_start
#include <stdio.h>   // for snprinf
#include <stdlib.h>  // for getenv
#include <string.h>  // for strlen
#include <time.h>    // for time_t

#ifdef _WIN32
#else
#include <syslog.h>  // for closelog, openlog, syslog, LOG_DAEMON
#endif

static int traceLevel = 2 /* NORMAL */;
static int useSyslog = 0;
static int syslog_opened = 0;
static FILE *traceFile = NULL;
static int output_dateprefix = -1; // initially "unknown"

#ifdef _WIN32
// Some dummy definitions to make windows compiling simpler
#define LOG_PID -1
#define LOG_DAEMON -2
#define LOG_INFO -3
void closelog () {
    return;
}
void openlog (char *s, int a, int b) {
    return;
}
void syslog (int a, char *fmt, ...) {
    return;
}
#endif

int getTraceLevel () {

    return(traceLevel);
}

void setTraceLevel (int level) {

    traceLevel = level;
}

void setUseSyslog (int use_syslog) {

    useSyslog = use_syslog;
}

void closeTraceFile () {

    if((traceFile != NULL) && (traceFile != stdout)) {
        fclose(traceFile);
    }
    if(useSyslog && syslog_opened) {
        closelog();
        syslog_opened = 0;
    }
}

#define N2N_TRACE_DATESIZE 32
void _traceEvent (int eventTraceLevel, char* file, int line, char * format, ...) {
    va_list va_ap;

    if(eventTraceLevel > traceLevel) {
        return;
    }

    char buf[1024];
    char *extra_msg = "";

    va_start(va_ap, format);
    int size = vsnprintf(buf, sizeof(buf) - 1, format, va_ap);
    va_end(va_ap);

    if(size > (sizeof(buf)-1)) {
        // truncation has occured
        buf[sizeof(buf)-1] = 0;
    }

    if(eventTraceLevel == TRACE_ERROR ) {
        extra_msg = "ERROR: ";
    } else if(eventTraceLevel == TRACE_WARNING ) {
        extra_msg = "WARNING: ";
    }

    // Remove trailing newlines
    while(buf[strlen(buf) - 1] == '\n') {
        buf[strlen(buf) - 1] = '\0';
    }

    if(useSyslog) {
        if(!syslog_opened) {
            openlog("n3n", LOG_PID, LOG_DAEMON);
            syslog_opened = 1;
        }

        syslog(LOG_INFO, "[%s:%i] %s%s", file, line, extra_msg, buf);
        return;
    } else {
        if(output_dateprefix == -1) {
            char *stream = getenv("JOURNAL_STREAM");
            if(stream == NULL) {
                output_dateprefix = 1;
            } else {
                // If we are outputting via the journald, avoid double dates
                output_dateprefix = 0;
            }
        }

        char theDate[N2N_TRACE_DATESIZE] = "";
        if(output_dateprefix == 1) {
            time_t theTime = time(NULL);
            strftime(theDate, N2N_TRACE_DATESIZE, "%d/%b/%Y %H:%M:%S ", localtime(&theTime));
        }

        if(traceFile == NULL) {
            traceFile = stderr;
        }

        fprintf(traceFile, "%s[%s:%d] %s%s\n", theDate, file, line, extra_msg, buf);
        fflush(traceFile);
        return;
    }
}
