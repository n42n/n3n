/**
 * (C) 2007-22 - ntop.org and contributors
 * Copyright (C) 2023 Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 */

#include <stdarg.h>  // for va_end, va_list, va_start
#include <stdio.h>   // for snprinf
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
void syslog (int a, char *s, char *buf) {
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

    if(traceFile == NULL) {
        traceFile = stderr;
    }

    char buf[1024];
    char out_buf[1280];
    char *extra_msg = "";
    time_t theTime = time(NULL);
    int i;

    /* We have two paths - one if we're logging, one if we aren't
     * Note that the no-log case is those systems which don't support it(WIN32),
     * those without the headers !defined(USE_SYSLOG)
     * those where it's parametrically off...
     */

    memset(buf, 0, sizeof(buf));

    va_start(va_ap, format);
    vsnprintf(buf, sizeof(buf) - 1, format, va_ap);
    va_end(va_ap);

    if(eventTraceLevel == 0 /* TRACE_ERROR */) {
        extra_msg = "ERROR: ";
    } else if(eventTraceLevel == 1 /* TRACE_WARNING */) {
        extra_msg = "WARNING: ";
    }

    while(buf[strlen(buf) - 1] == '\n') {
        buf[strlen(buf) - 1] = '\0';
    }

    if(useSyslog) {
        if(!syslog_opened) {
            openlog("n3n", LOG_PID, LOG_DAEMON);
            syslog_opened = 1;
        }

        snprintf(out_buf, sizeof(out_buf), "%s%s", extra_msg, buf);
        syslog(LOG_INFO, "%s", out_buf);
    } else {
        for(i = strlen(file) - 1; i > 0; i--) {
            if((file[i] == '/') || (file[i] == '\\')) {
                i++;
                break;
            }
        }
        char theDate[N2N_TRACE_DATESIZE];
        strftime(theDate, N2N_TRACE_DATESIZE, "%d/%b/%Y %H:%M:%S", localtime(&theTime));
        snprintf(out_buf, sizeof(out_buf), "%s [%s:%d] %s%s", theDate, &file[i], line, extra_msg, buf);
        fprintf(traceFile, "%s\n", out_buf);
        fflush(traceFile);
    }
}
