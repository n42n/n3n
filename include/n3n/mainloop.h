/**
 * Copyright (C) Hamish Coleman
 *
 * non public structure and function definitions
 *
 * TODO:
 * - fix the layering confusion in the calling code
 *   (apps/example_edge_embed.c apps/n3n-edge.c)
 *   and move this header back to the non-public src/ location
 */

#ifndef _MAINLOOP_H_
#define _MAINLOOP_H_

#include <connslot/strbuf.h>    // for strbuf_t
#include <n2n_typedefs.h>   // for n3n_runtime_data

#ifndef _WIN32
#include <sys/select.h>     // for fd_set
#endif

enum __attribute__((__packed__)) fd_info_proto {
    fd_info_proto_unknown = 0,
    fd_info_proto_tuntap,
    fd_info_proto_listen_http,
    fd_info_proto_v3udp,
    fd_info_proto_v3tcp,
    fd_info_proto_http,
};

// Place debug info from the slots into the strbuf
void mainloop_dump (strbuf_t **);

int mainloop_runonce (struct n3n_runtime_data *);

void mainloop_register_fd (int, enum fd_info_proto);
void mainloop_unregister_fd (int);


#endif
