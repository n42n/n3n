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

#include <n2n_typedefs.h>   // for n3n_runtime_data

enum __attribute__((__packed__)) fd_info_proto {
    fd_info_proto_unknown = 0,
    fd_info_proto_tuntap,
    fd_info_proto_listen_http,
};

int mainloop_runonce (fd_set *, fd_set *, struct n3n_runtime_data *);

void mainloop_register_fd (int, enum fd_info_proto);
void mainloop_unregister_fd (int);


#endif
