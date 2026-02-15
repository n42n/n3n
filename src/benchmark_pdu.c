/*
 * Copyright (C) Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 */

#include <n2n.h>            // for edge_init
#include <n2n_define.h>     // for N2N_PKT_BUF_SIZE
#include <n2n_typedefs.h>   // for n2n_edge_conf
#include <n3n/benchmark.h>  // for bench_item
#include <n3n/edge.h>       // for edge_init_conf_defaults, edge_verify_conf
#include <n3n/resolve.h>    // for resolve_supernode_str_add
#include <stddef.h>         // for NULL
#include <stdio.h>          // for perror
#include <stdlib.h>         // for calloc, free
#include <unistd.h>         // for read

#ifndef _WIN32
#include <sys/socket.h>     // for socketpair
#endif

#include "peer_info.h"      // for peer_info_malloc

struct bench_ctx {
    struct n3n_runtime_data eee;
    int sv[2];
    uint8_t outbuf[N2N_PKT_BUF_SIZE];
    ssize_t outbuf_size;
};

static void *bench_setup (void) {
    struct bench_ctx *ctx = calloc(1, sizeof(struct bench_ctx));

    edge_init_conf_defaults(&ctx->eee.conf,"edge");
    strcpy(ctx->eee.conf.community_name, "test");
    ctx->eee.conf.transop_id = N2N_TRANSFORM_ID_NULL;
    ctx->eee.last_sup = 1;
    ctx->eee.curr_sn = peer_info_malloc(null_mac);
    ctx->eee.curr_sn->sock.family = AF_INVALID;

    n2n_transop_null_init(&ctx->eee.conf, &ctx->eee.transop);

#ifndef _WIN32
    if(socketpair(AF_UNIX, SOCK_DGRAM, 0, ctx->sv) == -1) {
        perror("socketpair");
        exit(EXIT_FAILURE);
    }
    ctx->eee.device.fd = ctx->sv[0];
#else
    ctx->sv[0] = -1;
    ctx->sv[1] = -1;
#endif
    return ctx;
}

static void bench_teardown (void *_ctx) {
    struct bench_ctx *ctx = (struct bench_ctx *)_ctx;

    clear_peer_list(&ctx->eee.pending_peers);
    peer_info_free(ctx->eee.curr_sn);
    edge_term_conf(&ctx->eee.conf);
    free(ctx);
}

static const void *const bench_get_output (void *const _ctx) {
    struct bench_ctx *ctx = (struct bench_ctx *)_ctx;
    return &ctx->outbuf;
}

#ifdef _WIN32
static int const bench_check_fake (void *const _ctx, const int level) {
    // Since we cannot create a socketpair and read the PDU, we cannot run
    // checks on windows.
    // TODO:
    // - this is a limitation of how tuntap devs are handled / selected
    fprintf(stderr, "pdu2tun: WARN: cannot check on Win32 platform");
    return 0;
}
#endif

// TODO: use headers to declare this
void process_pdu (struct n3n_runtime_data *eee,
                  const struct sockaddr *sender_sock,
                  const SOCKET in_sock,
                  uint8_t *udp_buf,
                  size_t udp_size,
                  time_t now
);

static const ssize_t bench_pdu2tun_run (
    void *_ctx,
    const void *data_in,
    const ssize_t data_in_size,
    ssize_t *in
) {
    struct bench_ctx *ctx = (struct bench_ctx *)_ctx;

    struct sockaddr_in sa;
    time_t now = time(NULL);

    sa.sin_family = AF_INET;
    sa.sin_port = 1;
    sa.sin_addr.s_addr = 0x0fee1bad;

    // Avoid attempt to send a reply to this PDU
    ctx->eee.sock = -1;

    process_pdu(
        &ctx->eee,
        (struct sockaddr *)&sa,
        -1,
        (uint8_t *)data_in,
        data_in_size,
        now
    );

    // If we could not create the socketpair, we cannot read the buffer
    if(ctx->sv[1] != -1) {
        ctx->outbuf_size = read(ctx->sv[1], &ctx->outbuf, sizeof(ctx->outbuf));
    } else {
        ctx->outbuf_size = 0;
        ctx->outbuf[0] = 0;
    }
    *in = data_in_size;
    return ctx->outbuf_size;
}

static struct bench_item bench_pdu2tun = {
    .name = "pdu2tun",
    .setup = bench_setup,
    .run = bench_pdu2tun_run,
#ifndef _WIN32
    .get_output = bench_get_output,
#else
    .check = bench_check_fake,
#endif
    .teardown = bench_teardown,
    .data_in = test_data_pdu_v3,
    .data_out = test_data_pdu_eth,
};

void n3n_initfuncs_benchmark_pdu () {
    n3n_benchmark_register(&bench_pdu2tun);
}
