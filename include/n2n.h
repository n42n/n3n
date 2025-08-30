/**
 * (C) 2007-22 - ntop.org and contributors
 * Copyright (C) 2023-25 Hamish Coleman
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

#ifndef _N2N_H_
#define _N2N_H_

/*
    tunctl -t tun0
    tunctl -t tun1
    ifconfig tun0 1.2.3.4 up
    ifconfig tun1 1.2.3.5 up
    ./edge -d tun0 -l 2000 -r 127.0.0.1:3000 -c hello
    ./edge -d tun1 -l 3000 -r 127.0.0.1:2000 -c hello


    tunctl -u UID -t tunX
 */

#define N2N_HAVE_TCP    /* needs to be defined before it gets undefined */


#ifdef _WIN32
#include "config.h" /* Visual C++ */

#define N2N_CAN_NAME_IFACE 1
#undef N2N_HAVE_TCP           /* as explained on https://github.com/ntop/n2n/pull/627#issuecomment-782093706 */
#endif /* _WIN32 */


#include <stdbool.h>
#include <stdio.h>         // for size_t, FILE
#include "n2n_define.h"
#include "n2n_typedefs.h"

#ifdef _WIN32
#include <winsock2.h>           /* for tcp */
#include <lmaccess.h>           /* for privilege check in tools/n2n-route */
#include <lmapibuf.h>           /* for privilege check in tools/n2n-route */
#include <sys/stat.h>
#include <windows.h>            /* for privilege check in tools/n2n-route */
#define SHUT_RDWR   SD_BOTH     /* for tcp */
#endif /* #ifdef _WIN32 */

#ifndef _WIN32
#include <netinet/in.h>    // for in_addr (ptr only), in_addr_t
#include <pwd.h>
#include <stdint.h>        // for uint8_t, uint64_t, uint32_t, uint16_t
#include <sys/types.h>     // for time_t
#include <unistd.h>        // for close

#ifdef __linux__
#define N2N_CAN_NAME_IFACE 1
#endif /* #ifdef __linux__ */

#ifdef __FreeBSD__
#include <netinet/in_systm.h>
#endif /* #ifdef __FreeBSD__ */

#ifdef HAVE_LIBCRYPTO
#include <openssl/opensslv.h>
#include <openssl/crypto.h>
#endif
#endif /* #ifndef _WIN32 */




/* ************************************** */

/* Transop Init Functions */
int n2n_transop_null_init (const n2n_edge_conf_t *conf, n2n_trans_op_t *ttt);
int n2n_transop_tf_init (const n2n_edge_conf_t *conf, n2n_trans_op_t *ttt);
int n2n_transop_aes_init (const n2n_edge_conf_t *conf, n2n_trans_op_t *ttt);
int n2n_transop_cc20_init (const n2n_edge_conf_t *conf, n2n_trans_op_t *ttt);
int n2n_transop_speck_init (const n2n_edge_conf_t *conf, n2n_trans_op_t *ttt);
int n2n_transop_lzo_init (const n2n_edge_conf_t *conf, n2n_trans_op_t *ttt);
#ifdef HAVE_LIBZSTD
int n2n_transop_zstd_init (const n2n_edge_conf_t *conf, n2n_trans_op_t *ttt);
#endif

/* Tuntap API */
int tuntap_open (struct tuntap_dev *device, char *dev, uint8_t address_mode,
                 struct n2n_ip_subnet v4subnet,
                 const char * device_mac, int mtu,
                 int metric);
int tuntap_read (struct tuntap_dev *tuntap, unsigned char *buf, int len);
int tuntap_write (struct tuntap_dev *tuntap, unsigned char *buf, int len);
void tuntap_close (struct tuntap_dev *tuntap);
void tuntap_get_address (struct tuntap_dev *tuntap);

/* Utils */
uint32_t bitlen2mask (uint8_t bitlen);
uint8_t is_multi_broadcast (const n2n_mac_t dest_mac);
void print_n3n_version ();
int is_empty_ip_address (const n3n_sock_t * sock);
int memxor (uint8_t *destination, const uint8_t *source, size_t len);

/* Sockets */
SOCKET open_socket(struct sockaddr *, socklen_t, int type);
int sock_equal (const n3n_sock_t * a,
                const n3n_sock_t * b);

/* Header encryption */
uint64_t time_stamp (void);

/* Public functions */
struct n3n_runtime_data* edge_init (const n2n_edge_conf_t *conf, int *rv);
void update_supernode_reg (struct n3n_runtime_data * eee, time_t nowTime);
void readFromIPSocket (struct n3n_runtime_data * eee, int in_sock);
void edge_term (struct n3n_runtime_data *eee);
void edge_send_packet2net (struct n3n_runtime_data *eee, uint8_t *tap_pkt, size_t len);
int run_edge_loop (struct n3n_runtime_data *eee);
int quick_edge_init (char *device_name, char *community_name,
                     char *encrypt_key, char *device_mac,
                     in_addr_t local_ip_address,
                     char *supernode_ip_address_port,
                     bool *keep_on_running);
int comm_init (struct sn_community *comm, char *cmn);
void sn_init (struct n3n_runtime_data *sss);
void sn_term (struct n3n_runtime_data *sss);
int assign_one_ip_subnet (struct n3n_runtime_data *sss, struct sn_community *comm);

#endif /* _N2N_H_ */
