/**
 * (C) 2007-22 - ntop.org and contributors
 * Copyright (C) 2023 Hamish Coleman
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.    See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not see see <http://www.gnu.org/licenses/>
 *
 */


#include <n3n/conffile.h>
#include <n3n/edge.h>       // for edge_init_conf_defaults, edge_verify_conf
#include <n3n/peer_info.h>   // for n3n_peer_add_by_hostname
#include <stdbool.h>
#include <stdio.h>   // for snprintf, NULL
#include <stdlib.h>  // for exit
#include "n2n.h"     // for n2n_edge_conf_t, edge_init


static bool keep_running = true;

int main () {

    n2n_edge_conf_t conf;
    tuntap_dev tuntap;
    struct n3n_runtime_data *eee;
    int rc;

    edge_init_conf_defaults(&conf,"edge");
    n3n_config_load_env(&conf);
    conf.allow_routing = true;                                                               // Whether to allow the edge to route packets to other edges
    snprintf((char *)conf.community_name, sizeof(conf.community_name), "%s", "mycommunity"); // Community to connect to
    conf.allow_multicast = true;                                                             // Whether to enable multicast
    conf.encrypt_key = strdup("mysecret");                                                   // Secret to decrypt & encrypt with
    // conf.bind_address = sockaddr; // can be used to bind to a local port
    conf.register_interval = 1;                                                              // Interval for both UDP NAT hole punching and supernode registration
    conf.register_ttl = 1;                                                                   // Interval for UDP NAT hole punching through supernode
    n3n_peer_add_by_hostname(&conf.supernodes, "localhost:1234");                                        // Supernode to connect to
    conf.tos = 16;                                                                           // Type of service for sent packets
    conf.transop_id = N2N_TRANSFORM_ID_TWOFISH;                                              // Use the twofish encryption

    if(edge_verify_conf(&conf) != 0) {
        return -1;
    }

    struct n2n_ip_subnet subnet;
    subnet.net_addr = htonl(0x0a000001);    // Set ip address 10.0.0.1
    subnet.net_bitlen = 24;                 // Netmask to use

    if(tuntap_open(&tuntap,
                   "edge0",             // Name of the device to create
                   TUNTAP_IP_MODE_STATIC, // IP mode; static|dhcp
                   subnet,
                   "DE:AD:BE:EF:01:10", // Set mac address
                   DEFAULT_MTU,         // MTU to use
                   0                    // Metric - unused in n2n on most OS
                   ) < 0) {
        return -1;
    }

    eee = edge_init(&conf, &rc);
    if(eee == NULL) {
        exit(1);
    }

    eee->keep_running = &keep_running;
    rc = run_edge_loop(eee);

    edge_term(eee);
    tuntap_close(&tuntap);

    return rc;
}
