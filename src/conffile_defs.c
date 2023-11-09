/*
 * Copyright (C) 2023 Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Internal monolithic configuration definitions
 */

#include <stddef.h>
#include <n3n/conffile.h>

#include <n2n_typedefs.h>       // for n2n_edge_conf_t

static struct n3n_conf_option section_community[] = {
    {
        .name = "cipher",
        .type = n3n_conf_transform,
        .offset = offsetof(n2n_edge_conf_t, transop_id),
        .desc = "The cipher to use",
        .help = "Choose a ciper for payload encryption (requires a key). "
                "2=Twofish, 3=AES, 4=ChaCha20, 5=Speck-CTR.",
    },
    {
        .name = "key",
        .type = n3n_conf_strdup,
        .offset = offsetof(n2n_edge_conf_t, encrypt_key),
        .desc = "The encryption key (ASCII)",
        .help = "All edges within the same community must use the same key. "
                "If no key is specified then the edge uses cleartext mode "
                "(no encryption).",
    },
    {
        .name = "name",
        .type = n3n_conf_strncpy,
        .length = N2N_COMMUNITY_SIZE,
        .offset = offsetof(n2n_edge_conf_t, community_name),
        .desc = "The name of the community to join",
        .help = "All edges within the same community appear on the same LAN "
                "(layer 2 network segment).  Community name is "
                "N2N_COMMUNITY_SIZE bytes in length. A name smaller "
                "than this is padded with 0x00 bytes and a name longer than "
                "this is truncated to fit.",
    },
    {.name = NULL},
};

static struct n3n_conf_option section_connection[] = {
    {
        .name = "disable_pmtu",
        .type = n3n_conf_bool,
        .offset = offsetof(n2n_edge_conf_t, disable_pmtu_discovery),
        .desc = "Control use of PMTU discovery for network packets",
        .help = "This can reduce fragmentation but causes connections to "
                "stall if not properly supported by the network. "
                "(Ignored on operating systems where this socket option is "
                "not supported)",
    },
    {.name = NULL},
};

static struct n3n_conf_option section_daemon[] = {
    {
        .name = "userid",
        .type = n3n_conf_uint32,
        .offset = offsetof(n2n_edge_conf_t, userid),
        .desc = "The user id",
        .help = "Run the daemon with this user id (ignored on windows)",
    },
    {
        .name = "groupid",
        .type = n3n_conf_uint32,
        .offset = offsetof(n2n_edge_conf_t, groupid),
        .desc = "The group id",
        .help = "Run the daemon with this group id (ignored on windows)",
    },
    {
        .name = "background",
        .type = n3n_conf_bool,
        .offset = offsetof(n2n_edge_conf_t, daemon),
        .desc = "Daemonize the process",
        .help = "Runs as a daemon in the background (ignored on windows)",
    },
    {.name = NULL},
};

static struct n3n_conf_option section_filter[] = {
    {
        .name = "allow_routing",
        .type = n3n_conf_bool,
        .offset = offsetof(n2n_edge_conf_t, allow_routing),
        .desc = "enable IP packet forwarding/routing",
        .help = "Without this option, IP packets arriving over n2n are "
                "dropped if they are not for the IP address of the edge "
                "interface.  This setting is also used to enable bridging.",
    },
    {
        .name = "drop_multicast",
        .type = n3n_conf_bool,
        .offset = offsetof(n2n_edge_conf_t, drop_multicast),
        .desc = "Optionally filter multicast traffic",
        .help = "Amungst other things, multicast is used for IPv6 neighbour "
                "discovery.  If drop is true then these multicast packets "
                "are discarded.",
    },
    {.name = NULL},
};

static struct n3n_conf_option section_tuntap[] = {
    {
        .name = "macaddr",
        .type = n3n_conf_strncpy,
        .length = N2N_MACNAMSIZ,
        .offset = offsetof(n2n_edge_conf_t, device_mac),
        .desc = "Set the TAP interface MAC address",
        .help = "By default a random MAC address is used.",
    },
    {
        .name = "mtu",
        .type = n3n_conf_uint32,
        .offset = offsetof(n2n_edge_conf_t, mtu),
        .desc = "Set the TAP interface MTU",
        .help = "The default is chosen to work in most cases.",
    },
    {.name = NULL},
};

void n3n_conffile_defs_init () {
    n3n_config_register_section("community", section_community);
    n3n_config_register_section("connection", section_connection);
    n3n_config_register_section("daemon", section_daemon);
    n3n_config_register_section("filter", section_filter);
    n3n_config_register_section("tuntap", section_tuntap);
}
