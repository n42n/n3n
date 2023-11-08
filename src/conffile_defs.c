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

void n3n_conffile_defs_init () {
    n3n_config_register_section("community", section_community);
    n3n_config_register_section("daemon", section_daemon);
    n3n_config_register_section("filter", section_filter);
}
