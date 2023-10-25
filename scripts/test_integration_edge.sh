#!/bin/sh
#
# Copyright (C) 2023 Hamish Coleman
# SPDX-License-Identifier: GPL-3.0-only
#
# Do some quick tests via the Json API against the edge
#

AUTH=n3n

# boilerplate so we can support whaky cmake dirs
[ -z "$TOPDIR" ] && TOPDIR=.
[ -z "$BINDIR" ] && BINDIR=.

docmd() {
    echo "###"
    "$@"
    echo
}

# start a supernode
docmd "${BINDIR}"/apps/supernode -v

# Start the edge in the background
docmd sudo "${BINDIR}"/apps/edge -l localhost:7654 -c test >/dev/null
# TODO:
# - send edge messages to stderr?

# TODO: probe the api endpoint, waiting for both the supernode and edge to be
# available?
sleep 0.1

docmd "${TOPDIR}"/scripts/n3n-ctl communities
docmd "${TOPDIR}"/scripts/n3n-ctl packetstats
docmd "${TOPDIR}"/scripts/n3n-ctl edges --raw

# TODO:
# docmd ${TOPDIR}/scripts/n3n-ctl supernodes --raw
# - need fixed mac address
# - need to mask out:
#   - version string
#   - last_seen timestamp
#   - uptime

docmd "${TOPDIR}"/scripts/n3n-ctl verbose
docmd "${TOPDIR}"/scripts/n3n-ctl --write verbose 1 2>/dev/null
echo $?
docmd "${TOPDIR}"/scripts/n3n-ctl -k $AUTH --write verbose 1

# looks strange, but we are querying the state of the "stop" verb
docmd "${TOPDIR}"/scripts/n3n-ctl stop

# stop them both
docmd "${TOPDIR}"/scripts/n3n-ctl -k $AUTH --write stop
docmd "${TOPDIR}"/scripts/n3n-ctl -t 5645 -k $AUTH --write stop

