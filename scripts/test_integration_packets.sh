#!/bin/bash
#
# Copyright (C) 2023 Hamish Coleman
# SPDX-License-Identifier: GPL-3.0-only
#
# Send known packets to the daemons and allow confirming the expected replies
#

AUTH=n3n

# boilerplate so we can support whaky cmake dirs
[ -z "$TOPDIR" ] && TOPDIR=.
[ -z "$BINDIR" ] && BINDIR=.

docmd() {
    echo "### test: $*"
    "$@"
    local S=$?
    echo
    return $S
}

# start a supernode
docmd "${BINDIR}"/apps/supernode \
    -v \
    --daemon \
    -Oconnection.bind=7001 \
    -Osupernode.macaddr=02:00:00:00:00:01 \
    start ci_sn


docmd "${BINDIR}"/scripts/test_packets \
    --bind=7000 \
    -s localhost:7001 \
    test_REGISTER_SUPER

docmd "${BINDIR}"/scripts/test_packets \
    --bind=7000 \
    -s localhost:7001 \
    test_QUERY_PEER_ping

docmd "${TOPDIR}"/scripts/n3nctl -s ci_sn -k $AUTH stop
