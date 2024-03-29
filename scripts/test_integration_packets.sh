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

# We dont have perms for writing to the /run dir, TODO: improve this
sudo mkdir -p /run/n3n
sudo chown "$USER" /run/n3n

# start a supernode
echo -e "### supernode started\n"
apps/n3n-supernode \
    -vv \
    -Oconnection.bind=7001 \
    -Osupernode.macaddr=02:00:00:00:00:01 \
    start ci_sn1 1>&2 &

sleep 0.1

# Just request a PONG packet. Done before the registration binds us
docmd "${BINDIR}"/scripts/test_packets \
    --bind 7000 \
    -s localhost:7001 \
    test_QUERY_PEER_ping

# Register a mac address with the supernode
docmd "${BINDIR}"/scripts/test_packets \
    --bind 7000 \
    -s localhost:7001 \
    test_REGISTER_SUPER

# Confirm that the registration is visible
docmd "${TOPDIR}"/scripts/n3nctl -s ci_sn1 get_edges --raw |grep -v last_seen |grep -v time_alloc

# Once registered, we can query for that registration
docmd "${TOPDIR}"/scripts/test_packets \
    --bind 7000 \
    -s localhost:7001 \
    test_QUERY_PEER

# Since we are bound to the same udp port as the registration, when we
# send a register to that, the supernode forwards it to us - as we are
# listening on that registered port, we get the reply
docmd "${TOPDIR}"/scripts/test_packets \
    --bind 7000 \
    -s localhost:7001 \
    test_REGISTER

# Send a packet to the registered mac, expect it echoed back
docmd "${TOPDIR}"/scripts/test_packets \
    --bind 7000 \
    -s localhost:7001 \
    test_PACKET


docmd "${BINDIR}"/scripts/test_packets \
    --bind 7000 \
    -s localhost:7001 \
    --timeout 0 \
    test_UNREGISTER_SUPER

docmd "${TOPDIR}"/scripts/n3nctl -s ci_sn1 get_edges --raw

docmd "${TOPDIR}"/scripts/n3nctl -s ci_sn1 -k $AUTH stop
