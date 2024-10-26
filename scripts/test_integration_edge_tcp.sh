#!/bin/bash
#
# Copyright (C) Hamish Coleman
# SPDX-License-Identifier: GPL-3.0-only
#
# Do some quick tests via the Json API against the edge
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
docmd "${BINDIR}"/apps/n3n-supernode start ci_sn \
    -v \
    --daemon \
    -Osupernode.macaddr=02:00:00:55:00:00

# Start the edge in the background
docmd sudo "${BINDIR}"/apps/n3n-edge start ci_edge1 \
    --daemon \
    -l localhost:7654 \
    -c test \
    -Oconnection.bind=:7700 \
    -Oconnection.connect_tcp=true \
    -Odaemon.userid="$USER" \
    -Otuntap.macaddr=02:00:00:77:00:00 \
    1>&2

# TODO: probe the api endpoint, waiting for both the supernode and edge to be
# available?
sleep 0.1

docmd "${TOPDIR}"/scripts/n3nctl -s ci_edge1 get_communities

echo "### test: ${TOPDIR}/scripts/n3nctl -s ci_edge1 get_packetstats"
"${TOPDIR}"/scripts/n3nctl -s ci_edge1 get_packetstats |jq '.[0:5]'
# this is filtering out the type=multicast_drop line as that has a changing
# number of packets counted
echo

docmd "${TOPDIR}"/scripts/n3nctl -s ci_edge1 get_edges --raw |grep -v "last_seen"
docmd "${TOPDIR}"/scripts/n3nctl -s ci_sn get_edges --raw |grep -v -E "last_seen|time_alloc"


docmd ${TOPDIR}/scripts/n3nctl -s ci_edge1 get_supernodes --raw

# stop them both
docmd "${TOPDIR}"/scripts/n3nctl -s ci_edge1 -k $AUTH stop
docmd "${TOPDIR}"/scripts/n3nctl -s ci_sn -k $AUTH stop

