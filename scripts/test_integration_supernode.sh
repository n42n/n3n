#!/bin/sh
#
# Copyright (C) Hamish Coleman
# SPDX-License-Identifier: GPL-3.0-only
#
# Do some quick tests via the Json API against the supernode
#

AUTH=n3n

# boilerplate so we can support whaky cmake dirs
[ -z "$TOPDIR" ] && TOPDIR=.
[ -z "$BINDIR" ] && BINDIR=.

docmd() {
    echo "### test: $*"
    "$@"
    echo
}

# We dont have perms for writing to the /run dir, TODO: improve this
sudo mkdir -p /run/n3n
sudo chown "$USER" /run/n3n

# start it running in the background
docmd "${BINDIR}"/apps/n3n-supernode start ci_sn1 \
    --daemon \
    -Oconnection.bind=7001 \
    -Osupernode.macaddr=02:00:00:00:70:01 \
    -Osupernode.peer=localhost:7002
docmd "${BINDIR}"/apps/n3n-supernode start ci_sn2 \
    --daemon \
    -Oconnection.bind=7002 \
    -Osupernode.macaddr=02:00:00:00:70:02 \
    -Osupernode.peer=localhost:7001

# TODO: probe the api endpoint, waiting for the supernode to be available?
sleep 0.1

docmd "${TOPDIR}"/scripts/n3nctl -s ci_sn1 get_communities
docmd "${TOPDIR}"/scripts/n3nctl -s ci_sn2 get_communities

docmd "${TOPDIR}"/scripts/n3nctl -s ci_sn1 get_packetstats
docmd "${TOPDIR}"/scripts/n3nctl -s ci_sn2 get_packetstats

docmd "${TOPDIR}"/scripts/n3nctl -s ci_sn1 get_edges --raw | grep -vE "last_seen|time_alloc"
docmd "${TOPDIR}"/scripts/n3nctl -s ci_sn2 get_edges --raw | grep -vE "last_seen|time_alloc"

# Test with bad auth
docmd "${TOPDIR}"/scripts/n3nctl -s ci_sn1 set_verbose 1
echo $?

docmd "${TOPDIR}"/scripts/n3nctl -s ci_sn1 get_verbose
docmd "${TOPDIR}"/scripts/n3nctl -s ci_sn1 -k $AUTH set_verbose 1

# stop it
docmd "${TOPDIR}"/scripts/n3nctl -s ci_sn1 -k $AUTH stop
docmd "${TOPDIR}"/scripts/n3nctl -s ci_sn2 -k $AUTH stop
