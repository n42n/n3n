#!/bin/sh
#
# Copyright (C) 2023 Hamish Coleman
# SPDX-License-Identifier: GPL-3.0-only
#
# Do some quick tests via the Json API against the supernode
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

# We dont have perms for writing to the /run dir, TODO: improve this
sudo mkdir -p /run/n3n
sudo chown "$USER" /run/n3n

# start it running in the background
docmd "${BINDIR}"/apps/supernode start ci_sn -v

# TODO: probe the api endpoint, waiting for the supernode to be available?
sleep 0.1

docmd "${TOPDIR}"/scripts/n3nctl -s ci_sn get_communities
docmd "${TOPDIR}"/scripts/n3nctl -s ci_sn get_packetstats
docmd "${TOPDIR}"/scripts/n3nctl -s ci_sn get_edges --raw

docmd "${TOPDIR}"/scripts/n3nctl -s ci_sn get_verbose
docmd "${TOPDIR}"/scripts/n3nctl -s ci_sn -k $AUTH set_verbose 1

# Test with bad auth
docmd "${TOPDIR}"/scripts/n3nctl -s ci_sn set_verbose 1
echo $?

# stop it
docmd "${TOPDIR}"/scripts/n3nctl -s ci_sn -k $AUTH stop
