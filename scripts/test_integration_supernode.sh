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

# start it running in the background
docmd "${BINDIR}"/apps/supernode -v

# TODO: probe the api endpoint, waiting for the supernode to be available?
sleep 0.1

docmd "${TOPDIR}"/scripts/n3nctl -u http://localhost:5645 get_communities
docmd "${TOPDIR}"/scripts/n3nctl -u http://localhost:5645 get_packetstats
docmd "${TOPDIR}"/scripts/n3nctl -u http://localhost:5645 get_edges --raw

docmd "${TOPDIR}"/scripts/n3nctl -u http://localhost:5645 get_verbose
docmd "${TOPDIR}"/scripts/n3nctl -u http://localhost:5645 -k $AUTH set_verbose 1

# stop it
docmd "${TOPDIR}"/scripts/n3nctl -u http://localhost:5645 -k $AUTH stop
