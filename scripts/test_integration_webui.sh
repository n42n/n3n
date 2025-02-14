#!/bin/bash
#
# Copyright (C) Hamish Coleman
# SPDX-License-Identifier: GPL-3.0-only
#
# Do some quick tests via the http Web UI against the edge
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
    -Oconnection.description=ci_edge1 \
    -Odaemon.userid="$USER" \
    -Otuntap.macaddr=02:00:00:77:00:00 \
    1>&2

# TODO: probe the api endpoint, waiting for both the supernode and edge to be
# available?
sleep 0.1

docmd curl --unix-socket /run/n3n/ci_edge1/mgmt http://x/ -o /tmp/index.html
docmd diff -u src/management_index.html /tmp/index.html

docmd curl --unix-socket /run/n3n/ci_edge1/mgmt http://x/script.js -o /tmp/script.js
docmd diff -u src/management_script.js /tmp/script.js

# stop them both
docmd "${TOPDIR}"/scripts/n3nctl -s ci_edge1 -k $AUTH stop
docmd "${TOPDIR}"/scripts/n3nctl -s ci_sn -k $AUTH stop

