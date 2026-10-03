#!/bin/bash
#
# SPDX-FileCopyrightText: Copyright Hamish Coleman
# SPDX-License-Identifier: GPL-2.0-only
#
# Run builtin commands to generate test data
#

[ -z "$BINDIR" ] && BINDIR=.

docmd() {
    echo "### test: $*"
    "$@"
    local S=$?
    echo
    return $S
}

docmd "$BINDIR"/apps/n3n-edge test check

docmd "$BINDIR"/apps/n3n-edge test config roundtrip

docmd "$BINDIR"/apps/n3n-edge tools keygen logan 007
docmd "$BINDIR"/apps/n3n-edge tools keygen secretFed
