#!/bin/bash
#
# Copyright (C) 2024 Hamish Coleman
# SPDX-License-Identifier: GPL-3.0-only
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

docmd "$BINDIR"/apps/edge test hashing

docmd "$BINDIR"/apps/edge test config roundtrip /dev/null

docmd "$BINDIR"/apps/edge tools keygen logan 007
docmd "$BINDIR"/apps/edge tools keygen secretFed
