#!/bin/bash
#
# Copyright (C) 2024 Hamish Coleman
# SPDX-License-Identifier: GPL-3.0-only
#
# Run builtin commands to generate test data
#

docmd() {
    echo "### test: $*"
    "$@"
    local S=$?
    echo
    return $S
}

docmd "${BINDIR}"/apps/edge test config load_dump /dev/null
