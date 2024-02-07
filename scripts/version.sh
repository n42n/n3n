#!/bin/sh
#
# Copyright (C) 2023 Hamish Coleman
# SPDX-License-Identifier: GPL-3.0-only
#
# Output the current version number
#

usage() {
    echo "Usage: $0 [date|short|hash]"
    echo
    echo "Determine the correct version number for the current build"
    exit 1
}

# We assume this script is in the TOPDIR/scripts directory and use that
# to find any other files we need
TOPDIR=$(dirname "$0")/..

VER_FILE_SHORT=$(cat "${TOPDIR}/VERSION")

if [ -d "$TOPDIR/.git" ]; then
    # If there is a .git directory in our TOPDIR, then this is assumed to be
    # real git checkout

    cd "$TOPDIR" || exit 1

    VER_GIT_SHORT=$(git describe --abbrev=0)

    if [ "$VER_FILE_SHORT" != "$VER_GIT_SHORT" ]; then
        echo "Error: VERSION file does not match tag version ($VER_FILE_SHORT != $VER_GIT_SHORT)" 1>&2
        exit 1
    fi

    VER_SHORT="$VER_GIT_SHORT"
    VER_HASH=$(git rev-parse --short HEAD)
    VER=$(git describe --abbrev=7 --dirty)

    git diff --quiet
    if [ $? -eq 0 ]; then
        # In a clean build dir, use the last commit date
        DATE=$(git log -1 --format=%cd)
    else
        # if dirty, use the current date
        DATE=$(date)
    fi
else
    # If there is no .git directory in our TOPDIR, we fall back on relying on
    # the VERSION file

    VER_SHORT="$VER_FILE_SHORT"
    VER_HASH="HEAD"
    VER="$VER_FILE_SHORT"
    DATE=$(date)
fi

case "$1" in
    date)
        echo "$DATE"
        ;;
    hash)
        echo "$VER_HASH"
        ;;
    short)
        echo "$VER_SHORT"
        ;;
    "")
        echo "$VER"
        ;;
    *)
        usage
        ;;
esac
