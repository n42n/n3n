#!/bin/sh
#
# Copyright (C) Hamish Coleman
# SPDX-License-Identifier: GPL-2.0-only
#
# For macOS, where the system autotools are too old and installing newer ones
# means pulling in a package manager just to run ./configure once.
#
# This writes the two files the build actually needs - an empty config.h and a
# config.mak naming the toolchain - which is exactly what ./configure would
# produce for a build with no optional libraries enabled.
#
# Optional features (zstd, openssl, miniupnpc, natpmp, pcap, cap) all need
# their ./configure --with-* flag anyway, so leaving config.h empty simply
# builds without them.
#
# Override any of these from the environment, e.g.
#   CONFIG_PREFIX=/opt CONFIG_RUNDIR=/opt/var/run ./scripts/hack_fakeautoconf_macos.sh

set -e

# We assume this script is in the TOPDIR/scripts directory
TOPDIR=$(dirname "$0")/..
cd "$TOPDIR"

CC=${CC:-cc}
AR=${AR:-ar}
ARCH=${ARCH:-$(uname -m)}

CONFIG_PREFIX=${CONFIG_PREFIX:-/usr/local}
CONFIG_DOCDIR=${CONFIG_DOCDIR:-${CONFIG_PREFIX}/share/doc/n3n}
CONFIG_MANDIR=${CONFIG_MANDIR:-${CONFIG_PREFIX}/share/man}
# macOS has /var/run, but it is not writable by an unprivileged user
CONFIG_RUNDIR=${CONFIG_RUNDIR:-/var/run}
# No systemd here, but the Makefile still wants the variable defined
CONFIG_SYSTEMDDIR=${CONFIG_SYSTEMDDIR:-${CONFIG_PREFIX}/lib/systemd/system}

if ! command -v "$CC" >/dev/null 2>&1; then
    echo "Error: no '$CC' found. Install the Xcode Command Line Tools with:"
    echo "    xcode-select --install"
    exit 1
fi

echo "Wait please..."

cat <<EOF >include/config.h
// Created by hack fake autoconf for macOS
// not actually a config header
EOF

cat <<EOF >include/config.h.in
// Created by hack fake autoconf for macOS
// not actually a config input
EOF

# autogen.sh normally copies these into place for AC_CONFIG_AUX_DIR
cp -p scripts/config.sub.DIST scripts/config.sub
cp -p scripts/config.guess.DIST scripts/config.guess

cat >config.mak <<EOF
# Created by hack fake autoconf for macOS

CONFIG_HOST=${ARCH}-apple-darwin
CONFIG_HOST_OS=darwin

CONFIG_PREFIX=${CONFIG_PREFIX}
CONFIG_DOCDIR=\$(DESTDIR)${CONFIG_DOCDIR}
CONFIG_MANDIR=\$(DESTDIR)${CONFIG_MANDIR}
CONFIG_RUNDIR=\$(DESTDIR)${CONFIG_RUNDIR}
CONFIG_SYSTEMDDIR=\$(DESTDIR)${CONFIG_SYSTEMDDIR}

CONFIG_WITH_OPENSSL=no

CC=${CC}
AR=${AR}
WINDRES=windres
EXE=

CFLAGS+=${CFLAGS} -g -O2
LDFLAGS+=${LDFLAGS}
EOF

echo "Generated config.mak for ${ARCH}-apple-darwin:"
echo "  prefix  ${CONFIG_PREFIX}"
echo "  rundir  ${CONFIG_RUNDIR}"
echo
echo "Now run: make"
