#!/bin/bash
#
# SPDX-FileCopyrightText: Copyright Honey Bunny QT
# SPDX-License-Identifier: GPL-2.0-only
#
# Run the unit tests and the builtin self tests of a cross compiled tree
# under qemu-user, e.g. for a big endian or 32 bit host:
#
#   ./configure --host=mips-linux-gnu && make apps tools
#   scripts/test_qemu.sh qemu-mips -L /usr/mips-linux-gnu
#
# The results have to be the very same as on the host that made the
# expected files - only the pattern tests of tests-wire fill structs with
# byte patterns, which come out differently on a big endian host, so they
# are left out.

if [ -z "$1" ]; then
    echo "usage: $0 <qemu command and options>"
    exit 1
fi

RESULT=0
OUT=$(mktemp -d)
trap 'rm -rf "$OUT"' EXIT

check() {
    local name="$1"
    local expected="$2"

    if diff -u "$expected" "$OUT/$name" >"$OUT/$name.diff"; then
        echo "PASS $name"
    else
        echo "FAIL $name"
        cat "$OUT/$name.diff"
        RESULT=1
    fi
}

sed -e "s/#.*//" -e "/^ *$/d" tests/tests_units.list >"$OUT/list"
while read -r i; do
    "$@" "tools/$i" >"$OUT/$i" 2>/dev/null </dev/null
    if [ "$i" = "tests-wire" ]; then
        sed -i '/^pattern_/,$d' "$OUT/$i"
        sed '/^pattern_/,$d' "tests/$i.expected" >"$OUT/$i.expected"
        check "$i" "$OUT/$i.expected"
    else
        check "$i" "tests/$i.expected"
    fi
done <"$OUT/list"

# The builtin tests, without the lines naming the commands
sed "s|\"\$BINDIR\"/apps/n3n-edge|$* ./apps/n3n-edge|" scripts/test_builtin_edge.sh \
    | bash 2>/dev/null | grep -v "^### test:" >"$OUT/builtin"
grep -v "^### test:" tests/test_builtin_edge.sh.expected >"$OUT/builtin.expected"
check builtin "$OUT/builtin.expected"

exit $RESULT
