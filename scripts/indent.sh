#!/bin/sh
#
# Copyright (C) Hamish Coleman
# SPDX-License-Identifier: GPL-2.0-only
#
# Given one or more input source files, run a re-indenter on them.

help() {
    echo "Usage: scripts/indent [-i] [-e regex] [file...]"
    echo " -i   modify file in place with reindent results"
    echo ""
    echo "By default, will output a diff and exitcode if changed are needed"
    echo "If modifying files, no exit code or diff is output"
    exit 1
}

[ -z "$1" ] && help
[ "$1" = "-h" ] && help
[ "$1" = "--help" ] && help

INPLACE=0
if [ "$1" = "-i" ]; then
    shift
    INPLACE=1
fi

EXCLUDE=dont_exclude_any_token
if [ "$1" = "-e" ]; then
    EXCLUDE="$2"
    shift 2
fi

## indentOneClang() {
##     rm -f "$1.indent"
##     clang-format "$1" >"$1.indent"
##     if [ $? -ne 0 ]; then
##         echo "Error while formatting \"$1\""
##         RESULT=1
##         return
##     fi
##     diff -u "$1" "$1.indent"
##     if [ $? -ne 0 ]; then
##         RESULT=1
##     fi
## }

indentOne() {
    IFILE="$1"
    if [ "$INPLACE" -eq 0 ]; then
        OFILE="$1.indent"
        rm -f "$OFILE"
        CLEAN=true
    else
        OFILE="$1"
        CLEAN=false
    fi
    if ! uncrustify -c uncrustify.cfg -f "$IFILE" -o "$OFILE"; then
        echo "Error while formatting \"$1\""
        RESULT=1
        return
    fi
    if ! diff -u "$IFILE" "$OFILE"; then
        RESULT=1
    fi

    $CLEAN && rm -f "$OFILE"
}

indentDir() {
    for i in $(find "$1" -type f -name \*.h -o -name \*.c |sort); do
        echo "$i" | grep -E "$EXCLUDE" >/dev/null || indentOne "$i"
    done
}

RESULT=0
while [ -n "$1" ]; do
    if [ -d "$1" ]; then
        indentDir "$1"
    else
        indentOne "$1"
    fi
    shift
done
exit $RESULT
