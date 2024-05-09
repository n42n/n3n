#!/bin/sh

rm -f include/config.h include/config.h.in include/config.h.in~ config.mak configure

# The more I use autotools, the more I want to stop using autotools
cp -p scripts/config.sub.DIST scripts/config.sub
cp -p scripts/config.guess.DIST scripts/config.guess

echo "Wait please..."
autoreconf -if
