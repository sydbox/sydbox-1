#!/bin/sh

base=$(basename "$0")

TRACK_ORIGINS=

VALGRIND_VERSION=$(valgrind --version)
VALGRIND_MAJOR=$(expr "$VALGRIND_VERSION" : '[^0-9]*\([0-9]*\)')
VALGRIND_MINOR=$(expr "$VALGRIND_VERSION" : '[^0-9]*[0-9]*\.\([0-9]*\)')
test 3 -gt "$VALGRIND_MAJOR" ||
test 3 -eq "$VALGRIND_MAJOR" -a 4 -gt "$VALGRIND_MINOR" ||
TRACK_ORIGINS=--track-origins=yes

echo "-- $@ --"
exec valgrind --error-exitcode=126 \
    --trace-children=no \
    --leak-check=full \
    --gen-suppressions=all \
    $TRACK_ORIGINS \
    --log-fd=2 \
    --input-fd=4 \
    "$@"
