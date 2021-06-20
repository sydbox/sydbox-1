#!/bin/sh -x

root=$(git rev-parse --show-toplevel)

. "$root"/misc/prep-env.sh
cd "$root"
./autogen.sh
exec env \
    CC=afl-gcc CXX=afl-g++ \
    "$root"/./configure --prefix=/usr \
    --disable-code-coverage \
    --enable-maintainer-mode \
    --disable-static \
    --disable-dependency-tracking
