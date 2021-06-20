#!/bin/sh -x

root=$(git rev-parse --show-toplevel)

. "$root"/misc/prep-env.sh
cd "$root"
./autogen.sh
exec "$root"/./configure --prefix=/usr \
    --disable-code-coverage \
    --enable-maintainer-mode \
    --enable-static \
    --disable-dependency-tracking
