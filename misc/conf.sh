#!/bin/sh -x

root=$(git rev-parse --show-toplevel)

. "$root"/misc/prep-env.sh
cd "$root"
./autogen.sh
exec "$root"/./configure --prefix=/usr --sysconfdir=/etc \
    --enable-debug \
    --disable-code-coverage \
    --enable-maintainer-mode \
    --disable-static \
    --disable-dependency-tracking
