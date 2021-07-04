#!/bin/sh -x

root=$(git rev-parse --show-toplevel)

. "$root"/misc/prep-env.sh
cd "$root"
./autogen.sh
exec "$root"/./configure --prefix=/usr --sysconfdir=/etc \
    --enable-pandora \
    --enable-static \
    --disable-code-coverage \
    --disable-maintainer-mode \
    --disable-dependency-tracking
