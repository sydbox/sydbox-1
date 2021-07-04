#!/bin/sh -x

root=$(git rev-parse --show-toplevel)

. "$root"/misc/prep-env.sh
cd "$root"
./autogen.sh
exec "$root"/./configure --prefix=/usr --sysconfdir=/etc \
    --enable-maintainer-mode \
    --disable-code-coverage \
    --disable-static \
    --disable-pandora \
    --disable-dependency-tracking
