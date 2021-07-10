#!/bin/sh -x

root=$(git rev-parse --show-toplevel)

. "$root"/misc/prep-env.sh
CFLAGS="-O0 -pipe -ggdb"
export CFLAGS
cd "$root"
./autogen.sh
exec "$root"/./configure --prefix=/usr --sysconfdir=/etc \
    --enable-maintainer-mode \
    --disable-code-coverage \
    --enable-static \
    --disable-pandora \
    --disable-dependency-tracking
