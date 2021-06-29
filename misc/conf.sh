#!/bin/sh -x

root=$(git rev-parse --show-toplevel)

. "$root"/misc/prep-env.sh
cd "$root"
./autogen.sh
CFLAGS="-O2 -pipe -ggdb"
export CFLAGS
exec "$root"/./configure --prefix=/usr --sysconfdir=/etc \
    --disable-code-coverage \
    --enable-maintainer-mode \
    --enable-static \
    --disable-dependency-tracking
