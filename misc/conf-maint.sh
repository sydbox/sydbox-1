#!/bin/bash -x

root=$(git rev-parse --show-toplevel)

. "$root"/misc/prep-env-clang.sh
if test x"$1" = x"-d"; then
    CFLAGS="-O0 -pipe -ggdb"
    export CFLAGS
fi
cd "$root"
./autogen.sh
exec "$root"/./configure --prefix=/usr --sysconfdir=/etc \
    --enable-maintainer-mode \
    --disable-code-coverage \
    --enable-static \
    --disable-pandora \
    --disable-dependency-tracking
