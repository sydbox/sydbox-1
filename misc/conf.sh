#!/bin/sh -x

root=$(git rev-parse --show-toplevel)

. "$root"/misc/prep-env-clang.sh
cd "$root"
./autogen.sh
exec "$root"/./configure \
    --prefix=/usr \
    --sysconfdir=/etc \
    --libexecdir=/usr/libexec \
    --disable-pandora \
    --disable-static \
    --disable-code-coverage \
    --disable-maintainer-mode \
    --disable-dependency-tracking
