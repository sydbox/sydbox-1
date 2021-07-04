#!/bin/sh -x

root=$(git rev-parse --show-toplevel)

# 2021.07.04 name change gecesi resitaline özel
# hizlandirmak icin kapattik.
# --enable-debug \
. "$root"/misc/prep-env.sh
cd "$root"
./autogen.sh
exec "$root"/./configure --prefix=/usr --sysconfdir=/etc \
    --enable-pandora \
    --disable-code-coverage \
    --enable-maintainer-mode \
    --enable-static \
    --disable-dependency-tracking
