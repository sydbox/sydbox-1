#!/bin/sh -x

root=$(git rev-parse --show-toplevel)

. "$root"/misc/prep-env.sh
cd "$root"
./autogen.sh
exec ./configure --prefix=/usr --enable-maintainer-mode --disable-static
