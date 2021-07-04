#!/bin/sh
./configure \
    --build=x86_64-pc-linux-musl \
    --host=x86_64-pc-linux-musl \
    --prefix=/usr/x86_64-pc-linux-musl \
    --bindir=/usr/x86_64-pc-linux-musl/bin \
    --sbindir=/usr/x86_64-pc-linux-musl/bin \
    --libdir=/usr/x86_64-pc-linux-musl/lib \
    --datadir=/usr/share \
    --datarootdir=/usr/share \
    --docdir=/usr/share/doc/sydbox-scm \
    --infodir=/usr/share/info \
    --mandir=/usr/share/man \
    --sysconfdir=/etc \
    --localstatedir=/var/lib \
    --disable-dependency-tracking \
    --disable-silent-rules \
    --enable-fast-install \
    --enable-static
