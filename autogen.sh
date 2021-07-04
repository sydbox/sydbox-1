#!/bin/sh -ex

rm -fr autom4te.cache build-aux
rm -f config.cache
test -d build-aux || mkdir build-aux

PWD=
case "$0" in
*/*) srcdir=`dirname $0`;;
*) srcdir="";;
esac

libtoolize --copy --force
exec ${AUTORECONF:-autoreconf} --install --symlink "$@" ${srcdir:+"$srcdir"}
