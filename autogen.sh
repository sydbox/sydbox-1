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
exec ${AUTORECONF:-autoreconf} \
    --force \
    --install "$@" ${srcdir:+"$srcdir"} \
    --make \
    --no-recursive \
    --verbose
#Manual steps, use this to debug.
#aclocal --force --install --verbose -I m4
#autoheader
#automake --add-missing
#autoconf
