#!/bin/sh -x

CFLAGS="-D__ALIP_WAS_HERE"
# 2021.07.04 name change gecesi resitaline özel
# hizlandirmak icin kapattik.
#CFLAGS="${CFLAGS} -O0 -pipe -ggdb"
CFLAGS="${CFLAGS} -Ofast -march=native -mtune=native"
CFLAGS="${CFLAGS} -D__PINK_IS_BEHIND_THE_WALL"
export CFLAGS

if ! [ -e /etc/exherbo-release ]; then
    PKG_CONFIG_PATH="$HOME/.local/lib/pkgconfig:$PKG_CONFIG_PATH"
    export PKG_CONFIG_PATH
fi

#MALLOC_CHECK_=3
#MALLOC_PERTURB_=$(($RANDOM % 255 + 1))
#export MALLOC_CHECK_ MALLOC_PERTURB_
