#!/bin/sh -x

CFLAGS="-D__ALIP_WAS_HERE"
CFLAGS="${CFLAGS} -pedantic -W -Wall -Wextra -Wshadow -Wno-unused-parameter"
CFLAGS="${CFLAGS} -O0 -g -ggdb3"
CFLAGS="${CFLAGS} -Wall"
CFLAGS="${CFLAGS} -Werror=implicit-function-declaration"
CFLAGS="${CFLAGS} -Werror=implicit-int"
CFLAGS="${CFLAGS} -Werror=pointer-sign"
CFLAGS="${CFLAGS} -Werror=pointer-arith"
CFLAGS="${CFLAGS} -D__PINK_IS_BEHIND_THE_WALL"
export CFLAGS

if ! [ -e /etc/exherbo-release ]; then
    PKG_CONFIG_PATH="$HOME/.local/lib/pkgconfig:$PKG_CONFIG_PATH"
    export PKG_CONFIG_PATH
fi

#MALLOC_CHECK_=3
#MALLOC_PERTURB_=$(($RANDOM % 255 + 1))
#export MALLOC_CHECK_ MALLOC_PERTURB_
