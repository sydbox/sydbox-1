#!/bin/bash -x

CC="$(which clang)"
if "${CC}" --version | grep -q 10.0; then
    CC_11="$(which clang-11)"
    if [ -n "$CC_11" ]; then
        CC="$CC_11"
    fi
fi
if [[ ! -x "$CC" ]]; then
    echo >&2 "clang not found in PATH"
    exit 1
fi
export CC

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

MALLOC_CHECK_=3
MALLOC_PERTURB_=$(($RANDOM % 255 + 1))
export MALLOC_CHECK_ MALLOC_PERTURB_
