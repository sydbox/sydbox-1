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
export LD=lld
