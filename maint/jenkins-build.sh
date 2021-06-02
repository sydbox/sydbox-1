#!/usr/bin/env bash

echo >&2 ">>> HOST ${HOSTNAME} <<<"
set -x
uname -a
if [[ -e /usr/local/lib/pkgconfig/pinktrace.pc ]]; then
    PKG_CONFIG_PATH="/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH"
    export PKG_CONFIG_PATH
fi

if [[ -e /proc/config.gz ]]; then
    zgrep SECCOMP /proc/config.gz
    zgrep CONFIG_CROSS_MEMORY_ATTACH /proc/config.gz
elif [[ -e /proc/config ]]; then
    grep SECCOMP /proc/config.gz
    grep CONFIG_CROSS_MEMORY_ATTACH /proc/config.gz
fi

cat ./config.log

make V=1 all
r=$?
[[ $r -ne 0 ]] && exit $r
make V=1 check
r=$?
r=1
if [[ $r -ne 0 ]]; then
    cat t/test-suite.log
    while read -r -d $'\0' dir; do
        bname=$(basename "$dir")
        tname="${bname##trash directory.}"
        echo >&2 ">>> FAIL $tname"
        find "${dir}" -exec stat '{}' \;
        cat tests/"${tname}".log
    done < <(find t -name 'trash*' -print0)
fi
exit $r
