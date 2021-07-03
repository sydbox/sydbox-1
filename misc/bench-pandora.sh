#!/bin/sh
# Copyright (c) 2021 Ali Polatel <alip@exherbo.org>
# SPDX-License-Identifier: GPL-3.0-or-later

root=$(git rev-parse --show-toplevel)
pandora="$root"/target/release/pandora

mkdir -p "$root"/target/tmp
tmp="$root"/target/tmp
tmp=$(readlink -f "$tmp")
tao="$tmp"/TAO

bench=(
    "for x in seq 1000000; do cat \"$tao\"; done"
    "for x in seq 100000; do touch \"$tao\"; rm -f \"$tao\"; done"
    'for x in seq 10000; do dig +noall +answer dev.chessmuse.com; done'
)

fortune tao >"$tao" 2>/dev/null ||\
cat >"$tao"<<EOF
Peace

If you offer music and food
Strangers may stop with you;
But if you accord with the Way
All the people of the world will keep you
In safety, health, community, and peace.
The Way lacks art and flavour;
It can neither be seen nor heard,
But its benefit cannot be exhausted.
                -- Lao Tse, "Tao Te Ching"
EOF

out="$root"/bench/hyperfine-pandora-$(date +'%Y-%m-%d')-$(git rev-parse --short HEAD)
if [ -e "$out".json -o -e "$out".txt ]; then
    echo >&2 "Refusing to overwrite previous benchmark at \`$out'"
    exit 1
fi

hyperfine \
    --export-json "$out".json \
    --ignore-failure \
    --prepare 'sync; echo 3 | sudo tee /proc/sys/vm/drop_caches' \
    "/bin/sh -c '${bench[0]}'" \
    "strace -q /bin/sh -c '${bench[0]}'" \
    "\"$pandora\" box -m core/sandbox/read:off -m core/trace/use_seccomp:0 /bin/sh -c '${bench[0]}'" \
    "\"$pandora\" box -m core/sandbox/read:allow -m core/trace/use_seccomp:1 /bin/sh -c  '${bench[0]}'" \
    "\"$pandora\" box -m core/sandbox/read:allow -m core/trace/use_seccomp:0 /bin/sh -c '${bench[0]}'" \
    "\"$pandora\" box -m core/sandbox/read:deny -m core/trace/use_seccomp:1 /bin/sh -c '${bench[0]}'" \
    "\"$pandora\" box -m core/sandbox/read:deny -m core/trace/use_seccomp:0 /bin/sh -c '${bench[0]}'" \
    "\"$pandora\" box -m core/sandbox/read:deny -m core/trace/use_seccomp:1 -m \"allowlist/read+$tmp\" /bin/sh -c '${bench[0]}'" \
    "\"$pandora\" box -m core/sandbox/read:deny -m core/trace/use_seccomp:0 -m \"allowlist/read+$tmp\" /bin/sh -c '${bench[0]}'" \
    "\"$pandora\" box -m core/sandbox/write:off -m core/trace/use_seccomp:0 /bin/sh -c '${bench[1]}'" \
    "\"$pandora\" box -m core/sandbox/write:allow -m core/trace/use_seccomp:1 /bin/sh -c  '${bench[1]}'" \
    "\"$pandora\" box -m core/sandbox/write:allow -m core/trace/use_seccomp:0 /bin/sh -c '${bench[1]}'" \
    "\"$pandora\" box -m core/sandbox/write:deny -m core/trace/use_seccomp:1 /bin/sh -c '${bench[1]}'" \
    "\"$pandora\" box -m core/sandbox/write:deny -m core/trace/use_seccomp:0 /bin/sh -c '${bench[1]}'" \
    "\"$pandora\" box -m core/sandbox/write:deny -m core/trace/use_seccomp:1 -m \"allowlist/write+$tmp\" /bin/sh -c '${bench[1]}'" \
    "\"$pandora\" box -m core/sandbox/write:deny -m core/trace/use_seccomp:0 -m \"allowlist/write+$tmp\" /bin/sh -c '${bench[1]}'" \
    "\"$pandora\" box -m core/sandbox/network:deny -m core/trace/use_seccomp:0  /bin/sh -c '${bench[2]}'" \
    "\"$pandora\" box -m core/sandbox/network:deny -m core/trace/use_seccomp:1  /bin/sh -c '${bench[2]}'" \
    "\"$pandora\" box -m core/sandbox/network:deny -m core/trace/use_seccomp:0 -m 'allowlist/network/bind+LOOPBACK@0' -m 'allowlist/network/bind+LOOPBACK6@0' -m 'allowlist/network/bind+inet:0.0.0.0@0' /bin/sh -c '${bench[2]}'" \
    "\"$pandora\" box -m core/sandbox/network:deny -m core/trace/use_seccomp:1 -m 'allowlist/network/bind+LOOPBACK@0' -m 'allowlist/network/bind+LOOPBACK6@0' -m 'allowlist/network/bind+inet:0.0.0.0@0' /bin/sh -c '${bench[2]}'"

cat>"$out".txt<<EOF
Date: $(date -u)
SydB☮x: $(sydbox --version | tr '\n' ' ')
Pand☮ra: $("$pandora" --version)
HyperFine: $(hyperfine --version)
Tao:
$(cat "$tao")
EOF
