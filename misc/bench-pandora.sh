#!/bin/sh
# Copyright (c) 2021 Ali Polatel <alip@exherbo.org>
# SPDX-License-Identifier: GPL-3.0-or-later

root=$(git rev-parse --show-toplevel)
pandora="$root"/target/release/pandora

mkdir -p "$root"/target/tmp
tmp="$root"/target/tmp
tmp=$(readlink -f "$tmp")
tao="$tmp"/TAO

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

out="$root"/bench/hyperfine-pandora-$(date +'%Y-%m-%d')-$(git rev-parse --short).md
if [ -e "$out" ]; then
    echo >&2 "Refusing to overwrite previous benchmark at \`$out'"
    exit 1
fi

# --prepare 'sync; echo 3 | sudo tee /proc/sys/vm/drop_caches' \
hyperfine \
    --export-markdown "$out" \
    --ignore-failure \
    --min-runs 100000 \
    "cat $tao" \
    "strace -q cat $tao" \
    -n 'pandora box read:off seccomp:off cat TAO' \
    "pandora box -m core/sandbox/read:off -m core/trace/use_seccomp:0 cat \"$tao\"" \
    -n 'pandora box read:allow seccomp:on cat TAO' \
    "pandora box -m core/sandbox/read:allow -m core/trace/use_seccomp:1 cat \"$tao\"" \
    -n 'pandora box read:allow seccomp:off cat TAO' \
    "pandora box -m core/sandbox/read:allow -m core/trace/use_seccomp:0 cat \"$tao\"" \
    -n 'pandora box read:deny seccomp:on cat TAO' \
    "pandora box -m core/sandbox/read:deny -m core/trace/use_seccomp:1 cat \"$tao\"" \
    -n 'pandora box read:deny seccomp:off cat TAO' \
    "pandora box -m core/sandbox/read:deny -m core/trace/use_seccomp:0 cat \"$tao\"" \
    -n 'pandora box read:deny seccomp:on whitelist cat TAO' \
    "pandora box -m core/sandbox/read:deny -m core/trace/use_seccomp:1 -m \"whitelist/read+$tmp\" cat \"$tao\"" \
    -n 'pandora box read:deny seccomp:off whitelist cat TAO' \
    "pandora box -m core/sandbox/read:deny -m core/trace/use_seccomp:0 -m \"whitelist/read+$tmp\" cat \"$tao\""

echo >> "$out"
cat $tao >> "$out"
