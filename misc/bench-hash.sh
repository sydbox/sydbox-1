#!/bin/sh -x

tao=TAO
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

out=hyperfine-hash-$(date +'%Y-%m-%d')-$(git rev-parse --short HEAD)
if [ -e "$out".json -o -e "$out".txt ]; then
    echo >&2 "Refusing to overwrite previous benchmark at \`$out'"
    exit 1
fi

# Benchmark Sha1, Xxh32 and Xxh64 hashes:
# 1. 10G file with all zeroes.
# 2. 4G file with random data.
hyperfine \
    --warmup 3 \
    --export-asciidoc "$out".asciidoc \
    --export-csv "$out".csv \
    --export-json "$out".json \
    --export-markdown "$out".md \
    --show-output \
    'dd if=/dev/zero bs=1M count=1024 | syd hash -so-' \
    'dd if=/dev/zero bs=1M count=10240 | syd hash -o-' \
    'dd if=/dev/zero bs=1M count=10240 | syd hash -3o-' \
    | tee "§out".log

#hyperfine \
#    --warmup 3 \
#    --export-asciidoc bench-r.asciidoc \
#    --export-csv bench-r.csv \
#    --export-json bench-r.json \
#    --export-markdown bench-r.md \
#    --show-output \
#    'dd if=/dev/urandom bs=1M count=4096 | syd hash -o-' \
#    'dd if=/dev/urandom bs=1M count=4096 | syd hash -3o-' \
#    'dd if=/dev/urandom bs=1M count=4096 | syd hash -so-' \
#    tee bench-r.log

cat>"$out".txt<<EOF
Date: $(date -u)
SydB☮x: $(sydbox --version | tr '\n' ' ')
HyperFine: $(hyperfine --version)
Tao:
$(cat "$tao")
EOF
