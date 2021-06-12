#!/bin/sh
# Copyright 2021 Ali Polatel <alip@exherbo.org>
# Based in part upon strace/tests/threads-execve.test which is
#   Copyright (c) 2016 Dmitry V. Levin <ldv@strace.io>
#   Copyright (c) 2016-2020 The strace developers.
#   All rights reserved.
# Released under the terms of the GNU General Public License v2 or later

test_description='test execve() handling of sydbox'
. ./test-lib.sh

# FIXME: Add DUMP prereq!
test_expect_success DIFF,JQ 'multithreaded execve leader switch' '
    # Due to probabilistic nature of the test, try it several times.
    EXP="$(unique_file)" &&
    OUT="$(unique_file)" &&
    s0="$(date +%s)" &&
    r=0 &&
    while :; do
        f="$(unique_file)" &&
        rm -f "$f" &&
        sydbox \
            -d "$f" \
            -m core/sandbox/write:deny \
            "$SYDBOX_BUILD_DIR"/t/test-bin/threads_execve > "$OUT" || r=1 &&
        test $r = 1 && break
        test -s "$f" &&
        echo >&2 DUMP &&
        cat >&2 "$f" &&
        echo >&2 "--" &&
        jq -r \
            ". |\
                select(.event.name==\"execve_mt\") |\
                [.execve_thread.pid,.leader_thread.pid] | join(\" \")"  < "$f" > "$EXP"
        echo >&2 EXP &&
        cat >&2 "$EXP" &&
        echo >&2 "--" &&
        diff -u -- "$EXP" "$OUT" >&2
        cmp "$EXP" "$OUT" && break
        echo >&2 "--"
        s1="$(date +%s)"
        if [ "$(($s1-$s0))" -gt "$(($TIMEOUT_DURATION/10))" ]; then
            r=1
            break
        fi
    done
    test $r = 0
'

test_done