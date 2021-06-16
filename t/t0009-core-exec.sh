#!/bin/sh
# Copyright 2021 Ali Polatel <alip@exherbo.org>
# Based in part upon strace/tests/threads-execve.test which is
#   Copyright (c) 2016 Dmitry V. Levin <ldv@strace.io>
#   Copyright (c) 2016-2020 The strace developers.
#   All rights reserved.
# Released under the terms of the GNU General Public License v2 or later

test_description='test execve() handling of sydbox'
. ./test-lib.sh

save_SYDBOX_TEST_OPTIONS="$SYDBOX_TEST_OPTIONS"
SYDBOX_TEST_OPTIONS="$save_SYDBOX_TEST_OPTIONS
    -m core/violation/raise_safe:1
    -m core/sandbox/read:allow
    -m core/sandbox/write:allow
"
export SYDBOX_TEST_OPTIONS

if test -n "$SYDBOX_TEST_INSTALLED"; then
    threads_execve="${LIBEXECDIR}/sydbox/t/test-bin/threads_execve"
else
    threads_execve="${SYDBOX_BUILD_DIR}/t/test-bin/threads_execve"
fi

# FIXME: Add DUMP prereq!
test_expect_success_foreach_option DIFF,JQ 'multithreaded execve leader switch' '
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
            "'${threads_execve}'" > "$OUT" || r=1 &&
        test $r = 1 && break ||
        test -s "$f" &&
        echo >&2 DUMP &&
        cat >&2 "$f" &&
        echo >&2 "--" &&
        jq -r \
            ". |\
                select(.event.name==\"exec_mt\") |\
                [.execve_thread.pid,.leader_thread.pid] | join(\" \")"  < "$f" > "$EXP"
        echo >&2 EXP &&
        cat >&2 "$EXP" &&
        echo >&2 "--" &&
        diff -u -- "$EXP" "$OUT" >&2 || r=1 &&
        cmp "$EXP" "$OUT" && r=0 &&
        echo >&2 "--" &&
        s1="$(date +%s)" &&
        if [ "$(($s1-$s0))" -gt "$(($TIMEOUT_DURATION/4))" ]; then
            break
        fi
    done &&
    test $r = 0
'

test_done
