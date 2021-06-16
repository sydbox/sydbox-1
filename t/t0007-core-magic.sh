#!/bin/sh
# Copyright 2013, 2014, 2021 Ali Polatel <alip@exherbo.org>
# Released under the terms of the GNU General Public License v2

test_description='test the magic stat of sydbox'
. ./test-lib.sh

save_SYDBOX_TEST_OPTIONS="$SYDBOX_TEST_OPTIONS"
SYDBOX_TEST_OPTIONS="$save_SYDBOX_TEST_OPTIONS -mcore/sandbox/read:allow"
export SYDBOX_TEST_OPTIONS

test_expect_success_foreach_option 'magic /dev/sydbox API is 2' '
    sydbox -- sh -c "test -e /dev/sydbox/2" &&
    sydbox -- sh -c "test -e /dev/sydbox" &&
    test_expect_code 1 sydbox -- sh -c "test -e /dev/sydbox/1" &&
    test_expect_code 1 sydbox -- sh -c "test -e /dev/sydbox/0"
'

test_expect_success_foreach_option HAVE_NEWFSTATAT 'magic /dev/sydbox API is 2 using fstatat' '
    sydbox -- syd-fstatat cwd /dev/sydbox &&
    sydbox -- syd-fstatat cwd /dev/sydbox/2 &&
    sydbox -- syd-fstatat null /dev/sydbox &&
    sydbox -- syd-fstatat null /dev/sydbox/2 &&
    sydbox -- syd-fstatat /dev /dev/sydbox &&
    sydbox -- syd-fstatat /dev /dev/sydbox/2 &&
    test_expect_code 22 sydbox -- syd-fstatat cwd /dev/sydbox/1 && # EINVAL
    test_expect_code 22 sydbox -- syd-fstatat cwd /dev/sydbox/0    # ""
'

test_expect_failure_foreach_option 'magic /dev/sydbox boolean checking works with write:off' '
    sydbox -m core/sandbox/write:off -- sh <<-\EOF
test -e /dev/sydbox/core/sandbox/write"?"
test $? -eq 1 && exit 0
EOF
'

test_expect_success_foreach_option 'magic /dev/sydbox boolean checking works with write:deny' '
    sydbox -- sh <<-\EOF
test -e /dev/sydbox/core/sandbox/write:deny &&
test -e /dev/sydbox/core/sandbox/write"?"
EOF
'

SYDBOX_TEST_OPTIONS="$save_SYDBOX_TEST_OPTIONS"
export SYDBOX_TEST_OPTIONS

test_expect_failure_foreach_option HAVE_NEWFSTATAT 'magic /dev/sydbox boolean checking works with -m write:off' '
    test_expect_code 1 sydbox -m core/sandbox/write:off -- \
        syd-fstatat cwd /dev/sydbox/core/sandbox/write"?" # ENOENT
'

test_expect_success_foreach_option HAVE_NEWFSTATAT 'magic /dev/sydbox boolean checking works with -m write:deny' '
    sydbox -m core/sandbox/write:deny -- \
        syd-fstatat cwd /dev/sydbox/core/sandbox/write"?"
'

test_expect_success_foreach_option 'magic /dev/sydbox boolean checking works with -m switch' '
    sydbox -m core/sandbox/write:deny -- sh <<-\EOF
test -e /dev/sydbox/core/sandbox/write"?"
EOF
'

test_expect_success_foreach_option 'magic core/violation/exit_code:0 works' '
    f="no-$(unique_file)" &&
    rm -f "$f" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- sh <<EOF && test_path_is_missing "$f"
: > "$f"
EOF
'

test_expect_success_foreach_option 'magic core/violation/raise_fail:1 works' '
    f="no-$(unique_file)" &&
    d="$(unique_dir)" &&
    mkdir "$d" &&
    test_must_violate sydbox \
        -m core/violation/raise_fail:1 \
        -m core/sandbox/write:deny \
        -- sh <<EOF && test_path_is_missing "$d"/"$f"
: > "$d"/"$f"
EOF
'

test_expect_success_foreach_option TODO 'magic core/violation/raise_safe:1 works' '
    f="$(unique_file)" &&
    : > "$f" &&
    test_must_violate sydbox \
        -m core/violation/raise_safe:1 \
        -m core/sandbox/write:deny \
        -- emily access -e EACCES -w "$f"
'

test_expect_success_foreach_option 'no magic stat if magic lock is set via core config' '
    test_expect_code 1 sydbox \
        -m core/trace/magic_lock:on \
        -m core/sandbox/read:allow \
        stat /dev/sydbox/2
'

test_done
