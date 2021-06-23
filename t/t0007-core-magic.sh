#!/bin/sh
# Copyright 2013, 2014, 2021 Ali Polatel <alip@exherbo.org>
# Released under the terms of the GNU General Public License v2

test_description='test the magic stat of sydbox'
. ./test-lib.sh

save_SYDBOX_TEST_OPTIONS="$SYDBOX_TEST_OPTIONS"
for magic_mem_access in 0 1; do
    SYDBOX_TEST_OPTIONS="$save_SYDBOX_TEST_OPTIONS -mcore/sandbox/read:allow"
    export SYDBOX_TEST_OPTIONS

    test_expect_success \
        "magic /dev/sydbox stat works [memory_access:${magic_mem_access}]" '
    sydbox \
        -M '${magic_mem_access}' \
        -- test -e /dev/sydbox
'

    test_expect_success \
        "magic /dev/sydbox stat works using fstatat(AT_FDCWD, /dev/sydbox) [memory_access:${magic_mem_access}]" '
    sydbox \
        -M '${magic_mem_access}' \
        -- syd-fstatat cwd /dev/sydbox
'

    test_expect_success \
        "magic /dev/sydbox stat works using fstatat(0, /dev/sydbox) [memory_access:${magic_mem_access}]" '
    sydbox \
        -M '${magic_mem_access}' \
        -- syd-fstatat null /dev/sydbox
'

    test_expect_success \
        "magic /dev/sydbox stat works using fstatat(/dev, /dev/sydbox) [memory_access:${magic_mem_access}]" '
    sydbox \
        -M '${magic_mem_access}' \
        -- syd-fstatat /dev /dev/sydbox
'

    test_expect_success \
        "magic /dev/sydbox API is 2 [memory_access:${magic_mem_access}]" '
    sydbox \
        -M '${magic_mem_access}' \
        -- test -e /dev/sydbox/2
'

    test_expect_success HAVE_NEWFSTATAT \
        "magic /dev/sydbox API is 2 using fstatat(AT_FDCWD, /dev/sydbox/2) [memory_access:${magic_mem_access}]" '
    sydbox \
        -M '${magic_mem_access}' \
        -- syd-fstatat cwd /dev/sydbox/2
'

    test_expect_success HAVE_NEWFSTATAT \
        "magic /dev/sydbox API is 2 using fstatat(0, /dev/sydbox/2) [memory_access:${magic_mem_access}]" '
    sydbox \
        -M '${magic_mem_access}' \
        -- syd-fstatat null /dev/sydbox/2
'

    test_expect_success HAVE_NEWFSTATAT \
        "magic /dev/sydbox API is using fstatat(/dev, sydbox/2) [memory_access:${magic_mem_access}]" '
    sydbox \
        -M '${magic_mem_access}' \
        -- syd-fstatat /dev /dev/sydbox/2
'

    test_expect_success \
        "magic /dev/sydbox API is not 1 [memory_access:${magic_mem_access}]" '
    test_expect_code 1 sydbox \
        -M '${magic_mem_access}' \
        -- test -e /dev/sydbox/1
'

    test_expect_success HAVE_NEWFSTATAT \
        "magic /dev/sydbox API is not 1 using fstatat(cwd, sydbox/1) [memory_access:${magic_mem_access}]" '
    test_expect_code 22 sydbox \
        -M '${magic_mem_access}' \
        -- syd-fstatat cwd /dev/sydbox/1 # EINVAL
'

    test_expect_success \
        "magic /dev/sydbox API is not 0 [memory_access:${magic_mem_access}]" '
    test_expect_code 1 sydbox \
        -M '${magic_mem_access}' \
        -- sh -c "test -e /dev/sydbox/0"
'

    test_expect_success HAVE_NEWFSTATAT \
        "magic /dev/sydbox API is not 0 using fstatat(cwd, sydbox/0) [memory_access:${magic_mem_access}]" '
    test_expect_code 22 sydbox \
        -M '${magic_mem_access}' \
        -- syd-fstatat cwd /dev/sydbox/0 # EINVAL
'

    test_expect_failure \
        "magic /dev/sydbox boolean checking works with write:off [memory_access:${magic_mem_access}]" '
    sydbox \
        -M '${magic_mem_access}' \
        -m core/sandbox/write:off -- sh <<-\EOF
test -e /dev/sydbox/core/sandbox/write"?"
test $? -eq 1 && exit 0
EOF
'

    test_expect_success \
        "magic /dev/sydbox boolean checking works with write:deny [memory_access:${magic_mem_access}]" '
    sydbox \
        -M '${magic_mem_access}' \
        -- sh <<-\EOF
test -e /dev/sydbox/core/sandbox/write:deny &&
test -e /dev/sydbox/core/sandbox/write"?"
EOF
'

    SYDBOX_TEST_OPTIONS="$save_SYDBOX_TEST_OPTIONS"
    export SYDBOX_TEST_OPTIONS

    test_expect_failure HAVE_NEWFSTATAT \
        "magic /dev/sydbox boolean checking works with -m write:off [memory_access:${magic_mem_access}]" '
    test_expect_code 1 sydbox \
        -M '${magic_mem_access}' \
        -m core/sandbox/write:off -- \
        syd-fstatat cwd /dev/sydbox/core/sandbox/write"?" # ENOENT
'

    test_expect_success HAVE_NEWFSTATAT \
        "magic /dev/sydbox boolean checking works with -m write:deny [memory_access:${magic_mem_access}]" '
    sydbox \
        -M '${magic_mem_access}' \
        -m core/sandbox/write:deny -- \
        syd-fstatat cwd /dev/sydbox/core/sandbox/write"?"
'

    test_expect_success \
        "magic /dev/sydbox boolean checking works with -m switch [memory_access:${magic_mem_access}]" '
    sydbox \
        -M '${magic_mem_access}' \
        -m core/sandbox/write:deny -- sh <<-\EOF
test -e /dev/sydbox/core/sandbox/write"?"
EOF
'

    test_expect_success \
        "magic core/violation/exit_code:0 works [memory_access:${magic_mem_access}]" '
    f="no-$(unique_file)" &&
    rm -f "$f" &&
    test_must_violate sydbox \
        -M '${magic_mem_access}' \
        -m core/sandbox/write:deny \
        -- sh <<EOF && test_path_is_missing "$f"
: > "$f"
EOF
'

    test_expect_success \
        "magic core/violation/raise_fail:1 works [memory_access:${magic_mem_access}]" '
    f="no-$(unique_file)" &&
    d="$(unique_dir)" &&
    mkdir "$d" &&
    test_must_violate sydbox \
        -M '${magic_mem_access}' \
        -m core/violation/raise_fail:1 \
        -m core/sandbox/write:deny \
        -- sh <<EOF && test_path_is_missing "$d"/"$f"
: > "$d"/"$f"
EOF
'

    test_expect_success TODO \
        "magic core/violation/raise_safe:1 works [memory_access:${magic_mem_access}]" '
    f="$(unique_file)" &&
    : > "$f" &&
    test_must_violate sydbox \
        -M '${magic_mem_access}' \
        -m core/violation/raise_safe:1 \
        -m core/sandbox/write:deny \
        -- emily access -e EACCES -w "$f"
'

    test_expect_success \
        "no magic stat if magic lock is set via core config [memory_access:${magic_mem_access}]" '
    test_expect_code 1 sydbox \
        -M '${magic_mem_access}' \
        -m core/trace/magic_lock:on \
        -m core/sandbox/read:allow \
        stat /dev/sydbox/2
'
done

test_done
