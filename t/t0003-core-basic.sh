#!/bin/sh
# Copyright 2013, 2014, 2021 Ali Polatel <alip@exherbo.org>
# Released under the terms of the GNU General Public License v2

test_description='test the very basics of sydbox'
. ./test-lib.sh

save_SYDBOX_TEST_OPTIONS="$SYDBOX_TEST_OPTIONS"
SYDBOX_TEST_OPTIONS=
export SYDBOX_TEST_OPTIONS

test_expect_success 'compatible long options with sydbox-0' '
    sydbox --help &&
    sydbox --version &&
    sydfmt --help &&
    sydfmt --version
'

save_SYDBOX_TEST_OPTIONS="$SYDBOX_TEST_OPTIONS"
SYDBOX_TEST_OPTIONS="$save_SYDBOX_TEST_OPTIONS -mcore/sandbox/read:allow"
export SYDBOX_TEST_OPTIONS

test_expect_success 'return success if tracee returns success' '
    sydbox -- syd-true
'

test_expect_success 'return success if tracee returns success (STATIC)' '
    sydbox -- syd-true-static
'

test_expect_success 'return success if initial tracee returns success (FORK)' '
    sydbox -- syd-true-fork 64
'

test_expect_success 'return success if initial tracee returns success (STATIC|FORK)' '
    sydbox -- syd-true-fork-static 64
'

test_expect_success 'return success if initial tracee returns success (PTHREAD)' '
    sydbox -- syd-true-pthread 32
'

test_expect_success 'return failure if tracee returns failure' '
    test_expect_code 1 sydbox -- syd-false
'

test_expect_success 'return failure if tracee returns failure (STATIC)' '
    test_expect_code 1 sydbox -- syd-false-static
'

test_expect_success 'return failure if initial tracee returns failure (FORK)' '
    test_expect_code 1 sydbox -- syd-false-fork 64
'

test_expect_success 'return failure if initial tracee returns failure (STATIC|FORK)' '
    test_expect_code 1 sydbox -- syd-false-fork-static 64
'

test_expect_success 'return failure if initial tracee returns failure (PTHREAD)' '
    test_expect_code 1 sydbox -- syd-false-pthread 32
'

# These termination exit code checks fails on buildhost only when run via CI.
# The tests pass if you ssh into the buildhost and run the tests manually.
# The NOT_ON_BUILD_HOST prerequisite checks for the job id so we can still
# manually run these tests on the build host.
test_expect_success NOT_ON_BUILD_HOST 'return 128 + $SIGNUM if tracee is terminated' '
    test_expect_code 130 sydbox -- syd-abort 2 && # SIGINT
    test_expect_code 131 sydbox -- syd-abort 3 && # SIGQUIT
    test_expect_code 132 sydbox -- syd-abort 4 && # SIGILL
    test_expect_code 134 sydbox -- syd-abort 6 && # SIGABRT
    test_expect_code 136 sydbox -- syd-abort 8 && # SIGFPE
    test_expect_code 139 sydbox -- syd-abort 11 && # SIGFPE
    test_expect_code 141 sydbox -- syd-abort 13 && # SIGPIPE
    test_expect_code 142 sydbox -- syd-abort 14 && # SIGALRM
    test_expect_code 143 sydbox -- syd-abort 15 # SIGTERM
'

test_expect_success NOT_ON_BUILD_HOST 'return 128 + $SIGNUM if tracee is terminated (STATIC)' '
    test_expect_code 130 sydbox -- syd-abort-static 2 && # SIGINT
    test_expect_code 131 sydbox -- syd-abort-static 3 && # SIGQUIT
    test_expect_code 132 sydbox -- syd-abort-static 4 && # SIGILL
    test_expect_code 134 sydbox -- syd-abort-static 6 && # SIGABRT
    test_expect_code 136 sydbox -- syd-abort-static 8 && # SIGFPE
    test_expect_code 139 sydbox -- syd-abort-static 11 && # SIGFPE
    test_expect_code 141 sydbox -- syd-abort-static 13 && # SIGPIPE
    test_expect_code 142 sydbox -- syd-abort-static 14 && # SIGALRM
    test_expect_code 143 sydbox -- syd-abort-static 15 # SIGTERM
'

test_expect_success NOT_ON_BUILD_HOST 'return 128 + $SIGNUM if tracee is terminated (FORK)' '
    test_expect_code 130 sydbox -- syd-abort-fork 64 2 && # SIGINT
    test_expect_code 131 sydbox -- syd-abort-fork 64 3 && # SIGQUIT
    test_expect_code 132 sydbox -- syd-abort-fork 64 4 && # SIGILL
    test_expect_code 134 sydbox -- syd-abort-fork 64 6 && # SIGABRT
    test_expect_code 136 sydbox -- syd-abort-fork 64 8 && # SIGFPE
    test_expect_code 139 sydbox -- syd-abort-fork 64 11 && # SIGFPE
    test_expect_code 141 sydbox -- syd-abort-fork 64 13 && # SIGPIPE
    test_expect_code 142 sydbox -- syd-abort-fork 64 14 && # SIGALRM
    test_expect_code 143 sydbox -- syd-abort-fork 64 15 # SIGTERM
'

test_expect_success NOT_ON_BUILD_HOST 'return 128 + $SIGNUM if tracee is terminated (STATIC|FORK)' '
    test_expect_code 130 sydbox -- syd-abort-fork-static 64 2 && # SIGINT
    test_expect_code 131 sydbox -- syd-abort-fork-static 64 3 && # SIGQUIT
    test_expect_code 132 sydbox -- syd-abort-fork-static 64 4 && # SIGILL
    test_expect_code 134 sydbox -- syd-abort-fork-static 64 6 && # SIGABRT
    test_expect_code 136 sydbox -- syd-abort-fork-static 64 8 && # SIGFPE
    test_expect_code 139 sydbox -- syd-abort-fork-static 64 11 && # SIGFPE
    test_expect_code 141 sydbox -- syd-abort-fork-static 64 13 && # SIGPIPE
    test_expect_code 142 sydbox -- syd-abort-fork-static 64 14 && # SIGALRM
    test_expect_code 143 sydbox -- syd-abort-fork-static 64 15 # SIGTERM
'

test_expect_success TODO 'return 128 + $SIGNUM if tracee is terminated (PTHREAD)' '
    test_expect_code 130 sydbox -- syd-abort-pthread 8 2 && # SIGINT
    test_expect_code 131 sydbox -- syd-abort-pthread 8 3 && # SIGQUIT
    test_expect_code 132 sydbox -- syd-abort-pthread 8 4 && # SIGILL
    test_expect_code 134 sydbox -- syd-abort-pthread 8 6 && # SIGABRT
    test_expect_code 136 sydbox -- syd-abort-pthread 8 8 && # SIGFPE
    test_expect_code 139 sydbox -- syd-abort-pthread 8 11 && # SIGFPE
    test_expect_code 141 sydbox -- syd-abort-pthread 8 13 && # SIGPIPE
    test_expect_code 142 sydbox -- syd-abort-pthread 8 14 && # SIGALRM
    test_expect_code 143 sydbox -- syd-abort-pthread 8 15 # SIGTERM
'

test_expect_success 'return 128 + $SIGNUM if tracee is terminated (STATIC|PTHREAD)' '
    test_expect_code 130 sydbox -- syd-abort-pthread-static 8 2 && # SIGINT
    test_expect_code 131 sydbox -- syd-abort-pthread-static 8 3 && # SIGQUIT
    test_expect_code 132 sydbox -- syd-abort-pthread-static 8 4 && # SIGILL
    test_expect_code 134 sydbox -- syd-abort-pthread-static 8 6 && # SIGABRT
    test_expect_code 136 sydbox -- syd-abort-pthread-static 8 8 && # SIGFPE
    test_expect_code 139 sydbox -- syd-abort-pthread-static 8 11 && # SIGFPE
    test_expect_code 141 sydbox -- syd-abort-pthread-static 8 13 && # SIGPIPE
    test_expect_code 142 sydbox -- syd-abort-pthread-static 8 14 && # SIGALRM
    test_expect_code 143 sydbox -- syd-abort-pthread-static 8 15 # SIGTERM
'

test_expect_success 'magic /dev/sydbox API is 1' '
    sydbox -- sh -c "test -e /dev/sydbox/1" &&
    sydbox -- sh -c "test -e /dev/sydbox" &&
    test_expect_code 1 sydbox -- sh -c "test -e /dev/sydbox/0"
'

test_expect_success HAVE_NEWFSTATAT 'magic /dev/sydbox API is 1 using fstatat' '
    sydbox -- syd-fstatat cwd /dev/sydbox
    sydbox -- syd-fstatat cwd /dev/sydbox/1 &&
    sydbox -- syd-fstatat null /dev/sydbox &&
    sydbox -- syd-fstatat null /dev/sydbox/1 &&
    sydbox -- syd-fstatat /dev /dev/sydbox &&
    sydbox -- syd-fstatat /dev /dev/sydbox/1
    test_expect_code 22 sydbox -- syd-fstatat cwd /dev/sydbox/0 # EINVAL
'

test_expect_failure 'magic /dev/sydbox boolean checking works with write:off' '
    sydbox -m core/sandbox/write:off -- sh <<-\EOF
test -e /dev/sydbox/core/sandbox/write"?"
test $? -eq 1 && exit 0
EOF
'

test_expect_success 'magic /dev/sydbox boolean checking works with write:deny' '
    sydbox -- sh <<-\EOF
test -e /dev/sydbox/core/sandbox/write:deny &&
test -e /dev/sydbox/core/sandbox/write"?"
EOF
'

SYDBOX_TEST_OPTIONS="$save_SYDBOX_TEST_OPTIONS"
export SYDBOX_TEST_OPTIONS

test_expect_failure HAVE_NEWFSTATAT 'magic /dev/sydbox boolean checking works with -m write:off' '
    test_expect_code 1 sydbox -m core/sandbox/write:off -- \
        syd-fstatat cwd /dev/sydbox/core/sandbox/write"?" # ENOENT
'

test_expect_success HAVE_NEWFSTATAT 'magic /dev/sydbox boolean checking works with -m write:deny' '
    sydbox -m core/sandbox/write:deny -- \
        syd-fstatat cwd /dev/sydbox/core/sandbox/write"?"
'

test_expect_success 'magic /dev/sydbox boolean checking works with -m switch' '
    sydbox -m core/sandbox/write:deny -- sh <<-\EOF
test -e /dev/sydbox/core/sandbox/write"?"
EOF
'

test_expect_success 'magic core/violation/exit_code:0 works' '
    f="no-$(unique_file)" &&
    rm -f "$f" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- sh && <<EOF
: > "$f"
EOF
    test_path_is_missing "$f"
'

test_expect_success 'magic core/violation/raise_fail:1 works' '
    f="no-$(unique_file)" &&
    d="$(unique_dir)" &&
    mkdir "$d" &&
    test_must_violate sydbox \
        -m core/violation/raise_fail:1 \
        -m core/sandbox/write:deny \
        -- sh && <<EOF
: > "$d"/"$f"
EOF
    test_path_is_missing "$d"/"$f"
'

test_expect_success TODO 'magic core/violation/raise_safe:1 works' '
    f="$(unique_file)" &&
    : > "$f" &&
    test_must_violate sydbox \
        -m core/violation/raise_safe:1 \
        -m core/sandbox/write:deny \
        -- emily access -e EACCES -w "$f"
'

test_expect_success 'chdir() hook with EEXIST (mkdir -p) [RAISE_SAFE=0]' '
    pdir="$(unique_dir)" &&
    mkdir "$pdir" &&
    cdir="${pdir}/$(unique_dir)" &&
    mkdir "$cdir" &&
    sydbox \
        -m core/sandbox/write:deny \
        -m core/violation/raise_safe:0 \
        syd-mkdir-p "$cdir"
'

test_expect_success 'chdir() hook with EEXIST (mkdir -p) [RAISE_SAFE=0]' '
    pdir="$(unique_dir)" &&
    mkdir "$pdir" &&
    cdir="${pdir}/$(unique_dir)" &&
    mkdir "$cdir" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -m core/violation/raise_safe:1 \
        syd-mkdir-p "$cdir"
'

test_expect_success 'chdir() hook with EPERM (mkdir -p) [RAISE_SAFE=0]' '
    pdir="$(unique_dir)" &&
    mkdir "$pdir" &&
    cdir="${pdir}/$(unique_dir)" &&
    rm -fr "$cdir" &&
    test_expect_code 1 sydbox \
        -m core/sandbox/write:deny \
        -m core/violation/raise_safe:0 \
        syd-mkdir-p "$cdir"
'

test_expect_success 'chdir() hook with EPERM (mkdir -p) [RAISE_SAFE=0,WHITELIST]' '
    pdir="$(unique_dir)" &&
    mkdir "$pdir" &&
    cdir="${pdir}/$(unique_dir)" &&
    rm -fr "$cdir" &&
    sydbox \
        -m core/sandbox/write:deny \
        -m whitelist/write+"$HOMER"/"${cdir}" \
        -m core/violation/raise_safe:0 \
        syd-mkdir-p "$cdir"
'

# Note, we use test_must_fail here rather than ! so we know if sydbox exits
# abnormally, eg. segfaults.
test_expect_success 'read sandboxing for open works' '
    pdir="$(unique_dir)" &&
    mkdir "$pdir" &&
    cdir="${pdir}/$(unique_dir)" &&
    mkdir "$cdir" &&
    touch "$cdir"/readme &&
    test_must_fail sydbox \
        -m core/sandbox/read:deny \
        -m core/sandbox/write:off \
        -m core/sandbox/exec:off \
        -m core/sandbox/network:off \
        syd-open-static "$cdir"/readme rdonly
'

test_expect_success 'read sandboxing for open works with whitelist' '
    pdir="$(unique_dir)" &&
    mkdir "$pdir" &&
    cdir="${pdir}/$(unique_dir)" &&
    mkdir "$cdir" &&
    touch "$cdir"/readme &&
    sydbox \
        -m core/sandbox/read:deny \
        -m "whitelist/read+/***" \
        syd-open-static "$cdir"/readme rdonly
'

test_expect_success 'restrict file control works to deny open(path,O_ASYNC)' '
    pdir="$(unique_dir)" &&
    mkdir "$pdir" &&
    cdir="${pdir}/$(unique_dir)" &&
    mkdir "$cdir" &&
    touch "$cdir"/readme &&
    sydbox \
        -m core/sandbox/read:allow \
        -m core/restrict/file_control:false \
        syd-open-static "$cdir"/readme rdonly async
'

test_expect_success 'restrict file control works to deny open(path,O_DIRECT)' '
    pdir="$(unique_dir)" &&
    mkdir "$pdir" &&
    cdir="${pdir}/$(unique_dir)" &&
    mkdir "$cdir" &&
    touch "$cdir"/readme &&
    sydbox \
        -m core/sandbox/read:allow \
        -m core/restrict/file_control:false \
        syd-open-static "$cdir"/readme rdonly direct
'

test_expect_success 'restrict file control works to deny open(path,O_SYNC)' '
    pdir="$(unique_dir)" &&
    mkdir "$pdir" &&
    cdir="${pdir}/$(unique_dir)" &&
    mkdir "$cdir" &&
    touch "$cdir"/readme &&
    sydbox \
        -m core/sandbox/read:allow \
        -m core/restrict/file_control:false \
        syd-open-static "$cdir"/readme rdonly sync
'

test_expect_success 'restrict file control works to deny open(path,O_ASYNC) with EPERM' '
    pdir="$(unique_dir)" &&
    mkdir "$pdir" &&
    cdir="${pdir}/$(unique_dir)" &&
    mkdir "$cdir" &&
    touch "$cdir"/readme &&
    test_expect_code 1 sydbox \
        -m core/sandbox/read:allow \
        -m core/restrict/file_control:true \
        syd-open-static "$cdir"/readme rdonly async
'

test_expect_success 'restrict file control works to deny open(path,O_DIRECT) with EPERM' '
    pdir="$(unique_dir)" &&
    mkdir "$pdir" &&
    cdir="${pdir}/$(unique_dir)" &&
    mkdir "$cdir" &&
    touch "$cdir"/readme &&
    test_expect_code 1 sydbox \
        -m core/sandbox/read:allow \
        -m core/restrict/file_control:true \
        syd-open-static "$cdir"/readme rdonly direct
'

test_expect_success 'restrict file control works to deny open(path,O_SYNC) with EPERM' '
    pdir="$(unique_dir)" &&
    mkdir "$pdir" &&
    cdir="${pdir}/$(unique_dir)" &&
    mkdir "$cdir" &&
    touch "$cdir"/readme &&
    test_expect_code 1 sydbox \
        -m core/sandbox/read:allow \
        -m core/restrict/file_control:true \
        syd-open-static "$cdir"/readme rdonly sync
'

test_expect_success DIG 'network sandboxing = off' '
    pdir="$(unique_dir)" &&
    mkdir "$pdir" &&
    cdir="${pdir}/$(unique_dir)" &&
    mkdir "$cdir" &&
    touch "$cdir"/readme &&
    sydbox \
        -m core/sandbox/read:off \
        -m core/sandbox/write:off \
        -m core/sandbox/exec:off \
        -m core/sandbox/network:off \
        dig +noall +answer dev.chessmuse.com > "$cdir"/out &&
        test -s "$cdir"/out
'

test_expect_success DIG 'network sandboxing = allow' '
    pdir="$(unique_dir)" &&
    mkdir "$pdir" &&
    cdir="${pdir}/$(unique_dir)" &&
    mkdir "$cdir" &&
    touch "$cdir"/readme &&
    sydbox \
        -m core/sandbox/read:off \
        -m core/sandbox/write:off \
        -m core/sandbox/exec:off \
        -m core/sandbox/network:allow \
        dig +noall +answer dev.chessmuse.com > "$cdir"/out &&
    test -s "$cdir"/out
'

# TODO should be test_must_violate rather than test_must_fail
test_expect_success DIG 'network sandboxing = deny' '
    pdir="$(unique_dir)" &&
    mkdir "$pdir" &&
    cdir="${pdir}/$(unique_dir)" &&
    mkdir "$cdir" &&
    touch "$cdir"/readme &&
    test_must_fail sydbox \
        -m core/sandbox/read:off \
        -m core/sandbox/write:off \
        -m core/sandbox/exec:off \
        -m core/sandbox/network:deny \
        dig +noall +answer dev.chessmuse.com
'

test_done
