#!/bin/sh
# Copyright 2012, 2013, 2014 Ali Polatel <alip@exherbo.org>
# Released under the terms of the GNU General Public License v2

test_description='test pathname canonicalisation: realpath_mode()'
. ./test-lib.sh

test_expect_success SYMLINKS setup-symlinks '
    ln -sf self self &&
    ln -sf loop0 loop1 &&
    ln -sf loop1 loop0
'

test_expect_success 'non-absolute path returns EINVAL' '
    realpath_mode-1 EINVAL no-file existing NULL
'

test_expect_success 'empty path -> ENOENT' '
    realpath_mode-1 ENOENT "" existing NULL
'

test_expect_success NOT_ROOT 'permission was denied for a component of path prefix -> EACCES' '
    mkdir -p -m 700 foo/bar/baz &&
    test_when_finished "chmod 700 foo/bar" && chmod 000 foo/bar &&
    realpath_mode-1 EACCES "${HOMER}"/foo/bar/baz existing NULL
'

test_expect_success SYMLINKS,NOT_ROOT 'permission was denied for a symlink component of path prefix -> EACCES' '
    mkdir -p -m 700 foo/bar/baz &&
    ln -s bar foo/bal &&
    test_when_finished "chmod 700 foo/bar" && chmod 000 foo/bar &&
    realpath_mode-1 EACCES "${HOMER}"/foo/bal/baz existing NULL
'

test_expect_success SYMLINKS 'too many symbolic links for a component of path prefix -> ELOOP' '
    realpath_mode-1 ELOOP "${HOMER}"/loop0/foo existing NULL
'

test_expect_success SYMLINKS 'too many symbolic links for file -> ELOOP' '
    realpath_mode-1 ELOOP "${HOMER}"/loop0 existing NULL
'

test_expect_success SYMLINKS 'too many symbolic links for file (RPATH_NOLAST|RPATH_NOFOLLOW) -> OK' '
    realpath_mode-1 0 "${HOMER}"/loop0 "nolast|nofollow" "${HOMER}"/loop0
'

test_expect_success SYMLINKS 'self referencing symbolic link -> ELOOP' '
    realpath_mode-1 ELOOP "${HOMER}"/self/foo existing NULL &&
    realpath_mode-1 ELOOP "${HOMER}"/self existing NULL
'

test_expect_success 'too long file name -> ENAMETOOLONG' '
    realpath_mode-1 ENAMETOOLONG "${HOMER}/${NAMETOOLONG}/foo" existing NULL &&
    realpath_mode-1 ENAMETOOLONG "${HOMER}/${NAMETOOLONG}" existing NULL
'

test_expect_success 'component not a directory -> ENOTDIR' '
    mkdir -p foo && touch foo/bak &&
    realpath_mode-1 ENOTDIR "${HOMER}"/foo/bak/baz existing NULL
'

test_expect_success SYMLINKS 'symlink component not pointing to a directory -> ENOTDIR' '
    mkdir -p foo && touch foo/bak && ln -sf bak foo/ban &&
    realpath_mode-1 ENOTDIR "${HOMER}"/foo/ban/baz existing NULL
'

test_expect_success SYMLINKS 'symlink component not pointing to a directory (NOFOLLOW) -> ENOTDIR' '
    mkdir -p foo && touch foo/bak && ln -sf bak foo/ban &&
    realpath_mode-1 ENOTDIR "${HOMER}"/foo/ban/baz "existing|nofollow" NULL
'

test_expect_success 'realpath ., .., intermediate // handling' '
    touch intermediate &&
    realpath_mode-1 0 "$HOMER//./..//$HOME_BASE/intermediate" "existing" "$HOMER/intermediate"
'

test_expect_success 'realpath non-directory with trailing slash yields NULL' '
    touch non-directory-slash &&
    realpath_mode-1 ENOTDIR "$HOMER/non-directory-slash/" "existing" NULL
'

test_expect_success 'realpath recovers from missing parent directory' '
    realpath_mode-1 0 "$HOMER/missing-directory/.." "existing" "$HOMER"
'

test_expect_success SYMLINKS 'symlinks not resolved with RPATH_NOFOLLOW' '
    touch dont-resolve-to-me &&
    ln -sf dont-resolve-to-me dont-resolve-from-me &&
    realpath_mode-1 0 "$HOMER"/dont-resolve-from-me "existing|nofollow" "$HOMER"/dont-resolve-from-me
'

test_expect_success SYMLINKS 'symlinks to a file can be resolved' '
    touch resolve-to-me &&
    ln -sf resolve-to-me resolve-from-me &&
    realpath_mode-1 0 "$HOMER/resolve-from-me" "existing" "$HOMER/resolve-to-me"
'

test_expect_success SYMLINKS 'symlinks to a directory can be resolved' '
    mkdir -p resolve-to-this-dir &&
    ln -sf resolve-to-this-dir resolve-from-this-link-to-this-dir &&
    ln -sf resolve-from-this-link-to-this-dir resolve-from-this-link-to-that-link &&
    realpath_mode-1 0 "$HOMER/resolve-from-this-link-to-that-link" "existing" "$HOMER"/resolve-to-this-dir
'

test_expect_success SYMLINKS 'symlink to a non-existing file yields NULL' '
    rm -f file-dont-exist &&
    ln -sf file-dont-exist resolve-to-dont-exist-file &&
    realpath_mode-1 ENOENT "$HOMER/resolve-to-dont-exist-file" "existing" NULL
'

test_expect_success SYMLINKS 'non-directory symlink with a trailing slash yields NULL' '
    touch resolve-to-this-non-dir &&
    ln -sf resolve-to-this-non-dir resolve-from-this-link-to-this-non-dir &&
    realpath_mode-1 ENOTDIR "$HOMER/resolve-to-this-non-dir/" existing NULL
'

test_expect_success SYMLINKS 'recovers from missing directory via symlink' '
    rm -fr resolve-to-no-such-dir-in-the-sky &&
    ln -sf resolve-to-no-such-dir-in-the-sky resolve-from-this-link-to-no-such-dir-in-the-sky &&
    realpath_mode-1 0 "$HOMER/resolve-from-this-link-to-no-such-dir-in-the-sky/.." existing "$HOMER"
'

test_expect_success 'alternate modes can resolve basenames' '
    rm -f alternate-file-dont-exist &&
    realpath_mode-1 0 "$HOMER/alternate-file-dont-exist" "nolast" "$HOMER/alternate-file-dont-exist" &&
    realpath_mode-1 0 "$TRASH_DIRECTORY/alternate-file-dont-exist" "nolast" "$HOMER/alternate-file-dont-exist"
'

test_expect_success SYMLINKS 'alternate modes can resolve symlink basenames' '
    rm -f resolve-to-alternate-file-dont-exist &&
    ln -sf resolve-to-alternate-file-dont-exist resolve-from-this-link-to-alternate-file-dont-exist &&
    realpath_mode-1 0 "$HOMER/resolve-from-this-link-to-alternate-file-dont-exist" "nolast" "$HOMER/resolve-to-alternate-file-dont-exist" &&
    realpath_mode-1 0 "$TRASH_DIRECTORY/resolve-from-this-link-to-alternate-file-dont-exist" "nolast" "$HOMER/resolve-to-alternate-file-dont-exist"
'

test_expect_success 'alternate modes can handle missing dirnames' '
    rm -fr dir-dont-exist &&
    realpath_mode-1 0 "$HOMER/dir-dont-exist/nofile" nolast "$HOMER"/dir-dont-exist/nofile
'

test_expect_success SYMLINKS 'possible loop bug' '
    mkdir -p possible-loop-dir &&
    ln -sf possible-loop-dir point-to-possible-loop-dir &&
    ln -sf point-to-possible-loop-dir point-to-possible-loop-link &&
    touch possible-loop-dir/file &&
    ln -sf ../point-to-possible-loop-dir/file possible-loop-dir/link &&
    realpath_mode-1 0 "$HOMER/point-to-possible-loop-dir/link" existing "$HOMER"/possible-loop-dir/file
'

test_expect_success 'leading // is honoured correctly' '
    ln -sf //.//../.. leading-slash-link &&
    stat_inode / > inode-slash-one &&
    stat_inode // > inode-slash-two &&
    if test_cmp inode-slash-one inode-slash-two; then
        realpath_mode-1 0 //. existing / &&
        realpath_mode-1 0 "$HOMER"/leading-slash-link existing /
    else
        realpath_mode-1 0 //. existing // &&
        realpath_mode-1 0 "$HOMER"/leading-slash-link existing //
    fi
'

test_expect_success SYMLINKS 'non existing file under directory symlink' '
    mkdir -p this-dir-has-no-file &&
    mkdir -p this-dir-has-a-link &&
    ln -sf ../this-dir-has-no-file this-dir-has-a-link/link &&
    realpath_mode-1 0 "$HOMER"/this-dir-has-a-link/link/no-file "nolast" "$HOMER"/this-dir-has-no-file/no-file
'

test_done
