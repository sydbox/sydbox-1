#!/bin/sh
# vim: set noet ts=8 sts=8 sw=8 tw=80 :
# Copyright 2013, 2014 Ali Polatel <alip@exherbo.org>
# Released under the terms of the GNU General Public License v2

#
# Additions to test-lib-functions.sh
#

NAMETOOLONG=$(printf '%4096s' ' ' | tr ' ' x)
export NAMETOOLONG

stat_mtime() {
	case "$(uname -s)" in
	Linux)
		stat -c '%Y' "$@"
		;;
	*)
		echo >&2 'error: i do not know how to check mtime on this system.'
		exit 1
		;;
	esac
}

stat_inode() {
	case "$(uname -s)" in
	Linux)
		stat -c '%i' "$@"
		;;
	Darwin)
		stat -f '%i' "$@"
		;;
	FreeBSD)
		stat -f '%i' "$@"
		;;
	*)
		ls -di "$@" | cut -d ' ' -f 1
		;;
	esac
}

test_path_is_fifo () {
	if ! [ -p "$1" ]
	then
		echo "Fifo $1 doesn't exist. $*"
		false
	fi
}

test_path_is_symlink() {
	if ! [ -h "$1" ]
	then
		echo "Symbolic link $1 doesn't exist. $*"
		false
	fi
}

test_path_is_readable () {
	if ! [ -r "$1" ]
	then
		echo "Path $1 isn't readable. $*"
		false
	fi
}

test_path_is_not_readable () {
	if [ -r "$1" ]
	then
		echo "Path $1 is readable. $*"
		false
	fi
}

test_path_is_writable () {
	if ! [ -w "$1" ]
	then
		echo "Path $1 isn't writable. $*"
		false
	fi
}

test_path_is_not_writable () {
	if [ -w "$1" ]
	then
		echo "Path $1 is writable. $*"
		false
	fi
}

test_path_is_empty() {
	if [ -s "$1" ]
	then
		echo "File $1 isn't empty. $*"
		false
	fi
}

test_path_is_non_empty() {
	if ! [ -s "$1" ]
	then
		echo "File $1 is empty. $*"
		false
	fi
}

test_path_has_mtime() {
	local expected_mtime="$1" real_mtime=
	shift

	if ! [ -e "$1" ]
	then
		echo "File $1 does not exist. $*"
		false
	else
		real_mtime=$(stat_mtime "$1")
		if ! [ "$expected_mtime" = "$real_mtime" ]
		then
			echo "File $1 has unexpected mtime:$real_mtime (expected:$expected_mtime) $*"
			false
		fi
	fi
}

test_bpf_action() {
	local file="$1"
	local name="$2"
	local action="$3"

	echo >&2 "# BPF.PFC: NAME: $name ACTION: $action"
	test -s "$file" && cat >&2 "$file"
	echo >&2 '--8<--'

	test -s "$file" &&
	grep -iPz \
		"(?s)\n(\s*)#\s*$name action\s*\n\s*action $action;\s*\n" \
		"$file"
}

test_must_violate() {
	retval=0
	save_SYDBOX_TEST_OPTIONS="$SYDBOX_TEST_OPTIONS"
	SYDBOX_TEST_OPTIONS="$SYDBOX_TEST_OPTIONS -mcore/violation/exit_code:0"
	export SYDBOX_TEST_OPTIONS
	"$@"
	exit_code=$?
	if test $exit_code -eq 0
	then
		echo >&2 "test_must_violate: command succeeded. $*"
		retval=1
	elif test $exit_code -gt 129 -a $exit_code -le 192
	then
		echo >&2 "test_must_violate: died by signal: $*"
		retval=1
	elif test $exit_code = 127
	then
		echo >&2 "test_must_violate: command not found: $*"
		retval=1
	elif test $exit_code -ne 128
	then
		echo >&2 "test_must_violate: abnormal exit with code:$exit_code $*"
		retval=1
	fi
	SYDBOX_TEST_OPTIONS="$save_SYDBOX_TEST_OPTIONS"
	export SYDBOX_TEST_OPTIONS
	return "$retval"
}

#
# Test with different tracing options
#
test_expect_success_foreach_option() {
	test "$#" = 3 || test "$#" = 2 ||
	error "bug in the test script: not 2 or 3 parameters to test-expect-success-foreach-option"

	argc="$#" ; arg1="$1" ; arg2="$2" ; arg3="$3"
	for choice in 0 1 2 3
	do
		memory_access="$choice"
		suffix="[memory_access:${choice}]"
		if test "$argc" = 3
		then
			prereq="$arg1"
		fi
		if test "$argc" = 3
		then
			set -- "$prereq" "$arg2 $suffix" "$arg3"
		elif test -n "$prereq"
		then
			set -- "$prereq" "$arg1 $suffix" "$arg2"
		else
			set -- "$arg1 $suffix" "$arg2"
		fi
		test_sydbox_options=t test_expect_success "$@"
	done
}

test_expect_failure_foreach_option() {
	test "$#" = 3 || test "$#" = 2 ||
	error "bug in the test script: not 2 or 3 parameters to test-expect-failure-foreach-option"

	argc="$#" ; arg1="$1" ; arg2="$2" ; arg3="$3"
	for choice in 0 1 2 3
	do
		IFS=' ' read -r memory_access <<EOF
$choice
EOF
		suffix="[memory_access:${choice}]"
		if test "$argc" = 3
		then
			set -- "$arg1" "$arg2 $suffix" "$arg3"
		else
			set -- "$arg1 $suffix" "$arg2"
		fi
		test_sydbox_options=t test_expect_failure "$@"
	done
}

#
# Generate unique file/dir name for a testcase.
# Usage: test_tempname $dir $prefix
# Note: We don't care about security here!
#
test_tempnam() {
	case $# in
	2) ;;
	*) error "bug in the test script: not 2 parameters to test_tempnam" ;;
	esac

	"$PERL_PATH" \
		-e 'use File::Temp;' \
		-e 'print File::Temp::tempnam($ARGV[0], $ARGV[1]);' \
		-- "$@"
	exit_code=$?
	if test $exit_code != 0
	then
		error "bug in the test library: test_tempnam() exited with $exit_code"
	fi
}

test_tempnam_cwd() {
	basename "$(test_tempnam . "$1")"
	exit_code=$?
	if test $exit_code != 0
	then
		error "bug in the test library: basename exited with $exit_code"
	fi
}

test_unique_with_prefix() {
	prefix="$1"
	optpre="$2"

	printf "%s-%s_%s.%s" "$prefix" "$optpre" "$(test_tempnam_cwd . "")" "$test_count"
}

# Shorthand functions for convenience
unique_file() {
	test_unique_with_prefix "file" "$1"
}

unique_dir() {
	test_unique_with_prefix "dir" "$1"
}

unique_link() {
	test_unique_with_prefix "link" "$1"
}

unique_fifo() {
	test_unique_with_prefix "fifo" "$1"
}
