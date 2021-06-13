# Library of functions shared by all tests scripts, included by
# test-lib.sh.
#
# Copyright (c) 2005 Junio C Hamano
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see http://www.gnu.org/licenses/ .

# The semantics of the editor variables are that of invoking
# sh -c "$EDITOR \"$@\"" files ...
#
# If our trash directory contains shell metacharacters, they will be
# interpreted if we just set $EDITOR directly, so do a little dance with
# environment variables to work around this.
#
# In particular, quoting isn't enough, as the path may contain the same quote
# that we're using.
test_set_editor () {
	FAKE_EDITOR="$1"
	export FAKE_EDITOR
	EDITOR='"$FAKE_EDITOR"'
	export EDITOR
}

test_decode_color () {
	awk '
		function name(n) {
			if (n == 0) return "RESET";
			if (n == 1) return "BOLD";
			if (n == 2) return "FAINT";
			if (n == 3) return "ITALIC";
			if (n == 7) return "REVERSE";
			if (n == 30) return "BLACK";
			if (n == 31) return "RED";
			if (n == 32) return "GREEN";
			if (n == 33) return "YELLOW";
			if (n == 34) return "BLUE";
			if (n == 35) return "MAGENTA";
			if (n == 36) return "CYAN";
			if (n == 37) return "WHITE";
			if (n == 40) return "BLACK";
			if (n == 41) return "BRED";
			if (n == 42) return "BGREEN";
			if (n == 43) return "BYELLOW";
			if (n == 44) return "BBLUE";
			if (n == 45) return "BMAGENTA";
			if (n == 46) return "BCYAN";
			if (n == 47) return "BWHITE";
		}
		{
			while (match($0, /\033\[[0-9;]*m/) != 0) {
				printf "%s<", substr($0, 1, RSTART-1);
				codes = substr($0, RSTART+2, RLENGTH-3);
				if (length(codes) == 0)
					printf "%s", name(0)
				else {
					n = split(codes, ary, ";");
					sep = "";
					for (i = 1; i <= n; i++) {
						printf "%s%s", sep, name(ary[i]);
						sep = ";"
					}
				}
				printf ">";
				$0 = substr($0, RSTART + RLENGTH, length($0) - RSTART - RLENGTH + 1);
			}
			print
		}
	'
}

lf_to_nul () {
	perl -pe 'y/\012/\000/'
}

nul_to_q () {
	perl -pe 'y/\000/Q/'
}

q_to_nul () {
	perl -pe 'y/Q/\000/'
}

q_to_cr () {
	tr Q '\015'
}

q_to_tab () {
	tr Q '\011'
}

qz_to_tab_space () {
	tr QZ '\011\040'
}

append_cr () {
	sed -e 's/$/Q/' | tr Q '\015'
}

remove_cr () {
	tr '\015' Q | sed -e 's/Q$//'
}

# In some bourne shell implementations, the "unset" builtin returns
# nonzero status when a variable to be unset was not set in the first
# place.
#
# Use sane_unset when that should not be considered an error.

sane_unset () {
	unset "$@"
	return 0
}

# Stop execution and start a shell. This is useful for debugging tests.
#
# Be sure to remove all invocations of this command before submitting.

test_pause () {
	"$SHELL_PATH" <&6 >&5 2>&7
}

# Wrap sydbox with a debugger. Adding this to a command can make it easier
# to understand what is going on in a failing test.
#
# Examples:
#     debug sydbox
#     debug --debugger=nemiver sydbox $ARGS
#     debug -d "valgrind --tool=memcheck --track-origins=yes" sydbox $ARGS
debug () {
	case "$1" in
	-d)
		SYDBOX_DEBUGGER="$2" &&
		shift 2
		;;
	--debugger=*)
		SYDBOX_DEBUGGER="${1#*=}" &&
		shift 1
		;;
	*)
		SYDBOX_DEBUGGER=1
		;;
	esac &&
	SYDBOX_DEBUGGER="${SYDBOX_DEBUGGER}" "$@" <&6 >&5 2>&7
}

# Get the modebits from a file or directory, ignoring the setgid bit (g+s).
# This bit is inherited by subdirectories at their creation. So we remove it
# from the returning string to prevent callers from having to worry about the
# state of the bit in the test directory.
#
test_modebits () {
	ls -ld "$1" | sed -e 's|^\(..........\).*|\1|' \
			  -e 's|^\(......\)S|\1-|' -e 's|^\(......\)s|\1x|'
}



write_script () {
	{
		echo "#!${2-"$SHELL_PATH"}" &&
		cat
	} >"$1" &&
	chmod +x "$1"
}

# Use test_set_prereq to tell that a particular prerequisite is available.
# The prerequisite can later be checked for in two ways:
#
# - Explicitly using test_have_prereq.
#
# - Implicitly by specifying the prerequisite tag in the calls to
#   test_expect_{success,failure} and test_external{,_without_stderr}.
#
# The single parameter is the prerequisite tag (a simple word, in all
# capital letters by convention).

test_unset_prereq () {
	! test_have_prereq "$1" ||
	satisfied_prereq="${satisfied_prereq% $1 *} ${satisfied_prereq#* $1 }"
}

test_set_prereq () {
	if test -n "$SYDBOX_TEST_FAIL_PREREQS_INTERNAL"
	then
		case "$1" in
		# The "!" case is handled below with
		# test_unset_prereq()
		!*)
			;;
		# (Temporary?) whitelist of things we can't easily
		# pretend not to support
		SYMLINKS)
			;;
		# Inspecting whether SYDBOX_TEST_FAIL_PREREQS is on
		# should be unaffected.
		FAIL_PREREQS)
			;;
		*)
			return
		esac
	fi

	case "$1" in
	!*)
		test_unset_prereq "${1#!}"
		;;
	*)
		satisfied_prereq="$satisfied_prereq$1 "
		;;
	esac
}
satisfied_prereq=" "
lazily_testable_prereq= lazily_tested_prereq=

# Usage: test_lazy_prereq PREREQ 'script'
test_lazy_prereq () {
	lazily_testable_prereq="$lazily_testable_prereq$1 "
	eval test_prereq_lazily_$1=\$2
}

test_run_lazy_prereq_ () {
	script='
mkdir -p "$TRASH_DIRECTORY/prereq-test-dir-'"$1"'" &&
(
	cd "$TRASH_DIRECTORY/prereq-test-dir-'"$1"'" &&'"$2"'
)'
	say >&3 "checking prerequisite: $1"
	say >&3 "$script"
	test_eval_ "$script"
	eval_ret=$?
	rm -rf "$TRASH_DIRECTORY/prereq-test-dir-$1"
	if test "$eval_ret" = 0; then
		say >&3 "prerequisite $1 ok"
	else
		say >&3 "prerequisite $1 not satisfied"
	fi
	return $eval_ret
}

test_have_prereq () {
	# prerequisites can be concatenated with ','
	save_IFS=$IFS
	IFS=,
	set -- $*
	IFS=$save_IFS

	total_prereq=0
	ok_prereq=0
	missing_prereq=

	for prerequisite
	do
		case "$prerequisite" in
		!*)
			negative_prereq=t
			prerequisite=${prerequisite#!}
			;;
		*)
			negative_prereq=
		esac

		case " $lazily_tested_prereq " in
		*" $prerequisite "*)
			;;
		*)
			case " $lazily_testable_prereq " in
			*" $prerequisite "*)
				eval "script=\$test_prereq_lazily_$prerequisite" &&
				if test_run_lazy_prereq_ "$prerequisite" "$script"
				then
					test_set_prereq $prerequisite
				fi
				lazily_tested_prereq="$lazily_tested_prereq$prerequisite "
			esac
			;;
		esac

		total_prereq=$(($total_prereq + 1))
		case "$satisfied_prereq" in
		*" $prerequisite "*)
			satisfied_this_prereq=t
			;;
		*)
			satisfied_this_prereq=
		esac

		case "$satisfied_this_prereq,$negative_prereq" in
		t,|,t)
			ok_prereq=$(($ok_prereq + 1))
			;;
		*)
			# Keep a list of missing prerequisites; restore
			# the negative marker if necessary.
			prerequisite=${negative_prereq:+!}$prerequisite
			if test -z "$missing_prereq"
			then
				missing_prereq=$prerequisite
			else
				missing_prereq="$prerequisite,$missing_prereq"
			fi
		esac
	done

	test $total_prereq = $ok_prereq
}

test_declared_prereq () {
	case ",$test_prereq," in
	*,$1,*)
		return 0
		;;
	esac
	return 1
}

test_verify_prereq () {
	test -z "$test_prereq" ||
	expr >/dev/null "$test_prereq" : '[A-Z0-9_,!]*$' ||
	BUG "'$test_prereq' does not look like a prereq"
}

test_expect_failure () {
	test_start_
	test "$#" = 3 && { test_prereq=$1; shift; } || test_prereq=
	test "$#" = 2 ||
	BUG "not 2 or 3 parameters to test-expect-failure"
	test_verify_prereq
	export test_prereq
	if ! test_skip "$@"
	then
		say >&3 "checking known breakage of $TEST_NUMBER.$test_count '$1': $2"
		if test_run_ "$2" expecting_failure
		then
			test_known_broken_ok_ "$1"
		else
			test_known_broken_failure_ "$1"
		fi
	fi
	test_finish_
}

test_expect_success () {
	test_start_
	test "$#" = 3 && { test_prereq=$1; shift; } || test_prereq=
	test "$#" = 2 ||
	BUG "not 2 or 3 parameters to test-expect-success"
	test_verify_prereq
	export test_prereq
	if ! test_skip "$@"
	then
		say >&3 "expecting success of $TEST_NUMBER.$test_count '$1': $2"
		if test_run_ "$2"
		then
			test_ok_ "$1"
		else
			test_failure_ "$@"
		fi
	fi
	test_finish_
}

# test_external runs external test scripts that provide continuous
# test output about their progress, and succeeds/fails on
# zero/non-zero exit code.  It outputs the test output on stdout even
# in non-verbose mode, and announces the external script with "# run
# <n>: ..." before running it.  When providing relative paths, keep in
# mind that all scripts run in "trash directory".
# Usage: test_external description command arguments...
# Example: test_external 'Perl API' perl ../path/to/test.pl
test_external () {
	test "$#" = 4 && { test_prereq=$1; shift; } || test_prereq=
	test "$#" = 3 ||
	BUG "not 3 or 4 parameters to test_external"
	descr="$1"
	shift
	test_verify_prereq
	export test_prereq
	if ! test_skip "$descr" "$@"
	then
		# Announce the script to reduce confusion about the
		# test output that follows.
		say_color "" "# run $test_count: $descr ($*)"
		# Export TEST_DIRECTORY, TRASH_DIRECTORY and SYDBOX_TEST_LONG
		# to be able to use them in script
		export TEST_DIRECTORY TRASH_DIRECTORY SYDBOX_TEST_LONG
		# Run command; redirect its stderr to &4 as in
		# test_run_, but keep its stdout on our stdout even in
		# non-verbose mode.
		"$@" 2>&4
		if test "$?" = 0
		then
			if test $test_external_has_tap -eq 0; then
				test_ok_ "$descr"
			else
				say_color "" "# test_external test $descr was ok"
				test_success=$(($test_success + 1))
			fi
		else
			if test $test_external_has_tap -eq 0; then
				test_failure_ "$descr" "$@"
			else
				say_color error "# test_external test $descr failed: $@"
				test_failure=$(($test_failure + 1))
			fi
		fi
	fi
}

# Like test_external, but in addition tests that the command generated
# no output on stderr.
test_external_without_stderr () {
	# The temporary file has no (and must have no) security
	# implications.
	tmp=${TMPDIR:-/tmp}
	stderr="$tmp/sydbox-external-stderr.$$.tmp"
	test_external "$@" 4> "$stderr"
	test -f "$stderr" || error "Internal error: $stderr disappeared."
	descr="no stderr: $1"
	shift
	say >&3 "# expecting no stderr from previous command"
	if test ! -s "$stderr"
	then
		rm "$stderr"

		if test $test_external_has_tap -eq 0; then
			test_ok_ "$descr"
		else
			say_color "" "# test_external_without_stderr test $descr was ok"
			test_success=$(($test_success + 1))
		fi
	else
		if test "$verbose" = t
		then
			output=$(echo; echo "# Stderr is:"; cat "$stderr")
		else
			output=
		fi
		# rm first in case test_failure exits.
		rm "$stderr"
		if test $test_external_has_tap -eq 0; then
			test_failure_ "$descr" "$@" "$output"
		else
			say_color error "# test_external_without_stderr test $descr failed: $@: $output"
			test_failure=$(($test_failure + 1))
		fi
	fi
}

# debugging-friendly alternatives to "test [-f|-d|-e]"
# The commands test the existence or non-existence of $1
test_path_is_file () {
	test "$#" -ne 1 && BUG "1 param"
	if ! test -f "$1"
	then
		echo "File $1 doesn't exist"
		false
	fi
}

test_path_is_dir () {
	test "$#" -ne 1 && BUG "1 param"
	if ! test -d "$1"
	then
		echo "Directory $1 doesn't exist"
		false
	fi
}

test_path_exists () {
	test "$#" -ne 1 && BUG "1 param"
	if ! test -e "$1"
	then
		echo "Path $1 doesn't exist"
		false
	fi
}

# Check if the directory exists and is empty as expected, barf otherwise.
test_dir_is_empty () {
	test "$#" -ne 1 && BUG "1 param"
	test_path_is_dir "$1" &&
	if test -n "$(ls -a1 "$1" | egrep -v '^\.\.?$')"
	then
		echo "Directory '$1' is not empty, it contains:"
		ls -la "$1"
		return 1
	fi
}

# Check if the file exists and has a size greater than zero
test_file_not_empty () {
	test "$#" = 2 && BUG "2 param"
	if ! test -s "$1"
	then
		echo "'$1' is not a non-empty file."
		false
	fi
}

test_path_is_missing () {
	test "$#" -ne 1 && BUG "1 param"
	if test -e "$1"
	then
		echo "Path exists:"
		ls -ld "$1"
		if test $# -ge 1
		then
			echo "$*"
		fi
		false
	fi
}

# test_line_count checks that a file has the number of lines it
# ought to. For example:
#
#	test_expect_success 'produce exactly one line of output' '
#		do something >output &&
#		test_line_count = 1 output
#	'
#
# is like "test $(wc -l <output) = 1" except that it passes the
# output through when the number of lines is wrong.

test_line_count () {
	if test $# != 3
	then
		BUG "not 3 parameters to test_line_count"
	elif ! test $(wc -l <"$3") "$1" "$2"
	then
		echo "test_line_count: line count for $3 !$1 $2"
		cat "$3"
		return 1
	fi
}

test_file_size () {
	test "$#" -ne 1 && BUG "1 param"
	test-tool path-utils file-size "$1"
}

# Returns success if a comma separated string of keywords ($1) contains a
# given keyword ($2).
# Examples:
# `list_contains "foo,bar" bar` returns 0
# `list_contains "foo" bar` returns 1

list_contains () {
	case ",$1," in
	*,$2,*)
		return 0
		;;
	esac
	return 1
}

# Returns success if the arguments indicate that a command should be
# accepted by test_must_fail(). If the command is run with env, the env
# and its corresponding variable settings will be stripped before we
# test the command being run.
test_must_fail_acceptable () {
	if test "$1" = "env"
	then
		shift
		while test $# -gt 0
		do
			case "$1" in
			*?=*)
				shift
				;;
			*)
				break
				;;
			esac
		done
	fi

	case "$1" in
	syd*|shoebox|pandora|test-tool|test_terminal)
		return 0
		;;
	*)
		return 1
		;;
	esac
}

# This is not among top-level (test_expect_success | test_expect_failure)
# but is a prefix that can be used in the test script, like:
#
#	test_expect_success 'complain and die' '
#           do something &&
#           do something else &&
#	    test_must_fail git checkout ../outerspace
#	'
#
# Writing this as "! git checkout ../outerspace" is wrong, because
# the failure could be due to a segv.  We want a controlled failure.
#
# Accepts the following options:
#
#   ok=<signal-name>[,<...>]:
#     Don't treat an exit caused by the given signal as error.
#     Multiple signals can be specified as a comma separated list.
#     Currently recognized signal names are: sigpipe, success.
#     (Don't use 'success', use 'test_might_fail' instead.)
#
# Do not use this to run anything but "git" and other specific testable
# commands (see test_must_fail_acceptable()).  We are not in the
# business of vetting system supplied commands -- in other words, this
# is wrong:
#
#    test_must_fail grep pattern output
#
# Instead use '!':
#
#    ! grep pattern output

test_must_fail () {
	case "$1" in
	ok=*)
		_test_ok=${1#ok=}
		shift
		;;
	*)
		_test_ok=
		;;
	esac
	if ! test_must_fail_acceptable "$@"
	then
		echo >&7 "test_must_fail: only 'sydbox' is allowed: $*"
		return 1
	fi
	"$@" 2>&7
	exit_code=$?
	if test $exit_code -eq 0 && ! list_contains "$_test_ok" success
	then
		echo >&4 "test_must_fail: command succeeded: $*"
		return 1
	elif test_match_signal 13 $exit_code && list_contains "$_test_ok" sigpipe
	then
		return 0
	elif test $exit_code -gt 129 && test $exit_code -le 192
	then
		echo >&4 "test_must_fail: died by signal $(($exit_code - 128)): $*"
		return 1
	elif test $exit_code -eq 127
	then
		echo >&4 "test_must_fail: command not found: $*"
		return 1
	elif test $exit_code -eq 126
	then
		echo >&4 "test_must_fail: valgrind error: $*"
		return 1
	fi
	return 0
} 7>&2 2>&4

# Similar to test_must_fail, but tolerates success, too.  This is
# meant to be used in contexts like:
#
#	test_expect_success 'some command works without configuration' '
#		test_might_fail git config --unset all.configuration &&
#		do something
#	'
#
# Writing "git config --unset all.configuration || :" would be wrong,
# because we want to notice if it fails due to segv.
#
# Accepts the same options as test_must_fail.

test_might_fail () {
	test_must_fail ok=success "$@" 2>&7
} 7>&2 2>&4

# Similar to test_must_fail and test_might_fail, but check that a
# given command exited with a given exit code. Meant to be used as:
#
#	test_expect_success 'Merge with d/f conflicts' '
#		test_expect_code 1 git merge "merge msg" B master
#	'

test_expect_code () {
	want_code=$1
	shift
	"$@" 2>&7
	exit_code=$?
	if test $exit_code = $want_code
	then
		return 0
	fi

	echo >&4 "test_expect_code: command exited with $exit_code, we wanted $want_code $*"
	return 1
} 7>&2 2>&4

# test_cmp is a helper function to compare actual and expected output.
# You can use it like:
#
#	test_expect_success 'foo works' '
#		echo expected >expected &&
#		foo >actual &&
#		test_cmp expected actual
#	'
#
# This could be written as either "cmp" or "diff -u", but:
# - cmp's output is not nearly as easy to read as diff -u
# - not all diff versions understand "-u"

test_cmp() {
	test "$#" -ne 2 && BUG "2 param"
	eval "$SYDBOX_TEST_CMP" '"$@"'
}

# test_cmp_bin - helper to compare binary files

test_cmp_bin () {
	test "$#" -ne 2 && BUG "2 param"
	cmp "$@"
}

# Wrapper for grep which used to be used for
# GIT_TEST_GETTEXT_POISON=false. Only here as a shim for other
# in-flight changes. Should not be used and will be removed soon.
test_i18ngrep () {
	eval "last_arg=\${$#}"

	test -f "$last_arg" ||
	BUG "test_i18ngrep requires a file to read as the last parameter"

	if test $# -lt 2 ||
	   { test "x!" = "x$1" && test $# -lt 3 ; }
	then
		BUG "too few parameters to test_i18ngrep"
	fi

	if test "x!" = "x$1"
	then
		shift
		! grep "$@" && return 0

		echo >&4 "error: '! grep $@' did find a match in:"
	else
		grep "$@" && return 0

		echo >&4 "error: 'grep $@' didn't find a match in:"
	fi

	if test -s "$last_arg"
	then
		cat >&4 "$last_arg"
	else
		echo >&4 "<File '$last_arg' is empty>"
	fi

	return 1
}

# Call any command "$@" but be more verbose about its
# failure. This is handy for commands like "test" which do
# not output anything when they fail.
verbose () {
	"$@" && return 0
	echo >&4 "command failed: $(git rev-parse --sq-quote "$@")"
	return 1
}

# Check if the file expected to be empty is indeed empty, and barfs
# otherwise.

test_must_be_empty () {
	test "$#" -ne 1 && BUG "1 param"
	test_path_is_file "$1" &&
	if test -s "$1"
	then
		echo "'$1' is not empty, it contains:"
		cat "$1"
		return 1
	fi
}

# Print a sequence of integers in increasing order, either with
# two arguments (start and end):
#
#     test_seq 1 5 -- outputs 1 2 3 4 5 one line at a time
#
# or with one argument (end), in which case it starts counting
# from 1.

test_seq () {
	case $# in
	1)	set 1 "$@" ;;
	2)	;;
	*)	BUG "not 1 or 2 parameters to test_seq" ;;
	esac
	test_seq_counter__=$1
	while test "$test_seq_counter__" -le "$2"
	do
		echo "$test_seq_counter__"
		test_seq_counter__=$(( $test_seq_counter__ + 1 ))
	done
}

# This function can be used to schedule some commands to be run
# unconditionally at the end of the test to restore sanity:
#
#	test_expect_success 'test core.capslock' '
#		git config core.capslock true &&
#		test_when_finished "git config --unset core.capslock" &&
#		hello world
#	'
#
# That would be roughly equivalent to
#
#	test_expect_success 'test core.capslock' '
#		git config core.capslock true &&
#		hello world
#		git config --unset core.capslock
#	'
#
# except that the greeting and config --unset must both succeed for
# the test to pass.
#
# Note that under --immediate mode, no clean-up is done to help diagnose
# what went wrong.

test_when_finished () {
	# We cannot detect when we are in a subshell in general, but by
	# doing so on Bash is better than nothing (the test will
	# silently pass on other shells).
	test "${BASH_SUBSHELL-0}" = 0 ||
	BUG "test_when_finished does nothing in a subshell"
	test_cleanup="{ $*
		} && (exit \"\$eval_ret\"); eval_ret=\$?; $test_cleanup"
}

# This function can be used to schedule some commands to be run
# unconditionally at the end of the test script, e.g. to stop a daemon:
#
#	test_expect_success 'test git daemon' '
#		git daemon &
#		daemon_pid=$! &&
#		test_atexit 'kill $daemon_pid' &&
#		hello world
#	'
#
# The commands will be executed before the trash directory is removed,
# i.e. the atexit commands will still be able to access any pidfiles or
# socket files.
#
# Note that these commands will be run even when a test script run
# with '--immediate' fails.  Be careful with your atexit commands to
# minimize any changes to the failed state.

test_atexit () {
	# We cannot detect when we are in a subshell in general, but by
	# doing so on Bash is better than nothing (the test will
	# silently pass on other shells).
	test "${BASH_SUBSHELL-0}" = 0 ||
	BUG "test_atexit does nothing in a subshell"
	test_atexit_cleanup="{ $*
		} && (exit \"\$eval_ret\"); eval_ret=\$?; $test_atexit_cleanup"
}

# This function writes out its parameters, one per line
test_write_lines () {
	printf "%s\n" "$@"
}

perl () {
	command "$PERL_PATH" "$@" 2>&7
} 7>&2 2>&4
# Exit the test suite, either by skipping all remaining tests or by
# exiting with an error. If our prerequisite variable $1 falls back
# on a default assume we were opportunistically trying to set up some
# tests and we skip. If it is explicitly "true", then we report a failure.
#
# The error/skip message should be given by $2.
#
test_skip_or_die () {
	if ! test_bool_env "$1" false
	then
		skip_all=$2
		test_done
	fi
	error "$2"
}

# Like "env FOO=BAR some-program", but run inside a subshell, which means
# it also works for shell functions (though those functions cannot impact
# the environment outside of the test_env invocation).
test_env () {
	(
		while test $# -gt 0
		do
			case "$1" in
			*=*)
				eval "${1%%=*}=\${1#*=}"
				eval "export ${1%%=*}"
				shift
				;;
			*)
				"$@" 2>&7
				exit
				;;
			esac
		done
	)
} 7>&2 2>&4

# Returns true if the numeric exit code in "$2" represents the expected signal
# in "$1". Signals should be given numerically.
test_match_signal () {
	if test "$2" = "$((128 + $1))"
	then
		# POSIX
		return 0
	elif test "$2" = "$((256 + $1))"
	then
		# ksh
		return 0
	fi
	return 1
}

# Read up to "$1" bytes (or to EOF) from stdin and write them to stdout.
test_copy_bytes () {
	perl -e '
		my $len = $ARGV[1];
		while ($len > 0) {
			my $s;
			my $nread = sysread(STDIN, $s, $len);
			die "cannot read: $!" unless defined($nread);
			last unless $nread;
			print $s;
			$len -= $nread;
		}
	' - "$1"
}

# Choose a port number based on the test script's number and store it in
# the given variable name, unless that variable already contains a number.
test_set_port () {
	local var=$1 port

	if test $# -ne 1 || test -z "$var"
	then
		BUG "test_set_port requires a variable name"
	fi

	eval port=\$$var
	case "$port" in
	"")
		# No port is set in the given env var, use the test
		# number as port number instead.
		# Remove not only the leading 't', but all leading zeros
		# as well, so the arithmetic below won't (mis)interpret
		# a test number like '0123' as an octal value.
		port=${this_test#${this_test%%[1-9]*}}
		if test "${port:-0}" -lt 1024
		then
			# root-only port, use a larger one instead.
			port=$(($port + 10000))
		fi
		;;
	*[!0-9]*|0*)
		error >&7 "invalid port number: $port"
		;;
	*)
		# The user has specified the port.
		;;
	esac

	# Make sure that parallel '--stress' test jobs get different
	# ports.
	port=$(($port + ${GIT_TEST_STRESS_JOB_NR:-0}))
	eval $var=$port
}
# Check that the given command was invoked as part of the
# trace2-format trace on stdin.
#
#	test_subcommand [!] <command> <args>... < <trace>
#
# For example, to look for an invocation of "git upload-pack
# /path/to/repo"
#
#	GIT_TRACE2_EVENT=event.log git fetch ... &&
#	test_subcommand git upload-pack "$PATH" <event.log
#
# If the first parameter passed is !, this instead checks that
# the given command was not called.
#
test_subcommand () {
	local negate=
	if test "$1" = "!"
	then
		negate=t
		shift
	fi

	local expr=$(printf '"%s",' "$@")
	expr="${expr%,}"

	if test -n "$negate"
	then
		! grep "\[$expr\]"
	else
		grep "\[$expr\]"
	fi
}

# Check that the given command was invoked as part of the
# trace2-format trace on stdin.
#
#	test_region [!] <category> <label> git <command> <args>...
#
# For example, to look for trace2_region_enter("index", "do_read_index", repo)
# in an invocation of "git checkout HEAD~1", run
#
#	GIT_TRACE2_EVENT="$(pwd)/trace.txt" GIT_TRACE2_EVENT_NESTING=10 \
#		git checkout HEAD~1 &&
#	test_region index do_read_index <trace.txt
#
# If the first parameter passed is !, this instead checks that
# the given region was not entered.
#
test_region () {
	local expect_exit=0
	if test "$1" = "!"
	then
		expect_exit=1
		shift
	fi

	grep -e	'"region_enter".*"category":"'"$1"'","label":"'"$2"\" "$3"
	exitcode=$?

	if test $exitcode != $expect_exit
	then
		return 1
	fi

	grep -e	'"region_leave".*"category":"'"$1"'","label":"'"$2"\" "$3"
	exitcode=$?

	if test $exitcode != $expect_exit
	then
		return 1
	fi

	return 0
}
