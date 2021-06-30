#!/bin/bash
# Default bashrc for the SydBox shell
# Based in part upon /etc/bash/bashrc of Exherbo.
# Copyright (c) 2021 Ali Polatel <alip@exherbo.org>
# SPDX-License-Identifier: GPL-2.0-only

# Don't run anything here unless we have an interactive shell.
if [[ $- != *i* ]] ; then
	return
fi

# Set colorful PS1 only on colorful terminals.
# dircolors --print-database uses its own built-in database
# instead of using /etc/DIR_COLORS.  Try to use the external file
# first to take advantage of user additions.
_use_color=false
if type -P dircolors >/dev/null ; then
        # Enable colors for ls, etc.
        LS_COLORS=
        if [[ -f ~/.dir_colors ]] ; then
                # If you have a custom file, chances are high that it's not the default.
                _used_default_dircolors="no"
                eval "$(dircolors -b ~/.dir_colors)"
        elif [[ -f /etc/DIR_COLORS ]] ; then
                # People might have customized the system database.
                _used_default_dircolors="maybe"
                eval "$(dircolors -b /etc/DIR_COLORS)"
        else
                _used_default_dircolors="yes"
                eval "$(dircolors -b)"
        fi
        if [[ -n ${LS_COLORS:+set} ]] ; then
                _use_color=true

                # The majority of systems out there do not customize these files, so we
                # want to avoid always exporting the large $LS_COLORS variable.  This
                # keeps the active env smaller, and it means we don't have to deal with
                # running new/old (incompatible) versions of `ls` compared to when we
                # last sourced this file.
                case ${_used_default_dircolors} in
                no) ;;
                yes) unset LS_COLORS ;;
                *)
                        ls_colors=$(eval "$(dircolors -b)"; echo "${LS_COLORS}")
                        if [[ ${ls_colors} == "${LS_COLORS}" ]] ; then
                                unset LS_COLORS
                        fi
                        ;;
                esac
        fi
fi

if ${_use_color} ; then
        if [[ ${EUID} == 0 ]] ; then
                PS1='\[\033[01;31m\]\h\[\033[01;34m\] \w \$\[\033[00m\] '
        else
                PS1='\[\033[01;35m\]\u@\h\[\033[01;34m\] \w \$\[\033[00m\] '
        fi

        alias ls='ls --color=auto'
        [[ $(basename "$(readlink -f /usr/bin/grep)") == ggrep ]] && alias grep='grep --color=auto'
else
        # show root@ when we don't have colors
        PS1='\u@\h \w \$ '
fi

# Things in /etc/sydbox/bashrc.d/ will be sourced for all interactive shells.
# This is useful for e.g. bash-completion.
for _f in /etc/sydbox/bashrc.d/* ; do
	[[ -r "${_f}" ]] && . "${_f}"
done

# Try to keep environment pollution down.
unset _f _match_lhs _safe_term _use_color _used_default_dircolors

# http://tiswww.case.edu/php/chet/bash/FAQ E11
# Make bash check if the window has been resized
shopt -s checkwinsize

# Check magic command status.
if test -e '/dev/sydbox'; then
    stat /dev/sydbox
    echo "/dev/sydbox: [0;1;32;92mOK[0m"
else
    echo "/dev/sydbox: [0;1;31;91mLOCKED[0m"
fi

# Greet the user.
test -n "$SYDBOX" && echo "$SYDBOX"
exit() {
    :
}
