#!/bin/sh
# vim: noet sw=8 sts=8 :

VERS="$1"
DESC="$2"
ARCH="$3"

if test -z "$SYDBOX_COVERITY_TOKEN"
then
	echo >&2 "Define SYDBOX_COVERITY_TOKEN environment variable."
	exit 1
fi

if test -z "$VERS" -o -z "$DESC";
then
	echo >&2 "Usage: $0 VERSION DESCRIPTION ARCHIVE-FILE"
	exit 1
elif ! test -f "$ARCH"; then
	echo >&2 "Name '$ARCH' is not a file."
	echo >&2 "Usage: $0 VERSION DESCRIPTION ARCHIVE-FILE"
	exit 1
fi
exec curl \
	--form token="$SYDBOX_COVERITY_TOKEN" \
	--form email=alip@exherbo.org \
	--form file=@"$ARCH" \
	--form version="$VERS" \
	--form description="$DESC" \
	'https://scan.coverity.com/builds?project=sydbox'
