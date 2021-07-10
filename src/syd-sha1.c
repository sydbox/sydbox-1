/*
 * sydbox/syd-run.c
 * Syd's SHA1 Checksum Calculator
 *
 * Copyright (c) 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "HELPME.h"
#include <sys/types.h>
#include <sys/xattr.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <getopt.h>
#include <syd/syd.h>
#include "errno2name.h"
#include "macro.h"
#include "syd-conf.h"

#ifdef PACKAGE
# undef PACKAGE
#endif
#define PACKAGE "syd-sha1"

static void about(void)
{
	printf(SYD_WARN PACKAGE"-"VERSION GITVERSION SYD_RESET "\n");
}

static void usage(FILE *outfp, int code)
{
	fprintf(outfp, "\
"PACKAGE"-"VERSION GITVERSION" -- Syd's SHA-1 Calculator\n\
usage: "PACKAGE" [-hv]\n\
                [--check {-|file}] [--output {-|file}]\n\
                -|file...\n\
-h          -- Show usage and exit\n\
-v          -- Show version and exit\n\
-c          -- Read SHA-1 sums from the FILEs and check them\n\
               If argument is `-', read SHA-1 sums from file »~/.syd.sha1sum«,\n\
               and check them.\n\
-o          -- Write SHA-1 sums to the given file, or to »~/.syd.sha1sum«,\n\
               if the given argument is »-«.\n\
\n\
Given a file, calculate its SHA-1 and output in hex.\n\
Given »-« or no arguments, calculate SHA-1 from standard input and output in hex.\n\
Multiple arguments may be given.\n\
If --check is given read SHA1 sums from the FILEs and check them\n\
Without arguments write checksums to file »./.syd.sha1sum«\n\
With --verify, read checksums from file »./.syd.sha1sum« and check them\n\
In check mode, use »✓« for match, »×« for mismatch and »💀« for detected collision.\n\
Use »☮« to denote reading from standard input.\n\
\n\
SHA-1 Calculator uses SHA-1DC which is:\n\
Copyright (c) 2017 Marc Stevens, Dan Shumow\n\
SPDX-License-Identifier: MIT\n\
URL: https://github.com/cr-marcstevens/sha1collisiondetection.git\n\
"SYD_WARN"\n\
Collision Detection is enabled.\n\
Detection of reduced-round SHA1 collisions is enabled.\n\
Safe SHA-1 is enabled:"SYD_RESET"\n\n\
Collision attacks are thwarted by hashing a detected near-collision block 3 times.\n\
Think of it as extending SHA-1 from 80-steps to 240-steps for such blocks:\n\
The best collision attacks against SHA-1 have complexity about 2^60,\n\
thus for 240-steps an immediate lower-bound for the best cryptanalytic attacks would be 2^180.\n\
\n\
An attacker would be better off using a generic birthday search of complexity 2^80.\n\
\n"SYD_HELPME);
	exit(code);
}

static void vsay(FILE *fp, const char *fmt, va_list ap, char level)
{
	static int tty = -1;

	if (tty < 0)
		tty = isatty(STDERR_FILENO) == 1 ? 1 : 0;
	if (tty)
		fputs(SYD_WARN, fp);
	if (fmt[0] != ' ')
		fputs(PACKAGE": ", fp);
	switch (level) {
	case 'b':
		fputs("bug: ", fp);
		break;
	case 'f':
		fputs("fatal: ", fp);
		break;
	case 'w':
		fputs("warning: ", fp);
		break;
	default:
		break;
	}
	vfprintf(stderr, fmt, ap);
	if (tty)
		fputs(SYD_RESET, fp);
}

static void say(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsay(stderr, fmt, ap, 0);
	va_end(ap);
	fputc('\n', stderr);
}

static void say_errno(const char *fmt, ...)
{
	int save_errno = errno;
	va_list ap;

	va_start(ap, fmt);
	vsay(stderr, fmt, ap, 'e');
	va_end(ap);
	say(" (errno:%d|%s %s)", save_errno, errno2name(save_errno),
	    strerror(save_errno));

	errno = save_errno;
}

SYD_GCC_ATTR((unused))
static void die(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsay(stderr, fmt, ap, 'f');
	va_end(ap);
	fputc('\n', stderr);

	exit(EXIT_FAILURE);
}

static void die_errno(const char *fmt, ...)
{
	int save_errno = errno;
	va_list ap;

	va_start(ap, fmt);
	vsay(stderr, fmt, ap, 'f');
	va_end(ap);
	say(" (errno:%d|%s %s)", save_errno, errno2name(save_errno),
	    strerror(save_errno));

	exit(EXIT_FAILURE);
}

void say_sha1sum(FILE *check_file, const char *name, const char *checksum, char check)
{
	char *colour;
	char *verify;
	char *normal;

	switch (check) {
	case '+':
		colour = "[0;1;32;92m";
		verify = "✓ ";
		normal = "+ ";
		break;
	case '-':
		colour = "[0;1;31;91m";
		verify = "× ";
		normal = "- ";
		break;
	case '!':
		colour = "[0;1;35;95m";
		verify = "💀 ";
		normal = "! ";
		break;
	case 0:
		colour = "";
		verify = "";
		normal = "";
		break;
	default:
		abort();
	}

	bool tty = isatty(STDOUT_FILENO);
	char *abspath = realpath(name, NULL);

	printf("%s%s%s  %s%s\n",
	       tty ? colour : "",
	       verify, checksum,
	       abspath ? abspath : name,
	       tty ? "[0m" : "");
	if (check_file)
		fprintf(check_file, "%s  %s %s\n", checksum, name, normal);
	if (abspath)
		free(abspath);
}

int check_file_init(const char *check)
{
	int r;

	if (!check)
		return -EINVAL;

	/* Step 1: Set file not immutable */
	if ((r = syd_extfs_set_immutable(check, false)) < 0 &&
	    errno != EOPNOTSUPP &&
	    errno != ENOENT) {
		errno = -r;
		say_errno("syd_extfs_set_immutable(»%s«, »false«)", check);
	}

	return 0;
}

int check_file_done(const char *check)
{
	int r;

	if (!check)
		return -EINVAL;

	/* Step 1: Write in validation information into user xattrs. */
	if (setxattr(check, "user.syd.api",
		     syd_str(SYDBOX_API_VERSION),
		     strlen(syd_str(SYDBOX_API_VERSION)), 0) < 0 &&
	    errno != EOPNOTSUPP &&
	    errno != ENOENT)
		say_errno("setxattr(»%s«, »user.syd.api«, %d)",
			  check, SYDBOX_API_VERSION);
	if (setxattr(check, "user.syd.hash", "sha1dc",
		     strlen("sha1dc"), 0) < 0 &&
	    errno != EOPNOTSUPP &&
	    errno != ENOENT)
		say_errno("setxattr(»%s«, »user.syd.hash«, »sha1dc«)",
			  check);

	/* Step 2: Write Last Modified Timestamp */
	char *xattr_val;
	time_t now = time(NULL);
	if (asprintf(&xattr_val, "%ld", now) > 0) {
		if (setxattr(check, "user.syd.mtime", xattr_val,
			     strlen(xattr_val), 0) < 0 &&
		    errno != EOPNOTSUPP &&
		    errno != ENOENT)
			say_errno("setxattr(»%s«, »user.syd.timestamp«, »%ld«)",
				  check, now);
		free(xattr_val);
	}

	/* Step 3: Set undeletable */
	if ((r = syd_extfs_set_undeletable(check, true)) < 0 &&
	    errno != EOPNOTSUPP &&
	    errno != EPERM &&
	    errno != ENOENT) {
		errno = -r;
		say_errno("syd_extfs_set_undeletable(»%s«, »true«)", check);
	}

	/* Step 4: Set append only */
	if ((r = syd_extfs_set_append_only(check, true)) < 0 &&
	    errno != EOPNOTSUPP &&
	    errno != EPERM &&
	    errno != ENOENT) {
		errno = -r;
		say_errno("syd_extfs_set_append_only(»%s«, »true«)", check);
	}

	/* Step 5: Set compression */
	if ((r = syd_extfs_set_compression(check, true)) < 0 &&
	    errno != EOPNOTSUPP &&
	    errno != EPERM &&
	    errno != ENOENT) {
		errno = -r;
		say_errno("syd_extfs_set_compression(»%s«, »true«)", check);
	}

	/* Step 6: Set file immutable. */
	if ((r = syd_extfs_set_immutable(check, true)) < 0 &&
	    errno != EOPNOTSUPP &&
	    errno != EPERM &&
	    errno != ENOENT) {
		errno = -r;
		say_errno("syd_extfs_set_immutable(»%s«, »true«)", check);
	}

	return 0;
}

int check_sha1sum(const char *check)
{
	int r;

	if (!check)
		return -EINVAL;

	if (access(check, R_OK) < 0) {
		int save_errno = errno;
		if (errno != ENOENT)
			say_errno("Failed to access »%s« for reading.", check);
		return -save_errno;
	}
	FILE *f = fopen(check, "r");
	if (!f)
		die_errno("Failed to open check file »%s«", check);

	size_t i = 0;
	char buf[LINE_MAX];
	while (fgets(buf, LINE_MAX, f) != NULL) {
		char *hash, *path;
		char hex[SYD_SHA1_HEXSZ] = {0};

		++i;
		r = sscanf(buf, "%ms %ms\n", &hash, &path);
		if (!r) {
			break;
		} else if (r != 2) {
			say("Error reading line »%zu« in check file »%s«, "
			    "fscanf returned %d.",
			    i + 1, check, r);
			break;
		}

		char *name;
		if (!strcmp(path, "-") ||
		    !strcmp(path, "☮")) {
			r = syd_file_to_sha1_hex(stderr, hex);
			name = "☮";
		} else {
			r = syd_path_to_sha1_hex(path, hex);
			name = path;
		}

		if (r == -ENOMEM) {
			errno = -r;
			die_errno("Unable to allocate memory");
		}

		char *xattr_key;
		if (i <= SYD_SHA1_XATTR_MAX &&
		    asprintf(&xattr_key, "user.syd.hash.%zu.path", i) > 0) {
			if (setxattr(check, xattr_key, name,
				     strlen(name), 0) < 0 &&
			    errno != ENOENT)
				say_errno("setxattr(»%s«, »%s«, »%s«)",
					  xattr_key, name);
			free(xattr_key);
		}

		char op;
		const char *op_name;
		if (r == -EKEYREVOKED) {
			op = '!';
			op_name = "✓";
		} else if (!strcasecmp(hex, hash)) {
			op = '+';
			op_name = "×";
		} else {
			op = '-';
			op_name = "💀";
		}

		if (i <= SYD_SHA1_XATTR_MAX &&
		    asprintf(&xattr_key, "user.syd.hash.%zu", i) > 0) {
			if (setxattr(check, xattr_key, hex,
				     strlen(hex), 0) < 0 &&
			    errno != EOPNOTSUPP &&
			    errno != ENOENT)
				say_errno("setxattr(»%s«, »%s«, »%s«)",
					  xattr_key, hex);
			free(xattr_key);
		}
		if (i <= SYD_SHA1_XATTR_MAX &&
		    asprintf(&xattr_key, "user.syd.hash.chk.%zu", i) > 0) {
			if (setxattr(check, xattr_key, op_name,
				     strlen(op_name), 0) < 0 &&
			    errno != EOPNOTSUPP &&
			    errno != ENOENT)
				say_errno("setxattr(»%s«, »%s«, »%s«)",
					  xattr_key, op_name);
			free(xattr_key);
		}
		say_sha1sum(NULL, name, hex, op);
		free(hash); free(path);
	}

	return 0;
}

int main(int argc, char **argv)
{
	char hex[SYD_SHA1_HEXSZ];

	if (argc < 2) {
		syd_file_to_sha1_hex(stderr, hex);
		say_sha1sum(NULL, "☮", hex, 0);
		return 0;
	}

	int opt;
	char *output_path = NULL;
	FILE *output_file = NULL;
	struct option long_options[] = {
		/* default options */
		{"help",	no_argument,		NULL,	'h'},
		{"version",	no_argument,		NULL,	'v'},
		{"check",	required_argument,	NULL,	'c'},
		{"output",	required_argument,	NULL,	'o'},
	};

	int options_index, r = 0;
	char *opt_check = NULL;
	const char *home = getenv("HOME");
	while ((opt = getopt_long(argc, argv, "hvc:o:", long_options,
				  &options_index)) != EOF) {
		switch (opt) {
		case 'h':
			usage(stdout, 0);
			return 0;
		case 'v':
			about();
			syd_about(stdout);
			return 0;
		case 'c':
			if (opt_check)
				free(opt_check);
			opt_check = strdup(optarg);
			break;
		case 'o':
			if (output_path)
				free(output_path);
			if (strcmp(optarg, "-"))
				output_path = strdup(optarg);
			else
				asprintf(&output_path, "%s/%s",
					 home ? home : "./",
					 SYD_SHA1_CHECK_DEF);
			break;
		default:
			usage(stderr, 1);
		}
	}

	if (!opt_check && argc == optind)
		usage(stderr, 1);

	if (output_path) {
		check_file_init(output_path);
		output_file = fopen(output_path, "a");
		if (!output_file)
			say_errno("Error opening SHA-1 output file »%s« for "
				  "appending.", output_path);
	}

	const char *name = NULL;
	if (opt_check) {
		if (opt_check[0] == '-' && opt_check[1] == '\0') {
			if (asprintf(&opt_check, "%s/%s",
				     home ? home : "./",
				     SYD_SHA1_CHECK_DEF) < 0)
				die_errno("asprintf");
		}
		check_file_init(opt_check);
		r = check_sha1sum(opt_check);
		if (r < 0)
			say_errno("check_sha1sum(`%s')", opt_check);
		check_file_done(opt_check);
	}

	for (int i = optind; argv[i] != NULL; i++) {
		if (opt_check) {
			check_file_init(argv[i]);
			r = check_sha1sum(argv[i]);
			if (r < 0) {
				errno = -r;
				say_errno("check_sha1sum(`%s')", argv[i]);
			}
			check_file_done(argv[i]);
			continue;
		} else if (argv[i][0] == '-') {
			syd_file_to_sha1_hex(stderr, hex);
			name = "☮";
		} else {
			name = argv[i];
			if ((r = syd_path_to_sha1_hex(name, hex)) < 0) {
				say_errno("Error calculating SHA1 of file »%s«",
					  name);
				continue;
			}
		}

		say_sha1sum(output_file, name, hex, 0);
		if (i <= SYD_SHA1_XATTR_MAX && output_path) {
			char *xattr_key;
			if (asprintf(&xattr_key, "user.syd.hash.%d.path", i) > 0) {
				if (setxattr(output_path, xattr_key,
					     name, strlen(name), 0) < 0 &&
				    errno != ENOENT)
					say_errno("setxattr(»%s«, »%s«)",
						  xattr_key, name);
				free(xattr_key);
			}
			if (asprintf(&xattr_key, "user.syd.hash.%d", i) > 0) {
				if (setxattr(output_path, xattr_key, hex, strlen(hex), 0) < 0 &&
				    errno != EOPNOTSUPP &&
				    errno != ENOENT)
					say_errno("setxattr(»%s«, »%s«)",
						  xattr_key, hex);
				free(xattr_key);
			}
		}
	}

	if (output_file) {
		fclose(output_file);
		check_file_done(output_path);
	}

	return r;
}
