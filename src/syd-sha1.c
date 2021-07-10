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
               If argument is `-', read SHA-1 sums from file »./.syd.sha1sum«,\n\
               and check them.\n\
-o          -- Write SHA-1 sums to the given file, or to »./.syd.sha1sum«,\n\
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
SHA-1 Calculator uses SHA-1DC imported from Git, which is:\n\
Copyright (c) 2017 Marc Stevens, Dan Shumow\n\
SPDX-License-Identifier: MIT\n\
"SYD_WARN"\n\
Collision Detection is enabled.\n\
Detection of reduced-round SHA1 collisions is enabled.\n\
Safe SHA-1 is enabled:"SYD_RESET"\n\
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

void say_checksum(FILE *check_file, const char *name, const char *checksum, char check)
{
	char *verify;
	switch (check) {
	case '+':
		verify = "  ✓";
		break;
	case '-':
		verify = "  ×";
		break;
	case '!':
		verify = "  💀";
		break;
	case 0:
		verify = "";
		break;
	default:
		abort();
	}

	printf("%s  %s%s\n", checksum, name, verify);
	if (check_file)
		fprintf(check_file, "%s  %s%s\n", checksum, name, verify);
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

	/* Step 3: Set secure delete. */
	if ((r = syd_extfs_set_sec_delete(check, true)) < 0 &&
	    errno != EOPNOTSUPP &&
	    errno != EPERM &&
	    errno != ENOENT) {
		errno = -r;
		say_errno("syd_extfs_set_sec_delete(»%s«, »true«)", check);
	}

	/* Step 4: Set file immutable. */
	if ((r = syd_extfs_set_immutable(check, true)) < 0 &&
	    errno != EOPNOTSUPP &&
	    errno != EPERM &&
	    errno != ENOENT) {
		errno = -r;
		say_errno("syd_extfs_set_immutable(»%s«, »true«)", check);
	}

	return 0;
}

int check_checksum(const char *check)
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
			continue;
		}

		char *name;
		if (!strcmp(path, "-") ||
		    !strcmp(path, "☮")) {
			r = syd_fd_to_sha1_hex(STDIN_FILENO, hex);
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
		say_checksum(NULL, name, hex, op);
		free(hash); free(path);
	}

	return 0;
}

int main(int argc, char **argv)
{
	int fd;
	char hex[SYD_SHA1_HEXSZ];

	if (argc < 2) {
		fd = STDIN_FILENO;
		syd_fd_to_sha1_hex(fd, hex);
		say_checksum(NULL, "☮", hex, 0);
		return 0;
	}

	int opt;
	const char *output_path = NULL;
	FILE *output_file = NULL;
	struct option long_options[] = {
		/* default options */
		{"help",	no_argument,		NULL,	'h'},
		{"version",	no_argument,		NULL,	'v'},
		{"check",	no_argument,		NULL,	'c'},
		{"output",	required_argument,	NULL,	'o'},
	};

	int options_index, r = 0;
	bool opt_check = false;
	while ((opt = getopt_long(argc, argv, "hvco:", long_options,
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
			opt_check = true;
			break;
		case 'o':
			if (strcmp(optarg, "-"))
				output_path = optarg;
			else
				output_path = SYD_SHA1_CHECK_DEF;
			break;
		default:
			usage(stderr, 1);
		}
	}

	if (output_path) {
		check_file_init(output_path);
		output_file = fopen(output_path, "a");
		if (!output_file)
			say_errno("Error opening SHA-1 output file »%s« for "
				  "appending.", output_path);
	}

	for (int i = optind; argv[i] != NULL; i++) {
		const char *name = NULL;
		if (opt_check) {
			if (argv[i][0] == '-' &&
			    argv[i][1] == '\0') {
				check_file_init(SYD_SHA1_CHECK_DEF);
				r = check_checksum(SYD_SHA1_CHECK_DEF);
				name = SYD_SHA1_CHECK_DEF;
			} else {
				check_file_init(argv[i]);
				r = check_checksum(argv[i]);
				name = argv[i];
			}
			if (r < 0)
				say_errno("check_checksum(`%s')", name);
			check_file_done(name);
			continue;
		} else if (argv[i][0] == '-') {
			fd = STDIN_FILENO;
			syd_fd_to_sha1_hex(fd, hex);
			name = "☮";
		} else {
			name = argv[i];
			if ((r = syd_path_to_sha1_hex(name, hex)) < 0) {
				say_errno("Error calculating SHA1 of file »%s«",
					  name);
				continue;
			}
		}

		say_checksum(output_file, name, hex, 0);
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
